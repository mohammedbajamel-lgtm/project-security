[CmdletBinding()]
param(
    [Parameter(Mandatory, Position = 0)]
    [ValidateSet("deploy", "destroy")]
    [string]$Action,
    [ValidateSet("dev", "lab", "demo")]
    [string]$Environment = "lab",
    [switch]$ConfirmDestroy
)

$ErrorActionPreference = "Stop"
$repoRoot = $PSScriptRoot
$terraformRoot = Join-Path $repoRoot "terraform"
$tfvars = Join-Path $terraformRoot "environments/$Environment/$Environment.tfvars"
$backendConfig = Join-Path $terraformRoot "environments/$Environment/backend.hcl"
$backendRoot = Join-Path $terraformRoot "backend"

function Invoke-Checked {
    param([Parameter(Mandatory)][scriptblock]$Command)
    & $Command
    if ($LASTEXITCODE -ne 0) { throw "Command failed with exit code $LASTEXITCODE." }
}

function Get-TfvarsValue {
    param([Parameter(Mandatory)][string]$Name)
    $pattern = '^\s*' + [regex]::Escape($Name) + '\s*=\s*"([^"]+)"\s*$'
    $match = Select-String -LiteralPath $tfvars -Pattern $pattern | Select-Object -First 1
    if (-not $match) { return $null }
    return $match.Matches[0].Groups[1].Value
}

function Remove-BucketContents {
    param([Parameter(Mandatory)][string]$Bucket)
    Write-Host "Emptying Terraform-managed S3 bucket: $Bucket"
    while ($true) {
        $raw = aws s3api list-object-versions --bucket $Bucket --output json
        if ($LASTEXITCODE -ne 0) { throw "Could not list objects in $Bucket." }
        $listing = $raw | ConvertFrom-Json
        $objects = @()
        foreach ($version in @($listing.Versions)) {
            if ($null -ne $version) { $objects += @{ Key = $version.Key; VersionId = $version.VersionId } }
        }
        foreach ($marker in @($listing.DeleteMarkers)) {
            if ($null -ne $marker) { $objects += @{ Key = $marker.Key; VersionId = $marker.VersionId } }
        }
        if ($objects.Count -eq 0) { break }
        $payload = @{ Objects = $objects; Quiet = $true } | ConvertTo-Json -Depth 5 -Compress
        $tempFile = Join-Path ([IO.Path]::GetTempPath()) ("cloudsec-delete-{0}.json" -f [guid]::NewGuid())
        try {
            [IO.File]::WriteAllText($tempFile, $payload, [Text.UTF8Encoding]::new($false))
            $deleteRaw = aws s3api delete-objects --bucket $Bucket --delete "file://$tempFile" --bypass-governance-retention --output json
            if ($LASTEXITCODE -ne 0) { throw "AWS retention or permissions prevented deletion from $Bucket." }
            $deleteResult = $deleteRaw | ConvertFrom-Json
            if (@($deleteResult.Errors).Count -gt 0) { throw "AWS retention prevented one or more objects from being deleted from $Bucket." }
        }
        finally {
            Remove-Item -LiteralPath $tempFile -Force -ErrorAction SilentlyContinue
        }
    }
}

foreach ($tool in @("terraform", "aws")) {
    if (-not (Get-Command $tool -ErrorAction SilentlyContinue)) { throw "$tool is required and was not found in PATH." }
}
if (-not (Test-Path -LiteralPath $tfvars)) { throw "Missing $tfvars. Copy the example file, fill in your account values, and rerun." }
if (-not (Test-Path -LiteralPath $backendConfig)) { throw "Missing $backendConfig. The protected Terraform backend must be configured first." }

$expectedAccount = Get-TfvarsValue "security_account_id"
$actualAccount = (aws sts get-caller-identity --query Account --output text).Trim()
if ($LASTEXITCODE -ne 0) { throw "AWS authentication failed." }
if ($actualAccount -ne $expectedAccount) { throw "Safety stop: signed into AWS account $actualAccount, but tfvars specifies $expectedAccount." }

$env:TF_DATA_DIR = Join-Path $terraformRoot ".terraform-$Environment"
Push-Location $repoRoot
try {
    Invoke-Checked { terraform -chdir=terraform init -reconfigure -backend-config="environments/$Environment/backend.hcl" }
    Invoke-Checked { terraform -chdir=terraform validate }
    if ($Action -eq "deploy") {
        Invoke-Checked { terraform -chdir=terraform apply -auto-approve -var-file="environments/$Environment/$Environment.tfvars" }
        Write-Host "CloudSec $Environment deployment completed."
        exit 0
    }

    if (-not $ConfirmDestroy) { throw "Destruction requires -ConfirmDestroy because it permanently removes lab data." }
    Write-Host "Preparing lab resources for clean deletion."
    Invoke-Checked { terraform -chdir=terraform apply -auto-approve -var-file="environments/$Environment/$Environment.tfvars" }
    $bucketAddresses = @(terraform -chdir=terraform state list | Where-Object { $_ -match 'aws_s3_bucket\.[^.]+$' })
    foreach ($address in $bucketAddresses) {
        $state = terraform -chdir=terraform state show -no-color $address
        $idLine = $state | Select-String -Pattern '^\s*id\s*=\s*"([^\"]+)"' | Select-Object -First 1
        if ($idLine) { Remove-BucketContents $idLine.Matches[0].Groups[1].Value }
    }
    Invoke-Checked { terraform -chdir=terraform destroy -auto-approve -var-file="environments/$Environment/$Environment.tfvars" }

    $backendState = Join-Path $backendRoot "terraform.tfstate"
    if (Test-Path -LiteralPath $backendState) {
        $env:TF_DATA_DIR = Join-Path $backendRoot ".terraform"
        Invoke-Checked { terraform -chdir=terraform/backend init -reconfigure }
        $backendBucket = terraform -chdir=terraform/backend output -raw state_bucket_name
        if ($LASTEXITCODE -eq 0 -and $backendBucket) {
            Remove-BucketContents $backendBucket.Trim()
            $backendVars = Join-Path $backendRoot "dev.tfvars"
            if (Test-Path -LiteralPath $backendVars) {
                Invoke-Checked { terraform -chdir=terraform/backend destroy -auto-approve -var-file=dev.tfvars }
            } else {
                Write-Warning "Main stack is destroyed, but backend tfvars are missing; backend bucket remains."
            }
        }
    }
    Write-Host "CloudSec $Environment teardown completed. KMS keys remain pending deletion for AWS's waiting period."
}
finally {
    Pop-Location
}
