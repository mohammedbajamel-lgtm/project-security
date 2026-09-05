param(
    [Parameter(Mandatory = $true)]
    [string]$PlanPath
)

$ErrorActionPreference = "Stop"

function Get-ModuleResources {
    param([Parameter(Mandatory = $true)]$Module)

    @($Module.resources)
    foreach ($child in @($Module.child_modules)) {
        if ($null -ne $child) {
            Get-ModuleResources -Module $child
        }
    }
}

$projectRoot = Split-Path -Parent $PSScriptRoot
$terraformDir = Join-Path $projectRoot "terraform"
$resolvedPlan = (Resolve-Path -LiteralPath $PlanPath).Path

$identityJson = & aws sts get-caller-identity --output json
if ($LASTEXITCODE -ne 0) {
    throw "Unable to read the active AWS identity."
}

$identity = $identityJson | ConvertFrom-Json
if ($identity.Arn -match ":assumed-role/cloudsec-dev-terraform-deploy/") {
    throw "Run this bootstrap with the operator AWS identity, not the cloudsec-dev-terraform-deploy role."
}

$planJson = & terraform "-chdir=$terraformDir" show -json $resolvedPlan
if ($LASTEXITCODE -ne 0) {
    throw "Unable to read Terraform plan: $resolvedPlan"
}

$plan = $planJson | ConvertFrom-Json
$targetAddress = "module.iam.aws_iam_role_policy.terraform_deploy_phase2"
$resource = Get-ModuleResources -Module $plan.planned_values.root_module |
    Where-Object { $_.address -eq $targetAddress } |
    Select-Object -First 1

if (-not $resource) {
    throw "The planned deployment-policy resource was not found. Regenerate the Phase 2 plan first."
}

$policyJson = $resource.values.policy
if (-not $policyJson) {
    throw "The planned deployment policy is empty."
}

$temporaryPolicy = [System.IO.Path]::GetTempFileName()
try {
    [System.IO.File]::WriteAllText(
        $temporaryPolicy,
        $policyJson,
        [System.Text.UTF8Encoding]::new($false)
    )

    & aws iam put-role-policy `
        --role-name "cloudsec-dev-terraform-deploy" `
        --policy-name "cloudsec-dev-phase2-deployment" `
        --policy-document "file://$temporaryPolicy"

    if ($LASTEXITCODE -ne 0) {
        throw "AWS rejected the deployment-policy bootstrap update."
    }
}
finally {
    Remove-Item -LiteralPath $temporaryPolicy -Force -ErrorAction SilentlyContinue
}

Write-Host "PASS: Phase 2 deployment policy bootstrapped from the exact Terraform plan."
