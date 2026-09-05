param([Parameter(Mandatory = $true)][string]$PlanPath)

$ErrorActionPreference = "Stop"
function Get-Resources($Module) {
    @($Module.resources)
    foreach ($child in @($Module.child_modules)) { if ($null -ne $child) { Get-Resources $child } }
}

$projectRoot = Split-Path -Parent $PSScriptRoot
$terraformDir = Join-Path $projectRoot "terraform"
$resolvedPlan = (Resolve-Path -LiteralPath $PlanPath).Path
$identity = (aws sts get-caller-identity --output json | ConvertFrom-Json)
if ($LASTEXITCODE -ne 0) { throw "Unable to read AWS identity." }
if ($identity.Arn -match ":assumed-role/cloudsec-dev-terraform-deploy/") {
    throw "Run with the operator identity, not the Terraform deployment role."
}
$plan = (terraform "-chdir=$terraformDir" show -json $resolvedPlan | ConvertFrom-Json)
if ($LASTEXITCODE -ne 0) { throw "Unable to read the Terraform plan." }
$resources = @(Get-Resources $plan.planned_values.root_module)
$targets = @(
    @{ Address = "module.iam.aws_iam_role_policy.terraform_deploy_phase2"; Role = "cloudsec-dev-terraform-deploy"; Name = "cloudsec-dev-phase2-deployment" },
    @{ Address = "module.iam.aws_iam_role_policy.ingestion"; Role = "cloudsec-dev-ingestion-role"; Name = "cloudsec-ingestion-permissions" }
)
foreach ($target in $targets) {
    $resource = $resources | Where-Object address -eq $target.Address | Select-Object -First 1
    if (-not $resource.values.policy) { throw "Missing planned policy: $($target.Address)" }
    $temporary = [System.IO.Path]::GetTempFileName()
    try {
        [System.IO.File]::WriteAllText($temporary, $resource.values.policy, [Text.UTF8Encoding]::new($false))
        aws iam put-role-policy --role-name $target.Role --policy-name $target.Name --policy-document "file://$temporary"
        if ($LASTEXITCODE -ne 0) { throw "Policy bootstrap failed: $($target.Address)" }
    }
    finally { Remove-Item -LiteralPath $temporary -Force -ErrorAction SilentlyContinue }
}
Write-Host "PASS: Phase 3 IAM policies bootstrapped from the exact reviewed plan."
