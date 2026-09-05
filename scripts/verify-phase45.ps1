param([string]$Region = "us-east-1", [string]$Environment = "dev")
$ErrorActionPreference = "Stop"
function Assert-Check([bool]$Condition, [string]$Message) {
    if (-not $Condition) { throw "FAILED: $Message" }
    Write-Host "PASS: $Message"
}
$prefix = "cloudsec-$Environment"
$account = aws sts get-caller-identity --query Account --output text
Assert-Check ($account -match '^\d{12}$') "Authenticated to AWS account $account"
$table = aws dynamodb describe-table --table-name "$prefix-baselines" --region $Region --output json | ConvertFrom-Json
Assert-Check ($table.Table.KeySchema.Count -eq 2) "Baselines table has composite key"
Assert-Check ($table.Table.SSEDescription.Status -eq "ENABLED") "Baselines table encryption is enabled"
Assert-Check ($table.Table.GlobalSecondaryIndexes.IndexName -contains "account-index") "Baselines account-index exists"
$ttl = aws dynamodb describe-time-to-live --table-name "$prefix-baselines" --region $Region --output json | ConvertFrom-Json
Assert-Check ($ttl.TimeToLiveDescription.TimeToLiveStatus -in @("ENABLED", "ENABLING")) "Baselines TTL is enabled"
$fn = aws lambda get-function-configuration --function-name "$prefix-baseline-computation" --region $Region --output json | ConvertFrom-Json
Assert-Check ($fn.Timeout -eq 300) "Baseline scheduled job timeout is 300 seconds"
Assert-Check ($fn.ReservedConcurrentExecutions -eq $null) "Baseline Lambda uses unreserved concurrency for the current quota"
$rule = aws events describe-rule --name "$prefix-baseline-computation" --region $Region --output json | ConvertFrom-Json
Assert-Check ($rule.ScheduleExpression -eq "cron(0 3 * * ? *)") "Baseline schedule runs daily at 03:00 UTC"
foreach ($kind in @("principal", "ip", "resource")) {
    $value = aws ssm get-parameter --name "/cloudsec/$Environment/correlation/${kind}_window_minutes" --region $Region --query Parameter.Value --output text
    Assert-Check ($value -match '^\d+$') "$kind correlation window exists"
}
Write-Host "Phase 4-5 infrastructure verification completed. Complete the Phase 5 data-quality checkpoint manually."
