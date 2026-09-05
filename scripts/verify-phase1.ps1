param(
  [string]$Environment = "dev",
  [string]$Region = "us-east-1",
  [string]$AccountId = $env:CLOUDSEC_AWS_ACCOUNT_ID,
  [string]$StateBucket = $env:CLOUDSEC_STATE_BUCKET,
  [switch]$SendSnsTest
)

$ErrorActionPreference = "Stop"
if ($AccountId -notmatch '^\d{12}$') { throw "Set CLOUDSEC_AWS_ACCOUNT_ID or pass -AccountId" }
if ([string]::IsNullOrWhiteSpace($StateBucket)) { throw "Set CLOUDSEC_STATE_BUCKET or pass -StateBucket" }
$prefix = "cloudsec-$Environment"

function Invoke-AwsJson {
  param([Parameter(ValueFromRemainingArguments = $true)][string[]]$Arguments)
  $result = & aws @Arguments --region $Region --output json
  if ($LASTEXITCODE -ne 0) { throw "AWS CLI command failed: aws $($Arguments -join ' ')" }
  return $result | ConvertFrom-Json
}

function Assert-True([bool]$Condition, [string]$Message) {
  if (-not $Condition) { throw "FAILED: $Message" }
  Write-Host "PASS: $Message" -ForegroundColor Green
}

$identity = Invoke-AwsJson sts get-caller-identity
Assert-True ($identity.Account -eq $AccountId) "Authenticated to expected AWS account"

$versioning = Invoke-AwsJson s3api get-bucket-versioning --bucket $StateBucket
Assert-True ($versioning.Status -eq "Enabled") "State bucket versioning is enabled"

$encryption = Invoke-AwsJson s3api get-bucket-encryption --bucket $StateBucket
$algorithm = $encryption.ServerSideEncryptionConfiguration.Rules[0].ApplyServerSideEncryptionByDefault.SSEAlgorithm
Assert-True ($algorithm -eq "AES256") "State bucket default encryption is AES256"

$publicAccess = Invoke-AwsJson s3api get-public-access-block --bucket $StateBucket
$block = $publicAccess.PublicAccessBlockConfiguration
Assert-True ($block.BlockPublicAcls -and $block.IgnorePublicAcls -and $block.BlockPublicPolicy -and $block.RestrictPublicBuckets) "All state bucket public-access blocks are enabled"

$policyResult = Invoke-AwsJson s3api get-bucket-policy --bucket $StateBucket
$policy = $policyResult.Policy | ConvertFrom-Json
$requiredSids = @(
  "DenyInsecureTransport",
  "DenyUnencryptedUploads",
  "DenyStateObjectDeletion",
  "AllowListBucketForStateDiscovery",
  "AllowStateObjectReadWrite",
  "AllowStateLockFileReadWrite"
)
$actualSids = @($policy.Statement | ForEach-Object Sid)
foreach ($sid in $requiredSids) {
  Assert-True ($actualSids -contains $sid) "Backend policy contains $sid"
}

foreach ($component in @("incident", "evidence", "finding", "ssm")) {
  $alias = "alias/cloudsec/$Environment/$component"
  $aliasResult = Invoke-AwsJson kms list-aliases --query "Aliases[?AliasName=='$alias']|[0]"
  Assert-True ($null -ne $aliasResult.TargetKeyId) "KMS alias $alias exists"
  $rotation = Invoke-AwsJson kms get-key-rotation-status --key-id $aliasResult.TargetKeyId
  Assert-True ($rotation.KeyRotationEnabled -eq $true) "KMS rotation enabled for $alias"
}

$simulationCases = @(
  @{ Role = "$prefix-investigation-role"; Action = "dynamodb:GetItem"; Resource = "arn:aws:dynamodb:${Region}:${AccountId}:table/$prefix-incidents" },
  @{ Role = "$prefix-correlation-role"; Action = "dynamodb:GetItem"; Resource = "arn:aws:dynamodb:${Region}:${AccountId}:table/$prefix-findings" },
  @{ Role = "$prefix-safety-validation-role"; Action = "dynamodb:GetItem"; Resource = "arn:aws:dynamodb:${Region}:${AccountId}:table/$prefix-incidents" },
  @{ Role = "$prefix-remediation-role"; Action = "dynamodb:UpdateItem"; Resource = "arn:aws:dynamodb:${Region}:${AccountId}:table/$prefix-incidents" },
  @{ Role = "$prefix-verification-role"; Action = "dynamodb:GetItem"; Resource = "arn:aws:dynamodb:${Region}:${AccountId}:table/$prefix-incidents" },
  @{ Role = "$prefix-reporting-role"; Action = "dynamodb:GetItem"; Resource = "arn:aws:dynamodb:${Region}:${AccountId}:table/$prefix-incidents" }
)

foreach ($case in $simulationCases) {
  $roleArn = "arn:aws:iam::${AccountId}:role/$($case.Role)"
  $allowed = Invoke-AwsJson iam simulate-principal-policy --policy-source-arn $roleArn --action-names $case.Action --resource-arns $case.Resource
  Assert-True ($allowed.EvaluationResults[0].EvalDecision -eq "allowed") "$($case.Role) allows its scoped action"

  $denied = Invoke-AwsJson iam simulate-principal-policy --policy-source-arn $roleArn --action-names organizations:DeleteOrganization --resource-arns "*"
  Assert-True ($denied.EvaluationResults[0].EvalDecision -ne "allowed") "$($case.Role) denies an out-of-scope administrative action"
}

$budget = Invoke-AwsJson budgets describe-budget --account-id $AccountId --budget-name "$prefix-monthly-budget"
Assert-True ($budget.Budget.BudgetName -eq "$prefix-monthly-budget") "Monthly budget exists"
$notifications = Invoke-AwsJson budgets describe-notifications-for-budget --account-id $AccountId --budget-name "$prefix-monthly-budget"
$thresholds = @($notifications.Notifications | ForEach-Object Threshold)
foreach ($threshold in @(80, 100, 120)) {
  Assert-True ($thresholds -contains $threshold) "Budget contains the $threshold percent alert"
}

$topicArn = "arn:aws:sns:${Region}:${AccountId}:$prefix-cost-alerts"
$null = Invoke-AwsJson sns get-topic-attributes --topic-arn $topicArn
Assert-True $true "Cost-alert SNS topic exists"

if ($SendSnsTest) {
  $null = Invoke-AwsJson sns publish --topic-arn $topicArn --subject "CloudSec Phase 1 verification" --message "Phase 1 SNS delivery test for $Environment"
  Write-Host "PASS: SNS test notification published; confirm receipt at the subscribed endpoint." -ForegroundColor Green
} else {
  Write-Host "SKIP: SNS delivery test. Re-run with -SendSnsTest to publish a real notification." -ForegroundColor Yellow
}

Write-Host "Phase 1 live verification completed." -ForegroundColor Cyan
