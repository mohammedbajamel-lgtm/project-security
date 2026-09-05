param(
    [string]$Region = "us-east-1",
    [string]$ExpectedAccount = $env:CLOUDSEC_AWS_ACCOUNT_ID,
    [int]$ExpectedConcurrency = -1,
    [switch]$RunSyntheticCheckpoint
)

$ErrorActionPreference = "Stop"
if ($ExpectedAccount -notmatch '^\d{12}$') { throw "Set CLOUDSEC_AWS_ACCOUNT_ID or pass -ExpectedAccount" }
function Assert-Ok([bool]$Condition, [string]$Message) {
    if (-not $Condition) { throw "FAILED: $Message" }
    Write-Host "PASS: $Message"
}

$account = aws sts get-caller-identity --query Account --output text
Assert-Ok ($account -eq $ExpectedAccount) "Authenticated to expected AWS account"

foreach ($source in @("guardduty", "securityhub", "config")) {
    $rule = "cloudsec-dev-$source-findings"
    aws events describe-rule --name $rule --region $Region | Out-Null
    Assert-Ok ($LASTEXITCODE -eq 0) "$rule exists"
    $function = "cloudsec-dev-$source-ingestor"
    $config = aws lambda get-function-configuration --function-name $function --region $Region | ConvertFrom-Json
    Assert-Ok ($config.Timeout -eq 30) "$function timeout is 30 seconds"
    Assert-Ok ($config.MemorySize -eq 512) "$function memory is 512 MB"
    $concurrency = aws lambda get-function-concurrency --function-name $function --region $Region | ConvertFrom-Json
    if ($ExpectedConcurrency -eq -1) {
        Assert-Ok ($null -eq $concurrency.ReservedConcurrentExecutions) "$function uses unreserved concurrency"
    }
    else {
        Assert-Ok ($concurrency.ReservedConcurrentExecutions -eq $ExpectedConcurrency) "$function concurrency is $ExpectedConcurrency"
    }
}

aws dynamodb describe-table --table-name cloudsec-dev-findings --region $Region | Out-Null
Assert-Ok ($LASTEXITCODE -eq 0) "Findings table exists"
aws events describe-event-bus --name cloudsec-dev-security-bus --region $Region | Out-Null
Assert-Ok ($LASTEXITCODE -eq 0) "Security bus exists"
aws sqs get-queue-url --queue-name cloudsec-dev-dlq --region $Region | Out-Null
Assert-Ok ($LASTEXITCODE -eq 0) "DLQ exists"
Write-Host "Phase 3 infrastructure verification completed. Complete the telemetry delivery checkpoint manually."

if ($RunSyntheticCheckpoint) {
    $findingId = "cloudsec-phase3-check-$([guid]::NewGuid().ToString('N'))"
    $eventId = [guid]::NewGuid().ToString()
    $timestamp = [DateTime]::UtcNow.ToString("yyyy-MM-ddTHH:mm:ssZ")
    $detail = @{
        id        = $findingId
        severity  = 5
        updatedAt = $timestamp
        type      = "CloudSec:Verification/Synthetic"
        title     = "Safe Phase 3 delivery verification"
        service   = @{ serviceName = "guardduty" }
        resource  = @{ resourceArn = "arn:aws:iam::$ExpectedAccount:root" }
    } | ConvertTo-Json -Depth 8 -Compress
    $entry = @{
        id = $eventId; account = $ExpectedAccount; region = $Region; time = $timestamp
        detail = ($detail | ConvertFrom-Json)
    } | ConvertTo-Json -Depth 10 -Compress
    $entryFile = [System.IO.Path]::GetTempFileName()
    $responseFile = [System.IO.Path]::GetTempFileName()
    try {
        [System.IO.File]::WriteAllText($entryFile, $entry, [Text.UTF8Encoding]::new($false))
        $entryUri = "fileb://" + ($entryFile -replace '\\', '/')
        $rawResult = aws lambda invoke --function-name cloudsec-dev-guardduty-ingestor `
            --cli-binary-format raw-in-base64-out --payload $entryUri `
            --region $Region $responseFile 2>&1
        $eventExitCode = $LASTEXITCODE
        if ($eventExitCode -ne 0) { throw "FAILED: Lambda rejected the synthetic event: $rawResult" }
        $metadata = ($rawResult -join "`n") | ConvertFrom-Json
        Assert-Ok ($metadata.StatusCode -eq 200 -and -not $metadata.FunctionError) `
            "Synthetic GuardDuty event accepted by the ingestion Lambda"
    }
    finally {
        Remove-Item -LiteralPath $entryFile, $responseFile -Force -ErrorAction SilentlyContinue
    }

    Start-Sleep -Seconds 10
    $values = @{ ":finding" = @{ S = $findingId } } | ConvertTo-Json -Compress
    $valuesFile = [System.IO.Path]::GetTempFileName()
    try {
        [System.IO.File]::WriteAllText($valuesFile, $values, [Text.UTF8Encoding]::new($false))
        $valuesUri = "file://" + ($valuesFile -replace '\\', '/')
        $query = aws dynamodb query --table-name cloudsec-dev-findings `
            --key-condition-expression "finding_id = :finding" `
            --expression-attribute-values $valuesUri --region $Region | ConvertFrom-Json
    }
    finally { Remove-Item -LiteralPath $valuesFile -Force -ErrorAction SilentlyContinue }
    Assert-Ok ($query.Count -ge 1) "Synthetic finding reached DynamoDB"

    $queueUrl = aws sqs get-queue-url --queue-name cloudsec-dev-dlq --region $Region --query QueueUrl --output text
    $initialDepth = aws sqs get-queue-attributes --queue-url $queueUrl `
        --attribute-names ApproximateNumberOfMessages --region $Region `
        --query Attributes.ApproximateNumberOfMessages --output text
    $badEntry = @{ id = "malformed-$eventId"; account = $ExpectedAccount;
        region = $Region; time = $timestamp; detail = @{ id = "malformed-$eventId" } } |
        ConvertTo-Json -Depth 8 -Compress
    $badFile = [System.IO.Path]::GetTempFileName()
    $badResponseFile = [System.IO.Path]::GetTempFileName()
    try {
        [System.IO.File]::WriteAllText($badFile, $badEntry, [Text.UTF8Encoding]::new($false))
        $badEntryUri = "fileb://" + ($badFile -replace '\\', '/')
        $rawBadResult = aws lambda invoke --function-name cloudsec-dev-guardduty-ingestor `
            --cli-binary-format raw-in-base64-out --payload $badEntryUri `
            --region $Region $badResponseFile 2>&1
        $badExitCode = $LASTEXITCODE
        if ($badExitCode -ne 0) { throw "FAILED: Lambda invocation failed: $rawBadResult" }
        $badMetadata = ($rawBadResult -join "`n") | ConvertFrom-Json
        Assert-Ok ($badMetadata.FunctionError -eq "Unhandled") `
            "Malformed test event triggered the Lambda failure path"
    }
    finally {
        Remove-Item -LiteralPath $badFile, $badResponseFile -Force -ErrorAction SilentlyContinue
    }

    Start-Sleep -Seconds 30
    $depth = aws sqs get-queue-attributes --queue-url $queueUrl --attribute-names ApproximateNumberOfMessages `
        --region $Region --query Attributes.ApproximateNumberOfMessages --output text
    Assert-Ok ([int]$depth -gt [int]$initialDepth) "Malformed event increased the DLQ depth"
    Write-Host "Phase 3 synthetic delivery checkpoint completed. Finding ID: $findingId"
}
