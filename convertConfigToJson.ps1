# Convert legacy inline config variables to config.json
# Usage: Paste your old config block below the comment line, then run this script.

# --- Paste old config here ---

$IsTestingMode = $false
$IsDebugLoggingEnabled = $true

$linuxAzureSplunkWildcardPatterns = @(
    "/var/log/waagent*.log",
    "/tmp/log/.../*.log"
)

$linuxArcSplunkWildcardPatterns = @(
    "/var/log/azure/run-command-handler/handler*.log"
)

$windowsArcSplunkWildcardPatterns = @(
    "C:\Logs\Sample*.log"
)

$windowsAzureSplunkWildcardPatterns = $windowsArcSplunkWildcardPatterns;

$dcrLocation = "westeurope"
$scriptStorageAccount = "arserverssa"
$scriptContainerName = "scripts"
$dcrResourceGroup = "dcr-test-rg"
$maxFilePatternsPerDcr = 100
$maxParallelJobs = 10
$sleepTime = 60
$maxRetries = 30

# --- End of old config ---

$json = [ordered]@{
    isTestingMode         = $IsTestingMode
    isDebugLoggingEnabled = $IsDebugLoggingEnabled

    dcrLocation           = $dcrLocation
    dcrResourceGroup      = $dcrResourceGroup
    scriptStorageAccount  = $scriptStorageAccount
    scriptContainerName   = $scriptContainerName
    csvPath               = "./connectedMachinesAndVms.csv"

    maxFilePatternsPerDcr = $maxFilePatternsPerDcr
    maxParallelJobs       = $maxParallelJobs
    sleepTime             = $sleepTime
    maxRetries            = $maxRetries

    linuxAzureSplunkWildcardPatterns   = @($linuxAzureSplunkWildcardPatterns)
    linuxArcSplunkWildcardPatterns     = @($linuxArcSplunkWildcardPatterns)
    windowsArcSplunkWildcardPatterns   = @($windowsArcSplunkWildcardPatterns)
    windowsAzureSplunkWildcardPatterns = @($windowsAzureSplunkWildcardPatterns)
}

$outputPath = Join-Path $PSScriptRoot "dcrwildcardhelper.config.json"
$json | ConvertTo-Json -Depth 5 | Set-Content -Path $outputPath -Encoding UTF8
Write-Host "Config written to $outputPath" -ForegroundColor Green
