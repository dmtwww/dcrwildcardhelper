# Convert legacy inline config variables to config.json
# Usage: Paste your old config block below the comment line, then run this script.

# --- Paste old config here ---

$IsTestingMode = $false

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
$dcrResourceGroup = "dcr-test-rg"
$maxFilePatternsPerDcr = 100
$runCommandTimeoutSeconds = 600

# --- End of old config ---

$json = [ordered]@{
    isTestingMode         = $IsTestingMode

    dcrLocation           = $dcrLocation
    dcrResourceGroup      = $dcrResourceGroup
    csvPath               = "./connectedMachinesAndVms.csv"

    maxFilePatternsPerDcr      = $maxFilePatternsPerDcr
    runCommandTimeoutSeconds   = $runCommandTimeoutSeconds

    linuxAzureSplunkWildcardPatterns   = @($linuxAzureSplunkWildcardPatterns)
    linuxArcSplunkWildcardPatterns     = @($linuxArcSplunkWildcardPatterns)
    windowsArcSplunkWildcardPatterns   = @($windowsArcSplunkWildcardPatterns)
    windowsAzureSplunkWildcardPatterns = @($windowsAzureSplunkWildcardPatterns)
}

$outputPath = Join-Path $PSScriptRoot "dcrwildcardhelper.config.json"
$json | ConvertTo-Json -Depth 5 | Set-Content -Path $outputPath -Encoding UTF8
Write-Host "Config written to $outputPath" -ForegroundColor Green
