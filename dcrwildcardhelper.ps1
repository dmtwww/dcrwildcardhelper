# Enable strict mode to enforce variable declaration
Set-StrictMode -Version Latest

# Load configuration from JSON file
$configPath = Join-Path $PSScriptRoot "dcrwildcardhelper.config.json"
if (-not (Test-Path $configPath)) {
    throw "Configuration file not found: $configPath"
}
$config = Get-Content $configPath -Raw | ConvertFrom-Json

$IsTestingMode = $config.isTestingMode
$IsDebugLoggingEnabled = $config.isDebugLoggingEnabled

# Splunk wildcard patterns per platform
$linuxAzureSplunkWildcardPatterns = @($config.linuxAzureSplunkWildcardPatterns)
$linuxArcSplunkWildcardPatterns = @($config.linuxArcSplunkWildcardPatterns)
$windowsArcSplunkWildcardPatterns = @($config.windowsArcSplunkWildcardPatterns)
$windowsAzureSplunkWildcardPatterns = @($config.windowsAzureSplunkWildcardPatterns)

$dcrLocation = $config.dcrLocation
$scriptStorageAccount = $config.scriptStorageAccount
$scriptContainerName = $config.scriptContainerName
$dcrResourceGroup = $config.dcrResourceGroup

$maxFilePatternsPerDcr = $config.maxFilePatternsPerDcr
$maxParallelJobs = $config.maxParallelJobs
$sleepTime = $config.sleepTime
$maxRetries = $config.maxRetries

# Function to read CSV and populate VM lists
function Get-VMListsFromCSV {
    param (
        [Parameter(Mandatory = $true)]
        [string]$CsvPath
    )

    $result = @{ ArcWindowsVMs = @(); ArcLinuxVMs = @(); AzureWindowsVMs = @(); AzureLinuxVMs = @() }

    foreach ($row in (Import-Csv -Path $CsvPath)) {
        $vmEntry = @($row.SubscriptionId, $row.ResourceGroup, $row.VMName, $row.DCEName, $row.WorkspaceName, $row.TableName)
        $platform = if ($row.ArcAzure -eq "Arc") { "Arc" } else { "Azure" }
        $os = if ($row.WindowsLinux -eq "Windows") { "Windows" } else { "Linux" }
        $result["${platform}${os}VMs"] += ,@($vmEntry)
    }

    return $result
}

function Get-SplunkPathSeparator {
    param (
        [bool]$IsLinuxVm
    )

    if ($IsLinuxVm) {
        return '/'
    }

    return '\'
}

function Get-SplunkPathSegments {
    param (
        [string]$Path,
        [bool]$IsLinuxVm
    )

    $separator = Get-SplunkPathSeparator -IsLinuxVm $IsLinuxVm
    return @($Path -split [regex]::Escape($separator))
}

function Test-SplunkSegmentHasWildcard {
    param (
        [string]$Segment
    )

    return $Segment -eq '...' -or $Segment.IndexOf('*') -ge 0 -or $Segment.IndexOf('?') -ge 0
}

function Test-SplunkPatternHasWildcard {
    param (
        [string]$Pattern,
        [bool]$IsLinuxVm
    )

    foreach ($segment in (Get-SplunkPathSegments -Path $Pattern -IsLinuxVm $IsLinuxVm)) {
        if (Test-SplunkSegmentHasWildcard -Segment $segment) {
            return $true
        }
    }

    return $false
}

function Convert-SplunkWildcardToRegex {
    param (
        [Parameter(Mandatory = $true)]
        [string]$Pattern,
        [bool]$IsLinuxVm
    )

    $separator = Get-SplunkPathSeparator -IsLinuxVm $IsLinuxVm
    $sepRx = [regex]::Escape($separator)
    $segPlus = if ($IsLinuxVm) { '[^/]+' } else { '[^\\]+' }
    $segStar = if ($IsLinuxVm) { '[^/]*' } else { '[^\\]*' }
    $charAny = if ($IsLinuxVm) { '[^/]' } else { '[^\\]' }
    $segments = Get-SplunkPathSegments -Path $Pattern -IsLinuxVm $IsLinuxVm
    $hasLeadingSep = $IsLinuxVm -and $Pattern.StartsWith($separator)

    $rx = [System.Text.StringBuilder]::new()
    [void]$rx.Append('^')
    if ($hasLeadingSep) { [void]$rx.Append($sepRx) }

    $emitted = $false
    foreach ($seg in $segments) {
        if ([string]::IsNullOrEmpty($seg)) { continue }

        if ($seg -eq '...') {
            if ($emitted -or $hasLeadingSep) {
                [void]$rx.Append("(?:$sepRx$segPlus)+")
            } else {
                [void]$rx.Append("(?:$segPlus$sepRx)+")
            }
            $emitted = $true
            continue
        }

        if ($emitted) { [void]$rx.Append($sepRx) }

        # Escape the whole segment, then swap escaped wildcards for regex equivalents
        [void]$rx.Append([regex]::Escape($seg).Replace('\*', $segStar).Replace('\?', $charAny))
        $emitted = $true
    }

    [void]$rx.Append('$')
    return $rx.ToString()
}

function Test-SplunkPathMatch {
    param (
        [string]$Path,
        [string]$Pattern,
        [bool]$IsLinuxVm
    )

    $regexPattern = Convert-SplunkWildcardToRegex -Pattern $Pattern -IsLinuxVm $IsLinuxVm
    return $Path -match $regexPattern
}

function Get-ParentFolderPath {
    param (
        [string]$Path,
        [bool]$IsLinuxVm
    )

    $separator = Get-SplunkPathSeparator -IsLinuxVm $IsLinuxVm
    $lastSeparatorIndex = $Path.LastIndexOf($separator)

    if ($lastSeparatorIndex -lt 0) {
        return $null
    }

    if ($lastSeparatorIndex -eq 0) {
        return $separator
    }

    return $Path.Substring(0, $lastSeparatorIndex)
}

# Build the group DCR base name from location, OS, and table
function Get-GroupDcrBaseName {
    param (
        [string]$Location,
        [bool]$IsLinuxVm,
        [string]$TableName
    )
    $os = if ($IsLinuxVm) { "linux" } else { "windows" }
    return "dcr-$Location-$os-$TableName"
}

# Ensure file pattern exists in a group DCR and VM is associated.
# Uses a shared $DcrCache hashtable (name → resource) to avoid redundant API calls.
# Creates overflow DCRs when filePatterns exceed $maxFilePatternsPerDcr.
function Ensure-GroupDcrPatternAndAssociation {
    param (
        [string]$FilePattern,
        [string]$VmResourceId,
        [bool]$IsLinuxVm,
        [string]$SubscriptionId,
        [string]$DcrResourceGroup,
        [string]$DcrLocation,
        [string]$DceName,
        [string]$WorkspaceName,
        [string]$TableName,
        [hashtable]$DcrCache
    )

    $baseName = Get-GroupDcrBaseName -Location $DcrLocation -IsLinuxVm $IsLinuxVm -TableName $TableName
    $targetDcr = $null
    $dcrWithRoom = $null
    $patternExists = $false

    # Search cached group DCRs for this pattern or one with room
    foreach ($dcrName in ($DcrCache.Keys | Where-Object { $_ -like "$baseName-*" } | Sort-Object)) {
        $dcr = $DcrCache[$dcrName]
        $logFiles = $dcr.Properties.dataSources.logFiles
        if ($null -ne $logFiles) {
            $patterns = @($logFiles[0].filePatterns)
            if ($patterns -contains $FilePattern) {
                $targetDcr = $dcr
                $patternExists = $true
                break
            }
            if ($null -eq $dcrWithRoom -and $patterns.Count -lt $maxFilePatternsPerDcr) {
                $dcrWithRoom = $dcr
            }
        }
    }

    if (-not $patternExists) {
        if ($null -ne $dcrWithRoom) {
            # Add pattern to existing group DCR
            $logFile = $dcrWithRoom.Properties.dataSources.logFiles[0]
            $newPatterns = @($logFile.filePatterns) + @($FilePattern)
            $dataSource = New-AzLogFilesDataSourceObject `
                -Name $logFile.name `
                -FilePattern $newPatterns `
                -Stream $logFile.streams[0]
            $null = Update-AzDataCollectionRule `
                -Name $dcrWithRoom.Name `
                -ResourceGroupName $dcrWithRoom.ResourceGroupName `
                -SubscriptionId $SubscriptionId `
                -DataSourceLogFile $dataSource
            Write-Host "Added file pattern $FilePattern to DCR $($dcrWithRoom.Name)" -ForegroundColor Green
            # Refresh cache
            $targetDcr = Get-AzResource -ResourceId $dcrWithRoom.ResourceId
            $DcrCache[$targetDcr.Name] = $targetDcr
        }
        else {
            # Create new group DCR (first or overflow)
            $existingCount = @($DcrCache.Keys | Where-Object { $_ -like "$baseName-*" }).Count
            $nextIndex = $existingCount + 1
            $dcrName = "$baseName-$($nextIndex.ToString('000'))"
            if ($nextIndex -gt 1) {
                Write-Host "File pattern limit ($maxFilePatternsPerDcr) reached. Creating overflow DCR: $dcrName" -ForegroundColor Yellow
            }
            Write-Host "Creating group DCR: $dcrName with pattern $FilePattern" -ForegroundColor Yellow
            $newDcr = New-DcrFromWildcard `
                -dcrName $dcrName `
                -dcrResourceGroupName $DcrResourceGroup `
                -dcrSubscriptionId $SubscriptionId `
                -dcrLocation $DcrLocation `
                -dceName $DceName `
                -customLogPath $FilePattern `
                -tableName $TableName `
                -workspaceName $WorkspaceName `
                -isLinuxVm $IsLinuxVm
            $targetDcr = Get-AzResource -ResourceId $newDcr.Id
            $DcrCache[$targetDcr.Name] = $targetDcr
        }
    }
    else {
        Write-Host "File pattern $FilePattern already in DCR $($targetDcr.Name)" -ForegroundColor Green
    }

    # Ensure association (idempotent - catch conflict if already exists)
    $assocName = "assoc-$($targetDcr.Name)"
    try {
        $null = New-AzDataCollectionRuleAssociation `
            -AssociationName $assocName `
            -ResourceUri $VmResourceId `
            -DataCollectionRuleId $targetDcr.ResourceId
    }
    catch {
        # Association already exists or is being updated - ignore conflict
        if ($_.Exception.Message -notmatch 'already exists|Conflict|same association') {
            throw
        }
    }

    return $targetDcr
}

        # Create a DCR based on a name
function New-DcrFromWildcard {
    param (
        [string]$dcrName,
        [string]$dcrResourceGroupName,
        [string]$dcrSubscriptionId,
        [string]$dcrLocation,
        [string]$dceName,
        [string]$customLogPath,
        [string]$tableName,
        [string]$workspaceName,
        [bool]$isLinuxVm
    )

    $dceId = "/subscriptions/$dcrSubscriptionId/resourceGroups/$dcrResourceGroupName/providers/Microsoft.Insights/dataCollectionEndpoints/$dceName"
    
    $kind = if ($isLinuxVm) { "Linux" } else { "Windows" }

    # Resolve the actual workspace resource instead of assuming it shares the DCR resource group.
    $workspaceResource = @(Get-AzResource -ResourceType "Microsoft.OperationalInsights/workspaces" -Name $workspaceName -ErrorAction Stop) | Select-Object -First 1
    if ($null -eq $workspaceResource) {
        throw "Workspace $workspaceName was not found in subscription $dcrSubscriptionId."
    }

    $workspaceResourceId = $workspaceResource.ResourceId

    # Create DCR payload
    $dcrPayload = @{
        name = $dcrName
        location = $dcrLocation
        kind = $kind
        properties = @{
            dataCollectionEndpointId = "$dceId"
            streamDeclarations = @{
                "Custom-Text-$tableName" = @{
                    columns = @(
                        @{ "name" = "TimeGenerated"; "type" = "datetime" }
                        @{ "name" = "RawData"; "type" = "string" }
                        @{ "name" = "FilePath"; "type" = "string" }
                        @{ "name" = "Computer" ; "type" = "string" }
                    )
                }
            }
            dataSources = @{
                logFiles = @(  # Changed from fileLogs
                    @{
                        streams = @("Custom-Text-$tableName")
                        filePatterns = @($customLogPath)
                        format = "text"
                        settings = @{ "text" = @{ "recordStartTimestampFormat" = "ISO 8601" } }
                        name = "Custom-Text-$tableName"
                    }
                )
            }
            destinations = @{
                logAnalytics = @(
                    @{
                        workspaceResourceId = $workspaceResourceId
                        name = $dcrName
                    }
                )
            }
            dataFlows = @(
                @{
                    streams = @("Custom-Text-$tableName")
                    destinations = @($dcrName)
                    transformKql = "source | extend TimeGenerated, RawData, Computer, FilePath"
                    outputStream = "Custom-$tableName"
                }
            )
        }
    }

    $payload = $dcrPayload | ConvertTo-Json -depth 10
    
    # Deploy DCR
    $retDcr = New-AzDataCollectionRule `
        -Name "$dcrName" `
        -ResourceGroupName "$dcrResourceGroupName" `
        -JsonString $payload

    return $retDcr
}

# helper function to get the anchor from a wildcard folde pattern
# ie the base folder before any wildcards
# example: Get-AnchorFromWildcard -SplunkWildcardPathname "/home/*/.bash_history" returns "/home"
function Get-AnchorFromWildcard {
    param (
        [string]$SplunkWildcardPathname,
        [bool]$IsLinuxVm
    )

    $segments = Get-SplunkPathSegments -Path $SplunkWildcardPathname -IsLinuxVm $IsLinuxVm
    $separator = Get-SplunkPathSeparator -IsLinuxVm $IsLinuxVm
    
    $anchorSegments = @()
    foreach ($seg in $segments) {
        if (Test-SplunkSegmentHasWildcard -Segment $seg) { break }
        if ($seg -ne '') { $anchorSegments += $seg }
    }

    $anchor = $anchorSegments -join $separator
    if ($IsLinuxVm -and $SplunkWildcardPathname.StartsWith($separator)) {
        $anchor = "$separator$anchor"
    }

    return $anchor
}

# helper function to get the first matching wildcard pattern (converted to a DCR FilePattern) for a given folder
# for example if the Folder parameter is '/var/log' 
# and that matches the RegEx wildcard path '/var/[^/]+]/[^/]+.log' then return what DCR can process:
# the folder + globbed filename pattern. that is: '/var/log/*.log' 
function Get-FirstDcrFilePattern { 
    param (
        [string]$Folder,
        [array]$splunkWildcardPaths,
        [bool]$IsLinuxVm
    )

    foreach ($item in $splunkWildcardPaths) {
        if (Test-SplunkPathMatch -Path $Folder -Pattern $item -IsLinuxVm $IsLinuxVm) {
            return $Folder
        }

        $sep = Get-SplunkPathSeparator -IsLinuxVm $IsLinuxVm
        $splunkPatternFileName = $item.Substring($item.LastIndexOf($sep))

        # eg '/var/log' + '/*.log'
        $dcrFilePattern = $Folder + $splunkPatternFileName
        
        # eg '/var/log/*.log' matches '/var/[^/]+/[^/]+.log'
                if (Test-SplunkPathMatch -Path $dcrFilePattern -Pattern $item -IsLinuxVm $IsLinuxVm) {
            return $dcrFilePattern
        }
    }
    return $null
}

# helper function to build the script that will be executed on the VM
function Get-IngestScriptLinux {
    param (
        [bool]$isArcConnectedMachine,
        [string]$scriptStorageAccount,
        [string]$LogFilePath,
        [string]$tableName,
        [string]$dcrImmutableId,
        [string]$dceEndpointId,
        [string]$timestampColumn,
        [string]$timespan,
        [string]$scriptContainerName,
        [string]$workspaceId,
        [string]$VMName,
        [int]$sleepTime,
        [int]$maxRetries
    )

    if ($isArcConnectedMachine -eq $true) {
        $imdsHost = "localhost:40342"
    }
    else {
        $imdsHost = "169.254.169.254"
    }
    
    $script = @"
echo "Part I Get Access Token"
API_VERSION="2020-06-01"
RESOURCE="https://storage.azure.com/"
IDENTITY_ENDPOINT="http://$imdsHost/metadata/identity/oauth2/token"
ENDPOINT="`${IDENTITY_ENDPOINT}?resource=`${RESOURCE}&api-version=`${API_VERSION}"
"@

    # this ensures the next chunk starts on a new line
    $script += "`n"

    if ($isArcConnectedMachine -eq $true) {
        $script += @"
WWW_AUTH_HEADER=`$(curl -s -D - -o /dev/null -H "Metadata: true" "`$ENDPOINT" | grep -i "WWW-Authenticate")
SECRET_FILE=`$(echo `$WWW_AUTH_HEADER | awk -F 'Basic realm=' '{print `$2}' | sed 's/\r$//')
if [[ ! -f "`$SECRET_FILE" ]]; then echo "Error 2" && exit 1; fi
SECRET=`$(cat "`$SECRET_FILE")
RESPONSE=`$(curl -s -H "Metadata: true" -H "Authorization: Basic `$SECRET" "`$ENDPOINT")
"@
    }
    else {
        $script += @"
RESPONSE=`$(curl -s -H "Metadata: true" "`$ENDPOINT")`
"@
    }

    # this ensures the next chunk starts on a new line
    $script += "`n"

    $script += @"
ACCESS_TOKEN=`$(echo "`$RESPONSE" | sed -n 's/.*"access_token"[[:space:]]*:[[:space:]]*"\([^"]*\)".*/\1/p')
if [ -n "`$ACCESS_TOKEN" ]; then echo "`$ACCESS_TOKEN"; else echo "Error 003 `$RESPONSE" && exit 1; fi
echo "Part II Download script"
storage_account=$scriptStorageAccount
container_name=$scriptContainerName
source_log_file=$LogFilePath
target_table=$tableName
dcr_immutable_id=$dcrImmutableId
endpoint_uri=$dceEndpointId
timestamp_column=$timestampColumn
time_span=$timespan
blob_name="waitForLogsAndIngest.sh"
local_file="waitForLogsAndIngest.sh"
workspace_id=$workspaceId
computer_name=$VMName
is_arc_connected_machine=$isArcConnectedMachine
sleep_time=$sleepTime
max_retries=$maxRetries
blob_url="https://`${storage_account}.blob.core.windows.net/`${container_name}/`${blob_name}"
curl -H "Authorization: Bearer `$ACCESS_TOKEN" -H "x-ms-version: 2020-10-02" "`$blob_url" -o "`$local_file"
chmod +x "`$local_file"
sed -i 's/\r$//' "./`$local_file"
bash "./`$local_file" `$workspace_id `$computer_name `$source_log_file `$target_table `$dcr_immutable_id `$endpoint_uri `$timestamp_column `$time_span `$is_arc_connected_machine `$sleep_time `$max_retries > "`${local_file%.sh}.log" 2>&1
echo "Part III Upload log file"
log_blob_name="`${blob_name%.sh}.log"
log_blob_url="https://`${storage_account}.blob.core.windows.net/`${container_name}/`${log_blob_name}"
curl -X PUT -H "Authorization: Bearer `$ACCESS_TOKEN" -H "x-ms-version: 2020-10-02" -H "x-ms-blob-type: BlockBlob" --data-binary @"`${local_file%.sh}.log" "`$log_blob_url"
"@

    return $script
}

# Refer to this article for how to get the access_token 
# https://learn.microsoft.com/en-us/azure/azure-arc/servers/managed-identity-authentication#acquiring-an-access-token-using-rest-api
function Get-IngestScriptWindows {
    param (
        [bool]$isArcConnectedMachine,
        [string]$scriptStorageAccount,
        [string]$LogFilePath,
        [string]$tableName,
        [string]$dcrImmutableId,
        [string]$dceEndpointId,
        [string]$timestampColumn,
        [string]$timespan,
        [string]$scriptContainerName,
        [string]$workspaceId,
        [string]$VMName,
        [int]$sleepTime,
        [int]$maxRetries
    )

    if ($isArcConnectedMachine -eq $true) {
        $imdsHost = "localhost:40342"
    }
    else {
        $imdsHost = "169.254.169.254"
    }
    
    $script = @"
echo "Part I Get Access Token"
`$API_VERSION = "2020-06-01"
`$RESOURCE = "https://storage.azure.com/"
`$IDENTITY_ENDPOINT = "http://$imdsHost/metadata/identity/oauth2/token"
`$ENDPOINT = "`${IDENTITY_ENDPOINT}?resource=`$RESOURCE&api-version=`$API_VERSION"
"@

    # this ensures the next chunk starts on a new line
    $script += "`n"

    if ($isArcConnectedMachine -eq $true) {
        $script += @"
try { (Invoke-WebRequest -Uri `$ENDPOINT -Headers @{Metadata='true'} -UseBasicParsing -ErrorAction Stop).Headers['WWW-Authenticate'] } catch { `$WWW_AUTH_HEADER = `$_.Exception.Response.Headers['WWW-Authenticate'] }
`$SECRET_FILE = (`$WWW_AUTH_HEADER -split 'Basic realm=')[1] -replace "`r$",""
if (-not (Test-Path `$SECRET_FILE)) { Write-Output "Error 2"; exit 1 }
`$SECRET=`$(cat "`$SECRET_FILE")
`$RESPONSE = Invoke-WebRequest -Method Get -Uri `$ENDPOINT -Headers @{Metadata='True'; Authorization="Basic `$SECRET"} -UseBasicParsing
"@
    }
    else {
        $script += @"
`$RESPONSE = Invoke-WebRequest -Method Get -Uri `$ENDPOINT -Headers @{Metadata='True'} -UseBasicParsing
"@
    }

    # this ensures the next chunk starts on a new line
    $script += "`n"

    $script += @"
`$ACCESS_TOKEN = (ConvertFrom-Json -InputObject `$RESPONSE.Content).access_token
if ([string]::IsNullOrWhiteSpace(`$ACCESS_TOKEN)) { Write-Output "Error 003 `$env:RESPONSE"; exit 1 }
echo "Part II Download script"
`$STORAGE_ACCOUNT = "$scriptStorageAccount"
`$CONTAINER_NAME = "$scriptContainerName"
`$SOURCE_LOG_FILE = "$LogFilePath"
`$TARGET_TABLE = "$tableName"
`$DCR_IMMUTABLE_ID = "$dcrImmutableId"
`$ENDPOINT_URI = "$dceEndpointId"
`$TIMESTAMP_COLUMN = "$timestampColumn"
`$TIME_SPAN = "$timespan"
`$BLOB_NAME = "waitForLogsAndIngest.ps1"
`$LOCAL_FILE = "waitForLogsAndIngest.ps1"
`$WORKSPACE_ID = "$workspaceId"
`$COMPUTER_NAME = "$VMName"
`$IS_ARC_CONNECTED_MACHINE = "$isArcConnectedMachine"
`$SLEEP_TIME = "$sleepTime"
`$MAX_RETRIES = "$maxRetries"
`$LOG_BLOB_NAME = (`$BLOB_NAME -replace '\.ps1$', '') + '.log'
`$BLOB_URL = "https://`${STORAGE_ACCOUNT}.blob.core.windows.net/`${CONTAINER_NAME}/`${BLOB_NAME}"
Invoke-WebRequest -Uri `$BLOB_URL -Headers @{ "Authorization" = "Bearer `$ACCESS_TOKEN"; "x-ms-version" = "2020-10-02" } -UseBasicParsing -OutFile `$LOCAL_FILE
& "./`$LOCAL_FILE" -workspaceId "`$WORKSPACE_ID" -computerName "`$COMPUTER_NAME" -sourceLogFile "`$SOURCE_LOG_FILE" -targetTable "`$TARGET_TABLE" -dcrImmutableId "`$DCR_IMMUTABLE_ID" -endpointUri "`$ENDPOINT_URI" -timestampColumn "`$TIMESTAMP_COLUMN" -timeSpan "`$TIME_SPAN" -isArcConnectedMachine "`$IS_ARC_CONNECTED_MACHINE" -sleepTime "`$SLEEP_TIME" -maxRetries "`$MAX_RETRIES"
echo "Part III Upload log file"
`$LOG_BLOB_URL = "https://`${STORAGE_ACCOUNT}.blob.core.windows.net/`${CONTAINER_NAME}/`${LOG_BLOB_NAME}"
Invoke-WebRequest -Uri `$LOG_BLOB_URL -Headers @{ "Authorization" = "Bearer `$ACCESS_TOKEN"; "x-ms-version" = "2020-10-02"; "x-ms-blob-type" = "BlockBlob" } -Method Put -InFile "`$LOG_BLOB_NAME" -UseBasicParsing
"@

    return $script
}

# Get-IngestScript helper to choose Linux or Windows version
function Get-IngestScript {
    param (
        [bool]$isArcConnectedMachine,
        [string]$scriptStorageAccount,
        [string]$LogFilePath,
        [string]$tableName,
        [string]$dcrImmutableId,
        [string]$dceEndpointId,
        [string]$timestampColumn,
        [string]$timespan,
        [string]$scriptContainerName,
        [string]$workspaceId,
        [string]$VMName,
        [bool]$isLinuxVm,
        [int]$sleepTime,
        [int]$maxRetries
    )

    $params = @{
        isArcConnectedMachine = $isArcConnectedMachine
        scriptStorageAccount  = $scriptStorageAccount
        LogFilePath           = $LogFilePath
        tableName             = $tableName
        dcrImmutableId        = $dcrImmutableId
        dceEndpointId         = $dceEndpointId
        timestampColumn       = $timestampColumn
        timespan              = $timespan
        scriptContainerName   = $scriptContainerName
        workspaceId           = $workspaceId
        VMName                = $VMName
        sleepTime             = $sleepTime
        maxRetries            = $maxRetries
    }

    if ($isLinuxVm) { return Get-IngestScriptLinux @params }
    else { return Get-IngestScriptWindows @params }
}


# Execute a run command on a VM based on whether it's Arc-connected and Linux/Windows
function RunCommand {
    param (
        [string]$ResourceGroupName,
        [string]$VMName,
        [string]$ScriptString,
        [bool]$IsArcConnectedMachine,
        [bool]$IsLinuxVm,
        [bool]$IsAsync = $false
    )

    $retryMax = 10
    $retryDelay = 60  # seconds

    for ($attempt = 1; $attempt -le $retryMax; $attempt++) {
        try {
            $commandId = if ($IsLinuxVm) { 'RunShellScript' } else { 'RunPowerShellScript' }

            if ($IsArcConnectedMachine -and $IsAsync) {
                $result = New-AzConnectedMachineRunCommand `
                    -ResourceGroupName $ResourceGroupName `
                    -MachineName $VMName `
                    -Location $dcrLocation `
                    -RunCommandName "ArcRunCmd" `
                    -SourceScript $ScriptString `
                    -AsJob
            }
            elseif ($IsArcConnectedMachine) {
                $result = Invoke-AzConnectedMachineRunCommand `
                    -ResourceGroupName $ResourceGroupName `
                    -MachineName $VMName `
                    -CommandId $commandId `
                    -ScriptString $ScriptString `
                    -ErrorAction Stop
            }
            elseif ($IsAsync) {
                $result = Invoke-AzVMRunCommand `
                    -ResourceGroupName $ResourceGroupName `
                    -VMName $VMName `
                    -CommandId $commandId `
                    -ScriptString $ScriptString `
                    -AsJob
            }
            else {
                $result = Invoke-AzVMRunCommand `
                    -ResourceGroupName $ResourceGroupName `
                    -VMName $VMName `
                    -CommandId $commandId `
                    -ScriptString $ScriptString `
                    -ErrorAction Stop
            }

            return $result
        }
        catch {
            if ($_.Exception.Message -match '409|Conflict|in progress' -and $attempt -lt $retryMax) {
                Write-Host "Run command conflict on $VMName (attempt $attempt/$retryMax). Retrying in ${retryDelay}s..." -ForegroundColor Yellow
                Start-Sleep -Seconds $retryDelay
            }
            else {
                throw
            }
        }
    }
}

# start an async run-command to monitor the target table and ingest any missing log file entries
function RunCommandAsyncToIngestMissingLogs {
    param (
        [string]$SubscriptionId,
        [string]$ResourceGroupName,
        [string]$VMName,
        [string]$DcrName,
        [string]$LogFilePath,
        [string]$scriptStorageAccount,
        [string]$scriptContainerName,
        [bool]$isArcConnectedMachine,
        [string]$dcrImmutableId,
        [string]$dceEndpointId,
        [string]$workspaceId,
        [string]$tableName,
        [string]$timestampColumn,
        [string]$timespan,
        [bool]$isLinuxVm,
        [int]$sleepTime,
        [int]$maxRetries
    )

    # TODO implement the function to run a command asynchronously to monitor the target table and ingest any missing log file entries
    Write-Host "Starting async command to monitor logs for VM $VMName, DCR $DcrName, Log File Path $LogFilePath" -ForegroundColor Blue

    # script outline:
    # 1. Get an access token for Storage
    # 2. Download scripts from storage to the VM
    # 3. Run the script
    ## 1. Determine the target Log Analytics workspace associated with the DCR
    ## 2. Start a background job or scheduled task on the VM to periodically check the Log Analytics workspace for new log entries from the specified log file path
    ## 3. Ingest any missing log file entries into the target table

    # this script is a compact version of getAccessToken.sh and downloadScriptFromStorage.sh
    # note the backticks prevent the bash variables from being expanded in PowerShell
    # note on Azure VM get a token with:
    # http://169.254.169.254/metadata/identity/oauth2/token?api-version=2018-02-01&resource=<resource>
    # where resource is eg https://storage.azure.com/
    # on Arc enabled connected machine, use:
    # http://localhost:40342/metadata/identity/oauth2/token?api-version=2020-06-01&resource=<resource>
    # on Azure linux curl -s -H "Metadata: true" "$ENDPOINT" returns JSON with access_token

    # the KQL pattern matching for FilePath uses RegEx 
    # so convert the glob style pattern to RegEx
    $regexPattern = $LogFilePath -replace '\*', '.*' -replace '\?', '.'

    $script = Get-IngestScript `
        -isArcConnectedMachine $isArcConnectedMachine `
        -scriptStorageAccount $scriptStorageAccount `
        -LogFilePath $regexPattern `
        -tableName $tableName `
        -dcrImmutableId $dcrImmutableId `
        -dceEndpointId $dceEndpointId `
        -timestampColumn $timestampColumn `
        -timespan $timespan `
        -scriptContainerName $scriptContainerName `
        -workspaceId $workspaceId `
        -VMName $VMName `
        -isLinuxVm $isLinuxVm `
        -sleepTime $sleepTime `
        -maxRetries $maxRetries

    $scriptOneLine = ($script -split "`r?`n" | Where-Object { $_.Trim() -ne "" }) -join ";"

    $job = RunCommand `
        -ResourceGroupName $ResourceGroupName `
        -VMName $VMName `
        -ScriptString $scriptOneLine `
        -IsArcConnectedMachine $isArcConnectedMachine `
        -IsLinuxVm $isLinuxVm `
        -IsAsync $true

    Write-Host "Started async job for pre ingestion with ID: $($job.Id)" -ForegroundColor Blue
}

function main {
    param (
        [Parameter(Mandatory = $true)]
        [array]$SplunkWildcardPaths,
        [Parameter(Mandatory = $true)]
        [array]$VmList,
        [Parameter(Mandatory = $true)]
        [System.Boolean]$IsArcConnectedMachine,
        [Parameter(Mandatory = $true)]
        [System.Boolean]$IsLinuxVm
    )

    # Pre-load all existing group DCRs into a cache (name -> resource with properties)
    $groupDcrCache = @{}
    $allDcrs = @(Get-AzResource -ResourceGroupName $dcrResourceGroup -ResourceType "microsoft.insights/datacollectionrules" -ErrorAction SilentlyContinue)
    foreach ($d in $allDcrs) {
        $detail = Get-AzResource -ResourceId $d.ResourceId
        $groupDcrCache[$d.Name] = $detail
    }
    if ($IsDebugLoggingEnabled) {
        Write-Host "[DEBUG] Loaded $($groupDcrCache.Count) existing DCR(s) from $dcrResourceGroup" -ForegroundColor DarkYellow
    }

    $vmTypeLabel = "$(if ($IsArcConnectedMachine) { 'Arc' } else { 'Azure' }) $(if ($IsLinuxVm) { 'Linux' } else { 'Windows' })"

    # Build the discovery command once (same for all VMs sharing these patterns)
    $cmds = ""
    foreach ($wildcardPath in $SplunkWildcardPaths) {
        $anchor = Get-AnchorFromWildcard -SplunkWildcardPathname $wildcardPath -IsLinuxVm $IsLinuxVm
        $patternHasWildcard = Test-SplunkPatternHasWildcard -Pattern $wildcardPath -IsLinuxVm $IsLinuxVm

        if ($patternHasWildcard) {
            if ($IsLinuxVm) {
                $cmd = "find `"$anchor`" \( -type f -o -type d \) -printf '%y:%p`n'"
            }
            else {
                $cmd = "Get-ChildItem -Path '$anchor' -Recurse -Force | ForEach-Object { if (`$_.PSIsContainer) { 'd:' + `$_.FullName } else { 'f:' + `$_.FullName } }"
            }
        }
        else {
            if ($IsLinuxVm) {
                $cmd = "if [ -e `"$wildcardPath`" ]; then if [ -d `"$wildcardPath`" ]; then printf 'd:%s`n' `"$wildcardPath`"; else printf 'f:%s`n' `"$wildcardPath`"; fi; fi"
            }
            else {
                $cmd = "if (Test-Path -LiteralPath '$wildcardPath') { `$item = Get-Item -LiteralPath '$wildcardPath' -Force; if (`$item.PSIsContainer) { 'd:' + `$item.FullName } else { 'f:' + `$item.FullName } }"
            }
        }

        $cmds += $cmd + "; "
    }

    # ── Phase 1: Submit parallel discovery jobs ──
    Write-Host "`n=== Phase 1: Submitting discovery jobs for $($VmList.Count) ${vmTypeLabel} VM(s) ===" -ForegroundColor Cyan
    $discoveryEntries = @()  # array of @{ Job = <job|null>; Vm = <vm array> }

    if ($IsTestingMode) {
        foreach ($vm in $VmList) {
            $discoveryEntries += @{ Job = $null; Vm = $vm }
        }
    }
    else {
        # Group VMs by subscription to minimize Set-AzContext calls
        $vmsBySubscription = [ordered]@{}
        foreach ($vm in $VmList) {
            $subId = $vm[0]
            if (-not $vmsBySubscription.Contains($subId)) {
                $vmsBySubscription[$subId] = @()
            }
            $vmsBySubscription[$subId] += ,@($vm)
        }

        $commandId = if ($IsLinuxVm) { 'RunShellScript' } else { 'RunPowerShellScript' }

        foreach ($subId in $vmsBySubscription.Keys) {
            # Set context once per subscription before submitting its jobs
            if ($script:lastContextSubscriptionId -ne $subId) {
                $tenantId = (Get-AzSubscription -SubscriptionId $subId -WarningAction SilentlyContinue).TenantId
                Set-AzContext -Subscription $subId -TenantId $tenantId -WarningAction SilentlyContinue | Out-Null
                $script:lastContextSubscriptionId = $subId
            }

            foreach ($vm in $vmsBySubscription[$subId]) {
                $machine = $vm[2]
                $resourceGroup = $vm[1]

                # Throttle: wait if we have hit the max parallel limit
                while (@($discoveryEntries | Where-Object { $null -ne $_.Job -and $_.Job.State -eq 'Running' }).Count -ge $maxParallelJobs) {
                    Start-Sleep -Seconds 5
                }

                try {
                    Write-Host "  Submitting discovery job for $machine" -ForegroundColor Green
                    if ($IsArcConnectedMachine) {
                        $job = Invoke-AzConnectedMachineRunCommand `
                            -ResourceGroupName $resourceGroup `
                            -MachineName $machine `
                            -CommandId $commandId `
                            -ScriptString $cmds `
                            -AsJob
                    }
                    else {
                        $job = Invoke-AzVMRunCommand `
                            -ResourceGroupName $resourceGroup `
                            -VMName $machine `
                            -CommandId $commandId `
                            -ScriptString $cmds `
                            -AsJob
                    }
                    $discoveryEntries += @{ Job = $job; Vm = $vm }
                }
                catch {
                    Write-Host "  Error submitting discovery for ${machine}: $_" -ForegroundColor Red
                    $discoveryEntries += @{ Job = $null; Vm = $vm }
                }
            }
        }

        # Wait for all discovery jobs to complete
        $runningJobs = @($discoveryEntries | Where-Object { $null -ne $_.Job } | ForEach-Object { $_.Job })
        if ($runningJobs.Count -gt 0) {
            Write-Host "`nWaiting for $($runningJobs.Count) discovery job(s) to complete..." -ForegroundColor Cyan
            $runningJobs | Wait-Job | Out-Null
            $completedCount = @($runningJobs | Where-Object { $_.State -eq 'Completed' }).Count
            $failedCount = $runningJobs.Count - $completedCount
            Write-Host "Discovery complete: $completedCount succeeded, $failedCount failed." -ForegroundColor Green
        }
    }

    # ── Phase 2: Process results sequentially (match folders, create/update DCRs, associate, ingest) ──
    Write-Host "`n=== Phase 2: Processing results and managing DCRs ===" -ForegroundColor Cyan

    foreach ($entry in $discoveryEntries) {
        $vm = $entry.Vm
        $job = $entry.Job
        $serverStopwatch = [System.Diagnostics.Stopwatch]::StartNew()
        $subscriptionId = $vm[0]
        $resourceGroup = $vm[1]
        $machine = $vm[2]
        $dceName = $vm[3]
        $workspaceName = $vm[4]
        $tableName = $vm[5]

        if ($script:lastContextSubscriptionId -ne $subscriptionId) {
            $tenantId = (Get-AzSubscription -SubscriptionId $subscriptionId -WarningAction SilentlyContinue).TenantId
            Set-AzContext -Subscription $subscriptionId -TenantId $tenantId -WarningAction SilentlyContinue | Out-Null
            $script:lastContextSubscriptionId = $subscriptionId
        }

        Write-Host "`nProcessing ${vmTypeLabel} VM: $machine in Resource Group: $resourceGroup" -ForegroundColor Green

        # Retrieve discovery results
        if ($IsTestingMode) {
            $resultArr = ,@('d:C:\Logs')
        }
        else {
            if ($null -eq $job) {
                Write-Host "No discovery job for $machine. Skipping." -ForegroundColor Yellow
                continue
            }

            $result = $null
            try {
                $result = Receive-Job -Job $job -ErrorAction Stop
            }
            catch {
                Write-Host "Error receiving discovery result for ${machine}: $_" -ForegroundColor Red
                continue
            }
            finally {
                Remove-Job -Job $job -Force -ErrorAction SilentlyContinue
            }

            if ($null -eq $result -or $null -eq $result.Value -or $result.Value.Count -eq 0) {
                Write-Host "No output returned from discovery on VM ${machine}. Skipping." -ForegroundColor Yellow
                continue
            }
            $resultArr = $result.Value[0].Message -split "`n"
        }

        # Match discovered paths against Splunk wildcard patterns
        $matchedFolders = @()
        $debugMatchDetails = @{}
        foreach ($candidateLineRaw in ($resultArr | Select-Object -Unique)) {
            $candidateLine = $candidateLineRaw.Trim()

            if ([string]::IsNullOrWhiteSpace($candidateLine) -or $candidateLine.Length -lt 3 -or $candidateLine[1] -ne ':') {
                continue
            }

            $candidateType = $candidateLine.Substring(0, 1).ToLowerInvariant()
            $candidatePath = $candidateLine.Substring(2)

            if ($IsLinuxVm -eq $false) {
                if ($candidatePath -notmatch '^[a-zA-Z]:\\') { continue }
            }
            else {
                if ($candidatePath -notlike '/*') { continue }
            }

            foreach ($wildcardPath in $SplunkWildcardPaths) {
                if (-not (Test-SplunkPathMatch -Path $candidatePath -Pattern $wildcardPath -IsLinuxVm $IsLinuxVm)) {
                    continue
                }

                $resolvedFolder = $null
                if ($candidateType -eq 'd') {
                    $matchedFolders += $candidatePath
                    $resolvedFolder = $candidatePath
                }
                elseif ($candidateType -eq 'f') {
                    $parentFolder = Get-ParentFolderPath -Path $candidatePath -IsLinuxVm $IsLinuxVm
                    if ($null -ne $parentFolder) {
                        $matchedFolders += $parentFolder
                        $resolvedFolder = $parentFolder
                    }
                }

                if ($IsDebugLoggingEnabled -and $null -ne $resolvedFolder) {
                    if (-not $debugMatchDetails.ContainsKey($resolvedFolder)) {
                        $debugMatchDetails[$resolvedFolder] = @()
                    }
                    if ($debugMatchDetails[$resolvedFolder] -notcontains $wildcardPath) {
                        $debugMatchDetails[$resolvedFolder] += $wildcardPath
                    }
                }
            }
        }

        $resultArrUnique = @($matchedFolders | Select-Object -Unique)

        if ($IsDebugLoggingEnabled) {
            Write-Host "`n[DEBUG] Folder match summary for server: $machine" -ForegroundColor DarkYellow
            if ($resultArrUnique.Count -eq 0) {
                Write-Host "  (no matching folders found)" -ForegroundColor DarkGray
            }
            else {
                foreach ($debugFolder in $resultArrUnique) {
                    Write-Host "  Folder: $debugFolder" -ForegroundColor DarkCyan
                    if ($debugMatchDetails.ContainsKey($debugFolder)) {
                        foreach ($debugPattern in $debugMatchDetails[$debugFolder]) {
                            Write-Host "    Matched pattern: $debugPattern" -ForegroundColor DarkGray
                        }
                    }
                }
            }
            Write-Host ""
        }

        # Resolve per-VM resources once before iterating folders
        if ($IsArcConnectedMachine -eq $true) {
            $vmResourceId = (Get-AzResource -ResourceGroupName $resourceGroup -ResourceName $machine -ResourceType "Microsoft.HybridCompute/machines").ResourceId
        } else {
            $vmResourceId = (Get-AzResource -ResourceGroupName $resourceGroup -ResourceName $machine -ResourceType "Microsoft.Compute/virtualMachines").ResourceId
        }
        $workspaceResource = @(Get-AzResource -ResourceType "Microsoft.OperationalInsights/workspaces" -Name $workspaceName -ErrorAction Stop) | Select-Object -First 1
        $workspace = Get-AzOperationalInsightsWorkspace -ResourceGroupName $workspaceResource.ResourceGroupName -Name $workspaceName
        $workspaceId = $workspace.CustomerId

        foreach ($folder in $resultArrUnique) {

            if ($IsLinuxVm -eq $false) {
                if ($folder -notmatch "^[a-zA-Z]:\\") { continue }
            }
            else {
                if ($folder -notlike "/*") { continue }
            }

            $dcrFilePattern = Get-FirstDcrFilePattern -Folder $folder -splunkWildcardPaths $splunkWildcardPaths -IsLinuxVm $IsLinuxVm

            if ($null -eq $dcrFilePattern) {
                Write-Host "No matching wildcard pattern found for folder $folder on VM $machine - skipping" -ForegroundColor Yellow
                continue
            }

            Write-Host "Wildcard paths found on ${machine}:" -ForegroundColor Yellow
            Write-Host $folder -ForegroundColor Cyan

            $dcr = Ensure-GroupDcrPatternAndAssociation `
                -FilePattern $dcrFilePattern `
                -VmResourceId $vmResourceId `
                -IsLinuxVm $IsLinuxVm `
                -SubscriptionId $subscriptionId `
                -DcrResourceGroup $dcrResourceGroup `
                -DcrLocation $dcrLocation `
                -DceName $dceName `
                -WorkspaceName $workspaceName `
                -TableName $tableName `
                -DcrCache $groupDcrCache

            if ($dcr) {
                $dce = Get-AzResource -ResourceId $dcr.Properties.dataCollectionEndpointId

                Write-Host "Starting async command to monitor and ingest logs for VM $machine, DCR $($dcr.Name), Log File Path $dcrFilePattern" -ForegroundColor Blue

                RunCommandAsyncToIngestMissingLogs `
                    -SubscriptionId $subscriptionId `
                    -ResourceGroupName $resourceGroup `
                    -VMName $machine `
                    -DcrName $dcr.Name `
                    -LogFilePath $dcrFilePattern `
                    -scriptStorageAccount $scriptStorageAccount `
                    -scriptContainerName $scriptContainerName `
                    -isArcConnectedMachine $IsArcConnectedMachine `
                    -dcrImmutableId $dcr.Properties.immutableId `
                    -dceEndpointId $dce.Properties.logsIngestion.endpoint `
                    -WorkspaceId $workspaceId `
                    -tableName $tableName `
                    -timestampColumn "TimeGenerated" `
                    -timespan "P1D" `
                    -isLinuxVm $IsLinuxVm `
                    -sleepTime $sleepTime `
                    -maxRetries $maxRetries
            }
        }

        if ($IsDebugLoggingEnabled) {
            $serverStopwatch.Stop()
            Write-Host "[DEBUG] Server $machine processed in $($serverStopwatch.Elapsed.ToString('mm\:ss\.ff'))" -ForegroundColor DarkYellow
        }
    }
}

# track last subscription to skip redundant Set-AzContext calls
$script:lastContextSubscriptionId = $null

# read the configuration file
$connectedMachinesAndVmsHash = Get-VMListsFromCSV -CsvPath $config.csvPath

# entry point for Azure Linux VMs
if ($connectedMachinesAndVmsHash["AzureLinuxVMs"].Count -gt 0) {
    main -SplunkWildcardPaths $linuxAzureSplunkWildcardPatterns -VmList $connectedMachinesAndVmsHash["AzureLinuxVMs"] -IsArcConnectedMachine $false -IsLinuxVm $true
}

# Entry point for Arc Linux VMs
if ($connectedMachinesAndVmsHash["ArcLinuxVMs"].Count -gt 0) {
    main -SplunkWildcardPaths $linuxArcSplunkWildcardPatterns -VmList $connectedMachinesAndVmsHash["ArcLinuxVMs"]  -IsArcConnectedMachine $true -IsLinuxVm $true
}

# Entry point for Arc Windows VMs
if ($connectedMachinesAndVmsHash["ArcWindowsVMs"].Count -gt 0) {
    main -SplunkWildcardPaths $windowsArcSplunkWildcardPatterns -VmList $connectedMachinesAndVmsHash["ArcWindowsVMs"] -IsArcConnectedMachine $true -IsLinuxVm $false
}

# Entry point for Azure Windows VMs
if ($connectedMachinesAndVmsHash["AzureWindowsVMs"].Count -gt 0) {
    main -SplunkWildcardPaths $windowsAzureSplunkWildcardPatterns -VmList $connectedMachinesAndVmsHash["AzureWindowsVMs"] -IsArcConnectedMachine $false -IsLinuxVm $false
}

