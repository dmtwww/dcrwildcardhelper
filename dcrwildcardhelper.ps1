# Enable strict mode to enforce variable declaration
Set-StrictMode -Version Latest

# Load configuration from JSON file
$configPath = Join-Path $PSScriptRoot "dcrwildcardhelper.config.json"
if (-not (Test-Path $configPath)) {
    throw "Configuration file not found: $configPath"
}

$config = Get-Content $configPath -Raw | ConvertFrom-Json

# In testing mode speed things up by not calling run-command first time
$IsTestingMode = $config.isTestingMode
$IsDebugLoggingEnabled = $config.isDebugLoggingEnabled

# these are the RegEx equivalents of the original Splunk wildcards
# Splunk wildcards are proprietary as are DCR wildcards
# for example Splunk '/var/.../*.log' becomes '/var/.*/[^/]+.log' in RegEx and '/var/myparentfolder/myfolder*/*.log in DCR (multiple potentially required) 
# for example Splunk '/var/*/*.log' becomes '/var/[^/]+/[^/]+.log' in RegEx and '/var/myfolder*/*.log' in DCR (multiple potentially required)
$linuxAzureSplunkWildcardPatterns = @($config.linuxAzureSplunkWildcardPatterns)

$linuxArcSplunkWildcardPatterns = @($config.linuxArcSplunkWildcardPatterns)

# Define the Windows paths
$windowsArcSplunkWildcardPatterns = @($config.windowsArcSplunkWildcardPatterns)

$windowsAzureSplunkWildcardPatterns = @($config.windowsAzureSplunkWildcardPatterns)

# location for the DCRs
$dcrLocation = $config.dcrLocation
# storage account for scripts and script logs
$scriptStorageAccount = $config.scriptStorageAccount
# container name for scripts and script logs
$scriptContainerName = $config.scriptContainerName

# TODO make this a parameter
$dcrResourceGroup = $config.dcrResourceGroup

$sleepTime = $config.sleepTime
$maxRetries = $config.maxRetries

function Format-ElapsedTime {
    param (
        [System.Diagnostics.Stopwatch]$Stopwatch
    )

    if ($null -eq $Stopwatch) {
        return "00:00:00"
    }

    return $Stopwatch.Elapsed.ToString('hh\:mm\:ss')
}

function Write-PhaseLog {
    param (
        [string]$VMName,
        [string]$Phase,
        [System.Diagnostics.Stopwatch]$Stopwatch,
        [string]$Color = 'Cyan'
    )

    Write-Host "[$(Format-ElapsedTime -Stopwatch $Stopwatch)] [$VMName] $Phase" -ForegroundColor $Color
}

function Set-AzContextForSubscription {
    param (
        [Parameter(Mandatory = $true)]
        [string]$SubscriptionId
    )

    try {
        Set-AzContext -Subscription $SubscriptionId -ErrorAction Stop | Out-Null
        return
    }
    catch {
        $tenantId = $null

        try {
            $tenantId = az account show --subscription $SubscriptionId --query tenantId -o tsv 2>$null
        }
        catch {
            $tenantId = $null
        }

        if ([string]::IsNullOrWhiteSpace($tenantId)) {
            throw
        }

        Set-AzContext -Subscription $SubscriptionId -Tenant $tenantId -ErrorAction Stop | Out-Null
    }
}

# Function to read CSV and populate VM lists
function Get-VMListsFromCSV {
    param (
        [Parameter(Mandatory = $true)]
        [string]$CsvPath
    )

    # Initialize the four arrays
    $arcWindowsVMs = @()
    $arcLinuxVMs = @()
    $azureWindowsVMs = @()
    $azureLinuxVMs = @()

    # Read the CSV file
    $csvData = Import-Csv -Path $CsvPath

    foreach ($row in $csvData) {
        # Create an array for this VM: SubscriptionId, ResourceGroup, VMName, DCEName, WorkspaceName, TableName
        $vmEntry = @(
            $row.SubscriptionId,
            $row.ResourceGroup,
            $row.VMName,
            $row.DCEName,
            $row.WorkspaceName,
            $row.TableName
        )

        # Determine which list to add to based on IsArc and IsLinux columns
        $isArc = [bool]::Parse($row.ArcAzure.Equals("Arc", [System.StringComparison]::OrdinalIgnoreCase))
        $isDeviceWindows = [bool]::Parse($row.WindowsLinux.Equals("Windows", [System.StringComparison]::OrdinalIgnoreCase))

        if ($isArc -and -not $isDeviceWindows) {
            $arcLinuxVMs += ,@($vmEntry)
        }
        elseif ($isArc -and $isDeviceWindows) {
            $arcWindowsVMs += ,@($vmEntry)
        }
        elseif (-not $isArc -and -not $isDeviceWindows) {
            $azureLinuxVMs += ,@($vmEntry)
        }
        else {
            $azureWindowsVMs += ,@($vmEntry)
        }
    }

    # Return a hashtable with all four lists
    return @{
        ArcWindowsVMs = $arcWindowsVMs
        ArcLinuxVMs = $arcLinuxVMs
        AzureWindowsVMs = $azureWindowsVMs
        AzureLinuxVMs = $azureLinuxVMs
    }
}

function Convert-SplunkWildcardToRegex {
    param (
        [Parameter(Mandatory = $true)]
        [string]$Pattern,
        [Parameter(Mandatory = $true)]
        [bool]$IsLinuxVm = $true
    )

    # Replace escaped Splunk wildcards with regex equivalents.
    # Protect the recursive ellipsis token first so the '*' in '.*' is not rewritten below.
    $recursivePlaceholder = '__SPLUNK_ELLIPSIS__'
    $regexPattern = $Pattern -replace '\.\.\.', $recursivePlaceholder

    if ($IsLinuxVm -eq $true) {
        $regexPattern = $regexPattern -replace '\*', '[^/]+'      # '*' → '[^/]+'
    }
    else {
        # double backslashes for Windows
        $regexPattern = $regexPattern -replace '\\', '\\'      # '\' → '\\'
        $regexPattern = $regexPattern -replace '\*', '[^\\]+'      # '*' → '[^/]+'
    }

    $regexPattern = $regexPattern -replace $recursivePlaceholder, '.*'      # '...' → '.*'

    # Return the final regex pattern
    return $regexPattern
}

# Make a name from a wildcard path by stripping out any wildcard characters
# and prepending dcr_ to the name
function Get-DcrNameFromWildcard {
    param (
        [string]$WildcardPathname
    )

    $dcrName = $WildcardPathname -replace '[\*\?\[\]\^\.\:\\/]', '_'
    $dcrName = "dcr_" + $dcrName

    $maxLength = 64
    if ($dcrName.Length -gt $maxLength) {
        $hashBytes = [System.Security.Cryptography.MD5]::HashData([System.Text.Encoding]::UTF8.GetBytes($WildcardPathname))
        $hash = ([System.BitConverter]::ToString($hashBytes)).Replace('-', '').Substring(0, 8).ToLowerInvariant()
        $prefixLength = $maxLength - $hash.Length - 1
        $dcrName = $dcrName.Substring(0, $prefixLength) + "_" + $hash
    }

    return $dcrName
}

# Get the DCR Folder Path for a given VM Resource Id and Folder
function Get-DcrFolderPath {
    param (
        [string]$VmResourceId,
        [string]$Folder,
        [bool]$IsLinuxVm = $true
    )

    $retDcrFolderPath = $null

    # Is there a DCR Association for this VM
    $dcrAssociationArr = @(Get-AzDataCollectionRuleAssociation -ResourceUri $VmResourceId)

    foreach ($dcrAssociation in $dcrAssociationArr) {
        $dcrId = $dcrAssociation.DataCollectionRuleId

        if ($null -eq $dcrId) {
            Write-Host "DCR for Assoc. $($dcrAssociation.Name) does not exist - skipping" -ForegroundColor Yellow
            continue
        }

        if ($IsLinuxVm -eq $true) {
            $folderSeparator = "/"
        }
        else {
            $folderSeparator = "\"  
        }

        $dcr = Get-AzResource -ResourceId $dcrId

        # Get the Data Sources from the DCR  
        if ($dcr.Properties.dataSources.PSObject.Properties.Name.Equals("logFiles") -eq $false) {
            Write-Host "DCR $($dcr.Name) has no Log File Data Sources - skipping" -ForegroundColor Yellow
            continue
        }

        $logFileDataSourceArr = @($dcr.Properties.dataSources.logFiles) 
        
        foreach ($logFileDataSource in $logFileDataSourceArr) {

            foreach ($filePattern in $logFileDataSource.filePatterns) {
                Write-Host "Checking DCR File Pattern: $filePattern for VM $machine" -ForegroundColor Magenta

                # if there are wildcards in the pattern then extract the folder part
                # else the pattern is a folder only
                if ($filePattern -match '[\*\?\[\.]') {
                    $retDcrFolderPath = $filePattern.Substring(0, $filePattern.LastIndexOf($folderSeparator))
                }
                else {
                    $retDcrFolderPath = $filePattern
                }

                if ($retDcrFolderPath -eq $Folder) {
                    Write-Host "Found matching DCR File Pattern" -ForegroundColor Green
                    return $retDcrFolderPath
                }
                else {                       
                    $retDcrFolderPath = $null
                }                      
            }
        }
    }

    return $retDcrFolderPath
}

# this function will ensure the DCR, Data Sourc, File Pattern and DCR Association exist
# it is possible that some of these objects exist already, so lots of checks to see what is missing and create only that part
function New-DcrDataSourceAndAssociation {
    param (
        [Parameter(Mandatory = $false)]
        [AllowNull()]
        [object]$dcrName,
        [Parameter(Mandatory = $true)]
        [string]$DcrFilePattern,
        [Parameter(Mandatory = $true)]
        [string]$vmResourceId,
        [Parameter(Mandatory = $true)]
        [bool]$IsLinuxVm,
        [Parameter(Mandatory = $true)]
        [string]$subscriptionId,
        [Parameter(Mandatory = $true)]
        [string]$dcrResourceGroup,
        [Parameter(Mandatory = $true)]
        [string]$dcrLocation,
        [Parameter(Mandatory = $true)]
        [string]$dceName,
        [Parameter(Mandatory = $true)]
        [string]$workspaceName,
        [Parameter(Mandatory = $true)]
        [string]$tableName
        )

    $retDcrResource = $null
    $dcrCreated = $false
    $associationCreated = $false
    
    $dcrResource = Get-AzResource -ResourceGroupName $dcrResourceGroup `
                    -ResourceType "microsoft.insights/datacollectionrules" `
                    -Name $dcrName `
                    -ErrorAction SilentlyContinue

    if ($null -eq $dcrResource) {
        Write-Host "DCR $dcrName does not exist - creating it" -ForegroundColor Yellow
        # create the DCR if it does not exist
        $dcr = New-DcrFromWildcard `
            -dcrName $dcrName `
            -dcrResourceGroupName $dcrResourceGroup `
            -dcrSubscriptionId $subscriptionId `
            -dcrLocation $dcrLocation `
            -dceName $dceName `
            -customLogPath $dcrFilePattern `
            -tableName $tableName `
            -workspaceName $workspaceName `
            -isLinuxVm $IsLinuxVm

        if ($null -eq $dcr -or $dcr.PSObject.Properties.Match('Id').Count -eq 0 -or [string]::IsNullOrWhiteSpace($dcr.Id)) {
            throw "Failed to create DCR '$dcrName' for file pattern '$DcrFilePattern'."
        }

        $retDcrResource = Get-AzResource -ResourceId $dcr.Id
        $dcrCreated = $true
    }
    else {
        # create the new Data Source
        $incomingStream = "Custom-Stream"                 # incoming stream name
        $dataSourceName = $DcrFilePattern + "-logfile"   # friendly name for this data source

        # Cannot have more than one Data Source object of a given type (eg Log File)
        # So in this case need to add an extra File Pattern to an exisiting data source object
        if ($null -ne $dcrResource.Properties.dataSources.logFiles) {
            # the Log Files data source already exists - recreate the object appending the new file pattern
            $exisitingDataSourceLogFiles = $dcrResource.Properties.dataSources.logFiles[0]

            if ($exisitingDataSourceLogFiles.filePatterns -contains $DcrFilePattern) {
                Write-Host "DCR Data Source already contains File Pattern $DcrFilePattern - no update needed" -ForegroundColor Green
            }
            else {
                $newFilePatterns = $exisitingDataSourceLogFiles.filePatterns + @($DcrFilePattern)

                $dcrDataSource = New-AzLogFilesDataSourceObject `
                    -Name $exisitingDataSourceLogFiles.name  `
                    -FilePattern $newFilePatterns `
                    -Stream $exisitingDataSourceLogFiles.streams[0]    
                    
                # attach this to the exisiting DCR
                $null = Update-AzDataCollectionRule `
                    -Name $dcrResource.Name `
                    -ResourceGroupName $dcrResource.ResourceGroupName `
                    -SubscriptionId $dcrResource.SubscriptionId `
                    -DataSourceLogFile  $dcrDataSource 

            }
        }
        else {
            $dcrDataSource = New-AzLogFilesDataSourceObject `
                -Name $dataSourceName  `
                -FilePattern $DcrFilePattern `
                -Stream $incomingStream

            # attach this to the exisiting DCR
            $null = Update-AzDataCollectionRule `
                -Name $dcrResource.Name `
                -ResourceGroupName $dcrResource.ResourceGroupName `
                -SubscriptionId $dcrResource.SubscriptionId `
                -DataSourceLogFile  $dcrDataSource 
        }
            
        $retDcrResource = $dcrResource
    }

    # create the DCR Association
    $null = New-AzDataCollectionRuleAssociation `
        -AssociationName $retDcrResource.properties.dataSources.logFiles[0].name `
        -ResourceUri $vmResourceId `
        -DataCollectionRuleId $retDcrResource.ResourceId
    $associationCreated = $true

    return [PSCustomObject]@{
        DcrResource = $retDcrResource
        DcrCreated = $dcrCreated
        AssociationCreated = $associationCreated
        AssociationName = $retDcrResource.properties.dataSources.logFiles[0].name
    }
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
    
    if ($isLinuxVm -eq $true) {
        $kind = "Linux"
    }
    else {
        $kind = "Windows"
    }

    # Lookup Workspace Resource Id based on its Id
    $workspaceResourceId = "/subscriptions/$dcrSubscriptionId/resourcegroups/$dcrResourceGroupName/providers/microsoft.operationalinsights/workspaces/$workspaceName"

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
    try {
        $retDcr = New-AzDataCollectionRule `
            -Name "$dcrName" `
            -ResourceGroupName "$dcrResourceGroupName" `
            -JsonString $payload `
            -ErrorAction Stop
    }
    catch {
        Write-Host "New-AzDataCollectionRule failed for $dcrName, retrying via ARM REST API" -ForegroundColor Yellow

        $resourcePath = "/subscriptions/$dcrSubscriptionId/resourceGroups/$dcrResourceGroupName/providers/Microsoft.Insights/dataCollectionRules/$dcrName?api-version=2023-03-11"
        $restResponse = Invoke-AzRestMethod `
            -Method PUT `
            -Path $resourcePath `
            -Payload $payload `
            -ErrorAction Stop

        $restResource = $restResponse.Content | ConvertFrom-Json
        $retDcr = [PSCustomObject]@{
            Id = $restResource.id
        }
    }

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

    # Build an "anchor": everything before the first segment that contains a wildcard (* ? [)
    if ($IsLinuxVm -eq $true) {
        # Convert Windows path to use '/' for easier processing
        $segments = $SplunkWildcardPathname -split '/'
    }
    else {
        # Ensure Windows path uses '\' (it should already)
       $segments = $SplunkWildcardPathname -split '\\'
    }
    
    $anchorSegments = @()
    $sawWildcard = $false
    foreach ($seg in $segments) {
        if ($seg -match '[\*\?\[\.]') { $sawWildcard = $true; break }
        if ($seg -ne '') { $anchorSegments += $seg }
    }

    if ($IsLinuxVm) {
        # If the pattern starts with '/', keep it in the anchor for correct matching
        $leadingSlash = $SplunkWildcardPathname.StartsWith('/')

        $anchor = ($anchorSegments -join '/')
        if ($leadingSlash) { $anchor = "/$anchor" }
    }
    else {
        $anchor = ($anchorSegments -join '\')
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
        # eg '/var/.../*.log' becomes '/var/.*/[^/]+.log'
        $regexPattern = Convert-SplunkWildcardToRegex -Pattern $item -IsLinuxVm $IsLinuxVm

        # eg '/*.log'
        if ($IsLinuxVm -eq $true) {
            $splunkPatternFileName = $item.Substring($item.LastIndexOf('/'))
        }
        else {
            $splunkPatternFileName = $item.Substring($item.LastIndexOf('\'))
        }

        # eg '/var/log' + '/*.log'
        $dcrFilePattern = $Folder + $splunkPatternFileName
        
        # eg '/var/log/*.log' matches '/var/[^/]+/[^/]+.log'
        if ($dcrFilePattern -match $regexPattern) {
            return [PSCustomObject]@{
                SplunkWildcardPath = $item
                DcrFilePattern = $dcrFilePattern
            }
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
RESPONSE=`$(curl -s -H "Metadata: true" "`$ENDPOINT")
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

    if ($isLinuxVm -eq $true) {
        return Get-IngestScriptLinux `
            -isArcConnectedMachine $isArcConnectedMachine `
            -scriptStorageAccount $scriptStorageAccount `
            -LogFilePath $LogFilePath `
            -tableName $tableName `
            -dcrImmutableId $dcrImmutableId `
            -dceEndpointId $dceEndpointId `
            -timestampColumn $timestampColumn `
            -timespan $timespan `
            -scriptContainerName $scriptContainerName `
            -workspaceId $workspaceId `
            -VMName $VMName `
            -sleepTime $sleepTime `
            -maxRetries $maxRetries
    }
    else {
        return Get-IngestScriptWindows `
            -isArcConnectedMachine $isArcConnectedMachine `
            -scriptStorageAccount $scriptStorageAccount `
            -LogFilePath $LogFilePath `
            -tableName $tableName `
            -dcrImmutableId $dcrImmutableId `
            -dceEndpointId $dceEndpointId `
            -timestampColumn $timestampColumn `
            -timespan $timespan `
            -scriptContainerName $scriptContainerName `
            -workspaceId $workspaceId `
            -VMName $VMName `
            -sleepTime $sleepTime `
            -maxRetries $maxRetries
    }
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

    # Create a key combining all three boolean states
    $caseKey = "$IsArcConnectedMachine-$IsLinuxVm-$IsAsync"

    switch ($caseKey) {
        # Arc + Linux + Async
        "True-True-True" {
            $result = New-AzConnectedMachineRunCommand `
                -ResourceGroupName $ResourceGroupName `
                -MachineName $VMName `
                -Location $dcrLocation `
                -RunCommandName "ArcRunCmd-$(Get-Date -Format 'yyyyMMddHHmmss')" `
                -SourceScript $ScriptString `
                -AsJob
        }
        # Arc + Linux + Sync
        "True-True-False" {
                $result = New-AzConnectedMachineRunCommand `
                -ResourceGroupName $ResourceGroupName `
                -MachineName $VMName `
                    -Location $dcrLocation `
                    -RunCommandName "ArcRunCmd-$(Get-Date -Format 'yyyyMMddHHmmss')" `
                    -SourceScript $ScriptString
        }
        # Arc + Windows + Async
        "True-False-True" {
            $result = New-AzConnectedMachineRunCommand `
                -ResourceGroupName $ResourceGroupName `
                -MachineName $VMName `
                -Location $dcrLocation `
                -RunCommandName "ArcRunCmd-$(Get-Date -Format 'yyyyMMddHHmmss')" `
                -SourceScript $ScriptString `
                -AsJob
        }
        # Arc + Windows + Sync
        "True-False-False" {
                $result = New-AzConnectedMachineRunCommand `
                -ResourceGroupName $ResourceGroupName `
                -MachineName $VMName `
                    -Location $dcrLocation `
                    -RunCommandName "ArcRunCmd-$(Get-Date -Format 'yyyyMMddHHmmss')" `
                    -SourceScript $ScriptString
        }
        # Azure VM + Linux + Async
        "False-True-True" {
            $result = Invoke-AzVMRunCommand `
                -ResourceGroupName $ResourceGroupName `
                -VMName $VMName `
                -CommandId 'RunShellScript' `
                -ScriptString $ScriptString `
                -AsJob
        }
        # Azure VM + Linux + Sync
        "False-True-False" {
            $result = Invoke-AzVMRunCommand `
                -ResourceGroupName $ResourceGroupName `
                -VMName $VMName `
                -CommandId 'RunShellScript' `
                -ScriptString $ScriptString
        }
        # Azure VM + Windows + Async
        "False-False-True" {
            $result = Invoke-AzVMRunCommand `
                -ResourceGroupName $ResourceGroupName `
                -VMName $VMName `
                -CommandId 'RunPowerShellScript' `
                -ScriptString $ScriptString `
                -AsJob
        }
        # Azure VM + Windows + Sync
        "False-False-False" {
            $result = Invoke-AzVMRunCommand `
                -ResourceGroupName $ResourceGroupName `
                -VMName $VMName `
                -CommandId 'RunPowerShellScript' `
                -ScriptString $ScriptString
        }
    }

    return $result
}

function Invoke-DiscoveryRunCommandWithProgress {
    param (
        [string]$ResourceGroupName,
        [string]$VMName,
        [string]$ScriptString,
        [bool]$IsArcConnectedMachine,
        [bool]$IsLinuxVm,
        [System.Diagnostics.Stopwatch]$Stopwatch,
        [string]$RunCommandName = ""
    )

    if (-not $IsArcConnectedMachine) {
        return RunCommand `
            -ResourceGroupName $ResourceGroupName `
            -VMName $VMName `
            -ScriptString $ScriptString `
            -IsArcConnectedMachine $IsArcConnectedMachine `
            -IsLinuxVm $IsLinuxVm
    }

    $runCmdName = if ([string]::IsNullOrWhiteSpace($RunCommandName)) { "discover-$(Get-Date -Format 'yyyyMMddHHmmss')" } else { $RunCommandName }
    $job = New-AzConnectedMachineRunCommand `
        -ResourceGroupName $ResourceGroupName `
        -MachineName $VMName `
        -Location $dcrLocation `
        -RunCommandName $runCmdName `
        -SourceScript $ScriptString `
        -AsJob

    while ($job.State -eq 'Running' -or $job.State -eq 'NotStarted') {
        $statusParts = @("JobState=$($job.State)")
        try {
            $rcStatus = Get-AzConnectedMachineRunCommand `
                -ResourceGroupName $ResourceGroupName `
                -MachineName $VMName `
                -RunCommandName $runCmdName `
                -ErrorAction SilentlyContinue
            if ($rcStatus) {
                $statusParts += "ProvisioningState=$($rcStatus.ProvisioningState)"
            }
        }
        catch {
        }

        Write-PhaseLog -VMName $VMName -Phase ("discovery waiting: " + ($statusParts -join ', ')) -Stopwatch $Stopwatch -Color DarkGray
        Start-Sleep -Seconds 15
        $job = Get-Job -Id $job.Id
    }

    if ($job.State -ne 'Completed') {
        $jobErrors = Receive-Job -Job $job -Keep -ErrorAction SilentlyContinue 2>&1
        Remove-Job -Job $job -Force -ErrorAction SilentlyContinue
        throw "Arc discovery job failed for ${VMName} with state $($job.State). $($jobErrors | Out-String)"
    }

    $null = Receive-Job -Job $job -Keep -ErrorAction SilentlyContinue
    Remove-Job -Job $job -Force -ErrorAction SilentlyContinue
    $result = Get-AzConnectedMachineRunCommand `
        -ResourceGroupName $ResourceGroupName `
        -MachineName $VMName `
        -RunCommandName $runCmdName `
        -ErrorAction Stop
    return $result
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


    foreach ($vm in $VmList) {
        $subscriptionId = $vm[0]
        $resourceGroup = $vm[1]
        $machine = $vm[2]
        $dceName = $vm[3]
        $workspaceName = $vm[4]
        $tableName = $vm[5]
        $serverStopwatch = [System.Diagnostics.Stopwatch]::StartNew()

        try {
            Set-AzContextForSubscription -SubscriptionId $subscriptionId

            $vmTypeLabel = "$(if ($IsArcConnectedMachine) { 'Arc' } else { 'Azure' }) $(if ($IsLinuxVm) { 'Linux' } else { 'Windows' })"

            Write-Host "Processing $vmTypeLabel VM: $machine in Resource Group: $resourceGroup under Subscription: $subscriptionId" -ForegroundColor Green

            $cmdTemplateLinux = 'find $anchor -wholename "$path" $pipeline'
            $cmdTemplateWindows = 'Get-ChildItem -Path $anchor -Recurse -Force | Where-Object { $_.FullName -like "$path" } | Select-Object -ExpandProperty FullName'

            if ($IsLinuxVm -eq $false) {
                $cmdTemplate = $cmdTemplateWindows
            }
            else {
                $cmdTemplate = $cmdTemplateLinux
            }

            # make big command as run-command is expensive, so do once per server
            $cmds = ""
            foreach ($wildcardPath in $SplunkWildcardPaths) {
                $anchor = Get-AnchorFromWildcard -SplunkWildcardPathname $wildcardPath -IsLinuxVm $IsLinuxVm
                $regexPattern = if ($IsLinuxVm) { Convert-SplunkWildcardToRegex -Pattern $wildcardPath -IsLinuxVm $IsLinuxVm } else { $null }
                # if path contains a wildcard then use dirname to return the folder name only
                # else we already have the folder name eg /etc
                if ($wildcardPath -match '[\*\?\[\.]') {
                    $pipeline = "| xargs -I {} dirname {} | sort -u"
                }
                else {
                    $pipeline = "| sort -u"
                }
                if ($IsLinuxVm -and $wildcardPath -match '\.\.\.') {
                    $cmd = "find $anchor -regextype posix-extended -regex `"$regexPattern`" $pipeline"
                }
                else {
                    $cmd = $cmdTemplate `
                        -replace '\$anchor', $anchor `
                        -replace '\$path', $wildcardPath `
                        -replace '\$pipeline', $pipeline
                }
                $cmds += $cmd + "; "
            }

            # create a runCommand function and pass in OS and IsOnPrem parameters
            # TODO error handling if the VM is not reachable
            $result = $null
            $discoveryRunCommandName = if ($IsArcConnectedMachine) { "discover-$(Get-Date -Format 'yyyyMMddHHmmss')" } else { $null }
            $discoverySubmittedPhase = if ($IsArcConnectedMachine) { "discovery submitted: $discoveryRunCommandName" } else { 'discovery submitted' }
            Write-PhaseLog -VMName $machine -Phase $discoverySubmittedPhase -Stopwatch $serverStopwatch -Color DarkCyan

            if ($IsTestingMode) {
                # Azure Linux test case
                #$resultArr = ,@('/var/log')
                # Arc Linux Test Case
                #$resultArr = ,@('/var/log/azure/run-command-handler')
                # Arc Windows Text case
                $resultArr = ,@('C:\Logs')
                $sleepTime = 10
                $maxRetries = 3
            }
            else {
                $result = Invoke-DiscoveryRunCommandWithProgress `
                    -ResourceGroupName $resourceGroup `
                    -VMName $machine `
                    -ScriptString $cmds `
                    -IsArcConnectedMachine $IsArcConnectedMachine `
                    -IsLinuxVm $IsLinuxVm `
                    -Stopwatch $serverStopwatch `
                    -RunCommandName $discoveryRunCommandName
            }


        # convert the multiline string returned to an array
        # New-AzConnectedMachineRunCommand returns InstanceViewOutput; Invoke-AzVMRunCommand returns Value[0].Message
        if ($IsTestingMode -eq $false) {
            if ($result.PSObject.Properties.Match('InstanceViewOutput').Count -gt 0 -and $null -ne $result.InstanceViewOutput) {
                $resultArr = $result.InstanceViewOutput -split "`n"
            }
            elseif ($result.PSObject.Properties.Match('Value').Count -gt 0 -and $null -ne $result.Value -and $result.Value.Count -gt 0) {
                $resultArr = $result.Value[0].Message -split "`n"
            }
            else {
                Write-Host "No output returned from Run Command on VM ${machine} - skipping" -ForegroundColor Yellow
                continue
            }
        }

            Write-PhaseLog -VMName $machine -Phase 'discovery completed' -Stopwatch $serverStopwatch -Color Green

        # keep the unique entries in the array
        $resultArrUnique = $resultArr | Select-Object -Unique

        foreach ($folder in $resultArrUnique) {

            if ($IsLinuxVm -eq $false) {
                # filter out any non-windows folder paths
                if ($folder -notmatch "^[a-zA-Z]:\\") { continue }
            }
            else {
                # filter out any non-linux folder paths
                if ($folder -notlike "/*") { continue }
            }

            # lookup the first wildcard pattern and type associated with this folder
            $patternMatch = Get-FirstDcrFilePattern -Folder $folder -splunkWildcardPaths $splunkWildcardPaths -IsLinuxVm $IsLinuxVm
            $dcrFilePattern = if ($null -ne $patternMatch) { $patternMatch.DcrFilePattern } else { $null }

            # if no matches log the error and continue
            if ($null -eq $dcrFilePattern) {
                Write-Host "No matching wildcard pattern found for folder $folder on VM $machine - skipping" -ForegroundColor Yellow
                continue
            }

            Write-Host "Wildcard paths found on ${machine}:" -ForegroundColor Yellow
            Write-Host $folder -ForegroundColor Cyan
            Write-Host "Matched pattern: $($patternMatch.SplunkWildcardPath) -> $dcrFilePattern" -ForegroundColor DarkCyan

            # Get the VM Resource Id
            if ($IsArcConnectedMachine -eq $true) {
                $vmResourceId = (Get-AzResource -ResourceGroupName $resourceGroup -ResourceName $machine -ResourceType "Microsoft.HybridCompute/machines").ResourceId
            }
            else {  
                $vmResourceId = (Get-AzResource -ResourceGroupName $resourceGroup -ResourceName $machine -ResourceType "Microsoft.Compute/virtualMachines").ResourceId
            }

            $dcrFolderPath = Get-DcrFolderPath -VmResourceId $vmResourceId -Folder $folder -IsLinuxVm $IsLinuxVm

            if ($null -eq $dcrFolderPath) {
                # lookup the Dcr Id based on the Resource Group and Name
                $dcrName  = $(Get-DcrNameFromWildcard $dcrFilePattern)

                $dcrResult = New-DcrDataSourceAndAssociation `
                    -DcrName $dcrName `
                    -DcrFilePattern $dcrFilePattern `
                    -vmResourceId $vmResourceId `
                    -IsLinuxVm $IsLinuxVm `
                    -subscriptionId $subscriptionId `
                    -dcrResourceGroup $dcrResourceGroup `
                    -dcrLocation $dcrLocation `
                    -dceName $dceName `
                    -workspaceName $workspaceName `
                    -tableName $tableName

                if ($dcrResult -and $dcrResult.DcrResource) {
                    $dcr = $dcrResult.DcrResource
                    if ($dcrResult.DcrCreated) {
                        Write-PhaseLog -VMName $machine -Phase "DCR created: $dcrName" -Stopwatch $serverStopwatch -Color Green
                    }
                    else {
                        Write-PhaseLog -VMName $machine -Phase "DCR reused: $dcrName" -Stopwatch $serverStopwatch -Color DarkGreen
                    }
                    if ($dcrResult.AssociationCreated) {
                        Write-PhaseLog -VMName $machine -Phase "association created: $($dcrResult.AssociationName)" -Stopwatch $serverStopwatch -Color Green
                    }

                    # lookup the workspace immutable id based on the name and resourcegroup
                    $workspace = Get-AzOperationalInsightsWorkspace -ResourceGroupName $dcrResourceGroup -Name $workspaceName
                    $workspaceId = $workspace.CustomerId

                    # lookup the DCE endpoint
                    $dce = Get-AzResource -ResourceId $dcr.Properties.dataCollectionEndpointId

                    # output the command we are about to run into the log
                    Write-Host "Starting async command to monitor and ingest logs for VM $machine, DCR $dcrName, Log File Path $dcrFilePattern" -ForegroundColor Blue

                    # at this point we have the DCR, Data Source, Folder Path and Association created
                    # the detection of the new log file and the creation of the DCR plus time to first ingestion
                    # will take some time
                    # start an async run-command to monitor the target table and ingest any missing log file entries
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

                    Write-PhaseLog -VMName $machine -Phase "helper started: $dcrFilePattern" -Stopwatch $serverStopwatch -Color Blue
                }
            }
        }
        }
        catch {
            Write-Host "Error processing VM ${machine}: $_" -ForegroundColor Red
            continue
        }
        finally {
            $serverStopwatch.Stop()
            Write-Host "[$(Format-ElapsedTime -Stopwatch $serverStopwatch)] [$machine] Total controller time spent on server" -ForegroundColor Magenta
        }
    }
}

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

