# Enable strict mode to enforce variable declaration
Set-StrictMode -Version Latest

# In testing mode speed things up by not calling run-command first time
$IsTestingMode = $false

# When enabled, emit a debug summary of discovered folders per server and the patterns they matched
$IsDebugLoggingEnabled = $true

# Define the Linux paths
#$linuxPaths = @(
#    "/home/*/.bash_history",
#    "/etc",
#    "/var/log/waagent*.log"
#)

# these are the RegEx equivalents of the original Splunk wildcards
# Splunk wildcards are proprietary as are DCR wildcards
# for example Splunk '/var/.../*.log' becomes '/var/.*/[^/]+.log' in RegEx and '/var/myparentfolder/myfolder*/*.log in DCR (multiple potentially required) 
# for example Splunk '/var/*/*.log' becomes '/var/[^/]+/[^/]+.log' in RegEx and '/var/myfolder*/*.log' in DCR (multiple potentially required)
$linuxAzureSplunkWildcardPatterns = @(
    "/var/log/waagent*.log",
    "/tmp/log/.../*.log"
)

$linuxArcSplunkWildcardPatterns = @(
    "/var/log/azure/run-command-handler/handler*.log"
)

# Define the Windows paths
$windowsArcSplunkWildcardPatterns = @(
    "C:\Logs\Sample*.log"
)

$windowsAzureSplunkWildcardPatterns = $windowsArcSplunkWildcardPatterns;

# location for the DCRs
$dcrLocation = "westeurope"
# storage account for scripts and script logs
$scriptStorageAccount = "arcserversukssa"
# container name for scripts and script logs
$scriptContainerName = "scripts"

# TODO make this a parameter
$dcrResourceGroup = "arc-servers-uks"

$sleepTime = 60       # seconds to wait between retries
$maxRetries = 30      # max number of retries

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

function Convert-SplunkSegmentToRegex {
    param (
        [string]$Segment,
        [bool]$RegexMetaActive,
        [bool]$IsLinuxVm
    )

    $segmentWildcard = if ($IsLinuxVm) { '[^/]*' } else { '[^\\]*' }
    $singleCharWildcard = if ($IsLinuxVm) { '[^/]' } else { '[^\\]' }
    $regexBuilder = New-Object System.Text.StringBuilder
    $index = 0

    while ($index -lt $Segment.Length) {
        $char = $Segment[$index]

        if ($char -eq '[' -and $RegexMetaActive) {
            $classEnd = $Segment.IndexOf(']', $index + 1)
            if ($classEnd -gt $index) {
                [void]$regexBuilder.Append($Segment.Substring($index, $classEnd - $index + 1))
                $index = $classEnd + 1
                continue
            }
        }

        switch ($char) {
            '*' {
                [void]$regexBuilder.Append($segmentWildcard)
            }
            '?' {
                [void]$regexBuilder.Append($singleCharWildcard)
            }
            '.' {
                [void]$regexBuilder.Append('\.')
            }
            '(' {
                [void]$regexBuilder.Append($(if ($RegexMetaActive) { '(' } else { '\(' }))
            }
            ')' {
                [void]$regexBuilder.Append($(if ($RegexMetaActive) { ')' } else { '\)' }))
            }
            '|' {
                [void]$regexBuilder.Append($(if ($RegexMetaActive) { '|' } else { '\|' }))
            }
            '[' {
                [void]$regexBuilder.Append('\[')
            }
            ']' {
                [void]$regexBuilder.Append('\]')
            }
            '^' {
                [void]$regexBuilder.Append($(if ($RegexMetaActive) { '^' } else { '\^' }))
            }
            '$' {
                [void]$regexBuilder.Append($(if ($RegexMetaActive) { '$' } else { '\$' }))
            }
            '+' {
                [void]$regexBuilder.Append($(if ($RegexMetaActive) { '+' } else { '\+' }))
            }
            '{' {
                [void]$regexBuilder.Append($(if ($RegexMetaActive) { '{' } else { '\{' }))
            }
            '}' {
                [void]$regexBuilder.Append($(if ($RegexMetaActive) { '}' } else { '\}' }))
            }
            '\' {
                [void]$regexBuilder.Append('\\')
            }
            default {
                [void]$regexBuilder.Append([regex]::Escape([string]$char))
            }
        }

        $index++
    }

    return $regexBuilder.ToString()
}

function Convert-SplunkWildcardToRegex {
    param (
        [Parameter(Mandatory = $true)]
        [string]$Pattern,
        [bool]$IsLinuxVm
    )

    $separator = Get-SplunkPathSeparator -IsLinuxVm $IsLinuxVm
    $separatorRegex = [regex]::Escape($separator)
    $segmentOneOrMore = if ($IsLinuxVm) { '[^/]+' } else { '[^\\]+' }
    $segments = Get-SplunkPathSegments -Path $Pattern -IsLinuxVm $IsLinuxVm
    $regexBuilder = New-Object System.Text.StringBuilder
    $wildcardSeen = $false
    $hasLeadingSeparator = $IsLinuxVm -and $Pattern.StartsWith($separator)
    $emittedSegment = $false

    [void]$regexBuilder.Append('^')
    if ($hasLeadingSeparator) {
        [void]$regexBuilder.Append($separatorRegex)
    }

    foreach ($segment in $segments) {
        if ([string]::IsNullOrEmpty($segment)) {
            continue
        }

        if ($segment -eq '...') {
            if ($emittedSegment -or $hasLeadingSeparator) {
                [void]$regexBuilder.Append("(?:$separatorRegex$segmentOneOrMore)+")
            }
            else {
                [void]$regexBuilder.Append("(?:$segmentOneOrMore$separatorRegex)+")
            }

            $wildcardSeen = $true
            $emittedSegment = $true
            continue
        }

        if ($emittedSegment) {
            [void]$regexBuilder.Append($separatorRegex)
        }

        $segmentHasWildcard = Test-SplunkSegmentHasWildcard -Segment $segment
        $segmentRegex = Convert-SplunkSegmentToRegex -Segment $segment -RegexMetaActive ($wildcardSeen -or $segmentHasWildcard) -IsLinuxVm $IsLinuxVm
        [void]$regexBuilder.Append($segmentRegex)

        if ($segmentHasWildcard) {
            $wildcardSeen = $true
        }

        $emittedSegment = $true
    }

    [void]$regexBuilder.Append('$')
    return $regexBuilder.ToString()
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

# Make a name from a wildcard path by stripping out any wildcard characters
# and prepending dcr_ to the name
function Get-DcrNameFromWildcard {
    param (
        [string]$WildcardPathname
    )

    $dcrName = $WildcardPathname -replace '[\*\?\[\]\^\.\:\\/]', '_'
    $dcrName = "dcr_" + $dcrName

    return $dcrName
}

# Get the DCR Folder Path for a given VM Resource Id and Folder
function Get-DcrFolderPath {
    param (
        [string]$VmResourceId,
        [string]$Folder,
        [bool]$IsLinuxVm
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

        $retDcrResource = Get-AzResource -ResourceId $dcr.Id
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

    return $retDcrResource
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

    if ($IsLinuxVm) {
        # If the pattern starts with '/', keep it in the anchor for correct matching
        $leadingSlash = $SplunkWildcardPathname.StartsWith($separator)

        $anchor = ($anchorSegments -join $separator)
        if ($leadingSlash) { $anchor = "$separator$anchor" }
    }
    else {
        $anchor = ($anchorSegments -join $separator)
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

    $retryMax = 10
    $retryDelay = 60  # seconds

    for ($attempt = 1; $attempt -le $retryMax; $attempt++) {
        try {
            $result = $null
            # Create a key combining all three boolean states
            $caseKey = "$IsArcConnectedMachine-$IsLinuxVm-$IsAsync"

            switch ($caseKey) {
        # Arc + Linux + Async
        "True-True-True" {
            $result = New-AzConnectedMachineRunCommand `
                -ResourceGroupName $ResourceGroupName `
                -MachineName $VMName `
                -Location $dcrLocation `
                -RunCommandName "ArcRunCmd" `
                -SourceScript $ScriptString `
                -AsJob
        }
        # Arc + Linux + Sync
        "True-True-False" {
            $result = Invoke-AzConnectedMachineRunCommand `
                -ResourceGroupName $ResourceGroupName `
                -MachineName $VMName `
                -CommandId 'RunShellScript' `
                -ScriptString $ScriptString `
                -ErrorAction Stop
        }
        # Arc + Windows + Async
        "True-False-True" {
            $result = New-AzConnectedMachineRunCommand `
                -ResourceGroupName $ResourceGroupName `
                -MachineName $VMName `
                -Location $dcrLocation `
                -RunCommandName "ArcRunCmd" `
                -SourceScript $ScriptString `
                -AsJob
        }
        # Arc + Windows + Sync
        "True-False-False" {
            $result = Invoke-AzConnectedMachineRunCommand `
                -ResourceGroupName $ResourceGroupName `
                -MachineName $VMName `
                -CommandId 'RunPowerShellScript' `
                -ScriptString $ScriptString `
                -ErrorAction Stop
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
                -ScriptString $ScriptString `
                -ErrorAction Stop
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
                -ScriptString $ScriptString `
                -ErrorAction Stop
        }
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


    foreach ($vm in $VmList) {
        $serverStopwatch = [System.Diagnostics.Stopwatch]::StartNew()
        $subscriptionId = $vm[0]
        $resourceGroup = $vm[1]
        $machine = $vm[2]
        $dceName = $vm[3]
        $workspaceName = $vm[4]
        $tableName = $vm[5]

        $tenantId = (Get-AzSubscription -SubscriptionId $subscriptionId -WarningAction SilentlyContinue).TenantId
        Set-AzContext -Subscription $subscriptionId -TenantId $tenantId -WarningAction SilentlyContinue | Out-Null

        $vmTypeLabel = "$(if ($IsArcConnectedMachine) { 'Arc' } else { 'Azure' }) $(if ($IsLinuxVm) { 'Linux' } else { 'Windows' })"
        Write-Host "Processing ${vmTypeLabel} VM: $machine in Resource Group: $resourceGroup under Subscription: $subscriptionId" -ForegroundColor Green

        # make big command as run-command is expensive, so do once per server
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

        # create a runCommand function and pass in OS and IsOnPrem parameters
        # TODO error handling if the VM is not reachable
        $result = $null
        try {
            if ($IsTestingMode) {
                # Azure Linux test case
                #$resultArr = ,@('d:/var/log')
                # Arc Linux Test Case
                #$resultArr = ,@('d:/var/log/azure/run-command-handler')
                # Arc Windows Text case
                $resultArr = ,@('d:C:\Logs')
                $sleepTime = 10
                $maxRetries = 3
            }
            else {
                $result = RunCommand `
                    -ResourceGroupName $resourceGroup `
                    -VMName $machine `
                    -ScriptString $cmds `
                    -IsArcConnectedMachine $IsArcConnectedMachine `
                    -IsLinuxVm $IsLinuxVm
            }
    
        }
        catch {
            Write-Host "Error executing Run Command on VM ${machine}: $_" -ForegroundColor Red
            continue
        }


        # convert the multiline string returned to an array
        # Value[0] is StdOut on Windows. 
        # On Linux I believe its all combined so just ignore results that do not start with a /
        if ($IsTestingMode -eq $false) {
            if ($null -eq $result -or $null -eq $result.Value -or $result.Value.Count -eq 0) {
                Write-Host "No output returned from Run Command on VM ${machine}. Skipping." -ForegroundColor Yellow
                continue
            }
            $resultArr = $result.Value[0].Message -split "`n"
        }

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

        # keep the unique entries in the array
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
            $dcrFilePattern = Get-FirstDcrFilePattern -Folder $folder -splunkWildcardPaths $splunkWildcardPaths -IsLinuxVm $IsLinuxVm

            # if no matches log the error and continue
            if ($null -eq $dcrFilePattern) {
                Write-Host "No matching wildcard pattern found for folder $folder on VM $machine - skipping" -ForegroundColor Yellow
                continue
            }

            Write-Host "Wildcard paths found on ${machine}:" -ForegroundColor Yellow
            Write-Host $folder -ForegroundColor Cyan

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

                $dcr = New-DcrDataSourceAndAssociation `
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

                if ($dcr) {
                    # lookup the workspace immutable id - resolve the actual workspace resource group
                    $workspaceResource = @(Get-AzResource -ResourceType "Microsoft.OperationalInsights/workspaces" -Name $workspaceName -ErrorAction Stop) | Select-Object -First 1
                    $workspace = Get-AzOperationalInsightsWorkspace -ResourceGroupName $workspaceResource.ResourceGroupName -Name $workspaceName
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
                    -maxRetries $maxRetries `
                }
            }
        }

        if ($IsDebugLoggingEnabled) {
            $serverStopwatch.Stop()
            Write-Host "[DEBUG] Server $machine processed in $($serverStopwatch.Elapsed.ToString('mm\:ss\.ff'))" -ForegroundColor DarkYellow
        }
    }
}

# read the configuration file
$connectedMachinesAndVmsHash = Get-VMListsFromCSV -CsvPath ./connectedMachinesAndVms.csv

# entry point for Azure Linux VMs
main -SplunkWildcardPaths $linuxAzureSplunkWildcardPatterns -VmList $connectedMachinesAndVmsHash["AzureLinuxVMs"] -IsArcConnectedMachine $false -IsLinuxVm $true

# Entry point for Arc Linux VMs
#main -SplunkWildcardPaths $linuxArcSplunkWildcardPatterns -VmList $connectedMachinesAndVmsHash["ArcLinuxVMs"]  -IsArcConnectedMachine $true -IsLinuxVm $true

# Entry point for Arc Windows VMs
#main -SplunkWildcardPaths $windowsArcSplunkWildcardPatterns -VmList $connectedMachinesAndVmsHash["ArcWindowsVMs"] -IsArcConnectedMachine $true -IsLinuxVm $false

# Entry point for Azure Windows VMs
main -SplunkWildcardPaths $windowsAzureSplunkWildcardPatterns -VmList $connectedMachinesAndVmsHash["AzureWindowsVMs"] -IsArcConnectedMachine $false -IsLinuxVm $false

