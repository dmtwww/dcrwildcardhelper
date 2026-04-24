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

# these are the RegEx equivalents of the original Splunk wildcards
# Splunk wildcards are proprietary as are DCR wildcards
# for example Splunk '/var/.../*.log' becomes '/var/.*/[^/]+.log' in RegEx and '/var/myparentfolder/myfolder*/*.log in DCR (multiple potentially required) 
# for example Splunk '/var/*/*.log' becomes '/var/[^/]+/[^/]+.log' in RegEx and '/var/myfolder*/*.log' in DCR (multiple potentially required)
$linuxAzureSplunkWildcardPatterns = @($config.linuxAzureSplunkWildcardPatterns | Sort-Object)

$linuxArcSplunkWildcardPatterns = @($config.linuxArcSplunkWildcardPatterns | Sort-Object)

# Define the Windows paths
$windowsArcSplunkWildcardPatterns = @($config.windowsArcSplunkWildcardPatterns | Sort-Object)

$windowsAzureSplunkWildcardPatterns = @($config.windowsAzureSplunkWildcardPatterns | Sort-Object)

# location for the DCRs
$dcrLocation = $config.dcrLocation

# TODO make this a parameter
$dcrResourceGroup = $config.dcrResourceGroup

$maxFilePatternsPerDcr = if ($null -ne $config.maxFilePatternsPerDcr) { [int]$config.maxFilePatternsPerDcr } else { 10 }
$runCommandTimeoutSeconds = if ($null -ne $config.runCommandTimeoutSeconds) { [int]$config.runCommandTimeoutSeconds } else { 600 }

function Format-ElapsedTime {
    param (
        [System.Diagnostics.Stopwatch]$Stopwatch
    )

    if ($null -eq $Stopwatch) {
        return "00:00:00"
    }

    return $Stopwatch.Elapsed.ToString('hh\:mm\:ss')
}

function Format-CurrentLogTime {
    return (Get-Date).ToString('HH:mm:ss')
}

function Write-ServerLog {
    param (
        [string]$VMName,
        [string]$Message,
        [string]$Color = 'Cyan'
    )

    Write-Host "[$(Format-CurrentLogTime)] [$VMName] $Message" -ForegroundColor $Color
}

function Get-ErrorSummary {
    param (
        [Parameter(Mandatory = $true)]
        [object]$ErrorRecord
    )

    $parts = @()

    if ($ErrorRecord -is [System.Management.Automation.ErrorRecord]) {
        if ($ErrorRecord.Exception -and -not [string]::IsNullOrWhiteSpace($ErrorRecord.Exception.Message)) {
            $parts += $ErrorRecord.Exception.Message
        }
        if ($ErrorRecord.FullyQualifiedErrorId) {
            $parts += $ErrorRecord.FullyQualifiedErrorId
        }
    }
    elseif (-not [string]::IsNullOrWhiteSpace([string]$ErrorRecord)) {
        $parts += [string]$ErrorRecord
    }

    $summary = ($parts -join ' | ').Trim()
    $summary = $summary -replace '\s+', ' '

    if ($summary.Length -gt 500) {
        $summary = $summary.Substring(0, 500) + '...'
    }

    return $summary
}

function Test-IsPermissionIssue {
    param (
        [Parameter(Mandatory = $true)]
        [object]$ErrorRecord
    )

    $summary = Get-ErrorSummary -ErrorRecord $ErrorRecord
    return $summary -match '(?i)(AuthorizationFailed|LinkedAuthorizationFailed|AuthorizationPermissionMismatch|Authorization_RequestDenied|Forbidden|Unauthorized|AuthenticationFailed|Insufficient privileges|does not have authorization|not authorized|permission denied|status code 403|status code 401|access denied)'
}

function Write-PermissionWarning {
    param (
        [Parameter(Mandatory = $true)]
        [string]$VMName,
        [Parameter(Mandatory = $true)]
        [string]$Stage,
        [Parameter(Mandatory = $true)]
        [object]$ErrorRecord,
        [string]$PermissionHint = ''
    )

    if ($ErrorRecord -is [System.Management.Automation.ErrorRecord] -and $ErrorRecord.Exception.Data['PermissionWarningLogged']) {
        return
    }

    $summary = Get-ErrorSummary -ErrorRecord $ErrorRecord
    $hintText = if ([string]::IsNullOrWhiteSpace($PermissionHint)) { '' } else { " $PermissionHint" }

    Write-ServerLog -VMName $VMName -Message "WARNING: permission issue during '$Stage'.$hintText Azure returned: $summary" -Color Yellow

    if ($ErrorRecord -is [System.Management.Automation.ErrorRecord]) {
        $ErrorRecord.Exception.Data['PermissionWarningLogged'] = $true
    }
}

function Write-PhaseLog {
    param (
        [string]$VMName,
        [string]$Phase,
        [System.Diagnostics.Stopwatch]$Stopwatch,
        [string]$Color = 'Cyan'
    )

    Write-ServerLog -VMName $VMName -Message $Phase -Color $Color
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
        $dceSubscriptionId = if ([string]::IsNullOrWhiteSpace($row.DceSubscriptionId)) { $row.SubscriptionId } else { $row.DceSubscriptionId }

        $vmEntry = [PSCustomObject]@{
            SubscriptionId = $row.SubscriptionId
            ResourceGroup = $row.ResourceGroup
            VMName = $row.VMName
            DceSubscriptionId = $dceSubscriptionId
            DCEName = $row.DCEName
            WorkspaceName = $row.WorkspaceName
            TableName = $row.TableName
        }

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

# helper function to get the anchor from a wildcard folde pattern
# ie the base folder before any wildcards
# example: Get-AnchorFromWildcard -SplunkWildcardPathname "/home/*/.bash_history" returns "/home"
function Get-AnchorFromWildcard {
    param (
        [string]$SplunkWildcardPathname,
        [bool]$IsLinuxVm
    )

    # Build an "anchor": everything before the first segment that contains a wildcard (* ? [)
    param (
        [string]$VMName,
        [string]$VmResourceId,
        [string]$Folder,
        [bool]$IsLinuxVm = $true
    )

    $retDcrFolderPath = $null

    try {
        # Is there a DCR Association for this VM
        $dcrAssociationArr = @(Get-AzDataCollectionRuleAssociation -ResourceUri $VmResourceId)

        foreach ($dcrAssociation in $dcrAssociationArr) {
            $dcrId = $dcrAssociation.DataCollectionRuleId

            if ($null -eq $dcrId) {
                Write-ServerLog -VMName $VMName -Message "DCR for association '$($dcrAssociation.Name)' does not exist - skipping" -Color Yellow
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
                Write-ServerLog -VMName $VMName -Message "DCR '$($dcr.Name)' has no log file data sources - skipping" -Color Yellow
                continue
            }

            $logFileDataSourceArr = @($dcr.Properties.dataSources.logFiles) 
            
            foreach ($logFileDataSource in $logFileDataSourceArr) {

                foreach ($filePattern in $logFileDataSource.filePatterns) {
                    Write-ServerLog -VMName $VMName -Message "Scanning associated DCR '$($dcr.Name)' file pattern '$filePattern' for resource '$VmResourceId'" -Color Magenta

                # if there are wildcards in the pattern then extract the folder part
                # else the pattern is a folder only
                if ($filePattern -match '[\*\?\[\.]') {
                    $retDcrFolderPath = $filePattern.Substring(0, $filePattern.LastIndexOf($folderSeparator))
                }
                else {
                    $retDcrFolderPath = $filePattern
                }

                    Write-ServerLog -VMName $VMName -Message "Derived folder '$retDcrFolderPath' from associated pattern '$filePattern' while looking for target folder '$Folder'" -Color DarkMagenta

                    if ($retDcrFolderPath -eq $Folder) {
                        Write-ServerLog -VMName $VMName -Message "Associated DCR match found: target folder '$Folder' is already covered by DCR '$($dcr.Name)'" -Color Green
                        return $retDcrFolderPath
                    }
                    else {                       
                        Write-ServerLog -VMName $VMName -Message "Associated DCR pattern '$filePattern' does not cover target folder '$Folder'" -Color DarkYellow
                        $retDcrFolderPath = $null
                    }                     
                }
            }
        }
    }
    catch {
        if (Test-IsPermissionIssue -ErrorRecord $_) {
            Write-PermissionWarning -VMName $VMName -Stage "reading existing DCR associations for folder '$Folder'" -ErrorRecord $_ -PermissionHint "This stage uses the signed-in user context and requires read access to the VM/Arc resource and associated DCRs."
        }
        throw
    }

    return $retDcrFolderPath
}

# this function will ensure the DCR, Data Sourc, File Pattern and DCR Association exist
# it is possible that some of these objects exist already, so lots of checks to see what is missing and create only that part
function New-DcrDataSourceAndAssociation {
    param (
        [Parameter(Mandatory = $true)]
        [string]$VMName,
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

    try {
        $retDcrResource = $null
        $dcrCreated = $false
        $associationCreated = $false
        
        $dcrResource = Get-AzResource -ResourceGroupName $dcrResourceGroup `
                        -ResourceType "microsoft.insights/datacollectionrules" `
                        -Name $dcrName `
                        -ErrorAction SilentlyContinue

        if ($null -eq $dcrResource) {
            Write-ServerLog -VMName $VMName -Message "DCR '$dcrName' does not exist for target file pattern '$DcrFilePattern' - creating it" -Color Yellow
            # create the DCR if it does not exist
            $dcr = New-DcrFromWildcard `
                -VMName $VMName `
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

            Write-ServerLog -VMName $VMName -Message "Created DCR '$dcrName' for target file pattern '$DcrFilePattern'" -Color Green
            $retDcrResource = Get-AzResource -ResourceId $dcr.Id
            $dcrCreated = $true
        }
        else {
            Write-ServerLog -VMName $VMName -Message "Reusing existing DCR '$dcrName' for target file pattern '$DcrFilePattern'" -Color DarkGreen

        # create the new Data Source
        $incomingStream = "Custom-Stream"                 # incoming stream name
        $dataSourceName = $DcrFilePattern + "-logfile"   # friendly name for this data source

        # Cannot have more than one Data Source object of a given type (eg Log File)
        # So in this case need to add an extra File Pattern to an exisiting data source object
        if ($null -ne $dcrResource.Properties.dataSources.logFiles) {
            # the Log Files data source already exists - recreate the object appending the new file pattern
            $exisitingDataSourceLogFiles = $dcrResource.Properties.dataSources.logFiles[0]

            Write-ServerLog -VMName $VMName -Message "Existing DCR '$dcrName' file patterns: $($exisitingDataSourceLogFiles.filePatterns -join ', ')" -Color DarkCyan

            if ($exisitingDataSourceLogFiles.filePatterns -contains $DcrFilePattern) {
                Write-ServerLog -VMName $VMName -Message "DCR '$dcrName' data source already contains target file pattern '$DcrFilePattern' - no update needed" -Color Green
            }
            else {
                Write-ServerLog -VMName $VMName -Message "DCR '$dcrName' data source does not contain target file pattern '$DcrFilePattern' - updating it" -Color Yellow
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

                Write-ServerLog -VMName $VMName -Message "Updated DCR '$dcrName' to include target file pattern '$DcrFilePattern'" -Color Green

            }
        }
        else {
            Write-ServerLog -VMName $VMName -Message "DCR '$dcrName' has no log file data source - creating one for target file pattern '$DcrFilePattern'" -Color Yellow
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

            Write-ServerLog -VMName $VMName -Message "Created log file data source in DCR '$dcrName' for target file pattern '$DcrFilePattern'" -Color Green
        }
            
            $retDcrResource = $dcrResource
        }

        # create the DCR Association
        Write-ServerLog -VMName $VMName -Message "Creating DCR association '$($retDcrResource.properties.dataSources.logFiles[0].name)' between resource '$vmResourceId' and DCR '$($retDcrResource.Name)'" -Color Yellow
        $null = New-AzDataCollectionRuleAssociation `
            -AssociationName $retDcrResource.properties.dataSources.logFiles[0].name `
            -ResourceUri $vmResourceId `
            -DataCollectionRuleId $retDcrResource.ResourceId
        $associationCreated = $true
        Write-ServerLog -VMName $VMName -Message "Created DCR association '$($retDcrResource.properties.dataSources.logFiles[0].name)' for resource '$vmResourceId'" -Color Green

        return [PSCustomObject]@{
            DcrResource = $retDcrResource
            DcrCreated = $dcrCreated
            AssociationCreated = $associationCreated
            AssociationName = $retDcrResource.properties.dataSources.logFiles[0].name
        }
    }
    catch {
        if (Test-IsPermissionIssue -ErrorRecord $_) {
            Write-PermissionWarning -VMName $VMName -Stage "creating or updating DCR '$dcrName' and its association" -ErrorRecord $_ -PermissionHint "This stage uses the signed-in user context and requires write permissions on DCRs, associations, DCE, workspace, and the target VM/Arc resource."
        }
        throw
    }
}

        # Create a DCR based on a name
function New-DcrFromWildcard {
    param (
        [string]$VMName,
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
        Write-ServerLog -VMName $VMName -Message "New-AzDataCollectionRule failed for '$dcrName', retrying via ARM REST API" -Color Yellow

        try {
            $resourcePath = "/subscriptions/$dcrSubscriptionId/resourceGroups/$dcrResourceGroupName/providers/Microsoft.Insights/dataCollectionRules/${dcrName}?api-version=2023-03-11"
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
        catch {
            if (Test-IsPermissionIssue -ErrorRecord $_) {
                Write-PermissionWarning -VMName $VMName -Stage "creating DCR '$dcrName' via ARM REST API fallback" -ErrorRecord $_ -PermissionHint "This stage uses the signed-in user context and requires permission to create Microsoft.Insights/dataCollectionRules in resource group '$dcrResourceGroupName'."
            }
            throw
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

function Get-DceResourceId {
    param (
        [string]$DceSubscriptionId,
        [string]$DcrResourceGroup,
        [string]$DceName
    )

    return "/subscriptions/$DceSubscriptionId/resourceGroups/$DcrResourceGroup/providers/Microsoft.Insights/dataCollectionEndpoints/$DceName"
}

function Get-WorkspaceResourceId {
    param (
        [string]$DceSubscriptionId,
        [string]$DcrResourceGroup,
        [string]$WorkspaceName
    )

    return "/subscriptions/$DceSubscriptionId/resourceGroups/$DcrResourceGroup/providers/Microsoft.OperationalInsights/workspaces/$WorkspaceName"
}

function Get-DcrNameFromProfile {
    param (
        [string]$DceSubscriptionId,
        [string]$DcrResourceGroup,
        [string]$DceName,
        [string]$WorkspaceName,
        [string]$TableName,
        [bool]$IsLinuxVm,
        [array]$FilePatterns
    )

    $kind = if ($IsLinuxVm) { 'linux' } else { 'windows' }
    $signature = @{
        kind = $kind
        dceSubscriptionId = $DceSubscriptionId
        dcrResourceGroup = $DcrResourceGroup
        dceName = $DceName
        workspaceName = $WorkspaceName
        tableName = $TableName
        filePatterns = @($FilePatterns)
    } | ConvertTo-Json -Compress -Depth 5

    $hashBytes = [System.Security.Cryptography.MD5]::HashData([System.Text.Encoding]::UTF8.GetBytes($signature))
    $hash = ([System.BitConverter]::ToString($hashBytes)).Replace('-', '').ToLowerInvariant().Substring(0, 16)
    return "dcr_${kind}_$hash"
}

function Get-DcrAssociationName {
    param (
        [string]$DcrName
    )

    $baseName = "assoc_$DcrName"
    if ($baseName.Length -le 64) {
        return $baseName
    }

    $hashBytes = [System.Security.Cryptography.MD5]::HashData([System.Text.Encoding]::UTF8.GetBytes($baseName))
    $hash = ([System.BitConverter]::ToString($hashBytes)).Replace('-', '').ToLowerInvariant().Substring(0, 12)
    return $baseName.Substring(0, 51) + '_' + $hash
}

function Test-IsDirectDcrPatternSupported {
    param (
        [string]$Pattern,
        [bool]$IsLinuxVm
    )

    if ($Pattern -match '\.\.\.') {
        return $false
    }

    $separatorPattern = if ($IsLinuxVm) { '/' } else { '\\' }
    $segments = $Pattern -split $separatorPattern
    $wildcardIndexes = @()

    for ($i = 0; $i -lt $segments.Count; $i++) {
        if ($segments[$i] -match '[\*\?\[]') {
            $wildcardIndexes += $i
        }
    }

    if ($wildcardIndexes.Count -eq 0) {
        return $true
    }

    $allowedIndexes = @($segments.Count - 1)
    if ($segments.Count -ge 2) {
        $allowedIndexes += ($segments.Count - 2)
    }

    foreach ($index in $wildcardIndexes) {
        if ($allowedIndexes -notcontains $index) {
            return $false
        }
    }

    return $true
}

function Get-DcrPatternMatchForFolder {
    param (
        [string]$Folder,
        [string]$SplunkWildcardPath,
        [bool]$IsLinuxVm
    )

    $regexPattern = Convert-SplunkWildcardToRegex -Pattern $SplunkWildcardPath -IsLinuxVm $IsLinuxVm
    $separator = if ($IsLinuxVm) { '/' } else { '\' }
    $lastSeparatorIndex = $SplunkWildcardPath.LastIndexOf($separator)

    if ($lastSeparatorIndex -lt 0) {
        return $null
    }

    $fileNamePattern = $SplunkWildcardPath.Substring($lastSeparatorIndex)
    $expandedPattern = $Folder + $fileNamePattern

    if ($expandedPattern -notmatch $regexPattern) {
        return $null
    }

    $usesDirectPattern = Test-IsDirectDcrPatternSupported -Pattern $SplunkWildcardPath -IsLinuxVm $IsLinuxVm
    $dcrFilePattern = if ($usesDirectPattern) { $SplunkWildcardPath } else { $expandedPattern }

    return [PSCustomObject]@{
        Folder = $Folder
        SplunkWildcardPath = $SplunkWildcardPath
        DcrFilePattern = $dcrFilePattern
        UsesDirectPattern = $usesDirectPattern
    }
}

function Build-ServerDcrProfileFilePatterns {
    param (
        [string]$VMName,
        [array]$DiscoveredFolders,
        [array]$SplunkWildcardPaths,
        [bool]$IsLinuxVm
    )

    $validFolders = @()
    foreach ($folder in ($DiscoveredFolders | Select-Object -Unique | Sort-Object)) {
        if ($IsLinuxVm) {
            if ($folder -like '/*') {
                $validFolders += $folder.Trim()
            }
        }
        else {
            if ($folder -match '^[a-zA-Z]:\\') {
                $validFolders += $folder.Trim()
            }
        }
    }

    Write-ServerLog -VMName $VMName -Message "Building DCR profile from $($validFolders.Count) discovered directories and $($SplunkWildcardPaths.Count) sorted configured patterns" -Color DarkCyan

    $orderedEntries = New-Object System.Collections.Generic.List[string]
    $seenEntries = New-Object 'System.Collections.Generic.HashSet[string]'

    foreach ($pattern in $SplunkWildcardPaths) {
        $patternMatches = @()

        foreach ($folder in $validFolders) {
            $match = Get-DcrPatternMatchForFolder -Folder $folder -SplunkWildcardPath $pattern -IsLinuxVm $IsLinuxVm
            if ($null -ne $match) {
                $patternMatches += $match
            }
        }

        if ($patternMatches.Count -eq 0) {
            Write-ServerLog -VMName $VMName -Message "Configured pattern '$pattern' did not match any discovered directory on this server" -Color DarkGray
            continue
        }

        if ($patternMatches[0].UsesDirectPattern) {
            if ($seenEntries.Add($pattern)) {
                $orderedEntries.Add($pattern)
                Write-ServerLog -VMName $VMName -Message "Configured pattern '$pattern' matched $($patternMatches.Count) discovered directories and is directly supported by DCR, so the literal wildcard pattern will be used" -Color Green
            }
            continue
        }

        foreach ($match in $patternMatches) {
            if ($seenEntries.Add($match.DcrFilePattern)) {
                $orderedEntries.Add($match.DcrFilePattern)
                Write-ServerLog -VMName $VMName -Message "Configured pattern '$pattern' expanded discovered directory '$($match.Folder)' to DCR file pattern '$($match.DcrFilePattern)'" -Color Green
            }
        }
    }

    Write-ServerLog -VMName $VMName -Message "Final ordered DCR profile contains $($orderedEntries.Count) file patterns" -Color Cyan
    return @($orderedEntries)
}

function Split-ArrayIntoChunks {
    param (
        [array]$Items,
        [int]$ChunkSize
    )

    $chunks = @()
    if ($null -eq $Items -or $Items.Count -eq 0) {
        return ,$chunks
    }

    for ($index = 0; $index -lt $Items.Count; $index += $ChunkSize) {
        $endIndex = [Math]::Min($index + $ChunkSize - 1, $Items.Count - 1)
        $chunks += ,@($Items[$index..$endIndex])
    }

    return ,$chunks
}


function Find-ReusableDcrForProfile {
    param (
        [string]$VMName,
        [string]$DceSubscriptionId,
        [string]$DcrResourceGroup,
        [string]$DceName,
        [string]$WorkspaceName,
        [string]$TableName,
        [bool]$IsLinuxVm,
        [array]$FilePatterns
    )

    $expectedDcrName = Get-DcrNameFromProfile `
        -DceSubscriptionId $DceSubscriptionId `
        -DcrResourceGroup $DcrResourceGroup `
        -DceName $DceName `
        -WorkspaceName $WorkspaceName `
        -TableName $TableName `
        -IsLinuxVm $IsLinuxVm `
        -FilePatterns $FilePatterns

    $candidate = Get-AzResource -ResourceGroupName $DcrResourceGroup -ResourceType 'Microsoft.Insights/dataCollectionRules' -Name $expectedDcrName -ErrorAction SilentlyContinue
    if ($null -eq $candidate) {
        return $null
    }

    Write-ServerLog -VMName $VMName -Message "Found reusable DCR '$($candidate.Name)' by deterministic profile name lookup" -Color DarkGreen
    return $candidate
}

function New-DcrFromProfile {
    param (
        [string]$VMName,
        [string]$DcrName,
        [string]$DcrResourceGroupName,
        [string]$DcrSubscriptionId,
        [string]$DcrLocation,
        [string]$DceName,
        [string]$WorkspaceName,
        [string]$TableName,
        [bool]$IsLinuxVm,
        [array]$FilePatterns
    )

    $dceId = Get-DceResourceId -DceSubscriptionId $DcrSubscriptionId -DcrResourceGroup $DcrResourceGroupName -DceName $DceName
    $workspaceResourceId = Get-WorkspaceResourceId -DceSubscriptionId $DcrSubscriptionId -DcrResourceGroup $DcrResourceGroupName -WorkspaceName $WorkspaceName
    $kind = if ($IsLinuxVm) { 'Linux' } else { 'Windows' }

    $dcrPayload = @{
        name = $DcrName
        location = $DcrLocation
        kind = $kind
        properties = @{
            dataCollectionEndpointId = $dceId
            streamDeclarations = @{
                "Custom-Text-$TableName" = @{
                    columns = @(
                        @{ name = 'TimeGenerated'; type = 'datetime' }
                        @{ name = 'RawData'; type = 'string' }
                        @{ name = 'FilePath'; type = 'string' }
                        @{ name = 'Computer'; type = 'string' }
                    )
                }
            }
            dataSources = @{
                logFiles = @(
                    @{
                        streams = @("Custom-Text-$TableName")
                        filePatterns = @($FilePatterns)
                        format = 'text'
                        settings = @{ text = @{ recordStartTimestampFormat = 'ISO 8601' } }
                        name = "Custom-Text-$TableName"
                    }
                )
            }
            destinations = @{
                logAnalytics = @(
                    @{
                        workspaceResourceId = $workspaceResourceId
                        name = $DcrName
                    }
                )
            }
            dataFlows = @(
                @{
                    streams = @("Custom-Text-$TableName")
                    destinations = @($DcrName)
                    transformKql = 'source | extend TimeGenerated, RawData, Computer, FilePath'
                    outputStream = "Custom-$TableName"
                }
            )
        }
    }

    $payload = $dcrPayload | ConvertTo-Json -Depth 10

    try {
        $retDcr = New-AzDataCollectionRule `
            -Name $DcrName `
            -ResourceGroupName $DcrResourceGroupName `
            -JsonString $payload `
            -ErrorAction Stop
    }
    catch {
        Write-ServerLog -VMName $VMName -Message "New-AzDataCollectionRule failed for '$DcrName', retrying via ARM REST API" -Color Yellow

        try {
            $resourcePath = "/subscriptions/$DcrSubscriptionId/resourceGroups/$DcrResourceGroupName/providers/Microsoft.Insights/dataCollectionRules/${DcrName}?api-version=2023-03-11"
            $restResponse = Invoke-AzRestMethod `
                -Method PUT `
                -Path $resourcePath `
                -Payload $payload `
                -ErrorAction Stop

            $restResource = $restResponse.Content | ConvertFrom-Json
            $retDcr = [PSCustomObject]@{ Id = $restResource.id }
        }
        catch {
            if (Test-IsPermissionIssue -ErrorRecord $_) {
                Write-PermissionWarning -VMName $VMName -Stage "creating DCR '$DcrName' via ARM REST API fallback" -ErrorRecord $_ -PermissionHint "This stage uses the signed-in user context and requires permission to create Microsoft.Insights/dataCollectionRules in resource group '$DcrResourceGroupName'."
            }
            throw
        }
    }

    return $retDcr
}

function Ensure-DcrForProfileChunk {
    param (
        [string]$VMName,
        [string]$DceSubscriptionId,
        [string]$DcrResourceGroup,
        [string]$DcrLocation,
        [string]$DceName,
        [string]$WorkspaceName,
        [string]$TableName,
        [bool]$IsLinuxVm,
        [array]$FilePatterns
    )

    try {
        $reusableDcr = Find-ReusableDcrForProfile `
            -VMName $VMName `
            -DceSubscriptionId $DceSubscriptionId `
            -DcrResourceGroup $DcrResourceGroup `
            -DceName $DceName `
            -WorkspaceName $WorkspaceName `
            -TableName $TableName `
            -IsLinuxVm $IsLinuxVm `
            -FilePatterns $FilePatterns

        if ($null -ne $reusableDcr) {
            return [PSCustomObject]@{
                DcrResource = $reusableDcr
                DcrCreated = $false
            }
        }

        $dcrName = Get-DcrNameFromProfile `
            -DceSubscriptionId $DceSubscriptionId `
            -DcrResourceGroup $DcrResourceGroup `
            -DceName $DceName `
            -WorkspaceName $WorkspaceName `
            -TableName $TableName `
            -IsLinuxVm $IsLinuxVm `
            -FilePatterns $FilePatterns

        Write-ServerLog -VMName $VMName -Message "No reusable DCR found for this ordered profile chunk. Creating DCR '$dcrName'" -Color Yellow
        $createdDcr = New-DcrFromProfile `
            -VMName $VMName `
            -DcrName $dcrName `
            -DcrResourceGroupName $DcrResourceGroup `
            -DcrSubscriptionId $DceSubscriptionId `
            -DcrLocation $DcrLocation `
            -DceName $DceName `
            -WorkspaceName $WorkspaceName `
            -TableName $TableName `
            -IsLinuxVm $IsLinuxVm `
            -FilePatterns $FilePatterns

        $dcrResource = Get-AzResource -ResourceId $createdDcr.Id -ErrorAction Stop
        Write-ServerLog -VMName $VMName -Message "Created DCR '$($dcrResource.Name)' for ordered profile chunk" -Color Green

        return [PSCustomObject]@{
            DcrResource = $dcrResource
            DcrCreated = $true
        }
    }
    catch {
        if (Test-IsPermissionIssue -ErrorRecord $_) {
            Write-PermissionWarning -VMName $VMName -Stage 'finding or creating reusable DCR profile' -ErrorRecord $_ -PermissionHint "This stage uses the signed-in user context and requires read/write permissions in the DCR subscription and resource group '$DcrResourceGroup'."
        }
        throw
    }
}

function Ensure-DcrAssociationForResource {
    param (
        [string]$VMName,
        [string]$VmResourceId,
        [object]$DcrResource
    )

    try {
        $existingAssociations = @(Get-AzDataCollectionRuleAssociation -ResourceUri $VmResourceId -ErrorAction SilentlyContinue)
        $matchingAssociation = $existingAssociations | Where-Object { $_.DataCollectionRuleId -eq $DcrResource.ResourceId } | Select-Object -First 1

        if ($null -ne $matchingAssociation) {
            Write-ServerLog -VMName $VMName -Message "Association already exists between resource '$VmResourceId' and DCR '$($DcrResource.Name)'" -Color DarkGreen
            return [PSCustomObject]@{
                AssociationName = $matchingAssociation.Name
                AssociationCreated = $false
            }
        }

        $associationName = Get-DcrAssociationName -DcrName $DcrResource.Name
        Write-ServerLog -VMName $VMName -Message "Creating association '$associationName' between resource '$VmResourceId' and DCR '$($DcrResource.Name)'" -Color Yellow
        $null = New-AzDataCollectionRuleAssociation `
            -AssociationName $associationName `
            -ResourceUri $VmResourceId `
            -DataCollectionRuleId $DcrResource.ResourceId

        Write-ServerLog -VMName $VMName -Message "Created association '$associationName' between resource '$VmResourceId' and DCR '$($DcrResource.Name)'" -Color Green
        return [PSCustomObject]@{
            AssociationName = $associationName
            AssociationCreated = $true
        }
    }
    catch {
        if (Test-IsPermissionIssue -ErrorRecord $_) {
            Write-PermissionWarning -VMName $VMName -Stage "creating DCR association for '$($DcrResource.Name)'" -ErrorRecord $_ -PermissionHint 'This stage uses the signed-in user context and requires permission to create data collection rule associations on the target server resource.'
        }
        throw
    }
}

function Remove-SupersededDcrAssociations {
    param (
        [string]$VMName,
        [string]$VmResourceId,
        [array]$CurrentDcrResourceIds,
        [array]$AllNewFilePatterns
    )

    try {
        $allAssociations = @(Get-AzDataCollectionRuleAssociation -ResourceUri $VmResourceId -ErrorAction SilentlyContinue)

        if ($allAssociations.Count -eq 0) {
            return
        }

        $newPatternSet = New-Object 'System.Collections.Generic.HashSet[string]'
        foreach ($p in $AllNewFilePatterns) { $null = $newPatternSet.Add($p) }

        $currentDcrIdSet = New-Object 'System.Collections.Generic.HashSet[string]'([System.StringComparer]::OrdinalIgnoreCase)
        foreach ($id in $CurrentDcrResourceIds) { $null = $currentDcrIdSet.Add($id) }

        foreach ($assoc in $allAssociations) {
            $assocDcrId = $assoc.DataCollectionRuleId
            if ($null -eq $assocDcrId) { continue }
            if ($currentDcrIdSet.Contains($assocDcrId)) { continue }

            # Check if this old DCR's file patterns are fully covered by the new profile
            try {
                $oldDcr = Get-AzResource -ResourceId $assocDcrId -ErrorAction SilentlyContinue
                if ($null -eq $oldDcr) {
                    Write-ServerLog -VMName $VMName -Message "Association '$($assoc.Name)' points to non-existent DCR - removing" -Color Yellow
                    $null = Remove-AzDataCollectionRuleAssociation -AssociationName $assoc.Name -ResourceUri $VmResourceId -ErrorAction Stop
                    Write-ServerLog -VMName $VMName -Message "Removed orphaned association '$($assoc.Name)'" -Color DarkYellow
                    continue
                }

                # Only process DCRs that have logFiles data sources (these are ours)
                if ($null -eq $oldDcr.Properties.dataSources -or
                    $null -eq $oldDcr.Properties.dataSources.logFiles -or
                    $oldDcr.Properties.dataSources.logFiles.Count -eq 0) {
                    continue
                }

                $oldPatterns = @($oldDcr.Properties.dataSources.logFiles | ForEach-Object { $_.filePatterns } | ForEach-Object { $_ })
                $allCovered = $true
                foreach ($oldPattern in $oldPatterns) {
                    if (-not $newPatternSet.Contains($oldPattern)) {
                        $allCovered = $false
                        break
                    }
                }

                if ($allCovered) {
                    Write-ServerLog -VMName $VMName -Message "Old DCR '$($oldDcr.Name)' patterns are fully covered by new profile - removing association '$($assoc.Name)'" -Color Yellow
                    $null = Remove-AzDataCollectionRuleAssociation -AssociationName $assoc.Name -ResourceUri $VmResourceId -ErrorAction Stop
                    Write-ServerLog -VMName $VMName -Message "Removed superseded association '$($assoc.Name)' (old DCR '$($oldDcr.Name)' is preserved for other servers)" -Color DarkYellow
                }
                else {
                    $uncoveredPatterns = @($oldPatterns | Where-Object { -not $newPatternSet.Contains($_) })
                    Write-ServerLog -VMName $VMName -Message "Old DCR '$($oldDcr.Name)' has $($uncoveredPatterns.Count) pattern(s) not in new profile - keeping association" -Color DarkGray
                }
            }
            catch {
                Write-ServerLog -VMName $VMName -Message "Warning: could not evaluate old association '$($assoc.Name)': $(Get-ErrorSummary -ErrorRecord $_)" -Color Yellow
            }
        }
    }
    catch {
        if (Test-IsPermissionIssue -ErrorRecord $_) {
            Write-PermissionWarning -VMName $VMName -Stage 'cleaning up superseded DCR associations' -ErrorRecord $_ -PermissionHint 'This stage uses the signed-in user context and requires read/delete permissions on data collection rule associations.'
        }
        Write-ServerLog -VMName $VMName -Message "Warning: could not clean up superseded associations: $(Get-ErrorSummary -ErrorRecord $_)" -Color Yellow
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
        [bool]$IsAsync = $false,
        [string]$RunCommandName = ""
    )

    # Create a key combining all three boolean states
    $caseKey = "$IsArcConnectedMachine-$IsLinuxVm-$IsAsync"
    $maxConflictRetries = 6
    $conflictRetryDelaySeconds = 30

    for ($attempt = 1; $attempt -le $maxConflictRetries; $attempt++) {
    try {
        $resolvedRunCommandName = if ([string]::IsNullOrWhiteSpace($RunCommandName)) { "ArcRunCmd-$(Get-Date -Format 'yyyyMMddHHmmss')" } else { $RunCommandName }

        switch ($caseKey) {
            # Arc + Linux + Async
            "True-True-True" {
                $result = New-AzConnectedMachineRunCommand `
                    -ResourceGroupName $ResourceGroupName `
                    -MachineName $VMName `
                    -Location $dcrLocation `
                    -RunCommandName $resolvedRunCommandName `
                    -SourceScript $ScriptString `
                    -AsJob
            }
        # Arc + Linux + Sync
            "True-True-False" {
                    $result = New-AzConnectedMachineRunCommand `
                    -ResourceGroupName $ResourceGroupName `
                    -MachineName $VMName `
                    -Location $dcrLocation `
                    -RunCommandName $resolvedRunCommandName `
                    -SourceScript $ScriptString
            }
        # Arc + Windows + Async
            "True-False-True" {
                $result = New-AzConnectedMachineRunCommand `
                    -ResourceGroupName $ResourceGroupName `
                    -MachineName $VMName `
                    -Location $dcrLocation `
                    -RunCommandName $resolvedRunCommandName `
                    -SourceScript $ScriptString `
                    -AsJob
            }
        # Arc + Windows + Sync
            "True-False-False" {
                    $result = New-AzConnectedMachineRunCommand `
                    -ResourceGroupName $ResourceGroupName `
                    -MachineName $VMName `
                    -Location $dcrLocation `
                    -RunCommandName $resolvedRunCommandName `
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
    catch {
        $errorSummary = Get-ErrorSummary -ErrorRecord $_
        if ($errorSummary -match '(?i)(Conflict|409|in progress)' -and $attempt -lt $maxConflictRetries) {
            Write-ServerLog -VMName $VMName -Message "Run command conflict (attempt $attempt/$maxConflictRetries): another command is in progress. Waiting ${conflictRetryDelaySeconds}s..." -Color Yellow
            Start-Sleep -Seconds $conflictRetryDelaySeconds
            continue
        }
        if (Test-IsPermissionIssue -ErrorRecord $_) {
            Write-PermissionWarning -VMName $VMName -Stage "starting run command" -ErrorRecord $_ -PermissionHint "This stage uses the signed-in user context and requires run-command permissions on the target VM or Arc server."
        }
        throw
    }
    }
}

function Remove-StaleArcRunCommands {
    param (
        [string]$ResourceGroupName,
        [string]$VMName,
        [string]$SubscriptionId
    )

    try {
        $listUri = "/subscriptions/$SubscriptionId/resourceGroups/$ResourceGroupName/providers/Microsoft.HybridCompute/machines/$VMName/runCommands?api-version=2025-01-13"
        $listResponse = Invoke-AzRestMethod -Method GET -Path $listUri -ErrorAction Stop
        $runCommands = ($listResponse.Content | ConvertFrom-Json).value

        if ($null -eq $runCommands -or $runCommands.Count -eq 0) {
            return
        }

        $staleCommands = @($runCommands | Where-Object {
            $_.properties.provisioningState -in @('Creating', 'Failed')
        })

        if ($staleCommands.Count -eq 0) {
            Write-ServerLog -VMName $VMName -Message "No stale run commands found" -Color DarkGray
            return
        }

        Write-ServerLog -VMName $VMName -Message "Found $($staleCommands.Count) stale run command(s) in Creating/Failed state - cleaning up" -Color Yellow

        foreach ($cmd in $staleCommands) {
            $cmdName = $cmd.name
            try {
                $deleteUri = "/subscriptions/$SubscriptionId/resourceGroups/$ResourceGroupName/providers/Microsoft.HybridCompute/machines/$VMName/runCommands/${cmdName}?api-version=2025-01-13"
                $null = Invoke-AzRestMethod -Method DELETE -Path $deleteUri -ErrorAction Stop
                Write-ServerLog -VMName $VMName -Message "Deleted stale run command '$cmdName' (was $($cmd.properties.provisioningState))" -Color DarkYellow
            }
            catch {
                Write-ServerLog -VMName $VMName -Message "Failed to delete stale run command '$cmdName': $(Get-ErrorSummary -ErrorRecord $_)" -Color Yellow
            }
        }

        # Brief pause to let ARM settle after deletions
        Start-Sleep -Seconds 5
    }
    catch {
        Write-ServerLog -VMName $VMName -Message "Warning: could not clean up stale run commands: $(Get-ErrorSummary -ErrorRecord $_)" -Color Yellow
    }
}

function Test-ArcAgentHealth {
    param (
        [string]$ResourceGroupName,
        [string]$VMName,
        [string]$SubscriptionId
    )

    try {
        $machineUri = "/subscriptions/$SubscriptionId/resourceGroups/$ResourceGroupName/providers/Microsoft.HybridCompute/machines/${VMName}?api-version=2025-01-13"
        $response = Invoke-AzRestMethod -Method GET -Path $machineUri -ErrorAction Stop
        $machine = $response.Content | ConvertFrom-Json

        if ($machine.properties.status -ne 'Connected') {
            Write-ServerLog -VMName $VMName -Message "WARNING: Arc agent status is '$($machine.properties.status)' (not Connected). Run commands may fail or hang." -Color Red
            return $false
        }

        # lastStatusChange is when the status last transitioned (e.g. became Connected), NOT the last heartbeat.
        # A large age is normal for a healthy agent that has been Connected for days.
        if ($null -ne $machine.properties.lastStatusChange) {
            $lastStatusChange = [DateTimeOffset]::Parse($machine.properties.lastStatusChange).UtcDateTime
            $minutesAgo = ((Get-Date).ToUniversalTime() - $lastStatusChange).TotalMinutes
            Write-ServerLog -VMName $VMName -Message "Arc agent is Connected (status unchanged for $([math]::Round($minutesAgo, 1)) min)" -Color DarkGreen
        }
        else {
            Write-ServerLog -VMName $VMName -Message "Arc agent is Connected" -Color DarkGreen
        }

        # Check extensions for failures — especially AzureMonitorLinuxAgent/AzureMonitorWindowsAgent
        # which must be healthy for run commands and DCR log collection to work
        $extUri = "/subscriptions/$SubscriptionId/resourceGroups/$ResourceGroupName/providers/Microsoft.HybridCompute/machines/${VMName}/extensions?api-version=2025-01-13"
        $extResponse = Invoke-AzRestMethod -Method GET -Path $extUri -ErrorAction Stop
        $extensions = ($extResponse.Content | ConvertFrom-Json).value

        if ($null -ne $extensions -and $extensions.Count -gt 0) {
            $failedExtensions = @($extensions | Where-Object { $_.properties.provisioningState -eq 'Failed' })
            foreach ($ext in $failedExtensions) {
                $extName = $ext.name
                $extMessage = if ($null -ne $ext.properties.instanceView -and $null -ne $ext.properties.instanceView.status) { $ext.properties.instanceView.status.message } else { 'no details' }
                Write-ServerLog -VMName $VMName -Message "WARNING: Extension '$extName' is in Failed state: $extMessage" -Color Red

                if ($extName -match 'AzureMonitor') {
                    Write-ServerLog -VMName $VMName -Message "CRITICAL: The Azure Monitor Agent extension is failing. DCR log collection and run commands will not work reliably until this is resolved." -Color Red
                    return $false
                }
            }
        }

        return $true
    }
    catch {
        Write-ServerLog -VMName $VMName -Message "Warning: could not check Arc agent health: $(Get-ErrorSummary -ErrorRecord $_)" -Color Yellow
        return $true  # proceed anyway if we can't check
    }
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

    try {
        $runCmdName = if ([string]::IsNullOrWhiteSpace($RunCommandName)) { "discover-$(Get-Date -Format 'yyyyMMddHHmmss')" } else { $RunCommandName }
        if ($IsArcConnectedMachine) {
            Write-PhaseLog -VMName $VMName -Phase "discovery running via Arc run-command: $runCmdName (timeout: ${runCommandTimeoutSeconds}s)" -Stopwatch $Stopwatch -Color DarkGray
        }

        if ($IsArcConnectedMachine) {
            # Use -AsJob and poll ARM resource for progress instead of blocking silently
            $job = RunCommand `
                -ResourceGroupName $ResourceGroupName `
                -VMName $VMName `
                -ScriptString $ScriptString `
                -IsArcConnectedMachine $IsArcConnectedMachine `
                -IsLinuxVm $IsLinuxVm `
                -IsAsync $true `
                -RunCommandName $runCmdName

            $subscriptionId = (Get-AzContext).Subscription.Id
            $checkUri = "/subscriptions/$subscriptionId/resourceGroups/$ResourceGroupName/providers/Microsoft.HybridCompute/machines/$VMName/runCommands/${runCmdName}?api-version=2025-01-13"
            $pollIntervalSeconds = 15
            $elapsedSeconds = 0
            $lastState = ''

            while ($elapsedSeconds -lt $runCommandTimeoutSeconds) {
                $null = $job | Wait-Job -Timeout $pollIntervalSeconds
                $elapsedSeconds += $pollIntervalSeconds

                if ($job.State -eq 'Completed') {
                    $result = $job | Receive-Job
                    Remove-Job -Job $job -Force
                    Write-PhaseLog -VMName $VMName -Phase "run command completed (${elapsedSeconds}s)" -Stopwatch $Stopwatch -Color Green

                    # Normalize output: SDK MachineRunCommand has InstanceView.Output (nested),
                    # but the output parser expects flat InstanceViewOutput. Extract it.
                    $output = $null
                    if ($result.PSObject.Properties.Match('InstanceViewOutput').Count -gt 0) {
                        $output = $result.InstanceViewOutput
                    }
                    elseif ($result.PSObject.Properties.Match('InstanceView').Count -gt 0 -and $null -ne $result.InstanceView) {
                        $output = $result.InstanceView.Output
                    }

                    # If SDK object lacks output, fetch from ARM directly
                    if ([string]::IsNullOrWhiteSpace($output)) {
                        try {
                            $armResp = Invoke-AzRestMethod -Method GET -Path $checkUri -ErrorAction Stop
                            $armObj = $armResp.Content | ConvertFrom-Json
                            $output = $armObj.properties.instanceView.output
                            if (-not [string]::IsNullOrWhiteSpace($output)) {
                                Write-PhaseLog -VMName $VMName -Phase "retrieved output from ARM fallback (${elapsedSeconds}s)" -Stopwatch $Stopwatch -Color DarkGray
                            }
                        }
                        catch {
                            Write-PhaseLog -VMName $VMName -Phase "Warning: could not fetch run command output from ARM: $(Get-ErrorSummary -ErrorRecord $_)" -Stopwatch $Stopwatch -Color Yellow
                        }
                    }

                    return [PSCustomObject]@{
                        InstanceViewOutput = $output
                    }
                }

                # Poll ARM resource for current state
                try {
                    $checkResponse = Invoke-AzRestMethod -Method GET -Path $checkUri -ErrorAction Stop
                    $checkResource = $checkResponse.Content | ConvertFrom-Json
                    $provState = $checkResource.properties.provisioningState
                    $execState = $checkResource.properties.instanceView.executionState
                    $currentState = "$provState/$execState"

                    if ($currentState -ne $lastState) {
                        Write-PhaseLog -VMName $VMName -Phase "run command state: $currentState (${elapsedSeconds}s)" -Stopwatch $Stopwatch -Color DarkGray
                        $lastState = $currentState
                    }
                    else {
                        Write-PhaseLog -VMName $VMName -Phase "run command waiting... $currentState (${elapsedSeconds}s)" -Stopwatch $Stopwatch -Color DarkGray
                    }

                    # If ARM says Succeeded but the PS job hasn't caught up yet, grab the output directly
                    if ($provState -eq 'Succeeded') {
                        Remove-Job -Job $job -Force
                        Write-PhaseLog -VMName $VMName -Phase "run command succeeded (${elapsedSeconds}s)" -Stopwatch $Stopwatch -Color Green
                        return [PSCustomObject]@{
                            InstanceViewOutput = $checkResource.properties.instanceView.output
                        }
                    }

                    if ($provState -eq 'Failed') {
                        Remove-Job -Job $job -Force
                        $errorMsg = $checkResource.properties.instanceView.error
                        throw "Arc run command '$runCmdName' failed after ${elapsedSeconds}s. Error: $errorMsg"
                    }
                }
                catch [System.Management.Automation.RuntimeException] {
                    # Re-throw our own thrown exceptions
                    throw
                }
                catch {
                    Write-PhaseLog -VMName $VMName -Phase "run command polling error (${elapsedSeconds}s): $(Get-ErrorSummary -ErrorRecord $_)" -Stopwatch $Stopwatch -Color Yellow
                }
            }

            # Timeout reached
            Remove-Job -Job $job -Force
            try {
                $checkResponse = Invoke-AzRestMethod -Method GET -Path $checkUri -ErrorAction Stop
                $checkResource = $checkResponse.Content | ConvertFrom-Json
                if ($checkResource.properties.provisioningState -eq 'Succeeded') {
                    Write-ServerLog -VMName $VMName -Message "Run command '$runCmdName' succeeded at the wire despite timeout" -Color Green
                    return [PSCustomObject]@{
                        InstanceViewOutput = $checkResource.properties.instanceView.output
                    }
                }
                $state = "$($checkResource.properties.provisioningState)/$($checkResource.properties.instanceView.executionState)"
            }
            catch {
                $state = 'Unknown'
            }
            throw "Arc run command '$runCmdName' timed out after ${runCommandTimeoutSeconds}s (state: $state). The Arc agent on '$VMName' may be unresponsive or experiencing issues. Check the machine health and extensions."
        }
        else {
            $result = RunCommand `
                -ResourceGroupName $ResourceGroupName `
                -VMName $VMName `
                -ScriptString $ScriptString `
                -IsArcConnectedMachine $IsArcConnectedMachine `
                -IsLinuxVm $IsLinuxVm `
                -RunCommandName $runCmdName

            return $result
        }
    }
    catch {
        if (Test-IsPermissionIssue -ErrorRecord $_) {
            Write-PermissionWarning -VMName $VMName -Stage "running discovery command" -ErrorRecord $_ -PermissionHint "This stage uses the signed-in user context and requires run-command permissions on the Arc server."
        }
        throw
    }
}

# Submit Arc discovery commands for all VMs in a list. Returns an array of tracking objects.
# Each VM gets health-checked and stale commands cleaned up before submission.
# Context switching happens sequentially here (fast — no waiting for results).
function Submit-ArcDiscoveries {
    param (
        [array]$VmList,
        [array]$SplunkWildcardPaths,
        [bool]$IsLinuxVm
    )

    $trackers = @()
    $cmdTemplateLinux = 'find $anchor -wholename "$path" $pipeline'

    foreach ($vm in $VmList) {
        $machine = $vm.VMName
        $subscriptionId = $vm.SubscriptionId
        $resourceGroup = $vm.ResourceGroup

        try {
            Set-AzContextForSubscription -SubscriptionId $subscriptionId
        }
        catch {
            if (Test-IsPermissionIssue -ErrorRecord $_) {
                Write-PermissionWarning -VMName $machine -Stage "setting subscription context" -ErrorRecord $_ -PermissionHint "This stage uses the signed-in user context and requires access to subscription '$subscriptionId'."
            }
            Write-ServerLog -VMName $machine -Message "Failed to set subscription context - skipping: $(Get-ErrorSummary -ErrorRecord $_)" -Color Red
            continue
        }

        $vmTypeLabel = "Arc $(if ($IsLinuxVm) { 'Linux' } else { 'Windows' })"
        Write-ServerLog -VMName $machine -Message "Processing $vmTypeLabel VM in resource group '$resourceGroup' under subscription '$subscriptionId'" -Color Green

        # Health check
        $agentHealthy = Test-ArcAgentHealth -ResourceGroupName $resourceGroup -VMName $machine -SubscriptionId $subscriptionId
        if (-not $agentHealthy) {
            Write-ServerLog -VMName $machine -Message "Skipping server due to unhealthy Arc agent" -Color Red
            continue
        }

        Remove-StaleArcRunCommands -ResourceGroupName $resourceGroup -VMName $machine -SubscriptionId $subscriptionId

        # Build discovery command string
        $cmds = ""
        foreach ($wildcardPath in $SplunkWildcardPaths) {
            $anchor = Get-AnchorFromWildcard -SplunkWildcardPathname $wildcardPath -IsLinuxVm $IsLinuxVm

            if ($IsLinuxVm) {
                $regexPattern = Convert-SplunkWildcardToRegex -Pattern $wildcardPath -IsLinuxVm $IsLinuxVm
                if ($wildcardPath -match '[\*\?\[\.]') {
                    $pipeline = "| xargs -I {} dirname {} | sort -u"
                }
                else {
                    $pipeline = "| sort -u"
                }
                if ($wildcardPath -match '\.\.\.') {
                    $cmd = "find $anchor -regextype posix-extended -regex `"$regexPattern`" $pipeline"
                }
                else {
                    $cmd = $cmdTemplateLinux `
                        -replace '\$anchor', $anchor `
                        -replace '\$path', $wildcardPath `
                        -replace '\$pipeline', $pipeline
                }
            }
            else {
                if ($wildcardPath -match '\.\.\.') {
                    $likePattern = $wildcardPath -replace '\.\.\.', '*'
                    $cmd = "Get-ChildItem -Path '$anchor' -Recurse -Force -ErrorAction SilentlyContinue | Where-Object { `$_.FullName -like '$likePattern' } | ForEach-Object { `$_.Directory.FullName } | Sort-Object -Unique"
                }
                elseif ($wildcardPath -match '[\*\?\[]') {
                    $cmd = "Get-ChildItem -Path '$anchor' -Recurse -Force -ErrorAction SilentlyContinue | Where-Object { `$_.FullName -like '$wildcardPath' } | ForEach-Object { `$_.Directory.FullName } | Sort-Object -Unique"
                }
                else {
                    $cmd = "if (Test-Path '$wildcardPath') { '$wildcardPath' }"
                }
            }
            $cmds += $cmd + "; "
        }

        $runCmdName = "discover-$(Get-Date -Format 'yyyyMMddHHmmss')"

        try {
            $job = RunCommand `
                -ResourceGroupName $resourceGroup `
                -VMName $machine `
                -ScriptString $cmds `
                -IsArcConnectedMachine $true `
                -IsLinuxVm $IsLinuxVm `
                -IsAsync $true `
                -RunCommandName $runCmdName
        }
        catch {
            if (Test-IsPermissionIssue -ErrorRecord $_) {
                Write-PermissionWarning -VMName $machine -Stage "submitting discovery command" -ErrorRecord $_ -PermissionHint "This stage uses the signed-in user context and requires run-command permissions on the Arc server."
            }
            Write-ServerLog -VMName $machine -Message "Failed to submit discovery - skipping: $(Get-ErrorSummary -ErrorRecord $_)" -Color Red
            continue
        }

        Write-ServerLog -VMName $machine -Message "discovery submitted: $runCmdName" -Color DarkCyan

        $checkUri = "/subscriptions/$subscriptionId/resourceGroups/$resourceGroup/providers/Microsoft.HybridCompute/machines/$machine/runCommands/${runCmdName}?api-version=2025-01-13"
        $trackers += [PSCustomObject]@{
            VM             = $vm
            Job            = $job
            RunCmdName     = $runCmdName
            CheckUri       = $checkUri
            LastState      = ''
            IsLinuxVm      = $IsLinuxVm
            Result         = $null
            Failed         = $false
            ErrorMessage   = $null
        }
    }

    return ,$trackers
}

# Poll all pending Arc discovery commands in a single loop until all complete or global timeout.
# Reports only: state changes, errors, success, timeout. Suppresses repeated identical states.
function Wait-AllArcDiscoveries {
    param (
        [array]$Trackers
    )

    if ($Trackers.Count -eq 0) { return }

    $pending = [System.Collections.Generic.List[object]]::new()
    foreach ($t in $Trackers) { $pending.Add($t) }

    Write-Host "[$(Format-CurrentLogTime)] Waiting for $($pending.Count) Arc discovery command(s) to complete (timeout: ${runCommandTimeoutSeconds}s)..." -ForegroundColor Cyan

    $pollIntervalSeconds = 15
    $elapsedSeconds = 0

    while ($pending.Count -gt 0 -and $elapsedSeconds -lt $runCommandTimeoutSeconds) {
        # Wait one poll interval — check all jobs first for quick completions
        Start-Sleep -Seconds $pollIntervalSeconds
        $elapsedSeconds += $pollIntervalSeconds

        $completed = @()

        foreach ($tracker in $pending) {
            $machine = $tracker.VM.VMName

            # Check if PS job completed
            if ($tracker.Job.State -eq 'Completed') {
                try {
                    $result = $tracker.Job | Receive-Job
                    Remove-Job -Job $tracker.Job -Force

                    # Normalize output (same logic as Invoke-DiscoveryRunCommandWithProgress)
                    $output = $null
                    if ($result.PSObject.Properties.Match('InstanceViewOutput').Count -gt 0) {
                        $output = $result.InstanceViewOutput
                    }
                    elseif ($result.PSObject.Properties.Match('InstanceView').Count -gt 0 -and $null -ne $result.InstanceView) {
                        $output = $result.InstanceView.Output
                    }

                    # ARM fallback if SDK lacks output
                    if ([string]::IsNullOrWhiteSpace($output)) {
                        try {
                            $armResp = Invoke-AzRestMethod -Method GET -Path $tracker.CheckUri -ErrorAction Stop
                            $armObj = $armResp.Content | ConvertFrom-Json
                            $output = $armObj.properties.instanceView.output
                            if (-not [string]::IsNullOrWhiteSpace($output)) {
                                Write-ServerLog -VMName $machine -Message "retrieved output from ARM fallback (${elapsedSeconds}s)" -Color DarkGray
                            }
                        }
                        catch {
                            Write-ServerLog -VMName $machine -Message "Warning: could not fetch output from ARM: $(Get-ErrorSummary -ErrorRecord $_)" -Color Yellow
                        }
                    }

                    $tracker.Result = [PSCustomObject]@{ InstanceViewOutput = $output }
                    Write-ServerLog -VMName $machine -Message "discovery completed via job (${elapsedSeconds}s)" -Color Green
                }
                catch {
                    $tracker.Failed = $true
                    $tracker.ErrorMessage = Get-ErrorSummary -ErrorRecord $_
                    Write-ServerLog -VMName $machine -Message "discovery job failed: $($tracker.ErrorMessage)" -Color Red
                    try { Remove-Job -Job $tracker.Job -Force } catch {}
                }
                $completed += $tracker
                continue
            }

            # Check if PS job failed
            if ($tracker.Job.State -eq 'Failed') {
                try { $tracker.Job | Receive-Job -ErrorAction Stop } catch {
                    $tracker.ErrorMessage = Get-ErrorSummary -ErrorRecord $_
                }
                $tracker.Failed = $true
                Write-ServerLog -VMName $machine -Message "discovery job failed (${elapsedSeconds}s): $($tracker.ErrorMessage)" -Color Red
                try { Remove-Job -Job $tracker.Job -Force } catch {}
                $completed += $tracker
                continue
            }

            # Poll ARM for state
            try {
                $checkResponse = Invoke-AzRestMethod -Method GET -Path $tracker.CheckUri -ErrorAction Stop
                $checkResource = $checkResponse.Content | ConvertFrom-Json
                $provState = $checkResource.properties.provisioningState
                $execState = $checkResource.properties.instanceView.executionState
                $currentState = "$provState/$execState"

                # Only report state changes
                if ($currentState -ne $tracker.LastState) {
                    Write-ServerLog -VMName $machine -Message "state changed: $currentState (${elapsedSeconds}s)" -Color DarkGray
                    $tracker.LastState = $currentState
                }

                if ($provState -eq 'Succeeded') {
                    try { Remove-Job -Job $tracker.Job -Force } catch {}
                    $tracker.Result = [PSCustomObject]@{
                        InstanceViewOutput = $checkResource.properties.instanceView.output
                    }
                    Write-ServerLog -VMName $machine -Message "discovery completed (${elapsedSeconds}s)" -Color Green
                    $completed += $tracker
                    continue
                }

                if ($provState -eq 'Failed') {
                    try { Remove-Job -Job $tracker.Job -Force } catch {}
                    $tracker.Failed = $true
                    $tracker.ErrorMessage = "Run command failed: $($checkResource.properties.instanceView.error)"
                    Write-ServerLog -VMName $machine -Message "discovery failed (${elapsedSeconds}s): $($tracker.ErrorMessage)" -Color Red
                    $completed += $tracker
                    continue
                }
            }
            catch {
                Write-ServerLog -VMName $machine -Message "polling error (${elapsedSeconds}s): $(Get-ErrorSummary -ErrorRecord $_)" -Color Yellow
            }
        }

        foreach ($done in $completed) { $pending.Remove($done) | Out-Null }

        if ($pending.Count -gt 0 -and $completed.Count -gt 0) {
            Write-Host "[$(Format-CurrentLogTime)] $($completed.Count) completed, $($pending.Count) still pending (${elapsedSeconds}s)" -ForegroundColor Cyan
        }
    }

    # Handle remaining timeouts — do one final ARM check for each
    if ($pending.Count -gt 0) {
        Write-Host "[$(Format-CurrentLogTime)] Global timeout reached (${runCommandTimeoutSeconds}s). Checking $($pending.Count) remaining command(s)..." -ForegroundColor Yellow

        foreach ($tracker in $pending) {
            $machine = $tracker.VM.VMName
            try { Remove-Job -Job $tracker.Job -Force } catch {}

            try {
                $checkResponse = Invoke-AzRestMethod -Method GET -Path $tracker.CheckUri -ErrorAction Stop
                $checkResource = $checkResponse.Content | ConvertFrom-Json
                if ($checkResource.properties.provisioningState -eq 'Succeeded') {
                    $tracker.Result = [PSCustomObject]@{
                        InstanceViewOutput = $checkResource.properties.instanceView.output
                    }
                    Write-ServerLog -VMName $machine -Message "discovery succeeded at the wire despite timeout" -Color Green
                    continue
                }
                $state = "$($checkResource.properties.provisioningState)/$($checkResource.properties.instanceView.executionState)"
            }
            catch {
                $state = 'Unknown'
            }
            $tracker.Failed = $true
            $tracker.ErrorMessage = "Timed out after ${runCommandTimeoutSeconds}s (state: $state)"
            Write-ServerLog -VMName $machine -Message "discovery timed out (state: $state). Arc agent may be unresponsive." -Color Red
        }
    }

    $succeeded = @($Trackers | Where-Object { -not $_.Failed -and $null -ne $_.Result }).Count
    $failed = @($Trackers | Where-Object { $_.Failed }).Count
    Write-Host "[$(Format-CurrentLogTime)] All Arc discoveries finished: $succeeded succeeded, $failed failed out of $($Trackers.Count)" -ForegroundColor Cyan
}

# Process a single Arc VM after its discovery result is available.
# Handles: output parsing, DCR profile building, DCR creation/reuse, association, ingestion, cleanup.
function Process-ArcDiscoveryResult {
    param (
        [object]$VM,
        [object]$DiscoveryResult,
        [array]$SplunkWildcardPaths,
        [bool]$IsLinuxVm
    )

    $machine = $VM.VMName
    $subscriptionId = $VM.SubscriptionId
    $resourceGroup = $VM.ResourceGroup
    $dceSubscriptionId = $VM.DceSubscriptionId
    $dceName = $VM.DCEName
    $workspaceName = $VM.WorkspaceName
    $tableName = $VM.TableName
    $serverStopwatch = [System.Diagnostics.Stopwatch]::StartNew()

    try {
        Set-AzContextForSubscription -SubscriptionId $subscriptionId

        # Parse output
        $resultArr = $null
        if ($DiscoveryResult.PSObject.Properties.Match('InstanceViewOutput').Count -gt 0 -and $null -ne $DiscoveryResult.InstanceViewOutput) {
            $resultArr = $DiscoveryResult.InstanceViewOutput -split "`n"
        }
        if ($null -eq $resultArr -or $resultArr.Count -eq 0) {
            Write-ServerLog -VMName $machine -Message "No output returned from discovery - skipping" -Color Yellow
            return
        }

        Write-PhaseLog -VMName $machine -Phase 'discovery completed' -Stopwatch $serverStopwatch -Color Green

        $profileFilePatterns = @(Build-ServerDcrProfileFilePatterns `
            -VMName $machine `
            -DiscoveredFolders $resultArr `
            -SplunkWildcardPaths $SplunkWildcardPaths `
            -IsLinuxVm $IsLinuxVm)

        if ($profileFilePatterns.Count -eq 0) {
            Write-ServerLog -VMName $machine -Message "No DCR file patterns were produced for this server profile - skipping" -Color Yellow
            return
        }

        $dcrProfileChunks = Split-ArrayIntoChunks -Items $profileFilePatterns -ChunkSize $maxFilePatternsPerDcr
        if ($dcrProfileChunks.Count -gt 1) {
            Write-ServerLog -VMName $machine -Message "Server profile was split into $($dcrProfileChunks.Count) DCR chunks using a maximum of $maxFilePatternsPerDcr file patterns per DCR" -Color Cyan
        }

        $vmResourceId = (Get-AzResource -ResourceGroupName $resourceGroup -ResourceName $machine -ResourceType 'Microsoft.HybridCompute/machines').ResourceId

        Set-AzContextForSubscription -SubscriptionId $dceSubscriptionId

        $currentDcrResourceIds = @()
        $allIngestionEntries = @()

        for ($chunkIndex = 0; $chunkIndex -lt $dcrProfileChunks.Count; $chunkIndex++) {
            $chunkPatterns = @($dcrProfileChunks[$chunkIndex])
            if ($dcrProfileChunks.Count -gt 1) {
                Write-PhaseLog -VMName $machine -Phase "processing DCR profile chunk $($chunkIndex + 1)/$($dcrProfileChunks.Count)" -Stopwatch $serverStopwatch -Color DarkCyan
            }
            Write-ServerLog -VMName $machine -Message "Chunk $($chunkIndex + 1) ordered file patterns: $($chunkPatterns -join ' | ')" -Color DarkCyan

            Set-AzContextForSubscription -SubscriptionId $dceSubscriptionId
            $dcrResult = Ensure-DcrForProfileChunk `
                -VMName $machine `
                -DceSubscriptionId $dceSubscriptionId `
                -DcrResourceGroup $dcrResourceGroup `
                -DcrLocation $dcrLocation `
                -DceName $dceName `
                -WorkspaceName $workspaceName `
                -TableName $tableName `
                -IsLinuxVm $IsLinuxVm `
                -FilePatterns $chunkPatterns

            $dcr = $dcrResult.DcrResource
            $currentDcrResourceIds += $dcr.ResourceId
            $dceResourceId = Get-DceResourceId -DceSubscriptionId $dceSubscriptionId -DcrResourceGroup $dcrResourceGroup -DceName $dceName
            $dce = Get-AzResource -ResourceId $dceResourceId -ErrorAction Stop

            if ($dcrResult.DcrCreated) {
                Write-PhaseLog -VMName $machine -Phase "DCR created: $($dcr.Name)" -Stopwatch $serverStopwatch -Color Green
            }
            else {
                Write-PhaseLog -VMName $machine -Phase "DCR reused: $($dcr.Name)" -Stopwatch $serverStopwatch -Color DarkGreen
            }

            Set-AzContextForSubscription -SubscriptionId $subscriptionId
            $associationResult = Ensure-DcrAssociationForResource `
                -VMName $machine `
                -VmResourceId $vmResourceId `
                -DcrResource $dcr

            if ($associationResult.AssociationCreated) {
                Write-PhaseLog -VMName $machine -Phase "association created: $($associationResult.AssociationName)" -Stopwatch $serverStopwatch -Color Green
            }
            else {
                Write-PhaseLog -VMName $machine -Phase "association reused: $($associationResult.AssociationName)" -Stopwatch $serverStopwatch -Color DarkGreen
            }

            foreach ($dcrFilePattern in $chunkPatterns) {
                $allIngestionEntries += @{ Pattern = $dcrFilePattern; DcrImmutableId = $dcr.Properties.immutableId }
            }
        }

        if ($allIngestionEntries.Count -gt 0) {
            Set-AzContextForSubscription -SubscriptionId $subscriptionId
            Invoke-HistoricalLogIngestion `
                -ResourceGroupName $resourceGroup `
                -VMName $machine `
                -PatternEntries $allIngestionEntries `
                -TableName $tableName `
                -DceEndpoint $dce.Properties.logsIngestion.endpoint `
                -IsArcConnectedMachine $true `
                -IsLinuxVm $IsLinuxVm

            Write-PhaseLog -VMName $machine -Phase "ingestion started: $($allIngestionEntries.Count) pattern(s)" -Stopwatch $serverStopwatch -Color Blue
        }

        Set-AzContextForSubscription -SubscriptionId $subscriptionId
        Remove-SupersededDcrAssociations `
            -VMName $machine `
            -VmResourceId $vmResourceId `
            -CurrentDcrResourceIds $currentDcrResourceIds `
            -AllNewFilePatterns $profileFilePatterns
    }
    catch {
        if (Test-IsPermissionIssue -ErrorRecord $_) {
            Write-PermissionWarning -VMName $machine -Stage "processing VM" -ErrorRecord $_ -PermissionHint "This can be caused by missing RBAC for the signed-in user, or by missing permissions expected on the target server identity later in the workflow."
        }
        Write-ServerLog -VMName $machine -Message "Error processing VM: $_" -Color Red
    }
    finally {
        $serverStopwatch.Stop()
        Write-ServerLog -VMName $machine -Message "Total controller time spent on server: $(Format-ElapsedTime -Stopwatch $serverStopwatch)" -Color Magenta
    }
}

# Build a self-contained script that runs on the VM to ingest all historical log lines
# via the Log Ingestion API. No storage account dependency — the script is fully inline.
# Accepts an array of @{Pattern='...'; DcrImmutableId='...'} entries so that a single
# RunCommand handles every file pattern for one VM (Azure limits one concurrent RunCommand).
function Build-IngestScript {
    param (
        [bool]$IsArcConnectedMachine,
        [bool]$IsLinuxVm,
        [array]$PatternEntries,
        [string]$TableName,
        [string]$DceEndpoint,
        [string]$VMName
    )

    $imdsHost = if ($IsArcConnectedMachine) { 'localhost:40342' } else { '169.254.169.254' }
    $streamName = "Custom-Text-$TableName"

    if ($IsLinuxVm) {
        # Build token acquisition
        $tokenScript = @"
RESOURCE="https://monitor.azure.com/"
API_VERSION="2020-06-01"
ENDPOINT="http://$imdsHost/metadata/identity/oauth2/token?resource=`$RESOURCE&api-version=`$API_VERSION"
"@
        if ($IsArcConnectedMachine) {
            $tokenScript += @"

WWW_AUTH=`$(curl -s -D - -o /dev/null -H "Metadata: true" "`$ENDPOINT" | grep -i "WWW-Authenticate")
SECRET_FILE=`$(echo `$WWW_AUTH | awk -F 'Basic realm=' '{print `$2}' | sed 's/\r`$//')
SECRET=`$(cat "`$SECRET_FILE")
TOKEN=`$(curl -s -H "Metadata: true" -H "Authorization: Basic `$SECRET" "`$ENDPOINT" | grep -oP '"access_token"\s*:\s*"\K[^"]+')
"@
        }
        else {
            $tokenScript += @"

TOKEN=`$(curl -s -H "Metadata: true" "`$ENDPOINT" | grep -oP '"access_token"\s*:\s*"\K[^"]+')
"@
        }

        # Build bash arrays for patterns, anchors, and URIs
        $patternArr = ($PatternEntries | ForEach-Object { "`"$($_.Pattern)`"" }) -join ' '
        $anchorArr = ($PatternEntries | ForEach-Object {
            $a = Get-AnchorFromWildcard -SplunkWildcardPathname $_.Pattern -IsLinuxVm $true
            "`"$a`""
        }) -join ' '
        $uriArr = ($PatternEntries | ForEach-Object {
            "`"$DceEndpoint/dataCollectionRules/$($_.DcrImmutableId)/streams/$streamName`?api-version=2023-01-01`""
        }) -join ' '

        $script = @"
#!/bin/bash
$tokenScript
if [ -z "`$TOKEN" ]; then echo "ERROR: no token"; exit 1; fi
COMPUTER="$VMName"
MAXSIZE=950000
PATTERNS=($patternArr)
ANCHORS=($anchorArr)
URIS=($uriArr)
RECCOUNT=0
send_batch() {
  if [ `$RECCOUNT -eq 0 ]; then return; fi
  PAYLOAD="[`$BATCH]"
  HTTP_CODE=`$(curl -s -o /dev/null -w "%{http_code}" -X POST "`$CUR_URI" -H "Content-Type: application/json" -H "Authorization: Bearer `$TOKEN" -d "`$PAYLOAD")
  echo "Sent `$RECCOUNT records (`$BATCHSIZE bytes), HTTP `$HTTP_CODE"
  BATCH=""
  BATCHSIZE=0
  RECCOUNT=0
}
for idx in "`${!PATTERNS[@]}"; do
  PATTERN="`${PATTERNS[`$idx]}"
  ANCHOR="`${ANCHORS[`$idx]}"
  CUR_URI="`${URIS[`$idx]}"
  FILES=`$(find "`$ANCHOR" -wholename "`$PATTERN" 2>/dev/null)
  if [ -z "`$FILES" ]; then echo "No files match `$PATTERN"; continue; fi
  BATCH=""
  BATCHSIZE=0
  RECCOUNT=0
  for f in `$FILES; do
    echo "Processing `$f"
    while IFS= read -r line || [ -n "`$line" ]; do
      [ -z "`$line" ] && continue
      ESCAPED=`$(echo "`$line" | sed 's/\\/\\\\/g; s/"/\\"/g')
      TS=`$(echo "`$line" | cut -d',' -f1)
      RECORD="{\"TimeGenerated\":\"`$TS\",\"RawData\":\"`$ESCAPED\",\"FilePath\":\"`$f\",\"Computer\":\"`$COMPUTER\"}"
      RECLEN=`${#RECORD}
      if [ `$((`$BATCHSIZE + `$RECLEN + 2)) -gt `$MAXSIZE ] && [ `$RECCOUNT -gt 0 ]; then
        send_batch
      fi
      if [ `$RECCOUNT -gt 0 ]; then BATCH="`$BATCH,"; fi
      BATCH="`$BATCH`$RECORD"
      BATCHSIZE=`$((`$BATCHSIZE + `$RECLEN + 1))
      RECCOUNT=`$((`$RECCOUNT + 1))
    done < "`$f"
  done
  send_batch
done
echo "Done"
"@
    }
    else {
        # Windows PowerShell script
        if ($IsArcConnectedMachine) {
            $tokenBlock = @"
`$ep = 'http://$imdsHost/metadata/identity/oauth2/token?resource=https://monitor.azure.com/&api-version=2020-06-01'
try { Invoke-WebRequest -Uri `$ep -Headers @{Metadata='true'} -UseBasicParsing -ErrorAction Stop } catch { `$ww = `$_.Exception.Response.Headers['WWW-Authenticate'] }
`$sf = (`$ww -split 'Basic realm=')[1] -replace '\r',''
`$sec = Get-Content `$sf -Raw
`$resp = Invoke-WebRequest -Uri `$ep -Headers @{Metadata='True'; Authorization="Basic `$sec"} -UseBasicParsing
`$token = (`$resp.Content | ConvertFrom-Json).access_token
"@
        }
        else {
            $tokenBlock = @"
`$ep = 'http://$imdsHost/metadata/identity/oauth2/token?resource=https://monitor.azure.com/&api-version=2020-06-01'
`$resp = Invoke-WebRequest -Uri `$ep -Headers @{Metadata='True'} -UseBasicParsing
`$token = (`$resp.Content | ConvertFrom-Json).access_token
"@
        }

        # Build entries array for all patterns
        $entriesBlock = "`$entries = @(`n"
        foreach ($entry in $PatternEntries) {
            $anchor = Get-AnchorFromWildcard -SplunkWildcardPathname $entry.Pattern -IsLinuxVm $false
            $fileNamePattern = $entry.Pattern.Substring($entry.Pattern.LastIndexOf('\') + 1)
            $entryUri = "$DceEndpoint/dataCollectionRules/$($entry.DcrImmutableId)/streams/$streamName" + '?api-version=2023-01-01'
            $entriesBlock += "    @{Anchor='$anchor'; Filter='$fileNamePattern'; Like='$($entry.Pattern)'; Uri='$entryUri'}`n"
        }
        $entriesBlock += ")"

        $script = @"
$tokenBlock
if ([string]::IsNullOrEmpty(`$token)) { Write-Host 'ERROR: no token'; exit 1 }
`$computer = '$VMName'
`$authHeaders = @{ 'Content-Type'='application/json'; Authorization="Bearer `$token" }
$entriesBlock
`$maxSize = 950000
function Send-Batch {
    param(`$uri)
    if (`$batch.Count -eq 0) { return }
    `$payload = '[' + (`$batch -join ',') + ']'
    try {
        `$r = Invoke-WebRequest -Uri `$uri -Method Post -Headers `$authHeaders -Body ([System.Text.Encoding]::UTF8.GetBytes(`$payload)) -UseBasicParsing
        Write-Host "Sent `$(`$batch.Count) records, HTTP `$(`$r.StatusCode)"
    } catch {
        Write-Host "Send error: `$(`$_.Exception.Message)"
    }
    `$batch.Clear()
    `$script:batchLen = 0
}
foreach (`$e in `$entries) {
    `$files = @(Get-ChildItem -Path `$e.Anchor -Filter `$e.Filter -Recurse -File -ErrorAction SilentlyContinue | Where-Object { `$_.FullName -like `$e.Like })
    if (`$files.Count -eq 0) { Write-Host "No files match `$(`$e.Like)"; continue }
    `$batch = [System.Collections.Generic.List[string]]::new()
    `$batchLen = 0
    foreach (`$f in `$files) {
        Write-Host "Processing `$(`$f.FullName)"
        foreach (`$line in [System.IO.File]::ReadAllLines(`$f.FullName)) {
            if ([string]::IsNullOrWhiteSpace(`$line)) { continue }
            `$escaped = `$line -replace '\\','\\' -replace '"','\"'
            `$ts = `$line.Split(',')[0]
            `$fp = `$f.FullName -replace '\\','\\'
            `$rec = '{"TimeGenerated":"' + `$ts + '","RawData":"' + `$escaped + '","FilePath":"' + `$fp + '","Computer":"' + `$computer + '"}'
            if ((`$batchLen + `$rec.Length + 2) -gt `$maxSize -and `$batch.Count -gt 0) { Send-Batch -uri `$e.Uri }
            `$batch.Add(`$rec)
            `$script:batchLen += `$rec.Length + 1
        }
    }
    Send-Batch -uri `$e.Uri
}
Write-Host 'Done'
"@
    }

    return $script
}

# Run a single self-contained ingestion script on the VM covering all file patterns.
# Uses one RunCommand per VM (Azure limits concurrent RunCommands to one per VM).
function Invoke-HistoricalLogIngestion {
    param (
        [string]$ResourceGroupName,
        [string]$VMName,
        [array]$PatternEntries,
        [string]$TableName,
        [string]$DceEndpoint,
        [bool]$IsArcConnectedMachine,
        [bool]$IsLinuxVm
    )

    Write-ServerLog -VMName $VMName -Message "Building inline ingestion script for $($PatternEntries.Count) file pattern(s)" -Color Blue

    $script = Build-IngestScript `
        -IsArcConnectedMachine $IsArcConnectedMachine `
        -IsLinuxVm $IsLinuxVm `
        -PatternEntries $PatternEntries `
        -TableName $TableName `
        -DceEndpoint $DceEndpoint `
        -VMName $VMName

    try {
        $job = RunCommand `
            -ResourceGroupName $ResourceGroupName `
            -VMName $VMName `
            -ScriptString $script `
            -IsArcConnectedMachine $IsArcConnectedMachine `
            -IsLinuxVm $IsLinuxVm `
            -IsAsync $true
    }
    catch {
        if (Test-IsPermissionIssue -ErrorRecord $_) {
            Write-PermissionWarning -VMName $VMName -Stage "starting inline ingestion" -ErrorRecord $_ -PermissionHint "This stage uses the signed-in user context and requires run-command permissions on the target server."
        }
        throw
    }

    Write-ServerLog -VMName $VMName -Message "Started ingestion job '$($job.Id)' for $($PatternEntries.Count) pattern(s)" -Color Blue
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

    # Arc VMs: parallel discovery (submit all, wait all, then process results sequentially)
    if ($IsArcConnectedMachine) {
        $vmTypeLabel = "Arc $(if ($IsLinuxVm) { 'Linux' } else { 'Windows' })"
        Write-Host "[$(Format-CurrentLogTime)] Starting parallel discovery for $($VmList.Count) $vmTypeLabel VM(s)" -ForegroundColor Green

        # Phase 1: Submit all discoveries (sequential submission, fast — no waiting)
        $trackers = Submit-ArcDiscoveries -VmList $VmList -SplunkWildcardPaths $SplunkWildcardPaths -IsLinuxVm $IsLinuxVm

        if ($trackers.Count -eq 0) {
            Write-Host "[$(Format-CurrentLogTime)] No Arc discoveries were submitted - skipping" -ForegroundColor Yellow
            return
        }

        # Phase 2: Wait for all discoveries to complete (single polling loop)
        Wait-AllArcDiscoveries -Trackers $trackers

        # Phase 3: Process results sequentially (DCR creation, association, ingestion)
        foreach ($tracker in $trackers) {
            if ($tracker.Failed -or $null -eq $tracker.Result) {
                Write-ServerLog -VMName $tracker.VM.VMName -Message "Skipping - discovery did not succeed" -Color Yellow
                continue
            }

            Process-ArcDiscoveryResult `
                -VM $tracker.VM `
                -DiscoveryResult $tracker.Result `
                -SplunkWildcardPaths $SplunkWildcardPaths `
                -IsLinuxVm $IsLinuxVm
        }

        return
    }

    # Azure VMs: sequential processing (discovery is fast, no benefit from parallelization)
    foreach ($vm in $VmList) {
        $subscriptionId = $vm.SubscriptionId
        $resourceGroup = $vm.ResourceGroup
        $machine = $vm.VMName
        $dceSubscriptionId = $vm.DceSubscriptionId
        $dceName = $vm.DCEName
        $workspaceName = $vm.WorkspaceName
        $tableName = $vm.TableName
        $serverStopwatch = [System.Diagnostics.Stopwatch]::StartNew()

        try {
            try {
                Set-AzContextForSubscription -SubscriptionId $subscriptionId
            }
            catch {
                if (Test-IsPermissionIssue -ErrorRecord $_) {
                    Write-PermissionWarning -VMName $machine -Stage "setting subscription context" -ErrorRecord $_ -PermissionHint "This stage uses the signed-in user context and requires access to subscription '$subscriptionId'."
                }
                throw
            }

            $vmTypeLabel = "$(if ($IsArcConnectedMachine) { 'Arc' } else { 'Azure' }) $(if ($IsLinuxVm) { 'Linux' } else { 'Windows' })"

            Write-ServerLog -VMName $machine -Message "Processing $vmTypeLabel VM in resource group '$resourceGroup' under subscription '$subscriptionId'" -Color Green
            if ($dceSubscriptionId -ne $subscriptionId) {
                Write-ServerLog -VMName $machine -Message "This server uses DCE subscription '$dceSubscriptionId', which differs from the server subscription '$subscriptionId'" -Color DarkCyan
            }

            $cmdTemplateLinux = 'find $anchor -wholename "$path" $pipeline'

            # make big command as run-command is expensive, so do once per server
            $cmds = ""
            foreach ($wildcardPath in $SplunkWildcardPaths) {
                $anchor = Get-AnchorFromWildcard -SplunkWildcardPathname $wildcardPath -IsLinuxVm $IsLinuxVm

                if ($IsLinuxVm) {
                    $regexPattern = Convert-SplunkWildcardToRegex -Pattern $wildcardPath -IsLinuxVm $IsLinuxVm
                    # if path contains a wildcard then use dirname to return the folder name only
                    if ($wildcardPath -match '[\*\?\[\.]') {
                        $pipeline = "| xargs -I {} dirname {} | sort -u"
                    }
                    else {
                        $pipeline = "| sort -u"
                    }
                    if ($wildcardPath -match '\.\.\.') {
                        $cmd = "find $anchor -regextype posix-extended -regex `"$regexPattern`" $pipeline"
                    }
                    else {
                        $cmd = $cmdTemplateLinux `
                            -replace '\$anchor', $anchor `
                            -replace '\$path', $wildcardPath `
                            -replace '\$pipeline', $pipeline
                    }
                }
                else {
                    # Windows: convert Splunk ellipsis '...' to PowerShell-compatible discovery
                    if ($wildcardPath -match '\.\.\.') {
                        # For ellipsis patterns: replace '...' with '*' for -like matching, then use -Recurse from anchor
                        $likePattern = $wildcardPath -replace '\.\.\.', '*'
                        $cmd = "Get-ChildItem -Path '$anchor' -Recurse -Force -ErrorAction SilentlyContinue | Where-Object { `$_.FullName -like '$likePattern' } | ForEach-Object { `$_.Directory.FullName } | Sort-Object -Unique"
                    }
                    elseif ($wildcardPath -match '[\*\?\[]') {
                        # Non-ellipsis wildcard: use -like directly, extract parent directory
                        $cmd = "Get-ChildItem -Path '$anchor' -Recurse -Force -ErrorAction SilentlyContinue | Where-Object { `$_.FullName -like '$wildcardPath' } | ForEach-Object { `$_.Directory.FullName } | Sort-Object -Unique"
                    }
                    else {
                        # No wildcard: just test existence
                        $cmd = "if (Test-Path '$wildcardPath') { '$wildcardPath' }"
                    }
                }
                $cmds += $cmd + "; "
            }

            # create a runCommand function and pass in OS and IsOnPrem parameters
            $result = $null
            $discoveryRunCommandName = if ($IsArcConnectedMachine) { "discover-$(Get-Date -Format 'yyyyMMddHHmmss')" } else { $null }

            # For Arc machines: check agent health and clean up stale run commands before submitting a new one
            if ($IsArcConnectedMachine) {
                $agentHealthy = Test-ArcAgentHealth -ResourceGroupName $resourceGroup -VMName $machine -SubscriptionId $subscriptionId
                if (-not $agentHealthy) {
                    Write-ServerLog -VMName $machine -Message "Skipping server due to unhealthy Arc agent" -Color Red
                    continue
                }
                Remove-StaleArcRunCommands -ResourceGroupName $resourceGroup -VMName $machine -SubscriptionId $subscriptionId
            }

            $discoverySubmittedPhase = if ($IsArcConnectedMachine) { "discovery submitted: $discoveryRunCommandName" } else { 'discovery submitted' }
            Write-PhaseLog -VMName $machine -Phase $discoverySubmittedPhase -Stopwatch $serverStopwatch -Color DarkCyan

            if ($IsTestingMode) {
                # Azure Linux test case
                #$resultArr = ,@('/var/log')
                # Arc Linux Test Case
                #$resultArr = ,@('/var/log/azure/run-command-handler')
                # Arc Windows Text case
                $resultArr = ,@('C:\Logs')
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
                Write-ServerLog -VMName $machine -Message "No output returned from run command - skipping" -Color Yellow
                continue
            }
        }

            Write-PhaseLog -VMName $machine -Phase 'discovery completed' -Stopwatch $serverStopwatch -Color Green

            $profileFilePatterns = @(Build-ServerDcrProfileFilePatterns `
                -VMName $machine `
                -DiscoveredFolders $resultArr `
                -SplunkWildcardPaths $splunkWildcardPaths `
                -IsLinuxVm $IsLinuxVm)

            if ($profileFilePatterns.Count -eq 0) {
                Write-ServerLog -VMName $machine -Message "No DCR file patterns were produced for this server profile - skipping DCR and helper work" -Color Yellow
                continue
            }

            $dcrProfileChunks = Split-ArrayIntoChunks -Items $profileFilePatterns -ChunkSize $maxFilePatternsPerDcr
            if ($dcrProfileChunks.Count -gt 1) {
                Write-ServerLog -VMName $machine -Message "Server profile was split into $($dcrProfileChunks.Count) DCR chunks using a maximum of $maxFilePatternsPerDcr file patterns per DCR" -Color Cyan
            }

            try {
                if ($IsArcConnectedMachine -eq $true) {
                    $vmResourceId = (Get-AzResource -ResourceGroupName $resourceGroup -ResourceName $machine -ResourceType 'Microsoft.HybridCompute/machines').ResourceId
                }
                else {
                    $vmResourceId = (Get-AzResource -ResourceGroupName $resourceGroup -ResourceName $machine -ResourceType 'Microsoft.Compute/virtualMachines').ResourceId
                }
            }
            catch {
                if (Test-IsPermissionIssue -ErrorRecord $_) {
                    Write-PermissionWarning -VMName $machine -Stage 'reading target server resource' -ErrorRecord $_ -PermissionHint "This stage uses the signed-in user context and requires read access to the VM or Arc machine resource in resource group '$resourceGroup'."
                }
                throw
            }

            try {
                Set-AzContextForSubscription -SubscriptionId $dceSubscriptionId
            }
            catch {
                if (Test-IsPermissionIssue -ErrorRecord $_) {
                    Write-PermissionWarning -VMName $machine -Stage 'setting DCE subscription context' -ErrorRecord $_ -PermissionHint "This stage uses the signed-in user context and requires access to subscription '$dceSubscriptionId'."
                }
                throw
            }

            $currentDcrResourceIds = @()
            $allIngestionEntries = @()

            for ($chunkIndex = 0; $chunkIndex -lt $dcrProfileChunks.Count; $chunkIndex++) {
                $chunkPatterns = @($dcrProfileChunks[$chunkIndex])
                if ($dcrProfileChunks.Count -gt 1) {
                    Write-PhaseLog -VMName $machine -Phase "processing DCR profile chunk $($chunkIndex + 1)/$($dcrProfileChunks.Count)" -Stopwatch $serverStopwatch -Color DarkCyan
                }
                Write-ServerLog -VMName $machine -Message "Chunk $($chunkIndex + 1) ordered file patterns: $($chunkPatterns -join ' | ')" -Color DarkCyan

                try {
                    Set-AzContextForSubscription -SubscriptionId $dceSubscriptionId
                    $dcrResult = Ensure-DcrForProfileChunk `
                        -VMName $machine `
                        -DceSubscriptionId $dceSubscriptionId `
                        -DcrResourceGroup $dcrResourceGroup `
                        -DcrLocation $dcrLocation `
                        -DceName $dceName `
                        -WorkspaceName $workspaceName `
                        -TableName $tableName `
                        -IsLinuxVm $IsLinuxVm `
                        -FilePatterns $chunkPatterns

                    $dcr = $dcrResult.DcrResource
                    $currentDcrResourceIds += $dcr.ResourceId
                    $dceResourceId = Get-DceResourceId -DceSubscriptionId $dceSubscriptionId -DcrResourceGroup $dcrResourceGroup -DceName $dceName
                    $dce = Get-AzResource -ResourceId $dceResourceId -ErrorAction Stop
                }
                catch {
                    if (Test-IsPermissionIssue -ErrorRecord $_) {
                        Write-PermissionWarning -VMName $machine -Stage 'resolving DCR profile chunk in the DCE subscription' -ErrorRecord $_ -PermissionHint "This stage uses the signed-in user context and requires access to the DCR/DCE resources in subscription '$dceSubscriptionId'."
                    }
                    throw
                }

                if ($dcrResult.DcrCreated) {
                    Write-PhaseLog -VMName $machine -Phase "DCR created: $($dcr.Name)" -Stopwatch $serverStopwatch -Color Green
                }
                else {
                    Write-PhaseLog -VMName $machine -Phase "DCR reused: $($dcr.Name)" -Stopwatch $serverStopwatch -Color DarkGreen
                }

                try {
                    Set-AzContextForSubscription -SubscriptionId $subscriptionId
                    $associationResult = Ensure-DcrAssociationForResource `
                        -VMName $machine `
                        -VmResourceId $vmResourceId `
                        -DcrResource $dcr
                }
                catch {
                    if (Test-IsPermissionIssue -ErrorRecord $_) {
                        Write-PermissionWarning -VMName $machine -Stage 'ensuring DCR association on the server resource' -ErrorRecord $_ -PermissionHint "This stage uses the signed-in user context and requires permission to create associations on resources in subscription '$subscriptionId'."
                    }
                    throw
                }

                if ($associationResult.AssociationCreated) {
                    Write-PhaseLog -VMName $machine -Phase "association created: $($associationResult.AssociationName)" -Stopwatch $serverStopwatch -Color Green
                }
                else {
                    Write-PhaseLog -VMName $machine -Phase "association reused: $($associationResult.AssociationName)" -Stopwatch $serverStopwatch -Color DarkGreen
                }

                foreach ($dcrFilePattern in $chunkPatterns) {
                    $allIngestionEntries += @{ Pattern = $dcrFilePattern; DcrImmutableId = $dcr.Properties.immutableId }
                }
            }

            # Run a single ingestion RunCommand covering all file patterns for this VM
            if ($allIngestionEntries.Count -gt 0) {
                Set-AzContextForSubscription -SubscriptionId $subscriptionId
                Invoke-HistoricalLogIngestion `
                    -ResourceGroupName $resourceGroup `
                    -VMName $machine `
                    -PatternEntries $allIngestionEntries `
                    -TableName $tableName `
                    -DceEndpoint $dce.Properties.logsIngestion.endpoint `
                    -IsArcConnectedMachine $IsArcConnectedMachine `
                    -IsLinuxVm $IsLinuxVm

                Write-PhaseLog -VMName $machine -Phase "ingestion started: $($allIngestionEntries.Count) pattern(s)" -Stopwatch $serverStopwatch -Color Blue
            }

            # Clean up associations to old DCRs whose patterns are now fully covered
            Set-AzContextForSubscription -SubscriptionId $subscriptionId
            Remove-SupersededDcrAssociations `
                -VMName $machine `
                -VmResourceId $vmResourceId `
                -CurrentDcrResourceIds $currentDcrResourceIds `
                -AllNewFilePatterns $profileFilePatterns
        }
        catch {
            if (Test-IsPermissionIssue -ErrorRecord $_) {
                Write-PermissionWarning -VMName $machine -Stage "processing VM" -ErrorRecord $_ -PermissionHint "This can be caused by missing RBAC for the signed-in user, or by missing permissions expected on the target server identity later in the workflow."
            }
            Write-ServerLog -VMName $machine -Message "Error processing VM: $_" -Color Red
            continue
        }
        finally {
            $serverStopwatch.Stop()
            Write-ServerLog -VMName $machine -Message "Total controller time spent on server: $(Format-ElapsedTime -Stopwatch $serverStopwatch)" -Color Magenta
        }
    }
}

# read the configuration file
$csvPath = if ($null -ne $config.csvPath -and $config.csvPath -ne '') { $config.csvPath } else { './connectedMachinesAndVms.csv' }
$connectedMachinesAndVmsHash = Get-VMListsFromCSV -CsvPath $csvPath

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

