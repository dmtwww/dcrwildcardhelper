$scriptPath = Join-Path $PSScriptRoot 'dcrwildcardhelper.ps1'
$scriptContent = Get-Content -Path $scriptPath -Raw
$entryPointMarker = '# read the configuration file'
$entryPointIndex = $scriptContent.IndexOf($entryPointMarker)

if ($entryPointIndex -lt 0) {
    throw 'Unable to locate the helper function boundary in dcrwildcardhelper.ps1.'
}

$helpersOnly = $scriptContent.Substring(0, $entryPointIndex)
Invoke-Expression $helpersOnly

$matchCases = @(
    @{ Pattern = '/var/.../*.log'; Path = '/var/log/test.log'; IsLinux = $true; Expected = $true },
    @{ Pattern = '/var/log/.../*.log'; Path = '/var/log/test.log'; IsLinux = $true; Expected = $false },
    @{ Pattern = '/var/log/.../*.log'; Path = '/var/log/sub/test.log'; IsLinux = $true; Expected = $true },
    @{ Pattern = '/foo/*/bar'; Path = '/foo/1/bar'; IsLinux = $true; Expected = $true },
    @{ Pattern = '/foo/*/bar'; Path = '/foo/1/2/bar'; IsLinux = $true; Expected = $false },
    @{ Pattern = '/foo/*.log'; Path = '/foo/a.log'; IsLinux = $true; Expected = $true },
    @{ Pattern = '/foo/*.log'; Path = '/foo/sub/a.log'; IsLinux = $true; Expected = $false },
    @{ Pattern = '/var/log()/log*.log'; Path = '/var/log()/loga.log'; IsLinux = $true; Expected = $true },
    @{ Pattern = '/var/log()/log(a|b)*.log'; Path = '/var/log()/loga1.log'; IsLinux = $true; Expected = $true },
    @{ Pattern = '/var/log()/log(a|b)*.log'; Path = '/var/log()/logc1.log'; IsLinux = $true; Expected = $false },
    @{ Pattern = '/var/.../log(a|b).log'; Path = '/var/tmp/loga.log'; IsLinux = $true; Expected = $true },
    @{ Pattern = '/var/.../log(a|b).log'; Path = '/var/tmp/logc.log'; IsLinux = $true; Expected = $false },
    @{ Pattern = 'C:\foo\*\bar'; Path = 'C:\foo\1\bar'; IsLinux = $false; Expected = $true },
    @{ Pattern = 'C:\foo\*\bar'; Path = 'C:\foo\1\2\bar'; IsLinux = $false; Expected = $false },
    @{ Pattern = 'C:\foo\*.log'; Path = 'C:\foo\a.log'; IsLinux = $false; Expected = $true },
    @{ Pattern = 'C:\foo\*.log'; Path = 'C:\foo\sub\a.log'; IsLinux = $false; Expected = $false }
)

foreach ($case in $matchCases) {
    $actual = Test-SplunkPathMatch -Path $case.Path -Pattern $case.Pattern -IsLinuxVm $case.IsLinux
    if ($actual -ne $case.Expected) {
        throw "Match assertion failed for pattern '$($case.Pattern)' and path '$($case.Path)'. Expected $($case.Expected), got $actual."
    }
}

$filePatternCases = @(
    @{ Folder = '/apache/foo/logs'; Patterns = @('/apache/*/logs'); IsLinux = $true; Expected = '/apache/foo/logs' },
    @{ Folder = '/var/log'; Patterns = @('/var/log/waagent*.log'); IsLinux = $true; Expected = '/var/log/waagent*.log' },
    @{ Folder = '/var/log/sub'; Patterns = @('/var/.../*.log'); IsLinux = $true; Expected = '/var/log/sub/*.log' },
    @{ Folder = 'C:\Logs'; Patterns = @('C:\Logs\Sample*.log'); IsLinux = $false; Expected = 'C:\Logs\Sample*.log' }
)

foreach ($case in $filePatternCases) {
    $actual = Get-FirstDcrFilePattern -Folder $case.Folder -splunkWildcardPaths $case.Patterns -IsLinuxVm $case.IsLinux
    if ($actual -ne $case.Expected) {
        throw "DCR pattern assertion failed for folder '$($case.Folder)'. Expected '$($case.Expected)', got '$actual'."
    }
}

Write-Host 'Splunk wildcard matching checks passed.' -ForegroundColor Green