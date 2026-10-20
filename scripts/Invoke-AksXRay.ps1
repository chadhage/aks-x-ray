[CmdletBinding()]
param(
    [Parameter(ValueFromRemainingArguments = $true)]
    [object[]] $XRayArguments
)

$ErrorActionPreference = 'Stop'
$entryPoint = Join-Path $PSScriptRoot '..\bin\aks-xray.mjs'
Get-Command node -ErrorAction Stop | Out-Null
# PowerShell parses unquoted CSV arguments as arrays; preserve the CLI's comma syntax.
$forwardedArguments = foreach ($argument in $XRayArguments) {
    if ($argument -is [array]) {
        ($argument | ForEach-Object { [string] $_ }) -join ','
    } else {
        [string] $argument
    }
}
& node $entryPoint @forwardedArguments
exit $LASTEXITCODE
