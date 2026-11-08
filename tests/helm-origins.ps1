$ErrorActionPreference = "Stop"
$chart = Join-Path $PSScriptRoot "..\charts\signet"
$common = @("template", "signet", $chart,
    "--set", "database.secretName=test-db",
    "--set", "networkPolicy.enabled=false",
    "--set-json", 'issuerInstances=[{"kind":"SignetClusterIssuer","name":"manual","namespace":""}]')

function CheckOrigins {
    param([string[]]$Values, [bool]$Accept, [string]$Expected)
    $output = (& helm @common @Values 2>&1 | Out-String).Replace("`r`n", "`n")
    if (($LASTEXITCODE -eq 0) -ne $Accept) {
        throw "Unexpected Helm outcome for $Values`: $output"
    }
    if ($Accept -and -not $output.Contains($Expected)) {
        throw "Missing expected environment configuration: $Expected"
    }
}

CheckOrigins @("--set", "publicOrigin=https://signet.example.com") $true "name: PUBLIC_ORIGIN`n"
CheckOrigins @("--set-json", 'publicOrigins=["https://signet.example.com","https://signet.example.org:8443"]') $true 'value: "[\"https://signet.example.com\",\"https://signet.example.org:8443\"]"'
CheckOrigins @() $false ""
CheckOrigins @("--set", "publicOrigin=https://signet.example.com",
    "--set-json", 'publicOrigins=["https://signet.example.org"]') $false ""
CheckOrigins @("--set-json", 'publicOrigins=["https://signet.example.com","https://signet.example.com"]') $false ""
CheckOrigins @("--set-json", 'publicOrigins=["https://signet.example.com",1]') $false ""
foreach ($origin in @("http://signet.example.com", "https://*.example.com",
    "https://signet.example.com/", "https://user@signet.example.com",
    "https://signet.example.com?", "https://signet.example.com#",
    "https://signet.example.com:0", "https://signet.example.com:65536")) {
    $json = ConvertTo-Json -InputObject @("https://signet.example.org", $origin) -Compress
    CheckOrigins @("--set-json", "publicOrigins=$json") $false ""
}
Write-Output "Helm single/multiple origin configuration and rejection checks passed."
