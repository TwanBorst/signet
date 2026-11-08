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
CheckOrigins @("--set", "publicOrigin=https://signet.example.com",
    "--set", "database.secretKey=connection-string") $true 'key: "connection-string"'
CheckOrigins @("--set", "publicOrigin=https://signet.example.com",
    "--set", "database.secretKey=") $false ""
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

$destination = Join-Path (Join-Path $PSScriptRoot "..\.verification") ("chart-" + [Guid]::NewGuid().ToString("N"))
New-Item -ItemType Directory -Path $destination -Force | Out-Null
$archive = Join-Path $destination "signet-0.2.3.tgz"
try {
    & helm package $chart --version 0.2.3 --app-version 0.2.3 --destination $destination
    if ($LASTEXITCODE -ne 0) { throw "Chart packaging failed" }
    $metadata = & helm show chart $archive | Out-String
    if ($LASTEXITCODE -ne 0 -or $metadata -notmatch '(?m)^version: 0\.2\.3\r?$' -or $metadata -notmatch '(?m)^appVersion: "?0\.2\.3"?\r?$') {
        throw "Packaged chart version does not match release"
    }
    $original = $common[2]
    $common[2] = $archive
    CheckOrigins @("--set", "publicOrigin=https://signet.example.com") $true 'image: "ghcr.io/twanborst/signet:0.2.3"'
    CheckOrigins @("--set", "publicOrigin=https://signet.example.com",
        "--set", "image.repository=signet", "--set", "image.tag=local") $true 'image: "signet:local"'
    $common[2] = $original
} finally {
    Remove-Item -LiteralPath $archive -ErrorAction SilentlyContinue
    Remove-Item -LiteralPath $destination
}
Write-Output "Packaged chart version and default/override image checks passed."
