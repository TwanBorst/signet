$ErrorActionPreference = "Stop"
$chart = Join-Path $PSScriptRoot "..\charts\signet"
$common = @("template", "signet", $chart,
    "--set", "database.secretName=test-db",
    "--set", "networkPolicy.enabled=false")

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
CheckOrigins @("--set", "publicOrigin=https://signet.example.com",
    "--set", "database.port=5433") $true 'name: DATABASE_URL'
$individual = @("--set", "database.secretName=", "--set", "database.host=db.example.com",
    "--set", "database.name=signet", "--set", "database.username=signet",
    "--set", "database.passwordSecretName=db-password", "--set", "database.passwordSecretKey=passwd",
    "--set", "database.port=5433", "--set", "database.caSecretName=db-ca",
    "--set", "publicOrigin=https://signet.example.com")
foreach ($expected in @('name: DATABASE_HOST', 'value: "db.example.com"', 'name: DATABASE_NAME',
    'name: DATABASE_USERNAME', 'name: DATABASE_PORT', 'value: "5433"', 'name: DATABASE_PASSWORD',
    'name: "db-password"', 'key: "passwd"', 'name: DATABASE_SSLROOTCERT',
    'value: /etc/signet/db-ca/ca.crt')) {
    CheckOrigins $individual $true $expected
}
CheckOrigins ($individual + @("--set", "database.secretName=test-db")) $false ""
CheckOrigins ($individual + @("--set", "database.username=")) $false ""
CheckOrigins ($individual + @("--set", "database.passwordSecretName=")) $false ""
CheckOrigins ($individual + @("--set", "database.port=65536")) $false ""
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

function ScopeManifest {
    param([string[]]$Values, [bool]$Accept = $true)
    $output = (& helm @common --namespace signet --set publicOrigin=https://signet.example.com @Values 2>&1 | Out-String).Replace("`r`n", "`n")
    if (($LASTEXITCODE -eq 0) -ne $Accept) {
        throw "Unexpected deployment scope outcome for $Values`: $output"
    }
    return $output
}

$namespaced = ScopeManifest @()
foreach ($expected in @('runAsNonRoot: true', 'type: RuntimeDefault',
    'allowPrivilegeEscalation: false', 'readOnlyRootFilesystem: true', 'drop: ["ALL"]')) {
    if (-not $namespaced.Contains($expected)) { throw "Missing Pod security setting: $expected" }
}
if ($namespaced -match '(?m)^\s+(runAsUser|runAsGroup|fsGroup):') {
    throw "Chart must allow OpenShift SCC admission to assign namespace-specific IDs"
}
foreach ($expected in @('kind: Role', 'kind: RoleBinding', 'namespace: signet',
    'resources: ["signetissuers"]', 'name: WATCH_NAMESPACE', 'value: "signet"',
    'name: DEPLOYMENT_MODE', 'value: "namespace"', '"signetissuers.signet.io/*"')) {
    if (-not $namespaced.Contains($expected)) { throw "Missing namespaced scope configuration: $expected" }
}
if ($namespaced.Contains("signetclusterissuers") -or $namespaced.Contains("ISSUER_INSTANCES")) {
    throw "Namespace deployment must not grant or configure cluster issuer access"
}
$clusterRoles = @($namespaced -split '(?m)^---\n' | Where-Object { $_ -match '(?m)^kind: ClusterRole$' })
if ($clusterRoles.Count -ne 1 -or $clusterRoles[0].Contains('certificaterequests') -or
    -not $clusterRoles[0].Contains('resources: ["signers"]')) {
    throw "Namespace deployment must only grant cluster-scoped signer approval"
}
$custom = ScopeManifest @("--set", "deployment.namespace=team-a")
if ($custom -notmatch 'kind: Role\nmetadata:\n  name: [^\n]+\n  namespace: team-a' -or
    $custom -notmatch 'kind: RoleBinding\nmetadata:\n  name: [^\n]+\n  namespace: team-a' -or
    $custom -notmatch 'name: WATCH_NAMESPACE\n\s+value: "team-a"' -or
    $custom -notmatch 'kind: ServiceAccount\n\s+name: [^\n]+\n\s+namespace: signet') {
    throw "Custom watch namespace must scope the Role, RoleBinding and environment, not the ServiceAccount"
}
$clusterScope = ScopeManifest @("--set", "deployment.mode=cluster")
foreach ($expected in @('value: "cluster"', '"signetissuers.signet.io/*"', '"signetclusterissuers.signet.io/*"',
    'resources: ["signetissuers","signetclusterissuers"]',
    'resources: ["signetissuers/status","signetclusterissuers/status"]')) {
    if (-not $clusterScope.Contains($expected)) { throw "Missing cluster scope configuration: $expected" }
}
if ($clusterScope.Contains("WATCH_NAMESPACE") -or $clusterScope -match '(?m)^kind: Role(Binding)?$') {
    throw "Cluster deployment must not configure namespace-only watches or RBAC"
}
$null = ScopeManifest @("--set", "deployment.mode=invalid") $false
$null = ScopeManifest @("--set", "deployment.mode=cluster", "--set", "deployment.namespace=team-a") $false
$null = ScopeManifest @("--set", "deployment.namespace=Team_A") $false
$null = ScopeManifest @("--set-json", 'issuerInstances=[]') $false
Write-Output "Helm deployment scope, RBAC and legacy configuration rejection checks passed."

foreach ($case in @(
    @{ Release = "signet"; Name = "signet" },
    @{ Release = "prod-signet"; Name = "prod-signet" },
    @{ Release = "signet-prod"; Name = "signet-prod" },
    @{ Release = "prod"; Name = "prod-signet" },
    @{ Release = ("x" * 53); Name = (("x" * 53) + "-signet") }
)) {
    foreach ($mode in @("namespace", "cluster")) {
        $arguments = $common.Clone()
        $arguments[1] = $case.Release
        $output = (& helm @arguments --namespace release-ns --set publicOrigin=https://signet.example.com `
            --set "deployment.mode=$mode" --set networkPolicy.enabled=true `
            --set-json 'networkPolicy.ingressFrom=[{"namespaceSelector":{"team":"gateway"},"podSelector":{"app":"proxy"}}]' `
            --set-json 'networkPolicy.postgres.cidrs=["192.0.2.10/32"]' `
            --set-json 'networkPolicy.apiServer.cidrs=["192.0.2.20/32"]' 2>&1 | Out-String).Replace("`r`n", "`n")
        if ($LASTEXITCODE -ne 0) { throw "Naming render failed for $($case.Release): $output" }
        $documents = @($output -split '(?m)^---\n' | Where-Object { $_ -match '(?m)^kind:' })
        $roleKind = if ($mode -eq "cluster") { "ClusterRole" } else { "Role" }
        $resourceCount = 0
        foreach ($document in $documents) {
            $kind = [regex]::Match($document, '(?m)^kind: (\S+)$').Groups[1].Value
            $name = [regex]::Match($document, '(?m)^metadata:\n  name: (\S+)$').Groups[1].Value
            if ($kind -in @("Deployment", "Service", "ServiceAccount", "NetworkPolicy")) {
                if ($name -ne $case.Name -or $name.Length -gt 63 -or $name.EndsWith("-")) {
                    throw "Unexpected $kind name for $($case.Release): $name"
                }
                $resourceCount++
            } elseif ($kind -in @("Role", "ClusterRole", "RoleBinding", "ClusterRoleBinding")) {
                $workloadName = "$($case.Name)-release-ns"
                $approvalName = "$workloadName-approve"
                if ($name -notin @($workloadName, $approvalName)) {
                    throw "Unexpected RBAC name: $name"
                }
                if ($kind.EndsWith("Binding")) {
                    $referenceKind = if ($name -eq $approvalName) { "ClusterRole" } else { $roleKind }
                    $reference = "roleRef:`n  apiGroup: rbac.authorization.k8s.io`n  kind: $referenceKind`n  name: $name"
                    $subject = "subjects:`n  - kind: ServiceAccount`n    name: $($case.Name)`n    namespace: release-ns"
                    if (-not $document.Contains($reference) -or -not $document.Contains($subject)) {
                        throw "RBAC references do not match rendered resources: $name"
                    }
                }
            }
        }
        if ($resourceCount -ne 4 -or -not $output.Contains("serviceAccountName: $($case.Name)`n")) {
            throw "Missing named resources or Deployment ServiceAccount reference"
        }
        if (-not $output.Contains('app.kubernetes.io/name: signet') -or
            -not $output.Contains("app.kubernetes.io/instance: `"$($case.Release)`"")) {
            throw "Resource naming must preserve selector labels"
        }
    }
}
Write-Output "Helm resource names and cross-resource reference checks passed."

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
