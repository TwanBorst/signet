param(
    [string[]]$CertManagerVersions = @("v1.20.5", "v1.21.3")
)
$ErrorActionPreference = "Stop"
$root = (Resolve-Path (Join-Path $PSScriptRoot "..")).Path
$suffix = [Guid]::NewGuid().ToString("N").Substring(0, 8)
$cluster = "signet-$suffix"
$database = "signet-db-$suffix"
$tools = "signet-tools-$suffix"
$artifacts = Join-Path $root ".verification\$suffix"
New-Item -ItemType Directory -Path $artifacts -Force | Out-Null

function Checked {
    param([string]$Program, [string[]]$Arguments)
    & $Program @Arguments
    if ($LASTEXITCODE -ne 0) { throw "$Program failed with exit code $LASTEXITCODE" }
}
function Kind {
    param([string[]]$Arguments)
    Checked "docker" (@("run", "--rm",
        "--mount", "type=bind,source=/var/run/docker.sock,target=/var/run/docker.sock",
        "--mount", "type=volume,source=$tools,target=/tools",
        "--mount", "type=bind,source=$artifacts,target=/artifacts",
        "docker:cli", "/tools/kind") + $Arguments)
}
try {
    & (Join-Path $PSScriptRoot "helm-origins.ps1")
    Checked "docker" @("run", "--rm",
        "--mount", "type=volume,source=$tools,target=/tools",
        "-e", "CGO_ENABLED=0", "-e", "GOBIN=/tools",
        "golang:1.26", "go", "install", "sigs.k8s.io/kind@v0.33.0")
    Kind @("create", "cluster", "--name", $cluster, "--image", "kindest/node:v1.36.4",
        "--kubeconfig", "/artifacts/kubeconfig", "--wait", "120s")
    # Internal credentials are for containers on the dedicated cluster network.
    Checked "docker" @("run", "--rm",
        "--mount", "type=bind,source=/var/run/docker.sock,target=/var/run/docker.sock",
        "--mount", "type=volume,source=$tools,target=/tools",
        "--mount", "type=bind,source=$artifacts,target=/artifacts",
        "docker:cli", "sh", "-c",
        "/tools/kind get kubeconfig --name $cluster --internal > /artifacts/internal-kubeconfig")
    Checked "docker" @("run", "-d", "--name", $database, "--network", "kind",
        "-e", "POSTGRES_PASSWORD=signet-test-only", "-e", "POSTGRES_DB=signet", "postgres:17-alpine")
    $ready = $false
    for ($attempt = 0; $attempt -lt 30; $attempt++) {
        & docker exec $database pg_isready -U postgres | Out-Null
        if ($LASTEXITCODE -eq 0) { $ready = $true; break }
        Start-Sleep -Seconds 1
    }
    if (-not $ready) { throw "Disposable PostgreSQL did not become ready" }
    $go = @("run", "--rm", "--network", "kind",
        "--mount", "type=bind,source=$root,target=/src",
        "--mount", "type=bind,source=$artifacts,target=/artifacts",
        "--mount", "type=volume,source=signet-go-mod,target=/go/pkg/mod",
        "--mount", "type=volume,source=signet-go-build,target=/root/.cache/go-build",
        "-e", "SIGNET_TEST_DATABASE_URL=postgres://postgres:signet-test-only@${database}:5432/signet?sslmode=disable",
        "-w", "/src")
    Checked "docker" ($go + @("golang:1.26", "sh", "-c",
        "go test -race ./internal/... ./cmd/... ./api/... && cd third_party/issuer-lib && go test ./internal/ssaclient"))
    Checked "docker" @("run", "--rm",
        "--mount", "type=bind,source=$root,target=/src", "-w", "/src/ui",
        "node:24", "sh", "-c", "npm ci && npm test -- --run && npm run build && npm audit --audit-level=moderate")
    $kubeconfig = Join-Path $artifacts "kubeconfig"
    Checked "kubectl" @("--kubeconfig", $kubeconfig, "apply", "-f", (Join-Path $root "charts\signet\crds"))
    foreach ($version in $CertManagerVersions) {
        Checked "helm" @("upgrade", "--install", "cert-manager",
            "oci://quay.io/jetstack/charts/cert-manager", "--version", $version,
            "--namespace", "cert-manager", "--create-namespace", "--kubeconfig", $kubeconfig,
            "--set", "crds.enabled=true", "--wait", "--timeout", "5m")
        Checked "docker" ($go + @("-e", "SIGNET_E2E_KUBECONFIG=/artifacts/internal-kubeconfig",
            "golang:1.26", "go", "test", "-v", "./tests/e2e", "-count=1", "-timeout=15m"))
    }
} finally {
    # Only explicitly named resources created by this invocation are removed.
    & docker rm -f $database
    Kind @("delete", "cluster", "--name", $cluster)
    & docker volume rm $tools
    Remove-Item -LiteralPath (Join-Path $artifacts "kubeconfig") -ErrorAction SilentlyContinue
    Remove-Item -LiteralPath (Join-Path $artifacts "internal-kubeconfig") -ErrorAction SilentlyContinue
}
