param(
    [switch]$Validate,
    [int]$ReadyTimeoutSeconds = 90,
    [switch]$KeepDemoWorkloads
)

$ErrorActionPreference = "Stop"
. (Join-Path $PSScriptRoot 'assert-docker-storage.ps1')
$RepoRoot = Resolve-Path (Join-Path $PSScriptRoot "..")
Push-Location $RepoRoot
try {
    Assert-DockerStorageCapacity
    $env:DOCKER_BUILDKIT = "1"
    $env:COMPOSE_BAKE = "false"
    $env:COMPOSE_PARALLEL_LIMIT = "1"
    $env:BUILDKIT_STEP_LOG_MAX_SIZE = "10485760"

    docker version --format "Docker engine {{.Server.Version}}"
    if ($LASTEXITCODE -ne 0) { throw "Docker Desktop Linux engine is unavailable. Start Docker Desktop and retry." }

    if (-not $KeepDemoWorkloads) {
        & (Join-Path $PSScriptRoot "stop-demo-workloads.ps1")
        if ($LASTEXITCODE -ne 0) { throw "Unable to pause optional demo workloads before the UI build." }
    }

    if ($Validate) {
        docker run --rm `
            -v "${RepoRoot}\frontend\react:/app" `
            -v "kaiops_ui_node_modules:/app/node_modules" `
            -v "kaiops_ui_npm_cache:/root/.npm" `
            -w /app node:20-alpine `
            sh -lc "npm ci --prefer-offline --no-audit --no-fund && npm run typecheck && npm run test:unit && npm run build:budget"
        if ($LASTEXITCODE -ne 0) { throw "Frontend validation failed." }
    }

    docker compose build ui
    if ($LASTEXITCODE -ne 0) {
        throw "UI image build failed. The Dockerfile requires BuildKit; the existing UI image is preserved."
    }
    docker compose up -d --force-recreate --no-deps ui
    if ($LASTEXITCODE -ne 0) { throw "UI container start failed." }

    $deadline = (Get-Date).AddSeconds($ReadyTimeoutSeconds)
    do {
        Start-Sleep -Seconds 2
        try {
            $response = Invoke-WebRequest -UseBasicParsing "http://127.0.0.1:8501/" -TimeoutSec 5
            $status = $response.StatusCode
            if ($response.Content -notmatch '<div id="root"></div>') { $status = 0 }
        }
        catch { $status = 0 }
    } while ($status -ne 200 -and (Get-Date) -lt $deadline)

    if ($status -ne 200) { throw "UI did not become ready within $ReadyTimeoutSeconds seconds." }
    Write-Host "KaiMS UI is ready: http://127.0.0.1:8501" -ForegroundColor Green
}
finally {
    Pop-Location
}
