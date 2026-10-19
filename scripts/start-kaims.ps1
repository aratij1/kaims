param(
    [ValidateSet("lean", "observability", "monitoring-authoring", "evaluation", "full")]
    [string]$Profile = "lean",
    [switch]$Build,
    [int]$ReadyTimeoutSeconds = 600,
    [int]$MinimumFreeDiskGB = 10,
    [int]$MaximumRunningContainers = 48,
    [int]$DockerCommandTimeoutSeconds = 900
)

$ErrorActionPreference = "Stop"
$workspace = [System.IO.Path]::GetFullPath((Join-Path $PSScriptRoot ".."))
. (Join-Path $PSScriptRoot 'assert-docker-storage.ps1')
function Invoke-DockerCommand {
    param([string[]]$Arguments, [string]$Description)
    $stdout = Join-Path $env:TEMP ("kaims-docker-{0}.out" -f [guid]::NewGuid())
    $stderr = Join-Path $env:TEMP ("kaims-docker-{0}.err" -f [guid]::NewGuid())
    try {
        $process = Start-Process docker -ArgumentList $Arguments -NoNewWindow -PassThru -RedirectStandardOutput $stdout -RedirectStandardError $stderr
        # Retain the process handle before termination so Windows PowerShell
        # can reliably retrieve the native exit code after waiting.
        $null = $process.Handle
        if (-not $process.WaitForExit($DockerCommandTimeoutSeconds * 1000)) {
            $process.Kill()
            throw "$Description timed out after $DockerCommandTimeoutSeconds seconds. Docker Desktop is saturated; restart Docker Desktop before retrying."
        }
        # WaitForExit(timeout) can observe termination before PowerShell has
        # populated ExitCode and drained redirected output. Complete the
        # synchronous wait before inspecting either result.
        $process.WaitForExit()
        Get-Content $stdout -ErrorAction SilentlyContinue | Write-Host
        Get-Content $stderr -ErrorAction SilentlyContinue | Write-Host
        if ($null -eq $process.ExitCode) {
            throw "$Description ended without a readable exit code."
        }
        if ($process.ExitCode -ne 0) {
            throw "$Description failed with exit code $($process.ExitCode)."
        }
    }
    finally {
        Remove-Item $stdout, $stderr -Force -ErrorAction SilentlyContinue
    }
}
Push-Location $workspace
try {
    # Fail before starting any workload: a full host disk previously made the
    # Docker data filesystem read-only and prevented subsequent startup.
    $workspaceDrive = [System.IO.DriveInfo]::new([System.IO.Path]::GetPathRoot($workspace))
    if ($workspaceDrive.AvailableFreeSpace -lt ($MinimumFreeDiskGB * 1GB)) {
        throw "Insufficient free space on $($workspaceDrive.Name). Free at least $MinimumFreeDiskGB GB before starting KaiMS. Database volumes will not be deleted automatically."
    }
    $env:DOCKER_BUILDKIT = "1"
    Assert-DockerStorageCapacity -MinimumFreeDiskGB $MinimumFreeDiskGB
    $env:COMPOSE_BAKE = "false"
    $env:COMPOSE_PARALLEL_LIMIT = "1"
    docker version --format "Docker engine {{.Server.Version}}"
    if ($LASTEXITCODE -ne 0) { throw "Docker Desktop Linux engine is unavailable." }

    $optionalServices = @(
        "zookeeper", "kafka", "kafka-exporter", "fault-lab",
        "grafana", "temporal-ui", "ui-dev",
        "discovery-service", "metrics-validation-agent", "rule-generation-agent",
        "prometheus-config-service", "validation-agent", "dashboard-generator"
    )
    if ($Profile -eq "lean") {
        # Stop only known optional services. Avoid a project-wide orphan
        # reconciliation, which can touch an unrelated unhealthy core worker.
        Invoke-DockerCommand -Arguments (@("compose", "stop") + $optionalServices) -Description "Optional-service cleanup"
        & (Join-Path $PSScriptRoot "stop-demo-workloads.ps1")
        if ($LASTEXITCODE -ne 0) { throw "Unable to stop demo workloads" }
    }
    $dockerInfo = docker info --format "{{.NCPU}}|{{.MemTotal}}|{{.ContainersRunning}}"
    if ($LASTEXITCODE -ne 0 -or -not $dockerInfo) { throw "Docker engine did not return capacity information." }
    $capacity = $dockerInfo -split "\|"
    $memoryGb = [math]::Round(([double]$capacity[1] / 1GB), 1)
    $runningContainers = [int]$capacity[2]
    Write-Host "Docker capacity after optional-service cleanup: $($capacity[0]) CPU, ${memoryGb} GB, $runningContainers running containers."
    if ($runningContainers -gt $MaximumRunningContainers) {
        throw "Docker is still running $runningContainers containers (safe local limit: $MaximumRunningContainers). Stop overlapping Compose projects, then retry. Run 'docker compose ls' to identify them."
    }
    & (Join-Path $workspace "deploy/monitoring/start.ps1")
    $leanServices = @(
        "mysql", "temporal", "redis", "rabbitmq",
        "mysql-exporter", "node-exporter",
        "jaeger", "otel-collector",
        "monitoring-adapter", "monitoring-ingestion-worker", "application-onboarding", "connector-hub", "cloud-operations",
        "api-gateway", "alert-intelligence", "orchestrator", "context-agent",
        "discovery-mcp", "docker-socket-proxy", "model-router", "resolution-agent",
        "approval-service", "notification-service", "remediation-engine",
        "audit-service", "evaluation-service", "temporal-pilot-worker", "jenkins",
        "closure-service", "knowledge-development-worker", "ui"
    )
    $composeArguments = @("compose")
    if ($Profile -ne "lean") { $composeArguments += @("--profile", $Profile) }
    if ($Build) {
        if ($Profile -eq "lean") {
            & (Join-Path $PSScriptRoot 'build-kaims-images.ps1') -Services $leanServices
        } else {
            & (Join-Path $PSScriptRoot 'build-kaims-images.ps1')
        }
    }
    $composeArguments += @("up", "-d", "--no-build")
    # Let Compose recreate services whose configuration changed, so worker
    # and memory limits apply even when images do not need rebuilding.
    if ($Profile -eq "lean") { $composeArguments += $leanServices }
    Write-Host "Starting KaiMS profile '$Profile'..."
    Invoke-DockerCommand -Arguments $composeArguments -Description "KaiMS startup"

    $deadline = (Get-Date).AddSeconds($ReadyTimeoutSeconds)
    do {
        Start-Sleep -Seconds 3
        try {
            $response = Invoke-WebRequest -UseBasicParsing "http://127.0.0.1:8501/" -TimeoutSec 5
            $ready = $response.StatusCode -eq 200 -and $response.Content -match '<div id="root"></div>'
            if ($ready) {
                # auth/config is static and can succeed while login's database
                # is offline. Readiness must exercise the database connection.
                $databaseReady = Invoke-RestMethod "http://127.0.0.1:8501/api-gateway/readyz" -TimeoutSec 8
                $ready = $databaseReady.status -eq "ready"
            }
            if ($ready) {
                $auth = Invoke-RestMethod "http://127.0.0.1:8501/api-gateway/auth/config" -TimeoutSec 5
                $ready = $auth.mode -in @("local", "oidc")
                if ($ready) {
                    # These back the visible inventory, connector, and evaluation
                    # screens; UI HTML alone does not establish readiness.
                    & docker compose exec -T api-gateway python -c "import urllib.request; [urllib.request.urlopen('http://' + service + ':8000/healthz', timeout=5).close() for service in ('cloud-operations', 'evaluation-service')]" 2>$null
                    $ready = $LASTEXITCODE -eq 0
                }
            }
        }
        catch { $ready = $false }
    } while (-not $ready -and (Get-Date) -lt $deadline)
    if (-not $ready) {
        & docker compose ps
        & docker compose logs --tail 80 api-gateway ui
        throw "KaiMS UI and authentication API did not become ready within $ReadyTimeoutSeconds seconds."
    }
    & docker compose ps @leanServices
    Write-Host "KaiMS is ready: http://127.0.0.1:8501" -ForegroundColor Green
}
finally { Pop-Location }
