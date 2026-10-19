param([switch]$RebuildFrontend)
$ErrorActionPreference = 'Stop'
$repoRoot = (Resolve-Path (Join-Path $PSScriptRoot '../..')).Path
. (Join-Path $repoRoot 'scripts/assert-docker-storage.ps1')
Assert-DockerStorageCapacity
$sourceRoot = Join-Path $repoRoot 'external/telemetry/opentelemetry-demo'
if (-not (Test-Path (Join-Path $sourceRoot 'compose.yaml'))) {
    throw 'OpenTelemetry demo source is missing; restore external/telemetry/opentelemetry-demo first.'
}
$composeArgs = @('compose', '--parallel', '2', '--project-name', 'telemetry',
    '--env-file', (Join-Path $sourceRoot '.env'),
    '-f', (Join-Path $sourceRoot 'compose.yaml'),
    '-f', (Join-Path $PSScriptRoot 'compose.observability.yaml'),
    '-f', (Join-Path $PSScriptRoot 'compose.kaiops.yaml'),
    '-f', (Join-Path $PSScriptRoot 'compose.local.yaml'))
function Invoke-DockerChecked {
    param([string[]]$DockerArgs)
    & docker @DockerArgs
    if ($LASTEXITCODE -ne 0) { throw "Docker failed with exit code $LASTEXITCODE" }
}
& (Join-Path $repoRoot 'deploy/monitoring/start.ps1')
$localImageId = & docker image ls --quiet telemetry-local/frontend:20260911
if ($RebuildFrontend -or -not $localImageId) {
    Invoke-DockerChecked -DockerArgs @('build', '-t', 'telemetry-local/frontend:20260911', '-f', (Join-Path $sourceRoot 'src/frontend/Dockerfile'), $sourceRoot)
}
Invoke-DockerChecked -DockerArgs ($composeArgs + @('config', '--quiet'))
Invoke-DockerChecked -DockerArgs ($composeArgs + @('up', '-d', '--no-build', 'opensearch'))
$deadline = (Get-Date).AddMinutes(3)
do {
    $ready = $false
    try {
        $health = Invoke-RestMethod 'http://localhost:9200/_cluster/health' -TimeoutSec 5
        $ready = $health.status -in @('green', 'yellow')
    } catch { }
    if (-not $ready) { Start-Sleep -Seconds 3 }
} while (-not $ready -and (Get-Date) -lt $deadline)
if (-not $ready) { throw 'Telemetry OpenSearch did not become ready.' }
$template = Get-Content (Join-Path $PSScriptRoot 'opensearch-log-template.json') -Raw
Invoke-RestMethod -Method Put -Uri 'http://localhost:9200/_index_template/telemetry-logs-v2' -ContentType 'application/json' -Body $template | Out-Null
Invoke-DockerChecked -DockerArgs ($composeArgs + @('up', '-d', '--no-build', '--wait', '--wait-timeout', '180'))
Write-Output 'Telemetry started. Application: http://localhost:18080'
