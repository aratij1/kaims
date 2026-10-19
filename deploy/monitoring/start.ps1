$ErrorActionPreference = 'Stop'
foreach ($network in @('kaims_default', 'opentelemetry-demo')) {
    $existingNetwork = & docker network ls --filter "name=^$([regex]::Escape($network))$" --format '{{.Name}}'
    if ($LASTEXITCODE -ne 0) { throw 'Cannot list Docker networks' }
    if (-not $existingNetwork) {
        & docker network create $network
        if ($LASTEXITCODE -ne 0) { throw "Cannot create network $network" }
    }
}
$composeArgs = @('compose', '--project-name', 'monitoring')
$localEnv = Join-Path $PSScriptRoot 'local.env'
if (Test-Path $localEnv) { $composeArgs += @('--env-file', $localEnv) }
$composeArgs += @('-f', (Join-Path $PSScriptRoot 'compose.yaml'))
$config = (& docker @composeArgs config --format json | ConvertFrom-Json)
if ($LASTEXITCODE -ne 0) { throw 'Invalid monitoring configuration' }
# Refuse a silent data switch if local.env is lost or its mapping changes.
foreach ($service in $config.services.PSObject.Properties) {
    $existingIds = & docker ps -aq --filter "label=com.docker.compose.project=monitoring" --filter "label=com.docker.compose.service=$($service.Name)"
    if ($LASTEXITCODE -ne 0) { throw 'Cannot inspect existing monitoring containers' }
    foreach ($existingId in $existingIds) {
        $existing = @(& docker inspect $existingId | ConvertFrom-Json)[0]
        if ($LASTEXITCODE -ne 0) { throw 'Cannot inspect existing monitoring storage' }
        foreach ($mount in $service.Value.volumes) {
            if ($mount.type -ne 'volume') { continue }
            $expectedName = $config.volumes.($mount.source).name
            $actual = @($existing.Mounts | Where-Object { $_.Destination -eq $mount.target -and $_.Type -eq 'volume' })
            if ($actual.Count -gt 0 -and $actual[0].Name -ne $expectedName) {
                throw "Monitoring storage mismatch for $($service.Name). Restore local.env or migrate the existing volume explicitly before starting."
            }
        }
    }
}
foreach ($volume in $config.volumes.PSObject.Properties) {
    $existingVolume = & docker volume ls --filter "name=^$([regex]::Escape($volume.Value.name))$" --format '{{.Name}}'
    if ($LASTEXITCODE -ne 0) { throw 'Cannot list Docker volumes' }
    if (-not $existingVolume) {
        & docker volume create $volume.Value.name
        if ($LASTEXITCODE -ne 0) { throw 'Cannot create monitoring volume' }
    }
}
& docker @composeArgs up -d --wait --wait-timeout 120
if ($LASTEXITCODE -ne 0) { throw 'Monitoring startup failed' }
# Local container health checks do not detect detached Docker networks.
# Refuse to report readiness when application collectors cannot resolve a source.
foreach ($service in $config.services.PSObject.Properties) {
    $containerId = & docker @composeArgs ps -q $service.Name
    if ($LASTEXITCODE -ne 0 -or -not $containerId) { throw "Missing monitoring container: $($service.Name)" }
    $container = @(& docker inspect $containerId | ConvertFrom-Json)[0]
    if ($LASTEXITCODE -ne 0) { throw "Cannot inspect monitoring connectivity: $($service.Name)" }
    foreach ($network in $service.Value.networks.PSObject.Properties) {
        $networkName = $config.networks.($network.Name).name
        $attachment = $container.NetworkSettings.Networks.PSObject.Properties[$networkName]
        if (-not $attachment -or -not $attachment.Value.EndpointID -or -not $attachment.Value.IPAddress) {
            throw "Monitoring service $($service.Name) is detached from $networkName. Reconnect or recreate it before retrying."
        }
    }
}
Write-Output 'Independent monitoring started: Prometheus :9090, telemetry metrics :19090, Alertmanager :9093'
