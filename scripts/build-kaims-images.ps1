param([string[]]$Services = @())

$ErrorActionPreference = 'Stop'
. (Join-Path $PSScriptRoot 'assert-docker-storage.ps1')
$workspace = [IO.Path]::GetFullPath((Join-Path $PSScriptRoot '..'))
Push-Location $workspace
try {
    $env:DOCKER_BUILDKIT = '1'
    $env:COMPOSE_BAKE = 'false'
    $env:COMPOSE_PARALLEL_LIMIT = '1'
    Assert-DockerStorageCapacity
    $config = & docker compose config --format json | ConvertFrom-Json
    if ($LASTEXITCODE -ne 0) { throw 'Invalid Compose configuration' }
    $built = @{}
    foreach ($property in $config.services.PSObject.Properties) {
        $name = $property.Name
        $service = $property.Value
        if (-not $service.build -or ($Services.Count -and $name -notin $Services)) { continue }
        $signature = $service.build | ConvertTo-Json -Depth 30 -Compress
        $image = if ($service.image) { $service.image } else { "$($config.name)-$name" }
        if (-not $built.ContainsKey($signature)) {
            Assert-DockerStorageCapacity
            Write-Host "Building $name once for its shared build definition..."
            & docker compose build $name
            if ($LASTEXITCODE -ne 0) { throw "Image build failed: $name" }
            $built[$signature] = $image
        } elseif ($image -ne $built[$signature]) {
            & docker tag $built[$signature] $image
            if ($LASTEXITCODE -ne 0) { throw "Cannot tag shared image for $name" }
        }
        Write-Host "Image ready: $image ($name)"
    }
    Write-Host "Built $($built.Count) distinct image definitions sequentially. Data volumes were preserved."
} finally {
    Pop-Location
}
