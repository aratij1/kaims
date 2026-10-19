function Assert-DockerStorageCapacity {
    param([int]$MinimumFreeDiskGB = 10)
    # Docker Desktop can store its VHD on a different drive from the checkout.
    # Check that host drive; guest `df` reports the VHD's virtual capacity.
    $settingsPath = Join-Path $env:APPDATA 'Docker\settings-store.json'
    $dataRoot = Join-Path $env:LOCALAPPDATA 'Docker\wsl'
    if (Test-Path -LiteralPath $settingsPath) {
        $dockerSettings = Get-Content -LiteralPath $settingsPath -Raw | ConvertFrom-Json
        if ($dockerSettings.CustomWslDistroDir) {
            $dataRoot = [string]$dockerSettings.CustomWslDistroDir
        }
    }
    $driveRoot = [IO.Path]::GetPathRoot([IO.Path]::GetFullPath($dataRoot))
    $drive = [IO.DriveInfo]::new($driveRoot)
    if ($drive.AvailableFreeSpace -lt ($MinimumFreeDiskGB * 1GB)) {
        throw "Docker storage drive $driveRoot has less than $MinimumFreeDiskGB GB free. Reclaim storage before starting or rebuilding KaiMS. Database volumes will not be deleted automatically."
    }
}
