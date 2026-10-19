param(
    [Parameter(Mandatory = $true)][string]$Config,
    [string]$Output = '',
    [ValidateRange(2, 30)][int]$Seconds = 10,
    [ValidateRange(1, 1000000)][int]$Cycles = 1,
    [string]$Python = ''
)
$ErrorActionPreference = 'Stop'
if (-not $Output) { $Output = Join-Path $PSScriptRoot '..\backend\host-evidence\disk-attribution' }
if (-not $Python) { $Python = Join-Path $PSScriptRoot '..\.venv\Scripts\python.exe' }
$scope = Get-Content -LiteralPath $Config -Raw | ConvertFrom-Json
if ($scope.host_id -ine [Environment]::MachineName) { throw 'Registered host does not match this host' }
if ($scope.host_mount -notmatch '^[A-Za-z]:\\$') { throw 'host_mount must be an exact drive root' }
$Output = $ExecutionContext.SessionState.Path.GetUnresolvedProviderPathFromPSPath($Output)
$Config = $ExecutionContext.SessionState.Path.GetUnresolvedProviderPathFromPSPath($Config)
[IO.Directory]::CreateDirectory($Output) | Out-Null
# Named mutex prevents overlapping host collectors and capture sessions.
$mutex = New-Object Threading.Mutex($false, 'Local\KaiMSDiskAttribution')
if (-not $mutex.WaitOne(0)) { throw 'A disk collector is already running' }
$sessionName = 'KaiMSDisk-' + [guid]::NewGuid().ToString('N').Substring(0, 12)
Add-Type -TypeDefinition @'
using System;
using System.Text;
using System.Runtime.InteropServices;
public static class KaiMSVolume {
 [DllImport("kernel32.dll", CharSet=CharSet.Unicode, SetLastError=true)]
 public static extern uint QueryDosDevice(string name, StringBuilder target, int size);
 [DllImport("kernel32.dll", CharSet=CharSet.Unicode, SetLastError=true)]
 public static extern uint GetCompressedFileSize(string name, out uint high);
}
'@
$native = New-Object Text.StringBuilder 4096
if (-not [KaiMSVolume]::QueryDosDevice($scope.host_mount.Substring(0,2), $native, $native.Capacity)) { throw 'Cannot resolve native volume identity' }
if ($scope.native_volume -ine $native.ToString()) { throw 'Registered native_volume does not match QueryDosDevice' }
function Get-Processes {
    $result = @{}
    Get-Process | ForEach-Object {
        try { $result[[string]$_.Id] = @{ name = $_.ProcessName; started_at = $_.StartTime.ToUniversalTime().ToString('o') } } catch { }
    }
    return $result
}
function Get-TrackedFiles {
    $result = @{}
    foreach ($path in @($scope.tracked_paths | Select-Object -First 32)) {
        $resolved = [IO.Path]::GetFullPath($path)
        if (-not $resolved.StartsWith($scope.host_mount, [StringComparison]::OrdinalIgnoreCase)) { throw 'Tracked file outside registered volume' }
        try {
            $file = Get-Item -LiteralPath $resolved
            if ($file.PSIsContainer -or ($file.Attributes -band [IO.FileAttributes]::ReparsePoint)) { continue }
            [uint32]$high = 0
            $low = [KaiMSVolume]::GetCompressedFileSize($resolved, [ref]$high)
            if ($low -eq [uint32]::MaxValue) { continue }
            $key = ($scope.native_volume.TrimEnd('\') + '\' + $resolved.Substring(3)).ToLowerInvariant()
            $result[$key] = @{ size_bytes = $file.Length; allocated_bytes = ([uint64]$high * 4294967296 + $low); created_at = $file.CreationTimeUtc.ToString('o') }
        } catch { }
    }
    return $result
}
function Get-ExistingFileNames {
    $names = @{}
    $profile = Join-Path $PSScriptRoot '..\deploy\disk-attribution\file-names.wprp'
    $trace = Join-Path $Output 'names.etl'
    $instance = $sessionName + '-names'
    $running = $false
    try {
        $message = & wpr.exe -start ($profile + '!KaiMSFileNames.Light') -instancename $instance 2>&1
        if ($LASTEXITCODE -ne 0) { return @{ names = $names; status = 'unavailable' } }
        $running = $true
        Start-Sleep -Milliseconds 100
        $message = & wpr.exe -stop $trace -skipPdbGen -instancename $instance 2>&1
        if ($LASTEXITCODE -ne 0) { throw 'File-name rundown did not stop cleanly' }
        $running = $false
        if ((Get-Item -LiteralPath $trace).Length -gt 8388608) { throw 'File-name rundown exceeded 8 MB decode limit' }
        Get-WinEvent -Path $trace -Oldest -MaxEvents 100000 | ForEach-Object {
            [xml]$xml = $_.ToXml()
            if ($xml.Event.System.Provider.Guid -eq '{90cbdc39-4a3e-11d1-84f4-0000f80464e3}' -and $xml.Event.System.Opcode -eq '36' -and $names.Count -lt 2048) {
                # FileIo_Name is a pointer followed by a UTF-16 filename. Some
                # Windows builds expose classic MOF events as undecoded payload.
                $hex = [string]$xml.Event.ProcessingErrorData.EventPayload
                if ([Environment]::Is64BitProcess -and $hex.Length -ge 20 -and $hex.Length -le 16384) {
                    $bytes = New-Object byte[] ($hex.Length / 2)
                    for ($i=0; $i -lt $bytes.Length; $i++) { $bytes[$i] = [Convert]::ToByte($hex.Substring($i*2,2),16) }
                    $name = [Text.Encoding]::Unicode.GetString($bytes,8,$bytes.Length-8).TrimEnd([char]0)
                    if ($name.StartsWith($scope.native_volume.TrimEnd('\')+'\', [StringComparison]::OrdinalIgnoreCase)) {
                        $key = '0x' + [BitConverter]::ToUInt64($bytes,0).ToString('x')
                        $names[$key] = $name
                    }
                }
            }
        }
        return @{ names = $names; status = $(if ($names.Count) { 'completed' } else { 'no_matching_names' }) }
    } catch {
        return @{ names = @{}; status = 'unavailable' }
    } finally {
        if ($running) { & wpr.exe -cancel -instancename $instance | Out-Null }
    }
}
try {
    for ($cycle = 0; $cycle -lt $Cycles; $cycle++) {
        $etl = Join-Path $Output 'capture.etl'
        $rawPath = Join-Path $Output 'capture.json'
        $begin = [DateTime]::UtcNow.ToString('o')
        $beforeProcesses = Get-Processes
        $beforeFiles = Get-TrackedFiles
        $volumeBefore = [IO.DriveInfo]::new($scope.host_mount).AvailableFreeSpace
        $existingNames = Get-ExistingFileNames
        $started = $false
        $captureError = $null
        try {
            # Manifest provider: filename/create/write metadata only; no stacks,
            # file contents, network payloads, or process command lines.
            # 4 MB circular trace + 2..8 x 64 KB ETW buffers.
            $nativeOutput = & logman.exe create trace $sessionName -o $etl -p '{edd08927-9cc4-4e65-b970-c2560fb5c289}' 0x2B0 4 -bs 64 -nb 2 8 -f bincirc -max 4 -ow -ets 2>&1
            if ($LASTEXITCODE -ne 0) {
                $captureError = 'ETW unavailable: ' + ($nativeOutput -join ' ')
                Write-Warning $captureError
            } else { $started = $true }
            Start-Sleep -Seconds $Seconds
        } finally {
            if ($started) {
                & logman.exe stop $sessionName -ets | Out-Null
                if ($LASTEXITCODE -ne 0) { throw 'ETW session did not stop cleanly' }
            }
        }
        $afterFiles = Get-TrackedFiles
        $afterProcesses = Get-Processes
        $volumeAfter = [IO.DriveInfo]::new($scope.host_mount).AvailableFreeSpace
        $finish = [DateTime]::UtcNow.ToString('o')
        $stableProcesses = @{}
        foreach ($processIdKey in $afterProcesses.Keys) {
            if ($beforeProcesses.ContainsKey($processIdKey) -and $beforeProcesses[$processIdKey].started_at -eq $afterProcesses[$processIdKey].started_at) {
                $stableProcesses[$processIdKey] = $afterProcesses[$processIdKey]
                $stableProcesses[$processIdKey].stable_identity = $true
            }
        }
        $tracked = @{}
        foreach ($key in $afterFiles.Keys) {
            if ($beforeFiles.ContainsKey($key) -and $beforeFiles[$key].created_at -eq $afterFiles[$key].created_at) {
                $tracked[$key] = @{ before = $beforeFiles[$key]; after = $afterFiles[$key];
                    allocated_bytes_delta = ([long]$afterFiles[$key].allocated_bytes - [long]$beforeFiles[$key].allocated_bytes);
                    size_bytes_delta = ([long]$afterFiles[$key].size_bytes - [long]$beforeFiles[$key].size_bytes);
                    identity_method = 'path_and_creation_time'; writer_exclusivity_proven = $false }
            }
        }
        # Stream ETL decoding; keep <= 8,192 metadata events. Trace ring loss is
        # explicit unknown coverage, never evidence that no other writer existed.
        $events = New-Object 'Collections.Generic.List[object]'
        $readCount = 0
        if (-not $captureError) { Get-WinEvent -Path $etl -Oldest -ErrorAction Stop | ForEach-Object {
            $readCount++
            if ($events.Count -lt 8192 -and $_.ProviderName -eq 'Microsoft-Windows-Kernel-File' -and $_.Id -in @(10,11,12,14,16)) {
                [xml]$xml = $_.ToXml()
                $data = @{}
                foreach ($item in $xml.Event.EventData.Data) { $data[[string]$item.Name] = [string]$item.'#text' }
                $events.Add(@{ event_id = $_.Id; pid = [long]$xml.Event.System.Execution.ProcessID;
                    header_tid = [long]$xml.Event.System.Execution.ThreadID;
                    observed_at = $_.TimeCreated.ToUniversalTime().ToString('o'); data = $data })
            }
        }
        }
        $raw = @{ window_start = $begin; window_end = $finish; events = @($events.ToArray()); processes = $stableProcesses; file_names = $existingNames.names;
            tracked_files = $tracked; volume = @{ available_before = $volumeBefore; available_after = $volumeAfter };
            coverage = @{ events_read = $readCount; event_limit_reached = ($events.Count -ge 8192); events_lost = 'unknown';
                trace_limit_bytes = 4194304; capture_seconds = $Seconds; process_names = 'stable_before_after_only';
                writer_collection = $(if ($captureError) { 'unavailable' } else { 'enabled' }); writer_collection_error = $captureError;
                file_name_rundown = $existingNames.status; existing_file_names = $existingNames.names.Count;
                writes_are_requests = $true; monitored_volume = $scope.host_mount } }
        [IO.File]::WriteAllText($rawPath, ($raw | ConvertTo-Json -Depth 14 -Compress), [Text.UTF8Encoding]::new($false))
        & $Python "$PSScriptRoot\disk_attribution.py" --config $Config --output $Output --windows-input $rawPath
        if ($LASTEXITCODE -ne 0) { throw 'Disk attribution normalization failed' }
    }
} finally {
    $mutex.ReleaseMutex()
    $mutex.Dispose()
}
