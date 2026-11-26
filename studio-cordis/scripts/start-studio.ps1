# Fail-closed PktPath Studio launcher (pure Cordis Wave 1 / WAVE1-CONTRACT.md v1.2).
# SHA256 of frozen contract: 34c55d3fcfe32186a9c714e8b447bbfa9828cf5960ee078f861eb6fca286fc97
# Double-click entry is start-studio.cmd. If execution policy blocks this file:
#   powershell -NoProfile -ExecutionPolicy Bypass -File ".\start-studio.ps1"
# Never calls a Go Studio binary or a desktop window shell, never falls back to PATH Node.
# Official bundled Node v24.22.1 win-x64 node.exe SHA256 is pinned below and checked on Windows.
$ErrorActionPreference = "Stop"
try { [Console]::OutputEncoding = [System.Text.Encoding]::UTF8 } catch {}

# --- Frozen v1.2 launch constants (unchanged from v1.1 section 5) ---
$OfficialNodeExeSha256 = "d702daa815eabbff763c7d3808e235cf031cf2ca70211b56847bc72f51e240e5"
$EntryRel = "studio-cordis\src\main.ts"
$WebIndexRel = "studio-cordis\web\index.html"
$CordisCoreRel = "studio-cordis\node_modules\@cordisjs\core\package.json"
$CollectorsRel = "collectors"
$AndroidCollectorRel = "collectors\android-arm64\pktpath"
$DefaultHost = "127.0.0.1"
$HealthPath = "/api/health"
$QuitPath = "/api/app/quit"
$ReadyPrefix = "PKTPATH_STUDIO_READY"
$AppDirName = "PktPathStudio"
$ReadyTimeoutMs = 20000
$QuitWaitMs = 8000
$ForceKillWaitMs = 3000

function Fail([int]$Code, [string]$Message) {
    [Console]::Error.WriteLine($Message)
    exit $Code
}

function Get-WinArgvQuoted([string]$Value) {
    if ($null -eq $Value) { return '""' }
    if ($Value -notmatch '[ \t\n\v"]') { return $Value }
    $sb = New-Object System.Text.StringBuilder
    [void]$sb.Append('"')
    $slashes = 0
    foreach ($ch in $Value.ToCharArray()) {
        if ($ch -eq [char]0x5C) { $slashes++; continue }
        if ($ch -eq [char]'"') {
            [void]$sb.Append(('\' * (2 * $slashes + 1)))
            [void]$sb.Append('"')
            $slashes = 0
            continue
        }
        if ($slashes -gt 0) { [void]$sb.Append(('\' * $slashes)); $slashes = 0 }
        [void]$sb.Append($ch)
    }
    if ($slashes -gt 0) { [void]$sb.Append(('\' * (2 * $slashes))) }
    [void]$sb.Append('"')
    return $sb.ToString()
}

function Get-WinArgvJoined([string[]]$Parts) {
    $bits = New-Object System.Collections.Generic.List[string]
    foreach ($part in $Parts) { [void]$bits.Add((Get-WinArgvQuoted $part)) }
    return [string]::Join(" ", $bits)
}

function Parse-LaunchArgs([string[]]$Raw) {
    $parsed = @{
        Stop          = $false
        Foreground    = $false
        NoOpen        = $false
        Help          = $false
        Host          = $null
        Port          = $null
        AppDir        = $null
        CollectorsDir = $null
        WebDir        = $null
        Forward       = New-Object System.Collections.Generic.List[string]
    }
    $i = 0
    while ($i -lt $Raw.Count) {
        $a = $Raw[$i]
        switch -Regex ($a) {
            '^(--stop|-Stop)$' { $parsed.Stop = $true; $i++; continue }
            '^(--foreground|-Foreground)$' { $parsed.Foreground = $true; $i++; continue }
            '^(--no-open|--no-browser|-NoOpen|-NoBrowser)$' { $parsed.NoOpen = $true; $i++; continue }
            '^(--help|-h|-Help)$' { $parsed.Help = $true; $i++; continue }
            '^--host=(.*)$' { $parsed.Host = $Matches[1]; $i++; continue }
            '^(--host|-Host)$' {
                if ($i + 1 -ge $Raw.Count) { Fail 2 "缺少 --host 参数值。" }
                $parsed.Host = $Raw[$i + 1]; $i += 2; continue
            }
            '^--port=(.*)$' { $parsed.Port = $Matches[1]; $i++; continue }
            '^(--port|-Port)$' {
                if ($i + 1 -ge $Raw.Count) { Fail 2 "缺少 --port 参数值。" }
                $parsed.Port = $Raw[$i + 1]; $i += 2; continue
            }
            '^--app-dir=(.*)$' { $parsed.AppDir = $Matches[1]; $i++; continue }
            '^(--app-dir)$' {
                if ($i + 1 -ge $Raw.Count) { Fail 2 "缺少 --app-dir 参数值。" }
                $parsed.AppDir = $Raw[$i + 1]; $i += 2; continue
            }
            '^--collectors-dir=(.*)$' { $parsed.CollectorsDir = $Matches[1]; $i++; continue }
            '^(--collectors-dir)$' {
                if ($i + 1 -ge $Raw.Count) { Fail 2 "缺少 --collectors-dir 参数值。" }
                $parsed.CollectorsDir = $Raw[$i + 1]; $i += 2; continue
            }
            '^--web-dir=(.*)$' { $parsed.WebDir = $Matches[1]; $i++; continue }
            '^(--web-dir)$' {
                if ($i + 1 -ge $Raw.Count) { Fail 2 "缺少 --web-dir 参数值。" }
                $parsed.WebDir = $Raw[$i + 1]; $i += 2; continue
            }
            default { [void]$parsed.Forward.Add($a); $i++; continue }
        }
    }
    return $parsed
}

function Show-Usage {
    Write-Host "PktPath Studio 启动器"
    Write-Host ""
    Write-Host "请先将组合包完整解压，再双击 start-studio.cmd（不要在压缩包预览中直接运行）。"
    Write-Host "启动成功后会打开系统默认浏览器。本机不会做数据包采集。"
    Write-Host "停止服务：双击 stop-studio.cmd，或运行 start-studio.cmd --stop"
    Write-Host "排障时前台运行：start-studio.cmd --foreground"
}

function Get-DefaultAppDir {
    if ($env:PKTPATH_APP_DIR -and $env:PKTPATH_APP_DIR.Trim() -ne "") {
        return $env:PKTPATH_APP_DIR
    }
    if ($env:LOCALAPPDATA -and $env:LOCALAPPDATA.Trim() -ne "") {
        return (Join-Path $env:LOCALAPPDATA $AppDirName)
    }
    return (Join-Path $env:USERPROFILE (Join-Path "AppData\Local" $AppDirName))
}

function Get-RuntimePath([string]$AppDir) {
    return (Join-Path (Join-Path $AppDir "logs") "launcher-runtime.json")
}

function Ensure-Dir([string]$PathToDir) {
    if (-not (Test-Path -LiteralPath $PathToDir -PathType Container)) {
        New-Item -ItemType Directory -Path $PathToDir -Force | Out-Null
    }
}

function Test-RequiredFiles([string]$Here) {
    $node = Join-Path $Here "node\node.exe"
    $entry = Join-Path $Here $EntryRel
    $webIdx = Join-Path $Here $WebIndexRel
    $cordisPkg = Join-Path $Here $CordisCoreRel
    $androidBin = Join-Path $Here $AndroidCollectorRel
    if (-not (Test-Path -LiteralPath $node -PathType Leaf)) {
        Fail 1 "缺少随包 Node（node\node.exe），拒绝启动，不会回退到 PATH。"
    }
    if (-not (Test-Path -LiteralPath $entry -PathType Leaf)) {
        Fail 1 "缺少 Studio 入口（studio-cordis\src\main.ts），拒绝启动。"
    }
    if (-not (Test-Path -LiteralPath $webIdx -PathType Leaf)) {
        Fail 1 "缺少前端页面（studio-cordis\web\index.html），拒绝启动。"
    }
    if (-not (Test-Path -LiteralPath $cordisPkg -PathType Leaf)) {
        Fail 1 "缺少 @cordisjs/core（studio-cordis\node_modules\@cordisjs\core\package.json），拒绝启动。"
    }
    if (-not (Test-Path -LiteralPath $androidBin -PathType Leaf)) {
        Fail 1 "缺少 Android 采集器（collectors\android-arm64\pktpath），拒绝启动。"
    }
    return @{
        Node        = $node
        Entry       = $entry
        WebDir      = (Join-Path $Here "studio-cordis\web")
        CordisPkg   = $cordisPkg
        Collectors  = (Join-Path $Here $CollectorsRel)
        AndroidBin  = $androidBin
        AppRoot     = (Join-Path $Here "studio-cordis")
    }
}

function Test-OfficialNodeHash([string]$NodePath) {
    if ([System.Environment]::OSVersion.Platform -ne [System.PlatformID]::Win32NT) {
        return
    }
    $actual = (Get-FileHash -LiteralPath $NodePath -Algorithm SHA256).Hash.ToLowerInvariant()
    if ($actual -ne $OfficialNodeExeSha256) {
        Fail 1 "随包 node\node.exe 的 SHA256 与官方 Node v24.22.1 win-x64 不一致，拒绝启动，不会回退到 PATH。"
    }
}

function Test-CordisImport([string]$NodePath, [string]$AppRoot) {
    Push-Location -LiteralPath $AppRoot
    try {
        & $NodePath --input-type=module -e "await import('@cordisjs/core')"
        $impCode = $LASTEXITCODE
    } finally {
        Pop-Location
    }
    if ($impCode -ne 0) {
        Fail 1 "随包 Node 无法加载 @cordisjs/core，拒绝启动。"
    }
}

function Invoke-JsonHttp([string]$Method, [string]$Url, [string]$Body, [int]$TimeoutMs) {
    $req = [System.Net.HttpWebRequest]::Create($Url)
    $req.Method = $Method
    $req.Timeout = $TimeoutMs
    $req.ReadWriteTimeout = $TimeoutMs
    $req.KeepAlive = $false
    if ($Method -eq "POST") {
        $bytes = [Text.Encoding]::UTF8.GetBytes($Body)
        $req.ContentType = "application/json; charset=utf-8"
        $req.ContentLength = $bytes.Length
        $stream = $req.GetRequestStream()
        $stream.Write($bytes, 0, $bytes.Length)
        $stream.Close()
    }
    $resp = $req.GetResponse()
    try {
        $code = [int]$resp.StatusCode
        $reader = New-Object IO.StreamReader($resp.GetResponseStream())
        $text = $reader.ReadToEnd()
        $reader.Close()
        return @{ Code = $code; Body = $text }
    } finally {
        $resp.Close()
    }
}

function Test-HealthOk([string]$BaseUrl, [int]$TimeoutMs) {
    $url = $BaseUrl.TrimEnd("/") + $HealthPath
    try {
        $res = Invoke-JsonHttp "GET" $url $null $TimeoutMs
        if ($res.Code -eq 200 -and $res.Body -match '"ok"\s*:\s*true') { return $true }
    } catch { }
    return $false
}

function Send-Quit([string]$BaseUrl) {
    $url = $BaseUrl.TrimEnd("/") + $QuitPath
    try {
        $res = Invoke-JsonHttp "POST" $url "{}" 5000
        return ($res.Code -eq 200 -and $res.Body -match '"ok"\s*:\s*true')
    } catch {
        return $false
    }
}

function Test-ProcessAlive([int]$ProcId) {
    try {
        $p = Get-Process -Id $ProcId -ErrorAction Stop
        return ($null -ne $p -and -not $p.HasExited)
    } catch { return $false }
}

function Get-ProcessCommandLine([int]$ProcId) {
    try {
        $p = Get-CimInstance -ClassName Win32_Process -Filter "ProcessId=$ProcId" -ErrorAction SilentlyContinue
        if ($null -ne $p) { return "$($p.Name) $($p.CommandLine)" }
    } catch { }
    return ""
}

function Stop-PidCarefully([int]$ProcId, [string]$EntryHint) {
    if (-not (Test-ProcessAlive $ProcId)) { return }
    $cmd = Get-ProcessCommandLine $ProcId
    $nameOk = $cmd -match '(?i)node(\.exe)?'
    $hintOk = $true
    if ($EntryHint -and $EntryHint.Trim() -ne "") {
        $leaf = [IO.Path]::GetFileName($EntryHint)
        $hintOk = ($cmd -match [regex]::Escape($leaf)) -or ($cmd -match 'studio-cordis') -or ($cmd -match 'main\.ts')
    }
    if (-not ($nameOk -and $hintOk)) {
        [Console]::Error.WriteLine("拒绝结束 PID $ProcId：进程命令行与 Studio 入口不匹配，避免误杀。")
        return
    }
    try { Stop-Process -Id $ProcId -Force -ErrorAction Stop } catch { }
}

function Read-Runtime([string]$RuntimePath) {
    if (-not (Test-Path -LiteralPath $RuntimePath -PathType Leaf)) { return $null }
    try {
        return (Get-Content -LiteralPath $RuntimePath -Raw -Encoding UTF8 | ConvertFrom-Json)
    } catch { return $null }
}

function Write-Runtime([string]$RuntimePath, $Obj) {
    Ensure-Dir ([IO.Path]::GetDirectoryName($RuntimePath))
    $json = $Obj | ConvertTo-Json -Depth 6
    $utf8NoBom = New-Object Text.UTF8Encoding $false
    [IO.File]::WriteAllText($RuntimePath, $json, $utf8NoBom)
}

function Remove-Runtime([string]$RuntimePath) {
    if (Test-Path -LiteralPath $RuntimePath -PathType Leaf) {
        Remove-Item -LiteralPath $RuntimePath -Force -ErrorAction SilentlyContinue
    }
}

function Open-DefaultBrowser([string]$Url) {
    Start-Process $Url | Out-Null
}

function Wait-ProcessExit([int]$ProcId, [int]$TimeoutMs) {
    $deadline = [DateTime]::UtcNow.AddMilliseconds($TimeoutMs)
    while ([DateTime]::UtcNow -lt $deadline) {
        if (-not (Test-ProcessAlive $ProcId)) { return $true }
        Start-Sleep -Milliseconds 100
    }
    return -not (Test-ProcessAlive $ProcId)
}

function Invoke-Stop([string]$AppDir, [string]$EntryHint) {
    $runtimePath = Get-RuntimePath $AppDir
    $state = Read-Runtime $runtimePath
    if ($null -eq $state) {
        Write-Host "没有正在运行的 Studio 记录，无需停止。"
        exit 0
    }
    $procId = 0
    if ($state.pid) { $procId = [int]$state.pid }
    $url = [string]$state.url
    $alive = ($procId -gt 0) -and (Test-ProcessAlive $procId)
    if (-not $alive -and -not $url) {
        Remove-Runtime $runtimePath
        Write-Host "没有正在运行的 Studio 进程，已清理残留记录。"
        exit 0
    }
    if ($url) {
        [void](Send-Quit $url)
        if ($procId -gt 0) { [void](Wait-ProcessExit $procId $QuitWaitMs) }
    }
    if (($procId -gt 0) -and (Test-ProcessAlive $procId)) {
        Stop-PidCarefully $procId $EntryHint
        [void](Wait-ProcessExit $procId $ForceKillWaitMs)
    }
    if (($procId -gt 0) -and (Test-ProcessAlive $procId)) {
        Fail 1 "停止 Studio 超时，进程仍在运行（PID $procId）。"
    }
    Remove-Runtime $runtimePath
    Write-Host "Studio 已停止。"
    exit 0
}

function Find-ReadyInLog([string]$LogPath) {
    if (-not (Test-Path -LiteralPath $LogPath -PathType Leaf)) { return $null }
    $text = Get-Content -LiteralPath $LogPath -Raw -ErrorAction SilentlyContinue
    if (-not $text) { return $null }
    $m = [regex]::Match($text, "$ReadyPrefix\s+url=(\S+)\s+pid=(\d+)")
    if ($m.Success) {
        return @{ Url = $m.Groups[1].Value; Pid = [int]$m.Groups[2].Value }
    }
    return $null
}

function Start-HiddenNode([string]$NodePath, [string]$ArgString, [string]$WorkDir, [string]$OutLog, [string]$ErrLog) {
    foreach ($f in @($OutLog, $ErrLog)) {
        if (Test-Path -LiteralPath $f -PathType Leaf) { Remove-Item -LiteralPath $f -Force }
        New-Item -ItemType File -Path $f -Force | Out-Null
    }
    try {
        return Start-Process -FilePath $NodePath -ArgumentList $ArgString -WorkingDirectory $WorkDir -WindowStyle Hidden -RedirectStandardOutput $OutLog -RedirectStandardError $ErrLog -PassThru
    } catch {
        $psi = New-Object System.Diagnostics.ProcessStartInfo
        $psi.FileName = $NodePath
        $psi.Arguments = $ArgString
        $psi.WorkingDirectory = $WorkDir
        $psi.UseShellExecute = $false
        $psi.CreateNoWindow = $true
        $psi.RedirectStandardOutput = $true
        $psi.RedirectStandardError = $true
        $proc = New-Object System.Diagnostics.Process
        $proc.StartInfo = $psi
        $ok = $proc.Start()
        if (-not $ok) { Fail 1 "无法启动随包 Node。" }
        $outDest = $OutLog
        $errDest = $ErrLog
        Register-ObjectEvent -InputObject $proc -EventName OutputDataReceived -SourceIdentifier "pktpath-stdout" -Action {
            $line = $Event.SourceEventArgs.Data
            if ($null -ne $line) {
                [IO.File]::AppendAllText($Event.MessageData, $line + [Environment]::NewLine)
            }
        } -MessageData $outDest | Out-Null
        Register-ObjectEvent -InputObject $proc -EventName ErrorDataReceived -SourceIdentifier "pktpath-stderr" -Action {
            $line = $Event.SourceEventArgs.Data
            if ($null -ne $line) {
                [IO.File]::AppendAllText($Event.MessageData, $line + [Environment]::NewLine)
            }
        } -MessageData $errDest | Out-Null
        $proc.BeginOutputReadLine()
        $proc.BeginErrorReadLine()
        return $proc
    }
}

function Get-LaunchMutexName([string]$appDir) {
    $norm = $appDir.Trim().TrimEnd('\', '/').ToLowerInvariant()
    $bytes = [System.Text.Encoding]::UTF8.GetBytes($norm)
    $sha = [System.Security.Cryptography.SHA256]::Create()
    try {
        $hash = ($sha.ComputeHash($bytes) | ForEach-Object { $_.ToString("x2") }) -join ""
        return "Local\PktPathStudioLaunch-" + $hash.Substring(0, 16)
    } finally {
        $sha.Dispose()
    }
}

# --- main ---
$here = $PSScriptRoot
$parsed = Parse-LaunchArgs $args

if ($parsed.Help) { Show-Usage; exit 0 }

if ($env:PKTPATH_NO_OPEN -eq "1" -or $env:PKTPATH_NO_OPEN -eq "true") {
    $parsed.NoOpen = $true
}

$appDir = $parsed.AppDir
if (-not $appDir) { $appDir = Get-DefaultAppDir }
if ($parsed.Stop) {
    Invoke-Stop $appDir (Join-Path $here $EntryRel)
}

$paths = Test-RequiredFiles $here
Test-OfficialNodeHash $paths.Node
Test-CordisImport $paths.Node $paths.AppRoot

$hostName = $parsed.Host
if (-not $hostName) {
    if ($env:PKTPATH_HOST -and $env:PKTPATH_HOST.Trim() -ne "") { $hostName = $env:PKTPATH_HOST } else { $hostName = $DefaultHost }
}
$collectorsDir = $parsed.CollectorsDir
if (-not $collectorsDir) { $collectorsDir = $paths.Collectors }
$webDir = $parsed.WebDir
if (-not $webDir) { $webDir = $paths.WebDir }

Ensure-Dir (Join-Path $appDir "logs")
$outLog = Join-Path $appDir "logs\studio.out.log"
$errLog = Join-Path $appDir "logs\studio.err.log"
$runtimePath = Get-RuntimePath $appDir

$mutexName = Get-LaunchMutexName $appDir
$launchMutex = New-Object System.Threading.Mutex($false, $mutexName)
$hasLock = $false
$foregroundProc = $null
try {
    try {
        $hasLock = $launchMutex.WaitOne(15000)
    } catch [System.Threading.AbandonedMutexException] {
        $hasLock = $true
    }
    if (-not $hasLock) {
        Fail 1 "另一个 PktPath Studio 启动进程仍在初始化，请稍后再试。"
    }

    $existing = Read-Runtime $runtimePath
    if ($existing -and $existing.url -and $existing.pid) {
        $exPid = [int]$existing.pid
        if ((Test-ProcessAlive $exPid) -and (Test-HealthOk ([string]$existing.url) 2000)) {
            Write-Host "Studio 已在运行：$($existing.url)"
            if (-not $parsed.NoOpen) { Open-DefaultBrowser ([string]$existing.url) }
            exit 0
        }
        if (-not (Test-ProcessAlive $exPid)) { Remove-Runtime $runtimePath }
    }

    $launch = New-Object System.Collections.Generic.List[string]
    [void]$launch.Add($paths.Entry)
    [void]$launch.Add("--host"); [void]$launch.Add($hostName)
    [void]$launch.Add("--app-dir"); [void]$launch.Add($appDir)
    [void]$launch.Add("--collectors-dir"); [void]$launch.Add($collectorsDir)
    [void]$launch.Add("--web-dir"); [void]$launch.Add($webDir)
    [void]$launch.Add("--no-open")
    if ($parsed.Port -ne $null -and "$($parsed.Port)" -ne "") {
        [void]$launch.Add("--port"); [void]$launch.Add("$($parsed.Port)")
    }
    foreach ($fwd in $parsed.Forward) { [void]$launch.Add($fwd) }
    $argString = Get-WinArgvJoined $launch.ToArray()

    Write-Host "正在启动 PktPath Studio…"

    $proc = $null
    if ($parsed.Foreground) {
        $env:PKTPATH_LAUNCH_FOREGROUND = "1"
        $p = Start-Process -FilePath $paths.Node -ArgumentList $argString -WorkingDirectory $here -NoNewWindow -RedirectStandardOutput $outLog -RedirectStandardError $errLog -PassThru
        $proc = $p
    } else {
        $proc = Start-HiddenNode $paths.Node $argString $here $outLog $errLog
    }

    if ($null -eq $proc) { Fail 1 "无法启动随包 Node。" }

    $deadline = [DateTime]::UtcNow.AddMilliseconds($ReadyTimeoutMs)
    $ready = $null
    $readyHealthy = $false
    while ([DateTime]::UtcNow -lt $deadline) {
        if ($proc.HasExited) { break }
        $ready = Find-ReadyInLog $outLog
        if ($null -eq $ready) { $ready = Find-ReadyInLog $errLog }
        if ($null -ne $ready -and (Test-HealthOk $ready.Url 1500)) {
            $readyHealthy = $true
            break
        }
        Start-Sleep -Milliseconds 100
    }

    if ($ready -and ($readyHealthy -or (Test-HealthOk $ready.Url 2000))) {
        $studioPid = $ready.Pid
        if ($studioPid -le 0) { $studioPid = $proc.Id }
        Write-Runtime $runtimePath @{
            pid          = $studioPid
            launcher_pid = $proc.Id
            url          = $ready.Url
            host         = $hostName
            app_dir      = $appDir
            entry        = $paths.Entry
            node         = $paths.Node
            started_at   = ([DateTimeOffset]::Now).ToString("yyyy-MM-ddTHH:mm:sszzz")
            logs         = @{ out = $outLog; err = $errLog }
        }
        Write-Host "Studio 已就绪：$($ready.Url)"
        if (-not $parsed.NoOpen) { Open-DefaultBrowser $ready.Url }
        if ($parsed.Foreground) {
            $foregroundProc = $proc
        } else {
            exit 0
        }
    } else {
        # Failed to become ready: quit or kill, then show a Chinese error.
        $maybeReady = Find-ReadyInLog $outLog
        if ($null -eq $maybeReady) { $maybeReady = Find-ReadyInLog $errLog }
        if ($maybeReady -and $maybeReady.Url) { [void](Send-Quit $maybeReady.Url) }
        $killId = $proc.Id
        if ($maybeReady -and $maybeReady.Pid) { $killId = $maybeReady.Pid }
        [void](Wait-ProcessExit $killId 2000)
        if (Test-ProcessAlive $killId) { Stop-PidCarefully $killId $paths.Entry }
        if (Test-ProcessAlive $proc.Id) { Stop-PidCarefully $proc.Id $paths.Entry }
        Remove-Runtime $runtimePath
        $tail = ""
        if (Test-Path -LiteralPath $errLog) { $tail = (Get-Content -LiteralPath $errLog -ErrorAction SilentlyContinue | Select-Object -Last 8) -join "`n" }
        if (-not $tail -and (Test-Path -LiteralPath $outLog)) { $tail = (Get-Content -LiteralPath $outLog -ErrorAction SilentlyContinue | Select-Object -Last 8) -join "`n" }
        if ($proc.HasExited) {
            Fail 1 "Studio 在就绪前已退出。请查看日志：${outLog}`n$tail"
        }
        Fail 1 "等待 Studio 就绪超时，已停止后台进程，未打开浏览器。请查看日志：${outLog}`n$tail"
    }
} finally {
    if ($hasLock) {
        try { $launchMutex.ReleaseMutex() } catch {}
    }
    $launchMutex.Dispose()
}

if ($null -ne $foregroundProc) {
    Wait-Process -Id $foregroundProc.Id
    Remove-Runtime $runtimePath
    if ($foregroundProc.ExitCode -ne $null) { exit $foregroundProc.ExitCode }
    exit 0
}
