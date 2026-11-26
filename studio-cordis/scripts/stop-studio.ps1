# Stops a PktPath Studio instance started by start-studio.ps1.
# Delegates to start-studio.ps1 --stop (POST /api/app/quit).
$ErrorActionPreference = "Stop"
try { [Console]::OutputEncoding = [System.Text.Encoding]::UTF8 } catch {}
$here = $PSScriptRoot
$starter = Join-Path $here "start-studio.ps1"
if (-not (Test-Path -LiteralPath $starter -PathType Leaf)) {
    [Console]::Error.WriteLine("缺少 start-studio.ps1，无法停止。")
    exit 1
}
& $starter @("--stop") + $args
exit $LASTEXITCODE
