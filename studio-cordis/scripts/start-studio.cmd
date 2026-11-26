@echo off
chcp 65001 >nul
setlocal EnableExtensions DisableDelayedExpansion
rem PktPath Studio Wave 1 launcher (pure Cordis). Double-click entry.
rem Aligned with WAVE1-CONTRACT.md v1.2 (SHA256 34c55d3fcfe32186a9c714e8b447bbfa9828cf5960ee078f861eb6fca286fc97).
rem Fail-closed: only bundled node\node.exe, never PATH Node, never a Go Studio binary.
rem Extract the full zip before running. Under Restricted policy, this cmd calls:
rem   powershell -NoProfile -ExecutionPolicy Bypass -File ".\start-studio.ps1"

set "HERE=%~dp0"
if "%HERE:~-1%"=="\" set "HERE=%HERE:~0,-1%"

set "STOP=0"
set "HELP=0"
for %%A in (%*) do (
  if /I "%%~A"=="--stop" set "STOP=1"
  if /I "%%~A"=="-Stop" set "STOP=1"
  if /I "%%~A"=="--help" set "HELP=1"
  if /I "%%~A"=="-h" set "HELP=1"
  if /I "%%~A"=="-Help" set "HELP=1"
)

if "%STOP%"=="1" goto :runps
if "%HELP%"=="1" goto :runps

set "NODE=%HERE%\node\node.exe"
set "APPDIR=%HERE%\studio-cordis"
set "ENTRY=%APPDIR%\src\main.ts"
set "WEBIDX=%APPDIR%\web\index.html"
set "CORDISPKG=%APPDIR%\node_modules\@cordisjs\core\package.json"
set "COLLECTORS=%HERE%\collectors"
set "ANDROID_BIN=%COLLECTORS%\android-arm64\pktpath"

if not exist "%NODE%" (
  echo 缺少随包 Node（node\node.exe），拒绝启动，不会回退到 PATH。 >&2
  exit /b 1
)
if not exist "%ENTRY%" (
  echo 缺少 Studio 入口（studio-cordis\src\main.ts），拒绝启动。 >&2
  exit /b 1
)
if not exist "%WEBIDX%" (
  echo 缺少前端页面（studio-cordis\web\index.html），拒绝启动。 >&2
  exit /b 1
)
if not exist "%CORDISPKG%" (
  echo 缺少 @cordisjs/core（studio-cordis\node_modules\@cordisjs\core\package.json），拒绝启动。 >&2
  exit /b 1
)
if not exist "%ANDROID_BIN%" (
  echo 缺少 Android 采集器（collectors\android-arm64\pktpath），拒绝启动。 >&2
  exit /b 1
)

:runps
where powershell >nul 2>&1
if errorlevel 1 (
  echo 本机找不到 PowerShell，无法启动。请在已解压的目录使用 start-studio.ps1。 >&2
  exit /b 1
)

powershell -NoProfile -ExecutionPolicy Bypass -File "%HERE%\start-studio.ps1" %*
exit /b %ERRORLEVEL%
