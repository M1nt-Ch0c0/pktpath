@echo off
chcp 65001 >nul
setlocal EnableExtensions DisableDelayedExpansion
rem Stops a PktPath Studio instance started by start-studio.cmd.
rem Delegates to start-studio.ps1 --stop (POST /api/app/quit).
set "HERE=%~dp0"
if "%HERE:~-1%"=="\" set "HERE=%HERE:~0,-1%"
if exist "%HERE%\start-studio.cmd" (
  call "%HERE%\start-studio.cmd" --stop %*
  exit /b %ERRORLEVEL%
)
echo 缺少 start-studio.cmd，无法停止。 >&2
exit /b 1
