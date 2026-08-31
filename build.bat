@echo off
rem Double-click launcher for build.ps1: Windows blocks .ps1 scripts by
rem default (ExecutionPolicy Restricted), so run PowerShell with an override
rem and keep the window open afterwards.
powershell -NoProfile -ExecutionPolicy Bypass -File "%~dp0build.ps1" %*
echo.
pause
