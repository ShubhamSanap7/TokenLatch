@echo off
setlocal EnableExtensions
title TokenLatch - Health Check

echo.
echo ============================================================
echo                 TokenLatch HEALTH CHECK
echo ============================================================
echo.
echo This checks the installation, running processes, guarded paths,
echo Windows audit status, and every enabled remote alert channel.
echo It sends a clearly labeled diagnostic alert to enabled channels.
echo.

where python.exe >nul 2>&1
if errorlevel 1 (
    echo [FAIL] python.exe was not found on PATH.
    echo Install Python or repair PATH, then run this file again.
    pause
    exit /b 1
)

python "%~dp0access_watch.py" --diagnose
set "RESULT=%ERRORLEVEL%"
echo.
if not "%RESULT%"=="0" (
    echo One or more diagnostic checks or alert channels failed.
    echo Review the results above and %%LocalAppData%%\.dguard\access_alerts.log.
) else (
    echo All enabled diagnostic checks completed successfully.
)
echo.
pause
exit /b %RESULT%
