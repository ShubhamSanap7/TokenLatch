@echo off
setlocal EnableExtensions EnableDelayedExpansion
title TokenLatch - Discord Session Protection

set "TOOL_NAME=TokenLatch"
set "SCRIPT_DIR=%~dp0"
set "CONFIG_FILE=%SCRIPT_DIR%guard_config.json"
set "PYTHONW=pythonw.exe"
set "PYTHONW_PATH="
set "PYTHON_PATH="
for /f "delims=" %%P in ('where pythonw.exe 2^>nul') do if not defined PYTHONW_PATH set "PYTHONW_PATH=%%P"
for /f "delims=" %%P in ('where python.exe 2^>nul') do if not defined PYTHON_PATH set "PYTHON_PATH=%%P"
set "PID_DIR=%LocalAppData%\.dguard"
set "PID_FILE=%PID_DIR%\guard.pid"
set "ACCESS_PID_FILE=%PID_DIR%\access_watch.pid"
set "ACCESS_STOP_FILE=%PID_DIR%\access_watch.stop"
set "TASK_NAME=%TOOL_NAME% - Session Protection"
set "ACCESS_TASK_NAME=%TOOL_NAME% - Access Watcher"

if /I "%~1"=="--reconfigure" goto :wizard
if not exist "%CONFIG_FILE%" goto :wizard
call :load_config_selection
if errorlevel 1 exit /b 1
goto :control_panel

:wizard
cls
echo.
echo ============================================================
echo                    %TOOL_NAME% SETUP WIZARD
echo ============================================================
echo.
echo This tool protects your Discord session from token theft by
echo locking local session files when apps are closed.
echo.
call :ask_yn "Apply this protection? (Y/N)" APPLY
if /I not "!APPLY!"=="Y" (
    echo.
    echo No changes made. Exiting.
    exit /b 0
)

:browser_menu
cls
echo.
echo ============================================================
echo                    %TOOL_NAME% BROWSER SETUP
echo ============================================================
echo Toggle a browser with its number. Type D when finished.
echo.
if defined SEL_chrome (echo   1. [X] Chrome) else (echo   1. [ ] Chrome)
if defined SEL_edge (echo   2. [X] Edge) else (echo   2. [ ] Edge)
if defined SEL_brave (echo   3. [X] Brave) else (echo   3. [ ] Brave)
if defined SEL_firefox (echo   4. [X] Firefox) else (echo   4. [ ] Firefox)
if defined SEL_opera (echo   5. [X] Opera) else (echo   5. [ ] Opera)
if defined SEL_opera_gx (echo   6. [X] Opera GX) else (echo   6. [ ] Opera GX)
if defined SEL_vivaldi (echo   7. [X] Vivaldi) else (echo   7. [ ] Vivaldi)
if defined SEL_chromium (echo   8. [X] Chromium) else (echo   8. [ ] Chromium)
if defined SEL_yandex (echo   9. [X] Yandex Browser) else (echo   9. [ ] Yandex Browser)
echo.
set "BROWSER_INPUT="
set /p "BROWSER_INPUT=Selection: "
if /I "!BROWSER_INPUT!"=="D" goto :browser_done
echo(!BROWSER_INPUT!| findstr /R /X /C:"[1-9]" >nul
if errorlevel 1 (
    echo Invalid selection. Enter 1-9 or D.
    timeout /t 1 /nobreak >nul
    goto :browser_menu
)
if "!BROWSER_INPUT!"=="1" if defined SEL_chrome (set "SEL_chrome=") else (set "SEL_chrome=1")
if "!BROWSER_INPUT!"=="2" if defined SEL_edge (set "SEL_edge=") else (set "SEL_edge=1")
if "!BROWSER_INPUT!"=="3" if defined SEL_brave (set "SEL_brave=") else (set "SEL_brave=1")
if "!BROWSER_INPUT!"=="4" if defined SEL_firefox (set "SEL_firefox=") else (set "SEL_firefox=1")
if "!BROWSER_INPUT!"=="5" if defined SEL_opera (set "SEL_opera=") else (set "SEL_opera=1")
if "!BROWSER_INPUT!"=="6" if defined SEL_opera_gx (set "SEL_opera_gx=") else (set "SEL_opera_gx=1")
if "!BROWSER_INPUT!"=="7" if defined SEL_vivaldi (set "SEL_vivaldi=") else (set "SEL_vivaldi=1")
if "!BROWSER_INPUT!"=="8" if defined SEL_chromium (set "SEL_chromium=") else (set "SEL_chromium=1")
if "!BROWSER_INPUT!"=="9" if defined SEL_yandex (set "SEL_yandex=") else (set "SEL_yandex=1")
goto :browser_menu

:browser_done
set "BROWSERS="
if defined SEL_chrome set "BROWSERS=!BROWSERS! chrome"
if defined SEL_edge set "BROWSERS=!BROWSERS! edge"
if defined SEL_brave set "BROWSERS=!BROWSERS! brave"
if defined SEL_firefox set "BROWSERS=!BROWSERS! firefox"
if defined SEL_opera set "BROWSERS=!BROWSERS! opera"
if defined SEL_opera_gx set "BROWSERS=!BROWSERS! opera_gx"
if defined SEL_vivaldi set "BROWSERS=!BROWSERS! vivaldi"
if defined SEL_chromium set "BROWSERS=!BROWSERS! chromium"
if defined SEL_yandex set "BROWSERS=!BROWSERS! yandex"
if not defined BROWSERS (
    call :ask_yn "No browsers selected - only guard the Discord desktop app? (Y/N)" DISCORD_ONLY
    if /I "!DISCORD_ONLY!"=="N" goto :browser_menu
)

echo.
call :ask_yn "Start automatically at Windows login? (Y/N)" AUTOSTART

call :alert_setup

call :ask_yn "Send a test alert through the enabled channels? (Y/N)" SEND_TEST_ALERT
call :execute_setup
exit /b %errorlevel%

:execute_setup
echo.
echo ============================================================
echo                    EXECUTING TOKENLATCH SETUP
echo ============================================================
echo All answers are collected. No setup changes will be made after
echo an error; the process will stop and show the failing step.
echo.

echo [1/6] Closing selected apps...
call :close_selected_apps
if errorlevel 1 exit /b 1

echo [2/6] Saving configuration...
powershell -NoProfile -ExecutionPolicy Bypass -Command "$p='%CONFIG_FILE%'; $b=@(); if($env:SEL_chrome){$b+='chrome'}; if($env:SEL_edge){$b+='edge'}; if($env:SEL_brave){$b+='brave'}; if($env:SEL_firefox){$b+='firefox'}; if($env:SEL_opera){$b+='opera'}; if($env:SEL_opera_gx){$b+='opera_gx'}; if($env:SEL_vivaldi){$b+='vivaldi'}; if($env:SEL_chromium){$b+='chromium'}; if($env:SEL_yandex){$b+='yandex'}; $a=@{ntfy=@{enabled=($env:ALERT_NTFY_ENABLED -eq 'Y');topic_url=$env:ALERT_NTFY_URL};discord_webhook=@{enabled=($env:ALERT_DISCORD_ENABLED -eq 'Y');url=$env:ALERT_DISCORD_URL};email=@{enabled=($env:ALERT_EMAIL_ENABLED -eq 'Y');smtp_server=$env:ALERT_SMTP_SERVER;smtp_port=[int]$env:ALERT_SMTP_PORT;from_addr=$env:ALERT_FROM_ADDR;app_password=$env:ALERT_APP_PASSWORD;to_addr=$env:ALERT_TO_ADDR}}; $j=@{browsers=@($b);autostart=('%AUTOSTART%' -eq 'Y');alerts=$a} | ConvertTo-Json -Depth 6 -Compress; [IO.File]::WriteAllText($p,$j,(New-Object Text.UTF8Encoding($false)))" >nul
if errorlevel 1 (
    echo ERROR: Could not save guard_config.json. Setup stopped.
    pause
    exit /b 1
)

echo [3/6] Enabling Windows audit protection...
echo A UAC prompt may appear. Approve it to enable Event ID 4663 auditing.
call :configure_auditing
if errorlevel 1 exit /b 1

if /I "!SEND_TEST_ALERT!"=="Y" (
    echo [4/6] Sending test remote alert...
    if not defined PYTHON_PATH set "PYTHON_PATH=!PYTHONW_PATH!"
    if not defined PYTHON_PATH (
        echo ERROR: Python was not found for the alert test. Setup stopped.
        pause
        exit /b 1
    )
    start "" /wait "!PYTHON_PATH!" "%SCRIPT_DIR%access_watch.py" --test
    if errorlevel 1 (
        echo ERROR: Test alert process failed. Setup stopped.
        pause
        exit /b 1
    )
) else echo [4/6] Remote alert test skipped.

echo [5/6] Registering login tasks...
if /I "!AUTOSTART!"=="Y" (
    if not defined PYTHONW_PATH (
        echo ERROR: pythonw.exe was not found on PATH. Setup stopped.
        pause
        exit /b 1
    )
    schtasks /Create /F /SC ONLOGON /TN "%TASK_NAME%" /TR "\"!PYTHONW_PATH!\" \"%SCRIPT_DIR%discord_guard.pyw\"" >nul
    if errorlevel 1 (
        echo ERROR: Could not register the main login task. Setup stopped.
        pause
        exit /b 1
    )
    schtasks /Create /F /RL HIGHEST /SC ONLOGON /TN "%ACCESS_TASK_NAME%" /TR "\"!PYTHONW_PATH!\" \"%SCRIPT_DIR%access_watch.pyw\"" >nul
    if errorlevel 1 (
        echo ERROR: Could not register the access-watcher login task. Setup stopped.
        schtasks /Delete /F /TN "%TASK_NAME%" >nul 2>&1
        pause
        exit /b 1
    )
    echo Login auto-start enabled.
) else (
    schtasks /Delete /F /TN "%TASK_NAME%" >nul 2>&1
    schtasks /Delete /F /TN "%ACCESS_TASK_NAME%" >nul 2>&1
    echo Login auto-start disabled.
)

echo [6/6] Starting TokenLatch...
call :start_guard
if errorlevel 1 (
    call :remove_partial_setup
    exit /b 1
)
echo.
echo TokenLatch setup completed successfully.
exit /b 0

:control_panel
cls
echo.
echo ============================================================
echo                         %TOOL_NAME%
echo ============================================================
call :read_pid
call :read_access_pid
if defined RUNNING_PID (
    echo %TOOL_NAME% is currently running and protecting your session.
    echo.
    call :ask_yn "Stop it? (Y/N)" STOP_IT
    if /I "!STOP_IT!"=="Y" (
        call :stop_access_watch
        if errorlevel 1 exit /b 1
        call :stop_main_guard
        if errorlevel 1 exit /b 1
        schtasks /Delete /F /TN "%TASK_NAME%" >nul 2>&1
        schtasks /Delete /F /TN "%ACCESS_TASK_NAME%" >nul 2>&1
        call :reset_saved_setup
        echo %TOOL_NAME% stopped.
    ) else echo No changes made.
    exit /b 0
)
if defined ACCESS_RUNNING_PID (
    echo %TOOL_NAME% access watcher is still running, but the main guard is stopped.
    echo.
    call :ask_yn "Stop the access watcher too? (Y/N)" STOP_IT
    if /I "!STOP_IT!"=="Y" (
        call :stop_access_watch
        if errorlevel 1 exit /b 1
        call :reset_saved_setup
        echo %TOOL_NAME% access watcher stopped.
    ) else echo No changes made.
    exit /b 0
)

echo %TOOL_NAME% is currently stopped.
echo.
call :ask_yn "Start protection now? (Y/N)" START_IT
if /I "!START_IT!"=="Y" (
    call :close_selected_apps
    if errorlevel 1 exit /b 1
    call :start_guard
    if errorlevel 1 exit /b 1
)
exit /b 0

:load_config_selection
set "CONFIG_LOAD_ERROR="
powershell -NoProfile -Command "$c=Get-Content -Raw -LiteralPath $env:CONFIG_FILE | ConvertFrom-Json; if($null -eq $c.browsers){exit 2}" >nul 2>&1
if errorlevel 1 (
    echo ERROR: guard_config.json could not be read. Run setup.bat --reconfigure.
    pause
    exit /b 1
)
for /f "tokens=*" %%B in ('powershell -NoProfile -Command "$c=Get-Content -Raw -LiteralPath $env:CONFIG_FILE ^| ConvertFrom-Json; @($c.browsers) -join [char]32" 2^>nul') do (
    for %%C in (%%B) do set "SEL_%%C=1"
)
exit /b 0

:close_selected_apps
set "NEED_CLOSE="
set "APP_LIST="
call :mark_process "discord.exe" "Discord"
call :mark_process "discordptb.exe" "Discord PTB"
call :mark_process "discordcanary.exe" "Discord Canary"
if defined SEL_chrome call :mark_process "chrome.exe" "Chrome"
if defined SEL_edge call :mark_process "msedge.exe" "Edge"
if defined SEL_brave call :mark_process "brave.exe" "Brave"
if defined SEL_firefox call :mark_process "firefox.exe" "Firefox"
if defined SEL_opera call :mark_process "opera.exe" "Opera"
if defined SEL_opera_gx call :mark_process "opera_gx.exe" "Opera GX"
if defined SEL_vivaldi call :mark_process "vivaldi.exe" "Vivaldi"
if defined SEL_chromium call :mark_process "chromium.exe" "Chromium"
if defined SEL_yandex call :mark_process "browser.exe" "Yandex Browser"
if not defined NEED_CLOSE exit /b 0

echo.
echo The following apps need to close so TokenLatch can secure their session files:
echo !APP_LIST!
call :ask_yn "Close them now? (Y/N)" CLOSE_APPS
if /I "!CLOSE_APPS!"=="N" (
    echo TokenLatch cannot guarantee correct protection while those apps hold the files open.
    echo Setup/start cancelled. No processes were changed.
    exit /b 1
)

echo Closing selected apps gracefully. Please wait...
call :graceful_process "discord.exe"
call :graceful_process "discordptb.exe"
call :graceful_process "discordcanary.exe"
if defined SEL_chrome call :graceful_process "chrome.exe"
if defined SEL_edge call :graceful_process "msedge.exe"
if defined SEL_brave call :graceful_process "brave.exe"
if defined SEL_firefox call :graceful_process "firefox.exe"
if defined SEL_opera call :graceful_process "opera.exe"
if defined SEL_opera_gx call :graceful_process "opera_gx.exe"
if defined SEL_vivaldi call :graceful_process "vivaldi.exe"
if defined SEL_chromium call :graceful_process "chromium.exe"
if defined SEL_yandex call :graceful_process "browser.exe"
timeout /t 2 /nobreak >nul

call :force_process "discord.exe"
call :force_process "discordptb.exe"
call :force_process "discordcanary.exe"
if defined SEL_chrome call :force_process "chrome.exe"
if defined SEL_edge call :force_process "msedge.exe"
if defined SEL_brave call :force_process "brave.exe"
if defined SEL_firefox call :force_process "firefox.exe"
if defined SEL_opera call :force_process "opera.exe"
if defined SEL_opera_gx call :force_process "opera_gx.exe"
if defined SEL_vivaldi call :force_process "vivaldi.exe"
if defined SEL_chromium call :force_process "chromium.exe"
if defined SEL_yandex call :force_process "browser.exe"
timeout /t 1 /nobreak >nul

set "CLOSE_FAILED="
call :check_still_running "discord.exe"
call :check_still_running "discordptb.exe"
call :check_still_running "discordcanary.exe"
if defined SEL_chrome call :check_still_running "chrome.exe"
if defined SEL_edge call :check_still_running "msedge.exe"
if defined SEL_brave call :check_still_running "brave.exe"
if defined SEL_firefox call :check_still_running "firefox.exe"
if defined SEL_opera call :check_still_running "opera.exe"
if defined SEL_opera_gx call :check_still_running "opera_gx.exe"
if defined SEL_vivaldi call :check_still_running "vivaldi.exe"
if defined SEL_chromium call :check_still_running "chromium.exe"
if defined SEL_yandex call :check_still_running "browser.exe"
if defined CLOSE_FAILED (
    echo ERROR: One or more selected apps are still running. Setup/start stopped.
    pause
    exit /b 1
)
echo All selected apps are closed.
exit /b 0

:mark_process
tasklist /FI "IMAGENAME eq %~1" /NH 2>nul | findstr /I /C:"%~1" >nul
if not errorlevel 1 (
    set "NEED_CLOSE=1"
    set "APP_LIST=!APP_LIST! %~2"
)
exit /b 0

:graceful_process
tasklist /FI "IMAGENAME eq %~1" /NH 2>nul | findstr /I /C:"%~1" >nul
if not errorlevel 1 taskkill /IM "%~1" /T >nul 2>&1
exit /b 0

:force_process
tasklist /FI "IMAGENAME eq %~1" /NH 2>nul | findstr /I /C:"%~1" >nul
if not errorlevel 1 taskkill /IM "%~1" /T /F >nul 2>&1
exit /b 0

:check_still_running
tasklist /FI "IMAGENAME eq %~1" /NH 2>nul | findstr /I /C:"%~1" >nul
if not errorlevel 1 set "CLOSE_FAILED=1"
exit /b 0

:read_pid
set "RUNNING_PID="
if not exist "%PID_FILE%" exit /b 0
set /p "CHECK_PID="<"%PID_FILE%"
for /f "delims=" %%P in ('powershell -NoProfile -InputFormat None -Command "$p=Get-Process -Id !CHECK_PID! -ErrorAction SilentlyContinue; if($p -and $p.ProcessName -ieq 'pythonw') { 'yes' }" 2^>nul') do if /I "%%P"=="yes" set "RUNNING_PID=!CHECK_PID!"
if not defined RUNNING_PID del /q "%PID_FILE%" >nul 2>&1
exit /b 0

:start_guard
if not defined PYTHONW_PATH for /f "delims=" %%P in ('where pythonw.exe 2^>nul') do if not defined PYTHONW_PATH set "PYTHONW_PATH=%%P"
if not defined PYTHONW_PATH (
    echo ERROR: Python was not found. Install Python and ensure pythonw.exe is on PATH.
    pause
    exit /b 1
)
powershell.exe -NoProfile -InputFormat None -ExecutionPolicy Bypass -Command "$p=Start-Process -FilePath '!PYTHONW_PATH!' -WorkingDirectory '%SCRIPT_DIR%' -WindowStyle Hidden -PassThru -ArgumentList @('""%SCRIPT_DIR%discord_guard.pyw""'); if(-not $p){exit 1}" >nul
if errorlevel 1 (
    echo ERROR: Could not launch the main guard process.
    pause
    exit /b 1
)
timeout /t 1 /nobreak >nul
call :start_access_watch
if errorlevel 1 (
    echo ERROR: Access watcher failed to start. Stopping the main guard.
    call :stop_main_guard
    pause
    exit /b 1
)
call :read_pid
if not defined RUNNING_PID (
    echo ERROR: Main guard did not create its PID file. Check %%LocalAppData%%\.dguard\guard.log.
    call :stop_access_watch
    pause
    exit /b 1
)
echo %TOOL_NAME% is now protecting your session.
exit /b 0

:remove_partial_setup
if exist "%CONFIG_FILE%" del /q "%CONFIG_FILE%" >nul 2>&1
if exist "%CONFIG_FILE%" (
    echo WARNING: Could not remove the partial configuration file.
) else echo Partial setup removed. The next run will open the setup wizard.
exit /b 0

:stop_main_guard
call :read_pid
if not defined RUNNING_PID exit /b 0
taskkill /PID !RUNNING_PID! /T >nul 2>&1
call :wait_main_stopped
if not errorlevel 1 exit /b 0
echo Main guard did not exit gracefully; forcing it to stop...
call :read_pid
if defined RUNNING_PID taskkill /PID !RUNNING_PID! /T /F >nul 2>&1
call :wait_main_stopped
if errorlevel 1 (
    echo ERROR: Main guard is still running. It was not reported as stopped.
    exit /b 1
)
exit /b 0

:wait_main_stopped
for /L %%S in (1,1,6) do (
    call :read_pid
    if not defined RUNNING_PID exit /b 0
    timeout /t 1 /nobreak >nul
)
exit /b 1

:configure_auditing
echo.
echo A UAC prompt will appear now. Approve it to enable Event ID 4663
echo read auditing for TokenLatch's guarded folders.
powershell.exe -NoProfile -ExecutionPolicy Bypass -Command "$p=Start-Process powershell.exe -Verb RunAs -Wait -PassThru -ArgumentList @('-NoProfile','-ExecutionPolicy','Bypass','-File','%SCRIPT_DIR%audit_setup.ps1','-Configure','-ConfigPath','%CONFIG_FILE%'); exit [int]$p.ExitCode"
if errorlevel 1 (
    echo ERROR: Audit setup did not complete. Setup stopped.
    pause
    exit /b 1
)
echo File System auditing setup completed.
exit /b 0

:read_access_pid
set "ACCESS_RUNNING_PID="
if not exist "%ACCESS_PID_FILE%" exit /b 0
set /p "CHECK_ACCESS_PID="<"%ACCESS_PID_FILE%"
for /f "delims=" %%P in ('powershell -NoProfile -InputFormat None -Command "$p=Get-Process -Id !CHECK_ACCESS_PID! -ErrorAction SilentlyContinue; if($p -and $p.ProcessName -ieq 'pythonw') { 'yes' }" 2^>nul') do if /I "%%P"=="yes" set "ACCESS_RUNNING_PID=!CHECK_ACCESS_PID!"
if not defined ACCESS_RUNNING_PID del /q "%ACCESS_PID_FILE%" >nul 2>&1
exit /b 0

:start_access_watch
call :read_access_pid
if defined ACCESS_RUNNING_PID exit /b 0
powershell.exe -NoProfile -ExecutionPolicy Bypass -Command "Start-Process -FilePath '!PYTHONW_PATH!' -WorkingDirectory '%SCRIPT_DIR%' -Verb RunAs -ArgumentList @('""%SCRIPT_DIR%access_watch.pyw""')"
if errorlevel 1 (
    echo ERROR: Could not launch the elevated access watcher.
    exit /b 1
)
timeout /t 5 /nobreak >nul
call :read_access_pid
if not defined ACCESS_RUNNING_PID (
    echo ERROR: Access watcher did not remain running. Check %%LocalAppData%%\.dguard\guard.log and access_alerts.log.
    exit /b 1
)
exit /b 0

:stop_access_watch
call :read_access_pid
if not defined ACCESS_RUNNING_PID exit /b 0
rem Signal the elevated watcher through the user-writable .dguard directory.
rem This avoids requiring UAC for the normal stop path.
>"%ACCESS_STOP_FILE%" echo stop
for /L %%S in (1,1,5) do (
    call :read_access_pid
    if not defined ACCESS_RUNNING_PID exit /b 0
    timeout /t 1 /nobreak >nul
)
rem Last resort for a genuinely stuck watcher: request an elevated kill.
echo Access watcher did not exit from its stop request; requesting elevation...
powershell.exe -NoProfile -ExecutionPolicy Bypass -Command "$p=Start-Process powershell.exe -Verb RunAs -Wait -PassThru -ArgumentList @('-NoProfile','-ExecutionPolicy','Bypass','-Command','Stop-Process -Id !ACCESS_RUNNING_PID! -Force -ErrorAction Stop'); exit [int]$p.ExitCode" >nul
if errorlevel 1 (
    echo ERROR: Windows denied the elevated access-watcher stop request.
    exit /b 1
)
for /L %%S in (1,1,5) do (
    call :read_access_pid
    if not defined ACCESS_RUNNING_PID exit /b 0
    timeout /t 1 /nobreak >nul
)
echo ERROR: Access watcher is still running. It was not reported as stopped.
exit /b 1

:reset_saved_setup
if exist "%CONFIG_FILE%" (
    del /q "%CONFIG_FILE%" >nul 2>&1
    if exist "%CONFIG_FILE%" (
        echo WARNING: Could not remove guard_config.json. The next run may open the control panel again.
    ) else echo Saved setup removed. The next run will open the setup wizard.
)
exit /b 0

:ask_yn
set "%~2="
:ask_yn_loop
choice /N /C YN /M "%~1 "
if errorlevel 2 (set "%~2=N") else (set "%~2=Y")
if not defined %~2 goto :ask_yn_loop
exit /b 0

:alert_setup
set "ALERT_NTFY_ENABLED=N"
set "ALERT_NTFY_URL="
set "ALERT_DISCORD_ENABLED=N"
set "ALERT_DISCORD_URL="
set "ALERT_EMAIL_ENABLED=N"
set "ALERT_SMTP_SERVER="
set "ALERT_SMTP_PORT=587"
set "ALERT_FROM_ADDR="
set "ALERT_APP_PASSWORD="
set "ALERT_TO_ADDR="
echo.
echo ============================================================
echo                 REMOTE ALERT CHANNELS
echo ============================================================
echo These channels alert you when you are away from this PC.
echo ntfy.sh is recommended: it is free and needs no account.
call :ask_yn "Enable ntfy.sh phone alerts? (Y/N)" ALERT_NTFY_ENABLED
if /I "!ALERT_NTFY_ENABLED!"=="Y" set /p "ALERT_NTFY_URL=ntfy topic URL (for example https://ntfy.sh/your-random-topic): "
call :ask_yn "Enable Discord webhook alerts? (Y/N)" ALERT_DISCORD_ENABLED
if /I "!ALERT_DISCORD_ENABLED!"=="Y" set /p "ALERT_DISCORD_URL=Discord webhook URL: "
call :ask_yn "Enable email alerts? (Y/N)" ALERT_EMAIL_ENABLED
if /I "!ALERT_EMAIL_ENABLED!"=="Y" (
    set /p "ALERT_SMTP_SERVER=SMTP server (for Gmail: smtp.gmail.com): "
    call :ask_smtp_port ALERT_SMTP_PORT
    set /p "ALERT_FROM_ADDR=From email address: "
    set /p "ALERT_APP_PASSWORD=SMTP app password (not your normal password): "
    set /p "ALERT_TO_ADDR=Destination email address: "
)
exit /b 0

:ask_smtp_port
set "%~1=587"
:ask_smtp_port_loop
set /p "%~1=SMTP port (465 or 587): "
echo(!%~1!| findstr /R /X /C:"465" /C:"587" >nul
if errorlevel 1 (
    echo Enter 465 or 587.
    set "%~1=587"
    goto :ask_smtp_port_loop
)
exit /b 0
