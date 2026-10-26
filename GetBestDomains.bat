@echo off
setlocal
cd /d "%~dp0"

set "PYTHON_PATH=C:\Users\kuen\AppData\Local\Programs\Python\Python312\python.exe"
set "SCRIPT_PATH=%~dp0QwenGetBestIPs.py"

if not exist "%PYTHON_PATH%" (
    echo ERROR: Python executable not found: "%PYTHON_PATH%" 1>&2
    exit /b 1
)
if not exist "%SCRIPT_PATH%" (
    echo ERROR: Probe script not found: "%SCRIPT_PATH%" 1>&2
    exit /b 1
)

"%PYTHON_PATH%" -X utf8 -u "%SCRIPT_PATH%"
exit /b %errorlevel%
