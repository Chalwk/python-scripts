@echo off
cd /d "%~dp0"

echo Cleaning site...
call bundle exec jekyll clean || exit /b

echo Starting Jekyll server on 127.0.0.1:4000 with live reload...

start cmd /k "cd /d "%~dp0" && bundle exec jekyll serve --livereload --host 127.0.0.1 --baseurl="

echo Waiting for server to start...
set "PORT=4000"
set "TIMEOUT=30"

for /l %%i in (1,1,%TIMEOUT%) do (
    timeout /t 1 /nobreak >nul
    netstat -an | find ":%PORT% " | find "LISTENING" >nul && goto :ready
)

echo WARNING: Server not responding after %TIMEOUT% seconds. Opening browser anyway.

:ready
start http://127.0.0.1:4000/