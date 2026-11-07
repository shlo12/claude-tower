@echo off
setlocal
set "TASK_ROOT=%~dp0.."
cd /d "%TASK_ROOT%"
rem Build the native tray app with the Windows system compiler. No pip install.
call windows\shield\build.cmd
if errorlevel 1 (
    echo Native Shield compilation failed. Windows .NET Framework 4.8 is required.
    exit /b 1
)
cd /d "%TASK_ROOT%"
if not exist build\windows mkdir build\windows
copy /y windows\shield\WindowsShield.exe build\windows\WindowsShield.exe >nul
copy /y windows\shield\WindowsShield.exe WindowsShield.exe >nul
powershell.exe -NoProfile -NonInteractive -Command "$r=Join-Path $env:TEMP 'claude-shield-self-test.json'; $p=Start-Process '.\WindowsShield.exe' -ArgumentList ('--self-test '+[char]34+$r+[char]34) -Wait -PassThru; if($p.ExitCode -ne 0){exit 1}; $s=Get-Content -Raw $r|ConvertFrom-Json; $s|ConvertTo-Json; if(-not $s.ok){exit 1}"
if errorlevel 1 exit /b 1
echo WindowsShield.exe is ready. The Python tools still require the bundled runtime.
exit /b 0
