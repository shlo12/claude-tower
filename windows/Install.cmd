@echo off
cd /d "%~dp0"
if not exist "%~dp0WindowsShield.exe" exit /b 1
start "" "%~dp0WindowsShield.exe" --install
