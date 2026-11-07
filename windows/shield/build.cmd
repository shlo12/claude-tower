@echo off
setlocal
cd /d "%~dp0"
set "CSC=%SystemRoot%\Microsoft.NET\Framework64\v4.0.30319\csc.exe"
if not exist "%CSC%" set "CSC=%SystemRoot%\Microsoft.NET\Framework\v4.0.30319\csc.exe"
if not exist "%CSC%" exit /b 1
"%CSC%" /nologo /codepage:65001 /win32manifest:app.manifest /target:winexe /platform:anycpu /optimize+ /out:"WindowsShield.exe" /r:System.Windows.Forms.dll /r:System.Drawing.dll /r:System.Web.Extensions.dll /r:System.Security.dll /r:System.Core.dll /resource:Probe.ps1,WindowsShield.Probe.ps1 WindowsShield.cs Policy.cs PolicyTests.cs Installer.cs
exit /b %errorlevel%
