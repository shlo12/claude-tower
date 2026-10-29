@echo off
rem ============================================================
rem  Claude Tower · Windows 启动器
rem  优先用包里自带的运行时（runtime\python），对方不用装任何东西；
rem  没有自带运行时（比如你自己 clone 了源码）就退回系统 Python 3.9+。
rem ============================================================
cd /d "%~dp0"

set "BUNDLED=%~dp0runtime\python\python.exe"
if exist "%BUNDLED%" (
    "%BUNDLED%" app.py
    if errorlevel 1 goto :failed
    goto :eof
)

rem 依次尝试 python / py 启动器
where python >nul 2>nul
if %errorlevel%==0 (
    python app.py
    if errorlevel 1 goto :failed
    goto :eof
)
where py >nul 2>nul
if %errorlevel%==0 (
    py -3 app.py
    if errorlevel 1 goto :failed
    goto :eof
)

echo.
echo   [Claude Tower] 没有找到可用的 Python。
echo.
echo   如果你拿到的是完整压缩包，请确认 runtime\python\python.exe 还在
echo   （解压时被杀毒软件删掉过，重新解压一次通常就好）。
echo   如果你拿到的是源码，请到 python.org 安装 Python 3.9 以上版本。
echo.
pause
goto :eof

:failed
echo.
echo   [Claude Tower] 启动失败，上面是错误信息。
echo   把这段信息发回给提供者，比截图更有用。
echo.
pause
