@echo off
rem ============================================================
rem  Claude Tower · Windows 免安装打包脚本
rem  在 Windows 机器上运行：产出 dist\Claude Tower.exe（双击即用，无需装 Python）
rem  需要：本机装有 Python 3.9+ 和 PyInstaller
rem ============================================================
cd /d "%~dp0.."

where python >nul 2>nul
if errorlevel 1 (
    echo [x] 需要先安装 Python 3.9+（微软商店可装）
    pause
    exit /b 1
)

python -m pip install --quiet pyinstaller 2>nul
if errorlevel 1 (
    echo [x] PyInstaller 装不上，检查网络后重试
    pause
    exit /b 1
)

python -m PyInstaller --noconfirm --clean ^
    --onefile --noconsole ^
    --name "Claude Tower" ^
    --add-data "web;web" ^
    --icon NONE ^
    app.py

if errorlevel 1 (
    echo [x] 打包失败
    pause
    exit /b 1
)

echo.
echo   √ 完成：dist\Claude Tower.exe
echo   把它发给朋友，双击就能跑，不用装 Python。
echo.
pause
