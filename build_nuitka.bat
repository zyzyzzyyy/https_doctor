@echo off
REM Nuitka 打包脚本 - HTTPS Doctor
REM 生成约 24MB 的单文件 exe

echo ====================================
echo HTTPS Doctor 打包脚本 (Nuitka)
echo ====================================
echo.

REM 使用 venv 中的 Python
set PYTHON=venv_slim\Scripts\python.exe

echo 正在编译 Python 代码...
echo y | %PYTHON% -m nuitka ^
    --standalone ^
    --onefile ^
    --windows-console-mode=disable ^
    --enable-plugin=pyside6 ^
    --follow-imports ^
    --output-filename=HTTPS_Doctor.exe ^
    main.py

if errorlevel 1 (
    echo.
    echo [错误] 打包失败！
    pause
    exit /b 1
)

echo.
echo ====================================
echo 打包完成！
echo ====================================
for %%A in (HTTPS_Doctor.exe) do echo 文件: HTTPS_Doctor.exe
for %%A in (HTTPS_Doctor.exe) do echo 大小: %%~zA bytes
echo.
pause
