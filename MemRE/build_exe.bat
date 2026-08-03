@echo off
setlocal

:: ── Locate VS 2022 ──────────────────────────────────────────
set "VSWHERE=%ProgramFiles(x86)%\Microsoft Visual Studio\Installer\vswhere.exe"
for /f "usebackq tokens=*" %%i in (`"%VSWHERE%" -latest -property installationPath`) do set "VS_PATH=%%i"

if not defined VS_PATH (
    echo [!] Visual Studio 2022 not found.
    pause
    exit /b 1
)

call "%VS_PATH%\VC\Auxiliary\Build\vcvars64.bat" >nul 2>&1

:: ── Build ────────────────────────────────────────────────────
echo.
echo [*] Building YnJhemlsaWFuIGJ1c3R5IG1pbGY.exe (Release|x64)...
echo.

msbuild "%~dp0MemRE.vcxproj" /p:Configuration=Release /p:Platform=x64 /m /v:minimal

if %ERRORLEVEL% neq 0 (
    echo.
    echo [!] Build FAILED
    pause
    exit /b 1
)

echo.
echo [+] Build succeeded.
echo     Output: x64\Release\YnJhemlsaWFuIGJ1c3R5IG1pbGY.exe
echo.
pause
