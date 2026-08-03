@echo off
call "C:\Program Files\Microsoft Visual Studio\2022\Community\VC\Auxiliary\Build\vcvars64.bat" >nul 2>&1
msbuild "%~dp0MemRE.vcxproj" /p:Configuration=Release /p:Platform=x64 /v:minimal /t:Rebuild
echo EXIT_CODE=%ERRORLEVEL%
