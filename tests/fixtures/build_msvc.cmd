@echo off
rem Rebuild the MSVC PE fixtures (Windows + Visual Studio with the C++ workload).
rem   pe-x64-msvc.exe : PE32+, /GS, /guard:cf, CET-compatible, Rich header
rem   pe-x86-msvc.exe : PE32, /SAFESEH, /GS, /guard:cf
rem /Brepro makes the output reproducible (timestamp field becomes a hash).
setlocal
cd /d "%~dp0"
set "VSWHERE=%ProgramFiles(x86)%\Microsoft Visual Studio\Installer\vswhere.exe"
for /f "usebackq delims=" %%i in (`"%VSWHERE%" -latest -products * -property installationPath`) do set "VS=%%i"
if not defined VS (echo Visual Studio not found & exit /b 1)
set "VCVARS=%VS%\VC\Auxiliary\Build\vcvarsall.bat"
set "CFLAGS=/nologo /O1 /GS /guard:cf /MD /Brepro /D_CRT_SECURE_NO_WARNINGS"
set "LFLAGS=/DYNAMICBASE /NXCOMPAT /GUARD:CF /Brepro /INCREMENTAL:NO /PDBALTPATH:%%_PDB%%"
if not exist .build-msvc mkdir .build-msvc

call "%VCVARS%" x64 >nul || exit /b 1
cl %CFLAGS% src\vuln_win.c /Fo.build-msvc\ /Fd.build-msvc\ /Fe:bin\pe-x64-msvc.exe /link %LFLAGS% /CETCOMPAT /HIGHENTROPYVA /PDB:.build-msvc\pe-x64-msvc.pdb || exit /b 1

call "%VCVARS%" x86 >nul || exit /b 1
cl %CFLAGS% src\vuln_win.c /Fo.build-msvc\ /Fd.build-msvc\ /Fe:bin\pe-x86-msvc.exe /link %LFLAGS% /SAFESEH /PDB:.build-msvc\pe-x86-msvc.pdb || exit /b 1

rmdir /s /q .build-msvc
dir /b bin\*msvc*
