@echo off
setlocal EnableExtensions DisableDelayedExpansion

set "miiPauseAtEnd=1"
set "miiExitCode=2"
if /i "%~1"=="--no-pause" set "miiPauseAtEnd=0"
if not "%~2"=="" goto usageError
if not "%~1"=="" if /i not "%~1"=="--no-pause" goto usageError

for %%I in ("%~dp0.") do set "miiSourceDir=%%~fI"
for %%I in ("%miiSourceDir%") do set "miiBuildDir=%%~dpI%%~nxI-build"
set "miiExecutablePath=%miiBuildDir%\Release\Memory-Integrity-Inspector.exe"
set "miiVswherePath=%ProgramFiles(x86)%\Microsoft Visual Studio\Installer\vswhere.exe"
set "miiVisualStudioDir="
set "miiCompilerPath="
set "miiCmakePath="

echo ============================================================
echo                 Memory Integrity Inspector
echo                     x64 Release Build
echo ============================================================
echo.

if not exist "%miiVswherePath%" goto missingVisualStudio
for /f "usebackq delims=" %%I in (`call "%miiVswherePath%" -latest -products * -version "[17.0,18.0)" -requires Microsoft.VisualStudio.Component.VC.Tools.x86.x64 Microsoft.Component.MSBuild -property installationPath`) do set "miiVisualStudioDir=%%I"
if not defined miiVisualStudioDir goto missingVisualStudio
if not exist "%miiVisualStudioDir%\MSBuild\Current\Bin\MSBuild.exe" goto missingVisualStudio
for /f "usebackq delims=" %%I in (`call "%miiVswherePath%" -latest -products * -version "[17.0,18.0)" -requires Microsoft.VisualStudio.Component.VC.Tools.x86.x64 Microsoft.Component.MSBuild -find VC\Tools\MSVC\*\bin\Hostx64\x64\cl.exe`) do if exist "%%I" set "miiCompilerPath=%%I"
if not defined miiCompilerPath goto missingVisualStudio
if not exist "%miiVisualStudioDir%\VC\Auxiliary\Build\vcvars64.bat" goto missingVisualStudio

for %%I in (cmake.exe) do set "miiCmakePath=%%~$PATH:I"
if not defined miiCmakePath if exist "%ProgramFiles%\CMake\bin\cmake.exe" set "miiCmakePath=%ProgramFiles%\CMake\bin\cmake.exe"
if not defined miiCmakePath if exist "%miiVisualStudioDir%\Common7\IDE\CommonExtensions\Microsoft\CMake\CMake\bin\cmake.exe" set "miiCmakePath=%miiVisualStudioDir%\Common7\IDE\CommonExtensions\Microsoft\CMake\CMake\bin\cmake.exe"
if not defined miiCmakePath for /f "usebackq delims=" %%I in (`call "%miiVswherePath%" -all -products * -version "[17.0,18.0)" -find Common7\IDE\CommonExtensions\Microsoft\CMake\CMake\bin\cmake.exe`) do if not defined miiCmakePath if exist "%%I" set "miiCmakePath=%%I"
if not defined miiCmakePath goto missingCMake
"%miiCmakePath%" --version >nul 2>&1
if errorlevel 1 goto missingCMake

echo Source directory: "%miiSourceDir%"
echo Build directory : "%miiBuildDir%"
echo Visual Studio   : "%miiVisualStudioDir%"
echo CMake           : "%miiCmakePath%"
echo.
echo Initializing MSVC x64 tools...
call "%miiVisualStudioDir%\VC\Auxiliary\Build\vcvars64.bat"
if errorlevel 1 goto toolchainFailed

echo Configuring x64 project...
"%miiCmakePath%" -S "%miiSourceDir%" -B "%miiBuildDir%" -G "Visual Studio 17 2022" -A x64 "-DCMAKE_GENERATOR_INSTANCE:PATH=%miiVisualStudioDir%"
set "miiExitCode=%errorlevel%"
if not "%miiExitCode%"=="0" goto configureFailed

echo.
echo Building Release executable...
"%miiCmakePath%" --build "%miiBuildDir%" --config Release
set "miiExitCode=%errorlevel%"
if not "%miiExitCode%"=="0" goto buildFailed
if not exist "%miiExecutablePath%" goto missingExecutable

echo.
echo [SUCCESS] x64 Release build completed.
echo Executable: "%miiExecutablePath%"
goto finish

:usageError
echo [ERROR] Usage: build.bat [--no-pause]
goto finish

:missingVisualStudio
echo [ERROR] Visual Studio 2022 MSVC x64 build tools were not found.
echo Install Visual Studio 2022 or Build Tools with Desktop development
echo with C++, including MSVC x64 tools, MSBuild, and a Windows 10/11 SDK.
goto finish

:missingCMake
echo [ERROR] CMake could not be found or executed.
echo Install CMake 3.20 or newer and add it to PATH, or install the
echo C++ CMake tools for Windows component through Visual Studio Installer.
goto finish

:toolchainFailed
echo [ERROR] The MSVC x64 build environment could not be initialized.
echo Check the Visual Studio 2022 installation and its Windows SDK components.
goto finish

:configureFailed
echo.
echo [ERROR] CMake configuration failed with exit code %miiExitCode%.
echo Check the diagnostics above, CMake 3.20 or newer, and the Windows SDK.
goto finish

:buildFailed
echo.
echo [ERROR] Release compilation failed with exit code %miiExitCode%.
echo Check the compiler diagnostics above.
goto finish

:missingExecutable
set "miiExitCode=1"
echo [ERROR] The build returned success, but the executable was not found:
echo "%miiExecutablePath%"

:finish
echo.
if "%miiPauseAtEnd%"=="1" pause
endlocal & exit /b %miiExitCode%
