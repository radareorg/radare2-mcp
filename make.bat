@echo off
REM setlocal EnableDelayedExpansion
set r2mcp_version=1.2.0
if "%PLATFORM%" == "x64" (set target_arch=x86_64) else (set target_arch=x86)
set DEBUG=/O2

cl
if not %ERRORLEVEL%==0 (
	echo VSARCH not set, please run preconfigure.bat
	exit /b 1
)
if exist radare2 (
	set R2_BASE=%CD%\radare2
) else (
	if exist C:\radare2 (
		set R2_BASE=C:\radare2
	) else (
		echo ERROR: Cannot find radare2 in CWD or C:\
		exit /b 1
	)
)
set "PATH=%R2_BASE%\bin;%PATH%"

for /f %%i in ('cl /? ^| findstr Version') do set R2V=%%i
for /f %%i in ('radare2 -qv') do set R2V=%%i
for /f %%i in ('radare2 -H R2_USER_PLUGINS') do set R2_PLUGDIR=%%i

echo Using R2_BASE: %R2_BASE%
echo Radare2 Version: %R2V%
set R2_INC=/I"%R2_BASE%\include" /I"%R2_BASE%\include\libr" /I"%R2_BASE%\include\libr\sdb"
set R2=%R2_BASE%\bin\radare2.exe
for %%i in (%*) do (
	if "%%i"=="debug" (set DEBUG=/Z7)
	if "%%i"=="install" (set INSTALL=1)
)

echo Copying custom header for Windows
copy /y config.h.w64 config.h

cd src

echo Building r2mcp...
cl %DEBUG% /MT /nologo /Gy /DR2MCP_VERSION_STRING="""%r2mcp_version%""" %R2_INC% /I"%cd%" "%R2_BASE%\lib\*.lib" main.c r2mcp.c readbuffer.c tools.c prompts.c /link /defaultlib:setupapi.lib
if %ERRORLEVEL%==0 (
	echo "Compilation successful"
) else (
	echo "ERROR"
	cd ..
	exit /b 1
)
cd ..

echo Distribution Zip...
if exist r2mcp-%R2V%-w64.zip (
    del r2mcp-%R2V%-w64.zip
) else (
    echo r2mcp-%R2V%-w64.zip not deleted as Zip file not found.
)

if exist r2mcp-%R2V%-w64 (
    rd /q /s r2mcp-%R2V%-w64
) else (
   echo Directory r2mcp-%R2V%-w64 not found.
)
md r2mcp-%R2V%-w64
copy README.md r2mcp-%R2V%-w64\
copy src\r2mcp.exe r2mcp-%R2V%-w64\
copy install.bat r2mcp-%R2V%-w64\
powershell -command "Compress-Archive -Path r2mcp-%R2V%-w64 -DestinationPath r2mcp-%R2V%-w64.zip"

.\install.bat