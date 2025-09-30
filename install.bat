@echo off
set R2_BASE=""
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
set PATH=%R2_BASE%\bin:%PATH%

for /f %%i in ('%R2_BASE%\bin\radare2 -H R2_USER_PLUGINS') do set R2_PLUGDIR=%%i

echo Installing r2mcp into %R2_BASE%\bin
echo Copying 'r2mcp.exe' to %R2_BASE%\bin
copy src\r2mcp.exe "%R2_BASE%\bin\r2mcp.exe"