@echo OFF
set "R2V=6.0.2"
set "R2ZIP=https://github.com/radareorg/radare2/releases/download/%R2V%/radare2-%R2V%-w64.zip"
set "R2DIR=radare2"

echo Checking if radare2 is present in PATH...
set "CURRENT_R2V="
for /f "delims=" %%i in ('radare2 -qv 2^>nul') do (
    set "CURRENT_R2V=%%i"
)
echo Current radare2 version in PATH: %CURRENT_R2V%

if "%CURRENT_R2V%"=="" (
    echo radare2 not found in PATH. Checking local directory...
    if exist %R2DIR% (
        set "PATH=%CD%\%R2DIR%\bin;%PATH%"
        set "CURRENT_R2V="
        for /f "delims=" %%i in ('radare2 -qv 2^>nul') do (
            set "CURRENT_R2V=%%i"
        )
        if not "%CURRENT_R2V%"=="" (
            echo radare2 found in local directory.
            echo Local radare2 version: %CURRENT_R2V%
        )
    )
)

if "%CURRENT_R2V%"=="" (
    echo radare2 not found in PATH or local directory.
) else if "%CURRENT_R2V%"=="%R2V%" (
    echo radare2 version %R2V% is already installed.
    echo You can now run make.bat
    exit /b
) else (
    echo radare2 version %CURRENT_R2V% does not match required version %R2V%.
)

echo Downloading the matching release...
echo Download URL: %R2ZIP%
if exist %R2DIR% (
    echo Removing existing %R2DIR% directory...
    rd /s /q %R2DIR%
)
if exist radare2-%R2V%-w64.zip (
    echo Removing existing zip file...
    del radare2-%R2V%-w64.zip
)

echo Downloading radare2-%R2V%.zip...
powershell -Command "Invoke-WebRequest -Uri '%R2ZIP%' -OutFile 'radare2-%R2V%.zip'"
if not exist radare2-%R2V%.zip (
    echo ERROR: Download failed
    exit /b 1
)

echo Extracting ZIP...
powershell -Command "Expand-Archive -Path 'radare2-%R2V%.zip' -DestinationPath '%CD%' -Force"
if not exist radare2-%R2V%-w64 (
    echo ERROR: Extraction failed
    exit /b 1
)

echo Renaming directory...
ren radare2-%R2V%-w64 %R2DIR%

echo Deleting ZIP file...
del radare2-%R2V%.zip

set "PATH=%CD%\%R2DIR%\bin;%PATH%"
echo Updated PATH: %PATH%
set "CURRENT_R2V="
for /f "delims=" %%i in ('radare2 -qv 2^>nul') do (
    set "CURRENT_R2V=%%i"
)

echo Final radare2 version check: %CURRENT_R2V%
echo Expected version: %R2V%

if "%CURRENT_R2V%"=="%R2V%" (
    echo radare2 version %R2V% installed successfully.
    echo You can now run make.bat
    exit /b
) else (
    echo Failed to install radare2 version %R2V%.
    echo Current version: %CURRENT_R2V%
    exit /b
)