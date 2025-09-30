@echo off
REM Preconfigure script for Windows - r2mcp
REM This script sets up the Visual Studio environment for building r2mcp

echo === Finding Git...
git --version > NUL 2> NUL
if %ERRORLEVEL% == 0 (
  echo OK
) else (
  echo You need to install GIT
  exit /b 1
)

REM VisualStudio uses HOST_TARGET syntax, so: x86_amd64 means 32bit compiler for 64bit target
REM: Hosts: x86 amd64 x64
REM: Targets: x86 amd64 x64 arm arm64
REM Detect the host architecture intuitively and easily

IF "%PROCESSOR_ARCHITECTURE%"=="AMD64" (
    SET "HOST_ARCH=amd64"
) ELSE IF "%PROCESSOR_ARCHITECTURE%"=="x86" (
    SET "HOST_ARCH=x86"
) ELSE (
    SET "HOST_ARCH=unknown"
)

REM Check if arguments are passed
IF "%~1"=="" (
    echo Your current Host Architecture is %HOST_ARCH%
    ECHO Please select the Target Architecture:
    ECHO 1. x86
    ECHO 2. amd64 [x64]
    ECHO 3. arm
    ECHO 4. arm64
    SET /P "CHOICE=Enter your choice (1-4): "

    REM Set target architecture based on user input
    IF "%CHOICE%"=="1" (
        SET "TARGET_ARCH=x86"
    ) ELSE IF "%CHOICE%"=="2" (
        SET "TARGET_ARCH=amd64"
    ) ELSE IF "%CHOICE%"=="3" (
        SET "TARGET_ARCH=arm"
    ) ELSE IF "%CHOICE%"=="4" (
        SET "TARGET_ARCH=arm64"
    ) ELSE (
        ECHO Invalid choice. Defaulting to %HOST_ARCH%.
        SET "TARGET_ARCH=%HOST_ARCH%"
    )

    REM Check if target and host are the same and set VSARCH accordingly
    IF "%TARGET_ARCH%"=="" (
        SET "VSARCH=%HOST_ARCH%"
    ) ELSE IF "%TARGET_ARCH%"=="%HOST_ARCH%" (
        SET "VSARCH=%HOST_ARCH%"
    ) ELSE (
        SET "VSARCH=%HOST_ARCH%_%TARGET_ARCH%"
    )

) ELSE (
    REM Use provided host_target argument
    SET "VSARCH=%1"
)

ECHO VSARCH is set to: %VSARCH%

echo === Finding Visual Studio...
cl --help > NUL 2> NUL
if %ERRORLEVEL% == 0 (
  echo FOUND - cl.exe already in PATH
) else (
  echo cl.exe not found, searching for Visual Studio installations...
  
  REM Try GitHub Actions default VS 2022 location first
  if EXIST "C:\Program Files\Microsoft Visual Studio\2022\Enterprise\VC\Auxiliary\Build\vcvarsall.bat" (
    echo "Found 2022 Enterprise edition"
    call "C:\Program Files\Microsoft Visual Studio\2022\Enterprise\VC\Auxiliary\Build\vcvarsall.bat" %VSARCH%
  ) else (
    if EXIST "C:\Program Files\Microsoft Visual Studio\2022\Community\VC\Auxiliary\Build\vcvarsall.bat" (
      echo "Found 2022 Community edition"
      call "C:\Program Files\Microsoft Visual Studio\2022\Community\VC\Auxiliary\Build\vcvarsall.bat" %VSARCH%
    ) else (
      if EXIST "C:\Program Files\Microsoft Visual Studio\2022\Professional\VC\Auxiliary\Build\vcvarsall.bat" (
        echo "Found 2022 Professional edition"
        call "C:\Program Files\Microsoft Visual Studio\2022\Professional\VC\Auxiliary\Build\vcvarsall.bat" %VSARCH%
      ) else (
        if EXIST "C:\Program Files\Microsoft Visual Studio\2022\BuildTools\VC\Auxiliary\Build\vcvarsall.bat" (
          echo "Found 2022 BuildTools"
          call "C:\Program Files\Microsoft Visual Studio\2022\BuildTools\VC\Auxiliary\Build\vcvarsall.bat" %VSARCH%
        ) else (
          REM Try VS 2019 locations
          if EXIST "C:\Program Files (x86)\Microsoft Visual Studio\2019\Community\VC\Auxiliary\Build\vcvarsall.bat" (
            echo "Found 2019 Community edition"
            call "C:\Program Files (x86)\Microsoft Visual Studio\2019\Community\VC\Auxiliary\Build\vcvarsall.bat" %VSARCH%
          ) else (
            if EXIST "C:\Program Files (x86)\Microsoft Visual Studio\2019\Enterprise\VC\Auxiliary\Build\vcvarsall.bat" (
              echo "Found 2019 Enterprise edition"
              call "C:\Program Files (x86)\Microsoft Visual Studio\2019\Enterprise\VC\Auxiliary\Build\vcvarsall.bat" %VSARCH%
            ) else (
              if EXIST "C:\Program Files (x86)\Microsoft Visual Studio\2019\Professional\VC\Auxiliary\Build\vcvarsall.bat" (
                echo "Found 2019 Professional edition"
                call "C:\Program Files (x86)\Microsoft Visual Studio\2019\Professional\VC\Auxiliary\Build\vcvarsall.bat" %VSARCH%
              ) else (
                if EXIST "C:\Program Files (x86)\Microsoft Visual Studio\2019\BuildTools\VC\Auxiliary\Build\vcvarsall.bat" (
                  echo "Found 2019 BuildTools"
                  call "C:\Program Files (x86)\Microsoft Visual Studio\2019\BuildTools\VC\Auxiliary\Build\vcvarsall.bat" %VSARCH%
                ) else (
                  echo "ERROR: Visual Studio not found in any expected location"
                  echo "Please install Visual Studio 2019 or 2022 with C++ build tools"
                  exit /b 1
                )
              )
            )
          )
        )
      )
    )
  )
)

echo Now you can run 'configure.bat' and then 'make.bat'