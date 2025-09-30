# Windows Build Instructions

This document describes how to build r2mcp on Windows using the batch file approach, similar to how r2frida handles Windows compilation.

## Prerequisites

1. **Visual Studio** (2019 or 2022) with C++ build tools
   - Community, Professional, Enterprise, or Build Tools edition
   - Make sure to install the "MSVC v143 - VS 2022 C++ x64/x86 build tools" component

2. **Git** - Required for cloning the repository

3. **PowerShell** - Usually pre-installed on Windows 10/11

## Quick Start

The easiest way to build r2mcp on Windows is to use the provided batch files:

```cmd
# 1. Clone the repository
git clone https://github.com/radareorg/radare2-mcp.git
cd radare2-mcp

# 2. Set up Visual Studio environment (choose architecture)
preconfigure.bat amd64

# 3. Download and configure radare2 dependencies
configure.bat

# 4. Build r2mcp
make.bat

# 5. Install r2mcp (optional)
install.bat
```

## Detailed Build Process

### Step 1: Preconfigure Visual Studio Environment

The `preconfigure.bat` script automatically detects and sets up the Visual Studio environment:

```cmd
preconfigure.bat [architecture]
```

Supported architectures:
- `amd64` (64-bit, recommended)
- `x86` (32-bit)
- `arm` (ARM 32-bit)
- `arm64` (ARM 64-bit)

If no architecture is specified, you'll be prompted to choose one.

### Step 2: Configure Dependencies

The `configure.bat` script downloads and sets up radare2:

```cmd
configure.bat
```

This script:
- Checks if radare2 is already installed
- Downloads the appropriate radare2 release (version 6.0.2)
- Extracts it to the local `radare2` directory
- Sets up the PATH environment variable

### Step 3: Build r2mcp

The `make.bat` script compiles r2mcp:

```cmd
make.bat [options]
```

Options:
- `debug` - Build with debug symbols (`/Z7`)
- `install` - Automatically run install.bat after building

The build process:
1. Copies `config.h.w64` to `config.h`
2. Compiles all source files using MSVC
3. Links with radare2 libraries
4. Creates a distribution zip package

### Step 4: Install r2mcp

The `install.bat` script installs r2mcp:

```cmd
install.bat
```

This copies `r2mcp.exe` to the radare2 bin directory.

## Alternative Build Methods

### Using Makefile.w64

You can also use the Windows-specific Makefile directly:

```cmd
# Using nmake (Visual Studio's make)
nmake /f Makefile.w64 all

# Using GNU make (if available)
make -f Makefile.w64 all
```

Environment variables:
- `R2_BASE` - Path to radare2 installation (default: `C:\radare2`)
- `PLATFORM` - Target platform (`x86` or `x64`)

### Using Meson

The project also supports building with Meson:

```cmd
# Install Meson
pip install meson

# Configure
meson setup builddir --backend vs -Dr2_prefix=C:\radare2

# Build
meson compile -C builddir
```

## File Structure

The Windows build creates the following files:

```
r2mcp/
├── preconfigure.bat      # Visual Studio environment setup
├── configure.bat          # Dependency configuration
├── make.bat              # Main build script
├── install.bat           # Installation script
├── config.h.w64          # Windows configuration header
├── Makefile.w64          # Windows-specific Makefile
├── config.h              # Generated configuration (copied from config.h.w64)
├── src/
│   ├── r2mcp.exe         # Compiled executable
│   ├── *.obj             # Object files
│   └── ...
└── r2mcp-*-w64.zip       # Distribution package
```

## Troubleshooting

### Visual Studio Not Found

If you get "VSARCH not set, please run preconfigure.bat":

1. Make sure Visual Studio is installed
2. Run `preconfigure.bat` first
3. Check that the Visual Studio installation path is correct

### radare2 Not Found

If you get "ERROR: Cannot find radare2":

1. Run `configure.bat` to download radare2
2. Or manually set `R2_BASE` environment variable to your radare2 installation path

### Compilation Errors

Common issues:

1. **Missing headers**: Make sure radare2 development files are installed
2. **Linker errors**: Check that radare2 libraries are in the correct location
3. **Architecture mismatch**: Ensure you're using the correct architecture (x64 vs x86)

### Permission Issues

If you get permission errors:

1. Run Command Prompt as Administrator
2. Check that antivirus isn't blocking the build process
3. Ensure you have write permissions to the build directory

## CI/CD Integration

The Windows batch file approach is integrated into GitHub Actions:

- `.github/workflows/windows-batch-ci.yml` - Uses the batch file approach
- `.github/workflows/windows-ci.yml` - Uses Meson with MSYS2
- `.github/workflows/windows-msys2-ci.yml` - Uses Meson with MSVC

## Comparison with r2frida

This Windows build system is modeled after r2frida's approach:

| Component | r2frida | r2mcp |
|-----------|---------|-------|
| Preconfigure | `preconfigure.bat` | `preconfigure.bat` |
| Configure | `configure.bat` | `configure.bat` |
| Build | `make.bat` | `make.bat` |
| Install | `install.bat` | `install.bat` |
| Config | `config.h.w64` | `config.h.w64` |
| Makefile | N/A | `Makefile.w64` |

The main differences:
- r2mcp doesn't require Frida SDK download
- r2mcp has an additional Makefile.w64 for direct compilation
- r2mcp uses simpler source structure (no agent compilation)

## Support

For issues with Windows builds:

1. Check this documentation first
2. Look at the GitHub Actions logs for CI builds
3. Open an issue on the GitHub repository
4. Check the r2frida documentation for similar issues