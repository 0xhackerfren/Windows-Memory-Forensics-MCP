# Windows Memory Forensics MCP - Setup Script
# Author: Jacob Krell
# Status: Beta
#
# This script sets up the complete environment for the Memory Forensics MCP.
# Run from the repository root: .\setup.ps1
#
# PREREQUISITES:
#   1. Python 3.10+ (https://python.org)
#   2. Visual C++ Build Tools (for yara-python compilation)
#      Download: https://visualstudio.microsoft.com/visual-cpp-build-tools/
#      Install "Desktop development with C++" workload

param(
    [switch]$SkipVenv,
    [switch]$Force
)

$ErrorActionPreference = "Stop"

Write-Host ""
Write-Host "========================================" -ForegroundColor Cyan
Write-Host " Windows Memory Forensics MCP - Setup" -ForegroundColor Cyan
Write-Host "========================================" -ForegroundColor Cyan
Write-Host ""
Write-Host "Author: Jacob Krell"
Write-Host "Status: Beta"
Write-Host ""

# Check for Visual C++ Build Tools
Write-Host "[0/6] Checking prerequisites..." -ForegroundColor Yellow
$vsWhere = "${env:ProgramFiles(x86)}\Microsoft Visual Studio\Installer\vswhere.exe"
if (Test-Path $vsWhere) {
    $vsInstall = & $vsWhere -latest -products * -requires Microsoft.VisualStudio.Component.VC.Tools.x86.x64 -property installationPath 2>$null
    if ($vsInstall) {
        Write-Host "[OK] Visual C++ Build Tools found" -ForegroundColor Green
    } else {
        Write-Host "[WARNING] Visual C++ Build Tools not detected" -ForegroundColor Yellow
        Write-Host "         yara-python compilation may fail" -ForegroundColor Yellow
        Write-Host "         Download from: https://visualstudio.microsoft.com/visual-cpp-build-tools/" -ForegroundColor Gray
        Write-Host "         Install 'Desktop development with C++' workload" -ForegroundColor Gray
        Write-Host ""
    }
} else {
    Write-Host "[INFO] Could not check for Visual C++ Build Tools" -ForegroundColor Gray
}

# Check Python version
Write-Host "[1/6] Checking Python installation..." -ForegroundColor Yellow
try {
    $pythonVersion = python --version 2>&1
    if ($pythonVersion -match "Python (\d+)\.(\d+)") {
        $major = [int]$Matches[1]
        $minor = [int]$Matches[2]
        if ($major -lt 3 -or ($major -eq 3 -and $minor -lt 10)) {
            Write-Host "[ERROR] Python 3.10+ required. Found: $pythonVersion" -ForegroundColor Red
            exit 1
        }
        Write-Host "[OK] Found $pythonVersion" -ForegroundColor Green
    }
} catch {
    Write-Host "[ERROR] Python not found. Please install Python 3.10+" -ForegroundColor Red
    exit 1
}

# Create virtual environment
$venvPath = ".\venv"
if (-not $SkipVenv) {
    Write-Host ""
    Write-Host "[2/6] Creating virtual environment..." -ForegroundColor Yellow
    
    if (Test-Path $venvPath) {
        if ($Force) {
            Write-Host "  Removing existing venv..." -ForegroundColor Gray
            Remove-Item -Recurse -Force $venvPath
        } else {
            Write-Host "[OK] Virtual environment already exists. Use -Force to recreate." -ForegroundColor Green
        }
    }
    
    if (-not (Test-Path $venvPath)) {
        python -m venv venv
        if ($LASTEXITCODE -ne 0) {
            Write-Host "[ERROR] Failed to create virtual environment" -ForegroundColor Red
            exit 1
        }
        Write-Host "[OK] Virtual environment created at .\venv\" -ForegroundColor Green
    }
    
    # Set explicit paths for venv python/pip
    Write-Host ""
    Write-Host "[3/6] Configuring virtual environment..." -ForegroundColor Yellow
    $pythonExe = ".\venv\Scripts\python.exe"
    $pipExe = ".\venv\Scripts\pip.exe"
    Write-Host "[OK] Using venv Python at $pythonExe" -ForegroundColor Green
} else {
    Write-Host ""
    Write-Host "[2/6] Skipping virtual environment (--SkipVenv)" -ForegroundColor Gray
    Write-Host "[3/6] Skipping venv configuration" -ForegroundColor Gray
    $pythonExe = "python"
    $pipExe = "pip"
}

# Upgrade pip
Write-Host ""
Write-Host "[4/6] Upgrading pip..." -ForegroundColor Yellow
& $pythonExe -m pip install --upgrade pip --quiet
Write-Host "[OK] pip upgraded" -ForegroundColor Green

# Install all dependencies
Write-Host ""
Write-Host "[5/6] Installing dependencies..." -ForegroundColor Yellow
Write-Host ""
Write-Host "  Installing core dependencies..." -ForegroundColor Gray

# Core MCP dependency
& $pipExe install "mcp>=1.2.0" --quiet
if ($LASTEXITCODE -ne 0) {
    Write-Host "[ERROR] Failed to install mcp" -ForegroundColor Red
    exit 1
}
Write-Host "    [OK] mcp" -ForegroundColor Green

# Volatility 3 (primary backend)
Write-Host "  Installing Volatility 3 backend..." -ForegroundColor Gray
& $pipExe install "volatility3>=2.26.0" --quiet
if ($LASTEXITCODE -ne 0) {
    Write-Host "[ERROR] Failed to install volatility3" -ForegroundColor Red
    exit 1
}
Write-Host "    [OK] volatility3" -ForegroundColor Green

# pefile (for PE analysis)
& $pipExe install "pefile>=2024.8.26" --quiet
if ($LASTEXITCODE -ne 0) {
    Write-Host "[ERROR] Failed to install pefile" -ForegroundColor Red
    exit 1
}
Write-Host "    [OK] pefile" -ForegroundColor Green

# MemProcFS (advanced backend)
Write-Host "  Installing MemProcFS backend..." -ForegroundColor Gray
& $pipExe install "memprocfs>=5.9.0" --quiet
if ($LASTEXITCODE -ne 0) {
    Write-Host "[WARNING] Failed to install memprocfs - some advanced features will be unavailable" -ForegroundColor Yellow
} else {
    Write-Host "    [OK] memprocfs" -ForegroundColor Green
}

# yara-python (for YARA scanning)
Write-Host "  Installing yara-python..." -ForegroundColor Gray
& $pipExe install "yara-python>=4.5.0" --quiet 2>$null
if ($LASTEXITCODE -ne 0) {
    Write-Host "    [WARNING] yara-python failed - YARA scanning will be unavailable" -ForegroundColor Yellow
    Write-Host "    Note: yara-python requires Visual C++ Build Tools on Windows" -ForegroundColor Gray
} else {
    Write-Host "    [OK] yara-python" -ForegroundColor Green
}

Write-Host ""
Write-Host "[OK] Dependencies installed" -ForegroundColor Green

# Verify installation
Write-Host ""
Write-Host "[6/6] Verifying installation..." -ForegroundColor Yellow
Write-Host ""

$verifyScript = @"
import sys
sys.path.insert(0, 'src')
from memory_forensics_mcp import MemoryForensicsMCP
mcp = MemoryForensicsMCP()
status = mcp.check_installation()

print('Backend Status:')
print(f"  Volatility 3: {'[OK]' if status['backends']['volatility3']['installed'] else '[NOT INSTALLED]'}")
print(f"  MemProcFS:    {'[OK]' if status['backends']['memprocfs']['installed'] else '[NOT INSTALLED]'}")
print(f"  cdb.exe:      {'[OK]' if status['backends']['cdb']['installed'] else '[NOT INSTALLED]'}")
print(f"  dotnet-dump:  {'[OK]' if status['backends']['dotnet_dump']['installed'] else '[NOT INSTALLED]'}")
print()

if status['any_backend_available']:
    print('[OK] Installation verified - at least one backend available')
    sys.exit(0)
else:
    print('[ERROR] No backends available')
    sys.exit(1)
"@

& $pythonExe -c $verifyScript
if ($LASTEXITCODE -ne 0) {
    Write-Host ""
    Write-Host "[ERROR] Verification failed" -ForegroundColor Red
    exit 1
}

# Success message and next steps
Write-Host ""
Write-Host "========================================" -ForegroundColor Green
Write-Host " Setup Complete!" -ForegroundColor Green
Write-Host "========================================" -ForegroundColor Green
Write-Host ""
Write-Host "Next Steps:" -ForegroundColor Cyan
Write-Host ""
Write-Host "1. Configure your MCP client:" -ForegroundColor White
Write-Host ""
Write-Host "   For Cursor IDE - Add to .cursor/mcp.json:" -ForegroundColor Gray
Write-Host ""
$currentPath = (Get-Location).Path -replace '\\', '/'
Write-Host @"
   {
     "mcpServers": {
       "memory-forensics-mcp": {
         "command": "$currentPath/venv/Scripts/python.exe",
         "args": ["$currentPath/src/memory_forensics_mcp.py"]
       }
     }
   }
"@ -ForegroundColor Yellow
Write-Host ""
Write-Host "   For Claude Desktop - Add to %APPDATA%\Claude\claude_desktop_config.json" -ForegroundColor Gray
Write-Host ""
Write-Host "2. Restart Cursor/Claude Desktop to load the MCP" -ForegroundColor White
Write-Host ""
Write-Host "3. Test with a memory dump:" -ForegroundColor White
Write-Host "   python verify_setup.py C:\path\to\memory.raw" -ForegroundColor Yellow
Write-Host ""
Write-Host "4. Read AGENT_RULES.md for AI agent usage guidance" -ForegroundColor White
Write-Host ""
Write-Host "Optional: Install external tools for advanced features:" -ForegroundColor Cyan
Write-Host "  - cdb.exe: Install Windows SDK Debugging Tools" -ForegroundColor Gray
Write-Host "  - dotnet-dump: dotnet tool install -g dotnet-dump" -ForegroundColor Gray
Write-Host ""
