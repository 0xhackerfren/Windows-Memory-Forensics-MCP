#!/usr/bin/env python3
"""
Quick Start Example

Author: Jacob Krell
Status: Beta

Minimal example to verify installation and demonstrate basic usage.
"""

import sys
from pathlib import Path

# Add src to path for local testing
sys.path.insert(0, str(Path(__file__).parent.parent / "src"))

from memory_forensics_mcp import MemoryForensicsMCP


def main():
    print("Windows Memory Forensics MCP - Quick Start")
    print("=" * 50)
    print()
    
    # Initialize MCP
    mcp = MemoryForensicsMCP()
    
    # Check installation
    print("Checking backend installation...")
    status = mcp.check_installation()
    
    print(f"\nBackend Status:")
    print(f"  Volatility 3: {'[OK]' if status['backends']['volatility3']['installed'] else '[NOT INSTALLED]'}")
    print(f"  MemProcFS:    {'[OK]' if status['backends']['memprocfs']['installed'] else '[NOT INSTALLED]'}")
    print(f"  cdb.exe:      {'[OK]' if status['backends']['cdb']['installed'] else '[NOT INSTALLED]'}")
    print(f"  dotnet-dump:  {'[OK]' if status['backends']['dotnet_dump']['installed'] else '[NOT INSTALLED]'}")
    
    if status["any_backend_available"]:
        print("\n[OK] At least one backend is available!")
        print("\nTo analyze a memory dump, update a script with your memory file path:")
        print('  memory_file = "C:/evidence/memory.raw"')
        print("  result = mcp.list_processes(memory_file=memory_file)")
    else:
        print("\n[!] No backends installed!")
        print("\nInstall at least one backend:")
        print("  pip install volatility3    # Recommended")
        print("  pip install memprocfs      # For advanced features")
    
    print()
    print("Available tools:")
    caps = mcp.list_capabilities()
    for tool in caps["tools"]:
        print(f"  - {tool['name']}: {tool['description'][:60]}...")
    
    print()
    print("Run examples:")
    print("  python examples/basic_analysis.py <memory_file>")
    print("  python examples/malware_detection.py <memory_file> <pid>")
    print("  python examples/staged_payload.py <memory_file> <pid>")


if __name__ == "__main__":
    main()
