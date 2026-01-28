#!/usr/bin/env python3
"""
Basic Memory Analysis Example

Author: Jacob Krell
Status: Beta

Demonstrates core memory forensics workflows using the Memory Forensics MCP.

Usage:
    python basic_analysis.py <memory_file>
    python basic_analysis.py C:/evidence/memory.raw
"""

import argparse
import sys
from pathlib import Path

# Add src to path for local testing
sys.path.insert(0, str(Path(__file__).parent.parent / "src"))

from memory_forensics_mcp import MemoryForensicsMCP


def parse_args():
    parser = argparse.ArgumentParser(
        description="Basic memory analysis using Memory Forensics MCP",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
    python basic_analysis.py C:/evidence/memory.raw
    python basic_analysis.py /path/to/memory.dmp
        """
    )
    parser.add_argument(
        "memory_file",
        help="Path to the memory dump file"
    )
    return parser.parse_args()


def main():
    args = parse_args()
    memory_file = args.memory_file
    
    # Validate memory file exists
    if not Path(memory_file).exists():
        print(f"ERROR: Memory file not found: {memory_file}")
        sys.exit(1)
    
    # Initialize MCP
    mcp = MemoryForensicsMCP()
    
    # Check installation status
    print("=" * 60)
    print("Checking Backend Installation")
    print("=" * 60)
    status = mcp.check_installation()
    print(f"Volatility 3: {'Installed' if status['backends']['volatility3']['installed'] else 'Not installed'}")
    print(f"MemProcFS: {'Installed' if status['backends']['memprocfs']['installed'] else 'Not installed'}")
    print(f"cdb.exe: {'Installed' if status['backends']['cdb']['installed'] else 'Not installed'}")
    print(f"dotnet-dump: {'Installed' if status['backends']['dotnet_dump']['installed'] else 'Not installed'}")
    print()
    
    if not status["any_backend_available"]:
        print("ERROR: No backend available. Install volatility3 or memprocfs.")
        sys.exit(1)
    
    # List processes
    print("=" * 60)
    print("Process Listing")
    print("=" * 60)
    result = mcp.list_processes(memory_file=memory_file)
    
    if result["success"]:
        print(f"Found {result['count']} processes")
        print()
        print(f"{'PID':<8} {'PPID':<8} {'Name':<20} {'CreateTime'}")
        print("-" * 70)
        for proc in result["results"][:20]:  # Show first 20
            pid = proc.get("PID", "N/A")
            ppid = proc.get("PPID", "N/A")
            name = proc.get("ImageFileName", "Unknown")[:20]
            create_time = proc.get("CreateTime", "N/A")
            print(f"{pid:<8} {ppid:<8} {name:<20} {create_time}")
        if result["count"] > 20:
            print(f"... and {result['count'] - 20} more")
    else:
        print(f"Error: {result.get('error')}")
    print()
    
    # Find interesting processes
    print("=" * 60)
    print("Interesting Processes")
    print("=" * 60)
    interesting_names = ["powershell", "cmd", "mshta", "wscript", "cscript", "mmc"]
    for proc in result.get("results", []):
        name = proc.get("ImageFileName", "").lower()
        if any(n in name for n in interesting_names):
            print(f"  [{proc.get('PID')}] {proc.get('ImageFileName')}")
    print()
    
    # Network connections
    print("=" * 60)
    print("Network Connections")
    print("=" * 60)
    netscan_result = mcp.netscan(memory_file=memory_file)
    
    if netscan_result["success"]:
        print(f"Found {netscan_result['count']} network connections/listeners")
        for conn in netscan_result["results"][:10]:  # Show first 10
            print(f"  {conn.get('Proto', 'N/A')} {conn.get('LocalAddr', 'N/A')}:{conn.get('LocalPort', 'N/A')} -> "
                  f"{conn.get('ForeignAddr', 'N/A')}:{conn.get('ForeignPort', 'N/A')} "
                  f"[{conn.get('Owner', 'N/A')}]")
    else:
        print(f"Error: {netscan_result.get('error')}")
    print()
    
    # Malfind - Find injected code
    print("=" * 60)
    print("Malfind - Suspicious Code Regions")
    print("=" * 60)
    malfind_result = mcp.malfind(memory_file=memory_file)
    
    if malfind_result["success"]:
        print(f"Found {malfind_result['count']} suspicious regions")
        for finding in malfind_result["results"][:5]:  # Show first 5
            print(f"  PID {finding.get('PID')}: {finding.get('Process')} at {finding.get('Start')}")
    else:
        print(f"Error: {malfind_result.get('error')}")


if __name__ == "__main__":
    main()
