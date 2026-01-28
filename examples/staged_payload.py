#!/usr/bin/env python3
"""
Staged Payload Extraction Example

Author: Jacob Krell
Status: Beta

Demonstrates extraction and reconstruction of staged payloads from
environment variables. This is a common pattern used by malware like:
- PASTALOADER
- GrimResource
- Various .NET malware loaders

The technique involves storing payload chunks in environment variables
(e.g., B_1, B_2, ... B_N) and reconstructing them at runtime.

Usage:
    python staged_payload.py <memory_file> <pid> [--prefix PREFIX]
    python staged_payload.py C:/evidence/memory.raw 3120 --prefix B_
"""

import argparse
import sys
from pathlib import Path

# Add src to path for local testing
sys.path.insert(0, str(Path(__file__).parent.parent / "src"))

from memory_forensics_mcp import MemoryForensicsMCP


def parse_args():
    parser = argparse.ArgumentParser(
        description="Extract and reconstruct staged payloads from environment variables",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
    python staged_payload.py C:/evidence/memory.raw 3120
    python staged_payload.py C:/evidence/memory.raw 3120 --prefix B_
    python staged_payload.py /path/to/memory.dmp 1234 --prefix PAYLOAD_ --output ./results

Common variable prefixes:
    B_, C_, P_, PAYLOAD_, DATA_, CHUNK_
        """
    )
    parser.add_argument(
        "memory_file",
        help="Path to the memory dump file"
    )
    parser.add_argument(
        "pid",
        type=int,
        help="Target process ID to analyze"
    )
    parser.add_argument(
        "--prefix", "-p",
        default="B_",
        help="Environment variable prefix for staged chunks (default: B_)"
    )
    parser.add_argument(
        "--output", "-o",
        default="./output",
        help="Output directory for extracted payloads (default: ./output)"
    )
    return parser.parse_args()


def main():
    args = parse_args()
    memory_file = args.memory_file
    target_pid = args.pid
    var_prefix = args.prefix
    output_dir = Path(args.output)
    output_dir.mkdir(exist_ok=True)
    
    # Validate memory file exists
    if not Path(memory_file).exists():
        print(f"ERROR: Memory file not found: {memory_file}")
        sys.exit(1)
    
    # Initialize MCP
    mcp = MemoryForensicsMCP()
    
    # Check MemProcFS availability (required for environment extraction)
    status = mcp.check_installation()
    if not status["backends"]["memprocfs"]["installed"]:
        print("WARNING: MemProcFS not installed.")
        print("Environment variable extraction requires MemProcFS.")
        print("Install with: pip install memprocfs")
        print()
    
    print("=" * 70)
    print("STAGED PAYLOAD EXTRACTION")
    print("=" * 70)
    print(f"Memory file: {memory_file}")
    print(f"Target PID: {target_pid}")
    print(f"Variable prefix: {var_prefix}")
    print()
    
    # Step 1: Extract all environment variables
    print("-" * 70)
    print("Step 1: Extracting environment variables...")
    print("-" * 70)
    
    env_result = mcp.get_process_environment(
        memory_file=memory_file,
        pid=target_pid,
        filter_prefix=var_prefix
    )
    
    if not env_result["success"]:
        print(f"[!] Failed: {env_result.get('error')}")
        if "hint" in env_result:
            print(f"    Hint: {env_result['hint']}")
        return
    
    print(f"[+] PEB Address: {env_result.get('peb_address')}")
    print(f"[+] Environment Address: {env_result.get('environment_address')}")
    print(f"[+] Total environment variables: {env_result.get('env_count')}")
    print(f"[+] Variables matching '{var_prefix}*': {env_result.get('filtered_count', 0)}")
    print()
    
    if env_result.get("filtered_count", 0) == 0:
        print(f"No variables found with prefix '{var_prefix}'")
        print("Common prefixes to try: B_, C_, P_, PAYLOAD_, DATA_")
        return
    
    # Show first few variables
    filtered_vars = env_result.get("filtered_vars", {})
    print("Sample staged chunks:")
    sorted_keys = sorted(filtered_vars.keys(), key=lambda x: int(x[len(var_prefix):]) if x[len(var_prefix):].isdigit() else 0)
    for key in sorted_keys[:5]:
        value = filtered_vars[key]
        preview = value[:50] + "..." if len(value) > 50 else value
        print(f"  {key}: {preview} ({len(value)} chars)")
    if len(sorted_keys) > 5:
        print(f"  ... and {len(sorted_keys) - 5} more")
    print()
    
    # Step 2: Try different reconstruction algorithms
    print("-" * 70)
    print("Step 2: Reconstructing payload...")
    print("-" * 70)
    
    algorithms = ["raw_concat", "base64_concat", "pastaloader"]
    
    for algo in algorithms:
        print(f"\nTrying algorithm: {algo}")
        print("-" * 40)
        
        output_path = output_dir / f"payload_{algo}.bin"
        
        result = mcp.reconstruct_staged_payload(
            memory_file=memory_file,
            pid=target_pid,
            var_prefix=var_prefix,
            decode_algorithm=algo,
            output_path=str(output_path)
        )
        
        if result["success"]:
            print(f"  [+] Success!")
            print(f"      Variables used: {result.get('vars_used')}")
            print(f"      Joined length: {result.get('joined_length')} chars")
            print(f"      Decoded length: {result.get('decoded_length')} bytes")
            print(f"      MD5: {result.get('md5')}")
            print(f"      Output: {result.get('output_path')}")
            
            # Check if it's a valid PE
            with open(output_path, "rb") as f:
                header = f.read(2)
                if header == b"MZ":
                    print(f"      [!] Valid PE/DLL detected!")
        else:
            print(f"  [-] Failed: {result.get('error')}")
            if "hint" in result:
                print(f"      Hint: {result['hint']}")
    
    print()
    print("=" * 70)
    print("EXTRACTION COMPLETE")
    print("=" * 70)
    print(f"Output files saved to: {output_dir.resolve()}")
    print()
    print("Next steps:")
    print("  1. Compare MD5 hashes to known malware")
    print("  2. Submit to VirusTotal/malware sandbox")
    print("  3. Analyze in Ghidra/IDA")
    print()
    print("Algorithm notes:")
    print("  - raw_concat: Simple concatenation (try first)")
    print("  - base64_concat: Base64 decode after concat")
    print("  - pastaloader: Remove 'A$+', reverse, base64 decode")


if __name__ == "__main__":
    main()
