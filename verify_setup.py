#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Windows Memory Forensics MCP - Setup Verification

Author: Jacob Krell
Status: Proof of Concept - Use at your own risk

Verifies the MCP installation by running core operations against a memory file.

Usage:
    python verify_setup.py C:/path/to/memory.raw
    python verify_setup.py --check-only  # Only check backends, no memory file
"""

import sys
import argparse
import warnings
import time
from pathlib import Path

# Suppress deprecation warnings from Volatility
warnings.filterwarnings("ignore", category=FutureWarning)
warnings.filterwarnings("ignore", category=DeprecationWarning)

# Add src to path
sys.path.insert(0, str(Path(__file__).parent / "src"))


def print_header(text):
    """Print section header"""
    print()
    print("=" * 70)
    print(f" {text}")
    print("=" * 70)


def print_step(step, total, text):
    """Print step progress"""
    print(f"\n[{step}/{total}] {text}")


def print_substep(text):
    """Print substep"""
    print(f"    -> {text}")


def print_result(name, success, details=""):
    """Print test result"""
    status = "[PASS]" if success else "[FAIL]"
    print(f"  {status} {name}")
    if details:
        for line in details.split('\n'):
            print(f"         {line}")


def print_progress(text):
    """Print progress indicator"""
    print(f"    ... {text}", end="", flush=True)


def print_done(extra=""):
    """Print done indicator"""
    if extra:
        print(f" done. {extra}")
    else:
        print(" done.")


def check_backends(mcp):
    """Check backend installation status"""
    print_header("Backend Installation Check")
    
    print_step(1, 4, "Checking Volatility 3...")
    status = mcp.check_installation()
    
    all_pass = True
    
    # Volatility 3
    vol_ok = status['backends']['volatility3']['installed']
    vol_version = status['backends']['volatility3'].get('version', 'unknown')
    print_result(
        "Volatility 3",
        vol_ok,
        f"Version: {vol_version}" if vol_ok else "Not installed - run: pip install volatility3"
    )
    if not vol_ok:
        all_pass = False
    
    print_step(2, 4, "Checking MemProcFS...")
    # MemProcFS
    memprocfs_ok = status['backends']['memprocfs']['installed']
    memprocfs_version = status['backends']['memprocfs'].get('version', 'unknown')
    print_result(
        "MemProcFS",
        memprocfs_ok,
        f"Version: {memprocfs_version}" if memprocfs_ok else "Not installed - run: pip install memprocfs"
    )
    
    print_step(3, 4, "Checking cdb.exe (optional)...")
    # cdb.exe (optional)
    cdb_ok = status['backends']['cdb']['installed']
    cdb_path = status['backends']['cdb'].get('path', '')
    print_result(
        "cdb.exe",
        cdb_ok,
        f"Path: {cdb_path}" if cdb_ok else "Not installed - Install Windows SDK Debugging Tools"
    )
    
    print_step(4, 4, "Checking dotnet-dump (optional)...")
    # dotnet-dump (optional)
    dotnet_ok = status['backends']['dotnet_dump']['installed']
    print_result(
        "dotnet-dump",
        dotnet_ok,
        "" if dotnet_ok else "Not installed - run: dotnet tool install -g dotnet-dump"
    )
    
    # Overall
    print()
    if status['any_backend_available']:
        print("  [OK] At least one primary backend available")
    else:
        print("  [ERROR] No primary backend available!")
        print("          Run setup.ps1 or install volatility3/memprocfs manually")
        all_pass = False
    
    return all_pass, status


def test_list_processes(mcp, memory_file):
    """Test list_processes operation"""
    print_progress("listing processes")
    start = time.time()
    try:
        result = mcp.list_processes(memory_file=memory_file)
        elapsed = time.time() - start
        if result.get('success'):
            count = result.get('count', 0)
            engine = result.get('engine', 'unknown')
            print_done(f"{count} processes found in {elapsed:.1f}s")
            print_result(
                "list_processes",
                True,
                f"Engine: {engine}\nCount: {count} processes"
            )
            # Show a few sample processes
            procs = result.get('results', [])[:5]
            if procs:
                print("         Sample processes:")
                for p in procs:
                    pid = p.get('PID', 'N/A')
                    name = p.get('ImageFileName', 'Unknown')
                    print(f"           PID {pid}: {name}")
            return True, result.get('results', [])
        else:
            print_done("FAILED")
            print_result("list_processes", False, result.get('error', 'Unknown error'))
            return False, []
    except Exception as e:
        print_done("FAILED")
        print_result("list_processes", False, str(e))
        return False, []


def test_netscan(mcp, memory_file):
    """Test netscan operation"""
    print_progress("scanning network connections")
    start = time.time()
    try:
        result = mcp.netscan(memory_file=memory_file)
        elapsed = time.time() - start
        if result.get('success'):
            count = result.get('count', 0)
            print_done(f"{count} connections found in {elapsed:.1f}s")
            print_result("netscan", True, f"Count: {count} connections/listeners")
            # Show a few sample connections
            conns = result.get('results', [])[:3]
            if conns:
                print("         Sample connections:")
                for c in conns:
                    proto = c.get('Proto', 'N/A')
                    local = f"{c.get('LocalAddr', '?')}:{c.get('LocalPort', '?')}"
                    foreign = f"{c.get('ForeignAddr', '?')}:{c.get('ForeignPort', '?')}"
                    owner = c.get('Owner', 'N/A')
                    print(f"           {proto} {local} -> {foreign} [{owner}]")
            return True
        else:
            print_done("FAILED")
            print_result("netscan", False, result.get('error', 'Unknown error'))
            return False
    except Exception as e:
        print_done("FAILED")
        print_result("netscan", False, str(e))
        return False


def test_malfind(mcp, memory_file):
    """Test malfind operation"""
    print_progress("scanning for suspicious memory regions")
    start = time.time()
    try:
        result = mcp.malfind(memory_file=memory_file)
        elapsed = time.time() - start
        if result.get('success'):
            count = result.get('count', 0)
            print_done(f"{count} suspicious regions found in {elapsed:.1f}s")
            print_result("malfind", True, f"Count: {count} suspicious regions")
            # Show a few findings
            findings = result.get('results', [])[:3]
            if findings:
                print("         Sample findings:")
                for f in findings:
                    pid = f.get('PID', 'N/A')
                    proc = f.get('Process', 'Unknown')
                    start_addr = f.get('Start', 'N/A')
                    print(f"           PID {pid} ({proc}) at {start_addr}")
            return True
        else:
            print_done("FAILED")
            print_result("malfind", False, result.get('error', 'Unknown error'))
            return False
    except Exception as e:
        print_done("FAILED")
        print_result("malfind", False, str(e))
        return False


def test_list_dlls(mcp, memory_file, pid, proc_name):
    """Test list_dlls operation"""
    print_progress(f"listing DLLs for PID {pid} ({proc_name})")
    start = time.time()
    try:
        result = mcp.list_dlls(memory_file=memory_file, pid=pid)
        elapsed = time.time() - start
        if result.get('success'):
            count = result.get('count', 0)
            print_done(f"{count} DLLs found in {elapsed:.1f}s")
            print_result("list_dlls", True, f"PID: {pid}\nCount: {count} DLLs")
            # Show a few DLLs
            dlls = result.get('results', [])[:3]
            if dlls:
                print("         Sample DLLs:")
                for d in dlls:
                    name = d.get('Name', 'Unknown')
                    base = d.get('Base', 'N/A')
                    print(f"           {base}: {name}")
            return True
        else:
            print_done("FAILED")
            print_result("list_dlls", False, result.get('error', 'Unknown error'))
            return False
    except Exception as e:
        print_done("FAILED")
        print_result("list_dlls", False, str(e))
        return False


def test_get_cmdline(mcp, memory_file, pid, proc_name):
    """Test get_cmdline operation"""
    print_progress(f"getting command line for PID {pid} ({proc_name})")
    start = time.time()
    try:
        result = mcp.get_cmdline(memory_file=memory_file, pid=pid)
        elapsed = time.time() - start
        if result.get('success'):
            print_done(f"retrieved in {elapsed:.1f}s")
            results = result.get('results', [])
            if results and len(results) > 0:
                cmdline = results[0].get('Args', 'N/A')
            else:
                cmdline = "(no command line found)"
            # Truncate if too long
            if len(cmdline) > 80:
                cmdline = cmdline[:77] + "..."
            print_result("get_cmdline", True, f"PID: {pid}\nCommand: {cmdline}")
            return True
        else:
            print_done("FAILED")
            print_result("get_cmdline", False, result.get('error', 'Unknown error'))
            return False
    except Exception as e:
        print_done("FAILED")
        print_result("get_cmdline", False, str(e))
        return False


def test_vadinfo(mcp, memory_file, pid, proc_name):
    """Test vadinfo operation"""
    print_progress(f"listing VADs for PID {pid} ({proc_name})")
    start = time.time()
    try:
        result = mcp.vadinfo(memory_file=memory_file, pid=pid)
        elapsed = time.time() - start
        if result.get('success'):
            count = result.get('count', 0)
            print_done(f"{count} VADs found in {elapsed:.1f}s")
            print_result("vadinfo", True, f"PID: {pid}\nCount: {count} VAD entries")
            return True
        else:
            print_done("FAILED")
            print_result("vadinfo", False, result.get('error', 'Unknown error'))
            return False
    except Exception as e:
        print_done("FAILED")
        print_result("vadinfo", False, str(e))
        return False


def test_vfs_list(mcp, memory_file):
    """Test VFS list operation"""
    print_progress("listing VFS root directory")
    start = time.time()
    try:
        result = mcp.vfs_list(memory_file=memory_file, path="/")
        elapsed = time.time() - start
        if result.get('success'):
            count = result.get('count', 0)
            print_done(f"{count} entries in {elapsed:.1f}s")
            entries = [e.get('name', '?') for e in result.get('entries', [])[:5]]
            print_result("vfs_list", True, f"Root entries: {', '.join(entries)}...")
            return True
        else:
            print_done("FAILED")
            print_result("vfs_list", False, result.get('error', 'Unknown error'))
            return False
    except Exception as e:
        print_done("FAILED")
        print_result("vfs_list", False, str(e))
        return False


def test_registry_hives(mcp, memory_file):
    """Test registry hive listing"""
    print_progress("listing registry hives")
    start = time.time()
    try:
        result = mcp.list_registry_hives(memory_file=memory_file)
        elapsed = time.time() - start
        if result.get('success'):
            count = result.get('count', 0)
            print_done(f"{count} hives in {elapsed:.1f}s")
            print_result("list_registry_hives", True, f"Found {count} registry hives")
            return True
        else:
            print_done("FAILED")
            print_result("list_registry_hives", False, result.get('error', 'Unknown error'))
            return False
    except Exception as e:
        print_done("FAILED")
        print_result("list_registry_hives", False, str(e))
        return False


def test_tagging(mcp):
    """Test tagging functionality"""
    print_progress("testing tag operations")
    try:
        # Add a tag
        result = mcp.add_tag(tag_id="test_tag", tag_type="test", value="test_value", notes="Test")
        if not result.get('success'):
            print_done("FAILED")
            print_result("add_tag", False, result.get('error', 'Unknown error'))
            return False
        
        # List tags
        result = mcp.list_tags()
        if not result.get('success') or result.get('count', 0) < 1:
            print_done("FAILED")
            print_result("list_tags", False, "Tag not found after adding")
            return False
        
        # Clear tags
        result = mcp.clear_tags()
        if not result.get('success'):
            print_done("FAILED")
            print_result("clear_tags", False, result.get('error', 'Unknown error'))
            return False
        
        print_done("ok")
        print_result("tagging", True, "add_tag, list_tags, clear_tags all working")
        return True
    except Exception as e:
        print_done("FAILED")
        print_result("tagging", False, str(e))
        return False


def test_timeline(mcp):
    """Test timeline functionality"""
    print_progress("testing timeline operations")
    try:
        # Add an event
        result = mcp.add_timeline_event(
            timestamp="2024-01-01T00:00:00",
            event_type="test",
            description="Test event"
        )
        if not result.get('success'):
            print_done("FAILED")
            print_result("add_timeline_event", False, result.get('error', 'Unknown error'))
            return False
        
        # List timeline
        result = mcp.list_timeline()
        if not result.get('success') or result.get('count', 0) < 1:
            print_done("FAILED")
            print_result("list_timeline", False, "Event not found after adding")
            return False
        
        # Clear timeline
        result = mcp.clear_timeline()
        if not result.get('success'):
            print_done("FAILED")
            print_result("clear_timeline", False, result.get('error', 'Unknown error'))
            return False
        
        print_done("ok")
        print_result("timeline", True, "add_timeline_event, list_timeline, clear_timeline all working")
        return True
    except Exception as e:
        print_done("FAILED")
        print_result("timeline", False, str(e))
        return False


def run_memory_tests(mcp, memory_file):
    """Run tests against a memory file"""
    print_header("Memory Analysis Tests")
    print(f"  Memory file: {memory_file}")
    
    file_size = Path(memory_file).stat().st_size
    file_size_gb = file_size / (1024 * 1024 * 1024)
    print(f"  File size:   {file_size_gb:.2f} GB")
    print()
    print("  Running comprehensive tests (this may take a few minutes)...")
    
    passed = 0
    failed = 0
    total_tests = 10
    
    # Test 1: list_processes
    print_step(1, total_tests, "Testing process enumeration...")
    success, processes = test_list_processes(mcp, memory_file)
    if success:
        passed += 1
    else:
        failed += 1
    
    # Test 2: netscan
    print_step(2, total_tests, "Testing network scanning...")
    if test_netscan(mcp, memory_file):
        passed += 1
    else:
        failed += 1
    
    # Test 3: malfind
    print_step(3, total_tests, "Testing malware detection...")
    if test_malfind(mcp, memory_file):
        passed += 1
    else:
        failed += 1
    
    # Get a test PID (prefer something common like explorer.exe or svchost.exe)
    test_pid = None
    test_name = None
    if processes:
        # Try to find a known process
        for name in ['explorer.exe', 'svchost.exe', 'services.exe', 'lsass.exe']:
            for proc in processes:
                if proc.get('ImageFileName', '').lower() == name.lower():
                    test_pid = proc.get('PID')
                    test_name = proc.get('ImageFileName')
                    break
            if test_pid:
                break
        
        # Fall back to first process with a PID
        if not test_pid:
            for proc in processes:
                if proc.get('PID'):
                    test_pid = proc.get('PID')
                    test_name = proc.get('ImageFileName', 'Unknown')
                    break
    
    if test_pid:
        print(f"\n  Using test process: PID {test_pid} ({test_name})")
        
        # Test 4: list_dlls
        print_step(4, total_tests, "Testing DLL enumeration...")
        if test_list_dlls(mcp, memory_file, test_pid, test_name):
            passed += 1
        else:
            failed += 1
        
        # Test 5: get_cmdline
        print_step(5, total_tests, "Testing command line extraction...")
        if test_get_cmdline(mcp, memory_file, test_pid, test_name):
            passed += 1
        else:
            failed += 1
        
        # Test 6: vadinfo
        print_step(6, total_tests, "Testing VAD enumeration...")
        if test_vadinfo(mcp, memory_file, test_pid, test_name):
            passed += 1
        else:
            failed += 1
    else:
        print("\n  [WARNING] No test process found - skipping process-specific tests")
        print_result("list_dlls", False, "No test PID available")
        print_result("get_cmdline", False, "No test PID available")
        print_result("vadinfo", False, "No test PID available")
        failed += 3
    
    # Test 7: VFS browsing (MemProcFS)
    print_step(7, total_tests, "Testing VFS browsing (MemProcFS)...")
    if test_vfs_list(mcp, memory_file):
        passed += 1
    else:
        failed += 1
    
    # Test 8: Registry hives
    print_step(8, total_tests, "Testing registry hive listing...")
    if test_registry_hives(mcp, memory_file):
        passed += 1
    else:
        failed += 1
    
    # Test 9: Tagging
    print_step(9, total_tests, "Testing tagging utilities...")
    if test_tagging(mcp):
        passed += 1
    else:
        failed += 1
    
    # Test 10: Timeline
    print_step(10, total_tests, "Testing timeline utilities...")
    if test_timeline(mcp):
        passed += 1
    else:
        failed += 1
    
    return passed, failed


def main():
    parser = argparse.ArgumentParser(
        description="Verify Windows Memory Forensics MCP installation",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
    python verify_setup.py C:/evidence/memory.raw
    python verify_setup.py --check-only

Author: Jacob Krell
Status: Proof of Concept
        """
    )
    parser.add_argument(
        'memory_file',
        nargs='?',
        help='Path to memory dump file'
    )
    parser.add_argument(
        '--check-only',
        action='store_true',
        help='Only check backend installation, skip memory tests'
    )
    parser.add_argument(
        '-v', '--verbose',
        action='store_true',
        help='Enable verbose output'
    )
    
    args = parser.parse_args()
    
    print()
    print("=" * 70)
    print(" Windows Memory Forensics MCP - Setup Verification")
    print(" Author: Jacob Krell | Proof of Concept")
    print("=" * 70)
    
    # Initialize MCP
    print()
    print("Initializing MCP...")
    print_progress("loading memory forensics module")
    try:
        from memory_forensics_mcp import MemoryForensicsMCP
        mcp = MemoryForensicsMCP()
        print_done()
    except Exception as e:
        print_done("FAILED")
        print()
        print(f"[ERROR] Failed to initialize MCP: {e}")
        print("        Run setup.ps1 to install dependencies")
        sys.exit(1)
    
    # Check backends
    backends_ok, status = check_backends(mcp)
    
    if args.check_only:
        print()
        if backends_ok:
            print("[OK] Backend check passed")
            sys.exit(0)
        else:
            print("[FAIL] Backend check failed")
            sys.exit(1)
    
    # Validate memory file
    if not args.memory_file:
        print()
        print("[INFO] No memory file specified. Use --check-only or provide a path:")
        print("       python verify_setup.py C:/path/to/memory.raw")
        print()
        if backends_ok:
            print("[OK] Backend check passed (no memory tests run)")
            sys.exit(0)
        else:
            sys.exit(1)
    
    memory_path = Path(args.memory_file)
    if not memory_path.exists():
        print()
        print(f"[ERROR] Memory file not found: {args.memory_file}")
        sys.exit(1)
    
    if not status['any_backend_available']:
        print()
        print("[ERROR] Cannot run memory tests - no backend available")
        sys.exit(1)
    
    # Run memory tests
    passed, failed = run_memory_tests(mcp, str(memory_path.resolve()))
    
    # Summary
    print_header("Summary")
    total = passed + failed
    print(f"  Tests run:    {total}")
    print(f"  Tests passed: {passed}")
    print(f"  Tests failed: {failed}")
    print(f"  Success rate: {100*passed/total:.0f}%")
    print()
    
    if failed == 0:
        print("[OK] All tests passed - MCP is fully operational!")
        print()
        print("Next steps:")
        print("  1. Copy the MCP configuration to your .cursor/mcp.json")
        print("  2. Restart Cursor to load the MCP")
        print("  3. Start investigating with AI assistance!")
        print()
        print("See AGENT_RULES.md for AI agent usage guidance")
        sys.exit(0)
    elif passed > 0:
        print(f"[PARTIAL] {passed}/{total} tests passed")
        print()
        print("The MCP is partially working. Some features may be unavailable.")
        print("Check the failed tests above for details.")
        sys.exit(0)
    else:
        print("[FAIL] All tests failed")
        print()
        print("Troubleshooting:")
        print("  1. Check that the memory file is a valid Windows memory dump")
        print("  2. Try a different engine: engine='memprocfs' or engine='volatility'")
        print("  3. Re-run setup.ps1 to reinstall dependencies")
        sys.exit(1)


if __name__ == "__main__":
    main()
