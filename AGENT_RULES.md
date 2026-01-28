# Windows Memory Forensics MCP - AI Agent Rules

This document provides guidance for AI agents using the Windows Memory Forensics MCP.
It can be used as a system prompt, Cursor rule, or reference document.

Author: Jacob Krell
Status: Beta

---

## Overview

You have access to the **Windows Memory Forensics MCP**, which provides 33 tools for analyzing Windows memory dumps. The MCP supports multiple backends (Volatility 3, MemProcFS) and enables flexible, dynamic exploration of any part of a memory dump.

**Key Capabilities:**
- Process analysis and malware detection
- Arbitrary memory reads (virtual and physical)
- VFS browsing for flexible artifact access
- Custom YARA scanning
- Registry hive analysis
- Tagging and timeline utilities for investigation tracking

## Available Tools

### Process Analysis

| Tool | Description | Key Parameters |
|------|-------------|----------------|
| `list_processes` | List all processes with PIDs, names, timestamps | `memory_file`, `pid` (optional filter) |
| `get_cmdline` | Get command line arguments | `memory_file`, `pid` |
| `list_dlls` | List loaded DLLs for a process | `memory_file`, `pid` |
| `ldrmodules` | Compare loader lists to detect hidden modules | `memory_file`, `pid` |
| `handles` | List process handles | `memory_file`, `pid` |
| `handles_enriched` | Handles with filtering and cross-references | `memory_file`, `pid`, `object_type`, `name_filter` |

### Memory Extraction

| Tool | Description | Key Parameters |
|------|-------------|----------------|
| `vadinfo` | List Virtual Address Descriptors | `memory_file`, `pid` |
| `dump_vad` | Dump VAD region with PE reconstruction | `memory_file`, `pid`, `address`, `output_path` |
| `dump_vad_raw` | Dump raw VAD bytes (for hash matching) | `memory_file`, `pid`, `address`, `output_path` |
| `read_virtual_memory` | Read arbitrary virtual memory | `memory_file`, `pid`, `address`, `size` |
| `read_physical_memory` | Read physical memory at address | `memory_file`, `address`, `size` |
| `memprocfs_get_minidump` | Extract WinDbg-compatible minidump | `memory_file`, `pid`, `output_path` |

### VFS Browsing (MemProcFS)

| Tool | Description | Key Parameters |
|------|-------------|----------------|
| `vfs_list` | List directory entries in VFS | `memory_file`, `path` |
| `vfs_read` | Read bytes from VFS file | `memory_file`, `path`, `size`, `offset` |
| `vfs_export` | Export file from VFS to disk | `memory_file`, `vfs_path`, `output_path` |

### Malware Detection

| Tool | Description | Key Parameters |
|------|-------------|----------------|
| `malfind` | Find injected/suspicious code regions | `memory_file`, `pid` (optional) |
| `find_hidden_modules` | Find modules not in PEB loader lists | `memory_file`, `pid` |
| `yara_scan` | Scan memory with custom YARA rules | `memory_file`, `rules_text`, `scope`, `pid` |

### Network Forensics

| Tool | Description | Key Parameters |
|------|-------------|----------------|
| `netscan` | Scan for network connections | `memory_file` |
| `filescan` | Scan for file objects in memory | `memory_file` |

### Registry Analysis

| Tool | Description | Key Parameters |
|------|-------------|----------------|
| `list_registry_hives` | List registry hives in memory | `memory_file` |
| `registry_printkey` | Print registry key values | `memory_file`, `key_path`, `hive_offset` |

### CLR/.NET Analysis

| Tool | Description | Key Parameters |
|------|-------------|----------------|
| `list_clr_modules` | List CLR assemblies with addresses | `memory_file`, `pid` |

### Staged Payload Analysis

| Tool | Description | Key Parameters |
|------|-------------|----------------|
| `get_process_environment` | Extract environment variables from PEB | `memory_file`, `pid`, `filter_prefix` |
| `reconstruct_staged_payload` | Reconstruct payload from staged env vars | `memory_file`, `pid`, `var_prefix`, `decode_algorithm`, `output_path` |

### Tagging and Timeline (AI Workflow)

| Tool | Description | Key Parameters |
|------|-------------|----------------|
| `add_tag` | Tag a finding for later reference | `tag_id`, `tag_type`, `value`, `notes` |
| `list_tags` | List all session tags | `tag_type` (optional filter) |
| `clear_tags` | Clear all tags | (none) |
| `add_timeline_event` | Add event to timeline | `timestamp`, `event_type`, `description` |
| `list_timeline` | List timeline events | `event_type`, `pid` (optional filters) |
| `clear_timeline` | Clear timeline | (none) |

### Utility

| Tool | Description | Key Parameters |
|------|-------------|----------------|
| `check_installation` | Check backend installation status | (none) |
| `list_capabilities` | List all available tools | (none) |
| `get_documentation` | Get usage documentation | (none) |

---

## Investigation Workflow

### Step 1: Verify Setup

Always start by checking the installation:

```
check_installation()
```

This confirms which backends are available and operational.

### Step 2: Get Process Overview

List all processes to understand what was running:

```
list_processes(memory_file="path/to/memory.raw")
```

Look for:
- Suspicious process names (powershell, cmd, mshta, wscript, cscript)
- Unusual parent-child relationships
- Processes with unusual creation times

### Step 3: Investigate Suspicious Processes

For each suspicious process:

1. Get command line arguments:
   ```
   get_cmdline(memory_file="...", pid=1234)
   ```

2. List loaded DLLs:
   ```
   list_dlls(memory_file="...", pid=1234)
   ```

3. Check for hidden modules:
   ```
   ldrmodules(memory_file="...", pid=1234)
   find_hidden_modules(memory_file="...", pid=1234)
   ```

### Step 4: Check for Malware Indicators

Run malfind to detect injected code:

```
malfind(memory_file="path/to/memory.raw")
```

This finds:
- Memory regions with executable permissions but no file backing
- Injected shellcode
- Hollow processes

### Step 5: Network Analysis

Check for network connections:

```
netscan(memory_file="path/to/memory.raw")
```

Look for:
- Connections to unusual ports
- External IP addresses
- Listening services

---

## Common Analysis Patterns

### Pattern 1: .NET Malware Analysis

For .NET processes (look for clr.dll in loaded modules):

1. Extract minidump for deep analysis:
   ```
   memprocfs_get_minidump(memory_file="...", pid=1234, output_path="./output/process.dmp")
   ```

2. List CLR assemblies:
   ```
   list_clr_modules(memory_file="...", pid=1234)
   ```

### Pattern 2: Staged Payload Detection (PASTALOADER/GrimResource)

Modern malware stores payload chunks in environment variables:

1. Check for suspicious environment variables:
   ```
   get_process_environment(memory_file="...", pid=1234, filter_prefix="B_")
   ```

2. Reconstruct the payload:
   ```
   reconstruct_staged_payload(
       memory_file="...",
       pid=1234,
       var_prefix="B_",
       decode_algorithm="pastaloader",
       output_path="./output/payload.bin"
   )
   ```

### Pattern 3: Hidden Module Detection

Malware like DirtyCLR hides modules from the PEB:

1. Compare loader lists:
   ```
   ldrmodules(memory_file="...", pid=1234)
   ```
   Look for modules where InLoad=False, InInit=False, InMem=False

2. Use automated detection:
   ```
   find_hidden_modules(memory_file="...", pid=1234)
   ```

### Pattern 4: Memory Dumping for Hash Matching

To get accurate hashes of in-memory modules:

1. Use raw dump (no PE reconstruction):
   ```
   dump_vad_raw(
       memory_file="...",
       pid=1234,
       address=0x06630000,
       output_path="./output/module.bin",
       trim_trailing_zeros=True
   )
   ```

2. The result includes both raw and trimmed MD5 hashes

### Pattern 5: VFS Browsing for Flexible Exploration

Use MemProcFS VFS to explore any part of the memory dump:

1. List root directory to see available paths:
   ```
   vfs_list(memory_file="...", path="/")
   ```

2. Browse process-specific data:
   ```
   vfs_list(memory_file="...", path="/pid/1234/")
   vfs_list(memory_file="...", path="/pid/1234/modules/")
   ```

3. Read specific files:
   ```
   vfs_read(memory_file="...", path="/pid/1234/modules/ntdll.dll", size=4096)
   ```

4. Export artifacts:
   ```
   vfs_export(memory_file="...", vfs_path="/pid/1234/modules/suspicious.dll", output_path="./output/suspicious.dll")
   ```

### Pattern 6: Custom YARA Scanning

Scan memory with your own YARA rules:

1. Scan a specific process's VADs:
   ```
   yara_scan(
       memory_file="...",
       rules_text='rule test { strings: $a = "malware" condition: $a }',
       scope="process_vads",
       pid=1234
   )
   ```

2. Scan a specific memory range:
   ```
   yara_scan(
       memory_file="...",
       rules_text='rule shellcode { strings: $mz = { 4D 5A } condition: $mz }',
       scope="process_range",
       pid=1234,
       address=0x7ff00000,
       size=0x10000
   )
   ```

3. Scan the entire dump (slower):
   ```
   yara_scan(memory_file="...", rules_path="./rules/malware.yar", scope="full_dump")
   ```

### Pattern 7: Registry Analysis

Investigate registry artifacts in memory:

1. List available hives:
   ```
   list_registry_hives(memory_file="...")
   ```

2. Print key values (e.g., Run keys for persistence):
   ```
   registry_printkey(
       memory_file="...",
       key_path="Software\\Microsoft\\Windows\\CurrentVersion\\Run"
   )
   ```

### Pattern 8: Investigation Tracking with Tags and Timeline

Use tags and timeline to track findings across tool calls:

1. Tag important findings:
   ```
   add_tag(tag_id="suspicious_pid", tag_type="pid", value="3120", notes="PowerShell with encoded command")
   add_tag(tag_id="c2_ip", tag_type="ioc", value="192.168.1.100", notes="Outbound connection to C2")
   ```

2. Build a timeline of events:
   ```
   add_timeline_event(timestamp="2024-01-15T10:30:00", event_type="process_start", description="PowerShell started", pid=3120)
   add_timeline_event(timestamp="2024-01-15T10:31:00", event_type="network", description="C2 connection established")
   ```

3. Review findings:
   ```
   list_tags()
   list_timeline()
   ```

---

## Engine Selection

Most tools support an `engine` parameter:

- `"auto"` (default): Automatically select best available backend
- `"volatility"`: Force Volatility 3
- `"memprocfs"`: Force MemProcFS

MemProcFS is preferred for:
- Minidump extraction
- Reliable virtual address reads
- Module enumeration

Volatility is preferred for:
- Classic plugins (malfind, netscan, handles)
- Wider plugin ecosystem

---

## Error Handling

### Common Errors

| Error | Cause | Solution |
|-------|-------|----------|
| "No backend available" | Neither Volatility nor MemProcFS installed | Run `setup.ps1` |
| "Memory file not found" | Invalid path | Check file path, use absolute paths |
| "Process not found" | Invalid PID | Verify PID with `list_processes` |
| "Kernel symbols not found" | Missing symbol tables | Volatility auto-downloads from Microsoft |

### Troubleshooting

1. Check installation status:
   ```
   check_installation()
   ```

2. Try a different engine:
   ```
   list_processes(memory_file="...", engine="memprocfs")
   ```

3. Verify the memory file is a valid Windows memory dump

---

## Best Practices

1. **Start with overview**: Always run `list_processes` and `netscan` first
2. **Use absolute paths**: Provide full paths to memory files
3. **Check backends**: Verify backend availability before analysis
4. **Document findings**: Keep track of PIDs, addresses, and timestamps
5. **Extract artifacts**: Use `dump_vad_raw` for evidence preservation
6. **Validate results**: Cross-reference findings between backends

---

## Example Investigation Flow

```
# 1. Verify setup
check_installation()

# 2. Get process list
list_processes(memory_file="C:/evidence/memory.raw")

# 3. Found suspicious powershell.exe (PID 3120)
get_cmdline(memory_file="C:/evidence/memory.raw", pid=3120)
list_dlls(memory_file="C:/evidence/memory.raw", pid=3120)

# 4. Check for injected code
malfind(memory_file="C:/evidence/memory.raw", pid=3120)

# 5. Look for hidden modules
find_hidden_modules(memory_file="C:/evidence/memory.raw", pid=3120)

# 6. Check environment variables for staged payloads
get_process_environment(memory_file="C:/evidence/memory.raw", pid=3120)

# 7. Extract suspicious module
dump_vad_raw(
    memory_file="C:/evidence/memory.raw",
    pid=3120,
    address=0x06630000,
    output_path="C:/output/suspicious.bin"
)

# 8. Check network connections
netscan(memory_file="C:/evidence/memory.raw")
```

---

## Quick Reference

| Task | Tool |
|------|------|
| List processes | `list_processes` |
| Get command line | `get_cmdline` |
| Find injected code | `malfind` |
| Find hidden modules | `find_hidden_modules` |
| List network connections | `netscan` |
| Dump memory region | `dump_vad_raw` |
| Extract .NET info | `list_clr_modules`, `memprocfs_get_minidump` |
| Extract staged payload | `reconstruct_staged_payload` |

---

*This MCP is a proof of concept. Always validate forensic findings through multiple methods.*
