# Windows Memory Forensics MCP

<p align="center">
  <img src="https://img.shields.io/badge/status-Proof_of_Concept-orange" alt="Proof of Concept">
  <img src="https://img.shields.io/badge/python-3.10%2B-blue" alt="Python 3.10+">
  <img src="https://img.shields.io/badge/MCP-1.2.0%2B-green" alt="MCP 1.2.0+">
  <img src="https://img.shields.io/badge/license-MIT-blue" alt="MIT License">
  <img src="https://img.shields.io/badge/platform-Windows-lightgrey" alt="Windows">
</p>

> **WARNING: PROOF OF CONCEPT**
>
> This is a proof-of-concept implementation developed for research and CTF purposes.
> **Use at your own risk.** Not recommended for production forensic investigations without thorough testing and validation.

A Model Context Protocol (MCP) server for Windows memory forensics. Provides AI agents with 33 tools for analyzing memory dumps using Volatility 3, MemProcFS, and CLR analysis backends.

**Author:** Jacob Krell

## Prerequisites

Before running setup, ensure you have:

1. **Python 3.10+** - [Download from python.org](https://python.org)
2. **Visual C++ Build Tools** - Required for yara-python compilation
   - [Download Visual C++ Build Tools](https://visualstudio.microsoft.com/visual-cpp-build-tools/)
   - During installation, select **"Desktop development with C++"** workload
   - This is required for YARA scanning functionality

## Quick Setup (One Command)

```powershell
# Clone and setup
git clone https://github.com/0xhackerfren/windows-memory-forensics-mcp.git
cd windows-memory-forensics-mcp
.\setup.ps1
```

The setup script will:
- Create a Python virtual environment
- Install all dependencies (Volatility 3, MemProcFS, pefile, yara-python)
- Verify the installation
- Print configuration instructions for Cursor/Claude

After setup, verify with a memory dump:

```powershell
python verify_setup.py C:\path\to\memory.raw
```

## AI Agent Usage

For AI agent guidance, see **[AGENT_RULES.md](AGENT_RULES.md)** - this file contains:
- Complete tool reference
- Investigation workflow patterns
- Common analysis patterns
- Example commands

You can use AGENT_RULES.md as:
- A Cursor rule (copy to `.cursor/rules/`)
- A Claude Desktop system prompt
- A reference document

## Disclaimer

This software is provided "as-is" for research, education, and CTF purposes.

- **No warranty or guarantee** of accuracy or completeness
- **Test thoroughly** before using on real forensic evidence
- **Not intended for production use** - validate all results independently
- The author is **not responsible** for any damages, data loss, or incorrect conclusions drawn from this tool
- Always follow proper chain-of-custody procedures for real forensic investigations

## Features

- **Pluggable Backends**: Volatility 3, MemProcFS, cdb.exe, dotnet-dump
- **Process Analysis**: List processes, command lines, DLLs, handles
- **Malware Detection**: malfind, hidden module detection, injection detection
- **Memory Extraction**: VAD dumping (raw and reconstructed), arbitrary memory reads
- **CLR/.NET Analysis**: Deep .NET inspection via SOS commands on minidumps
- **Staged Payload Reconstruction**: Extract and decode payloads from environment variables (PASTALOADER, GrimResource patterns)
- **Network Forensics**: Network connection enumeration

## MCP Client Configuration

### Cursor IDE

Add to `.cursor/mcp.json` (create the file if it doesn't exist):

```json
{
  "mcpServers": {
    "memory-forensics-mcp": {
      "command": "C:/path/to/windows-memory-forensics-mcp/venv/Scripts/python.exe",
      "args": ["C:/path/to/windows-memory-forensics-mcp/src/memory_forensics_mcp.py"]
    }
  }
}
```

**Important**: Use the virtual environment Python (`venv/Scripts/python.exe`) to ensure dependencies are available.

Restart Cursor to load the MCP.

### Claude Desktop / Claude Code

Add to `%APPDATA%\Claude\claude_desktop_config.json`:

```json
{
  "mcpServers": {
    "memory-forensics-mcp": {
      "command": "C:/path/to/windows-memory-forensics-mcp/venv/Scripts/python.exe",
      "args": ["C:/path/to/windows-memory-forensics-mcp/src/memory_forensics_mcp.py"]
    }
  }
}
```

Restart Claude Desktop to load the MCP.

## Available Tools (33)

### Process Analysis
| Tool | Description |
|------|-------------|
| `list_processes` | List all processes with PIDs, names, and timestamps |
| `get_cmdline` | Get command line arguments for processes |
| `list_dlls` | List loaded DLLs for a process |
| `ldrmodules` | Compare module lists to detect hidden modules |
| `handles` | List process handles |
| `handles_enriched` | Handles with filtering, summaries, and cross-references |

### Memory Extraction
| Tool | Description |
|------|-------------|
| `vadinfo` | List Virtual Address Descriptors for a process |
| `dump_vad` | Dump VAD region to file (with PE reconstruction) |
| `dump_vad_raw` | Dump raw VAD bytes without reconstruction |
| `read_virtual_memory` | Read arbitrary virtual memory from a process |
| `read_physical_memory` | Read physical memory at a given address |
| `memprocfs_get_minidump` | Extract WinDbg-compatible minidump |

### VFS Browsing (MemProcFS)
| Tool | Description |
|------|-------------|
| `vfs_list` | List directory entries in MemProcFS virtual file system |
| `vfs_read` | Read bytes from a file in MemProcFS VFS |
| `vfs_export` | Export a file from MemProcFS VFS to disk |

### Malware Detection
| Tool | Description |
|------|-------------|
| `malfind` | Find injected or suspicious code |
| `find_hidden_modules` | Find modules not in PEB loader lists |
| `yara_scan` | Scan memory with custom YARA rules |

### Network Forensics
| Tool | Description |
|------|-------------|
| `netscan` | Scan for network connections |
| `filescan` | Scan for file objects in memory |

### Registry Analysis
| Tool | Description |
|------|-------------|
| `list_registry_hives` | List registry hives found in memory |
| `registry_printkey` | Print registry key values from memory |

### CLR/.NET Analysis
| Tool | Description |
|------|-------------|
| `list_clr_modules` | List CLR assemblies with addresses (via SOS) |

### Staged Payload Analysis
| Tool | Description |
|------|-------------|
| `get_process_environment` | Extract environment variables from PEB |
| `reconstruct_staged_payload` | Reconstruct payload from staged env vars |

### Tagging and Timeline (AI Workflow)
| Tool | Description |
|------|-------------|
| `add_tag` | Add a tag to track findings across tool calls |
| `list_tags` | List all tags in the session |
| `clear_tags` | Clear all tags |
| `add_timeline_event` | Add an event to the investigation timeline |
| `list_timeline` | List timeline events |
| `clear_timeline` | Clear timeline events |

### Utility
| Tool | Description |
|------|-------------|
| `check_installation` | Check backend installation status |
| `list_capabilities` | List all available tools |
| `get_documentation` | Get usage documentation |

## Usage Examples

### Basic Process Analysis

```python
# List all processes
result = list_processes(memory_file="C:/evidence/memory.raw")
for proc in result["results"]:
    print(f"PID {proc['PID']}: {proc['ImageFileName']}")

# Get command line for suspicious process
cmdline = get_cmdline(memory_file="C:/evidence/memory.raw", pid=1234)
print(cmdline["results"])
```

### Detect Hidden/Injected Modules

```python
# Use ldrmodules to find modules with suspicious flags
ldr = ldrmodules(memory_file="memory.raw", pid=3120)
for mod in ldr["results"]:
    if not mod["InLoad"] and not mod["InInit"] and not mod["InMem"]:
        print(f"Hidden module: {mod['Base']} - {mod['MappedPath']}")

# Or use the automated detection
hidden = find_hidden_modules(memory_file="memory.raw", pid=3120)
print(f"Found {hidden['count']} hidden modules")
```

### Detect Staged Payloads (PASTALOADER/GrimResource Pattern)

```python
# Extract environment variables with a specific prefix
env = get_process_environment(
    memory_file="memory.raw",
    pid=3120,
    filter_prefix="B_"  # PASTALOADER uses B_1, B_2, ... B_N
)
print(f"Found {env['filtered_count']} staged payload chunks")

# Reconstruct the payload
payload = reconstruct_staged_payload(
    memory_file="memory.raw",
    pid=3120,
    var_prefix="B_",
    decode_algorithm="pastaloader",
    output_path="./output/reconstructed_payload.bin"
)
print(f"Payload MD5: {payload['md5']}")
```

## Backends

The setup script installs all backends automatically:

| Backend | Purpose | Status |
|---------|---------|--------|
| **Volatility 3** | Classic memory forensics | Installed by setup.ps1 |
| **MemProcFS** | VFS access, minidumps, reliable VA reads | Installed by setup.ps1 |
| **pefile** | PE file parsing | Installed by setup.ps1 |
| **yara-python** | YARA rule scanning | Installed by setup.ps1 (may require Visual C++) |

### Optional External Tools

| Tool | Purpose | Install Command |
|------|---------|-----------------|
| **cdb.exe** | Deep CLR/SOS analysis | Install Windows SDK Debugging Tools |
| **dotnet-dump** | .NET Core dump analysis | `dotnet tool install -g dotnet-dump` |

### Backend Selection

Most tools support an `engine` parameter:

```python
# Auto-select best available backend (default)
list_processes(memory_file="memory.raw", engine="auto")

# Force Volatility 3
list_processes(memory_file="memory.raw", engine="volatility")

# Force MemProcFS
list_processes(memory_file="memory.raw", engine="memprocfs")
```

## Troubleshooting

### Common Issues

| Issue | Solution |
|-------|----------|
| "No backend available" | Run `.\setup.ps1` to install dependencies |
| "mcp module not found" | Use venv Python: `venv/Scripts/python.exe` |
| "Memory file not found" | Use absolute paths to memory files |
| "yara-python failed to install" | Install Visual C++ Build Tools, then retry |
| "Kernel symbols not found" | Volatility auto-downloads from Microsoft - ensure internet access |

### Verify Installation

```powershell
# Check backends only
python verify_setup.py --check-only

# Full test with memory file
python verify_setup.py C:\path\to\memory.raw
```

### Manual Installation

If `setup.ps1` fails, install manually:

```powershell
python -m venv venv
.\venv\Scripts\Activate.ps1
pip install mcp volatility3 pefile memprocfs
```

## Project Structure

```
windows-memory-forensics-mcp/
+-- src/
|   +-- memory_forensics_mcp.py  # Main MCP server
+-- examples/
|   +-- basic_analysis.py        # Basic usage examples
|   +-- malware_detection.py     # Malware detection workflow
|   +-- staged_payload.py        # Staged payload reconstruction
|   +-- quickstart.py            # Quick verification script
+-- .cursor/
|   +-- mcp.json.example         # Cursor configuration example
+-- setup.ps1                    # One-command setup script
+-- verify_setup.py              # Installation verification
+-- AGENT_RULES.md               # AI agent usage guide
+-- requirements.txt             # Python dependencies
+-- pyproject.toml               # Package metadata
+-- LICENSE                      # MIT License
+-- README.md                    # This file
```

## Requirements

- Windows 10/11
- Python 3.10+
- PowerShell 5.1+ (for setup.ps1)

All Python dependencies are installed automatically by `setup.ps1`.

## Contributing

Contributions are welcome! Please:

1. Fork the repository
2. Create a feature branch (`git checkout -b feature/amazing-feature`)
3. Commit your changes (`git commit -m 'Add amazing feature'`)
4. Push to the branch (`git push origin feature/amazing-feature`)
5. Open a Pull Request

## License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

## Author

**Jacob Krell** - Creator and maintainer

## Acknowledgments

- [Volatility Foundation](https://www.volatilityfoundation.org/) for Volatility 3
- [Ulf Frisk](https://github.com/ufrisk) for MemProcFS
- [Anthropic](https://anthropic.com/) for the MCP specification
- Hack The Box for the Sherlock challenges that drove development

## Related Projects

- [Volatility 3](https://github.com/volatilityfoundation/volatility3) - Memory forensics framework
- [MemProcFS](https://github.com/ufrisk/MemProcFS) - Memory Process File System
- [MCP Specification](https://modelcontextprotocol.io/) - Model Context Protocol

---

**Proof of Concept** - Created from real-world DFIR investigations. Battle-tested on HTB Sherlock challenges including Novitas (Insane difficulty).

*Use at your own risk. Always validate forensic findings through multiple methods.*
