# -*- coding: utf-8 -*-
"""
Windows Memory Forensics MCP Server

Author: Jacob Krell
License: MIT
Status: Beta

A Model Context Protocol (MCP) server for Windows memory forensics.
Provides AI agents with 33 tools for analyzing memory dumps.

Backends:
- Volatility 3: Classic memory forensics (pslist, dlllist, malfind, etc.)
- MemProcFS: VFS access + per-process minidumps + reliable VA reads
- cdb.exe/dotnet-dump: Deep CLR inspection via SOS commands

See README.md for full tool list and usage instructions.
"""

import sys
import os
import json
import hashlib
import logging
import subprocess
import shutil
import re
import struct
import base64
import traceback
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple
from datetime import datetime


# Standalone BaseMCP class (no external dependencies)
class BaseMCP:
    """Base class for MCP servers - provides minimal interface"""
    
    def __init__(self):
        self.name = "base-mcp"
        self.version = "1.0.0"
        self.tool_name = "tool"
        self.category = "core"
        self.official_docs = ""
        self.tool_path = None
        self.is_wsl = False
    
    def _register_mcp(self):
        """Register MCP (no-op for standalone)"""
        pass

# Backend availability flags
VOLATILITY_AVAILABLE = False
MEMPROCFS_AVAILABLE = False

# Try to import Volatility 3
try:
    import volatility3
    from volatility3 import framework
    from volatility3.framework import contexts, automagic, plugins, interfaces
    from volatility3.framework.configuration import requirements
    import volatility3.plugins
    VOLATILITY_AVAILABLE = True
except ImportError:
    pass

# Try to import MemProcFS
try:
    import memprocfs
    MEMPROCFS_AVAILABLE = True
except ImportError:
    pass

logger = logging.getLogger(__name__)

# MCP Server metadata
MCP_INFO = {
    "name": "memory-forensics-mcp",
    "version": "1.1.0",
    "description": "Windows memory forensics MCP with Volatility 3, MemProcFS, and CLR analysis",
    "category": "forensics",
    "author": "Jacob Krell",
    "license": "MIT",
    "status": "proof-of-concept"
}


# =============================================================================
# BACKEND CLASSES
# =============================================================================

class VolatilityBackend:
    """
    Volatility 3 backend for memory forensics
    
    Provides classic Volatility 3 plugin access via library calls.
    """
    
    def __init__(self):
        self._current_memory_file = None
        self._context = None
        self._automagics = None
        self._plugins_loaded = False
    
    @property
    def available(self) -> bool:
        return VOLATILITY_AVAILABLE
    
    def _load_plugins(self):
        """Load all Volatility 3 plugins
        
        Note: Some plugins may fail to load due to missing optional dependencies
        (e.g., yara-python for YARA scanning plugins). This is expected and
        does not affect core functionality.
        """
        if self._plugins_loaded:
            return
        
        try:
            framework.require_interface_version(2, 0, 0)
            # Suppress plugin loading failures - they are typically for optional
            # features like YARA scanning that require extra dependencies
            failures = framework.import_files(volatility3.plugins, True)
            # Only log at debug level to avoid noisy output
            if failures:
                logger.debug(f"Optional plugins not loaded (missing dependencies): {len(failures)}")
            self._plugins_loaded = True
        except Exception as e:
            logger.error(f"Failed to load Volatility plugins: {e}")
    
    def get_context(self, memory_file: str) -> Optional[contexts.Context]:
        """Create or return cached Volatility context for memory file"""
        if not VOLATILITY_AVAILABLE:
            return None

        # Lazy-load plugins to avoid noisy startup for simple scripts
        # (for example, quickstart scripts that only call check_installation()).
        self._load_plugins()
        
        memory_path = Path(memory_file).resolve()
        if not memory_path.exists():
            logger.error(f"Memory file not found: {memory_path}")
            return None
        
        if self._context is None or self._current_memory_file != str(memory_path):
            try:
                self._context = contexts.Context()
                file_uri = memory_path.as_uri()
                self._context.config['automagic.LayerStacker.single_location'] = file_uri
                self._automagics = automagic.available(self._context)
                self._current_memory_file = str(memory_path)
                logger.info(f"Created context for: {memory_path}")
            except Exception as e:
                logger.error(f"Failed to create context: {e}")
                self._context = None
                return None
        
        return self._context
    
    def run_plugin(self, memory_file: str, plugin_class, **plugin_args) -> Dict[str, Any]:
        """Run a Volatility plugin and return results"""
        ctx = self.get_context(memory_file)
        if ctx is None:
            return {"success": False, "error": "Failed to create Volatility context"}
        
        try:
            constructed = plugins.construct_plugin(
                ctx,
                self._automagics,
                plugin_class,
                "plugins",
                None,
                None
            )
            
            treegrid = constructed.run()
            
            results = []
            columns = [col.name for col in treegrid.columns]
            
            def visitor(node, accumulator):
                row = {}
                for i, col_name in enumerate(columns):
                    value = node.values[i]
                    if hasattr(value, 'vol'):
                        row[col_name] = str(value)
                    elif isinstance(value, datetime):
                        row[col_name] = value.isoformat()
                    elif isinstance(value, bytes):
                        row[col_name] = value.hex()
                    elif hasattr(value, '__int__'):
                        row[col_name] = int(value)
                    else:
                        row[col_name] = str(value) if value is not None else None
                accumulator.append(row)
                return accumulator
            
            treegrid.populate(visitor, results)
            
            return {
                "success": True,
                "columns": columns,
                "results": results,
                "count": len(results)
            }
            
        except Exception as e:
            logger.error(f"Plugin execution failed: {e}")
            return {
                "success": False,
                "error": str(e),
                "traceback": traceback.format_exc()
            }
    
    def get_version(self) -> Optional[str]:
        """Get Volatility 3 version"""
        if not VOLATILITY_AVAILABLE:
            return None
        try:
            return volatility3.__version__ if hasattr(volatility3, '__version__') else "installed"
        except Exception:
            return None


class MemProcFSBackend:
    """
    MemProcFS backend for memory forensics
    
    Provides alternative parsing + VFS access + per-process minidumps.
    Uses the Python memprocfs library.
    """
    
    def __init__(self):
        self._vmm_cache: Dict[str, Any] = {}  # Cache VMM instances per memory file
    
    @property
    def available(self) -> bool:
        return MEMPROCFS_AVAILABLE
    
    def _get_vmm(self, memory_file: str) -> Optional[Any]:
        """Get or create VMM instance for memory file"""
        if not MEMPROCFS_AVAILABLE:
            return None
        
        memory_path = str(Path(memory_file).resolve())
        
        if memory_path in self._vmm_cache:
            return self._vmm_cache[memory_path]
        
        try:
            # Initialize MemProcFS with the memory file
            vmm = memprocfs.Vmm(['-device', memory_path])
            self._vmm_cache[memory_path] = vmm
            logger.info(f"Created MemProcFS VMM for: {memory_path}")
            return vmm
        except Exception as e:
            logger.error(f"Failed to create MemProcFS VMM: {e}")
            return None
    
    def list_processes(self, memory_file: str, pid: Optional[int] = None) -> Dict[str, Any]:
        """List processes using MemProcFS"""
        vmm = self._get_vmm(memory_file)
        if vmm is None:
            return {"success": False, "error": "MemProcFS not available or failed to open memory file"}
        
        try:
            results = []
            processes = vmm.process_list()
            
            for proc in processes:
                if pid is not None and proc.pid != pid:
                    continue
                
                proc_info = {
                    "PID": proc.pid,
                    "ImageFileName": proc.name,
                    "PPID": proc.ppid if hasattr(proc, 'ppid') else None,
                }
                
                # Try to get additional info
                try:
                    proc_info["Wow64"] = proc.is_wow64 if hasattr(proc, 'is_wow64') else None
                except (AttributeError, TypeError):
                    pass
                
                results.append(proc_info)
            
            return {
                "success": True,
                "engine": "memprocfs",
                "results": results,
                "count": len(results)
            }
        except Exception as e:
            logger.error(f"MemProcFS list_processes failed: {e}")
            return {"success": False, "error": str(e)}
    
    def list_modules(self, memory_file: str, pid: int) -> Dict[str, Any]:
        """List modules for a process using MemProcFS"""
        vmm = self._get_vmm(memory_file)
        if vmm is None:
            return {"success": False, "error": "MemProcFS not available"}
        
        try:
            proc = vmm.process(pid)
            if proc is None:
                return {"success": False, "error": f"Process {pid} not found"}
            
            results = []
            modules = proc.module_list()
            
            for mod in modules:
                mod_info = {
                    "Base": hex(mod.base) if hasattr(mod, 'base') else None,
                    "Size": mod.size if hasattr(mod, 'size') else None,
                    "Name": mod.name if hasattr(mod, 'name') else None,
                    "Path": mod.fullname if hasattr(mod, 'fullname') else None,
                }
                results.append(mod_info)
            
            return {
                "success": True,
                "engine": "memprocfs",
                "pid": pid,
                "results": results,
                "count": len(results)
            }
        except Exception as e:
            logger.error(f"MemProcFS list_modules failed: {e}")
            return {"success": False, "error": str(e)}
    
    def get_minidump(self, memory_file: str, pid: int, output_path: str) -> Dict[str, Any]:
        """
        Extract a WinDbg-compatible minidump for a process
        
        MemProcFS generates minidump.dmp files in the virtual file system
        at: /pid/{pid}/minidump/minidump.dmp
        """
        vmm = self._get_vmm(memory_file)
        if vmm is None:
            return {"success": False, "error": "MemProcFS not available"}
        
        try:
            proc = vmm.process(pid)
            if proc is None:
                return {"success": False, "error": f"Process {pid} not found"}
            
            # Try to read the minidump from VFS
            # Path in MemProcFS VFS: /pid/{pid}/minidump/minidump.dmp
            vfs_dir = f"/pid/{pid}/minidump"
            vfs_path = f"{vfs_dir}/minidump.dmp"
            
            try:
                # Determine minidump size from VFS metadata
                meta = vmm.vfs.list(vfs_dir)
                if "minidump.dmp" not in meta or not isinstance(meta["minidump.dmp"], dict):
                    return {"success": False, "error": f"Minidump not found in VFS: {vfs_path}"}

                total_size = int(meta["minidump.dmp"].get("size", 0) or 0)
                if total_size <= 0:
                    return {"success": False, "error": f"Invalid minidump size from VFS metadata: {total_size}"}

                # Stream-read minidump in chunks to avoid truncation (default read is 1MB)
                output_file = Path(output_path)
                output_file.parent.mkdir(parents=True, exist_ok=True)

                md5 = hashlib.md5()
                chunk_size = 16 * 1024 * 1024  # 16 MiB
                written = 0

                with open(output_file, "wb") as f:
                    offset = 0
                    while offset < total_size:
                        to_read = min(chunk_size, total_size - offset)
                        # Signature observed: read(path, size, offset)
                        chunk = vmm.vfs.read(vfs_path, to_read, offset)
                        if chunk is None or len(chunk) == 0:
                            return {
                                "success": False,
                                "error": f"MemProcFS returned empty chunk at offset {offset} (requested {to_read})",
                                "written": written,
                                "expected_size": total_size,
                                "vfs_path": vfs_path,
                            }

                        f.write(chunk)
                        md5.update(chunk)
                        written += len(chunk)
                        offset += len(chunk)

                return {
                    "success": True,
                    "pid": pid,
                    "output_path": str(output_file.resolve()),
                    "size": written,
                    "expected_size": total_size,
                    "md5": md5.hexdigest(),
                }
            except AttributeError:
                # VFS interface may differ, try alternative approach
                # MemProcFS 5.x uses different API
                try:
                    # Alternative: Use memory read with minidump reconstruction
                    # This is a fallback if VFS read is not available
                    
                    # Check if process supports minidump generation
                    minidump_data = proc.minidump()  # Some versions have this method
                    
                    if minidump_data:
                        output_file = Path(output_path)
                        output_file.parent.mkdir(parents=True, exist_ok=True)
                        output_file.write_bytes(minidump_data)
                        
                        return {
                            "success": True,
                            "pid": pid,
                            "output_path": str(output_file.resolve()),
                            "size": len(minidump_data),
                            "md5": hashlib.md5(minidump_data).hexdigest()
                        }
                except Exception as e2:
                    logger.debug(f"Alternative minidump method failed: {e2}")
                
                return {
                    "success": False,
                    "error": "MemProcFS VFS read not available for minidump extraction",
                    "hint": "Try using volatility backend or manual minidump generation"
                }
                
        except Exception as e:
            logger.error(f"MemProcFS get_minidump failed: {e}")
            return {"success": False, "error": str(e), "traceback": traceback.format_exc()}
    
    def _parse_env_block_utf16(self, env_bytes: bytes) -> Dict[str, str]:
        """
        Parse UTF-16LE environment block into dictionary.
        
        Environment block format: NAME=VALUE\0NAME=VALUE\0\0
        Each entry is null-terminated, block ends with double-null.
        """
        env_vars = {}
        try:
            # Decode UTF-16LE
            decoded = env_bytes.decode('utf-16-le', errors='replace')
            
            # Split on null characters
            entries = decoded.split('\x00')
            
            for entry in entries:
                if '=' in entry and len(entry) > 0:
                    # Handle case where name contains '=' (rare but possible)
                    idx = entry.index('=')
                    name = entry[:idx]
                    value = entry[idx + 1:]
                    if name:  # Skip entries with empty names
                        env_vars[name] = value
                elif entry == '':
                    # Double null - end of block
                    break
        except Exception as e:
            logger.warning(f"Error parsing env block: {e}")
        
        return env_vars
    
    def get_process_environment(self, memory_file: str, pid: int, 
                                 filter_prefix: Optional[str] = None) -> Dict[str, Any]:
        """
        Extract environment variables from a process's environment block.
        
        Reads: PEB -> RTL_USER_PROCESS_PARAMETERS -> Environment
        Parses: UTF-16LE NAME=VALUE\0NAME=VALUE\0\0 format
        
        Args:
            memory_file: Path to memory dump
            pid: Process ID
            filter_prefix: Optional prefix filter (e.g., "B_" for staged payloads)
        
        Returns:
            Dictionary with environment variables
        """
        vmm = self._get_vmm(memory_file)
        if vmm is None:
            return {"success": False, "error": "MemProcFS not available or failed to open memory file"}
        
        try:
            proc = vmm.process(pid)
            if proc is None:
                return {"success": False, "error": f"Process {pid} not found"}
            
            # Determine architecture (64-bit vs 32-bit)
            is_wow64 = proc.is_wow64 if hasattr(proc, 'is_wow64') else False
            
            # Get PEB address
            peb = int(proc.peb) if hasattr(proc, 'peb') else None
            if peb is None or peb == 0:
                return {
                    "success": False,
                    "error": "Could not locate PEB for process",
                    "pid": pid,
                    "hint": "Process may not have a valid PEB (kernel process or terminated)"
                }
            
            # Read PEB to get ProcessParameters pointer
            # For 64-bit: ProcessParameters at offset 0x20
            # For 32-bit (WoW64): ProcessParameters at offset 0x10
            if is_wow64:
                peb_bytes = proc.memory.read(peb, 0x20)
                if peb_bytes is None or len(peb_bytes) < 0x14:
                    return {"success": False, "error": "Failed to read PEB"}
                proc_params = struct.unpack_from("<I", peb_bytes, 0x10)[0]
                
                # For 32-bit: Environment at offset 0x48
                pp_bytes = proc.memory.read(proc_params, 0x60)
                if pp_bytes is None or len(pp_bytes) < 0x4C:
                    return {"success": False, "error": "Failed to read RTL_USER_PROCESS_PARAMETERS"}
                env_ptr = struct.unpack_from("<I", pp_bytes, 0x48)[0]
            else:
                # 64-bit process
                peb_bytes = proc.memory.read(peb, 0x40)
                if peb_bytes is None or len(peb_bytes) < 0x28:
                    return {"success": False, "error": "Failed to read PEB"}
                proc_params = struct.unpack_from("<Q", peb_bytes, 0x20)[0]
                
                # For 64-bit: Environment at offset 0x80
                pp_bytes = proc.memory.read(proc_params, 0x100)
                if pp_bytes is None or len(pp_bytes) < 0x88:
                    return {"success": False, "error": "Failed to read RTL_USER_PROCESS_PARAMETERS"}
                env_ptr = struct.unpack_from("<Q", pp_bytes, 0x80)[0]
            
            if env_ptr == 0:
                return {
                    "success": False,
                    "error": "Environment pointer is null",
                    "pid": pid
                }
            
            # Read environment block (up to 5MB should be enough for most cases)
            max_env_size = 5 * 1024 * 1024
            env_bytes = proc.memory.read(env_ptr, max_env_size)
            
            if env_bytes is None or len(env_bytes) == 0:
                return {"success": False, "error": "Failed to read environment block"}
            
            # Find the end of the environment block (double null in UTF-16)
            # Look for \x00\x00\x00\x00 pattern (two null UTF-16 chars)
            end_idx = len(env_bytes)
            for i in range(0, len(env_bytes) - 3, 2):
                if env_bytes[i:i+4] == b'\x00\x00\x00\x00':
                    end_idx = i + 4
                    break
            
            env_bytes = env_bytes[:end_idx]
            
            # Parse environment block
            env_vars = self._parse_env_block_utf16(env_bytes)
            
            result = {
                "success": True,
                "pid": pid,
                "peb_address": hex(peb),
                "process_params_address": hex(proc_params),
                "environment_address": hex(env_ptr),
                "env_block_size": len(env_bytes),
                "env_count": len(env_vars),
                "environment": env_vars
            }
            
            # Apply filter if specified
            if filter_prefix:
                filtered = {k: v for k, v in env_vars.items() if k.startswith(filter_prefix)}
                result["filtered_count"] = len(filtered)
                result["filtered_vars"] = filtered
                result["filter_prefix"] = filter_prefix
            
            return result
            
        except Exception as e:
            logger.error(f"MemProcFS get_process_environment failed: {e}")
            return {"success": False, "error": str(e), "traceback": traceback.format_exc()}
    
    def read_virtual_memory(self, memory_file: str, pid: int, 
                             address: int, size: int) -> Dict[str, Any]:
        """
        Read arbitrary virtual memory from a process.
        
        Uses MemProcFS for reliable VA->PA translation.
        
        Args:
            memory_file: Path to memory dump
            pid: Process ID
            address: Virtual address to read from
            size: Number of bytes to read
        
        Returns:
            Dictionary with memory data (base64 encoded)
        """
        vmm = self._get_vmm(memory_file)
        if vmm is None:
            return {"success": False, "error": "MemProcFS not available"}
        
        try:
            proc = vmm.process(pid)
            if proc is None:
                return {"success": False, "error": f"Process {pid} not found"}
            
            # Clamp size to reasonable maximum
            max_read = 100 * 1024 * 1024  # 100MB max
            if size > max_read:
                logger.warning(f"Clamping read size from {size} to {max_read}")
                size = max_read
            
            # Read memory
            data = proc.memory.read(address, size)
            
            if data is None or len(data) == 0:
                return {
                    "success": False,
                    "error": f"Failed to read memory at {hex(address)}",
                    "pid": pid,
                    "hint": "Address may be invalid or memory not paged in"
                }
            
            # Calculate hash and create preview
            md5_hash = hashlib.md5(data).hexdigest()
            
            # Create hex preview (first 64 bytes)
            preview_len = min(64, len(data))
            hex_preview = ' '.join(f'{b:02x}' for b in data[:preview_len])
            
            return {
                "success": True,
                "pid": pid,
                "address": hex(address),
                "requested_size": size,
                "actual_size": len(data),
                "data_b64": base64.b64encode(data).decode('ascii'),
                "md5": md5_hash,
                "data_hex_preview": hex_preview
            }
            
        except Exception as e:
            logger.error(f"MemProcFS read_virtual_memory failed: {e}")
            return {"success": False, "error": str(e), "traceback": traceback.format_exc()}
    
    # =========================================================================
    # VFS BROWSING METHODS
    # =========================================================================
    
    def vfs_list(self, memory_file: str, path: str = "/") -> Dict[str, Any]:
        """
        List directory entries in the MemProcFS virtual file system.
        
        Common VFS paths:
        - / : Root directory
        - /name/ : Named processes directory
        - /pid/ : All processes by PID
        - /pid/{pid}/ : Process directory (contains modules, memory maps, etc.)
        - /pid/{pid}/modules/ : Loaded modules
        - /pid/{pid}/minidump/ : Minidump files
        - /pid/{pid}/vad/ : Virtual Address Descriptors
        - /registry/ : Registry hives
        - /sys/ : System information
        
        Args:
            memory_file: Path to memory dump
            path: VFS path to list (default: root)
        
        Returns:
            Dictionary with directory entries and metadata
        """
        vmm = self._get_vmm(memory_file)
        if vmm is None:
            return {"success": False, "error": "MemProcFS not available or failed to open memory file"}
        
        try:
            # Normalize path
            if not path.startswith("/"):
                path = "/" + path
            
            entries = vmm.vfs.list(path)
            
            if entries is None:
                return {
                    "success": False,
                    "error": f"Path not found or not accessible: {path}",
                    "path": path
                }
            
            # Convert to structured format
            results = []
            for name, meta in entries.items():
                entry = {"name": name}
                if isinstance(meta, dict):
                    entry["size"] = meta.get("size", 0)
                    entry["is_directory"] = meta.get("f_isdir", False)
                else:
                    entry["size"] = 0
                    entry["is_directory"] = True
                results.append(entry)
            
            # Sort: directories first, then by name
            results.sort(key=lambda x: (not x.get("is_directory", False), x.get("name", "")))
            
            return {
                "success": True,
                "path": path,
                "entries": results,
                "count": len(results)
            }
            
        except Exception as e:
            logger.error(f"MemProcFS vfs_list failed: {e}")
            return {"success": False, "error": str(e), "traceback": traceback.format_exc()}
    
    def vfs_read(self, memory_file: str, path: str, size: int = 4096, 
                 offset: int = 0) -> Dict[str, Any]:
        """
        Read bytes from a file in the MemProcFS virtual file system.
        
        Args:
            memory_file: Path to memory dump
            path: VFS file path to read
            size: Number of bytes to read (default 4096, max 100MB)
            offset: Offset in the file to start reading from
        
        Returns:
            Dictionary with file data (base64 encoded) and metadata
        """
        vmm = self._get_vmm(memory_file)
        if vmm is None:
            return {"success": False, "error": "MemProcFS not available"}
        
        try:
            # Normalize path
            if not path.startswith("/"):
                path = "/" + path
            
            # Clamp size
            max_read = 100 * 1024 * 1024  # 100MB max
            if size > max_read:
                logger.warning(f"Clamping VFS read size from {size} to {max_read}")
                size = max_read
            
            # Read data
            data = vmm.vfs.read(path, size, offset)
            
            if data is None:
                return {
                    "success": False,
                    "error": f"Failed to read from VFS path: {path}",
                    "path": path,
                    "offset": offset,
                    "requested_size": size
                }
            
            # Calculate hash and preview
            md5_hash = hashlib.md5(data).hexdigest()
            preview_len = min(64, len(data))
            hex_preview = ' '.join(f'{b:02x}' for b in data[:preview_len])
            
            return {
                "success": True,
                "path": path,
                "offset": offset,
                "requested_size": size,
                "actual_size": len(data),
                "data_b64": base64.b64encode(data).decode('ascii'),
                "md5": md5_hash,
                "data_hex_preview": hex_preview
            }
            
        except Exception as e:
            logger.error(f"MemProcFS vfs_read failed: {e}")
            return {"success": False, "error": str(e), "traceback": traceback.format_exc()}
    
    def vfs_export(self, memory_file: str, vfs_path: str, output_path: str) -> Dict[str, Any]:
        """
        Export a file from the MemProcFS VFS to disk.
        
        Streams large files in chunks to avoid memory issues.
        
        Args:
            memory_file: Path to memory dump
            vfs_path: VFS path to export (e.g., /pid/1234/modules/kernel32.dll)
            output_path: Local filesystem path to save the file
        
        Returns:
            Dictionary with export status and file info
        """
        vmm = self._get_vmm(memory_file)
        if vmm is None:
            return {"success": False, "error": "MemProcFS not available"}
        
        try:
            # Normalize path
            if not vfs_path.startswith("/"):
                vfs_path = "/" + vfs_path
            
            # Get file size from parent directory listing
            parent_dir = "/".join(vfs_path.split("/")[:-1]) or "/"
            file_name = vfs_path.split("/")[-1]
            
            try:
                meta = vmm.vfs.list(parent_dir)
                if file_name not in meta:
                    return {
                        "success": False,
                        "error": f"File not found in VFS: {vfs_path}",
                        "parent_dir": parent_dir,
                        "file_name": file_name
                    }
                
                file_meta = meta[file_name]
                if isinstance(file_meta, dict):
                    total_size = int(file_meta.get("size", 0) or 0)
                else:
                    total_size = 0
            except Exception:
                # If we can't get size, try to read anyway
                total_size = 0
            
            # Stream-read in chunks
            output_file = Path(output_path)
            output_file.parent.mkdir(parents=True, exist_ok=True)
            
            md5 = hashlib.md5()
            chunk_size = 16 * 1024 * 1024  # 16 MiB
            written = 0
            
            with open(output_file, "wb") as f:
                offset = 0
                max_size = 1024 * 1024 * 1024  # 1GB safety limit
                
                while True:
                    if total_size > 0 and offset >= total_size:
                        break
                    if offset >= max_size:
                        break
                    
                    to_read = chunk_size
                    if total_size > 0:
                        to_read = min(chunk_size, total_size - offset)
                    
                    chunk = vmm.vfs.read(vfs_path, to_read, offset)
                    
                    if chunk is None or len(chunk) == 0:
                        break
                    
                    f.write(chunk)
                    md5.update(chunk)
                    written += len(chunk)
                    offset += len(chunk)
                    
                    # If we read less than requested, we're at EOF
                    if len(chunk) < to_read:
                        break
            
            return {
                "success": True,
                "vfs_path": vfs_path,
                "output_path": str(output_file.resolve()),
                "size": written,
                "expected_size": total_size if total_size > 0 else "unknown",
                "md5": md5.hexdigest()
            }
            
        except Exception as e:
            logger.error(f"MemProcFS vfs_export failed: {e}")
            return {"success": False, "error": str(e), "traceback": traceback.format_exc()}
    
    def read_physical_memory(self, memory_file: str, address: int, size: int) -> Dict[str, Any]:
        """
        Read physical memory at a given address.
        
        Uses MemProcFS to access raw physical memory.
        
        Args:
            memory_file: Path to memory dump
            address: Physical address to read from
            size: Number of bytes to read
        
        Returns:
            Dictionary with memory data (base64 encoded)
        """
        vmm = self._get_vmm(memory_file)
        if vmm is None:
            return {"success": False, "error": "MemProcFS not available"}
        
        try:
            # Clamp size
            max_read = 100 * 1024 * 1024  # 100MB max
            if size > max_read:
                logger.warning(f"Clamping physical read size from {size} to {max_read}")
                size = max_read
            
            # Read physical memory using MemProcFS
            # The kernel layer provides access to physical memory
            data = vmm.memory.read(address, size)
            
            if data is None or len(data) == 0:
                return {
                    "success": False,
                    "error": f"Failed to read physical memory at {hex(address)}",
                    "address": hex(address),
                    "size": size
                }
            
            # Calculate hash and preview
            md5_hash = hashlib.md5(data).hexdigest()
            preview_len = min(64, len(data))
            hex_preview = ' '.join(f'{b:02x}' for b in data[:preview_len])
            
            return {
                "success": True,
                "address": hex(address),
                "requested_size": size,
                "actual_size": len(data),
                "data_b64": base64.b64encode(data).decode('ascii'),
                "md5": md5_hash,
                "data_hex_preview": hex_preview
            }
            
        except Exception as e:
            logger.error(f"MemProcFS read_physical_memory failed: {e}")
            return {"success": False, "error": str(e), "traceback": traceback.format_exc()}
    
    def get_version(self) -> Optional[str]:
        """Get MemProcFS version"""
        if not MEMPROCFS_AVAILABLE:
            return None
        try:
            return memprocfs.__version__ if hasattr(memprocfs, '__version__') else "installed"
        except Exception:
            return None


class CLRAnalyzer:
    """
    CLR/SOS command analyzer for deep .NET inspection
    
    Uses cdb.exe (WinDbg) or dotnet-dump to run SOS commands on minidumps.
    """
    
    def __init__(self):
        self._cdb_path = self._find_cdb()
        self._dotnet_dump_available = self._check_dotnet_dump()
    
    @property
    def cdb_available(self) -> bool:
        return self._cdb_path is not None
    
    @property
    def dotnet_dump_available(self) -> bool:
        return self._dotnet_dump_available
    
    def _find_cdb(self) -> Optional[str]:
        """Find cdb.exe in common Windows SDK locations"""
        # Check PATH first
        cdb = shutil.which("cdb.exe")
        if cdb:
            return cdb
        
        # Check common Windows SDK locations
        sdk_paths = [
            r"C:\Program Files (x86)\Windows Kits\10\Debuggers\x64\cdb.exe",
            r"C:\Program Files\Windows Kits\10\Debuggers\x64\cdb.exe",
            r"C:\Program Files (x86)\Windows Kits\8.1\Debuggers\x64\cdb.exe",
            r"C:\Debuggers\cdb.exe",
        ]
        
        for path in sdk_paths:
            if Path(path).exists():
                return path
        
        return None
    
    def _check_dotnet_dump(self) -> bool:
        """Check if dotnet-dump is available"""
        try:
            result = subprocess.run(
                ["dotnet", "tool", "list", "-g"],
                capture_output=True,
                text=True,
                timeout=10
            )
            return "dotnet-dump" in result.stdout
        except (subprocess.SubprocessError, OSError, FileNotFoundError):
            return False
    
    def run_sos_command_cdb(self, minidump_path: str, sos_command: str, timeout: int = 60) -> Dict[str, Any]:
        """
        Run SOS command using cdb.exe on a minidump
        
        Args:
            minidump_path: Path to minidump file
            sos_command: SOS command to run (e.g., "!clrstack", "!dumpheap -stat")
            timeout: Command timeout in seconds
        
        Returns:
            Dictionary with command output
        """
        if not self.cdb_available:
            return {"success": False, "error": "cdb.exe not found"}
        
        minidump = Path(minidump_path)
        if not minidump.exists():
            return {"success": False, "error": f"Minidump not found: {minidump_path}"}
        
        try:
            # Build cdb command
            # Load SOS extension and run command
            cdb_script = f".loadby sos clr; {sos_command}; q"
            
            cmd = [
                self._cdb_path,
                "-z", str(minidump),
                "-c", cdb_script
            ]
            
            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=timeout
            )
            
            return {
                "success": result.returncode == 0,
                "command": sos_command,
                "stdout": result.stdout,
                "stderr": result.stderr,
                "returncode": result.returncode
            }
        except subprocess.TimeoutExpired:
            return {"success": False, "error": f"cdb command timed out after {timeout}s"}
        except Exception as e:
            return {"success": False, "error": str(e)}
    
    def run_sos_command_dotnet_dump(self, minidump_path: str, sos_command: str, timeout: int = 60) -> Dict[str, Any]:
        """
        Run SOS command using dotnet-dump on a minidump
        
        Note: dotnet-dump is primarily for .NET Core dumps, may not work well with .NET Framework.
        
        Args:
            minidump_path: Path to minidump file
            sos_command: SOS command to run
            timeout: Command timeout in seconds
        
        Returns:
            Dictionary with command output
        """
        if not self.dotnet_dump_available:
            return {"success": False, "error": "dotnet-dump not installed"}
        
        minidump = Path(minidump_path)
        if not minidump.exists():
            return {"success": False, "error": f"Minidump not found: {minidump_path}"}
        
        try:
            cmd = [
                "dotnet-dump", "analyze",
                str(minidump),
                "--command", sos_command,
                "--command", "exit"
            ]
            
            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=timeout
            )
            
            return {
                "success": result.returncode == 0,
                "command": sos_command,
                "stdout": result.stdout,
                "stderr": result.stderr,
                "returncode": result.returncode
            }
        except subprocess.TimeoutExpired:
            return {"success": False, "error": f"dotnet-dump command timed out after {timeout}s"}
        except Exception as e:
            return {"success": False, "error": str(e)}
    
    def list_clr_assemblies(self, minidump_path: str, method: str = "auto") -> Dict[str, Any]:
        """
        List CLR assemblies loaded in a process using SOS !dumpdomain
        
        This extracts actual CLR Assembly addresses, not just PE module addresses.
        
        Args:
            minidump_path: Path to minidump file
            method: "auto", "cdb", or "dotnet-dump"
        
        Returns:
            Dictionary with CLR assembly information
        """
        # Try cdb first (better for .NET Framework)
        if method in ("auto", "cdb") and self.cdb_available:
            result = self.run_sos_command_cdb(minidump_path, "!dumpdomain")
            if result["success"]:
                parsed = self._parse_dumpdomain_output(result["stdout"])
                if parsed["success"]:
                    return parsed
        
        # Fall back to dotnet-dump
        if method in ("auto", "dotnet-dump") and self.dotnet_dump_available:
            result = self.run_sos_command_dotnet_dump(minidump_path, "dumpdomain")
            if result["success"]:
                parsed = self._parse_dumpdomain_output(result["stdout"])
                if parsed["success"]:
                    return parsed
        
        return {
            "success": False,
            "error": "No CLR analyzer available or failed to run SOS commands",
            "cdb_available": self.cdb_available,
            "dotnet_dump_available": self.dotnet_dump_available
        }
    
    def _parse_dumpdomain_output(self, output: str) -> Dict[str, Any]:
        """
        Parse !dumpdomain output to extract assembly addresses
        
        Example output format:
        Assembly:           00007ff8abc12345 [C:\\Windows\\Microsoft.Net\\assembly\\...]
        """
        try:
            assemblies = []
            
            # Pattern for Assembly lines in dumpdomain output
            # Format: "Assembly:           <address> [<path>]"
            assembly_pattern = re.compile(r"Assembly:\s+([0-9a-fA-F]+)\s+\[(.+?)\]", re.IGNORECASE)
            
            for match in assembly_pattern.finditer(output):
                addr_str = match.group(1)
                path = match.group(2)
                
                # Convert to integer for sorting
                addr_int = int(addr_str, 16)
                
                # Extract module name from path
                name = Path(path).stem if path else "Unknown"
                
                assemblies.append({
                    "address": addr_int,
                    "address_hex": f"0x{addr_int:016X}",
                    "name": name,
                    "path": path
                })
            
            if not assemblies:
                # Try alternative pattern for Module addresses
                module_pattern = re.compile(r"Module\s+([0-9a-fA-F]+)", re.IGNORECASE)
                for match in module_pattern.finditer(output):
                    addr_str = match.group(1)
                    addr_int = int(addr_str, 16)
                    assemblies.append({
                        "address": addr_int,
                        "address_hex": f"0x{addr_int:016X}",
                        "name": "Unknown",
                        "path": None
                    })
            
            if not assemblies:
                return {"success": False, "error": "No assemblies found in output", "raw_output": output}
            
            # Sort by address ascending
            assemblies.sort(key=lambda x: x["address"])

            # Extract sorted addresses (formatted) and de-duplicate for convenience.
            # dumpdomain can list the same assembly multiple times (e.g., multiple domains).
            sorted_addresses = [a["address_hex"] for a in assemblies]
            sorted_addresses_unique = []
            seen = set()
            for addr in sorted_addresses:
                if addr not in seen:
                    seen.add(addr)
                    sorted_addresses_unique.append(addr)
            
            return {
                "success": True,
                "assemblies": assemblies,
                "count": len(assemblies),
                "sorted_addresses": sorted_addresses,
                "sorted_addresses_unique": sorted_addresses_unique,
                "sorted_addresses_decimal": [a["address"] for a in assemblies]
            }
        except Exception as e:
            return {"success": False, "error": f"Failed to parse dumpdomain output: {e}", "raw_output": output}


# =============================================================================
# MAIN MCP CLASS
# =============================================================================

class MemoryForensicsMCP(BaseMCP):
    """
    Generalized Memory Forensics MCP
    
    Provides unified interface to multiple memory analysis backends:
    - Volatility 3: Classic memory forensics
    - MemProcFS: Alternative parsing + VFS + minidumps
    - CLR Analyzer: Deep .NET inspection via SOS
    """
    
    def __init__(self):
        super().__init__()
        self.name = MCP_INFO["name"]
        self.version = MCP_INFO["version"]
        self.tool_name = "memory-forensics"
        self.category = MCP_INFO["category"]
        self.official_docs = "https://volatility3.readthedocs.io/"
        
        # Initialize backends
        self.volatility = VolatilityBackend()
        self.memprocfs = MemProcFSBackend()
        self.clr = CLRAnalyzer()
        
        self._register_mcp()
    
    def _select_engine(self, engine: str, for_tool: str = "general") -> str:
        """
        Select appropriate engine based on preference and availability
        
        Args:
            engine: "auto", "volatility", or "memprocfs"
            for_tool: Tool name for context-specific selection
        
        Returns:
            Selected engine name
        """
        if engine == "volatility":
            if not self.volatility.available:
                raise ValueError("Volatility 3 not available")
            return "volatility"
        elif engine == "memprocfs":
            if not self.memprocfs.available:
                raise ValueError("MemProcFS not available")
            return "memprocfs"
        else:  # auto
            # Prefer Volatility for most forensics tasks
            if self.volatility.available:
                return "volatility"
            elif self.memprocfs.available:
                return "memprocfs"
            else:
                raise ValueError("No memory analysis backend available")
    
    # =========================================================================
    # MANDATORY MCP METHODS
    # =========================================================================
    
    def list_capabilities(self) -> Dict[str, Any]:
        """List all available Memory Forensics MCP tools"""
        return {
            "mcp_name": self.name,
            "version": self.version,
            "description": MCP_INFO["description"],
            "category": self.category,
            "backends": {
                "volatility": {
                    "available": self.volatility.available,
                    "version": self.volatility.get_version()
                },
                "memprocfs": {
                    "available": self.memprocfs.available,
                    "version": self.memprocfs.get_version()
                },
                "cdb": {
                    "available": self.clr.cdb_available,
                    "path": self.clr._cdb_path
                },
                "dotnet_dump": {
                    "available": self.clr.dotnet_dump_available
                }
            },
            "tools": [
                {
                    "name": "list_processes",
                    "description": "List all processes with PIDs and start times",
                    "parameters": {
                        "memory_file": {"type": "string", "required": True},
                        "pid": {"type": "integer", "required": False},
                        "engine": {"type": "string", "required": False, "default": "auto"}
                    }
                },
                {
                    "name": "list_dlls",
                    "description": "List loaded DLLs for a process",
                    "parameters": {
                        "memory_file": {"type": "string", "required": True},
                        "pid": {"type": "integer", "required": False},
                        "engine": {"type": "string", "required": False, "default": "auto"}
                    }
                },
                {
                    "name": "get_cmdline",
                    "description": "Get command line arguments for processes",
                    "parameters": {
                        "memory_file": {"type": "string", "required": True},
                        "pid": {"type": "integer", "required": False}
                    }
                },
                {
                    "name": "vadinfo",
                    "description": "List Virtual Address Descriptors for a process",
                    "parameters": {
                        "memory_file": {"type": "string", "required": True},
                        "pid": {"type": "integer", "required": True}
                    }
                },
                {
                    "name": "dump_vad",
                    "description": "Dump a VAD region to file",
                    "parameters": {
                        "memory_file": {"type": "string", "required": True},
                        "pid": {"type": "integer", "required": True},
                        "address": {"type": "string", "required": True},
                        "output_path": {"type": "string", "required": True}
                    }
                },
                {
                    "name": "malfind",
                    "description": "Find injected or suspicious code in processes",
                    "parameters": {
                        "memory_file": {"type": "string", "required": True},
                        "pid": {"type": "integer", "required": False}
                    }
                },
                {
                    "name": "netscan",
                    "description": "Scan for network connections",
                    "parameters": {
                        "memory_file": {"type": "string", "required": True}
                    }
                },
                {
                    "name": "filescan",
                    "description": "Scan for file objects in memory",
                    "parameters": {
                        "memory_file": {"type": "string", "required": True}
                    }
                },
                {
                    "name": "handles",
                    "description": "List process handles",
                    "parameters": {
                        "memory_file": {"type": "string", "required": True},
                        "pid": {"type": "integer", "required": False}
                    }
                },
                {
                    "name": "ldrmodules",
                    "description": "List loaded modules comparing different sources (detect hidden)",
                    "parameters": {
                        "memory_file": {"type": "string", "required": True},
                        "pid": {"type": "integer", "required": False}
                    }
                },
                {
                    "name": "memprocfs_get_minidump",
                    "description": "Extract WinDbg-compatible minidump for a process using MemProcFS",
                    "parameters": {
                        "memory_file": {"type": "string", "required": True},
                        "pid": {"type": "integer", "required": True},
                        "output_path": {"type": "string", "required": True}
                    }
                },
                {
                    "name": "list_clr_modules",
                    "description": "List CLR/.NET modules with assembly addresses using SOS",
                    "parameters": {
                        "memory_file": {"type": "string", "required": True},
                        "pid": {"type": "integer", "required": True},
                        "method": {"type": "string", "required": False, "default": "auto"}
                    }
                },
                {
                    "name": "get_process_environment",
                    "description": "Extract environment variables from process PEB (for staged payloads)",
                    "parameters": {
                        "memory_file": {"type": "string", "required": True},
                        "pid": {"type": "integer", "required": True},
                        "filter_prefix": {"type": "string", "required": False, "description": "Filter by prefix (e.g., 'B_')"}
                    }
                },
                {
                    "name": "read_virtual_memory",
                    "description": "Read arbitrary virtual memory from a process",
                    "parameters": {
                        "memory_file": {"type": "string", "required": True},
                        "pid": {"type": "integer", "required": True},
                        "address": {"type": "integer", "required": True, "description": "Virtual address (hex or int)"},
                        "size": {"type": "integer", "required": True, "description": "Bytes to read"}
                    }
                },
                {
                    "name": "find_hidden_modules",
                    "description": "Find modules not in PEB loader lists (detect injection)",
                    "parameters": {
                        "memory_file": {"type": "string", "required": True},
                        "pid": {"type": "integer", "required": True}
                    }
                },
                {
                    "name": "dump_vad_raw",
                    "description": "Dump raw VAD bytes without PE reconstruction",
                    "parameters": {
                        "memory_file": {"type": "string", "required": True},
                        "pid": {"type": "integer", "required": True},
                        "address": {"type": "integer", "required": True},
                        "output_path": {"type": "string", "required": True},
                        "trim_trailing_zeros": {"type": "boolean", "required": False, "default": False}
                    }
                },
                {
                    "name": "reconstruct_staged_payload",
                    "description": "Reconstruct payload from staged env vars (PASTALOADER pattern)",
                    "parameters": {
                        "memory_file": {"type": "string", "required": True},
                        "pid": {"type": "integer", "required": True},
                        "var_prefix": {"type": "string", "required": False, "default": "B_"},
                        "decode_algorithm": {"type": "string", "required": False, "default": "raw_concat"},
                        "output_path": {"type": "string", "required": False}
                    }
                },
                {
                    "name": "check_installation",
                    "description": "Check installation status of all backends",
                    "parameters": {}
                },
                # VFS Browsing
                {
                    "name": "vfs_list",
                    "description": "List directory entries in MemProcFS virtual file system",
                    "parameters": {
                        "memory_file": {"type": "string", "required": True},
                        "path": {"type": "string", "required": False, "default": "/"}
                    }
                },
                {
                    "name": "vfs_read",
                    "description": "Read bytes from a file in MemProcFS VFS",
                    "parameters": {
                        "memory_file": {"type": "string", "required": True},
                        "path": {"type": "string", "required": True},
                        "size": {"type": "integer", "required": False, "default": 4096},
                        "offset": {"type": "integer", "required": False, "default": 0}
                    }
                },
                {
                    "name": "vfs_export",
                    "description": "Export a file from MemProcFS VFS to local disk",
                    "parameters": {
                        "memory_file": {"type": "string", "required": True},
                        "vfs_path": {"type": "string", "required": True},
                        "output_path": {"type": "string", "required": True}
                    }
                },
                # Physical Memory
                {
                    "name": "read_physical_memory",
                    "description": "Read raw physical memory at specified address",
                    "parameters": {
                        "memory_file": {"type": "string", "required": True},
                        "address": {"type": "integer", "required": True},
                        "size": {"type": "integer", "required": True}
                    }
                },
                # YARA Scanning
                {
                    "name": "yara_scan",
                    "description": "Scan memory with YARA rules",
                    "parameters": {
                        "memory_file": {"type": "string", "required": True},
                        "rules_text": {"type": "string", "required": False},
                        "rules_path": {"type": "string", "required": False},
                        "scope": {"type": "string", "required": False, "default": "process_vads"},
                        "pid": {"type": "integer", "required": False},
                        "address": {"type": "integer", "required": False},
                        "size": {"type": "integer", "required": False}
                    }
                },
                # Registry
                {
                    "name": "list_registry_hives",
                    "description": "List registry hives found in memory",
                    "parameters": {
                        "memory_file": {"type": "string", "required": True}
                    }
                },
                {
                    "name": "registry_printkey",
                    "description": "Print registry key values",
                    "parameters": {
                        "memory_file": {"type": "string", "required": True},
                        "key_path": {"type": "string", "required": True},
                        "hive_offset": {"type": "integer", "required": False}
                    }
                },
                # Handles (enriched)
                {
                    "name": "handles_enriched",
                    "description": "List handles with enhanced filtering and summary",
                    "parameters": {
                        "memory_file": {"type": "string", "required": True},
                        "pid": {"type": "integer", "required": False},
                        "object_type": {"type": "string", "required": False},
                        "name_filter": {"type": "string", "required": False}
                    }
                },
                # Tagging
                {
                    "name": "add_tag",
                    "description": "Add a tag to track findings (persists for session)",
                    "parameters": {
                        "tag_id": {"type": "string", "required": True},
                        "tag_type": {"type": "string", "required": True},
                        "value": {"type": "string", "required": True},
                        "notes": {"type": "string", "required": False}
                    }
                },
                {
                    "name": "list_tags",
                    "description": "List all recorded tags",
                    "parameters": {
                        "tag_type": {"type": "string", "required": False}
                    }
                },
                {
                    "name": "clear_tags",
                    "description": "Clear all tags",
                    "parameters": {}
                },
                # Timeline
                {
                    "name": "add_timeline_event",
                    "description": "Add an event to investigation timeline",
                    "parameters": {
                        "timestamp": {"type": "string", "required": True},
                        "event_type": {"type": "string", "required": True},
                        "description": {"type": "string", "required": True},
                        "source": {"type": "string", "required": False},
                        "pid": {"type": "integer", "required": False}
                    }
                },
                {
                    "name": "list_timeline",
                    "description": "List timeline events",
                    "parameters": {
                        "event_type": {"type": "string", "required": False},
                        "pid": {"type": "integer", "required": False}
                    }
                },
                {
                    "name": "clear_timeline",
                    "description": "Clear timeline",
                    "parameters": {}
                }
            ]
        }
    
    def get_documentation(self, topic: str = "general") -> Dict[str, Any]:
        """Get documentation for Memory Forensics MCP"""
        docs = {
            "tool": self.tool_name,
            "mcp": self.name,
            "official_docs": self.official_docs,
            "topic": topic
        }
        
        if topic == "general":
            docs["description"] = MCP_INFO["description"]
            docs["common_use_cases"] = [
                "Process analysis - List running processes with timestamps",
                "DLL enumeration - Find loaded modules in processes",
                "Malware detection - Find injected code with malfind",
                "Network forensics - List network connections",
                "Memory extraction - Dump process memory regions",
                "CLR analysis - Deep inspection of .NET applications",
                "Staged payload extraction - Reconstruct payloads from env vars (NEW)",
                "Hidden module detection - Find injected DLLs not in loader lists (NEW)"
            ]
            docs["examples"] = [
                "list_processes(memory_file='memory.raw')",
                "list_dlls(memory_file='memory.raw', pid=1234)",
                "memprocfs_get_minidump(memory_file='memory.raw', pid=3120, output_path='proc.dmp')",
                "list_clr_modules(memory_file='memory.raw', pid=3120)",
                "get_process_environment(memory_file='memory.raw', pid=3120, filter_prefix='B_')",
                "read_virtual_memory(memory_file='memory.raw', pid=3120, address=0x7ff8abc12345, size=4096)",
                "find_hidden_modules(memory_file='memory.raw', pid=3120)",
                "dump_vad_raw(memory_file='memory.raw', pid=3120, address=0x06630000, output_path='vad.bin')",
                "reconstruct_staged_payload(memory_file='memory.raw', pid=3120, var_prefix='B_', decode_algorithm='pastaloader')"
            ]
        
        return docs
    
    def check_installation(self) -> Dict[str, Any]:
        """Check installation status of all backends"""
        result = {
            "mcp": self.name,
            "version": self.version,
            "backends": {
                "volatility3": {
                    "installed": self.volatility.available,
                    "version": self.volatility.get_version(),
                    "install_command": "pip install volatility3"
                },
                "memprocfs": {
                    "installed": self.memprocfs.available,
                    "version": self.memprocfs.get_version(),
                    "install_command": "pip install memprocfs"
                },
                "cdb": {
                    "installed": self.clr.cdb_available,
                    "path": self.clr._cdb_path,
                    "install_notes": "Install Windows SDK Debugging Tools"
                },
                "dotnet_dump": {
                    "installed": self.clr.dotnet_dump_available,
                    "install_command": "dotnet tool install -g dotnet-dump"
                }
            },
            "any_backend_available": (
                self.volatility.available or 
                self.memprocfs.available
            ),
            "clr_analysis_available": (
                self.clr.cdb_available or 
                self.clr.dotnet_dump_available
            )
        }
        
        return result
    
    # =========================================================================
    # PROCESS ANALYSIS
    # =========================================================================
    
    def list_processes(self, memory_file: str, pid: Optional[int] = None, 
                       engine: str = "auto") -> Dict[str, Any]:
        """List all processes with PIDs and start times"""
        try:
            selected_engine = self._select_engine(engine)
        except ValueError as e:
            return {"success": False, "error": str(e)}
        
        if selected_engine == "volatility":
            if not self.volatility.available:
                return {"success": False, "error": "volatility3 not installed"}
            
            from volatility3.plugins.windows import pslist
            
            result = self.volatility.run_plugin(memory_file, pslist.PsList)
            
            if not result["success"]:
                return result
            
            if pid is not None:
                result["results"] = [
                    p for p in result["results"] 
                    if p.get("PID") == pid or str(p.get("PID")) == str(pid)
                ]
                result["count"] = len(result["results"])
            
            result["engine"] = "volatility"
            return result
        
        elif selected_engine == "memprocfs":
            return self.memprocfs.list_processes(memory_file, pid)
        
        return {"success": False, "error": f"Unknown engine: {selected_engine}"}
    
    def list_dlls(self, memory_file: str, pid: Optional[int] = None,
                  engine: str = "auto") -> Dict[str, Any]:
        """List loaded DLLs for processes"""
        try:
            selected_engine = self._select_engine(engine)
        except ValueError as e:
            return {"success": False, "error": str(e)}
        
        if selected_engine == "volatility":
            if not self.volatility.available:
                return {"success": False, "error": "volatility3 not installed"}
            
            from volatility3.plugins.windows import dlllist
            
            ctx = self.volatility.get_context(memory_file)
            if ctx is None:
                return {"success": False, "error": "Failed to create context"}
            
            if pid is not None:
                ctx.config['plugins.DllList.pid'] = [pid]
            
            result = self.volatility.run_plugin(memory_file, dlllist.DllList)
            result["engine"] = "volatility"
            return result
        
        elif selected_engine == "memprocfs":
            if pid is None:
                return {"success": False, "error": "PID required for MemProcFS module listing"}
            return self.memprocfs.list_modules(memory_file, pid)
        
        return {"success": False, "error": f"Unknown engine: {selected_engine}"}
    
    def get_cmdline(self, memory_file: str, pid: Optional[int] = None) -> Dict[str, Any]:
        """Get command line arguments for processes (Volatility only)"""
        if not self.volatility.available:
            return {"success": False, "error": "volatility3 not installed"}
        
        from volatility3.plugins.windows import cmdline
        
        ctx = self.volatility.get_context(memory_file)
        if ctx is None:
            return {"success": False, "error": "Failed to create context"}
        
        if pid is not None:
            ctx.config['plugins.CmdLine.pid'] = [pid]
        
        result = self.volatility.run_plugin(memory_file, cmdline.CmdLine)
        result["engine"] = "volatility"
        return result
    
    # =========================================================================
    # MEMORY ANALYSIS
    # =========================================================================
    
    def vadinfo(self, memory_file: str, pid: int, engine: str = "auto") -> Dict[str, Any]:
        """List Virtual Address Descriptors for a process (Volatility only)"""
        if not self.volatility.available:
            return {"success": False, "error": "volatility3 not installed (vadinfo requires Volatility)"}
        
        from volatility3.plugins.windows import vadinfo
        
        ctx = self.volatility.get_context(memory_file)
        if ctx is None:
            return {"success": False, "error": "Failed to create context"}
        
        ctx.config['plugins.VadInfo.pid'] = [pid]
        
        result = self.volatility.run_plugin(memory_file, vadinfo.VadInfo)
        result["engine"] = "volatility"
        return result
    
    def dump_vad(self, memory_file: str, pid: int, address: str, 
                 output_path: str) -> Dict[str, Any]:
        """Dump a VAD region to file (Volatility only)"""
        if not self.volatility.available:
            return {"success": False, "error": "volatility3 not installed"}
        
        try:
            from volatility3.plugins.windows import vadinfo, pslist
            
            ctx = self.volatility.get_context(memory_file)
            if ctx is None:
                return {"success": False, "error": "Failed to create context"}
            
            # Parse address
            if isinstance(address, str):
                addr_int = int(address, 16) if address.startswith('0x') else int(address)
            else:
                addr_int = address
            
            # Get kernel layer info via pslist
            _pslist_plugin = plugins.construct_plugin(
                ctx,
                self.volatility._automagics,
                pslist.PsList,
                "plugins",
                None,
                None,
            )
            
            kernel_layer_name = None
            kernel_symbol_table = None
            
            try:
                kernel_layer_name = ctx.config["plugins.PsList.primary"]
                kernel_symbol_table = ctx.config["plugins.PsList.kernel"]
            except KeyError:
                pass
            
            if not kernel_layer_name or not kernel_symbol_table:
                try:
                    kernel_layer_name = _pslist_plugin.config.get("primary", kernel_layer_name)
                    kernel_symbol_table = _pslist_plugin.config.get("kernel", kernel_symbol_table)
                except Exception:
                    pass
            
            if not kernel_layer_name or not kernel_symbol_table:
                return {
                    "success": False,
                    "error": "Failed to determine kernel layer/symbol table"
                }
            
            for proc in pslist.PsList.list_processes(ctx, kernel_layer_name, kernel_symbol_table):
                if proc.UniqueProcessId == pid:
                    proc_layer_name = proc.add_process_layer()
                    proc_layer = ctx.layers[proc_layer_name]
                    
                    for vad in proc.get_vad_root().traverse():
                        if vad.get_start() == addr_int:
                            size = vad.get_end() - vad.get_start()
                            try:
                                data = proc_layer.read(addr_int, size, pad=True)
                                
                                output_file = Path(output_path)
                                output_file.parent.mkdir(parents=True, exist_ok=True)
                                
                                with open(output_path, 'wb') as f:
                                    f.write(data)
                                
                                md5_hash = hashlib.md5(data).hexdigest()
                                
                                return {
                                    "success": True,
                                    "engine": "volatility",
                                    "pid": pid,
                                    "address": hex(addr_int),
                                    "size": size,
                                    "output_path": str(output_file.resolve()),
                                    "md5": md5_hash
                                }
                            except Exception as read_error:
                                return {
                                    "success": False,
                                    "error": f"Failed to read memory: {read_error}"
                                }
            
            return {
                "success": False,
                "error": f"VAD at address {address} not found for PID {pid}"
            }
            
        except Exception as e:
            return {
                "success": False,
                "error": str(e),
                "traceback": traceback.format_exc()
            }
    
    def malfind(self, memory_file: str, pid: Optional[int] = None) -> Dict[str, Any]:
        """Find injected or suspicious code in processes (Volatility only)"""
        if not self.volatility.available:
            return {"success": False, "error": "volatility3 not installed"}
        
        from volatility3.plugins.windows import malfind
        
        ctx = self.volatility.get_context(memory_file)
        if ctx is None:
            return {"success": False, "error": "Failed to create context"}
        
        if pid is not None:
            ctx.config['plugins.Malfind.pid'] = [pid]
        
        result = self.volatility.run_plugin(memory_file, malfind.Malfind)
        result["engine"] = "volatility"
        return result
    
    def netscan(self, memory_file: str) -> Dict[str, Any]:
        """Scan for network connections (Volatility only)"""
        if not self.volatility.available:
            return {"success": False, "error": "volatility3 not installed"}
        
        from volatility3.plugins.windows import netscan
        
        result = self.volatility.run_plugin(memory_file, netscan.NetScan)
        result["engine"] = "volatility"
        return result
    
    def filescan(self, memory_file: str) -> Dict[str, Any]:
        """Scan for file objects in memory (Volatility only)"""
        if not self.volatility.available:
            return {"success": False, "error": "volatility3 not installed"}
        
        from volatility3.plugins.windows import filescan
        
        result = self.volatility.run_plugin(memory_file, filescan.FileScan)
        result["engine"] = "volatility"
        return result
    
    def handles(self, memory_file: str, pid: Optional[int] = None) -> Dict[str, Any]:
        """List process handles (Volatility only)"""
        if not self.volatility.available:
            return {"success": False, "error": "volatility3 not installed"}
        
        from volatility3.plugins.windows import handles
        
        ctx = self.volatility.get_context(memory_file)
        if ctx is None:
            return {"success": False, "error": "Failed to create context"}
        
        if pid is not None:
            ctx.config['plugins.Handles.pid'] = [pid]
        
        result = self.volatility.run_plugin(memory_file, handles.Handles)
        result["engine"] = "volatility"
        return result
    
    def ldrmodules(self, memory_file: str, pid: Optional[int] = None) -> Dict[str, Any]:
        """List loaded modules comparing different sources (Volatility only)"""
        if not self.volatility.available:
            return {"success": False, "error": "volatility3 not installed"}
        
        from volatility3.plugins.windows import ldrmodules
        
        ctx = self.volatility.get_context(memory_file)
        if ctx is None:
            return {"success": False, "error": "Failed to create context"}
        
        if pid is not None:
            ctx.config['plugins.LdrModules.pid'] = [pid]
        
        result = self.volatility.run_plugin(memory_file, ldrmodules.LdrModules)
        result["engine"] = "volatility"
        return result
    
    # =========================================================================
    # DEEP CLR ANALYSIS (NEW)
    # =========================================================================
    
    def memprocfs_get_minidump(self, memory_file: str, pid: int, 
                                output_path: str) -> Dict[str, Any]:
        """
        Extract a WinDbg-compatible minidump for a process using MemProcFS
        
        Args:
            memory_file: Path to memory dump file
            pid: Process ID
            output_path: Path to save the minidump
        
        Returns:
            Dictionary with minidump information
        """
        if not self.memprocfs.available:
            return {"success": False, "error": "MemProcFS not installed. Install via: pip install memprocfs"}
        
        return self.memprocfs.get_minidump(memory_file, pid, output_path)
    
    def list_clr_modules(self, memory_file: str, pid: int, 
                         method: str = "auto") -> Dict[str, Any]:
        """
        List CLR/.NET modules with their assembly addresses using SOS commands
        
        This function:
        1. Extracts a minidump using MemProcFS (if available)
        2. Runs SOS !dumpdomain to get CLR Assembly addresses
        3. Returns sorted assembly addresses
        
        Args:
            memory_file: Path to memory dump file
            pid: Process ID of .NET application
            method: "auto" (try cdb then dotnet-dump), "cdb", or "dotnet-dump"
        
        Returns:
            Dictionary with CLR assembly information including sorted addresses
        """
        # Check if any CLR analyzer is available
        if not self.clr.cdb_available and not self.clr.dotnet_dump_available:
            return {
                "success": False,
                "error": "No CLR analyzer available. Install cdb.exe (Windows SDK) or dotnet-dump",
                "cdb_available": self.clr.cdb_available,
                "dotnet_dump_available": self.clr.dotnet_dump_available
            }
        
        # Step 1: Get minidump
        minidump_path = None
        
        # Try MemProcFS first
        if self.memprocfs.available:
            temp_dir = Path(memory_file).parent / "Temp"
            temp_dir.mkdir(parents=True, exist_ok=True)
            minidump_path = str(temp_dir / f"pid{pid}_minidump.dmp")
            
            minidump_result = self.memprocfs.get_minidump(memory_file, pid, minidump_path)
            
            if not minidump_result["success"]:
                # Try alternative: Look for existing minidump
                logger.warning(f"MemProcFS minidump extraction failed: {minidump_result.get('error')}")
                minidump_path = None
        
        if minidump_path is None:
            return {
                "success": False,
                "error": "Could not extract minidump. MemProcFS required for minidump extraction.",
                "memprocfs_available": self.memprocfs.available,
                "hint": "Install memprocfs: pip install memprocfs"
            }
        
        # Step 2: Run SOS analysis
        clr_result = self.clr.list_clr_assemblies(minidump_path, method)
        
        if clr_result["success"]:
            clr_result["minidump_path"] = minidump_path
            clr_result["pid"] = pid
        
        return clr_result
    
    # =========================================================================
    # NEW TOOLS FROM NOVITAS INVESTIGATION (January 2026)
    # =========================================================================
    
    def get_process_environment(self, memory_file: str, pid: int,
                                  filter_prefix: Optional[str] = None) -> Dict[str, Any]:
        """
        Extract environment variables from a process's environment block.
        
        Reads: PEB -> RTL_USER_PROCESS_PARAMETERS -> Environment
        Parses: UTF-16LE NAME=VALUE\0NAME=VALUE\0\0 format
        
        This is critical for staged payload cases (GrimResource, PASTALOADER)
        where malware stores payload chunks in environment variables.
        
        Args:
            memory_file: Path to memory dump
            pid: Process ID
            filter_prefix: Optional prefix filter (e.g., "B_" for staged payloads)
        
        Returns:
            Dictionary with environment variables
        """
        if not self.memprocfs.available:
            return {
                "success": False,
                "error": "MemProcFS not installed. Install via: pip install memprocfs",
                "hint": "This tool requires MemProcFS for reliable PEB access"
            }
        
        return self.memprocfs.get_process_environment(memory_file, pid, filter_prefix)
    
    def read_virtual_memory(self, memory_file: str, pid: int,
                             address: int, size: int) -> Dict[str, Any]:
        """
        Read arbitrary virtual memory from a process.
        
        Uses MemProcFS for reliable VA->PA translation. This is useful for:
        - Reading specific memory structures (PEB, TEB, etc.)
        - Extracting data from specific addresses
        - Following pointers in memory
        
        Args:
            memory_file: Path to memory dump
            pid: Process ID
            address: Virtual address to read from (can be hex string or int)
            size: Number of bytes to read
        
        Returns:
            Dictionary with memory data (base64 encoded)
        """
        if not self.memprocfs.available:
            return {
                "success": False,
                "error": "MemProcFS not installed. Install via: pip install memprocfs"
            }
        
        # Handle hex string addresses
        if isinstance(address, str):
            address = int(address, 16) if address.startswith('0x') else int(address)
        
        return self.memprocfs.read_virtual_memory(memory_file, pid, address, size)
    
    def find_hidden_modules(self, memory_file: str, pid: int) -> Dict[str, Any]:
        """
        Find modules that exist in memory but aren't in PEB loader lists.
        
        Cross-references:
        - ldrmodules (InLoad, InInit, InMem flags)
        - VAD mappings with MappedPath
        - PE headers at VAD bases
        
        This detects DirtyCLR, process hollowing, and other injection techniques.
        
        Args:
            memory_file: Path to memory dump
            pid: Process ID
        
        Returns:
            Dictionary with hidden modules found
        """
        # First, get ldrmodules output
        ldr_result = self.ldrmodules(memory_file, pid)
        if not ldr_result.get("success"):
            return {
                "success": False,
                "error": f"Failed to get ldrmodules: {ldr_result.get('error')}"
            }
        
        hidden_modules = []
        
        # Look for modules where InLoad=InInit=InMem=False
        for mod in ldr_result.get("results", []):
            in_load = mod.get("InLoad", True)
            in_init = mod.get("InInit", True) 
            in_mem = mod.get("InMem", True)
            
            # Handle string boolean values
            if isinstance(in_load, str):
                in_load = in_load.lower() == 'true'
            if isinstance(in_init, str):
                in_init = in_init.lower() == 'true'
            if isinstance(in_mem, str):
                in_mem = in_mem.lower() == 'true'
            
            # A hidden module is typically NOT in any loader list
            if not in_load and not in_init and not in_mem:
                base = mod.get("Base", mod.get("MappedPath", "Unknown"))
                hidden_modules.append({
                    "base": base,
                    "in_load": in_load,
                    "in_init": in_init,
                    "in_mem": in_mem,
                    "mapped_path": mod.get("MappedPath", ""),
                    "raw_entry": mod
                })
        
        # Also check VADs for executable regions with PE headers
        vad_result = self.vadinfo(memory_file, pid)
        if vad_result.get("success"):
            for vad in vad_result.get("results", []):
                protection = str(vad.get("Protection", ""))
                # Look for executable VADs
                if "EXECUTE" in protection.upper():
                    vad_start = vad.get("Start", vad.get("VadStart"))
                    if vad_start:
                        # Check if this VAD is already known (in module list)
                        vad_hex = vad_start if isinstance(vad_start, str) else hex(vad_start)
                        
                        # Try to read first bytes to check for PE header
                        if self.memprocfs.available:
                            try:
                                addr = int(vad_hex, 16) if isinstance(vad_hex, str) else vad_hex
                                mem_result = self.memprocfs.read_virtual_memory(
                                    memory_file, pid, addr, 2
                                )
                                if mem_result.get("success"):
                                    # Decode first 2 bytes
                                    data_b64 = mem_result.get("data_b64", "")
                                    if data_b64:
                                        header = base64.b64decode(data_b64)
                                        has_pe = header[:2] == b'MZ'
                                        
                                        if has_pe:
                                            # Check if this is already in hidden list
                                            already_found = any(
                                                h.get("base") == vad_hex for h in hidden_modules
                                            )
                                            if not already_found:
                                                hidden_modules.append({
                                                    "base": vad_hex,
                                                    "size": vad.get("End", 0) - addr if vad.get("End") else None,
                                                    "vad_protection": protection,
                                                    "has_pe_header": True,
                                                    "source": "vad_scan"
                                                })
                            except Exception as e:
                                logger.debug(f"Could not check VAD {vad_hex}: {e}")
        
        return {
            "success": True,
            "pid": pid,
            "hidden_modules": hidden_modules,
            "count": len(hidden_modules),
            "engine": "volatility+memprocfs"
        }
    
    def dump_vad_raw(self, memory_file: str, pid: int, address: int,
                      output_path: str, trim_trailing_zeros: bool = False) -> Dict[str, Any]:
        """
        Dump raw VAD bytes without PE reconstruction.
        
        Unlike dump_vad which may apply PE reconstruction, this dumps exact raw bytes.
        Useful for hash matching and malware analysis.
        
        Args:
            memory_file: Path to memory dump
            pid: Process ID
            address: VAD start address (can be hex string or int)
            output_path: Path to save the dump
            trim_trailing_zeros: If True, trim trailing zero bytes
        
        Returns:
            Dictionary with dump information and hashes
        """
        if not self.memprocfs.available:
            # Fall back to standard dump_vad
            result = self.dump_vad(memory_file, pid, str(address) if isinstance(address, int) else address, output_path)
            if result.get("success"):
                result["method"] = "volatility_fallback"
                result["note"] = "Used Volatility dump_vad (may include PE reconstruction)"
            return result
        
        try:
            vmm = self.memprocfs._get_vmm(memory_file)
            if vmm is None:
                return {"success": False, "error": "Failed to open memory file with MemProcFS"}
            
            proc = vmm.process(pid)
            if proc is None:
                return {"success": False, "error": f"Process {pid} not found"}
            
            # Parse address
            if isinstance(address, str):
                addr_int = int(address, 16) if address.startswith('0x') else int(address)
            else:
                addr_int = address
            
            # Find the VAD containing this address
            # Use MemProcFS maps to find the VAD bounds
            vad_info = None
            try:
                maps = proc.maps()
                for m in maps:
                    if hasattr(m, 'base') and hasattr(m, 'size'):
                        if m.base <= addr_int < m.base + m.size:
                            vad_info = {"start": m.base, "size": m.size}
                            break
            except (AttributeError, TypeError, KeyError):
                pass
            
            if vad_info is None:
                # Try to get size from vadinfo
                vad_result = self.vadinfo(memory_file, pid)
                if vad_result.get("success"):
                    for vad in vad_result.get("results", []):
                        vad_start = vad.get("Start", vad.get("VadStart"))
                        if vad_start:
                            start_int = int(vad_start, 16) if isinstance(vad_start, str) else vad_start
                            if start_int == addr_int:
                                end = vad.get("End", vad.get("VadEnd"))
                                if end:
                                    end_int = int(end, 16) if isinstance(end, str) else end
                                    vad_info = {"start": start_int, "size": end_int - start_int}
                                    break
            
            if vad_info is None:
                return {
                    "success": False,
                    "error": f"Could not find VAD at address {hex(addr_int)}",
                    "pid": pid
                }
            
            # Read raw bytes
            size = vad_info["size"]
            data = proc.memory.read(addr_int, size)
            
            if data is None or len(data) == 0:
                return {
                    "success": False,
                    "error": f"Failed to read VAD memory at {hex(addr_int)}"
                }
            
            # Calculate raw hash
            md5_raw = hashlib.md5(data).hexdigest()
            size_raw = len(data)
            
            # Trim trailing zeros if requested
            if trim_trailing_zeros:
                # Find last non-zero byte
                trimmed = data.rstrip(b'\x00')
                md5_trimmed = hashlib.md5(trimmed).hexdigest()
                size_trimmed = len(trimmed)
            else:
                trimmed = data
                md5_trimmed = md5_raw
                size_trimmed = size_raw
            
            # Write to file
            output_file = Path(output_path)
            output_file.parent.mkdir(parents=True, exist_ok=True)
            
            with open(output_file, 'wb') as f:
                f.write(trimmed if trim_trailing_zeros else data)
            
            return {
                "success": True,
                "pid": pid,
                "address": hex(addr_int),
                "output_path": str(output_file.resolve()),
                "size_raw": size_raw,
                "size_trimmed": size_trimmed,
                "md5_raw": md5_raw,
                "md5_trimmed": md5_trimmed,
                "trim_trailing_zeros": trim_trailing_zeros,
                "method": "memprocfs_raw"
            }
            
        except Exception as e:
            logger.error(f"dump_vad_raw failed: {e}")
            return {"success": False, "error": str(e), "traceback": traceback.format_exc()}
    
    def reconstruct_staged_payload(self, memory_file: str, pid: int,
                                    var_prefix: str = "B_",
                                    decode_algorithm: str = "raw_concat",
                                    output_path: Optional[str] = None) -> Dict[str, Any]:
        """
        Reconstruct payload from staged environment variables.
        
        Common malware pattern (PASTALOADER, GrimResource) stores payload chunks
        in numbered environment variables like B_1, B_2, ... B_N.
        
        Supported decode_algorithms:
        - "raw_concat": Simple concatenation of all vars in order
        - "base64_concat": Concat then base64 decode
        - "pastaloader": Replace("A$+", ""), Reverse, Pad, Base64Decode
        
        Args:
            memory_file: Path to memory dump
            pid: Process ID
            var_prefix: Prefix for staged variables (default "B_")
            decode_algorithm: Decoding algorithm to use
            output_path: Optional path to save reconstructed payload
        
        Returns:
            Dictionary with reconstructed payload info
        """
        # Get environment variables
        env_result = self.get_process_environment(memory_file, pid, filter_prefix=var_prefix)
        
        if not env_result.get("success"):
            return {
                "success": False,
                "error": f"Failed to get environment: {env_result.get('error')}"
            }
        
        filtered_vars = env_result.get("filtered_vars", {})
        
        if not filtered_vars:
            return {
                "success": False,
                "error": f"No environment variables found with prefix '{var_prefix}'",
                "pid": pid
            }
        
        # Sort variables by numeric suffix
        def get_sort_key(name):
            try:
                # Extract numeric part after prefix
                suffix = name[len(var_prefix):]
                return int(suffix)
            except (ValueError, TypeError):
                return 0
        
        sorted_names = sorted(filtered_vars.keys(), key=get_sort_key)
        
        # Concatenate values in order
        joined = ''.join(filtered_vars[name] for name in sorted_names)
        
        # Apply decoding algorithm
        try:
            if decode_algorithm == "raw_concat":
                # Just concatenate, encode as bytes
                decoded = joined.encode('utf-8')
                
            elif decode_algorithm == "base64_concat":
                # Concat then base64 decode
                decoded = base64.b64decode(joined)
                
            elif decode_algorithm == "pastaloader":
                # PASTALOADER algorithm:
                # 1. Remove "A$+" markers
                # 2. Reverse the string
                # 3. Pad to multiple of 4
                # 4. Base64 decode
                cleaned = joined.replace("A$+", "")
                reversed_str = cleaned[::-1]
                
                # Pad for base64
                padding = 4 - (len(reversed_str) % 4)
                if padding != 4:
                    reversed_str += '=' * padding
                
                decoded = base64.b64decode(reversed_str)
                
            else:
                return {
                    "success": False,
                    "error": f"Unknown decode_algorithm: {decode_algorithm}",
                    "supported": ["raw_concat", "base64_concat", "pastaloader"]
                }
                
        except Exception as e:
            return {
                "success": False,
                "error": f"Decoding failed: {e}",
                "algorithm": decode_algorithm,
                "joined_length": len(joined),
                "hint": "Try a different decode_algorithm"
            }
        
        # Calculate hash
        md5_hash = hashlib.md5(decoded).hexdigest()
        
        result = {
            "success": True,
            "pid": pid,
            "var_prefix": var_prefix,
            "vars_found": len(filtered_vars),
            "vars_used": len(sorted_names),
            "joined_length": len(joined),
            "decoded_length": len(decoded),
            "md5": md5_hash.upper(),
            "decode_algorithm": decode_algorithm
        }
        
        # Save to file if output path specified
        if output_path:
            output_file = Path(output_path)
            output_file.parent.mkdir(parents=True, exist_ok=True)
            
            with open(output_file, 'wb') as f:
                f.write(decoded)
            
            result["output_path"] = str(output_file.resolve())
        else:
            # Include base64 encoded payload in result
            result["payload_b64"] = base64.b64encode(decoded).decode('ascii')
        
        return result
    
    # =========================================================================
    # VFS BROWSING (MemProcFS)
    # =========================================================================
    
    def vfs_list(self, memory_file: str, path: str = "/") -> Dict[str, Any]:
        """
        List directory entries in the MemProcFS virtual file system.
        
        Args:
            memory_file: Path to memory dump
            path: VFS path to list (default: "/" for root)
        
        Returns:
            Dictionary with directory entries
        """
        if not self.memprocfs.available:
            return {"success": False, "error": "MemProcFS not installed (required for VFS access)"}
        return self.memprocfs.vfs_list(memory_file, path)
    
    def vfs_read(self, memory_file: str, path: str, size: int = 4096, 
                 offset: int = 0) -> Dict[str, Any]:
        """
        Read bytes from a file in the MemProcFS VFS.
        
        Args:
            memory_file: Path to memory dump
            path: VFS file path to read
            size: Number of bytes to read (max 100MB)
            offset: Offset in file to start reading
        
        Returns:
            Dictionary with file data (base64 encoded)
        """
        if not self.memprocfs.available:
            return {"success": False, "error": "MemProcFS not installed"}
        return self.memprocfs.vfs_read(memory_file, path, size, offset)
    
    def vfs_export(self, memory_file: str, vfs_path: str, output_path: str) -> Dict[str, Any]:
        """
        Export a file from the MemProcFS VFS to disk.
        
        Args:
            memory_file: Path to memory dump
            vfs_path: VFS path to export
            output_path: Local path to save the file
        
        Returns:
            Dictionary with export status
        """
        if not self.memprocfs.available:
            return {"success": False, "error": "MemProcFS not installed"}
        return self.memprocfs.vfs_export(memory_file, vfs_path, output_path)
    
    def read_physical_memory(self, memory_file: str, address: int, size: int) -> Dict[str, Any]:
        """
        Read physical memory at a given address.
        
        Args:
            memory_file: Path to memory dump
            address: Physical address to read
            size: Number of bytes to read
        
        Returns:
            Dictionary with memory data (base64 encoded)
        """
        if not self.memprocfs.available:
            return {"success": False, "error": "MemProcFS not installed (required for physical memory access)"}
        return self.memprocfs.read_physical_memory(memory_file, address, size)
    
    # =========================================================================
    # YARA SCANNING
    # =========================================================================
    
    def yara_scan(self, memory_file: str, rules_text: Optional[str] = None,
                  rules_path: Optional[str] = None, scope: str = "process_vads",
                  pid: Optional[int] = None, address: Optional[int] = None,
                  size: Optional[int] = None, max_matches: int = 100) -> Dict[str, Any]:
        """
        Scan memory with custom YARA rules.
        
        Args:
            memory_file: Path to memory dump
            rules_text: YARA rules as string
            rules_path: Path to YARA rules file
            scope: Scan scope - "process_vads", "process_range", or "full_dump"
            pid: Process ID (required for process_vads and process_range)
            address: Start address (for process_range scope)
            size: Size to scan (for process_range scope)
            max_matches: Maximum number of matches to return
        
        Returns:
            Dictionary with YARA matches
        """
        try:
            import yara
        except ImportError:
            return {"success": False, "error": "yara-python not installed. Install via: pip install yara-python"}
        
        if not rules_text and not rules_path:
            return {"success": False, "error": "Either rules_text or rules_path must be provided"}
        
        try:
            # Compile rules
            if rules_path:
                rules = yara.compile(filepath=rules_path)
            else:
                rules = yara.compile(source=rules_text)
            
            matches_found = []
            
            if scope == "process_range":
                # Scan a specific memory range
                if pid is None or address is None or size is None:
                    return {"success": False, "error": "process_range scope requires pid, address, and size"}
                
                mem_result = self.read_virtual_memory(memory_file, pid, address, size)
                if not mem_result.get("success"):
                    return mem_result
                
                data = base64.b64decode(mem_result["data_b64"])
                matches = rules.match(data=data)
                
                for match in matches[:max_matches]:
                    match_info = {
                        "rule": match.rule,
                        "tags": list(match.tags),
                        "pid": pid,
                        "base_address": hex(address),
                        "strings": []
                    }
                    for string_match in match.strings[:10]:
                        match_info["strings"].append({
                            "identifier": string_match.identifier,
                            "offset": string_match.instances[0].offset if string_match.instances else 0,
                            "data_preview": string_match.instances[0].matched_data[:32].hex() if string_match.instances else ""
                        })
                    matches_found.append(match_info)
                    
            elif scope == "process_vads":
                # Scan all VADs for a process
                if pid is None:
                    return {"success": False, "error": "process_vads scope requires pid"}
                
                vad_result = self.vadinfo(memory_file, pid)
                if not vad_result.get("success"):
                    return vad_result
                
                vads_scanned = 0
                max_vads = 50  # Limit VADs to scan for performance
                
                for vad in vad_result.get("results", [])[:max_vads]:
                    try:
                        vad_start = int(vad.get("Start", "0"), 16) if isinstance(vad.get("Start"), str) else vad.get("Start", 0)
                        vad_end = int(vad.get("End", "0"), 16) if isinstance(vad.get("End"), str) else vad.get("End", 0)
                        vad_size = vad_end - vad_start
                        
                        if vad_size <= 0 or vad_size > 50 * 1024 * 1024:  # Skip invalid or too large
                            continue
                        
                        mem_result = self.read_virtual_memory(memory_file, pid, vad_start, vad_size)
                        if not mem_result.get("success"):
                            continue
                        
                        data = base64.b64decode(mem_result["data_b64"])
                        matches = rules.match(data=data)
                        
                        for match in matches:
                            if len(matches_found) >= max_matches:
                                break
                            match_info = {
                                "rule": match.rule,
                                "tags": list(match.tags),
                                "pid": pid,
                                "vad_start": hex(vad_start),
                                "vad_protection": vad.get("Protection", "unknown"),
                                "strings": []
                            }
                            for string_match in match.strings[:5]:
                                match_info["strings"].append({
                                    "identifier": string_match.identifier,
                                    "offset": string_match.instances[0].offset if string_match.instances else 0
                                })
                            matches_found.append(match_info)
                        
                        vads_scanned += 1
                        
                    except Exception as e:
                        logger.debug(f"Error scanning VAD: {e}")
                        continue
                
                return {
                    "success": True,
                    "scope": scope,
                    "pid": pid,
                    "vads_scanned": vads_scanned,
                    "matches": matches_found,
                    "match_count": len(matches_found)
                }
                
            elif scope == "full_dump":
                # Scan the raw memory file directly
                matches = rules.match(filepath=memory_file)
                
                for match in matches[:max_matches]:
                    match_info = {
                        "rule": match.rule,
                        "tags": list(match.tags),
                        "strings": []
                    }
                    for string_match in match.strings[:10]:
                        match_info["strings"].append({
                            "identifier": string_match.identifier,
                            "offset": string_match.instances[0].offset if string_match.instances else 0
                        })
                    matches_found.append(match_info)
            else:
                return {"success": False, "error": f"Unknown scope: {scope}. Use: process_vads, process_range, or full_dump"}
            
            return {
                "success": True,
                "scope": scope,
                "matches": matches_found,
                "match_count": len(matches_found)
            }
            
        except yara.Error as e:
            return {"success": False, "error": f"YARA error: {e}"}
        except Exception as e:
            logger.error(f"yara_scan failed: {e}")
            return {"success": False, "error": str(e), "traceback": traceback.format_exc()}
    
    # =========================================================================
    # REGISTRY HIVE TOOLS (Volatility)
    # =========================================================================
    
    def list_registry_hives(self, memory_file: str) -> Dict[str, Any]:
        """
        List registry hives found in memory.
        
        Uses Volatility's hivelist plugin.
        
        Args:
            memory_file: Path to memory dump
        
        Returns:
            Dictionary with hive list
        """
        if not self.volatility.available:
            return {"success": False, "error": "Volatility 3 not installed"}
        
        try:
            from volatility3.plugins.windows.registry import hivelist
            
            result = self.volatility.run_plugin(memory_file, hivelist.HiveList)
            result["engine"] = "volatility"
            return result
        except ImportError:
            return {"success": False, "error": "Volatility hivelist plugin not available"}
        except Exception as e:
            return {"success": False, "error": str(e)}
    
    def registry_printkey(self, memory_file: str, key_path: str, 
                          hive_offset: Optional[int] = None) -> Dict[str, Any]:
        """
        Print registry key values.
        
        Uses Volatility's printkey plugin.
        
        Args:
            memory_file: Path to memory dump
            key_path: Registry key path (e.g., "Software\\Microsoft\\Windows\\CurrentVersion\\Run")
            hive_offset: Optional hive offset (from hivelist)
        
        Returns:
            Dictionary with key values
        """
        if not self.volatility.available:
            return {"success": False, "error": "Volatility 3 not installed"}
        
        try:
            from volatility3.plugins.windows.registry import printkey
            
            ctx = self.volatility.get_context(memory_file)
            if ctx is None:
                return {"success": False, "error": "Failed to create context"}
            
            ctx.config['plugins.PrintKey.key'] = key_path
            if hive_offset is not None:
                ctx.config['plugins.PrintKey.offset'] = hive_offset
            
            result = self.volatility.run_plugin(memory_file, printkey.PrintKey)
            result["engine"] = "volatility"
            result["key_path"] = key_path
            return result
        except ImportError:
            return {"success": False, "error": "Volatility printkey plugin not available"}
        except Exception as e:
            return {"success": False, "error": str(e)}
    
    # =========================================================================
    # ENRICHED HANDLES
    # =========================================================================
    
    def handles_enriched(self, memory_file: str, pid: Optional[int] = None,
                         object_type: Optional[str] = None,
                         name_filter: Optional[str] = None) -> Dict[str, Any]:
        """
        Get enriched handle information with filtering and summaries.
        
        Args:
            memory_file: Path to memory dump
            pid: Filter by specific PID
            object_type: Filter by object type (e.g., "File", "Key", "Process", "Thread")
            name_filter: Filter by name pattern (substring match)
        
        Returns:
            Dictionary with handles, summaries, and cross-references
        """
        # Get handles
        handles_result = self.handles(memory_file, pid)
        if not handles_result.get("success"):
            return handles_result
        
        handles = handles_result.get("results", [])
        
        # Get process list for cross-reference
        proc_result = self.list_processes(memory_file)
        pid_to_name = {}
        if proc_result.get("success"):
            for proc in proc_result.get("results", []):
                pid_to_name[proc.get("PID")] = proc.get("ImageFileName", "Unknown")
        
        # Filter and enrich
        filtered_handles = []
        type_counts = {}
        process_counts = {}
        
        for handle in handles:
            handle_type = handle.get("Type", "Unknown")
            handle_name = handle.get("Name", "") or ""
            handle_pid = handle.get("PID")
            
            # Apply filters
            if object_type and handle_type.lower() != object_type.lower():
                continue
            if name_filter and name_filter.lower() not in handle_name.lower():
                continue
            
            # Enrich with process name
            enriched = dict(handle)
            if handle_pid in pid_to_name:
                enriched["ProcessName"] = pid_to_name[handle_pid]
            
            filtered_handles.append(enriched)
            
            # Count by type
            type_counts[handle_type] = type_counts.get(handle_type, 0) + 1
            
            # Count by process
            if handle_pid:
                process_counts[handle_pid] = process_counts.get(handle_pid, 0) + 1
        
        # Sort type counts
        sorted_types = sorted(type_counts.items(), key=lambda x: x[1], reverse=True)
        
        return {
            "success": True,
            "engine": handles_result.get("engine", "volatility"),
            "total_handles": len(handles),
            "filtered_count": len(filtered_handles),
            "filters_applied": {
                "pid": pid,
                "object_type": object_type,
                "name_filter": name_filter
            },
            "type_summary": dict(sorted_types[:20]),
            "handles": filtered_handles[:500],  # Limit output size
            "truncated": len(filtered_handles) > 500
        }
    
    # =========================================================================
    # TAGGING AND TIMELINE UTILITIES
    # =========================================================================
    
    def add_tag(self, tag_id: str, tag_type: str, value: str, 
                notes: Optional[str] = None, metadata: Optional[Dict] = None) -> Dict[str, Any]:
        """
        Add a tag to the in-memory tag store.
        
        Tags persist for the MCP session lifetime. Useful for AI agents
        to track findings across multiple tool calls.
        
        Args:
            tag_id: Unique identifier for the tag
            tag_type: Type of tag (e.g., "ioc", "pid", "address", "finding")
            value: Tag value
            notes: Optional notes
            metadata: Optional additional metadata
        
        Returns:
            Dictionary with tag info
        """
        if not hasattr(self, '_tags'):
            self._tags = {}
        
        tag = {
            "id": tag_id,
            "type": tag_type,
            "value": value,
            "notes": notes,
            "metadata": metadata or {},
            "created_at": datetime.now().isoformat()
        }
        
        self._tags[tag_id] = tag
        
        return {
            "success": True,
            "tag": tag,
            "total_tags": len(self._tags)
        }
    
    def list_tags(self, tag_type: Optional[str] = None) -> Dict[str, Any]:
        """
        List all tags in the in-memory store.
        
        Args:
            tag_type: Optional filter by tag type
        
        Returns:
            Dictionary with tags
        """
        if not hasattr(self, '_tags'):
            self._tags = {}
        
        tags = list(self._tags.values())
        
        if tag_type:
            tags = [t for t in tags if t.get("type") == tag_type]
        
        return {
            "success": True,
            "tags": tags,
            "count": len(tags),
            "filter": tag_type
        }
    
    def clear_tags(self) -> Dict[str, Any]:
        """Clear all tags from the in-memory store."""
        if not hasattr(self, '_tags'):
            self._tags = {}
        
        count = len(self._tags)
        self._tags = {}
        
        return {
            "success": True,
            "cleared_count": count
        }
    
    def add_timeline_event(self, timestamp: str, event_type: str, 
                           description: str, source: Optional[str] = None,
                           pid: Optional[int] = None, 
                           metadata: Optional[Dict] = None) -> Dict[str, Any]:
        """
        Add an event to the investigation timeline.
        
        Timeline events persist for the MCP session lifetime.
        
        Args:
            timestamp: Event timestamp (ISO format or any string)
            event_type: Type of event (e.g., "process_start", "network", "file_access")
            description: Event description
            source: Source of the event (e.g., tool name)
            pid: Associated process ID
            metadata: Additional metadata
        
        Returns:
            Dictionary with event info
        """
        if not hasattr(self, '_timeline'):
            self._timeline = []
        
        event = {
            "id": len(self._timeline) + 1,
            "timestamp": timestamp,
            "event_type": event_type,
            "description": description,
            "source": source,
            "pid": pid,
            "metadata": metadata or {},
            "added_at": datetime.now().isoformat()
        }
        
        self._timeline.append(event)
        
        # Sort by timestamp
        try:
            self._timeline.sort(key=lambda x: x.get("timestamp", ""))
        except (TypeError, KeyError):
            pass
        
        return {
            "success": True,
            "event": event,
            "total_events": len(self._timeline)
        }
    
    def list_timeline(self, event_type: Optional[str] = None,
                      pid: Optional[int] = None) -> Dict[str, Any]:
        """
        List timeline events.
        
        Args:
            event_type: Optional filter by event type
            pid: Optional filter by PID
        
        Returns:
            Dictionary with timeline events
        """
        if not hasattr(self, '_timeline'):
            self._timeline = []
        
        events = self._timeline.copy()
        
        if event_type:
            events = [e for e in events if e.get("event_type") == event_type]
        if pid is not None:
            events = [e for e in events if e.get("pid") == pid]
        
        return {
            "success": True,
            "events": events,
            "count": len(events),
            "filters": {"event_type": event_type, "pid": pid}
        }
    
    def clear_timeline(self) -> Dict[str, Any]:
        """Clear all timeline events."""
        if not hasattr(self, '_timeline'):
            self._timeline = []
        
        count = len(self._timeline)
        self._timeline = []
        
        return {
            "success": True,
            "cleared_count": count
        }


# =============================================================================
# TOOL DEFINITIONS FOR MCP SERVER
# =============================================================================

def get_tools():
    """Return tool definitions in standard format"""
    return [
        {
            "type": "function",
            "function": {
                "name": "list_processes",
                "description": "List all processes with PIDs and start times",
                "parameters": {
                    "type": "object",
                    "properties": {
                        "memory_file": {"type": "string", "description": "Path to memory dump"},
                        "pid": {"type": "integer", "description": "Filter by specific PID"},
                        "engine": {"type": "string", "description": "Backend: auto, volatility, memprocfs"}
                    },
                    "required": ["memory_file"]
                }
            }
        },
        {
            "type": "function",
            "function": {
                "name": "list_dlls",
                "description": "List loaded DLLs for a process",
                "parameters": {
                    "type": "object",
                    "properties": {
                        "memory_file": {"type": "string", "description": "Path to memory dump"},
                        "pid": {"type": "integer", "description": "Filter by specific PID"},
                        "engine": {"type": "string", "description": "Backend: auto, volatility, memprocfs"}
                    },
                    "required": ["memory_file"]
                }
            }
        },
        {
            "type": "function",
            "function": {
                "name": "get_cmdline",
                "description": "Get command line arguments for processes",
                "parameters": {
                    "type": "object",
                    "properties": {
                        "memory_file": {"type": "string", "description": "Path to memory dump"},
                        "pid": {"type": "integer", "description": "Filter by specific PID"}
                    },
                    "required": ["memory_file"]
                }
            }
        },
        {
            "type": "function",
            "function": {
                "name": "vadinfo",
                "description": "List Virtual Address Descriptors for a process",
                "parameters": {
                    "type": "object",
                    "properties": {
                        "memory_file": {"type": "string", "description": "Path to memory dump"},
                        "pid": {"type": "integer", "description": "Process ID"}
                    },
                    "required": ["memory_file", "pid"]
                }
            }
        },
        {
            "type": "function",
            "function": {
                "name": "dump_vad",
                "description": "Dump a VAD region to file",
                "parameters": {
                    "type": "object",
                    "properties": {
                        "memory_file": {"type": "string", "description": "Path to memory dump"},
                        "pid": {"type": "integer", "description": "Process ID"},
                        "address": {"type": "string", "description": "VAD start address (hex)"},
                        "output_path": {"type": "string", "description": "Output file path"}
                    },
                    "required": ["memory_file", "pid", "address", "output_path"]
                }
            }
        },
        {
            "type": "function",
            "function": {
                "name": "malfind",
                "description": "Find injected or suspicious code in processes",
                "parameters": {
                    "type": "object",
                    "properties": {
                        "memory_file": {"type": "string", "description": "Path to memory dump"},
                        "pid": {"type": "integer", "description": "Filter by specific PID"}
                    },
                    "required": ["memory_file"]
                }
            }
        },
        {
            "type": "function",
            "function": {
                "name": "netscan",
                "description": "Scan for network connections",
                "parameters": {
                    "type": "object",
                    "properties": {
                        "memory_file": {"type": "string", "description": "Path to memory dump"}
                    },
                    "required": ["memory_file"]
                }
            }
        },
        {
            "type": "function",
            "function": {
                "name": "filescan",
                "description": "Scan for file objects in memory",
                "parameters": {
                    "type": "object",
                    "properties": {
                        "memory_file": {"type": "string", "description": "Path to memory dump"}
                    },
                    "required": ["memory_file"]
                }
            }
        },
        {
            "type": "function",
            "function": {
                "name": "handles",
                "description": "List process handles",
                "parameters": {
                    "type": "object",
                    "properties": {
                        "memory_file": {"type": "string", "description": "Path to memory dump"},
                        "pid": {"type": "integer", "description": "Filter by specific PID"}
                    },
                    "required": ["memory_file"]
                }
            }
        },
        {
            "type": "function",
            "function": {
                "name": "ldrmodules",
                "description": "List loaded modules comparing different sources (detect hidden)",
                "parameters": {
                    "type": "object",
                    "properties": {
                        "memory_file": {"type": "string", "description": "Path to memory dump"},
                        "pid": {"type": "integer", "description": "Filter by specific PID"}
                    },
                    "required": ["memory_file"]
                }
            }
        },
        {
            "type": "function",
            "function": {
                "name": "memprocfs_get_minidump",
                "description": "Extract WinDbg-compatible minidump for a process using MemProcFS",
                "parameters": {
                    "type": "object",
                    "properties": {
                        "memory_file": {"type": "string", "description": "Path to memory dump"},
                        "pid": {"type": "integer", "description": "Process ID"},
                        "output_path": {"type": "string", "description": "Output path for minidump"}
                    },
                    "required": ["memory_file", "pid", "output_path"]
                }
            }
        },
        {
            "type": "function",
            "function": {
                "name": "list_clr_modules",
                "description": "List CLR/.NET modules with assembly addresses using SOS commands",
                "parameters": {
                    "type": "object",
                    "properties": {
                        "memory_file": {"type": "string", "description": "Path to memory dump"},
                        "pid": {"type": "integer", "description": "Process ID"},
                        "method": {"type": "string", "description": "Method: auto, cdb, dotnet-dump"}
                    },
                    "required": ["memory_file", "pid"]
                }
            }
        },
        {
            "type": "function",
            "function": {
                "name": "get_process_environment",
                "description": "Extract environment variables from a process's PEB. Critical for staged payload analysis (GrimResource, PASTALOADER).",
                "parameters": {
                    "type": "object",
                    "properties": {
                        "memory_file": {"type": "string", "description": "Path to memory dump"},
                        "pid": {"type": "integer", "description": "Process ID"},
                        "filter_prefix": {"type": "string", "description": "Optional prefix to filter vars (e.g., 'B_')"}
                    },
                    "required": ["memory_file", "pid"]
                }
            }
        },
        {
            "type": "function",
            "function": {
                "name": "read_virtual_memory",
                "description": "Read arbitrary virtual memory from a process. Uses MemProcFS for reliable VA->PA translation.",
                "parameters": {
                    "type": "object",
                    "properties": {
                        "memory_file": {"type": "string", "description": "Path to memory dump"},
                        "pid": {"type": "integer", "description": "Process ID"},
                        "address": {"type": "integer", "description": "Virtual address to read (can be hex string)"},
                        "size": {"type": "integer", "description": "Number of bytes to read"}
                    },
                    "required": ["memory_file", "pid", "address", "size"]
                }
            }
        },
        {
            "type": "function",
            "function": {
                "name": "find_hidden_modules",
                "description": "Find modules not in PEB loader lists (DirtyCLR, hollowing detection)",
                "parameters": {
                    "type": "object",
                    "properties": {
                        "memory_file": {"type": "string", "description": "Path to memory dump"},
                        "pid": {"type": "integer", "description": "Process ID"}
                    },
                    "required": ["memory_file", "pid"]
                }
            }
        },
        {
            "type": "function",
            "function": {
                "name": "dump_vad_raw",
                "description": "Dump raw VAD bytes without PE reconstruction. Useful for hash matching.",
                "parameters": {
                    "type": "object",
                    "properties": {
                        "memory_file": {"type": "string", "description": "Path to memory dump"},
                        "pid": {"type": "integer", "description": "Process ID"},
                        "address": {"type": "integer", "description": "VAD start address (hex or int)"},
                        "output_path": {"type": "string", "description": "Output file path"},
                        "trim_trailing_zeros": {"type": "boolean", "description": "Trim trailing zeros for hash matching"}
                    },
                    "required": ["memory_file", "pid", "address", "output_path"]
                }
            }
        },
        {
            "type": "function",
            "function": {
                "name": "reconstruct_staged_payload",
                "description": "Reconstruct payload from staged environment variables (PASTALOADER pattern)",
                "parameters": {
                    "type": "object",
                    "properties": {
                        "memory_file": {"type": "string", "description": "Path to memory dump"},
                        "pid": {"type": "integer", "description": "Process ID"},
                        "var_prefix": {"type": "string", "description": "Prefix for staged vars (default: 'B_')"},
                        "decode_algorithm": {"type": "string", "description": "Algorithm: raw_concat, base64_concat, pastaloader"},
                        "output_path": {"type": "string", "description": "Optional output file path"}
                    },
                    "required": ["memory_file", "pid"]
                }
            }
        },
        {
            "type": "function",
            "function": {
                "name": "check_installation",
                "description": "Check installation status of all backends",
                "parameters": {
                    "type": "object",
                    "properties": {}
                }
            }
        },
        {
            "type": "function",
            "function": {
                "name": "list_capabilities",
                "description": "List all available tools and backends",
                "parameters": {
                    "type": "object",
                    "properties": {}
                }
            }
        },
        # VFS Browsing Tools
        {
            "type": "function",
            "function": {
                "name": "vfs_list",
                "description": "List directory entries in MemProcFS virtual file system. Use to browse /pid/, /registry/, /sys/ etc.",
                "parameters": {
                    "type": "object",
                    "properties": {
                        "memory_file": {"type": "string", "description": "Path to memory dump"},
                        "path": {"type": "string", "description": "VFS path to list (default: /)"}
                    },
                    "required": ["memory_file"]
                }
            }
        },
        {
            "type": "function",
            "function": {
                "name": "vfs_read",
                "description": "Read bytes from a file in MemProcFS VFS. Returns base64-encoded data.",
                "parameters": {
                    "type": "object",
                    "properties": {
                        "memory_file": {"type": "string", "description": "Path to memory dump"},
                        "path": {"type": "string", "description": "VFS file path to read"},
                        "size": {"type": "integer", "description": "Bytes to read (default 4096, max 100MB)"},
                        "offset": {"type": "integer", "description": "Offset in file (default 0)"}
                    },
                    "required": ["memory_file", "path"]
                }
            }
        },
        {
            "type": "function",
            "function": {
                "name": "vfs_export",
                "description": "Export a file from MemProcFS VFS to local disk",
                "parameters": {
                    "type": "object",
                    "properties": {
                        "memory_file": {"type": "string", "description": "Path to memory dump"},
                        "vfs_path": {"type": "string", "description": "VFS path to export"},
                        "output_path": {"type": "string", "description": "Local path to save file"}
                    },
                    "required": ["memory_file", "vfs_path", "output_path"]
                }
            }
        },
        {
            "type": "function",
            "function": {
                "name": "read_physical_memory",
                "description": "Read physical memory at a given address",
                "parameters": {
                    "type": "object",
                    "properties": {
                        "memory_file": {"type": "string", "description": "Path to memory dump"},
                        "address": {"type": "integer", "description": "Physical address to read"},
                        "size": {"type": "integer", "description": "Bytes to read"}
                    },
                    "required": ["memory_file", "address", "size"]
                }
            }
        },
        # YARA Scanning
        {
            "type": "function",
            "function": {
                "name": "yara_scan",
                "description": "Scan memory with custom YARA rules. Scopes: process_vads, process_range, full_dump",
                "parameters": {
                    "type": "object",
                    "properties": {
                        "memory_file": {"type": "string", "description": "Path to memory dump"},
                        "rules_text": {"type": "string", "description": "YARA rules as string"},
                        "rules_path": {"type": "string", "description": "Path to YARA rules file"},
                        "scope": {"type": "string", "description": "Scan scope: process_vads, process_range, full_dump"},
                        "pid": {"type": "integer", "description": "Process ID (for process scopes)"},
                        "address": {"type": "integer", "description": "Start address (for process_range)"},
                        "size": {"type": "integer", "description": "Size to scan (for process_range)"},
                        "max_matches": {"type": "integer", "description": "Max matches to return (default 100)"}
                    },
                    "required": ["memory_file"]
                }
            }
        },
        # Registry Tools
        {
            "type": "function",
            "function": {
                "name": "list_registry_hives",
                "description": "List registry hives found in memory",
                "parameters": {
                    "type": "object",
                    "properties": {
                        "memory_file": {"type": "string", "description": "Path to memory dump"}
                    },
                    "required": ["memory_file"]
                }
            }
        },
        {
            "type": "function",
            "function": {
                "name": "registry_printkey",
                "description": "Print registry key values from memory",
                "parameters": {
                    "type": "object",
                    "properties": {
                        "memory_file": {"type": "string", "description": "Path to memory dump"},
                        "key_path": {"type": "string", "description": "Registry key path"},
                        "hive_offset": {"type": "integer", "description": "Optional hive offset from hivelist"}
                    },
                    "required": ["memory_file", "key_path"]
                }
            }
        },
        # Enriched Handles
        {
            "type": "function",
            "function": {
                "name": "handles_enriched",
                "description": "Get handles with filtering, summaries, and process cross-references",
                "parameters": {
                    "type": "object",
                    "properties": {
                        "memory_file": {"type": "string", "description": "Path to memory dump"},
                        "pid": {"type": "integer", "description": "Filter by PID"},
                        "object_type": {"type": "string", "description": "Filter by type (File, Key, Process, Thread, etc.)"},
                        "name_filter": {"type": "string", "description": "Filter by name substring"}
                    },
                    "required": ["memory_file"]
                }
            }
        },
        # Tagging Tools
        {
            "type": "function",
            "function": {
                "name": "add_tag",
                "description": "Add a tag to track findings across tool calls (persists for session)",
                "parameters": {
                    "type": "object",
                    "properties": {
                        "tag_id": {"type": "string", "description": "Unique tag identifier"},
                        "tag_type": {"type": "string", "description": "Tag type (ioc, pid, address, finding, etc.)"},
                        "value": {"type": "string", "description": "Tag value"},
                        "notes": {"type": "string", "description": "Optional notes"},
                        "metadata": {"type": "object", "description": "Optional additional metadata"}
                    },
                    "required": ["tag_id", "tag_type", "value"]
                }
            }
        },
        {
            "type": "function",
            "function": {
                "name": "list_tags",
                "description": "List all tags in the session",
                "parameters": {
                    "type": "object",
                    "properties": {
                        "tag_type": {"type": "string", "description": "Filter by tag type"}
                    },
                    "required": []
                }
            }
        },
        {
            "type": "function",
            "function": {
                "name": "clear_tags",
                "description": "Clear all tags from the session",
                "parameters": {
                    "type": "object",
                    "properties": {}
                }
            }
        },
        # Timeline Tools
        {
            "type": "function",
            "function": {
                "name": "add_timeline_event",
                "description": "Add an event to the investigation timeline (persists for session)",
                "parameters": {
                    "type": "object",
                    "properties": {
                        "timestamp": {"type": "string", "description": "Event timestamp (ISO format or any string)"},
                        "event_type": {"type": "string", "description": "Event type (process_start, network, file_access, etc.)"},
                        "description": {"type": "string", "description": "Event description"},
                        "source": {"type": "string", "description": "Source of the event (tool name)"},
                        "pid": {"type": "integer", "description": "Associated process ID"},
                        "metadata": {"type": "object", "description": "Additional metadata"}
                    },
                    "required": ["timestamp", "event_type", "description"]
                }
            }
        },
        {
            "type": "function",
            "function": {
                "name": "list_timeline",
                "description": "List timeline events",
                "parameters": {
                    "type": "object",
                    "properties": {
                        "event_type": {"type": "string", "description": "Filter by event type"},
                        "pid": {"type": "integer", "description": "Filter by PID"}
                    },
                    "required": []
                }
            }
        },
        {
            "type": "function",
            "function": {
                "name": "clear_timeline",
                "description": "Clear all timeline events",
                "parameters": {
                    "type": "object",
                    "properties": {}
                }
            }
        }
    ]


# =============================================================================
# MCP SERVER ENTRY POINT
# =============================================================================

async def main():
    """Main entry point for MCP server"""
    try:
        from mcp.server import Server
        from mcp.server.stdio import stdio_server
        from mcp import types
    except ImportError:
        print("Error: mcp package not found. Install via: pip install mcp", file=sys.stderr)
        sys.exit(1)
    
    # Setup logging to stderr
    logging.basicConfig(
        level=logging.ERROR,
        format='%(levelname)s: %(message)s',
        stream=sys.stderr
    )
    
    server = Server("memory-forensics-mcp")
    
    mcp_instance = None
    
    def get_mcp_instance():
        """Lazy initialization of MCP instance"""
        nonlocal mcp_instance
        if mcp_instance is None:
            try:
                mcp_instance = MemoryForensicsMCP()
            except Exception as e:
                print(f"Error initializing MCP: {e}", file=sys.stderr)
                traceback.print_exc(file=sys.stderr)
                raise
        return mcp_instance
    
    @server.list_tools()
    async def handle_list_tools():
        try:
            tools = []
            for tool_def in get_tools():
                tools.append(
                    types.Tool(
                        name=tool_def["function"]["name"],
                        description=tool_def["function"]["description"],
                        inputSchema=tool_def["function"]["parameters"]
                    )
                )
            return tools
        except Exception as e:
            print(f"Error in list_tools: {e}", file=sys.stderr)
            traceback.print_exc(file=sys.stderr)
            return []
    
    @server.call_tool()
    async def handle_call_tool(name: str, arguments: dict):
        try:
            instance = get_mcp_instance()
            
            if not hasattr(instance, name):
                return [types.TextContent(
                    type="text",
                    text=json.dumps({"error": f"Tool '{name}' not found"}, indent=2)
                )]
            
            method = getattr(instance, name)
            result = method(**arguments)
            
            if isinstance(result, dict):
                return [types.TextContent(type="text", text=json.dumps(result, indent=2, default=str))]
            else:
                return [types.TextContent(type="text", text=str(result))]
        except Exception as e:
            print(f"Error in call_tool({name}): {e}", file=sys.stderr)
            traceback.print_exc(file=sys.stderr)
            return [types.TextContent(
                type="text",
                text=json.dumps({"error": str(e)}, indent=2)
            )]
    
    async with stdio_server() as (read_stream, write_stream):
        await server.run(
            read_stream,
            write_stream,
            server.create_initialization_options()
        )


if __name__ == "__main__":
    import asyncio
    asyncio.run(main())
