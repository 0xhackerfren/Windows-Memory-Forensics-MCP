"""
Windows Memory Forensics MCP

A Model Context Protocol (MCP) server for Windows memory forensics.
"""

from .memory_forensics_mcp import MemoryForensicsMCP, MCP_INFO

__version__ = MCP_INFO["version"]
__all__ = ["MemoryForensicsMCP", "MCP_INFO", "__version__", "run"]


def run():
    """Synchronous entry point for the MCP server (used by console_scripts)."""
    import asyncio
    from .memory_forensics_mcp import main
    asyncio.run(main())
