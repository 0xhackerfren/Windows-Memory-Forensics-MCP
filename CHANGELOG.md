# Changelog

**Author:** Jacob Krell

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added
- Nothing yet

### Changed
- Nothing yet

### Fixed
- Nothing yet

## [1.1.0] - 2026-01-28

### Added
- `get_process_environment`: Extract environment variables from process PEB
  - Supports 32-bit and 64-bit processes
  - Filter by prefix (e.g., `B_` for staged payloads)
  - Critical for PASTALOADER/GrimResource malware detection

- `read_virtual_memory`: Read arbitrary virtual memory from a process
  - Uses MemProcFS for reliable VA->PA translation
  - Returns base64-encoded data with MD5 hash
  - Includes hex preview for quick inspection

- `find_hidden_modules`: Find modules not in PEB loader lists
  - Cross-references ldrmodules with VAD mappings
  - Detects DirtyCLR, process hollowing, and injection
  - Checks for PE headers at VAD bases

- `dump_vad_raw`: Dump raw VAD bytes without PE reconstruction
  - Preserves exact bytes for hash matching
  - Optional trailing zero trimming
  - Returns both raw and trimmed MD5 hashes

- `reconstruct_staged_payload`: Reconstruct payload from staged env vars
  - Supports multiple decode algorithms:
    - `raw_concat`: Simple concatenation
    - `base64_concat`: Concat then base64 decode
    - `pastaloader`: PASTALOADER-specific decoding

### Changed
- Version bumped to 1.1.0
- Updated documentation with new tool examples

## [1.0.0] - 2026-01-15

### Added
- Initial release with core memory forensics tools
- Volatility 3 backend support
- MemProcFS backend support
- CLR analysis via cdb.exe and dotnet-dump
- Basic process analysis: list_processes, get_cmdline, list_dlls
- Memory extraction: vadinfo, dump_vad
- Malware detection: malfind, ldrmodules
- Network forensics: netscan
- File analysis: filescan, handles
- CLR analysis: memprocfs_get_minidump, list_clr_modules
