# portex

A Zig library for parsing and analyzing Portable Executable (PE/COFF) binary files. Supports both PE32 (32-bit) and PE32+ (64-bit) formats with comprehensive coverage of all major PE structures.

## Overview

portex implements a multi-phase parsing pipeline that processes PE binaries through 14 sequential stages, building derived lookup caches and performing cross-table validation and resolution. The library is designed for binary analysis workflows including malware triage, packer detection, and executable inspection.

## Supported Structures

- **DOS Header** — MZ stub parsing with Rich header detection
- **COFF Header** — Machine type, section count, symbol table location
- **Optional Header** — PE32/PE32+ with all data directory entries
- **Section Table** — Headers, data loading, long name resolution via COFF string table
- **Import Table** — Import descriptors, ILT/IAT thunks, hint/name resolution
- **Export Table** — Export address table, name pointers, ordinal table, forwarder detection
- **Relocation Table** — Base relocation blocks with per-entry target resolution
- **Debug Directory** — CodeView/PDB path extraction, POGO, reproducible build markers
- **Resource Tree** — Recursive directory parsing, flat indexing, version info extraction
- **Symbol Table** — COFF symbols with string table name resolution and auxiliary records
- **Exception Table** — x64 RUNTIME_FUNCTION entries with UNWIND_INFO parsing
- **Delay Import Table** — Delay-load descriptors with RVA/VA addressing modes
- **String Table** — COFF string table indexing and lookup

## Architecture

The parsing pipeline runs in order:

1. DOS header → 2. PE signature + COFF → 3. Optional header → 4. Section table → 5. String table → 6. Symbol table → 7. Imports → 8. Exports → 9. Relocations → 10. Debug → 11. Resources → 12. Cache construction → 13. Cross-table validation → 14. Cross-reference resolution

Phase 12 builds derived caches that store pointers into parsed data buffers for efficient lookup. Phase 13 validates consistency across tables and may reload section data or rebuild the string table when inconsistencies are detected. Phase 14 reads the cached pointers to perform cross-reference analysis.

## Analysis Features

- Shannon entropy calculation per section
- Data block classification (code, compressed, padding, text)
- Section overlap detection in both VA and file offset space
- Code cave detection in executable sections
- Import API categorization and suspicious API detection
- Packer signature detection via section name heuristics
- PE anomaly scoring for malware triage
- Import hash computation for sample clustering
- Rich header parsing and build tool identification
- Overlay data detection

## Building

```sh
zig build
```

## Fuzzing

Three fuzzer harnesses are included for ClusterFuzzLite integration:

- `parse_fuzz` — Full parse pipeline exercising all phases
- `import_fuzz` — Import, debug, and symbol resolution paths
- `resource_fuzz` — Resource tree, relocation, and section analysis paths

## License

MIT
