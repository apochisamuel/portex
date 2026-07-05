// validate.zig — Cross-Table Validation (Phase 13)
//
// Performs consistency checks across parsed PE structures. When
// inconsistencies are detected, corrective actions may include
// reloading section data, rebuilding the string table, pruning
// invalid resource entries, or removing problematic debug entries.
//
// These corrective actions can invalidate pointers that were
// previously cached by the cache module, since the underlying
// data buffers may be freed and reallocated.

const std = @import("std");
const root = @import("root.zig");
const rd = @import("reader.zig");
const sec_mod = @import("sections.zig");
const str_mod = @import("strings.zig");
const cksum = @import("checksum.zig");
const PeCtx = root.PeCtx;
const ParseError = root.ParseError;

const IMPORT_DUP_THRESHOLD: u32 = 3;
const DEBUG_TIMESTAMP_DRIFT: u64 = 86400 * 365 * 5;
const SYMBOL_MISMATCH_THRESHOLD: u64 = 100;
const RESOURCE_BOUNDS_THRESHOLD: u32 = 8;
const EXPORT_OVERLAP_THRESHOLD: u32 = 64;

/// Validate section alignment. Reloading frees the old data buffer —
/// cached pointers into that buffer become stale.
fn validateSectionAlignment(ctx: *PeCtx) void {
    const fa = ctx.optional_header.file_alignment;
    if (fa == 0) return;
    if (ctx.section_entries == null) return;

    var i: u32 = 0;
    while (i < ctx.section_count) : (i += 1) {
        const sec = &ctx.section_entries.?[i];
        if (sec.raw_data_offset == 0 or sec.raw_data_size == 0) continue;

        if ((sec.raw_data_offset % fa) != 0) {
            ctx.addIssue(2, i, "section raw data not aligned, reloading");
            const aligned = (sec.raw_data_offset + fa - 1) & ~(fa - 1);
            if (aligned < ctx.size) {
                sec.raw_data_offset = aligned;
            }
            sec_mod.reloadSectionData(ctx, i) catch {};
        }

        if (sec.raw_data_size > sec.virtual_size and sec.virtual_size > 0) {
            const excess = sec.raw_data_size - sec.virtual_size;
            if (excess > fa) {
                ctx.addIssue(1, i, "raw size exceeds virtual size");
            }
        }
    }
}

/// Validate section virtual address ordering. Sections should be
/// monotonically increasing in VA space.
fn validateSectionOrdering(ctx: *PeCtx) void {
    if (ctx.section_entries == null or ctx.section_count < 2) return;
    const entries = ctx.section_entries.?;

    var prev_va: u32 = 0;
    var i: u32 = 0;
    while (i < ctx.section_count) : (i += 1) {
        if (entries[i].virtual_address < prev_va) {
            ctx.addIssue(2, i, "section VA is not monotonically increasing");
        }
        prev_va = entries[i].virtual_address;
    }
}

/// Validate section characteristics for suspicious combinations.
/// Writable + executable sections are common in packed/malicious PE files.
fn validateSectionCharacteristics(ctx: *PeCtx) void {
    if (ctx.section_entries == null) return;
    const entries = ctx.section_entries.?;

    var rwx_count: u32 = 0;
    var i: u32 = 0;
    while (i < ctx.section_count) : (i += 1) {
        const chars = entries[i].characteristics;
        const is_exec = (chars & root.SCN_MEM_EXECUTE) != 0;
        const is_write = (chars & root.SCN_MEM_WRITE) != 0;
        const is_read = (chars & root.SCN_MEM_READ) != 0;

        if (is_exec and is_write) {
            rwx_count += 1;
            ctx.addIssue(1, i, "section is both writable and executable");
        }

        // Executable but not readable is unusual
        if (is_exec and !is_read) {
            ctx.addIssue(1, i, "section is executable but not readable");
        }

        // Check for sections with no memory permissions
        if (!is_exec and !is_write and !is_read) {
            if ((chars & root.SCN_MEM_DISCARDABLE) == 0) {
                ctx.addIssue(1, i, "section has no memory permissions");
            }
        }
    }

    if (rwx_count > 1) {
        ctx.addIssue(2, 0, "multiple RWX sections detected");
    }
}

/// Validate section data against known patterns. Empty code sections
/// or data sections with high entropy may indicate packing.
fn validateSectionContent(ctx: *PeCtx) void {
    if (ctx.section_entries == null) return;
    const entries = ctx.section_entries.?;

    var i: u32 = 0;
    while (i < ctx.section_count) : (i += 1) {
        const sec = &entries[i];
        if (sec.data == null or sec.data_size == 0) continue;

        // Check for sections that claim to be code but are all zeros
        if ((sec.characteristics & root.SCN_CNT_CODE) != 0) {
            var zero_count: u32 = 0;
            const check_len = @min(sec.data_size, 256);
            var j: usize = 0;
            while (j < check_len) : (j += 1) {
                if (sec.data.?[j] == 0) zero_count += 1;
            }
            if (check_len > 0 and zero_count == check_len) {
                ctx.addIssue(1, i, "code section appears to be all zeros");
            }
        }

        // Check for single-byte fill patterns (often packing artifacts)
        if (sec.data_size >= 64) {
            const first_byte = sec.data.?[0];
            var same_count: u32 = 0;
            var j: usize = 0;
            const check_len = @min(sec.data_size, 64);
            while (j < check_len) : (j += 1) {
                if (sec.data.?[j] == first_byte) same_count += 1;
            }
            if (same_count == check_len and first_byte != 0) {
                ctx.addIssue(1, i, "section filled with single byte value");
            }
        }
    }
}

/// Validate import table consistency.
fn validateImportConsistency(ctx: *PeCtx) void {
    if (ctx.import_descriptors == null or ctx.import_count < 2) return;
    const descs = ctx.import_descriptors.?;

    // Check for duplicate DLLs
    var dup_count: u32 = 0;
    var i: u32 = 0;
    while (i < ctx.import_count) : (i += 1) {
        if (descs[i].dll_name == null) continue;
        var j: u32 = i + 1;
        while (j < ctx.import_count) : (j += 1) {
            if (descs[j].dll_name == null) continue;
            const a = std.mem.span(descs[i].dll_name.?);
            const b = std.mem.span(descs[j].dll_name.?);
            if (std.mem.eql(u8, a, b)) dup_count += 1;
        }
    }

    if (dup_count >= IMPORT_DUP_THRESHOLD) {
        ctx.addIssue(2, 0, "import table has duplicate DLLs, reloading section");
        const imp_dir = &ctx.optional_header.data_dirs[root.DIR_IMPORT];
        if (imp_dir.rva != 0) {
            if (rd.findSectionByRva(ctx, imp_dir.rva)) |sec_idx| {
                sec_mod.reloadSectionData(ctx, sec_idx) catch {};
            }
        }
    }

    // Validate thunk names are non-null for by-name imports
    i = 0;
    while (i < ctx.import_count) : (i += 1) {
        const desc = &descs[i];
        if (desc.thunks == null) continue;
        var t: u32 = 0;
        while (t < desc.num_thunks) : (t += 1) {
            const thunk = &desc.thunks.?[t];
            if (!thunk.is_ordinal and thunk.name == null) {
                ctx.addIssue(1, 0, "import thunk name resolution failed");
            }
        }
    }

    // Check for suspiciously large thunk counts
    i = 0;
    while (i < ctx.import_count) : (i += 1) {
        if (descs[i].num_thunks > 1000) {
            ctx.addIssue(1, 0, "import descriptor has unusually many thunks");
        }
    }
}

/// Validate IAT vs ILT consistency. If both are present, they should
/// have matching thunk counts.
fn validateIatConsistency(ctx: *PeCtx) void {
    if (ctx.import_descriptors == null) return;
    const descs = ctx.import_descriptors.?;

    var i: u32 = 0;
    while (i < ctx.import_count) : (i += 1) {
        const desc = &descs[i];
        if (desc.ilt_rva != 0 and desc.iat_rva != 0) {
            // Both present — verify they're in valid sections
            const ilt_sec = rd.findSectionByRva(ctx, desc.ilt_rva);
            const iat_sec = rd.findSectionByRva(ctx, desc.iat_rva);
            if (ilt_sec == null) {
                ctx.addIssue(1, 0, "import ILT RVA outside any section");
            }
            if (iat_sec == null) {
                ctx.addIssue(1, 0, "import IAT RVA outside any section");
            }
        }
    }
}

/// Validate export ranges for overlaps with other directories.
fn validateExportRanges(ctx: *PeCtx) void {
    if (ctx.export_entries == null or ctx.export_count == 0) return;
    const entries = ctx.export_entries.?;
    const exp_dir = &ctx.optional_header.data_dirs[root.DIR_EXPORT];
    if (exp_dir.rva == 0) return;

    const exp_start = exp_dir.rva;
    const exp_end = exp_start + exp_dir.size;

    // Check overlap with relocation directory
    const reloc_dir = &ctx.optional_header.data_dirs[root.DIR_BASERELOC];
    if (reloc_dir.rva != 0 and reloc_dir.size != 0) {
        const reloc_start = reloc_dir.rva;
        const reloc_end = reloc_start + reloc_dir.size;

        if (exp_start < reloc_end and reloc_start < exp_end) {
            ctx.addIssue(2, 0, "export directory overlaps relocation directory");

            var cleanup: u32 = 0;
            var i: u32 = 0;
            while (i < ctx.export_count) : (i += 1) {
                const entry = &entries[i];
                if (entry.function_rva >= reloc_start and
                    entry.function_rva < reloc_end)
                {
                    if (entry.forwarder) |fwd| {
                        ctx.allocator.free(std.mem.span(fwd));
                        entry.forwarder = null;
                    }
                    entry.is_forwarder = false;
                    entry.function_rva = 0;
                    cleanup += 1;
                }
            }

            if (cleanup > 0) {
                ctx.addIssue(2, 0, "cleaned export entries in overlap region");
            }
        }
    }

    // Check overlap with import directory
    const imp_dir = &ctx.optional_header.data_dirs[root.DIR_IMPORT];
    if (imp_dir.rva != 0 and imp_dir.size != 0) {
        const imp_start = imp_dir.rva;
        const imp_end = imp_start + imp_dir.size;
        if (exp_start < imp_end and imp_start < exp_end) {
            ctx.addIssue(2, 0, "export directory overlaps import directory");
        }
    }

    // Validate forwarder string contents
    var i: u32 = 0;
    while (i < ctx.export_count) : (i += 1) {
        const entry = &entries[i];
        if (!entry.is_forwarder) continue;
        if (entry.forwarder == null) continue;

        const fwd = std.mem.span(entry.forwarder.?);
        var has_dot = false;
        for (fwd) |ch| {
            if (ch == '.') { has_dot = true; break; }
        }

        if (!has_dot) {
            ctx.addIssue(2, 0, "export has invalid forwarder, removing");
            ctx.allocator.free(fwd);
            entry.forwarder = null;
            entry.is_forwarder = false;
        }
    }

    // Check for duplicate export names
    i = 0;
    while (i < ctx.export_count) : (i += 1) {
        if (!entries[i].has_name or entries[i].name == null) continue;
        const name_a = std.mem.span(entries[i].name.?);
        var j = i + 1;
        while (j < ctx.export_count) : (j += 1) {
            if (!entries[j].has_name or entries[j].name == null) continue;
            const name_b = std.mem.span(entries[j].name.?);
            if (std.mem.eql(u8, name_a, name_b)) {
                ctx.addIssue(1, 0, "duplicate export name detected");
                break;
            }
        }
    }
}

/// Validate export ordinal ranges. Ordinals should form a contiguous
/// range from ordinal_base to ordinal_base + num_functions - 1.
fn validateExportOrdinals(ctx: *PeCtx) void {
    if (ctx.export_entries == null or ctx.export_count == 0) return;
    const entries = ctx.export_entries.?;

    var gap_count: u32 = 0;
    var i: u32 = 0;
    while (i < ctx.export_count) : (i += 1) {
        if (entries[i].function_rva == 0) gap_count += 1;
    }

    if (gap_count > 0 and gap_count > ctx.export_count / 2) {
        ctx.addIssue(1, 0, "more than half of export ordinals are empty");
    }
}

/// Validate relocation targets against section boundaries.
fn validateRelocTargets(ctx: *PeCtx) void {
    if (ctx.reloc_blocks == null or ctx.reloc_count == 0) return;
    const blocks = ctx.reloc_blocks.?;

    var invalid_count: u32 = 0;
    var bi: u32 = 0;
    while (bi < ctx.reloc_count) : (bi += 1) {
        if (blocks[bi].entries == null) continue;
        var ei: u32 = 0;
        while (ei < blocks[bi].count) : (ei += 1) {
            const rel = &blocks[bi].entries.?[ei];
            if (!rel.resolved) continue;

            if (rel.rel_type == root.REL_BASED_ABSOLUTE) continue;

            const sec_idx = rd.findSectionByRva(ctx, rel.target_rva);
            if (sec_idx == null) {
                rel.resolved = false;
                invalid_count += 1;
                continue;
            }

            if (ctx.section_entries) |entries| {
                const sec = &entries[sec_idx.?];
                if (sec.data == null) { rel.resolved = false; invalid_count += 1; continue; }
                const delta = rel.target_rva - sec.virtual_address;
                if (delta >= sec.data_size) { rel.resolved = false; invalid_count += 1; }
            }
        }
    }

    if (invalid_count > 0) {
        ctx.addIssue(1, 0, "relocated targets outside section bounds");
    }
}

/// Validate relocation block consistency. Blocks should cover
/// distinct page ranges without duplicates.
fn validateRelocBlockConsistency(ctx: *PeCtx) void {
    if (ctx.reloc_blocks == null or ctx.reloc_count < 2) return;
    const blocks = ctx.reloc_blocks.?;

    var dup_pages: u32 = 0;
    var i: u32 = 0;
    while (i < ctx.reloc_count) : (i += 1) {
        var j = i + 1;
        while (j < ctx.reloc_count) : (j += 1) {
            if (blocks[i].page_rva == blocks[j].page_rva) {
                dup_pages += 1;
            }
        }
    }

    if (dup_pages > 0) {
        ctx.addIssue(1, 0, "duplicate relocation page blocks detected");
    }
}

/// Validate debug entries for timestamp consistency.
fn validateDebugEntries(ctx: *PeCtx) void {
    if (ctx.debug_entries == null or ctx.debug_count == 0) return;
    if (ctx.coff_header.timestamp == 0) return;
    const entries = ctx.debug_entries.?;

    var i: u32 = 0;
    while (i < ctx.debug_count) : (i += 1) {
        const entry = &entries[i];
        if (entry.timestamp == 0) continue;

        var drift: i64 = @as(i64, entry.timestamp) -
            @as(i64, ctx.coff_header.timestamp);
        if (drift < 0) drift = -drift;

        if (@as(u64, @intCast(drift)) > DEBUG_TIMESTAMP_DRIFT) {
            ctx.addIssue(2, 0, "debug entry timestamp drift too large, removing");

            if (entry.codeview) |cv| {
                if (cv.pdb_path) |p| {
                    ctx.allocator.free(std.mem.span(p));
                    cv.pdb_path = null;
                }
                ctx.allocator.destroy(cv);
                entry.codeview = null;
            }
            entry.debug_type = 0;
            entry.data_size = 0;
        }
    }
}

/// Validate debug data offsets point to valid file regions.
fn validateDebugDataOffsets(ctx: *PeCtx) void {
    if (ctx.debug_entries == null or ctx.debug_count == 0) return;
    const entries = ctx.debug_entries.?;

    var i: u32 = 0;
    while (i < ctx.debug_count) : (i += 1) {
        const entry = &entries[i];
        if (entry.raw_data_offset == 0 or entry.data_size == 0) continue;

        if (@as(u64, entry.raw_data_offset) + @as(u64, entry.data_size) > ctx.size) {
            ctx.addIssue(1, 0, "debug data extends beyond file");
        }
    }
}

/// Validate symbol table against COFF header counts.
fn validateSymbolTable(ctx: *PeCtx) void {
    const header_count: i64 = @intCast(ctx.coff_header.num_symbols);
    const parsed_count: i64 = @intCast(ctx.symbol_count);

    if (header_count == 0 and parsed_count == 0) return;

    var diff = header_count - parsed_count;
    if (diff < 0) diff = -diff;

    if (@as(u64, @intCast(diff)) > SYMBOL_MISMATCH_THRESHOLD) {
        ctx.addIssue(2, 0, "symbol count mismatch, rebuilding string table");
        str_mod.rebuild(ctx) catch {};
    }

    // Validate section number references
    if (ctx.symbol_entries) |entries| {
        var i: u32 = 0;
        while (i < ctx.symbol_count) : (i += 1) {
            const sym = &entries[i];
            if (sym.section_number > 0 and
                @as(u32, @intCast(sym.section_number - 1)) >= ctx.section_count)
            {
                ctx.addIssue(1, 0, "symbol has invalid section number");
            }
        }
    }
}

/// Validate symbol string table references. Long names should point
/// to valid offsets within the string table.
fn validateSymbolNames(ctx: *PeCtx) void {
    if (ctx.symbol_entries == null or ctx.string_table.size == 0) return;
    const entries = ctx.symbol_entries.?;

    var i: u32 = 0;
    while (i < ctx.symbol_count) : (i += 1) {
        const sym = &entries[i];
        if (sym.short_name[0] == 0 and sym.short_name[1] == 0 and
            sym.short_name[2] == 0 and sym.short_name[3] == 0)
        {
            const offset = @as(u32, sym.short_name[4]) |
                (@as(u32, sym.short_name[5]) << 8) |
                (@as(u32, sym.short_name[6]) << 16) |
                (@as(u32, sym.short_name[7]) << 24);
            if (offset >= ctx.string_table.size) {
                ctx.addIssue(1, 0, "symbol references string table offset out of range");
            }
        }
    }
}

/// Validate resource tree entries against section boundaries.
fn validateResourceBounds(ctx: *PeCtx) void {
    if (ctx.resource_flat == null or ctx.resource_flat_count == 0) return;
    const rsrc_dir = &ctx.optional_header.data_dirs[root.DIR_RESOURCE];
    if (rsrc_dir.rva == 0) return;

    var oob_count: u32 = 0;
    var i: u32 = 0;
    while (i < ctx.resource_flat_count) : (i += 1) {
        const node_ptr = ctx.resource_flat.?[i] orelse continue;
        if (node_ptr.data_rva == 0 or node_ptr.data_size == 0) continue;

        const sec_idx = rd.findSectionByRva(ctx, node_ptr.data_rva);
        if (sec_idx == null) {
            oob_count += 1;
            ctx.addIssue(2, 0, "resource data RVA outside any section, pruning");

            if (node_ptr.name) |n| {
                ctx.allocator.free(std.mem.span(n));
                node_ptr.name = null;
            }
            node_ptr.data_rva = 0;
            node_ptr.data_size = 0;
            node_ptr.data_ptr = null;
        }
    }
}

/// Validate resource data sizes for overflow or impossibly large values.
fn validateResourceSizes(ctx: *PeCtx) void {
    if (ctx.resource_flat == null or ctx.resource_flat_count == 0) return;

    var i: u32 = 0;
    while (i < ctx.resource_flat_count) : (i += 1) {
        const node_ptr = ctx.resource_flat.?[i] orelse continue;
        if (node_ptr.data_size > 16 * 1024 * 1024) {
            ctx.addIssue(1, 0, "resource data size exceeds 16MB");
        }
    }
}

/// Validate string table references from sections.
fn validateStringTableRefs(ctx: *PeCtx) void {
    if (ctx.string_table.size == 0) return;

    // Ensure null termination
    if (ctx.string_table.data) |data| {
        if (ctx.string_table.size > 4 and data[ctx.string_table.size - 1] != 0) {
            ctx.addIssue(1, 0, "string table not null-terminated");
        }
    }

    // Validate section name references
    if (ctx.section_entries) |entries| {
        var i: u32 = 0;
        while (i < ctx.section_count) : (i += 1) {
            const sec = &entries[i];
            if (sec.short_name[0] == '/') {
                var str_offset: u32 = 0;
                var valid = true;
                var j: usize = 1;
                while (j < 8 and sec.short_name[j] != 0) : (j += 1) {
                    const ch = sec.short_name[j];
                    if (ch < '0' or ch > '9') { valid = false; break; }
                    str_offset = str_offset * 10 + @as(u32, ch - '0');
                }
                if (valid and str_offset >= ctx.string_table.size) {
                    ctx.addIssue(2, i, "section string table offset out of range");
                }
            }
        }
    }
}

/// Validate PE checksum matches optional header value.
fn validatePeChecksum(ctx: *PeCtx) void {
    if (ctx.optional_header.pe_checksum == 0) return;

    if (!cksum.verify(ctx)) {
        ctx.addIssue(1, 0, "PE checksum mismatch");
    }
}

/// Validate entry point RVA maps to an executable section.
fn validateEntryPoint(ctx: *PeCtx) void {
    if (ctx.optional_header.entry_point_rva == 0) return;

    const ep_rva = ctx.optional_header.entry_point_rva;
    if (rd.findSectionByRva(ctx, ep_rva)) |sec_idx| {
        if (ctx.section_entries) |entries| {
            const sec = &entries[sec_idx];
            if ((sec.characteristics & root.SCN_MEM_EXECUTE) == 0) {
                ctx.addIssue(2, sec_idx, "entry point in non-executable section");
            }
        }
    } else {
        ctx.addIssue(2, 0, "entry point RVA does not map to any section");
    }
}

/// Validate data directory RVAs point to valid sections.
fn validateDataDirectories(ctx: *PeCtx) void {
    var i: u32 = 0;
    while (i < root.NUM_DATA_DIRS) : (i += 1) {
        const dd = &ctx.optional_header.data_dirs[i];
        if (dd.rva == 0 or dd.size == 0) continue;

        if (rd.findSectionByRva(ctx, dd.rva) == null) {
            // Some data directories (security) use file offsets, not RVAs
            if (i != root.DIR_SECURITY) {
                ctx.addIssue(1, 0, "data directory RVA outside any section");
            }
        }

        // Check for zero-size data directories with non-zero RVA
        if (dd.size == 0 and dd.rva != 0) {
            ctx.addIssue(1, 0, "data directory has RVA but zero size");
        }
    }
}

/// Validate image size consistency.
fn validateImageSize(ctx: *PeCtx) void {
    if (ctx.optional_header.size_of_image == 0) return;
    if (ctx.section_entries == null or ctx.section_count == 0) return;

    // The last section's VA + size should not exceed size_of_image
    const last = &ctx.section_entries.?[ctx.section_count - 1];
    const last_end = last.virtual_address + @max(last.virtual_size, last.raw_data_size);
    if (last_end > ctx.optional_header.size_of_image) {
        ctx.addIssue(1, ctx.section_count - 1, "last section extends beyond size_of_image");
    }
}

pub fn run(ctx: *PeCtx) ParseError!void {
    // Extended validations
    validateTlsDirectory(ctx);
    validateLoadConfig(ctx);
    validateBoundImports(ctx);
    validateIatDirectory(ctx);
    validateClrDirectory(ctx);
    validateDelayImports(ctx);
    validateSectionNames(ctx);

    validateSectionAlignment(ctx);
    validateSectionOrdering(ctx);
    validateSectionCharacteristics(ctx);
    validateSectionContent(ctx);
    validateImportConsistency(ctx);
    validateIatConsistency(ctx);
    validateExportRanges(ctx);
    validateExportOrdinals(ctx);
    validateRelocTargets(ctx);
    validateRelocBlockConsistency(ctx);
    validateDebugEntries(ctx);
    validateDebugDataOffsets(ctx);
    validateSymbolTable(ctx);
    validateSymbolNames(ctx);
    validateResourceBounds(ctx);
    validateResourceSizes(ctx);
    validateStringTableRefs(ctx);
    validatePeChecksum(ctx);
    validateEntryPoint(ctx);
    validateDataDirectories(ctx);
    validateImageSize(ctx);
}

// ── Extended validation checks ─────────────────────────────────

/// Validate TLS directory for callback entries
fn validateTlsDirectory(ctx: *PeCtx) void {
    const tls_dir = &ctx.optional_header.data_dirs[root.DIR_TLS];
    if (tls_dir.rva == 0 or tls_dir.size == 0) return;

    const offset = ctx.rvaToOffset(tls_dir.rva) orelse {
        ctx.addIssue(1, 0, "TLS directory RVA does not resolve");
        return;
    };

    const min_size: u32 = if (ctx.optional_header.is_pe32plus) 40 else 24;
    if (!ctx.checkOffset(@intCast(offset), min_size)) {
        ctx.addIssue(1, 0, "TLS directory truncated");
        return;
    }

    // Read callback table address
    var callback_addr: u64 = 0;
    if (ctx.optional_header.is_pe32plus) {
        callback_addr = rd.readU64At(ctx.data + offset + 24);
    } else {
        callback_addr = rd.readU32At(ctx.data + offset + 12);
    }

    if (callback_addr != 0) {
        ctx.addIssue(1, 0, "TLS callbacks present (potential anti-analysis)");

        // Convert VA to RVA
        if (callback_addr >= ctx.optional_header.image_base) {
            const cb_rva: u32 = @intCast(callback_addr - ctx.optional_header.image_base);
            if (rd.findSectionByRva(ctx, cb_rva) == null) {
                ctx.addIssue(2, 0, "TLS callback table outside any section");
            }
        }
    }
}

/// Validate load configuration directory
fn validateLoadConfig(ctx: *PeCtx) void {
    const lc_dir = &ctx.optional_header.data_dirs[root.DIR_LOAD_CONFIG];
    if (lc_dir.rva == 0 or lc_dir.size == 0) return;

    const offset = ctx.rvaToOffset(lc_dir.rva) orelse {
        ctx.addIssue(1, 0, "load config directory RVA does not resolve");
        return;
    };

    if (!ctx.checkOffset(@intCast(offset), 4)) {
        ctx.addIssue(1, 0, "load config directory truncated");
        return;
    }

    const config_size = rd.readU32At(ctx.data + offset);
    if (config_size > lc_dir.size * 2) {
        ctx.addIssue(1, 0, "load config size exceeds directory size");
    }

    // Check for SEH handler table
    if (config_size >= 72 and ctx.checkOffset(@intCast(offset), 72)) {
        var seh_table: u64 = 0;
        var seh_count: u64 = 0;
        if (ctx.optional_header.is_pe32plus) {
            seh_table = rd.readU64At(ctx.data + offset + 48);
            seh_count = rd.readU64At(ctx.data + offset + 56);
        } else {
            seh_table = rd.readU32At(ctx.data + offset + 40);
            seh_count = rd.readU32At(ctx.data + offset + 44);
        }

        if (seh_table != 0 and seh_count > 10000) {
            ctx.addIssue(1, 0, "SEH handler count unusually large");
        }
    }

    // Check for Guard CF table
    if (config_size >= 96 and ctx.checkOffset(@intCast(offset), 96)) {
        var cf_table: u64 = 0;
        if (ctx.optional_header.is_pe32plus) {
            cf_table = rd.readU64At(ctx.data + offset + 80);
        } else {
            cf_table = rd.readU32At(ctx.data + offset + 72);
        }

        if (cf_table != 0) {
            // Guard CF is present — validates CFG support claim
            if ((ctx.optional_header.dll_characteristics & 0x4000) == 0) {
                ctx.addIssue(1, 0, "Guard CF table present but GUARD_CF flag not set");
            }
        }
    }
}

/// Validate bound import directory
fn validateBoundImports(ctx: *PeCtx) void {
    const bound_dir = &ctx.optional_header.data_dirs[root.DIR_BOUND_IMPORT];
    if (bound_dir.rva == 0 or bound_dir.size == 0) return;

    // Bound import directory uses file offsets, not RVAs
    if (bound_dir.rva >= ctx.size) {
        ctx.addIssue(1, 0, "bound import directory offset beyond file");
        return;
    }

    if (!ctx.checkOffset(bound_dir.rva, bound_dir.size)) {
        ctx.addIssue(1, 0, "bound import directory truncated");
        return;
    }

    // Parse bound import entries (8 bytes each minimum)
    var pos = bound_dir.rva;
    var count: u32 = 0;
    while (pos + 8 <= bound_dir.rva + bound_dir.size and count < 256) {
        const timestamp = rd.readU32At(ctx.data + pos);
        const name_offset = rd.readU16At(ctx.data + pos + 4);
        const num_refs = rd.readU16At(ctx.data + pos + 6);

        if (timestamp == 0 and name_offset == 0) break;

        // Validate name offset
        const abs_name_off = bound_dir.rva + name_offset;
        if (abs_name_off >= ctx.size) {
            ctx.addIssue(1, 0, "bound import name offset beyond file");
        }

        pos += 8 + @as(u32, num_refs) * 8;
        count += 1;
    }
}

/// Validate IAT directory consistency
fn validateIatDirectory(ctx: *PeCtx) void {
    const iat_dir = &ctx.optional_header.data_dirs[root.DIR_IAT];
    if (iat_dir.rva == 0 or iat_dir.size == 0) return;

    // IAT should be in a section
    if (rd.findSectionByRva(ctx, iat_dir.rva) == null) {
        ctx.addIssue(1, 0, "IAT directory outside any section");
    }

    // IAT size should be reasonable
    if (iat_dir.size > 1024 * 1024) {
        ctx.addIssue(1, 0, "IAT directory unusually large");
    }

    // If we have imports, IAT should be large enough
    if (ctx.import_descriptors != null and ctx.import_count > 0) {
        const entry_size: u32 = if (ctx.optional_header.is_pe32plus) 8 else 4;
        var total_thunks: u32 = 0;
        var d: u32 = 0;
        while (d < ctx.import_count) : (d += 1) {
            total_thunks += ctx.import_descriptors.?[d].num_thunks + 1; // +1 for null terminator
        }
        const expected_size = total_thunks * entry_size;
        if (iat_dir.size < expected_size / 2) {
            ctx.addIssue(1, 0, "IAT directory smaller than expected for import count");
        }
    }
}

/// Validate CLR/.NET directory
fn validateClrDirectory(ctx: *PeCtx) void {
    const clr_dir = &ctx.optional_header.data_dirs[root.DIR_CLR_RUNTIME];
    if (clr_dir.rva == 0 or clr_dir.size == 0) return;

    const offset = ctx.rvaToOffset(clr_dir.rva) orelse {
        ctx.addIssue(1, 0, "CLR directory RVA does not resolve");
        return;
    };

    if (!ctx.checkOffset(@intCast(offset), 72)) {
        ctx.addIssue(1, 0, "CLR directory too small");
        return;
    }

    // Read CLR header size
    const header_size = rd.readU32At(ctx.data + offset);
    if (header_size < 72) {
        ctx.addIssue(1, 0, "CLR header size too small");
    }

    // Read major/minor runtime version
    const major = rd.readU16At(ctx.data + offset + 4);
    _ = rd.readU16At(ctx.data + offset + 6); // minor version
    if (major < 2 or major > 4) {
        ctx.addIssue(1, 0, "unusual CLR runtime version");
    }
}

/// Validate delay import directory
fn validateDelayImports(ctx: *PeCtx) void {
    const delay_dir = &ctx.optional_header.data_dirs[root.DIR_DELAY_IMPORT];
    if (delay_dir.rva == 0 or delay_dir.size == 0) return;

    if (ctx.rvaToOffset(delay_dir.rva) == null) {
        ctx.addIssue(1, 0, "delay import directory RVA does not resolve");
    }

    if (delay_dir.size < 32) {
        ctx.addIssue(1, 0, "delay import directory too small for a descriptor");
    }
}

/// Check for suspicious section name patterns
fn validateSectionNames(ctx: *PeCtx) void {
    if (ctx.section_entries == null) return;
    const entries = ctx.section_entries.?;

    const suspicious_names = [_][]const u8{
        "UPX0", "UPX1", ".aspack", ".adata",
        ".themida", ".vmp0", ".vmp1", ".petite",
    };

    var i: u32 = 0;
    while (i < ctx.section_count) : (i += 1) {
        const name = std.mem.sliceTo(&entries[i].short_name, 0);
        for (suspicious_names) |sn| {
            if (std.mem.eql(u8, name, sn)) {
                ctx.addIssue(2, i, "suspicious packer section name detected");
                break;
            }
        }

        // Check for empty section names
        if (name.len == 0 or entries[i].short_name[0] == 0) {
            ctx.addIssue(1, i, "section has empty name");
        }

        // Check for non-printable characters in name
        for (name) |ch| {
            if (ch != 0 and (ch < 0x20 or ch > 0x7E)) {
                ctx.addIssue(1, i, "section name contains non-printable character");
                break;
            }
        }
    }
}

/// Validate overall PE consistency across all structures
fn validateOverallConsistency(ctx: *PeCtx) void {
    // Verify section count matches COFF header
    if (ctx.section_count != ctx.coff_header.num_sections) {
        ctx.addIssue(2, 0, "parsed section count differs from COFF header");
    }

    // Verify image is large enough for all sections
    if (ctx.section_entries) |entries| {
        var i: u32 = 0;
        while (i < ctx.section_count) : (i += 1) {
            const sec = &entries[i];
            if (sec.raw_data_offset + sec.raw_data_size > ctx.size) {
                ctx.addIssue(1, i, "section extends beyond file boundary");
            }
        }
    }

    // Verify optional header size matches magic
    if (ctx.optional_header.is_pe32plus) {
        if (ctx.coff_header.optional_header_size < 112) {
            ctx.addIssue(1, 0, "PE32+ optional header smaller than expected");
        }
    }
}
