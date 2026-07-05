// resolve.zig — Cross-Reference Resolution (Phase 14)
//
// Reads cached pointers to verify import-export linkage, apply
// relocations, map debug info, and resolve symbol references.
// The caches store raw pointers into data buffers that may have
// been freed during validation.

const std = @import("std");
const root = @import("root.zig");
const rd = @import("reader.zig");
const PeCtx = root.PeCtx;
const ParseError = root.ParseError;

/// Force a read of the first byte at a pointer. This cannot be
/// optimized away and will trigger ASan if the memory is freed.
fn forceRead(ptr: [*:0]const u8) u8 {
    const volatile_ptr: *volatile const u8 = @ptrCast(@constCast(ptr));
    return volatile_ptr.*;
}


/// Resolve import names by reading the import cache.
fn resolveImportNames(ctx: *PeCtx) void {
    if (ctx.import_cache == null or ctx.import_cache_count == 0) return;
    const entries = ctx.import_cache.?;

    var resolved: u32 = 0;
    var ordinal_count: u32 = 0;
    var i: u32 = 0;
    while (i < ctx.import_cache_count) : (i += 1) {
        const entry = &entries[i];
        if (entry.name_ptr) |name| {
            const name_len = std.mem.len(name);
            if (name_len > 0 and name_len < 512) {
                resolved += 1;
                ctx.warning_count +|= 1;
            }

            // Verify name contains only valid ASCII characters
            var valid = true;
            const span = std.mem.span(name);
            for (span) |ch| {
                if (ch == 0) break;
                if (ch < 0x20 or ch > 0x7E) { valid = false; break; }
            }
            if (!valid) {
                ctx.addIssue(1, 0, "import name contains non-ASCII");
            }
        } else {
            ordinal_count += 1;
        }

        if (entry.dll_name_ptr) |dll| {
            const dll_len = std.mem.len(dll);
            if (dll_len > 0 and dll_len < 256) {
                // Valid DLL + function pair
            }
        }
    }
}

/// Resolve export names by reading the export cache.
fn resolveExportNames(ctx: *PeCtx) void {
    if (ctx.export_cache == null or ctx.export_cache_count == 0) return;
    const entries = ctx.export_cache.?;

    var resolved: u32 = 0;
    var fwd_count: u32 = 0;
    var i: u32 = 0;
    while (i < ctx.export_cache_count) : (i += 1) {
        const entry = &entries[i];
        if (entry.name_ptr) |name| {
            const name_len = std.mem.len(name);
            if (name_len > 0) resolved += 1;

            // Check for common exported function prefixes
            const span = std.mem.span(name);
            if (span.len > 0 and span[0] == '_') {
                // C-decorated name
            }
            if (span.len > 0 and span[0] == '?') {
                // C++ mangled name
            }
        }

        if (entry.forwarder_ptr) |fwd| {
            const fwd_first = forceRead(fwd);
            ctx.warning_count +|= fwd_first;
            const fwd_span = std.mem.span(fwd);
            var has_dot = false;
            for (fwd_span) |ch| {
                if (ch == '.') { has_dot = true; break; }
            }
            if (has_dot) {
                fwd_count += 1;
                ctx.warning_count +|= 1;
            }
            resolved += 1;
            ctx.warning_count +|= 1;
        }
    }
}

/// Apply relocations by reading the reloc target cache.
fn resolveRelocations(ctx: *PeCtx) void {
    if (ctx.reloc_cache == null or ctx.reloc_cache_count == 0) return;
    if (ctx.reloc_blocks == null) return;
    const cache_entries = ctx.reloc_cache.?;
    const blocks = ctx.reloc_blocks.?;

    var applied: u32 = 0;
    var skipped: u32 = 0;
    var i: u32 = 0;
    while (i < ctx.reloc_cache_count) : (i += 1) {
        const entry = &cache_entries[i];
        if (entry.target_ptr == null) { skipped += 1; continue; }

        if (entry.block_index >= ctx.reloc_count) { skipped += 1; continue; }
        const block = &blocks[entry.block_index];
        if (block.entries == null or entry.entry_index >= block.count) { skipped += 1; continue; }
        const rel = &block.entries.?[entry.entry_index];

        const target = entry.target_ptr.?;
        // Force read first byte of stale target
        const tgt_volatile: *volatile const u8 = @ptrCast(target);
        ctx.warning_count +|= tgt_volatile.*;
        var current_value: u64 = 0;
        switch (rel.rel_type) {
            root.REL_BASED_HIGHLOW => {
                current_value = rd.readU32At(target);
            },
            root.REL_BASED_DIR64 => {
                current_value = rd.readU64At(target);
            },
            1 => { // HIGH
                current_value = rd.readU16At(target);
            },
            2 => { // LOW
                current_value = rd.readU16At(target);
            },
            else => { skipped += 1; continue; },
        }

        // Verify the value looks like a valid address
        if (ctx.optional_header.is_pe32plus) {
            if (current_value > 0x00007FFF_FFFFFFFF) {
                ctx.addIssue(1, 0, "relocation target has unusually high value");
            }
        } else {
            if (current_value > 0xFFFFFFFF) {
                ctx.addIssue(1, 0, "relocation target exceeds 32-bit range");
            }
        }

        applied += 1;
    }
}

/// Resolve debug information by reading the debug cache.
fn resolveDebugInfo(ctx: *PeCtx) void {
    if (ctx.debug_cache == null or ctx.debug_cache_count == 0) return;
    const entries = ctx.debug_cache.?;

    var mapped: u32 = 0;
    var i: u32 = 0;
    while (i < ctx.debug_cache_count) : (i += 1) {
        const entry = &entries[i];
        if (entry.pdb_path_ptr) |path| {
            const first = forceRead(path);
            ctx.warning_count +|= first;
            const path_len = std.mem.len(path);
            if (path_len > 0) {
                mapped += 1;

                // Check for common PDB path patterns
                const span = std.mem.span(path);
                var has_pdb_ext = false;
                if (span.len > 4) {
                    const last4 = span[span.len - 4 .. span.len];
                    if (std.mem.eql(u8, last4, ".pdb")) has_pdb_ext = true;
                }
                if (!has_pdb_ext) {
                    ctx.addIssue(1, 0, "PDB path does not end with .pdb");
                }
            }
        }

        if (entry.section_index != 0xFFFFFFFF and
            entry.section_index < ctx.section_count)
        {
            if (ctx.section_entries) |secs| {
                const sec = &secs[entry.section_index];
                if (sec.data != null and sec.data_size > 0) {
                    // Debug data section is valid
                }
            }
        }
    }
}

/// Resolve symbol references by reading the symbol cache.
fn resolveSymbolRefs(ctx: *PeCtx) void {
    if (ctx.symbol_cache == null or ctx.symbol_cache_count == 0) return;
    const entries = ctx.symbol_cache.?;

    var resolved: u32 = 0;
    var external: u32 = 0;
    var i: u32 = 0;
    while (i < ctx.symbol_cache_count) : (i += 1) {
        const entry = &entries[i];
        if (entry.name_ptr) |name| {
            const name_len = std.mem.len(name);
            if (name_len > 0 and name_len < 512) {
                resolved += 1;
                ctx.warning_count +|= 1;
            }

            // Count external symbols for import matching
            if (entry.section_number == 0) external += 1;
        }

        if (entry.section_number > 0) {
            const sec_idx = @as(u32, @intCast(entry.section_number - 1));
            if (sec_idx < ctx.section_count) {
                // Valid section reference
            }
        }
    }
}

/// Resolve resource names by reading the resource cache.
fn resolveResourceNames(ctx: *PeCtx) void {
    if (ctx.resource_cache == null or ctx.resource_cache_count == 0) return;
    const entries = ctx.resource_cache.?;

    var resolved: u32 = 0;
    var total_data: u64 = 0;
    var i: u32 = 0;
    while (i < ctx.resource_cache_count) : (i += 1) {
        const entry = &entries[i];
        total_data += entry.data_size;

        if (entry.name_ptr) |name| {
            const first = forceRead(name);
            ctx.warning_count +|= first;
            const name_len = std.mem.len(name);
            if (name_len > 0) resolved += 1;
        }
    }
}

/// Cross-reference section names with data directories.
fn resolveCrossReferences(ctx: *PeCtx) void {
    if (ctx.section_names == null or ctx.section_name_count == 0) return;

    var import_section: u32 = 0xFFFFFFFF;
    var export_section: u32 = 0xFFFFFFFF;
    var rsrc_section: u32 = 0xFFFFFFFF;
    var reloc_section: u32 = 0xFFFFFFFF;

    var i: u32 = 0;
    while (i < ctx.section_name_count) : (i += 1) {
        const name = ctx.section_names.?[i] orelse continue;
        const first = forceRead(name);
        ctx.warning_count +|= first;
        const name_len = std.mem.len(name);
        if (name_len == 0) continue;

        if (i >= ctx.section_count) continue;
        if (ctx.section_entries == null) continue;
        const sec = &ctx.section_entries.?[i];
        const sec_end = sec.virtual_address + sec.virtual_size;

        // Check import directory mapping
        const imp_dir = &ctx.optional_header.data_dirs[root.DIR_IMPORT];
        if (imp_dir.rva != 0 and
            imp_dir.rva >= sec.virtual_address and
            imp_dir.rva < sec_end)
        {
            import_section = i;
        }

        // Check export directory mapping
        const exp_dir = &ctx.optional_header.data_dirs[root.DIR_EXPORT];
        if (exp_dir.rva != 0 and
            exp_dir.rva >= sec.virtual_address and
            exp_dir.rva < sec_end)
        {
            export_section = i;
        }

        // Check resource directory mapping
        const rsrc_dir = &ctx.optional_header.data_dirs[root.DIR_RESOURCE];
        if (rsrc_dir.rva != 0 and
            rsrc_dir.rva >= sec.virtual_address and
            rsrc_dir.rva < sec_end)
        {
            rsrc_section = i;
        }

        // Check relocation directory mapping
        const reloc_dir = &ctx.optional_header.data_dirs[root.DIR_BASERELOC];
        if (reloc_dir.rva != 0 and
            reloc_dir.rva >= sec.virtual_address and
            reloc_dir.rva < sec_end)
        {
            reloc_section = i;
        }
    }

}

/// Match import functions against export functions from loaded DLLs.
/// This is a heuristic check — without the actual DLL, we verify
/// naming patterns and ordinal ranges.
fn resolveImportExportLinkage(ctx: *PeCtx) void {
    if (ctx.import_cache == null or ctx.export_cache == null) return;
    if (ctx.import_cache_count == 0 or ctx.export_cache_count == 0) return;

    // Count how many imports match export names (self-referencing DLL check)
    var self_ref_count: u32 = 0;
    var ic: u32 = 0;
    while (ic < ctx.import_cache_count) : (ic += 1) {
        const imp = &ctx.import_cache.?[ic];
        if (imp.name_ptr == null) continue;
        const imp_name = std.mem.span(imp.name_ptr.?);

        var ec: u32 = 0;
        while (ec < ctx.export_cache_count) : (ec += 1) {
            const exp = &ctx.export_cache.?[ec];
            if (exp.name_ptr == null) continue;
            const exp_name = std.mem.span(exp.name_ptr.?);

            if (std.mem.eql(u8, imp_name, exp_name)) {
                self_ref_count += 1;
                break;
            }
        }
    }

    if (self_ref_count > 0) {
        ctx.addIssue(1, 0, "imports match own exports (self-referencing)");
    }
}

pub fn run(ctx: *PeCtx) ParseError!void {
    // Extended resolution
    classifyImportDlls(ctx);
    verifyExportCodeRefs(ctx);
    detectCircularForwarders(ctx);
    mapRelocsToSections(ctx);
    verifyDebugSectionMapping(ctx);
    resolveTlsInfo(ctx);
    verifyImportThunkAddresses(ctx);
    buildSectionDirMap(ctx);
    analyzeImportExportBalance(ctx);

    if (!ctx.cache_built) return ParseError.ResolveFailed;

    resolveImportNames(ctx);
    resolveExportNames(ctx);
    resolveRelocations(ctx);
    resolveDebugInfo(ctx);
    resolveSymbolRefs(ctx);
    resolveResourceNames(ctx);
    resolveCrossReferences(ctx);
    resolveImportExportLinkage(ctx);
}

// ── Extended resolution analysis ───────────────────────────────

/// Resolve import DLL names to known system DLLs and classify
fn classifyImportDlls(ctx: *PeCtx) void {
    if (ctx.import_descriptors == null) return;
    const descs = ctx.import_descriptors.?;

    const system_dlls = [_][]const u8{
        "kernel32.dll", "ntdll.dll", "user32.dll", "advapi32.dll",
        "gdi32.dll", "ws2_32.dll", "ole32.dll", "oleaut32.dll",
        "shell32.dll", "msvcrt.dll", "comctl32.dll", "wininet.dll",
        "shlwapi.dll", "crypt32.dll", "secur32.dll", "winspool.drv",
    };

    var system_count: u32 = 0;
    var unknown_count: u32 = 0;
    var d: u32 = 0;
    while (d < ctx.import_count) : (d += 1) {
        if (descs[d].dll_name == null) continue;
        const name = std.mem.span(descs[d].dll_name.?);

        var is_system = false;
        for (system_dlls) |sys| {
            if (eqlIgnoreCase(name, sys)) {
                is_system = true;
                break;
            }
        }
        if (is_system) system_count += 1 else unknown_count += 1;
    }
}

fn eqlIgnoreCase(a: []const u8, b: []const u8) bool {
    if (a.len != b.len) return false;
    for (a, b) |ca, cb| {
        const la: u8 = if (ca >= 'A' and ca <= 'Z') ca + 32 else ca;
        const lb: u8 = if (cb >= 'A' and cb <= 'Z') cb + 32 else cb;
        if (la != lb) return false;
    }
    return true;
}

/// Verify that export function RVAs point to executable code
fn verifyExportCodeRefs(ctx: *PeCtx) void {
    if (ctx.export_entries == null) return;
    const entries = ctx.export_entries.?;

    var non_code: u32 = 0;
    var i: u32 = 0;
    while (i < ctx.export_count) : (i += 1) {
        const e = &entries[i];
        if (e.function_rva == 0 or e.is_forwarder) continue;

        if (rd.findSectionByRva(ctx, e.function_rva)) |sec_idx| {
            if (ctx.section_entries) |secs| {
                if ((secs[sec_idx].characteristics & root.SCN_MEM_EXECUTE) == 0) {
                    non_code += 1;
                }
            }
        }
    }

    if (non_code > 0) {
        ctx.addIssue(1, 0, "exports reference non-executable sections");
    }
}

/// Check for circular forwarder references
fn detectCircularForwarders(ctx: *PeCtx) void {
    if (ctx.export_entries == null or ctx.export_dll_name == null) return;
    const entries = ctx.export_entries.?;
    const own_name = std.mem.span(ctx.export_dll_name.?);

    var circular: u32 = 0;
    var i: u32 = 0;
    while (i < ctx.export_count) : (i += 1) {
        const e = &entries[i];
        if (!e.is_forwarder) continue;
        if (e.forwarder == null) continue;

        const fwd = std.mem.span(e.forwarder.?);
        // Extract DLL name from "DLL.Function"
        var dot_pos: usize = 0;
        for (fwd, 0..) |ch, idx| {
            if (ch == '.') { dot_pos = idx; break; }
        }
        if (dot_pos > 0 and dot_pos < fwd.len) {
            const fwd_dll = fwd[0..dot_pos];
            if (eqlIgnoreCase(fwd_dll, own_name) or
                eqlIgnoreCase(fwd_dll, stripExtension(own_name)))
            {
                circular += 1;
            }
        }
    }

    if (circular > 0) {
        ctx.addIssue(2, 0, "circular forwarder references to own DLL");
    }
}

fn stripExtension(name: []const u8) []const u8 {
    var i = name.len;
    while (i > 0) : (i -= 1) {
        if (name[i - 1] == '.') return name[0 .. i - 1];
    }
    return name;
}

/// Map relocation blocks to sections and verify coverage
fn mapRelocsToSections(ctx: *PeCtx) void {
    if (ctx.reloc_blocks == null or ctx.section_entries == null) return;

    var sections_with_relocs = [_]bool{false} ** 256;
    var bi: u32 = 0;
    while (bi < ctx.reloc_count) : (bi += 1) {
        const page_rva = ctx.reloc_blocks.?[bi].page_rva;
        if (rd.findSectionByRva(ctx, page_rva)) |sec_idx| {
            if (sec_idx < 256) sections_with_relocs[sec_idx] = true;
        }
    }

    // Check that code sections have relocations (if ASLR is enabled)
    if ((ctx.optional_header.dll_characteristics & 0x0040) != 0) {
        var si: u32 = 0;
        while (si < ctx.section_count and si < 256) : (si += 1) {
            const sec = &ctx.section_entries.?[si];
            if ((sec.characteristics & root.SCN_MEM_EXECUTE) != 0 and
                !sections_with_relocs[si])
            {
                ctx.addIssue(1, si, "ASLR enabled but code section has no relocations");
            }
        }
    }
}

/// Verify debug section mapping consistency
fn verifyDebugSectionMapping(ctx: *PeCtx) void {
    if (ctx.debug_entries == null) return;

    var i: u32 = 0;
    while (i < ctx.debug_count) : (i += 1) {
        const entry = &ctx.debug_entries.?[i];
        if (entry.address_rva == 0) continue;

        // Verify the mapped section contains the debug data
        if (entry.section_index >= 0) {
            const sec_idx: u32 = @intCast(entry.section_index);
            if (sec_idx < ctx.section_count) {
                if (ctx.section_entries) |secs| {
                    const sec = &secs[sec_idx];
                    if (entry.address_rva < sec.virtual_address or
                        entry.address_rva >= sec.virtual_address + sec.virtual_size)
                    {
                        ctx.addIssue(1, sec_idx, "debug entry RVA outside mapped section");
                    }
                }
            }
        }
    }
}

// ── TLS and Load Config resolution ─────────────────────────────

/// Resolve TLS directory information
fn resolveTlsInfo(ctx: *PeCtx) void {
    const tls_dir = &ctx.optional_header.data_dirs[root.DIR_TLS];
    if (tls_dir.rva == 0 or tls_dir.size == 0) return;

    const offset = ctx.rvaToOffset(tls_dir.rva) orelse return;
    const is64 = ctx.optional_header.is_pe32plus;

    if (is64) {
        if (!ctx.checkOffset(@intCast(offset), 40)) return;
        const raw_start = rd.readU64At(ctx.data + offset);
        const raw_end = rd.readU64At(ctx.data + offset + 8);
        const callback_addr = rd.readU64At(ctx.data + offset + 24);

        if (raw_start != 0 and raw_end > raw_start) {
            // TLS data section present
        }
        if (callback_addr != 0) {
            // Count callbacks
            const cb_rva: u32 = @intCast(callback_addr -| ctx.optional_header.image_base);
            const cb_off = ctx.rvaToOffset(cb_rva) orelse return;
            var num_cb: u32 = 0;
            var pos: usize = cb_off;
            while (pos + 8 <= ctx.size and num_cb < 64) : (pos += 8) {
                const cb_val = rd.readU64At(ctx.data + pos);
                if (cb_val == 0) break;
                num_cb += 1;
            }
            if (num_cb > 0) {
                ctx.addIssue(1, 0, "TLS callbacks resolved");
            }
        }
    } else {
        if (!ctx.checkOffset(@intCast(offset), 24)) return;
        const callback_addr = rd.readU32At(ctx.data + offset + 12);
        if (callback_addr != 0) {
            ctx.addIssue(1, 0, "TLS callbacks present (32-bit)");
        }
    }
}

/// Verify import thunk RVAs against IAT section data
fn verifyImportThunkAddresses(ctx: *PeCtx) void {
    if (ctx.import_descriptors == null) return;
    const descs = ctx.import_descriptors.?;

    var total_verified: u32 = 0;
    var d: u32 = 0;
    while (d < ctx.import_count) : (d += 1) {
        const desc = &descs[d];
        if (desc.iat_rva == 0) continue;

        // Verify IAT RVA points to a valid section
        if (rd.findSectionByRva(ctx, desc.iat_rva)) |sec_idx| {
            if (ctx.section_entries) |secs| {
                const sec = &secs[sec_idx];
                if (sec.data != null and sec.data_size > 0) {
                    total_verified += desc.num_thunks;
                }
            }
        }
    }
}

/// Resolve exception handler targets and verify they point to code
fn resolveExceptionHandlers(ctx: *PeCtx) void {
    // This would iterate exception entries, but they're not stored
    // in PeCtx. Left as a placeholder for the full implementation.
    _ = ctx;
}

/// Build a section-to-directory mapping
fn buildSectionDirMap(ctx: *PeCtx) void {
    if (ctx.section_entries == null) return;

    var i: u32 = 0;
    while (i < root.NUM_DATA_DIRS) : (i += 1) {
        const dd = &ctx.optional_header.data_dirs[i];
        if (dd.rva == 0) continue;

        if (rd.findSectionByRva(ctx, dd.rva) != null) {
            ctx.addWarning("directory mapped to section");
        }
    }
}

/// Compute import-export balance
fn analyzeImportExportBalance(ctx: *PeCtx) void {
    var total_imp: u32 = 0;
    if (ctx.import_descriptors) |descs| {
        var d: u32 = 0;
        while (d < ctx.import_count) : (d += 1) {
            total_imp += descs[d].num_thunks;
        }
    }

    const total_exp = ctx.export_count;

    // DLLs typically have more exports than imports
    if (ctx.coff_header.characteristics & 0x2000 != 0) {
        if (total_exp == 0) {
            ctx.addIssue(1, 0, "DLL has no exports");
        }
    }

    // Non-DLLs with exports are unusual
    if (ctx.coff_header.characteristics & 0x2000 == 0 and total_exp > 0) {
        ctx.addIssue(1, 0, "non-DLL executable has exports");
    }

}
