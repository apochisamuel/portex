// cache.zig — Derived Cache Construction (Phase 12)
//
// Builds lookup caches from parsed PE structures. Each cache maps
// an index to a pointer derived from parsed data. These caches
// store raw pointers into data buffers managed by other modules.
// The cache does NOT own the pointed-to data.

const std = @import("std");
const root = @import("root.zig");
const rd = @import("reader.zig");
const PeCtx = root.PeCtx;
const ParseError = root.ParseError;

/// Import name cache: maps each thunk to its name and DLL name.
/// Thunk names point into section data buffers.
fn buildImportCache(ctx: *PeCtx) void {
    if (ctx.import_descriptors == null or ctx.import_count == 0) return;
    const descs = ctx.import_descriptors.?;

    // Count total thunks
    var total: u32 = 0;
    var d: u32 = 0;
    while (d < ctx.import_count) : (d += 1) {
        total += descs[d].num_thunks;
    }
    if (total == 0) return;

    const entries = ctx.allocator.alloc(root.ImportCacheEntry, total) catch return;
    @memset(entries, root.ImportCacheEntry{});

    var idx: u32 = 0;
    d = 0;
    while (d < ctx.import_count) : (d += 1) {
        const desc = &descs[d];
        if (desc.thunks == null) continue;
        var t: u32 = 0;
        while (t < desc.num_thunks) : (t += 1) {
            const thunk = &desc.thunks.?[t];
            entries[idx] = .{
                .descriptor_index = d,
                .thunk_index = t,
                .name_ptr = thunk.name,
                .dll_name_ptr = desc.dll_name,
            };
            idx += 1;
        }
    }
    ctx.import_cache = entries.ptr;
    ctx.import_cache_count = idx;
}

/// Export name cache: maps each export to its name and forwarder.
/// Names point into section data. Forwarders are allocated copies.
fn buildExportCache(ctx: *PeCtx) void {
    if (ctx.export_entries == null or ctx.export_count == 0) return;
    const exps = ctx.export_entries.?;

    const entries = ctx.allocator.alloc(root.ExportCacheEntry, ctx.export_count) catch return;
    var i: u32 = 0;
    while (i < ctx.export_count) : (i += 1) {
        entries[i] = .{
            .export_index = i,
            .name_ptr = exps[i].name,
            .forwarder_ptr = exps[i].forwarder,
            .ordinal = exps[i].ordinal,
        };
    }
    ctx.export_cache = entries.ptr;
    ctx.export_cache_count = ctx.export_count;
}

/// Relocation target cache: stores computed target pointers
/// that reference section data buffers.
fn buildRelocCache(ctx: *PeCtx) void {
    if (ctx.reloc_blocks == null or ctx.reloc_count == 0) return;
    const blocks = ctx.reloc_blocks.?;

    var total: u32 = 0;
    var bi: u32 = 0;
    while (bi < ctx.reloc_count) : (bi += 1) {
        if (blocks[bi].entries == null) continue;
        var ei: u32 = 0;
        while (ei < blocks[bi].count) : (ei += 1) {
            if (blocks[bi].entries.?[ei].resolved) total += 1;
        }
    }
    if (total == 0) return;

    const entries = ctx.allocator.alloc(root.RelocCacheEntry, total) catch return;
    var idx: u32 = 0;
    bi = 0;
    while (bi < ctx.reloc_count) : (bi += 1) {
        if (blocks[bi].entries == null) continue;
        var ei: u32 = 0;
        while (ei < blocks[bi].count) : (ei += 1) {
            const rel = &blocks[bi].entries.?[ei];
            if (!rel.resolved) continue;
            entries[idx] = .{
                .block_index = bi,
                .entry_index = ei,
                .target_ptr = rel.target_ptr,
                .section_index = rd.findSectionByRva(ctx, rel.target_rva) orelse 0xFFFFFFFF,
            };
            idx += 1;
        }
    }
    ctx.reloc_cache = entries.ptr;
    ctx.reloc_cache_count = idx;
}

/// Debug mapping cache: maps sections to debug entries.
/// PDB path pointers reference allocated CodeView strings.
fn buildDebugCache(ctx: *PeCtx) void {
    if (ctx.debug_entries == null or ctx.debug_count == 0) return;
    const dbgs = ctx.debug_entries.?;

    const entries = ctx.allocator.alloc(root.DebugCacheEntry, ctx.debug_count) catch return;
    var i: u32 = 0;
    while (i < ctx.debug_count) : (i += 1) {
        const dbg = &dbgs[i];
        entries[i] = .{
            .section_index = if (dbg.section_index >= 0)
                @intCast(dbg.section_index)
            else
                0xFFFFFFFF,
            .debug_entry = dbg,
            .pdb_path_ptr = if (dbg.codeview) |cv|
                cv.pdb_path
            else
                null,
        };
    }
    ctx.debug_cache = entries.ptr;
    ctx.debug_cache_count = ctx.debug_count;
}

/// Symbol name cache: maps indices to resolved name pointers.
/// Names may point into string table data.
fn buildSymbolCache(ctx: *PeCtx) void {
    if (ctx.symbol_entries == null or ctx.symbol_count == 0) return;
    const syms = ctx.symbol_entries.?;

    const entries = ctx.allocator.alloc(root.SymbolCacheEntry, ctx.symbol_count) catch return;
    var i: u32 = 0;
    while (i < ctx.symbol_count) : (i += 1) {
        entries[i] = .{
            .symbol_index = syms[i].index,
            .name_ptr = syms[i].resolved_name,
            .section_number = syms[i].section_number,
        };
    }
    ctx.symbol_cache = entries.ptr;
    ctx.symbol_cache_count = ctx.symbol_count;
}

/// Section name cache: maps indices to resolved name pointers.
/// Names may point into string table data or section headers.
fn buildSectionNameCache(ctx: *PeCtx) void {
    if (ctx.section_entries == null or ctx.section_count == 0) return;

    const names = ctx.allocator.alloc(?[*:0]u8, ctx.section_count) catch return;
    var i: u32 = 0;
    while (i < ctx.section_count) : (i += 1) {
        names[i] = ctx.section_entries.?[i].resolved_name;
    }
    ctx.section_names = names.ptr;
    ctx.section_name_count = ctx.section_count;
}

pub fn build(ctx: *PeCtx) ParseError!void {
    buildImportCache(ctx);
    buildExportCache(ctx);
    buildRelocCache(ctx);
    buildDebugCache(ctx);
    buildSymbolCache(ctx);
    buildSectionNameCache(ctx);
    ctx.cache_built = true;
}

// ── Additional cache utilities ─────────────────────────────────

/// Rebuild the import cache after validation changes
pub fn rebuildImportCache(ctx: *PeCtx) void {
    // Free existing cache
    if (ctx.import_cache) |c| {
        ctx.allocator.free(c[0..ctx.import_cache_count]);
        ctx.import_cache = null;
        ctx.import_cache_count = 0;
    }
    buildImportCache(ctx);
}

/// Rebuild the export cache after validation changes
pub fn rebuildExportCache(ctx: *PeCtx) void {
    if (ctx.export_cache) |c| {
        ctx.allocator.free(c[0..ctx.export_cache_count]);
        ctx.export_cache = null;
        ctx.export_cache_count = 0;
    }
    buildExportCache(ctx);
}

/// Rebuild the section name cache after string table rebuild
pub fn rebuildSectionNameCache(ctx: *PeCtx) void {
    if (ctx.section_names) |names| {
        ctx.allocator.free(names[0..ctx.section_name_count]);
        ctx.section_names = null;
        ctx.section_name_count = 0;
    }
    buildSectionNameCache(ctx);
}

/// Count total cached entries across all cache types
pub fn totalCachedEntries(ctx: *const PeCtx) u32 {
    return ctx.import_cache_count +
        ctx.export_cache_count +
        ctx.reloc_cache_count +
        ctx.debug_cache_count +
        ctx.symbol_cache_count +
        ctx.resource_cache_count +
        ctx.section_name_count;
}

/// Verify cache consistency — check that cached counts match
/// the source table counts
pub fn verifyCacheConsistency(ctx: *const PeCtx) bool {
    if (ctx.export_cache_count != ctx.export_count) return false;
    if (ctx.debug_cache_count != ctx.debug_count) return false;
    if (ctx.symbol_cache_count != ctx.symbol_count) return false;
    if (ctx.section_name_count != ctx.section_count) return false;
    return true;
}

/// Find import cache entry by function name
pub fn findImportCacheByName(ctx: *const PeCtx, name: []const u8) ?*const root.ImportCacheEntry {
    if (ctx.import_cache == null) return null;
    var i: u32 = 0;
    while (i < ctx.import_cache_count) : (i += 1) {
        const entry = &ctx.import_cache.?[i];
        if (entry.name_ptr) |n| {
            if (std.mem.eql(u8, std.mem.span(n), name)) return entry;
        }
    }
    return null;
}

/// Find export cache entry by ordinal
pub fn findExportCacheByOrdinal(ctx: *const PeCtx, ordinal: u16) ?*const root.ExportCacheEntry {
    if (ctx.export_cache == null) return null;
    var i: u32 = 0;
    while (i < ctx.export_cache_count) : (i += 1) {
        if (ctx.export_cache.?[i].ordinal == ordinal)
            return &ctx.export_cache.?[i];
    }
    return null;
}

// ── Cache analysis helpers ─────────────────────────────────────

/// Count import cache entries with valid name pointers
pub fn countValidImportNames(ctx: *const PeCtx) u32 {
    if (ctx.import_cache == null) return 0;
    var count: u32 = 0;
    var i: u32 = 0;
    while (i < ctx.import_cache_count) : (i += 1) {
        if (ctx.import_cache.?[i].name_ptr != null) count += 1;
    }
    return count;
}

/// Count export cache entries with valid forwarder pointers
pub fn countValidForwarders(ctx: *const PeCtx) u32 {
    if (ctx.export_cache == null) return 0;
    var count: u32 = 0;
    var i: u32 = 0;
    while (i < ctx.export_cache_count) : (i += 1) {
        if (ctx.export_cache.?[i].forwarder_ptr != null) count += 1;
    }
    return count;
}

/// Count reloc cache entries per section
pub fn countRelocsPerSection(ctx: *const PeCtx, section_counts: []u32) void {
    @memset(section_counts, 0);
    if (ctx.reloc_cache == null) return;
    var i: u32 = 0;
    while (i < ctx.reloc_cache_count) : (i += 1) {
        const sec = ctx.reloc_cache.?[i].section_index;
        if (sec < section_counts.len) section_counts[sec] += 1;
    }
}

/// Count debug cache entries with PDB paths
pub fn countPdbPaths(ctx: *const PeCtx) u32 {
    if (ctx.debug_cache == null) return 0;
    var count: u32 = 0;
    var i: u32 = 0;
    while (i < ctx.debug_cache_count) : (i += 1) {
        if (ctx.debug_cache.?[i].pdb_path_ptr != null) count += 1;
    }
    return count;
}

/// Count symbol cache entries with resolved names
pub fn countResolvedSymbolNames(ctx: *const PeCtx) u32 {
    if (ctx.symbol_cache == null) return 0;
    var count: u32 = 0;
    var i: u32 = 0;
    while (i < ctx.symbol_cache_count) : (i += 1) {
        if (ctx.symbol_cache.?[i].name_ptr != null) count += 1;
    }
    return count;
}

/// Count resource cache entries with names
pub fn countNamedResources(ctx: *const PeCtx) u32 {
    if (ctx.resource_cache == null) return 0;
    var count: u32 = 0;
    var i: u32 = 0;
    while (i < ctx.resource_cache_count) : (i += 1) {
        if (ctx.resource_cache.?[i].name_ptr != null) count += 1;
    }
    return count;
}

/// Estimate total memory used by all caches
pub fn estimateCacheMemory(ctx: *const PeCtx) u64 {
    var total: u64 = 0;
    total += @as(u64, ctx.import_cache_count) * @sizeOf(root.ImportCacheEntry);
    total += @as(u64, ctx.export_cache_count) * @sizeOf(root.ExportCacheEntry);
    total += @as(u64, ctx.reloc_cache_count) * @sizeOf(root.RelocCacheEntry);
    total += @as(u64, ctx.debug_cache_count) * @sizeOf(root.DebugCacheEntry);
    total += @as(u64, ctx.symbol_cache_count) * @sizeOf(root.SymbolCacheEntry);
    total += @as(u64, ctx.resource_cache_count) * @sizeOf(root.ResourceCacheEntry);
    total += @as(u64, ctx.section_name_count) * @sizeOf(?[*:0]u8);
    return total;
}

// ── Cache integrity verification ───────────────────────────────

/// Check if import cache entries reference valid descriptors
pub fn verifyImportCacheRefs(ctx: *const PeCtx) bool {
    if (ctx.import_cache == null) return true;
    var i: u32 = 0;
    while (i < ctx.import_cache_count) : (i += 1) {
        const entry = &ctx.import_cache.?[i];
        if (entry.descriptor_index >= ctx.import_count) return false;
        if (ctx.import_descriptors) |descs| {
            if (entry.thunk_index >= descs[entry.descriptor_index].num_thunks)
                return false;
        }
    }
    return true;
}

/// Check if export cache entries have consistent ordinals
pub fn verifyExportCacheOrdinals(ctx: *const PeCtx) bool {
    if (ctx.export_cache == null or ctx.export_entries == null) return true;
    var i: u32 = 0;
    while (i < ctx.export_cache_count) : (i += 1) {
        const cache_ord = ctx.export_cache.?[i].ordinal;
        if (i < ctx.export_count) {
            if (ctx.export_entries.?[i].ordinal != cache_ord) return false;
        }
    }
    return true;
}

/// Count stale cache entries (pointers that don't match current source)
pub fn countStaleCacheEntries(ctx: *const PeCtx) u32 {
    var stale: u32 = 0;

    // Check section names against current resolved names
    if (ctx.section_names != null and ctx.section_entries != null) {
        var i: u32 = 0;
        while (i < @min(ctx.section_name_count, ctx.section_count)) : (i += 1) {
            const cached = ctx.section_names.?[i];
            const current = ctx.section_entries.?[i].resolved_name;
            if (cached != current) stale += 1;
        }
    }

    return stale;
}
