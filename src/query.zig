// query.zig — Public Query API
//
// Accessor functions for querying PE metadata. Uses cached data
// built during the analysis pipeline.

const std = @import("std");
const root = @import("root.zig");
const rd = @import("reader.zig");
const str = @import("strings.zig");
const sec_mod = @import("sections.zig");
const PeCtx = root.PeCtx;

// ── Header access ──────────────────────────────────────────────

pub fn getDosHeader(ctx: *const PeCtx) *const root.DosHeader {
    return &ctx.dos_header;
}

pub fn getCoffHeader(ctx: *const PeCtx) *const root.CoffHeader {
    return &ctx.coff_header;
}

pub fn getOptionalHeader(ctx: *const PeCtx) *const root.OptionalHeader {
    return &ctx.optional_header;
}

// ── Section queries ────────────────────────────────────────────

pub fn getSectionCount(ctx: *const PeCtx) u32 {
    return ctx.section_count;
}

pub fn getSection(ctx: *const PeCtx, index: u32) ?*const root.Section {
    if (ctx.section_entries == null or index >= ctx.section_count) return null;
    return &ctx.section_entries.?[index];
}

/// Get resolved name using cache. May return pointer into
/// string table data (stale if table was rebuilt in validation).
pub fn getSectionName(ctx: *const PeCtx, index: u32) ?[*:0]const u8 {
    if (index >= ctx.section_count) return null;

    // Use cached name if available
    if (ctx.section_names != null and ctx.section_name_count > index) {
        if (ctx.section_names.?[index]) |cached| return cached;
    }

    // Fall back to section entry
    if (ctx.section_entries) |entries| {
        return entries[index].resolved_name;
    }
    return null;
}

pub fn findSectionByName(ctx: *const PeCtx, name: []const u8) ?*const root.Section {
    if (ctx.section_entries == null) return null;
    var i: u32 = 0;
    while (i < ctx.section_count) : (i += 1) {
        const sec = &ctx.section_entries.?[i];
        if (sec.resolved_name) |rn| {
            if (std.mem.eql(u8, std.mem.span(rn), name)) return sec;
        }
    }
    return null;
}

pub fn findSectionByRva(ctx: *const PeCtx, rva: u32) ?*const root.Section {
    if (ctx.section_entries == null) return null;
    var i: u32 = 0;
    while (i < ctx.section_count) : (i += 1) {
        const sec = &ctx.section_entries.?[i];
        var sec_end = sec.virtual_address + sec.virtual_size;
        if (sec.virtual_size == 0) sec_end = sec.virtual_address + sec.raw_data_size;
        if (rva >= sec.virtual_address and rva < sec_end) return sec;
    }
    return null;
}

// ── Import queries ─────────────────────────────────────────────

pub fn getImportDescriptorCount(ctx: *const PeCtx) u32 {
    return ctx.import_count;
}

pub fn getImportDescriptor(ctx: *const PeCtx, index: u32) ?*const root.ImportDescriptor {
    if (ctx.import_descriptors == null or index >= ctx.import_count) return null;
    return &ctx.import_descriptors.?[index];
}

pub fn getImportDllName(ctx: *const PeCtx, desc_index: u32) ?[*:0]const u8 {
    const desc = getImportDescriptor(ctx, desc_index) orelse return null;
    return desc.dll_name;
}

pub fn getImportThunkCount(ctx: *const PeCtx, desc_index: u32) u32 {
    const desc = getImportDescriptor(ctx, desc_index) orelse return 0;
    return desc.num_thunks;
}

pub fn getImportThunk(ctx: *const PeCtx, desc_index: u32, thunk_index: u32) ?*const root.ImportThunk {
    const desc = getImportDescriptor(ctx, desc_index) orelse return null;
    if (desc.thunks == null or thunk_index >= desc.num_thunks) return null;
    return &desc.thunks.?[thunk_index];
}

// ── Export queries ──────────────────────────────────────────────

pub fn getExportCount(ctx: *const PeCtx) u32 {
    return ctx.export_count;
}

pub fn getExport(ctx: *const PeCtx, index: u32) ?*const root.ExportEntry {
    if (ctx.export_entries == null or index >= ctx.export_count) return null;
    return &ctx.export_entries.?[index];
}

pub fn findExportByName(ctx: *const PeCtx, name: []const u8) ?*const root.ExportEntry {
    if (ctx.export_entries == null) return null;
    var i: u32 = 0;
    while (i < ctx.export_count) : (i += 1) {
        const e = &ctx.export_entries.?[i];
        if (e.has_name and e.name != null) {
            if (std.mem.eql(u8, std.mem.span(e.name.?), name)) return e;
        }
    }
    return null;
}

pub fn findExportByOrdinal(ctx: *const PeCtx, ordinal: u16) ?*const root.ExportEntry {
    if (ctx.export_entries == null) return null;
    var i: u32 = 0;
    while (i < ctx.export_count) : (i += 1) {
        if (ctx.export_entries.?[i].ordinal == ordinal)
            return &ctx.export_entries.?[i];
    }
    return null;
}

pub fn getExportDllName(ctx: *const PeCtx) ?[*:0]const u8 {
    return ctx.export_dll_name;
}

// ── Symbol queries ─────────────────────────────────────────────

pub fn getSymbolCount(ctx: *const PeCtx) u32 {
    return ctx.symbol_count;
}

pub fn getSymbol(ctx: *const PeCtx, index: u32) ?*const root.Symbol {
    if (ctx.symbol_entries == null or index >= ctx.symbol_count) return null;
    return &ctx.symbol_entries.?[index];
}

pub fn getSymbolName(ctx: *const PeCtx, index: u32) ?[*:0]const u8 {
    const sym = getSymbol(ctx, index) orelse return null;
    return sym.resolved_name;
}

// ── Debug queries ──────────────────────────────────────────────

pub fn getDebugEntryCount(ctx: *const PeCtx) u32 {
    return ctx.debug_count;
}

pub fn getDebugEntry(ctx: *const PeCtx, index: u32) ?*const root.DebugEntry {
    if (ctx.debug_entries == null or index >= ctx.debug_count) return null;
    return &ctx.debug_entries.?[index];
}

pub fn getPdbPath(ctx: *const PeCtx, index: u32) ?[*:0]const u8 {
    const entry = getDebugEntry(ctx, index) orelse return null;
    if (entry.codeview) |cv| return cv.pdb_path;
    return null;
}

// ── Relocation queries ─────────────────────────────────────────

pub fn getRelocBlockCount(ctx: *const PeCtx) u32 {
    return ctx.reloc_count;
}

pub fn getRelocBlock(ctx: *const PeCtx, index: u32) ?*const root.RelocBlock {
    if (ctx.reloc_blocks == null or index >= ctx.reloc_count) return null;
    return &ctx.reloc_blocks.?[index];
}

// ── Resource queries ───────────────────────────────────────────

pub fn getResourceRoot(ctx: *const PeCtx) ?*const root.ResourceNode {
    return ctx.resource_root;
}

pub fn getResourceFlatCount(ctx: *const PeCtx) u32 {
    return ctx.resource_flat_count;
}

/// Query resource name by flat index using cache.
/// May return dangling pointer if resource was pruned in validation.
pub fn queryResourceName(ctx: *const PeCtx, flat_index: u32) ?[*:0]const u8 {
    // Use cached name if available
    if (ctx.resource_cache != null and flat_index < ctx.resource_cache_count) {
        const entry = &ctx.resource_cache.?[flat_index];
        if (entry.name_ptr) |name| return name;
    }

    // Fall back to direct tree access
    if (ctx.resource_flat != null and flat_index < ctx.resource_flat_count) {
        if (ctx.resource_flat.?[flat_index]) |node| return node.name;
    }
    return null;
}

// ── String table queries ───────────────────────────────────────

pub fn getString(ctx: *const PeCtx, offset: u32) ?[*:0]const u8 {
    return str.lookup(&ctx.string_table, offset);
}

// ── Validation issue queries ───────────────────────────────────

pub fn getIssueCount(ctx: *const PeCtx) u32 {
    return ctx.issue_count;
}

pub fn getIssue(ctx: *const PeCtx, index: u32) ?*const root.ValidationIssue {
    if (ctx.issues == null or index >= ctx.issue_count) return null;
    return &ctx.issues.?[index];
}

// ── Image property queries ─────────────────────────────────────

pub fn isDll(ctx: *const PeCtx) bool {
    return (ctx.coff_header.characteristics & 0x2000) != 0;
}

pub fn isExecutable(ctx: *const PeCtx) bool {
    return (ctx.coff_header.characteristics & 0x0002) != 0;
}

pub fn is64bit(ctx: *const PeCtx) bool {
    return ctx.optional_header.is_pe32plus;
}

pub fn hasAslr(ctx: *const PeCtx) bool {
    return (ctx.optional_header.dll_characteristics & 0x0040) != 0;
}

pub fn hasDep(ctx: *const PeCtx) bool {
    return (ctx.optional_header.dll_characteristics & 0x0100) != 0;
}

pub fn hasCfg(ctx: *const PeCtx) bool {
    return (ctx.optional_header.dll_characteristics & 0x4000) != 0;
}

pub fn hasSeh(ctx: *const PeCtx) bool {
    return (ctx.optional_header.dll_characteristics & 0x0400) == 0;
}

// ── Section property helpers ───────────────────────────────────

pub fn sectionIsExecutable(sec: *const root.Section) bool {
    return sec_mod.isExecutable(sec);
}

pub fn sectionIsWritable(sec: *const root.Section) bool {
    return sec_mod.isWritable(sec);
}

pub fn sectionContainsCode(sec: *const root.Section) bool {
    return sec_mod.containsCode(sec);
}

pub fn sectionContainsData(sec: *const root.Section) bool {
    return sec_mod.containsData(sec);
}

pub fn sectionGetAlignment(sec: *const root.Section) u32 {
    const align_val = (sec.characteristics & 0x00F00000) >> 20;
    if (align_val == 0) return 0;
    return @as(u32, 1) << @intCast(align_val - 1);
}

// ── Statistics ─────────────────────────────────────────────────

pub const PeStats = struct {
    total_sections: u32 = 0,
    code_sections: u32 = 0,
    data_sections: u32 = 0,
    total_raw_size: u64 = 0,
    total_virtual_size: u64 = 0,
    total_imports: u32 = 0,
    total_import_dlls: u32 = 0,
    total_exports: u32 = 0,
    total_forwarders: u32 = 0,
    total_reloc_entries: u32 = 0,
    total_symbols: u32 = 0,
    total_resources: u32 = 0,
    total_debug_entries: u32 = 0,
    validation_issues: u32 = 0,
    validation_warnings: u32 = 0,
    validation_errors: u32 = 0,
};

pub fn computeStats(ctx: *const PeCtx) PeStats {
    var stats = PeStats{};

    if (ctx.section_entries) |entries| {
        stats.total_sections = ctx.section_count;
        var i: u32 = 0;
        while (i < ctx.section_count) : (i += 1) {
            const sec = &entries[i];
            stats.total_raw_size += sec.raw_data_size;
            stats.total_virtual_size += sec.virtual_size;
            if ((sec.characteristics & root.SCN_CNT_CODE) != 0) stats.code_sections += 1;
            if ((sec.characteristics & root.SCN_CNT_INIT_DATA) != 0) stats.data_sections += 1;
        }
    }

    stats.total_import_dlls = ctx.import_count;
    if (ctx.import_descriptors) |descs| {
        var d: u32 = 0;
        while (d < ctx.import_count) : (d += 1) {
            stats.total_imports += descs[d].num_thunks;
        }
    }

    stats.total_exports = ctx.export_count;
    if (ctx.export_entries) |exps| {
        var i: u32 = 0;
        while (i < ctx.export_count) : (i += 1) {
            if (exps[i].is_forwarder) stats.total_forwarders += 1;
        }
    }

    if (ctx.reloc_blocks) |blocks| {
        var i: u32 = 0;
        while (i < ctx.reloc_count) : (i += 1) {
            stats.total_reloc_entries += blocks[i].count;
        }
    }

    stats.total_symbols = ctx.symbol_count;
    stats.total_resources = ctx.resource_flat_count;
    stats.total_debug_entries = ctx.debug_count;
    stats.validation_issues = ctx.issue_count;

    if (ctx.issues) |issues| {
        var i: u32 = 0;
        while (i < ctx.issue_count) : (i += 1) {
            if (issues[i].severity >= 2) stats.validation_errors += 1
            else if (issues[i].severity == 1) stats.validation_warnings += 1;
        }
    }

    return stats;
}

// ── Delay import queries ───────────────────────────────────────

pub fn getDelayImportCount(ctx: *const PeCtx) u32 {
    _ = ctx;
    return 0; // Delay imports not stored in PeCtx yet
}

// ── Exception queries ──────────────────────────────────────────

pub fn getExceptionCount(ctx: *const PeCtx) u32 {
    _ = ctx;
    return 0; // Exceptions not stored in PeCtx yet
}

// ── Computed statistics caching ────────────────────────────────

/// Compute full PE statistics with caching
pub fn computeFullStats(ctx: *const PeCtx) PeStats {
    var stats = computeStats(ctx);

    // Compute section entropy stats
    if (ctx.section_entries) |entries| {
        var entropy_sum: f64 = 0.0;
        var max_entropy: f64 = 0.0;
        var entropy_count: u32 = 0;
        var suspicious: u32 = 0;

        var i: u32 = 0;
        while (i < ctx.section_count) : (i += 1) {
            const sec = &entries[i];
            if (sec.data == null or sec.data_size == 0) continue;

            const e = @import("analysis.zig").calculateEntropy(sec.data, sec.data_size);
            entropy_sum += e;
            entropy_count += 1;
            if (e > max_entropy) max_entropy = e;

            if (e > 7.0 and
                (sec.characteristics & root.SCN_MEM_WRITE) != 0 and
                (sec.characteristics & root.SCN_MEM_EXECUTE) != 0)
            {
                suspicious += 1;
            }
        }

        if (entropy_count > 0) {
            stats.avg_section_entropy = entropy_sum / @as(f64, @floatFromInt(entropy_count));
        }
        stats.max_section_entropy = max_entropy;
        stats.suspicious_section_count = suspicious;
    }

    return stats;
}

// ── Section convenience queries ────────────────────────────────

/// Get the entry point section index
pub fn getEntryPointSection(ctx: *const PeCtx) ?u32 {
    if (ctx.optional_header.entry_point_rva == 0) return null;
    return @import("reader.zig").findSectionByRva(ctx, ctx.optional_header.entry_point_rva);
}

/// Check if the PE has a valid digital signature directory
pub fn hasDigitalSignature(ctx: *const PeCtx) bool {
    const sec_dir = &ctx.optional_header.data_dirs[root.DIR_SECURITY];
    return sec_dir.rva != 0 and sec_dir.size > 0;
}

/// Check if PE has bound imports
pub fn hasBoundImports(ctx: *const PeCtx) bool {
    const bound_dir = &ctx.optional_header.data_dirs[root.DIR_BOUND_IMPORT];
    return bound_dir.rva != 0 and bound_dir.size > 0;
}

/// Check if PE has TLS directory
pub fn hasTls(ctx: *const PeCtx) bool {
    const tls_dir = &ctx.optional_header.data_dirs[root.DIR_TLS];
    return tls_dir.rva != 0 and tls_dir.size > 0;
}

/// Check if PE has load configuration
pub fn hasLoadConfig(ctx: *const PeCtx) bool {
    const lc_dir = &ctx.optional_header.data_dirs[root.DIR_LOAD_CONFIG];
    return lc_dir.rva != 0 and lc_dir.size > 0;
}

/// Check if PE has CLR/.NET metadata
pub fn hasDotNet(ctx: *const PeCtx) bool {
    const clr_dir = &ctx.optional_header.data_dirs[root.DIR_CLR_RUNTIME];
    return clr_dir.rva != 0 and clr_dir.size > 0;
}

/// Check if PE has exception handling data
pub fn hasExceptionData(ctx: *const PeCtx) bool {
    const exc_dir = &ctx.optional_header.data_dirs[root.DIR_EXCEPTION];
    return exc_dir.rva != 0 and exc_dir.size > 0;
}

/// Get the number of data directories present
pub fn countPresentDataDirs(ctx: *const PeCtx) u32 {
    var count: u32 = 0;
    for (&ctx.optional_header.data_dirs) |dd| {
        if (dd.rva != 0 or dd.size != 0) count += 1;
    }
    return count;
}

/// Get image base as displayable address
pub fn getImageBase(ctx: *const PeCtx) u64 {
    return ctx.optional_header.image_base;
}

/// Get file alignment
pub fn getFileAlignment(ctx: *const PeCtx) u32 {
    return ctx.optional_header.file_alignment;
}

/// Get section alignment
pub fn getSectionAlignment(ctx: *const PeCtx) u32 {
    return ctx.optional_header.section_alignment;
}
