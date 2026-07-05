// exports.zig — Export Table Parsing (Phase 8)
//
// Parses the export directory: EAT, name pointer table, ordinal table.
// Export names are pointers into section data. Forwarder strings are
// allocated copies (may be freed during validation).

const std = @import("std");
const root = @import("root.zig");
const rd = @import("reader.zig");
const PeCtx = root.PeCtx;
const ParseError = root.ParseError;
const Reader = rd.Reader;

/// Read export name as pointer into section data (not a copy)
fn readNamePtr(ctx: *PeCtx, rva: u32) ?[*:0]u8 {
    const sec_idx = rd.findSectionByRva(ctx, rva) orelse return null;
    const ptr = rd.sectionRvaToPtr(ctx, sec_idx, rva, 1) orelse return null;

    if (ctx.section_entries) |entries| {
        const sec = &entries[sec_idx];
        const delta = rva - sec.virtual_address;
        const remaining = sec.data_size - delta;
        var len: usize = 0;
        while (len < remaining and ptr[len] != 0) : (len += 1) {}
        if (len >= remaining) return null;
    }
    return @ptrCast(ptr);
}

/// Read forwarder string as allocated copy
fn readForwarder(ctx: *PeCtx, rva: u32) ?[*:0]u8 {
    const ptr = ctx.rvaToPtr(rva, 1) orelse return null;
    var max_len = ctx.size - @as(usize, @intFromPtr(ptr) - @intFromPtr(ctx.data));
    if (max_len > 512) max_len = 512;

    var len: usize = 0;
    while (len < max_len and ptr[len] != 0) : (len += 1) {}

    const str = ctx.allocator.alloc(u8, len + 1) catch return null;
    @memcpy(str[0..len], ptr[0..len]);
    str[len] = 0;
    return @ptrCast(str.ptr);
}

fn parseEntries(ctx: *PeCtx, func_rva: u32, name_rva: u32,
                ordinal_rva: u32, ordinal_base: u32) ParseError!void {
    var num_funcs = ctx.export_count;
    if (num_funcs == 0) return;
    if (num_funcs > root.MAX_EXPORTS) num_funcs = root.MAX_EXPORTS;

    const entries = ctx.allocator.alloc(root.ExportEntry, num_funcs) catch
        return ParseError.OutOfMemory;
    @memset(entries, root.ExportEntry{});
    ctx.export_entries = entries.ptr;
    ctx.export_capacity = num_funcs;

    // Read function RVAs from EAT
    const eat_offset = ctx.rvaToOffset(func_rva) orelse return ParseError.InvalidExport;
    var i: u32 = 0;
    while (i < num_funcs) : (i += 1) {
        if (!ctx.checkOffset(@intCast(eat_offset + i * 4), 4)) break;
        entries[i].function_rva = rd.readU32At(ctx.data + eat_offset + i * 4);
        entries[i].ordinal = @intCast(ordinal_base + i);
    }

    // Read name pointers and ordinals
    const num_names = ctx.export_count; // reused field
    if (num_names > 0 and name_rva != 0 and ordinal_rva != 0) {
        const npt_off = ctx.rvaToOffset(name_rva) orelse return;
        const ot_off = ctx.rvaToOffset(ordinal_rva) orelse return;

        var ni: u32 = 0;
        const name_count = @min(num_names, num_funcs);
        while (ni < name_count) : (ni += 1) {
            if (!ctx.checkOffset(@intCast(npt_off + ni * 4), 4)) break;
            if (!ctx.checkOffset(@intCast(ot_off + ni * 2), 2)) break;

            const name_entry_rva = rd.readU32At(ctx.data + npt_off + ni * 4);
            const ordinal_index = rd.readU16At(ctx.data + ot_off + ni * 2);

            if (ordinal_index < num_funcs) {
                const entry = &entries[ordinal_index];
                entry.has_name = true;
                entry.name_ordinal = @intCast(ni);
                entry.name = readNamePtr(ctx, name_entry_rva);
            }
        }
    }
}

fn resolveForwarders(ctx: *PeCtx, dir_rva: u32, dir_size: u32) void {
    if (ctx.export_entries == null) return;
    const entries = ctx.export_entries.?;
    const dir_end = dir_rva + dir_size;

    var i: u32 = 0;
    while (i < ctx.export_count) : (i += 1) {
        const entry = &entries[i];
        if (entry.function_rva == 0) continue;
        if (entry.function_rva >= dir_rva and entry.function_rva < dir_end) {
            entry.is_forwarder = true;
            entry.forwarder = readForwarder(ctx, entry.function_rva);
        }
    }
}

pub fn parse(ctx: *PeCtx) ParseError!void {
    const export_dir = &ctx.optional_header.data_dirs[root.DIR_EXPORT];
    if (export_dir.rva == 0 or export_dir.size == 0) return;

    const dir_offset = ctx.rvaToOffset(export_dir.rva) orelse
        return ParseError.InvalidExport;

    if (!ctx.checkOffset(@intCast(dir_offset), 40))
        return ParseError.Truncated;

    var r = Reader.init(ctx.data, ctx.size);
    if (!r.seek(dir_offset)) return ParseError.Truncated;

    // Export directory table (40 bytes)
    _ = r.readU32(); // characteristics
    _ = r.readU32(); // timestamp
    _ = r.readU16(); // major version
    _ = r.readU16(); // minor version
    const name_rva = r.readU32() orelse return ParseError.Truncated;
    const ordinal_base = r.readU32() orelse return ParseError.Truncated;
    const num_functions = r.readU32() orelse return ParseError.Truncated;
    _ = r.readU32() orelse return ParseError.Truncated; // num_names
    const func_rva = r.readU32() orelse return ParseError.Truncated;
    const npt_rva = r.readU32() orelse return ParseError.Truncated;
    const ot_rva = r.readU32() orelse return ParseError.Truncated;

    ctx.export_count = num_functions;

    // Resolve DLL name (pointer into section data)
    if (name_rva != 0) {
        ctx.export_dll_name = readNamePtr(ctx, name_rva);
    }

    try parseEntries(ctx, func_rva, npt_rva, ot_rva, ordinal_base);
    resolveForwarders(ctx, export_dir.rva, export_dir.size);
}

// ── Additional export analysis ─────────────────────────────────

/// Verify export name table is sorted (required by PE spec)
pub fn verifyNameTableSort(ctx: *const PeCtx) bool {
    if (ctx.export_entries == null or ctx.export_count < 2) return true;
    const entries = ctx.export_entries.?;

    var prev_name: ?[*:0]u8 = null;
    var i: u32 = 0;
    while (i < ctx.export_count) : (i += 1) {
        if (!entries[i].has_name or entries[i].name == null) continue;
        if (prev_name) |pn| {
            const a = std.mem.span(pn);
            const b = std.mem.span(entries[i].name.?);
            // Names should be in ascending order
            if (std.mem.order(u8, a, b) == .gt) return false;
        }
        prev_name = entries[i].name;
    }
    return true;
}

/// Count export functions by type
pub fn countByType(ctx: *const PeCtx) struct { named: u32, ordinal_only: u32, forwarders: u32 } {
    var result = .{ .named = @as(u32, 0), .ordinal_only = @as(u32, 0), .forwarders = @as(u32, 0) };
    if (ctx.export_entries == null) return result;
    var i: u32 = 0;
    while (i < ctx.export_count) : (i += 1) {
        const e = &ctx.export_entries.?[i];
        if (e.function_rva == 0) continue;
        if (e.is_forwarder) { result.forwarders += 1; continue; }
        if (e.has_name) result.named += 1 else result.ordinal_only += 1;
    }
    return result;
}

/// Find ordinal gaps (unused ordinal slots)
pub fn countOrdinalGaps(ctx: *const PeCtx) u32 {
    if (ctx.export_entries == null) return 0;
    var gaps: u32 = 0;
    var i: u32 = 0;
    while (i < ctx.export_count) : (i += 1) {
        if (ctx.export_entries.?[i].function_rva == 0) gaps += 1;
    }
    return gaps;
}

/// Check if any exports reference sections outside the image
pub fn validateExportRvas(ctx: *const PeCtx) u32 {
    if (ctx.export_entries == null) return 0;
    var invalid: u32 = 0;
    var i: u32 = 0;
    while (i < ctx.export_count) : (i += 1) {
        const e = &ctx.export_entries.?[i];
        if (e.function_rva == 0 or e.is_forwarder) continue;
        if (rd.findSectionByRva(ctx, e.function_rva) == null) invalid += 1;
    }
    return invalid;
}

/// Get export function RVA by name
pub fn getRvaByName(ctx: *const PeCtx, name: []const u8) ?u32 {
    if (ctx.export_entries == null) return null;
    var i: u32 = 0;
    while (i < ctx.export_count) : (i += 1) {
        const e = &ctx.export_entries.?[i];
        if (e.has_name and e.name != null) {
            if (std.mem.eql(u8, std.mem.span(e.name.?), name))
                return e.function_rva;
        }
    }
    return null;
}

/// Analyze forwarder chain depth. Multiple levels of forwarding
/// may indicate unusual linking patterns.
pub fn analyzeForwarderTargets(ctx: *const PeCtx) u32 {
    if (ctx.export_entries == null) return 0;
    var unique_targets: u32 = 0;
    var i: u32 = 0;
    while (i < ctx.export_count) : (i += 1) {
        const e = &ctx.export_entries.?[i];
        if (!e.is_forwarder) continue;
        if (e.forwarder == null) continue;

        const fwd = std.mem.span(e.forwarder.?);
        // Extract DLL name from "DLL.Function" format
        var dot_pos: ?usize = null;
        for (fwd, 0..) |ch, idx| {
            if (ch == '.') { dot_pos = idx; break; }
        }
        if (dot_pos != null) unique_targets += 1;
    }
    return unique_targets;
}

// ── Export table utilities ──────────────────────────────────────

/// Compute export table hash for fingerprinting
pub fn computeExportHash(ctx: *const PeCtx) u64 {
    if (ctx.export_entries == null) return 0;
    var hash: u64 = 0xcbf29ce484222325;
    var i: u32 = 0;
    while (i < ctx.export_count) : (i += 1) {
        const e = &ctx.export_entries.?[i];
        if (e.name) |name| {
            const span = std.mem.span(name);
            for (span) |ch| {
                hash ^= ch;
                hash *%= 0x100000001b3;
            }
        }
        hash ^= @as(u8, @intCast(e.ordinal & 0xFF));
        hash *%= 0x100000001b3;
    }
    return hash;
}

/// Count exports with C++ mangled names
pub fn countMangledExports(ctx: *const PeCtx) u32 {
    if (ctx.export_entries == null) return 0;
    var count: u32 = 0;
    var i: u32 = 0;
    while (i < ctx.export_count) : (i += 1) {
        const e = &ctx.export_entries.?[i];
        if (e.name) |name| {
            if (name[0] == '?') count += 1;
        }
    }
    return count;
}

/// Count exports with C-decorated names (leading underscore)
pub fn countDecoratedExports(ctx: *const PeCtx) u32 {
    if (ctx.export_entries == null) return 0;
    var count: u32 = 0;
    var i: u32 = 0;
    while (i < ctx.export_count) : (i += 1) {
        const e = &ctx.export_entries.?[i];
        if (e.name) |name| {
            if (name[0] == '_') count += 1;
        }
    }
    return count;
}

/// Get ordinal range (min and max)
pub fn getOrdinalRange(ctx: *const PeCtx) struct { min: u16, max: u16 } {
    if (ctx.export_entries == null or ctx.export_count == 0)
        return .{ .min = 0, .max = 0 };
    var min_ord: u16 = 0xFFFF;
    var max_ord: u16 = 0;
    var i: u32 = 0;
    while (i < ctx.export_count) : (i += 1) {
        const ord = ctx.export_entries.?[i].ordinal;
        if (ord < min_ord) min_ord = ord;
        if (ord > max_ord) max_ord = ord;
    }
    return .{ .min = min_ord, .max = max_ord };
}

/// Count unique forwarder DLL targets
pub fn countForwarderDlls(ctx: *const PeCtx) u32 {
    if (ctx.export_entries == null) return 0;

    var seen: [64]u64 = [_]u64{0} ** 64;
    var seen_count: u32 = 0;

    var i: u32 = 0;
    while (i < ctx.export_count) : (i += 1) {
        const e = &ctx.export_entries.?[i];
        if (!e.is_forwarder or e.forwarder == null) continue;
        const fwd = std.mem.span(e.forwarder.?);
        // Extract DLL part and hash it
        var dot_pos: usize = 0;
        for (fwd, 0..) |ch, idx| {
            if (ch == '.') { dot_pos = idx; break; }
        }
        if (dot_pos == 0) continue;
        var dll_hash: u64 = 0;
        for (fwd[0..dot_pos]) |ch| {
            const lower: u8 = if (ch >= 'A' and ch <= 'Z') ch + 32 else ch;
            dll_hash = dll_hash *% 31 +% lower;
        }
        // Check if already seen
        var found = false;
        var j: u32 = 0;
        while (j < seen_count) : (j += 1) {
            if (seen[j] == dll_hash) { found = true; break; }
        }
        if (!found and seen_count < 64) {
            seen[seen_count] = dll_hash;
            seen_count += 1;
        }
    }
    return seen_count;
}
