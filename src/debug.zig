// debug.zig — Debug Directory Parsing (Phase 10)
//
// Parses the debug directory containing entries for CodeView,
// COFF debug info, FPO data, and reproducible build markers.
// CodeView entries contain PDB path information.

const std = @import("std");
const root = @import("root.zig");
const rd = @import("reader.zig");
const PeCtx = root.PeCtx;
const ParseError = root.ParseError;
const Reader = rd.Reader;

/// Parse CodeView debug data at given file offset
fn parseCodeview(ctx: *PeCtx, offset: u32, size: u32) ?*root.CodeviewInfo {
    if (size < 24 or !ctx.checkOffset(offset, size)) return null;

    const cv = ctx.allocator.create(root.CodeviewInfo) catch return null;
    cv.* = root.CodeviewInfo{};

    var r = Reader.init(ctx.data, ctx.size);
    if (!r.seek(offset)) {
        ctx.allocator.destroy(cv);
        return null;
    }

    cv.cv_signature = r.readU32() orelse {
        ctx.allocator.destroy(cv);
        return null;
    };

    // Validate CV signature (RSDS = 0x53445352 for PDB 7.0)
    if (cv.cv_signature != 0x53445352 and cv.cv_signature != 0x3031424E) {
        ctx.addWarning("unknown CodeView signature");
    }

    if (!r.readBytes(&cv.guid)) {
        ctx.allocator.destroy(cv);
        return null;
    }

    cv.age = r.readU32() orelse {
        ctx.allocator.destroy(cv);
        return null;
    };

    // PDB path is remaining bytes as null-terminated string
    const path_len = size - 24;
    if (path_len > 0 and path_len < 512) {
        const path = ctx.allocator.alloc(u8, path_len + 1) catch {
            ctx.allocator.destroy(cv);
            return null;
        };
        if (!r.readBytes(path[0..path_len])) {
            ctx.allocator.free(path);
            ctx.allocator.destroy(cv);
            return null;
        }
        path[path_len] = 0;

        // Validate PDB path contains reasonable characters
        var valid = true;
        for (path[0..path_len]) |ch| {
            if (ch == 0) break;
            if (ch < 0x20 or ch > 0x7E) {
                if (ch != '\\' and ch != '/') {
                    valid = false;
                    break;
                }
            }
        }

        if (valid) {
            cv.pdb_path = @ptrCast(path.ptr);
        } else {
            ctx.allocator.free(path);
            ctx.addWarning("CodeView PDB path contains invalid characters");
        }
    }
    return cv;
}

/// Validate a debug entry
fn validateEntry(ctx: *PeCtx, entry: *root.DebugEntry, index: u32) void {
    // Check data offset bounds
    if (entry.raw_data_offset > 0 and
        @as(u64, entry.raw_data_offset) + @as(u64, entry.data_size) > ctx.size)
    {
        ctx.addIssue(1, 0, "debug entry data extends beyond file");
    }

    // Check section mapping
    if (entry.address_rva != 0 and entry.section_index < 0) {
        ctx.addIssue(1, 0, "debug entry RVA does not map to any section");
    }

    // Validate timestamp relationship with COFF header
    if (entry.timestamp != 0 and ctx.coff_header.timestamp != 0) {
        var drift: i64 = @as(i64, entry.timestamp) -
            @as(i64, ctx.coff_header.timestamp);
        if (drift < 0) drift = -drift;
        if (@as(u64, @intCast(drift)) > 86400 * 365 * 10) {
            ctx.addIssue(1, 0, "debug entry timestamp drift > 10 years");
        }
    }

    // CodeView-specific validation
    if (entry.codeview) |cv| {
        if (cv.age == 0) {
            ctx.addWarning("CodeView age is zero");
        }
        if (cv.pdb_path) |path| {
            const path_len = std.mem.len(path);
            if (path_len > 260) {
                ctx.addIssue(1, 0, "PDB path exceeds MAX_PATH");
            }
            // Check for relative vs absolute path
            const span = std.mem.span(path);
            if (span.len > 1 and span[1] != ':' and span[0] != '\\') {
                ctx.addWarning("PDB path is relative");
            }
        }
    }

    _ = index;
}

/// Count CodeView entries
pub fn countCodeviewEntries(ctx: *const PeCtx) u32 {
    if (ctx.debug_entries == null) return 0;
    var count: u32 = 0;
    var i: u32 = 0;
    while (i < ctx.debug_count) : (i += 1) {
        if (ctx.debug_entries.?[i].debug_type == root.DEBUG_TYPE_CODEVIEW) count += 1;
    }
    return count;
}

/// Count entries with reproducible build markers
pub fn countReproEntries(ctx: *const PeCtx) u32 {
    if (ctx.debug_entries == null) return 0;
    var count: u32 = 0;
    var i: u32 = 0;
    while (i < ctx.debug_count) : (i += 1) {
        if (ctx.debug_entries.?[i].debug_type == root.DEBUG_TYPE_REPRO) count += 1;
    }
    return count;
}

/// Get PDB path from first CodeView entry
pub fn getFirstPdbPath(ctx: *const PeCtx) ?[*:0]const u8 {
    if (ctx.debug_entries == null) return null;
    var i: u32 = 0;
    while (i < ctx.debug_count) : (i += 1) {
        const entry = &ctx.debug_entries.?[i];
        if (entry.debug_type == root.DEBUG_TYPE_CODEVIEW) {
            if (entry.codeview) |cv| return cv.pdb_path;
        }
    }
    return null;
}

pub fn parse(ctx: *PeCtx) ParseError!void {
    const debug_dir = &ctx.optional_header.data_dirs[root.DIR_DEBUG];
    if (debug_dir.rva == 0 or debug_dir.size == 0) return;

    const dir_offset = ctx.rvaToOffset(debug_dir.rva) orelse return;
    const num_entries = debug_dir.size / 28;
    if (num_entries == 0 or num_entries > root.MAX_DEBUG_ENTRIES) return;

    const entries = ctx.allocator.alloc(root.DebugEntry, num_entries) catch
        return ParseError.OutOfMemory;
    @memset(entries, root.DebugEntry{});
    ctx.debug_entries = entries.ptr;
    ctx.debug_count = @intCast(num_entries);
    ctx.debug_capacity = @intCast(num_entries);

    var r = Reader.init(ctx.data, ctx.size);
    if (!r.seek(dir_offset)) return;

    var i: u32 = 0;
    while (i < num_entries) : (i += 1) {
        const e = &entries[i];
        e.characteristics = r.readU32() orelse break;
        e.timestamp = r.readU32() orelse break;
        e.major_version = r.readU16() orelse break;
        e.minor_version = r.readU16() orelse break;
        e.debug_type = r.readU32() orelse break;
        e.data_size = r.readU32() orelse break;
        e.address_rva = r.readU32() orelse break;
        e.raw_data_offset = r.readU32() orelse break;

        // Parse CodeView data
        if (e.debug_type == root.DEBUG_TYPE_CODEVIEW and
            e.raw_data_offset > 0 and e.data_size > 0)
        {
            e.codeview = parseCodeview(ctx, e.raw_data_offset, e.data_size);
        }

        // Map to section
        if (e.address_rva != 0) {
            if (rd.findSectionByRva(ctx, e.address_rva)) |sec_idx| {
                e.section_index = @intCast(sec_idx);
            }
        }

        validateEntry(ctx, e, i);
    }
}

// ── Additional debug analysis ──────────────────────────────────

/// Check if debug info indicates a reproducible build
pub fn isReproducibleBuild(ctx: *const PeCtx) bool {
    if (ctx.debug_entries == null) return false;
    var i: u32 = 0;
    while (i < ctx.debug_count) : (i += 1) {
        if (ctx.debug_entries.?[i].debug_type == root.DEBUG_TYPE_REPRO) return true;
    }
    return false;
}

/// Get CodeView signature type as string
pub fn getCodeviewSigName(sig: u32) []const u8 {
    return switch (sig) {
        0x53445352 => "RSDS (PDB 7.0)",
        0x3031424E => "NB10 (PDB 2.0)",
        0x3130424E => "NB10 (alternate)",
        else => "Unknown",
    };
}

/// Check if PDB path is a local path (contains drive letter)
pub fn isPdbLocal(pdb_path: ?[*:0]const u8) bool {
    if (pdb_path == null) return false;
    const span = std.mem.span(pdb_path.?);
    if (span.len > 1 and span[1] == ':') return true;
    return false;
}

/// Check if PDB path is a UNC path
pub fn isPdbUnc(pdb_path: ?[*:0]const u8) bool {
    if (pdb_path == null) return false;
    const span = std.mem.span(pdb_path.?);
    if (span.len > 2 and span[0] == '\\' and span[1] == '\\') return true;
    return false;
}

/// Extract just the filename from a PDB path
pub fn getPdbFilename(pdb_path: ?[*:0]const u8) ?[]const u8 {
    if (pdb_path == null) return null;
    const span = std.mem.span(pdb_path.?);
    var last_sep: usize = 0;
    for (span, 0..) |ch, idx| {
        if (ch == '\\' or ch == '/') last_sep = idx + 1;
    }
    if (last_sep < span.len) return span[last_sep..];
    return span;
}

/// Compute total debug data size
pub fn totalDebugDataSize(ctx: *const PeCtx) u64 {
    if (ctx.debug_entries == null) return 0;
    var total: u64 = 0;
    var i: u32 = 0;
    while (i < ctx.debug_count) : (i += 1) {
        total += ctx.debug_entries.?[i].data_size;
    }
    return total;
}

// ── Debug directory statistics ─────────────────────────────────

/// Classify debug entries by type
pub fn classifyDebugEntries(ctx: *const PeCtx) struct {
    codeview: u32, coff: u32, fpo: u32, misc: u32,
    repro: u32, pogo: u32, other: u32,
} {
    var result: @TypeOf(classifyDebugEntries(undefined)) = undefined;
    @memset(std.mem.asBytes(&result), 0);

    if (ctx.debug_entries == null) return result;
    var i: u32 = 0;
    while (i < ctx.debug_count) : (i += 1) {
        switch (ctx.debug_entries.?[i].debug_type) {
            2 => result.codeview += 1,
            1 => result.coff += 1,
            3 => result.fpo += 1,
            4 => result.misc += 1,
            16 => result.repro += 1,
            13 => result.pogo += 1,
            else => result.other += 1,
        }
    }
    return result;
}

/// Check if all debug entries have matching timestamps
pub fn hasConsistentTimestamps(ctx: *const PeCtx) bool {
    if (ctx.debug_entries == null or ctx.debug_count < 2) return true;
    const first_ts = ctx.debug_entries.?[0].timestamp;
    var i: u32 = 1;
    while (i < ctx.debug_count) : (i += 1) {
        if (ctx.debug_entries.?[i].timestamp != first_ts) return false;
    }
    return true;
}

/// Get total raw data size across all debug entries
pub fn totalRawDebugSize(ctx: *const PeCtx) u64 {
    if (ctx.debug_entries == null) return 0;
    var total: u64 = 0;
    var i: u32 = 0;
    while (i < ctx.debug_count) : (i += 1) {
        total += ctx.debug_entries.?[i].data_size;
    }
    return total;
}

/// Check if debug directory has POGO (profile guided optimization) data
pub fn hasPogoData(ctx: *const PeCtx) bool {
    if (ctx.debug_entries == null) return false;
    var i: u32 = 0;
    while (i < ctx.debug_count) : (i += 1) {
        if (ctx.debug_entries.?[i].debug_type == 13) return true;
    }
    return false;
}

/// Count debug entries with data in the file
pub fn countWithFileData(ctx: *const PeCtx) u32 {
    if (ctx.debug_entries == null) return 0;
    var count: u32 = 0;
    var i: u32 = 0;
    while (i < ctx.debug_count) : (i += 1) {
        if (ctx.debug_entries.?[i].raw_data_offset != 0 and
            ctx.debug_entries.?[i].data_size > 0) count += 1;
    }
    return count;
}
