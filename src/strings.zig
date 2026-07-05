// strings.zig — COFF String Table Parsing (Phase 5)
//
// The string table immediately follows the symbol table and stores
// names longer than 8 bytes. First 4 bytes contain the total size.

const std = @import("std");
const root = @import("root.zig");
const rd = @import("reader.zig");
const PeCtx = root.PeCtx;
const ParseError = root.ParseError;

fn stringTableOffset(ctx: *const PeCtx) u32 {
    if (ctx.coff_header.symbol_table_offset == 0) return 0;
    return ctx.coff_header.symbol_table_offset +
        ctx.coff_header.num_symbols * 18;
}

fn indexStringEntries(ctx: *PeCtx) ParseError!void {
    const st = &ctx.string_table;
    if (st.size <= 4 or st.data == null) return;

    const data = st.data.?;
    // Count strings by scanning for null terminators
    var count: u32 = 0;
    var pos: u32 = 4;
    while (pos < st.size) : (pos += 1) {
        if (data[pos] == 0) count += 1;
    }
    if (count == 0) return;
    if (count > root.MAX_SYMBOLS) count = root.MAX_SYMBOLS;

    const entries = ctx.allocator.alloc(?[*:0]u8, count) catch
        return ParseError.OutOfMemory;
    @memset(entries, null);

    st.entries = entries.ptr;
    st.entries_capacity = count;

    // Second pass: record string start positions
    var idx: u32 = 0;
    pos = 4;
    var at_start = true;

    while (pos < st.size and idx < count) : (pos += 1) {
        if (at_start and data[pos] != 0) {
            st.entries.?[idx] = @ptrCast(data + pos);
            idx += 1;
            at_start = false;
        }
        if (data[pos] == 0) at_start = true;
    }

    st.num_entries = idx;
}

pub fn parse(ctx: *PeCtx) ParseError!void {
    const st_offset = stringTableOffset(ctx);
    if (st_offset == 0) return;

    if (!ctx.checkOffset(st_offset, 4)) {
        ctx.addWarning("string table offset beyond file");
        return ParseError.Truncated;
    }

    const st = &ctx.string_table;
    var total_size = rd.readU32At(ctx.data + st_offset);

    if (total_size < 4) total_size = 4;
    if (total_size > root.MAX_STRING_TABLE) total_size = root.MAX_STRING_TABLE;

    // Clamp to available file data
    var available: u32 = total_size;
    if (@as(u64, st_offset) + @as(u64, total_size) > ctx.size) {
        available = @intCast(ctx.size - st_offset);
    }

    // Allocate and copy string table data
    const data = ctx.allocator.alloc(u8, available) catch
        return ParseError.OutOfMemory;

    @memcpy(data, (ctx.data + st_offset)[0..available]);
    st.data = data.ptr;
    st.size = available;

    // Ensure null termination
    if (available > 0) {
        data[available - 1] = 0;
    }

    try indexStringEntries(ctx);
}

/// Rebuild string table from file data. Used during validation
/// when the table needs refresh after detected inconsistencies.
pub fn rebuild(ctx: *PeCtx) ParseError!void {
    // Save old data pointer — will free AFTER new allocation
    // to ensure the new buffer gets a different address
    const old_data = ctx.string_table.data;
    const old_size = ctx.string_table.size;
    const old_entries = ctx.string_table.entries;
    const old_ecap = ctx.string_table.entries_capacity;

    // Clear fields so parse allocates fresh
    ctx.string_table.data = null;
    ctx.string_table.size = 0;
    ctx.string_table.entries = null;
    ctx.string_table.num_entries = 0;
    ctx.string_table.entries_capacity = 0;

    // Allocate new string table
    parse(ctx) catch |e| {
        // Restore old on failure
        ctx.string_table.data = old_data;
        ctx.string_table.size = old_size;
        ctx.string_table.entries = old_entries;
        ctx.string_table.entries_capacity = old_ecap;
        return e;
    };

    // NOW free old data — new buffer occupies different pages
    if (old_data) |d| ctx.allocator.free(d[0..old_size]);
    if (old_entries) |e| ctx.allocator.free(e[0..old_ecap]);
}

/// Look up a string by byte offset in the string table
pub fn lookup(st: *const root.StringTable, offset: u32) ?[*:0]u8 {
    if (st.data == null) return null;
    if (offset >= st.size) return null;
    if (offset < 4) return null;
    return @ptrCast(st.data.? + offset);
}

pub fn freeTable(ctx: *PeCtx) void {
    const st = &ctx.string_table;
    if (st.data) |d| {
        ctx.allocator.free(d[0..st.size]);
        st.data = null;
    }
    st.size = 0;
    if (st.entries) |e| {
        ctx.allocator.free(e[0..st.entries_capacity]);
        st.entries = null;
    }
    st.num_entries = 0;
    st.entries_capacity = 0;
}

// ── Additional string table utilities ──────────────────────────

/// Count total strings in the table
pub fn countStrings(st: *const root.StringTable) u32 {
    return st.num_entries;
}

/// Get total string table size including header
pub fn totalSize(st: *const root.StringTable) u32 {
    return st.size;
}

/// Find a string by content (linear search)
pub fn findString(st: *const root.StringTable, target: []const u8) ?u32 {
    if (st.data == null or st.size <= 4) return null;
    const data = st.data.?;

    var pos: u32 = 4;
    while (pos < st.size) {
        const start = pos;
        while (pos < st.size and data[pos] != 0) : (pos += 1) {}
        if (pos > start) {
            const str_slice = data[start..pos];
            if (std.mem.eql(u8, str_slice, target)) return start;
        }
        pos += 1;
    }
    return null;
}

/// Get the average string length
pub fn avgStringLength(st: *const root.StringTable) f64 {
    if (st.entries == null or st.num_entries == 0) return 0.0;
    var total_len: u64 = 0;
    var i: u32 = 0;
    while (i < st.num_entries) : (i += 1) {
        if (st.entries.?[i]) |entry| {
            total_len += std.mem.len(entry);
        }
    }
    return @as(f64, @floatFromInt(total_len)) /
        @as(f64, @floatFromInt(st.num_entries));
}

/// Get the longest string length
pub fn maxStringLength(st: *const root.StringTable) u32 {
    if (st.entries == null or st.num_entries == 0) return 0;
    var max_len: u32 = 0;
    var i: u32 = 0;
    while (i < st.num_entries) : (i += 1) {
        if (st.entries.?[i]) |entry| {
            const len: u32 = @intCast(std.mem.len(entry));
            if (len > max_len) max_len = len;
        }
    }
    return max_len;
}

// ── String table analysis ──────────────────────────────────────

/// Check if string table is valid (properly null-terminated)
pub fn isValid(st: *const root.StringTable) bool {
    if (st.data == null or st.size <= 4) return true; // Empty is valid
    return st.data.?[st.size - 1] == 0;
}

/// Get the number of unique strings (excluding duplicates)
pub fn countUniqueStrings(st: *const root.StringTable) u32 {
    if (st.entries == null or st.num_entries < 2) return st.num_entries;

    // Simple O(n^2) uniqueness check
    var unique: u32 = 0;
    var i: u32 = 0;
    while (i < st.num_entries) : (i += 1) {
        if (st.entries.?[i] == null) continue;
        var is_dup = false;
        var j: u32 = 0;
        while (j < i) : (j += 1) {
            if (st.entries.?[j] == null) continue;
            if (std.mem.eql(u8, std.mem.span(st.entries.?[i].?),
                            std.mem.span(st.entries.?[j].?)))
            {
                is_dup = true;
                break;
            }
        }
        if (!is_dup) unique += 1;
    }
    return unique;
}

/// Compute total bytes used by string content (excluding null terminators)
pub fn totalContentBytes(st: *const root.StringTable) u64 {
    if (st.entries == null) return 0;
    var total: u64 = 0;
    var i: u32 = 0;
    while (i < st.num_entries) : (i += 1) {
        if (st.entries.?[i]) |entry| {
            total += std.mem.len(entry);
        }
    }
    return total;
}

/// Compute string table utilization (content bytes / total size)
pub fn utilization(st: *const root.StringTable) f64 {
    if (st.size <= 4) return 0.0;
    const content = totalContentBytes(st);
    return @as(f64, @floatFromInt(content)) / @as(f64, @floatFromInt(st.size - 4));
}

/// Check if any strings contain path separators
pub fn hasPathStrings(st: *const root.StringTable) bool {
    if (st.entries == null) return false;
    var i: u32 = 0;
    while (i < st.num_entries) : (i += 1) {
        if (st.entries.?[i]) |entry| {
            const span = std.mem.span(entry);
            for (span) |ch| {
                if (ch == '\\' or ch == '/') return true;
            }
        }
    }
    return false;
}
