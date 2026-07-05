// format.zig — Formatting Utilities
//
// Human-readable formatting for PE structures: characteristics,
// section flags, data directories, timestamps, GUIDs, hex dumps.

const std = @import("std");
const root = @import("root.zig");
const coff_mod = @import("coff.zig");

pub fn getMachineName(machine: u16) []const u8 {
    return coff_mod.getMachineName(machine);
}

pub fn getSubsystemName(subsystem: u16) []const u8 {
    return switch (subsystem) {
        0 => "Unknown", 1 => "Native", 2 => "Windows GUI",
        3 => "Windows Console", 7 => "POSIX Console",
        9 => "Windows CE", 10 => "EFI Application",
        else => "Other",
    };
}

pub fn getDebugTypeName(debug_type: u32) []const u8 {
    return switch (debug_type) {
        0 => "Unknown", 1 => "COFF", 2 => "CodeView",
        3 => "FPO", 4 => "Misc", 9 => "Borland",
        13 => "POGO", 16 => "Repro",
        else => "Other",
    };
}

pub fn getResourceTypeName(type_id: u32) []const u8 {
    return switch (type_id) {
        1 => "Cursor", 2 => "Bitmap", 3 => "Icon",
        4 => "Menu", 5 => "Dialog", 6 => "String",
        7 => "FontDir", 8 => "Font", 9 => "Accelerator",
        10 => "RCData", 11 => "MessageTable",
        12 => "GroupCursor", 14 => "GroupIcon",
        16 => "Version", 24 => "Manifest",
        else => "Unknown",
    };
}

pub fn getDataDirName(index: u32) []const u8 {
    return switch (index) {
        0 => "Export", 1 => "Import", 2 => "Resource",
        3 => "Exception", 4 => "Security", 5 => "Base Reloc",
        6 => "Debug", 7 => "Architecture", 8 => "Global Ptr",
        9 => "TLS", 10 => "Load Config", 11 => "Bound Import",
        12 => "IAT", 13 => "Delay Import", 14 => "CLR Runtime",
        15 => "Reserved",
        else => "Unknown",
    };
}

pub fn getSymbolClassName(class: u8) []const u8 {
    return switch (class) {
        0 => "NULL", 2 => "EXTERNAL", 3 => "STATIC",
        6 => "LABEL", 101 => "FUNCTION", 103 => "FILE",
        104 => "SECTION", 105 => "WEAK_EXTERNAL",
        else => "OTHER",
    };
}

pub fn getRelocTypeName(rel_type: u16) []const u8 {
    return switch (rel_type) {
        0 => "ABSOLUTE", 1 => "HIGH", 2 => "LOW",
        3 => "HIGHLOW", 4 => "HIGHADJ", 10 => "DIR64",
        else => "UNKNOWN",
    };
}

/// Format characteristics flags as comma-separated list
pub fn formatCharacteristics(chars: u16, buf: []u8) usize {
    var pos: usize = 0;
    const flags = [_]struct { bit: u16, name: []const u8 }{
        .{ .bit = 0x0001, .name = "RELOCS_STRIPPED" },
        .{ .bit = 0x0002, .name = "EXECUTABLE" },
        .{ .bit = 0x0020, .name = "LARGE_ADDRESS" },
        .{ .bit = 0x0100, .name = "32BIT" },
        .{ .bit = 0x2000, .name = "DLL" },
        .{ .bit = 0x0200, .name = "DEBUG_STRIPPED" },
    };

    for (flags) |f| {
        if (chars & f.bit != 0) {
            if (pos > 0 and pos + 2 < buf.len) {
                buf[pos] = ',';
                buf[pos + 1] = ' ';
                pos += 2;
            }
            const copy_len = @min(f.name.len, buf.len - pos);
            @memcpy(buf[pos..][0..copy_len], f.name[0..copy_len]);
            pos += copy_len;
        }
    }
    return pos;
}

/// Format section characteristics
pub fn formatSectionFlags(chars: u32, buf: []u8) usize {
    var pos: usize = 0;
    const flags = [_]struct { bit: u32, name: []const u8 }{
        .{ .bit = root.SCN_CNT_CODE, .name = "CODE" },
        .{ .bit = root.SCN_CNT_INIT_DATA, .name = "INIT_DATA" },
        .{ .bit = root.SCN_CNT_UNINIT_DATA, .name = "UNINIT_DATA" },
        .{ .bit = root.SCN_MEM_EXECUTE, .name = "EXEC" },
        .{ .bit = root.SCN_MEM_READ, .name = "READ" },
        .{ .bit = root.SCN_MEM_WRITE, .name = "WRITE" },
        .{ .bit = root.SCN_MEM_DISCARDABLE, .name = "DISCARD" },
    };

    for (flags) |f| {
        if (chars & f.bit != 0) {
            if (pos > 0 and pos + 2 < buf.len) {
                buf[pos] = ',';
                buf[pos + 1] = ' ';
                pos += 2;
            }
            const copy_len = @min(f.name.len, buf.len - pos);
            @memcpy(buf[pos..][0..copy_len], f.name[0..copy_len]);
            pos += copy_len;
        }
    }
    return pos;
}

/// Format DLL characteristics
pub fn formatDllCharacteristics(chars: u16, buf: []u8) usize {
    var pos: usize = 0;
    const flags = [_]struct { bit: u16, name: []const u8 }{
        .{ .bit = 0x0020, .name = "HIGH_ENTROPY_VA" },
        .{ .bit = 0x0040, .name = "DYNAMIC_BASE" },
        .{ .bit = 0x0080, .name = "FORCE_INTEGRITY" },
        .{ .bit = 0x0100, .name = "NX_COMPAT" },
        .{ .bit = 0x0200, .name = "NO_ISOLATION" },
        .{ .bit = 0x0400, .name = "NO_SEH" },
        .{ .bit = 0x1000, .name = "APPCONTAINER" },
        .{ .bit = 0x4000, .name = "GUARD_CF" },
        .{ .bit = 0x8000, .name = "TERMINAL_SERVER" },
    };

    for (flags) |f| {
        if (chars & f.bit != 0) {
            if (pos > 0 and pos + 2 < buf.len) {
                buf[pos] = ',';
                buf[pos + 1] = ' ';
                pos += 2;
            }
            const copy_len = @min(f.name.len, buf.len - pos);
            @memcpy(buf[pos..][0..copy_len], f.name[0..copy_len]);
            pos += copy_len;
        }
    }
    return pos;
}

/// Format a GUID as a string
pub fn formatGuid(guid: [16]u8, buf: []u8) usize {
    if (buf.len < 36) return 0;
    const hex = "0123456789ABCDEF";
    var pos: usize = 0;

    // Format as {8-4-4-4-12}
    const pattern = [_]u8{ 3, 2, 1, 0, 0xFF, 5, 4, 0xFF, 7, 6, 0xFF, 8, 9, 0xFF, 10, 11, 12, 13, 14, 15 };
    for (pattern) |idx| {
        if (idx == 0xFF) {
            buf[pos] = '-';
            pos += 1;
        } else {
            buf[pos] = hex[guid[idx] >> 4];
            buf[pos + 1] = hex[guid[idx] & 0xF];
            pos += 2;
        }
    }
    return pos;
}

/// Format hex dump of data (up to 64 bytes shown)
pub fn formatHexDump(data: [*]const u8, len: usize, buf: []u8) usize {
    const hex = "0123456789abcdef";
    var pos: usize = 0;
    const show_len = @min(len, 64);

    var i: usize = 0;
    while (i < show_len and pos + 3 < buf.len) : (i += 1) {
        if (i > 0) {
            buf[pos] = ' ';
            pos += 1;
        }
        buf[pos] = hex[data[i] >> 4];
        buf[pos + 1] = hex[data[i] & 0xF];
        pos += 2;
    }

    if (len > 64 and pos + 4 < buf.len) {
        buf[pos] = ' ';
        buf[pos + 1] = '.';
        buf[pos + 2] = '.';
        buf[pos + 3] = '.';
        pos += 4;
    }

    return pos;
}

// ── Extended formatting ────────────────────────────────────────

/// Format file size in human-readable form (B/KB/MB)
pub fn formatFileSize(size: u64, buf: []u8) usize {
    if (buf.len < 8) return 0;
    if (size < 1024) {
        return writeU64(size, buf) + writeLiteral(" B", buf[writeU64(size, buf)..]);
    } else if (size < 1024 * 1024) {
        const kb = size / 1024;
        const pos = writeU64(kb, buf);
        return pos + writeLiteral(" KB", buf[pos..]);
    } else {
        const mb = size / (1024 * 1024);
        const pos = writeU64(mb, buf);
        return pos + writeLiteral(" MB", buf[pos..]);
    }
}

fn writeU64(val: u64, buf: []u8) usize {
    if (buf.len == 0) return 0;
    if (val == 0) { buf[0] = '0'; return 1; }
    var tmp: [20]u8 = undefined;
    var len: usize = 0;
    var v = val;
    while (v > 0) : (v /= 10) {
        tmp[len] = @intCast('0' + v % 10);
        len += 1;
    }
    const copy = @min(len, buf.len);
    var i: usize = 0;
    while (i < copy) : (i += 1) {
        buf[i] = tmp[len - 1 - i];
    }
    return copy;
}

fn writeLiteral(literal: []const u8, buf: []u8) usize {
    const copy = @min(literal.len, buf.len);
    @memcpy(buf[0..copy], literal[0..copy]);
    return copy;
}

/// Format an RVA as "0xNNNNNNNN"
pub fn formatRva(rva: u32, buf: []u8) usize {
    if (buf.len < 10) return 0;
    const hex = "0123456789ABCDEF";
    buf[0] = '0';
    buf[1] = 'x';
    var i: usize = 0;
    while (i < 8) : (i += 1) {
        const shift: u5 = @intCast((7 - i) * 4);
        buf[2 + i] = hex[@intCast((rva >> shift) & 0xF)];
    }
    return 10;
}

/// Format a u64 as "0xNNNNNNNNNNNNNNNN"
pub fn formatAddress(addr: u64, buf: []u8) usize {
    if (buf.len < 18) return 0;
    const hex = "0123456789ABCDEF";
    buf[0] = '0';
    buf[1] = 'x';
    var i: usize = 0;
    while (i < 16) : (i += 1) {
        const shift: u6 = @intCast((15 - i) * 4);
        buf[2 + i] = hex[@intCast((addr >> shift) & 0xF)];
    }
    return 18;
}

/// Format timestamp as ISO-like date (simplified — no timezone)
pub fn formatTimestamp(timestamp: u32, buf: []u8) usize {
    if (buf.len < 19 or timestamp == 0) return 0;

    // Simplified Unix timestamp to date conversion
    const t: u64 = timestamp;
    const secs_per_day: u64 = 86400;
    const days = t / secs_per_day;
    const time_of_day = t % secs_per_day;

    const hours = time_of_day / 3600;
    const minutes = (time_of_day % 3600) / 60;
    const seconds = time_of_day % 60;

    // Simplified year/month/day (good enough for display)
    var remaining_days = days;
    var year: u32 = 1970;
    while (remaining_days >= 365) {
        const is_leap: u64 = if (year % 4 == 0 and (year % 100 != 0 or year % 400 == 0)) 1 else 0;
        const year_days: u64 = 365 + is_leap;
        if (remaining_days < year_days) break;
        remaining_days -= year_days;
        year += 1;
    }

    const month: u32 = @intCast(remaining_days / 30 + 1);
    const day: u32 = @intCast(remaining_days % 30 + 1);

    // Format: YYYY-MM-DD HH:MM:SS
    var pos: usize = 0;
    pos += writeU64(year, buf[pos..]);
    buf[pos] = '-'; pos += 1;
    if (month < 10) { buf[pos] = '0'; pos += 1; }
    pos += writeU64(month, buf[pos..]);
    buf[pos] = '-'; pos += 1;
    if (day < 10) { buf[pos] = '0'; pos += 1; }
    pos += writeU64(day, buf[pos..]);
    buf[pos] = ' '; pos += 1;
    if (hours < 10) { buf[pos] = '0'; pos += 1; }
    pos += writeU64(hours, buf[pos..]);
    buf[pos] = ':'; pos += 1;
    if (minutes < 10) { buf[pos] = '0'; pos += 1; }
    pos += writeU64(minutes, buf[pos..]);
    buf[pos] = ':'; pos += 1;
    if (seconds < 10) { buf[pos] = '0'; pos += 1; }
    pos += writeU64(seconds, buf[pos..]);

    return pos;
}

/// Get import ordinal description for known DLLs
pub fn getKnownOrdinalName(dll_name: []const u8, ordinal: u16) ?[]const u8 {
    // Common ws2_32.dll ordinals
    if (std.mem.eql(u8, dll_name, "ws2_32.dll") or
        std.mem.eql(u8, dll_name, "WS2_32.dll"))
    {
        return switch (ordinal) {
            1 => "accept",
            2 => "bind",
            3 => "closesocket",
            4 => "connect",
            9 => "getpeername",
            10 => "getsockname",
            11 => "getsockopt",
            16 => "listen",
            18 => "recv",
            19 => "recvfrom",
            20 => "select",
            21 => "send",
            22 => "sendto",
            23 => "setsockopt",
            115 => "WSAStartup",
            116 => "WSACleanup",
            else => null,
        };
    }
    return null;
}

/// Format section permissions as "RWX" string
pub fn formatPermissions(chars: u32, buf: []u8) usize {
    if (buf.len < 3) return 0;
    buf[0] = if (chars & root.SCN_MEM_READ != 0) 'R' else '-';
    buf[1] = if (chars & root.SCN_MEM_WRITE != 0) 'W' else '-';
    buf[2] = if (chars & root.SCN_MEM_EXECUTE != 0) 'X' else '-';
    return 3;
}

// ── Additional formatters ──────────────────────────────────────

/// Format import thunk as "DLL!Function" or "DLL!#ordinal"
pub fn formatImportThunk(dll_name: ?[*:0]const u8, thunk: *const root.ImportThunk,
                          buf: []u8) usize {
    var pos: usize = 0;
    if (dll_name) |dll| {
        const span = std.mem.span(dll);
        const copy = @min(span.len, buf.len - 2);
        @memcpy(buf[0..copy], span[0..copy]);
        pos += copy;
    }
    if (pos < buf.len) { buf[pos] = '!'; pos += 1; }

    if (thunk.is_ordinal) {
        if (pos < buf.len) { buf[pos] = '#'; pos += 1; }
        pos += writeU64(thunk.ordinal, buf[pos..]);
    } else if (thunk.name) |name| {
        const span = std.mem.span(name);
        const copy = @min(span.len, buf.len - pos);
        @memcpy(buf[pos..][0..copy], span[0..copy]);
        pos += copy;
    }
    return pos;
}

/// Format export entry as "name (ordinal N)" or "ordinal N"
pub fn formatExportEntry(entry: *const root.ExportEntry, buf: []u8) usize {
    var pos: usize = 0;
    if (entry.has_name and entry.name != null) {
        const span = std.mem.span(entry.name.?);
        const copy = @min(span.len, buf.len - 20);
        @memcpy(buf[0..copy], span[0..copy]);
        pos += copy;
        pos += writeLiteral(" (ord ", buf[pos..]);
        pos += writeU64(entry.ordinal, buf[pos..]);
        if (pos < buf.len) { buf[pos] = ')'; pos += 1; }
    } else {
        pos += writeLiteral("ordinal ", buf[pos..]);
        pos += writeU64(entry.ordinal, buf[pos..]);
    }

    if (entry.is_forwarder and entry.forwarder != null) {
        pos += writeLiteral(" -> ", buf[pos..]);
        const fwd = std.mem.span(entry.forwarder.?);
        const copy = @min(fwd.len, buf.len - pos);
        @memcpy(buf[pos..][0..copy], fwd[0..copy]);
        pos += copy;
    }
    return pos;
}

/// Format validation issue as "severity: message"
pub fn formatIssue(issue: *const root.ValidationIssue, buf: []u8) usize {
    var pos: usize = 0;
    const sev_str: []const u8 = switch (issue.severity) {
        0 => "INFO",
        1 => "WARN",
        2 => "ERROR",
        else => "CRIT",
    };
    pos += writeLiteral(sev_str, buf[pos..]);
    pos += writeLiteral(": ", buf[pos..]);

    const msg = std.mem.sliceTo(&issue.message, 0);
    const copy = @min(msg.len, buf.len - pos);
    @memcpy(buf[pos..][0..copy], msg[0..copy]);
    pos += copy;
    return pos;
}

/// Format a section summary line
pub fn formatSectionSummary(sec: *const root.Section, index: u32, buf: []u8) usize {
    var pos: usize = 0;
    pos += writeLiteral("[", buf[pos..]);
    pos += writeU64(index, buf[pos..]);
    pos += writeLiteral("] ", buf[pos..]);

    const name = std.mem.sliceTo(&sec.short_name, 0);
    const name_copy = @min(name.len, buf.len - pos - 20);
    @memcpy(buf[pos..][0..name_copy], name[0..name_copy]);
    pos += name_copy;

    pos += writeLiteral(" VA=", buf[pos..]);
    pos += formatRva(sec.virtual_address, buf[pos..]);
    pos += writeLiteral(" Raw=", buf[pos..]);
    pos += writeU64(sec.raw_data_size, buf[pos..]);

    // Permissions
    pos += writeLiteral(" ", buf[pos..]);
    pos += formatPermissions(sec.characteristics, buf[pos..]);

    return pos;
}
