// delay_import.zig — Delay Import Directory Parsing (Phase 7b)
//
// Parses delay-load import directory for DLLs loaded on demand.
// Supports both RVA-based (modern) and VA-based (legacy) addressing.

const std = @import("std");
const root = @import("root.zig");
const rd = @import("reader.zig");
const imp = @import("imports.zig");
const PeCtx = root.PeCtx;
const ParseError = root.ParseError;
const Reader = rd.Reader;

pub const DelayThunk = struct {
    is_ordinal: bool = false,
    ordinal: u16 = 0,
    hint: u16 = 0,
    name: ?[*:0]u8 = null,
};

pub const DelayDescriptor = struct {
    attributes: u32 = 0,
    name_rva: u32 = 0,
    module_handle_rva: u32 = 0,
    iat_rva: u32 = 0,
    int_rva: u32 = 0,
    bound_iat_rva: u32 = 0,
    unload_iat_rva: u32 = 0,
    timestamp: u32 = 0,
    dll_name: ?[*:0]u8 = null,
    thunks: ?[*]DelayThunk = null,
    num_thunks: u32 = 0,
    thunks_capacity: u32 = 0,
    name_section: u32 = 0xFFFFFFFF,
    iat_section: u32 = 0xFFFFFFFF,

    fn usesRva(self: *const DelayDescriptor) bool {
        return (self.attributes & 1) != 0;
    }

    fn toRva(self: *const DelayDescriptor, ctx: *const PeCtx, addr: u32) u32 {
        if (addr == 0) return 0;
        if (self.usesRva()) return addr;
        if (@as(u64, addr) >= ctx.optional_header.image_base) {
            return @intCast(@as(u64, addr) - ctx.optional_header.image_base);
        }
        return addr;
    }
};

fn parseDescriptor(r: *Reader, desc: *DelayDescriptor) ParseError!void {
    desc.* = DelayDescriptor{};
    desc.attributes = r.readU32() orelse return ParseError.Truncated;
    desc.name_rva = r.readU32() orelse return ParseError.Truncated;
    desc.module_handle_rva = r.readU32() orelse return ParseError.Truncated;
    desc.iat_rva = r.readU32() orelse return ParseError.Truncated;
    desc.int_rva = r.readU32() orelse return ParseError.Truncated;
    desc.bound_iat_rva = r.readU32() orelse return ParseError.Truncated;
    desc.unload_iat_rva = r.readU32() orelse return ParseError.Truncated;
    desc.timestamp = r.readU32() orelse return ParseError.Truncated;
}

fn resolveDllName(ctx: *PeCtx, desc: *const DelayDescriptor) ?[*:0]u8 {
    const name_rva = desc.toRva(ctx, desc.name_rva);
    if (name_rva == 0) return null;

    const ptr = ctx.rvaToPtr(name_rva, 1) orelse return null;
    var max_len = ctx.size - @as(usize, @intFromPtr(ptr) - @intFromPtr(ctx.data));
    if (max_len > 256) max_len = 256;

    var len: usize = 0;
    while (len < max_len and ptr[len] != 0) : (len += 1) {}

    const name = ctx.allocator.alloc(u8, len + 1) catch return null;
    @memcpy(name[0..len], ptr[0..len]);
    name[len] = 0;
    return @ptrCast(name.ptr);
}

fn parseDelayThunks(ctx: *PeCtx, desc: *DelayDescriptor) void {
    const int_rva = desc.toRva(ctx, desc.int_rva);
    if (int_rva == 0) return;

    const int_offset = ctx.rvaToOffset(int_rva) orelse return;
    const is_pe32plus = ctx.optional_header.is_pe32plus;

    var r = Reader.init(ctx.data, ctx.size);
    if (!r.seek(int_offset)) return;

    // Pre-allocate
    const initial_cap: u32 = 16;
    const thunks = ctx.allocator.alloc(DelayThunk, initial_cap) catch return;
    @memset(thunks, DelayThunk{});
    desc.thunks = thunks.ptr;
    desc.thunks_capacity = initial_cap;

    while (desc.num_thunks < root.MAX_THUNKS) {
        var thunk_val: u64 = 0;
        if (is_pe32plus) {
            thunk_val = r.readU64() orelse break;
        } else {
            thunk_val = r.readU32() orelse break;
        }
        if (thunk_val == 0) break;

        // Grow if needed
        if (desc.num_thunks >= desc.thunks_capacity) {
            const new_cap = desc.thunks_capacity * 2;
            const new_arr = ctx.allocator.alloc(DelayThunk, new_cap) catch break;
            @memcpy(new_arr[0..desc.num_thunks], desc.thunks.?[0..desc.num_thunks]);
            ctx.allocator.free(desc.thunks.?[0..desc.thunks_capacity]);
            desc.thunks = new_arr.ptr;
            desc.thunks_capacity = new_cap;
        }

        const thunk = &desc.thunks.?[desc.num_thunks];
        thunk.* = DelayThunk{};

        const ordinal_flag: u64 = if (is_pe32plus) 0x8000000000000000 else 0x80000000;
        if (thunk_val & ordinal_flag != 0) {
            thunk.is_ordinal = true;
            thunk.ordinal = @intCast(thunk_val & 0xFFFF);
        } else {
            var hn_rva: u32 = @intCast(thunk_val & 0x7FFFFFFF);
            hn_rva = desc.toRva(ctx, hn_rva);
            // Resolve hint/name - reuse import resolution
            const sec_idx = rd.findSectionByRva(ctx, hn_rva) orelse {
                desc.num_thunks += 1;
                continue;
            };
            const ptr = rd.sectionRvaToPtr(ctx, sec_idx, hn_rva, 3) orelse {
                desc.num_thunks += 1;
                continue;
            };
            thunk.hint = rd.readU16At(ptr);
            thunk.name = @ptrCast(ptr + 2);
        }

        desc.num_thunks += 1;
    }
}

fn validateDescriptor(ctx: *PeCtx, desc: *const DelayDescriptor) void {
    if (desc.name_rva == 0)
        ctx.addIssue(1, 0, "delay import: null DLL name RVA");
    if (desc.int_rva == 0 and desc.iat_rva == 0)
        ctx.addIssue(1, 0, "delay import: both INT and IAT null");
    if (desc.dll_name) |dll| {
        const name_len = std.mem.len(dll);
        if (name_len > 128) ctx.addIssue(1, 0, "delay import: DLL name too long");
        var has_ext = false;
        const span = std.mem.span(dll);
        for (span) |ch| {
            if (ch == '.') has_ext = true;
        }
        if (!has_ext) ctx.addIssue(1, 0, "delay import: no file extension");
    }
}

fn crossRefWithRegularImports(ctx: *PeCtx, descs: [*]DelayDescriptor, count: u32) void {
    if (count == 0 or ctx.import_descriptors == null or ctx.import_count == 0) return;
    const imp_descs = ctx.import_descriptors.?;

    var d: u32 = 0;
    while (d < count) : (d += 1) {
        if (descs[d].dll_name == null) continue;
        const delay_name = std.mem.span(descs[d].dll_name.?);
        var i: u32 = 0;
        while (i < ctx.import_count) : (i += 1) {
            if (imp_descs[i].dll_name == null) continue;
            const imp_name = std.mem.span(imp_descs[i].dll_name.?);
            if (std.mem.eql(u8, delay_name, imp_name)) {
                ctx.addIssue(1, 0, "delay import also in regular imports");
            }
        }
    }
}

fn mapToSections(ctx: *PeCtx, descs: [*]DelayDescriptor, count: u32) void {
    var d: u32 = 0;
    while (d < count) : (d += 1) {
        const desc = &descs[d];
        const name_rva = desc.toRva(ctx, desc.name_rva);
        if (name_rva != 0) {
            desc.name_section = rd.findSectionByRva(ctx, name_rva) orelse 0xFFFFFFFF;
        }
        const iat_rva = desc.toRva(ctx, desc.iat_rva);
        if (iat_rva != 0) {
            desc.iat_section = rd.findSectionByRva(ctx, iat_rva) orelse 0xFFFFFFFF;
        }
    }
}

pub fn parse(ctx: *PeCtx) ParseError!void {
    const delay_dir = &ctx.optional_header.data_dirs[root.DIR_DELAY_IMPORT];
    if (delay_dir.rva == 0 or delay_dir.size == 0) return;

    const dir_offset = ctx.rvaToOffset(delay_dir.rva) orelse return;
    var r = Reader.init(ctx.data, ctx.size);
    if (!r.seek(dir_offset)) return;

    var max_descs = delay_dir.size / 32;
    if (max_descs > root.MAX_IMPORTS) max_descs = root.MAX_IMPORTS;
    if (max_descs == 0) max_descs = 1;

    const descs = ctx.allocator.alloc(DelayDescriptor, max_descs) catch return;
    @memset(descs, DelayDescriptor{});

    var count: u32 = 0;
    while (count < max_descs) {
        if (r.remaining() < 32) break;

        const desc = &descs[count];
        parseDescriptor(&r, desc) catch break;

        if (desc.attributes == 0 and desc.name_rva == 0 and
            desc.iat_rva == 0 and desc.int_rva == 0) break;

        desc.dll_name = resolveDllName(ctx, desc);
        parseDelayThunks(ctx, desc);
        validateDescriptor(ctx, desc);
        count += 1;
    }

    if (count > 0) {
        crossRefWithRegularImports(ctx, descs.ptr, count);
        mapToSections(ctx, descs.ptr, count);
    }

    // Free (delay imports aren't stored in PeCtx currently)
    var d: u32 = 0;
    while (d < count) : (d += 1) {
        if (descs[d].dll_name) |n| ctx.allocator.free(std.mem.span(n));
        if (descs[d].thunks) |t| ctx.allocator.free(t[0..descs[d].thunks_capacity]);
    }
    ctx.allocator.free(descs);
}

// ── Delay import analysis ──────────────────────────────────────

/// Check if delay import uses RVA-based addressing
pub fn usesRvaAddressing(desc: *const DelayDescriptor) bool {
    return desc.usesRva();
}

/// Convert delay import address to RVA
pub fn toRva(ctx: *const PeCtx, desc: *const DelayDescriptor, addr: u32) u32 {
    return desc.toRva(ctx, addr);
}

/// Count total delay import thunks across all descriptors
pub fn countTotalDelayThunks(descs: []const DelayDescriptor) u32 {
    var total: u32 = 0;
    for (descs) |d| {
        total += d.num_thunks;
    }
    return total;
}

/// Count delay imports by ordinal
pub fn countDelayOrdinals(descs: []const DelayDescriptor) u32 {
    var count: u32 = 0;
    for (descs) |d| {
        if (d.thunks == null) continue;
        var t: u32 = 0;
        while (t < d.num_thunks) : (t += 1) {
            if (d.thunks.?[t].is_ordinal) count += 1;
        }
    }
    return count;
}

/// Find delay import descriptor by DLL name
pub fn findDelayDescByName(descs: []const DelayDescriptor, dll_name: []const u8) ?*const DelayDescriptor {
    for (descs) |*d| {
        if (d.dll_name) |dn| {
            if (std.mem.eql(u8, std.mem.span(dn), dll_name)) return d;
        }
    }
    return null;
}

/// Check for common delay-loaded DLLs
pub fn isCommonDelayDll(name: []const u8) bool {
    const common = [_][]const u8{
        "version.dll", "winspool.drv", "comdlg32.dll",
        "wininet.dll", "urlmon.dll", "shell32.dll",
        "shlwapi.dll", "crypt32.dll", "dbghelp.dll",
        "imagehlp.dll", "setupapi.dll", "wintrust.dll",
    };
    for (common) |c| {
        if (name.len == c.len) {
            var match = true;
            for (name, c) |a, b| {
                const la: u8 = if (a >= 'A' and a <= 'Z') a + 32 else a;
                if (la != b) { match = false; break; }
            }
            if (match) return true;
        }
    }
    return false;
}
