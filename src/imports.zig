// imports.zig — Import Table Parsing (Phase 7)
//
// Parses import directory table and ILT entries. Each descriptor
// references a DLL name and imported functions by name or ordinal.
// Import names are resolved as pointers into section data buffers.

const std = @import("std");
const root = @import("root.zig");
const rd = @import("reader.zig");
const PeCtx = root.PeCtx;
const ParseError = root.ParseError;
const Reader = rd.Reader;

/// Read null-terminated string at RVA, returning allocated copy
fn readStringAtRva(ctx: *PeCtx, rva: u32) ?[*:0]u8 {
    const offset = ctx.rvaToOffset(rva) orelse return null;
    if (offset >= ctx.size) return null;

    var max_len = ctx.size - offset;
    if (max_len > 512) max_len = 512;

    const start = ctx.data + offset;
    var len: usize = 0;
    while (len < max_len and start[len] != 0) : (len += 1) {}

    const str = ctx.allocator.alloc(u8, len + 1) catch return null;
    @memcpy(str[0..len], start[0..len]);
    str[len] = 0;
    return @ptrCast(str.ptr);
}

/// Resolve hint/name table entry from RVA. Returns pointer into
/// section data buffer (not a copy). The hint is a 2-byte ordinal
/// hint preceding the name string.
fn resolveHintName(ctx: *PeCtx, rva: u32, hint_out: *u16) ?[*:0]u8 {
    const sec_idx = rd.findSectionByRva(ctx, rva) orelse return null;
    const ptr = rd.sectionRvaToPtr(ctx, sec_idx, rva, 3) orelse return null;

    hint_out.* = rd.readU16At(ptr);
    const name_ptr: [*]u8 = ptr + 2;

    // Verify null termination within section bounds
    if (ctx.section_entries) |entries| {
        const sec = &entries[sec_idx];
        const delta = rva - sec.virtual_address;
        if (delta + 2 >= sec.data_size) return null;
        const remaining = sec.data_size - delta - 2;
        var name_len: usize = 0;
        while (name_len < remaining and name_ptr[name_len] != 0) : (name_len += 1) {}
        if (name_len >= remaining) return null;
    }

    return @ptrCast(name_ptr);
}

fn parseThunks(ctx: *PeCtx, desc: *root.ImportDescriptor, is_pe32plus: bool) ParseError!void {
    if (desc.ilt_rva == 0) return;

    const ilt_offset = ctx.rvaToOffset(desc.ilt_rva) orelse return ParseError.InvalidImport;
    const entry_size: usize = if (is_pe32plus) 8 else 4;

    // Count entries
    var count: u32 = 0;
    var scan_pos: usize = ilt_offset;
    while (ctx.checkOffset(@intCast(scan_pos), @intCast(entry_size)) and
        count < root.MAX_THUNKS)
    {
        var val: u64 = 0;
        if (entry_size == 8) {
            val = rd.readU64At(ctx.data + scan_pos);
        } else {
            val = rd.readU32At(ctx.data + scan_pos);
        }
        if (val == 0) break;
        count += 1;
        scan_pos += entry_size;
    }

    if (count == 0) return;

    const thunks = ctx.allocator.alloc(root.ImportThunk, count) catch
        return ParseError.OutOfMemory;
    @memset(thunks, root.ImportThunk{});
    desc.thunks = thunks.ptr;
    desc.thunks_capacity = count;

    var r = Reader.init(ctx.data, ctx.size);
    if (!r.seek(ilt_offset)) return;

    var i: u32 = 0;
    while (i < count) : (i += 1) {
        const thunk = &thunks[i];
        if (is_pe32plus) {
            const val = r.readU64() orelse break;
            thunk.thunk_rva = @intCast(val & 0x7FFFFFFF);
            if (val & 0x8000000000000000 != 0) {
                thunk.is_ordinal = true;
                thunk.ordinal = @intCast(val & 0xFFFF);
            } else {
                const hn_rva: u32 = @intCast(val & 0x7FFFFFFF);
                thunk.name = resolveHintName(ctx, hn_rva, &thunk.hint);
            }
        } else {
            const val = r.readU32() orelse break;
            thunk.thunk_rva = val & 0x7FFFFFFF;
            if (val & 0x80000000 != 0) {
                thunk.is_ordinal = true;
                thunk.ordinal = @intCast(val & 0xFFFF);
            } else {
                const hn_rva = val & 0x7FFFFFFF;
                thunk.name = resolveHintName(ctx, hn_rva, &thunk.hint);
            }
        }
        desc.num_thunks = i + 1;
    }
}

fn parseDescriptor(r: *Reader, desc: *root.ImportDescriptor) ParseError!void {
    desc.* = root.ImportDescriptor{};
    desc.ilt_rva = r.readU32() orelse return ParseError.Truncated;
    desc.timestamp = r.readU32() orelse return ParseError.Truncated;
    desc.forwarder_chain = r.readU32() orelse return ParseError.Truncated;
    desc.name_rva = r.readU32() orelse return ParseError.Truncated;
    desc.iat_rva = r.readU32() orelse return ParseError.Truncated;
}

fn isNullDescriptor(desc: *const root.ImportDescriptor) bool {
    return desc.ilt_rva == 0 and desc.timestamp == 0 and
        desc.forwarder_chain == 0 and desc.name_rva == 0 and
        desc.iat_rva == 0;
}

pub fn parse(ctx: *PeCtx) ParseError!void {
    const import_dir = &ctx.optional_header.data_dirs[root.DIR_IMPORT];
    if (import_dir.rva == 0 or import_dir.size == 0) return;

    const dir_offset = ctx.rvaToOffset(import_dir.rva) orelse
        return ParseError.InvalidImport;

    var r = Reader.init(ctx.data, ctx.size);
    if (!r.seek(dir_offset)) return ParseError.Truncated;

    var count: u32 = 0;
    while (count < root.MAX_IMPORTS) {
        var desc = root.ImportDescriptor{};
        parseDescriptor(&r, &desc) catch break;
        if (isNullDescriptor(&desc)) break;

        // Resolve DLL name (allocated copy)
        if (desc.name_rva != 0) {
            desc.dll_name = readStringAtRva(ctx, desc.name_rva);
        }

        // Grow descriptor array
        if (ctx.import_descriptors == null or ctx.import_count >= ctx.import_capacity) {
            const new_cap = if (ctx.import_capacity == 0) @as(u32, 16) else ctx.import_capacity * 2;
            const new_arr = ctx.allocator.alloc(root.ImportDescriptor, new_cap) catch
                return ParseError.OutOfMemory;
            if (ctx.import_descriptors) |old| {
                @memcpy(new_arr[0..ctx.import_count], old[0..ctx.import_count]);
                ctx.allocator.free(old[0..ctx.import_capacity]);
            }
            ctx.import_descriptors = new_arr.ptr;
            ctx.import_capacity = new_cap;
        }

        ctx.import_descriptors.?[ctx.import_count] = desc;
        parseThunks(ctx, &ctx.import_descriptors.?[ctx.import_count],
                    ctx.optional_header.is_pe32plus) catch {};
        ctx.import_count += 1;
        count += 1;
    }
}

// ── Additional import validation and analysis ──────────────────

/// Validate all import DLL names are reasonable
pub fn validateDllNames(ctx: *PeCtx) void {
    if (ctx.import_descriptors == null) return;
    const descs = ctx.import_descriptors.?;

    var i: u32 = 0;
    while (i < ctx.import_count) : (i += 1) {
        const desc = &descs[i];
        if (desc.dll_name == null) {
            ctx.addIssue(1, 0, "import descriptor has null DLL name");
            continue;
        }

        const name = std.mem.span(desc.dll_name.?);
        if (name.len == 0) {
            ctx.addIssue(1, 0, "import descriptor has empty DLL name");
            continue;
        }

        if (name.len > 256) {
            ctx.addIssue(1, 0, "import DLL name exceeds 256 characters");
        }

        // Check for file extension
        var has_ext = false;
        for (name) |ch| {
            if (ch == '.') has_ext = true;
        }
        if (!has_ext) {
            ctx.addIssue(1, 0, "import DLL name has no extension");
        }

        // Check for path separators (unusual in import DLL names)
        for (name) |ch| {
            if (ch == '\\' or ch == '/') {
                ctx.addIssue(1, 0, "import DLL name contains path separator");
                break;
            }
        }

        // Check for non-ASCII characters
        for (name) |ch| {
            if (ch < 0x20 or ch > 0x7E) {
                ctx.addIssue(1, 0, "import DLL name has non-ASCII character");
                break;
            }
        }
    }
}

/// Count total imported functions across all descriptors
pub fn countTotalThunks(ctx: *const PeCtx) u32 {
    if (ctx.import_descriptors == null) return 0;
    var total: u32 = 0;
    var i: u32 = 0;
    while (i < ctx.import_count) : (i += 1) {
        total += ctx.import_descriptors.?[i].num_thunks;
    }
    return total;
}

/// Count imports by ordinal vs by name
pub fn countByOrdinal(ctx: *const PeCtx) u32 {
    if (ctx.import_descriptors == null) return 0;
    var count: u32 = 0;
    var d: u32 = 0;
    while (d < ctx.import_count) : (d += 1) {
        const desc = &ctx.import_descriptors.?[d];
        if (desc.thunks == null) continue;
        var t: u32 = 0;
        while (t < desc.num_thunks) : (t += 1) {
            if (desc.thunks.?[t].is_ordinal) count += 1;
        }
    }
    return count;
}

/// Find import descriptor by DLL name
pub fn findDescriptorByName(ctx: *const PeCtx, dll_name: []const u8) ?*const root.ImportDescriptor {
    if (ctx.import_descriptors == null) return null;
    var i: u32 = 0;
    while (i < ctx.import_count) : (i += 1) {
        const desc = &ctx.import_descriptors.?[i];
        if (desc.dll_name) |dn| {
            if (std.mem.eql(u8, std.mem.span(dn), dll_name)) return desc;
        }
    }
    return null;
}

/// Check if a specific function is imported from a specific DLL
pub fn hasImport(ctx: *const PeCtx, dll_name: []const u8, func_name: []const u8) bool {
    const desc = findDescriptorByName(ctx, dll_name) orelse return false;
    if (desc.thunks == null) return false;
    var t: u32 = 0;
    while (t < desc.num_thunks) : (t += 1) {
        if (desc.thunks.?[t].name) |name| {
            if (std.mem.eql(u8, std.mem.span(name), func_name)) return true;
        }
    }
    return false;
}

/// Analyze import patterns for suspicious API usage
pub fn analyzeSuspiciousImports(ctx: *const PeCtx) u32 {
    var suspicious: u32 = 0;
    const suspicious_apis = [_][]const u8{
        "VirtualAlloc", "VirtualProtect", "WriteProcessMemory",
        "CreateRemoteThread", "NtCreateSection", "NtMapViewOfSection",
        "IsDebuggerPresent", "CheckRemoteDebuggerPresent",
        "SetWindowsHookEx", "GetAsyncKeyState",
    };

    if (ctx.import_descriptors == null) return 0;
    var d: u32 = 0;
    while (d < ctx.import_count) : (d += 1) {
        const desc = &ctx.import_descriptors.?[d];
        if (desc.thunks == null) continue;
        var t: u32 = 0;
        while (t < desc.num_thunks) : (t += 1) {
            if (desc.thunks.?[t].name) |name| {
                const name_span = std.mem.span(name);
                for (suspicious_apis) |api| {
                    if (std.mem.eql(u8, name_span, api)) {
                        suspicious += 1;
                        break;
                    }
                }
            }
        }
    }
    return suspicious;
}

// ── Import hashing and fingerprinting ──────────────────────────

/// Compute imphash-style hash for the import table
/// Uses lowercase DLL.function format, FNV-1a hash
pub fn computeImphash(ctx: *const PeCtx) u64 {
    if (ctx.import_descriptors == null) return 0;
    var hash: u64 = 0xcbf29ce484222325;

    var d: u32 = 0;
    while (d < ctx.import_count) : (d += 1) {
        const desc = &ctx.import_descriptors.?[d];
        if (desc.dll_name == null) continue;
        if (desc.thunks == null) continue;

        const dll = std.mem.span(desc.dll_name.?);

        var t: u32 = 0;
        while (t < desc.num_thunks) : (t += 1) {
            const thunk = &desc.thunks.?[t];
            if (thunk.is_ordinal) continue;
            if (thunk.name == null) continue;

            // Hash "dll.function" in lowercase
            for (dll) |ch| {
                const lower: u8 = if (ch >= 'A' and ch <= 'Z') ch + 32 else ch;
                hash ^= lower;
                hash *%= 0x100000001b3;
            }
            hash ^= '.';
            hash *%= 0x100000001b3;

            const func_name = std.mem.span(thunk.name.?);
            for (func_name) |ch| {
                const lower: u8 = if (ch >= 'A' and ch <= 'Z') ch + 32 else ch;
                hash ^= lower;
                hash *%= 0x100000001b3;
            }
            hash ^= ',';
            hash *%= 0x100000001b3;
        }
    }
    return hash;
}

/// Group imports by DLL and return counts per DLL
pub fn countImportsPerDll(ctx: *const PeCtx, counts: []u32) void {
    if (ctx.import_descriptors == null) return;
    var d: u32 = 0;
    while (d < ctx.import_count and d < counts.len) : (d += 1) {
        counts[d] = ctx.import_descriptors.?[d].num_thunks;
    }
}

/// Check for imports from unusual DLLs (not standard Windows DLLs)
pub fn countNonStandardDlls(ctx: *const PeCtx) u32 {
    if (ctx.import_descriptors == null) return 0;

    const standard = [_][]const u8{
        "kernel32.dll", "ntdll.dll", "user32.dll", "advapi32.dll",
        "gdi32.dll", "ws2_32.dll", "ole32.dll", "oleaut32.dll",
        "shell32.dll", "msvcrt.dll", "comctl32.dll", "wininet.dll",
        "shlwapi.dll", "crypt32.dll", "secur32.dll", "winspool.drv",
        "comdlg32.dll", "version.dll", "imm32.dll", "winmm.dll",
        "setupapi.dll", "rpcrt4.dll", "iphlpapi.dll", "psapi.dll",
        "msvcp140.dll", "vcruntime140.dll", "ucrtbase.dll",
        "api-ms-win-core", "ext-ms-win",
    };

    var non_std: u32 = 0;
    var d: u32 = 0;
    while (d < ctx.import_count) : (d += 1) {
        if (ctx.import_descriptors.?[d].dll_name == null) continue;
        const name = std.mem.span(ctx.import_descriptors.?[d].dll_name.?);

        var is_standard = false;
        for (standard) |s| {
            if (name.len >= s.len) {
                var match = true;
                for (s, 0..) |ch, i| {
                    const nc: u8 = if (name[i] >= 'A' and name[i] <= 'Z') name[i] + 32 else name[i];
                    if (nc != ch) { match = false; break; }
                }
                if (match) { is_standard = true; break; }
            }
        }
        if (!is_standard) non_std += 1;
    }
    return non_std;
}

/// Find import thunk by function name across all descriptors
pub fn findImportByName(ctx: *const PeCtx, func_name: []const u8) ?struct { dll_index: u32, thunk_index: u32 } {
    if (ctx.import_descriptors == null) return null;
    var d: u32 = 0;
    while (d < ctx.import_count) : (d += 1) {
        const desc = &ctx.import_descriptors.?[d];
        if (desc.thunks == null) continue;
        var t: u32 = 0;
        while (t < desc.num_thunks) : (t += 1) {
            if (desc.thunks.?[t].name) |name| {
                if (std.mem.eql(u8, std.mem.span(name), func_name))
                    return .{ .dll_index = d, .thunk_index = t };
            }
        }
    }
    return null;
}

/// Count imports that use ordinals instead of names
pub fn countOrdinalImports(ctx: *const PeCtx) u32 {
    if (ctx.import_descriptors == null) return 0;
    var count: u32 = 0;
    var d: u32 = 0;
    while (d < ctx.import_count) : (d += 1) {
        const desc = &ctx.import_descriptors.?[d];
        if (desc.thunks == null) continue;
        var t: u32 = 0;
        while (t < desc.num_thunks) : (t += 1) {
            if (desc.thunks.?[t].is_ordinal) count += 1;
        }
    }
    return count;
}

/// Detect API loading patterns (LoadLibrary + GetProcAddress)
pub fn detectDynamicLoading(ctx: *const PeCtx) bool {
    const has_loadlib = hasImport(ctx, "kernel32.dll", "LoadLibraryA") or
        hasImport(ctx, "kernel32.dll", "LoadLibraryW") or
        hasImport(ctx, "kernel32.dll", "LoadLibraryExA") or
        hasImport(ctx, "kernel32.dll", "LoadLibraryExW");
    const has_getproc = hasImport(ctx, "kernel32.dll", "GetProcAddress");
    return has_loadlib and has_getproc;
}
