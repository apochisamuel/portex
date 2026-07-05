// exception.zig — Exception Directory Parsing (Phase 11b)
//
// Parses the exception directory containing RUNTIME_FUNCTION entries
// for x64 structured exception handling. Each entry describes a code
// range and points to UNWIND_INFO for stack unwinding.

const std = @import("std");
const root = @import("root.zig");
const rd = @import("reader.zig");
const PeCtx = root.PeCtx;
const ParseError = root.ParseError;
const Reader = rd.Reader;

// Unwind operation codes
const UWOP_PUSH_NONVOL: u8 = 0;
const UWOP_ALLOC_LARGE: u8 = 1;
const UWOP_ALLOC_SMALL: u8 = 2;
const UWOP_SET_FPREG: u8 = 3;
const UWOP_SAVE_NONVOL: u8 = 4;
const UWOP_SAVE_NONVOL_FAR: u8 = 5;
const UWOP_SAVE_XMM128: u8 = 8;
const UWOP_SAVE_XMM128_FAR: u8 = 9;
const UWOP_PUSH_MACHFRAME: u8 = 10;

// UNW_FLAG values
const UNW_FLAG_EHANDLER: u8 = 0x01;
const UNW_FLAG_UHANDLER: u8 = 0x02;
const UNW_FLAG_CHAININFO: u8 = 0x04;

const MAX_UNWIND_CODES: u32 = 256;

pub const UnwindCode = struct {
    offset_in_prolog: u8 = 0,
    operation: u8 = 0,
    op_info: u8 = 0,
    extra_value: u32 = 0,
};

pub const UnwindInfo = struct {
    version: u8 = 0,
    flags: u8 = 0,
    prolog_size: u8 = 0,
    code_count: u8 = 0,
    frame_register: u8 = 0,
    frame_offset: u8 = 0,
    codes: ?[*]UnwindCode = null,
    parsed_code_count: u32 = 0,
    codes_capacity: u32 = 0,
    handler_rva: u32 = 0,
    has_handler: bool = false,
    chained_begin: u32 = 0,
    chained_end: u32 = 0,
    chained_unwind: u32 = 0,
    is_chained: bool = false,
};

pub const ExceptionEntry = struct {
    begin_rva: u32 = 0,
    end_rva: u32 = 0,
    unwind_rva: u32 = 0,
    unwind: UnwindInfo = .{},
    code_section: u32 = 0xFFFFFFFF,
    handler_section: u32 = 0xFFFFFFFF,
};

pub const ExceptionTable = struct {
    entries: ?[*]ExceptionEntry = null,
    count: u32 = 0,
    capacity: u32 = 0,
    is_sorted: bool = false,
    total_code_size: u32 = 0,
    max_function_size: u32 = 0,
    min_function_size: u32 = 0,
    handler_count: u32 = 0,
    chained_count: u32 = 0,
};

pub fn getRegisterName(reg: u8) []const u8 {
    const names = [_][]const u8{
        "RAX", "RCX", "RDX", "RBX", "RSP", "RBP", "RSI", "RDI",
        "R8",  "R9",  "R10", "R11", "R12", "R13", "R14", "R15",
    };
    if (reg < 16) return names[reg];
    return "???";
}

pub fn getUnwindOpName(opcode: u8) []const u8 {
    return switch (opcode) {
        UWOP_PUSH_NONVOL => "PUSH_NONVOL",
        UWOP_ALLOC_LARGE => "ALLOC_LARGE",
        UWOP_ALLOC_SMALL => "ALLOC_SMALL",
        UWOP_SET_FPREG => "SET_FPREG",
        UWOP_SAVE_NONVOL => "SAVE_NONVOL",
        UWOP_SAVE_NONVOL_FAR => "SAVE_NONVOL_FAR",
        UWOP_SAVE_XMM128 => "SAVE_XMM128",
        UWOP_SAVE_XMM128_FAR => "SAVE_XMM128_FAR",
        UWOP_PUSH_MACHFRAME => "PUSH_MACHFRAME",
        else => "UNKNOWN",
    };
}

fn uwopSlotCount(opcode: u8, op_info: u8) u32 {
    return switch (opcode) {
        UWOP_PUSH_NONVOL, UWOP_ALLOC_SMALL, UWOP_SET_FPREG, UWOP_PUSH_MACHFRAME => 1,
        UWOP_ALLOC_LARGE => if (op_info == 0) @as(u32, 2) else @as(u32, 3),
        UWOP_SAVE_NONVOL, UWOP_SAVE_XMM128 => 2,
        UWOP_SAVE_NONVOL_FAR, UWOP_SAVE_XMM128_FAR => 3,
        else => 1,
    };
}

fn parseUnwindInfo(ctx: *PeCtx, entry: *ExceptionEntry, unwind_rva: u32) void {
    const offset = ctx.rvaToOffset(unwind_rva) orelse return;
    if (offset + 4 > ctx.size) return;

    const info = &entry.unwind;
    const ver_flags = ctx.data[offset];
    info.version = ver_flags & 0x07;
    info.flags = (ver_flags >> 3) & 0x1F;
    info.prolog_size = ctx.data[offset + 1];
    info.code_count = ctx.data[offset + 2];

    const frame_byte = ctx.data[offset + 3];
    info.frame_register = frame_byte & 0x0F;
    info.frame_offset = (frame_byte >> 4) & 0x0F;

    // Parse unwind codes
    const codes_offset = offset + 4;
    const codes_size = @as(u32, info.code_count) * 2;
    if (codes_offset + codes_size > ctx.size) {
        info.code_count = 0;
        return;
    }

    if (info.code_count > 0 and info.code_count <= MAX_UNWIND_CODES) {
        const codes = ctx.allocator.alloc(UnwindCode, info.code_count) catch return;
        @memset(codes, UnwindCode{});
        info.codes = codes.ptr;
        info.codes_capacity = info.code_count;

        var ci: u32 = 0;
        var slot: u32 = 0;
        while (slot < info.code_count and ci < info.code_count) {
            const code_off = codes_offset + slot * 2;
            if (code_off + 2 > ctx.size) break;

            const uc = &codes[ci];
            uc.offset_in_prolog = ctx.data[code_off];
            const op_and_info = ctx.data[code_off + 1];
            uc.operation = op_and_info & 0x0F;
            uc.op_info = (op_and_info >> 4) & 0x0F;

            const slots = uwopSlotCount(uc.operation, uc.op_info);
            if (slots >= 2 and code_off + 4 <= ctx.size) {
                uc.extra_value = rd.readU16At(ctx.data + code_off + 2);
            }
            if (slots >= 3 and code_off + 6 <= ctx.size) {
                uc.extra_value |= @as(u32, rd.readU16At(ctx.data + code_off + 4)) << 16;
            }

            slot += slots;
            ci += 1;
        }
        info.parsed_code_count = ci;
    }

    // Check for exception/unwind handler
    const aligned_count = (info.code_count + 1) & ~@as(u32, 1);
    const handler_off = codes_offset + aligned_count * 2;

    if (info.flags & (UNW_FLAG_EHANDLER | UNW_FLAG_UHANDLER) != 0) {
        if (handler_off + 4 <= ctx.size) {
            info.handler_rva = rd.readU32At(ctx.data + handler_off);
            info.has_handler = true;
            if (info.handler_rva != 0) {
                entry.handler_section = rd.findSectionByRva(ctx, info.handler_rva) orelse 0xFFFFFFFF;
            }
        }
    }

    // Check for chained unwind info
    if (info.flags & UNW_FLAG_CHAININFO != 0) {
        if (handler_off + 12 <= ctx.size) {
            info.chained_begin = rd.readU32At(ctx.data + handler_off);
            info.chained_end = rd.readU32At(ctx.data + handler_off + 4);
            info.chained_unwind = rd.readU32At(ctx.data + handler_off + 8);
            info.is_chained = true;
        }
    }
}

fn validateEntry(ctx: *PeCtx, entry: *ExceptionEntry, index: u32) void {
    if (entry.end_rva <= entry.begin_rva) {
        ctx.addIssue(1, 0, "exception entry: end <= begin");
    }

    const func_size = entry.end_rva -| entry.begin_rva;
    if (func_size > 1024 * 1024) {
        ctx.addIssue(1, 0, "exception entry: unusually large function");
    }

    if (rd.findSectionByRva(ctx, entry.begin_rva)) |sec_idx| {
        entry.code_section = sec_idx;
        if (ctx.section_entries) |entries| {
            if ((entries[sec_idx].characteristics & root.SCN_MEM_EXECUTE) == 0) {
                ctx.addIssue(1, sec_idx, "exception in non-executable section");
            }
        }
    }

    if (entry.unwind.version > 2) {
        ctx.addIssue(1, 0, "unsupported unwind version");
    }

    // Validate unwind codes
    if (entry.unwind.codes) |codes| {
        var i: u32 = 0;
        while (i < entry.unwind.parsed_code_count) : (i += 1) {
            if (codes[i].offset_in_prolog > entry.unwind.prolog_size) {
                ctx.addIssue(1, 0, "unwind code offset exceeds prolog");
            }
        }
    }
    _ = index;
}

fn computeStats(table: *ExceptionTable) void {
    if (table.entries == null or table.count == 0) return;
    const entries = table.entries.?;

    var total_code: u32 = 0;
    var max_func: u32 = 0;
    var min_func: u32 = 0xFFFFFFFF;
    var handlers: u32 = 0;
    var chained: u32 = 0;

    var i: u32 = 0;
    while (i < table.count) : (i += 1) {
        const func_size = entries[i].end_rva -| entries[i].begin_rva;
        total_code += func_size;
        if (func_size > max_func) max_func = func_size;
        if (func_size < min_func) min_func = func_size;
        if (entries[i].unwind.has_handler) handlers += 1;
        if (entries[i].unwind.is_chained) chained += 1;
    }

    table.total_code_size = total_code;
    table.max_function_size = max_func;
    table.min_function_size = if (table.count > 0) min_func else 0;
    table.handler_count = handlers;
    table.chained_count = chained;
}

fn verifySortOrder(ctx: *PeCtx, table: *ExceptionTable) void {
    if (table.entries == null or table.count < 2) {
        table.is_sorted = true;
        return;
    }
    const entries = table.entries.?;
    table.is_sorted = true;
    var i: u32 = 1;
    while (i < table.count) : (i += 1) {
        if (entries[i].begin_rva < entries[i - 1].begin_rva) {
            ctx.addIssue(2, 0, "exception table not sorted");
            table.is_sorted = false;
            break;
        }
    }
}

fn findOverlaps(ctx: *PeCtx, table: *ExceptionTable) void {
    if (table.entries == null or table.count < 2) return;
    const entries = table.entries.?;
    var overlap_count: u32 = 0;

    var i: u32 = 0;
    while (i < table.count) : (i += 1) {
        var j = i + 1;
        while (j < table.count) : (j += 1) {
            if (entries[i].begin_rva < entries[j].end_rva and
                entries[j].begin_rva < entries[i].end_rva)
            {
                overlap_count += 1;
                if (overlap_count <= 5) {
                    ctx.addIssue(1, 0, "overlapping exception entries");
                }
            }
            if (table.is_sorted and entries[j].begin_rva >= entries[i].end_rva)
                break;
        }
    }
}

pub fn parse(ctx: *PeCtx) ParseError!void {
    // Only meaningful for x64/ARM64
    if (ctx.coff_header.machine != root.MACHINE_AMD64 and
        ctx.coff_header.machine != root.MACHINE_ARM64) return;

    const exc_dir = &ctx.optional_header.data_dirs[root.DIR_EXCEPTION];
    if (exc_dir.rva == 0 or exc_dir.size == 0) return;

    const dir_offset = ctx.rvaToOffset(exc_dir.rva) orelse return;

    var num_entries = exc_dir.size / 12;
    if (num_entries > root.MAX_EXCEPTION_ENTRIES) num_entries = root.MAX_EXCEPTION_ENTRIES;
    if (num_entries == 0) return;

    // Allocate — we'll use a simple struct instead of PeCtx field
    // since exception table was previously a separate type
    const entries = ctx.allocator.alloc(ExceptionEntry, num_entries) catch
        return ParseError.OutOfMemory;
    @memset(entries, ExceptionEntry{});

    var r = Reader.init(ctx.data, ctx.size);
    if (!r.seek(dir_offset)) return;

    var count: u32 = 0;
    var i: u32 = 0;
    while (i < num_entries) : (i += 1) {
        const entry = &entries[count];
        entry.begin_rva = r.readU32() orelse break;
        entry.end_rva = r.readU32() orelse break;
        entry.unwind_rva = r.readU32() orelse break;

        if (entry.begin_rva == 0 and entry.end_rva == 0) continue;

        if (entry.unwind_rva != 0) {
            parseUnwindInfo(ctx, entry, entry.unwind_rva);
        }

        validateEntry(ctx, entry, i);
        count += 1;
    }

    // Store in a temporary table for stats
    var table = ExceptionTable{
        .entries = entries.ptr,
        .count = count,
        .capacity = @intCast(num_entries),
    };
    verifySortOrder(ctx, &table);
    findOverlaps(ctx, &table);
    computeStats(&table);

    // Free entries (not stored in PeCtx for now)
    var ei: u32 = 0;
    while (ei < count) : (ei += 1) {
        if (entries[ei].unwind.codes) |codes| {
            ctx.allocator.free(codes[0..entries[ei].unwind.codes_capacity]);
        }
    }
    ctx.allocator.free(entries);
}

/// Find exception entry covering an RVA (binary search if sorted)
pub fn findByRva(entries: []const ExceptionEntry, rva: u32, is_sorted: bool) ?*const ExceptionEntry {
    if (is_sorted) {
        var lo: u32 = 0;
        var hi: u32 = @intCast(entries.len);
        while (lo < hi) {
            const mid = lo + (hi - lo) / 2;
            const e = &entries[mid];
            if (rva < e.begin_rva) {
                hi = mid;
            } else if (rva >= e.end_rva) {
                lo = mid + 1;
            } else {
                return e;
            }
        }
        return null;
    }
    for (entries) |*e| {
        if (rva >= e.begin_rva and rva < e.end_rva) return e;
    }
    return null;
}

// ── Extended exception analysis ────────────────────────────────

/// Classify unwind operations by type
pub fn classifyUnwindOps(info: *const UnwindInfo) struct {
    pushes: u32, allocs: u32, saves: u32, frame_ops: u32, other: u32
} {
    var result = .{
        .pushes = @as(u32, 0), .allocs = @as(u32, 0),
        .saves = @as(u32, 0), .frame_ops = @as(u32, 0),
        .other = @as(u32, 0),
    };
    if (info.codes == null) return result;

    var i: u32 = 0;
    while (i < info.parsed_code_count) : (i += 1) {
        switch (info.codes.?[i].operation) {
            UWOP_PUSH_NONVOL, UWOP_PUSH_MACHFRAME => result.pushes += 1,
            UWOP_ALLOC_LARGE, UWOP_ALLOC_SMALL => result.allocs += 1,
            UWOP_SAVE_NONVOL, UWOP_SAVE_NONVOL_FAR,
            UWOP_SAVE_XMM128, UWOP_SAVE_XMM128_FAR => result.saves += 1,
            UWOP_SET_FPREG => result.frame_ops += 1,
            else => result.other += 1,
        }
    }
    return result;
}

/// Compute total stack frame size from unwind codes
pub fn computeStackFrameSize(info: *const UnwindInfo) u32 {
    if (info.codes == null) return 0;
    var total: u32 = 0;

    var i: u32 = 0;
    while (i < info.parsed_code_count) : (i += 1) {
        const uc = &info.codes.?[i];
        switch (uc.operation) {
            UWOP_PUSH_NONVOL => total += 8, // 64-bit register push
            UWOP_ALLOC_SMALL => total += (@as(u32, uc.op_info) + 1) * 8,
            UWOP_ALLOC_LARGE => {
                if (uc.op_info == 0) {
                    total += uc.extra_value * 8;
                } else {
                    total += uc.extra_value;
                }
            },
            else => {},
        }
    }
    return total;
}

/// Check if function uses frame pointer
pub fn usesFramePointer(info: *const UnwindInfo) bool {
    return info.frame_register != 0;
}

/// Get the frame pointer register name
pub fn getFramePointerReg(info: *const UnwindInfo) []const u8 {
    if (info.frame_register == 0) return "none";
    return getRegisterName(info.frame_register);
}

/// Count functions with exception handlers
pub fn countWithHandlers(entries: []const ExceptionEntry) u32 {
    var count: u32 = 0;
    for (entries) |e| {
        if (e.unwind.has_handler) count += 1;
    }
    return count;
}

/// Count chained unwind entries
pub fn countChained(entries: []const ExceptionEntry) u32 {
    var count: u32 = 0;
    for (entries) |e| {
        if (e.unwind.is_chained) count += 1;
    }
    return count;
}

/// Find the largest function by code size
pub fn findLargestFunction(entries: []const ExceptionEntry) ?u32 {
    if (entries.len == 0) return null;
    var max_idx: u32 = 0;
    var max_size: u32 = 0;
    for (entries, 0..) |e, idx| {
        const size = e.end_rva -| e.begin_rva;
        if (size > max_size) {
            max_size = size;
            max_idx = @intCast(idx);
        }
    }
    return max_idx;
}

/// Find the smallest function by code size
pub fn findSmallestFunction(entries: []const ExceptionEntry) ?u32 {
    if (entries.len == 0) return null;
    var min_idx: u32 = 0;
    var min_size: u32 = 0xFFFFFFFF;
    for (entries, 0..) |e, idx| {
        const size = e.end_rva -| e.begin_rva;
        if (size > 0 and size < min_size) {
            min_size = size;
            min_idx = @intCast(idx);
        }
    }
    return min_idx;
}

/// Compute average function size
pub fn avgFunctionSize(entries: []const ExceptionEntry) f64 {
    if (entries.len == 0) return 0.0;
    var total: u64 = 0;
    for (entries) |e| {
        total += e.end_rva -| e.begin_rva;
    }
    return @as(f64, @floatFromInt(total)) / @as(f64, @floatFromInt(entries.len));
}

/// Count functions in each code section
pub fn countPerSection(entries: []const ExceptionEntry, counts: []u32) void {
    @memset(counts, 0);
    for (entries) |e| {
        if (e.code_section < counts.len) counts[e.code_section] += 1;
    }
}
