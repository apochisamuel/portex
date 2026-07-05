// optional.zig — PE Optional Header Parsing (Phase 3)
//
// Supports PE32 (32-bit) and PE32+ (64-bit) formats. Extracts
// data directory entries for import, export, reloc, debug, resource tables.

const std = @import("std");
const root = @import("root.zig");
const rd = @import("reader.zig");
const PeCtx = root.PeCtx;
const ParseError = root.ParseError;
const Reader = rd.Reader;

fn parsePe32Fields(ctx: *PeCtx, r: *Reader) ParseError!void {
    const opt = &ctx.optional_header;

    opt.base_of_data = r.readU32() orelse return ParseError.Truncated;
    opt.image_base = @as(u64, r.readU32() orelse return ParseError.Truncated);
    opt.section_alignment = r.readU32() orelse return ParseError.Truncated;
    opt.file_alignment = r.readU32() orelse return ParseError.Truncated;
    opt.major_os_version = r.readU16() orelse return ParseError.Truncated;
    opt.minor_os_version = r.readU16() orelse return ParseError.Truncated;
    opt.major_image_version = r.readU16() orelse return ParseError.Truncated;
    opt.minor_image_version = r.readU16() orelse return ParseError.Truncated;
    opt.major_subsystem_version = r.readU16() orelse return ParseError.Truncated;
    opt.minor_subsystem_version = r.readU16() orelse return ParseError.Truncated;
    opt.win32_version_value = r.readU32() orelse return ParseError.Truncated;
    opt.size_of_image = r.readU32() orelse return ParseError.Truncated;
    opt.size_of_headers = r.readU32() orelse return ParseError.Truncated;
    opt.pe_checksum = r.readU32() orelse return ParseError.Truncated;
    opt.subsystem = r.readU16() orelse return ParseError.Truncated;
    opt.dll_characteristics = r.readU16() orelse return ParseError.Truncated;

    // PE32: 4-byte stack/heap fields
    opt.stack_reserve = @as(u64, r.readU32() orelse return ParseError.Truncated);
    opt.stack_commit = @as(u64, r.readU32() orelse return ParseError.Truncated);
    opt.heap_reserve = @as(u64, r.readU32() orelse return ParseError.Truncated);
    opt.heap_commit = @as(u64, r.readU32() orelse return ParseError.Truncated);

    opt.loader_flags = r.readU32() orelse return ParseError.Truncated;
    opt.num_data_dirs = r.readU32() orelse return ParseError.Truncated;
    opt.is_pe32plus = false;
}

fn parsePe32PlusFields(ctx: *PeCtx, r: *Reader) ParseError!void {
    const opt = &ctx.optional_header;

    opt.base_of_data = 0;
    opt.image_base = r.readU64() orelse return ParseError.Truncated;
    opt.section_alignment = r.readU32() orelse return ParseError.Truncated;
    opt.file_alignment = r.readU32() orelse return ParseError.Truncated;
    opt.major_os_version = r.readU16() orelse return ParseError.Truncated;
    opt.minor_os_version = r.readU16() orelse return ParseError.Truncated;
    opt.major_image_version = r.readU16() orelse return ParseError.Truncated;
    opt.minor_image_version = r.readU16() orelse return ParseError.Truncated;
    opt.major_subsystem_version = r.readU16() orelse return ParseError.Truncated;
    opt.minor_subsystem_version = r.readU16() orelse return ParseError.Truncated;
    opt.win32_version_value = r.readU32() orelse return ParseError.Truncated;
    opt.size_of_image = r.readU32() orelse return ParseError.Truncated;
    opt.size_of_headers = r.readU32() orelse return ParseError.Truncated;
    opt.pe_checksum = r.readU32() orelse return ParseError.Truncated;
    opt.subsystem = r.readU16() orelse return ParseError.Truncated;
    opt.dll_characteristics = r.readU16() orelse return ParseError.Truncated;

    // PE32+: 8-byte stack/heap fields
    opt.stack_reserve = r.readU64() orelse return ParseError.Truncated;
    opt.stack_commit = r.readU64() orelse return ParseError.Truncated;
    opt.heap_reserve = r.readU64() orelse return ParseError.Truncated;
    opt.heap_commit = r.readU64() orelse return ParseError.Truncated;

    opt.loader_flags = r.readU32() orelse return ParseError.Truncated;
    opt.num_data_dirs = r.readU32() orelse return ParseError.Truncated;
    opt.is_pe32plus = true;
}

fn parseDataDirectories(ctx: *PeCtx, r: *Reader) ParseError!void {
    const opt = &ctx.optional_header;
    var count = opt.num_data_dirs;

    if (count > root.NUM_DATA_DIRS) {
        ctx.addWarning("data directory count exceeds standard, clamping");
        count = root.NUM_DATA_DIRS;
    }

    opt.data_dirs = [_]root.DataDir{.{}} ** root.NUM_DATA_DIRS;

    var i: u32 = 0;
    while (i < count) : (i += 1) {
        opt.data_dirs[i].rva = r.readU32() orelse return ParseError.Truncated;
        opt.data_dirs[i].size = r.readU32() orelse return ParseError.Truncated;
    }

    // Skip extra data directory entries beyond standard set
    if (opt.num_data_dirs > root.NUM_DATA_DIRS) {
        const extra = opt.num_data_dirs - root.NUM_DATA_DIRS;
        if (!r.skip(extra * 8))
            return ParseError.Truncated;
    }
}

fn validateOptionalFields(ctx: *PeCtx) ParseError!void {
    const opt = &ctx.optional_header;

    if (opt.section_alignment == 0)
        return ParseError.InvalidOptional;
    if (opt.file_alignment == 0)
        return ParseError.InvalidOptional;

    if (opt.file_alignment < 512 or opt.file_alignment > 65536)
        ctx.addWarning("unusual file alignment");

    if ((opt.file_alignment & (opt.file_alignment - 1)) != 0)
        ctx.addWarning("file alignment not power of 2");

    if (opt.section_alignment < opt.file_alignment)
        ctx.addWarning("section alignment < file alignment");

    if (opt.size_of_image == 0)
        ctx.addWarning("size of image is zero");

    if (opt.size_of_headers == 0)
        ctx.addWarning("size of headers is zero");

    if (opt.entry_point_rva != 0 and opt.size_of_image != 0 and
        opt.entry_point_rva >= opt.size_of_image)
    {
        ctx.addWarning("entry point exceeds image size");
    }

    // Validate data directory entries
    var i: u32 = 0;
    while (i < root.NUM_DATA_DIRS) : (i += 1) {
        const dd = &opt.data_dirs[i];
        if (dd.rva == 0 and dd.size == 0) continue;
        if (dd.rva != 0 and dd.size == 0)
            ctx.addWarning("data directory has RVA but zero size");
        if (dd.size != 0 and dd.rva == 0)
            ctx.addWarning("data directory has size but zero RVA");
    }
}

pub fn parse(ctx: *PeCtx, offset: u32) ParseError!void {
    if (!ctx.checkOffset(offset, 2))
        return ParseError.Truncated;

    var r = Reader.init(ctx.data, ctx.size);
    if (!r.seek(offset))
        return ParseError.Truncated;

    const opt = &ctx.optional_header;

    // Standard fields common to PE32 and PE32+
    opt.magic = r.readU16() orelse return ParseError.Truncated;
    if (opt.magic != root.OPT_MAGIC_PE32 and opt.magic != root.OPT_MAGIC_PE32PLUS)
        return ParseError.InvalidOptional;

    opt.major_linker = r.readU8() orelse return ParseError.Truncated;
    opt.minor_linker = r.readU8() orelse return ParseError.Truncated;
    opt.size_of_code = r.readU32() orelse return ParseError.Truncated;
    opt.size_of_init_data = r.readU32() orelse return ParseError.Truncated;
    opt.size_of_uninit_data = r.readU32() orelse return ParseError.Truncated;
    opt.entry_point_rva = r.readU32() orelse return ParseError.Truncated;
    opt.base_of_code = r.readU32() orelse return ParseError.Truncated;

    // Format-specific fields
    if (opt.magic == root.OPT_MAGIC_PE32) {
        try parsePe32Fields(ctx, &r);
    } else {
        try parsePe32PlusFields(ctx, &r);
    }

    try parseDataDirectories(ctx, &r);
    try validateOptionalFields(ctx);
}

// ── Additional optional header analysis ────────────────────────

pub fn getSubsystemName(subsystem: u16) []const u8 {
    return switch (subsystem) {
        0 => "Unknown", 1 => "Native", 2 => "Windows GUI",
        3 => "Windows Console", 7 => "POSIX Console",
        9 => "Windows CE", 10 => "EFI Application",
        11 => "EFI Boot Service Driver",
        12 => "EFI Runtime Driver",
        13 => "EFI ROM", 14 => "XBOX",
        16 => "Windows Boot Application",
        else => "Other",
    };
}

/// Check if ASLR (Dynamic Base) is enabled
pub fn hasAslr(opt: *const root.OptionalHeader) bool {
    return (opt.dll_characteristics & 0x0040) != 0;
}

/// Check if DEP (NX Compat) is enabled
pub fn hasDep(opt: *const root.OptionalHeader) bool {
    return (opt.dll_characteristics & 0x0100) != 0;
}

/// Check if Control Flow Guard is enabled
pub fn hasCfg(opt: *const root.OptionalHeader) bool {
    return (opt.dll_characteristics & 0x4000) != 0;
}

/// Check if SEH is disabled (NO_SEH flag)
pub fn hasSeh(opt: *const root.OptionalHeader) bool {
    return (opt.dll_characteristics & 0x0400) == 0;
}

/// Check if high entropy ASLR is enabled
pub fn hasHighEntropyAslr(opt: *const root.OptionalHeader) bool {
    return (opt.dll_characteristics & 0x0020) != 0;
}

/// Count non-empty data directories
pub fn countDataDirectories(opt: *const root.OptionalHeader) u32 {
    var count: u32 = 0;
    for (&opt.data_dirs) |dd| {
        if (dd.rva != 0 or dd.size != 0) count += 1;
    }
    return count;
}

/// Get total size of all data directories
pub fn totalDataDirSize(opt: *const root.OptionalHeader) u64 {
    var total: u64 = 0;
    for (&opt.data_dirs) |dd| {
        total += dd.size;
    }
    return total;
}

// ── Security feature detection ─────────────────────────────────

/// Check if AppContainer is enabled
pub fn isAppContainer(opt: *const root.OptionalHeader) bool {
    return (opt.dll_characteristics & 0x1000) != 0;
}

/// Check if WDM driver
pub fn isWdmDriver(opt: *const root.OptionalHeader) bool {
    return (opt.dll_characteristics & 0x2000) != 0;
}

/// Check if terminal server aware
pub fn isTerminalServerAware(opt: *const root.OptionalHeader) bool {
    return (opt.dll_characteristics & 0x8000) != 0;
}

/// Check if force integrity
pub fn hasForceIntegrity(opt: *const root.OptionalHeader) bool {
    return (opt.dll_characteristics & 0x0080) != 0;
}

/// Check if isolation disabled
pub fn hasNoIsolation(opt: *const root.OptionalHeader) bool {
    return (opt.dll_characteristics & 0x0200) != 0;
}

/// Get stack reserve in human-readable form
pub fn getStackReserveKb(opt: *const root.OptionalHeader) u64 {
    return opt.stack_reserve / 1024;
}

/// Get heap reserve in human-readable form
pub fn getHeapReserveKb(opt: *const root.OptionalHeader) u64 {
    return opt.heap_reserve / 1024;
}

/// Compute the ratio of code size to image size
pub fn codeToImageRatio(opt: *const root.OptionalHeader) f64 {
    if (opt.size_of_image == 0) return 0.0;
    return @as(f64, @floatFromInt(opt.size_of_code)) /
        @as(f64, @floatFromInt(opt.size_of_image));
}

/// Compute the ratio of initialized data to image size
pub fn dataToImageRatio(opt: *const root.OptionalHeader) f64 {
    if (opt.size_of_image == 0) return 0.0;
    return @as(f64, @floatFromInt(opt.size_of_init_data)) /
        @as(f64, @floatFromInt(opt.size_of_image));
}

/// Count security mitigations enabled
pub fn countMitigations(opt: *const root.OptionalHeader) u32 {
    var count: u32 = 0;
    if (hasAslr(opt)) count += 1;
    if (hasDep(opt)) count += 1;
    if (hasCfg(opt)) count += 1;
    if (hasSeh(opt)) count += 1;
    if (hasHighEntropyAslr(opt)) count += 1;
    if (hasForceIntegrity(opt)) count += 1;
    return count;
}
