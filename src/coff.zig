// coff.zig — PE Signature and COFF File Header Parsing (Phase 2)
//
// Validates the PE signature and parses the 20-byte COFF header.

const std = @import("std");
const root = @import("root.zig");
const rd = @import("reader.zig");
const PeCtx = root.PeCtx;
const ParseError = root.ParseError;
const Reader = rd.Reader;

fn isKnownMachine(machine: u16) bool {
    return switch (machine) {
        root.MACHINE_I386,
        root.MACHINE_AMD64,
        root.MACHINE_ARM64,
        root.MACHINE_ARMNT,
        0x0000, // UNKNOWN
        0x0200, // IA64
        0x01C0, // ARM
        => true,
        else => false,
    };
}

pub fn getMachineName(machine: u16) []const u8 {
    return switch (machine) {
        0x0000 => "Unknown",
        root.MACHINE_I386 => "i386",
        root.MACHINE_AMD64 => "AMD64",
        0x01C0 => "ARM",
        root.MACHINE_ARM64 => "ARM64",
        root.MACHINE_ARMNT => "ARM Thumb-2",
        0x0200 => "IA-64",
        else => "Unrecognized",
    };
}

fn validateCoffFields(ctx: *PeCtx) ParseError!void {
    const cof = &ctx.coff_header;

    if (!isKnownMachine(cof.machine))
        ctx.addWarning("unrecognized machine type");

    if (cof.num_sections == 0)
        return ParseError.InvalidCoff;

    if (cof.num_sections > root.MAX_SECTIONS)
        return ParseError.InvalidCoff;

    if (cof.optional_header_size > 0 and cof.optional_header_size < 28)
        ctx.addWarning("optional header size unexpectedly small");

    if (cof.symbol_table_offset != 0 and cof.symbol_table_offset >= ctx.size)
        ctx.addWarning("symbol table offset beyond file");

    if (cof.num_symbols > root.MAX_SYMBOLS)
        ctx.addWarning("large symbol count");
}

fn analyzeCharacteristics(ctx: *PeCtx) void {
    const chars = ctx.coff_header.characteristics;
    if ((chars & 0x0002) == 0 and (chars & 0x2000) == 0)
        ctx.addWarning("neither executable nor DLL flag set");
}

pub fn parsePeSignature(ctx: *PeCtx, offset: u32) ParseError!void {
    if (!ctx.checkOffset(offset, 4))
        return ParseError.Truncated;

    const sig = rd.readU32At(ctx.data + offset);
    if (sig != root.PE_SIGNATURE)
        return ParseError.InvalidPeSig;
}

pub fn parse(ctx: *PeCtx) ParseError!void {
    const offset = ctx.dos_header.e_lfanew + 4;

    if (!ctx.checkOffset(offset, 20))
        return ParseError.Truncated;

    var r = Reader.init(ctx.data, ctx.size);
    if (!r.seek(offset))
        return ParseError.Truncated;

    const cof = &ctx.coff_header;
    cof.machine = r.readU16() orelse return ParseError.Truncated;
    cof.num_sections = r.readU16() orelse return ParseError.Truncated;
    cof.timestamp = r.readU32() orelse return ParseError.Truncated;
    cof.symbol_table_offset = r.readU32() orelse return ParseError.Truncated;
    cof.num_symbols = r.readU32() orelse return ParseError.Truncated;
    cof.optional_header_size = r.readU16() orelse return ParseError.Truncated;
    cof.characteristics = r.readU16() orelse return ParseError.Truncated;

    try validateCoffFields(ctx);
    analyzeCharacteristics(ctx);
}

// ── Additional COFF analysis ───────────────────────────────────

/// Get characteristics description
pub fn getCharacteristicsDesc(chars: u16) []const u8 {
    if (chars & 0x0002 != 0 and chars & 0x2000 != 0) return "DLL (executable)";
    if (chars & 0x2000 != 0) return "DLL";
    if (chars & 0x0002 != 0) return "Executable";
    return "Object/Other";
}

/// Check if large address aware
pub fn isLargeAddressAware(chars: u16) bool {
    return (chars & 0x0020) != 0;
}

/// Check if relocations stripped
pub fn isRelocsStripped(chars: u16) bool {
    return (chars & 0x0001) != 0;
}

/// Check if debug info stripped
pub fn isDebugStripped(chars: u16) bool {
    return (chars & 0x0200) != 0;
}

/// Check if 32-bit machine
pub fn is32BitMachine(chars: u16) bool {
    return (chars & 0x0100) != 0;
}

/// Validate machine type vs optional header magic
pub fn validateMachineVsMagic(machine: u16, magic: u16) bool {
    if (machine == root.MACHINE_AMD64 or machine == root.MACHINE_ARM64) {
        return magic == root.OPT_MAGIC_PE32PLUS;
    }
    if (machine == root.MACHINE_I386) {
        return magic == root.OPT_MAGIC_PE32;
    }
    return true; // Unknown machine, can't validate
}

// ── COFF timestamp and characteristics analysis ────────────────

/// Check if timestamp is in the future (potential indicator of manipulation)
pub fn isTimestampFuture(timestamp: u32) bool {
    // Approximate current time as mid-2025 epoch seconds
    const approx_now: u32 = 1750000000;
    return timestamp > approx_now;
}

/// Check if timestamp is zero (often indicates a reproducible build)
pub fn isTimestampZero(timestamp: u32) bool {
    return timestamp == 0;
}

/// Check if timestamp matches a known linker default
pub fn isKnownDefaultTimestamp(timestamp: u32) bool {
    return switch (timestamp) {
        0x00000000, // Zero
        0xFFFFFFFF, // All ones
        0x4C6B4523, // Delphi default
        0x556F61C0, // Known MSVC default
        => true,
        else => false,
    };
}

/// Compute a fingerprint from COFF header fields
pub fn computeCoffFingerprint(hdr: *const root.CoffHeader) u64 {
    var fp: u64 = 0xcbf29ce484222325;
    fp ^= hdr.machine;
    fp *%= 0x100000001b3;
    fp ^= hdr.num_sections;
    fp *%= 0x100000001b3;
    fp ^= hdr.characteristics;
    fp *%= 0x100000001b3;
    fp ^= hdr.optional_header_size;
    fp *%= 0x100000001b3;
    return fp;
}

/// Get the expected pointer size based on machine type
pub fn getPointerSize(machine: u16) u8 {
    return switch (machine) {
        root.MACHINE_AMD64, root.MACHINE_ARM64 => 8,
        root.MACHINE_I386, root.MACHINE_ARMNT => 4,
        else => 4,
    };
}

/// Check if machine type is ARM-family
pub fn isArmMachine(machine: u16) bool {
    return machine == root.MACHINE_ARM64 or
        machine == root.MACHINE_ARMNT or
        machine == 0x01C0;
}

/// Check if machine type is x86-family
pub fn isX86Machine(machine: u16) bool {
    return machine == root.MACHINE_I386 or
        machine == root.MACHINE_AMD64;
}
