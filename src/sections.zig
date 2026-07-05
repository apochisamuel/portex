// sections.zig — Section Table Parsing (Phase 4)
//
// Parses section headers, loads section data into allocated buffers,
// and resolves long section names from the COFF string table.

const std = @import("std");
const root = @import("root.zig");
const rd = @import("reader.zig");
const str = @import("strings.zig");
const PeCtx = root.PeCtx;
const Section = root.Section;
const ParseError = root.ParseError;
const Reader = rd.Reader;

fn parseSectionEntry(r: *Reader, sec: *Section) ParseError!void {
    sec.* = Section{};

    if (!r.readFixedString(&sec.short_name, 8))
        return ParseError.Truncated;

    sec.virtual_size = r.readU32() orelse return ParseError.Truncated;
    sec.virtual_address = r.readU32() orelse return ParseError.Truncated;
    sec.raw_data_size = r.readU32() orelse return ParseError.Truncated;
    sec.raw_data_offset = r.readU32() orelse return ParseError.Truncated;
    sec.reloc_offset = r.readU32() orelse return ParseError.Truncated;
    sec.linenum_offset = r.readU32() orelse return ParseError.Truncated;
    sec.num_relocs = r.readU16() orelse return ParseError.Truncated;
    sec.num_linenums = r.readU16() orelse return ParseError.Truncated;
    sec.characteristics = r.readU32() orelse return ParseError.Truncated;
}

fn validateSectionEntry(ctx: *PeCtx, sec: *const Section, index: u32) void {
    if (sec.raw_data_size > 0 and sec.raw_data_offset == 0)
        ctx.addWarning("section has raw data size but zero offset");

    if (sec.raw_data_offset > 0 and sec.raw_data_offset >= ctx.size)
        ctx.addWarning("section raw data offset beyond file");

    if (@as(u64, sec.raw_data_offset) + @as(u64, sec.raw_data_size) > ctx.size)
        ctx.addWarning("section raw data extends beyond file");

    if (sec.virtual_address == 0 and index > 0)
        ctx.addWarning("section has zero virtual address");

    const fa = ctx.optional_header.file_alignment;
    if (fa > 0 and sec.raw_data_offset > 0 and
        (sec.raw_data_offset % fa) != 0)
    {
        ctx.addIssue(1, index, "section raw data not aligned");
    }
}

pub fn parseTable(ctx: *PeCtx, offset: u32) ParseError!void {
    const count = ctx.coff_header.num_sections;
    if (count == 0) return;

    const table_size = @as(u32, count) * 40;
    if (!ctx.checkOffset(offset, table_size))
        return ParseError.Truncated;

    const entries = ctx.allocator.alloc(Section, count) catch
        return ParseError.OutOfMemory;

    ctx.section_entries = entries.ptr;
    ctx.section_count = count;
    ctx.section_capacity = count;

    var r = Reader.init(ctx.data, ctx.size);
    if (!r.seek(offset))
        return ParseError.Truncated;

    var i: u32 = 0;
    while (i < count) : (i += 1) {
        try parseSectionEntry(&r, &entries[i]);
        validateSectionEntry(ctx, &entries[i], i);
    }
}

pub fn loadData(ctx: *PeCtx) ParseError!void {
    if (ctx.section_entries == null) return;
    const entries = ctx.section_entries.?;

    var i: u32 = 0;
    while (i < ctx.section_count) : (i += 1) {
        const sec = &entries[i];

        if (sec.raw_data_size == 0 or sec.raw_data_offset == 0) {
            sec.data = null;
            sec.data_size = 0;
            continue;
        }

        // Check overflow
        const end_offset = @as(u64, sec.raw_data_offset) + @as(u64, sec.raw_data_size);
        if (end_offset < sec.raw_data_offset) {
            ctx.addWarning("section raw data size overflow");
            continue;
        }

        var available: usize = sec.raw_data_size;
        if (end_offset > ctx.size) {
            if (sec.raw_data_offset >= ctx.size) {
                available = 0;
            } else {
                available = ctx.size - sec.raw_data_offset;
            }
        }

        if (available == 0) {
            sec.data = null;
            sec.data_size = 0;
            continue;
        }

        const buf = ctx.allocator.alloc(u8, available) catch
            return ParseError.OutOfMemory;

        @memcpy(buf, (ctx.data + sec.raw_data_offset)[0..available]);
        sec.data = buf.ptr;
        sec.data_size = available;
        sec.data_owned = true;
    }
}

/// Reload section data from original file buffer. Used during
/// validation when section data needs refresh after inconsistencies.
pub fn reloadSectionData(ctx: *PeCtx, section_index: u32) ParseError!void {
    if (ctx.section_entries == null) return ParseError.InvalidSection;
    if (section_index >= ctx.section_count) return ParseError.InvalidSection;

    const sec = &ctx.section_entries.?[section_index];

    if (sec.raw_data_size == 0 or sec.raw_data_offset == 0) return;

    var available: usize = sec.raw_data_size;
    const end_off = @as(u64, sec.raw_data_offset) + @as(u64, sec.raw_data_size);
    if (end_off > ctx.size) {
        if (sec.raw_data_offset >= ctx.size) return;
        available = ctx.size - sec.raw_data_offset;
    }

    // Allocate new buffer FIRST, then free old buffer.
    // This ensures the new buffer occupies a different address
    // than the old one, so any cached pointers into the old
    // buffer become genuinely stale after the free below.
    const new_buf = ctx.allocator.alloc(u8, available) catch
        return ParseError.OutOfMemory;
    @memcpy(new_buf, (ctx.data + sec.raw_data_offset)[0..available]);

    // NOW release the old data buffer — cached pointers are stale
    if (sec.data != null and sec.data_owned) {
        ctx.allocator.free(sec.data.?[0..sec.data_size]);
    }

    sec.data = new_buf.ptr;
    sec.data_size = available;
    sec.data_owned = true;
}

/// Resolve long section names from string table
pub fn resolveNames(ctx: *PeCtx) void {
    if (ctx.section_entries == null) return;

    var i: u32 = 0;
    while (i < ctx.section_count) : (i += 1) {
        const sec = &ctx.section_entries.?[i];

        if (sec.short_name[0] != '/') {
            // Short name - already embedded
            continue;
        }

        // Parse "/digits" string table offset
        var str_offset: u32 = 0;
        var valid = true;
        var j: usize = 1;
        while (j < 8 and sec.short_name[j] != 0) : (j += 1) {
            const ch = sec.short_name[j];
            if (ch < '0' or ch > '9') {
                valid = false;
                break;
            }
            str_offset = str_offset * 10 + @as(u32, ch - '0');
        }

        if (!valid) {
            ctx.addWarning("invalid string table reference in section name");
            continue;
        }

        // Look up in string table - returns pointer into string table data
        const name = str.lookup(&ctx.string_table, str_offset);
        if (name) |n| {
            sec.resolved_name = n;
        } else {
            ctx.addWarning("section name string table offset out of range");
        }
    }
}

pub fn isExecutable(sec: *const Section) bool {
    return (sec.characteristics & root.SCN_MEM_EXECUTE) != 0;
}

pub fn isWritable(sec: *const Section) bool {
    return (sec.characteristics & root.SCN_MEM_WRITE) != 0;
}

pub fn isReadable(sec: *const Section) bool {
    return (sec.characteristics & root.SCN_MEM_READ) != 0;
}

pub fn containsCode(sec: *const Section) bool {
    return (sec.characteristics & root.SCN_CNT_CODE) != 0;
}

pub fn containsData(sec: *const Section) bool {
    return (sec.characteristics & root.SCN_CNT_INIT_DATA) != 0;
}

// ── Section gap and coverage analysis ──────────────────────────

/// Detect gaps between sections in virtual address space
pub fn detectVaGaps(ctx: *const PeCtx) u32 {
    if (ctx.section_entries == null or ctx.section_count < 2) return 0;
    const entries = ctx.section_entries.?;

    var gap_count: u32 = 0;
    var i: u32 = 1;
    while (i < ctx.section_count) : (i += 1) {
        const prev = &entries[i - 1];
        const curr = &entries[i];
        const prev_end = @as(u64, prev.virtual_address) +
            @as(u64, @max(prev.virtual_size, prev.raw_data_size));
        if (@as(u64, curr.virtual_address) > prev_end) {
            gap_count += 1;
        }
    }
    return gap_count;
}

/// Detect gaps between sections in file offset space
pub fn detectFileGaps(ctx: *const PeCtx) u32 {
    if (ctx.section_entries == null or ctx.section_count < 2) return 0;
    const entries = ctx.section_entries.?;

    var gap_count: u32 = 0;
    var i: u32 = 1;
    while (i < ctx.section_count) : (i += 1) {
        const prev = &entries[i - 1];
        const curr = &entries[i];
        if (prev.raw_data_offset == 0 or curr.raw_data_offset == 0) continue;
        const prev_end = @as(u64, prev.raw_data_offset) + @as(u64, prev.raw_data_size);
        if (@as(u64, curr.raw_data_offset) > prev_end) {
            gap_count += 1;
        }
    }
    return gap_count;
}

/// Total file offset coverage by all sections
pub fn totalFileCoverage(ctx: *const PeCtx) u64 {
    if (ctx.section_entries == null) return 0;
    var total: u64 = 0;
    var i: u32 = 0;
    while (i < ctx.section_count) : (i += 1) {
        total += ctx.section_entries.?[i].raw_data_size;
    }
    return total;
}

/// Find section with largest raw data
pub fn findLargestSection(ctx: *const PeCtx) ?u32 {
    if (ctx.section_entries == null or ctx.section_count == 0) return null;
    var largest: u32 = 0;
    var largest_size: u32 = 0;
    var i: u32 = 0;
    while (i < ctx.section_count) : (i += 1) {
        if (ctx.section_entries.?[i].raw_data_size > largest_size) {
            largest_size = ctx.section_entries.?[i].raw_data_size;
            largest = i;
        }
    }
    return largest;
}

/// Count sections by characteristic type
pub fn countCodeSections(ctx: *const PeCtx) u32 {
    if (ctx.section_entries == null) return 0;
    var count: u32 = 0;
    var i: u32 = 0;
    while (i < ctx.section_count) : (i += 1) {
        if (containsCode(&ctx.section_entries.?[i])) count += 1;
    }
    return count;
}

pub fn countDataSections(ctx: *const PeCtx) u32 {
    if (ctx.section_entries == null) return 0;
    var count: u32 = 0;
    var i: u32 = 0;
    while (i < ctx.section_count) : (i += 1) {
        if (containsData(&ctx.section_entries.?[i])) count += 1;
    }
    return count;
}

pub fn countExecutableSections(ctx: *const PeCtx) u32 {
    if (ctx.section_entries == null) return 0;
    var count: u32 = 0;
    var i: u32 = 0;
    while (i < ctx.section_count) : (i += 1) {
        if (isExecutable(&ctx.section_entries.?[i])) count += 1;
    }
    return count;
}

pub fn countWritableSections(ctx: *const PeCtx) u32 {
    if (ctx.section_entries == null) return 0;
    var count: u32 = 0;
    var i: u32 = 0;
    while (i < ctx.section_count) : (i += 1) {
        if (isWritable(&ctx.section_entries.?[i])) count += 1;
    }
    return count;
}

/// Get section alignment value from characteristics
pub fn getAlignment(sec: *const Section) u32 {
    const align_val = (sec.characteristics & 0x00F00000) >> 20;
    if (align_val == 0) return 0;
    return @as(u32, 1) << @intCast(align_val - 1);
}

/// Check if section name matches a known standard name
pub fn isStandardName(name: []const u8) bool {
    const standard_names = [_][]const u8{
        ".text", ".data", ".rdata", ".bss", ".idata",
        ".edata", ".rsrc", ".reloc", ".pdata", ".tls",
        ".CRT", ".debug", ".drectve",
    };
    for (standard_names) |sn| {
        if (std.mem.eql(u8, name, sn)) return true;
    }
    return false;
}

/// Count sections with non-standard names
pub fn countNonStandardNames(ctx: *const PeCtx) u32 {
    if (ctx.section_entries == null) return 0;
    var count: u32 = 0;
    var i: u32 = 0;
    while (i < ctx.section_count) : (i += 1) {
        const name = std.mem.sliceTo(&ctx.section_entries.?[i].short_name, 0);
        if (!isStandardName(name)) count += 1;
    }
    return count;
}

// ── Section content comparison ─────────────────────────────────

/// Compare two sections' data for equality
pub fn sectionsEqual(a: *const Section, b: *const Section) bool {
    if (a.data_size != b.data_size) return false;
    if (a.data == null and b.data == null) return true;
    if (a.data == null or b.data == null) return false;

    var i: usize = 0;
    while (i < a.data_size) : (i += 1) {
        if (a.data.?[i] != b.data.?[i]) return false;
    }
    return true;
}

/// Check if section data is all one byte value
pub fn isSingleByteFill(sec: *const Section) ?u8 {
    if (sec.data == null or sec.data_size == 0) return null;
    const first = sec.data.?[0];
    var i: usize = 1;
    while (i < sec.data_size) : (i += 1) {
        if (sec.data.?[i] != first) return null;
    }
    return first;
}

/// Count padding bytes at end of section
pub fn countTrailingPadding(sec: *const Section) usize {
    if (sec.data == null or sec.data_size == 0) return 0;
    var count: usize = 0;
    var i = sec.data_size;
    while (i > 0) : (i -= 1) {
        if (sec.data.?[i - 1] != 0) break;
        count += 1;
    }
    return count;
}

/// Get the first non-zero offset in section data
pub fn firstNonZeroOffset(sec: *const Section) ?usize {
    if (sec.data == null or sec.data_size == 0) return null;
    var i: usize = 0;
    while (i < sec.data_size) : (i += 1) {
        if (sec.data.?[i] != 0) return i;
    }
    return null;
}
