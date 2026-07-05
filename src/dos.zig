// dos.zig — DOS Stub Header Parsing (Phase 1)
//
// Parses the legacy DOS MZ header. The critical field is e_lfanew
// which provides the offset to the PE signature.

const std = @import("std");
const root = @import("root.zig");
const rd = @import("reader.zig");
const PeCtx = root.PeCtx;
const ParseError = root.ParseError;
const Reader = rd.Reader;

fn readDosFields(ctx: *PeCtx, r: *Reader) ParseError!void {
    const dos = &ctx.dos_header;

    dos.e_magic = r.readU16() orelse return ParseError.Truncated;
    if (dos.e_magic != root.DOS_MAGIC)
        return ParseError.InvalidDos;

    dos.e_cblp = r.readU16() orelse return ParseError.Truncated;
    dos.e_cp = r.readU16() orelse return ParseError.Truncated;
    dos.e_crlc = r.readU16() orelse return ParseError.Truncated;
    dos.e_cparhdr = r.readU16() orelse return ParseError.Truncated;
    dos.e_minalloc = r.readU16() orelse return ParseError.Truncated;
    dos.e_maxalloc = r.readU16() orelse return ParseError.Truncated;
    dos.e_ss = r.readU16() orelse return ParseError.Truncated;
    dos.e_sp = r.readU16() orelse return ParseError.Truncated;
    dos.e_csum = r.readU16() orelse return ParseError.Truncated;
    dos.e_ip = r.readU16() orelse return ParseError.Truncated;
    dos.e_cs = r.readU16() orelse return ParseError.Truncated;
    dos.e_lfarlc = r.readU16() orelse return ParseError.Truncated;
    dos.e_ovno = r.readU16() orelse return ParseError.Truncated;

    // Reserved words e_res[4]
    var i: usize = 0;
    while (i < 4) : (i += 1) {
        _ = r.readU16() orelse return ParseError.Truncated;
    }

    dos.e_oemid = r.readU16() orelse return ParseError.Truncated;
    dos.e_oeminfo = r.readU16() orelse return ParseError.Truncated;

    // Reserved words e_res2[10]
    i = 0;
    while (i < 10) : (i += 1) {
        _ = r.readU16() orelse return ParseError.Truncated;
    }

    dos.e_lfanew = r.readU32() orelse return ParseError.Truncated;
}

fn validateLfanew(ctx: *PeCtx) ParseError!void {
    const lfanew = ctx.dos_header.e_lfanew;

    if (lfanew < 64)
        return ParseError.InvalidDos;

    if (lfanew > ctx.size - 4)
        return ParseError.InvalidDos;

    if (lfanew & 3 != 0)
        ctx.addWarning("e_lfanew not 4-byte aligned");

    if (lfanew > 1024)
        ctx.addWarning("large DOS stub");
}

fn analyzeDosStub(ctx: *PeCtx) void {
    const stub_start: u32 = 64;
    const stub_end = ctx.dos_header.e_lfanew;
    if (stub_end <= stub_start) return;

    // Check for Rich header signature
    if (stub_end > 8) {
        var off = stub_start;
        while (off < stub_end -| 8) : (off += 4) {
            if (ctx.checkOffset(off, 4)) {
                const val = rd.readU32At(ctx.data + off);
                if (val == 0x68636952) { // "Rich"
                    ctx.addWarning("Rich header detected");
                    break;
                }
            }
        }
    }
}

pub fn parse(ctx: *PeCtx) ParseError!void {
    if (ctx.size < 64)
        return ParseError.Truncated;

    var r = Reader.init(ctx.data, ctx.size);

    try readDosFields(ctx, &r);
    try validateLfanew(ctx);
    analyzeDosStub(ctx);
}

// ── Additional DOS analysis ────────────────────────────────────

/// Get DOS stub size
pub fn getDosStubSize(ctx: *const PeCtx) u32 {
    if (ctx.dos_header.e_lfanew <= 64) return 0;
    return ctx.dos_header.e_lfanew - 64;
}

/// Check if DOS stub contains a valid program
pub fn hasValidDosProgram(ctx: *const PeCtx) bool {
    if (ctx.dos_header.e_lfanew <= 64) return false;
    // Check for typical "This program cannot be run..." message
    const stub_start: usize = 64;
    const stub_end = @min(@as(usize, ctx.dos_header.e_lfanew), ctx.size);
    if (stub_end <= stub_start) return false;

    // Look for "This program" text
    const needle = "This program";
    var i = stub_start;
    while (i + needle.len < stub_end) : (i += 1) {
        var match = true;
        for (needle, 0..) |ch, j| {
            if (ctx.data[i + j] != ch) { match = false; break; }
        }
        if (match) return true;
    }
    return false;
}

/// Check if Rich header is present
pub fn hasRichHeader(ctx: *const PeCtx) bool {
    const stub_end: usize = @min(@as(usize, ctx.dos_header.e_lfanew), ctx.size);
    if (stub_end <= 72) return false;

    var i: usize = 64;
    while (i + 4 < stub_end) : (i += 4) {
        if (rd.readU32At(ctx.data + i) == 0x68636952) return true;
    }
    return false;
}

// ── Rich header utilities ──────────────────────────────────────

/// Parse Rich header entries from DOS stub
pub fn parseRichEntries(ctx: *const PeCtx, entries: []root.RichEntry) u32 {
    const stub_end: usize = @min(@as(usize, ctx.dos_header.e_lfanew), ctx.size);
    if (stub_end <= 72) return 0;

    // Find "Rich" signature
    var rich_off: ?usize = null;
    var i: usize = 64;
    while (i + 4 < stub_end) : (i += 4) {
        if (rd.readU32At(ctx.data + i) == 0x68636952) {
            rich_off = i;
            break;
        }
    }
    const offset = rich_off orelse return 0;
    if (offset + 4 >= ctx.size) return 0;

    const xor_key = rd.readU32At(ctx.data + offset + 4);

    // Find DanS marker
    var dans_off: ?usize = null;
    i = 64;
    while (i < offset) : (i += 4) {
        if (rd.readU32At(ctx.data + i) == (0x536E6144 ^ xor_key)) {
            dans_off = i;
            break;
        }
    }
    const start = dans_off orelse return 0;

    // Parse entries
    var count: u32 = 0;
    var pos = start + 16; // Skip DanS + padding
    while (pos + 8 <= offset and count < entries.len) : (pos += 8) {
        const comp_id = rd.readU32At(ctx.data + pos) ^ xor_key;
        const use_count = rd.readU32At(ctx.data + pos + 4) ^ xor_key;

        entries[count] = root.RichEntry{
            .comp_id = comp_id,
            .build_id = @intCast(comp_id >> 16),
            .product_id = @intCast(comp_id & 0xFFFF),
            .use_count = use_count,
        };
        count += 1;
    }
    return count;
}

/// Compute Rich header hash (XOR key)
pub fn getRichHash(ctx: *const PeCtx) ?u32 {
    const stub_end: usize = @min(@as(usize, ctx.dos_header.e_lfanew), ctx.size);
    if (stub_end <= 72) return null;

    var i: usize = 64;
    while (i + 8 < stub_end) : (i += 4) {
        if (rd.readU32At(ctx.data + i) == 0x68636952) {
            return rd.readU32At(ctx.data + i + 4);
        }
    }
    return null;
}

/// Count Rich header entries
pub fn countRichEntries(ctx: *const PeCtx) u32 {
    var entries: [64]root.RichEntry = undefined;
    return parseRichEntries(ctx, &entries);
}
