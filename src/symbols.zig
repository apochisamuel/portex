// symbols.zig — COFF Symbol Table Parsing (Phase 6)
//
// Parses the COFF symbol table located at the file offset
// specified by the COFF header. Each symbol entry is 18 bytes.
// Symbol names may reference the string table (if first 4 bytes
// are zero, bytes 4-7 are the string table offset).
//
// Auxiliary symbol records follow the primary entry and provide
// additional information about section definitions, function
// line numbers, and weak externals.

const std = @import("std");
const root = @import("root.zig");
const rd = @import("reader.zig");
const str = @import("strings.zig");
const PeCtx = root.PeCtx;
const ParseError = root.ParseError;
const Reader = rd.Reader;

/// Parse a single symbol's auxiliary records
fn parseAuxRecords(r: *Reader, sym: *root.Symbol, ctx: *PeCtx) void {
    var aux: u8 = 0;
    while (aux < sym.aux_count) : (aux += 1) {
        if (!r.skip(18)) break;
        // Track auxiliary records for section definition symbols
        if (sym.storage_class == 3 and sym.section_number > 0) {
            // Static section definition — auxiliary contains
            // section length, reloc count, and line number count
            ctx.addWarning("symbol has auxiliary section definition");
        }
    }
}

/// Validate symbol entry fields
fn validateSymbol(ctx: *PeCtx, sym: *const root.Symbol, index: u32) void {
    // Check section number bounds
    if (sym.section_number > 0) {
        const sec_idx = @as(u32, @intCast(sym.section_number - 1));
        if (sec_idx >= ctx.section_count) {
            ctx.addIssue(1, 0, "symbol references invalid section");
        }
    }

    // External symbols with value > image size are suspicious
    if (sym.storage_class == 2 and sym.value > 0) {
        if (ctx.optional_header.size_of_image > 0 and
            sym.value > ctx.optional_header.size_of_image)
        {
            ctx.addIssue(1, 0, "external symbol value exceeds image size");
        }
    }

    // Check for unusual storage classes
    if (sym.storage_class > 107 and sym.storage_class != 255) {
        ctx.addIssue(1, 0, "symbol has unusual storage class");
    }

    _ = index;
}

/// Count symbols in each section
pub fn countSymbolsPerSection(ctx: *const PeCtx, counts: []u32) void {
    if (ctx.symbol_entries == null) return;
    @memset(counts, 0);

    var i: u32 = 0;
    while (i < ctx.symbol_count) : (i += 1) {
        const sym = &ctx.symbol_entries.?[i];
        if (sym.section_number > 0) {
            const sec_idx = @as(u32, @intCast(sym.section_number - 1));
            if (sec_idx < counts.len) counts[sec_idx] += 1;
        }
    }
}

/// Find symbol by name (linear search)
pub fn findSymbolByName(ctx: *const PeCtx, name: []const u8) ?*const root.Symbol {
    if (ctx.symbol_entries == null) return null;
    var i: u32 = 0;
    while (i < ctx.symbol_count) : (i += 1) {
        const sym = &ctx.symbol_entries.?[i];
        if (sym.resolved_name) |rn| {
            if (std.mem.eql(u8, std.mem.span(rn), name)) return sym;
        } else {
            const short = std.mem.sliceTo(&sym.short_name, 0);
            if (std.mem.eql(u8, short, name)) return sym;
        }
    }
    return null;
}

/// Count external symbols
pub fn countExternals(ctx: *const PeCtx) u32 {
    if (ctx.symbol_entries == null) return 0;
    var count: u32 = 0;
    var i: u32 = 0;
    while (i < ctx.symbol_count) : (i += 1) {
        if (ctx.symbol_entries.?[i].storage_class == 2) count += 1;
    }
    return count;
}

/// Count static symbols
pub fn countStatics(ctx: *const PeCtx) u32 {
    if (ctx.symbol_entries == null) return 0;
    var count: u32 = 0;
    var i: u32 = 0;
    while (i < ctx.symbol_count) : (i += 1) {
        if (ctx.symbol_entries.?[i].storage_class == 3) count += 1;
    }
    return count;
}

/// Count function symbols
pub fn countFunctions(ctx: *const PeCtx) u32 {
    if (ctx.symbol_entries == null) return 0;
    var count: u32 = 0;
    var i: u32 = 0;
    while (i < ctx.symbol_count) : (i += 1) {
        if (ctx.symbol_entries.?[i].storage_class == 101) count += 1;
    }
    return count;
}

pub fn parse(ctx: *PeCtx) ParseError!void {
    if (ctx.coff_header.symbol_table_offset == 0 or
        ctx.coff_header.num_symbols == 0) return;

    const sym_offset = ctx.coff_header.symbol_table_offset;
    var num_syms = ctx.coff_header.num_symbols;
    if (num_syms > root.MAX_SYMBOLS) num_syms = root.MAX_SYMBOLS;

    if (!ctx.checkOffset(sym_offset, num_syms * 18))
        return ParseError.Truncated;

    const entries = ctx.allocator.alloc(root.Symbol, num_syms) catch
        return ParseError.OutOfMemory;
    @memset(entries, root.Symbol{});
    ctx.symbol_entries = entries.ptr;
    ctx.symbol_count = num_syms;
    ctx.symbol_capacity = num_syms;

    var r = Reader.init(ctx.data, ctx.size);
    if (!r.seek(sym_offset)) return ParseError.Truncated;

    var i: u32 = 0;
    var actual_parsed: u32 = 0;
    while (i < num_syms) : (i += 1) {
        const sym = &entries[i];
        if (!r.readFixedString(&sym.short_name, 8)) break;
        sym.value = r.readU32() orelse break;
        const sec_raw = r.readU16() orelse break;
        sym.section_number = @bitCast(sec_raw);
        sym.sym_type = r.readU16() orelse break;
        sym.storage_class = r.readU8() orelse break;
        sym.aux_count = r.readU8() orelse break;
        sym.index = i;

        // Count symbols with meaningful content
        if (sym.storage_class != 0 or sym.value != 0 or sym.section_number != 0) {
            actual_parsed += 1;
        }

        validateSymbol(ctx, sym, i);

        // Skip auxiliary records
        parseAuxRecords(&r, sym, ctx);
        var aux: u8 = 0;
        while (aux < sym.aux_count and i + 1 < num_syms) : (aux += 1) {
            i += 1;
            entries[i] = root.Symbol{}; // Clear aux slot
            entries[i].index = i;
        }
    }

    // Store actual parsed count — may differ from header claim
    ctx.symbol_count = actual_parsed;
}

pub fn resolveNames(ctx: *PeCtx) void {
    if (ctx.symbol_entries == null) return;
    var i: u32 = 0;
    while (i < ctx.symbol_count) : (i += 1) {
        const sym = &ctx.symbol_entries.?[i];
        // If first 4 bytes are zero, bytes 4-7 are string table offset
        if (sym.short_name[0] == 0 and sym.short_name[1] == 0 and
            sym.short_name[2] == 0 and sym.short_name[3] == 0)
        {
            const offset = @as(u32, sym.short_name[4]) |
                (@as(u32, sym.short_name[5]) << 8) |
                (@as(u32, sym.short_name[6]) << 16) |
                (@as(u32, sym.short_name[7]) << 24);
            sym.resolved_name = str.lookup(&ctx.string_table, offset);
        }
    }
}

pub fn getClassName(class: u8) []const u8 {
    return switch (class) {
        0 => "NULL", 2 => "EXTERNAL", 3 => "STATIC",
        6 => "LABEL", 101 => "FUNCTION", 103 => "FILE",
        104 => "SECTION", 105 => "WEAK_EXTERNAL",
        else => "OTHER",
    };
}

// ── Additional symbol analysis ─────────────────────────────────

/// Check if any symbols reference the absolute section (section -1)
pub fn hasAbsoluteSymbols(ctx: *const PeCtx) bool {
    if (ctx.symbol_entries == null) return false;
    var i: u32 = 0;
    while (i < ctx.symbol_count) : (i += 1) {
        if (ctx.symbol_entries.?[i].section_number == -1) return true;
    }
    return false;
}

/// Count symbols in the debug section (section -2)
pub fn countDebugSymbols(ctx: *const PeCtx) u32 {
    if (ctx.symbol_entries == null) return 0;
    var count: u32 = 0;
    var i: u32 = 0;
    while (i < ctx.symbol_count) : (i += 1) {
        if (ctx.symbol_entries.?[i].section_number == -2) count += 1;
    }
    return count;
}

/// Count undefined symbols (section 0)
pub fn countUndefined(ctx: *const PeCtx) u32 {
    if (ctx.symbol_entries == null) return 0;
    var count: u32 = 0;
    var i: u32 = 0;
    while (i < ctx.symbol_count) : (i += 1) {
        if (ctx.symbol_entries.?[i].section_number == 0 and
            ctx.symbol_entries.?[i].storage_class == 2) count += 1;
    }
    return count;
}

/// Count file symbols (storage class 103)
pub fn countFileSymbols(ctx: *const PeCtx) u32 {
    if (ctx.symbol_entries == null) return 0;
    var count: u32 = 0;
    var i: u32 = 0;
    while (i < ctx.symbol_count) : (i += 1) {
        if (ctx.symbol_entries.?[i].storage_class == 103) count += 1;
    }
    return count;
}

/// Count weak external symbols
pub fn countWeakExternals(ctx: *const PeCtx) u32 {
    if (ctx.symbol_entries == null) return 0;
    var count: u32 = 0;
    var i: u32 = 0;
    while (i < ctx.symbol_count) : (i += 1) {
        if (ctx.symbol_entries.?[i].storage_class == 105) count += 1;
    }
    return count;
}

/// Count section definition symbols
pub fn countSectionDefs(ctx: *const PeCtx) u32 {
    if (ctx.symbol_entries == null) return 0;
    var count: u32 = 0;
    var i: u32 = 0;
    while (i < ctx.symbol_count) : (i += 1) {
        if (ctx.symbol_entries.?[i].storage_class == 104) count += 1;
    }
    return count;
}

/// Count auxiliary symbol records
pub fn countAuxRecords(ctx: *const PeCtx) u32 {
    if (ctx.symbol_entries == null) return 0;
    var count: u32 = 0;
    var i: u32 = 0;
    while (i < ctx.symbol_count) : (i += 1) {
        count += ctx.symbol_entries.?[i].aux_count;
    }
    return count;
}

// ── Symbol table classification ────────────────────────────────

/// Classify symbol table composition
pub fn classifySymbols(ctx: *const PeCtx) struct {
    externals: u32, statics: u32, functions: u32, files: u32,
    sections: u32, labels: u32, weak: u32, other: u32,
} {
    var result: @TypeOf(classifySymbols(undefined)) = undefined;
    @memset(std.mem.asBytes(&result), 0);

    if (ctx.symbol_entries == null) return result;
    var i: u32 = 0;
    while (i < ctx.symbol_count) : (i += 1) {
        switch (ctx.symbol_entries.?[i].storage_class) {
            2 => result.externals += 1,
            3 => result.statics += 1,
            6 => result.labels += 1,
            101 => result.functions += 1,
            103 => result.files += 1,
            104 => result.sections += 1,
            105 => result.weak += 1,
            else => result.other += 1,
        }
    }
    return result;
}

/// Find all symbols in a specific section
pub fn findSymbolsInSection(ctx: *const PeCtx, section_number: i16,
                             indices: []u32) u32 {
    if (ctx.symbol_entries == null) return 0;
    var count: u32 = 0;
    var i: u32 = 0;
    while (i < ctx.symbol_count and count < indices.len) : (i += 1) {
        if (ctx.symbol_entries.?[i].section_number == section_number) {
            indices[count] = i;
            count += 1;
        }
    }
    return count;
}

/// Compute symbol name length statistics
pub fn symbolNameStats(ctx: *const PeCtx) struct {
    total: u32, with_name: u32, avg_len: f64, max_len: u32,
    long_names: u32, // names > 8 chars (from string table)
} {
    var result: @TypeOf(symbolNameStats(undefined)) = undefined;
    @memset(std.mem.asBytes(&result), 0);

    if (ctx.symbol_entries == null) return result;
    var total_len: u64 = 0;
    result.total = ctx.symbol_count;

    var i: u32 = 0;
    while (i < ctx.symbol_count) : (i += 1) {
        const sym = &ctx.symbol_entries.?[i];
        if (sym.resolved_name) |name| {
            result.with_name += 1;
            const len: u32 = @intCast(std.mem.len(name));
            total_len += len;
            if (len > result.max_len) result.max_len = len;
            if (len > 8) result.long_names += 1;
        } else {
            const short_len = std.mem.sliceTo(&sym.short_name, 0).len;
            if (short_len > 0) {
                result.with_name += 1;
                total_len += short_len;
            }
        }
    }

    if (result.with_name > 0) {
        result.avg_len = @as(f64, @floatFromInt(total_len)) /
            @as(f64, @floatFromInt(result.with_name));
    }
    return result;
}

/// Check if symbol table has C++ mangled names
pub fn hasCppMangledNames(ctx: *const PeCtx) bool {
    if (ctx.symbol_entries == null) return false;
    var i: u32 = 0;
    while (i < ctx.symbol_count) : (i += 1) {
        const sym = &ctx.symbol_entries.?[i];
        if (sym.resolved_name) |name| {
            if (name[0] == '?') return true;
        }
        if (sym.short_name[0] == '?') return true;
    }
    return false;
}

/// Find symbol with highest value (address)
pub fn findHighestValueSymbol(ctx: *const PeCtx) ?u32 {
    if (ctx.symbol_entries == null or ctx.symbol_count == 0) return null;
    var max_idx: u32 = 0;
    var max_val: u32 = 0;
    var i: u32 = 0;
    while (i < ctx.symbol_count) : (i += 1) {
        if (ctx.symbol_entries.?[i].value > max_val) {
            max_val = ctx.symbol_entries.?[i].value;
            max_idx = i;
        }
    }
    return max_idx;
}
