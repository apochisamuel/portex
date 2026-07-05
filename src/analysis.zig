// analysis.zig — PE Image Analysis Utilities
//
// Section entropy calculation, data pattern classification,
// overlap detection, RVA coverage mapping. Supports malware
// analysis and binary inspection workflows.

const std = @import("std");
const root = @import("root.zig");
const rd = @import("reader.zig");
const cksum = @import("checksum.zig");
const PeCtx = root.PeCtx;

/// Shannon entropy of a byte sequence (0.0 to 8.0).
/// > 7.0 suggests encrypted/compressed. < 1.0 suggests padding.
pub fn calculateEntropy(data: ?[*]const u8, size: usize) f64 {
    if (data == null or size == 0) return 0.0;
    const d = data.?;

    var freq = [_]u32{0} ** 256;
    var i: usize = 0;
    while (i < size) : (i += 1) {
        freq[d[i]] += 1;
    }

    var entropy: f64 = 0.0;
    const fsize: f64 = @floatFromInt(size);

    for (&freq) |f| {
        if (f == 0) continue;
        const p: f64 = @as(f64, @floatFromInt(f)) / fsize;
        entropy -= p * @log2(p);
    }

    return entropy;
}

/// Classify data block based on byte distribution
pub fn classifyDataBlock(data: ?[*]const u8, size: usize) []const u8 {
    if (data == null or size == 0) return "empty";
    const d = data.?;

    const entropy = calculateEntropy(data, size);
    var zero_count: u32 = 0;
    var printable_count: u32 = 0;
    var highbit_count: u32 = 0;

    var i: usize = 0;
    while (i < size) : (i += 1) {
        if (d[i] == 0x00) zero_count += 1;
        if (d[i] >= 0x20 and d[i] <= 0x7E) printable_count += 1;
        if (d[i] >= 0x80) highbit_count += 1;
    }

    const fsize: f64 = @floatFromInt(size);
    const zero_ratio: f64 = @as(f64, @floatFromInt(zero_count)) / fsize;
    const print_ratio: f64 = @as(f64, @floatFromInt(printable_count)) / fsize;
    const high_ratio: f64 = @as(f64, @floatFromInt(highbit_count)) / fsize;

    if (zero_ratio > 0.90) return "padding/uninitialized";
    if (entropy > 7.5 and high_ratio > 0.30) return "encrypted/compressed";
    if (entropy > 6.5) return "high-entropy data";
    if (print_ratio > 0.80) return "text/strings";
    if (entropy < 2.0 and zero_ratio > 0.50) return "sparse data";
    if (entropy >= 4.0 and entropy <= 6.5) return "native code";
    return "mixed data";
}

/// Detect overlapping sections in virtual address space
pub fn detectSectionOverlaps(ctx: *const PeCtx) u32 {
    if (ctx.section_entries == null) return 0;
    const entries = ctx.section_entries.?;
    var overlap_count: u32 = 0;

    var i: u32 = 0;
    while (i < ctx.section_count) : (i += 1) {
        const a = &entries[i];
        var a_end = a.virtual_address + a.virtual_size;
        if (a.virtual_size == 0) a_end = a.virtual_address + a.raw_data_size;

        var j = i + 1;
        while (j < ctx.section_count) : (j += 1) {
            const b = &entries[j];
            var b_end = b.virtual_address + b.virtual_size;
            if (b.virtual_size == 0) b_end = b.virtual_address + b.raw_data_size;

            if (a.virtual_address < b_end and b.virtual_address < a_end)
                overlap_count += 1;
        }
    }
    return overlap_count;
}

/// Detect overlapping sections in file offset space
pub fn detectRawOverlaps(ctx: *const PeCtx) u32 {
    if (ctx.section_entries == null) return 0;
    const entries = ctx.section_entries.?;
    var overlap_count: u32 = 0;

    var i: u32 = 0;
    while (i < ctx.section_count) : (i += 1) {
        const a = &entries[i];
        if (a.raw_data_size == 0 or a.raw_data_offset == 0) continue;
        const a_end = a.raw_data_offset + a.raw_data_size;

        var j = i + 1;
        while (j < ctx.section_count) : (j += 1) {
            const b = &entries[j];
            if (b.raw_data_size == 0 or b.raw_data_offset == 0) continue;
            const b_end = b.raw_data_offset + b.raw_data_size;

            if (a.raw_data_offset < b_end and b.raw_data_offset < a_end)
                overlap_count += 1;
        }
    }
    return overlap_count;
}

/// Section analysis results
pub const SectionAnalysis = struct {
    entropy: f64 = 0.0,
    classification: []const u8 = "unknown",
    hash: u64 = 0,
    has_executable_code: bool = false,
    has_writable_data: bool = false,
    zero_fill_ratio: f64 = 0.0,
    unique_byte_count: u32 = 0,
};

/// Analyze a single section
pub fn analyzeSection(sec: *const root.Section) SectionAnalysis {
    var result = SectionAnalysis{};

    if (sec.data == null or sec.data_size == 0) return result;

    result.entropy = calculateEntropy(sec.data, sec.data_size);
    result.classification = classifyDataBlock(sec.data, sec.data_size);
    result.hash = cksum.fnv1a(sec.data.?, sec.data_size);
    result.has_executable_code = (sec.characteristics & root.SCN_MEM_EXECUTE) != 0;
    result.has_writable_data = (sec.characteristics & root.SCN_MEM_WRITE) != 0;

    // Count zero bytes
    var zero_count: u32 = 0;
    var seen = [_]bool{false} ** 256;
    var i: usize = 0;
    while (i < sec.data_size) : (i += 1) {
        if (sec.data.?[i] == 0) zero_count += 1;
        seen[sec.data.?[i]] = true;
    }
    result.zero_fill_ratio = @as(f64, @floatFromInt(zero_count)) /
        @as(f64, @floatFromInt(sec.data_size));

    var unique: u32 = 0;
    for (seen) |s| {
        if (s) unique += 1;
    }
    result.unique_byte_count = unique;

    return result;
}

/// Image-level analysis results
pub const ImageAnalysis = struct {
    total_sections: u32 = 0,
    code_sections: u32 = 0,
    data_sections: u32 = 0,
    total_raw_size: u64 = 0,
    total_virtual_size: u64 = 0,
    avg_entropy: f64 = 0.0,
    max_entropy: f64 = 0.0,
    min_entropy: f64 = 8.0,
    va_overlap_count: u32 = 0,
    raw_overlap_count: u32 = 0,
    suspicious_sections: u32 = 0,
    total_imports: u32 = 0,
    total_exports: u32 = 0,
    total_relocs: u32 = 0,
};

/// Analyze the complete PE image
pub fn analyzeImage(ctx: *const PeCtx) ImageAnalysis {
    var result = ImageAnalysis{};

    if (ctx.section_entries == null) return result;
    const entries = ctx.section_entries.?;

    result.total_sections = ctx.section_count;
    var entropy_sum: f64 = 0.0;
    var entropy_count: u32 = 0;

    var i: u32 = 0;
    while (i < ctx.section_count) : (i += 1) {
        const sec = &entries[i];
        result.total_raw_size += sec.raw_data_size;
        result.total_virtual_size += sec.virtual_size;

        if ((sec.characteristics & root.SCN_CNT_CODE) != 0) result.code_sections += 1;
        if ((sec.characteristics & root.SCN_CNT_INIT_DATA) != 0) result.data_sections += 1;

        if (sec.data != null and sec.data_size > 0) {
            const e = calculateEntropy(sec.data, sec.data_size);
            entropy_sum += e;
            entropy_count += 1;
            if (e > result.max_entropy) result.max_entropy = e;
            if (e < result.min_entropy) result.min_entropy = e;

            // Flag suspicious: high entropy + writable + executable
            if (e > 7.0 and
                (sec.characteristics & root.SCN_MEM_WRITE) != 0 and
                (sec.characteristics & root.SCN_MEM_EXECUTE) != 0)
            {
                result.suspicious_sections += 1;
            }
        }
    }

    if (entropy_count > 0) {
        result.avg_entropy = entropy_sum / @as(f64, @floatFromInt(entropy_count));
    }
    if (result.min_entropy > 7.99) result.min_entropy = 0.0;

    result.va_overlap_count = detectSectionOverlaps(ctx);
    result.raw_overlap_count = detectRawOverlaps(ctx);
    result.total_imports = ctx.import_count;
    result.total_exports = ctx.export_count;
    result.total_relocs = ctx.reloc_count;

    return result;
}

/// Check for common packer signatures in section names
pub fn detectPackerSignatures(ctx: *const PeCtx) u32 {
    if (ctx.section_entries == null) return 0;
    const entries = ctx.section_entries.?;

    const packer_names = [_][]const u8{
        "UPX0", "UPX1", "UPX2", ".aspack", ".adata",
        ".ndata", ".rsrc1", ".themida", "CODE",
        ".vmp0", ".vmp1", ".petite", ".yP",
    };

    var matches: u32 = 0;
    var i: u32 = 0;
    while (i < ctx.section_count) : (i += 1) {
        const name = entries[i].short_name;
        const name_slice = std.mem.sliceTo(&name, 0);
        for (packer_names) |pn| {
            if (std.mem.eql(u8, name_slice, pn)) {
                matches += 1;
                break;
            }
        }
    }
    return matches;
}

/// Count imported functions across all descriptors
pub fn countTotalImportedFunctions(ctx: *const PeCtx) u32 {
    if (ctx.import_descriptors == null) return 0;
    var total: u32 = 0;
    var i: u32 = 0;
    while (i < ctx.import_count) : (i += 1) {
        total += ctx.import_descriptors.?[i].num_thunks;
    }
    return total;
}

/// Count exported forwarders
pub fn countForwarders(ctx: *const PeCtx) u32 {
    if (ctx.export_entries == null) return 0;
    var count: u32 = 0;
    var i: u32 = 0;
    while (i < ctx.export_count) : (i += 1) {
        if (ctx.export_entries.?[i].is_forwarder) count += 1;
    }
    return count;
}

/// Count total relocation entries across all blocks
pub fn countTotalRelocEntries(ctx: *const PeCtx) u32 {
    if (ctx.reloc_blocks == null) return 0;
    var total: u32 = 0;
    var i: u32 = 0;
    while (i < ctx.reloc_count) : (i += 1) {
        total += ctx.reloc_blocks.?[i].count;
    }
    return total;
}

// ── Advanced analysis functions ────────────────────────────────

/// Compute byte frequency histogram
pub fn computeByteHistogram(data: ?[*]const u8, size: usize, histogram: *[256]u32) void {
    @memset(histogram, 0);
    if (data == null or size == 0) return;
    const d = data.?;
    var i: usize = 0;
    while (i < size) : (i += 1) {
        histogram[d[i]] += 1;
    }
}

/// Calculate chi-squared statistic against uniform distribution
pub fn chiSquaredUniform(histogram: *const [256]u32, total: u64) f64 {
    if (total == 0) return 0.0;
    const expected: f64 = @as(f64, @floatFromInt(total)) / 256.0;
    var chi_sq: f64 = 0.0;
    for (histogram) |count| {
        const observed: f64 = @floatFromInt(count);
        const diff = observed - expected;
        chi_sq += (diff * diff) / expected;
    }
    return chi_sq;
}

/// Detect potential code caves (regions of NOP/INT3/zeros within
/// executable sections that could be used for code injection)
pub fn detectCodeCaves(ctx: *const PeCtx, min_size: u32) u32 {
    if (ctx.section_entries == null) return 0;
    var cave_count: u32 = 0;

    var si: u32 = 0;
    while (si < ctx.section_count) : (si += 1) {
        const sec = &ctx.section_entries.?[si];
        if ((sec.characteristics & root.SCN_MEM_EXECUTE) == 0) continue;
        if (sec.data == null or sec.data_size == 0) continue;

        var run_start: u32 = 0;
        var in_cave = false;
        var j: u32 = 0;
        while (j < sec.data_size) : (j += 1) {
            const byte = sec.data.?[j];
            const is_filler = (byte == 0x00 or byte == 0x90 or byte == 0xCC);
            if (is_filler) {
                if (!in_cave) {
                    run_start = j;
                    in_cave = true;
                }
            } else {
                if (in_cave and j - run_start >= min_size) {
                    cave_count += 1;
                }
                in_cave = false;
            }
        }
        if (in_cave and sec.data_size - run_start >= min_size) {
            cave_count += 1;
        }
    }
    return cave_count;
}

/// Detect potential anti-debugging imports
pub fn detectAntiDebugImports(ctx: *const PeCtx) u32 {
    const anti_debug = [_][]const u8{
        "IsDebuggerPresent", "CheckRemoteDebuggerPresent",
        "NtQueryInformationProcess", "NtSetInformationThread",
        "OutputDebugStringA", "OutputDebugStringW",
        "CloseHandle", "UnhandledExceptionFilter",
    };

    if (ctx.import_descriptors == null) return 0;
    var count: u32 = 0;
    var d: u32 = 0;
    while (d < ctx.import_count) : (d += 1) {
        const desc = &ctx.import_descriptors.?[d];
        if (desc.thunks == null) continue;
        var t: u32 = 0;
        while (t < desc.num_thunks) : (t += 1) {
            if (desc.thunks.?[t].name) |name| {
                const span = std.mem.span(name);
                for (anti_debug) |api| {
                    if (std.mem.eql(u8, span, api)) { count += 1; break; }
                }
            }
        }
    }
    return count;
}

/// Compute import table hash (useful for malware family clustering)
pub fn computeImportHash(ctx: *const PeCtx) u64 {
    if (ctx.import_descriptors == null) return 0;
    var hash: u64 = 0xcbf29ce484222325;

    var d: u32 = 0;
    while (d < ctx.import_count) : (d += 1) {
        const desc = &ctx.import_descriptors.?[d];
        if (desc.dll_name) |dll| {
            const span = std.mem.span(dll);
            for (span) |ch| {
                const lower: u8 = if (ch >= 'A' and ch <= 'Z') ch + 32 else ch;
                hash ^= lower;
                hash *%= 0x100000001b3;
            }
        }
        if (desc.thunks == null) continue;
        var t: u32 = 0;
        while (t < desc.num_thunks) : (t += 1) {
            if (desc.thunks.?[t].name) |name| {
                const span = std.mem.span(name);
                for (span) |ch| {
                    hash ^= ch;
                    hash *%= 0x100000001b3;
                }
            }
        }
        hash ^= 0xFF;
        hash *%= 0x100000001b3;
    }
    return hash;
}

/// Analyze RVA coverage — find unmapped virtual address regions
pub fn analyzeRvaCoverage(ctx: *const PeCtx) struct { mapped: u64, unmapped: u64 } {
    var result = .{ .mapped = @as(u64, 0), .unmapped = @as(u64, 0) };
    if (ctx.section_entries == null or ctx.section_count == 0) return result;
    if (ctx.optional_header.size_of_image == 0) return result;

    const entries = ctx.section_entries.?;
    var prev_end: u32 = ctx.optional_header.size_of_headers;

    var i: u32 = 0;
    while (i < ctx.section_count) : (i += 1) {
        const sec = &entries[i];
        if (sec.virtual_address > prev_end) {
            result.unmapped += sec.virtual_address - prev_end;
        }
        const sec_size = @max(sec.virtual_size, sec.raw_data_size);
        result.mapped += sec_size;
        prev_end = sec.virtual_address + sec_size;
    }

    if (ctx.optional_header.size_of_image > prev_end) {
        result.unmapped += ctx.optional_header.size_of_image - prev_end;
    }

    return result;
}

/// Detect TLS callbacks (often used by malware for anti-analysis)
pub fn hasTlsCallbacks(ctx: *const PeCtx) bool {
    const tls_dir = &ctx.optional_header.data_dirs[root.DIR_TLS];
    return tls_dir.rva != 0 and tls_dir.size >= 24;
}

/// Check for .NET/CLR metadata
pub fn hasDotNet(ctx: *const PeCtx) bool {
    const clr_dir = &ctx.optional_header.data_dirs[root.DIR_CLR_RUNTIME];
    return clr_dir.rva != 0 and clr_dir.size > 0;
}

/// Compute section-level similarity (Jaccard index on byte sets)
pub fn sectionSimilarity(sec_a: *const root.Section, sec_b: *const root.Section) f64 {
    if (sec_a.data == null or sec_b.data == null) return 0.0;
    if (sec_a.data_size == 0 or sec_b.data_size == 0) return 0.0;

    var set_a = [_]bool{false} ** 256;
    var set_b = [_]bool{false} ** 256;

    var i: usize = 0;
    while (i < sec_a.data_size) : (i += 1) set_a[sec_a.data.?[i]] = true;
    i = 0;
    while (i < sec_b.data_size) : (i += 1) set_b[sec_b.data.?[i]] = true;

    var intersection: u32 = 0;
    var union_count: u32 = 0;
    for (set_a, set_b) |a, b| {
        if (a and b) intersection += 1;
        if (a or b) union_count += 1;
    }

    if (union_count == 0) return 0.0;
    return @as(f64, @floatFromInt(intersection)) /
        @as(f64, @floatFromInt(union_count));
}

// ── Rich Header Analysis ───────────────────────────────────────

/// Parse Rich header from DOS stub
pub fn parseRichHeader(data: [*]const u8, size: usize) ?struct {
    xor_key: u32,
    entry_count: u32,
    entries: [32]struct { comp_id: u32, use_count: u32 },
} {
    if (size < 128) return null;

    // Search for "Rich" signature
    var rich_offset: ?usize = null;
    var i: usize = 64;
    while (i + 4 < size and i < 1024) : (i += 4) {
        if (rd.readU32At(data + i) == 0x68636952) {
            rich_offset = i;
            break;
        }
    }

    const offset = rich_offset orelse return null;
    if (offset + 4 >= size) return null;

    // XOR key follows "Rich"
    const xor_key = rd.readU32At(data + offset + 4);

    // Search backwards for "DanS" ^ xor_key
    const dans_marker = 0x536E6144 ^ xor_key;
    var dans_offset: ?usize = null;
    i = 64;
    while (i < offset) : (i += 4) {
        if (rd.readU32At(data + i) == dans_marker) {
            dans_offset = i;
            break;
        }
    }

    const start = dans_offset orelse return null;

    var result: struct {
        xor_key: u32,
        entry_count: u32,
        entries: [32]struct { comp_id: u32, use_count: u32 },
    } = undefined;
    result.xor_key = xor_key;
    result.entry_count = 0;
    result.entries = [_]struct { comp_id: u32, use_count: u32 }{.{ .comp_id = 0, .use_count = 0 }} ** 32;

    // Parse entries (skip first 16 bytes = DanS + 3 padding)
    var pos = start + 16;
    while (pos + 8 <= offset and result.entry_count < 32) : (pos += 8) {
        const comp_id = rd.readU32At(data + pos) ^ xor_key;
        const use_count = rd.readU32At(data + pos + 4) ^ xor_key;
        result.entries[result.entry_count] = .{
            .comp_id = comp_id,
            .use_count = use_count,
        };
        result.entry_count += 1;
    }

    return result;
}

/// Extract printable ASCII strings from a data buffer
pub fn extractStrings(data: ?[*]const u8, size: usize, min_len: usize,
                      callback: *const fn(offset: usize, str: []const u8) void) u32 {
    if (data == null or size == 0) return 0;
    const d = data.?;

    var count: u32 = 0;
    var run_start: usize = 0;
    var in_string = false;

    var i: usize = 0;
    while (i < size) : (i += 1) {
        const is_printable = d[i] >= 0x20 and d[i] <= 0x7E;
        if (is_printable) {
            if (!in_string) {
                run_start = i;
                in_string = true;
            }
        } else {
            if (in_string and i - run_start >= min_len) {
                callback(run_start, d[run_start..i]);
                count += 1;
            }
            in_string = false;
        }
    }
    if (in_string and size - run_start >= min_len) {
        callback(run_start, d[run_start..size]);
        count += 1;
    }

    return count;
}

/// Count printable strings in a section
pub fn countStringsInSection(sec: *const root.Section, min_len: usize) u32 {
    if (sec.data == null or sec.data_size == 0) return 0;

    var count: u32 = 0;
    var run_len: usize = 0;

    var i: usize = 0;
    while (i < sec.data_size) : (i += 1) {
        const ch = sec.data.?[i];
        if (ch >= 0x20 and ch <= 0x7E) {
            run_len += 1;
        } else {
            if (run_len >= min_len) count += 1;
            run_len = 0;
        }
    }
    if (run_len >= min_len) count += 1;

    return count;
}

/// Compute PE anomaly score (0-100, higher = more suspicious)
pub fn computeAnomalyScore(ctx: *const PeCtx) u32 {
    var score: u32 = 0;

    // Check entry point
    if (ctx.optional_header.entry_point_rva == 0 and
        (ctx.coff_header.characteristics & 0x2000) == 0)
    {
        score += 10; // Non-DLL with no entry point
    }

    // Check for RWX sections
    if (ctx.section_entries) |entries| {
        var i: u32 = 0;
        while (i < ctx.section_count) : (i += 1) {
            const chars = entries[i].characteristics;
            if ((chars & root.SCN_MEM_WRITE) != 0 and
                (chars & root.SCN_MEM_EXECUTE) != 0)
            {
                score += 15;
            }
        }
    }

    // No relocations but ASLR flag set
    if ((ctx.optional_header.dll_characteristics & 0x0040) != 0 and
        ctx.reloc_count == 0)
    {
        score += 10;
    }

    // Very few imports
    if (ctx.import_count > 0 and ctx.import_count < 3) {
        score += 10;
    }

    // Non-standard section names
    if (ctx.section_entries) |entries| {
        var non_std: u32 = 0;
        var i: u32 = 0;
        while (i < ctx.section_count) : (i += 1) {
            const name = std.mem.sliceTo(&entries[i].short_name, 0);
            const standard = [_][]const u8{
                ".text", ".data", ".rdata", ".bss", ".idata",
                ".edata", ".rsrc", ".reloc", ".pdata",
            };
            var is_std = false;
            for (standard) |sn| {
                if (std.mem.eql(u8, name, sn)) { is_std = true; break; }
            }
            if (!is_std) non_std += 1;
        }
        if (non_std > ctx.section_count / 2) score += 15;
    }

    // High entropy in first code section
    if (ctx.section_entries) |entries| {
        var i: u32 = 0;
        while (i < ctx.section_count) : (i += 1) {
            if ((entries[i].characteristics & root.SCN_CNT_CODE) != 0) {
                const e = calculateEntropy(entries[i].data, entries[i].data_size);
                if (e > 7.0) score += 20;
                break;
            }
        }
    }

    // Checksum mismatch
    if (ctx.optional_header.pe_checksum != 0) {
        if (!cksum.verify(ctx)) score += 5;
    }

    // Many validation issues
    if (ctx.issue_count > 10) score += 10;

    return @min(score, 100);
}

/// Detect potential overlay data (data after last section)
pub fn detectOverlay(ctx: *const PeCtx) struct { has_overlay: bool, offset: u32, size: u64 } {
    var result = .{ .has_overlay = false, .offset = @as(u32, 0), .size = @as(u64, 0) };

    if (ctx.section_entries == null or ctx.section_count == 0) return result;

    // Find the end of the last section's raw data
    var max_end: u32 = 0;
    var i: u32 = 0;
    while (i < ctx.section_count) : (i += 1) {
        const sec = &ctx.section_entries.?[i];
        if (sec.raw_data_offset == 0 or sec.raw_data_size == 0) continue;
        const end = sec.raw_data_offset + sec.raw_data_size;
        if (end > max_end) max_end = end;
    }

    if (max_end > 0 and max_end < ctx.size) {
        result.has_overlay = true;
        result.offset = max_end;
        result.size = ctx.size - max_end;
    }

    return result;
}

// ── PE structure anomaly detection ─────────────────────────────

/// Detect potential process hollowing indicators
pub fn detectHollowingIndicators(ctx: *const PeCtx) u32 {
    var indicators: u32 = 0;

    // Unmapped entry point
    if (ctx.optional_header.entry_point_rva != 0) {
        if (rd.findSectionByRva(ctx, ctx.optional_header.entry_point_rva) == null) {
            indicators += 1;
        }
    }

    // Discrepancy between virtual and raw sizes
    if (ctx.section_entries) |entries| {
        var i: u32 = 0;
        while (i < ctx.section_count) : (i += 1) {
            const sec = &entries[i];
            if (sec.virtual_size > 0 and sec.raw_data_size == 0 and
                (sec.characteristics & root.SCN_CNT_CODE) != 0)
            {
                indicators += 1;
            }
        }
    }

    return indicators;
}

/// Compute a normalized suspicion score based on multiple factors
pub fn computeSuspicionScore(ctx: *const PeCtx) struct { score: u32, factors: [8]bool } {
    var result: struct { score: u32, factors: [8]bool } = undefined;
    result.score = 0;
    result.factors = [_]bool{false} ** 8;

    // Factor 0: RWX sections
    if (ctx.section_entries) |entries| {
        var i: u32 = 0;
        while (i < ctx.section_count) : (i += 1) {
            const c = entries[i].characteristics;
            if (c & root.SCN_MEM_WRITE != 0 and c & root.SCN_MEM_EXECUTE != 0) {
                result.factors[0] = true;
                result.score += 20;
                break;
            }
        }
    }

    // Factor 1: High entropy code section
    if (ctx.section_entries) |entries| {
        var i: u32 = 0;
        while (i < ctx.section_count) : (i += 1) {
            if (entries[i].characteristics & root.SCN_CNT_CODE != 0) {
                if (calculateEntropy(entries[i].data, entries[i].data_size) > 7.0) {
                    result.factors[1] = true;
                    result.score += 25;
                }
                break;
            }
        }
    }

    // Factor 2: Very few imports
    if (ctx.import_count > 0 and ctx.import_count <= 2) {
        result.factors[2] = true;
        result.score += 15;
    }

    // Factor 3: Non-standard section names
    if (ctx.section_entries) |entries| {
        const names = [_][]const u8{ ".text", ".data", ".rdata", ".bss", ".idata", ".edata", ".rsrc", ".reloc", ".pdata" };
        var non_std: u32 = 0;
        var i: u32 = 0;
        while (i < ctx.section_count) : (i += 1) {
            const name = std.mem.sliceTo(&entries[i].short_name, 0);
            var found = false;
            for (names) |n| { if (std.mem.eql(u8, name, n)) { found = true; break; } }
            if (!found) non_std += 1;
        }
        if (non_std > ctx.section_count / 2) {
            result.factors[3] = true;
            result.score += 15;
        }
    }

    // Factor 4: TLS callbacks
    if (ctx.optional_header.data_dirs[root.DIR_TLS].rva != 0) {
        result.factors[4] = true;
        result.score += 10;
    }

    // Factor 5: No relocations but ASLR
    if (ctx.optional_header.dll_characteristics & 0x0040 != 0 and ctx.reloc_count == 0) {
        result.factors[5] = true;
        result.score += 10;
    }

    // Factor 6: Checksum mismatch
    if (ctx.optional_header.pe_checksum != 0 and !cksum.verify(ctx)) {
        result.factors[6] = true;
        result.score += 5;
    }

    // Factor 7: Many validation issues
    if (ctx.issue_count > 10) {
        result.factors[7] = true;
        result.score += 10;
    }

    if (result.score > 100) result.score = 100;
    return result;
}

/// Analyze import API categories
pub fn categorizeImports(ctx: *const PeCtx) struct {
    file_io: u32, registry: u32, network: u32, process: u32,
    memory: u32, crypto: u32, debug_api: u32, other: u32
} {
    var result: struct {
        file_io: u32, registry: u32, network: u32, process: u32,
        memory: u32, crypto: u32, debug_api: u32, other: u32
    } = .{ .file_io = 0, .registry = 0, .network = 0, .process = 0,
           .memory = 0, .crypto = 0, .debug_api = 0, .other = 0 };

    if (ctx.import_descriptors == null) return result;

    const file_apis = [_][]const u8{ "CreateFile", "ReadFile", "WriteFile", "DeleteFile", "CopyFile", "MoveFile" };
    const reg_apis = [_][]const u8{ "RegOpenKey", "RegSetValue", "RegQueryValue", "RegDeleteKey", "RegCreateKey" };
    const net_apis = [_][]const u8{ "connect", "send", "recv", "socket", "bind", "listen", "accept" };
    const proc_apis = [_][]const u8{ "CreateProcess", "OpenProcess", "TerminateProcess", "CreateThread", "CreateRemoteThread" };
    const mem_apis = [_][]const u8{ "VirtualAlloc", "VirtualProtect", "VirtualFree", "HeapAlloc", "HeapFree" };
    const crypto_apis = [_][]const u8{ "CryptEncrypt", "CryptDecrypt", "CryptGenKey", "CryptImportKey" };
    const debug_apis = [_][]const u8{ "IsDebuggerPresent", "CheckRemoteDebuggerPresent", "OutputDebugString" };

    var d: u32 = 0;
    while (d < ctx.import_count) : (d += 1) {
        const desc = &ctx.import_descriptors.?[d];
        if (desc.thunks == null) continue;
        var t: u32 = 0;
        while (t < desc.num_thunks) : (t += 1) {
            if (desc.thunks.?[t].name == null) continue;
            const name = std.mem.span(desc.thunks.?[t].name.?);

            var categorized = false;
            for (file_apis) |api| { if (startsWith(name, api)) { result.file_io += 1; categorized = true; break; } }
            if (!categorized) for (reg_apis) |api| { if (startsWith(name, api)) { result.registry += 1; categorized = true; break; } };
            if (!categorized) for (net_apis) |api| { if (std.mem.eql(u8, name, api)) { result.network += 1; categorized = true; break; } };
            if (!categorized) for (proc_apis) |api| { if (startsWith(name, api)) { result.process += 1; categorized = true; break; } };
            if (!categorized) for (mem_apis) |api| { if (startsWith(name, api)) { result.memory += 1; categorized = true; break; } };
            if (!categorized) for (crypto_apis) |api| { if (startsWith(name, api)) { result.crypto += 1; categorized = true; break; } };
            if (!categorized) for (debug_apis) |api| { if (startsWith(name, api)) { result.debug_api += 1; categorized = true; break; } };
            if (!categorized) result.other += 1;
        }
    }
    return result;
}

fn startsWith(str: []const u8, prefix: []const u8) bool {
    if (str.len < prefix.len) return false;
    return std.mem.eql(u8, str[0..prefix.len], prefix);
}

// ── PE header anomaly assessment ───────────────────────────────

/// Check for header anomalies that may indicate tampering
pub fn checkHeaderAnomalies(ctx: *const PeCtx) u32 {
    var anomalies: u32 = 0;

    // DOS header anomalies
    if (ctx.dos_header.e_lfanew > 4096) anomalies += 1;
    if (ctx.dos_header.e_lfanew < 64) anomalies += 1;

    // COFF anomalies
    if (ctx.coff_header.num_sections == 0) anomalies += 1;
    if (ctx.coff_header.num_sections > 96) anomalies += 1;
    if (ctx.coff_header.timestamp == 0xFFFFFFFF) anomalies += 1;

    // Optional header anomalies
    if (ctx.optional_header.section_alignment < ctx.optional_header.file_alignment)
        anomalies += 1;
    if (ctx.optional_header.size_of_image == 0) anomalies += 1;
    if (ctx.optional_header.size_of_headers == 0) anomalies += 1;
    if (ctx.optional_header.size_of_headers > ctx.optional_header.size_of_image)
        anomalies += 1;

    // Image base anomalies
    if (ctx.optional_header.image_base == 0) anomalies += 1;
    if (!ctx.optional_header.is_pe32plus and ctx.optional_header.image_base > 0xFFFFFFFF)
        anomalies += 1;

    return anomalies;
}

/// Estimate the minimum file size needed for this PE
pub fn estimateMinFileSize(ctx: *const PeCtx) u64 {
    var min_size: u64 = ctx.optional_header.size_of_headers;
    if (ctx.section_entries) |entries| {
        var i: u32 = 0;
        while (i < ctx.section_count) : (i += 1) {
            const end = @as(u64, entries[i].raw_data_offset) +
                @as(u64, entries[i].raw_data_size);
            if (end > min_size) min_size = end;
        }
    }
    return min_size;
}

/// Compute file padding ratio (unused space / total size)
pub fn computePaddingRatio(ctx: *const PeCtx) f64 {
    if (ctx.size == 0) return 0.0;
    var used: u64 = ctx.optional_header.size_of_headers;
    if (ctx.section_entries) |entries| {
        var i: u32 = 0;
        while (i < ctx.section_count) : (i += 1) {
            used += entries[i].raw_data_size;
        }
    }
    if (used >= ctx.size) return 0.0;
    return @as(f64, @floatFromInt(ctx.size - used)) /
        @as(f64, @floatFromInt(ctx.size));
}

// PE/COFF analysis complete
