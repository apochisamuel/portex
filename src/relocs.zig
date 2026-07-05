// relocs.zig — Base Relocation Table Parsing (Phase 9)
//
// Parses the base relocation table which contains fixup entries
// applied when the image is loaded at a different base address.
// Each block covers a 4KB page and contains type+offset entries.

const std = @import("std");
const root = @import("root.zig");
const rd = @import("reader.zig");
const PeCtx = root.PeCtx;
const ParseError = root.ParseError;
const Reader = rd.Reader;

/// Validate a relocation entry
fn validateEntry(ctx: *PeCtx, rel: *const root.RelocEntry, block_rva: u32) void {
    // Type validation
    switch (rel.rel_type) {
        root.REL_BASED_ABSOLUTE,
        1, 2, // HIGH, LOW
        root.REL_BASED_HIGHLOW,
        4, // HIGHADJ
        root.REL_BASED_DIR64,
        => {},
        else => {
            ctx.addIssue(1, 0, "unknown relocation type");
        },
    }

    // Offset should be within the 4KB page
    if (rel.offset >= 4096) {
        ctx.addIssue(1, 0, "relocation offset exceeds page boundary");
    }

    // Skip ABSOLUTE entries (used for padding)
    if (rel.rel_type == root.REL_BASED_ABSOLUTE) return;

    // Target RVA should be within the image
    if (ctx.optional_header.size_of_image > 0 and
        rel.target_rva >= ctx.optional_header.size_of_image)
    {
        ctx.addIssue(1, 0, "relocation target outside image");
    }

    _ = block_rva;
}

/// Validate a relocation block
fn validateBlock(ctx: *PeCtx, page_rva: u32, block_size: u32) void {
    if (block_size < 8) {
        ctx.addIssue(2, 0, "relocation block too small");
    }

    // Page RVA should be page-aligned
    if (page_rva & 0xFFF != 0) {
        ctx.addIssue(1, 0, "relocation page RVA not page-aligned");
    }

    // Block size should be reasonable
    if (block_size > 65536) {
        ctx.addIssue(1, 0, "relocation block unusually large");
    }
}

/// Count absolute (padding) entries in a block
pub fn countAbsoluteEntries(block: *const root.RelocBlock) u32 {
    if (block.entries == null) return 0;
    var count: u32 = 0;
    var i: u32 = 0;
    while (i < block.count) : (i += 1) {
        if (block.entries.?[i].rel_type == root.REL_BASED_ABSOLUTE) count += 1;
    }
    return count;
}

/// Count HIGHLOW entries (32-bit relocations)
pub fn countHighLowEntries(ctx: *const PeCtx) u32 {
    if (ctx.reloc_blocks == null) return 0;
    var count: u32 = 0;
    var bi: u32 = 0;
    while (bi < ctx.reloc_count) : (bi += 1) {
        const block = &ctx.reloc_blocks.?[bi];
        if (block.entries == null) continue;
        var ei: u32 = 0;
        while (ei < block.count) : (ei += 1) {
            if (block.entries.?[ei].rel_type == root.REL_BASED_HIGHLOW) count += 1;
        }
    }
    return count;
}

/// Count DIR64 entries (64-bit relocations)
pub fn countDir64Entries(ctx: *const PeCtx) u32 {
    if (ctx.reloc_blocks == null) return 0;
    var count: u32 = 0;
    var bi: u32 = 0;
    while (bi < ctx.reloc_count) : (bi += 1) {
        const block = &ctx.reloc_blocks.?[bi];
        if (block.entries == null) continue;
        var ei: u32 = 0;
        while (ei < block.count) : (ei += 1) {
            if (block.entries.?[ei].rel_type == root.REL_BASED_DIR64) count += 1;
        }
    }
    return count;
}

/// Get the page RVA range covered by all relocation blocks
pub fn getCoveredRange(ctx: *const PeCtx) struct { min_rva: u32, max_rva: u32 } {
    var result = .{ .min_rva = @as(u32, 0xFFFFFFFF), .max_rva = @as(u32, 0) };
    if (ctx.reloc_blocks == null) return result;
    var bi: u32 = 0;
    while (bi < ctx.reloc_count) : (bi += 1) {
        const rva = ctx.reloc_blocks.?[bi].page_rva;
        if (rva < result.min_rva) result.min_rva = rva;
        if (rva + 4096 > result.max_rva) result.max_rva = rva + 4096;
    }
    return result;
}

pub fn parse(ctx: *PeCtx) ParseError!void {
    const reloc_dir = &ctx.optional_header.data_dirs[root.DIR_BASERELOC];
    if (reloc_dir.rva == 0 or reloc_dir.size == 0) return;

    const dir_offset = ctx.rvaToOffset(reloc_dir.rva) orelse return ParseError.InvalidReloc;
    var r = Reader.init(ctx.data, ctx.size);
    if (!r.seek(dir_offset)) return ParseError.Truncated;

    var bytes_read: u32 = 0;
    while (bytes_read < reloc_dir.size and ctx.reloc_count < root.MAX_RELOC_BLOCKS) {
        const page_rva = r.readU32() orelse break;
        const block_size = r.readU32() orelse break;
        if (block_size < 8) break;

        validateBlock(ctx, page_rva, block_size);

        const num_entries = (block_size - 8) / 2;
        const entries = ctx.allocator.alloc(root.RelocEntry, num_entries) catch break;
        @memset(entries, root.RelocEntry{});

        var ei: u32 = 0;
        while (ei < num_entries) : (ei += 1) {
            const val = r.readU16() orelse break;
            entries[ei].rel_type = (val >> 12) & 0xF;
            entries[ei].offset = val & 0xFFF;
            entries[ei].target_rva = page_rva + entries[ei].offset;

            // Resolve target pointer into section data
            if (rd.findSectionByRva(ctx, entries[ei].target_rva)) |si| {
                entries[ei].target_ptr = rd.sectionRvaToPtr(ctx, si, entries[ei].target_rva, 1);
                entries[ei].resolved = entries[ei].target_ptr != null;
            }

            validateEntry(ctx, &entries[ei], page_rva);
        }

        // Grow block array
        if (ctx.reloc_blocks == null or ctx.reloc_count >= ctx.reloc_capacity) {
            const new_cap = if (ctx.reloc_capacity == 0) @as(u32, 16) else ctx.reloc_capacity * 2;
            const new_arr = ctx.allocator.alloc(root.RelocBlock, new_cap) catch break;
            if (ctx.reloc_blocks) |old| {
                @memcpy(new_arr[0..ctx.reloc_count], old[0..ctx.reloc_count]);
                ctx.allocator.free(old[0..ctx.reloc_capacity]);
            }
            ctx.reloc_blocks = new_arr.ptr;
            ctx.reloc_capacity = new_cap;
        }

        ctx.reloc_blocks.?[ctx.reloc_count] = root.RelocBlock{
            .page_rva = page_rva,
            .block_size = block_size,
            .entries = entries.ptr,
            .count = ei,
            .capacity = @intCast(num_entries),
        };
        ctx.reloc_count += 1;
        bytes_read += block_size;
    }
}

// ── Additional relocation analysis ─────────────────────────────

/// Count unique page RVAs in the relocation table
pub fn countUniquePages(ctx: *const PeCtx) u32 {
    if (ctx.reloc_blocks == null) return 0;
    // Since blocks should be unique per page, just return block count
    return ctx.reloc_count;
}

/// Compute total number of fixups that would be applied
pub fn countTotalFixups(ctx: *const PeCtx) u32 {
    if (ctx.reloc_blocks == null) return 0;
    var total: u32 = 0;
    var bi: u32 = 0;
    while (bi < ctx.reloc_count) : (bi += 1) {
        if (ctx.reloc_blocks.?[bi].entries == null) continue;
        var ei: u32 = 0;
        while (ei < ctx.reloc_blocks.?[bi].count) : (ei += 1) {
            const rel = &ctx.reloc_blocks.?[bi].entries.?[ei];
            if (rel.rel_type != root.REL_BASED_ABSOLUTE) total += 1;
        }
    }
    return total;
}

/// Check if relocations cover the entry point page
pub fn coversEntryPoint(ctx: *const PeCtx) bool {
    if (ctx.reloc_blocks == null or ctx.optional_header.entry_point_rva == 0) return false;
    const ep_page = ctx.optional_header.entry_point_rva & ~@as(u32, 0xFFF);
    var bi: u32 = 0;
    while (bi < ctx.reloc_count) : (bi += 1) {
        if (ctx.reloc_blocks.?[bi].page_rva == ep_page) return true;
    }
    return false;
}

/// Analyze relocation density (fixups per page)
pub fn avgFixupsPerBlock(ctx: *const PeCtx) f64 {
    if (ctx.reloc_blocks == null or ctx.reloc_count == 0) return 0.0;
    var total: u32 = 0;
    var bi: u32 = 0;
    while (bi < ctx.reloc_count) : (bi += 1) {
        total += ctx.reloc_blocks.?[bi].count;
    }
    return @as(f64, @floatFromInt(total)) / @as(f64, @floatFromInt(ctx.reloc_count));
}

/// Find the block with the most fixups
pub fn findDensestBlock(ctx: *const PeCtx) ?u32 {
    if (ctx.reloc_blocks == null or ctx.reloc_count == 0) return null;
    var max_idx: u32 = 0;
    var max_count: u32 = 0;
    var bi: u32 = 0;
    while (bi < ctx.reloc_count) : (bi += 1) {
        if (ctx.reloc_blocks.?[bi].count > max_count) {
            max_count = ctx.reloc_blocks.?[bi].count;
            max_idx = bi;
        }
    }
    return max_idx;
}

// ── Relocation statistics and analysis ─────────────────────────

/// Compute statistics across all relocation blocks
pub fn computeRelocStats(ctx: *const PeCtx) struct {
    total_blocks: u32, total_entries: u32, total_fixups: u32,
    total_absolute: u32, total_highlow: u32, total_dir64: u32,
    avg_per_block: f64, max_per_block: u32, min_per_block: u32,
    unique_pages: u32, covered_bytes: u64,
} {
    var result: @TypeOf(computeRelocStats(undefined)) = undefined;
    @memset(std.mem.asBytes(&result), 0);
    result.min_per_block = 0xFFFFFFFF;

    if (ctx.reloc_blocks == null or ctx.reloc_count == 0) {
        result.min_per_block = 0;
        return result;
    }
    const blocks = ctx.reloc_blocks.?;
    result.total_blocks = ctx.reloc_count;
    result.unique_pages = ctx.reloc_count;

    var bi: u32 = 0;
    while (bi < ctx.reloc_count) : (bi += 1) {
        const block = &blocks[bi];
        result.total_entries += block.count;
        if (block.count > result.max_per_block) result.max_per_block = block.count;
        if (block.count < result.min_per_block) result.min_per_block = block.count;
        result.covered_bytes += 4096;

        if (block.entries == null) continue;
        var ei: u32 = 0;
        while (ei < block.count) : (ei += 1) {
            const rel = &block.entries.?[ei];
            switch (rel.rel_type) {
                root.REL_BASED_ABSOLUTE => result.total_absolute += 1,
                root.REL_BASED_HIGHLOW => { result.total_highlow += 1; result.total_fixups += 1; },
                root.REL_BASED_DIR64 => { result.total_dir64 += 1; result.total_fixups += 1; },
                else => result.total_fixups += 1,
            }
        }
    }

    if (result.total_blocks > 0) {
        result.avg_per_block = @as(f64, @floatFromInt(result.total_entries)) /
            @as(f64, @floatFromInt(result.total_blocks));
    }

    return result;
}

/// Check if relocations are sorted by page RVA
pub fn isSortedByPage(ctx: *const PeCtx) bool {
    if (ctx.reloc_blocks == null or ctx.reloc_count < 2) return true;
    const blocks = ctx.reloc_blocks.?;
    var i: u32 = 1;
    while (i < ctx.reloc_count) : (i += 1) {
        if (blocks[i].page_rva < blocks[i - 1].page_rva) return false;
    }
    return true;
}

/// Compute the percentage of image covered by relocations
pub fn relocationCoverage(ctx: *const PeCtx) f64 {
    if (ctx.optional_header.size_of_image == 0 or ctx.reloc_count == 0) return 0.0;
    const covered = @as(u64, ctx.reloc_count) * 4096;
    return @as(f64, @floatFromInt(covered)) /
        @as(f64, @floatFromInt(ctx.optional_header.size_of_image));
}

/// Find relocation entries targeting a specific RVA
pub fn findRelocsForRva(ctx: *const PeCtx, rva: u32) u32 {
    if (ctx.reloc_blocks == null) return 0;
    const page_rva = rva & ~@as(u32, 0xFFF);
    const offset = rva & 0xFFF;

    var count: u32 = 0;
    var bi: u32 = 0;
    while (bi < ctx.reloc_count) : (bi += 1) {
        const block = &ctx.reloc_blocks.?[bi];
        if (block.page_rva != page_rva) continue;
        if (block.entries == null) continue;
        var ei: u32 = 0;
        while (ei < block.count) : (ei += 1) {
            if (block.entries.?[ei].offset == @as(u16, @intCast(offset))) count += 1;
        }
    }
    return count;
}

/// Check if entry point has relocations
pub fn entryPointHasRelocs(ctx: *const PeCtx) bool {
    if (ctx.optional_header.entry_point_rva == 0) return false;
    return findRelocsForRva(ctx, ctx.optional_header.entry_point_rva) > 0;
}
