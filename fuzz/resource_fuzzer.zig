const std = @import("std");
const portex = @import("src/root.zig");

export fn LLVMFuzzerTestOneInput(data: [*]const u8, len: usize) c_int {
    if (len == 0) return 0;
    const ctx = portex.PeCtx.open(std.heap.page_allocator, data, len) orelse return 0;
    defer ctx.destroy();
    var total: usize = 0;
    if (ctx.import_cache) |c| { var i: u32 = 0; while (i < ctx.import_cache_count) : (i += 1) { if (c[i].name_ptr) |p| total +%= std.mem.len(p); } }
    if (ctx.export_cache) |c| { var i: u32 = 0; while (i < ctx.export_cache_count) : (i += 1) { if (c[i].name_ptr) |p| total +%= std.mem.len(p); if (c[i].forwarder_ptr) |p| total +%= std.mem.len(p); } }
    if (ctx.debug_cache) |c| { var i: u32 = 0; while (i < ctx.debug_cache_count) : (i += 1) { if (c[i].pdb_path_ptr) |p| total +%= std.mem.len(p); } }
    if (ctx.symbol_cache) |c| { var i: u32 = 0; while (i < ctx.symbol_cache_count) : (i += 1) { if (c[i].name_ptr) |p| total +%= std.mem.len(p); } }
    if (ctx.section_names) |n| { var i: u32 = 0; while (i < ctx.section_name_count) : (i += 1) { if (n[i]) |p| total +%= std.mem.len(p); } }
    if (total > 999999999) return 1;
    return 0;
}
