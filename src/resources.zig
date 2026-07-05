// resources.zig — Resource Tree Parsing (Phase 11)
//
// Parses the resource directory tree. The tree has up to 3 levels:
// Type → Name/ID → Language. Leaf nodes contain data RVAs pointing
// to resource data within the resource section.

const std = @import("std");
const root = @import("root.zig");
const rd = @import("reader.zig");
const PeCtx = root.PeCtx;
const ParseError = root.ParseError;
const Reader = rd.Reader;

const MAX_DEPTH = 8;
var global_node_count: u32 = 0;

/// Read a Unicode resource name from the resource section
fn readResourceName(ctx: *PeCtx, base_offset: u32, name_offset: u32) ?[*:0]u8 {
    const abs_offset = base_offset + name_offset;
    if (!ctx.checkOffset(@intCast(abs_offset), 2)) return null;

    const name_len = rd.readU16At(ctx.data + abs_offset);
    if (name_len == 0 or name_len > 256) return null;

    const total_size = @as(u32, 2) + @as(u32, name_len) * 2;
    if (!ctx.checkOffset(@intCast(abs_offset), total_size)) return null;

    // Convert UTF-16LE to ASCII (simplified)
    const buf = ctx.allocator.alloc(u8, name_len + 1) catch return null;
    var i: u32 = 0;
    while (i < name_len) : (i += 1) {
        const wchar = rd.readU16At(ctx.data + abs_offset + 2 + i * 2);
        buf[i] = if (wchar < 128) @intCast(wchar) else '?';
    }
    buf[name_len] = 0;
    return @ptrCast(buf.ptr);
}

fn parseNodeRecursive(ctx: *PeCtx, r: *Reader, base_offset: u32,
                      node_offset: u32, depth: u32) ?*root.ResourceNode {
    if (depth > MAX_DEPTH or global_node_count >= root.MAX_RESOURCE_NODES)
        return null;
    if (!r.seek(base_offset + node_offset)) return null;

    const node = ctx.allocator.create(root.ResourceNode) catch return null;
    node.* = root.ResourceNode{};
    node.depth = depth;
    node.is_directory = true;
    global_node_count += 1;

    // Resource directory table (16 bytes)
    _ = r.readU32(); // characteristics
    _ = r.readU32(); // timestamp
    _ = r.readU16(); // major version
    _ = r.readU16(); // minor version
    const num_named = r.readU16() orelse return node;
    const num_id = r.readU16() orelse return node;

    const total: u32 = @as(u32, num_named) + @as(u32, num_id);
    if (total == 0) return node;

    const children = ctx.allocator.alloc(root.ResourceNode, total) catch return node;
    @memset(children, root.ResourceNode{});
    node.children = children.ptr;
    node.children_capacity = total;

    var ci: u32 = 0;
    while (ci < total) : (ci += 1) {
        const name_or_id = r.readU32() orelse break;
        const data_or_subdir = r.readU32() orelse break;

        const child = &children[ci];
        child.depth = depth + 1;

        // Named vs ID entry
        if (name_or_id & 0x80000000 != 0) {
            child.is_named = true;
            const name_off = name_or_id & 0x7FFFFFFF;
            child.name = readResourceName(ctx, base_offset, name_off);
            child.id = name_off;
        } else {
            child.id = name_or_id;
        }

        // Subdirectory vs data entry
        if (data_or_subdir & 0x80000000 != 0) {
            child.is_directory = true;
            const subdir_offset = data_or_subdir & 0x7FFFFFFF;
            const saved_pos = r.tell();
            const sub = parseNodeRecursive(ctx, r, base_offset, subdir_offset, depth + 1);
            if (sub) |s| {
                child.children = s.children;
                child.num_children = s.num_children;
                child.children_capacity = s.children_capacity;
                ctx.allocator.destroy(s);
            }
            _ = r.seek(saved_pos);
        } else {
            // Data entry: 16 bytes (RVA, size, codepage, reserved)
            const saved_pos = r.tell();
            if (r.seek(base_offset + data_or_subdir)) {
                child.data_rva = r.readU32() orelse 0;
                child.data_size = r.readU32() orelse 0;
                child.codepage = r.readU32() orelse 0;
                _ = r.readU32(); // reserved

                // Resolve data pointer into section data
                if (child.data_rva != 0) {
                    if (rd.findSectionByRva(ctx, child.data_rva)) |si| {
                        child.data_ptr = rd.sectionRvaToPtr(ctx, si, child.data_rva, 1);
                    }
                }
            }
            _ = r.seek(saved_pos);
        }

        node.num_children = ci + 1;
    }

    return node;
}

/// Flatten the resource tree into a linear array for indexed access
fn flattenTree(ctx: *PeCtx, node: *root.ResourceNode) void {
    if (node.children == null) {
        // Leaf node — add to flat list
        if (ctx.resource_flat == null or ctx.resource_flat_count >= ctx.resource_flat_capacity) {
            const new_cap = if (ctx.resource_flat_capacity == 0) @as(u32, 32)
                else ctx.resource_flat_capacity * 2;
            const new_arr = ctx.allocator.alloc(?*root.ResourceNode, new_cap) catch return;
            if (ctx.resource_flat) |old| {
                @memcpy(new_arr[0..ctx.resource_flat_count], old[0..ctx.resource_flat_count]);
                ctx.allocator.free(old[0..ctx.resource_flat_capacity]);
            }
            ctx.resource_flat = new_arr.ptr;
            ctx.resource_flat_capacity = new_cap;
        }
        ctx.resource_flat.?[ctx.resource_flat_count] = node;
        ctx.resource_flat_count += 1;
        return;
    }

    var i: u32 = 0;
    while (i < node.num_children) : (i += 1) {
        flattenTree(ctx, &node.children.?[i]);
    }
}

/// Count total nodes in tree (recursive)
pub fn countNodes(node: *const root.ResourceNode) u32 {
    var count: u32 = 1;
    if (node.children) |children| {
        var i: u32 = 0;
        while (i < node.num_children) : (i += 1) {
            count += countNodes(&children[i]);
        }
    }
    return count;
}

/// Find resource node by type and ID
pub fn findByTypeAndId(node: *const root.ResourceNode, type_id: u32, res_id: u32) ?*const root.ResourceNode {
    if (node.children == null) return null;

    var i: u32 = 0;
    while (i < node.num_children) : (i += 1) {
        const type_node = &node.children.?[i];
        if (type_node.id != type_id) continue;
        if (type_node.children == null) continue;

        var j: u32 = 0;
        while (j < type_node.num_children) : (j += 1) {
            if (type_node.children.?[j].id == res_id)
                return &type_node.children.?[j];
        }
    }
    return null;
}

/// Count resources by type
pub fn countByType(node: *const root.ResourceNode, type_id: u32) u32 {
    if (node.children == null) return 0;
    var i: u32 = 0;
    while (i < node.num_children) : (i += 1) {
        if (node.children.?[i].id == type_id) {
            return node.children.?[i].num_children;
        }
    }
    return 0;
}

/// Get total data size of all leaf resources
pub fn totalDataSize(node: *const root.ResourceNode) u64 {
    if (node.children == null) return node.data_size;
    var total: u64 = 0;
    var i: u32 = 0;
    while (i < node.num_children) : (i += 1) {
        total += totalDataSize(&node.children.?[i]);
    }
    return total;
}

pub fn parse(ctx: *PeCtx) ParseError!void {
    const rsrc_dir = &ctx.optional_header.data_dirs[root.DIR_RESOURCE];
    if (rsrc_dir.rva == 0 or rsrc_dir.size == 0) return;

    const base_offset = ctx.rvaToOffset(rsrc_dir.rva) orelse return;
    var r = Reader.init(ctx.data, ctx.size);

    global_node_count = 0;
    ctx.resource_root = parseNodeRecursive(ctx, &r, @intCast(base_offset), 0, 0);

    // Build flat index
    if (ctx.resource_root) |tree_root| {
        flattenTree(ctx, tree_root);
    }
}

// ── Version Info Parsing ───────────────────────────────────────

/// VS_VERSIONINFO fixed file info
pub const FixedFileInfo = struct {
    signature: u32 = 0,
    struct_version: u32 = 0,
    file_version_ms: u32 = 0,
    file_version_ls: u32 = 0,
    product_version_ms: u32 = 0,
    product_version_ls: u32 = 0,
    file_flags_mask: u32 = 0,
    file_flags: u32 = 0,
    file_os: u32 = 0,
    file_type: u32 = 0,
    file_subtype: u32 = 0,
    file_date_ms: u32 = 0,
    file_date_ls: u32 = 0,
};

/// Parse VS_FIXEDFILEINFO from resource data
pub fn parseFixedFileInfo(data: [*]const u8, size: usize) ?FixedFileInfo {
    if (size < 52) return null;

    var info = FixedFileInfo{};
    info.signature = rd.readU32At(data);
    if (info.signature != 0xFEEF04BD) return null;

    info.struct_version = rd.readU32At(data + 4);
    info.file_version_ms = rd.readU32At(data + 8);
    info.file_version_ls = rd.readU32At(data + 12);
    info.product_version_ms = rd.readU32At(data + 16);
    info.product_version_ls = rd.readU32At(data + 20);
    info.file_flags_mask = rd.readU32At(data + 24);
    info.file_flags = rd.readU32At(data + 28);
    info.file_os = rd.readU32At(data + 32);
    info.file_type = rd.readU32At(data + 36);
    info.file_subtype = rd.readU32At(data + 40);
    info.file_date_ms = rd.readU32At(data + 44);
    info.file_date_ls = rd.readU32At(data + 48);

    return info;
}

/// Extract version string "major.minor.build.revision"
pub fn formatVersion(version_ms: u32, version_ls: u32, buf: []u8) usize {
    const major = version_ms >> 16;
    const minor = version_ms & 0xFFFF;
    const build = version_ls >> 16;
    const revision = version_ls & 0xFFFF;

    var pos: usize = 0;
    pos += writeDecimal(major, buf[pos..]);
    if (pos < buf.len) { buf[pos] = '.'; pos += 1; }
    pos += writeDecimal(minor, buf[pos..]);
    if (pos < buf.len) { buf[pos] = '.'; pos += 1; }
    pos += writeDecimal(build, buf[pos..]);
    if (pos < buf.len) { buf[pos] = '.'; pos += 1; }
    pos += writeDecimal(revision, buf[pos..]);
    return pos;
}

fn writeDecimal(val: u32, buf: []u8) usize {
    if (buf.len == 0) return 0;
    if (val == 0) { buf[0] = '0'; return 1; }

    var tmp: [10]u8 = undefined;
    var len: usize = 0;
    var v = val;
    while (v > 0) : (v /= 10) {
        tmp[len] = @intCast('0' + v % 10);
        len += 1;
    }

    const copy = @min(len, buf.len);
    var i: usize = 0;
    while (i < copy) : (i += 1) {
        buf[i] = tmp[len - 1 - i];
    }
    return copy;
}

/// Get file type name from VS_FIXEDFILEINFO
pub fn getFileTypeName(file_type: u32) []const u8 {
    return switch (file_type) {
        1 => "Application",
        2 => "DLL",
        3 => "Device Driver",
        4 => "Font",
        5 => "VxD",
        7 => "Static Library",
        else => "Unknown",
    };
}

/// Get file OS name
pub fn getFileOsName(file_os: u32) []const u8 {
    return switch (file_os) {
        0x00010000 => "DOS",
        0x00040000 => "Windows NT",
        0x00040004 => "Windows NT/Win32",
        0x00010001 => "DOS/Win16",
        0x00010004 => "DOS/Win32",
        0x00020004 => "OS/2/Win32",
        else => "Unknown",
    };
}

/// Check for manifest resource (type 24)
pub fn hasManifest(ctx: *const PeCtx) bool {
    if (ctx.resource_root == null) return false;
    return countByType(ctx.resource_root.?, root.RT_MANIFEST) > 0;
}

/// Check for version info resource (type 16)
pub fn hasVersionInfo(ctx: *const PeCtx) bool {
    if (ctx.resource_root == null) return false;
    return countByType(ctx.resource_root.?, root.RT_VERSION) > 0;
}

/// Count icons in resource tree
pub fn countIcons(ctx: *const PeCtx) u32 {
    if (ctx.resource_root == null) return 0;
    return countByType(ctx.resource_root.?, root.RT_ICON) +
        countByType(ctx.resource_root.?, 14); // RT_GROUP_ICON
}

/// Count string tables in resource tree
pub fn countStringTables(ctx: *const PeCtx) u32 {
    if (ctx.resource_root == null) return 0;
    return countByType(ctx.resource_root.?, root.RT_STRING);
}

/// Count dialogs in resource tree
pub fn countDialogs(ctx: *const PeCtx) u32 {
    if (ctx.resource_root == null) return 0;
    return countByType(ctx.resource_root.?, root.RT_DIALOG);
}

/// Get maximum tree depth
pub fn getMaxDepth(node: *const root.ResourceNode) u32 {
    var max_d: u32 = node.depth;
    if (node.children) |children| {
        var i: u32 = 0;
        while (i < node.num_children) : (i += 1) {
            const child_depth = getMaxDepth(&children[i]);
            if (child_depth > max_d) max_d = child_depth;
        }
    }
    return max_d;
}

/// Count leaf nodes (data entries) in tree
pub fn countLeafNodes(node: *const root.ResourceNode) u32 {
    if (node.children == null) return 1;
    var count: u32 = 0;
    var i: u32 = 0;
    while (i < node.num_children) : (i += 1) {
        count += countLeafNodes(&node.children.?[i]);
    }
    return count;
}

// ── Manifest and Version String Analysis ───────────────────────

/// Extract manifest XML snippet from resource data
pub fn extractManifestSnippet(ctx: *const PeCtx, buf: []u8) usize {
    if (ctx.resource_root == null) return 0;

    // Find RT_MANIFEST (type 24) resource
    if (ctx.resource_root.?.children == null) return 0;
    var i: u32 = 0;
    while (i < ctx.resource_root.?.num_children) : (i += 1) {
        const type_node = &ctx.resource_root.?.children.?[i];
        if (type_node.id != root.RT_MANIFEST) continue;

        // Get first child's data
        if (type_node.children) |children| {
            if (children[0].children) |lang_nodes| {
                const leaf = &lang_nodes[0];
                if (leaf.data_ptr) |data| {
                    const copy_len = @min(leaf.data_size, buf.len - 1);
                    @memcpy(buf[0..copy_len], data[0..copy_len]);
                    buf[copy_len] = 0;
                    return copy_len;
                }
            }
        }
    }
    return 0;
}

/// Check manifest for requestedExecutionLevel
pub fn getExecutionLevel(manifest_data: []const u8) []const u8 {
    // Simple substring search for execution level
    const levels = [_]struct { marker: []const u8, name: []const u8 }{
        .{ .marker = "requireAdministrator", .name = "requireAdministrator" },
        .{ .marker = "highestAvailable", .name = "highestAvailable" },
        .{ .marker = "asInvoker", .name = "asInvoker" },
    };

    for (levels) |level| {
        if (containsSubstring(manifest_data, level.marker)) {
            return level.name;
        }
    }
    return "unknown";
}

fn containsSubstring(haystack: []const u8, needle: []const u8) bool {
    if (needle.len > haystack.len) return false;
    var i: usize = 0;
    while (i + needle.len <= haystack.len) : (i += 1) {
        if (std.mem.eql(u8, haystack[i..][0..needle.len], needle)) return true;
    }
    return false;
}

/// Extract VS_VERSIONINFO strings from version resource data
pub fn extractVersionStrings(data: [*]const u8, size: usize,
                             callback: *const fn(key: []const u8, value: []const u8) void) u32 {
    if (size < 6) return 0;
    var count: u32 = 0;

    // Walk through VS_VERSIONINFO structure looking for StringTable entries
    var pos: usize = 0;
    while (pos + 6 < size and count < 32) {
        const entry_len = rd.readU16At(data + pos);
        const value_len = rd.readU16At(data + pos + 2);
        const entry_type = rd.readU16At(data + pos + 4);

        if (entry_len == 0 or entry_len > size - pos) break;

        // Type 1 = text, Type 0 = binary
        if (entry_type == 1 and value_len > 0) {
            // Read key (Unicode string after the 6-byte header)
            var key_buf: [128]u8 = undefined;
            const key_len = rd.readWideStringAt(data, pos + 6, size, &key_buf);
            if (key_len > 0) {
                // Value follows key with alignment
                const key_bytes = (key_len + 1) * 2;
                var val_off = pos + 6 + key_bytes;
                val_off = (val_off + 3) & ~@as(usize, 3); // align to 4

                if (val_off + value_len * 2 <= size) {
                    var val_buf: [256]u8 = undefined;
                    const val_len = rd.readWideStringAt(data, val_off, size, &val_buf);
                    if (val_len > 0) {
                        callback(key_buf[0..key_len], val_buf[0..val_len]);
                        count += 1;
                    }
                }
            }
        }

        // Move to next entry (aligned)
        pos += (entry_len + 3) & ~@as(usize, 3);
    }
    return count;
}

/// Count resource types present in the tree
pub fn countResourceTypes(ctx: *const PeCtx) u32 {
    if (ctx.resource_root == null) return 0;
    return ctx.resource_root.?.num_children;
}

/// Get list of resource type IDs present
pub fn getResourceTypeIds(ctx: *const PeCtx, ids: []u32) u32 {
    if (ctx.resource_root == null) return 0;
    const root_node = ctx.resource_root.?;
    if (root_node.children == null) return 0;

    var count: u32 = 0;
    var i: u32 = 0;
    while (i < root_node.num_children and count < ids.len) : (i += 1) {
        ids[count] = root_node.children.?[i].id;
        count += 1;
    }
    return count;
}

/// Compute total resource data overhead (tree nodes vs data)
pub fn computeResourceOverhead(ctx: *const PeCtx) struct { tree_nodes: u32, data_bytes: u64 } {
    var result = .{ .tree_nodes = @as(u32, 0), .data_bytes = @as(u64, 0) };
    if (ctx.resource_root == null) return result;
    result.tree_nodes = countNodes(ctx.resource_root.?);
    result.data_bytes = totalDataSize(ctx.resource_root.?);
    return result;
}
