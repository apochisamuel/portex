// reader.zig — Binary data reader utilities
//
// Cursor-based reader for safe sequential and random access
// to raw PE binary data. All multi-byte reads are little-endian
// per the PE/COFF specification.

const std = @import("std");
const root = @import("root.zig");
const PeCtx = root.PeCtx;

pub const Reader = struct {
    base: [*]const u8,
    total_size: usize,
    offset: usize,

    pub fn init(data: [*]const u8, size: usize) Reader {
        return .{
            .base = data,
            .total_size = size,
            .offset = 0,
        };
    }

    pub fn seek(self: *Reader, off: usize) bool {
        if (off > self.total_size) return false;
        self.offset = off;
        return true;
    }

    pub fn skip(self: *Reader, count: usize) bool {
        if (count > self.total_size - self.offset) return false;
        self.offset += count;
        return true;
    }

    pub fn tell(self: *const Reader) usize {
        return self.offset;
    }

    pub fn remaining(self: *const Reader) usize {
        if (self.offset >= self.total_size) return 0;
        return self.total_size - self.offset;
    }

    pub fn canRead(self: *const Reader, count: usize) bool {
        return self.offset <= self.total_size and
            count <= self.total_size - self.offset;
    }

    pub fn readU8(self: *Reader) ?u8 {
        if (!self.canRead(1)) return null;
        const v = self.base[self.offset];
        self.offset += 1;
        return v;
    }

    pub fn readU16(self: *Reader) ?u16 {
        if (!self.canRead(2)) return null;
        const ptr = self.base + self.offset;
        const v = @as(u16, ptr[0]) | (@as(u16, ptr[1]) << 8);
        self.offset += 2;
        return v;
    }

    pub fn readU32(self: *Reader) ?u32 {
        if (!self.canRead(4)) return null;
        const ptr = self.base + self.offset;
        const v = @as(u32, ptr[0]) |
            (@as(u32, ptr[1]) << 8) |
            (@as(u32, ptr[2]) << 16) |
            (@as(u32, ptr[3]) << 24);
        self.offset += 4;
        return v;
    }

    pub fn readU64(self: *Reader) ?u64 {
        if (!self.canRead(8)) return null;
        const lo = @as(u64, self.readU32() orelse return null);
        const hi = @as(u64, self.readU32() orelse return null);
        return lo | (hi << 32);
    }

    pub fn readBytes(self: *Reader, buf: []u8) bool {
        if (!self.canRead(buf.len)) return false;
        @memcpy(buf, self.base[self.offset..][0..buf.len]);
        self.offset += buf.len;
        return true;
    }

    pub fn peek(self: *const Reader, count: usize) ?[*]const u8 {
        if (!self.canRead(count)) return null;
        return self.base + self.offset;
    }

    pub fn readFixedString(self: *Reader, buf: []u8, len: usize) bool {
        if (!self.canRead(len)) return false;
        const copy_len = @min(len, buf.len - 1);
        @memcpy(buf[0..copy_len], self.base[self.offset..][0..copy_len]);
        buf[copy_len] = 0;
        self.offset += len;
        return true;
    }

    /// Read a null-terminated C string, returns length
    pub fn readCString(self: *Reader, buf: []u8) ?usize {
        if (buf.len == 0) return null;
        var i: usize = 0;
        var max_read = self.remaining();
        if (max_read > buf.len - 1) max_read = buf.len - 1;

        while (i < max_read) {
            const ch = self.base[self.offset + i];
            if (ch == 0) {
                buf[i] = 0;
                self.offset += i + 1;
                return i;
            }
            buf[i] = ch;
            i += 1;
        }
        buf[i] = 0;
        self.offset += i;
        return i;
    }

    /// Copy a range of bytes from the underlying data
    pub fn copyRange(self: *const Reader, allocator: std.mem.Allocator, off: usize, length: usize) ?[]u8 {
        if (off > self.total_size or length > self.total_size - off) return null;
        if (length == 0) return null;
        const buf = allocator.alloc(u8, length) catch return null;
        @memcpy(buf, self.base[off..][0..length]);
        return buf;
    }
};

/// Read a little-endian u16 from a raw pointer
pub fn readU16At(ptr: [*]const u8) u16 {
    return @as(u16, ptr[0]) | (@as(u16, ptr[1]) << 8);
}

/// Read a little-endian u32 from a raw pointer
pub fn readU32At(ptr: [*]const u8) u32 {
    return @as(u32, ptr[0]) |
        (@as(u32, ptr[1]) << 8) |
        (@as(u32, ptr[2]) << 16) |
        (@as(u32, ptr[3]) << 24);
}

/// Read a little-endian u64 from a raw pointer
pub fn readU64At(ptr: [*]const u8) u64 {
    const lo = @as(u64, readU32At(ptr));
    const hi = @as(u64, readU32At(ptr + 4));
    return lo | (hi << 32);
}

/// Find section index containing an RVA
pub fn findSectionByRva(ctx: *const PeCtx, rva: u32) ?u32 {
    if (ctx.section_entries) |entries| {
        var i: u32 = 0;
        while (i < ctx.section_count) : (i += 1) {
            const sec = &entries[i];
            var sec_end = sec.virtual_address + sec.virtual_size;
            if (sec.virtual_size == 0) {
                sec_end = sec.virtual_address + sec.raw_data_size;
            }
            if (rva >= sec.virtual_address and rva < sec_end) {
                return i;
            }
        }
    }
    return null;
}

/// Get a writable pointer into a section's loaded data buffer
pub fn sectionRvaToPtr(ctx: *const PeCtx, section_index: u32, rva: u32, min_size: usize) ?[*]u8 {
    if (ctx.section_entries == null) return null;
    if (section_index >= ctx.section_count) return null;

    const sec = &ctx.section_entries.?[section_index];
    if (sec.data == null or sec.data_size == 0) return null;
    if (rva < sec.virtual_address) return null;

    const delta = rva - sec.virtual_address;
    if (delta >= sec.data_size or min_size > sec.data_size - delta) return null;

    return sec.data.? + delta;
}

// ── Extended reader utilities ──────────────────────────────────

/// Read a null-terminated ASCII string at a given offset (no copy)
pub fn readStringAt(data: [*]const u8, offset: usize, max_size: usize, max_len: usize) ?[]const u8 {
    if (offset >= max_size) return null;
    var available = max_size - offset;
    if (available > max_len) available = max_len;

    var len: usize = 0;
    while (len < available and data[offset + len] != 0) : (len += 1) {}
    if (len == 0) return null;
    return data[offset..][0..len];
}

/// Scan for a byte pattern in data
pub fn findPattern(data: [*]const u8, size: usize, pattern: []const u8) ?usize {
    if (pattern.len == 0 or pattern.len > size) return null;
    var i: usize = 0;
    while (i + pattern.len <= size) : (i += 1) {
        var match = true;
        for (pattern, 0..) |p, j| {
            if (data[i + j] != p) { match = false; break; }
        }
        if (match) return i;
    }
    return null;
}

/// Scan for a u32 value in data (little-endian)
pub fn findU32(data: [*]const u8, size: usize, value: u32) ?usize {
    if (size < 4) return null;
    var i: usize = 0;
    while (i + 4 <= size) : (i += 1) {
        if (readU32At(data + i) == value) return i;
    }
    return null;
}

/// Count occurrences of a byte in data
pub fn countByte(data: [*]const u8, size: usize, byte: u8) u32 {
    var count: u32 = 0;
    var i: usize = 0;
    while (i < size) : (i += 1) {
        if (data[i] == byte) count += 1;
    }
    return count;
}

/// Check if a range is all zeros
pub fn isZeroFilled(data: [*]const u8, offset: usize, size: usize, total: usize) bool {
    if (offset + size > total) return false;
    var i: usize = 0;
    while (i < size) : (i += 1) {
        if (data[offset + i] != 0) return false;
    }
    return true;
}

/// Compute a simple checksum over a range
pub fn rangeChecksum(data: [*]const u8, offset: usize, size: usize, total: usize) u32 {
    if (offset + size > total) return 0;
    var sum: u32 = 0;
    var i: usize = 0;
    while (i < size) : (i += 1) {
        sum +%= data[offset + i];
    }
    return sum;
}

// ── Wide string and alignment utilities ────────────────────────

/// Read a UTF-16LE string at offset, convert to ASCII, return length
pub fn readWideStringAt(data: [*]const u8, offset: usize, max_size: usize,
                        buf: []u8) usize {
    if (offset >= max_size or buf.len == 0) return 0;
    var available = max_size - offset;
    if (available > buf.len * 2) available = buf.len * 2;

    var i: usize = 0;
    while (i * 2 + 1 < available and i < buf.len - 1) {
        const lo = data[offset + i * 2];
        const hi = data[offset + i * 2 + 1];
        if (lo == 0 and hi == 0) break;
        buf[i] = if (hi == 0 and lo >= 0x20 and lo <= 0x7E) lo else '?';
        i += 1;
    }
    buf[i] = 0;
    return i;
}

/// Read a u32 with alignment padding check
pub fn readU32Aligned(data: [*]const u8, offset: usize, size: usize) ?u32 {
    if (offset + 4 > size) return null;
    if (offset & 3 != 0) return null; // Not aligned
    return readU32At(data + offset);
}

/// Read a u64 with alignment check
pub fn readU64Aligned(data: [*]const u8, offset: usize, size: usize) ?u64 {
    if (offset + 8 > size) return null;
    if (offset & 7 != 0) return null;
    return readU64At(data + offset);
}

/// Copy a bounded range from data, clamping to available size
pub fn copyBounded(data: [*]const u8, offset: usize, length: usize,
                   total_size: usize, dest: []u8) usize {
    if (offset >= total_size) return 0;
    var avail = total_size - offset;
    if (avail > length) avail = length;
    if (avail > dest.len) avail = dest.len;
    @memcpy(dest[0..avail], data[offset..][0..avail]);
    return avail;
}

/// Scan forward from offset for a non-zero byte
pub fn findNonZero(data: [*]const u8, offset: usize, size: usize) ?usize {
    if (offset >= size) return null;
    var i = offset;
    while (i < size) : (i += 1) {
        if (data[i] != 0) return i;
    }
    return null;
}

/// Count consecutive zero bytes from offset
pub fn countZeros(data: [*]const u8, offset: usize, size: usize) usize {
    if (offset >= size) return 0;
    var count: usize = 0;
    var i = offset;
    while (i < size and data[i] == 0) : (i += 1) {
        count += 1;
    }
    return count;
}

/// Read a length-prefixed Pascal-style string
pub fn readPascalString(data: [*]const u8, offset: usize, size: usize,
                        buf: []u8) ?usize {
    if (offset >= size) return null;
    const len = data[offset];
    if (len == 0) return 0;
    if (offset + 1 + len > size) return null;
    const copy_len = @min(@as(usize, len), buf.len - 1);
    @memcpy(buf[0..copy_len], data[offset + 1 ..][0..copy_len]);
    buf[copy_len] = 0;
    return copy_len;
}

/// Check if data at offset looks like a PE signature
pub fn looksLikePe(data: [*]const u8, offset: usize, size: usize) bool {
    if (offset + 2 > size) return false;
    return data[offset] == 'M' and data[offset + 1] == 'Z';
}

/// Compute a rolling hash over a window of bytes
pub fn rollingHash(data: [*]const u8, size: usize, window: usize) u32 {
    if (size < window or window == 0) return 0;
    var hash: u32 = 0;
    var i: usize = 0;
    while (i < window) : (i += 1) {
        hash = hash *% 31 +% data[i];
    }
    return hash;
}
