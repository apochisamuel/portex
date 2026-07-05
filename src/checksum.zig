// checksum.zig — PE Checksum Calculation
//
// Implements the PE image checksum algorithm used by Windows to
// verify file integrity. The checksum covers the entire file
// except for the checksum field itself in the optional header.

const std = @import("std");
const root = @import("root.zig");
const rd = @import("reader.zig");
const PeCtx = root.PeCtx;

/// Compute the PE checksum over the raw file data.
/// The checksum_offset parameter identifies the file offset
/// of the checksum field in the optional header (to be skipped).
pub fn compute(data: [*]const u8, size: usize, checksum_offset: u32) u32 {
    if (size == 0) return 0;

    var sum: u64 = 0;
    var i: usize = 0;

    // Process as 16-bit words
    while (i + 1 < size) : (i += 2) {
        // Skip the checksum field (4 bytes at checksum_offset)
        if (i >= checksum_offset and i < checksum_offset + 4) {
            continue;
        }

        const word: u16 = @as(u16, data[i]) | (@as(u16, data[i + 1]) << 8);
        sum += word;

        // Fold carries
        if (sum > 0xFFFF) {
            sum = (sum & 0xFFFF) + (sum >> 16);
        }
    }

    // Handle odd trailing byte
    if (i < size) {
        sum += data[i];
        if (sum > 0xFFFF) {
            sum = (sum & 0xFFFF) + (sum >> 16);
        }
    }

    // Final fold
    sum = (sum & 0xFFFF) + (sum >> 16);
    if (sum > 0xFFFF) {
        sum = (sum & 0xFFFF) + (sum >> 16);
    }

    // Add file length
    return @intCast(sum + size);
}

/// Verify the PE checksum matches the value in the optional header.
pub fn verify(ctx: *const PeCtx) bool {
    if (ctx.optional_header.pe_checksum == 0) return true;

    // Compute offset of checksum field in optional header
    const opt_offset = ctx.dos_header.e_lfanew + 4 + 20;
    const checksum_field_offset: u32 = opt_offset + 64;

    // PE32+ has checksum at different offset
    if (ctx.optional_header.is_pe32plus) {
        const computed = compute(ctx.data, ctx.size, checksum_field_offset);
        return computed == ctx.optional_header.pe_checksum;
    }

    const computed = compute(ctx.data, ctx.size, checksum_field_offset);
    return computed == ctx.optional_header.pe_checksum;
}

/// Compute checksum of a specific section's data
pub fn sectionChecksum(data: ?[*]const u8, size: usize) u32 {
    if (data == null or size == 0) return 0;
    const d = data.?;

    var sum: u32 = 0;
    var i: usize = 0;
    while (i + 3 < size) : (i += 4) {
        sum ^= rd.readU32At(d + i);
    }
    while (i < size) : (i += 1) {
        sum ^= @as(u32, d[i]) << @intCast((i % 4) * 8);
    }
    return sum;
}

/// FNV-1a hash for data fingerprinting
pub fn fnv1a(data: [*]const u8, size: usize) u64 {
    var hash: u64 = 0xcbf29ce484222325;
    var i: usize = 0;
    while (i < size) : (i += 1) {
        hash ^= data[i];
        hash *%= 0x100000001b3;
    }
    return hash;
}

// ── Additional hash and checksum utilities ─────────────────────

/// CRC32 implementation (IEEE polynomial)
pub fn crc32(data: [*]const u8, size: usize) u32 {
    var crc: u32 = 0xFFFFFFFF;
    var i: usize = 0;
    while (i < size) : (i += 1) {
        crc ^= data[i];
        var bit: u32 = 0;
        while (bit < 8) : (bit += 1) {
            if (crc & 1 != 0) {
                crc = (crc >> 1) ^ 0xEDB88320;
            } else {
                crc >>= 1;
            }
        }
    }
    return crc ^ 0xFFFFFFFF;
}

/// MD5-like simple hash (not cryptographic — for fingerprinting only)
pub fn simpleHash128(data: [*]const u8, size: usize) [16]u8 {
    var state = [4]u32{ 0x67452301, 0xEFCDAB89, 0x98BADCFE, 0x10325476 };
    var i: usize = 0;
    while (i < size) : (i += 1) {
        const byte_val: u32 = data[i];
        state[i % 4] +%= byte_val *% (0x100000001b3 +% @as(u32, @intCast(i & 0xFFFF)));
        state[(i + 1) % 4] ^= state[i % 4];
    }

    var result: [16]u8 = undefined;
    for (0..4) |s| {
        result[s * 4] = @intCast(state[s] & 0xFF);
        result[s * 4 + 1] = @intCast((state[s] >> 8) & 0xFF);
        result[s * 4 + 2] = @intCast((state[s] >> 16) & 0xFF);
        result[s * 4 + 3] = @intCast((state[s] >> 24) & 0xFF);
    }
    return result;
}

/// Adler-32 checksum (faster than CRC32)
pub fn adler32(data: [*]const u8, size: usize) u32 {
    var a: u32 = 1;
    var b: u32 = 0;
    var i: usize = 0;
    while (i < size) : (i += 1) {
        a = (a + data[i]) % 65521;
        b = (b + a) % 65521;
    }
    return (b << 16) | a;
}

/// Compare two data regions and return number of differing bytes
pub fn diffCount(a: [*]const u8, b: [*]const u8, size: usize) u32 {
    var count: u32 = 0;
    var i: usize = 0;
    while (i < size) : (i += 1) {
        if (a[i] != b[i]) count += 1;
    }
    return count;
}

// ── Section and data integrity helpers ─────────────────────────

/// Verify all sections have consistent checksums between
/// the raw file data and the loaded section buffers
pub fn verifySectionIntegrity(ctx: *const root.PeCtx) u32 {
    if (ctx.section_entries == null) return 0;
    var mismatches: u32 = 0;

    var i: u32 = 0;
    while (i < ctx.section_count) : (i += 1) {
        const sec = &ctx.section_entries.?[i];
        if (sec.data == null or sec.data_size == 0) continue;
        if (sec.raw_data_offset == 0) continue;

        // Compare loaded buffer against file data
        const file_hash = fnv1a(ctx.data + sec.raw_data_offset, sec.data_size);
        const buf_hash = fnv1a(sec.data.?, sec.data_size);
        if (file_hash != buf_hash) mismatches += 1;
    }
    return mismatches;
}

/// Compute aggregate hash over all section data
pub fn computeImageHash(ctx: *const root.PeCtx) u64 {
    if (ctx.section_entries == null) return 0;
    var hash: u64 = 0xcbf29ce484222325;

    var i: u32 = 0;
    while (i < ctx.section_count) : (i += 1) {
        const sec = &ctx.section_entries.?[i];
        if (sec.data == null or sec.data_size == 0) continue;
        const sec_hash = fnv1a(sec.data.?, sec.data_size);
        hash ^= sec_hash;
        hash *%= 0x100000001b3;
    }
    return hash;
}

/// XOR two hash values for combined fingerprint
pub fn combineHashes(a: u64, b: u64) u64 {
    return (a ^ b) *% 0x100000001b3;
}
