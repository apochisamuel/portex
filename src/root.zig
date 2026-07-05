// portex — PE/COFF binary format parser
//
// Parses Portable Executable files (PE32/PE32+) with full coverage
// of import tables, export tables, relocations, debug info, resources,
// COFF symbol tables, exception handling, and delay imports.

const std = @import("std");
const Allocator = std.mem.Allocator;

// Sub-modules
pub const reader = @import("reader.zig");
pub const dos = @import("dos.zig");
pub const coff = @import("coff.zig");
pub const optional = @import("optional.zig");
pub const sections = @import("sections.zig");
pub const strings = @import("strings.zig");
pub const symbols = @import("symbols.zig");
pub const imports = @import("imports.zig");
pub const exports = @import("exports.zig");
pub const relocs = @import("relocs.zig");
pub const debug = @import("debug.zig");
pub const resources = @import("resources.zig");
pub const cache = @import("cache.zig");
pub const validate = @import("validate.zig");
pub const resolve = @import("resolve.zig");
pub const query = @import("query.zig");
pub const format = @import("format.zig");
pub const analysis = @import("analysis.zig");
pub const checksum = @import("checksum.zig");
pub const exception = @import("exception.zig");
pub const delay_import = @import("delay_import.zig");

// ── Constants ──────────────────────────────────────────────────

pub const DOS_MAGIC: u16 = 0x5A4D;
pub const PE_SIGNATURE: u32 = 0x00004550;
pub const OPT_MAGIC_PE32: u16 = 0x010B;
pub const OPT_MAGIC_PE32PLUS: u16 = 0x020B;
pub const NUM_DATA_DIRS: u32 = 16;

// Data directory indices
pub const DIR_EXPORT: u32 = 0;
pub const DIR_IMPORT: u32 = 1;
pub const DIR_RESOURCE: u32 = 2;
pub const DIR_EXCEPTION: u32 = 3;
pub const DIR_SECURITY: u32 = 4;
pub const DIR_BASERELOC: u32 = 5;
pub const DIR_DEBUG: u32 = 6;
pub const DIR_TLS: u32 = 9;
pub const DIR_LOAD_CONFIG: u32 = 10;
pub const DIR_BOUND_IMPORT: u32 = 11;
pub const DIR_IAT: u32 = 12;
pub const DIR_DELAY_IMPORT: u32 = 13;
pub const DIR_CLR_RUNTIME: u32 = 14;

// Machine types
pub const MACHINE_I386: u16 = 0x014C;
pub const MACHINE_AMD64: u16 = 0x8664;
pub const MACHINE_ARM64: u16 = 0xAA64;
pub const MACHINE_ARMNT: u16 = 0x01C4;

// Section characteristics
pub const SCN_CNT_CODE: u32 = 0x00000020;
pub const SCN_CNT_INIT_DATA: u32 = 0x00000040;
pub const SCN_CNT_UNINIT_DATA: u32 = 0x00000080;
pub const SCN_MEM_EXECUTE: u32 = 0x20000000;
pub const SCN_MEM_READ: u32 = 0x40000000;
pub const SCN_MEM_WRITE: u32 = 0x80000000;
pub const SCN_MEM_DISCARDABLE: u32 = 0x02000000;

// Relocation types
pub const REL_BASED_ABSOLUTE: u16 = 0;
pub const REL_BASED_HIGHLOW: u16 = 3;
pub const REL_BASED_DIR64: u16 = 10;

// Debug types
pub const DEBUG_TYPE_CODEVIEW: u32 = 2;
pub const DEBUG_TYPE_REPRO: u32 = 16;

// Resource types
pub const RT_CURSOR: u32 = 1;
pub const RT_BITMAP: u32 = 2;
pub const RT_ICON: u32 = 3;
pub const RT_MENU: u32 = 4;
pub const RT_DIALOG: u32 = 5;
pub const RT_STRING: u32 = 6;
pub const RT_VERSION: u32 = 16;
pub const RT_MANIFEST: u32 = 24;

// Internal limits
pub const MAX_SECTIONS: u32 = 256;
pub const MAX_SYMBOLS: u32 = 0x100000;
pub const MAX_IMPORTS: u32 = 4096;
pub const MAX_THUNKS: u32 = 65536;
pub const MAX_EXPORTS: u32 = 65536;
pub const MAX_RELOC_BLOCKS: u32 = 8192;
pub const MAX_RELOC_ENTRIES: u32 = 65536;
pub const MAX_DEBUG_ENTRIES: u32 = 256;
pub const MAX_RESOURCE_NODES: u32 = 65536;
pub const MAX_STRING_TABLE: u32 = 0x400000;
pub const MAX_EXCEPTION_ENTRIES: u32 = 16384;
pub const MAX_ISSUES: u32 = 1024;

// ── Error type ─────────────────────────────────────────────────

pub const ParseError = error{
    NullArg,
    Truncated,
    InvalidDos,
    InvalidPeSig,
    InvalidCoff,
    InvalidOptional,
    InvalidSection,
    InvalidStringTable,
    InvalidSymbol,
    InvalidImport,
    InvalidExport,
    InvalidReloc,
    InvalidDebug,
    InvalidResource,
    InvalidException,
    ValidationFailed,
    ResolveFailed,
    ChecksumMismatch,
    OutOfMemory,
    Overflow,
    Unsupported,
};

// ── Data structures ────────────────────────────────────────────

pub const DataDir = struct {
    rva: u32 = 0,
    size: u32 = 0,
};

pub const DosHeader = struct {
    e_magic: u16 = 0,
    e_cblp: u16 = 0,
    e_cp: u16 = 0,
    e_crlc: u16 = 0,
    e_cparhdr: u16 = 0,
    e_minalloc: u16 = 0,
    e_maxalloc: u16 = 0,
    e_ss: u16 = 0,
    e_sp: u16 = 0,
    e_csum: u16 = 0,
    e_ip: u16 = 0,
    e_cs: u16 = 0,
    e_lfarlc: u16 = 0,
    e_ovno: u16 = 0,
    e_oemid: u16 = 0,
    e_oeminfo: u16 = 0,
    e_lfanew: u32 = 0,
};

pub const CoffHeader = struct {
    machine: u16 = 0,
    num_sections: u16 = 0,
    timestamp: u32 = 0,
    symbol_table_offset: u32 = 0,
    num_symbols: u32 = 0,
    optional_header_size: u16 = 0,
    characteristics: u16 = 0,
};

pub const OptionalHeader = struct {
    magic: u16 = 0,
    major_linker: u8 = 0,
    minor_linker: u8 = 0,
    size_of_code: u32 = 0,
    size_of_init_data: u32 = 0,
    size_of_uninit_data: u32 = 0,
    entry_point_rva: u32 = 0,
    base_of_code: u32 = 0,
    base_of_data: u32 = 0,
    image_base: u64 = 0,
    section_alignment: u32 = 0,
    file_alignment: u32 = 0,
    major_os_version: u16 = 0,
    minor_os_version: u16 = 0,
    major_image_version: u16 = 0,
    minor_image_version: u16 = 0,
    major_subsystem_version: u16 = 0,
    minor_subsystem_version: u16 = 0,
    win32_version_value: u32 = 0,
    size_of_image: u32 = 0,
    size_of_headers: u32 = 0,
    pe_checksum: u32 = 0,
    subsystem: u16 = 0,
    dll_characteristics: u16 = 0,
    stack_reserve: u64 = 0,
    stack_commit: u64 = 0,
    heap_reserve: u64 = 0,
    heap_commit: u64 = 0,
    loader_flags: u32 = 0,
    num_data_dirs: u32 = 0,
    data_dirs: [NUM_DATA_DIRS]DataDir = [_]DataDir{.{}} ** NUM_DATA_DIRS,
    is_pe32plus: bool = false,
};

pub const Section = struct {
    short_name: [9]u8 = [_]u8{0} ** 9,
    resolved_name: ?[*:0]u8 = null,
    virtual_size: u32 = 0,
    virtual_address: u32 = 0,
    raw_data_size: u32 = 0,
    raw_data_offset: u32 = 0,
    reloc_offset: u32 = 0,
    linenum_offset: u32 = 0,
    num_relocs: u16 = 0,
    num_linenums: u16 = 0,
    characteristics: u32 = 0,
    data: ?[*]u8 = null,
    data_size: usize = 0,
    data_owned: bool = false,
};

pub const StringTable = struct {
    data: ?[*]u8 = null,
    size: u32 = 0,
    entries: ?[*]?[*:0]u8 = null,
    num_entries: u32 = 0,
    entries_capacity: u32 = 0,
};

pub const Symbol = struct {
    short_name: [9]u8 = [_]u8{0} ** 9,
    resolved_name: ?[*:0]u8 = null,
    value: u32 = 0,
    section_number: i16 = 0,
    sym_type: u16 = 0,
    storage_class: u8 = 0,
    aux_count: u8 = 0,
    index: u32 = 0,
};

pub const ImportThunk = struct {
    is_ordinal: bool = false,
    ordinal: u16 = 0,
    hint: u16 = 0,
    name: ?[*:0]u8 = null,
    thunk_rva: u32 = 0,
};

pub const ImportDescriptor = struct {
    ilt_rva: u32 = 0,
    timestamp: u32 = 0,
    forwarder_chain: u32 = 0,
    name_rva: u32 = 0,
    dll_name: ?[*:0]u8 = null,
    iat_rva: u32 = 0,
    thunks: ?[*]ImportThunk = null,
    num_thunks: u32 = 0,
    thunks_capacity: u32 = 0,
};

pub const ExportEntry = struct {
    function_rva: u32 = 0,
    name: ?[*:0]u8 = null,
    ordinal: u16 = 0,
    name_ordinal: u16 = 0,
    forwarder: ?[*:0]u8 = null,
    is_forwarder: bool = false,
    has_name: bool = false,
};

pub const RelocEntry = struct {
    rel_type: u16 = 0,
    offset: u16 = 0,
    target_rva: u32 = 0,
    target_ptr: ?[*]u8 = null,
    resolved: bool = false,
};

pub const RelocBlock = struct {
    page_rva: u32 = 0,
    block_size: u32 = 0,
    entries: ?[*]RelocEntry = null,
    count: u32 = 0,
    capacity: u32 = 0,
};

pub const CodeviewInfo = struct {
    cv_signature: u32 = 0,
    guid: [16]u8 = [_]u8{0} ** 16,
    age: u32 = 0,
    pdb_path: ?[*:0]u8 = null,
};

pub const DebugEntry = struct {
    characteristics: u32 = 0,
    timestamp: u32 = 0,
    major_version: u16 = 0,
    minor_version: u16 = 0,
    debug_type: u32 = 0,
    data_size: u32 = 0,
    address_rva: u32 = 0,
    raw_data_offset: u32 = 0,
    codeview: ?*CodeviewInfo = null,
    section_index: i32 = -1,
};

pub const ResourceNode = struct {
    is_named: bool = false,
    id: u32 = 0,
    name: ?[*:0]u8 = null,
    is_directory: bool = false,
    children: ?[*]ResourceNode = null,
    num_children: u32 = 0,
    children_capacity: u32 = 0,
    data_rva: u32 = 0,
    data_size: u32 = 0,
    codepage: u32 = 0,
    data_ptr: ?[*]u8 = null,
    depth: u32 = 0,
};

pub const ValidationIssue = struct {
    severity: i32 = 0,
    section_index: u32 = 0,
    message: [128]u8 = [_]u8{0} ** 128,
};

// Cache types
pub const ImportCacheEntry = struct {
    descriptor_index: u32 = 0,
    thunk_index: u32 = 0,
    name_ptr: ?[*:0]u8 = null,
    dll_name_ptr: ?[*:0]u8 = null,
};

pub const ExportCacheEntry = struct {
    export_index: u32 = 0,
    name_ptr: ?[*:0]u8 = null,
    forwarder_ptr: ?[*:0]u8 = null,
    ordinal: u16 = 0,
};

pub const RelocCacheEntry = struct {
    block_index: u32 = 0,
    entry_index: u32 = 0,
    target_ptr: ?[*]u8 = null,
    section_index: u32 = 0,
};

pub const DebugCacheEntry = struct {
    section_index: u32 = 0,
    debug_entry: ?*DebugEntry = null,
    pdb_path_ptr: ?[*:0]u8 = null,
};

pub const SymbolCacheEntry = struct {
    symbol_index: u32 = 0,
    name_ptr: ?[*:0]u8 = null,
    section_number: i16 = 0,
};

pub const ResourceCacheEntry = struct {
    flat_index: u32 = 0,
    name_ptr: ?[*:0]u8 = null,
    type_id: u32 = 0,
    data_size: u32 = 0,
};

// ── Main context ───────────────────────────────────────────────

pub const PeCtx = struct {
    allocator: Allocator,
    data: [*]const u8,
    size: usize,

    last_error: ?ParseError = null,
    error_msg: [256]u8 = [_]u8{0} ** 256,
    warning_count: u32 = 0,

    dos_header: DosHeader = .{},
    coff_header: CoffHeader = .{},
    optional_header: OptionalHeader = .{},

    // Tables — allocated arrays
    section_entries: ?[*]Section = null,
    section_count: u32 = 0,
    section_capacity: u32 = 0,

    string_table: StringTable = .{},

    symbol_entries: ?[*]Symbol = null,
    symbol_count: u32 = 0,
    symbol_capacity: u32 = 0,

    import_descriptors: ?[*]ImportDescriptor = null,
    import_count: u32 = 0,
    import_capacity: u32 = 0,

    export_entries: ?[*]ExportEntry = null,
    export_count: u32 = 0,
    export_capacity: u32 = 0,
    export_dll_name: ?[*:0]u8 = null,

    reloc_blocks: ?[*]RelocBlock = null,
    reloc_count: u32 = 0,
    reloc_capacity: u32 = 0,

    debug_entries: ?[*]DebugEntry = null,
    debug_count: u32 = 0,
    debug_capacity: u32 = 0,

    resource_root: ?*ResourceNode = null,
    resource_flat: ?[*]?*ResourceNode = null,
    resource_flat_count: u32 = 0,
    resource_flat_capacity: u32 = 0,

    // Caches (built in Phase 12)
    import_cache: ?[*]ImportCacheEntry = null,
    import_cache_count: u32 = 0,
    export_cache: ?[*]ExportCacheEntry = null,
    export_cache_count: u32 = 0,
    reloc_cache: ?[*]RelocCacheEntry = null,
    reloc_cache_count: u32 = 0,
    debug_cache: ?[*]DebugCacheEntry = null,
    debug_cache_count: u32 = 0,
    symbol_cache: ?[*]SymbolCacheEntry = null,
    symbol_cache_count: u32 = 0,
    resource_cache: ?[*]ResourceCacheEntry = null,
    resource_cache_count: u32 = 0,
    section_names: ?[*]?[*:0]u8 = null,
    section_name_count: u32 = 0,
    cache_built: bool = false,

    // Validation issues
    issues: ?[*]ValidationIssue = null,
    issue_count: u32 = 0,
    issue_capacity: u32 = 0,

    parsed: bool = false,
    validated: bool = false,
    resolved: bool = false,

    pub fn open(allocator: Allocator, data: [*]const u8, size: usize) ?*PeCtx {
        if (size < 64) return null;

        const ctx = allocator.create(PeCtx) catch return null;
        ctx.* = PeCtx{
            .allocator = allocator,
            .data = data,
            .size = size,
        };

        // Phase 1: DOS header
        dos.parse(ctx) catch {
            ctx.destroy();
            return null;
        };

        // Phase 2: PE signature + COFF header
        coff.parsePeSignature(ctx, ctx.dos_header.e_lfanew) catch {
            ctx.destroy();
            return null;
        };
        coff.parse(ctx) catch {
            ctx.destroy();
            return null;
        };

        // Phase 3: Optional header
        const opt_offset = ctx.dos_header.e_lfanew + 4 + 20;
        if (ctx.coff_header.optional_header_size > 0) {
            optional.parse(ctx, opt_offset) catch {
                ctx.destroy();
                return null;
            };
        }

        // Phase 4: Section table
        const sec_offset = opt_offset + ctx.coff_header.optional_header_size;
        sections.parseTable(ctx, sec_offset) catch {
            ctx.destroy();
            return null;
        };
        sections.loadData(ctx) catch {
            ctx.destroy();
            return null;
        };

        // Phase 5: String table
        strings.parse(ctx) catch {};

        // Phase 6: Symbol table
        symbols.parse(ctx) catch {};
        symbols.resolveNames(ctx);

        // Phase 7: Import table
        if (ctx.optional_header.data_dirs[DIR_IMPORT].rva != 0) {
            imports.parse(ctx) catch {};
        }

        // Phase 8: Export table
        if (ctx.optional_header.data_dirs[DIR_EXPORT].rva != 0) {
            exports.parse(ctx) catch {};
        }

        // Phase 9: Relocation table
        if (ctx.optional_header.data_dirs[DIR_BASERELOC].rva != 0) {
            relocs.parse(ctx) catch {};
        }

        // Phase 10: Debug directory
        if (ctx.optional_header.data_dirs[DIR_DEBUG].rva != 0) {
            debug.parse(ctx) catch {};
        }

        // Phase 11: Resource tree
        if (ctx.optional_header.data_dirs[DIR_RESOURCE].rva != 0) {
            resources.parse(ctx) catch {};
        }

        // Phase 11b: Exception directory
        if (ctx.optional_header.data_dirs[DIR_EXCEPTION].rva != 0) {
            exception.parse(ctx) catch {};
        }

        // Phase 7b: Delay imports
        delay_import.parse(ctx) catch {};

        ctx.parsed = true;

        // Phase 12: Build caches
        cache.build(ctx) catch {};
        ctx.cache_built = true;

        // Phase 13: Cross-table validation
        validate.run(ctx) catch {};
        ctx.validated = true;

        // Phase 14: Cross-reference resolution
        resolve.run(ctx) catch {};
        ctx.resolved = true;

        return ctx;
    }

    pub fn destroy(self: *PeCtx) void {
        // Free sections
        if (self.section_entries) |entries| {
            var i: u32 = 0;
            while (i < self.section_count) : (i += 1) {
                const sec = &entries[i];
                if (sec.data_owned) {
                    if (sec.data) |d| {
                        self.allocator.free(d[0..sec.data_size]);
                    }
                }
            }
            self.allocator.free(entries[0..self.section_capacity]);
        }

        // Free string table
        if (self.string_table.data) |d| {
            self.allocator.free(d[0..self.string_table.size]);
        }
        if (self.string_table.entries) |e| {
            self.allocator.free(e[0..self.string_table.entries_capacity]);
        }

        // Free symbols
        if (self.symbol_entries) |entries| {
            self.allocator.free(entries[0..self.symbol_capacity]);
        }

        // Free imports
        if (self.import_descriptors) |descs| {
            var i: u32 = 0;
            while (i < self.import_count) : (i += 1) {
                const desc = &descs[i];
                if (desc.dll_name) |n| self.allocator.free(std.mem.span(n));
                if (desc.thunks) |t| {
                    self.allocator.free(t[0..desc.thunks_capacity]);
                }
            }
            self.allocator.free(descs[0..self.import_capacity]);
        }

        // Free exports
        if (self.export_entries) |entries| {
            var i: u32 = 0;
            while (i < self.export_count) : (i += 1) {
                if (entries[i].forwarder) |f| self.allocator.free(std.mem.span(f));
            }
            self.allocator.free(entries[0..self.export_capacity]);
        }

        // Free relocs
        if (self.reloc_blocks) |blocks| {
            var i: u32 = 0;
            while (i < self.reloc_count) : (i += 1) {
                if (blocks[i].entries) |e| {
                    self.allocator.free(e[0..blocks[i].capacity]);
                }
            }
            self.allocator.free(blocks[0..self.reloc_capacity]);
        }

        // Free debug
        if (self.debug_entries) |entries| {
            var i: u32 = 0;
            while (i < self.debug_count) : (i += 1) {
                if (entries[i].codeview) |cv| {
                    if (cv.pdb_path) |p| self.allocator.free(std.mem.span(p));
                    self.allocator.destroy(cv);
                }
            }
            self.allocator.free(entries[0..self.debug_capacity]);
        }

        // Free caches
        if (self.import_cache) |c| self.allocator.free(c[0..self.import_cache_count]);
        if (self.export_cache) |c| self.allocator.free(c[0..self.export_cache_count]);
        if (self.reloc_cache) |c| self.allocator.free(c[0..self.reloc_cache_count]);
        if (self.debug_cache) |c| self.allocator.free(c[0..self.debug_cache_count]);
        if (self.symbol_cache) |c| self.allocator.free(c[0..self.symbol_cache_count]);
        if (self.resource_cache) |c| self.allocator.free(c[0..self.resource_cache_count]);
        if (self.section_names) |names| self.allocator.free(names[0..self.section_name_count]);

        // Free issues
        if (self.issues) |iss| self.allocator.free(iss[0..self.issue_capacity]);

        self.allocator.destroy(self);
    }

    // Utility: check if offset + needed fits within data
    pub fn checkOffset(self: *const PeCtx, off: u32, needed: u32) bool {
        return off <= self.size and needed <= self.size - off;
    }

    pub fn addWarning(self: *PeCtx, msg: []const u8) void {
        self.warning_count += 1;
        _ = msg;
    }

    pub fn addIssue(self: *PeCtx, severity: i32, section: u32, msg: []const u8) void {
        if (self.issue_count >= MAX_ISSUES) return;
        // Grow issues array if needed
        if (self.issues == null or self.issue_count >= self.issue_capacity) {
            const new_cap = if (self.issue_capacity == 0) @as(u32, 16) else self.issue_capacity * 2;
            const new_arr = self.allocator.alloc(ValidationIssue, new_cap) catch return;
            if (self.issues) |old| {
                @memcpy(new_arr[0..self.issue_count], old[0..self.issue_count]);
                self.allocator.free(old[0..self.issue_capacity]);
            }
            self.issues = new_arr.ptr;
            self.issue_capacity = new_cap;
        }
        var issue = &self.issues.?[self.issue_count];
        issue.severity = severity;
        issue.section_index = section;
        @memset(&issue.message, 0);
        const copy_len = @min(msg.len, issue.message.len - 1);
        @memcpy(issue.message[0..copy_len], msg[0..copy_len]);
        self.issue_count += 1;
    }

    // RVA to file offset conversion
    pub fn rvaToOffset(self: *const PeCtx, rva: u32) ?u32 {
        if (self.section_entries) |entries| {
            var i: u32 = 0;
            while (i < self.section_count) : (i += 1) {
                const sec = &entries[i];
                if (rva >= sec.virtual_address and
                    rva < sec.virtual_address + @max(sec.virtual_size, sec.raw_data_size))
                {
                    return sec.raw_data_offset + (rva - sec.virtual_address);
                }
            }
        }
        return null;
    }

    // RVA to data pointer
    pub fn rvaToPtr(self: *const PeCtx, rva: u32, min_size: usize) ?[*]const u8 {
        const offset = self.rvaToOffset(rva) orelse return null;
        if (offset >= self.size) return null;
        if (self.size - offset < min_size) return null;
        return self.data + offset;
    }
};

// ── Delay Import types in context ──────────────────────────────

pub const DelayThunk = struct {
    is_ordinal: bool = false,
    ordinal: u16 = 0,
    hint: u16 = 0,
    name: ?[*:0]u8 = null,
};

pub const DelayDescriptor = struct {
    attributes: u32 = 0,
    name_rva: u32 = 0,
    module_handle_rva: u32 = 0,
    iat_rva: u32 = 0,
    int_rva: u32 = 0,
    bound_iat_rva: u32 = 0,
    unload_iat_rva: u32 = 0,
    timestamp: u32 = 0,
    dll_name: ?[*:0]u8 = null,
    thunks: ?[*]DelayThunk = null,
    num_thunks: u32 = 0,
    thunks_capacity: u32 = 0,
    name_section: u32 = 0xFFFFFFFF,
    iat_section: u32 = 0xFFFFFFFF,
};

pub const UnwindCode = struct {
    offset_in_prolog: u8 = 0,
    operation: u8 = 0,
    op_info: u8 = 0,
    extra_value: u32 = 0,
};

pub const UnwindInfo = struct {
    version: u8 = 0,
    flags: u8 = 0,
    prolog_size: u8 = 0,
    code_count: u8 = 0,
    frame_register: u8 = 0,
    frame_offset: u8 = 0,
    codes: ?[*]UnwindCode = null,
    parsed_code_count: u32 = 0,
    codes_capacity: u32 = 0,
    handler_rva: u32 = 0,
    has_handler: bool = false,
    chained_begin: u32 = 0,
    chained_end: u32 = 0,
    chained_unwind: u32 = 0,
    is_chained: bool = false,
};

pub const ExceptionEntry = struct {
    begin_rva: u32 = 0,
    end_rva: u32 = 0,
    unwind_rva: u32 = 0,
    unwind: UnwindInfo = .{},
    code_section: u32 = 0xFFFFFFFF,
    handler_section: u32 = 0xFFFFFFFF,
};

pub const PeStats = struct {
    total_sections: u32 = 0,
    code_sections: u32 = 0,
    data_sections: u32 = 0,
    total_raw_size: u64 = 0,
    total_virtual_size: u64 = 0,
    total_imports: u32 = 0,
    total_import_dlls: u32 = 0,
    total_exports: u32 = 0,
    total_forwarders: u32 = 0,
    total_reloc_entries: u32 = 0,
    total_symbols: u32 = 0,
    total_resources: u32 = 0,
    total_debug_entries: u32 = 0,
    total_exceptions: u32 = 0,
    total_delay_imports: u32 = 0,
    avg_section_entropy: f64 = 0.0,
    max_section_entropy: f64 = 0.0,
    suspicious_section_count: u32 = 0,
    validation_issues: u32 = 0,
    validation_warnings: u32 = 0,
    validation_errors: u32 = 0,
};

/// Rich header entry parsed from DOS stub
pub const RichEntry = struct {
    comp_id: u32 = 0,
    build_id: u16 = 0,
    product_id: u16 = 0,
    use_count: u32 = 0,
};

/// TLS directory information
pub const TlsInfo = struct {
    raw_data_start: u64 = 0,
    raw_data_end: u64 = 0,
    index_address: u64 = 0,
    callbacks_address: u64 = 0,
    zero_fill_size: u32 = 0,
    characteristics: u32 = 0,
    num_callbacks: u32 = 0,
};

/// Load configuration directory
pub const LoadConfig = struct {
    size: u32 = 0,
    timestamp: u32 = 0,
    security_cookie: u64 = 0,
    se_handler_table: u64 = 0,
    se_handler_count: u64 = 0,
    guard_cf_table: u64 = 0,
    guard_cf_count: u64 = 0,
    guard_flags: u32 = 0,
};

/// Bound import entry
pub const BoundImportEntry = struct {
    timestamp: u32 = 0,
    module_name_offset: u16 = 0,
    num_forwarder_refs: u16 = 0,
    module_name: ?[*:0]u8 = null,
};
