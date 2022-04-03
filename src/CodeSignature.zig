const CodeSignature = @This();

const std = @import("std");
const assert = std.debug.assert;
const fs = std.fs;
const log = std.log.scoped(.link);
const macho = std.macho;
const mem = std.mem;
const testing = std.testing;

const Allocator = mem.Allocator;
const MachO = @import("MachO.zig");
const Sha256 = std.crypto.hash.sha2.Sha256;
const ZigKit = @import("ZigKit");

const hash_size: u8 = 32;

const Blob = union(enum) {
    code_directory: *CodeDirectory,
    der_entitlements: *DerEntitlements,
    requirements: *Requirements,
    requirement: *Requirement,
    entitlements: *Entitlements,
    signature: *Signature,

    fn slotType(self: Blob) u32 {
        return switch (self) {
            .code_directory => |x| x.slotType(),
            .der_entitlements => |x| x.slotType(),
            .requirements => |x| x.slotType(),
            .requirement => |x| x.slotType(),
            .entitlements => |x| x.slotType(),
            .signature => |x| x.slotType(),
        };
    }

    fn size(self: Blob) u32 {
        return switch (self) {
            .code_directory => |x| x.size(),
            .der_entitlements => |x| x.size(),
            .requirements => |x| x.size(),
            .requirement => |x| x.size(),
            .entitlements => |x| x.size(),
            .signature => |x| x.size(),
        };
    }

    fn write(self: Blob, writer: anytype) !void {
        return switch (self) {
            .code_directory => |x| x.write(writer),
            .der_entitlements => |x| x.write(writer),
            .requirements => |x| x.write(writer),
            .requirement => |x| x.write(writer),
            .entitlements => |x| x.write(writer),
            .signature => |x| x.write(writer),
        };
    }
};

const CodeDirectory = struct {
    inner: macho.CodeDirectory,
    ident: []const u8,
    team_ident: ?[]const u8 = null,
    special_slots: [n_special_slots][hash_size]u8,
    code_slots: std.ArrayListUnmanaged([hash_size]u8) = .{},

    const n_special_slots: usize = 7;

    fn init(page_size: u16, ident: []const u8) CodeDirectory {
        var cdir: CodeDirectory = .{
            .inner = .{
                .magic = macho.CSMAGIC_CODEDIRECTORY,
                .length = @sizeOf(macho.CodeDirectory),
                .version = macho.CS_SUPPORTSEXECSEG,
                .flags = 0,
                .hashOffset = 0,
                .identOffset = @sizeOf(macho.CodeDirectory),
                .nSpecialSlots = 0,
                .nCodeSlots = 0,
                .codeLimit = 0,
                .hashSize = hash_size,
                .hashType = macho.CS_HASHTYPE_SHA256,
                .platform = 0,
                .pageSize = @truncate(u8, std.math.log2(page_size)),
                .spare2 = 0,
                .scatterOffset = 0,
                .teamOffset = 0,
                .spare3 = 0,
                .codeLimit64 = 0,
                .execSegBase = 0,
                .execSegLimit = 0,
                .execSegFlags = 0,
            },
            .ident = ident,
            .special_slots = undefined,
        };
        comptime var i = 0;
        inline while (i < n_special_slots) : (i += 1) {
            cdir.special_slots[i] = [_]u8{0} ** hash_size;
        }
        return cdir;
    }

    fn deinit(self: *CodeDirectory, allocator: Allocator) void {
        self.code_slots.deinit(allocator);
    }

    pub fn addTeamIdent(self: *CodeDirectory, team_ident: []const u8) void {
        self.team_ident = team_ident;
        self.inner.teamOffset = self.inner.identOffset + @intCast(u32, self.ident.len + 1);
    }

    fn addSpecialHash(self: *CodeDirectory, index: u32, hash: [hash_size]u8) void {
        assert(index > 0);
        self.inner.nSpecialSlots = std.math.max(self.inner.nSpecialSlots, index);
        mem.copy(u8, &self.special_slots[index - 1], &hash);
    }

    fn hashOffset(self: CodeDirectory) u32 {
        var partial = @sizeOf(macho.CodeDirectory) +
            @intCast(u32, self.ident.len + 1) +
            self.inner.nSpecialSlots * hash_size;
        if (self.team_ident) |ti| {
            partial += @intCast(u32, ti.len + 1);
        }
        return partial;
    }

    fn slotType(self: CodeDirectory) u32 {
        _ = self;
        return macho.CSSLOT_CODEDIRECTORY;
    }

    pub fn size(self: CodeDirectory) u32 {
        const code_slots = self.inner.nCodeSlots * hash_size;
        const special_slots = self.inner.nSpecialSlots * hash_size;
        var partial = @sizeOf(macho.CodeDirectory) + @intCast(u32, self.ident.len + 1) + special_slots + code_slots;
        if (self.team_ident) |team_ident| {
            partial += @intCast(u32, team_ident.len + 1);
        }
        return partial;
    }

    pub fn write(self: CodeDirectory, writer: anytype) !void {
        try writer.writeIntBig(u32, self.inner.magic);
        try writer.writeIntBig(u32, self.inner.length);
        try writer.writeIntBig(u32, self.inner.version);
        try writer.writeIntBig(u32, self.inner.flags);
        try writer.writeIntBig(u32, self.inner.hashOffset);
        try writer.writeIntBig(u32, self.inner.identOffset);
        try writer.writeIntBig(u32, self.inner.nSpecialSlots);
        try writer.writeIntBig(u32, self.inner.nCodeSlots);
        try writer.writeIntBig(u32, self.inner.codeLimit);
        try writer.writeByte(self.inner.hashSize);
        try writer.writeByte(self.inner.hashType);
        try writer.writeByte(self.inner.platform);
        try writer.writeByte(self.inner.pageSize);
        try writer.writeIntBig(u32, self.inner.spare2);
        try writer.writeIntBig(u32, self.inner.scatterOffset);
        try writer.writeIntBig(u32, self.inner.teamOffset);
        try writer.writeIntBig(u32, self.inner.spare3);
        try writer.writeIntBig(u64, self.inner.codeLimit64);
        try writer.writeIntBig(u64, self.inner.execSegBase);
        try writer.writeIntBig(u64, self.inner.execSegLimit);
        try writer.writeIntBig(u64, self.inner.execSegFlags);

        try writer.writeAll(self.ident);
        try writer.writeByte(0);

        if (self.team_ident) |team_ident| {
            try writer.writeAll(team_ident);
            try writer.writeByte(0);
        }

        var i: isize = @intCast(isize, self.inner.nSpecialSlots);
        while (i > 0) : (i -= 1) {
            try writer.writeAll(&self.special_slots[@intCast(usize, i - 1)]);
        }

        for (self.code_slots.items) |slot| {
            try writer.writeAll(&slot);
        }
    }
};

pub const DerEntitlements = struct {
    inner: []const u8,

    fn deinit(self: *DerEntitlements, allocator: Allocator) void {
        _ = self;
        _ = allocator;
    }

    fn slotType(self: DerEntitlements) u32 {
        _ = self;
        return macho.CSSLOT_DER_ENTITLEMENTS;
    }

    fn size(self: DerEntitlements) u32 {
        return 2 * @sizeOf(u32) + @intCast(u32, self.inner.len);
    }

    fn write(self: DerEntitlements, writer: anytype) !void {
        try writer.writeIntBig(u32, macho.CSMAGIC_EMBEDDED_DER_ENTITLEMENTS);
        try writer.writeIntBig(u32, self.size());
        try writer.writeAll(self.inner);
    }
};

pub const Requirements = struct {
    requirements: std.ArrayListUnmanaged(Requirement) = .{},

    fn deinit(self: *Requirements, allocator: Allocator) void {
        for (self.requirements.items) |*req| {
            req.deinit(allocator);
        }
        self.requirements.deinit(allocator);
    }

    fn slotType(self: Requirements) u32 {
        _ = self;
        return macho.CSSLOT_REQUIREMENTS;
    }

    fn size(self: Requirements) u32 {
        var partial: u32 = 0;
        for (self.requirements.items) |req| {
            partial += @sizeOf(macho.BlobIndex) + req.size();
        }
        return 3 * @sizeOf(u32) + partial;
    }

    pub fn write(self: Requirements, writer: anytype) !void {
        try writer.writeIntBig(u32, macho.CSMAGIC_REQUIREMENTS);
        try writer.writeIntBig(u32, self.size());
        try writer.writeIntBig(u32, @intCast(u32, self.requirements.items.len));

        var offset: u32 = 3 * @sizeOf(u32) +
            @sizeOf(macho.BlobIndex) * @intCast(u32, self.requirements.items.len);
        for (self.requirements.items) |req| {
            try writer.writeIntBig(u32, req.slotType());
            try writer.writeIntBig(u32, offset);
            offset += req.size();
        }

        for (self.requirements.items) |req| {
            try req.write(writer);
        }
    }
};

pub const Requirement = struct {
    insts: std.MultiArrayList(Op) = .{},
    extra: std.ArrayListUnmanaged(u32) = .{},
    strtab: std.ArrayListUnmanaged(u8) = .{},
    bytes: std.ArrayListUnmanaged(u8) = .{},

    pub const Op = struct {
        opc: ExprOp,
        data: Data,

        pub const Index = u32;

        pub const Data = union {
            str: u32,
            payload: u32,
        };

        pub const CertField = struct {
            slot: i32,
            ident: u32,
            match: u32,
            ident2: u32,
        };

        pub const CertGeneric = struct {
            slot: i32,
            ident_off: u32,
            ident_len: u32,
            match: u32,
        };
    };

    pub fn deinit(self: *Requirement, allocator: Allocator) void {
        self.insts.deinit(allocator);
        self.extra.deinit(allocator);
        self.strtab.deinit(allocator);
        self.bytes.deinit(allocator);
    }

    fn addExtra(self: *Requirement, allocator: Allocator, extra: anytype) !u32 {
        const fields = std.meta.fields(@TypeOf(extra));
        try self.extra.ensureUnusedCapacity(allocator, fields.len);
        return self.addExtraAssumeCapacity(extra);
    }

    fn addExtraAssumeCapacity(self: *Requirement, extra: anytype) u32 {
        const fields = std.meta.fields(@TypeOf(extra));
        const result = @intCast(u32, self.extra.items.len);
        self.extra.items.len += fields.len;
        self.setExtra(result, extra);
        return result;
    }

    fn setExtra(self: *Requirement, index: usize, extra: anytype) void {
        const fields = std.meta.fields(@TypeOf(extra));
        var i = index;
        inline for (fields) |field| {
            self.extra.items[i] = switch (field.field_type) {
                u32 => @field(extra, field.name),
                i32 => @bitCast(u32, @field(extra, field.name)),
                else => @compileError("bad field type"),
            };
            i += 1;
        }
    }

    pub fn extraData(self: Requirement, comptime T: type, index: usize) struct { data: T, end: usize } {
        const fields = std.meta.fields(T);
        var i: usize = index;
        var result: T = undefined;
        inline for (fields) |field| {
            @field(result, field.name) = switch (field.field_type) {
                u32 => self.extra.items[i],
                i32 => @bitCast(i32, self.extra.items[i]),
                else => @compileError("bad field type"),
            };
            i += 1;
        }
        return .{
            .data = result,
            .end = i,
        };
    }

    fn makeString(self: *Requirement, allocator: Allocator, bytes: []const u8) !u32 {
        const index = @intCast(u32, self.strtab.items.len);
        try self.strtab.appendSlice(allocator, bytes);
        try self.strtab.append(allocator, 0);
        return index;
    }

    pub fn getString(self: Requirement, off: u32) []const u8 {
        assert(off < self.strtab.items.len);
        return mem.sliceTo(@ptrCast([*:0]const u8, self.strtab.items.ptr + off), 0);
    }

    fn addBytes(self: *Requirement, allocator: Allocator, bytes: []const u8) !u32 {
        const index = @intCast(u32, self.bytes.items.len);
        try self.bytes.appendSlice(allocator, bytes);
        return index;
    }

    pub fn getBytes(self: Requirement, off: u32, len: u32) []const u8 {
        assert(off < self.bytes.items.len);
        assert(off + len <= self.bytes.items.len);
        return self.bytes.items[off..][0..len];
    }

    pub fn op(self: *Requirement, allocator: Allocator, opc: ExprOp) !void {
        try self.insts.append(allocator, .{
            .opc = opc,
            .data = undefined,
        });
    }

    pub fn opWithString(self: *Requirement, allocator: Allocator, opc: ExprOp, str: []const u8) !void {
        try self.insts.append(allocator, .{
            .opc = opc,
            .data = .{ .str = try self.makeString(allocator, str) },
        });
    }

    pub const CertField = struct {
        slot: i32,
        ident: []const u8,
        match: MatchOperation,
        ident2: []const u8,
    };

    pub fn opCertField(self: *Requirement, allocator: Allocator, cert_field: CertField) !void {
        const payload = try self.addExtra(allocator, Op.CertField{
            .slot = cert_field.slot,
            .ident = try self.makeString(allocator, cert_field.ident),
            .match = @enumToInt(cert_field.match),
            .ident2 = try self.makeString(allocator, cert_field.ident2),
        });
        try self.insts.append(allocator, .{
            .opc = .op_cert_field,
            .data = .{ .payload = payload },
        });
    }

    pub const CertGeneric = struct {
        slot: i32,
        ident: []const u8,
        match: MatchOperation,
    };

    pub fn opCertGeneric(self: *Requirement, allocator: Allocator, cert_generic: CertGeneric) !void {
        const payload = try self.addExtra(allocator, Op.CertGeneric{
            .slot = cert_generic.slot,
            .ident_off = try self.addBytes(allocator, cert_generic.ident),
            .ident_len = @intCast(u32, cert_generic.ident.len),
            .match = @enumToInt(cert_generic.match),
        });
        try self.insts.append(allocator, .{
            .opc = .op_cert_generic,
            .data = .{ .payload = payload },
        });
    }

    fn slotType(self: Requirement) u32 {
        _ = self;
        return macho.CSSLOT_RESOURCEDIR;
    }

    fn size(self: Requirement) u32 {
        var partial: u32 = 0;
        for (self.insts.items(.opc)) |opc, i| {
            partial += 4;
            switch (opc) {
                .op_ident => {
                    const off = self.insts.items(.data)[i].str;
                    const str = self.getString(off);
                    const aligned = mem.alignForwardGeneric(u32, @intCast(u32, str.len), @sizeOf(u32));
                    partial += 4 + aligned;
                },
                .op_cert_field => {
                    const payload = self.insts.items(.data)[i].payload;
                    const cert_field = self.extraData(CodeSignature.Requirement.Op.CertField, payload).data;
                    const ident = self.getString(cert_field.ident);
                    const aligned_ident = mem.alignForwardGeneric(
                        u32,
                        @intCast(u32, ident.len),
                        @sizeOf(u32),
                    );
                    const ident2 = self.getString(cert_field.ident2);
                    const aligned_ident2 = mem.alignForwardGeneric(
                        u32,
                        @intCast(u32, ident2.len),
                        @sizeOf(u32),
                    );
                    partial += 4 * 4 + aligned_ident + aligned_ident2;
                },
                .op_cert_generic => {
                    const payload = self.insts.items(.data)[i].payload;
                    const cert_generic = self.extraData(
                        CodeSignature.Requirement.Op.CertGeneric,
                        payload,
                    ).data;
                    const aligned = mem.alignForwardGeneric(u32, cert_generic.ident_len, @sizeOf(u32));
                    partial += 3 * 4 + aligned;
                },
                else => {},
            }
        }
        return 2 * @sizeOf(u32) + partial;
    }

    pub fn write(self: Requirement, writer: anytype) !void {
        try writer.writeIntBig(u32, macho.CSMAGIC_REQUIREMENT);
        try writer.writeIntBig(u32, self.size());

        for (self.insts.items(.opc)) |opc, i| {
            try writer.writeIntBig(u32, @enumToInt(opc));
            switch (opc) {
                .op_ident => {
                    const off = self.insts.items(.data)[i].str;
                    const str = self.getString(off);
                    const str_len = @intCast(u32, str.len);
                    const aligned = mem.alignForwardGeneric(u32, str_len, @sizeOf(u32));
                    try writer.writeIntBig(u32, str_len);
                    try writer.writeAll(str);
                    try writer.writeByteNTimes(0, aligned - str_len);
                },
                .op_cert_field => {
                    const payload = self.insts.items(.data)[i].payload;
                    const cert_field = self.extraData(CodeSignature.Requirement.Op.CertField, payload).data;
                    const ident = self.getString(cert_field.ident);
                    const ident_len = @intCast(u32, ident.len);
                    const aligned_ident = mem.alignForwardGeneric(u32, ident_len, @sizeOf(u32));
                    const ident2 = self.getString(cert_field.ident2);
                    const ident2_len = @intCast(u32, ident2.len);
                    const aligned_ident2 = mem.alignForwardGeneric(u32, ident2_len, @sizeOf(u32));
                    try writer.writeIntBig(i32, cert_field.slot);
                    try writer.writeIntBig(u32, ident_len);
                    try writer.writeAll(ident);
                    try writer.writeByteNTimes(0, aligned_ident - ident_len);
                    try writer.writeIntBig(u32, cert_field.match);
                    try writer.writeIntBig(u32, ident2_len);
                    try writer.writeAll(ident2);
                    try writer.writeByteNTimes(0, aligned_ident2 - ident2_len);
                },
                .op_cert_generic => {
                    const payload = self.insts.items(.data)[i].payload;
                    const cert_gen = self.extraData(CodeSignature.Requirement.Op.CertGeneric, payload).data;
                    const bytes = self.getBytes(cert_gen.ident_off, cert_gen.ident_len);
                    const aligned = mem.alignForwardGeneric(u32, cert_gen.ident_len, @sizeOf(u32));
                    try writer.writeIntBig(i32, cert_gen.slot);
                    try writer.writeIntBig(u32, cert_gen.ident_len);
                    try writer.writeAll(bytes);
                    if (aligned - cert_gen.ident_len > 0) {
                        try writer.writeByteNTimes(0, aligned - cert_gen.ident_len);
                    }
                    try writer.writeIntBig(u32, cert_gen.match);
                },
                else => {},
            }
        }
    }
};

const Entitlements = struct {
    inner: []const u8,

    fn deinit(self: *Entitlements, allocator: Allocator) void {
        allocator.free(self.inner);
    }

    fn slotType(self: Entitlements) u32 {
        _ = self;
        return macho.CSSLOT_ENTITLEMENTS;
    }

    fn size(self: Entitlements) u32 {
        return @intCast(u32, self.inner.len) + 2 * @sizeOf(u32);
    }

    fn write(self: Entitlements, writer: anytype) !void {
        try writer.writeIntBig(u32, macho.CSMAGIC_EMBEDDED_ENTITLEMENTS);
        try writer.writeIntBig(u32, self.size());
        try writer.writeAll(self.inner);
    }
};

const Signature = struct {
    inner: *ZigKit.CoreFoundation.CFData,

    fn deinit(self: *Signature, allocator: Allocator) void {
        _ = allocator;
        self.inner.release();
    }

    fn slotType(self: Signature) u32 {
        _ = self;
        return macho.CSSLOT_SIGNATURESLOT;
    }

    fn size(self: Signature) u32 {
        return 2 * @sizeOf(u32) + @intCast(u32, self.inner.len());
    }

    fn write(self: Signature, writer: anytype) !void {
        try writer.writeIntBig(u32, macho.CSMAGIC_BLOBWRAPPER);
        try writer.writeIntBig(u32, self.size());
        try writer.writeAll(self.inner.asSlice());
    }
};

page_size: u16,
header: macho.SuperBlob = undefined,
blobs: std.ArrayListUnmanaged(Blob) = .{},
code_directory: CodeDirectory,
requirements: ?Requirements = null,
entitlements: ?Entitlements = null,
der_entitlements: ?DerEntitlements = null,
signature: ?Signature = null,
info_plist: ?[]const u8 = null,
code_res: ?[]const u8 = null,

pub fn init(page_size: u16, ident: []const u8) CodeSignature {
    return .{
        .page_size = page_size,
        .code_directory = CodeDirectory.init(page_size, ident),
    };
}

pub fn deinit(self: *CodeSignature, allocator: Allocator) void {
    self.blobs.deinit(allocator);
    self.code_directory.deinit(allocator);
    if (self.requirements) |*req| {
        req.deinit(allocator);
    }
    if (self.entitlements) |*ents| {
        ents.deinit(allocator);
    }
    if (self.signature) |*sig| {
        sig.deinit(allocator);
    }
    if (self.info_plist) |contents| {
        allocator.free(contents);
    }
    if (self.code_res) |cres| {
        allocator.free(cres);
    }
}

pub fn addEntitlements(self: *CodeSignature, allocator: Allocator, path: []const u8) !void {
    const file = try fs.cwd().openFile(path, .{});
    defer file.close();
    const inner = try file.readToEndAlloc(allocator, std.math.maxInt(u32));
    self.entitlements = .{ .inner = inner };
}

pub fn addInfoPlist(self: *CodeSignature, allocator: Allocator, file: fs.File) !void {
    try file.seekTo(0);
    self.info_plist = try file.readToEndAlloc(allocator, std.math.maxInt(u32));
}

pub fn addCodeResources(self: *CodeSignature, allocator: Allocator, file: fs.File) !void {
    try file.seekTo(0);
    self.code_res = try file.readToEndAlloc(allocator, std.math.maxInt(u32));
}

pub fn addSignature(self: *CodeSignature, allocator: Allocator, data: *ZigKit.CoreFoundation.CFData) !void {
    self.signature = .{ .inner = data };
    if (self.signature) |*sig| {
        try self.blobs.append(allocator, .{ .signature = sig });
        self.header.count += 1;
        self.header.length += @sizeOf(macho.BlobIndex) + sig.size();
    }
}

pub const Opts = struct {
    bin_file: *const MachO,
    flags: u32 = macho.CS_ADHOC,
};

pub fn finalizeForSigning(self: *CodeSignature, allocator: Allocator, opts: Opts) !void {
    self.header = .{
        .magic = macho.CSMAGIC_EMBEDDED_SIGNATURE,
        .length = @sizeOf(macho.SuperBlob),
        .count = 0,
    };

    const text_seg = opts.bin_file.load_commands.items[opts.bin_file.text_segment_cmd.?].segment;
    const code_sig_cmd = opts.bin_file.load_commands.items[opts.bin_file.code_signature_cmd.?].linkedit_data;

    self.code_directory.inner.flags = opts.flags;
    self.code_directory.inner.execSegBase = text_seg.inner.fileoff;
    self.code_directory.inner.execSegLimit = text_seg.inner.filesize;
    self.code_directory.inner.execSegFlags = if (opts.bin_file.output_mode == .Exe)
        macho.CS_EXECSEG_MAIN_BINARY
    else
        0;
    const file_size = code_sig_cmd.dataoff;
    self.code_directory.inner.codeLimit = file_size;

    const total_pages = mem.alignForward(file_size, self.page_size) / self.page_size;

    var buffer = try allocator.alloc(u8, self.page_size);
    defer allocator.free(buffer);

    try self.code_directory.code_slots.ensureTotalCapacityPrecise(allocator, total_pages);

    // Calculate hash for each page (in file) and write it to the buffer
    var hash: [hash_size]u8 = undefined;
    var i: usize = 0;
    while (i < total_pages) : (i += 1) {
        const fstart = i * self.page_size;
        const fsize = if (fstart + self.page_size > file_size) file_size - fstart else self.page_size;
        const len = try opts.bin_file.file.preadAll(buffer, fstart);
        assert(fsize <= len);

        Sha256.hash(buffer[0..fsize], &hash, .{});

        self.code_directory.code_slots.appendAssumeCapacity(hash);
        self.code_directory.inner.nCodeSlots += 1;
    }

    try self.blobs.append(allocator, .{ .code_directory = &self.code_directory });
    self.header.length += @sizeOf(macho.BlobIndex);
    self.header.count += 1;

    if (self.requirements) |*req| {
        var buf = std.ArrayList(u8).init(allocator);
        defer buf.deinit();
        try req.write(buf.writer());
        Sha256.hash(buf.items, &hash, .{});
        self.code_directory.addSpecialHash(req.slotType(), hash);

        try self.blobs.append(allocator, .{ .requirements = req });
        self.header.count += 1;
        self.header.length += @sizeOf(macho.BlobIndex) + req.size();
    }

    if (self.entitlements) |*ents| {
        var buf = std.ArrayList(u8).init(allocator);
        defer buf.deinit();
        try ents.write(buf.writer());
        Sha256.hash(buf.items, &hash, .{});
        self.code_directory.addSpecialHash(ents.slotType(), hash);

        try self.blobs.append(allocator, .{ .entitlements = ents });
        self.header.count += 1;
        self.header.length += @sizeOf(macho.BlobIndex) + ents.size();
    }

    if (self.der_entitlements) |*ents| {
        var buf = std.ArrayList(u8).init(allocator);
        defer buf.deinit();
        try ents.write(buf.writer());
        Sha256.hash(buf.items, &hash, .{});
        self.code_directory.addSpecialHash(ents.slotType(), hash);

        try self.blobs.append(allocator, .{ .der_entitlements = ents });
        self.header.count += 1;
        self.header.length += @sizeOf(macho.BlobIndex) + ents.size();
    }

    if (self.info_plist) |contents| {
        Sha256.hash(contents, &hash, .{});
        self.code_directory.addSpecialHash(macho.CSSLOT_INFOSLOT, hash);
    }

    if (self.code_res) |contents| {
        Sha256.hash(contents, &hash, .{});
        self.code_directory.addSpecialHash(macho.CSSLOT_RESOURCEDIR, hash);
    }

    self.code_directory.inner.hashOffset = self.code_directory.hashOffset();
    self.code_directory.inner.length = self.code_directory.size();
    self.header.length += self.code_directory.size();
}

pub fn write(self: *CodeSignature, writer: anytype) !void {
    try writer.writeIntBig(u32, self.header.magic);
    try writer.writeIntBig(u32, self.header.length);
    try writer.writeIntBig(u32, self.header.count);

    var offset: u32 = @sizeOf(macho.SuperBlob) + @sizeOf(macho.BlobIndex) * @intCast(u32, self.blobs.items.len);
    for (self.blobs.items) |blob| {
        try writer.writeIntBig(u32, blob.slotType());
        try writer.writeIntBig(u32, offset);
        offset += blob.size();
    }

    for (self.blobs.items) |blob| {
        try blob.write(writer);
    }
}

pub fn size(self: CodeSignature) u32 {
    var ssize: u32 = @sizeOf(macho.SuperBlob) + @sizeOf(macho.BlobIndex) + self.code_directory.size();
    if (self.requirements) |req| {
        ssize += @sizeOf(macho.BlobIndex) + req.size();
    }
    if (self.entitlements) |ent| {
        ssize += @sizeOf(macho.BlobIndex) + ent.size();
    }
    if (self.der_entitlements) |ent| {
        ssize += @sizeOf(macho.BlobIndex) + ent.size();
    }
    if (self.signature) |sig| {
        ssize += @sizeOf(macho.BlobIndex) + sig.size();
    }
    return ssize;
}

pub fn estimateSize(self: CodeSignature, file_size: u64) u32 {
    var ssize: u64 = @sizeOf(macho.SuperBlob) + @sizeOf(macho.BlobIndex) + self.code_directory.size();
    // Approx code slots
    const total_pages = mem.alignForwardGeneric(u64, file_size, self.page_size) / self.page_size;
    ssize += total_pages * hash_size;
    var n_special_slots: u32 = 0;
    if (self.requirements) |req| {
        ssize += @sizeOf(macho.BlobIndex) + req.size();
        n_special_slots = std.math.max(n_special_slots, req.slotType());
    }
    if (self.entitlements) |ent| {
        ssize += @sizeOf(macho.BlobIndex) + ent.size();
        n_special_slots = std.math.max(n_special_slots, ent.slotType());
    }
    if (self.der_entitlements) |ent| {
        ssize += @sizeOf(macho.BlobIndex) + ent.size();
        n_special_slots = std.math.max(n_special_slots, ent.slotType());
    }
    if (self.info_plist) |_| {
        n_special_slots = std.math.max(n_special_slots, macho.CSSLOT_INFOSLOT);
    }
    if (self.code_res) |_| {
        n_special_slots = std.math.max(n_special_slots, macho.CSSLOT_RESOURCEDIR);
    }
    // We won't know the size of signature until we actually sign, so set some fairly high limit
    // TODO there has to be a formula for this...
    ssize += @sizeOf(macho.BlobIndex) + 0x4000;
    // if (self.signature) |sig| {
    //     ssize += @sizeOf(macho.BlobIndex) + sig.size();
    // }
    ssize += n_special_slots * hash_size;
    return @intCast(u32, mem.alignForwardGeneric(u64, ssize, @sizeOf(u64)));
}

pub fn clear(self: *CodeSignature, allocator: Allocator) void {
    self.code_directory.deinit(allocator);
    self.code_directory = CodeDirectory.init(self.page_size);
}

pub const ExprOp = enum(u32) {
    op_false,
    op_true,
    op_ident,
    op_apple_anchor,
    op_anchor_hash,
    op_info_key_value,
    op_and,
    op_or,
    op_cd_hash,
    op_not,
    op_info_key_field,
    op_cert_field,
    op_trusted_cert,
    op_trusted_certs,
    op_cert_generic,
    op_apple_generic_anchor,
    op_entitlement_field,
    op_cert_policy,
    op_named_anchor,
    op_named_code,
    op_platform,
    op_notarized,
    op_cert_field_date,
    op_legacy_dev_id,
    _,
};

pub const MatchOperation = enum(u32) {
    match_exists,
    match_equal,
    match_contains,
    match_begins_with,
    match_ends_with,
    match_less_than,
    match_greater_than,
    match_less_equal,
    match_greater_equal,
    match_on,
    match_before,
    match_after,
    match_on_or_before,
    match_on_or_after,
    match_absent,
    _,
};

pub const EXPR_OP_FLAG_MASK: u32 = 0xff;
pub const EXPR_OP_GENERIC_FALSE: u32 = 0x80;
pub const EXPR_OP_GENERIC_SKIP: u32 = 0x40;

pub const LEAF_CERT = 0;
pub const ROOT_CERT = -1;
