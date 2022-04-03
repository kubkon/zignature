const MachO = @This();

const std = @import("std");
const assert = std.debug.assert;
const fs = std.fs;
const log = std.log;
const macho = std.macho;
const mem = std.mem;

const Allocator = mem.Allocator;
const CodeSignature = @import("CodeSignature.zig");

gpa: Allocator,
file: fs.File,
output_mode: std.builtin.OutputMode = .Exe,

header: macho.mach_header_64,
load_commands: std.ArrayListUnmanaged(macho.LoadCommand) = .{},

text_segment_cmd: ?u16 = null,
linkedit_segment_cmd: ?u16 = null,
code_signature_cmd: ?u16 = null,

const page_size: u16 = 0x4000;

pub fn init(gpa: Allocator, file: fs.File) MachO {
    return .{
        .gpa = gpa,
        .file = file,
        .header = undefined,
    };
}

pub fn deinit(self: *MachO) void {
    for (self.load_commands.items) |*cmd| {
        cmd.deinit(self.gpa);
    }
    self.load_commands.deinit(self.gpa);
}

pub fn parse(self: *MachO) !void {
    const reader = self.file.reader();
    self.header = try reader.readStruct(macho.mach_header_64);

    const ncmds = self.header.ncmds;
    try self.load_commands.ensureTotalCapacity(self.gpa, ncmds);

    var i: u16 = 0;
    while (i < ncmds) : (i += 1) {
        const cmd = try macho.LoadCommand.read(self.gpa, reader);
        switch (cmd.cmd()) {
            macho.LC.SEGMENT_64 => if (mem.eql(u8, cmd.segment.inner.segName(), "__TEXT")) {
                self.text_segment_cmd = i;
            } else if (mem.eql(u8, cmd.segment.inner.segName(), "__LINKEDIT")) {
                self.linkedit_segment_cmd = i;
            },
            macho.LC.CODE_SIGNATURE => self.code_signature_cmd = i,
            else => {},
        }
        self.load_commands.appendAssumeCapacity(cmd);
    }

    // TODO don't do this on the original binary; create a temp copy, and commit by moving ONLY when
    // successful
    if (self.code_signature_cmd) |index| {
        const seg = &self.load_commands.items[self.linkedit_segment_cmd.?].segment;
        const cmd = &self.load_commands.items[index].linkedit_data;

        seg.inner.filesize = cmd.dataoff - seg.inner.fileoff;
        seg.inner.vmsize = mem.alignForwardGeneric(u64, seg.inner.filesize, page_size);
        cmd.datasize = 0;
    } else {
        const seg = self.load_commands.items[self.text_segment_cmd.?].segment;
        assert(seg.sections.items.len > 0);
        const padding = seg.sections.items[0].offset - self.header.sizeofcmds;
        if (padding < @sizeOf(macho.linkedit_data_command)) {
            log.err("not enough space between the end of the header to the start of __TEXT segment", .{});
            return error.NotEnoughSpaceForCodeSignatureLC;
        }

        // Code signature data has to be 16-bytes aligned for Apple tools to recognize the file
        // https://github.com/opensource-apple/cctools/blob/fdb4825f303fd5c0751be524babd32958181b3ed/libstuff/checkout.c#L271
        const linkedit = &self.load_commands.items[self.linkedit_segment_cmd.?].segment;
        const dataoff = mem.alignForwardGeneric(u64, linkedit.inner.fileoff + linkedit.inner.filesize, 16);
        const linkedit_padding = dataoff - (linkedit.inner.fileoff + linkedit.inner.filesize);
        try self.file.pwriteAll(&[_]u8{0}, dataoff);

        // Advance size of __LINKEDIT segment
        linkedit.inner.filesize += linkedit_padding;
        linkedit.inner.vmsize = mem.alignForwardGeneric(u64, linkedit.inner.filesize, page_size);

        self.code_signature_cmd = @intCast(u16, self.load_commands.items.len);
        try self.load_commands.append(self.gpa, .{
            .linkedit_data = .{
                .cmd = macho.LC.CODE_SIGNATURE,
                .cmdsize = @sizeOf(macho.linkedit_data_command),
                .dataoff = @intCast(u32, dataoff),
                .datasize = 0,
            },
        });

        self.header.ncmds += 1;
        self.header.sizeofcmds += @sizeOf(macho.linkedit_data_command);
    }
}

pub fn writeHeader(self: *MachO) !void {
    assert(self.code_signature_cmd != null);

    try self.file.pwriteAll(mem.asBytes(&self.header), 0);

    var buffer = std.ArrayList(u8).init(self.gpa);
    defer buffer.deinit();
    try buffer.ensureTotalCapacity(self.header.sizeofcmds);

    for (self.load_commands.items) |lc| {
        try lc.write(buffer.writer());
    }

    try self.file.pwriteAll(buffer.items, @sizeOf(macho.mach_header_64));
}

pub fn writeCodeSignaturePadding(self: *MachO, code_sig: CodeSignature) !void {
    const seg = &self.load_commands.items[self.linkedit_segment_cmd.?].segment;
    const code_sig_cmd = &self.load_commands.items[self.code_signature_cmd.?].linkedit_data;
    const needed_size = code_sig.estimateSize(code_sig_cmd.dataoff);
    code_sig_cmd.datasize = needed_size;

    // Advance size of __LINKEDIT segment
    seg.inner.filesize += needed_size;
    if (seg.inner.vmsize < seg.inner.filesize) {
        seg.inner.vmsize = mem.alignForwardGeneric(u64, seg.inner.filesize, page_size);
    }
    log.debug("writing code signature padding from 0x{x} to 0x{x}", .{
        code_sig_cmd.dataoff,
        code_sig_cmd.dataoff + needed_size,
    });
    // Pad out the space. We need to do this to calculate valid hashes for everything in the file
    // except for code signature data.
    try self.file.pwriteAll(&[_]u8{0}, code_sig_cmd.dataoff + needed_size - 1);
}

pub fn writeCodeSignature(self: *MachO, code_sig: *CodeSignature) !void {
    const code_sig_cmd = self.load_commands.items[self.code_signature_cmd.?].linkedit_data;

    var buffer = std.ArrayList(u8).init(self.gpa);
    defer buffer.deinit();
    try buffer.ensureTotalCapacityPrecise(code_sig.size());
    try code_sig.write(buffer.writer());
    assert(buffer.items.len == code_sig.size());

    log.debug("writing code signature from 0x{x} to 0x{x}", .{
        code_sig_cmd.dataoff,
        code_sig_cmd.dataoff + buffer.items.len,
    });

    try self.file.pwriteAll(buffer.items, code_sig_cmd.dataoff);
}
