const std = @import("std");
const assert = std.debug.assert;
const fs = std.fs;
const log = std.log;
const mem = std.mem;
const testing = std.testing;

const Allocator = mem.Allocator;
const CodeSignature = @import("CodeSignature.zig");
const MachO = @import("MachO.zig");
const ZigKit = @import("ZigKit");

const page_size: u16 = 0x1000;
// TODO this goes once I know how to parse XML
const ident: []const u8 = "com.my.app";
const team_ident: []const u8 = "DEADBEEF";

pub const Opts = struct {
    identity: ?[]const u8 = null,
    entitlements: ?[]const u8 = null,
};

pub fn signApp(gpa: Allocator, path: []const u8, opts: Opts) !void {
    _ = opts;

    var dir = fs.cwd().openDir(path, .{}) catch |err| switch (err) {
        error.NotDir => {
            const bin_file = try fs.cwd().openFile(path, .{ .mode = .read_write });
            defer bin_file.close();

            var macho = MachO.init(gpa, bin_file);
            defer macho.deinit();
            try macho.parse();

            var code_sig = CodeSignature.init(page_size, path);
            defer code_sig.deinit(gpa);

            // TODO handle adding actual signature
            if (opts.entitlements) |ents| {
                try code_sig.addEntitlements(gpa, ents);
            }

            try macho.writeCodeSignaturePadding(code_sig);
            try macho.writeHeader();

            try code_sig.finalizeForSigning(gpa, .{
                .bin_file = &macho,
                .flags = std.macho.CS_ADHOC,
            });

            try macho.writeCodeSignature(&code_sig);

            try fs.cwd().copyFile(path, fs.cwd(), path, .{});

            return;
        },
        else => |e| return e,
    };
    defer dir.close();

    const plist_file = try dir.openFile("Info.plist", .{});
    defer plist_file.close();
    const bin_file = try dir.openFile("app", .{ .mode = .read_write });
    defer bin_file.close();

    try hashAssets(gpa, dir, &[_]fs.File{plist_file});

    var macho = MachO.init(gpa, bin_file);
    defer macho.deinit();
    try macho.parse();

    var code_sig = CodeSignature.init(page_size, ident);
    defer code_sig.deinit(gpa);
    code_sig.code_directory.addTeamIdent(team_ident);

    if (opts.entitlements) |ents| {
        try code_sig.addEntitlements(gpa, ents);
        // TODO populate DER entitlements
        // code_sig.der_entitlements = .{ .inner = undefined };
    }
    try code_sig.addInfoPlist(gpa, plist_file);

    const code_res_file = try dir.openFile("_CodeSignature/CodeResources", .{});
    defer code_res_file.close();
    try code_sig.addCodeResources(gpa, code_res_file);

    var req = CodeSignature.Requirement{};
    try req.op(gpa, .op_true);
    try req.op(gpa, .op_and);
    try req.opWithString(gpa, .op_ident, ident);
    try req.op(gpa, .op_and);
    try req.op(gpa, .op_apple_generic_anchor);
    try req.op(gpa, .op_and);
    try req.opCertField(gpa, .{
        .slot = CodeSignature.LEAF_CERT,
        .ident = "subject.CN",
        .match = .match_equal,
        .ident2 = "My Name (DEADBEEF2)",
    });
    try req.opCertGeneric(gpa, .{
        .slot = 1,
        // TODO encode the OID in its binary format
        .ident = &[_]u8{ 0xef, 0xbe, 0xad, 0xde, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0 },
        .match = .match_exists,
    });
    var reqs = CodeSignature.Requirements{};
    try reqs.requirements.append(gpa, req);
    code_sig.requirements = reqs;

    try macho.writeCodeSignaturePadding(code_sig);
    try macho.writeHeader();

    try code_sig.finalizeForSigning(gpa, .{
        .bin_file = &macho,
        .flags = std.macho.CS_SIGNER_TYPE_UNKNOWN,
    });

    const encoder = try ZigKit.Security.CMSEncoder.create();
    defer encoder.release();

    const cert_file = try fs.cwd().openFile(opts.identity.?, .{});
    defer cert_file.close();
    const cert_bytes = try cert_file.readToEndAlloc(gpa, std.math.maxInt(u32));
    defer gpa.free(cert_bytes);
    const cert = try ZigKit.Security.SecCertificate.initWithData(cert_bytes);
    defer cert.release();
    const signer = try ZigKit.Security.SecIdentity.initWithCertificate(cert);
    defer signer.release();
    try encoder.setCertificateChainMode(.chain_with_root_or_fail);
    try encoder.addSigner(signer);
    try encoder.setSignerAlgorithm(.sha256);
    try encoder.setHasDetachedContent(true);

    var cd = std.ArrayList(u8).init(gpa);
    defer cd.deinit();
    try cd.ensureTotalCapacity(code_sig.code_directory.size());
    try code_sig.code_directory.write(cd.writer());

    try encoder.updateContent(cd.items);
    try code_sig.addSignature(gpa, try encoder.finalize());

    try macho.writeCodeSignature(&code_sig);

    try dir.copyFile("app", dir, "app", .{});
}

fn hashAssets(gpa: Allocator, dir: fs.Dir, assets: []fs.File) !void {
    var cs_dir = try dir.makeOpenPath("_CodeSignature", .{});
    defer cs_dir.close();
    const res = try cs_dir.createFile("CodeResources", .{});
    defer res.close();

    assert(assets.len == 1);

    const contents = try assets[0].readToEndAlloc(gpa, std.math.maxInt(u32));
    defer gpa.free(contents);

    const Sha1 = std.crypto.hash.Sha1;
    const template = @import("code_resources_blob.zig");

    var buf: [Sha1.digest_length]u8 = undefined;
    Sha1.hash(contents, &buf, .{});

    const enc = std.base64.standard.Encoder;
    var base64_buf: [enc.calcSize(Sha1.digest_length)]u8 = undefined;
    const base64 = enc.encode(&base64_buf, &buf);

    try res.writer().print("{s}{s}{s}", .{ template.lower, base64, template.upper });
}
