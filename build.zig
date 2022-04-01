const std = @import("std");

pub fn build(b: *std.build.Builder) void {
    const mode = b.standardReleaseOptions();
    const target = b.standardTargetOptions(.{});

    const lib = b.addStaticLibrary("zig-codesign", "src/codesign.zig");
    lib.setTarget(target);
    lib.setBuildMode(mode);
    lib.install();

    const exe = b.addExecutable("zig-codesign", "src/main.zig");
    exe.setTarget(target);
    exe.setBuildMode(mode);
    exe.install();

    const main_tests = b.addTest("src/codesign.zig");
    main_tests.setTarget(target);
    main_tests.setBuildMode(mode);

    const test_step = b.step("test", "Run library tests");
    test_step.dependOn(&main_tests.step);
}
