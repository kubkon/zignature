pub const lower: []const u8 =
    \\<?xml version="1.0" encoding="UTF-8"?>
    \\<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
    \\<plist version="1.0">
    \\<dict>
    \\	<key>files</key>
    \\	<dict>
    \\		<key>Info.plist</key>
    \\		<data>
;

pub const upper: []const u8 =
    \\</data>
    \\	</dict>
    \\	<key>files2</key>
    \\	<dict/>
    \\	<key>rules</key>
    \\	<dict>
    \\		<key>^.*</key>
    \\		<true/>
    \\		<key>^.*\.lproj/</key>
    \\		<dict>
    \\			<key>optional</key>
    \\			<true/>
    \\			<key>weight</key>
    \\			<real>1000</real>
    \\		</dict>
    \\		<key>^.*\.lproj/locversion.plist$</key>
    \\		<dict>
    \\			<key>omit</key>
    \\			<true/>
    \\			<key>weight</key>
    \\			<real>1100</real>
    \\		</dict>
    \\		<key>^Base\.lproj/</key>
    \\		<dict>
    \\			<key>weight</key>
    \\			<real>1010</real>
    \\		</dict>
    \\		<key>^version.plist$</key>
    \\		<true/>
    \\	</dict>
    \\	<key>rules2</key>
    \\	<dict>
    \\		<key>.*\.dSYM($|/)</key>
    \\		<dict>
    \\			<key>weight</key>
    \\			<real>11</real>
    \\		</dict>
    \\		<key>^(.*/)?\.DS_Store$</key>
    \\		<dict>
    \\			<key>omit</key>
    \\			<true/>
    \\			<key>weight</key>
    \\			<real>2000</real>
    \\		</dict>
    \\		<key>^.*</key>
    \\		<true/>
    \\		<key>^.*\.lproj/</key>
    \\		<dict>
    \\			<key>optional</key>
    \\			<true/>
    \\			<key>weight</key>
    \\			<real>1000</real>
    \\		</dict>
    \\		<key>^.*\.lproj/locversion.plist$</key>
    \\		<dict>
    \\			<key>omit</key>
    \\			<true/>
    \\			<key>weight</key>
    \\			<real>1100</real>
    \\		</dict>
    \\		<key>^Base\.lproj/</key>
    \\		<dict>
    \\			<key>weight</key>
    \\			<real>1010</real>
    \\		</dict>
    \\		<key>^Info\.plist$</key>
    \\		<dict>
    \\			<key>omit</key>
    \\			<true/>
    \\			<key>weight</key>
    \\			<real>20</real>
    \\		</dict>
    \\		<key>^PkgInfo$</key>
    \\		<dict>
    \\			<key>omit</key>
    \\			<true/>
    \\			<key>weight</key>
    \\			<real>20</real>
    \\		</dict>
    \\		<key>^embedded\.provisionprofile$</key>
    \\		<dict>
    \\			<key>weight</key>
    \\			<real>20</real>
    \\		</dict>
    \\		<key>^version\.plist$</key>
    \\		<dict>
    \\			<key>weight</key>
    \\			<real>20</real>
    \\		</dict>
    \\	</dict>
    \\</dict>
    \\</plist>
;