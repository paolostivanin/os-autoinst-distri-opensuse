# Copyright 2023 SUSE LLC
# SPDX-License-Identifier: GPL-2.0-or-later
#
# Summary: create the baseline file
# Maintainer: QE Security <none@suse.de>

use base 'consoletest';
use version_utils qw(is_sle);
use registration qw(add_suseconnect_product);
use strict;
use warnings;
use testapi;
use utils;
use lynis::lynistest;

sub run {
    my $lynis_baseline_file = $lynis::lynistest::lynis_baseline_file;
    my $dir = $lynis::lynistest::testdir;

    select_console "root-console";

    add_suseconnect_product("PackageHub", undef, undef, undef, 300, 1) if is_sle;
    add_suseconnect_product("sle-module-legacy", undef, undef, undef, 300, 1) if is_sle;
    # Set timeout to 300s as the default 90s is not enough in some situations
    zypper_call("in lynis", timeout => 300);

    # Record the pkgs' version for reference
    my $results = script_output("rpm -qi lynis");
    record_info("Pkg_ver", "Lynix packages' version is: $results");

    my $out_file = "lynis_baseline_" . get_var('DESKTOP');
    assert_script_run("lynis audit system --no-colors > $out_file");
    upload_logs("$out_file");
}

sub test_flags {
    return {milestone => 1, fatal => 1};
}

1;
