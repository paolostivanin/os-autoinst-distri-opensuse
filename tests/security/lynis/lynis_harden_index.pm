# Copyright 2025 SUSE LLC
# SPDX-License-Identifier: GPL-2.0-or-later
#
# Summary: Integrate the Lynis scanner into OpenQA: compare the "Hardening
#          index" of the current audit with the baseline
# Maintainer: QE Security <none@suse.de>
# Tags: poo#78224, poo#78230

use Mojo::Base 'consoletest';
use testapi;
use utils;
use serial_terminal 'select_text_console';
use lynis::lynistest;

sub run {
    my $dir = $lynis::lynistest::testdir;
    my $lynis_baseline_file = "$dir" . $lynis::lynistest::lynis_baseline_file;
    my $lynis_current_file = "$dir" . $lynis::lynistest::lynis_audit_system_current_file;
    my $str = "Hardening index";

    select_text_console;

    # The index changes by a point or two when a single test gives a
    # different result, e.g. after a maintenance update. Only a larger drop
    # needs a check.
    my $max_drop = 2;

    # Parse the "Hardening index" of baseline and current files
    my $out_b = script_output("grep \"$str\" $lynis_baseline_file");
    my $out_c = script_output("grep \"$str\" $lynis_current_file");
    my ($index_b) = $out_b =~ /$str\s*:\s*(\d+)/;
    my ($index_c) = $out_c =~ /$str\s*:\s*(\d+)/;
    die "Cannot parse the \"$str\" values" unless defined $index_b && defined $index_c;
    my $values = "Baseline: $out_b\nCurrent: $out_c";
    if ($index_c == $index_b) {
        record_info("Same", "\"$str\" is the same.\n$values");
    }
    elsif ($index_b - $index_c <= $max_drop) {
        record_info("Changed", "\"$str\" is not the same, but did not drop by more than $max_drop.\n$values");
    }
    else {
        record_info("Dropped", "\"$str\" dropped by more than $max_drop.\n$values");
        record_soft_failure("poo#91383, \"$str\" dropped by more than $max_drop, please check");
    }
}

1;
