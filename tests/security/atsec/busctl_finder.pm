# SUSE's openQA tests
#
# Copyright 2022 SUSE LLC
# SPDX-License-Identifier: FSFAP
#
# Summary: find missing busctl targets
# Maintainer: QE Security <none@suse.de>

use base 'consoletest';
use strict;
use warnings;
use testapi;
use utils;

sub run {
    my ($self) = shift;

    select_console 'root-console';

    my $log_file = "busctl_list.log";

    my $cont = 1;
    while ($cont) {
        script_output("busctl list | grep -E '1\\.27|1\\.28|1\\.34|1\\.35' > $log_file");
        if (script_output("grep -E '1\\.27|1\\.28|1\\.34|1\\.35' $log_file") == 0) {
            record_soft_failure(script_output("cat $log_file"));
            $cont = 0;
        }
    }

}

1;
