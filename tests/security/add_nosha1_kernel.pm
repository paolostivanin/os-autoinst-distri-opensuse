# SUSE's openQA tests
#
# Copyright 2024 SUSE LLC

# Summary: boot disk using the right moodules
# Maintainer: QE Security <none@suse.de>

use strict;
use warnings;
use base 'opensusebasetest';
use serial_terminal 'select_serial_terminal';
use testapi;
use utils 'zypper_call';

sub run {
    select_serial_terminal;

    my $kernel_repo = 'http://download.suse.de/ibs/home:/nstange:/FIPS:/Kernel:/SLE16-sha1-disabled/standard/';

    zypper_call("ar -f -p 90 $kernel_repo kernel-no-sha1"); 
    zypper_call '--no-gpg-checks dup';
}

sub test_flags {
    return {fatal => 1};
}

1;

