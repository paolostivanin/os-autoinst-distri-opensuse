# SUSE's openQA tests
#
# Copyright SUSE LLC
# SPDX-License-Identifier: FSFAP
#
# Summary: Run FIPS-mode Java crypto tests: JCA provider hashing, elliptic-curve math/ECDSA
#          and the RSA tool chain (key generation, OAEP encrypt/decrypt, SHA256withRSA sign/verify)
# Maintainer: QE Security <none@suse.de>

use Mojo::Base 'opensusebasetest';
use testapi;
use serial_terminal 'select_serial_terminal';
use agnosticTestRunner;

sub run {
    select_serial_terminal;
    # 4096-bit RSA key generation has a long tail on slow workers, the 90s default is not enough
    my %run_timeout = (java_rsa => 300);
    for my $name (qw(java_hashing java_elliptic java_rsa)) {
        agnosticTestRunner->new({language => 'java', name => $name, domain => 'security',
                run_timeout => $run_timeout{$name}})
          ->setup()->run_test()->parse_results()->cleanup();
    }
}

sub test_flags {
    return {always_rollback => 0};
}

1;
