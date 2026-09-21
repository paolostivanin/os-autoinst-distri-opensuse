# SUSE's openQA tests
#
# Copyright SUSE LLC
# SPDX-License-Identifier: FSFAP
#
# Summary: Run FIPS-mode GSSAPI/SPNEGO HTTPS authentication test with python3-requests-gssapi
# Maintainer: QE Security <none@suse.de>
# Ticket: PED-16727, bsc#1266006

use Mojo::Base 'opensusebasetest';
use testapi;
use serial_terminal 'select_serial_terminal';
use agnosticTestRunner;
use version_utils 'is_sle';
use package_utils 'install_package';
use Utils::Systemd 'systemctl';

sub stop_services {
    # later modules in the same schedule (e.g. console/nginx) need port 443
    systemctl("stop apache2", ignore_failure => 1);
    systemctl("stop krb5kdc", ignore_failure => 1);
}

sub run {
    select_serial_terminal;

    if (!is_sle('=15-SP7')) {
        record_info('SKIP', 'This test targets the python3-requests-gssapi maintenance update for SLE 15-SP7');
        return;
    }

    my $fips_enabled = script_output('cat /proc/sys/crypto/fips_enabled', proceed_on_failure => 1);
    if ($fips_enabled ne '1') {
        record_info('SKIP', 'FIPS mode is not enabled');
        return;
    }

    my $test = agnosticTestRunner->new({
            language => 'python',
            name => 'testRequestsGssapiFips',
            domain => 'security',
        }
    );
    # setup() also registers Package Hub on SLE 15, which provides apache2-mod_auth_gssapi
    $test->setup();

    install_package("apache2 apache2-mod_auth_gssapi krb5 krb5-server krb5-client python3-requests-gssapi", trup_reboot => 1);
    record_info('Package versions', script_output('rpm -q python3-requests-gssapi python3-gssapi krb5-server apache2-mod_auth_gssapi', proceed_on_failure => 1));

    $test->run_test()->parse_results()->cleanup();
}

sub post_run_hook {
    my ($self) = @_;
    stop_services;
    $self->SUPER::post_run_hook;
}

sub post_fail_hook {
    my ($self) = @_;
    stop_services;
    $self->SUPER::post_fail_hook;
}

sub test_flags {
    return {always_rollback => 0};
}

1;
