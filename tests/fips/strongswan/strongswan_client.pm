# strongswan test
#
# Copyright 2025 SUSE LLC
# SPDX-License-Identifier: FSFAP
#
# Package: strongswan
# Summary: FIPS: strongswan_client
#          In fips mode, testing strongswan
#
# Maintainer: QE Security <none@suse.de>
# Tags: poo#108620, tc#1769974

use Mojo::Base 'consoletest';
use testapi;
use utils;
use lockapi;
use package_utils 'install_package';
use version_utils qw(package_version_cmp is_sle is_leap has_selinux);
use Utils::Architectures 'is_s390x';
use Utils::Systemd qw(disable_and_stop_service check_unit_file);

sub run {
    my $self = shift;
    select_console 'root-console';

    # Install the runtime dependencies transactional-aware: trup_apply lets us
    # start the service without a reboot on immutable systems
    my @pkgs = qw(strongswan strongswan-hmac wget);
    push @pkgs, qw(strongswan-mysql strongswan-sqlite) if is_sle('>=16');
    # semanage allows sshd on the extra port on s390x, see below
    push @pkgs, 'policycoreutils-python-utils' if (is_s390x && has_selinux);
    install_package(join(' ', @pkgs), trup_apply => 1);

    my $remote_ip = get_var('SERVER_IP', '10.0.2.101');
    my $local_ip = get_var('CLIENT_IP', '10.0.2.102');

    # setup_multimachine does not run on s390x. Add the known IP address
    # to the default network device and stop the firewall instead.
    # The server copies the keys with scp as root, so permit the root login.
    # The s390x guests cannot connect to each other on port 22, so sshd also
    # listens on port 2222, the same as in the 389ds test.
    my $net_dev;
    if (is_s390x) {
        $net_dev = script_output(q(ip route show default | awk '{print $5; exit}'));
        assert_script_run("ip addr add $local_ip/24 dev $net_dev");
        disable_and_stop_service($self->firewall, ignore_failure => 1) if check_unit_file($self->firewall);
        permit_root_ssh();
        my $sshd_conf = (is_sle('<16') || is_leap('<16.0')) ? '/etc/ssh/sshd_config' : '/etc/ssh/sshd_config.d/50-strongswan-port.conf';
        assert_script_run("printf 'Port 22\\nPort 2222\\n' >> $sshd_conf");
        assert_script_run('semanage port -a -t ssh_port_t -p tcp 2222') if has_selinux;
        systemctl('restart sshd');
    }

    my ($conf, $conf_temp, $conf_backup) = '';

    my $version = script_output("rpm -q --qf '%{version}' strongswan");

    if (package_version_cmp($version, '6.0.0') < 0) {
        # Configure ipsec.conf
        $conf = '/etc/ipsec.conf';
        $conf_temp = 'ipsec.conf.temp';
        $conf_backup = '/etc/ipsec.conf.bak';
    } else {
        # Configure swanctl.conf
        $conf = '/etc/swanctl/swanctl.conf';
        $conf_temp = 'swanctl.conf.temp';
        $conf_backup = '/etc/swanctl/swanctl.conf.bak';
    }

    if (package_version_cmp($version, '6.0.0') < 0) {
        # Workaround for bsc#1184144
        record_info('The next two steps are workaround for bsc#1184144');
        assert_script_run('mv /usr/lib/systemd/system/strongswan.service /usr/lib/systemd/system/strongswan-swanctl.service');
        assert_script_run('cp /usr/lib/systemd/system/strongswan-starter.service /usr/lib/systemd/system/strongswan.service');
    }

    # Download the template of ipsec.conf
    assert_script_run("wget --quiet " . data_url("strongswan/$conf_temp"));

    # Replace the vars %VARS% with correct value
    if (package_version_cmp($version, '6.0.0') < 0) {
        # only in ipsec.conf
        assert_script_run("sed -i 's/%LOCAL_IP%/$local_ip/' $conf_temp");
    }
    assert_script_run("sed -i 's/%REMOTE_IP%/$remote_ip/' $conf_temp");
    assert_script_run("sed -i 's/%HOST_CERT_PEM%/host2.cert.pem/' $conf_temp");
    assert_script_run("sed -i 's/%HOST%/host1/' $conf_temp");

    # Create a backup of the appropriate config file
    # and replace it with the filled-in template file
    assert_script_run("cp $conf $conf_backup");
    assert_script_run("cp $conf_temp $conf");

    if (package_version_cmp($version, '6.0.0') < 0) {
        # Edit /etc/ipsec.secrets
        assert_script_run('echo ": RSA host2.pem" >> /etc/ipsec.secrets');
    }

    mutex_create('STRONGSWAN_HOST2_UP');

    # for > v6.0 strongSwan will only start if the secrets are present
    mutex_wait('STRONGSWAN_HOST1_SECRETS_COPIED');

    mutex_wait('STRONGSWAN_HOST1_SERVER_START');

    systemctl 'restart strongswan';

    if (package_version_cmp($version, '6.0.0') < 0) {
        # establish the ipsec tunnel
        assert_script_run('ipsec up host-host');
    } else {
        #  establish a connection with swanctl
        assert_script_run("swanctl --initiate --child host-host");
    }

    mutex_create('STRONGSWAN_HOST2_START');
    systemctl 'is-active strongswan';

    if (package_version_cmp($version, '6.0.0') < 0) {
        validate_script_output('ipsec status', sub { m/Routed Connections/ && m/host-host\{\d\}:\s+$local_ip\/32\s===\s$remote_ip\/32/ && m/Security Associations.*1 up/ });
        validate_script_output('ipsec statusall', sub { m/host-host\[\d\]: IKEv2 SPIs/ && m/host-host\[\d\]: IKE proposal/ });
    }
    mutex_wait('TCPDUMP_READY');

    assert_script_run("ping -c 5 $remote_ip");
    mutex_create('PING_DONE');

    assert_script_run("ip addr del $local_ip/24 dev $net_dev") if is_s390x;
}

1;
