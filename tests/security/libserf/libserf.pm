# SUSE's openQA tests
#
# Copyright 2025 SUSE LLC
# SPDX-License-Identifier: FSFAP
#
# Summary: Setup Apache2 with SSL enabled and test libserf by using SVN.
# This test validates libserf’s handling of HTTPS, authentication, SSL certs,
# and common SVN operations (checkout, update, commit, diff, log).
#
# Maintainer: QE Security <none@suse.de>
# Tags: poo#110434, tc#1769948, poo#112550

use base 'consoletest';
use testapi;
use utils;
use Utils::Architectures;
use Utils::Logging qw(tar_and_upload_log);

my $server_name = 'example-ssl.com';
my $repo_root = '/srv/www/svn/repos';
my $test_project = 'mytestproj';
my $vhost_ssl_conf = '/etc/apache2/vhosts.d/vhost-ssl.conf';
my $svn_conf_file = '/etc/apache2/conf.d/subversion.conf';
my $svn_user = 'testuser';
my $svn_pass = 'testpass';

sub setup_apache {
    zypper_call('in apache2 subversion-server openssl');

    # Enable SSL
    assert_script_run('a2enmod ssl');
    assert_script_run("echo '127.0.0.1 $server_name localhost' > /etc/hosts");

    # Generate SSL cert
    assert_script_run("gensslcert -n $server_name -e webmaster\@$server_name");

    # Configure SSL vhost
    type_string("cat >> $vhost_ssl_conf <<EOF
<IfDefine SSL>
<IfDefine !NOSSL>
<VirtualHost _default_:443>
    DocumentRoot \"/srv/www/vhosts/$server_name\"
    ServerName $server_name
    ServerAdmin webmaster\@$server_name
    ErrorLog /var/log/apache2/$server_name-error_log
    TransferLog /var/log/apache2/$server_name-access_log
    CustomLog /var/log/apache2/$server_name-ssl_request_log ssl_combined

    SSLEngine on
    SSLCertificateFile /etc/apache2/ssl.crt/$server_name-server.crt
    SSLCertificateKeyFile /etc/apache2/ssl.key/$server_name-server.key
    SSLCertificateChainFile /etc/apache2/ssl.crt/$server_name-ca.crt

    <Directory \"/srv/www/vhosts/$server_name\">
        Options Indexes FollowSymLinks
        AllowOverride None
        Require all granted
    </Directory>
</VirtualHost>
</IfDefine>
</IfDefine>
EOF
");

    # Ensure apache runs with SSL
    assert_script_run("sed -i '/^APACHE_SERVER_FLAGS=*/c\\APACHE_SERVER_FLAGS=\"SSL\"' /etc/sysconfig/apache2");
}

sub setup_svn {
    # Configure Subversion + Auth
    assert_script_run("htpasswd -cb /etc/apache2/svn.passwd $svn_user $svn_pass");
    type_string("cat >> $svn_conf_file <<EOF
LoadModule dav_module       /usr/lib64/apache2/mod_dav.so
LoadModule dav_svn_module   /usr/lib64/apache2/mod_dav_svn.so
<IfModule mod_dav_svn.c>
<Location /repos>
    DAV svn
    SVNPath $repo_root
    AuthType Basic
    AuthName \"SVN Repo\"
    AuthUserFile /etc/apache2/svn.passwd
    Require valid-user
</Location>
</IfModule>
EOF
");

    systemctl('restart apache2');
    systemctl('is-active apache2');

    # Create SVN repository
    assert_script_run("mkdir -pZ $repo_root");
    assert_script_run("svnadmin create $repo_root");
    assert_script_run("chown -R wwwrun:wwwrun $repo_root");

    # Import initial project structure
    assert_script_run('cd /tmp && mkdir mytestproj && cd mytestproj');
    assert_script_run('mkdir configurations options main');
    assert_script_run('echo "testconf1" > configurations/testconf1.cfg');
    assert_script_run('echo "testopts1" > options/testopts1.cfg');
    assert_script_run('echo "mainfile1" > main/mainfile1.cfg');
    validate_script_output(
        "svn import /tmp/$test_project/ file://$repo_root/$test_project -m \"Init commit\"",
        sub { m/Committed/ }
    );
}

sub svn_url {
    return "https://$server_name/repos/$test_project";
}

sub run {
    my ($self) = @_;
    select_console('root-console');

    setup_apache;
    setup_svn;

    # Allow SVN to accept the self-signed cert automatically
    assert_script_run("yes p | svn ls " . svn_url() . " --username $svn_user --password $svn_pass");

    # Checkout + Update flow
    assert_script_run("svn co " . svn_url() . " --username $svn_user --password $svn_pass");
    assert_script_run("cd $test_project && echo 'newline' >> configurations/testconf1.cfg");
    validate_script_output("svn commit -m 'Add a new line' --username $svn_user --password $svn_pass", sub { m/Committed/ });
    assert_script_run("svn update --username $svn_user --password $svn_pass");

    # Diff & Log (different HTTP REPORT/GET requests)
    validate_script_output("svn diff --username $svn_user --password $svn_pass", sub { m/newline/ });
    validate_script_output("svn log --username $svn_user --password $svn_pass", sub { m/Init commit/ });

    # Add + Delete files
    assert_script_run("cp /etc/hosts configurations/");
    validate_script_output("svn add configurations/hosts", sub { m/A\s+configurations\/hosts/ });
    validate_script_output("svn commit -m 'Add hosts file' --username $svn_user --password $svn_pass", sub { m/Committed/ });
    validate_script_output("svn delete configurations/testconf1.cfg", sub { m/D\s+configurations\/testconf1.cfg/ });
    validate_script_output("svn commit -m 'Delete testconf1.cfg' --username $svn_user --password $svn_pass", sub { m/Committed/ });

    # Concurrency test (multi-checkout sync)
    assert_script_run("cd && svn co " . svn_url() . " $test_project-2 --username $svn_user --password $svn_pass");
    assert_script_run("cd $test_project-2 && echo 'from_second_wc' >> options/testopts1.cfg");
    validate_script_output("svn commit -m 'Commit from second WC' --username $svn_user --password $svn_pass", sub { m/Committed/ });
    assert_script_run("cd ../$test_project && svn update --username $svn_user --password $svn_pass");
    validate_script_output("grep from_second_wc options/testopts1.cfg", sub { m/from_second_wc/ });

    # TLS check: only allow TLSv1.2 and test connection
    assert_script_run("sed -i '/SSLEngine on/a SSLProtocol -all +TLSv1.2' $vhost_ssl_conf");
    systemctl('restart apache2');
    assert_script_run("openssl s_client -connect localhost:443 -tls1_2 < /dev/null | grep 'SSL-Session'");
    assert_script_run("svn ls " . svn_url() . " --username $svn_user --password $svn_pass");

    # Expired cert test (expect failure)
    assert_script_run("gensslcert -n expired.$server_name -e webmaster\@$server_name -c --days 0");
    # This should fail because cert is expired
    script_run("svn ls https://expired.$server_name/repos", 90);

    # Cleanup
    assert_script_run("cd && rm -rf $test_project $test_project-2");
}

sub post_fail_hook {
    my ($self) = @_;
    select_console('log-console');
    tar_and_upload_log('/var/log/apache2', '/tmp/apache-logs.tar.bz2');
    tar_and_upload_log($repo_root, '/tmp/svn-repo.tar.bz2');
    upload_logs($vhost_ssl_conf);
    upload_logs($svn_conf_file);
    $self->SUPER::post_fail_hook;
}

1;
