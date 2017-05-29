# Copyright (C) 2015, 2017 SUSE Linux Products GmbH
#
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation; either version 2 of the License, or
# (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License along
# with this program; if not, see <http://www.gnu.org/licenses/>.

# Summary: support for saving and loading of hdd image
# Maintainer: Vladimir Nadvornik <nadvornik@suse.cz>

use strict;
use base 'basetest';
use testapi;
use utils qw(sle_version_at_least power_action);

sub run {
    select_console('root-console');
    if (get_var('DROP_PERSISTENT_NET_RULES')) {
        type_string "rm -f /etc/udev/rules.d/70-persistent-net.rules\n";
    }
    if (!sle_version_at_least('12-SP2') && check_var('VIRTIO_CONSOLE', 1)) {
        type_string("echo 'hvc0' >> /etc/securetty\n");
        script_run('systemctl enable serial-getty@hvc0');
        script_run('systemctl start serial-getty@hvc0');
    }
    power_action('poweroff');
}

sub test_flags {
    return {fatal => 1};
}

1;

# vim: set sw=4 et:
