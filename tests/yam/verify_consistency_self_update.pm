# Copyright 2024 SUSE LLC
# SPDX-License-Identifier: GPL-2.0-or-later
#
# Summary: Test 'CAP_BPF' capability is available when 'unprivileged_bpf_disabled=1'
# Maintainer: QE YaST and Migration (QE Yam) <qe-yam at suse de>

use base "consoletest";
use strict;
use warnings;
use testapi;
use utils;
use serial_terminal 'select_serial_terminal';

sub run {
  select_serial_terminal;

  zypper_call 'ar -f http://dist.suse.de/ibs/SUSE:/Maintenance:/Test:/SLE-INSTALLER:/15-SP5:/x86_64/update/ self-update';
  zypper_call 'dup';
}

1;
