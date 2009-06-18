#! /bin/sh

#
# smt_fw_ra_status.sh
#
# (C) Copyright IBM Corp. 2008
#
# THIS FILE IS PROVIDED UNDER THE TERMS OF THE ECLIPSE PUBLIC LICENSE
# ("AGREEMENT"). ANY USE, REPRODUCTION OR DISTRIBUTION OF THIS FILE
# CONSTITUTES RECIPIENTS ACCEPTANCE OF THE AGREEMENT.
#
# You can obtain a current copy of the Eclipse Public License from
# http://www.opensource.org/licenses/eclipse-1.0.php
#
# Author:     Riyashmon Haneefa <riayshh1@in.ibm.com>
#             Ashoka S Rao      <ashoka.rao@in.ibm.com>
#
#
#

#check for the presence of iptable kernel modules under use!
modules=`cat /proc/net/ip_tables_names 2>/dev/null`

#look for the lockfiles available in var
filelock=/var/lock/subsys/iptables


if [ -f "$filelock" -a -n "$modules" ]; then
    echo -n $"Firewall is running."
    echo
    exit 5
else
    echo -n $"Firewall is stopped."
    echo 
    exit 0
fi


