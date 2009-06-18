#!/bin/bash
# ==================================================================
# © Copyright IBM Corp.  2008
#
# THIS FILE IS PROVIDED UNDER THE TERMS OF THE ECLIPSE PUBLIC LICENSE
# ("AGREEMENT"). ANY USE, REPRODUCTION OR DISTRIBUTION OF THIS FILE
# CONSTITUTES RECIPIENTS ACCEPTANCE OF THE AGREEMENT.
#
# You can obtain a current copy of the Eclipse Public License from
# http://www.opensource.org/licenses/eclipse-1.0.php
#
# Authors : Ashoka Rao S <ashoka.rao (at) in.ibm.com>
#           Riyashmon Haneefa <riyashh1 (at) in.ibm.com>
# ==================================================================


#*****************************************************************************#
export FIREWALLCONFFILE=/etc/sysconfig/iptables-config 

#*****************************************************************************#
PWD1=`pwd`

init() {
    echo " "
    echo "Initializing FIREWALL Test case environment"

     if [[ -a $FIREWALLCONFFILE ]]; then 
    echo " copy the $FIREWALLCONFFILE file to $FIREWALLCONFFILE.original "
    cp -p $FIREWALLCONFFILE $FIREWALLCONFFILE.original
    cp -p ./iptables-config /etc/sysconfig/
    else
    echo " copying the ./iptables-config to /etc/sysconfig "
    cp -p ./iptables-config /etc/sysconfig/
    fi
}

#*****************************************************************************#
cleanup() {
    echo "Cleanup system from FIREWALL Test case environment"
    
    if [[ -a $FIREWALLCONFFILE.original ]]; then
    echo " Copy back the $FIREWALLCONFFILE file "
    cp -p $FIREWALLCONFFILE.original $FIREWALLCONFFILE
    fi

}

#*****************************************************************************#
trap cleanup 2 3 4 6 9 15

#*****************************************************************************#

declare -a CLASSNAMES[];
CLASSNAMES=(
[1]=Linux_FirewallService
[2]=Linux_FirewallServiceConfiguration
[3]=Linux_FirewallServiceConfigurationForService
[4]=Linux_FirewallInterface
[5]=Linux_FirewallManagedPorts
[6]=Linux_FirewallTrustedServices
[7]=Linux_FirewallManagedPortsForInterface
[8]=Linux_FirewallTrustedServicesForInterface
)

#*****************************************************************************#

init

declare -i max=8;
declare -i i=1;


. ./run.sh Linux_FirewallRegisteredProfile -n /root/PG_InterOp || exit 1;
. ./run.sh Linux_FirewallElementConformsToProfile -n /root/PG_InterOp || exit 1;

while(($i<=$max))
do
 . ./run.sh ${CLASSNAMES[$i]} || exit 1;
  i=$i+1;
done

cleanup
