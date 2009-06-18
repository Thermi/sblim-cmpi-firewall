# ==================================================================
# © Copyright IBM Corp. 2007
#
# THIS FILE IS PROVIDED UNDER THE TERMS OF THE ECLIPSE PUBLIC LICENSE
# ("AGREEMENT"). ANY USE, REPRODUCTION OR DISTRIBUTION OF THIS FILE
# CONSTITUTES RECIPIENTS ACCEPTANCE OF THE AGREEMENT.
#
# You can obtain a current copy of the Eclipse Public License from
# http://www.opensource.org/licenses/eclipse-1.0.php
#
# Authors:	Ashoka Rao S <ashoka.rao (at) in.ibm.com>
#               Riyashmon Haneefa <riyashh1 (at) in.ibm.com>
# ==================================================================


# docdir defines where the documentation goes
docdir = $(datadir)/doc/$(PACKAGE)-$(VERSION)


######################################################################################
# Automake instructions for ./test subdir
EXTRA_DIST = README.test $(testsuite_SCRIPTS) $(testsuiteconf_DATA) system cim 

doc_DATA = README.test

testsuitedir=@TESTSUITEDIR@
testsuitesystemdir=@TESTSUITEDIR@/system/linux
testsuitecimdir=@TESTSUITEDIR@/cim
testsuitexmldir=@TESTSUITEDIR@/xml

testsuite_SCRIPTS=test-cmpi-firewall.sh

testsuitecim_DATA=\
    cim/Linux_FirewallElementConformsToProfile.cim \
    cim/Linux_FirewallInterface.cim \
    cim/Linux_FirewallManagedPorts.cim \
    cim/Linux_FirewallManagedPortsForInterface.cim \
    cim/Linux_FirewallRegisteredProfile.cim \
    cim/Linux_FirewallService.cim \
    cim/Linux_FirewallServiceConfiguration.cim \
    cim/Linux_FirewallServiceConfigurationForService.cim \
    cim/Linux_FirewallTrustedServices.cim \
    cim/Linux_FirewallTrustedServicesForInterface.cim

testsuitesystem_DATA=\
    system/linux/Linux_FirewallElementConformsToProfile.system \
    system/linux/Linux_FirewallInterface.system \
    system/linux/Linux_FirewallManagedPorts.system \
    system/linux/Linux_FirewallManagedPortsForInterface.system \
    system/linux/Linux_FirewallRegisteredProfile.system \
    system/linux/Linux_FirewallService.system \
    system/linux/Linux_FirewallServiceConfiguration.system \
    system/linux/Linux_FirewallServiceConfigurationForService.system \
    system/linux/Linux_FirewallTrustedServices.system \
    system/linux/Linux_FirewallTrustedServicesForInterface.system

