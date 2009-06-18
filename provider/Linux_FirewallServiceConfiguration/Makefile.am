# ==================================================================
# © Copyright IBM Corp. 2008
#
# THIS FILE IS PROVIDED UNDER THE TERMS OF THE ECLIPSE PUBLIC LICENSE
# ("AGREEMENT"). ANY USE, REPRODUCTION OR DISTRIBUTION OF THIS FILE
# CONSTITUTES RECIPIENTS ACCEPTANCE OF THE AGREEMENT.
#
# You can obtain a current copy of the Eclipse Public License from
# http://www.opensource.org/licenses/eclipse-1.0.php
#
# Author:       Ashoka Rao <ashoka.rao (at) in.ibm.com>
#               Riyashmon Haneefa <riyashh1 (at) in.ibm.com>
#
# ==================================================================


# providerdir defines where provider libraries will be installed 
# (@PROVIDERDIR@ is set by the configure script). 
providerdir = @PROVIDERDIR@

###############################################################################
AM_CFLAGS = -g \
    -Wall \
    -Werror

AM_CPPFLAGS = \
    -D_GNU_SOURCE \
        -DDEBUG \
    -DSBLIM_DEBUG\
    -D_COMPILE_UNIX \
    -I${top_srcdir}/include/ \
    -I${top_srcdir}/resource-access/ 


################################################################################
provider_LTLIBRARIES = \
    libcmpiLinux_FirewallServiceConfiguration.la 

libcmpiLinux_FirewallServiceConfiguration_la_LDFLAGS = \
    -avoid-version

libcmpiLinux_FirewallServiceConfiguration_la_SOURCES = \
    Linux_FirewallServiceConfiguration.c\
    Linux_FirewallServiceConfiguration_Resource.c

noinst_HEADERS = \
    Linux_FirewallServiceConfiguration_Resource.h

libcmpiLinux_FirewallServiceConfiguration_la_LIBADD = \
     ${top_builddir}/resource-access/libRaToolsFirewall.la
