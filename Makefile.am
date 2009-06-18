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
# Author:       Ashoka Rao S <ashoka.rao@in.ibm.com>
#				Riyashmon Haneefa <riyashh1@in.ibm.com>
# Description:  Automake input file for cmpi provider and resource
#               access layer.
# ==================================================================

#Include local M4 macros
ACLOCAL_AMFLAGS = -I m4

# SBLIM Include Directory
sblimincdir = $(includedir)/sblim

# SBLIM Headers to be installed
sbliminc_HEADERS =

# docdir defines where the documentation goes
docdir = $(datadir)/doc/$(PACKAGE)-$(VERSION)

# Non-Installable Header Files
noinst_HEADERS =

# Configuration files
sysconf_DATA =

# Scripts that are used in the libraries
pkgdata_SCRIPTS =

# System wide libraries
lib_LTLIBRARIES =

# providerdir defines where provider libraries will be installed (@PROVIDERDIR@ is set by the configure script). 
providerdir = @PROVIDERDIR@

# Start from an empty list for files to clean up
CLEANFILES = include/sblim-fw.h

# Start from an empty extra distribution file list
EXTRA_DIST = sblim-cmpi-firewall.spec

# Pre Build requirements need to be compiled prior anything else
BUILT_SOURCES = include/sblim-fw.h

# Build subdirectories
#if TESTSUITE_SUPPORT
 # TESTCASE_DIR = test
#endif
SUBDIRS = resource-access provider po man test


######################################################################################
# Automake instructions for documentation
doc_DATA = README AUTHORS COPYING

######################################################################################
# We must explicity add the RPM spec file to the distribution package
EXTRA_DIST += $(PACKAGE).spec

######################################################################################
# We must explicity take care of the common header file to search/replace everything 
# correctly
include/sblim-fw.h: include/sblim-fw.h.pre
	sed -e 's,[@]SCRIPTDIR[@],$(pkgdatadir),g' -e s?$$\{prefix\}?$(prefix)?g -e s?$$\{exec_prefix\}?$(prefix)?g $< > $@

noinst_HEADERS += include/sblim-fw.h

######################################################################################
# Generate the *.gmo's during make
all-local:
	$(MAKE) update-gmo -C po

#######################################################################################
# Automake instructions for ./model subdir

######################################################################################
SCHEMAS = \
    model/Linux_FirewallService.mof \
    model/Linux_FirewallTrustedServices.mof \
    model/Linux_FirewallInterface.mof \
    model/Linux_FirewallManagedPorts.mof \
    model/Linux_FirewallManagedPortsForInterface.mof \
    model/Linux_FirewallTrustedServicesForInterface.mof \
    model/Linux_FirewallServiceConfiguration.mof \
    model/Linux_FirewallRegisteredProfile.mof \
    model/Linux_FirewallElementConformsToProfile.mof \
    model/Linux_FirewallServiceConfigurationForService.mof 

######################################################################################
REGISTRATIONS = \
    model/registration/Linux_FirewallService.registration \
    model/registration/Linux_FirewallTrustedServices.registration \
    model/registration/Linux_FirewallTrustedServicesForInterface.registration \
    model/registration/Linux_FirewallInterface.registration \
    model/registration/Linux_FirewallManagedPorts.registration \
    model/registration/Linux_FirewallManagedPortsForInterface.registration \
    model/registration/Linux_FirewallServiceConfiguration.registration \
    model/registration/Linux_FirewallServiceConfigurationForService.registration 

######################################################################################
INTEROP_SCHEMAS = \
    model/Linux_FirewallService.mof \
    model/Linux_FirewallRegisteredProfile.mof \
    model/Linux_FirewallElementConformsToProfile.mof

######################################################################################
INTEROP_REGISTRATIONS = \
    model/registration/Linux_FirewallRegisteredProfile.registration \
    model/registration/Linux_FirewallElementConformsToProfile.registration

######################################################################################

# We must explicity add all the schema files to the distribution package
pkgdata_DATA = $(SCHEMAS) $(REGISTRATIONS) $(INTEROP_SCHEMAS) $(INTEROP_REGISTRATIONS)

pkgdata_SCRIPTS += $(srcdir)/provider-register.sh $(srcdir)/template.rule

EXTRA_DIST += $(pkgdata_SCRIPTS) $(pkgdata_DATA)

# Register the provider(s) and class definition(s) to the current CIM server/CIMOM
postinstall:
	sh provider-register.sh -t @CIMSERVER@ -r $(REGISTRATIONS) -m $(SCHEMAS)
	sh provider-register.sh -t @CIMSERVER@ -n "root/PG_InterOp" -r $(INTEROP_REGISTRATIONS) -m $(INTEROP_SCHEMAS)

preuninstall:
	sh provider-register.sh -d -t @CIMSERVER@ -r $(REGISTRATIONS) -m $(SCHEMAS)
	sh provider-register.sh -d -t @CIMSERVER@ -n "root/PG_InterOp" -r $(INTEROP_REGISTRATIONS) -m $(INTEROP_SCHEMAS)

dist-hook:
	test -d "$(distdir)" &&	rm -rf `find $(distdir) -type d -name CVS`

