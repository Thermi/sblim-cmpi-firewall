# ==================================================================
# © Copyright IBM Corp. 2008,  
#  
# THIS FILE IS PROVIDED UNDER THE TERMS OF THE ECLIPSE PUBLIC LICENSE  
# ("AGREEMENT"). ANY USE, REPRODUCTION OR DISTRIBUTION OF THIS FILE  
# CONSTITUTES RECIPIENTS ACCEPTANCE OF THE AGREEMENT.  
#  
# You can obtain a current copy of the Eclipse Public License from  
# http://www.opensource.org/licenses/eclipse-1.0.php  
#
# Authors:	Riyashmon Haneefa <riyashh1@in.ibm.com>
# Description:  Automake input file for resource access layer.
# ==================================================================

AM_CFLAGS = -Wall 
#AM_CFLAGS = -Wall -g -DDEBUG -DTRACE

LEX = flex
LFLAGS = -i

YACC = bison
YFLAGS = -d --verbose

CC = cc
#CFLAGS = -g -DDEBUG -DTRACE


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

# Start from an empty extra distribution file list
EXTRA_DIST =

# Start from an empty list of programs not to install
noinst_PROGRAMS =

# System wide libraries
lib_LTLIBRARIES = 

######################################################################################
# Automake instructions for 'resource-access' dir

smt_fw_ra_support.conf: smt_fw_ra_support.conf.pre
	sed -e 's,[@]SCRIPTDIR[@],$(pkgdatadir),g' -e s?$$\{prefix\}?$(prefix)?g -e s?$$\{exec_prefix\}?$(prefix)?g $< > $@

# Adding new generated files to file list for clean up
CLEANFILES = \
	fw.fwconf.parser.tab.c \
	fw.fwconf.parser.tab.h \
	fw.fwconf.parser.output \
	lex.fwconf.c \
	smt_fw_ra_support.conf \
	smt_fw_ra_support.conf.pre \
	fw.rule.parser.tab.c \
	fw.rule.parser.tab.h \
	fw.rule.parser.output \
	lex.rule.c 

# Files for /etc directory
sysconf_DATA += smt_fw_ra_support.conf

pkgdata_SCRIPTS = \
    smt_fw_ra_status.sh 

pkgdata_DATA = 

# LibRaTools libraries
lib_LTLIBRARIES += \
	 libRaToolsFirewall.la 

# LibRaTools sources
libRaToolsFirewall_la_SOURCES = \
    fw-provider-support.c  \
    fw-ra-support.c \
    smt_fw_ra_service.c
    
nodist_libRaToolsFirewall_la_SOURCES = \
    fw.fwconf.parser.tab.c \
    lex.fwconf.c \
    fw.fwconf.parser.tab.h \
    fw.rule.parser.tab.c \
    fw.rule.parser.tab.h \
    lex.rule.c 

libRaToolsFirewall_la_CPPFLAGS = \
    -fPIC \
    -DPROVIDER_CONFFILE=\"$(sysconfdir)/smt_fw_ra_support.conf\" \
    -D_GNU_SOURCE \
    -I${srcdir}/../include/ 

libRaToolsFirewall_la_CFLAGS = \
    -DTRACE -g -DDEBUG -Wall

libRaToolsFirewall_la_LDFLAGS = \
    -fPIC -lpthread 

# Installable Header Files
noinst_HEADERS += \
    fw-provider-support.h \
    smt_fw_ra_service.h \
    fw-ra-support.h

# Parser binaries for testing
noinst_PROGRAMS += confTest 

confTest_SOURCES = \
        conftest.c 

confTest_CPPFLAGS = \
        -D_GNU_SOURCE \
        -DDEBUG_YACC \
        -I${srcdir}/../include/ 
       

confTest_CFLAGS = \
        -DTRACE -g -DDEBUG -DDEBUG_YACCC -Wall

confTest_LDADD  = \
        libRaToolsFirewall.la


# We must explicitly add the list of scripts to the 
EXTRA_DIST += $(pkgdata_DATA) $(pkgdata_SCRIPTS) fw.fwconf.lexer.l fw.fwconf.parser.y fw.rule.lexer.l fw.rule.parser.y


lex.fwconf.c: fw.fwconf.lexer.l
	$(LEX) $(LFLAGS) $<

lex.rule.c: fw.rule.lexer.l
	$(LEX) $(LFLAGS) $<

fw.fwconf.parser.tab.c: fw.fwconf.parser.y
	$(YACC) $(YFLAGS) $<

fw.rule.parser.tab.c: fw.rule.parser.y
	$(YACC) $(YFLAGS) $<

