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
# Author:       Riyashmon Haneefa <riyashh1 (at) in.ibm.com>
#
# ==================================================================

CLEANFILES = smt_fw_ra_support.conf.5

smt_fw_ra_support.conf.5: smt_fw_ra_support.conf.5.pre
	sed -e 's,[@]SCRIPTDIR[@],$(pkgdatadir),g' -e s?$$\{prefix\}?$(prefix)?g -e s?$$\{exec_prefix\}?$(prefix)?g $< > $@

man5_MANS = \
    smt_fw_ra_support.conf.5

dist_man_MANS = \
    smt_fw_ra_support.conf.5
