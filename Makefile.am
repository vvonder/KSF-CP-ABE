#
#
# LIBFENC -- The Functional Encryption Library
#
#-------------------------------------------------------------------------------------------

# Have configure setup a Makefile in a subdirectory.
SUBDIRS = . tools benchmark

# Set the lib version value.
SO_VERSION = 0:2:0

ACLOCAL_AMFLAGS = -I m4
# Something I picked up by copying PBC's git log.
ChangeLog: 
	svn log > ChangeLog

# Maintain a pretty and effective make clean.
CLEANFILES = *~
maintainer-clean-local:
	-rm -rf Makefile.in ltmain.sh config.h.in configure \
	aclocal.m4 install-sh autom4te.cache


# Library.
lib_LTLIBRARIES = libfenc.la

# Includes.
include $(srcdir)/param

library_includedir = $(includedir)/fenc
library_include_HEADERS = libfenc_ABE_common.h \
libfenc_group_params.h \
libfenc.h \
libfenc_LSSS.h \
libfenc_LSW.h \
libfenc_utils.h \
libfenc_WatersCP.h \
libfenc_WatersSimpleCP.h \
abe_policy.h \
abe_policy.y \
sha1.h

libfenc_la_SOURCES = libfenc.c libfenc_LSW.c libfenc_WatersCP.c \
	libfenc_ABE_common.c libfenc_LSSS.c libfenc_WatersSimpleCP.c \
	libfenc_group_params.c libfenc_utils.c sha1.c abe_policy.tab.c

libfenc_la_LDFLAGS =  -lgmp -lpbc -lm -version-info $(SO_VERSION) $(FENC_LDFLAGS) $(LIBFENC_LDFLAGS)

libfenc_la_LIBS = -lstdc++

libfenc_la_AR = ar

libfenc_la_ARARGS = rcs

libfenc_la_BISON = bison

abe_policy.tab.c: abe_policy.y
	${libfenc_la_BISON} $<
