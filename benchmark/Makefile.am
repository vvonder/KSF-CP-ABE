#
#
# LIBFENC -- The Functional Encryption Library
#
#-------------------------------------------------------------------------------------------

SUBDIRS = .

CLEANFILES = *~
maintainer-clean-local:
	-rm -rf Makefile.in
	
# Link libs.
AM_LDFLAGS = -lgmp -lpbc
AM_CPPFLAGS = -I/usr/local/include -I/usr/include -I../
LDADD = ../libfenc.la

# Doesn't install to */bin
noinst_PROGRAMS = benchmark

benchmark_SOURCES = benchmark.c base64.c base64.h \
 		    common.c common.h

