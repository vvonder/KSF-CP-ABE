#
#
# LIBFENC -- The Functional Encryption Library
#
#-------------------------------------------------------------------------------------------

# Have configure setup a Makefile in a subdirectory.
SUBDIRS = .

# Maintain a pretty and effective make clean.
CLEANFILES = *~
maintainer-clean-local:
	-rm -rf Makefile.in
	
# Link in those libraries. Can't use -lfenc yet.
AM_LDFLAGS = -lgmp -lpbc -lcrypto
AM_CPPFLAGS = -I/usr/local/include -I/usr/include -I../
LDADD = ../libfenc.la

bin_PROGRAMS = abe-setup abe-keygen abe-enc abe-dec policy-test abe-ukeygen ksf-keygen ksf-trapdoor ksf-search abe-qdec

abe_setup_SOURCES = mgabe-setup.c base64.c base64.h \
		    common.c common.h
abe_keygen_SOURCES = mgabe-keygen.c base64.c common.c
abe_enc_SOURCES = mgabe-enc.c base64.c common.c
abe_dec_SOURCES = mgabe-dec.c base64.c common.c
policy_test_SOURCES = policy-tool.c common.c
abe_ukeygen_SOURCES = ksfcpabe-ukeygen.c base64.c common.c
ksf_keygen_SOURCES = ksfcpabe-ksfkeygen.c base64.c common.c
ksf_trapdoor_SOURCES = ksfcpabe-trapdoor.c base64.c common.c
ksf_search_SOURCES = ksfcpabe-search.c base64.c common.c
abe_qdec_SOURCES = ksfcpabe-qdec.c base64.c common.c

abe_setup_CFLAGS = $(AM_CFLAGS)
abe_keygen_CFLAGS = $(AM_CFLAGS)
abe_enc_CFLAGS = $(AM_CFLAGS)
abe_dec_CFLAGS = $(AM_CFLAGS)
policy_test_CFLAGS = $(AM_CFLAGS)
abe_ukeygen_CFLAGS = $(AM_CFLAGS)
ksf_keygen_CFLAGS = $(AM_CFLAGS)
ksf_trapdoor_CFLAGS = $(AM_CFLAGS)
ksf_search_CFLAGS = $(AM_CFLAGS)
abe_qdec_CFLAGS = $(AM_CFLAGS)

lib_LTLIBRARIES = libabe-setup.la libabe-keygen.la libabe-enc.la libabe-dec.la libpolicy-test.la libabe-ukeygen.la libksf-keygen.la libksf-trapdoor.la libksf-search.la libabe-qdec.la

libabe_setup_la_SOURCES = mgabe-setup.c base64.c base64.h \
		    common.c common.h
libabe_keygen_la_SOURCES = mgabe-keygen.c base64.c common.c
libabe_enc_la_SOURCES = mgabe-enc.c base64.c common.c
libabe_dec_la_SOURCES = mgabe-dec.c base64.c common.c
libpolicy_test_la_SOURCES = policy-tool.c common.c
libabe_ukeygen_la_SOURCES = ksfcpabe-ukeygen.c base64.c common.c
libksf_keygen_la_SOURCES = ksfcpabe-ksfkeygen.c base64.c common.c
libksf_trapdoor_la_SOURCES = ksfcpabe-trapdoor.c base64.c common.c
libksf_search_la_SOURCES = ksfcpabe-search.c base64.c common.c
libabe_qdec_la_SOURCES = ksfcpabe-qdec.c base64.c common.c

libabe_setup_la_LIBADD = ../libfenc.la
libabe_keygen_la_LIBADD = ../libfenc.la
libabe_enc_la_LIBADD = ../libfenc.la
libabe_dec_la_LIBADD = ../libfenc.la
libpolicy_test_la_LIBADD = ../libfenc.la
libabe_ukeygen_la_LIBADD = ../libfenc.la
libksf_keygen_la_LIBADD = ../libfenc.la
libksf_trapdoor_la_LIBADD = ../libfenc.la
libksf_search_la_LIBADD = ../libfenc.la
libabe_qdec_la_LIBADD = ../libfenc.la

COMMON_LDFLAGS = -no-undefined
libabe_setup_la_LDFLAGS = $(COMMON_LDFLAGS)
libabe_keygen_la_LDFLAGS = $(COMMON_LDFLAGS)
libabe_enc_la_LDFLAGS = $(COMMON_LDFLAGS)
libabe_dec_la_LDFLAGS = $(COMMON_LDFLAGS)
libpolicy_test_la_LDFLAGS = $(COMMON_LDFLAGS)
libabe_ukeygen_la_LDFLAGS = $(COMMON_LDFLAGS)
libksf_keygen_la_LDFLAGS = $(COMMON_LDFLAGS)
libksf_trapdoor_la_LDFLAGS = $(COMMON_LDFLAGS)
libksf_search_la_LDFLAGS = $(COMMON_LDFLAGS)
libabe_qdec_la_LDFLAGS = $(COMMON_LDFLAGS)
