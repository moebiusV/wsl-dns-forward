# SPDX-License-Identifier: ISC
sbin_PROGRAMS = wsl-dns-forward
wsl_dns_forward_SOURCES = main.c dns.c dns.h

AM_CPPFLAGS = $(FORTIFY_CPPFLAGS) -DPKGDATADIR='"$(pkgdatadir)"' -DLOCALSTATEDIR='"$(localstatedir)"'
AM_CFLAGS = $(WARN_CFLAGS) $(HARDEN_CFLAGS) $(SAN_CFLAGS)
AM_LDFLAGS = $(HARDEN_LDFLAGS) $(SAN_CFLAGS)

dist_pkgdata_DATA = mdns-helper.ps1
dist_man_MANS = wsl-dns-forward.8

# Expanded here, not by configure, so ${exec_prefix} is already resolved.
wsl-dns-forward.service: wsl-dns-forward.service.in Makefile
	$(AM_V_GEN)sed -e 's|@WMF_SBINDIR@|$(sbindir)|g' $(srcdir)/wsl-dns-forward.service.in > $@
CLEANFILES = wsl-dns-forward.service

if HAVE_SYSTEMD_UNIT
systemdunit_DATA = wsl-dns-forward.service
systemdunitdir = $(systemdunitpath)
endif

# ---- tests ----
check_PROGRAMS = test_dns fakeup replay_query replay_relay replay_helper
test_dns_SOURCES = tests/test_dns.c dns.c dns.h
fakeup_SOURCES = tests/fakeup.c dns.c dns.h
replay_query_SOURCES = fuzz/fuzz_query.c fuzz/replay.c dns.c dns.h
replay_relay_SOURCES = fuzz/fuzz_relay.c fuzz/replay.c dns.c dns.h
replay_helper_SOURCES = fuzz/fuzz_helper.c fuzz/replay.c dns.c dns.h

TESTS = test_dns tests/corpus.sh tests/helper-size.sh tests/check.sh
TESTS_ENVIRONMENT = WMF_BIN=$(abs_builddir)/wsl-dns-forward FAKEUP=$(abs_builddir)/fakeup \
	REPLAY_DIR=$(abs_builddir) CORPUS_DIR=$(abs_srcdir)/fuzz/corpus; export WMF_BIN FAKEUP REPLAY_DIR CORPUS_DIR;

# Re-run the whole suite under valgrind (memory errors, leaks, leaked file descriptors).
check-valgrind: all $(check_PROGRAMS)
	$(MAKE) check TESTS="tests/corpus.sh tests/check.sh" WMF_WRAP=valgrind

if ENABLE_FUZZERS
noinst_PROGRAMS = fuzz_query fuzz_relay fuzz_helper
fuzz_query_SOURCES = fuzz/fuzz_query.c dns.c dns.h
fuzz_relay_SOURCES = fuzz/fuzz_relay.c dns.c dns.h
fuzz_helper_SOURCES = fuzz/fuzz_helper.c dns.c dns.h
fuzz_query_CFLAGS = $(FUZZ_CFLAGS)
fuzz_relay_CFLAGS = $(FUZZ_CFLAGS)
fuzz_helper_CFLAGS = $(FUZZ_CFLAGS)
fuzz_query_LDFLAGS = $(FUZZ_CFLAGS)
fuzz_relay_LDFLAGS = $(FUZZ_CFLAGS)
fuzz_helper_LDFLAGS = $(FUZZ_CFLAGS)
endif

EXTRA_DIST = README.md README.distributions tests/check.sh tests/corpus.sh tests/fake-helper.sh tests/helper-size.sh \
	fuzz/corpus packaging wsl-dns-forward.service.in

.PHONY: check-valgrind
