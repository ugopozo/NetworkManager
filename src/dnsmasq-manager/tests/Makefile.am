AM_CPPFLAGS = \
	-I$(top_srcdir)/shared \
	-I${top_builddir}/shared \
	-I${top_srcdir}/libnm-core \
	-I${top_builddir}/libnm-core \
	-I$(top_srcdir)/src/dnsmasq-manager \
	-I$(top_srcdir)/src \
	-I$(top_srcdir)/src/platform \
	-DG_LOG_DOMAIN=\""NetworkManager"\" \
	-DNETWORKMANAGER_COMPILATION=NM_NETWORKMANAGER_COMPILATION_INSIDE_DAEMON \
	$(GLIB_CFLAGS) \
	-DTESTDIR="\"$(abs_srcdir)\""

noinst_PROGRAMS = test-dnsmasq-utils

test_dnsmasq_utils_SOURCES = \
	test-dnsmasq-utils.c

test_dnsmasq_utils_LDADD = \
	$(top_builddir)/src/libNetworkManager.la

@VALGRIND_RULES@
TESTS = test-dnsmasq-utils

