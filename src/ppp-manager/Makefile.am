if WITH_PPP

AM_CPPFLAGS = \
	-I${top_srcdir}/shared \
	-I${top_builddir}/shared \
	-I${top_srcdir}/libnm-core \
	-I${top_srcdir}/src \
	-I${top_builddir}/libnm-core \
	-DG_LOG_DOMAIN=\""nm-pppd-plugin"\" \
	-DNETWORKMANAGER_COMPILATION=NM_NETWORKMANAGER_COMPILATION_INSIDE_DAEMON \
	$(GLIB_CFLAGS)

pppd_plugindir = $(PPPD_PLUGIN_DIR)
pppd_plugin_LTLIBRARIES = nm-pppd-plugin.la

nm_pppd_plugin_la_SOURCES = \
	nm-pppd-plugin.c \
	nm-pppd-plugin.h \
	nm-ppp-status.h

nm_pppd_plugin_la_LDFLAGS = -module -avoid-version

nm_pppd_plugin_la_LIBADD = \
	$(GLIB_LIBS) \
	$(DL_LIBS) \
	$(NULL)

endif
