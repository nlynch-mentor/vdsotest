EXTRA_DIST =
CLEANFILES =
ACLOCAL_AMFLAGS = -I m4 ${ACLOCAL_FLAGS}
AM_MAKEFLAGS = --no-print-directory

AM_CPPFLAGS = \
	-include $(top_builddir)/config.h \
	-DSYSCONFDIR=\""$(sysconfdir)"\" \
	-DLIBEXECDIR=\""$(libexecdir)"\" \
	-I${top_srcdir}/src

AM_CFLAGS = ${my_CFLAGS} \
	-ffunction-sections \
	-fdata-sections

AM_LDFLAGS = \
	-Wl,--gc-sections \
	-Wl,--as-needed

bin_PROGRAMS = vdsotest
vdsotest_SOURCES = \
	src/clock-monotonic.c \
	src/clock-monotonic-coarse.c \
	src/clock-realtime.c \
	src/clock-realtime-coarse.c \
	src/compiler.h \
	src/getcpu.c \
	src/gettimeofday.c \
	src/util.c \
	src/util.h \
	src/vdsotest.c \
	src/vdsotest.h

vdsotest_LDADD = -lrt -ldl

bin_SCRIPTS = vdsotest-all

CLEANFILES += $(bin_SCRIPTS)

do_subst = sed -e 's,[@]vdsotest[@],$(bindir)/vdsotest,g'

vdsotest-all: src/vdsotest-all.in Makefile
	$(do_subst) < $(srcdir)/src/vdsotest-all.in > vdsotest-all
	chmod +x vdsotest-all

EXTRA_DIST += \
	src/clock_getres_template.c \
	src/clock_gettime_template.c \
	src/vdsotest-all.in
