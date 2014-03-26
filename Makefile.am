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
	src/clock-monotonic-coarse.c \
	src/clock-monotonic.c \
	src/clock-realtime-coarse.c \
	src/clock-realtime.c \
	src/getcpu.c \
	src/gettimeofday.c \
	src/util.c \
	src/vdsotest.c
vdsotest_LDADD = -lrt
