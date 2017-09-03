dnl Process this file with autoconf to produce a configure script
AC_INIT([osmo-mgw],
	m4_esyscmd([./git-version-gen .tarball-version]),
	[openbsc@lists.osmocom.org])

dnl *This* is the root dir, even if an install-sh exists in ../ or ../../
AC_CONFIG_AUX_DIR([.])

AM_INIT_AUTOMAKE([dist-bzip2])
AC_CONFIG_TESTDIR(tests)

dnl kernel style compile messages
m4_ifdef([AM_SILENT_RULES], [AM_SILENT_RULES([yes])])

dnl include release helper
RELMAKE='-include osmo-release.mk'
AC_SUBST([RELMAKE])

dnl checks for programs
AC_PROG_MAKE_SET
AC_PROG_CC
AC_PROG_INSTALL
LT_INIT

dnl check for pkg-config (explained in detail in libosmocore/configure.ac)
AC_PATH_PROG(PKG_CONFIG_INSTALLED, pkg-config, no)
if test "x$PKG_CONFIG_INSTALLED" = "xno"; then
        AC_MSG_WARN([You need to install pkg-config])
fi
PKG_PROG_PKG_CONFIG([0.20])

dnl check for AX_CHECK_COMPILE_FLAG
m4_ifdef([AX_CHECK_COMPILE_FLAG], [], [
	AC_MSG_ERROR([Please install autoconf-archive; re-run 'autoreconf -fi' for it to take effect.])
	])

dnl checks for libraries
AC_SEARCH_LIBS([dlopen], [dl dld], [LIBRARY_DL="$LIBS";LIBS=""])
AC_SUBST(LIBRARY_DL)


PKG_CHECK_MODULES(LIBOSMOCORE, libosmocore >= 0.9.5)
PKG_CHECK_MODULES(LIBOSMOVTY, libosmovty >= 0.3.0)
PKG_CHECK_MODULES(LIBOSMONETIF, libosmo-netif >= 0.0.1)

# Enable/disable transcoding within osmo-bsc_mgcp?
AC_ARG_ENABLE([mgcp-transcoding], [AS_HELP_STRING([--enable-mgcp-transcoding], [Build the MGCP gateway with internal transcoding enabled.])],
    [osmo_ac_mgcp_transcoding="$enableval"],[osmo_ac_mgcp_transcoding="no"])
AC_ARG_WITH([g729], [AS_HELP_STRING([--with-g729], [Enable G.729 encoding/decoding.])], [osmo_ac_with_g729="$withval"],[osmo_ac_with_g729="no"])

if test "$osmo_ac_mgcp_transcoding" = "yes" ; then
    AC_SEARCH_LIBS([gsm_create], [gsm], [LIBRARY_GSM="$LIBS";LIBS=""], [AC_MSG_ERROR([--enable-mgcp-transcoding: cannot find usable libgsm])])
    AC_SUBST(LIBRARY_GSM)
    if test "$osmo_ac_with_g729" = "yes" ; then
	PKG_CHECK_MODULES(LIBBCG729, libbcg729 >= 0.1, [AC_DEFINE([HAVE_BCG729], [1], [Use bgc729 decoder/encoder])])
    fi
    AC_DEFINE(BUILD_MGCP_TRANSCODING, 1, [Define if we want to build the MGCP gateway with transcoding support])
fi
AM_CONDITIONAL(BUILD_MGCP_TRANSCODING, test "x$osmo_ac_mgcp_transcoding" = "xyes")
AC_SUBST(osmo_ac_mgcp_transcoding)

dnl Checks for typedefs, structures and compiler characteristics

# The following test is taken from WebKit's webkit.m4
saved_CFLAGS="$CFLAGS"
CFLAGS="$CFLAGS -fvisibility=hidden "
AC_MSG_CHECKING([if ${CC} supports -fvisibility=hidden])
AC_COMPILE_IFELSE([AC_LANG_SOURCE([char foo;])],
      [ AC_MSG_RESULT([yes])
        SYMBOL_VISIBILITY="-fvisibility=hidden"],
        AC_MSG_RESULT([no]))
CFLAGS="$saved_CFLAGS"
AC_SUBST(SYMBOL_VISIBILITY)

AX_CHECK_COMPILE_FLAG([-Werror=implicit], [CFLAGS="$CFLAGS -Werror=implicit"])
AX_CHECK_COMPILE_FLAG([-Werror=maybe-uninitialized], [CFLAGS="$CFLAGS -Werror=maybe-uninitialized"])
AX_CHECK_COMPILE_FLAG([-Werror=memset-transposed-args], [CFLAGS="$CFLAGS -Werror=memset-transposed-args"])
AX_CHECK_COMPILE_FLAG([-Werror=null-dereference], [CFLAGS="$CFLAGS -Werror=null-dereference"])
AX_CHECK_COMPILE_FLAG([-Werror=sizeof-array-argument], [CFLAGS="$CFLAGS -Werror=sizeof-array-argument"])
AX_CHECK_COMPILE_FLAG([-Werror=sizeof-pointer-memaccess], [CFLAGS="$CFLAGS -Werror=sizeof-pointer-memaccess"])

# Coverage build taken from WebKit's configure.in
AC_MSG_CHECKING([whether to enable code coverage support])
AC_ARG_ENABLE(coverage,
              AC_HELP_STRING([--enable-coverage],
                             [enable code coverage support [default=no]]),
              [],[enable_coverage="no"])
AC_MSG_RESULT([$enable_coverage])
if test "$enable_coverage" = "yes"; then
   COVERAGE_CFLAGS="-ftest-coverage -fprofile-arcs"
   COVERAGE_LDFLAGS="-ftest-coverage -fprofile-arcs"
   AC_SUBST([COVERAGE_CFLAGS])
   AC_SUBST([COVERAGE_LDFLAGS])
fi

AC_ARG_ENABLE([vty_tests],
		AC_HELP_STRING([--enable-vty-tests],
				[Include the VTY/CTRL tests in make check (deprecated)
				[default=no]]),
		[enable_ext_tests="$enableval"],[enable_ext_tests="no"])
AC_ARG_ENABLE([external_tests],
		AC_HELP_STRING([--enable-external-tests],
				[Include the VTY/CTRL tests in make check [default=no]]),
		[enable_ext_tests="$enableval"],[enable_ext_tests="no"])
if test "x$enable_ext_tests" = "xyes" ; then
	AM_PATH_PYTHON
	AC_CHECK_PROG(OSMOTESTEXT_CHECK,osmotestvty.py,yes)
	 if test "x$OSMOTESTEXT_CHECK" != "xyes" ; then
		AC_MSG_ERROR([Please install git://osmocom.org/python/osmo-python-tests to run the VTY/CTRL tests.])
	fi
fi
AC_MSG_CHECKING([whether to enable VTY/CTRL tests])
AC_MSG_RESULT([$enable_ext_tests])
AM_CONDITIONAL(ENABLE_EXT_TESTS, test "x$enable_ext_tests" = "xyes")

dnl Generate the output
AM_CONFIG_HEADER(bscconfig.h)

AC_OUTPUT(
    libosmo-legacy-mgcp.pc
    libosmo-mgcp-client.pc
    include/Makefile
    include/osmocom/Makefile
    include/osmocom/legacy_mgcp/Makefile
    include/osmocom/mgcp_client/Makefile
    src/Makefile
    src/libosmo-legacy-mgcp/Makefile
    src/libosmo-mgcp-client/Makefile
    src/osmo-bsc_mgcp/Makefile
    tests/Makefile
    tests/atlocal
    tests/legacy_mgcp/Makefile
    tests/mgcp_client/Makefile
    doc/Makefile
    doc/examples/Makefile
    contrib/Makefile
    Makefile)
