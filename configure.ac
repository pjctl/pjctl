AC_PREREQ([2.64])

AC_INIT([pjctl],
        [1],
        [benjaminfranzke@googlemail.com],
        [pjctl],
        [https://github.com/pjctl/pjctl/])

AC_CONFIG_HEADERS([config.h])
AC_CONFIG_MACRO_DIR([m4])

AM_INIT_AUTOMAKE([foreign dist-bzip2])

m4_ifdef([AM_SILENT_RULES], [AM_SILENT_RULES([yes])])

# Check for programs
AC_PROG_CC

PKG_PROG_PKG_CONFIG()
PKG_CHECK_MODULES(crypto, [libcrypto])

if test "x$GCC" = "xyes"; then
	GCC_CFLAGS="-Wall -g -Wstrict-prototypes -Wmissing-prototypes -fvisibility=hidden"
fi
AC_SUBST([GCC_CFLAGS])

AC_CONFIG_FILES([Makefile
		 src/Makefile])
AC_OUTPUT
