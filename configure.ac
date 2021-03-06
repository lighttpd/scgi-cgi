#                                               -*- Autoconf -*-
# Process this file with autoconf to produce a configure script.

AC_PREREQ([2.63])
AC_INIT([scgi-cgi], [0.1.1], [lighttpd@stbuehler.de])
AC_CONFIG_SRCDIR([scgi-cgi.c])
AC_CONFIG_HEADERS([config.h])

AM_INIT_AUTOMAKE([-Wall -Werror foreign])

# Checks for programs.
AC_PROG_CC
AC_PROG_MAKE_SET

# Checks for libraries.

# libevent
PKG_CHECK_MODULES(LIBEVENT, libevent >= 2.0, [],[AC_MSG_ERROR("libevent >= 2.0 not found")])

# Checks for header files.
AC_CHECK_HEADERS([arpa/inet.h fcntl.h stdlib.h string.h sys/socket.h unistd.h])

# Checks for typedefs, structures, and compiler characteristics.
AC_TYPE_PID_T
AC_TYPE_SIZE_T

# Checks for library functions.
AC_FUNC_FORK
AC_CHECK_FUNCS([dup2])

# check for extra compiler options (warning options)
if test "${GCC}" = "yes"; then
    CFLAGS="${CFLAGS} -Wall -W -Wshadow -pedantic -std=gnu99"
fi

AC_ARG_ENABLE([extra-warnings],
 [AS_HELP_STRING([--enable-extra-warnings],[enable extra warnings (gcc specific)])],
 [case "${enableval}" in
   yes) extrawarnings=true ;;
    no) extrawarnings=false ;;
     *) AC_MSG_ERROR([bad value ${enableval} for --enable-extra-warnings]) ;;
  esac],[extrawarnings=false])

if test x$extrawarnings = xtrue; then
    CFLAGS="${CFLAGS} -g -O2 -g2 -Wall -Wmissing-declarations -Wdeclaration-after-statement -Wcast-align -Wsign-compare -Wnested-externs -Wpointer-arith -Wmissing-prototypes -Wshadow -Wno-pointer-sign -Wformat-security -Wl,--as-needed -Wl,--no-undefined"
fi

AC_CONFIG_FILES([Makefile])
AC_OUTPUT
