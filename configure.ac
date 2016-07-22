dnl Process this file with autoconf to produce a configure script.
dnl
dnl This file is free software; as a special exception the author gives
dnl unlimited permission to copy and/or distribute it, with or without
dnl modifications, as long as this notice is preserved.
dnl
dnl This program is distributed in the hope that it will be useful, but
dnl WITHOUT ANY WARRANTY, to the extent permitted by law; without even the
dnl implied warranty of MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.
dnl
AC_INIT([Coap], [0.0], [sstewartgallus00@mylangara.bc.ca],,
                  [https://gitlab.com/linted/coap])
dnl
dnl Other software uses a shell command to get the date but that
dnl prevents deterministic builds.
AC_DEFINE([COPYRIGHT_YEAR], ["2016"], [year in copyright message])
AC_DEFINE([PACKAGE_NAME_SPACE], ["com.gitlab.linted.coap"],
                               [package hierarchical name space])
dnl
AC_CONFIG_AUX_DIR([build-aux])
AM_INIT_AUTOMAKE([subdir-objects -Wall foreign])
AC_CONFIG_HEADER([config.h])
dnl
AC_PREREQ([2.62])
AC_CONFIG_SRCDIR([src/server/main.c])
dnl
AS_IF([test "x${CFLAGS}" = "x"], [
  [CFLAGS='']
])
dnl
AC_CANONICAL_HOST
AS_IF([test "x${cross_compiling}" = "xno"], [
        AC_MSG_WARN([dnl
[Native and cross builds do not result in the exact same binaries.]
[Explicitly set the --host and --build options and do not use native builds.]dnl
])
])
dnl
AC_PROG_CC
dnl
AM_PROG_AR
dnl
dnl We only use static convenience libraries anyway
LT_INIT([disable-shared])
dnl
AC_SYS_LARGEFILE
AC_C_INLINE
dnl
COAP_WARNINGS
dnl
AC_CONFIG_MACRO_DIR([m4])
AC_CONFIG_FILES([Makefile])
dnl
AC_OUTPUT
