dnl -*-Autoconf-*-
dnl This file is free software; as a special exception the author gives
dnl unlimited permission to copy and/or distribute it, with or without
dnl modifications, as long as this notice is preserved.
dnl
dnl This program is distributed in the hope that it will be useful, but
dnl WITHOUT ANY WARRANTY, to the extent permitted by law; without even the
dnl implied warranty of MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.
dnl
dnl Autodetects compiler warnings
AC_DEFUN([COAP_WARNINGS],[
COAP_CHECK_CFLAGS([coap_CFLAGS_WARNINGS],[
        [-Werror=unknown-warning-option]dnl
dnl
        [-Wall]dnl
        [-Wextra]dnl
dnl
        [-Wstack-usage=900]dnl
dnl
        [-Wdate-time]dnl Reproducible builds are GOOD
dnl
        [-Woverflow]dnl
        [-Wformat=2]dnl
        [-Wunused] [-Wno-unused-parameter]dnl
        [-Wshadow]dnl
        [-Wunreachable-code]dnl
        [-Wstrict-prototypes]dnl
        [-Wmissing-prototypes]dnl
        [-Wmissing-declarations]dnl
        [-Wold-style-definition]dnl
        [-Wlogical-op]dnl
        [-Wstrict-aliasing=3]dnl
        [-Wstrict-overflow=5]dnl
        [-Wtrampolines]dnl We force a nonexecutable stack so for most
                       dnl targets would generate broken code if we
                       dnl used trampolines.
dnl
dnl     Make the = { 0 } idiom not cause warnings
        [-Wno-missing-field-initializers]dnl
        [-Wno-missing-braces]dnl
])
AC_SUBST([coap_CFLAGS_WARNINGS])
dnl
COAP_CHECK_LDFLAGS([coap_LDFLAGS_WARNINGS],[
        [-Wl,--warn-common]dnl
        [-Wl,--warn-execstack]dnl
        [-Wl,--warn-search-mismatch]dnl
        [-Wl,--warn-shared-textrel]dnl
        [-Wl,--no-undefined]dnl
        [-Wl,--no-allow-shlib-undefined]dnl
])
AC_SUBST([coap_LDFLAGS_WARNINGS])
])
