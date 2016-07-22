# This file is free software; as a special exception the author gives
# unlimited permission to copy and/or distribute it, with or without
# modifications, as long as this notice is preserved.
#
# This program is distributed in the hope that it will be useful, but
# WITHOUT ANY WARRANTY, to the extent permitted by law; without even
# the implied warranty of MERCHANTABILITY or FITNESS FOR A PARTICULAR
# PURPOSE.
AM_CFLAGS=
AM_CPPFLAGS=
AM_LDFLAGS=

bin_PROGRAMS=
noinst_LTLIBRARIES=

AM_CPPFLAGS+=\
  -I$(srcdir)/include
AM_CFLAGS+=\
  $(coap_CFLAGS_WARNINGS)
AM_LDFLAGS+=\
  $$(for II in \
  -pthread $(coap_LDFLAGS_WARNINGS); do echo -Xcompiler "$$II"; done)

bin_PROGRAMS+=%D%/src/server/server
%C%_src_server_server_SOURCES=\
  %D%/src/server/main.c
%C%_src_server_server_LDADD=\
  src/coap/libcoap.la\
  src/parse/libparse.la\
  src/uri/liburi.la

bin_PROGRAMS+=%D%/src/client/client
%C%_src_client_client_SOURCES=\
  %D%/src/client/main.c
%C%_src_client_client_LDADD=\
  src/coap/libcoap.la\
  src/parse/libparse.la\
  src/uri/liburi.la

bin_PROGRAMS+=%D%/src/ping/ping
%C%_src_ping_ping_SOURCES=\
  %D%/src/ping/main.c
%C%_src_ping_ping_LDADD=\
  src/coap/libcoap.la\
  src/parse/libparse.la\
  src/uri/liburi.la

noinst_LTLIBRARIES+=%D%/src/coap/libcoap.la
%C%_src_coap_libcoap_la_SOURCES=%D%/src/coap/coap.c include/coap/coap.h

noinst_LTLIBRARIES+=%D%/src/parse/libparse.la
%C%_src_parse_libparse_la_SOURCES=%D%/src/parse/parse.c include/coap/parse.h

noinst_LTLIBRARIES+=%D%/src/uri/liburi.la
%C%_src_uri_liburi_la_SOURCES=%D%/src/uri/uri.c include/coap/uri.h

indent:
	find $(srcdir)/src $(srcdir)/include -type f -name '*.[ch]' -exec \
	  clang-format-3.6 -style=file -i '{}' '+'
