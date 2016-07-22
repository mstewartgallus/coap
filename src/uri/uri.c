/*
 * Copyright 2016 Steven Stewart-Gallus
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or
 * implied.  See the License for the specific language governing
 * permissions and limitations under the License.
 */
#include "coap/uri.h"

#include <string.h>
#include <sys/types.h>

#define ARRAY_SIZE(...) (sizeof __VA_ARGS__ / sizeof(__VA_ARGS__)[0U])

struct uri_scheme_pair {
	char const *scheme_str;
	uri_scheme scheme;
};

uri_scheme uri_scheme_from_name(char const *name)
{
	static struct uri_scheme_pair const uri_schemes[] = {
	    {"coap", URI_SCHEME_COAP},
	    {"coaps", URI_SCHEME_COAPS},
	    {"file", URI_SCHEME_FILE},
	    {"ftp", URI_SCHEME_FTP},
	    {"http", URI_SCHEME_HTTP},
	    {"https", URI_SCHEME_HTTPS}};

	for (size_t ii = 0U; ii < ARRAY_SIZE(uri_schemes); ++ii) {
		char const *str = uri_schemes[ii].scheme_str;
		uri_scheme scheme = uri_schemes[ii].scheme;
		if (0 == strcmp(str, name))
			return scheme;
	}

	return 0;
}
