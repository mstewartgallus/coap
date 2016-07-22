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
#define _GNU_SOURCE

#include "coap/parse.h"

#include <ctype.h>
#include <errno.h>
#include <stdbool.h>
#include <stdlib.h>
#include <string.h>

#include <stdio.h>

static size_t find_special(char const *c);

int parse_http_like_hier(char const *hier, char **user_infop,
                         char **hostp, uint_fast16_t *portp,
                         bool *set_portp, char **pathp)
{
	if (0 != strncmp(hier, "//", 2U)) {
		errno = EINVAL;
		return -1;
	}

	char const *mark = hier + 2U;

	char const *user_info_start = 0;
	char const *user_info_end = 0;

	char const *host_start = 0;
	{
		size_t ii = find_special(mark);
		switch (mark[ii]) {
		case '@':
			user_info_start = mark;
			user_info_end = mark + ii;
			host_start = mark + ii + 1U;
			break;

		case '[':
		case '.':
		case '/':
		case ':':
		case '\0':
			host_start = mark;
			break;

		default:
			errno = EINVAL;
			return -1;
		}
	}

	char const *host_end;
	if ('[' == host_start[0U]) {
		host_end = strchr(host_start, ']');
		if (0 == host_end) {
			errno = EINVAL;
			return -1;
		}
	} else {
		size_t ii = find_special(host_start);
		switch (host_start[ii]) {
		case ':':
		case '/':
		case '\0':
			host_end = host_start + ii;
			break;

		default:
			errno = EINVAL;
			return -1;
		}
	}
	mark = host_end;

	char const *port_start = 0;
	char const *port_end = 0;
	if (':' == mark[0U]) {
		port_start = mark + 1U;
		size_t ii = find_special(port_start);
		switch (port_start[ii]) {
		case '/':
		case '\0':
			port_end = port_start + ii;
			break;

		default:
			errno = EINVAL;
			return -1;
		}
		mark = port_end;
	}

	char const *path_start = 0;
	if ('/' == mark[0U]) {
		path_start = mark + 1U;

		size_t ii = find_special(path_start);
		switch (path_start[ii]) {
		case '\0':
			break;

		default:
			errno = EINVAL;
			return -1;
		}
	}

	long port_value = 0;

	if (port_start != 0) {
		char first_char = port_start[0U];
		switch (first_char) {
		case '+':
		case '-':
			errno = EINVAL;
			return -1;
		}
		if (isspace(first_char)) {
			errno = EINVAL;
			return -1;
		}

		errno = 0;
		char *xx;
		port_value = strtol(port_start, &xx, 10);
		if (errno != 0)
			return -1;

		if (xx != port_end) {
			errno = EINVAL;
			return -1;
		}

		if (port_value < 0) {
			errno = ERANGE;
			return -1;
		}

		if (port_value >= UINT16_MAX) {
			errno = ERANGE;
			return -1;
		}
	}

	char *host = strndup(host_start, host_end - host_start);
	if (0 == host)
		return -1;

	char *path = 0;
	char *user_info = 0;

	if (user_info_start != 0) {
		user_info = strndup(user_info_start,
		                    user_info_end - user_info_start);
		if (0 == user_info)
			goto free_host;
	}

	if (path_start != 0) {
		path = strdup(path_start);
		if (0 == path)
			goto free_user_info;
	}

	*user_infop = user_info;
	*hostp = host;
	*set_portp = port_start != 0;
	*portp = port_value;
	*pathp = path;

	return 0;

free_user_info : {
	int err = errno;
	free(user_info);
	errno = err;
}

free_host : {
	int err = errno;
	free(host);
	errno = err;
}
	return -1;
}

int parse_uri(char const *uri, char **schemep, char **hierp,
              char **queryp, char **fragmentp)
{
	char const *scheme_start = uri;
	char const *scheme_end = 0;
	{
		size_t ii = find_special(uri);
		switch (uri[ii]) {
		case ':':
			scheme_end = uri + ii;
			break;

		default:
			errno = EINVAL;
			return -1;
		}
	}

	char const *hier_start = scheme_end + 1U;
	char const *hier_end = 0;
	{
		size_t ii = 0U;
		for (;;) {
			ii += find_special(hier_start + ii);
			switch (hier_start[ii]) {
			case '.':
			case '/':
			case ':':
				++ii;
				continue;

			case '?':
			case '#':
			case '\0':
				hier_end = hier_start + ii;
				break;

			default:
				errno = EINVAL;
				return -1;
			}
			break;
		}
	}

	char const *mark = hier_end;

	char const *query_start = 0;
	char const *query_end = 0;
	if ('?' == mark[0U]) {
		query_start = mark + 1U;

		size_t ii = 0U;
		for (;;) {
			ii += find_special(query_start + ii);
			switch (query_start[ii]) {
			case '=':
			case ';':
			case '&':
				++ii;
				continue;

			case '#':
			case '\0':
				query_end = query_start + ii;
				break;

			default:
				errno = EINVAL;
				return -1;
			}
			break;
		}

		mark = query_end;
	}

	char const *fragment_start = 0;
	if ('#' == mark[0U]) {
		fragment_start = mark + 1U;

		size_t ii = find_special(fragment_start);
		switch (fragment_start[ii]) {
		case '\0':
			break;

		default:
			errno = EINVAL;
			return -1;
		}
	}

	char *scheme = strndup(uri, scheme_end - scheme_start);
	if (0 == scheme)
		return -1;

	char *hier = strndup(hier_start, hier_end - hier_start);
	if (0 == hier)
		goto free_scheme;

	char *query = 0;
	if (query_start != 0) {
		query = strndup(query_start, query_end - query_start);
		if (0 == query)
			goto free_hier;
	}

	char *fragment = 0;
	if (fragment_start != 0) {
		fragment = strdup(fragment_start);
		if (0 == fragment)
			goto free_query;
	}

	*schemep = scheme;
	*hierp = hier;
	*fragmentp = fragment;
	*queryp = query;
	return 0;

free_query : {
	int err = errno;
	free(query);
	errno = err;
}

free_hier : {
	int err = errno;
	free(hier);
	errno = err;
}

free_scheme : {
	int err = errno;
	free(scheme);
	errno = err;
}

	return -1;
}

static size_t find_special(char const *str)
{
	size_t size = strlen(str);
	size_t ii = 0U;
	for (; ii < size; ++ii) {
		char c = str[ii];

		if (!(('a' <= c && c <= 'z') ||
		      ('A' <= c && c <= 'Z') ||
		      ('0' <= c && c <= '9') || '-' == c || '.' == c ||
		      '_' == c || '~' == c))
			break;
	}
	return ii;
}
