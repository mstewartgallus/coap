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

#include "coap/coap.h"
#include "coap/uri.h"
#include "coap/parse.h"

#include <arpa/inet.h>
#include <assert.h>
#include <endian.h>
#include <errno.h>
#include <ctype.h>
#include <inttypes.h>
#include <netdb.h>
#include <stdarg.h>
#include <stdbool.h>
#include <stdlib.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <sys/poll.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <unistd.h>

/* https://tools.ietf.org/html/rfc7252 */

struct request {
	char buf[1024U];
	uint_fast16_t message_id;
	uint_fast64_t token;
	size_t size;
	unsigned long transmission_counter;
	int timeout;
	bool acked;
};

#define ARRAY_SIZE(...) (sizeof __VA_ARGS__ / sizeof(__VA_ARGS__)[0U])

static struct coap_logger my_logger;

static unsigned long random_timeout_ms(struct coap_cfg const *cfg);
static int slurp_file(FILE *file, char **bufp, size_t *sizep);
static int connect_to_service(char const *service, char const *node,
                              int *sockfdp);

int main(int argc, char **argv)
{
	int error;

	bool print_help = false;
	bool bad_invocation = false;
	bool read_stdin = false;
	for (;;) {
		int opt = getopt(argc, argv, "hi");
		if (-1 == opt)
			break;

		switch (opt) {
		case 'h':
			print_help = true;
			break;

		case 'i':
			read_stdin = true;
			break;

		case '?':
		case ':':
			bad_invocation = true;
			break;
		}
	}

	if (bad_invocation) {
		fprintf(stderr, "Usage: %s [-hi] URI\n", argv[0U]);
		return EXIT_FAILURE;
	}

	if (print_help) {
		fprintf(stdout, "Usage: %s [-hi] URI\n", argv[0U]);
		return EXIT_SUCCESS;
	}

	struct coap_cfg const *mycfg = coap_cfg_default();

	size_t uris_count = argc - optind;
	if (uris_count != 1) {
		fprintf(stderr, "Usage: %s [-hi] URI\n", argv[0U]);
		return EXIT_FAILURE;
	}

	char const *uri = argv[optind];

	char *scheme_str;
	char *hier;
	char *query;
	char *fragment;
	{
		char *xx;
		char *yy;
		char *zz;
		char *ww;
		if (-1 == parse_uri(uri, &xx, &yy, &zz, &ww)) {
			perror("parse_uri");
			return EXIT_FAILURE;
		}
		scheme_str = xx;
		hier = yy;
		query = zz;
		fragment = ww;
	}

	if (fragment != 0)
		fprintf(stderr, "fragment `%s' not used yet\n",
		        fragment);

	uri_scheme scheme = uri_scheme_from_name(scheme_str);
	if (0 == scheme) {
		fprintf(stderr, "Unknown URI scheme: %s\n", scheme_str);
		return EXIT_FAILURE;
	}

	char *user_info;
	char *host;
	uint_fast16_t port;
	bool set_port;
	char *path;
	{
		char *xx;
		char *yy;
		uint_fast16_t zz;
		bool ww;
		char *uu;
		if (-1 == parse_http_like_hier(hier, &xx, &yy, &zz, &ww,
		                               &uu)) {
			perror("parse_http_hier");
			return EXIT_FAILURE;
		}
		user_info = xx;
		host = yy;
		port = zz;
		set_port = ww;
		path = uu;
	}

	if (user_info != 0) {
		fprintf(stderr, "User info is not supported\n");
		return EXIT_FAILURE;
	}

	char const *node = host;

	if (!set_port && scheme == URI_SCHEME_COAP) {
		port = 5683U;
		set_port = true;
	}

	char *port_str = 0;
	if (set_port) {
		char *xx;
		if (-1 ==
		    asprintf(&xx, "%" PRIu16, (uint_least16_t)port)) {
			perror("asprintf");
			return EXIT_FAILURE;
		}
		port_str = xx;
	} else {
		if (0 == (port_str = strdup(scheme_str))) {
			perror("strdup");
			return EXIT_FAILURE;
		}
	}

	char const *service = port_str;

	size_t stdin_size = 0U;
	char *stdin_buf = 0;
	if (read_stdin) {
		char *xx;
		size_t yy;
		int err = slurp_file(stdin, &xx, &yy);
		if (err != 0) {
			errno = err;
			perror("slurp_file");
			return EXIT_FAILURE;
		}
		stdin_buf = xx;
		stdin_size = yy;
	}

	int sockfd;
	{
		int xx;
		int err = connect_to_service(service, node, &xx);
		if (err != 0) {
			errno = err;
			perror("connect_to_service");
			return EXIT_FAILURE;
		}
		sockfd = xx;
	}

	{
		struct sockaddr_storage addr = {0};
		socklen_t addr_size = sizeof addr;
		if (-1 ==
		    getsockname(sockfd, (void *)&addr, &addr_size)) {
			perror("getsockname");
			return EXIT_FAILURE;
		}

		switch (addr.ss_family) {
		case AF_INET: {
			struct sockaddr_in *in_addr = (void *)&addr;
			uint_fast16_t my_port =
			    ntohs(in_addr->sin_port);

			char buf[INET_ADDRSTRLEN + 1U] = {0};
			inet_ntop(AF_INET, &in_addr->sin_addr, buf,
			          sizeof buf);
			fprintf(stdout,
			        "Connected as %s://%s:%" PRIu16 "\n",
			        scheme_str, buf,
			        (uint_least16_t)my_port);
			break;
		}

		case AF_INET6: {
			struct sockaddr_in6 *in6_addr = (void *)&addr;
			port = ntohs(in6_addr->sin6_port);

			char buf[INET6_ADDRSTRLEN + 1U] = {0};
			inet_ntop(AF_INET6, &in6_addr->sin6_addr, buf,
			          sizeof buf);
			fprintf(stdout,
			        "Connected as %s://[%s]:%" PRIu16 "\n",
			        scheme_str, buf, (uint_least16_t)port);
			break;
		}

		default:
			fprintf(stderr, "Unknown address family\n");
			break;
		}
	}

	{
		struct sockaddr_storage addr = {0};
		socklen_t addr_size = sizeof addr;
		if (-1 ==
		    getpeername(sockfd, (void *)&addr, &addr_size)) {
			perror("getpeername");
			return EXIT_FAILURE;
		}

		char real_service[25U] = {0};
		char real_host[256U] = {0};
		error = getnameinfo((void const *)&addr, sizeof addr,
		                    real_host, sizeof real_host,
		                    real_service, sizeof real_service,
		                    NI_NAMEREQD);
		if (error != 0) {
			if (EAI_SYSTEM == error) {
				perror("getnameinfo");
			} else {
				fprintf(stderr, "%s: getnameinfo: %s\n",
				        argv[0U], gai_strerror(error));
			}
			return EXIT_FAILURE;
		}

		fprintf(stderr, "service: %s, host: %s\n", real_service,
		        real_host);
	}

	/* Here we have now found the server we are connecting to. */

	static char recv_buf[1024U] = {0};

	struct request request = {0};

	{
		uint_fast16_t message_id = (uint_least16_t)random();
		uint_fast64_t token = (uint_fast64_t)random();

		coap_type message_type = COAP_TYPE_CONFIRMABLE;

		fprintf(stderr, "sending message id 0x%" PRIx16
		                " token 0x%" PRIx64 "\n",
		        (uint_least16_t)message_id,
		        (uint_least64_t)token);

		struct coap_encoder encoder = {0};

		coap_error err;
		err = coap_encode_start(
		    &encoder, (struct coap_logger *)&my_logger, 1U,
		    message_type, COAP_CODE_REQUEST_GET, message_id,
		    token, request.buf, sizeof request.buf);
		if (err != 0)
			goto coap_error;

		if (host != 0) {
			err = coap_encode_option_string(
			    &encoder, COAP_OPTION_TYPE_URI_HOST, host,
			    strlen(host));
			if (err != 0)
				goto coap_error;
		}

		err = coap_encode_option_uint(
		    &encoder, COAP_OPTION_TYPE_URI_PORT, port);
		if (err != 0)
			goto coap_error;

		if (path != 0) {
			err = coap_encode_option_string(
			    &encoder, COAP_OPTION_TYPE_URI_PATH, path,
			    strlen(path));
			if (err != 0)
				goto coap_error;
		}

		if (query != 0) {
			err = coap_encode_option_string(
			    &encoder, COAP_OPTION_TYPE_URI_QUERY, query,
			    strlen(query));
			if (err != 0)
				goto coap_error;
		}

		err = coap_encode_option_uint(
		    &encoder, COAP_OPTION_TYPE_ACCEPT,
		    COAP_CONTENT_FORMAT_APPLICATION_JSON);
		if (err != 0)
			goto coap_error;

		if (read_stdin) {
			err = coap_encode_payload(&encoder, stdin_buf,
			                          stdin_size);
			if (err != 0)
				goto coap_error;
		}

	coap_error:
		switch (err) {
		case 0:
			break;

		case COAP_ERROR_UNSUPPORTED_VERSION:
			fprintf(stderr, "unsupported version\n");
			return EXIT_FAILURE;

		case COAP_ERROR_BAD_PACKET:
			fprintf(stderr, "bad packet\n");
			return EXIT_FAILURE;

		case COAP_ERROR_BAD_OPTION:
			fprintf(stderr, "bad option\n");
			return EXIT_FAILURE;
		}

		request.message_id = message_id;
		request.token = token;
		request.timeout = random_timeout_ms(mycfg);
		request.transmission_counter = 0;
		request.size = encoder.buffer_index;

		if (-1 == send(sockfd, request.buf, request.size, 0)) {
			perror("send");
			return EXIT_FAILURE;
		}
	}

	for (;;) {
		{
			struct pollfd pollfds[] = {
			    {.fd = sockfd, .events = POLLIN}};
			int nfds =
			    poll(pollfds, ARRAY_SIZE(pollfds),
			         request.acked ? -1 : request.timeout);
			if (nfds < 0) {
				perror("poll");
				return EXIT_FAILURE;
			}
			if ((pollfds[0].revents & POLLERR) != 0) {
				int xx;
				socklen_t yy = sizeof xx;
				if (-1 == getsockopt(sockfd, SOL_SOCKET,
				                     SO_ERROR, &xx,
				                     &yy)) {
					perror("getsockopt");
					return EXIT_FAILURE;
				}
				errno = xx;
				perror("poll");
				return EXIT_FAILURE;
			}

			if ((pollfds[0].revents & POLLIN) != 0)
				goto recved_message;
		}

		if (-1 == send(sockfd, request.buf, request.size, 0)) {
			perror("send");
			return EXIT_FAILURE;
		}

		request.timeout *= 2;
		++request.transmission_counter;
		if (request.transmission_counter >
		    coap_cfg_max_retransmit(mycfg)) {
			fprintf(stderr, "message timeout\n");
			return EXIT_FAILURE;
		}
		continue;

	recved_message:
		;
		size_t message_size;
		{
			ssize_t xx =
			    recv(sockfd, recv_buf, sizeof recv_buf, 0);
			if (xx < 0) {
				perror("recv");
				return EXIT_FAILURE;
			}
			message_size = xx;
		}

		struct coap_decoder decoder = {0};
		{
			coap_error err = coap_header_decode_start(
			    &decoder, &my_logger, recv_buf,
			    message_size);
			switch (err) {
			case 0:
				break;

			case COAP_ERROR_UNSUPPORTED_VERSION:
				fprintf(stderr,
				        "unsupported version\n");
				return EXIT_FAILURE;

			case COAP_ERROR_BAD_PACKET:
				fprintf(stderr, "bad packet\n");
				return EXIT_FAILURE;

			case COAP_ERROR_BAD_OPTION:
				fprintf(stderr, "bad option\n");
				return EXIT_FAILURE;
			}
		}

		char const *type_str = coap_type_string(decoder.type);

		char const *details = coap_code_string(decoder.code);
		if (0 == details)
			details = "unknown request code detail";

		fprintf(stderr, "Received COAP request:\n");
		fprintf(stderr, "\t%s\n", type_str);
		fprintf(stderr, "\t%s\n", details);
		fprintf(stderr, "\tMessage Id: 0x%" PRIx16 "\n",
		        (uint_least16_t)decoder.message_id);
		fprintf(stderr, "\tToken: 0x%" PRIx64 "\n",
		        (uint_least64_t)decoder.token);

		if (request.message_id != decoder.message_id) {
			fprintf(stderr, "Bad message id ignoring!\n");
			continue;
		}

		if (request.token != decoder.token) {
			fprintf(stderr, "Bad token ignoring!\n");
			continue;
		}

		if (!request.acked &&
		    decoder.type != COAP_TYPE_ACKNOWLEDGEMENT) {
			fprintf(stderr, "Not an ack!\n");
			continue;
		}

		if (request.acked &&
		    decoder.type == COAP_TYPE_ACKNOWLEDGEMENT) {
			fprintf(stderr, "Is an ack!\n");
			continue;
		}

		uint_fast64_t content_format;
		bool content_format_set = false;

		for (;;) {
			coap_header_decode_option(&decoder);
			if (decoder.done)
				break;

			switch (decoder.option_type) {
			case COAP_OPTION_TYPE_CONTENT_FORMAT: {
				content_format = decoder.uint;
				content_format_set = true;

				char const *content_str =
				    coap_content_format_string(
				        content_format);
				if (0 == content_str) {
					fprintf(
					    stderr,
					    "\tContent-Format: %" PRIu64
					    "\n",
					    content_format);
				} else {
					fprintf(
					    stderr,
					    "\tContent-Format: %s\n",
					    content_str);
				}
				break;
			}
			}
		}
		fprintf(stderr, "\n");

		request.acked = true;
		if (!decoder.has_payload)
			continue;

		fprintf(stderr, "%s\n",
		        strndup(recv_buf + decoder.header_size,
		                message_size - decoder.header_size));

		if (!content_format_set) {
			fprintf(stderr, "\tContent-Format not set\n");
		}
		if (content_format !=
		    COAP_CONTENT_FORMAT_APPLICATION_JSON) {
			fprintf(stderr, "\tUnknown content format\n");
		}

		break;
	}

	if (-1 == shutdown(sockfd, SHUT_RDWR)) {
		perror("shutdown");
		return EXIT_FAILURE;
	}

	if (-1 == close(sockfd)) {
		perror("close");
		return EXIT_FAILURE;
	}

	return EXIT_SUCCESS;
}

static unsigned long random_timeout_ms(struct coap_cfg const *cfg)
{
	unsigned long bottom = coap_cfg_ack_timeout_ms(cfg);
	unsigned long top =
	    (coap_cfg_ack_timeout_ms(cfg) *
	     coap_cfg_ack_random_factor_numerator(cfg)) /
	    coap_cfg_ack_random_factor_denominator(cfg);

	/* This is not a perfectly uniform distribution but it is good
	 * enough */

	return random() % (top - bottom) + bottom;
}

static int slurp_file(FILE *file, char **bufp, size_t *sizep)
{
	size_t buf_size = 1024U;
	size_t bytes_read = 0;

	int err = 0;

	char *buf = malloc(buf_size);
	if (0 == buf) {
		return errno;
	}

	flockfile(file);
	for (;;) {
		size_t bytes_to_read = buf_size - bytes_read;
		size_t read_bytes =
		    fread_unlocked(buf, 1U, bytes_to_read, file);

		if (ferror_unlocked(file)) {
			return errno;
		}
		bytes_read += read_bytes;
		if (read_bytes < bytes_to_read) {
			break;
		}
		char *new_ptr = realloc(buf, 2 * buf_size);
		if (new_ptr != 0) {
			err = errno;
			free(buf);
			return err;
		}
		buf = new_ptr;
		buf_size = 2 * buf_size;
	}
	funlockfile(file);

	if (0 == freopen("/dev/null", "rw", file)) {
		err = errno;
		free(buf);
		return err;
	}

	*bufp = buf;
	*sizep = bytes_read;

	return 0;
}

static int connect_to_service(char const *service, char const *node,
                              int *sockfdp)
{
	int err = 0;

	struct addrinfo *addrinfo_head;
	{
		struct addrinfo *xx;
		struct addrinfo hints = {0};

		hints.ai_flags = AI_CANONNAME;
		hints.ai_family = PF_UNSPEC;
		hints.ai_socktype = SOCK_DGRAM;

		bool has_ip6_addr = false;
		char buf[INET6_ADDRSTRLEN + 1U] = {0};
		if (node[0U] == '[') {
			strncpy(buf, node + 1U, sizeof buf);
			*strchr(buf, ']') = '\0';
			hints.ai_flags |= AI_NUMERICHOST;
			has_ip6_addr = true;
		}

		int error = getaddrinfo(has_ip6_addr ? buf : node,
		                        service, &hints, &xx);
		if (error != 0) {
			if (EAI_SYSTEM == error) {
				return errno;
			} else {
				return ENOSYS;
			}
		}
		addrinfo_head = xx;
	}

	int sockfd = -1;

	struct addrinfo *aip;
	for (aip = addrinfo_head; aip != 0; aip = aip->ai_next) {
		sockfd = socket(aip->ai_family,
		                aip->ai_socktype | SOCK_CLOEXEC,
		                aip->ai_protocol);
		if (sockfd < 0) {
			err = errno;
			switch (err) {
			case EAFNOSUPPORT:
			case EPROTONOSUPPORT:
				if (aip->ai_next != 0) {
					err = 0;
					continue;
				}

				goto free_addr_info;

			default:
				goto free_addr_info;
			}
		}

		{
			int xx = 1;
			if (-1 == setsockopt(sockfd, SOL_SOCKET,
			                     SO_REUSEADDR, &xx,
			                     sizeof xx)) {
				err = errno;
				if (aip->ai_next != 0)
					err = 0;
				goto close_sock;
			}
		}

		if (-1 ==
		    connect(sockfd, aip->ai_addr, aip->ai_addrlen)) {
			err = errno;

			if (aip->ai_next != 0)
				err = 0;

			goto close_sock;
		}
		break;

	close_sock:
		close(sockfd);
		if (err != 0)
			break;
		continue;
	}

free_addr_info:
	freeaddrinfo(addrinfo_head);

	if (0 == err) {
		*sockfdp = sockfd;
	}

	return err;
}

static void my_log(struct coap_logger *logger, char const *format, ...);
static struct coap_logger my_logger = {.log = my_log};

static void my_log(struct coap_logger *logger, char const *format, ...)
{
	va_list ap;
	va_start(ap, format);
	vfprintf(stderr, format, ap);
	fprintf(stderr, "\n");
	va_end(ap);
}
