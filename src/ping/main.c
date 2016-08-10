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

#define ARRAY_SIZE(...) (sizeof __VA_ARGS__ / sizeof(__VA_ARGS__)[0U])

static struct coap_logger my_logger;

struct config {
	unsigned long ack_timeout_ns;
	unsigned long ack_random_factor_numerator;
	unsigned long ack_random_factor_demoninator;
	unsigned long nstart;
	unsigned long default_leisure_ns;
	unsigned long probing_rate;
	uint_least8_t max_retransmit;
};

static struct config const *default_config(void)
{
	static struct config const default_config = {
	    .ack_timeout_ns = 2U * 10000000U,
	    .ack_random_factor_numerator = 3,
	    .ack_random_factor_demoninator = 2,
	    .max_retransmit = 4U,
	    .nstart = 1U,
	    .default_leisure_ns = 5U * 10000000U,
	    .probing_rate = 1U};
	return &default_config;
}

static unsigned long ack_timeout_ms(struct config const *config)
{
	return config->ack_timeout_ns / 100000;
}

static unsigned long
ack_random_factor_numerator(struct config const *config)
{
	return config->ack_random_factor_numerator;
}

static unsigned long
ack_random_factor_denominator(struct config const *config)
{
	return config->ack_random_factor_demoninator;
}

static uint_fast8_t max_retransmit(struct config const *config)
{
	return config->max_retransmit;
}

static unsigned long random_timeout_ms(struct config const *config)
{
	unsigned long bottom = ack_timeout_ms(config);
	unsigned long top = (ack_timeout_ms(config) *
	                     ack_random_factor_numerator(config)) /
	                    ack_random_factor_denominator(config);

	/* This is not a perfectly uniform distribution but it is good
	 * enough */

	return random() % (top - bottom) + bottom;
}

int main(int argc, char **argv)
{
	int sockfd;
	int error;

	bool print_help = false;
	bool bad_invocation = false;
	for (;;) {
		int opt = getopt(argc, argv, "h");
		if (-1 == opt)
			break;

		switch (opt) {
		case 'h':
			print_help = true;
			break;

		case '?':
		case ':':
			bad_invocation = true;
			break;
		}
	}

	if (bad_invocation) {
		fprintf(stderr, "Usage: %s [-h] URI\n", argv[0U]);
		return EXIT_FAILURE;
	}

	if (print_help) {
		fprintf(stdout, "Usage: %s [-h] URI\n", argv[0U]);
		return EXIT_SUCCESS;
	}

	size_t uris_count = argc - optind;
	if (uris_count != 1) {
		fprintf(stderr, "Usage: %s [-h] URI\n", argv[0U]);
		return EXIT_FAILURE;
	}

	char const *uri = argv[1U];

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

	struct addrinfo *addrinfo_head;
	{
		struct addrinfo *xx;
		struct addrinfo hints = {0};

		hints.ai_flags = AI_CANONNAME;
		hints.ai_family = PF_UNSPEC;
		hints.ai_socktype = SOCK_DGRAM;

		bool has_ip6_addr = false;
		char buf[INET6_ADDRSTRLEN + 1U] = {0};
		if (host[0U] == '[') {
			strncpy(buf, host + 1U, sizeof buf);
			*strchr(buf, ']') = '\0';
			hints.ai_flags |= AI_NUMERICHOST;
			has_ip6_addr = true;
		}

		error = getaddrinfo(has_ip6_addr ? buf : node, service,
		                    &hints, &xx);
		if (error != 0) {
			if (EAI_SYSTEM == error) {
				perror("getaddrinfo");
			} else {
				fprintf(stderr, "%s: getaddrinfo: %s\n",
				        argv[0U], gai_strerror(error));
			}
			return EXIT_FAILURE;
		}
		addrinfo_head = xx;
	}

	struct addrinfo *aip;
	for (aip = addrinfo_head; aip != 0; aip = aip->ai_next) {
		sockfd = socket(aip->ai_family,
		                aip->ai_socktype | SOCK_CLOEXEC,
		                aip->ai_protocol);
		if (sockfd < 0) {
			switch (errno) {
			case EAFNOSUPPORT:
			case EPROTONOSUPPORT:
				if (aip->ai_next != 0)
					continue;

				perror("socket");
				return EXIT_FAILURE;

			default:
				perror("socket");
				return EXIT_FAILURE;
			}
		}

		{
			int xx = 1;
			if (-1 == setsockopt(sockfd, SOL_SOCKET,
			                     SO_REUSEADDR, &xx,
			                     sizeof xx)) {
				if (aip->ai_next != 0)
					goto close_sock;
				perror("setsockopt");
				return EXIT_FAILURE;
			}
		}

		if (-1 ==
		    connect(sockfd, aip->ai_addr, aip->ai_addrlen)) {
			if (aip->ai_next != 0)
				goto close_sock;

			perror("connect");
			return EXIT_FAILURE;
		}
		goto got_socket;

	close_sock:
		close(sockfd);
		continue;
	}
	fprintf(stderr, "%s: no connectable address found\n", argv[0U]);
	return EXIT_FAILURE;

got_socket:
	freeaddrinfo(addrinfo_head);

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

	uint_fast16_t ping_message_id = random() % UINT16_MAX;

	char message[4U] = {0};
	coap_empty_packet(COAP_TYPE_CONFIRMABLE, ping_message_id,
	                  message);
	size_t encoded_size = COAP_EMPTY_PACKET_SIZE;

	if (-1 == send(sockfd, message, encoded_size, 0)) {
		perror("send");
		return EXIT_FAILURE;
	}

	{
		int timeout = random_timeout_ms(default_config());
		unsigned long transmission_counter = 0U;
		for (;;) {
			struct pollfd pollfds[] = {
			    {.fd = sockfd, .events = POLLIN}};
			int nfds =
			    poll(pollfds, ARRAY_SIZE(pollfds), timeout);
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
				break;

			timeout *= 2;
			++transmission_counter;
			if (transmission_counter >
			    max_retransmit(default_config())) {
				fprintf(stderr, "message timeout\n");
				return EXIT_FAILURE;
			}

			if (-1 ==
			    send(sockfd, message, encoded_size, 0)) {
				perror("send");
				return EXIT_FAILURE;
			}
		}
	}

	static char buf[4U] = {0};

	size_t message_size;
	{
		ssize_t xx = recv(sockfd, buf, sizeof buf, 0);
		if (xx < 0) {
			perror("recv");
			return EXIT_FAILURE;
		}
		message_size = xx;
	}

	struct coap_decoder decoder = {0};
	coap_error err = coap_header_decode_start(&decoder, &my_logger,
	                                          buf, message_size);
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

	if (decoder.type != COAP_TYPE_ACKNOWLEDGEMENT) {
		fprintf(stderr, "bad type\n");
		return EXIT_FAILURE;
	}

	if (decoder.message_id != ping_message_id) {
		fprintf(stderr, "bad message id\n");
		return EXIT_FAILURE;
	}

	char const *type_str = coap_type_string(decoder.type);

	char const *details = coap_code_string(decoder.code);
	if (0 == details)
		details = "unknown response code detail";

	fprintf(stderr, "Received COAP response:\n");
	fprintf(stderr, "\t%s\n", type_str);
	fprintf(stderr, "\t%s\n", details);
	fprintf(stderr, "\tMessage Id: 0x%" PRIx16 "\n",
	        (uint_least16_t)decoder.message_id);
	fprintf(stderr, "\tToken: 0x%" PRIx64 "\n",
	        (uint_least64_t)decoder.token);

	for (;;) {
		coap_header_decode_option(&decoder);
		if (decoder.done)
			break;
	}
	fprintf(stderr, "\n");

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
