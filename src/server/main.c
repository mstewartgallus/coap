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
#include "coap/parse.h"
#include "coap/uri.h"

#include <assert.h>
#include <arpa/inet.h>
#include <errno.h>
#include <fcntl.h>
#include <ctype.h>
#include <inttypes.h>
#include <netdb.h>
#include <poll.h>
#include <stdarg.h>
#include <stdbool.h>
#include <stdlib.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <ucontext.h>
#include <unistd.h>

#define ARRAY_SIZE(...) (sizeof __VA_ARGS__ / sizeof(__VA_ARGS__)[0U])

typedef struct {
	char dummy;
} continuation;

enum { STATE_POLLIN,
       STATE_PROCESS_POLLIN,
       STATE_RECV,
       STATE_SENDING,
       STATE_PROCESS_POLLOUT,
};
typedef unsigned char state;

struct server {
	ucontext_t poll_context;
	bool fail;
};

struct listener {
	ucontext_t context;
	struct server *server;

	char *recv_buffer;
	char *send_buffer;

	struct coap_logger *logger;

	char const *scheme_str;
	char const *service;
	char const *node;
	uint_least16_t port;

	struct sockaddr_storage from_addr;
	bool do_fail;
	bool do_poll;
	struct pollfd *pollfd;
	size_t send_size;

	int sockfd;

	int socket_error;
};

static short sock_poll(struct listener *listener, int fd, short flags);
static void sock_fail(struct listener *listener, int err);

static void process_sockfd(struct listener *listener);

static void my_log(struct coap_logger *logger, char const *format, ...);

union my_logger {
	struct coap_logger *logger;
	struct {
		struct coap_logger logger;
		FILE *file;
	} data;
};

#define DEFAULT_MESSAGE_SIZE 1152U
#define DEFAULT_PAYLOAD_SIZE 1024U

#define RECV_BUFFER_SIZE 1152U
#define SEND_BUFFER_SIZE 1152U

int main(int argc, char **argv)
{
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
		fprintf(stderr, "Usage: %s [-h] URI...\n", argv[0U]);
		return EXIT_FAILURE;
	}

	if (print_help) {
		fprintf(stderr, "Usage: %s [-h] URI...\n", argv[0U]);
		return EXIT_SUCCESS;
	}

	/* Set up basic stuff */
	if (0 == freopen("/dev/null", "rw", stdout)) {
		perror("freopen");
		return EXIT_FAILURE;
	}

	size_t uris_count = argc - optind;
	if (0U == uris_count)
		return EXIT_SUCCESS;

	if (uris_count > 1U) {
		fprintf(stderr,
		        "multiple URIs temporarily unimplemented\n");
		return EXIT_FAILURE;
	}

	struct listener *listeners =
	    calloc(uris_count, sizeof listeners[0U]);
	if (0 == listeners) {
		perror("calloc");
		return EXIT_FAILURE;
	}

	struct pollfd *pollfds = calloc(uris_count, sizeof pollfds[0U]);
	if (0 == pollfds) {
		perror("calloc");
		return EXIT_FAILURE;
	}

	union my_logger my_logger = {
	    .data = {.logger = {.log = my_log}, .file = stderr}};

	for (size_t ii = 0U; ii < uris_count; ++ii) {
		char const *uri = argv[optind + ii];

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
		if (query != 0) {
			fprintf(stderr, "Query attached\n");
			return EXIT_FAILURE;
		}
		if (fragment != 0) {
			fprintf(stderr, "Fragment attached\n");
			return EXIT_FAILURE;
		}

		uri_scheme scheme = uri_scheme_from_name(scheme_str);
		if (0 == scheme) {
			fprintf(stderr, "Unknown URI scheme: %s\n",
			        scheme_str);
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
			uint_fast16_t zz = 0U;
			bool ww;
			char *uu;
			if (-1 == parse_http_like_hier(hier, &xx, &yy,
			                               &zz, &ww, &uu)) {
				perror("parse_http_like_hier");
				return EXIT_FAILURE;
			}
			user_info = xx;
			host = yy;
			port = zz;
			set_port = ww;
			path = uu;
		}

		if (user_info != 0) {
			fprintf(stderr, "User info attached\n");
			return EXIT_FAILURE;
		}

		if (path != 0) {
			fprintf(stderr, "Path attached\n");
			return EXIT_FAILURE;
		}

		if (host[0U] == '[') {
			fprintf(stderr,
			        "IP literals are not supported as host "
			        "names yet\n");
			return EXIT_FAILURE;
		}

		if (!set_port && URI_SCHEME_COAP == scheme) {
			port = 5683U;
			set_port = true;
		}

		char const *node = host;

		char *port_str = 0;
		if (set_port) {
			char *xx;
			if (-1 == asprintf(&xx, "%" PRIu16,
			                   (uint_least16_t)port)) {
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

		listeners[ii].logger =
		    (struct coap_logger *)&my_logger.logger;
		listeners[ii].scheme_str = scheme_str;
		listeners[ii].node = node;
		listeners[ii].service = port_str;
		listeners[ii].port = port;
	}

	for (size_t ii = 0U; ii < uris_count; ++ii) {
		struct listener *listener = &listeners[ii];

		char const *scheme_str = listener->scheme_str;
		char const *service = listener->service;
		char const *node = listener->node;
		uint_fast16_t port = listener->port;

		struct addrinfo *addrinfo_head;
		{
			struct addrinfo *xx;
			struct addrinfo hints = {0};

			hints.ai_flags = AI_PASSIVE | AI_CANONNAME;
			hints.ai_family = AF_UNSPEC;
			hints.ai_socktype = SOCK_DGRAM;

			error = getaddrinfo(node, service, &hints, &xx);
			if (error != 0) {
				if (EAI_SYSTEM == error) {
					perror("getaddrinfo");
				} else {
					fprintf(stderr,
					        "%s: getaddrinfo: %s\n",
					        argv[0U],
					        gai_strerror(error));
				}
				return EXIT_FAILURE;
			}
			addrinfo_head = xx;
		}

		int sockfd;
		struct addrinfo *aip;
		for (aip = addrinfo_head; aip != 0;
		     aip = aip->ai_next) {
			sa_family_t family = aip->ai_family;
			sockfd = socket(family, aip->ai_socktype |
			                            SOCK_CLOEXEC |
			                            SOCK_NONBLOCK,
			                aip->ai_protocol);
			if (sockfd < 0) {
				switch (errno) {
				case EAFNOSUPPORT:
				case EPROTONOSUPPORT:
					if (aip->ai_next)
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

			switch (family) {
			case AF_INET: {
				int xx = 1;
				if (-1 == setsockopt(sockfd, IPPROTO_IP,
				                     IP_FREEBIND, &xx,
				                     sizeof xx)) {
					if (aip->ai_next != 0)
						goto close_sock;
					perror("setsockopt");
					return EXIT_FAILURE;
				}
			} break;

			case AF_INET6:
				break;

			default:
				goto close_sock;
			}

			if (-1 == bind(sockfd, aip->ai_addr,
			               aip->ai_addrlen)) {
				if (aip->ai_next)
					goto close_sock;
				perror("bind");
				return EXIT_FAILURE;
			}
			goto got_socket;

		close_sock:
			close(sockfd);
			continue;
		}

		fprintf(stderr, "%s: no bindable address found\n",
		        argv[0U]);
		return EXIT_FAILURE;

		{
		got_socket:
			;
			struct sockaddr_storage addr = {0};
			socklen_t addr_size = sizeof addr;
			if (-1 == getsockname(sockfd, (void *)&addr,
			                      &addr_size)) {
				perror("getsockname");
				return EXIT_FAILURE;
			}
			switch (addr.ss_family) {
			case AF_INET: {
				port =
				    ntohs(((struct sockaddr_in *)&addr)
				              ->sin_port);
				fprintf(stdout,
				        "Bound as %s://%s:%" PRIu16
				        "\n",
				        scheme_str, aip->ai_canonname,
				        (uint_least16_t)port);
				break;
			}

			case AF_INET6: {
				port =
				    ntohs(((struct sockaddr_in6 *)&addr)
				              ->sin6_port);
				fprintf(stdout,
				        "Bound as %s://%s:%" PRIu16
				        "\n",
				        scheme_str, aip->ai_canonname,
				        (uint_least16_t)port);
				break;
			}

			default:
				fprintf(stderr,
				        "Unknown address family\n");
				break;
			}
		}

		freeaddrinfo(addrinfo_head);

		listener->sockfd = sockfd;
	}

	for (size_t ii = 0U; ii < uris_count; ++ii) {
		struct listener *listener = &listeners[ii];

		char *recv_buffer = calloc(RECV_BUFFER_SIZE, 1U);
		if (0 == recv_buffer) {
			perror("calloc");
			return EXIT_FAILURE;
		}

		char *send_buffer = calloc(SEND_BUFFER_SIZE, 1U);
		if (0 == send_buffer) {
			perror("calloc");
			return EXIT_FAILURE;
		}

		listener->recv_buffer = recv_buffer;
		listener->send_buffer = send_buffer;
	}

	for (size_t ii = 0U; ii < uris_count; ++ii) {
		pollfds[ii].fd = listeners[ii].sockfd;
		pollfds[ii].events = POLLIN;
	}

	for (size_t ii = 0U; ii < uris_count; ++ii) {
		listeners[ii].pollfd = &pollfds[ii];
	}

	static struct server server = {0};

	for (size_t ii = 0U; ii < uris_count; ++ii) {

		void *stack = mmap(0, 20U * sysconf(_SC_PAGE_SIZE),
		                   PROT_READ | PROT_WRITE,
		                   MAP_PRIVATE | MAP_ANONYMOUS |
		                       MAP_GROWSDOWN | MAP_STACK,
		                   -1, 0);
		;
		if (MAP_FAILED == stack) {
			perror("mmap");
			return EXIT_FAILURE;
		}

		listeners[ii].server = &server;
		memset(&listeners[ii].context, 0,
		       sizeof listeners[ii].context);
		getcontext(&listeners[ii].context);
		listeners[ii].context.uc_stack.ss_sp = stack;
		listeners[ii].context.uc_stack.ss_size =
		    20U * sysconf(_SC_PAGE_SIZE);

		makecontext(&listeners[ii].context,
		            (void (*)(void))process_sockfd, 1,
		            &listeners[ii]);
	}

	for (;;) {
		int nfds = poll(pollfds, uris_count, -1);
		if (nfds < 0) {
			error = errno;
			if (EINTR == error)
				continue;
			if (ENOMEM == error)
				continue;

			perror("poll");
			return EXIT_FAILURE;
		}

		for (size_t ii = 0U; ii < uris_count; ++ii) {
			if (0 == pollfds[ii].revents)
				continue;

			listeners[ii].do_poll = false;
			for (;;) {
				swapcontext(&server.poll_context,
				            &listeners[ii].context);
				if (listeners[ii].do_poll)
					break;
			}

			--nfds;
			if (0 == nfds)
				break;
		}
	}

	int exit_status = EXIT_SUCCESS;
	for (size_t ii = 0U; ii < uris_count; ++ii) {
		struct listener *listener = &listeners[ii];

		int sockfd = listener->sockfd;

		if (-1 == shutdown(sockfd, SHUT_RDWR)) {
			perror("shutdown");
			exit_status = EXIT_FAILURE;
		}

		if (-1 == close(sockfd)) {
			perror("close");
			exit_status = EXIT_FAILURE;
		}
	}

	return exit_status;
}

enum { RESPONSE_ERROR,

       RESPONSE_EMPTY,
       RESPONSE_SUCCESS,
};
typedef unsigned char response;

static void process_sockfd(struct listener *listener)
{
	int error = 0;

	char *recv_buffer = listener->recv_buffer;
	char *send_buffer = listener->send_buffer;

	struct coap_logger *logger = listener->logger;
	char const *scheme_str = listener->scheme_str;
	int sockfd = listener->sockfd;

	uint_fast64_t acceptable_format = 0;
	bool acceptable_format_set = false;
	struct sockaddr_storage *from_addr = &listener->from_addr;

	for (;;) {
		short revents = sock_poll(listener, sockfd, POLLIN);
		if (0 == (revents & POLLIN))
			continue;

		size_t message_size;
		{
			socklen_t xx = sizeof *from_addr;

			ssize_t maybe_message_size =
			    recvfrom(sockfd, recv_buffer,
			             RECV_BUFFER_SIZE, MSG_DONTWAIT,
			             (struct sockaddr *)from_addr, &xx);

			if (maybe_message_size < 0) {
				error = errno;
				if (EINTR == error) {
					error = 0;
					continue;
				}
				if (EAGAIN == error) {
					error = 0;
					continue;
				}
				sock_fail(listener, errno);
			}
			message_size = maybe_message_size;
			if (0U == message_size)
				continue;
		}

		switch (from_addr->ss_family) {
		case AF_INET: {
			struct sockaddr_in *in_addr = (void *)from_addr;
			in_port_t from_port = in_addr->sin_port;

			char ip_buf[INET_ADDRSTRLEN] = {0};

			inet_ntop(AF_INET, &in_addr->sin_addr, ip_buf,
			          sizeof ip_buf);
			fprintf(stderr, "Received message from "
			                "%s://%s:%" PRIu16 "\n",
			        scheme_str, ip_buf, ntohs(from_port));
			break;
		}

		case AF_INET6: {
			struct sockaddr_in6 *in_addr =
			    (void *)from_addr;
			in_port_t from_port = in_addr->sin6_port;

			char ip_buf[INET6_ADDRSTRLEN] = {0};

			inet_ntop(AF_INET6, &in_addr->sin6_addr, ip_buf,
			          sizeof ip_buf);
			fprintf(stderr, "Received message from "
			                "%s://[%s]:%" PRIu16 "\n",
			        scheme_str, ip_buf, ntohs(from_port));
			break;
		}

		default:
			fprintf(stderr, "Received message from unknown "
			                "address family\n");
			break;
		}

		struct coap_decoder decoder = {0};

		coap_code response_code;
		{
			coap_error err = coap_header_decode_start(
			    &decoder, logger, recv_buffer,
			    message_size);
			switch (err) {
			case 0:
				break;

			case COAP_ERROR_UNSUPPORTED_VERSION:
				response_code =
				    COAP_CODE_RESPONSE_CLIENT_ERROR_BAD_REQUEST;
				goto setup_response;

			case COAP_ERROR_BAD_PACKET:
				response_code =
				    COAP_CODE_RESPONSE_CLIENT_ERROR_BAD_REQUEST;
				goto setup_response;

			case COAP_ERROR_BAD_OPTION:
				response_code =
				    COAP_CODE_RESPONSE_CLIENT_ERROR_BAD_OPTION;
				goto setup_response;
			}

			switch (decoder.code) {
			case COAP_CODE_EMPTY:
			case COAP_CODE_REQUEST_GET:
				break;

			default:
				response_code =
				    COAP_CODE_RESPONSE_CLIENT_ERROR_METHOD_NOT_FOUND;
				goto setup_response;
			}

			char const *type_str =
			    coap_type_string(decoder.type);
			char const *request_str =
			    coap_code_string(decoder.code);

			fprintf(stderr, "Received COAP request:\n");
			fprintf(stderr, "\t%s\n", type_str);
			fprintf(stderr, "\t%s\n", request_str);
			fprintf(stderr, "\tMessage Id: 0x%" PRIx16 "\n",
			        (uint_least16_t)decoder.message_id);
			fprintf(stderr, "\tToken: 0x%" PRIx64 "\n",
			        (uint_least64_t)decoder.token);

			for (;;) {
				char buf[255U + 1U] = {0};

				coap_header_decode_option(&decoder);
				if (decoder.done)
					break;

				switch (decoder.option_type) {
				case COAP_OPTION_TYPE_CONTENT_FORMAT:
					fprintf(stderr,
					        "\tContent-Format: "
					        "0x%" PRIx64 "\n",
					        (uint_least64_t)
					            decoder.uint);
					break;

				case COAP_OPTION_TYPE_URI_PATH:
					memcpy(buf, decoder.str.str,
					       decoder.str.size);
					fprintf(stderr,
					        "\tUri-Path: %s\n",
					        buf);
					break;

				case COAP_OPTION_TYPE_URI_HOST:
					memcpy(buf, decoder.str.str,
					       decoder.str.size);
					fprintf(stderr,
					        "\tUri-Host: %s\n",
					        buf);
					break;

				case COAP_OPTION_TYPE_URI_PORT:
					fprintf(stderr, "\tUri-Port: "
					                "%" PRIu64 "\n",
					        (uint_least64_t)
					            decoder.uint);
					break;

				case COAP_OPTION_TYPE_URI_QUERY:
					memcpy(buf, decoder.str.str,
					       decoder.str.size);
					fprintf(stderr,
					        "\tUri-Query: %s\n",
					        buf);
					break;

				case COAP_OPTION_TYPE_ACCEPT: {
					acceptable_format =
					    decoder.uint;
					acceptable_format_set = true;

					char const *str =
					    coap_content_format_string(
					        acceptable_format);
					if (0 == str) {
						fprintf(
						    stderr,
						    "\tAccept: "
						    "%" PRIu64 "\n",
						    (uint_least64_t)
						        acceptable_format);
					} else {
						fprintf(
						    stderr,
						    "\tAccept: %s\n",
						    str);
					}
					break;
				}
				}
			}
		}

		/* Just ignore these */
		if (decoder.type != COAP_TYPE_CONFIRMABLE) {
			response_code =
			    COAP_CODE_RESPONSE_CLIENT_ERROR_BAD_REQUEST;
			goto setup_response;
		}

		if (decoder.has_payload) {
			for (size_t ii = decoder.message_index;
			     ii < decoder.message_size; ++ii) {
				fputc(recv_buffer[ii], stderr);
			}
			fputc('\n', stderr);
		}
		fprintf(stderr, "\n");

		size_t encoded_size = 0U;

		if (COAP_CODE_EMPTY == decoder.code) {
			coap_error err;
			size_t header_size;
			{
				size_t xx = 0U;
				err = coap_header_encode(
				    logger, &xx, 1U,
				    COAP_TYPE_ACKNOWLEDGEMENT,
				    COAP_CODE_EMPTY, decoder.message_id,
				    0, 0, 0U, true, send_buffer,
				    SEND_BUFFER_SIZE);
				header_size = xx;
			}
			assert(err != COAP_ERROR_UNSUPPORTED_VERSION);
			assert(err != COAP_ERROR_BAD_PACKET);
			assert(err != COAP_ERROR_BAD_OPTION);
			assert(0 == err);

			encoded_size = header_size;
			goto send;
		}

		response_code = COAP_CODE_RESPONSE_SUCCESS_CONTENT;

		if (acceptable_format !=
		    COAP_CONTENT_FORMAT_APPLICATION_JSON) {
			response_code =
			    COAP_CODE_RESPONSE_CLIENT_ERROR_UNSUPPORTED_CONTENT_FORMAT;
			goto setup_response;
		}

	setup_response:
		;
		coap_type type;
		switch (response_code) {
		case COAP_CODE_RESPONSE_CLIENT_ERROR_BAD_REQUEST:
			type = COAP_TYPE_RESET;
			break;

		case COAP_CODE_RESPONSE_CLIENT_ERROR_BAD_OPTION:
			type = COAP_TYPE_RESET;
			break;

		case COAP_CODE_RESPONSE_CLIENT_ERROR_METHOD_NOT_FOUND:
			type = COAP_TYPE_RESET;
			break;

		case COAP_CODE_EMPTY:
			type = COAP_TYPE_RESET;
			break;

		case COAP_CODE_RESPONSE_SUCCESS_CONTENT:
			type = COAP_TYPE_ACKNOWLEDGEMENT;
			break;
		}

		{
			static struct coap_option const options[] = {
			    {.type = COAP_OPTION_TYPE_CONTENT_FORMAT,
			     .value = {
			         .uint =
			             COAP_CONTENT_FORMAT_APPLICATION_JSON}}};

			coap_error err;
			size_t header_size;
			{
				size_t xx = 0U;
				err = coap_header_encode(
				    logger, &xx, 1U,
				    COAP_TYPE_ACKNOWLEDGEMENT,
				    response_code, decoder.message_id,
				    decoder.token, options,
				    ARRAY_SIZE(options), true,
				    send_buffer, SEND_BUFFER_SIZE);
				header_size = xx;
			}
			assert(err != COAP_ERROR_UNSUPPORTED_VERSION);
			assert(err != COAP_ERROR_BAD_PACKET);
			assert(err != COAP_ERROR_BAD_OPTION);
			assert(0 == err);

			encoded_size = header_size;

			if (response_code != COAP_CODE_EMPTY) {
				/* Dummy payload */
				static char const payload[] =
				    "{ 'hello' : 'world' }";

				encoded_size += sizeof payload - 1U;

				assert(encoded_size <=
				       SEND_BUFFER_SIZE);

				memcpy(send_buffer + encoded_size -
				           sizeof payload + 1U,
				       payload, sizeof payload - 1U);
			}
		}
	send:
		for (;;) {
			if (sendto(sockfd, send_buffer, encoded_size,
			           MSG_DONTWAIT | MSG_NOSIGNAL,
			           (void *)from_addr,
			           sizeof *from_addr) != -1) {
				break;
			}

			error = errno;

			if (ENOMEM == error) {
				error = 0;
			}

			if (EAGAIN == error || EWOULDBLOCK == error) {
				error = 0;
			}

			if (error != 0) {
				perror("sendto");
				sock_fail(listener, errno);
			}

			short rflags =
			    sock_poll(listener, sockfd, POLLOUT);

			if ((rflags & POLLHUP) != 0)
				sock_fail(listener, errno);
		}
	}
}

static short sock_poll(struct listener *listener, int fd, short flags)
{
	listener->do_poll = true;
	listener->pollfd[0].fd = fd;
	listener->pollfd[0].events = flags;

	swapcontext(&listener->context,
	            &listener->server->poll_context);

	return listener->pollfd[0].revents;
}

static void sock_fail(struct listener *listener, int err)
{
	listener->socket_error = err;
	listener->do_fail = true;

	swapcontext(&listener->context,
	            &listener->server->poll_context);
}

static void my_log(struct coap_logger *logger, char const *format, ...)
{
	union my_logger *my_logger = (void *)logger;

	FILE *file = my_logger->data.file;

	va_list ap;
	va_start(ap, format);

	flockfile(file);
	vfprintf(file, format, ap);
	fprintf(file, "\n");
	funlockfile(file);

	va_end(ap);
}
