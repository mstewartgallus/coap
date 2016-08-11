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
#ifndef COAP_H
#define COAP_H

#include <stdint.h>
#include <sys/types.h>

enum { COAP_TYPE_CONFIRMABLE,
       COAP_TYPE_NONCONFIRMABLE,
       COAP_TYPE_ACKNOWLEDGEMENT,
       COAP_TYPE_RESET,
};
typedef unsigned char coap_type;

enum { COAP_CODE_EMPTY };
enum { COAP_CODE_REQUEST_GET = 1U,
       COAP_CODE_REQUEST_POST = 2U,
       COAP_CODE_REQUEST_PUT = 3U,
       COAP_CODE_REQUEST_DELETE = 4U,
};
enum { COAP_CODE_RESPONSE_SUCCESS_CREATED = (2U << 5U) | 1U,
       COAP_CODE_RESPONSE_SUCCESS_DELETED = (2U << 5U) | 2U,
       COAP_CODE_RESPONSE_SUCCESS_VALID = (2U << 5U) | 3U,
       COAP_CODE_RESPONSE_SUCCESS_CHANGED = (2U << 5U) | 4U,
       COAP_CODE_RESPONSE_SUCCESS_CONTENT = (2U << 5U) | 5U,
};
enum { COAP_CODE_RESPONSE_CLIENT_ERROR_BAD_REQUEST = (4U << 5U) | 0U,
       COAP_CODE_RESPONSE_CLIENT_ERROR_UNAUTHORIZED = (4U << 5U) | 1U,
       COAP_CODE_RESPONSE_CLIENT_ERROR_BAD_OPTION = (4U << 5U) | 2U,
       COAP_CODE_RESPONSE_CLIENT_ERROR_FORBIDDEN = (4U << 5U) | 3U,
       COAP_CODE_RESPONSE_CLIENT_ERROR_NOT_FOUND = (4U << 5U) | 4U,
       COAP_CODE_RESPONSE_CLIENT_ERROR_METHOD_NOT_FOUND =
	   (4U << 5U) | 5U,
       COAP_CODE_RESPONSE_CLIENT_ERROR_NOT_ACCEPTABLE = (4U << 5U) | 6U,
       COAP_CODE_RESPONSE_CLIENT_ERROR_PRECONDITION_FAILED =
	   (4U << 5U) | 12U,
       COAP_CODE_RESPONSE_CLIENT_ERROR_REQUEST_ENTITY_TOO_LARGE =
	   (4U << 5U) | 13U,
       COAP_CODE_RESPONSE_CLIENT_ERROR_UNSUPPORTED_CONTENT_FORMAT =
	   (4U << 5U) | 15U,
};
enum { COAP_CODE_RESPONSE_INTERNAL_SERVER_ERROR_NOT_IMPLEMENTED =
	   (5U << 5U) | 1U,
       COAP_CODE_RESPONSE_INTERNAL_SERVER_ERROR_BAD_GATEWAY =
	   (5U << 5U) | 2U,
       COAP_CODE_RESPONSE_INTERNAL_SERVER_ERROR_SERVICE_UNAVAILABLE =
	   (5U << 5U) | 3U,
       COAP_CODE_RESPONSE_INTERNAL_SERVER_ERROR_GATEWAY_TIMEOUT =
	   (5U << 5U) | 4U,
       COAP_CODE_RESPONSE_INTERNAL_SERVER_ERROR_PROXYING_NOT_SUPPORTED =
	   (5U << 5U) | 5U,
};
typedef unsigned char coap_code;

enum { COAP_CONTENT_FORMAT_TEXT_PLAIN_CHARSET_UTF_8 = 0,
       COAP_CONTENT_FORMAT_APPLICATION_LINK_FORMAT = 40,
       COAP_CONTENT_FORMAT_APPLICATION_XML = 41,
       COAP_CONTENT_FORMAT_APPLICATION_OCTET_STREAM = 42,
       COAP_CONTENT_FORMAT_APPLICATION_EXI = 47,
       COAP_CONTENT_FORMAT_APPLICATION_JSON = 50,
};
typedef unsigned coap_content_format;

enum { COAP_OPTION_VALUE_UINT, COAP_OPTION_VALUE_STRING };
typedef unsigned char coap_option_value;

enum { COAP_OPTION_TYPE_IF_MATCH = 1U,
       COAP_OPTION_TYPE_URI_HOST = 3U,
       COAP_OPTION_TYPE_ETAG = 4U,
       COAP_OPTION_TYPE_IF_NONE_MATCH = 5U,
       COAP_OPTION_TYPE_URI_PORT = 7U,
       COAP_OPTION_TYPE_LOCATION_PATH = 8U,
       COAP_OPTION_TYPE_URI_PATH = 11U,
       COAP_OPTION_TYPE_CONTENT_FORMAT = 12U,
       COAP_OPTION_TYPE_MAX_AGE = 14U,
       COAP_OPTION_TYPE_URI_QUERY = 15U,
       COAP_OPTION_TYPE_ACCEPT = 17U,
       COAP_OPTION_TYPE_LOCATION_QUERY = 20U,
       COAP_OPTION_TYPE_PROXY_URI = 35U,
       COAP_OPTION_TYPE_PROXY_SCHEME = 39U,
       COAP_OPTION_TYPE_SIZE1 = 60U };
typedef unsigned char coap_option_type;

enum { COAP_ERROR_UNSUPPORTED_VERSION = 1,
       COAP_ERROR_BUFFER_OVERFLOW,
       COAP_ERROR_BAD_PACKET,
       COAP_ERROR_BAD_OPTION };
typedef unsigned char coap_error;

union coap_option_value {
	struct {
		char *buf;
		size_t size;
	} string;
	uint64_t uint;
};

struct coap_option {
	unsigned char type;
	union coap_option_value value;
};

struct coap_logger {
	void (*log)(struct coap_logger *logger, char const *format,
	            ...);
};

struct coap_decoder {
	struct coap_logger *logger;
	char const *message;
	size_t header_size;
	size_t message_size;
	size_t message_index;
	unsigned char version;
	coap_type type;
	uint_least16_t message_id;
	uint_least64_t token;
	uint_least64_t option_type;
	coap_code code;
	_Bool has_payload;

	_Bool done;
	_Bool is_uint;
	union {
		uint64_t uint;
		struct {
			char const *str;
			size_t size;
		} str;
	};
};

struct coap_encoder {
	struct coap_logger *logger;
	char *buffer;
	size_t buffer_size;
	size_t buffer_index;
	size_t last_option_type;
};

enum { COAP_EMPTY_PACKET_SIZE = 4 };

struct coap_cfg;

struct coap_cfg const *coap_cfg_default(void);

unsigned long coap_cfg_ack_timeout_ms(struct coap_cfg const *cfg);
unsigned long
coap_cfg_ack_random_factor_numerator(struct coap_cfg const *cfg);
unsigned long
coap_cfg_ack_random_factor_denominator(struct coap_cfg const *cfg);
uint_fast8_t coap_cfg_max_retransmit(struct coap_cfg const *cfg);

void coap_empty_packet(coap_type type, uint_fast16_t message_id,
                       char *buffer);

coap_error coap_decode_start(struct coap_decoder *decoder,
                             struct coap_logger *logger,
                             char const *message, size_t message_size);
coap_error coap_decode_option(struct coap_decoder *decoder);

coap_error coap_encode_start(struct coap_encoder *encoder,
                             struct coap_logger *logger,
                             unsigned char version, coap_type type,
                             coap_code code, uint_fast16_t message_id,
                             uint_fast64_t token, char *buffer,
                             size_t buffer_size);
coap_error coap_encode_option_string(struct coap_encoder *encoder,
                                     coap_option_type option_type,
                                     char const *str, size_t str_size);
coap_error coap_encode_option_uint(struct coap_encoder *encoder,
                                   coap_option_type option_type,
                                   uint64_t uint);
coap_error coap_encode_payload(struct coap_encoder *encoder,
                               char const *payload,
                               size_t payload_size);

char const *coap_type_string(coap_type type);
char const *coap_code_string(coap_code code);
char const *coap_content_format_string(coap_content_format code);
#endif
