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

#include <arpa/inet.h>
#include <ctype.h>
#include <errno.h>
#include <stdbool.h>
#include <stdlib.h>
#include <string.h>

#include <stdio.h>

struct coap_cfg {
	unsigned long ack_timeout_ns;
	unsigned long ack_random_factor_numerator;
	unsigned long ack_random_factor_demoninator;
	unsigned long nstart;
	unsigned long default_leisure_ns;
	unsigned long probing_rate;
	uint_least8_t max_retransmit;
};

#define LOG(LOGGER, ...)                                               \
	do {                                                           \
		if ((LOGGER) != 0)                                     \
			(LOGGER)->log((LOGGER), __VA_ARGS__);          \
	} while (0)

struct coap_cfg const *coap_cfg_default(void)
{
	static struct coap_cfg const default_cfg = {
	    .ack_timeout_ns = 2U * 10000000U,
	    .ack_random_factor_numerator = 3,
	    .ack_random_factor_demoninator = 2,
	    .max_retransmit = 4U,
	    .nstart = 1U,
	    .default_leisure_ns = 5U * 10000000U,
	    .probing_rate = 1U};
	return &default_cfg;
}

unsigned long coap_cfg_ack_timeout_ms(struct coap_cfg const *cfg)
{
	return cfg->ack_timeout_ns / 100000;
}

unsigned long
coap_cfg_ack_random_factor_numerator(struct coap_cfg const *cfg)
{
	return cfg->ack_random_factor_numerator;
}

unsigned long
coap_cfg_ack_random_factor_denominator(struct coap_cfg const *cfg)
{
	return cfg->ack_random_factor_demoninator;
}

uint_fast8_t coap_cfg_max_retransmit(struct coap_cfg const *cfg)
{
	return cfg->max_retransmit;
}

void coap_empty_packet(coap_type type, uint_fast16_t message_id,
                       char *buffer)
{
	coap_header_encode(0, 0, 1U, type, COAP_CODE_EMPTY, message_id,
	                   0, 0, 0U, false, buffer, 4U);
}

static size_t count_bytes(uint_fast64_t value)
{
	size_t ii = 0U;
	size_t option_length = 8U;
	for (; ii < 8U; ++ii) {
		uint64_t offset = 8U * (7U - ii);
		unsigned char byte = (value >> offset) & UINT64_C(0xFF);
		if (0 == byte) {
			--option_length;
			continue;
		}
		break;
	}
	return option_length;
}

static void write_bytes(char *buf, uint_fast64_t value)
{
	size_t bytes = count_bytes(value);

	for (size_t ii = 0U; ii < bytes; ++ii) {
		uint64_t offset = 8U * ii;
		unsigned char byte = (value >> offset) & UINT64_C(0xFF);
		buf[bytes - 1U - ii] = byte;
	}
}

static uint_fast64_t decode_bytes(char const *buf, size_t size)
{
	uint_fast64_t value = 0U;
	for (size_t ii = 0U; ii < size; ++ii) {
		uint_fast8_t byte = buf[ii];
		uint_fast64_t offset = 8U * (size - 1U - ii);
		value |= ((uint_fast64_t)byte) << offset;
	}
	return value;
}

coap_error coap_header_encode(struct coap_logger *logger,
                              size_t *header_sizep,
                              unsigned char version, coap_type type,
                              coap_code code, uint_fast16_t message_id,
                              uint_fast64_t token,
                              struct coap_option const *options,
                              size_t options_size, bool have_payload,
                              char *buffer, size_t buffer_size)
{
	size_t encoded_size = 0U;

	if (version != 1U)
		return COAP_ERROR_UNSUPPORTED_VERSION;

	uint_least16_t network_message_id = htons(message_id);

	size_t token_size = count_bytes(token);

	unsigned char first_byte = version | (type << 2U) |
	                           (((unsigned char)token_size) << 4U);

	unsigned char header_bytes[4U] = {0};
	memcpy(header_bytes, &first_byte, 1U);
	memcpy(header_bytes + 1U, &code, 1U);
	memcpy(header_bytes + 2U, &network_message_id, 2U);

	encoded_size += sizeof header_bytes;
	if (encoded_size > buffer_size)
		goto size_overflow;
	memcpy(buffer, header_bytes, sizeof header_bytes);

	encoded_size += token_size;
	if (encoded_size > buffer_size)
		goto size_overflow;
	write_bytes(buffer + encoded_size - token_size, token);

	unsigned char last_value = 0U;
	for (size_t ii = 0U; ii < options_size; ++ii) {
		int coap_option_delta = options[ii].type - last_value;
		if (coap_option_delta < 0) {
			LOG(logger, "options out of order %lu",
			    options[ii].type);
			return COAP_ERROR_BAD_OPTION;
		}

		last_value = options[ii].type;

		coap_option_value option_value_type;
		uint16_t option_length;
		char const *option_string;
		uint_fast64_t option_uint;

		switch (last_value) {
		case COAP_OPTION_TYPE_URI_HOST:
		case COAP_OPTION_TYPE_URI_PATH:
		case COAP_OPTION_TYPE_URI_QUERY: {
			option_string = options[ii].value.string.buf;
			size_t str_length =
			    options[ii].value.string.size;
			if (str_length > 255U)
				return COAP_ERROR_BAD_PACKET;
			option_length = str_length;
			option_value_type = COAP_OPTION_VALUE_STRING;
			break;
		}

		case COAP_OPTION_TYPE_ACCEPT:
		case COAP_OPTION_TYPE_URI_PORT:
		case COAP_OPTION_TYPE_CONTENT_FORMAT: {
			option_uint = options[ii].value.uint;
			option_length = count_bytes(option_uint);
			option_value_type = COAP_OPTION_VALUE_UINT;
			break;
		}

		default:
			LOG(logger, "unknown option %lu encountered",
			    last_value);
			return COAP_ERROR_BAD_OPTION;
		}

		unsigned char option_header = coap_option_delta << 4U;

		encoded_size += sizeof option_header;
		if (encoded_size > buffer_size)
			goto size_overflow;

		if (option_length <= 12U) {
			option_header |= option_length;
		} else if (option_length <= 268U) {
			option_header |= 13U;
		} else {
			/* Currently unimplemented */
			return COAP_ERROR_BAD_PACKET;
		}

		memcpy(buffer + encoded_size - sizeof option_header,
		       &option_header, sizeof option_header);

		if (12U < option_length && option_length <= 268U) {
			unsigned char length_byte = option_length - 13U;
			encoded_size += 1U;
			if (encoded_size > buffer_size)
				goto size_overflow;
			memcpy(buffer + encoded_size - 1U, &length_byte,
			       1U);
		}

		encoded_size += option_length;
		if (encoded_size > buffer_size)
			goto size_overflow;

		switch (option_value_type) {
		case COAP_OPTION_VALUE_UINT:
			write_bytes(buffer + encoded_size -
			                option_length,
			            option_uint);
			break;

		case COAP_OPTION_VALUE_STRING:
			memcpy(buffer + encoded_size - option_length,
			       option_string, option_length);
			break;
		}
	}

	if (have_payload) {
		unsigned char options_end = 0xFF;
		encoded_size += sizeof options_end;
		if (encoded_size > buffer_size)
			goto size_overflow;
		memcpy(buffer + encoded_size - sizeof options_end,
		       &options_end, sizeof options_end);
	}

	if (header_sizep != 0)
		*header_sizep = encoded_size;
	return 0;

size_overflow:
	return COAP_ERROR_BAD_PACKET;
}

coap_error coap_header_decode_start(struct coap_decoder *decoder,
                                    struct coap_logger *logger,
                                    char const *message,
                                    size_t message_size)
{
	memset(decoder, 0, sizeof *decoder);

	decoder->message = message;
	decoder->message_size = message_size;
	decoder->logger = logger;

	size_t message_index = 0U;

	unsigned char header_bytes[4U];
	message_index += sizeof header_bytes;
	if (message_index > message_size)
		return COAP_ERROR_BAD_PACKET;
	memcpy(header_bytes, message, sizeof header_bytes);

	unsigned char first_byte = header_bytes[0U];

	unsigned char version = first_byte & ((1U << 2U) - 1U);
	decoder->version = version;

	if (version != 1U)
		return COAP_ERROR_UNSUPPORTED_VERSION;

	unsigned char type = (first_byte >> 2U) & 0x03U;

	decoder->type = type;

	unsigned char token_length = first_byte >> 4U;
	if (token_length >= 9U)
		return COAP_ERROR_BAD_PACKET;

	unsigned char code = header_bytes[1U];

	decoder->code = code;

	uint_fast16_t message_id =
	    decode_bytes((char *)header_bytes + 2U, 2U);

	decoder->message_id = message_id;

	message_index += token_length;
	if (message_index > message_size)
		return COAP_ERROR_BAD_PACKET;

	uint_fast64_t token = decode_bytes(
	    message + message_index - token_length, token_length);

	decoder->token = token;

	decoder->message_index = message_index;

	return 0;
}

coap_error coap_header_decode_option(struct coap_decoder *decoder)
{
	struct coap_logger *logger = decoder->logger;
	char const *message = decoder->message;
	size_t message_index = decoder->message_index;
	size_t message_size = decoder->message_size;

	for (;;) {
		unsigned char option_header;
		message_index += 1U;
		if (message_index > message_size) {
			/* No payload */
			message_index -= 1U;
			decoder->done = true;
			decoder->message_index = message_index;
			decoder->header_size = message_index;
			decoder->has_payload = false;
			return 0;
		}
		memcpy(&option_header, message + message_index - 1U,
		       1U);
		if (0xFFU == option_header) {
			decoder->done = true;
			decoder->message_index = message_index;
			decoder->header_size = message_index;
			decoder->has_payload = true;
			return 0;
		}

		unsigned char option_delta = option_header >> 4U;
		size_t option_length = option_header & 0xFU;
		switch (option_delta) {
		case 13U:
		case 14U:
		case 15U:
			LOG(logger, "special delta options are not "
			            "implemented");
			return COAP_ERROR_BAD_PACKET;
		}
		switch (option_length) {
		case 13U: {
			unsigned char length_byte;
			message_index += sizeof length_byte;
			if (message_index > message_size)
				goto packet_too_small;
			memcpy(&length_byte, message + message_index -
			                         sizeof length_byte,
			       sizeof length_byte);
			option_length = length_byte + 13U;
			break;
		}

		case 14U:
		case 15U:
			LOG(logger, "special length options are not "
			            "implemented");
			return COAP_ERROR_BAD_PACKET;
		}
		decoder->option_type += option_delta;

		message_index += option_length;
		if (message_index > message_size)
			goto malformed_packet;

		char const *option_start =
		    message + message_index - option_length;

		bool critical_option =
		    (decoder->option_type & (1U << 7U)) != 0U;

		bool repeatable;
		switch (decoder->option_type) {
		case COAP_OPTION_TYPE_IF_MATCH:
		case COAP_OPTION_TYPE_ETAG:
		case COAP_OPTION_TYPE_LOCATION_PATH:
		case COAP_OPTION_TYPE_URI_PATH:
		case COAP_OPTION_TYPE_URI_QUERY:
		case COAP_OPTION_TYPE_LOCATION_QUERY:
			repeatable = true;
			break;

		case COAP_OPTION_TYPE_URI_HOST:
		case COAP_OPTION_TYPE_URI_PORT:
		case COAP_OPTION_TYPE_IF_NONE_MATCH:
		case COAP_OPTION_TYPE_CONTENT_FORMAT:
		case COAP_OPTION_TYPE_MAX_AGE:
		case COAP_OPTION_TYPE_ACCEPT:
		case COAP_OPTION_TYPE_PROXY_URI:
		case COAP_OPTION_TYPE_PROXY_SCHEME:
		case COAP_OPTION_TYPE_SIZE1:
			repeatable = false;
			break;
		}
		if (repeatable && 0U == option_delta)
			goto bad_option_error;

		switch (decoder->option_type) {
		case COAP_OPTION_TYPE_URI_HOST:
			if (option_length <= 0U)
				goto bad_option_error;
			if (option_length > 255U) {
				LOG(logger, "abnormally long "
				            "Uri-Host option of "
				            "size %lu encountered",
				    option_length);
				goto bad_option_error;
			}

			decoder->str.str = option_start;
			decoder->str.size = option_length;
			break;

		case COAP_OPTION_TYPE_URI_PORT: {
			if (option_length > 2U) {
				LOG(logger, "abnormally long Uri-Port "
				            "option of size %lu "
				            "encountered",
				    option_length);
				goto bad_option_error;
			}

			decoder->uint =
			    decode_bytes(option_start, option_length);
			break;
		}

		case COAP_OPTION_TYPE_URI_PATH:
			if (option_length > 255U)
				goto bad_option_error;
			decoder->str.str = option_start;
			decoder->str.size = option_length;
			break;

		case COAP_OPTION_TYPE_URI_QUERY:
			if (option_length > 255U) {
				LOG(logger, "abnormally long "
				            "Uri-Query option of "
				            "size %lu encountered",
				    option_length);
				goto bad_option_error;
			}

			decoder->str.str = option_start;
			decoder->str.size = option_length;
			break;

		case COAP_OPTION_TYPE_CONTENT_FORMAT: {
			if (option_length > 2U) {
				LOG(logger, "abnormally long "
				            "Content-Format option of "
				            "size %lu encountered",
				    option_length);
				goto bad_option_error;
			}

			decoder->uint =
			    decode_bytes(option_start, option_length);
			break;
		}

		case COAP_OPTION_TYPE_ACCEPT: {
			if (option_length > 2U) {
				LOG(logger, "abnormally long Accept "
				            "option of size %lu "
				            "encountered",
				    option_length);
				goto bad_option_error;
			}

			decoder->uint =
			    decode_bytes(option_start, option_length);
			break;
		}

		default:
			LOG(logger, "unknown option %lu encountered",
			    decoder->option_type);
			goto bad_option_error;
		}

		decoder->message_index = message_index;

		return 0;

	bad_option_error:
		/* Ignore elective options we don't understand */
		if (!critical_option) {
			continue;
		}

		return COAP_ERROR_BAD_OPTION;
	}

malformed_packet:
packet_too_small:
	return COAP_ERROR_BAD_PACKET;
}

char const *coap_type_string(coap_type code)
{
	switch (code) {
	default:
		return 0;

	case COAP_TYPE_CONFIRMABLE:
		return "Confirmable";

	case COAP_TYPE_NONCONFIRMABLE:
		return "Noncomfirmable";

	case COAP_TYPE_ACKNOWLEDGEMENT:
		return "Acknowledgement";

	case COAP_TYPE_RESET:
		return "Reset";
	}
}

char const *coap_code_string(coap_code code)
{
	switch (code) {
	default:
		return 0;

	case COAP_CODE_EMPTY:
		return "Empty";

	case COAP_CODE_REQUEST_GET:
		return "GET";

	case COAP_CODE_REQUEST_POST:
		return "POST";

	case COAP_CODE_REQUEST_PUT:
		return "PUT";

	case COAP_CODE_REQUEST_DELETE:
		return "DELETE";

	case COAP_CODE_RESPONSE_SUCCESS_CREATED:
		return "CREATED";

	case COAP_CODE_RESPONSE_SUCCESS_DELETED:
		return "DELETED";

	case COAP_CODE_RESPONSE_SUCCESS_VALID:
		return "VALID";

	case COAP_CODE_RESPONSE_SUCCESS_CHANGED:
		return "CHANGED";

	case COAP_CODE_RESPONSE_SUCCESS_CONTENT:
		return "CONTENT";

	case COAP_CODE_RESPONSE_CLIENT_ERROR_BAD_REQUEST:
		return "BAD REQUEST";

	case COAP_CODE_RESPONSE_CLIENT_ERROR_UNAUTHORIZED:
		return "UNAUTHORIZED";

	case COAP_CODE_RESPONSE_CLIENT_ERROR_BAD_OPTION:
		return "BAD OPTION";

	case COAP_CODE_RESPONSE_CLIENT_ERROR_FORBIDDEN:
		return "FORBIDDEN";

	case COAP_CODE_RESPONSE_CLIENT_ERROR_NOT_FOUND:
		return "NOT FOUND";

	case COAP_CODE_RESPONSE_CLIENT_ERROR_METHOD_NOT_FOUND:
		return "METHOD NOT FOUND";

	case COAP_CODE_RESPONSE_CLIENT_ERROR_NOT_ACCEPTABLE:
		return "METHOD NOT ACCEPTABLE";

	case COAP_CODE_RESPONSE_CLIENT_ERROR_PRECONDITION_FAILED:
		return "PRECONDITION FAILED";

	case COAP_CODE_RESPONSE_CLIENT_ERROR_REQUEST_ENTITY_TOO_LARGE:
		return "ENTITY TOO LARGE";

	case COAP_CODE_RESPONSE_CLIENT_ERROR_UNSUPPORTED_CONTENT_FORMAT:
		return "UNSUPPORTED CONTENT FORMAT";

	case COAP_CODE_RESPONSE_INTERNAL_SERVER_ERROR_NOT_IMPLEMENTED:
		return "NOT IMPLEMENTED";

	case COAP_CODE_RESPONSE_INTERNAL_SERVER_ERROR_BAD_GATEWAY:
		return "BAD GATEWAY";

	case COAP_CODE_RESPONSE_INTERNAL_SERVER_ERROR_SERVICE_UNAVAILABLE:
		return "SERVICE UNAVAILABLE";

	case COAP_CODE_RESPONSE_INTERNAL_SERVER_ERROR_GATEWAY_TIMEOUT:
		return "GATEWAY TIMEOUT";

	case COAP_CODE_RESPONSE_INTERNAL_SERVER_ERROR_PROXYING_NOT_SUPPORTED:
		return "PROXYING NOT SUPPORTED";
	}
}

char const *
coap_content_format_string(coap_content_format content_format)
{
	switch (content_format) {
	case COAP_CONTENT_FORMAT_TEXT_PLAIN_CHARSET_UTF_8:
		return "text/plain;charset=utf-8";
	case COAP_CONTENT_FORMAT_APPLICATION_LINK_FORMAT:
		return "application/link-format";
	case COAP_CONTENT_FORMAT_APPLICATION_XML:
		return "application/xml";
	case COAP_CONTENT_FORMAT_APPLICATION_OCTET_STREAM:
		return "application/octet-stream";
	case COAP_CONTENT_FORMAT_APPLICATION_EXI:
		return "application/exi";
	case COAP_CONTENT_FORMAT_APPLICATION_JSON:
		return "application/json";
	default:
		return 0;
	}
}
