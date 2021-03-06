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
#include <inttypes.h>
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
	unsigned version = 1U;
	coap_code code = COAP_CODE_EMPTY;

	uint_least16_t network_message_id = htons(message_id);

	unsigned char first_byte = version | (type << 2U) | (0U << 4U);

	unsigned char header_bytes[4U] = {0};
	memcpy(header_bytes, &first_byte, 1U);

	memcpy(header_bytes + 1U, &code, 1U);
	memcpy(header_bytes + 2U, &network_message_id, 2U);

	memcpy(buffer, header_bytes, sizeof header_bytes);
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

enum { ENCODER_STATE_START = 1,
       ENCODER_STATE_WRITING_OPTIONS,
       ENCODER_STATE_WROTE_PAYLOAD };

coap_error coap_encode_init(struct coap_encoder *encoder,
                            struct coap_logger *logger,
                            unsigned char version, char *buffer,
                            size_t buffer_size)
{
	if (version != 1U)
		return COAP_ERROR_UNSUPPORTED_VERSION;

	encoder->_logger = logger;
	encoder->_buffer = buffer;
	encoder->_buffer_size = buffer_size;
	encoder->_buffer_index = 0U;
	encoder->_last_option_type = 0U;
	encoder->_version = 1U;
	encoder->_state = ENCODER_STATE_START;

	return 0;
}

coap_error coap_encode_header(struct coap_encoder *encoder,
                              coap_type type, coap_code code,
                              uint_fast16_t message_id,
                              uint_fast64_t token)
{
	if (ENCODER_STATE_START != encoder->_state)
		abort();

	size_t last_option_type = encoder->_last_option_type;
	char *buffer = encoder->_buffer;
	size_t buffer_index = encoder->_buffer_index;
	size_t buffer_size = encoder->_buffer_size;
	unsigned char version = encoder->_version;

	uint_least16_t network_message_id = htons(message_id);

	size_t token_size = count_bytes(token);

	unsigned char first_byte = version | (type << 2U) |
	                           (((unsigned char)token_size) << 4U);

	unsigned char header_bytes[4U] = {0};
	memcpy(header_bytes, &first_byte, 1U);
	memcpy(header_bytes + 1U, &code, 1U);
	memcpy(header_bytes + 2U, &network_message_id, 2U);

	buffer_index += sizeof header_bytes;
	if (buffer_index > buffer_size)
		return COAP_ERROR_BUFFER_OVERFLOW;
	memcpy(buffer, header_bytes, sizeof header_bytes);

	buffer_index += token_size;
	if (buffer_index > buffer_size)
		return COAP_ERROR_BUFFER_OVERFLOW;
	write_bytes(buffer + buffer_index - token_size, token);

	encoder->_buffer_index = buffer_index;
	encoder->_last_option_type = 0U;
	encoder->_state = ENCODER_STATE_WRITING_OPTIONS;

	return 0;
}

coap_error coap_encode_option_string(struct coap_encoder *encoder,
                                     coap_option_type option_type,
                                     char const *str, size_t str_size)
{
	if (ENCODER_STATE_WRITING_OPTIONS != encoder->_state)
		abort();

	size_t last_option_type = encoder->_last_option_type;
	struct coap_logger *logger = encoder->_logger;
	char *buffer = encoder->_buffer;
	size_t buffer_index = encoder->_buffer_index;
	size_t buffer_size = encoder->_buffer_size;

	if (str_size > 255U)
		return COAP_ERROR_BUFFER_OVERFLOW;

	int coap_option_delta = option_type - last_option_type;
	if (coap_option_delta < 0) {
		LOG(logger, "options out of order %lu",
		    last_option_type);
		return COAP_ERROR_BAD_OPTION;
	}

	unsigned char option_header = ((unsigned)coap_option_delta)
	                              << 4U;

	buffer_index += sizeof option_header;
	if (buffer_index > buffer_size)
		return COAP_ERROR_BUFFER_OVERFLOW;

	if (str_size <= 12U) {
		option_header |= str_size;
	} else if (str_size <= 268U) {
		option_header |= 13U;
	} else {
		/* Currently unimplemented */
		return COAP_ERROR_BAD_PACKET;
	}

	memcpy(buffer + buffer_index - sizeof option_header,
	       &option_header, sizeof option_header);

	if (12U < str_size && str_size <= 268U) {
		unsigned char length_byte = str_size - 13U;
		buffer_index += 1U;
		if (buffer_index > buffer_size)
			return COAP_ERROR_BUFFER_OVERFLOW;
		memcpy(buffer + buffer_index - 1U, &length_byte, 1U);
	}

	buffer_index += str_size;
	if (buffer_index > buffer_size)
		return COAP_ERROR_BUFFER_OVERFLOW;

	memcpy(buffer + buffer_index - str_size, str, str_size);

	encoder->_last_option_type = option_type;
	encoder->_buffer_index = buffer_index;

	return 0;
}

coap_error coap_encode_option_uint(struct coap_encoder *encoder,
                                   coap_option_type option_type,
                                   uint64_t uint)
{
	if (ENCODER_STATE_WRITING_OPTIONS != encoder->_state)
		abort();

	size_t last_option_type = encoder->_last_option_type;
	struct coap_logger *logger = encoder->_logger;
	char *buffer = encoder->_buffer;
	size_t buffer_index = encoder->_buffer_index;
	size_t buffer_size = encoder->_buffer_size;

	int coap_option_delta = option_type - last_option_type;
	if (coap_option_delta < 0) {
		LOG(logger, "options out of order %lu",
		    last_option_type);
		return COAP_ERROR_BAD_OPTION;
	}

	size_t option_length = count_bytes(uint);

	unsigned char option_header =
	    ((unsigned)coap_option_delta) << 4U | option_length;

	buffer_index += sizeof option_header;
	if (buffer_index > buffer_size)
		return COAP_ERROR_BUFFER_OVERFLOW;

	memcpy(buffer + buffer_index - sizeof option_header,
	       &option_header, sizeof option_header);

	buffer_index += option_length;
	if (buffer_index > buffer_size)
		return COAP_ERROR_BUFFER_OVERFLOW;

	write_bytes(buffer + buffer_index - option_length, uint);

	encoder->_last_option_type = option_type;
	encoder->_buffer_index = buffer_index;

	return 0;
}

coap_error coap_encode_payload(struct coap_encoder *encoder,
                               char const *payload, size_t payload_size)
{
	if (ENCODER_STATE_WRITING_OPTIONS != encoder->_state)
		abort();

	char *buffer = encoder->_buffer;
	size_t buffer_index = encoder->_buffer_index;
	size_t buffer_size = encoder->_buffer_size;

	unsigned char options_end = 0xFF;
	buffer_index += sizeof options_end;
	if (buffer_index > buffer_size)
		return COAP_ERROR_BUFFER_OVERFLOW;
	memcpy(buffer + buffer_index - sizeof options_end, &options_end,
	       sizeof options_end);

	buffer_index += payload_size;
	if (buffer_index > buffer_size)
		return COAP_ERROR_BUFFER_OVERFLOW;

	memcpy(buffer + buffer_index - payload_size, payload,
	       payload_size);

	encoder->_state = ENCODER_STATE_WROTE_PAYLOAD;
	encoder->_buffer_index = buffer_index;

	return 0;
}

size_t coap_encode_size(struct coap_encoder *encoder)
{
	return encoder->_buffer_index;
}

coap_error coap_decode_start(struct coap_decoder *decoder,
                             struct coap_logger *logger,
                             char const *message, size_t message_size)
{
	memset(decoder, 0, sizeof *decoder);

	decoder->message = message;
	decoder->message_size = message_size;
	decoder->logger = logger;

	size_t message_index = 0U;

	unsigned char header_bytes[4U];
	message_index += sizeof header_bytes;
	if (message_index > message_size)
		return COAP_ERROR_BUFFER_OVERFLOW;
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

coap_error coap_decode_option(struct coap_decoder *decoder)
{
	struct coap_logger *logger = decoder->logger;
	char const *message = decoder->message;
	size_t message_index = decoder->message_index;
	size_t message_size = decoder->message_size;

restart:
	;
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
	memcpy(&option_header, message + message_index - 1U, 1U);
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
		memcpy(&length_byte,
		       message + message_index - sizeof length_byte,
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
		goto restart;
	}

	return COAP_ERROR_BAD_OPTION;

packet_too_small:
malformed_packet:
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

void coap_log_msg(FILE *file, char const *buf, size_t buf_size)
{
	struct coap_decoder decoder = {0};

	if (coap_decode_start(&decoder, 0, buf, buf_size) != 0)
		return;

	char const *type_str = coap_type_string(decoder.type);
	char const *request_str = coap_code_string(decoder.code);

	fprintf(file, "Received COAP request:\n");
	fprintf(file, "\t%s\n", type_str);
	fprintf(file, "\t%s\n", request_str);
	fprintf(file, "\tMessage Id: 0x%" PRIx16 "\n",
	        (uint_least16_t)decoder.message_id);
	fprintf(file, "\tToken: 0x%" PRIx64 "\n",
	        (uint_least64_t)decoder.token);

	for (;;) {
		char strbuf[255U + 1U] = {0};

		coap_decode_option(&decoder);
		if (decoder.done)
			break;

		switch (decoder.option_type) {
		case COAP_OPTION_TYPE_CONTENT_FORMAT: {
			char const *content_str =
			    coap_content_format_string(decoder.uint);
			if (0 == content_str) {
				fprintf(file,
				        "\tContent-Format: %" PRIu64
				        "\n",
				        decoder.uint);
			} else {
				fprintf(file, "\tContent-Format: %s\n",
				        content_str);
			}

			fprintf(file, "\tContent-Format: "
			              "0x%" PRIx64 "\n",
			        (uint_least64_t)decoder.uint);
			break;
		}

		case COAP_OPTION_TYPE_URI_PATH:
			memcpy(strbuf, decoder.str.str,
			       decoder.str.size);
			fprintf(file, "\tUri-Path: %s\n", strbuf);
			break;

		case COAP_OPTION_TYPE_URI_HOST:
			memcpy(strbuf, decoder.str.str,
			       decoder.str.size);
			fprintf(file, "\tUri-Host: %s\n", strbuf);
			break;

		case COAP_OPTION_TYPE_URI_PORT:
			fprintf(file, "\tUri-Port: "
			              "%" PRIu64 "\n",
			        (uint_least64_t)decoder.uint);
			break;

		case COAP_OPTION_TYPE_URI_QUERY:
			memcpy(strbuf, decoder.str.str,
			       decoder.str.size);
			fprintf(file, "\tUri-Query: %s\n", strbuf);
			break;

		case COAP_OPTION_TYPE_ACCEPT: {
			coap_content_format acceptable_format =
			    decoder.uint;

			char const *str = coap_content_format_string(
			    acceptable_format);
			if (0 == str) {
				fprintf(
				    file, "\tAccept: "
				          "%" PRIu64 "\n",
				    (uint_least64_t)acceptable_format);
			} else {
				fprintf(file, "\tAccept: %s\n", str);
			}
			break;
		}
		}
	}
}
