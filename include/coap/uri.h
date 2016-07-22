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
#ifndef COAP_URI_H
#define COAP_URI_H

#include <stdint.h>

enum { URI_SCHEME_COAP = 1,
       URI_SCHEME_COAPS,
       URI_SCHEME_FILE,
       URI_SCHEME_FTP,
       URI_SCHEME_HTTP,
       URI_SCHEME_HTTPS };
typedef uint_fast16_t uri_scheme;

uri_scheme uri_scheme_from_name(char const *name);

#endif
