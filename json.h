/******************************************************************************
  Copyright 2010 Todd Sundsted. All rights reserved.

  Redistribution and use in source and binary forms, with or without
  modification, are permitted provided that the following conditions are met:

   1. Redistributions of source code must retain the above copyright notice,
      this list of conditions and the following disclaimer.

   2. Redistributions in binary form must reproduce the above copyright notice,
      this list of conditions and the following disclaimer in the documentation
      and/or other materials provided with the distribution.

  THIS SOFTWARE IS PROVIDED BY TODD SUNDSTED ``AS IS'' AND ANY EXPRESS OR
  IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES OF
  MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO
  EVENT SHALL TODD SUNDSTED OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT,
  INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT
  LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA,
  OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF
  LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING
  NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE,
  EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.

  The views and conclusions contained in the software and documentation are
  those of the authors and should not be interpreted as representing official
  policies, either expressed or implied, of Todd Sundsted.
 *****************************************************************************/

#include "yajl_parse.h"
#include "yajl_gen.h"


struct stack_item {
      struct stack_item *prev;
      Var v;
};


// functions
int json_handle_null(void *ctx);
int json_handle_end_array(void *ctx);
int json_handle_start_array(void *ctx);
int json_handle_end_map(void *ctx);
int json_handle_start_map(void *ctx);
int
json_handle_string(void *ctx, const unsigned char *stringVal, unsigned int stringLen);
int json_handle_float(void *ctx, double doubleVal);
int json_handle_integer(void *ctx, long integerVal);
int json_handle_boolean(void *ctx, int boolean);
void json_push(struct stack_item **, Var);
Var json_pop(struct stack_item **);

#define PUSH(top, v) json_push(&(top), v)
#define POP(top) json_pop(&(top))



static yajl_callbacks callbacks = {
    json_handle_null,
    json_handle_boolean,
    json_handle_integer,
    json_handle_float,
    NULL,
    json_handle_string,
    json_handle_start_map,
    json_handle_string,
    json_handle_end_map,
    json_handle_start_array,
    json_handle_end_array
};


typedef enum {
      MODE_COMMON_SUBSET, MODE_EMBEDDED_TYPES
} mode_type;

struct parse_context {
   struct stack_item stack;
   struct stack_item *top;
   mode_type mode;
};

struct generate_context {
      mode_type mode;
};

#define ARRAY_SENTINEL -1
#define MAP_SENTINEL -2
