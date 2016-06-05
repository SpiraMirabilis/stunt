/*  Copyright (c) 2012, Michael Munson
 * All rights reserved.
 * Permission to use, copy, modify, and/or distribute this software for any purpose 
 * with or without fee is hereby granted, provided that the above copyright notice 
 * and this permission notice appear in all copies.
 * 
 * THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES WITH REGARD 
 * TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS. 
 * IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR ANY SPECIAL, DIRECT, INDIRECT, OR 
 * CONSEQUENTIAL DAMAGES OR ANY DAMAGES WHATSOEVER RESULTING FROM LOSS OF USE, 
 * DATA OR PROFITS, WHETHER IN AN ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, 
 * ARISING OUT OF OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE. */
#ifndef Moosql_H
#define Moosql_H 1


#include <stdio.h>
#include <stdlib.h>
#include <mysql.h>

#include "numbers.h"
#include "functions.h"
#include "storage.h"
#include "utils.h"
#include "list.h"
#include "map.h"
#include "yajl_parse.h"
#include "json.h"
#include <map>

#define MOOSQL_MAX_FIELDS 100 // MySQL has a maximum columns of 2599, but we dont
#define SANITIZE_STRINGS 1 /* IF THIS IS 0 SANITIZE_RESULT_STRING WONT BE CALLED */
#define MOOSQL_SANITIZED_NEWLINE '\t' /* we will replace newline chars (\n) with this */
#define MOOSQL_ERROR_LEN 512 /* maximum length of a MySQL error message */
#define MOOSQL_MAX_CON 10 /* maximum simultaneous MySQL connections */
#define MOOSQL_STRING_LEN 256


#if !defined(MYSQL_VERSION_ID) || MYSQL_VERSION_ID<32224
#define mysql_field_count mysql_num_fields
#endif

typedef enum {
      MODE_KEY_VALUE_PAIR, MODE_VALUE_LIST
} row_mode;

typedef struct MYSQL_CONN MYSQL_CONN;
struct MYSQL_CONN
{
  int connect_time;
  int last_query_time;
  int active;
  int inQuery;
  int numRows;
  int port;
  Objid id;
  char server[MOOSQL_STRING_LEN];
  char username[MOOSQL_STRING_LEN];
  char database[MOOSQL_STRING_LEN];
  char *field_names[MOOSQL_MAX_FIELDS];
  enum enum_field_types field_types[MOOSQL_MAX_FIELDS];
  int field_names_len;
  unsigned int field_flags[MOOSQL_MAX_FIELDS];
  int auto_json;
  row_mode row_type;
  mode_type json_mode;
  int convert_types;

  MYSQL_CONN *next;
  MYSQL_RES *result;
  MYSQL *conn;
};

static MYSQL_CONN* newSqlConn(const Objid cid);
int totalSqlConns(void);

static int do_mysql_connect (MYSQL_CONN *wrapper, const char *host_name, const char *user_name, const char *password, const char *db_name,
				      const unsigned int port_num, const char *socket_name, const unsigned int flags, char *error_string);
static void do_mysql_disconnect (MYSQL_CONN *conn);
static int mysql_connection_ping (MYSQL_CONN *conn);
static void sanitize_result_string(const char *string);
static int mysql_connection_status(MYSQL_CONN *wrapper);
static int process_mysql_query (MYSQL_CONN *conn, char * res_string);
static Var process_row_map(MYSQL_CONN *wrapper, const MYSQL_ROW *row);
static Var process_row_list(MYSQL_CONN *wrapper, const MYSQL_ROW *row);
static Var process_result_set (MYSQL_CONN *conn, MYSQL_RES *res_set);
static int connection_array_index(); /* returns the index to the array for the first unused connection. 0 if none. */
static MYSQL_CONN* resolve_mysql_connection(int); /* this verb takes the int id assigned by do_mysql_connect and returns the correct wrapper */


/* ------- UGLY GLOBAL VARIABLES GO HERE ----- */
// we're using an arbitrary negative number to represent unique SQL connections.
std::map<int, MYSQL_CONN*> SQLMap;
Objid next_mysql_connection = NOTHING - 1; 
// this isn't the most elegant way to do this. It would be better if there were no maximum number of
// connections and the code allocated and freed memory for them as they were used and destroyed
// this table at 10 max connections will use a little more than 12000 bytes of memory
/* ----- DONE WITH UGLY GLOBALS ---- */
#endif
