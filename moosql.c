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

#include "moosql.h"

/* this function takes the integer given by do_mysql_connect() and returns a MYSQL_CONN associated with that */
static MYSQL_CONN* resolve_mysql_connection(int id) {
    int lcv = 0;
    MYSQL_CONN *ptr = NULL;
    for (lcv = 0; lcv < MOOSQL_MAX_CON; lcv++) {
        if (SQL_CONNECTIONS[lcv].id == id)
            return &SQL_CONNECTIONS[lcv];
    }
    return (NULL);
}

/* the standard LambdaMOO database format is a flat text file. *
 * As such carriage return characters ruin it pretty quickly 
 * we change out carriage returns for an arbitrary character (currently tab)
 * that the MOO can then parse and recognize as a newline.
 * this is compile time option for people who have databases which can store returns */
static void sanitize_result_string(const char *string) {
#ifdef SANITIZE_STRINGS
    int lcv = 0;
    char *ptr = string;
    for (lcv = 0; lcv < strlen(string); lcv++) {
        if (*ptr == '\n')
            *ptr = MOOSQL_SANITIZED_NEWLINE;
        ptr++; /* go to next character */
    }
#endif
}

static int connection_array_index() {
    /* This function returns the index for the first blank entry in SQL_CONNECTIONS. Returns -1 if none are available */
    int lcv = 0;
    for (lcv = 0; lcv < MOOSQL_MAX_CON; lcv++) {
        if (!SQL_CONNECTIONS[lcv].active)
            return lcv;
        else if (SQL_CONNECTIONS[lcv].conn == NULL) {
            /* Somehow the connection is null but the active flag hasn't been reset. Oh well, we'll do that. */
            SQL_CONNECTIONS[lcv].active = 0;
            SQL_CONNECTIONS[lcv].id = 0;
            SQL_CONNECTIONS[lcv].port = 0;
            return lcv;
        }
    }
    return -1;
}

static MYSQL_CONN *do_mysql_connect(const char *host_name, const char *user_name, const char *password, const char *db_name,
        const unsigned int port_num, const char *socket_name, const unsigned int flags, char *error_string) {
    MYSQL *conn; /* pointer to connection handler */

    int ndx = 0;
    ndx = connection_array_index(); /* find out where it should go. */
    if (ndx == -1) /* No room in the index! */ {
        snprintf(error_string, MOOSQL_ERROR_LEN, "no mysql connections available, close some?");
        return (NULL);
    }

    conn = mysql_init(NULL); /* allocate the handler */
    if (conn == NULL) {
        snprintf(error_string, MOOSQL_ERROR_LEN, "mysql_init failed");
        return (NULL);
    }
    if (mysql_real_connect(conn, host_name, user_name, password,
            db_name, port_num, socket_name, flags) == NULL) {
        snprintf(error_string, MOOSQL_ERROR_LEN, "Error %u (%s)",
                mysql_errno(conn), mysql_error(conn));
        return (NULL);
    }
    SQL_CONNECTIONS[ndx].active = 1;
    SQL_CONNECTIONS[ndx].id = next_mysql_connection--;
    SQL_CONNECTIONS[ndx].port = port_num;
    SQL_CONNECTIONS[ndx].connect_time = time(0);
    SQL_CONNECTIONS[ndx].last_query_time = time(0);
    SQL_CONNECTIONS[ndx].json_mode = MODE_EMBEDDED_TYPES;
    SQL_CONNECTIONS[ndx].auto_json = 0;
    SQL_CONNECTIONS[ndx].row_type = MODE_KEY_VALUE_PAIR;
    SQL_CONNECTIONS[ndx].convert_types = 1;
    snprintf(SQL_CONNECTIONS[ndx].server, MOOSQL_STRING_LEN, host_name, "%s");
    snprintf(SQL_CONNECTIONS[ndx].username, MOOSQL_STRING_LEN, user_name, "%s");
    snprintf(SQL_CONNECTIONS[ndx].database, MOOSQL_STRING_LEN, db_name, "%s");
    SQL_CONNECTIONS[ndx].conn = conn;

    return &SQL_CONNECTIONS[ndx];
}


// Clear out everything on the wrapper so we can use it again

static void do_mysql_disconnect(MYSQL_CONN *conn_wrapper) {
    int i = 0;
    if (conn_wrapper->field_names != NULL) {
        for (i = 0; i < conn_wrapper->field_names_len; i++) {
            free_str(conn_wrapper->field_names[i]);
            conn_wrapper->field_names[i] = NULL;
            conn_wrapper->field_types[i] = 0;
            conn_wrapper->field_flags[i] = 0;

        }
        conn_wrapper->field_names_len = 0;
    }
    if (conn_wrapper->result != NULL) {
        mysql_free_result(conn_wrapper->result);
        conn_wrapper->result = NULL;
    }
    conn_wrapper->active = 0;
    conn_wrapper->id = 0;
    conn_wrapper->port = 0;
    conn_wrapper->connect_time = 0;
    conn_wrapper->last_query_time = 0;
    mysql_close(conn_wrapper->conn);
    conn_wrapper->conn = NULL;
}

// it took me a while to realize you can only fetch a field one time.
// this stores the field names, flags and types for each column at the time
// the query is made, and the memory is freed and values cleared after the last
// row is fetched.

static Var assign_field_names(MYSQL_CONN *wrapper) {
    MYSQL_RES *res_set = wrapper->result;
    Var ret;
    int i = 0;
    int num_fields = wrapper->field_names_len;
    ret.type = TYPE_LIST;
    ret = new_list(num_fields);
    for (i = 0; i < num_fields; i++) {
        MYSQL_FIELD *field = mysql_fetch_field(res_set);
        char *str = str_dup(field->name);
        wrapper->field_names[i] = str;
        wrapper->field_types[i] = field->type;
        wrapper->field_flags[i] = field->flags;
    }
    return ret;

}

// this will set the Var (that is pointed to by valPtr) to the type and value consistent with 

static void produce_row_value(MYSQL_CONN *wrapper, const MYSQL_ROW *row, int i, Var *valPtr) {
    const char *str = row[i];
    int flg = wrapper->field_flags[i];
    int type = wrapper->field_types[i];
    if (str == NULL) {
        valPtr->type = TYPE_STR;
        valPtr->v.str = str_dup("");
    } else {

        if ((flg & NUM_FLAG) && wrapper->convert_types) { // our field is some type of number
            if (type == MYSQL_TYPE_FLOAT || type == MYSQL_TYPE_DOUBLE || type == MYSQL_TYPE_DECIMAL || type == MYSQL_TYPE_NEWDECIMAL) {
                //  r.v.list[i + 1].v.fnum = new_float(0.0);
                valPtr->type = TYPE_FLOAT;
                valPtr->v.fnum = mymalloc(sizeof (double), M_FLOAT);
                int ok = parse_float(row[i], valPtr->v.fnum);
                if (!ok) {
                    sanitize_result_string(str);
                    myfree(valPtr->v.fnum, M_FLOAT);
                    valPtr->v.str = str_dup(str);
                    valPtr->type = TYPE_STR;
                }
            } else { // converting str to int is pretty easy
                valPtr->type = TYPE_INT;
                int *f = &valPtr->v.num;
                int ok = parse_number(str, f, 0);
                if (!ok) {
                    sanitize_result_string(str);
                    valPtr->v.str = str_dup(str);
                    valPtr->type = TYPE_STR;
                }
            }


        } else { // our field is a non-number, right now thats string only
            sanitize_result_string(str);
            Var v;
            int error = 0, done = 0;
            // this code below to parse json is stolen pretty directly from parse_json method in json.c
            // we only try to parse json in fields which are type "BLOB" which is all TEXT types.
            // BLOB (straight data) is also this.
            if (wrapper->auto_json && type == MYSQL_TYPE_BLOB) {
                yajl_handle hand;
                yajl_parser_config cfg = {1, 1};
                yajl_status stat;
                struct parse_context pctx;
                pctx.top = &pctx.stack;
                pctx.stack.v.type = TYPE_INT;
                pctx.stack.v.v.num = 0;
                pctx.mode = wrapper->json_mode;
                hand = yajl_alloc(&callbacks, &cfg, NULL, (void *) &pctx);
                size_t len = strlen(str);
                while (!done) {
                    if (len == 0)
                        done = 1;

                    if (done)
                        stat = yajl_parse_complete(hand);
                    else
                        stat = yajl_parse(hand, (const unsigned char *) str, len);

                    len = 0;

                    if (done) {
                        if (stat != yajl_status_ok) {
                            /* clean up the stack */
                            while (pctx.top != &pctx.stack) {
                                v = POP(pctx.top);
                                free_var(v);
                            }
                            error = 1;
                        } else {
                            v = POP(pctx.top);
                        }
                    }
                }

                yajl_free(hand);
                if (error) {
                    // not valid json, so we just throw the string out there
                    valPtr->type = TYPE_STR;
                    valPtr->v.str = str_dup(str);
                } else {
                    *valPtr = v;
                }
            } else { // either auto-json is off, or the field is a non-text type (like TIMESTAMP, etc)
                valPtr->type = TYPE_STR;
                valPtr->v.str = str_dup(str);
            }
        }
    }
}

static Var process_row_list(MYSQL_CONN *wrapper, const MYSQL_ROW *row) {
    Var r;
    MYSQL_RES *res_set = wrapper->result;
    int num_fields = 0;
    int i = 0;
    double dval = 0.0;
    MYSQL_FIELD *field;
    Var v;
    package pack;
    int error = 0;

    num_fields = wrapper->field_names_len;
    r.type = TYPE_LIST;
    r = new_list(num_fields);
    for (i = 0; i < num_fields; i++) {
        Var *p = &r.v.list[i + 1];
        produce_row_value(wrapper, row, i, p);
    }



    return r;

}

static Var process_row_map(MYSQL_CONN *wrapper, const MYSQL_ROW *row) {
    Var ret;
    MYSQL_RES *res_set = wrapper->result;
    int num_fields = 0;
    int i = 0;
    double dval = 0.0;
    MYSQL_FIELD *field;

    num_fields = wrapper->field_names_len;
    ret.type = TYPE_MAP;
    ret = new_map();
    for (i = 0; i < num_fields; i++) {
        Var key, value;
        key.type = TYPE_STR;
        key.v.str = str_dup(wrapper->field_names[i]);
        produce_row_value(wrapper, row, i, &value);
        ret = mapinsert(ret, key, value);
    }
    return ret;
}


static int process_mysql_query(MYSQL_CONN *conn, char * res_string) {
    MYSQL_RES *res_set;
    unsigned int field_count;

    /* query succeeded err */
    res_set = mysql_store_result(conn->conn);
    if (res_set == NULL) /* no result */ {
        /* check if its an error or just a query with no result */
        if (mysql_field_count(conn->conn) > 0) {
            snprintf(res_string, MOOSQL_ERROR_LEN, "Error processing SQL result set");
            return 0;
        } else {
            snprintf(res_string, MOOSQL_ERROR_LEN, "%lu rows affected.", (unsigned long) mysql_affected_rows(conn->conn));
            return 0;
        }
    } else {
        conn->result = res_set;
        return 1;
    }
}

/* our MOO functions are below */

static int mysql_connection_status(MYSQL_CONN *wrapper) {
    int ping;

    if (wrapper == NULL || wrapper->conn == NULL)
        return 0;
    ping = mysql_ping(wrapper->conn);
    if (ping == 0)
        return 1;
    else
        return 0;
}

// this is the function callback that is used by a mapforeach to set
// options for the connection.

static int compare_options(Var key, Var value, void *sptr, int first) {
    MYSQL_CONN *wrapper = sptr;
    if (key.type == TYPE_STR) {
        if (!strcmp(key.v.str, "auto-json")) {
            if (!strcmp(value.v.str, "yes"))
                wrapper->auto_json = 1;
            else if (!strcmp(value.v.str, "no"))
                wrapper->auto_json = 0;
        } else if (!strcmp(key.v.str, "json-mode")) {
            if (!strcmp(value.v.str, "embedded-types"))
                wrapper->json_mode = MODE_EMBEDDED_TYPES;
            else if (!strcmp(value.v.str, "common-subset"))
                wrapper->json_mode = MODE_COMMON_SUBSET;
        } else if (!strcmp(key.v.str, "row-type")) {
            if (!strcmp(value.v.str, "key-value-pair"))
                wrapper->row_type = MODE_KEY_VALUE_PAIR;
            else if (!strcmp(value.v.str, "value-list"))
                wrapper->row_type = MODE_VALUE_LIST;
        } else if (!strcmp(key.v.str, "convert-types")) {
            if (!strcmp(value.v.str, "yes"))
                wrapper->convert_types = 1;
            else if (!strcmp(value.v.str, "no"))
                wrapper->convert_types = 0;
        }
    }
    return 0;
}


// returns a LIST of strings, the strings being the field names for the current row
// if there is no current row or result it returns E_NONE
// if there is no connection, it raises E_INVARG

static package bf_mysql_fields(Var arglist, Byte next, void *vdata, Objid progr) {
    Var r;
    Objid oid = arglist.v.list[1].v.obj;
    free_var(arglist);
    if (!is_wizard(progr))
        return make_error_pack(E_PERM);
    MYSQL_CONN *wrapper;
    wrapper = resolve_mysql_connection(oid);
    if (wrapper == NULL || wrapper->active == 0)
        return make_error_pack(E_INVARG);
    if (wrapper->field_names_len == 0) {
        r.type = TYPE_ERR;
        r.v.err = E_NONE;
        return make_var_pack(r);
    } else {
        int i;
        r = new_list(wrapper->field_names_len);
        for (i = 1; i <= wrapper->field_names_len; i++) {
            r.v.list[i].type = TYPE_STR;
            r.v.list[i].v.str = str_dup(wrapper->field_names[i - 1]);
        }
        return make_var_pack(r);
    }
}

static Var current_mysql_vars(MYSQL_CONN *wrapper, int onlyOptions) {
    Var r;
    r = new_map();
    Var key, value;
    key.type = TYPE_STR;
    key.v.str = str_dup("hostname");
    value.type = TYPE_STR;
    value.v.str = str_dup(wrapper->server);
    r = mapinsert(r, key, value);

    key.v.str = str_dup("port");
    if (wrapper->port == 0)
        value.v.str = str_dup("default");
    else {
        value.type = TYPE_INT;
        value.v.num = wrapper->port;
    }
    r = mapinsert(r, key, value);
    key.v.str = str_dup("username");
    value.type = TYPE_STR;
    value.v.str = str_dup(wrapper->username);
    r = mapinsert(r, key, value);
    key.v.str = str_dup("database");
    value.v.str = str_dup(wrapper->database);
    r = mapinsert(r, key, value);
    key.v.str = str_dup("auto-json");
    if (wrapper->auto_json)
        value.v.str = str_dup("yes");
    else
        value.v.str = str_dup("no");
    r = mapinsert(r, key, value);
    key.v.str = str_dup("row-type");
    switch (wrapper->row_type) {
        case MODE_KEY_VALUE_PAIR:
            value.v.str = str_dup("key-value-pair");
            break;
        case MODE_VALUE_LIST:
            value.v.str = str_dup("value-list");
            break;
        default:
            value.v.str = str_dup("<error>");
            break;
    }
    r = mapinsert(r, key, value);
    key.v.str = str_dup("json-mode");
    switch (wrapper->json_mode) {
        case MODE_EMBEDDED_TYPES:
            value.v.str = str_dup("embedded-types");
            break;
        case MODE_COMMON_SUBSET:
            value.v.str = str_dup("common-subset");
            break;
        default:
            value.v.str = str_dup("<error>");
            break;
    }
    r = mapinsert(r, key, value);
    key.v.str = str_dup("convert-types");
    value.type = TYPE_STR;
    if (wrapper->convert_types)
        value.v.str = str_dup("yes");
    else
        value.v.str = str_dup("no");
    r = mapinsert(r, key, value);

    if (!onlyOptions) {
        value.type = TYPE_INT;
        key.v.str = str_dup("connect_time");
        value.v.num = wrapper->connect_time;
        r = mapinsert(r, key, value);
        key.v.str = str_dup("last_query_time");
        value.v.num = wrapper->last_query_time;
        r = mapinsert(r, key, value);
        key.v.str = str_dup("server_version");
        value.v.num = mysql_get_server_version(wrapper->conn);
        r = mapinsert(r, key, value);
        key.v.str = str_dup("in_query");
        if (wrapper->result == NULL)
            value.v.num = 0;
        else
            value.v.num = 1;
    }


    return r;
}

static package bf_mysql_set_options(Var arglist, Byte next, void *vdata, Objid progr) {
    Var opts;
    Var r;
    MYSQL_CONN *wrapper;
    Objid oid = arglist.v.list[1].v.obj;
    wrapper = resolve_mysql_connection(oid);
    if (wrapper == NULL || wrapper->active == 0)
        return make_error_pack(E_INVARG);
    opts = map_dup(arglist.v.list[2]);
    if (opts.type != TYPE_MAP)
        return make_error_pack(E_INVARG);

    free_var(arglist);
    mapforeach(opts, compare_options, (void *) wrapper);
    free_var(opts);
    opts = current_mysql_vars(wrapper, 1);
    return make_var_pack(opts);
    // 

}

static package bf_mysql_status(Var arglist, Byte next, void *vdata, Objid progr) {
    Var r;
    Objid oid = arglist.v.list[1].v.obj;
    free_var(arglist);
    if (!is_wizard(progr))
        return make_error_pack(E_PERM);
    MYSQL_CONN *wrapper;
    wrapper = resolve_mysql_connection(oid);
    if (wrapper == NULL || wrapper->active == 0)
        return make_error_pack(E_INVARG);

    r = current_mysql_vars(wrapper, 0);

    return make_var_pack(r);
}

static package bf_mysql_connections(Var arglist, Byte next, void *vdata, Objid progr) {
    Var r;
    free_var(arglist);
    if (!is_wizard(progr))
        return make_error_pack(E_PERM);
    int count = 0;
    int lcv = 0;
    for (lcv = 0; lcv < MOOSQL_MAX_CON; lcv++)
        if (SQL_CONNECTIONS[lcv].active == 1)
            count++;
    r = new_list(count); /* needed to know how many to allocate the list firstly */
    count = 0;
    for (lcv = 0; lcv < MOOSQL_MAX_CON; lcv++) {
        if (SQL_CONNECTIONS[lcv].active == 1) {
            count++;
            r.v.list[count].type = TYPE_OBJ;
            r.v.list[count].v.obj = SQL_CONNECTIONS[lcv].id;
        }
    }
    return make_var_pack(r);
}

static package bf_mysql_close(Var arglist, Byte next, void *vdata, Objid progr) {
    Var r;
    Objid oid = arglist.v.list[1].v.obj;
    r.type = TYPE_INT;
    free_var(arglist);
    MYSQL_CONN *wrapper;
    if (!is_wizard(progr))
        return make_error_pack(E_PERM);
    wrapper = resolve_mysql_connection(oid);
    if (wrapper == NULL) {
        r.v.num = 0;
        return make_var_pack(r);
    } else {
        wrapper->active = 0;
        wrapper->id = 0;
        wrapper->port = 0;
        wrapper->connect_time = 0;
        wrapper->last_query_time = 0;
        r.v.num = 1;
    }
    if (mysql_connection_status(wrapper) != 0) {
        do_mysql_disconnect(wrapper);
        wrapper->conn = NULL;
        r.v.num = 1;
    }
    return make_var_pack(r);
}

static package bf_mysql_next_row(Var arglist, Byte next, void *vdata, Objid progr) {
    Objid oid = arglist.v.list[1].v.obj;
    MYSQL_CONN *wrapper;
    free_var(arglist);
    int i;

    if (!is_wizard(progr))
        return make_error_pack(E_PERM);

    Var map;
    wrapper = resolve_mysql_connection(oid);
    if (wrapper == NULL)
        return make_error_pack(E_INVARG);

    MYSQL_ROW row;
    if (wrapper->result == NULL)
        row = NULL;
    else
        row = mysql_fetch_row(wrapper->result);
    if (row == NULL) {
        // no more rows. lets free the result set and return 0
        mysql_free_result(wrapper->result);
        wrapper->result = NULL;
        if (wrapper->field_names != NULL) {
            for (i = 0; i < wrapper->field_names_len; i++) {
                free_str(wrapper->field_names[i]);
                wrapper->field_names[i] = NULL;
                wrapper->field_types[i] = 0;
                wrapper->field_flags[i] = 0;

            }
            wrapper->field_names_len = 0;
        }
        map.type = TYPE_INT;
        map.v.num = 0;
        return make_var_pack(map);
    } else {
        // we have a row to display, lets have at it.
        switch (wrapper->row_type) {
            case MODE_KEY_VALUE_PAIR:
                map = process_row_map(wrapper, (const MYSQL_ROW *) row);
                break;
            case MODE_VALUE_LIST:
                map = process_row_list(wrapper, (const MYSQL_ROW *) row);
                break;
        }
        return make_var_pack(map);
    }
}

static package bf_mysql_query(Var arglist, Byte next, void *vdata, Objid progr) {
    Var ret;
    char error_string[MOOSQL_ERROR_LEN];
    MYSQL_CONN *wrapper;
    MYSQL_RES *res_set;
    int qOk = 0;
    if (!is_wizard(progr)) {
        free_var(arglist);
        return make_error_pack(E_PERM);
    }
    Objid oid = arglist.v.list[1].v.obj;
    wrapper = resolve_mysql_connection(oid);

    // the object number given doesn't correspond to an active connection
    if (wrapper == NULL || wrapper->conn == NULL || wrapper->active == 0) {
        free_var(arglist);
        return make_error_pack(E_INVARG);
    }

    // the connection exists but there is a query already being made
    if (wrapper->result != NULL) {
        free_var(arglist);
        return make_error_pack(E_QUOTA);
    }
    const char *query = arglist.v.list[2].v.str;
    free_var(arglist);
    /* we do the query now. */
    if (mysql_query(wrapper->conn, query) != 0) /* failed */ {
        /* there is an error, so we will return that string. similar to below which
         * returns a string for a successful query with no result set which is handled in
         * process_mysql_query */
        snprintf(error_string, MOOSQL_ERROR_LEN, "ERR: %s", mysql_error(wrapper->conn));
        ret.type = TYPE_STR;
        ret.v.str = str_dup(error_string);
        return make_var_pack(ret);
    }
    wrapper->last_query_time = time(0);
    qOk = process_mysql_query(wrapper, error_string);
    if (wrapper->result == NULL || !qOk) /* there was no result on this query */ {
        ret.type = TYPE_STR;
        ret.v.str = str_dup(error_string);
        return make_var_pack(ret);

    } else {
        wrapper->field_names_len = mysql_num_fields(wrapper->result);
        assign_field_names(wrapper);
        int numRows = mysql_num_rows(wrapper->result);
        if (numRows < 1) {
            mysql_free_result(wrapper->result);
            wrapper->result = NULL;
            ret.type = TYPE_ERR;
            ret.v.err = E_NONE;
            return make_var_pack(ret);
        } else {
            ret.type = TYPE_INT;
            ret.v.num = numRows;
            return make_var_pack(ret);
        }
    }

    ;


}

static package
bf_mysql_connect(Var arglist, Byte next, void *vdata, Objid progr) {

#ifdef OUTBOUND_NETWORK
    Var r;
    char error_string[MOOSQL_ERROR_LEN];
    MYSQL_CONN *wrapper;
    if (!is_wizard(progr)) {
        free_var(arglist);
        return make_error_pack(E_PERM);
    }

    const char *hostname = arglist.v.list[1].v.str;
    const int port = arglist.v.list[2].v.num;
    const char *username = arglist.v.list[3].v.str;
    const char *password = arglist.v.list[4].v.str;
    const char *dbname = arglist.v.list[5].v.str;
    free_var(arglist); /* get rid of that now */
    /* try to connect to mysql server */
    /* check if we have enough connection slots. */
    int index = -1;
    index = connection_array_index();
    if (index == -1)
        return make_error_pack(E_QUOTA);
    wrapper = do_mysql_connect(hostname, username, password, dbname, port, NULL, CLIENT_MULTI_STATEMENTS, error_string);
    if (wrapper == NULL || wrapper->conn == NULL) {
        /* an error happened in the connect, return that as a STR */
        r.type = TYPE_STR;
        r.v.str = str_dup(error_string);
        return make_var_pack(r);
    }
    r.type = TYPE_OBJ;
    r.v.obj = wrapper->id;

    // we allow the user to "overload" the default settable options by having
    // a MAP at this location: $server_options.default_mysql_options
    Var serv_opts;
    serv_opts = get_system_property("server_options");
    if (serv_opts.type == TYPE_OBJ && valid(serv_opts.v.obj)) {
        Var value;
        db_prop_handle h;
        h = db_find_property(serv_opts.v.obj, "default_mysql_options", &value);
        if (h.ptr) {
            if (value.type == TYPE_MAP)
                mapforeach(value, compare_options, (void *) wrapper);
                
        }
    }

    return make_var_pack(r);


#else                           /* !OUTBOUND_NETWORK */

    /* This function is disabled in this server. */
    free_var(arglist);
    return make_error_pack(E_PERM);

#endif
}

void register_mysql(void) {
    (void) register_function("mysql_connect", 5, 5, bf_mysql_connect, TYPE_STR, TYPE_INT, TYPE_STR, TYPE_STR, TYPE_STR);
    (void) register_function("mysql_close", 1, 1, bf_mysql_close, TYPE_OBJ);
    (void) register_function("mysql_status", 1, 1, bf_mysql_status, TYPE_OBJ);
    (void) register_function("mysql_query", 2, 2, bf_mysql_query, TYPE_OBJ, TYPE_STR);
    (void) register_function("mysql_connections", 0, 0, bf_mysql_connections);
    (void) register_function("mysql_next_row", 1, 1, bf_mysql_next_row, TYPE_OBJ);
    (void) register_function("mysql_field_names", 1, 1, bf_mysql_fields, TYPE_OBJ);
    (void) register_function("mysql_set_options", 2, 2, bf_mysql_set_options, TYPE_OBJ, TYPE_MAP);
}
