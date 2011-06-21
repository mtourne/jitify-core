/**
 * Copyright (C) 2011 CloudFlare
 * @author Matthieu Tourne <matthieu@cloudflare.com>
 */

#ifndef _NGX_COMMON_CONF_H_
#define _NGX_COMMON_CONF_H_

#include <nginx.h>
#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_http.h>

struct ngx_common_varval_s;

typedef ngx_int_t (*ngx_common_val_checker_pt)(
    ngx_log_t *log, struct ngx_common_varval_s *vval, ngx_int_t val);

/* getter should return NGX_OK or NGX_ERROR for status
 * and set vval->data.value to return a value
 */
typedef ngx_int_t (*ngx_common_val_getter_pt)(
    ngx_log_t *log, struct ngx_common_varval_s *vval, ngx_str_t *value);

typedef enum {
    unset = 0,
    value,
    var
} ngx_common_varval_type_t;

typedef struct {
    ngx_int_t   index;
    ngx_str_t   name;
} ngx_common_var_t;

typedef struct ngx_common_varval_s {
    ngx_common_var_t            var;
    uintptr_t                   value;

    ngx_common_varval_type_t    type;

    ngx_common_val_checker_pt   checker;

    ngx_common_val_getter_pt    getter;
    void                        *getter_data;
} ngx_common_varval_t;

typedef struct  {
    /* post handler needs to be first */
    ngx_conf_post_handler_pt    post_handler;
    ngx_common_val_checker_pt   checker;
} ngx_common_varval_post_t;

#define ngx_common_conf_merge_varval(_conf, _prev, _default_val)        \
    if (_conf.type == unset) {                                          \
        if (_prev.type == unset) {                                      \
            _conf.type = value;                                         \
            _conf.value = _default_val;                                 \
        } else {                                                        \
            ngx_memcpy(&_conf, &_prev, sizeof(ngx_common_varval_t));    \
        }                                                               \
    }

char* ngx_common_conf_complex_value_slot(ngx_conf_t *cf,
                                         ngx_command_t *cmd,
                                         void *conf);

char* ngx_common_conf_varval_slot(ngx_conf_t *cf,
                                 ngx_command_t *cmd,
                                 void* conf);

char* ngx_common_conf_varval_add_checker(ngx_conf_t *cf,
                                         void *data,
                                         void* conf);

char* ngx_common_conf_varval_set(ngx_conf_t *cf,
                                 ngx_common_varval_t *vval,
                                 ngx_str_t *conf_value);

ngx_int_t ngx_common_get_varval(ngx_http_request_t *r,
                                ngx_common_varval_t *vval);

char* ngx_common_varval_log(ngx_common_varval_t *vval);

#endif /* !_NGX_COMMON_CONF_H_ */
