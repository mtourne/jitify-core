/**
 * Copyright (C) 2011 CloudFlare
 * @author Matthieu Tourne <matthieu@cloudflare.com>
 */

#include "ngx_common_conf.h"

#define LOG_BUF_SZ 128

u_char      ngx_common_conf_log_buf[LOG_BUF_SZ];


char*
ngx_common_conf_complex_value_slot(ngx_conf_t *cf,
                                   ngx_command_t *cmd,
                                   void *conf) {

    char                                *p = conf;

    ngx_http_compile_complex_value_t    ccv;
    ngx_http_complex_value_t            *cv;
    ngx_str_t                           *value;
    ngx_conf_post_t                     *post;

    cv = (ngx_http_complex_value_t *) (p + cmd->offset);

    value = cf->args->elts;

    ngx_memzero(&ccv, sizeof(ngx_http_compile_complex_value_t));

    ccv.cf = cf;
    ccv.value = &value[1];
    ccv.complex_value = cv;

    if (ngx_http_compile_complex_value(&ccv) != NGX_OK) {
        return NGX_CONF_ERROR;
    }

    if (cmd->post) {
        post = cmd->post;
        return  post->post_handler(cf, post, cv);
    }

    return NGX_CONF_OK;
}

char*
ngx_common_conf_varval_slot(ngx_conf_t *cf,
                            ngx_command_t *cmd,
                            void* conf) {

    char                        *p = conf;

    ngx_common_varval_t         *vval;
    ngx_str_t                   *value;
    ngx_conf_post_t             *post;
    char                        *rc;

    vval = (ngx_common_varval_t *) (p + cmd->offset);

    value = cf->args->elts;

    rc = ngx_common_conf_varval_set(cf, vval, &value[1]);
    if (rc != NGX_CONF_OK) {
        return rc;
    }

    if (cmd->post) {
        post = cmd->post;
        return post->post_handler(cf, post, vval);
    }

    return NGX_CONF_OK;
}

char*
ngx_common_conf_varval_add_checker(ngx_conf_t *cf, void *data, void* conf) {
    ngx_common_varval_post_t    *vval_post = data;
    ngx_common_varval_t         *vval = conf;

    vval->checker = vval_post->checker;
    if (vval->type == value
        && vval->checker
        && vval->checker(cf->log, vval, vval->value) != NGX_OK) {
        return NGX_CONF_ERROR;
    }
    return NGX_CONF_OK;
}

/*
 * set a varval at configuration time
 *
 * Note: potential getter and checker functions
 *  must be defined prior to using varval_set()
 */
char*
ngx_common_conf_varval_set(ngx_conf_t *cf,
                           ngx_common_varval_t *vval,
                           ngx_str_t *conf_value) {
    if (vval->type != unset) {
        return "is duplicate";
    }
    if (conf_value->data[0] == '$') {
        ngx_common_var_t        *v;
        /* variable */

        vval->type = var;

        conf_value->len--;
        conf_value->data++;

        v = &vval->var;
        v->name = *conf_value;

        v->index = ngx_http_get_variable_index(cf, conf_value);
        if (v->index == NGX_ERROR) {
            return NGX_CONF_ERROR;
        }
    } else {
        /* value */
        vval->type = value;

        if (vval->getter) {
            if (vval->getter(cf->log, vval, conf_value) != NGX_OK) {
                return NGX_CONF_ERROR;
            }
        } else {
            /* if no specific getter is set
             * process data as numeric value
             */

            vval->value = ngx_atoi(conf_value->data, conf_value->len);
            if (vval->value == (ngx_uint_t) NGX_ERROR) {
                return NGX_CONF_ERROR;
            }
        }

        /* check a numeric value right away at conf time */
        if (vval->checker &&
            vval->checker(cf->log, vval, vval->value) != NGX_OK) {
            return NGX_CONF_ERROR;
        }
    }
    return NGX_CONF_OK;
}

/*
 * get a varval at runtime
 *
 * Warning: if a specialized getter is used vval->value must be used,
 *
 * TODO (mtourne): cleanup and use only ret for return code
 */
ngx_int_t
ngx_common_get_varval(ngx_http_request_t *r,
                      ngx_common_varval_t *vval) {
    ngx_http_variable_value_t   *vv;
    ngx_int_t                   ret = NGX_OK;
    ngx_str_t                   raw_value;

    switch (vval->type) {
        case value:
            ret = vval->value;
            /* for a value checker and getter should have
             * been called at config time before set_varval()
             */
            return ret;

        case var:
            vv = ngx_http_get_indexed_variable(r, vval->var.index);
            if (vv != NULL && vval->getter) {
                raw_value.data = vv->data;
                raw_value.len = vv->len;
                if (vval->getter(r->connection->log, vval, &raw_value) != NGX_OK) {
                    return NGX_ERROR;
                }
            } else {
                /* make quick tests for 0 or 1 (useful for on/off switches)
                 * and atoi for everything else
                 */
                if (vv == NULL || vv->not_found || vv->len < 1 || vv->data[0] == '0') {
                    ret = 0;
                } else if (vv->len == 1 && vv->data[0] == '1') {
                    ret = 1;
                } else {
                    ret = ngx_atoi(vv->data, vv->len);
                }
                vval->value = ret;
            }
            if (vval->checker &&
                vval->checker(r->connection->log, vval, ret) != NGX_OK) {
                /* if a checker function is defined execute it */
                return NGX_ERROR;
            }
            return ret;

        case unset:
        default:
            ngx_log_error(NGX_LOG_NOTICE, r->connection->log, 0,
                          "using undefined varval");
                return NGX_ERROR;
    }

    /* impossible code path */
    return NGX_ERROR;
}

char*
ngx_common_varval_log(ngx_common_varval_t *vval) {
    switch (vval->type) {
        case value:
            return "varval value";
        case var:
            ngx_snprintf(ngx_common_conf_log_buf, LOG_BUF_SZ,
                             "varval variable \"%V\"",
                             &vval->var.name);
            return (char *) ngx_common_conf_log_buf;
        case unset:
            return "varval unset";
        default:
            return "unknown varval type";
    }
}
