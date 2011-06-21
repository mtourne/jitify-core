#define JITIFY_INTERNAL
#include "jitify_nginx_glue.h"

#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_http.h>

#include <ngx_common_conf.h>

#define JITIFY_JS_ON    (1 << 0)
#define JITIFY_CSS_ON   (1 << 1)
#define JITIFY_HTML_ON  (1 << 2)

static ngx_http_output_header_filter_pt jitify_next_header_filter;
static ngx_http_output_body_filter_pt   jitify_next_body_filter;

ngx_module_t jitify_module;

static ngx_str_t jitify_js_default_types[] = {
    ngx_string("text/javascript"),
    ngx_string("application/javascript"),
    ngx_string("application/x-javascript"),
    ngx_null_string
};

static ngx_str_t jitify_css_default_types[] = {
    ngx_string("text/css"),
    ngx_null_string
};

typedef struct {
    ngx_common_varval_t minify;

    ngx_hash_t		html_types;
    ngx_array_t		*html_types_keys;

    ngx_hash_t		css_types;
    ngx_array_t		*css_types_keys;

    ngx_hash_t		js_types;
    ngx_array_t		*js_types_keys;
} jitify_conf_t;

typedef jitify_lexer_t *(*create_lexer_t)(jitify_pool_t *pool, jitify_output_stream_t *out);

static ngx_int_t jitify_output(ngx_http_request_t *r, jitify_filter_ctx_t *ctx);

static ngx_int_t
jitify_create_lexer(ngx_http_request_t *r, create_lexer_t create_func) {
    jitify_filter_ctx_t         *ctx;

    ctx = ngx_pcalloc(r->pool, sizeof(jitify_filter_ctx_t));
    if (ctx == NULL) {
        return NGX_ERROR;
    }
    ctx->pool = jitify_nginx_pool_create(r->pool);
    ctx->jout = jitify_nginx_output_stream_create(ctx->pool);
    ctx->lexer = create_func(ctx->pool, ctx->jout);
    ctx->last_out = &ctx->out;
    ctx->request = r;

    if (ctx->lexer == NULL) {
        return NGX_ERROR;
    }

    ngx_log_debug2(NGX_LOG_DEBUG, r->connection->log, 0,
                  "jitify: enabling content scanning for uri=%V content-type=%V",
                  &(r->uri), &(r->headers_out.content_type));

    ngx_http_clear_content_length(r);
    ngx_http_clear_last_modified(r);
    ngx_http_clear_accept_ranges(r);

    /* TODO (mtourne): add option for remove_space and remove_comment */
    jitify_lexer_set_minify_rules(ctx->lexer, 1, 1);
    ngx_http_set_ctx(r, ctx, jitify_module);

    r->main_filter_need_in_memory = 1;

    return NGX_OK;
}

static ngx_int_t jitify_header_filter(ngx_http_request_t *r)
{
  ngx_log_t *log = r->connection->log;

  jitify_conf_t         *jconf;
  ngx_int_t             minify;

  if (r != r->main) {
      return jitify_next_header_filter(r);
  }

  jconf = ngx_http_get_module_loc_conf(r, jitify_module);
  if (jconf == NULL) {
      ngx_log_error(NGX_LOG_WARN, log, 0, "internal error: mod_jitify configuration missing");
      return jitify_next_header_filter(r);
  }

  minify = ngx_common_get_varval(r, &jconf->minify);
  if (minify == 0) {
      return jitify_next_header_filter(r);
  }

  if (minify & JITIFY_JS_ON) {
      /* check for js */
      if (ngx_http_test_content_type(r, &jconf->js_types) != NULL) {
          if (jitify_create_lexer(r, jitify_js_lexer_create) != NGX_OK) {
              return NGX_ERROR;
          }
          return jitify_next_header_filter(r);
      }
  }

  if (minify & JITIFY_CSS_ON) {
      /* check for css */
      if (ngx_http_test_content_type(r, &jconf->css_types) != NULL) {
          if (jitify_create_lexer(r, jitify_css_lexer_create) != NGX_OK) {
              return NGX_ERROR;
          }
          return jitify_next_header_filter(r);
      }
  }

  if (minify & JITIFY_HTML_ON) {
      /* check for html */
      if (ngx_http_test_content_type(r, &jconf->html_types) != NULL) {
          if (jitify_create_lexer(r, jitify_html_lexer_create) != NGX_OK) {
              return NGX_ERROR;
          }
          return jitify_next_header_filter(r);
      }
  }

  ngx_log_error(NGX_LOG_DEBUG, log, 0, "no lexer for uri=%V content-type=%V",
                    &(r->uri), &(r->headers_out.content_type));

  return jitify_next_header_filter(r);
}

#define DEFAULT_ERR_LEN 80

static ngx_int_t jitify_body_filter(ngx_http_request_t *r, ngx_chain_t *in)
{
  ngx_log_t		*log = r->connection->log;
  jitify_filter_ctx_t	*jctx;
  int			send_flush;
  int			send_eof;

  jctx = ngx_http_get_module_ctx(r->main, jitify_module);

  if (jctx == NULL || jctx->lexer == NULL) {
    return jitify_next_body_filter(r, in);
  }

  ngx_log_debug1(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
		 "jitify body filter \"%V\"", &r->uri);

  jctx->jout->state = jctx;
  send_flush = send_eof = 0;

  while (in) {

    ngx_buf_t *buf = in->buf;

    if (buf->last_buf) {
      send_eof = 1;
    }

    if (buf->last_buf || (buf->last > buf->pos)) {
      const char *err;

      jitify_lexer_scan(jctx->lexer, buf->pos, buf->last - buf->pos, buf->last_buf);
      err = jitify_lexer_get_err(jctx->lexer);

      if (err) {
        char err_buf[DEFAULT_ERR_LEN + 1];
        size_t err_len = DEFAULT_ERR_LEN;
        size_t max_err_len = (const char*)(buf->last) - err;
        if (err_len > max_err_len) {
          err_len = max_err_len;
        }
        memcpy(err_buf, err, err_len);
        err_buf[err_len] = 0;
        ngx_log_error(NGX_LOG_WARN, log, 0, "parse error in %V near '%s', entering failsafe mode", &(r->uri), err_buf);
      }
    }

    if (buf->flush) {
      send_flush = 1;
    }

    /* Setting buf->pos=buf->last enables the nginx core to recycle this buffer */
    if (buf->pos < buf->last) {
      buf->pos = buf->last;
    }

    in = in->next;
  }

  if (send_eof) {

    size_t processing_time_in_usec = jitify_lexer_get_processing_time(jctx->lexer);
    size_t bytes_in = jitify_lexer_get_bytes_in(jctx->lexer);
    size_t bytes_out = jitify_lexer_get_bytes_out(jctx->lexer);

    ngx_log_error(NGX_LOG_INFO, log, 0, "jitify stats: bytes_in=%l bytes_out=%l, nsec/byte=%l, bufs=%d for %V",
		  (long)bytes_in, (long)bytes_out,
		  (long)(bytes_in ? processing_time_in_usec * 1000 / bytes_in : 0),
		  jctx->bufs,
		  &(r->uri));

    jitify_nginx_add_eof(jctx);
  }

  if (send_flush && jctx->out_buf) {
    jctx->out_buf->flush = 1;
  }

  if (jctx->out == NULL && jctx->busy == NULL) {
    return NGX_OK;
  }

  return jitify_output(r, jctx);
}

static ngx_int_t
jitify_output(ngx_http_request_t *r, jitify_filter_ctx_t *ctx) {
  ngx_int_t	rc;
  ngx_chain_t	*cl;
  ngx_buf_t	*b;

#if 1
  b = NULL;
  for (cl = ctx->out; cl; cl = cl->next) {
    ngx_log_debug2(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
		   "jitify out: %p %p", cl->buf, cl->buf->pos);
    if (cl->buf == b) {
      ngx_log_error(NGX_LOG_ALERT, r->connection->log, 0,
		    "the same buf was used in jitify");
      ngx_debug_point();
      return NGX_ERROR;
    }
    b = cl->buf;
  }
#endif

  rc = jitify_next_body_filter(r, ctx->out);

  ngx_chain_update_chains(&ctx->free, &ctx->busy, &ctx->out,
			  (ngx_buf_tag_t) &jitify_module);

  ctx->last_out = &ctx->out;
  ctx->out_buf = NULL;

  return rc;
}

static ngx_int_t jitify_post_config(ngx_conf_t *cf)
{
  jitify_next_header_filter = ngx_http_top_header_filter;
  ngx_http_top_header_filter = jitify_header_filter;
  jitify_next_body_filter = ngx_http_top_body_filter;
  ngx_http_top_body_filter = jitify_body_filter;
  return NGX_OK;
}

static void *jitify_create_conf(ngx_conf_t *cf)
{
  jitify_conf_t *conf;

  conf = ngx_pcalloc(cf->pool, sizeof(*conf));

  if (conf == NULL) {
      return NULL;
  }

  return conf;
}

static char *jitify_merge_conf(ngx_conf_t *cf, void *parent, void *child)
{
  jitify_conf_t *prev = parent;
  jitify_conf_t *conf = child;

  ngx_common_conf_merge_varval(conf->minify, prev->minify, 0);

  if (NGX_OK != ngx_http_merge_types(cf, &conf->html_types_keys, &conf->html_types,
                                     &prev->html_types_keys, &prev->html_types,
                                     ngx_http_html_default_types)) {
      return NGX_CONF_ERROR;
  }

  if (NGX_OK != ngx_http_merge_types(cf, &conf->js_types_keys, &conf->js_types,
                                     &prev->js_types_keys, &prev->js_types,
                                     jitify_js_default_types)) {
      return NGX_CONF_ERROR;
  }

  if (NGX_OK != ngx_http_merge_types(cf, &conf->css_types_keys, &conf->css_types,
                                     &prev->css_types_keys, &prev->css_types,
                                     jitify_css_default_types)) {
      return NGX_CONF_ERROR;
  }

  return NGX_CONF_OK;
}

static ngx_http_module_t jitify_module_ctx = {
  NULL,                     /* pre-config                            */
  jitify_post_config,       /* post-config                           */
  NULL,                     /* create main (top-level) config struct */
  NULL,                     /* init main (top-level) config struct   */
  NULL,                     /* create server-level config struct     */
  NULL,                     /* merge server-level config struct      */
  jitify_create_conf,       /* create location-level config struct   */
  jitify_merge_conf         /* merge location-level config struct    */
};

static ngx_command_t jitify_commands[] = {
  {
    ngx_string("jitify"),
    NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_TAKE1,
    ngx_common_conf_varval_slot,
    NGX_HTTP_LOC_CONF_OFFSET,
    offsetof(jitify_conf_t, minify),
    NULL
  },

  { ngx_string("jitify_html_types"),
    NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_1MORE,
    ngx_http_types_slot,
    NGX_HTTP_LOC_CONF_OFFSET,
    offsetof(jitify_conf_t, html_types_keys),
    &ngx_http_html_default_types[0] },

  { ngx_string("jitify_js_types"),
    NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_1MORE,
    ngx_http_types_slot,
    NGX_HTTP_LOC_CONF_OFFSET,
    offsetof(jitify_conf_t, js_types_keys),
    &jitify_js_default_types[0] },

  { ngx_string("jitify_css_types"),
    NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_1MORE,
    ngx_http_types_slot,
    NGX_HTTP_LOC_CONF_OFFSET,
    offsetof(jitify_conf_t, css_types_keys),
    &jitify_css_default_types[0] },

  ngx_null_command
};

ngx_module_t jitify_module = {
  NGX_MODULE_V1,
  &jitify_module_ctx,
  jitify_commands,
  NGX_HTTP_MODULE,
  NULL,                     /* init master     */
  NULL,                     /* init module     */
  NULL,                     /* init process    */
  NULL,                     /* init thread     */
  NULL,                     /* cleanup thread  */
  NULL,                     /* cleanup process */
  NULL,                     /* cleanup master  */
  NGX_MODULE_V1_PADDING
};
