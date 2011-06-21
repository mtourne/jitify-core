#ifndef jitify_nginx_glue_h
#define jitify_nginx_glue_h

/* It's important that these three includes, in this order, are
 * the first things included within all compilation units.  Otherwise,
 * on some platforms (e.g., Fedora 8 on 32-bit x86), off_t gets defined
 * as a different-sized type in mod_jitify than in the nginx core.
 * As key data structures like ngx_http_request_t contain off_t fields,
 * the sizes and field offsets of these structures will be different
 * between the nginx core and mod_jitify, resulting in inscrutable
 * segfaults.
 */
#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_http.h>

#include "jitify.h"

/* Wrapper for an expandable list of buffers */
/* DEPRECATED */
typedef struct {
  ngx_chain_t      *first;
  ngx_chain_t      *last;
  ngx_pool_t       *pool;
} jitify_nginx_chain_t;

typedef struct {
  jitify_pool_t			*pool;
  jitify_lexer_t		*lexer;
  jitify_output_stream_t	*jout;

  ngx_buf_t			*out_buf;

  ngx_chain_t			*out;
  ngx_chain_t			**last_out;
  ngx_chain_t			*busy;
  ngx_chain_t			*free;

  ngx_uint_t			bufs;

  ngx_http_request_t		*request;
} jitify_filter_ctx_t;



jitify_pool_t *jitify_nginx_pool_create(ngx_pool_t *pool);

jitify_output_stream_t *jitify_nginx_output_stream_create(jitify_pool_t *pool);

/* Utility function to allocate, from a pool, a null-terminated copy of one of nginx's pointer/length strings */
char *jitify_nginx_strdup(jitify_pool_t *pool, ngx_str_t *str);

void jitify_nginx_add_eof(jitify_filter_ctx_t *ctx);



#endif /* !defined(jitify_nginx_glue_h) */
