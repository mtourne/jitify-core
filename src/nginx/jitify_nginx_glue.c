#define JITIFY_INTERNAL
#include "jitify_nginx_glue.h"

#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_http.h>

extern ngx_module_t jitify_module;

static void *nginx_malloc_wrapper(jitify_pool_t *pool, size_t len)
{
  return ngx_palloc(pool->state, len);
}

static void *nginx_calloc_wrapper(jitify_pool_t *pool, size_t len)
{
  return ngx_pcalloc(pool->state, len);
}

static void nginx_free_wrapper(jitify_pool_t *pool, void *block)
{
}

jitify_pool_t *jitify_nginx_pool_create(ngx_pool_t *pool)
{
  jitify_pool_t *jpool = ngx_pcalloc(pool, sizeof(*jpool));
  jpool->state = pool;
  jpool->malloc = nginx_malloc_wrapper;
  jpool->calloc = nginx_calloc_wrapper;
  jpool->free = nginx_free_wrapper;
  return jpool;
}

static int nginx_buf_write(jitify_output_stream_t *stream, const void *data, size_t len)
{
  jitify_filter_ctx_t	*ctx = stream->state;
  const char		*cdata = data;
  ngx_http_request_t	*r = ctx->request;
  size_t		bytes_remaining;
  size_t		write_size;
  ngx_chain_t		*cl;

  if (!data) {
    return 0;
  }

  bytes_remaining = len;

  while (bytes_remaining) {

    if (ctx->out_buf == NULL  
	|| !ctx->out_buf->temporary
	|| ctx->out_buf->last >= ctx->out_buf->end) {
      if (ctx->free) {
	ngx_log_debug2(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
		       "jitify filter using free chain link: %p buf: %p", 
		       ctx->free, ctx->free->buf);
	cl = ctx->free;
	ctx->free = ctx->free->next;
	ctx->out_buf = cl->buf;

      } else {
	ctx->out_buf = ngx_create_temp_buf(r->pool, ngx_pagesize);
	if (ctx->out_buf == NULL) {
	  ngx_log_error(NGX_LOG_CRIT, r->connection->log, 0, 
			"jitify filter unable to alloc mem");
	  return 0;
	}
	
	cl = ngx_alloc_chain_link(r->pool);
	if (cl == NULL) {
	  ngx_log_error(NGX_LOG_CRIT, r->connection->log, 0, 
			"jitify filter unable to alloc mem");
	  return 0;
	}
	ctx->out_buf->tag = (ngx_buf_tag_t) &jitify_module;
	cl->buf = ctx->out_buf;
      }

      cl->next = NULL;
      *ctx->last_out = cl;
      ctx->last_out = &cl->next;
      ctx->bufs++;
    }

    write_size = ctx->out_buf->end - ctx->out_buf->last;
    if (write_size > bytes_remaining) {
      write_size = bytes_remaining;
    }
    ngx_memcpy(ctx->out_buf->last, cdata, write_size);
    cdata += write_size;
    ctx->out_buf->last += write_size;
    bytes_remaining -= write_size;
  }
    
  return len;
}

jitify_output_stream_t *jitify_nginx_output_stream_create(jitify_pool_t *pool)
{
  jitify_output_stream_t *stream = jitify_calloc(pool, 
						 sizeof(jitify_output_stream_t));

  stream->pool = pool;
  stream->write = nginx_buf_write;
  return stream;
}

char *jitify_nginx_strdup(jitify_pool_t *pool, ngx_str_t *str)
{
  size_t len;
  char *buf;

  if (!str || !str->data) {
    return NULL;
  }
  len = str->len;
  buf = jitify_malloc(pool, len + 1);
  memcpy(buf, str->data, len);
  buf[len] = 0;
  return buf;
}

void jitify_nginx_add_eof(jitify_filter_ctx_t *ctx)
{
  ngx_chain_t	*cl = ngx_pcalloc(ctx->request->pool, sizeof(ngx_chain_t));
  ngx_buf_t	*b = ngx_calloc_buf(ctx->request->pool);

  b->last_buf = 1;
  b->sync = 1;

  cl->buf = b;
  *ctx->last_out = cl;
  ctx->last_out = &cl->next;
}
