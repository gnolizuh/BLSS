
/*
 * Copyright (C) Roman Arutyunyan
 */


#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_rtmp.h>
#include <ngx_rtmp_cmd_module.h>
#include <ngx_rtmp_codec_module.h>
#include "ngx_rtmp_hls_module.h"
#include "ngx_rtmp_live_module.h"
#include "ngx_rtmp_notify_module.h"
#include "ngx_rtmp_mpegts.h"
#include "ngx_rtmp_log_module.h"

static ngx_rtmp_publish_pt              next_publish;
static ngx_rtmp_play_pt                 next_play;
static ngx_rtmp_close_stream_pt         next_close_stream;
static ngx_rtmp_stream_begin_pt         next_stream_begin;
static ngx_rtmp_stream_eof_pt           next_stream_eof;


static char * ngx_rtmp_hls_variant(ngx_conf_t *cf, ngx_command_t *cmd,
       void *conf);
static ngx_int_t ngx_rtmp_hls_postconfiguration(ngx_conf_t *cf);
static void * ngx_rtmp_hls_create_app_conf(ngx_conf_t *cf);
static char * ngx_rtmp_hls_merge_app_conf(ngx_conf_t *cf,
       void *parent, void *child);
static ngx_int_t ngx_rtmp_hls_flush_audio(ngx_rtmp_session_t *s);
static ngx_int_t ngx_rtmp_hls_ensure_directory(ngx_rtmp_session_t *s);

static void * ngx_rtmp_http_hls_create_conf(ngx_conf_t *cf);
static char * ngx_rtmp_http_hls_merge_conf(ngx_conf_t *cf, void *parent, void *child);
static ngx_chain_t *ngx_rtmp_hls_proxy_create(ngx_rtmp_session_t *s, void *arg, ngx_pool_t *pool);
static ngx_int_t ngx_rtmp_hls_proxy_handle(ngx_rtmp_session_t *s, void *arg, ngx_chain_t *in);
static ngx_int_t ngx_rtmp_http_hls_play_local(ngx_http_request_t *r);
static ngx_int_t ngx_rtmp_http_hls_handler(ngx_http_request_t *r);
static ngx_int_t ngx_rtmp_http_hls_init(ngx_conf_t *cf);
static ngx_url_t *ngx_rtmp_parse_http_url(ngx_http_request_t *r, ngx_str_t *url);
static ngx_int_t ngx_rtmp_http_hls_change_uri(ngx_http_request_t *r, ngx_str_t unique_name, ngx_rtmp_hls_app_conf_t *hacf);
static ngx_int_t ngx_rtmp_hls_open_file(ngx_http_request_t *r, ngx_chain_t *out);
static ngx_int_t ngx_rtmp_http_hls_get_info(ngx_str_t *uri, ngx_str_t *app, ngx_str_t *name, ngx_str_t *fname);
static ngx_int_t ngx_rtmp_hls_flush_expire(ngx_rtmp_session_t *s);
static ngx_int_t ngx_rtmp_hls_read_expire(ngx_str_t *path, ngx_msec_t *out_expire);

extern void ngx_rtmp_close_connection(ngx_connection_t *c);
extern void ngx_rtmp_codec_dump_header(ngx_rtmp_session_t *s, const char *type,
            ngx_chain_t *in);

ngx_str_t   ngx_rtmp_hls_urlencoded = ngx_string("application/x-www-form-urlencoded");
ngx_uint_t  ngx_rtmp_hls_naccepted;

typedef struct {
    ngx_flag_t                          hls;
} ngx_rtmp_http_hls_loc_conf_t;

typedef struct {
    ngx_str_t                           path;
    ngx_msec_t                          hls_playlist_length;
    ngx_flag_t                          continuous;
} ngx_rtmp_hls_cleanup_t;


#define NGX_RTMP_HLS_NAMING_SEQUENTIAL         1
#define NGX_RTMP_HLS_NAMING_TIMESTAMP          2
#define NGX_RTMP_HLS_NAMING_SYSTEM             3
#define NGX_RTMP_HLS_NAMING_TIMESTAMP_SEQ      4


#define NGX_RTMP_HLS_SLICING_PLAIN             1
#define NGX_RTMP_HLS_SLICING_ALIGNED           2


#define NGX_RTMP_HLS_TYPE_LIVE                 1
#define NGX_RTMP_HLS_TYPE_EVENT                2

static ngx_conf_enum_t                  ngx_rtmp_hls_naming_slots[] = {
    { ngx_string("sequential"),         NGX_RTMP_HLS_NAMING_SEQUENTIAL    },
    { ngx_string("timestamp"),          NGX_RTMP_HLS_NAMING_TIMESTAMP     },
    { ngx_string("system"),             NGX_RTMP_HLS_NAMING_SYSTEM        },
    { ngx_string("timestamp_seq"),      NGX_RTMP_HLS_NAMING_TIMESTAMP_SEQ },
    { ngx_null_string,                  0 }
};


static ngx_conf_enum_t                  ngx_rtmp_hls_slicing_slots[] = {
    { ngx_string("plain"),              NGX_RTMP_HLS_SLICING_PLAIN },
    { ngx_string("aligned"),            NGX_RTMP_HLS_SLICING_ALIGNED  },
    { ngx_null_string,                  0 }
};


static ngx_conf_enum_t                  ngx_rtmp_hls_type_slots[] = {
    { ngx_string("live"),               NGX_RTMP_HLS_TYPE_LIVE  },
    { ngx_string("event"),              NGX_RTMP_HLS_TYPE_EVENT },
    { ngx_null_string,                  0 }
};


typedef struct {
    size_t                buffer_size;
    size_t                max_buffer_size;
} ngx_http_mp4_conf_t;


static ngx_command_t  ngx_rtmp_http_hls_commands[] = {

    { ngx_string("hls"),
      NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_TAKE1,
      ngx_conf_set_flag_slot,
      NGX_HTTP_LOC_CONF_OFFSET,
      offsetof(ngx_rtmp_http_hls_loc_conf_t, hls),
      NULL },

      ngx_null_command
};


static ngx_http_module_t  ngx_rtmp_http_hls_module_ctx = {
    NULL,                          /* preconfiguration */
    ngx_rtmp_http_hls_init,        /* postconfiguration */

    NULL,                          /* create main configuration */
    NULL,                          /* init main configuration */

    NULL,                          /* create server configuration */
    NULL,                          /* merge server configuration */

    ngx_rtmp_http_hls_create_conf, /* create location configuration */
    ngx_rtmp_http_hls_merge_conf   /* merge location configuration */
};


ngx_module_t  ngx_rtmp_http_hls_module = {
    NGX_MODULE_V1,
    &ngx_rtmp_http_hls_module_ctx, /* module context */
    ngx_rtmp_http_hls_commands,    /* module directives */
    NGX_HTTP_MODULE,               /* module type */
    NULL,                          /* init master */
    NULL,                          /* init module */
    NULL,                          /* init process */
    NULL,                          /* init thread */
    NULL,                          /* exit thread */
    NULL,                          /* exit process */
    NULL,                          /* exit master */
    NGX_MODULE_V1_PADDING
};


static ngx_command_t ngx_rtmp_hls_commands[] = {

    { ngx_string("hls"),
      NGX_RTMP_MAIN_CONF|NGX_RTMP_SRV_CONF|NGX_RTMP_APP_CONF|NGX_CONF_TAKE1,
      ngx_conf_set_flag_slot,
      NGX_RTMP_APP_CONF_OFFSET,
      offsetof(ngx_rtmp_hls_app_conf_t, hls),
      NULL },

    { ngx_string("hls_fragment"),
      NGX_RTMP_MAIN_CONF|NGX_RTMP_SRV_CONF|NGX_RTMP_APP_CONF|NGX_CONF_TAKE1,
      ngx_conf_set_msec_slot,
      NGX_RTMP_APP_CONF_OFFSET,
      offsetof(ngx_rtmp_hls_app_conf_t, hls_fragment),
      NULL },

    { ngx_string("hls_fragment_wave"),
        NGX_RTMP_MAIN_CONF|NGX_RTMP_SRV_CONF|NGX_RTMP_APP_CONF|NGX_CONF_TAKE1,
        ngx_conf_set_num_slot,
        NGX_RTMP_APP_CONF_OFFSET,
        offsetof(ngx_rtmp_hls_app_conf_t, hls_fragment_wave),
        NULL },

    { ngx_string("hls_playlist_length"),
      NGX_RTMP_MAIN_CONF|NGX_RTMP_SRV_CONF|NGX_RTMP_APP_CONF|NGX_CONF_TAKE1,
      ngx_conf_set_msec_slot,
      NGX_RTMP_APP_CONF_OFFSET,
      offsetof(ngx_rtmp_hls_app_conf_t, hls_playlist_length),
      NULL },

    { ngx_string("hls_max_fragment"),
      NGX_RTMP_MAIN_CONF|NGX_RTMP_SRV_CONF|NGX_RTMP_APP_CONF|NGX_CONF_TAKE1,
      ngx_conf_set_msec_slot,
      NGX_RTMP_APP_CONF_OFFSET,
      offsetof(ngx_rtmp_hls_app_conf_t, max_fraglen),
      NULL },

    { ngx_string("hls_path"),
      NGX_RTMP_MAIN_CONF|NGX_RTMP_SRV_CONF|NGX_RTMP_APP_CONF|NGX_CONF_TAKE1,
      ngx_conf_set_str_slot,
      NGX_RTMP_APP_CONF_OFFSET,
      offsetof(ngx_rtmp_hls_app_conf_t, path),
      NULL },

    { ngx_string("hls_muxdelay"),
      NGX_RTMP_MAIN_CONF|NGX_RTMP_SRV_CONF|NGX_RTMP_APP_CONF|NGX_CONF_TAKE1,
      ngx_conf_set_msec_slot,
      NGX_RTMP_APP_CONF_OFFSET,
      offsetof(ngx_rtmp_hls_app_conf_t, muxdelay),
      NULL },

    { ngx_string("hls_sync"),
      NGX_RTMP_MAIN_CONF|NGX_RTMP_SRV_CONF|NGX_RTMP_APP_CONF|NGX_CONF_TAKE1,
      ngx_conf_set_msec_slot,
      NGX_RTMP_APP_CONF_OFFSET,
      offsetof(ngx_rtmp_hls_app_conf_t, sync),
      NULL },

    { ngx_string("hls_continuous"),
      NGX_RTMP_MAIN_CONF|NGX_RTMP_SRV_CONF|NGX_RTMP_APP_CONF|NGX_CONF_TAKE1,
      ngx_conf_set_flag_slot,
      NGX_RTMP_APP_CONF_OFFSET,
      offsetof(ngx_rtmp_hls_app_conf_t, continuous),
      NULL },

    { ngx_string("hls_nested"),
      NGX_RTMP_MAIN_CONF|NGX_RTMP_SRV_CONF|NGX_RTMP_APP_CONF|NGX_CONF_TAKE1,
      ngx_conf_set_flag_slot,
      NGX_RTMP_APP_CONF_OFFSET,
      offsetof(ngx_rtmp_hls_app_conf_t, nested),
      NULL },

    { ngx_string("hls_fragment_naming"),
      NGX_RTMP_MAIN_CONF|NGX_RTMP_SRV_CONF|NGX_RTMP_APP_CONF|NGX_CONF_TAKE1,
      ngx_conf_set_enum_slot,
      NGX_RTMP_APP_CONF_OFFSET,
      offsetof(ngx_rtmp_hls_app_conf_t, naming),
      &ngx_rtmp_hls_naming_slots },

    { ngx_string("hls_fragment_slicing"),
      NGX_RTMP_MAIN_CONF|NGX_RTMP_SRV_CONF|NGX_RTMP_APP_CONF|NGX_CONF_TAKE1,
      ngx_conf_set_enum_slot,
      NGX_RTMP_APP_CONF_OFFSET,
      offsetof(ngx_rtmp_hls_app_conf_t, slicing),
      &ngx_rtmp_hls_slicing_slots },

    { ngx_string("hls_type"),
      NGX_RTMP_MAIN_CONF|NGX_RTMP_SRV_CONF|NGX_RTMP_APP_CONF|NGX_CONF_TAKE1,
      ngx_conf_set_enum_slot,
      NGX_RTMP_APP_CONF_OFFSET,
      offsetof(ngx_rtmp_hls_app_conf_t, type),
      &ngx_rtmp_hls_type_slots },

    { ngx_string("hls_max_audio_delay"),
      NGX_RTMP_MAIN_CONF|NGX_RTMP_SRV_CONF|NGX_RTMP_APP_CONF|NGX_CONF_TAKE1,
      ngx_conf_set_msec_slot,
      NGX_RTMP_APP_CONF_OFFSET,
      offsetof(ngx_rtmp_hls_app_conf_t, max_audio_delay),
      NULL },

    { ngx_string("hls_audio_buffer_size"),
      NGX_RTMP_MAIN_CONF|NGX_RTMP_SRV_CONF|NGX_RTMP_APP_CONF|NGX_CONF_TAKE1,
      ngx_conf_set_size_slot,
      NGX_RTMP_APP_CONF_OFFSET,
      offsetof(ngx_rtmp_hls_app_conf_t, audio_buffer_size),
      NULL },

    { ngx_string("hls_cleanup"),
      NGX_RTMP_MAIN_CONF|NGX_RTMP_SRV_CONF|NGX_RTMP_APP_CONF|NGX_CONF_TAKE1,
      ngx_conf_set_flag_slot,
      NGX_RTMP_APP_CONF_OFFSET,
      offsetof(ngx_rtmp_hls_app_conf_t, cleanup),
      NULL },

    { ngx_string("hls_variant"),
      NGX_RTMP_MAIN_CONF|NGX_RTMP_SRV_CONF|NGX_RTMP_APP_CONF|NGX_CONF_1MORE,
      ngx_rtmp_hls_variant,
      NGX_RTMP_APP_CONF_OFFSET,
      0,
      NULL },

    { ngx_string("hls_base_url"),
      NGX_RTMP_MAIN_CONF|NGX_RTMP_SRV_CONF|NGX_RTMP_APP_CONF|NGX_CONF_TAKE1,
      ngx_conf_set_str_slot,
      NGX_RTMP_APP_CONF_OFFSET,
      offsetof(ngx_rtmp_hls_app_conf_t, base_url),
      NULL },

    { ngx_string("hls_fragment_naming_granularity"),
      NGX_RTMP_MAIN_CONF|NGX_RTMP_SRV_CONF|NGX_RTMP_APP_CONF|NGX_CONF_TAKE1,
      ngx_conf_set_num_slot,
      NGX_RTMP_APP_CONF_OFFSET,
      offsetof(ngx_rtmp_hls_app_conf_t, granularity),
      NULL },

    ngx_null_command
};


static ngx_rtmp_module_t  ngx_rtmp_hls_module_ctx = {
    NULL,                               /* preconfiguration */
    ngx_rtmp_hls_postconfiguration,     /* postconfiguration */

    NULL,                               /* create main configuration */
    NULL,                               /* init main configuration */

    NULL,                               /* create server configuration */
    NULL,                               /* merge server configuration */

    ngx_rtmp_hls_create_app_conf,       /* create application configuration */
    ngx_rtmp_hls_merge_app_conf,        /* merge application configuration */
};


ngx_module_t  ngx_rtmp_hls_module = {
    NGX_MODULE_V1,
    &ngx_rtmp_hls_module_ctx,           /* module context */
    ngx_rtmp_hls_commands,              /* module directives */
    NGX_RTMP_MODULE,                    /* module type */
    NULL,                               /* init master */
    NULL,                               /* init module */
    NULL,                               /* init process */
    NULL,                               /* init thread */
    NULL,                               /* exit thread */
    NULL,                               /* exit process */
    NULL,                               /* exit master */
    NGX_MODULE_V1_PADDING
};


static void
ngx_rtmp_hls_send(ngx_event_t *wev)
{
    ngx_connection_t           *c;
    ngx_rtmp_session_t         *s;
    ngx_http_request_t         *r;
    ngx_int_t                   n;
    ngx_rtmp_core_srv_conf_t   *cscf;
    ngx_rtmp_http_hls_ctx_t    *httpctx;
    ngx_rtmp_live_ctx_t        *lctx;
    ngx_rtmp_hls_ctx_t         *hctx;

    c = wev->data;
    r = c->data;

    httpctx = ngx_http_get_module_ctx(r, ngx_rtmp_http_hls_module);

    s = httpctx->s;

    if (c->destroyed) {
        return;
    }

    if (!s) {

        ngx_log_error(NGX_LOG_ERR, c->log, 0, "hls rtmp session is null");
        return;
    }

    hctx = ngx_rtmp_get_module_ctx(s, ngx_rtmp_hls_module);
    if (wev->timedout) {
        ngx_log_error(NGX_LOG_ERR, c->log, NGX_ETIMEDOUT,
                "client timed out");
        c->timedout = 1;
        c->write->handler = hctx->write_handler_backup;
        ngx_rtmp_finalize_session(s);
        return;
    }

    if (wev->timer_set) {
        ngx_del_timer(wev);
    }

    if (s->out_chain == NULL && s->out_pos != s->out_last) {
        s->out_chain = s->out[s->out_pos];
        s->out_bpos = s->out_chain->buf->pos;
    }

    lctx = ngx_rtmp_get_module_ctx(s, ngx_rtmp_live_module);
    while (s->out_chain) {
        n = c->send(c, s->out_bpos, s->out_chain->buf->last - s->out_bpos);

        if (n == NGX_AGAIN || n == 0) {
            ngx_add_timer(c->write, s->timeout);
            if (ngx_handle_write_event(c->write, 0) != NGX_OK) {
                c->write->handler = hctx->write_handler_backup;
                ngx_rtmp_finalize_session(s);
            }
            return;
        }

        if (n < 0) {
            c->write->handler = hctx->write_handler_backup;
            ngx_rtmp_finalize_session(s);
            return;
        }

        s->out_bytes += n;
        s->ping_reset = 1;

        ngx_rtmp_update_bandwidth(&ngx_rtmp_bw_out, n);

        if(lctx && lctx->stream){
            ngx_rtmp_update_bandwidth(&lctx->stream->bw_out, n);

            if (s->relay_type == NGX_NONE_RELAY) {

                ngx_rtmp_update_bandwidth(&lctx->stream->bw_out_bytes, n);
            }
        }

        s->out_bpos += n;
        if (s->out_bpos == s->out_chain->buf->last) {
            s->out_chain = s->out_chain->next;
            if (s->out_chain == NULL) {
                cscf = ngx_rtmp_get_module_srv_conf(s, ngx_rtmp_core_module);
                ngx_rtmp_free_shared_chain(cscf, s->out[s->out_pos]);
                s->out[s->out_pos] = NULL;
                ++s->out_pos;
                s->out_pos %= s->out_queue;
                if (s->out_pos == s->out_last) {
                    break;
                }
                s->out_chain = s->out[s->out_pos];
            }
            s->out_bpos = s->out_chain->buf->pos;
        }
    }

    s->rc = NGX_OK;
    c->write->handler = hctx->write_handler_backup;

    ngx_rtmp_finalize_session(s);
}


static ngx_int_t
ngx_rtmp_hls_send_message(ngx_rtmp_session_t *s, ngx_chain_t *out,
        ngx_uint_t priority)
{
    ngx_uint_t                      nmsg;

    if (!ngx_hls_type(s->protocol)) {

        return NGX_OK;
    }

    nmsg = (s->out_last - s->out_pos) % s->out_queue + 1;

    if (priority > 3) {
        priority = 3;
    }

    /* drop packet?
     * Note we always leave 1 slot free */
    if (nmsg + priority * s->out_queue / 4 >= s->out_queue) {
    /*
        ngx_log_debug2(NGX_LOG_DEBUG_RTMP, s->connection->log, 0,
                "RTMP drop message bufs=%ui, priority=%ui",
                nmsg, priority);
    */
        ngx_log_error(NGX_LOG_WARN, s->connection->log, 0,
            "RTMP drop message bufs=%ui, priority=%ui, s->out_last=%d, s->out_pos=%d, s->out_queue=%d ",
            nmsg, priority, s->out_last, s->out_pos, s->out_queue);
        return NGX_AGAIN;
    }

    s->out[s->out_last++] = out;
    s->out_last %= s->out_queue;

    ngx_rtmp_acquire_shared_chain(out);

    ngx_log_debug3(NGX_LOG_DEBUG_RTMP, s->connection->log, 0,
            "RTMP send nmsg=%ui, priority=%ui #%ui",
            nmsg, priority, s->out_last);

    if (priority && s->out_buffer && nmsg < s->out_cork) {
        return NGX_OK;
    }

    if (!s->connection->write->active) {

        ngx_rtmp_hls_send(s->connection->write);
    }

    return NGX_OK;
}


static ngx_rtmp_hls_frag_t *
ngx_rtmp_hls_get_frag(ngx_rtmp_session_t *s, ngx_int_t n)
{
    ngx_rtmp_hls_ctx_t         *ctx;
    
    ctx = ngx_rtmp_get_module_ctx(s, ngx_rtmp_hls_module);

    return &ctx->frags[(ctx->frag + n) % (ctx->winfrags * 2 + 1)];
}


static void
ngx_rtmp_hls_next_frag(ngx_rtmp_session_t *s)
{
    ngx_rtmp_hls_ctx_t         *ctx;

    ctx = ngx_rtmp_get_module_ctx(s, ngx_rtmp_hls_module);

    if (ctx->nfrags == ctx->winfrags) {
        ctx->frag++;
    } else {
        ctx->nfrags++;
    }
}


ngx_int_t
ngx_rtmp_hls_rename_file(u_char *src, u_char *dst)
{
    /* rename file with overwrite */

#if (NGX_WIN32)
    return MoveFileEx((LPCTSTR) src, (LPCTSTR) dst, MOVEFILE_REPLACE_EXISTING);
#else
    return ngx_rename_file(src, dst);
#endif
}


static ngx_int_t
ngx_rtmp_hls_write_variant_playlist(ngx_rtmp_session_t *s)
{
    static u_char             buffer[1024];

    u_char                    *p, *last;
    ssize_t                    rc;
    ngx_fd_t                   fd;
    ngx_str_t                 *arg;
    ngx_uint_t                 n, k;
    ngx_rtmp_hls_ctx_t        *ctx;
    ngx_rtmp_hls_variant_t    *var;
    ngx_rtmp_hls_app_conf_t   *hacf;

    hacf = ngx_rtmp_get_module_app_conf(s, ngx_rtmp_hls_module);
    ctx = ngx_rtmp_get_module_ctx(s, ngx_rtmp_hls_module);

    fd = ngx_open_file(ctx->var_playlist_bak.data, NGX_FILE_WRONLY,
                       NGX_FILE_TRUNCATE, NGX_FILE_DEFAULT_ACCESS);

    if (fd == NGX_INVALID_FILE) {
        ngx_log_error(NGX_LOG_ERR, s->connection->log, ngx_errno,
                      "hls: " ngx_open_file_n " failed: '%V'",
                      &ctx->var_playlist_bak);

        return NGX_ERROR;
    }

#define NGX_RTMP_HLS_VAR_HEADER "#EXTM3U\n#EXT-X-VERSION:3\n"

    rc = ngx_write_fd(fd, NGX_RTMP_HLS_VAR_HEADER,
                      sizeof(NGX_RTMP_HLS_VAR_HEADER) - 1);
    if (rc < 0) {
        ngx_log_error(NGX_LOG_ERR, s->connection->log, ngx_errno,
                      "hls: " ngx_write_fd_n " failed: '%V'",
                      &ctx->var_playlist_bak);
        ngx_close_file(fd);
        return NGX_ERROR;
    }

    var = hacf->variant->elts;
    for (n = 0; n < hacf->variant->nelts; n++, var++)
    {
        p = buffer;
        last = buffer + sizeof(buffer);

        p = ngx_slprintf(p, last, "#EXT-X-STREAM-INF:PROGRAM-ID=1");

        arg = var->args.elts;
        for (k = 0; k < var->args.nelts; k++, arg++) {
            p = ngx_slprintf(p, last, ",%V", arg);
        }

        if (p < last) {
            *p++ = '\n';
        }

        p = ngx_slprintf(p, last, "%V%*s%V",
                         &hacf->base_url,
                         s->name.len - ctx->var->suffix.len, s->name.data,
                         &var->suffix);
        if (hacf->nested) {
            p = ngx_slprintf(p, last, "%s", "/index");
        }

        p = ngx_slprintf(p, last, "%s", ".m3u8\n");

        rc = ngx_write_fd(fd, buffer, p - buffer);
        if (rc < 0) {
            ngx_log_error(NGX_LOG_ERR, s->connection->log, ngx_errno,
                          "hls: " ngx_write_fd_n " failed '%V'",
                          &ctx->var_playlist_bak);
            ngx_close_file(fd);
            return NGX_ERROR;
        }
    }

    ngx_close_file(fd);

    if (ngx_rtmp_hls_rename_file(ctx->var_playlist_bak.data,
                                 ctx->var_playlist.data)
        == NGX_FILE_ERROR)
    {
        ngx_log_error(NGX_LOG_ERR, s->connection->log, ngx_errno,
                      "hls: rename failed: '%V'->'%V'",
                      &ctx->var_playlist_bak, &ctx->var_playlist);
        return NGX_ERROR;
    }

    return NGX_OK;
}


static ngx_int_t
ngx_rtmp_hls_write_playlist(ngx_rtmp_session_t *s)
{
    static u_char                   buffer[1024];
    ngx_fd_t                        fd;
    u_char                         *p;
    ngx_rtmp_hls_ctx_t             *ctx;
    ssize_t                         n;
    ngx_rtmp_hls_app_conf_t        *hacf;
    ngx_rtmp_hls_frag_t            *f;
    ngx_uint_t                      i, max_frag;
    ngx_str_t                       name_part;
    const char                     *sep;
    char                           *dot;

    hacf = ngx_rtmp_get_module_app_conf(s, ngx_rtmp_hls_module);
    ctx = ngx_rtmp_get_module_ctx(s, ngx_rtmp_hls_module);

    fd = ngx_open_file(ctx->playlist_bak.data, NGX_FILE_WRONLY,
                       NGX_FILE_TRUNCATE, NGX_FILE_DEFAULT_ACCESS);

    if (fd == NGX_INVALID_FILE) {
        ngx_log_error(NGX_LOG_ERR, s->connection->log, ngx_errno,
                      "hls: " ngx_open_file_n " failed: '%V'",
                      &ctx->playlist_bak);
        return NGX_ERROR;
    }

    max_frag = ngx_rtmp_get_attr_conf(hacf, hls_fragment) / 1000;

    for (i = 0; i < ctx->nfrags; i++) {

        f = ngx_rtmp_hls_get_frag(s, i);
        if (f->duration > max_frag) {

            max_frag = (ngx_uint_t) (f->duration + .5);
        }
    }

    p = ngx_snprintf(buffer, sizeof(buffer),
                     "#EXTM3U\n"
                     "#EXT-X-VERSION:3\n"
                     "#EXT-X-MEDIA-SEQUENCE:%uL\n"
                     "#EXT-X-TARGETDURATION:%ui\n"
                     "%s",
                     ctx->frag, max_frag,
                     hacf->type == NGX_RTMP_HLS_TYPE_EVENT ?
                     "#EXT-X-PLAYLIST-TYPE: EVENT\n" : "");

    n = ngx_write_fd(fd, buffer, p - buffer);
    if (n < 0) {
        ngx_log_error(NGX_LOG_ERR, s->connection->log, ngx_errno,
                      "hls: " ngx_write_fd_n " failed: '%V'",
                      &ctx->playlist_bak);
        ngx_close_file(fd);
        return NGX_ERROR;
    }

    sep = hacf->nested ? (hacf->base_url.len ? "/" : "") : "";

    name_part.len = 0;
    if (!hacf->nested || hacf->base_url.len) {
        name_part = s->name;
    }

	dot = hacf->nested ? "" : ".";

    for (i = 0; i < ctx->nfrags; i++) {

        f = ngx_rtmp_hls_get_frag(s, i);
        p = ngx_snprintf(buffer, sizeof(buffer),
                         "%s"
                         "#EXTINF:%.3f,\n"
                         "%V%V%s%s%uL.ts\n",
                         f->discont ? "#EXT-X-DISCONTINUITY\n" : "",
                         f->duration, &(hacf->base_url), &name_part, (char *)dot, (char *)sep, f->id);

        ngx_log_debug6(NGX_LOG_DEBUG_RTMP, s->connection->log, 0,
                       "hls: fragment frag=%uL, n=%ui/%ui, duration=%.3f, "
                       "discont=%i, id=%uL",
                       ctx->frag, i + 1, ctx->nfrags, f->duration, f->discont, f->id);

        n = ngx_write_fd(fd, buffer, p - buffer);
        if (n < 0) {
            ngx_log_error(NGX_LOG_ERR, s->connection->log, ngx_errno,
                          "hls: " ngx_write_fd_n " failed '%V'",
                          &ctx->playlist_bak);
            ngx_close_file(fd);
            return NGX_ERROR;
        }
    }

    ngx_close_file(fd);

    if (ngx_rtmp_hls_rename_file(ctx->playlist_bak.data, ctx->playlist.data)
        == NGX_FILE_ERROR)
    {
        ngx_log_error(NGX_LOG_ERR, s->connection->log, ngx_errno,
                      "hls: rename failed: '%V'->'%V'",
                      &ctx->playlist_bak, &ctx->playlist);
        return NGX_ERROR;
    }

    if (ctx->var) {
        return ngx_rtmp_hls_write_variant_playlist(s);
    }

    return NGX_OK;
}


ngx_int_t
ngx_rtmp_hls_copy(ngx_rtmp_session_t *s, void *dst, u_char **src, size_t n,
    ngx_chain_t **in)
{
    u_char  *last;
    size_t   pn;

    if (*in == NULL) {
        return NGX_ERROR;
    }

    for ( ;; ) {
        last = (*in)->buf->last;

        if ((size_t)(last - *src) >= n) {
            if (dst) {
                ngx_memcpy(dst, *src, n);
            }

            *src += n;

            while (*in && *src == (*in)->buf->last) {
                *in = (*in)->next;
                if (*in) {
                    *src = (*in)->buf->pos;
                }
            }

            return NGX_OK;
        }

        pn = last - *src;

        if (dst) {
            ngx_memcpy(dst, *src, pn);
            dst = (u_char *)dst + pn;
        }

        n -= pn;
        *in = (*in)->next;

        if (*in == NULL) {
            ngx_log_error(NGX_LOG_ERR, s->connection->log, 0,
                          "hls: failed to read %uz byte(s)", n);
            return NGX_ERROR;
        }

        *src = (*in)->buf->pos;
    }
}

ngx_int_t
ngx_rtmp_hls_append_aud_h264(ngx_rtmp_session_t *s, ngx_buf_t *out)
{
    static u_char   aud_nal[] = { 0x00, 0x00, 0x00, 0x01, 0x09, 0xf0 };

    if (out->last + sizeof(aud_nal) > out->end) {
        return NGX_ERROR;
    }

    out->last = ngx_cpymem(out->last, aud_nal, sizeof(aud_nal));

    return NGX_OK;
}


ngx_int_t
ngx_rtmp_hls_append_aud_h265(ngx_rtmp_session_t *s, ngx_buf_t *out)
{
    static u_char   aud_nal[] = { 0x00, 0x00, 0x00, 0x01, 0x46, 0x01, 0x10 };

    if (out->last + sizeof(aud_nal) > out->end) {
        return NGX_ERROR;
    }

    out->last = ngx_cpymem(out->last, aud_nal, sizeof(aud_nal));

    return NGX_OK;
}


ngx_int_t
ngx_rtmp_hls_append_sps_pps_h264(ngx_rtmp_session_t *s, ngx_buf_t *out)
{
    ngx_rtmp_codec_ctx_t           *codec_ctx;
    u_char                         *p;
    ngx_chain_t                    *in;
    int8_t                          nnals;
    uint16_t                        len, rlen;
    ngx_int_t                       n;

    codec_ctx = ngx_rtmp_get_module_ctx(s, ngx_rtmp_codec_module);
    if (codec_ctx == NULL) {
        return NGX_ERROR;
    }

    in = codec_ctx->video_header;
    if (in == NULL) {
        return NGX_ERROR;
    }

    p = in->buf->pos;

    /*
     * Skip bytes:
     * - flv fmt
     * - H264 CONF/PICT (0x00)
     * - 0
     * - 0
     * - 0
     * - version
     * - profile
     * - compatibility
     * - level
     * - nal bytes
     */

    if (ngx_rtmp_hls_copy(s, NULL, &p, 10, &in) != NGX_OK) {
        return NGX_ERROR;
    }

    /* number of SPS NALs */
    if (ngx_rtmp_hls_copy(s, &nnals, &p, 1, &in) != NGX_OK) {
        return NGX_ERROR;
    }

    nnals &= 0x1f; /* 5lsb */

    ngx_log_debug1(NGX_LOG_DEBUG_RTMP, s->connection->log, 0,
                   "hls: SPS number: %uz", nnals);

    /* SPS */
    for (n = 0; ; ++n) {
        for (; nnals; --nnals) {

            /* NAL length */
            if (ngx_rtmp_hls_copy(s, &rlen, &p, 2, &in) != NGX_OK) {
                return NGX_ERROR;
            }

            ngx_rtmp_rmemcpy(&len, &rlen, 2);

            ngx_log_debug1(NGX_LOG_DEBUG_RTMP, s->connection->log, 0,
                           "hls: header NAL length: %uz", (size_t) len);

            /* AnnexB prefix */
            if (out->end - out->last < 4) {
                ngx_log_error(NGX_LOG_ERR, s->connection->log, 0,
                              "hls: too small buffer for header NAL size");
                return NGX_ERROR;
            }

            *out->last++ = 0;
            *out->last++ = 0;
            *out->last++ = 0;
            *out->last++ = 1;

            /* NAL body */
            if (out->end - out->last < len) {
                ngx_log_error(NGX_LOG_ERR, s->connection->log, 0,
                              "hls: too small buffer for header NAL");
                return NGX_ERROR;
            }

            if (ngx_rtmp_hls_copy(s, out->last, &p, len, &in) != NGX_OK) {
                return NGX_ERROR;
            }

            out->last += len;
        }

        if (n == 1) {
            break;
        }

        /* number of PPS NALs */
        if (ngx_rtmp_hls_copy(s, &nnals, &p, 1, &in) != NGX_OK) {
            return NGX_ERROR;
        }

        ngx_log_debug1(NGX_LOG_DEBUG_RTMP, s->connection->log, 0,
                       "hls: PPS number: %uz", nnals);
    }

    return NGX_OK;
}


ngx_int_t
ngx_rtmp_hls_append_sps_pps_h265(ngx_rtmp_session_t *s, ngx_buf_t *out)
{
    ngx_rtmp_codec_ctx_t    *codec_ctx;
    ngx_chain_t             *in;
    u_char                  *p;
    ngx_uint_t              num_array;
    int8_t                  nal_type;
    uint16_t                nnals,  nal_num, rlen, len;
    ngx_int_t               n;

    codec_ctx = ngx_rtmp_get_module_ctx(s, ngx_rtmp_codec_module);
    if(codec_ctx == NULL) {
        return NGX_ERROR;
    }

    in = codec_ctx->video_header;
    if(in == NULL) {
        return NGX_ERROR;
    }

#if (NGX_DEBUG)
    ngx_rtmp_codec_dump_header(s,"hls_hevc",in);
#endif

    p = in->buf->pos;

    if(ngx_rtmp_hls_copy(s, NULL, &p, 27, &in) != NGX_OK) {
        return NGX_ERROR;
    }

    if (ngx_rtmp_hls_copy(s, &num_array, &p, 1, &in) != NGX_OK) {
        return NGX_ERROR;
    }

    if(num_array <= 0) {
        return NGX_ERROR;
    }

    /* vps NALs type */
    if (ngx_rtmp_hls_copy(s, &nal_type, &p, 1, &in) != NGX_OK) {
        return NGX_ERROR;
    }

    /* number of vps NALs */
    if (ngx_rtmp_hls_copy(s, &nnals, &p, 2, &in) != NGX_OK) {
        return NGX_ERROR;
    }

    ngx_rtmp_rmemcpy(&nal_num, &nnals, 2);

    for (n = 0; ; ++n) {
        for (; nal_num; --nal_num) {
            /* NAL length */
            if (ngx_rtmp_hls_copy(s, &rlen, &p, 2, &in) != NGX_OK) {
                return NGX_ERROR;
            }

            ngx_rtmp_rmemcpy(&len, &rlen, 2);

            ngx_log_debug1(NGX_LOG_DEBUG_RTMP, s->connection->log, 0,
                           "hls: h265 header NAL length: %uz", (size_t) len);

            if ((nal_type == HEVC_NAL_SPS ||
                 nal_type == HEVC_NAL_PPS ||
                 nal_type == HEVC_NAL_VPS)) {

                /* AnnexB prefix */
                if (out->end - out->last < 4) {
                    ngx_log_error(NGX_LOG_ERR, s->connection->log, 0,
                                  "hls: too small buffer for header NAL size");
                    return NGX_ERROR;
                }

                *out->last++ = 0;
                *out->last++ = 0;
                *out->last++ = 0;
                *out->last++ = 1;

                /* NAL body */
                if (out->end - out->last < len) {
                    ngx_log_error(NGX_LOG_ERR, s->connection->log, 0,
                                  "hls: too small buffer for header NAL");
                    return NGX_ERROR;
                }

                if (ngx_rtmp_hls_copy(s, out->last, &p, len, &in) != NGX_OK) {
                    return NGX_ERROR;
                }

                out->last += len;
            } else {
                if (ngx_rtmp_hls_copy(s, NULL, &p, len, &in) != NGX_OK) {
                    return NGX_ERROR;
                }
            }
        }

        if (n == 2) {
            break;
        }

        if (ngx_rtmp_hls_copy(s, &nal_type, &p, 1, &in) != NGX_OK) {
            return NGX_ERROR;
        }

        /* number of PPS NALs */
        if (ngx_rtmp_hls_copy(s, &nnals, &p, 2, &in) != NGX_OK) {
            return NGX_ERROR;
        }

        ngx_rtmp_rmemcpy(&nal_num, &nnals, 2);
    }

    return NGX_OK;
}

static uint64_t
ngx_rtmp_hls_get_fragment_id(ngx_rtmp_session_t *s, uint64_t ts)
{
    ngx_rtmp_hls_ctx_t         *ctx;
    ngx_rtmp_hls_app_conf_t    *hacf;

    ctx = ngx_rtmp_get_module_ctx(s, ngx_rtmp_hls_module);

    hacf = ngx_rtmp_get_module_app_conf(s, ngx_rtmp_hls_module);

    switch (hacf->naming) {

        case NGX_RTMP_HLS_NAMING_TIMESTAMP:
            return ts;

        case NGX_RTMP_HLS_NAMING_SYSTEM:
            return (uint64_t) ngx_cached_time->sec * 1000 + ngx_cached_time->msec;

        case NGX_RTMP_HLS_NAMING_TIMESTAMP_SEQ:
            return ctx->frag_seq;

        default: /* NGX_RTMP_HLS_NAMING_SEQUENTIAL */
            return ctx->frag + ctx->nfrags;
    }
}


static ngx_int_t
ngx_rtmp_hls_close_fragment(ngx_rtmp_session_t *s, uint64_t ts)
{
    ngx_rtmp_hls_ctx_t         *ctx;

    ctx = ngx_rtmp_get_module_ctx(s, ngx_rtmp_hls_module);
    if (ctx == NULL || !ctx->opened) {
        return NGX_OK;
    }

    ngx_close_file(ctx->file.fd);

    ctx->opened = 0;
    ctx->file.fd = NGX_INVALID_FILE;

    ngx_log_debug1(NGX_LOG_DEBUG_RTMP, s->connection->log, 0,
                   "hls: close fragment n=%uL", ctx->frag);

    ngx_rtmp_hls_next_frag(s);

    ngx_rtmp_hls_write_playlist(s);
    ngx_rtmp_hls_flush_expire(s);

    return NGX_OK;
}


static ngx_int_t
ngx_rtmp_hls_open_fragment(ngx_rtmp_session_t *s, uint64_t ts,
    ngx_int_t discont, ngx_rtmp_header_t *h)
{
    uint64_t                  id;
    ngx_uint_t                g, psi_cc;
    ngx_rtmp_hls_ctx_t       *ctx;
    ngx_rtmp_codec_ctx_t     *codec_ctx;
    ngx_rtmp_hls_frag_t      *f;
    ngx_rtmp_hls_app_conf_t  *hacf;

    ctx = ngx_rtmp_get_module_ctx(s, ngx_rtmp_hls_module);
    if (ctx->opened) {
        return NGX_OK;
    }

    codec_ctx = ngx_rtmp_get_module_ctx(s, ngx_rtmp_codec_module);
    if(codec_ctx == NULL) {
        return NGX_OK;
    }

    if (ngx_rtmp_hls_ensure_directory(s) != NGX_OK) {
        return NGX_ERROR;
    }

    hacf = ngx_rtmp_get_module_app_conf(s, ngx_rtmp_hls_module);

    ctx->frag_seq = ts / (ngx_rtmp_get_attr_conf(hacf, hls_fragment) * 90);

    id = ngx_rtmp_hls_get_fragment_id(s, ts);

    if (hacf->granularity) {
        g = (ngx_uint_t) hacf->granularity;
        id = (uint64_t) (id / g) * g;
    }

    if (hacf->nested)
        *ngx_sprintf(ctx->stream.data + ctx->stream.len, "%uL.ts", id) = 0;
    else
        *ngx_sprintf(ctx->stream.data + ctx->stream.len, ".%uL.ts", id) = 0;

    ngx_log_debug5(NGX_LOG_ERR, s->connection->log, 0,
                   "hls: open fragment file='%s', frag=%uL, n=%ui, time=%uL, "
                   "discont=%i",
                   ctx->stream.data, ctx->frag, ctx->nfrags, ts, discont);

    ngx_memzero(&ctx->file, sizeof(ctx->file));

    ctx->file.log = s->connection->log;

    ngx_str_set(&ctx->file.name, "hls");

    ctx->file.fd = ngx_open_file(ctx->stream.data, NGX_FILE_WRONLY,
                                 NGX_FILE_TRUNCATE, NGX_FILE_DEFAULT_ACCESS);

    if (ctx->file.fd == NGX_INVALID_FILE) {
        ngx_log_error(NGX_LOG_ERR, s->connection->log, ngx_errno,
                      "hls: error creating fragment file");
        return NGX_ERROR;
    }

    psi_cc = ctx->psi_cc ++;

    if (ngx_rtmp_mpegts_write_header(&ctx->file, psi_cc & 0x0F,
            codec_ctx->video_codec_id == NGX_RTMP_VIDEO_H265) != NGX_OK) {
        ngx_log_error(NGX_LOG_ERR, s->connection->log, ngx_errno,
                      "hls: error writing fragment header");
        ctx->psi_cc --;
        ngx_close_file(ctx->file.fd);
        return NGX_ERROR;
    }

    ctx->opened = 1;

    f = ngx_rtmp_hls_get_frag(s, ctx->nfrags);

    ngx_memzero(f, sizeof(*f));

    f->active = 1;
    f->discont = discont;
    f->id = id;
    f->duration = 0.;

    h->type == NGX_RTMP_MSG_AUDIO ? (ctx->last_audio_ts = ts) : (ctx->last_video_ts = ts);
    ctx->frag_ts = ts;
    ctx->frag_ts_system = ngx_current_msec;

    /* start fragment with audio to make iPhone happy */

    ngx_rtmp_hls_flush_audio(s);
	
    return NGX_OK;
}


static void
ngx_rtmp_hls_restore_stream(ngx_rtmp_session_t *s)
{
    ngx_rtmp_hls_ctx_t             *ctx;
    ngx_file_t                      file;
    ssize_t                         ret;
    off_t                           offset;
    u_char                         *p, *last, *end, *next;
    static u_char                   buffer[4096];

    ctx = ngx_rtmp_get_module_ctx(s, ngx_rtmp_hls_module);

    ngx_memzero(&file, sizeof(file));

    file.log = s->connection->log;

    ngx_str_set(&file.name, "m3u8");

    file.fd = ngx_open_file(ctx->playlist_bak.data, NGX_FILE_RDONLY, NGX_FILE_OPEN,
                            0);
    if (file.fd == NGX_INVALID_FILE) {
        return;
    }

    offset = 0;
    ctx->nfrags = 0;

    for ( ;; ) {

        ret = ngx_read_file(&file, buffer, sizeof(buffer), offset);
        if (ret <= 0) {
            goto done;
        }

        p = buffer;
        end = buffer + ret;

        for ( ;; ) {
            last = ngx_strlchr(p, end, '\n');

            if (last == NULL) {
                if (p == buffer) {
                    goto done;
                }
                break;
            }

            next = last + 1;
            offset += (next - p);

            if (p != last && last[-1] == '\r') {
                last--;
            }

#define NGX_RTMP_MSEQ           "#EXT-X-MEDIA-SEQUENCE:"
#define NGX_RTMP_MSEQ_LEN       (sizeof(NGX_RTMP_MSEQ) - 1)

            if (ngx_memcmp(p, NGX_RTMP_MSEQ, NGX_RTMP_MSEQ_LEN) == 0) {

                ctx->frag = (uint64_t) strtod((const char *)
                                              &p[NGX_RTMP_MSEQ_LEN], NULL);

                ngx_log_debug1(NGX_LOG_DEBUG_RTMP, s->connection->log, 0,
                               "hls: restore sequence frag=%uL", ctx->frag);
            }

            /* find '.ts\r' */

            if (p + 4 <= last &&
                last[-3] == '.' && last[-2] == 't' && last[-1] == 's')
            {

                ++ ctx->frag;

                ngx_log_debug1(NGX_LOG_DEBUG_RTMP, s->connection->log, 0,
                               "hls: restore sequence frag=%uL", ctx->frag);
            }

            p = next;
        }
    }

done:
    ngx_close_file(file.fd);
}


static ngx_int_t
ngx_rtmp_hls_ensure_directory(ngx_rtmp_session_t *s)
{
    ngx_file_info_t           fi;
    ngx_rtmp_hls_app_conf_t  *hacf;
    ngx_rtmp_core_srv_conf_t *cscf;
    u_char                   *p;
    ngx_int_t                 plen = 0;
    static u_char             path[NGX_MAX_PATH + 1];

    hacf = ngx_rtmp_get_module_app_conf(s, ngx_rtmp_hls_module);

    cscf = ngx_rtmp_get_module_srv_conf(s, ngx_rtmp_core_module);

    ngx_memzero(path, sizeof(path));
    p = ngx_cpymem(path, hacf->path.data, hacf->path.len);
    plen += hacf->path.len;
    if (p[-1] != '/') {
        *p++ = '/';
        plen++;
    }

    // path = /tmp/hls/xiaoyi/live
    p = ngx_cpymem(p, ngx_rtmp_get_attr_conf(cscf, unique_name).data, ngx_rtmp_get_attr_conf(cscf, unique_name).len);
    *p++ = '/';

    p = ngx_cpymem(p, s->app.data, s->app.len);
    *p++ = '/';

    if (ngx_file_info(path, &fi) == NGX_FILE_ERROR) {

        if (ngx_errno != NGX_ENOENT) {
            ngx_log_debug1(NGX_LOG_DEBUG_RTMP, s->connection->log, ngx_errno,
                           "hls: " ngx_file_info_n " failed on '%s'",
                           path);
            return NGX_ERROR;
        }

        /* ENOENT */

        if (ngx_create_full_path(path, NGX_RTMP_HLS_DIR_ACCESS) == NGX_FILE_ERROR) {
            ngx_log_debug1(NGX_LOG_DEBUG_RTMP, s->connection->log, ngx_errno,
                           "hls: " ngx_create_dir_n " failed on '%s'",
                           path);
            return NGX_ERROR;
        }

        ngx_log_debug1(NGX_LOG_DEBUG_RTMP, s->connection->log, 0,
                       "hls: directory '%s' created", path);

    } else {

        if (!ngx_is_dir(&fi)) {
            ngx_log_debug1(NGX_LOG_DEBUG_RTMP, s->connection->log, 0,
                           "hls: '%s' exists and is not a directory",
                           path);
            return  NGX_ERROR;
        }

        ngx_log_debug1(NGX_LOG_DEBUG_RTMP, s->connection->log, 0,
                       "hls: directory '%s' exists", path);
    }

    if (!hacf->nested) {
        return NGX_OK;
    }

    p = ngx_cpymem(p, s->name.data, s->name.len);
    *p++ = '/';

    if (ngx_file_info(path, &fi) != NGX_FILE_ERROR) {

        if (ngx_is_dir(&fi)) {
            ngx_log_debug1(NGX_LOG_DEBUG_RTMP, s->connection->log, 0,
                           "hls: directory '%s' exists", path);
        } else {

            ngx_log_error(NGX_LOG_ERR, s->connection->log, 0,
                          "hls: '%s' exists and is not a directory", path);

            return  NGX_ERROR;
        }

    } else {

        if (ngx_errno != NGX_ENOENT) {
            ngx_log_error(NGX_LOG_ERR, s->connection->log, ngx_errno,
                          "hls: " ngx_file_info_n " failed on '%s'", path);
            return NGX_ERROR;
        }

        /* NGX_ENOENT */

        if (ngx_create_dir(path, NGX_RTMP_HLS_DIR_ACCESS) == NGX_FILE_ERROR) {
            ngx_log_error(NGX_LOG_ERR, s->connection->log, ngx_errno,
                          "hls: " ngx_create_dir_n " failed on '%s'", path);
            return NGX_ERROR;
        }

        ngx_log_debug1(NGX_LOG_DEBUG_RTMP, s->connection->log, 0,
                       "hls: directory '%s' created", path);
    }

    return NGX_OK;
}


static ngx_int_t
ngx_rtmp_hls_flush_expire(ngx_rtmp_session_t *s)
{
    ngx_rtmp_hls_app_conf_t    *hacf;
    ngx_rtmp_hls_ctx_t         *ctx;
    ngx_int_t                   n;
    u_char                      buff[1024], *p;
    char                       *p1;

    hacf = ngx_rtmp_get_module_app_conf(s, ngx_rtmp_hls_module);  

    if (hacf == NULL) {
        return NGX_ERROR;
    }

    ctx = ngx_rtmp_get_module_ctx(s, ngx_rtmp_hls_module);
    if (ctx == NULL) {
        return NGX_ERROR;
    }

    ngx_memzero(&ctx->expire_file, sizeof(ctx->expire_file));
    ctx->expire_file.log = s->connection->log;
    ngx_str_set(&ctx->expire_file.name, NGX_RTMP_HLS_EXIPRE_FILE_NAME_BAK);
    ctx->expire_file.fd = ngx_open_file(ctx->expire.data, NGX_FILE_WRONLY, NGX_FILE_TRUNCATE, NGX_FILE_DEFAULT_ACCESS);

    if (ctx->expire_file.fd == NGX_INVALID_FILE) {
		
        ngx_log_error(NGX_LOG_ERR, s->connection->log, ngx_errno, "hls: error creating expire file");
        return NGX_ERROR;
    }

    p = ngx_snprintf(buff, sizeof(buff), "EXPIRE:%ui\r\n", ngx_rtmp_get_attr_conf(hacf, hls_playlist_length));

    n = ngx_write_fd(ctx->expire_file.fd, buff, p - buff);
    if (n < 0) {

        ngx_log_error(NGX_LOG_ERR, s->connection->log, ngx_errno,
            "expire: " ngx_write_fd_n " failed: '%V'", &ctx->expire);
        ngx_close_file(ctx->expire_file.fd);
        return NGX_ERROR;
    }   

    ngx_close_file(ctx->expire_file.fd);
    ctx->expire_file.fd = NGX_INVALID_FILE;

    //rename .expinfo.bak to .expinfo
    ngx_memzero(buff, sizeof(buff));
    ngx_memcpy(buff, ctx->expire.data, ngx_min(ctx->expire.len, sizeof(buff) - 1));
    p1 = ngx_strstr((char *)buff, ".bak");
    *p1 = 0;

    ngx_rtmp_hls_rename_file(ctx->expire.data, buff);
	
    return NGX_OK;
}


ngx_int_t
ngx_rtmp_hls_read_expire(ngx_str_t *path, ngx_msec_t *out_expire)
{
    u_char                               buff[1024], dir[1024], *pcur;
    char                                *p;
    ngx_file_info_t                      fi;
    ngx_uint_t                           nlen, nlen1;
    ngx_file_t                           expire_file;
    ngx_msec_t                           expire = 0;

    ngx_memzero(&expire_file, sizeof(expire_file));
    ngx_str_set(&expire_file.name, NGX_RTMP_HLS_EXIPRE_FILE_NAME);
    expire_file.offset = 0;
    expire_file.log = ngx_cycle->log;

    pcur = ngx_snprintf(dir, 1024, "%V", path);
    *ngx_snprintf(pcur, 1024, "/%s", NGX_RTMP_HLS_EXIPRE_FILE_NAME) = 0;

    ngx_log_debug1(NGX_LOG_DEBUG_RTMP, ngx_cycle->log, 0,
        "ngx_rtmp_hls_read_expire: open file %s", (char *)dir);

    expire_file.fd = ngx_open_file((char *)dir, NGX_FILE_RDONLY, NGX_FILE_OPEN,
        NGX_FILE_DEFAULT_ACCESS);
    if (expire_file.fd == NGX_INVALID_FILE) {

        ngx_log_error(NGX_LOG_ERR, ngx_cycle->log, 0,
            "ngx_rtmp_hls_read_expire: open file failed", (char *)dir);
        return NGX_ERROR;
    }

    if (ngx_link_info((char *)dir, &fi) == NGX_FILE_ERROR) {
        ngx_close_file(expire_file.fd);
        return NGX_ERROR;
    }

    ngx_memzero(buff, 0);
    nlen = ngx_file_size(&fi);
    ngx_read_file(&expire_file, buff, nlen, 0);
    ngx_close_file(expire_file.fd);

    if (ngx_strlen(buff) > 0) {
		
        p  = ngx_strstr((char *)buff, "EXPIRE:");
	    if (p) {
            nlen1 = nlen - ngx_strlen("EXPIRE:") - ngx_strlen("\r\n");
            expire = (ngx_uint_t)ngx_atoi(buff + ngx_strlen("EXPIRE:"), nlen1);

            ngx_log_debug1(NGX_LOG_DEBUG, ngx_cycle->log, 0,
                "ngx_rtmp_hls_read_expire: read expire %ui", expire);
	    }
    }

    *out_expire = expire;
    return NGX_OK;
}


static ngx_int_t
ngx_rtmp_hls_publish(ngx_rtmp_session_t *s, ngx_rtmp_publish_t *v)
{
    ngx_rtmp_core_srv_conf_t       *cscf;
    ngx_rtmp_hls_app_conf_t        *hacf;
    ngx_rtmp_hls_ctx_t             *ctx;
    u_char                         *p, *pp, *p4;
    ngx_rtmp_hls_frag_t            *f;
    ngx_buf_t                      *b;
    size_t                          len;
    ngx_rtmp_hls_variant_t         *var;
    ngx_uint_t                      n;

    hacf = ngx_rtmp_get_module_app_conf(s, ngx_rtmp_hls_module);
    if (hacf == NULL || hacf->path.len == 0) {
        goto next;
    }

    cscf = ngx_rtmp_get_module_srv_conf(s, ngx_rtmp_core_module);
    if (cscf == NULL) {
        goto next;
    }

    if (!ngx_rtmp_get_attr_conf(hacf, hls)) {
        goto next;
    }

    // reap fragment by NGX_NONE_RELAY.
    if (s->relay_type != NGX_NONE_RELAY) {
        goto next;
    }

    ngx_log_debug2(NGX_LOG_DEBUG_RTMP, s->connection->log, 0,
                   "hls_publish: name='%s' type='%s'",
                   v->name, v->type);

    ctx = ngx_rtmp_get_module_ctx(s, ngx_rtmp_hls_module);

    if (ctx == NULL) {

        ctx = ngx_pcalloc(s->pool, sizeof(ngx_rtmp_hls_ctx_t));
        ngx_rtmp_set_ctx(s, ctx, ngx_rtmp_hls_module);

    } else {

        f = ctx->frags;
        b = ctx->aframe;
        ngx_memzero(ctx, sizeof(ngx_rtmp_hls_ctx_t));
        ctx->frags = f;
        ctx->aframe = b;

        if (b) {
            b->pos = b->last = b->start;
        }
    }

    ctx->publisher = 1;
    ctx->winfrags = ngx_rtmp_get_attr_conf(hacf, hls_playlist_length) / ngx_rtmp_get_attr_conf(hacf, hls_fragment);

    if (ctx->frags == NULL) {
        ctx->frags = ngx_pcalloc(s->pool,
                                 sizeof(ngx_rtmp_hls_frag_t) *
                                 (ctx->winfrags * 2 + 1));
        if (ctx->frags == NULL) {
            return NGX_ERROR;
        }
    }

    if (ngx_strstr(v->name, "..")) {
        
        ngx_log_error(NGX_LOG_ERR, s->connection->log, 0, "hls: bad stream name: '%s'", v->name);
        return NGX_ERROR;
    }

    len = hacf->path.len + 1 + ngx_rtmp_get_attr_conf(cscf, unique_name).len + 1
			+ s->app.len + 1 + s->name.len + sizeof(".m3u8");
    if (hacf->nested) {
        len += sizeof("/index") - 1;
    }

    ctx->playlist.data = ngx_palloc(s->pool, len);
    
    // playlist = /tmp/hls/
    p = ngx_cpymem(ctx->playlist.data, hacf->path.data, hacf->path.len);
    if (p[-1] != '/') {
        *p++ = '/';
    }

    // playlist = /tmp/hls/xiaoyi/
    p = ngx_cpymem(p, ngx_rtmp_get_attr_conf(cscf, unique_name).data, ngx_rtmp_get_attr_conf(cscf, unique_name).len);
    *p++ = '/';

    // playlist = /tmp/hls/xiaoyi/app/
    p = ngx_cpymem(p, s->app.data, s->app.len);
    *p++ = '/';

    // playlist = /tmp/hls/xiaoyi/app/huzilong_demo_1
    p = ngx_cpymem(p, s->name.data, s->name.len);

    /*
     * ctx->stream holds initial part of stream file path
     * however the space for the whole stream path
     * is allocated
     */

    // /tmp/hls/xiaoyi/app/huzilong_demo_1 + . or / + tsnumber + .ts
    ctx->stream.len = p - ctx->playlist.data + 1;
    ctx->stream.data = ngx_palloc(s->pool,
                                  ctx->stream.len + 1 +
                                  NGX_INT64_LEN + ngx_strlen(".ts"));

    // stream = /tmp/hls/xiaoyi/app/huzilong_demo_1/
    ngx_memcpy(ctx->stream.data, ctx->playlist.data, ctx->stream.len - 1);
    if (hacf->nested) {
        ctx->stream.data[ctx->stream.len - 1] = '/';
    } else {
        ctx->stream.len --;
    }

    //calculate the expire dir
    ctx->expire.len = hacf->path.len + 1 + ngx_rtmp_get_attr_conf(cscf, unique_name).len + 1
        + s->app.len + 1 + s->name.len + 1 + ngx_strlen(NGX_RTMP_HLS_EXIPRE_FILE_NAME_BAK) + 1;
    ctx->expire.data = ngx_palloc(s->pool, ctx->expire.len);
    p4 = ngx_cpymem(ctx->expire.data, hacf->path.data, hacf->path.len);
    if (p4[-1] != '/') {
        *p4++ = '/';
    }

    p4 = ngx_cpymem(p4, ngx_rtmp_get_attr_conf(cscf, unique_name).data, ngx_rtmp_get_attr_conf(cscf, unique_name).len);
    *p4++ = '/';
    p4 = ngx_cpymem(p4, s->app.data, s->app.len);
    *p4++ = '/';
    p4 = ngx_cpymem(p4, s->name.data, s->name.len);
    *p4++ = '/';
    *ngx_cpymem(p4, NGX_RTMP_HLS_EXIPRE_FILE_NAME_BAK, ngx_strlen(NGX_RTMP_HLS_EXIPRE_FILE_NAME_BAK)) = 0;	

    /* varint playlist path */

    if (hacf->variant) {
        var = hacf->variant->elts;
        for (n = 0; n < hacf->variant->nelts; n++, var++) {
            if (s->name.len > var->suffix.len &&
                ngx_memcmp(var->suffix.data,
                           s->name.data + s->name.len - var->suffix.len,
                           var->suffix.len) == 0)
            {
                ctx->var = var;

                len = (size_t) (p - ctx->playlist.data);

                ctx->var_playlist.len = len - var->suffix.len + sizeof(".m3u8")
                                        - 1;
                ctx->var_playlist.data = ngx_palloc(s->pool,
                                                    ctx->var_playlist.len + 1);

                pp = ngx_cpymem(ctx->var_playlist.data, ctx->playlist.data,
                               len - var->suffix.len);
                pp = ngx_cpymem(pp, ".m3u8", sizeof(".m3u8") - 1);
                *pp = 0;

                ctx->var_playlist_bak.len = ctx->var_playlist.len +
                                            sizeof(".bak") - 1;
                ctx->var_playlist_bak.data = ngx_palloc(s->pool,
                                                 ctx->var_playlist_bak.len + 1);

                pp = ngx_cpymem(ctx->var_playlist_bak.data,
                                ctx->var_playlist.data,
                                ctx->var_playlist.len);
                pp = ngx_cpymem(pp, ".bak", sizeof(".bak") - 1);
                *pp = 0;

                break;
            }
        }
    }

    /* playlist path */

    // playlist = /tmp/hls/xiaoyi/app/huzilong_demo_1/index.m3u8
    if (hacf->nested) {
        p = ngx_cpymem(p, "/index.m3u8", sizeof("/index.m3u8") - 1);
    } else {
        p = ngx_cpymem(p, ".m3u8", sizeof(".m3u8") - 1);
    }

    ctx->playlist.len = p - ctx->playlist.data;
    *p = 0;

    /* playlist bak (new playlist) path */
    ctx->playlist_bak.data = ngx_palloc(s->pool,
                                        ctx->playlist.len + sizeof(".bak"));
    p = ngx_cpymem(ctx->playlist_bak.data, ctx->playlist.data,
                   ctx->playlist.len);
    p = ngx_cpymem(p, ".bak", sizeof(".bak") - 1);

    ctx->playlist_bak.len = p - ctx->playlist_bak.data;

    *p = 0;
    if (hacf->continuous) {
        ngx_rtmp_hls_restore_stream(s);
    }

next:
    return next_publish(s, v);
}


static ngx_url_t *
ngx_rtmp_parse_http_url(ngx_http_request_t *r, ngx_str_t *url)
{
    ngx_url_t  *u;
    size_t      add;

    add = 0;

    u = ngx_pcalloc(r->pool, sizeof(ngx_url_t));
    if (u == NULL) {
        return NULL;
    }

    if (ngx_strncasecmp(url->data, (u_char *) "http://", 7) == 0) {
        add = 7;
    }

    u->url.len = url->len - add;
    u->url.data = url->data + add;
    u->default_port = 80;
    u->uri_part = 1;

    if (ngx_parse_url(r->pool, u) != NGX_OK) {
        if (u->err) {
            ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
                    "%s in url \"%V\"", u->err, &u->url);
        }
        return NULL;
    }

    return u;
}


static ngx_int_t
ngx_rtmp_hls_play(ngx_rtmp_session_t *s, ngx_rtmp_play_t *v)
{
    ngx_rtmp_hls_app_conf_t        *hacf;
    ngx_rtmp_core_srv_conf_t       *cscf;
    ngx_rtmp_hls_ctx_t             *ctx;
    ngx_http_request_t             *r;
    ngx_url_t                      *url;
    ngx_str_t                      tmp_uri;
    ngx_rtmp_netcall_init_t        ci;
    ngx_chain_t                    out;

    hacf = ngx_rtmp_get_module_app_conf(s, ngx_rtmp_hls_module);
    if (hacf == NULL || hacf->path.len == 0) {
        goto next;
    }

    cscf = ngx_rtmp_get_module_srv_conf(s, ngx_rtmp_core_module);

    r = s->r;
    if (r == NULL) {
        goto next;
    }

    if (!ngx_hls_pull_type(s->protocol)) {
        goto next;
    }

    if (!ngx_rtmp_get_attr_conf(hacf, hls)) {

        s->rc = NGX_DECLINED;
        ngx_rtmp_finalize_session(s);
        goto next;
    }

    ngx_log_debug8(NGX_LOG_DEBUG_RTMP, s->connection->log, 0, "hls_play: name='%s' "
                   "start='%uD' duration='%uD' reset='%d' page_url='%V' addr_text='%V' "
       	           "tc_url='%V' flashver='%V'", v->name, (uint32_t) v->start, 
                   (uint32_t) v->duration, (uint32_t) v->reset,
                   &s->page_url, s->addr_text, &s->tc_url, &s->flashver);

    ctx  = ngx_rtmp_get_module_ctx(s, ngx_rtmp_hls_module);
    tmp_uri = r->uri;

    // try to open local cache at first.
    if (ngx_rtmp_http_hls_change_uri(r, ngx_rtmp_get_attr_conf(cscf, unique_name), hacf) == NGX_OK) {
        s->hls_stime_ms = ngx_current_msec;

        if (ngx_rtmp_hls_open_file(r, &out) == NGX_OK) {

            s->rc = ngx_http_output_filter(r, &out);
            s->status_code = 200;

            ngx_rtmp_finalize_session(s);
            goto next;
        }
    }

    r->uri = tmp_uri;

    if (ctx->upstream_url.len == 0) {
        s->rc = NGX_HTTP_NOT_FOUND;
        s->status_code = s->rc;
        
        ngx_rtmp_finalize_session(s);
        goto next;
    }

    ngx_log_debug1(NGX_LOG_DEBUG_RTMP, r->connection->log, 0,
        "hls_play upstream to %V", &ctx->upstream_url);

    url = ngx_rtmp_parse_http_url(r, &ctx->upstream_url);
    if (url == NULL) {

        ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
            "hls_play parse url failed");

        s->rc = NGX_HTTP_NOT_FOUND;
        s->status_code = s->rc;

        ngx_rtmp_finalize_session(s);
        goto next;
    }

    ngx_memzero(&ci, sizeof(ci));

    ci.name = (u_char*)"upstream";
    ci.url = url;
    ci.create = ngx_rtmp_hls_proxy_create;
    ci.handle = ngx_rtmp_hls_proxy_handle;
    ci.arg = v;
    ci.argsize = v ? sizeof(*v) : 0;

    return ngx_rtmp_netcall_create(s, &ci);

next:
    return next_play(s, v);
}


static ngx_int_t
ngx_rtmp_hls_open_file(ngx_http_request_t *r, ngx_chain_t *out)
{
	u_char                     *last;
	off_t                       start, len;
	size_t                      root;
	ngx_int_t                   rc;
	ngx_uint_t                  level;
	ngx_str_t                   path;
	ngx_log_t                  *log;
	ngx_buf_t                  *b;
	ngx_open_file_info_t        of;
	ngx_http_core_loc_conf_t   *clcf;

	last = ngx_http_map_uri_to_path(r, &path, &root, 0);
	if (last == NULL) {
        return NGX_ERROR;
	}

	log = r->connection->log;

	path.len = last - path.data;

	ngx_log_debug1(NGX_LOG_DEBUG_RTMP, log, 0,
                  "http hls open filename: \"%V\"", &path);

	clcf = ngx_http_get_module_loc_conf(r, ngx_http_core_module);

	ngx_memzero(&of, sizeof(ngx_open_file_info_t));

	of.read_ahead = clcf->read_ahead;
	of.directio = clcf->directio;
	of.valid = clcf->open_file_cache_valid;
	of.min_uses = clcf->open_file_cache_min_uses;
	of.errors = clcf->open_file_cache_errors;
	of.events = clcf->open_file_cache_events;

	if (ngx_open_cached_file(clcf->open_file_cache, &path, &of, r->pool) != NGX_OK) {

		switch (of.err) {

		case 0:
			return NGX_HTTP_INTERNAL_SERVER_ERROR;

		case NGX_ENOENT:
		case NGX_ENOTDIR:
		case NGX_ENAMETOOLONG:

			level = NGX_LOG_ERR;
			rc = NGX_HTTP_NOT_FOUND;
			break;

		case NGX_EACCES:
#if (NGX_HAVE_OPENAT)
		case NGX_EMLINK:
		case NGX_ELOOP:
#endif

			level = NGX_LOG_ERR;
			rc = NGX_HTTP_FORBIDDEN;
			break;

		default:

			level = NGX_LOG_CRIT;
			rc = NGX_HTTP_INTERNAL_SERVER_ERROR;
			break;
		}

		if (rc != NGX_HTTP_NOT_FOUND || clcf->log_not_found) {
			ngx_log_error(level, log, of.err,
						  "%s \"%s\" failed", of.failed, path.data);
		}

		return NGX_ERROR;
	}

	if (!of.is_file) {

        if (ngx_close_file(of.fd) == NGX_FILE_ERROR) {
            ngx_log_error(NGX_LOG_ALERT, log, ngx_errno,
                          ngx_close_file_n " \"%s\" failed", path.data);
        }

        return NGX_ERROR;
	}

	r->root_tested = !r->error_page;

	start = 0;
	len = of.size;

	log->action = "sending hls file to client";

	r->headers_out.status = NGX_HTTP_OK;
	r->headers_out.content_length_n = len;
	r->headers_out.last_modified_time = of.mtime;

	if (ngx_http_set_etag(r) != NGX_OK) {
        return NGX_ERROR;
	}

	if (ngx_http_set_content_type(r) != NGX_OK) {
        return NGX_ERROR;
	}

	b = ngx_pcalloc(r->pool, sizeof(ngx_buf_t));
	if (b == NULL) {
        return NGX_ERROR;
	}

	b->file = ngx_pcalloc(r->pool, sizeof(ngx_file_t));
	if (b->file == NULL) {
        return NGX_ERROR;
	}

	if (!r->header_sent) {
        ngx_http_send_header(r);
	}

	b->file_pos = start;
	b->file_last = of.size;

	b->in_file = b->file_last ? 1: 0;
	b->last_buf = (r == r->main) ? 1 : 0;
	b->last_in_chain = 1;

	b->file->fd = of.fd;
	b->file->name = path;
	b->file->log = log;
	b->file->directio = of.is_directio;

	out->buf = b;
	out->next = NULL;

	return NGX_OK;
}


static ngx_int_t
ngx_rtmp_hls_close_stream(ngx_rtmp_session_t *s, ngx_rtmp_close_stream_t *v)
{
    ngx_rtmp_hls_app_conf_t        *hacf;
    ngx_rtmp_hls_ctx_t             *ctx;

    hacf = ngx_rtmp_get_module_app_conf(s, ngx_rtmp_hls_module);
    if (hacf == NULL) {
        goto next;
    }

    if (!ngx_rtmp_get_attr_conf(hacf, hls)) {
        goto next;
    }

    ctx = ngx_rtmp_get_module_ctx(s, ngx_rtmp_hls_module);
    if (ctx == NULL) {
	goto next;
    }

    ngx_log_debug2(NGX_LOG_DEBUG_RTMP, s->connection->log, 0,
        "hls: leave '%V', publisher=%i",
        &s->name, ctx->publisher);

    if (ctx->publisher && ctx->closed == 0) {

        ngx_rtmp_hls_close_fragment(s, 0);

        if (hacf->continuous) {

            if (ngx_rtmp_hls_rename_file(ctx->playlist.data, 
				         ctx->playlist_bak.data)
                == NGX_FILE_ERROR)
            {
                ngx_log_error(NGX_LOG_ERR, s->connection->log, ngx_errno,
                    "hls: rename failed: '%V'->'%V'",
                    &ctx->playlist, &ctx->playlist_bak);
                return NGX_ERROR;
            }
        }
        ctx->closed = 1;
    }

next:
    return next_close_stream(s, v);
}


ngx_int_t
ngx_rtmp_hls_parse_aac_header(ngx_rtmp_session_t *s, ngx_uint_t *objtype,
    ngx_uint_t *srindex, ngx_uint_t *chconf)
{
    ngx_rtmp_codec_ctx_t   *codec_ctx;
    ngx_chain_t            *cl;
    u_char                 *p, b0, b1;

    codec_ctx = ngx_rtmp_get_module_ctx(s, ngx_rtmp_codec_module);

    cl = codec_ctx->aac_header;

    p = cl->buf->pos;

    if (ngx_rtmp_hls_copy(s, NULL, &p, 2, &cl) != NGX_OK) {
        return NGX_ERROR;
    }

    if (ngx_rtmp_hls_copy(s, &b0, &p, 1, &cl) != NGX_OK) {
        return NGX_ERROR;
    }

    if (ngx_rtmp_hls_copy(s, &b1, &p, 1, &cl) != NGX_OK) {
        return NGX_ERROR;
    }

    *objtype = b0 >> 3;
    if (*objtype == 0 || *objtype == 0x1f) {
        ngx_log_debug1(NGX_LOG_DEBUG_RTMP, s->connection->log, 0,
                       "hls: unsupported adts object type:%ui", *objtype);
        return NGX_ERROR;
    }

    if (*objtype > 4) {

        /*
         * Mark all extended profiles as LC
         * to make Android as happy as possible.
         */

        *objtype = 2;
    }

    *srindex = ((b0 << 1) & 0x0f) | ((b1 & 0x80) >> 7);
    if (*srindex == 0x0f) {
        ngx_log_debug1(NGX_LOG_DEBUG_RTMP, s->connection->log, 0,
                       "hls: unsupported adts sample rate:%ui", *srindex);
        return NGX_ERROR;
    }

    *chconf = (b1 >> 3) & 0x0f;

    ngx_log_debug3(NGX_LOG_DEBUG_RTMP, s->connection->log, 0,
                   "hls: aac object_type:%ui, sample_rate_index:%ui, "
                   "channel_config:%ui", *objtype, *srindex, *chconf);

    return NGX_OK;
}


static void
ngx_rtmp_hls_update_fragment(ngx_rtmp_session_t *s, uint64_t ts,
    ngx_int_t boundary, ngx_uint_t flush_rate, ngx_rtmp_header_t *h)
{
    ngx_rtmp_hls_ctx_t         *ctx;
    ngx_rtmp_hls_app_conf_t    *hacf;
    ngx_rtmp_hls_frag_t        *f;
    ngx_msec_t                  ts_frag_len;
    ngx_int_t                   same_frag, force, discont;
    double                      up_fragrate;
    double                      low_fragrate;
    ngx_buf_t                  *b;
    int64_t                     d, d1, system_duration;

    hacf = ngx_rtmp_get_module_app_conf(s, ngx_rtmp_hls_module);
    ctx = ngx_rtmp_get_module_ctx(s, ngx_rtmp_hls_module);
    f = NULL;
    force = 0;
    discont = 1;
    system_duration = 0;
    up_fragrate = 1 + (double) hacf->hls_fragment_wave / 100;
    low_fragrate = 1 - (double) hacf->hls_fragment_wave / 100;

    if (ctx->opened) {

        if (ngx_current_msec > ctx->frag_ts_system) {

            system_duration = ngx_current_msec - ctx->frag_ts_system;
        }

        f = ngx_rtmp_hls_get_frag(s, ctx->nfrags);
        d = (int64_t) (ts - ctx->frag_ts);
        d1 = (h->type == NGX_RTMP_MSG_AUDIO) ?
                    (int64_t) (ts - ctx->last_audio_ts) : (int64_t)(ts - ctx->last_video_ts);

        if (d > (int64_t) hacf->max_fraglen * 90) {

            force = 1;
        } else if (d > (int64_t) (ngx_rtmp_get_attr_conf(hacf, hls_fragment) * up_fragrate * 90)) {

            discont = 0;
            force = 1;
        } else if (d > 0) {

            f->duration = (ts - ctx->frag_ts) / 90000.; // Only ascending dts frames having a right to alter f->duration.
            discont = 0;
        } else if (system_duration > 0 && system_duration > (int64_t) hacf->max_fraglen) {

            f->duration = system_duration / 1000.;
            force = 1;
        }

        if (d1 < 0) {

            ngx_log_error(NGX_LOG_WARN, s->connection->log, 0,
                    "%s curr timestamp(%uL) less then last timestamp(%uL)",
                    h->type == NGX_RTMP_MSG_AUDIO ? "audio" : "video", ts,
                    h->type == NGX_RTMP_MSG_AUDIO ? ctx->last_audio_ts : ctx->last_video_ts);
            f->discont = 1;
        }

        h->type == NGX_RTMP_MSG_AUDIO ? (ctx->last_audio_ts = ts) : (ctx->last_video_ts = ts);

        if (force) {
            ngx_log_error(NGX_LOG_WARN, s->connection->log, 0,
                    "force to reap a hls fragment %uL.ts by ts %uL", f->id, ts);
        }
    }

    same_frag = 0;
    switch (hacf->slicing) {

        case NGX_RTMP_HLS_SLICING_PLAIN:

            if (f && f->duration < (uint32_t) (low_fragrate * ngx_rtmp_get_attr_conf(hacf, hls_fragment) / 1000.)) {

                boundary = 0;
            }

            break;

        case NGX_RTMP_HLS_SLICING_ALIGNED:

            ts_frag_len = ngx_rtmp_get_attr_conf(hacf, hls_fragment) * 90;
            same_frag   = (ctx->frag_ts / ts_frag_len) == (ts / ts_frag_len);
            if (f && same_frag) {

                boundary = 0;
            }

            if (f == NULL && (ctx->frag_ts == 0 || same_frag)) {

                ctx->frag_ts = ts;
                if (s->relay_type != NGX_NONE_RELAY) {

                    boundary = 0;
                }
            }

            break;
    }

    if (boundary || force) {

        ngx_rtmp_hls_close_fragment(s, ts);
        ngx_rtmp_hls_open_fragment(s, ts, discont, h);
    }

    b = ctx->aframe;
    if (ctx->opened && b && b->last > b->pos &&
        ctx->aframe_pts + (uint64_t) hacf->max_audio_delay * 90 / flush_rate
        < ts)
    {
        ngx_rtmp_hls_flush_audio(s);
    }
}


static ngx_int_t
ngx_rtmp_hls_flush_audio(ngx_rtmp_session_t *s)
{
    ngx_rtmp_hls_ctx_t              *ctx;
    ngx_rtmp_mpegts_frame_t          frame;
    ngx_buf_t                       *b;
    ngx_rtmp_hls_app_conf_t         *hacf;

    ctx = ngx_rtmp_get_module_ctx(s, ngx_rtmp_hls_module);

    if (ctx == NULL || !ctx->opened) {
        return NGX_OK;
    }
	
    hacf = ngx_rtmp_get_module_app_conf(s, ngx_rtmp_hls_module);
    if (hacf == NULL) {
        return NGX_OK;
    }

    b = ctx->aframe;

    if (b == NULL || b->pos == b->last) {
        return NGX_OK;
    }

    ngx_memzero(&frame, sizeof(frame));

    frame.dts = ctx->aframe_pts;
    frame.pts = frame.dts;
    frame.cc = ctx->audio_cc;
    frame.pid = 0x101;
    frame.sid = 0xc0;

    ngx_log_debug1(NGX_LOG_DEBUG_RTMP, s->connection->log, 0,
        "hls: flush audio pts=%uL", frame.pts);

    if (ngx_rtmp_mpegts_write_frame(&ctx->file, &frame, b) != NGX_OK) {

        ngx_log_error(NGX_LOG_ERR, s->connection->log, 0, "hls: audio flush failed");
    }

    ctx->audio_cc = frame.cc;
    b->pos = b->last = b->start;

    return NGX_OK;
}


static ngx_int_t
ngx_rtmp_hls_audio(ngx_rtmp_session_t *s, ngx_rtmp_header_t *h,
    ngx_chain_t *in)
{
    ngx_rtmp_hls_app_conf_t        *hacf;
    ngx_rtmp_hls_ctx_t             *ctx;
    ngx_rtmp_codec_ctx_t           *codec_ctx;
    uint64_t                       pts, est_pts;
    int64_t                        dpts;
    size_t                         bsize;
    ngx_buf_t                      *b;
    u_char                         *p;
    ngx_uint_t                     objtype, srindex, chconf, size;
    uint32_t                       timestamp;

    hacf = ngx_rtmp_get_module_app_conf(s, ngx_rtmp_hls_module);

    ctx = ngx_rtmp_get_module_ctx(s, ngx_rtmp_hls_module);

    codec_ctx = ngx_rtmp_get_module_ctx(s, ngx_rtmp_codec_module);

    if (hacf == NULL || ctx == NULL || codec_ctx == NULL  || h->mlen < 2) {
        return NGX_OK;
    }

    /* ngx_rtmp_codec_dump_header(s, "aac", in); */

    if (!ngx_rtmp_get_attr_conf(hacf, hls)) {
        return NGX_OK;
    }

    // reap fragment by NGX_NONE_RELAY.
    if (s->relay_type != NGX_NONE_RELAY) {
        return NGX_OK;
    }

    if (codec_ctx->audio_codec_id != NGX_RTMP_AUDIO_AAC ||
        codec_ctx->aac_header == NULL || ngx_rtmp_is_codec_header(in))
    {
        return NGX_OK;
    }

    b = ctx->aframe;

    if (b == NULL) {

        b = ngx_pcalloc(s->pool, sizeof(ngx_buf_t));
        if (b == NULL) {
            return NGX_ERROR;
        }

        ctx->aframe = b;

        b->start = ngx_palloc(s->pool, hacf->audio_buffer_size);
        if (b->start == NULL) {
            return NGX_ERROR;
        }

        b->end = b->start + hacf->audio_buffer_size;
        b->pos = b->last = b->start;
    }

    timestamp = h->timestamp;

    size = h->mlen - 2 + 7;
    pts = (uint64_t) timestamp * 90;

    if (b->start + size > b->end) {
        ngx_log_error(NGX_LOG_ERR, s->connection->log, 0,
                      "hls: too big audio frame");
        return NGX_OK;
    }

    /*
     * start new fragment here if
     * there's no video at all, otherwise
     * do it in video handler
     */

    ngx_rtmp_hls_update_fragment(s, pts, codec_ctx->video_header == NULL, 2, h);

    if (b->last + size > b->end) {
        ngx_rtmp_hls_flush_audio(s);
    }

    ngx_log_debug1(NGX_LOG_DEBUG_RTMP, s->connection->log, 0,
                   "hls: audio pts=%uL", pts);

    if (b->last + 7 > b->end) {
        ngx_log_debug0(NGX_LOG_DEBUG_RTMP, s->connection->log, 0,
                       "hls: not enough buffer for audio header");
        return NGX_OK;
    }

    p = b->last;
    b->last += 5;

    /* copy payload */

    for (; in && b->last < b->end; in = in->next) {

        bsize = in->buf->last - in->buf->pos;
        if (b->last + bsize > b->end) {
            bsize = b->end - b->last;
        }

        b->last = ngx_cpymem(b->last, in->buf->pos, bsize);
    }

    /* make up ADTS header */

    if (ngx_rtmp_hls_parse_aac_header(s, &objtype, &srindex, &chconf)
        != NGX_OK)
    {
        ngx_log_error(NGX_LOG_ERR, s->connection->log, 0,
                      "hls: aac header error");
        return NGX_OK;
    }

    /* we have 5 free bytes + 2 bytes of RTMP frame header */

    p[0] = 0xff;
    p[1] = 0xf1;
    p[2] = (u_char) (((objtype - 1) << 6) | (srindex << 2) |
                     ((chconf & 0x04) >> 2));
    p[3] = (u_char) (((chconf & 0x03) << 6) | ((size >> 11) & 0x03));
    p[4] = (u_char) (size >> 3);
    p[5] = (u_char) ((size << 5) | 0x1f);
    p[6] = 0xfc;

    if (p != b->start) {
        ctx->aframe_num++;
        return NGX_OK;
    }

    ctx->aframe_pts = pts;

    if (!hacf->sync || codec_ctx->sample_rate == 0) {
        return NGX_OK;
    }

    /* align audio frames */

    /* TODO: We assume here AAC frame size is 1024
     *       Need to handle AAC frames with frame size of 960 */

    est_pts = ctx->aframe_base + ctx->aframe_num * 90000 * 1024 /
                                 codec_ctx->sample_rate;
    dpts = (int64_t) (est_pts - pts);

    ngx_log_debug2(NGX_LOG_DEBUG_RTMP, s->connection->log, 0,
        "hls: audio sync dpts=%L (%.5fs)",
        dpts, dpts / 90000.);

    if (dpts <= (int64_t) hacf->sync * 90 &&
        dpts >= (int64_t) hacf->sync * -90)
    {
        ctx->aframe_num++;
        ctx->aframe_pts = est_pts;
        return NGX_OK;
    }

    ctx->aframe_base = pts;
    ctx->aframe_num  = 1;

    ngx_log_debug2(NGX_LOG_DEBUG_RTMP, s->connection->log, 0,
        "hls: audio sync gap dpts=%L (%.5fs)",
         dpts, dpts / 90000.);

    return NGX_OK;
}


static ngx_int_t
ngx_rtmp_hls_video(ngx_rtmp_session_t *s, ngx_rtmp_header_t *h,
    ngx_chain_t *in)
{
    ngx_rtmp_hls_app_conf_t        *hacf;
    ngx_rtmp_hls_ctx_t             *ctx;
    ngx_rtmp_codec_ctx_t           *codec_ctx;
    u_char                         *p;
    uint8_t                        fmt, ftype, htype, nal_type, src_nal_type;
    uint32_t                       len, rlen;
    ngx_buf_t                      out, *b;
    int32_t                        cts;
    ngx_rtmp_mpegts_frame_t        frame;
    ngx_uint_t                     nal_bytes;
    ngx_int_t                      aud_sent, sps_pps_sent, boundary;
    uint32_t                       timestamp;
    u_char                         buffer[NGX_RTMP_HLS_BUFSIZE];

    hacf = ngx_rtmp_get_module_app_conf(s, ngx_rtmp_hls_module);

    ctx = ngx_rtmp_get_module_ctx(s, ngx_rtmp_hls_module);

    codec_ctx = ngx_rtmp_get_module_ctx(s, ngx_rtmp_codec_module);

    if (hacf == NULL || ctx == NULL || codec_ctx->video_header == NULL ||
	    h->mlen < 1) 
    {
        return NGX_OK;
    }

    if (!ngx_rtmp_get_attr_conf(hacf, hls)) {
        return NGX_OK;
    }

    // reap fragment by NGX_NONE_RELAY.
    if (s->relay_type != NGX_NONE_RELAY) {
        return NGX_OK;
    }

    /* Only H264/H265 are supported */
    if (codec_ctx->video_codec_id != NGX_RTMP_VIDEO_H264 &&
        codec_ctx->video_codec_id != NGX_RTMP_VIDEO_H265) {
        return NGX_OK;
    }

    if(!codec_ctx->avc_nal_bytes) {
        ngx_log_error(NGX_LOG_WARN, s->connection->log, 0,
                      "hls: avc_nal_bytes occurs zero, name:%V, codec id=%uD",
                      &s->name, codec_ctx->video_codec_id);

        ngx_rtmp_codec_dump_header(s, "hls_video", codec_ctx->video_header);

        return NGX_OK;
    }

    p = in->buf->pos;
    if (ngx_rtmp_hls_copy(s, &fmt, &p, 1, &in) != NGX_OK) {
        return NGX_ERROR;
    }

    /* 1: keyframe (IDR)
     * 2: inter frame
     * 3: disposable inter frame
     * 4: generated keyframe
     * 5: video info/command frame
     */

    ftype = (fmt & 0xf0) >> 4;

    /* H264 HDR/PICT */

    if (ngx_rtmp_hls_copy(s, &htype, &p, 1, &in) != NGX_OK) {
        return NGX_ERROR;
    }

    /* proceed only with PICT.
     *
     * 0: AVC sequence header
     * 1: AVC NALU
     * 2: AVC end of sequence
     */

    if (htype != 1) {
        return NGX_OK;
    }

    /* 3 bytes: decoder delay */

    if (ngx_rtmp_hls_copy(s, &cts, &p, 3, &in) != NGX_OK) {
        return NGX_ERROR;
    }

    cts = ((cts & 0x00FF0000) >> 16) | ((cts & 0x000000FF) << 16) |
          (cts & 0x0000FF00);

    ngx_memzero(&out, sizeof(out));

    out.start = buffer;
    out.end = buffer + sizeof(buffer);
    out.pos = out.start;
    out.last = out.pos;

    nal_bytes = codec_ctx->avc_nal_bytes;
    aud_sent = 0;
    sps_pps_sent = 0;

    /* h264 nal -> len + body */
    /* body: nal_type(1) +  */
    while (in) {
        if (ngx_rtmp_hls_copy(s, &rlen, &p, nal_bytes, &in) != NGX_OK) {
            return NGX_OK;
        }

        len = 0;
        ngx_rtmp_rmemcpy(&len, &rlen, nal_bytes);

        if (len == 0) {
            continue;
        }

        if (ngx_rtmp_hls_copy(s, &src_nal_type, &p, 1, &in) != NGX_OK) {
            return NGX_OK;
        }

        nal_type = (codec_ctx->video_codec_id == NGX_RTMP_VIDEO_H264) ? (src_nal_type & 0x1f) : ((src_nal_type & 0x7e) >> 1);

        ngx_log_debug3(NGX_LOG_DEBUG_RTMP, s->connection->log, 0,
		               "hls: (%s) NAL type=%ui, len=%uD",
                       ((codec_ctx->video_codec_id == NGX_RTMP_VIDEO_H264) ? "avc" : "hevc"), 
                       (ngx_uint_t) nal_type, len);

        if (codec_ctx->video_codec_id == NGX_RTMP_VIDEO_H264 &&
            !(nal_type >= AVC_NAL_SPS && nal_type <= AVC_NAL_AUD)) {
            // not avc sps/pps
        } else if (codec_ctx->video_codec_id == NGX_RTMP_VIDEO_H265 &&
                   !(nal_type >= HEVC_NAL_VPS && nal_type <= HEVC_NAL_AUD)) {
            // not hevc vps/sps/pps
        } else {
            // ignore
            if (ngx_rtmp_hls_copy(s, NULL, &p, len - 1, &in) != NGX_OK) {
                return NGX_ERROR;
            }
            continue;
        }

        if (codec_ctx->video_codec_id == NGX_RTMP_VIDEO_H264) {
            if (!aud_sent) {
                switch (nal_type) {
                case AVC_NAL_SLICE:
                case AVC_NAL_IDR_SLICE:
                case AVC_NAL_SEI:
                    if (ngx_rtmp_hls_append_aud_h264(s, &out) != NGX_OK) {
                        ngx_log_error(NGX_LOG_ERR, s->connection->log, 0,
                                      "hls: error appending AUD NAL");
                    }
                case AVC_NAL_AUD:
                    aud_sent = 1;
                    break;
                }
            }

            switch (nal_type) {
            case AVC_NAL_SLICE:
                sps_pps_sent = 0;
                break;
            case AVC_NAL_IDR_SLICE:
                if (sps_pps_sent) {
                    break;
                }
                if (ngx_rtmp_hls_append_sps_pps_h264(s, &out) != NGX_OK) {
                    ngx_log_error(NGX_LOG_ERR, s->connection->log, 0,
                                  "hls: error appending AVC SPS/PPS NALs");
                }
                sps_pps_sent = 1;
                break;
            }
        } else if (codec_ctx->video_codec_id == NGX_RTMP_VIDEO_H265) {
            if (!aud_sent) {
                switch (nal_type) {
                case HEVC_NAL_TRAIL_N:
                case HEVC_NAL_TRAIL_R:
                case HEVC_NAL_IDR_W_RADL:
                case HEVC_NAL_RASL_N:
                case HEVC_NAL_RASL_R:
                case HEVC_NAL_CRA_NUT:
                    if (ngx_rtmp_hls_append_aud_h265(s, &out) != NGX_OK) {
                        ngx_log_error(NGX_LOG_ERR, s->connection->log, 0,
                                      "hls: error appending AUD NAL");
                    }
                case HEVC_NAL_AUD:
                    aud_sent = 1;
                    break;
                }
            }

            switch (nal_type) {
            case HEVC_NAL_TRAIL_N:
            case HEVC_NAL_TRAIL_R:
                sps_pps_sent = 0;
                break;
            case HEVC_NAL_CRA_NUT:
            case HEVC_NAL_IDR_W_RADL:
                if(sps_pps_sent) {
                    break;
                }
                if (ngx_rtmp_hls_append_sps_pps_h265(s, &out) != NGX_OK) {
                    ngx_log_error(NGX_LOG_ERR, s->connection->log, 0,
                                  "hls: error appending HEVC SPS/PPS NALs");
                }
                sps_pps_sent = 1;
                break;
            }
        } else {
            // Not H264/H265 we do nothing.
        }

        /* AnnexB prefix */

        if (out.end - out.last < 5) {
            ngx_log_error(NGX_LOG_ERR, s->connection->log, 0,
                          "hls: not enough buffer for AnnexB prefix");
            return NGX_OK;
        }

        /* first AnnexB prefix is long (4 bytes) */

        if (out.last == out.pos) {
            *out.last++ = 0;
        }

        *out.last++ = 0;
        *out.last++ = 0;
        *out.last++ = 1;
        *out.last++ = src_nal_type;

        /* NAL body */

        if (out.end - out.last < (ngx_int_t) len) {
            ngx_log_error(NGX_LOG_ERR, s->connection->log, 0,
                          "hls: not enough buffer for NAL");
            return NGX_OK;
        }

        if (ngx_rtmp_hls_copy(s, out.last, &p, len - 1, &in) != NGX_OK) {
            return NGX_ERROR;
        }

        out.last += (len - 1);
    }

    /* hls timstamp clear zero */
    timestamp = h->timestamp;

    /* set frame value */
    ngx_memzero(&frame, sizeof(frame));
    frame.cc = ctx->video_cc;
    frame.dts = (uint64_t) timestamp * 90;
    frame.pts = (uint64_t)((int64_t)frame.dts + cts * 90);
    frame.pid = 0x100;
    frame.sid = 0xe0;
    frame.key = (ftype == 1);

    /*
     * start new fragment if
     * - we have video key frame AND
     * - we have audio buffered or have no audio at all or stream is closed
     */

    b = ctx->aframe;
    boundary = frame.key && (codec_ctx->aac_header == NULL || !ctx->opened ||
                             (b && b->last > b->pos));

    ngx_rtmp_hls_update_fragment(s, frame.dts, boundary, 1, h);

    if (!ctx->opened) {
        return NGX_OK;
    }

    ngx_log_debug3(NGX_LOG_DEBUG_RTMP, s->connection->log, 0,
                   "hls: video pts=%uL, dts=%uL, cts=%D", frame.pts, frame.dts, cts);

    if (ngx_rtmp_mpegts_write_frame(&ctx->file, &frame, &out) != NGX_OK) {

        ngx_log_error(NGX_LOG_ERR, s->connection->log, 0, "hls: video frame failed");
    }

    ctx->video_cc = frame.cc;

    return NGX_OK;
}


static ngx_int_t
ngx_rtmp_hls_connect_done(ngx_rtmp_session_t *s, ngx_rtmp_header_t *h,
    ngx_chain_t *in)
{
    ngx_http_request_t    *r;

    if (!ngx_hls_pull_type(s->protocol)) {

        return NGX_OK;
    }

    r = s->r;

    return ngx_rtmp_http_hls_play_local(r);
}


static ngx_int_t
ngx_rtmp_hls_stream_begin(ngx_rtmp_session_t *s, ngx_rtmp_stream_begin_t *v)
{
    return next_stream_begin(s, v);
}


static ngx_int_t
ngx_rtmp_hls_stream_eof(ngx_rtmp_session_t *s, ngx_rtmp_stream_eof_t *v)
{
    ngx_rtmp_hls_flush_audio(s);

    ngx_rtmp_hls_close_fragment(s, 0);

    return next_stream_eof(s, v);
}


static ngx_int_t
ngx_rtmp_hls_cleanup_dir(ngx_str_t *ppath)
{
    ngx_dir_t                dir;
    time_t                   mtime, max_age;
    ngx_err_t                err;
    ngx_str_t                name, spath;
    u_char                  *p;
    ngx_int_t                nentries, nerased, fact;
    u_char                   path[NGX_MAX_PATH + 1];
    ngx_msec_t               expire;
    ngx_flag_t               read;
 
    ngx_log_debug1(NGX_LOG_DEBUG_RTMP, ngx_cycle->log, 0,
                   "hls: cleanup path='%V'",
                   ppath);

    if (ngx_open_dir(ppath, &dir) != NGX_OK) {
        ngx_log_debug1(NGX_LOG_DEBUG_RTMP, ngx_cycle->log, ngx_errno,
                      "hls: cleanup open dir failed '%V'", ppath);
        return NGX_ERROR;
    }

    nentries = 0;
    nerased = 0;
    expire = 0;
    read = 0;

    for ( ;; ) {
        ngx_set_errno(0);

        if (ngx_read_dir(&dir) == NGX_ERROR) {
            err = ngx_errno;

            if (ngx_close_dir(&dir) == NGX_ERROR) {
                ngx_log_error(NGX_LOG_ERR, ngx_cycle->log, ngx_errno,
                              "hls: cleanup " ngx_close_dir_n " \"%V\" failed",
                              ppath);
            }

            if (err == NGX_ENOMOREFILES) {
                return nentries - nerased;
            }

            ngx_log_error(NGX_LOG_ERR, ngx_cycle->log, err,
                          "hls: cleanup " ngx_read_dir_n
                          " '%V' failed", ppath);
            return NGX_ERROR;
        }

        name.data = ngx_de_name(&dir);
        name.len  = ngx_de_namelen(&dir);

        if (name.data[0] == '.') {
            if (name.len != ngx_strlen(NGX_RTMP_HLS_EXIPRE_FILE_NAME) ||
                ngx_strncmp(name.data, NGX_RTMP_HLS_EXIPRE_FILE_NAME, name.len) != 0) {

                continue;
            }
        }

        p = ngx_snprintf(path, sizeof(path) - 1, "%V/%V", ppath, &name);
        *p = 0;

        spath.data = path;
        spath.len = p - path;

        nentries++;

        if (!dir.valid_info && ngx_de_info(path, &dir) == NGX_FILE_ERROR) {
            ngx_log_error(NGX_LOG_ERR, ngx_cycle->log, ngx_errno,
                          "hls: cleanup " ngx_de_info_n " \"%V\" failed",
                          &spath);
            continue;
        }

        if (ngx_de_is_dir(&dir)) {

            if (ngx_rtmp_hls_cleanup_dir(&spath) == 0) {
                ngx_log_debug1(NGX_LOG_DEBUG_RTMP, ngx_cycle->log, 0,
                               "hls: cleanup dir '%V'", &name);

                /*
                 * null-termination gets spoiled in win32
                 * version of ngx_open_dir
                 */
                *p = 0;
                if (ngx_delete_dir(path) == NGX_FILE_ERROR) {
                    ngx_log_error(NGX_LOG_ERR, ngx_cycle->log, ngx_errno,
                                  "hls: cleanup " ngx_delete_dir_n
                                  " failed on '%V'", &spath);
                } else {
                    nerased++;
                }
            }

            continue;
        }

        if (!ngx_de_is_file(&dir)) {
            continue;
        }

        if (name.len >= 3 && name.data[name.len - 3] == '.' &&
                             name.data[name.len - 2] == 't' &&
                             name.data[name.len - 1] == 's')
        {
            fact = 400;

        } else if (name.len >= 5 && name.data[name.len - 5] == '.' &&
                                    name.data[name.len - 4] == 'm' &&
                                    name.data[name.len - 3] == '3' &&
                                    name.data[name.len - 2] == 'u' &&
                                    name.data[name.len - 1] == '8')
        {
            fact = 1000;

        } else if (name.len >= 9 && name.data[name.len - 9] == '.' &&
                                    name.data[name.len - 8] == 'm' &&
                                    name.data[name.len - 7] == '3' &&
                                    name.data[name.len - 6] == 'u' &&
                                    name.data[name.len - 5] == '8' &&
                                    name.data[name.len - 4] == '.' &&
                                    name.data[name.len - 3] == 'b' &&
                                    name.data[name.len - 2] == 'a' &&
                                    name.data[name.len - 1] == 'k' )
        {
            fact = 1000;

        } else if (name.len == 8 && name.data[name.len - 8] == '.' &&
                                    name.data[name.len - 7] == 'e' &&
                                    name.data[name.len - 6] == 'x' &&
                                    name.data[name.len - 5] == 'p' &&
                                    name.data[name.len - 4] == 'i' &&
                                    name.data[name.len - 3] == 'n' &&
                                    name.data[name.len - 2] == 'f' &&
                                    name.data[name.len - 1] == 'o' )
        {
            fact = 400;

        } else {
            ngx_log_debug1(NGX_LOG_DEBUG_RTMP, ngx_cycle->log, 0,
                           "hls: cleanup skip unknown file type '%V'", &name);
            continue;
        }

        if (!read) {

            if (ngx_rtmp_hls_read_expire(ppath, &expire) == NGX_ERROR) {

                ngx_log_debug0(NGX_LOG_DEBUG_RTMP, ngx_cycle->log, 0,
                           "ngx_rtmp_hls_cleanup_dir: read expinfo file failed");
                expire = 0;
            }

            read = 1;
	    }

        max_age = expire / fact;
        mtime = ngx_de_mtime(&dir);
        if (mtime + max_age > ngx_cached_time->sec) {
            continue;
        }

        ngx_log_debug3(NGX_LOG_DEBUG_RTMP, ngx_cycle->log, 0,
                       "hls: cleanup '%V' mtime=%T age=%T ",
                       &name, mtime, ngx_cached_time->sec - mtime);

    	if (ngx_delete_file(path) == NGX_FILE_ERROR) {
        	ngx_log_error(NGX_LOG_ERR, ngx_cycle->log, ngx_errno,
                      "hls: cleanup " ngx_delete_file_n " failed on '%V'",
                      &spath);
        	continue;
    	}

        nerased++;
    }
}


static time_t
ngx_rtmp_hls_cleanup(void *data)
{
    ngx_rtmp_hls_cleanup_t *cleanup = data;

    ngx_rtmp_hls_cleanup_dir(&cleanup->path);

    return cleanup->hls_playlist_length / 500;
}


static char *
ngx_rtmp_hls_variant(ngx_conf_t *cf, ngx_command_t *cmd, void *conf)
{
    ngx_rtmp_hls_app_conf_t  *hacf = conf;
    ngx_str_t                *value, *arg;
    ngx_uint_t                n;
    ngx_rtmp_hls_variant_t   *var;

    value = cf->args->elts;

    if (hacf->variant == NULL) {
        hacf->variant = ngx_array_create(cf->pool, 1,
                                         sizeof(ngx_rtmp_hls_variant_t));
        if (hacf->variant == NULL) {
            return NGX_CONF_ERROR;
        }
    }

    var = ngx_array_push(hacf->variant);
    if (var == NULL) {
        return NGX_CONF_ERROR;
    }

    ngx_memzero(var, sizeof(ngx_rtmp_hls_variant_t));

    var->suffix = value[1];

    if (cf->args->nelts == 2) {
        return NGX_CONF_OK;
    }

    if (ngx_array_init(&var->args, cf->pool, cf->args->nelts - 2,
                       sizeof(ngx_str_t))
        != NGX_OK)
    {
        return NGX_CONF_ERROR;
    }

    arg = ngx_array_push_n(&var->args, cf->args->nelts - 2);
    if (arg == NULL) {
        return NGX_CONF_ERROR;
    }

    for (n = 2; n < cf->args->nelts; n++) {
        *arg++ = value[n];
    }

    return NGX_CONF_OK;
}


static void *
ngx_rtmp_hls_create_app_conf(ngx_conf_t *cf)
{
    ngx_rtmp_hls_app_conf_t *conf;

    conf = ngx_pcalloc(cf->pool, sizeof(ngx_rtmp_hls_app_conf_t));
    if (conf == NULL) {
        return NULL;
    }

    conf->hls = NGX_CONF_UNSET;
    conf->hls_fragment = NGX_CONF_UNSET_MSEC;
    conf->hls_fragment_wave = NGX_CONF_UNSET_UINT;
    conf->hls_playlist_length = NGX_CONF_UNSET_MSEC;
    conf->max_fraglen = NGX_CONF_UNSET_MSEC;
    conf->muxdelay = NGX_CONF_UNSET_MSEC;
    conf->sync = NGX_CONF_UNSET_MSEC;
    conf->winfrags = NGX_CONF_UNSET_UINT;
    conf->continuous = NGX_CONF_UNSET;
    conf->nested = NGX_CONF_UNSET;
    conf->naming = NGX_CONF_UNSET_UINT;
    conf->slicing = NGX_CONF_UNSET_UINT;
    conf->type = NGX_CONF_UNSET_UINT;
    conf->max_audio_delay = NGX_CONF_UNSET_MSEC;
    conf->audio_buffer_size = NGX_CONF_UNSET_SIZE;
    conf->cleanup = NGX_CONF_UNSET;
    conf->granularity = NGX_CONF_UNSET;

    return conf;
}


static char *
ngx_rtmp_hls_merge_app_conf(ngx_conf_t *cf, void *parent, void *child)
{
    ngx_rtmp_hls_app_conf_t    *prev = parent;
    ngx_rtmp_hls_app_conf_t    *conf = child;
    ngx_rtmp_hls_cleanup_t     *cleanup;
    ngx_path_t                **path;

    ngx_conf_merge_value(conf->hls, prev->hls, 0);
    ngx_conf_merge_msec_value(conf->hls_fragment, prev->hls_fragment, 5000);
    ngx_conf_merge_uint_value(conf->hls_fragment_wave, prev->hls_fragment_wave, 20);
    ngx_conf_merge_msec_value(conf->max_fraglen, prev->max_fraglen,
                              conf->hls_fragment * 3);
    ngx_conf_merge_msec_value(conf->muxdelay, prev->muxdelay, 700);
    ngx_conf_merge_msec_value(conf->sync, prev->sync, 2);
    ngx_conf_merge_msec_value(conf->hls_playlist_length, prev->hls_playlist_length, 15000);
    ngx_conf_merge_value(conf->continuous, prev->continuous, 0);
    ngx_conf_merge_value(conf->nested, prev->nested, 1);
    ngx_conf_merge_uint_value(conf->naming, prev->naming,
                              NGX_RTMP_HLS_NAMING_SYSTEM);
    ngx_conf_merge_uint_value(conf->slicing, prev->slicing,
                              NGX_RTMP_HLS_SLICING_PLAIN);
    ngx_conf_merge_uint_value(conf->type, prev->type,
                              NGX_RTMP_HLS_TYPE_LIVE);
    ngx_conf_merge_msec_value(conf->max_audio_delay, prev->max_audio_delay,
                              300);
    ngx_conf_merge_size_value(conf->audio_buffer_size, prev->audio_buffer_size,
                              NGX_RTMP_HLS_BUFSIZE);
    
    ngx_conf_merge_value(conf->cleanup, prev->cleanup, 1);
    ngx_conf_merge_str_value(conf->base_url, prev->base_url, "");
    ngx_conf_merge_value(conf->granularity, prev->granularity, 0);
    ngx_conf_merge_str_value(conf->path, prev->path, "/dev/shm");

    if (conf->hls_fragment) {
        conf->winfrags = conf->hls_playlist_length / conf->hls_fragment;
        conf->max_fraglen = conf->hls_fragment * 3;
    }

    /* schedule cleanup */

    if (conf->path.len && conf->cleanup &&
        conf->type != NGX_RTMP_HLS_TYPE_EVENT)
    {
        if (conf->path.data[conf->path.len - 1] == '/') {
            conf->path.len--;
        }

        cleanup = ngx_pcalloc(cf->pool, sizeof(*cleanup));
        if (cleanup == NULL) {
            return NGX_CONF_ERROR;
        }

        cleanup->path = conf->path;
        cleanup->hls_playlist_length = conf->hls_playlist_length;
        cleanup->continuous = conf->continuous;

        conf->slot = ngx_pcalloc(cf->pool, sizeof(*conf->slot));
        if (conf->slot == NULL) {
            return NGX_CONF_ERROR;
        }

        conf->slot->manager = ngx_rtmp_hls_cleanup;
        conf->slot->name = conf->path;
        conf->slot->data = cleanup;
        conf->slot->conf_file = cf->conf_file->file.name.data;
        conf->slot->line = cf->conf_file->line;

        path = ngx_array_push(&cf->cycle->paths);
        if (path == NULL) {
            return NGX_CONF_ERROR;
        }

        *path = conf->slot;
    }

    return NGX_CONF_OK;
}

static void
ngx_rtmp_hls_close_session_handler(ngx_rtmp_session_t *s)
{
    ngx_connection_t                   *c;
    ngx_rtmp_core_srv_conf_t           *cscf;

    c = s->connection;

    cscf = ngx_rtmp_get_module_srv_conf(s, ngx_rtmp_core_module);

    ngx_log_error(NGX_LOG_INFO, c->log, 0, "hls close session");

    s->hls_etime_ms = ngx_current_msec;

    ngx_rtmp_log_evt_hls_out(s);

    ngx_rtmp_fire_event(s, NGX_RTMP_DISCONNECT, NULL, NULL);

    if (s->ping_evt.timer_set) {
        ngx_del_timer(&s->ping_evt);
    }

    if (s->in_old_pool) {
        ngx_destroy_pool(s->in_old_pool);
    }

    if (s->in_pool) {
        ngx_destroy_pool(s->in_pool);
    }

    ngx_rtmp_free_handshake_buffers(s);

    while (s->out_pos != s->out_last) {
        ngx_rtmp_free_shared_chain(cscf, s->out[s->out_pos++]);
        s->out_pos %= s->out_queue;
    }
}

static void
ngx_rtmp_hls_close_connection(ngx_http_request_t *r)
{
    ngx_rtmp_session_t		   *s;
    ngx_rtmp_http_hls_ctx_t    *httpctx;

    httpctx = ngx_http_get_module_ctx(r, ngx_rtmp_http_hls_module);

    s = httpctx->s;

    ngx_log_error(NGX_LOG_INFO, s->connection->log, 0, "hls close connection");

    if (s->connection->write && s->connection->write->timer_set) {

        ngx_del_timer(s->connection->write);
    }

    if (s->connection->read && s->connection->read->timer_set) {

        ngx_del_timer(s->connection->read);
    }

    --ngx_rtmp_hls_naccepted;

    ngx_rtmp_hls_close_session_handler(s);
}


static ngx_rtmp_session_t *
ngx_rtmp_http_hls_init_session(ngx_http_request_t *r, ngx_rtmp_addr_conf_t *addr_conf)
{
    ngx_rtmp_core_srv_conf_t       *cscf;
    ngx_rtmp_http_hls_ctx_t        *ctx;
    ngx_rtmp_session_t             *s;
    ngx_connection_t               *c;

    c = r->connection;

    s = ngx_pcalloc(r->pool, sizeof(ngx_rtmp_session_t) +
                    sizeof(ngx_chain_t *) * ((ngx_rtmp_core_srv_conf_t *)
                    addr_conf->ctx->srv_conf[ngx_rtmp_core_module
                    .ctx_index])->out_queue);
    if (s == NULL) {
        ngx_http_finalize_request(r, NGX_DECLINED);
        return NULL;
    }

    ctx = ngx_pcalloc(r->pool, sizeof(ngx_rtmp_http_hls_ctx_t));
    if (ctx == NULL) {
        return NULL;
    }

    ngx_http_set_ctx(r, ctx, ngx_rtmp_http_hls_module);

    // attach rtmp session to http ctx.
    ctx->s = s;

    s->pool = r->pool;

    s->r = r;
    s->rc = NGX_OK;

    s->addr_conf = addr_conf;

    s->main_conf = addr_conf->ctx->main_conf;
    s->srv_conf = addr_conf->ctx->srv_conf;

    s->addr_text = &addr_conf->addr_text;

    s->connection = c;
    r->rtmp_http_close_handler = ngx_rtmp_hls_close_connection;

    s->ctx = ngx_pcalloc(s->pool, sizeof(void *) * ngx_rtmp_max_module);
    if (s->ctx == NULL) {
        ngx_rtmp_finalize_session(s);
        return NULL;
    }

    cscf = ngx_rtmp_get_module_srv_conf(s, ngx_rtmp_core_module);

    s->out_queue = cscf->out_queue;
    s->out_cork = cscf->out_cork;
    s->in_streams = ngx_pcalloc(s->pool, sizeof(ngx_rtmp_stream_t)
                                * cscf->max_streams);
    if (s->in_streams == NULL) {
        ngx_rtmp_finalize_session(s);
        return NULL;
    }
    
#if (nginx_version >= 1007005)
    ngx_queue_init(&s->posted_dry_events);
#endif

    s->epoch = ngx_current_msec;
    s->timeout = cscf->timeout;
    s->buflen = cscf->buflen;
    ngx_rtmp_set_chunk_size(s, NGX_RTMP_DEFAULT_CHUNK_SIZE);

    if (ngx_rtmp_fire_event(s, NGX_RTMP_CONNECT, NULL, NULL) != NGX_OK) {
        ngx_rtmp_finalize_session(s);
        return NULL;
    }

    /** to init the session event'log **/
    s->connect_time = ngx_time();
    s->stream_stat = NGX_RTMP_STREAM_BEGIN;

    return s;
}


static ngx_int_t
ngx_rtmp_http_hls_init_connection(ngx_http_request_t *r, ngx_rtmp_conf_port_t *cf_port)
{
    ngx_uint_t             i;
    ngx_rtmp_port_t       *port;
    ngx_rtmp_session_t    *s;
    ngx_rtmp_addr_conf_t  *addr_conf;
    ngx_connection_t      *c;
    struct sockaddr       *sa;
    struct sockaddr_in    *sin;
    ngx_rtmp_in_addr_t    *addr;
    ngx_int_t              unix_socket;
#if (NGX_HAVE_INET6)
    struct sockaddr_in6   *sin6;
    ngx_rtmp_in6_addr_t   *addr6;
#endif

    c = r->connection;

    ++ngx_rtmp_hls_naccepted;

    port = cf_port->ports.elts;
    unix_socket = 0;

    if (port->naddrs > 1) {

        /*
         * There are several addresses on this port and one of them
         * is the "*:port" wildcard so getsockname() is needed to determine
         * the server address.
         *
         * AcceptEx() already gave this address.
         */

        if (ngx_connection_local_sockaddr(c, NULL, 0) != NGX_OK) {
            ngx_rtmp_close_connection(c);
            return NGX_ERROR;
        }

        sa = c->local_sockaddr;

        switch (sa->sa_family) {

#if (NGX_HAVE_INET6)
        case AF_INET6:
            sin6 = (struct sockaddr_in6 *) sa;

            addr6 = port->addrs;

            /* the last address is "*" */

            for (i = 0; i < port->naddrs - 1; i++) {
                if (ngx_memcmp(&addr6[i].addr6, &sin6->sin6_addr, 16) == 0) {
                    break;
                }
            }

            addr_conf = &addr6[i].conf;

            break;
#endif

        case AF_UNIX:
            unix_socket = 1;

        default: /* AF_INET */
            sin = (struct sockaddr_in *) sa;

            addr = port->addrs;

            /* the last address is "*" */

            for (i = 0; i < port->naddrs - 1; i++) {
                if (addr[i].addr == sin->sin_addr.s_addr) {
                    break;
                }
            }

            addr_conf = &addr[i].conf;

            break;
        }

    } else {
        switch (c->local_sockaddr->sa_family) {

#if (NGX_HAVE_INET6)
        case AF_INET6:
            addr6 = port->addrs;
            addr_conf = &addr6[0].conf;
            break;
#endif

        case AF_UNIX:
            unix_socket = 1;

        default: /* AF_INET */
            addr = port->addrs;
            addr_conf = &addr[0].conf;
            break;
        }
    }

    ngx_log_error(NGX_LOG_INFO, c->log, 0, "hls client connected '%V'", &c->addr_text);

    s = ngx_rtmp_http_hls_init_session(r, addr_conf);
    if (s == NULL) {
        return NGX_ERROR;
    }

    r->read_event_handler = ngx_http_test_reading;
    // r->blocked = 1;

    s->auto_pushed = unix_socket;

	return NGX_OK;
}


static ngx_chain_t *
ngx_rtmp_hls_proxy_create(ngx_rtmp_session_t *s, void *arg,
        ngx_pool_t *pool)
{
    ngx_rtmp_hls_ctx_t             *ctx;
    ngx_chain_t                    *al;
    ngx_buf_t                      *b;
    ngx_http_request_t             *r;
    ngx_str_t                       args, vhost;
    u_char                         *colon;
    ngx_int_t                       family = AF_INET;

    ctx = ngx_rtmp_get_module_ctx(s, ngx_rtmp_hls_module);
    if (ctx == NULL) {
        return NGX_OK;
    }

    r = s->r;

    al = ngx_alloc_chain_link(pool);
    if (al == NULL) {
        return NULL;
    }

    vhost = r->headers_in.host->value;
    colon = (u_char *)ngx_strchr(vhost.data, ':');
    if (colon) {

        vhost.len = colon - vhost.data;
    }

    b = ngx_create_temp_buf(pool, r->args.len);
    if (b == NULL) {
        return NULL;
    }

    ngx_memzero(&args, sizeof(args));

    al->buf = b;
    al->next = NULL;

    if (r->args.len > 0) {

        b->last = ngx_cpymem(b->last, r->args.data, r->args.len);
    }

    return ngx_rtmp_netcall_http_format_request(NGX_RTMP_NETCALL_HTTP_GET, &vhost, family,
                                                &r->uri, &args, al, s->x_forwarded_for, NULL, pool,
                                                &ngx_rtmp_hls_urlencoded);
}


static ngx_int_t
ngx_rtmp_hls_proxy_handle(ngx_rtmp_session_t *s,
        void *arg, ngx_chain_t *in)
{
    ngx_rtmp_core_srv_conf_t       *cscf;
    ngx_rtmp_hls_ctx_t             *ctx;
    ngx_chain_t                    *out;
    ngx_rtmp_play_t                *v = arg;

    u_char                          status_code[NGX_RTMP_MAX_NAME];

    cscf = ngx_rtmp_get_module_srv_conf(s, ngx_rtmp_core_module);

    ctx = ngx_rtmp_get_module_ctx(s, ngx_rtmp_hls_module);
    if (ctx == NULL) {
        goto next;
    }

    if (!in) {
        ngx_log_error(NGX_LOG_WARN, s->connection->log, 0,
        	      "hls: proxy received none!");
        return NGX_ERROR;
    }

    ngx_memzero(status_code, NGX_RTMP_MAX_NAME);
    ngx_rtmp_notify_parse_http_retcode(s, in, status_code);

    s->status_code = ngx_atoi(status_code, ngx_strlen(status_code));

    ctx->write_handler_backup = s->connection->write->handler;
    s->connection->write->handler = ngx_rtmp_hls_send;

    ngx_log_debug0(NGX_LOG_DEBUG_RTMP, s->connection->log, 0, "hls proxy handle");

    out = ngx_rtmp_append_shared_bufs(cscf, NULL, in);

    if (ngx_rtmp_hls_send_message(s, out, 0) != NGX_OK) {

        goto error;
    }

    ngx_rtmp_free_shared_chain(cscf, out);

next:
    return next_play(s, v);

error:
    ngx_rtmp_free_shared_chain(cscf, out);
    return NGX_ERROR;
}


static ngx_int_t
ngx_rtmp_http_hls_change_uri(ngx_http_request_t *r, ngx_str_t unique_name,
	ngx_rtmp_hls_app_conf_t *hacf)
{
    u_char                   *p;
    ngx_str_t                 uri;
    ngx_connection_t         *c;

    c = r->connection;

    uri.len = 1 + unique_name.len + r->uri.len;  /*  '/' + unique_name + r->uri("/live/stream/index.m3u8") */
    uri.data = ngx_palloc(c->pool, uri.len);

    p = uri.data;

    *p++ = '/';
    p = ngx_cpymem(p, unique_name.data, unique_name.len);

    p = ngx_cpymem(p, r->uri.data, r->uri.len);

    r->uri = uri;

    return NGX_OK;
}


#define NGX_RTMP_HLS_HTTP_TAG  "http://"

ngx_int_t
ngx_rtmp_http_hls_build_url(ngx_rtmp_session_t *s, ngx_str_t *remote_ip, ngx_int_t remote_port)
{
    ngx_http_request_t       *r;
    u_char                    strport[32];
    ngx_rtmp_hls_ctx_t       *ctx;

    r = s->r;
    if (r == NULL) {

        return NGX_ERROR;
    }

    ctx = ngx_rtmp_get_module_ctx(s, ngx_rtmp_hls_module);
    if (ctx == NULL) {

        return NGX_ERROR;
    }

    ngx_memzero(&ctx->upstream_url, sizeof(ctx->upstream_url));

    ctx->upstream_url.len =  ngx_strlen(NGX_RTMP_HLS_HTTP_TAG); // + http://
    ctx->upstream_url.len += remote_ip->len;                    // + 127.0.0.1

    ngx_log_debug2(NGX_LOG_DEBUG_RTMP, r->connection->log, 0,
    		"http_hls auth len: '%d' remote_ip: '%V'", ctx->upstream_url.len, remote_ip);

    if (remote_port != 80) {
        ctx->upstream_url.len ++;                               // + :

        ngx_memzero(strport, sizeof(strport));
        ngx_sprintf(strport, "%d", remote_port);
        ctx->upstream_url.len += ngx_strlen(strport);           // + 8080

        ngx_log_debug2(NGX_LOG_DEBUG_RTMP, r->connection->log, 0,
        		"http_hls auth len: '%d' strport: '%s'", ctx->upstream_url.len, strport);
    }

    ctx->upstream_url.len += r->uri.len;

    ngx_log_debug2(NGX_LOG_DEBUG_RTMP, r->connection->log, 0,
    		"http_hls auth len: '%d' uri: '%V'", ctx->upstream_url.len, &r->uri);

    ctx->upstream_url.data = ngx_palloc(r->pool, ctx->upstream_url.len);

    if (remote_port != 80) {
        *ngx_sprintf(ctx->upstream_url.data, NGX_RTMP_HLS_HTTP_TAG"%V:%d%V",
    			remote_ip, remote_port, &r->uri) = 0;
    } else {
        *ngx_sprintf(ctx->upstream_url.data, NGX_RTMP_HLS_HTTP_TAG"%V%V",
    			remote_ip, &r->uri) = 0;
    }

    ngx_log_error(NGX_LOG_INFO, r->connection->log, 0,
    		"http_hls auth set location: '%V'", &ctx->upstream_url);

    return NGX_OK;
}

static ngx_int_t
ngx_rtmp_http_hls_play_local(ngx_http_request_t *r)
{
    static ngx_rtmp_play_t      v;

    ngx_rtmp_session_t         *s;
    ngx_rtmp_hls_ctx_t         *ctx;
    ngx_rtmp_core_srv_conf_t   *cscf;
    ngx_rtmp_core_app_conf_t   *cacf;
    ngx_rtmp_http_hls_ctx_t    *httpctx;

    httpctx = ngx_http_get_module_ctx(r, ngx_rtmp_http_hls_module);

    s = httpctx->s;

    ngx_memzero(&v, sizeof(ngx_rtmp_play_t));

    ngx_memcpy(v.name, s->name.data, ngx_min(s->name.len, sizeof(v.name) - 1));
    ngx_memcpy(v.args, s->args.data, ngx_min(s->args.len, sizeof(v.args) - 1));

    if (!ngx_rtmp_remote_conf()) {

        if (ngx_rtmp_cmd_get_core_srv_conf(s, NGX_RTMP_CMD_HLS_PLAY, &s->host_in, &s->app, &cscf, &cacf) != NGX_OK) {

            ngx_log_error(NGX_LOG_WARN, s->connection->log, 0, "hls_play: forbidden");
            return NGX_ERROR;
        }

        s->app_conf = cacf->app_conf;

    } else {

        cscf = ngx_rtmp_get_module_srv_conf(s, ngx_rtmp_core_module);

        s->app_conf = cscf->ctx->app_conf;
    }

    ctx = ngx_rtmp_get_module_ctx(s, ngx_rtmp_hls_module);
    if (ctx == NULL) {
        ctx = ngx_pcalloc(s->pool, sizeof(ngx_rtmp_hls_ctx_t));
        ngx_rtmp_set_ctx(s, ctx, ngx_rtmp_hls_module);
    }

    ctx->upstream_url.data = NULL;
    ctx->upstream_url.len = 0;

    return ngx_rtmp_cmd_start_play(s, &v);
}


static ngx_int_t
ngx_rtmp_http_hls_connect_local(ngx_http_request_t *r, ngx_str_t *app, ngx_str_t *name, ngx_str_t *fname, ngx_int_t protocol)
{
    static ngx_rtmp_connect_t   v;

    ngx_rtmp_session_t         *s;
    ngx_connection_t           *c;
    ngx_rtmp_http_hls_ctx_t    *httpctx;
    ngx_rtmp_hls_ctx_t         *ctx;

    httpctx = ngx_http_get_module_ctx(r, ngx_rtmp_http_hls_module);

    s = httpctx->s;
    c = r->connection;

    if (!(r->headers_in.host && r->headers_in.host->value.len > 0)) {

        return NGX_ERROR;
    }

    ngx_memzero(&v, sizeof(ngx_rtmp_connect_t));

    ngx_memcpy(v.app, app->data, ngx_min(app->len, sizeof(v.app) - 1));
    ngx_memcpy(v.args, r->args.data, ngx_min(r->args.len, sizeof(v.args) - 1));
    ngx_memcpy(v.flashver, "HLS flashver", ngx_strlen("HLS flashver"));
    ngx_memcpy(v.swf_url, "HLS swf_url", ngx_strlen("HLS swf_url"));
    ngx_memcpy(v.tc_url, "HLS tc_url", ngx_strlen("HLS tc_url"));
    ngx_memcpy(v.page_url, "HLS page_url", ngx_strlen("HLS page_url"));

    ngx_str_set(&s->host_in, "default_host");
    s->port_in = 8080;

    NGX_RTMP_SET_STRPAR(app);
    NGX_RTMP_SET_STRPAR(args);
    NGX_RTMP_SET_STRPAR(flashver);
    NGX_RTMP_SET_STRPAR(swf_url);
    NGX_RTMP_SET_STRPAR(tc_url);
    NGX_RTMP_SET_STRPAR(page_url);

    ngx_rtmp_parse_host(s->pool, r->headers_in.host->value, &s->host_in, &s->port_in);

    ngx_http_arg(r, (u_char*)"vhost", 5, &s->host_in);

    s->name.len = name->len;
    s->name.data = ngx_pstrdup(s->pool, name);

    s->hls_name.len = fname->len;
    s->hls_name.data = ngx_pstrdup(s->pool, fname);

    s->protocol = protocol;

    ctx = ngx_rtmp_get_module_ctx(s, ngx_rtmp_hls_module);
    if (ctx == NULL) {
        ctx = ngx_pcalloc(s->pool, sizeof(ngx_rtmp_hls_ctx_t));
        ngx_rtmp_set_ctx(s, ctx, ngx_rtmp_hls_module);
    }

    ctx->upstream_url.data = NULL;
    ctx->upstream_url.len = 0;

    return ngx_rtmp_cmd_start_connect(s, &v);
}


static ngx_int_t
ngx_rtmp_http_hls_handler(ngx_http_request_t *r)
{
    ngx_rtmp_http_hls_loc_conf_t        *hlcf;
    ngx_rtmp_core_main_conf_t           *cmcf;
    ngx_rtmp_conf_port_t                *port;
    ngx_int_t                            protocol, rc = 0;
    ngx_str_t                            app, name, fname;
    ngx_int_t                            nslash;
    size_t                               i;

    cmcf = ngx_rtmp_core_main_conf;
    if (cmcf == NULL || cmcf->ports.nelts == 0) {
        return NGX_ERROR;
    }

    hlcf = ngx_http_get_module_loc_conf(r, ngx_rtmp_http_hls_module);
    if (hlcf == NULL || !hlcf->hls) {
        return NGX_DECLINED;
    }

    if (!(r->method & (NGX_HTTP_GET|NGX_HTTP_HEAD))
        || r->headers_in.host == NULL) {
        return NGX_HTTP_NOT_ALLOWED;
    }

    if (r->uri.data[r->uri.len - 1] == '/' &&
		r->uri.len > ngx_strlen(".ts")) {
        return NGX_DECLINED;
    }

    nslash = 0;
    for (i = 0; i < r->uri.len; ++ i) {

        if (r->uri.data[i] == '/') {

            ++ nslash;
        } else if (r->uri.data[i] == '?') {

            break;
        }
    }

    if (nslash != 3) {

        return NGX_DECLINED;
    }

    if (r->uri.data[r->uri.len - 1] == 's' &&
        r->uri.data[r->uri.len - 2] == 't' &&
        r->uri.data[r->uri.len - 3] == '.') {
        protocol = NGX_RTMP_PULL_TYPE_HLS_TS;
    } else if (r->uri.len > ngx_strlen(".m3u8") &&
        r->uri.data[r->uri.len - 1] == '8' &&
        r->uri.data[r->uri.len - 2] == 'u' &&
        r->uri.data[r->uri.len - 3] == '3' &&
        r->uri.data[r->uri.len - 4] == 'm' &&
        r->uri.data[r->uri.len - 5] == '.') {
        protocol = NGX_RTMP_PULL_TYPE_HLS_M3U8;
    } else {
        return NGX_DECLINED;
    }

    rc = ngx_http_discard_request_body(r);
    if (rc != NGX_OK) {
        return rc;
    }

    ngx_log_error(NGX_LOG_INFO, r->connection->log, 0,
        "http_hls handle uri: '%V' args: '%V'", &r->uri, &r->args);

    if (ngx_rtmp_http_hls_get_info(&r->uri, &app, &name, &fname) != NGX_OK) {
        return NGX_DECLINED;
    }

    ngx_log_error(NGX_LOG_INFO, r->connection->log, 0,
              "http_hls handle app: '%V' name: '%V' fname: '%V'", &app, &name, &fname);


    port = cmcf->ports.elts;
    if (ngx_rtmp_http_hls_init_connection(r, &port[0]) != NGX_OK) {

        return NGX_HTTP_NOT_FOUND;
    }

    if (ngx_rtmp_http_hls_connect_local(r, &app, &name, &fname, protocol) != NGX_OK) {

        return NGX_HTTP_NOT_FOUND;
    }

    return NGX_CUSTOME;
}


static void *
ngx_rtmp_http_hls_create_conf(ngx_conf_t *cf)
{
    ngx_rtmp_http_hls_loc_conf_t  *hlcf;

    hlcf = ngx_palloc(cf->pool, sizeof(ngx_rtmp_http_hls_loc_conf_t));
    if (hlcf == NULL) {
        return NULL;
    }

    hlcf->hls = NGX_CONF_UNSET;

    return hlcf;
}


static char *
ngx_rtmp_http_hls_merge_conf(ngx_conf_t *cf, void *parent, void *child)
{
    ngx_rtmp_http_hls_loc_conf_t *prev = parent;
    ngx_rtmp_http_hls_loc_conf_t *conf = child;

    ngx_conf_merge_value(conf->hls, prev->hls, 0);

    return NGX_CONF_OK;
}


static ngx_int_t
ngx_rtmp_http_hls_get_info(ngx_str_t *uri, ngx_str_t *app, ngx_str_t *name, ngx_str_t *fname)
{
    size_t    len;

    if (uri == NULL || uri->len == 0) {

        return NGX_ERROR;
    }

    len = 0;
    for(; uri->data[len] == '/' || uri->len == len; ++ len); // skip first '/'

    app->data = &uri->data[len];                             // we got app

    for(; uri->data[len] != '/' || uri->len == len; ++ len); // reach next '/'

    app->len  = &uri->data[len ++] - app->data;
    name->data = &uri->data[len];                            // we got name

    for(; uri->data[len] != '/' || uri->len == len; ++ len); // reach next '/'

    name->len  = &uri->data[len ++] - name->data;
    fname->data = &uri->data[len];

    for(; len < uri->len && uri->data[len] != '?'; ++ len); // reach next '/'

    fname->len = &uri->data[len] - fname->data;

    return NGX_OK;
}


static ngx_int_t
ngx_rtmp_http_hls_init(ngx_conf_t *cf)
{
    ngx_http_handler_pt        *h;
    ngx_http_core_main_conf_t  *cmcf;

    cmcf = ngx_http_conf_get_module_main_conf(cf, ngx_http_core_module);

    h = ngx_array_push(&cmcf->phases[NGX_HTTP_CONTENT_PHASE].handlers);
    if (h == NULL) {
        return NGX_ERROR;
    }

    *h = ngx_rtmp_http_hls_handler;

    return NGX_OK;
}


static ngx_int_t
ngx_rtmp_hls_postconfiguration(ngx_conf_t *cf)
{
    ngx_rtmp_core_main_conf_t   *cmcf;
    ngx_rtmp_handler_pt         *h;

    cmcf = ngx_rtmp_conf_get_module_main_conf(cf, ngx_rtmp_core_module);

    h = ngx_array_push(&cmcf->events[NGX_RTMP_MSG_VIDEO]);
    *h = ngx_rtmp_hls_video;

    h = ngx_array_push(&cmcf->events[NGX_RTMP_MSG_AUDIO]);
    *h = ngx_rtmp_hls_audio;

    h = ngx_array_push(&cmcf->events[NGX_RTMP_CONNECT_DONE]);
    *h = ngx_rtmp_hls_connect_done;

    next_publish = ngx_rtmp_publish;
    ngx_rtmp_publish = ngx_rtmp_hls_publish;

    next_play = ngx_rtmp_play;
    ngx_rtmp_play = ngx_rtmp_hls_play;

    next_close_stream = ngx_rtmp_close_stream;
    ngx_rtmp_close_stream = ngx_rtmp_hls_close_stream;

    next_stream_begin = ngx_rtmp_stream_begin;
    ngx_rtmp_stream_begin = ngx_rtmp_hls_stream_begin;

    next_stream_eof = ngx_rtmp_stream_eof;
    ngx_rtmp_stream_eof = ngx_rtmp_hls_stream_eof;

    return NGX_OK;
}
