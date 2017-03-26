
/*
 * Copyright (C) Roman Arutyunyan
 */


#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_rtmp.h>
#include "ngx_rtmp_live_module.h"
#include "ngx_rtmp_cmd_module.h"
#include "ngx_rtmp_codec_module.h"

#define NGX_RTMP_LIVE_GOP_SIZE          100   /* gop cache */
#define NGX_RTMP_LIVE_PER_GOP_MAX_TIME  30000 /* per gop cache`s max time */

/* reason of cleaning gop */
typedef enum {
    NGX_RTMP_GOP_CLEAN_NO,
    NGX_RTMP_GOP_CLEAN_UNIQUE,
    NGX_RTMP_GOP_CLEAN_MIN,
    NGX_RTMP_GOP_CLEAN_MAX
} ngx_rtmp_gop_clean_t;


static ngx_rtmp_publish_pt              next_publish;
static ngx_rtmp_play_pt                 next_play;
static ngx_rtmp_close_stream_pt         next_close_stream;
static ngx_rtmp_pause_pt                next_pause;
static ngx_rtmp_stream_begin_pt         next_stream_begin;
static ngx_rtmp_stream_eof_pt           next_stream_eof;


static ngx_int_t ngx_rtmp_live_postconfiguration(ngx_conf_t *cf);
static void * ngx_rtmp_live_create_app_conf(ngx_conf_t *cf);
static char * ngx_rtmp_live_merge_app_conf(ngx_conf_t *cf,
       void *parent, void *child);
static char *ngx_rtmp_live_set_msec_slot(ngx_conf_t *cf, ngx_command_t *cmd,
       void *conf);
static void ngx_rtmp_live_start(ngx_rtmp_session_t *s);
static void ngx_rtmp_live_stop(ngx_rtmp_session_t *s);
static void ngx_rtmp_live_gop_cleanup(ngx_rtmp_session_t *s);


static ngx_command_t  ngx_rtmp_live_commands[] = {

    { ngx_string("live"),
      NGX_RTMP_MAIN_CONF|NGX_RTMP_SRV_CONF|NGX_RTMP_APP_CONF|NGX_CONF_TAKE1,
      ngx_conf_set_flag_slot,
      NGX_RTMP_APP_CONF_OFFSET,
      offsetof(ngx_rtmp_live_app_conf_t, live),
      NULL },

    { ngx_string("stream_buckets"),
      NGX_RTMP_MAIN_CONF|NGX_RTMP_SRV_CONF|NGX_RTMP_APP_CONF|NGX_CONF_TAKE1,
      ngx_conf_set_str_slot,
      NGX_RTMP_APP_CONF_OFFSET,
      offsetof(ngx_rtmp_live_app_conf_t, nbuckets),
      NULL },

    { ngx_string("buffer"),
      NGX_RTMP_MAIN_CONF|NGX_RTMP_SRV_CONF|NGX_RTMP_APP_CONF|NGX_CONF_TAKE1,
      ngx_conf_set_msec_slot,
      NGX_RTMP_APP_CONF_OFFSET,
      offsetof(ngx_rtmp_live_app_conf_t, buflen),
      NULL },

    { ngx_string("sync"),
      NGX_RTMP_MAIN_CONF|NGX_RTMP_SRV_CONF|NGX_RTMP_APP_CONF|NGX_CONF_TAKE1,
      ngx_rtmp_live_set_msec_slot,
      NGX_RTMP_APP_CONF_OFFSET,
      offsetof(ngx_rtmp_live_app_conf_t, sync),
      NULL },

    { ngx_string("interleave"),
      NGX_RTMP_MAIN_CONF|NGX_RTMP_SRV_CONF|NGX_RTMP_APP_CONF|NGX_CONF_TAKE1,
      ngx_conf_set_flag_slot,
      NGX_RTMP_APP_CONF_OFFSET,
      offsetof(ngx_rtmp_live_app_conf_t, interleave),
      NULL },

    { ngx_string("gop_cache"),
        NGX_RTMP_MAIN_CONF|NGX_RTMP_SRV_CONF|NGX_RTMP_APP_CONF|NGX_CONF_TAKE1,
        ngx_conf_set_flag_slot,
        NGX_RTMP_APP_CONF_OFFSET,
        offsetof(ngx_rtmp_live_app_conf_t, gop_cache),
        NULL },

    { ngx_string("gop_cache_mintime"),
        NGX_RTMP_MAIN_CONF|NGX_RTMP_SRV_CONF|NGX_RTMP_APP_CONF|NGX_CONF_TAKE1,
        ngx_rtmp_live_set_msec_slot,
        NGX_RTMP_APP_CONF_OFFSET,
        offsetof(ngx_rtmp_live_app_conf_t, gop_cache_mintime),
        NULL },

    { ngx_string("gop_cache_maxtime"),
        NGX_RTMP_MAIN_CONF|NGX_RTMP_SRV_CONF|NGX_RTMP_APP_CONF|NGX_CONF_TAKE1,
        ngx_rtmp_live_set_msec_slot,
        NGX_RTMP_APP_CONF_OFFSET,
        offsetof(ngx_rtmp_live_app_conf_t, gop_cache_maxtime),
        NULL },

    { ngx_string("wait_key"),
      NGX_RTMP_MAIN_CONF|NGX_RTMP_SRV_CONF|NGX_RTMP_APP_CONF|NGX_CONF_TAKE1,
      ngx_conf_set_flag_slot,
      NGX_RTMP_APP_CONF_OFFSET,
      offsetof(ngx_rtmp_live_app_conf_t, wait_key),
      NULL },

    { ngx_string("wait_video"),
      NGX_RTMP_MAIN_CONF|NGX_RTMP_SRV_CONF|NGX_RTMP_APP_CONF|NGX_CONF_TAKE1,
      ngx_conf_set_flag_slot,
      NGX_RTMP_APP_CONF_OFFSET,
      offsetof(ngx_rtmp_live_app_conf_t, wait_video),
      NULL },

    { ngx_string("publish_notify"),
      NGX_RTMP_MAIN_CONF|NGX_RTMP_SRV_CONF|NGX_RTMP_APP_CONF|NGX_CONF_TAKE1,
      ngx_conf_set_flag_slot,
      NGX_RTMP_APP_CONF_OFFSET,
      offsetof(ngx_rtmp_live_app_conf_t, publish_notify),
      NULL },

    { ngx_string("play_restart"),
      NGX_RTMP_MAIN_CONF|NGX_RTMP_SRV_CONF|NGX_RTMP_APP_CONF|NGX_CONF_TAKE1,
      ngx_conf_set_flag_slot,
      NGX_RTMP_APP_CONF_OFFSET,
      offsetof(ngx_rtmp_live_app_conf_t, play_restart),
      NULL },

    { ngx_string("idle_streams"),
      NGX_RTMP_MAIN_CONF|NGX_RTMP_SRV_CONF|NGX_RTMP_APP_CONF|NGX_CONF_TAKE1,
      ngx_conf_set_flag_slot,
      NGX_RTMP_APP_CONF_OFFSET,
      offsetof(ngx_rtmp_live_app_conf_t, idle_streams),
      NULL },

    { ngx_string("drop_idle_publisher"),
      NGX_RTMP_MAIN_CONF|NGX_RTMP_SRV_CONF|NGX_RTMP_APP_CONF|NGX_CONF_TAKE1,
      ngx_rtmp_live_set_msec_slot,
      NGX_RTMP_APP_CONF_OFFSET,
      offsetof(ngx_rtmp_live_app_conf_t, idle_timeout),
      NULL },

      ngx_null_command
};


static ngx_rtmp_module_t  ngx_rtmp_live_module_ctx = {
    NULL,                                   /* preconfiguration */
    ngx_rtmp_live_postconfiguration,        /* postconfiguration */
    NULL,                                   /* create main configuration */
    NULL,                                   /* init main configuration */
    NULL,                                   /* create server configuration */
    NULL,                                   /* merge server configuration */
    ngx_rtmp_live_create_app_conf,          /* create app configuration */
    ngx_rtmp_live_merge_app_conf            /* merge app configuration */
};


ngx_module_t  ngx_rtmp_live_module = {
    NGX_MODULE_V1,
    &ngx_rtmp_live_module_ctx,              /* module context */
    ngx_rtmp_live_commands,                 /* module directives */
    NGX_RTMP_MODULE,                        /* module type */
    NULL,                                   /* init master */
    NULL,                                   /* init module */
    NULL,                                   /* init process */
    NULL,                                   /* init thread */
    NULL,                                   /* exit thread */
    NULL,                                   /* exit process */
    NULL,                                   /* exit master */
    NGX_MODULE_V1_PADDING
};


static void *
ngx_rtmp_live_create_app_conf(ngx_conf_t *cf)
{
    ngx_rtmp_live_app_conf_t      *lacf;

    lacf = ngx_pcalloc(cf->pool, sizeof(ngx_rtmp_live_app_conf_t));
    if (lacf == NULL) {
        return NULL;
    }

    lacf->live = NGX_CONF_UNSET;
    lacf->nbuckets = NGX_CONF_UNSET;
    lacf->buflen = NGX_CONF_UNSET_MSEC;
    lacf->sync = NGX_CONF_UNSET_MSEC;
    lacf->idle_timeout = NGX_CONF_UNSET_MSEC;
    lacf->interleave = NGX_CONF_UNSET;
    lacf->gop_cache_mintime = NGX_CONF_UNSET_MSEC;
    lacf->gop_cache_maxtime = NGX_CONF_UNSET_MSEC;
    lacf->gop_cache = NGX_CONF_UNSET;
    lacf->wait_key = NGX_CONF_UNSET;
    lacf->wait_video = NGX_CONF_UNSET;
    lacf->publish_notify = NGX_CONF_UNSET;
    lacf->play_restart = NGX_CONF_UNSET;
    lacf->idle_streams = NGX_CONF_UNSET;

    return lacf;
}


static char *
ngx_rtmp_live_merge_app_conf(ngx_conf_t *cf, void *parent, void *child)
{
    ngx_rtmp_live_app_conf_t *prev = parent;
    ngx_rtmp_live_app_conf_t *conf = child;

    ngx_conf_merge_value(conf->live, prev->live, 0);
    ngx_conf_merge_value(conf->nbuckets, prev->nbuckets, 1024);
    ngx_conf_merge_msec_value(conf->buflen, prev->buflen, 0);
    ngx_conf_merge_msec_value(conf->sync, prev->sync, 300);
    ngx_conf_merge_msec_value(conf->idle_timeout, prev->idle_timeout, 0);
    ngx_conf_merge_value(conf->interleave, prev->interleave, 0);
    ngx_conf_merge_value(conf->gop_cache, prev->gop_cache, 1);
    ngx_conf_merge_msec_value(conf->gop_cache_mintime, prev->gop_cache_mintime, 0);
    ngx_conf_merge_msec_value(conf->gop_cache_maxtime, prev->gop_cache_maxtime, NGX_RTMP_LIVE_PER_GOP_MAX_TIME);
    ngx_conf_merge_value(conf->wait_key, prev->wait_key, 1);
    ngx_conf_merge_value(conf->wait_video, prev->wait_video, 0);
    ngx_conf_merge_value(conf->publish_notify, prev->publish_notify, 0);
    ngx_conf_merge_value(conf->play_restart, prev->play_restart, 0);
    ngx_conf_merge_value(conf->idle_streams, prev->idle_streams, 1);

    conf->pool = ngx_create_pool(4096, &cf->cycle->new_log);
    if (conf->pool == NULL) {
        return NGX_CONF_ERROR;
    }

    conf->streams = ngx_pcalloc(cf->pool,
            sizeof(ngx_rtmp_live_stream_t *) * conf->nbuckets);

    return NGX_CONF_OK;
}


static char *
ngx_rtmp_live_set_msec_slot(ngx_conf_t *cf, ngx_command_t *cmd, void *conf)
{
    char                       *p = conf;
    ngx_str_t                  *value;
    ngx_msec_t                 *msp;

    msp = (ngx_msec_t *) (p + cmd->offset);

    value = cf->args->elts;

    if (value[1].len == sizeof("off") - 1 &&
        ngx_strncasecmp(value[1].data, (u_char *) "off", value[1].len) == 0)
    {
        *msp = 0;
        return NGX_CONF_OK;
    }

    return ngx_conf_set_msec_slot(cf, cmd, conf);
}


static ngx_rtmp_live_stream_t **
ngx_rtmp_live_get_stream(ngx_rtmp_session_t *s, u_char *name, int create)
{
    ngx_rtmp_live_app_conf_t   *lacf;
    ngx_rtmp_live_stream_t    **stream;
    size_t                      len;

    lacf = ngx_rtmp_get_module_app_conf(s, ngx_rtmp_live_module);
    if (lacf == NULL) {
        return NULL;
    }

    len = ngx_strlen(name);
    stream = &lacf->streams[ngx_hash_key(name, len) % lacf->nbuckets];

    for (; *stream; stream = &(*stream)->next) {
        if (ngx_strcmp(name, (*stream)->name) == 0) {
            return stream;
        }
    }

    if (!create) {
        return NULL;
    }

    ngx_log_debug1(NGX_LOG_DEBUG_RTMP, s->connection->log, 0,
            "live: create stream '%s'", name);

    if (lacf->free_streams) {
        *stream = lacf->free_streams;
        lacf->free_streams = lacf->free_streams->next;
    } else {
        *stream = ngx_palloc(lacf->pool, sizeof(ngx_rtmp_live_stream_t));
    }
    ngx_memzero(*stream, sizeof(ngx_rtmp_live_stream_t));
    ngx_memcpy((*stream)->name, name,
            ngx_min(sizeof((*stream)->name) - 1, len));
    (*stream)->epoch = ngx_current_msec;

    return stream;
}


static void
ngx_rtmp_live_idle(ngx_event_t *pev)
{
    ngx_connection_t           *c;
    ngx_rtmp_session_t         *s;

    c = pev->data;
    s = c->data;

    ngx_log_error(NGX_LOG_ERR, s->connection->log, 0,
                  "live: drop idle publisher");

    ngx_rtmp_finalize_session(s);
}


static void
ngx_rtmp_live_set_status(ngx_rtmp_session_t *s, ngx_chain_t *control,
                         ngx_chain_t **status, size_t nstatus,
                         unsigned active)
{
    ngx_rtmp_live_app_conf_t   *lacf;
    ngx_rtmp_live_ctx_t        *ctx, *pctx;
    ngx_chain_t               **cl;
    ngx_event_t                *e;
    size_t                      n;

    lacf = ngx_rtmp_get_module_app_conf(s, ngx_rtmp_live_module);

    ctx = ngx_rtmp_get_module_ctx(s, ngx_rtmp_live_module);

    ngx_log_debug1(NGX_LOG_DEBUG_RTMP, s->connection->log, 0,
                   "live: set active=%ui", active);

    if (ctx->active == active) {
        ngx_log_debug1(NGX_LOG_DEBUG_RTMP, s->connection->log, 0,
                       "live: unchanged active=%ui", active);
        return;
    }

    ctx->active = active;

    if (ctx->publishing) {

        /* publisher */

        if (lacf->idle_timeout) {
            e = &ctx->idle_evt;

            if (active && !ctx->idle_evt.timer_set) {
                e->data = s->connection;
                e->log = s->connection->log;
                e->handler = ngx_rtmp_live_idle;

                ngx_add_timer(e, lacf->idle_timeout);

            } else if (!active && ctx->idle_evt.timer_set) {
                ngx_del_timer(e);
            }
        }

        ctx->stream->active = active;

        for (pctx = ctx->stream->ctx; pctx; pctx = pctx->next) {
            if (pctx->publishing == 0) {
                ngx_rtmp_live_set_status(pctx->session, control, status,
                                         nstatus, active);
            }
        }

        return;
    }

    /* subscriber */

    if (control && ngx_rtmp_send_message(s, control, 0) != NGX_OK) {
        ngx_rtmp_finalize_session(s);
        return;
    }

    if (!ctx->silent) {
        cl = status;

        for (n = 0; n < nstatus; ++n, ++cl) {
            if (*cl && ngx_rtmp_send_message(s, *cl, 0) != NGX_OK) {
                ngx_rtmp_finalize_session(s);
                return;
            }
        }
    }

    ctx->cs[0].active = 0;
    ctx->cs[0].dropped = 0;

    ctx->cs[1].active = 0;
    ctx->cs[1].dropped = 0;
}


static void
ngx_rtmp_live_start(ngx_rtmp_session_t *s)
{
    ngx_rtmp_core_srv_conf_t   *cscf;
    ngx_rtmp_live_app_conf_t   *lacf;
    ngx_chain_t                *control;
    ngx_chain_t                *status[3];
    size_t                      n, nstatus;

    cscf = ngx_rtmp_get_module_srv_conf(s, ngx_rtmp_core_module);

    lacf = ngx_rtmp_get_module_app_conf(s, ngx_rtmp_live_module);

    control = ngx_rtmp_create_stream_begin(s, NGX_RTMP_MSID);

    nstatus = 0;

    if (lacf->play_restart) {
        status[nstatus++] = ngx_rtmp_create_status(s, "NetStream.Play.Start",
                                                   "status", "Start live");
        status[nstatus++] = ngx_rtmp_create_sample_access(s);
    }

    if (lacf->publish_notify) {
        status[nstatus++] = ngx_rtmp_create_status(s,
                                                 "NetStream.Play.PublishNotify",
                                                 "status", "Start publishing");
    }

    ngx_rtmp_live_set_status(s, control, status, nstatus, 1);

    if (control) {
        ngx_rtmp_free_shared_chain(cscf, control);
    }

    for (n = 0; n < nstatus; ++n) {
        ngx_rtmp_free_shared_chain(cscf, status[n]);
    }
}


static void
ngx_rtmp_live_stop(ngx_rtmp_session_t *s)
{
    ngx_rtmp_core_srv_conf_t   *cscf;
    ngx_rtmp_live_app_conf_t   *lacf;
    ngx_chain_t                *control;
    ngx_chain_t                *status[3];
    size_t                      n, nstatus;

    cscf = ngx_rtmp_get_module_srv_conf(s, ngx_rtmp_core_module);

    lacf = ngx_rtmp_get_module_app_conf(s, ngx_rtmp_live_module);

    control = ngx_rtmp_create_stream_eof(s, NGX_RTMP_MSID);

    nstatus = 0;

    if (lacf->play_restart) {
        status[nstatus++] = ngx_rtmp_create_status(s, "NetStream.Play.Stop",
                                                   "status", "Stop live");
    }

    if (lacf->publish_notify) {
        status[nstatus++] = ngx_rtmp_create_status(s,
                                               "NetStream.Play.UnpublishNotify",
                                               "status", "Stop publishing");
    }

    ngx_rtmp_live_set_status(s, control, status, nstatus, 0);

    if (control) {
        ngx_rtmp_free_shared_chain(cscf, control);
    }

    for (n = 0; n < nstatus; ++n) {
        ngx_rtmp_free_shared_chain(cscf, status[n]);
    }
}


static ngx_int_t
ngx_rtmp_live_stream_begin(ngx_rtmp_session_t *s, ngx_rtmp_stream_begin_t *v)
{
    ngx_rtmp_live_ctx_t    *ctx;

    ctx = ngx_rtmp_get_module_ctx(s, ngx_rtmp_live_module);

    if (ctx == NULL || ctx->stream == NULL || !ctx->publishing) {
        goto next;
    }

    ngx_log_debug0(NGX_LOG_DEBUG_RTMP, s->connection->log, 0,
                   "live: stream_begin");

    ngx_rtmp_live_start(s);

next:
    return next_stream_begin(s, v);
}


static ngx_int_t
ngx_rtmp_live_stream_eof(ngx_rtmp_session_t *s, ngx_rtmp_stream_eof_t *v)
{
    ngx_rtmp_live_ctx_t    *ctx;

    ctx = ngx_rtmp_get_module_ctx(s, ngx_rtmp_live_module);

    if (ctx == NULL || ctx->stream == NULL || !ctx->publishing) {
        goto next;
    }

    ngx_log_debug0(NGX_LOG_DEBUG_RTMP, s->connection->log, 0,
                   "live: stream_eof");

    ngx_rtmp_live_stop(s);

next:
    return next_stream_eof(s, v);
}


static void
ngx_rtmp_live_join(ngx_rtmp_session_t *s, u_char *name, unsigned publisher)
{
    ngx_rtmp_live_ctx_t            *ctx;
    ngx_rtmp_live_stream_t        **stream;
    ngx_rtmp_live_app_conf_t       *lacf;

    lacf = ngx_rtmp_get_module_app_conf(s, ngx_rtmp_live_module);
    if (lacf == NULL) {
        return;
    }

    ctx = ngx_rtmp_get_module_ctx(s, ngx_rtmp_live_module);
    if (ctx && ctx->stream) {
        ngx_log_debug0(NGX_LOG_DEBUG_RTMP, s->connection->log, 0,
                       "live: already joined");
        return;
    }

    if (ctx == NULL) {
        ctx = ngx_palloc(s->connection->pool, sizeof(ngx_rtmp_live_ctx_t));
        ngx_rtmp_set_ctx(s, ctx, ngx_rtmp_live_module);
    }

    ngx_memzero(ctx, sizeof(*ctx));

    ctx->session = s;

    ngx_log_debug1(NGX_LOG_DEBUG_RTMP, s->connection->log, 0,
                   "live: join '%s'", name);

    stream = ngx_rtmp_live_get_stream(s, name, publisher || lacf->idle_streams);

    if (stream == NULL ||
        !(publisher || (*stream)->publishing || lacf->idle_streams))
    {
        ngx_log_error(NGX_LOG_ERR, s->connection->log, 0,
                      "live: stream not found");

        ngx_rtmp_send_status(s, "NetStream.Play.StreamNotFound", "error",
                             "No such stream");

        ngx_rtmp_finalize_session(s);

        return;
    }

    if (publisher) {
        if ((*stream)->publishing) {
            ngx_log_error(NGX_LOG_ERR, s->connection->log, 0,
                          "live: already publishing");

            ngx_rtmp_send_status(s, "NetStream.Publish.BadName", "error",
                                 "Already publishing");

            return;
        }

        (*stream)->publishing = 1;
    }

    ctx->stream = *stream;
    ctx->publishing = publisher;
    ctx->next = (*stream)->ctx;

    (*stream)->ctx = ctx;

    if (lacf->buflen) {
        s->out_buffer = 1;
    }

    ctx->cs[0].csid = NGX_RTMP_CSID_VIDEO;
    ctx->cs[1].csid = NGX_RTMP_CSID_AUDIO;

    if (!ctx->publishing && ctx->stream->active) {
        ngx_rtmp_live_start(s);
    }
}


static ngx_int_t
ngx_rtmp_live_close_stream(ngx_rtmp_session_t *s, ngx_rtmp_close_stream_t *v)
{
    ngx_rtmp_session_t             *ss;
    ngx_rtmp_live_ctx_t            *ctx, **cctx, *pctx;
    ngx_rtmp_live_stream_t        **stream;
    ngx_rtmp_live_app_conf_t       *lacf;

    lacf = ngx_rtmp_get_module_app_conf(s, ngx_rtmp_live_module);
    if (lacf == NULL) {
        goto next;
    }

    ctx = ngx_rtmp_get_module_ctx(s, ngx_rtmp_live_module);
    if (ctx == NULL) {
        goto next;
    }

    if (ctx->stream == NULL) {
        ngx_log_debug0(NGX_LOG_DEBUG_RTMP, s->connection->log, 0,
                       "live: not joined");
        goto next;
    }

    ngx_log_debug1(NGX_LOG_DEBUG_RTMP, s->connection->log, 0,
                   "live: leave '%s'", ctx->stream->name);

    if (ctx->stream->publishing && ctx->publishing) {
        ctx->stream->publishing = 0;
    }

    for (cctx = &ctx->stream->ctx; *cctx; cctx = &(*cctx)->next) {
        if (*cctx == ctx) {
            *cctx = ctx->next;
            break;
        }
    }

    if (ctx->publishing || ctx->stream->active) {
        ngx_rtmp_live_stop(s);
    }

    if (ctx->publishing) {
        ngx_rtmp_send_status(s, "NetStream.Unpublish.Success",
                             "status", "Stop publishing");
        if (!lacf->idle_streams) {
            for (pctx = ctx->stream->ctx; pctx; pctx = pctx->next) {
                if (pctx->publishing == 0) {
                    ss = pctx->session;
                    ngx_log_debug0(NGX_LOG_DEBUG_RTMP, ss->connection->log, 0,
                                   "live: no publisher");
                    ngx_rtmp_finalize_session(ss);
                }
            }
        }
    }

    if (ctx->stream->ctx) {
        ctx->stream = NULL;
        goto next;
    }

    ngx_log_debug1(NGX_LOG_DEBUG_RTMP, s->connection->log, 0,
                   "live: delete empty stream '%s'",
                   ctx->stream->name);

    stream = ngx_rtmp_live_get_stream(s, ctx->stream->name, 0);
    if (stream == NULL) {
        goto next;
    }
    *stream = (*stream)->next;

    ctx->stream->next = lacf->free_streams;
    lacf->free_streams = ctx->stream;
    ctx->stream = NULL;

    if (!ctx->silent && !ctx->publishing && !lacf->play_restart) {
        ngx_rtmp_send_status(s, "NetStream.Play.Stop", "status", "Stop live");
    }

next:
    return next_close_stream(s, v);
}


static ngx_int_t
ngx_rtmp_live_pause(ngx_rtmp_session_t *s, ngx_rtmp_pause_t *v)
{
    ngx_rtmp_live_ctx_t            *ctx;

    ctx = ngx_rtmp_get_module_ctx(s, ngx_rtmp_live_module);

    if (ctx == NULL || ctx->stream == NULL) {
        goto next;
    }

    ngx_log_debug2(NGX_LOG_DEBUG_RTMP, s->connection->log, 0,
                   "live: pause=%i timestamp=%f",
                   (ngx_int_t) v->pause, v->position);

    if (v->pause) {
        if (ngx_rtmp_send_status(s, "NetStream.Pause.Notify", "status",
                                 "Paused live")
            != NGX_OK)
        {
            return NGX_ERROR;
        }

        ctx->paused = 1;

        ngx_rtmp_live_stop(s);

    } else {
        if (ngx_rtmp_send_status(s, "NetStream.Unpause.Notify", "status",
                                 "Unpaused live")
            != NGX_OK)
        {
            return NGX_ERROR;
        }

        ctx->paused = 0;

        ngx_rtmp_live_start(s);
    }

next:
    return next_pause(s, v);
}


static ngx_rtmp_live_gop_frame_t *
ngx_rtmp_live_gop_alloc_frame(ngx_rtmp_session_t *s)
{
    ngx_rtmp_live_ctx_t            *ctx;
    ngx_rtmp_live_gop_frame_t      *frame;

    ctx = ngx_rtmp_get_module_ctx(s, ngx_rtmp_live_module);
    if (ctx == NULL) {
        return NULL;
    }

    if (ctx->free_frame) {
        frame = ctx->free_frame;
        ctx->free_frame = frame->next;

        ngx_memzero(frame, sizeof(ngx_rtmp_live_gop_frame_t));
        return frame;
    }

    if (!ctx->gop_pool) {
        ctx->gop_pool = ngx_create_pool(4096, s->connection->log);
    }

    frame = ngx_pcalloc(ctx->gop_pool, sizeof(ngx_rtmp_live_gop_frame_t));

    return frame;
}


static void
ngx_rtmp_live_gop_free_frame(ngx_rtmp_session_t *s, ngx_rtmp_live_gop_frame_t *free_frame)
{
    ngx_rtmp_core_srv_conf_t       *cscf;
    ngx_rtmp_live_ctx_t            *ctx;

    cscf = ngx_rtmp_get_module_srv_conf(s, ngx_rtmp_core_module);
    if (cscf == NULL) {
        return;
    }

    ctx = ngx_rtmp_get_module_ctx(s, ngx_rtmp_live_module);
    if (ctx == NULL) {
        return;
    }

    if (free_frame->frame) {
        ngx_rtmp_free_shared_chain(cscf, free_frame->frame);
        free_frame->frame = NULL;
    }

    if (free_frame->h.type == NGX_RTMP_MSG_VIDEO) {
        ctx->vcach_cnt --;
    } else if (free_frame->h.type == NGX_RTMP_MSG_AUDIO) {
        ctx->acach_cnt --;
    }
}


static ngx_int_t
ngx_rtmp_live_gop_link_frame(ngx_rtmp_session_t *s, ngx_rtmp_live_gop_frame_t *frame)
{
    ngx_rtmp_live_ctx_t            *ctx;
    ngx_rtmp_live_gop_cache_t      *cache;

    ctx = ngx_rtmp_get_module_ctx(s, ngx_rtmp_live_module);
    if (ctx == NULL) {
        return NGX_ERROR;
    }

    cache = ctx->gop_cache_tail;
    if (cache == NULL) {
        return NGX_ERROR;
    }

    if(cache->gop_frame_head == NULL) {
        cache->gop_frame_head = cache->gop_frame_tail = frame;
    } else {
        cache->gop_frame_tail->next = frame;
        cache->gop_frame_tail = frame;
    }

    /*increase video/audio cnt*/
    if (frame->h.type == NGX_RTMP_MSG_VIDEO) {
        ctx->vcach_cnt ++;
        ctx->audio_after_last_video_cnt = 0;
        cache->vframe_cnt ++;
    } else if(frame->h.type == NGX_RTMP_MSG_AUDIO){
        ctx->acach_cnt ++;
        cache->aframe_cnt ++;
    }

    return NGX_OK;
}


static ngx_int_t
ngx_rtmp_live_gop_alloc_cache(ngx_rtmp_session_t *s)
{
    ngx_rtmp_live_ctx_t            *ctx;
    ngx_rtmp_codec_ctx_t           *codec_ctx;
    ngx_rtmp_core_srv_conf_t       *cscf;
    ngx_rtmp_live_gop_cache_t      *cache;
    u_char                         *pos;
    ngx_chain_t                    *meta;

    ctx = ngx_rtmp_get_module_ctx(s, ngx_rtmp_live_module);
    if (ctx == NULL) {
        return NGX_ERROR;
    }

    codec_ctx = ngx_rtmp_get_module_ctx(s, ngx_rtmp_codec_module);
    if (codec_ctx == NULL) {
        return NGX_ERROR;
    }

    cscf = ngx_rtmp_get_module_srv_conf(s, ngx_rtmp_core_module);
    if (cscf == NULL) {
        return NGX_ERROR;
    }

    if (ctx->free_cache) {
        cache = ctx->free_cache;
        ctx->free_cache = cache->next;

        ngx_memzero(cache, sizeof(ngx_rtmp_live_gop_cache_t));
    } else {
        if (!ctx->gop_pool) {
            ctx->gop_pool = ngx_create_pool(4096, s->connection->log);
        }

        cache = ngx_pcalloc(ctx->gop_pool, sizeof(ngx_rtmp_live_gop_cache_t));
        if (cache == NULL) {
            return NGX_ERROR;
        }
    }

    if (codec_ctx->video_header) {
        cache->gop_codec_info.video_header = ngx_rtmp_append_shared_bufs(cscf, NULL, codec_ctx->video_header);
    }

    meta = NULL;

    if(codec_ctx->meta != NULL) {
        cache->gop_codec_info.metah         = codec_ctx->metah;
        cache->gop_codec_info.meta_version  = codec_ctx->meta_version;

        meta = codec_ctx->meta;
        pos = meta->buf->pos;
        meta->buf->pos = meta->buf->start + NGX_RTMP_MAX_CHUNK_HEADER;

        cache->gop_codec_info.meta          = ngx_rtmp_append_shared_bufs(cscf, NULL, meta);

        meta->buf->pos = pos;

        ngx_rtmp_prepare_message(s, &codec_ctx->metah, NULL, cache->gop_codec_info.meta);
    }

    if(ctx->gop_cache == NULL) {
        ctx->gop_cache_tail = ctx->gop_cache = cache;
    } else {
        ctx->gop_cache_tail->next = cache;
        ctx->gop_cache_tail = cache;
    }

    ctx->gcach_cnt ++;

    return NGX_OK;
}


static void
ngx_rtmp_live_gop_free_cache(ngx_rtmp_session_t *s,
                             ngx_rtmp_live_gop_cache_t *cache)
{
    ngx_rtmp_core_srv_conf_t       *cscf;
    ngx_rtmp_live_gop_frame_t      *gop_frame;
    ngx_rtmp_live_ctx_t            *ctx;

    cscf = ngx_rtmp_get_module_srv_conf(s, ngx_rtmp_core_module);
    if (cscf == NULL) {
        return;
    }

    ctx = ngx_rtmp_get_module_ctx(s, ngx_rtmp_live_module);
    if (ctx == NULL) {
        return;
    }

    if (cache->gop_codec_info.video_header) {
        ngx_rtmp_free_shared_chain(cscf, cache->gop_codec_info.video_header);
        cache->gop_codec_info.video_header = NULL;
    }

    if (cache->gop_codec_info.meta) {
        ngx_rtmp_free_shared_chain(cscf, cache->gop_codec_info.meta);
        cache->gop_codec_info.meta = NULL;
    }

    for (gop_frame = cache->gop_frame_head; gop_frame; gop_frame = gop_frame->next) {
        ngx_rtmp_live_gop_free_frame(s, gop_frame);
    }

    // recycle mem of gop frame
    cache->gop_frame_tail->next = ctx->free_frame;
    ctx->free_frame = cache->gop_frame_head;

    ctx->gcach_cnt --;
}


static void
ngx_rtmp_live_gop_unlink_cache(ngx_rtmp_session_t *s,
                               ngx_rtmp_live_gop_cache_t **cache)
{
    ngx_rtmp_live_gop_cache_t      *tcache;
    ngx_rtmp_live_ctx_t            *ctx;

    ctx = ngx_rtmp_get_module_ctx(s, ngx_rtmp_live_module);
    if (ctx == NULL) {
        return;
    }

    // backup.
    tcache = *cache;

    ngx_rtmp_live_gop_free_cache(s, *cache);

    // unlink from list. if there is no gop destroy pool
    *cache = (*cache)->next;
    if(*cache == NULL) {
        ngx_rtmp_live_gop_cleanup(s);
        return;
    }

    // link to recycle list.
    tcache->next = ctx->free_cache;
    ctx->free_cache = tcache;
}


static void
ngx_rtmp_live_gop_cleanup(ngx_rtmp_session_t *s)
{
    ngx_rtmp_live_ctx_t            *ctx;
    ngx_rtmp_core_srv_conf_t       *cscf;
    ngx_rtmp_live_gop_cache_t      *cache;

    cscf = ngx_rtmp_get_module_srv_conf(s, ngx_rtmp_core_module);
    if (cscf == NULL) {
        return;
    }

    ctx = ngx_rtmp_get_module_ctx(s, ngx_rtmp_live_module);
    if (ctx == NULL) {
        return;
    }

    for (cache = ctx->gop_cache; cache; cache = cache->next) {
        ngx_rtmp_live_gop_free_cache(s, cache);
    }

    if (ctx->gop_pool) {
        ngx_destroy_pool(ctx->gop_pool);
        ctx->gop_pool = NULL;
    }

    ctx->gop_cache_tail = ctx->gop_cache = NULL;
    ctx->free_cache = NULL;
    ctx->free_frame = NULL;
    ctx->gcach_cnt = 0;
    ctx->acach_cnt = 0;
    ctx->vcach_cnt = 0;
    ctx->audio_after_last_video_cnt = 0;
}


static ngx_msec_t
ngx_rtmp_calculate_audio_interval(ngx_uint_t audio_cnt,
                                ngx_uint_t audio_codec_id,
                                ngx_uint_t sample_rate)
{
    ngx_msec_t interval;

    interval = audio_cnt * (audio_codec_id == NGX_RTMP_AUDIO_AAC
                ? NGX_RTMP_AUDIO_FRAME_SIZE_AAC
                : NGX_RTMP_AUDIO_FRAME_SIZE_MP3) * 1000 / ( sample_rate > 0
                ? sample_rate
                : 44100);

    return interval;
}


static ngx_msec_t
ngx_rtmp_calculate_video_interval(ngx_uint_t video_cnt,
                                ngx_rtmp_live_frame_rate_t video_frame_rate)
{
    ngx_msec_t interval;

    interval = video_frame_rate.fps > 0
                ? video_cnt * 1000 * 1000 / video_frame_rate.fps
                : 0;

    return interval;
}


static void
ngx_rtmp_live_gop_update(ngx_rtmp_session_t *s)
{
    ngx_rtmp_live_app_conf_t    *lacf;
    ngx_rtmp_live_ctx_t         *ctx;
    ngx_rtmp_codec_ctx_t        *codec_ctx;
    ngx_msec_t                  max_time;
    ngx_msec_t                  catime, cvtime; // whole time duration in gop.
    ngx_msec_t                  dvtime, datime; // time duration expect first gop.
    ngx_msec_t                  rvtime, ratime, rtime; //remained duration after delete
    ngx_msec_t                  gop_cache_mintime;
    ngx_msec_t                  gop_cache_maxtime;
    ngx_rtmp_gop_clean_t        clean_status;

#if(NGX_DEBUG)
    ngx_rtmp_live_gop_cache_t   *fcache;
#endif

    lacf = ngx_rtmp_get_module_app_conf(s, ngx_rtmp_live_module);
    if (lacf == NULL || lacf->gop_cache == 0) {
        return;
    }

    codec_ctx = ngx_rtmp_get_module_ctx(s, ngx_rtmp_codec_module);
    if (codec_ctx == NULL) {
        return;
    }

    ctx = ngx_rtmp_get_module_ctx(s, ngx_rtmp_live_module);
    if (ctx == NULL) {
        return;
    }

    gop_cache_mintime = lacf->gop_cache_mintime;
    gop_cache_maxtime = lacf->gop_cache_maxtime;

    clean_status = NGX_RTMP_GOP_CLEAN_NO;

    do {
        // each time remove one gop
        if (clean_status != NGX_RTMP_GOP_CLEAN_NO) {
#if(NGX_DEBUG)
            fcache = ctx->gop_cache;
#endif
            ngx_rtmp_live_gop_unlink_cache(s, &ctx->gop_cache);

            ngx_log_debug8(NGX_LOG_DEBUG_RTMP, s->connection->log, 0,
                          "clean_status:%uD,"
                          "freed video cnt %uD, time %uD, remained video cnt %D,"
                          "freed audio cnt %uD, time %uD, remained audio cnt %D,"
                          "remain gop cnt %uD",
                          clean_status,
                          fcache->vframe_cnt, dvtime,ctx->vcach_cnt,
                          fcache->aframe_cnt, datime,ctx->acach_cnt,
                          ctx->gcach_cnt);

            clean_status = NGX_RTMP_GOP_CLEAN_NO;
        }

        if (ctx->gop_cache == NULL) {
            break;
        }

        catime = ngx_rtmp_calculate_audio_interval(
                              ctx->acach_cnt,
                              codec_ctx->audio_codec_id,
                              codec_ctx->sample_rate);

        cvtime = ngx_rtmp_calculate_video_interval(
                              ctx->vcach_cnt,
                              ctx->stream->video_frame_rate);

        max_time = ngx_max(catime, cvtime);

        datime = ngx_rtmp_calculate_audio_interval(
                              ctx->gop_cache->aframe_cnt,
                              codec_ctx->audio_codec_id,
                              codec_ctx->sample_rate);

        dvtime = ngx_rtmp_calculate_video_interval(
                              ctx->gop_cache->vframe_cnt,
                              ctx->stream->video_frame_rate);

        ratime = catime - datime;
        rvtime = cvtime - dvtime;

        rtime = ngx_max(ratime, rvtime);

        // remained gop is longer than min threshold
        if (rtime > gop_cache_mintime) {
            clean_status = NGX_RTMP_GOP_CLEAN_MIN;
        }

        // total gop duration is longer than max threshold
        if (max_time > ngx_max(gop_cache_maxtime, NGX_RTMP_LIVE_PER_GOP_MAX_TIME)) {
            clean_status = NGX_RTMP_GOP_CLEAN_MAX;
        }

        ngx_log_debug6(NGX_LOG_ERR, s->connection->log, 0,
                          "max gop time %uD,"
                          "cached video (time %uD, cnt %uD),"
                          "cache audio (time %uD, cnt %uD),"
                          "cached gop cnt %uD",
                          gop_cache_mintime,
                          cvtime, ctx->vcach_cnt,
                          catime, ctx->acach_cnt,
                          ctx->gcach_cnt);

    } while (clean_status);
}

static void
ngx_rtmp_live_gop_cache_frame(ngx_rtmp_session_t *s, ngx_uint_t prio, ngx_rtmp_header_t *ch, ngx_chain_t *frame)
{
    ngx_rtmp_live_ctx_t            *ctx;
    ngx_rtmp_codec_ctx_t           *codec_ctx;
    ngx_rtmp_core_srv_conf_t       *cscf;
    ngx_rtmp_live_app_conf_t       *lacf;
    ngx_rtmp_live_gop_frame_t      *gop_frame;

    lacf = ngx_rtmp_get_module_app_conf(s, ngx_rtmp_live_module);
    if (lacf == NULL || !lacf->gop_cache) {
        return;
    }

    cscf = ngx_rtmp_get_module_srv_conf(s, ngx_rtmp_core_module);
    if (cscf == NULL) {
        return;
    }

    ctx = ngx_rtmp_get_module_ctx(s, ngx_rtmp_live_module);
    if (ctx == NULL) {
        return;
    }

    codec_ctx = ngx_rtmp_get_module_ctx(s, ngx_rtmp_codec_module);

    if (ch->type == NGX_RTMP_MSG_VIDEO) {

        // drop video when not h.264 or h.265
        if (!codec_ctx ||
            (codec_ctx->video_codec_id != NGX_RTMP_VIDEO_H264 &&
             codec_ctx->video_codec_id != NGX_RTMP_VIDEO_H265)) {

            return;
        }

        // drop non-key-video when 1'st keyframe wasn't arrived
        if (prio != NGX_RTMP_VIDEO_KEY_FRAME &&
            ctx->gop_pool == NULL) {

            ngx_log_error(NGX_LOG_ERR, s->connection->log, 0,
                          "drop non-key frame type='%s' timestamp='%uD'",
                          ch->type == NGX_RTMP_MSG_AUDIO ? "audio" : "video",
                          ch->timestamp);
            return;
        }
    }

    // pure audio?
    if (ctx->vcach_cnt == 0 &&
        ch->type == NGX_RTMP_MSG_AUDIO) {
        return;
    }

    if (ch->type == NGX_RTMP_MSG_AUDIO) {
        ctx->audio_after_last_video_cnt ++;
    }

    if (ctx->audio_after_last_video_cnt > NGX_RTMP_LIVE_PURE_AUDIO_GUESS_CNT) {

        ngx_rtmp_live_gop_cleanup(s);

        return;
    }

    if (ch->type == NGX_RTMP_MSG_VIDEO &&
        prio == NGX_RTMP_VIDEO_KEY_FRAME) {

        if (ngx_rtmp_live_gop_alloc_cache(s) != NGX_OK) {
            return;
        }
    }

    gop_frame = ngx_rtmp_live_gop_alloc_frame(s);
    if (gop_frame == NULL) {
        return;
    }

    gop_frame->h = *ch;
    gop_frame->prio = prio;
    gop_frame->next = NULL;
    gop_frame->frame = ngx_rtmp_append_shared_bufs(cscf, NULL, frame);

    if (ngx_rtmp_live_gop_link_frame(s, gop_frame) != NGX_OK) {

        ngx_rtmp_free_shared_chain(cscf, gop_frame->frame);
    }

    ngx_rtmp_live_gop_update(s);

    ngx_log_debug2(NGX_LOG_DEBUG_RTMP, s->connection->log, 0,
               "gop_cache: cache packet type='%s' timestamp='%uD'",
               gop_frame->h.type == NGX_RTMP_MSG_AUDIO ? "audio" : "video",
               gop_frame->h.timestamp);
}


static void
ngx_rtmp_live_gop_cache_send(ngx_rtmp_session_t *ss)
{
    ngx_rtmp_session_t             *s;
    ngx_chain_t                    *pkt, *apkt, *meta, *header;
    ngx_rtmp_live_ctx_t            *pctx, *publisher, *player;
    ngx_rtmp_codec_ctx_t           *codec_ctx;
    ngx_rtmp_core_srv_conf_t       *cscf;
    ngx_rtmp_live_app_conf_t       *lacf;
    ngx_rtmp_live_gop_cache_t      *cache;
    ngx_rtmp_live_gop_frame_t       *gop_frame;
    ngx_rtmp_header_t               ch, lh;
    ngx_uint_t                      meta_version;
    uint32_t                        delta;
    ngx_int_t                       csidx;
    ngx_rtmp_live_chunk_stream_t   *cs;

    lacf = ngx_rtmp_get_module_app_conf(ss, ngx_rtmp_live_module);
    if (lacf == NULL) {
        return;
    }

    cscf = ngx_rtmp_get_module_srv_conf(ss, ngx_rtmp_core_module);
    if (cscf == NULL) {
        return;
    }

    player = ngx_rtmp_get_module_ctx(ss, ngx_rtmp_live_module);
    if (player == NULL || player->stream == NULL) {
        return;
    }

    if (!ngx_rtmp_type(ss->protocol)) {
        return;
    }

    for (pctx = player->stream->ctx; pctx; pctx = pctx->next) {
        if (pctx->publishing) {
            break;
        }
    }

    if (pctx == NULL) {
        return;
    }

    pkt = NULL;
    apkt = NULL;
    meta = NULL;
    header = NULL;
    meta_version = 0;

    publisher = pctx;
    s         = publisher->session;
    ss        = player->session;

    if (!lacf->gop_cache) {
        return;
    }

    codec_ctx = ngx_rtmp_get_module_ctx(s, ngx_rtmp_codec_module);
    if (codec_ctx == NULL) {
        return;
    }

    for (cache = publisher->gop_cache; cache; cache = cache->next) {

        if (cache->gop_codec_info.meta) {
            meta = cache->gop_codec_info.meta;
            meta_version = cache->gop_codec_info.meta_version;
        }

        /* send metadata */
        if (meta && meta_version != player->meta_version) {
            ngx_log_debug0(NGX_LOG_DEBUG_RTMP, ss->connection->log, 0,
                           "live: meta");

            if (ngx_rtmp_send_message(ss, meta, 0) == NGX_OK) {
                player->meta_version = meta_version;
            }
        }

        for (gop_frame = cache->gop_frame_head; gop_frame; gop_frame = gop_frame->next) {
            csidx = !(lacf->interleave || gop_frame->h.type == NGX_RTMP_MSG_VIDEO);

            cs = &player->cs[csidx];

            lh = ch = gop_frame->h;

            if (cs->active) {
                lh.timestamp = cs->timestamp;
            }

            delta = ch.timestamp - lh.timestamp;

            if (!cs->active) {

                header = gop_frame->h.type == NGX_RTMP_MSG_VIDEO ? cache->gop_codec_info.video_header : codec_ctx->aac_header;
                if (header) {
                    apkt = ngx_rtmp_append_shared_bufs(cscf, NULL, header);
                    ngx_rtmp_prepare_message(s, &lh, NULL, apkt);
                }

                if (apkt && ngx_rtmp_send_message(ss, apkt, 0) == NGX_OK) {

                    cs->timestamp = lh.timestamp;
                    cs->active = 1;
                    ss->current_time = cs->timestamp;
                }

                if (apkt) {
                    ngx_rtmp_free_shared_chain(cscf, apkt);
                    apkt = NULL;
                }
            }

            pkt = ngx_rtmp_append_shared_bufs(cscf, NULL, gop_frame->frame);

            ngx_rtmp_prepare_message(s, &ch, &lh, pkt);

            if (ngx_rtmp_send_message(ss, pkt, gop_frame->prio) != NGX_OK) {
                ++pctx->ndropped;

                cs->dropped += delta;

                return;
            }

            if (pkt) {
                ngx_rtmp_free_shared_chain(cscf, pkt);
                pkt = NULL;
            }

            ngx_log_debug3(NGX_LOG_DEBUG_RTMP, ss->connection->log, 0,
                           "live_gop_send: send tag type='%s' prio='%d' ltimestamp='%uD'",
                           gop_frame->h.type == NGX_RTMP_MSG_AUDIO ? "audio" : "video",
                           gop_frame->prio,
                           lh.timestamp);

            cs->timestamp += delta;
            ss->current_time = cs->timestamp;
        }
    }
}

static ngx_int_t
ngx_rtmp_live_av(ngx_rtmp_session_t *s, ngx_rtmp_header_t *h,
                 ngx_chain_t *in)
{
    ngx_rtmp_live_ctx_t            *ctx, *pctx;
    ngx_rtmp_codec_ctx_t           *codec_ctx;
    ngx_chain_t                    *header, *coheader, *meta,
                                   *apkt, *aapkt, *acopkt, *rpkt;
    ngx_rtmp_core_srv_conf_t       *cscf;
    ngx_rtmp_live_app_conf_t       *lacf;
    ngx_rtmp_session_t             *ss;
    ngx_rtmp_header_t               ch, lh, clh;
    ngx_int_t                       rc, mandatory, dummy_audio;
    ngx_uint_t                      prio;
    ngx_uint_t                      peers;
    ngx_uint_t                      meta_version;
    ngx_uint_t                      csidx;
    uint32_t                        delta;
    ngx_rtmp_live_chunk_stream_t   *cs;
#ifdef NGX_DEBUG
    const char                     *type_s;

    type_s = (h->type == NGX_RTMP_MSG_VIDEO ? "video" : "audio");
#endif

    lacf = ngx_rtmp_get_module_app_conf(s, ngx_rtmp_live_module);
    if (lacf == NULL) {
        return NGX_ERROR;
    }

    if (!lacf->live || in == NULL  || in->buf == NULL) {
        return NGX_OK;
    }

    ctx = ngx_rtmp_get_module_ctx(s, ngx_rtmp_live_module);
    if (ctx == NULL || ctx->stream == NULL) {
        return NGX_OK;
    }

    if (ctx->publishing == 0) {
        ngx_log_debug1(NGX_LOG_DEBUG_RTMP, s->connection->log, 0,
                       "live: %s from non-publisher", type_s);
        return NGX_OK;
    }

    if (!ctx->stream->active) {
        ngx_rtmp_live_start(s);
    }

    if (ctx->idle_evt.timer_set) {
        ngx_add_timer(&ctx->idle_evt, lacf->idle_timeout);
    }

    ngx_log_debug2(NGX_LOG_DEBUG_RTMP, s->connection->log, 0,
                   "live: %s packet timestamp=%uD",
                   type_s, h->timestamp);

    s->current_time = h->timestamp;

    peers = 0;
    apkt = NULL;
    aapkt = NULL;
    acopkt = NULL;
    header = NULL;
    coheader = NULL;
    meta = NULL;
    meta_version = 0;
    mandatory = 0;

    prio = (h->type == NGX_RTMP_MSG_VIDEO ?
            ngx_rtmp_get_video_frame_type(in) : 0);

    cscf = ngx_rtmp_get_module_srv_conf(s, ngx_rtmp_core_module);

    csidx = !(lacf->interleave || h->type == NGX_RTMP_MSG_VIDEO);

    cs = &ctx->cs[csidx];

    ngx_memzero(&ch, sizeof(ch));

    ch.timestamp = h->timestamp;
    ch.msid = NGX_RTMP_MSID;
    ch.csid = cs->csid;
    ch.type = h->type;

    lh = ch;

    if (cs->active) {
        lh.timestamp = cs->timestamp;
    }

    clh = lh;
    clh.type = (h->type == NGX_RTMP_MSG_AUDIO ? NGX_RTMP_MSG_VIDEO :
                                                NGX_RTMP_MSG_AUDIO);

    cs->active = 1;
    cs->timestamp = ch.timestamp;

    delta = ch.timestamp - lh.timestamp;
/*
    if (delta >> 31) {
        ngx_log_debug2(NGX_LOG_DEBUG_RTMP, s->connection->log, 0,
                       "live: clipping non-monotonical timestamp %uD->%uD",
                       lh.timestamp, ch.timestamp);

        delta = 0;

        ch.timestamp = lh.timestamp;
    }
*/
    rpkt = ngx_rtmp_append_shared_bufs(cscf, NULL, in);

    ngx_rtmp_prepare_message(s, &ch, &lh, rpkt);
	
	ngx_rtmp_live_gop_cache_frame(s, prio, &ch, in);

    codec_ctx = ngx_rtmp_get_module_ctx(s, ngx_rtmp_codec_module);

    if (codec_ctx) {

        if (h->type == NGX_RTMP_MSG_AUDIO) {
            header = codec_ctx->aac_header;

            if (lacf->interleave) {
                coheader = codec_ctx->video_header;
            }

            if (codec_ctx->audio_codec_id == NGX_RTMP_AUDIO_AAC &&
                ngx_rtmp_is_codec_header(in))
            {
                prio = 0;
                mandatory = 1;
            }

        } else {
            header = codec_ctx->video_header;

            if (lacf->interleave) {
                coheader = codec_ctx->aac_header;
            }

            if ((codec_ctx->video_codec_id == NGX_RTMP_VIDEO_H264 ||
                 codec_ctx->video_codec_id == NGX_RTMP_VIDEO_H265) &&
                 ngx_rtmp_is_codec_header(in))
            {
                prio = 0;
                mandatory = 1;
            }
        }

        if (codec_ctx->meta) {
            meta = codec_ctx->meta;
            meta_version = codec_ctx->meta_version;
        }
    }

    /* broadcast to all subscribers */

    for (pctx = ctx->stream->ctx; pctx; pctx = pctx->next) {
        if (pctx == ctx || pctx->paused) {
            continue;
        }

        ss = pctx->session;
        cs = &pctx->cs[csidx];

        /* send metadata */

        if (meta && meta_version != pctx->meta_version) {
            ngx_log_debug0(NGX_LOG_DEBUG_RTMP, ss->connection->log, 0,
                           "live: meta");

            if (ngx_rtmp_send_message(ss, meta, 0) == NGX_OK) {
                pctx->meta_version = meta_version;
            }
        }

        /* sync stream */

        if (cs->active && (lacf->sync && cs->dropped > lacf->sync)) {
            ngx_log_debug2(NGX_LOG_DEBUG_RTMP, ss->connection->log, 0,
                           "live: sync %s dropped=%uD", type_s, cs->dropped);

            cs->active = 0;
            cs->dropped = 0;
        }

        /* absolute packet */

        if (!cs->active) {

            if (mandatory) {
                ngx_log_debug0(NGX_LOG_DEBUG_RTMP, ss->connection->log, 0,
                               "live: skipping header");
                continue;
            }

            if (lacf->wait_video && h->type == NGX_RTMP_MSG_AUDIO &&
                !pctx->cs[0].active)
            {
                ngx_log_debug0(NGX_LOG_DEBUG_RTMP, ss->connection->log, 0,
                               "live: waiting for video");
                continue;
            }

            if (lacf->wait_key && prio != NGX_RTMP_VIDEO_KEY_FRAME &&
               (lacf->interleave || h->type == NGX_RTMP_MSG_VIDEO))
            {
                ngx_log_debug0(NGX_LOG_DEBUG_RTMP, ss->connection->log, 0,
                               "live: skip non-key");
                continue;
            }

            dummy_audio = 0;
            if (lacf->wait_video && h->type == NGX_RTMP_MSG_VIDEO &&
                !pctx->cs[1].active)
            {
                dummy_audio = 1;
                if (aapkt == NULL) {
                    aapkt = ngx_rtmp_alloc_shared_buf(cscf);
                    ngx_rtmp_prepare_message(s, &clh, NULL, aapkt);
                }
            }

            if (header || coheader) {

                /* send absolute codec header */

                ngx_log_debug2(NGX_LOG_DEBUG_RTMP, ss->connection->log, 0,
                               "live: abs %s header timestamp=%uD",
                               type_s, lh.timestamp);

                if (header) {
                    if (apkt == NULL) {
                        apkt = ngx_rtmp_append_shared_bufs(cscf, NULL, header);
                        ngx_rtmp_prepare_message(s, &lh, NULL, apkt);
                    }

                    rc = ngx_rtmp_send_message(ss, apkt, 0);
                    if (rc != NGX_OK) {
                        continue;
                    }
                }

                if (coheader) {
                    if (acopkt == NULL) {
                        acopkt = ngx_rtmp_append_shared_bufs(cscf, NULL, coheader);
                        ngx_rtmp_prepare_message(s, &clh, NULL, acopkt);
                    }

                    rc = ngx_rtmp_send_message(ss, acopkt, 0);
                    if (rc != NGX_OK) {
                        continue;
                    }

                } else if (dummy_audio) {
                    ngx_rtmp_send_message(ss, aapkt, 0);
                }

                cs->timestamp = lh.timestamp;
                cs->active = 1;
                ss->current_time = cs->timestamp;

            } else {

                /* send absolute packet */

                ngx_log_debug2(NGX_LOG_DEBUG_RTMP, ss->connection->log, 0,
                               "live: abs %s packet timestamp=%uD",
                               type_s, ch.timestamp);

                if (apkt == NULL) {
                    apkt = ngx_rtmp_append_shared_bufs(cscf, NULL, in);
                    ngx_rtmp_prepare_message(s, &ch, NULL, apkt);
                }

                rc = ngx_rtmp_send_message(ss, apkt, prio);
                if (rc != NGX_OK) {
                    continue;
                }

                cs->timestamp = ch.timestamp;
                cs->active = 1;
                ss->current_time = cs->timestamp;

                ++peers;

                if (dummy_audio) {
                    ngx_rtmp_send_message(ss, aapkt, 0);
                }

                continue;
            }
        }

        /* send relative packet */

        ngx_log_debug2(NGX_LOG_DEBUG_RTMP, ss->connection->log, 0,
                       "live: rel %s packet delta=%uD",
                       type_s, delta);

        if (ngx_rtmp_send_message(ss, rpkt, prio) != NGX_OK) {
            ++pctx->ndropped;

            cs->dropped += delta;

            if (mandatory) {
                ngx_log_debug0(NGX_LOG_DEBUG_RTMP, ss->connection->log, 0,
                               "live: mandatory packet failed");
                ngx_rtmp_finalize_session(ss);
            }

            continue;
        }

        cs->timestamp += delta;
        ++peers;
        ss->current_time = cs->timestamp;
    }

    if (rpkt) {
        ngx_rtmp_free_shared_chain(cscf, rpkt);
    }

    if (apkt) {
        ngx_rtmp_free_shared_chain(cscf, apkt);
    }

    if (aapkt) {
        ngx_rtmp_free_shared_chain(cscf, aapkt);
    }

    if (acopkt) {
        ngx_rtmp_free_shared_chain(cscf, acopkt);
    }

    ngx_rtmp_update_bandwidth(&ctx->stream->bw_in, h->mlen);
    ngx_rtmp_update_bandwidth(&ctx->stream->bw_out, h->mlen * peers);

    ngx_rtmp_update_bandwidth(h->type == NGX_RTMP_MSG_AUDIO ?
                              &ctx->stream->bw_in_audio :
                              &ctx->stream->bw_in_video,
                              h->mlen);

    return NGX_OK;
}


static ngx_int_t
ngx_rtmp_live_publish(ngx_rtmp_session_t *s, ngx_rtmp_publish_t *v)
{
    ngx_rtmp_live_app_conf_t       *lacf;
    ngx_rtmp_live_ctx_t            *ctx;

    lacf = ngx_rtmp_get_module_app_conf(s, ngx_rtmp_live_module);

    if (lacf == NULL || !lacf->live) {
        goto next;
    }

    ngx_log_debug2(NGX_LOG_DEBUG_RTMP, s->connection->log, 0,
                   "live: publish: name='%s' type='%s'",
                   v->name, v->type);

    /* join stream as publisher */

    ngx_rtmp_live_join(s, v->name, 1);

    ctx = ngx_rtmp_get_module_ctx(s, ngx_rtmp_live_module);
    if (ctx == NULL || !ctx->publishing) {
        goto next;
    }

    ctx->silent = v->silent;

    if (!ctx->silent) {
        ngx_rtmp_send_status(s, "NetStream.Publish.Start",
                             "status", "Start publishing");
    }

next:
    return next_publish(s, v);
}


static ngx_int_t
ngx_rtmp_live_play(ngx_rtmp_session_t *s, ngx_rtmp_play_t *v)
{
    ngx_rtmp_live_app_conf_t       *lacf;
    ngx_rtmp_live_ctx_t            *ctx;

    lacf = ngx_rtmp_get_module_app_conf(s, ngx_rtmp_live_module);

    if (lacf == NULL || !lacf->live) {
        goto next;
    }

    ngx_log_debug4(NGX_LOG_DEBUG_RTMP, s->connection->log, 0,
                   "live: play: name='%s' start=%uD duration=%uD reset=%d",
                   v->name, (uint32_t) v->start,
                   (uint32_t) v->duration, (uint32_t) v->reset);

    /* join stream as subscriber */

    ngx_rtmp_live_join(s, v->name, 0);

    ctx = ngx_rtmp_get_module_ctx(s, ngx_rtmp_live_module);
    if (ctx == NULL) {
        goto next;
    }

    ctx->silent = v->silent;

    if (!ctx->silent && !lacf->play_restart) {
        ngx_rtmp_send_status(s, "NetStream.Play.Start",
                             "status", "Start live");
        ngx_rtmp_send_sample_access(s);
    }

    ngx_rtmp_live_gop_cache_send(s);

    ngx_rtmp_playing++;

next:
    return next_play(s, v);
}


static ngx_int_t
ngx_rtmp_live_postconfiguration(ngx_conf_t *cf)
{
    ngx_rtmp_core_main_conf_t          *cmcf;
    ngx_rtmp_handler_pt                *h;

    cmcf = ngx_rtmp_conf_get_module_main_conf(cf, ngx_rtmp_core_module);

    /* register raw event handlers */

    h = ngx_array_push(&cmcf->events[NGX_RTMP_MSG_AUDIO]);
    *h = ngx_rtmp_live_av;

    h = ngx_array_push(&cmcf->events[NGX_RTMP_MSG_VIDEO]);
    *h = ngx_rtmp_live_av;

    /* chain handlers */

    next_publish = ngx_rtmp_publish;
    ngx_rtmp_publish = ngx_rtmp_live_publish;

    next_play = ngx_rtmp_play;
    ngx_rtmp_play = ngx_rtmp_live_play;

    next_close_stream = ngx_rtmp_close_stream;
    ngx_rtmp_close_stream = ngx_rtmp_live_close_stream;

    next_pause = ngx_rtmp_pause;
    ngx_rtmp_pause = ngx_rtmp_live_pause;

    next_stream_begin = ngx_rtmp_stream_begin;
    ngx_rtmp_stream_begin = ngx_rtmp_live_stream_begin;

    next_stream_eof = ngx_rtmp_stream_eof;
    ngx_rtmp_stream_eof = ngx_rtmp_live_stream_eof;

    return NGX_OK;
}
