

/*
 * Copyright (C) Roman Arutyunyan
 */


#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_rtmp.h>
#include "ngx_rtmp_live_module.h"
#include "ngx_rtmp_cmd_module.h"
#include "ngx_rtmp_codec_module.h"
#include "ngx_rtmp_notify_module.h"
#include "ngx_rtmp_bitop.h"
#include "ngx_rtmp_log_module.h"

#define NGX_RTMP_LIVE_GOP_SIZE          100 /* gop cache */
#define NGX_RTMP_LIVE_PER_GOP_MAX_TIME  30000 /* per gop cache`s max time */

/* reason of cleaning gop*/
typedef enum {
    NGX_RTMP_GOP_CLEAN_NO,
    NGX_RTMP_GOP_CLEAN_UNIQUE,
    NGX_RTMP_GOP_CLEAN_MIN,
    NGX_RTMP_GOP_CLEAN_MAX
} ngx_rtmp_gop_clean_t;


static ngx_rtmp_connect_pt              next_connect;
static ngx_rtmp_publish_pt              next_publish;
static ngx_rtmp_play_pt                 next_play;
static ngx_rtmp_delete_stream_pt        next_delete_stream;
static ngx_rtmp_close_stream_pt         next_close_stream;
static ngx_rtmp_pause_pt                next_pause;
static ngx_rtmp_stream_begin_pt         next_stream_begin;
static ngx_rtmp_stream_eof_pt           next_stream_eof;

extern ngx_uint_t ngx_rtmp_publishing;
extern ngx_uint_t ngx_rtmp_playing;

static ngx_int_t ngx_rtmp_live_postconfiguration(ngx_conf_t *cf);
static void *ngx_rtmp_live_create_main_conf(ngx_conf_t *cf);
static void *ngx_rtmp_live_create_app_conf(ngx_conf_t *cf);
static char *ngx_rtmp_live_merge_app_conf(ngx_conf_t *cf,
       void *parent, void *child);
static char *ngx_rtmp_live_set_msec_slot(ngx_conf_t *cf, ngx_command_t *cmd,
       void *conf);
static void ngx_rtmp_live_start(ngx_rtmp_session_t *s);
static void ngx_rtmp_live_stop(ngx_rtmp_session_t *s);
static void ngx_rtmp_live_gop_cleanup(ngx_rtmp_session_t *s);
static ngx_int_t ngx_rtmp_live_connect(ngx_rtmp_session_t *s, ngx_rtmp_connect_t *v);
static ngx_int_t ngx_rtmp_live_create_flux_timer(ngx_rtmp_live_stream_t *stream);
static ngx_int_t ngx_rtmp_live_create_check_timer(ngx_rtmp_live_stream_t *stream);
static void ngx_rtmp_live_destory_check_timer(ngx_rtmp_live_stream_t *stream);
static void ngx_rtmp_live_update_fps(ngx_rtmp_live_frame_rate_t *fr, unsigned increase);


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

    { ngx_string("idle_timeout"),
      NGX_RTMP_MAIN_CONF|NGX_RTMP_SRV_CONF|NGX_RTMP_APP_CONF|NGX_CONF_TAKE1,
      ngx_rtmp_live_set_msec_slot,
      NGX_RTMP_APP_CONF_OFFSET,
      offsetof(ngx_rtmp_live_app_conf_t, idle_timeout),
      NULL },

    { ngx_string("check_timeout"),
      NGX_RTMP_MAIN_CONF|NGX_RTMP_SRV_CONF|NGX_RTMP_APP_CONF|NGX_CONF_TAKE1,
      ngx_rtmp_live_set_msec_slot,
      NGX_RTMP_APP_CONF_OFFSET,
      offsetof(ngx_rtmp_live_app_conf_t, check_timeout),
      NULL },

    { ngx_string("dryup_timeout"),
      NGX_RTMP_MAIN_CONF|NGX_RTMP_SRV_CONF|NGX_RTMP_APP_CONF|NGX_CONF_TAKE1,
      ngx_rtmp_live_set_msec_slot,
      NGX_RTMP_APP_CONF_OFFSET,
      offsetof(ngx_rtmp_live_app_conf_t, dryup_timeout),
      NULL },

      ngx_null_command
};


static ngx_rtmp_module_t  ngx_rtmp_live_module_ctx = {
    NULL,                                   /* preconfiguration */
    ngx_rtmp_live_postconfiguration,        /* postconfiguration */
    ngx_rtmp_live_create_main_conf,         /* create main configuration */
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
ngx_rtmp_live_create_main_conf(ngx_conf_t *cf)
{
    ngx_rtmp_live_main_conf_t      *lmcf;

    lmcf = ngx_pcalloc(cf->pool, sizeof(ngx_rtmp_live_main_conf_t));
    if (lmcf == NULL) {
        return NULL;
    }

    ngx_rtmp_live_main_conf = lmcf;

    lmcf->pool = ngx_create_pool(4096, &cf->cycle->new_log);
    if (lmcf->pool == NULL) {
        return NGX_CONF_ERROR;
    }

    return lmcf;
}


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
    lacf->dryup_timeout = NGX_CONF_UNSET_MSEC;
    lacf->interleave = NGX_CONF_UNSET;
    lacf->gop_cache_mintime = NGX_CONF_UNSET_MSEC;
    lacf->gop_cache_maxtime = NGX_CONF_UNSET_MSEC;
    lacf->gop_cache = NGX_CONF_UNSET;
    lacf->wait_key = NGX_CONF_UNSET;
    lacf->wait_video = NGX_CONF_UNSET;
    lacf->publish_notify = NGX_CONF_UNSET;
    lacf->play_restart = NGX_CONF_UNSET;
    lacf->idle_streams = NGX_CONF_UNSET;
    lacf->check_timeout = NGX_CONF_UNSET;

    return lacf;
}


static char *
ngx_rtmp_live_merge_app_conf(ngx_conf_t *cf, void *parent, void *child)
{
    ngx_rtmp_live_app_conf_t *prev = parent;
    ngx_rtmp_live_app_conf_t *conf = child;

    ngx_conf_merge_value(conf->live, prev->live, 1);
    ngx_conf_merge_value(conf->nbuckets, prev->nbuckets, 1024);
    ngx_conf_merge_msec_value(conf->buflen, prev->buflen, 0);
    ngx_conf_merge_msec_value(conf->sync, prev->sync, 300);
    ngx_conf_merge_msec_value(conf->idle_timeout, prev->idle_timeout, 0);
    ngx_conf_merge_msec_value(conf->dryup_timeout, prev->dryup_timeout, 1000);
    ngx_conf_merge_value(conf->interleave, prev->interleave, 0);
    ngx_conf_merge_value(conf->gop_cache, prev->gop_cache, 1);
    ngx_conf_merge_msec_value(conf->gop_cache_mintime, prev->gop_cache_mintime, 0);
    ngx_conf_merge_msec_value(conf->gop_cache_maxtime, prev->gop_cache_maxtime, NGX_RTMP_LIVE_PER_GOP_MAX_TIME);
    ngx_conf_merge_value(conf->wait_key, prev->wait_key, 1);
    ngx_conf_merge_value(conf->wait_video, prev->wait_video, 1);
    ngx_conf_merge_value(conf->publish_notify, prev->publish_notify, 0);
    ngx_conf_merge_value(conf->play_restart, prev->play_restart, 0);
    ngx_conf_merge_value(conf->idle_streams, prev->idle_streams, 1);
    ngx_conf_merge_value(conf->check_timeout, prev->check_timeout, 2000);

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
    ngx_memcpy((*stream)->name, name, ngx_min(sizeof((*stream)->name) - 1, len));
    (*stream)->epoch = ngx_current_msec;
    (*stream)->check_evt_msec = lacf->check_timeout;

    return stream;
}


ngx_rtmp_live_dyn_srv_t **
ngx_rtmp_live_get_srv_dynamic(ngx_rtmp_live_main_conf_t *lmcf, ngx_str_t *uniqname, int create)
{
    ngx_rtmp_live_dyn_srv_t   **srv;

    if (lmcf == NULL) {
        return NULL;
    }

    srv = &lmcf->srvs[ngx_hash_key(uniqname->data, uniqname->len) % NGX_RTMP_MAX_SRV_NBUCKET];
    for (; *srv; srv = &(*srv)->next) {
        if (ngx_strlen((*srv)->name) == uniqname->len &&
            ngx_strncmp(uniqname->data, (*srv)->name, uniqname->len) == 0) {
            return srv;
        }
    }

    if (!create) {
        return NULL;
    }

    if (lmcf->free_srvs) {
        *srv = lmcf->free_srvs;
        lmcf->free_srvs = lmcf->free_srvs->next;
    } else {
        *srv = ngx_palloc(lmcf->pool, sizeof(ngx_rtmp_live_dyn_srv_t));
    }

    ngx_memzero(*srv, sizeof(ngx_rtmp_live_dyn_srv_t));
    ngx_memcpy((*srv)->name, uniqname->data, ngx_min(sizeof((*srv)->name) - 1, uniqname->len));
    (*srv)->napp = 0;

    return srv;
}


ngx_rtmp_live_dyn_app_t **
ngx_rtmp_live_get_app_dynamic(ngx_rtmp_live_main_conf_t *lmcf, ngx_rtmp_live_dyn_srv_t **srv, ngx_str_t *appname, int create)
{
    ngx_rtmp_live_dyn_app_t   **app;

    if (lmcf == NULL) {
        return NULL;
    }

    app = &(*srv)->apps[ngx_hash_key(appname->data, appname->len) % NGX_RTMP_MAX_APP_NBUCKET];
    for (; *app; app = &(*app)->next) {
        if (ngx_strlen((*app)->name) == appname->len &&
            ngx_strncmp(appname->data, (*app)->name, appname->len) == 0) {
            return app;
        }
    }

    if (!create) {
        return NULL;
    }

    if (lmcf->free_apps) {
        *app = lmcf->free_apps;
        lmcf->free_apps = lmcf->free_apps->next;
    } else {
        *app = ngx_palloc(lmcf->pool, sizeof(ngx_rtmp_live_dyn_app_t));
    }

    ngx_memzero(*app, sizeof(ngx_rtmp_live_dyn_app_t));
    ngx_memcpy((*app)->name, appname->data, ngx_min(sizeof((*app)->name) - 1, appname->len));
    (*app)->nstream = 0;
    (*srv)->napp ++;

    return app;
}


ngx_rtmp_live_stream_t **
ngx_rtmp_live_get_name_dynamic(ngx_rtmp_live_main_conf_t *lmcf, ngx_rtmp_live_app_conf_t *lacf,
    ngx_rtmp_live_dyn_app_t **app, ngx_str_t *name, int create)
{
    ngx_rtmp_live_stream_t   **stream;

    if (lmcf == NULL || lacf == NULL) {
        return NULL;
    }

    stream = &(*app)->streams[ngx_hash_key(name->data, name->len) % NGX_RTMP_MAX_STREAM_NBUCKET];
    for (; *stream; stream = &(*stream)->next) {
        if (ngx_strlen((*stream)->name) == name->len &&
            ngx_strncmp(name->data, (*stream)->name, name->len) == 0) {
            return stream;
        }
    }

    if (!create) {
        return NULL;
    }

    if (lmcf->free_streams) {
        *stream = lmcf->free_streams;
        lmcf->free_streams = lmcf->free_streams->next;
    } else {
        *stream = ngx_palloc(lmcf->pool, sizeof(ngx_rtmp_live_stream_t));
    }

    ngx_memzero(*stream, sizeof(ngx_rtmp_live_stream_t));
    ngx_memcpy((*stream)->name, name->data, ngx_min(sizeof((*stream)->name) - 1, name->len));
    (*stream)->epoch = ngx_current_msec;
    (*stream)->check_evt_msec = lacf->check_timeout;
    (*app)->nstream ++;

    return stream;
}


static ngx_rtmp_live_stream_t **
ngx_rtmp_live_get_stream_dynamic(ngx_rtmp_session_t *s, int create, ngx_rtmp_live_dyn_srv_t ***srv,
    ngx_rtmp_live_dyn_app_t ***app)
{
    ngx_rtmp_live_app_conf_t   *lacf;
    ngx_rtmp_live_main_conf_t  *lmcf;
    ngx_rtmp_core_srv_conf_t   *cscf;
    ngx_rtmp_live_stream_t    **stream;
    ngx_rtmp_live_ctx_t        *ctx;
    ngx_str_t                   unique_name;

    lacf = ngx_rtmp_get_module_app_conf(s, ngx_rtmp_live_module);
    if (lacf == NULL) {
        return NULL;
    }

    lmcf = ngx_rtmp_get_module_main_conf(s, ngx_rtmp_live_module);
    if (lmcf == NULL) {
        return NULL;
    }

    cscf = ngx_rtmp_get_module_srv_conf(s, ngx_rtmp_core_module);

    unique_name = ngx_rtmp_get_attr_conf(cscf, unique_name);

    ctx = ngx_rtmp_get_module_ctx(s, ngx_rtmp_live_module);
    if (ctx == NULL) {
        return NULL;
    }

    *srv = ngx_rtmp_live_get_srv_dynamic(lmcf, &unique_name, create);
    if (*srv == NULL) {
        return NULL;
    }

    *app = ngx_rtmp_live_get_app_dynamic(lmcf, *srv, &s->app, create);
    if (*app == NULL) {
        return NULL;
    }

    stream = ngx_rtmp_live_get_name_dynamic(lmcf, lacf, *app, &s->name, create);
    if (stream == NULL) {
        return NULL;
    }

    ngx_log_debug3(NGX_LOG_DEBUG_RTMP, s->connection->log, 0,
            "live: dynamic create unique_name='%V' app='%V' stream='%V'",
            &unique_name, &s->app, &s->name);

    return stream;
}

static ngx_rtmp_live_ctx_t*
ngx_rtmp_live_get_publisher_ctx(ngx_rtmp_live_stream_t *stream)
{
    ngx_rtmp_live_ctx_t        *pctx;

    if(stream == NULL || stream->ctx == NULL) {
        return NULL;
    }

    for (pctx = stream->ctx; pctx; pctx = pctx->next) {
        if (pctx->publishing) {
            break;
        }
    }

    return pctx;
}

static void
ngx_rtmp_live_flux_timer(ngx_event_t *e)
{
    ngx_rtmp_session_t         *s;
    ngx_rtmp_live_stream_t     *stream;
    ngx_rtmp_log_main_conf_t   *lmcf;
    ngx_rtmp_live_ctx_t        *pctx;

    stream = e->data;

    pctx = ngx_rtmp_live_get_publisher_ctx (stream);

    if(pctx == NULL) {
        goto error;
    }

    s = pctx->session;

    if (s == NULL) {
        goto error;
    }

    lmcf = ngx_rtmp_get_module_main_conf(s, ngx_rtmp_log_module);

    // trigger writing a line to flux logger.
    s->log_time = ngx_current_msec;
    ngx_rtmp_log_flux(s);

    e = &stream->flux_evt;
    e->data = stream;
    e->log = s->connection->log;
    e->handler = ngx_rtmp_live_flux_timer;

    ngx_add_timer(&stream->flux_evt, lmcf->flux_interval);

    return;

error:
    if (stream->flux_evt.timer_set) {
        ngx_del_timer(&stream->flux_evt);
    }

    return;
}

static ngx_int_t
ngx_rtmp_live_create_flux_timer(ngx_rtmp_live_stream_t *stream)
{
    ngx_rtmp_session_t         *s;
    ngx_rtmp_live_ctx_t        *pctx;
    ngx_event_t                *e;
    ngx_rtmp_log_main_conf_t   *lmcf;
    ngx_uint_t                 remainder;
    ngx_msec_t                 flux_interval;

    if (stream == NULL) {
        goto error;
    }

    if (stream->flux_evt.timer_set) {
        return NGX_OK;
    }

    pctx = ngx_rtmp_live_get_publisher_ctx (stream);
    if(pctx == NULL) {
        goto error;
    }

    s = pctx->session;

    if (s == NULL) {
        goto error;
    }

    lmcf = ngx_rtmp_get_module_main_conf(s, ngx_rtmp_log_module);

    e = &stream->flux_evt;
    e->data = stream;
    e->log = s->connection->log;
    e->handler = ngx_rtmp_live_flux_timer;

    remainder = s->connect_time % 60;
    if (remainder != 0) {

        flux_interval = (60 - remainder) * 1000;
        ngx_add_timer(&stream->flux_evt, flux_interval);

    } else {

        s->log_time = ngx_current_msec;
        ngx_rtmp_log_flux(s);
        ngx_add_timer(&stream->flux_evt, lmcf->flux_interval);
    }

    return NGX_OK;

error:
    if (stream->flux_evt.timer_set) {
        ngx_del_timer(&stream->flux_evt);
    }

    return NGX_OK;
}

static void
ngx_rtmp_live_dryup_handler(ngx_event_t *e)
{
    ngx_rtmp_session_t         *s;
    ngx_connection_t           *c;
    ngx_rtmp_live_ctx_t        *ctx;

    c = e->data;
    if (c == NULL) {
       return;
    }

    s = !ngx_rtmp_type(c->protocol) ? c->http_data : c->data;
    if (s == NULL) {
       return;
    }

    ctx = ngx_rtmp_get_module_ctx(s, ngx_rtmp_live_module);
    if (ctx == NULL || ctx->stream == NULL) {
       return;
    }

    ngx_rtmp_cal_av_bandwidth(&ctx->stream->bw_in_av);
    ngx_rtmp_live_update_fps(&ctx->stream->video_frame_rate, 0);
}

static void
ngx_rtmp_live_dryup_timer(ngx_rtmp_session_t *s, unsigned active)
{
    ngx_rtmp_live_app_conf_t   *lacf;
    ngx_rtmp_live_ctx_t        *ctx;
    ngx_event_t                *e;

    lacf = ngx_rtmp_get_module_app_conf(s, ngx_rtmp_live_module);
    if (lacf == NULL) {
        return;
    }

    ctx = ngx_rtmp_get_module_ctx(s, ngx_rtmp_live_module);
    if (ctx == NULL) {
        return;
    }

    e = &ctx->dryup_evt;
    if (e == NULL) {
        return;
    }

    if (active) {

        e->data = s->connection;
        e->log = s->connection->log;
        e->handler = ngx_rtmp_live_dryup_handler;

        ngx_add_timer(e, lacf->dryup_timeout);

    } else if (ctx->dryup_evt.timer_set) {

        ngx_del_timer(e);
    }
}

static void
ngx_rtmp_live_destory_flux_timer(ngx_rtmp_session_t *s)
{
    ngx_rtmp_live_stream_t *stream;
    ngx_rtmp_live_ctx_t    *ctx;

    if (!s) {
        return;
    }

    ctx = ngx_rtmp_get_module_ctx(s, ngx_rtmp_live_module);
    if (!ctx) {
        return;
    }

    stream = ctx->stream;
    if (!stream) {
        return;
    }

    s->log_time = ngx_current_msec;
    ngx_rtmp_log_flux(s);

    if (stream->flux_evt.timer_set) {
        ngx_del_timer(&stream->flux_evt);
    }

    return;
}

#define PLAY_RETRY_MAX 5
#define PLAY_RETRY_INTERVAL 2000

static void
ngx_rtmp_live_check_timer(ngx_event_t *e)
{
    static ngx_rtmp_play_t      v;

    ngx_rtmp_session_t         *s;
    ngx_rtmp_live_stream_t     *stream;
    ngx_rtmp_live_ctx_t        *pctx;

    stream = e->data;
    if (stream == NULL || stream->ctx == NULL || stream->publishing) {
        goto error;
    }

    s = stream->ctx->session;

    if (s == NULL) {
        goto error;
    }

    /* relay timeout close all player */
    if (stream->check_evt_msec == PLAY_RETRY_INTERVAL * PLAY_RETRY_MAX) {
        for(pctx = stream->ctx; pctx; pctx = pctx->next) {
            s = pctx->session;
            ngx_log_error(NGX_LOG_INFO, s->connection->log, 0,
                          "live: close relay session timeout = %ui",
                          stream->check_evt_msec);
            ngx_rtmp_finalize_session(s);
        }

        return;
    }

    ngx_memzero(&v, sizeof(v));
    *ngx_cpymem(v.name, s->name.data, ngx_min(s->name.len, NGX_RTMP_MAX_NAME - 1)) = 0;
    *ngx_cpymem(v.args, s->args.data, ngx_min(s->args.len, NGX_RTMP_MAX_ARGS - 1)) = 0;
    v.start = s->start;
    v.duration = s->duration;
    v.reset = s->reset;
    v.silent = s->silent;

    ngx_rtmp_notify_play1(s, &v);

    e = &stream->check_evt;
    e->data = stream;
    e->log = s->connection->log;
    e->handler = ngx_rtmp_live_check_timer;

    stream->check_evt_msec += PLAY_RETRY_INTERVAL;
    ngx_add_timer(&stream->check_evt, stream->check_evt_msec);

    return;

error:
    ngx_rtmp_live_destory_check_timer(stream);

    return;
}

#undef PLAY_RETRY_MAX
#undef PLAY_RETRY_INTERVAL

static ngx_int_t
ngx_rtmp_live_create_check_timer(ngx_rtmp_live_stream_t *stream)
{
    ngx_rtmp_session_t             *s;
    ngx_event_t                    *e;
    ngx_rtmp_live_app_conf_t       *lacf;

    if (stream == NULL || stream->ctx == NULL) {
        goto error;
    }

    if (stream->check_evt.timer_set) {
        return NGX_OK;
    }

    s = stream->ctx->session;

    if (s == NULL) {
        goto error;
    }

    lacf = ngx_rtmp_get_module_app_conf(s, ngx_rtmp_live_module);

    if(lacf == NULL) {
        goto error;
    }

    e = &stream->check_evt;
    e->data = stream;
    e->log = s->connection->log;
    e->handler = ngx_rtmp_live_check_timer;

    stream->check_evt_msec = lacf->check_timeout;

    ngx_add_timer(&stream->check_evt, stream->check_evt_msec);

    return NGX_OK;

error:
    ngx_rtmp_live_destory_check_timer(stream);

    return NGX_OK;
}


static void
ngx_rtmp_live_destory_check_timer(ngx_rtmp_live_stream_t *stream)
{
    if (stream == NULL) {
        return;
    }

    if (stream->check_evt.timer_set) {
        ngx_del_timer(&stream->check_evt);
    }
}


static void
ngx_rtmp_live_idle(ngx_event_t *pev)
{
    ngx_connection_t           *c;
    ngx_rtmp_session_t         *s;

    c = pev->data;
    s = !ngx_rtmp_type(c->protocol) ? c->http_data : c->data;

    ngx_log_error(NGX_LOG_INFO, s->connection->log, 0,
                  "live: drop idle publisher");

    ngx_rtmp_set_fincode(s, NGX_RTMP_LOG_FINALIZE_DROP_IDLE_CODE);

    ngx_rtmp_finalize_session(s);
}


static void
ngx_rtmp_live_idle_timer(ngx_rtmp_session_t *s, unsigned active)
{
    ngx_rtmp_live_app_conf_t   *lacf;
    ngx_rtmp_live_ctx_t        *ctx;
    ngx_event_t                *e;

    lacf = ngx_rtmp_get_module_app_conf(s, ngx_rtmp_live_module);
    if (lacf == NULL) {
        return;
    }

    ctx = ngx_rtmp_get_module_ctx(s, ngx_rtmp_live_module);
    if (ctx == NULL) {
        return;
    }

    e = &ctx->idle_evt;
    if (e == NULL) {
        return;
    }

    if (active) {
        if (ngx_rtmp_get_attr_conf(lacf, idle_timeout) <= 0) {
            return;
        }

        e->data = s->connection;
        e->log = s->connection->log;
        e->handler = ngx_rtmp_live_idle;

        ngx_add_timer(e, ngx_rtmp_get_attr_conf(lacf, idle_timeout));
    } else if (ctx->idle_evt.timer_set) {
        ngx_del_timer(e);
    }
}

static void
ngx_rtmp_live_del_idle_timer(ngx_rtmp_session_t *s, unsigned active)
{
    ngx_rtmp_live_ctx_t        *ctx;
    ngx_event_t                *e;

    ctx = ngx_rtmp_get_module_ctx(s, ngx_rtmp_live_module);
    if (ctx == NULL) {
        return;
    }

    e = &ctx->idle_evt;
    if (e == NULL) {
        return;
    }

    if (ctx->idle_evt.timer_set && !active) {
        ngx_del_timer(e);
    }
}


static void
ngx_rtmp_live_del_dryup_timer(ngx_rtmp_session_t *s, unsigned active)
{
    ngx_rtmp_live_ctx_t        *ctx;
    ngx_event_t                *e;

    ctx = ngx_rtmp_get_module_ctx(s, ngx_rtmp_live_module);
    if (ctx == NULL) {
        return;
    }

    e = &ctx->dryup_evt;
    if (e == NULL) {
        return;
    }

    if (ctx->dryup_evt.timer_set && !active) {
        ngx_del_timer(e);
    }
}


static void
ngx_rtmp_live_update_fps(ngx_rtmp_live_frame_rate_t *fr, unsigned increase)
{
#define NGX_RTMP_FRAME_RATE_INTERVAL 1000

    if (ngx_current_msec > fr->time_end) {
        fr->fps = ngx_current_msec
            > fr->time_end + NGX_RTMP_FRAME_RATE_INTERVAL
            ? 0
            : fr->frame_cnt * 1000 * 1000 / (NGX_RTMP_FRAME_RATE_INTERVAL + (ngx_current_msec - fr->time_end));
        fr->frame_cnt = 0;
        fr->time_end = ngx_current_msec + NGX_RTMP_FRAME_RATE_INTERVAL;
    }

    if (increase) fr->frame_cnt ++;

#undef NGX_RTMP_FRAME_RATE_INTERVAL
}


static void
ngx_rtmp_live_set_status(ngx_rtmp_session_t *s, ngx_chain_t *control,
                         ngx_chain_t **status, size_t nstatus,
                         unsigned active)
{
    ngx_rtmp_live_ctx_t        *ctx, *pctx;
    ngx_chain_t               **cl;
    size_t                      n;

    ctx = ngx_rtmp_get_module_ctx(s, ngx_rtmp_live_module);

    ngx_log_debug1(NGX_LOG_DEBUG_RTMP, s->connection->log, 0,
                   "live: set active=%ui", active);

    if (ctx->active == active) {
        ngx_log_debug1(NGX_LOG_DEBUG_RTMP, s->connection->log, 0,
                       "live: unchanged active=%ui", active);
        ngx_rtmp_live_del_idle_timer(s, active);
        ngx_rtmp_live_del_dryup_timer(s, active);
        return;
    }

    ctx->active = active;

    if (ctx->publishing) {

        /* publisher */

        ngx_rtmp_live_idle_timer(s, active);
        ngx_rtmp_live_dryup_timer(s, active);

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

    if (ctx == NULL ||
        ctx->stream == NULL ||
        !ctx->publishing) {

        goto next;
    }

    ngx_log_debug0(NGX_LOG_DEBUG_RTMP, s->connection->log, 0,
                   "live: stream_begin");

    ngx_rtmp_live_start(s);

next:
    return next_stream_begin(s, v);
}


ngx_chain_t *
ngx_rtmp_gop_alloc_chain(ngx_array_t *a)
{
    u_char                     *p;
    ngx_buf_t                  *b;
    ngx_chain_t                *out, **free = a->elts;
    size_t                      size;

    if (*free) {
        out = *free;
        *free = (*free)->next;

    } else {

        size = NGX_RTMP_DEFAULT_CHUNK_SIZE;

        p = ngx_pcalloc(a->pool, sizeof(ngx_chain_t)
                        + sizeof(ngx_buf_t) + size);
        if (p == NULL) {
            return NULL;
        }

        out = (ngx_chain_t *)p;

        p += sizeof(ngx_chain_t);
        out->buf = (ngx_buf_t *)p;

        p += sizeof(ngx_buf_t);
        out->buf->start = p;
        out->buf->end = p + size;
    }

    out->next = NULL;
    b = out->buf;
    b->pos = b->last = b->start;
    b->memory = 1;

    return out;
}


static ngx_int_t
ngx_rtmp_live_stream_eof(ngx_rtmp_session_t *s, ngx_rtmp_stream_eof_t *v)
{
    ngx_rtmp_live_ctx_t    *ctx;

    ctx = ngx_rtmp_get_module_ctx(s, ngx_rtmp_live_module);

    if (ctx == NULL ||
        ctx->stream == NULL ||
        !ctx->publishing) {

        goto next;
    }

    ngx_log_debug0(NGX_LOG_DEBUG_RTMP, s->connection->log, 0,
                   "live: stream_eof");

    ngx_rtmp_live_stop(s);

next:
    return next_stream_eof(s, v);
}


inline void
ngx_rtmp_live_ctx_link(ngx_rtmp_live_stream_t *stream, ngx_rtmp_live_ctx_t *ctx, unsigned publisher)
{
    if (stream == NULL || ctx == NULL) {
        return;
    }

    ctx->next = stream->ctx;
    stream->ctx = ctx;

    if (!publisher) {
        ++ stream->npull;

        ngx_log_debug1(NGX_LOG_DEBUG_RTMP, ctx->session->connection->log, 0,
                       "live ctx link: new player comes, npull: %uL", stream->npull);
    }
}


inline void
ngx_rtmp_live_ctx_delink(ngx_rtmp_live_stream_t *stream, ngx_rtmp_live_ctx_t *ctx, unsigned publisher)
{
    ngx_rtmp_live_ctx_t  **cctx;

    if (stream == NULL || ctx == NULL) {
        return;
    }

    for (cctx = &stream->ctx; *cctx; cctx = &(*cctx)->next) {
        if (*cctx == ctx) {
            *cctx = ctx->next;

            if (!publisher) {
                -- stream->npull;

                ngx_log_debug1(NGX_LOG_DEBUG_RTMP, ctx->session->connection->log, 0,
                               "live ctx link: new player gone, npull: %uL", stream->npull);
            }

            break;
        }
    }
}


void
ngx_rtmp_live_join(ngx_rtmp_session_t *s, u_char *name, unsigned publisher)
{
    ngx_rtmp_live_ctx_t            *ctx;
    ngx_rtmp_live_dyn_srv_t        **srv;
    ngx_rtmp_live_dyn_app_t        **app;
    ngx_rtmp_live_stream_t         **stream;
    ngx_rtmp_live_app_conf_t       *lacf;
    int                            create;

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
        ctx = ngx_palloc(s->pool, sizeof(ngx_rtmp_live_ctx_t));
        ngx_rtmp_set_ctx(s, ctx, ngx_rtmp_live_module);
    }

    ngx_memzero(ctx, sizeof(*ctx));

    ctx->session = s;
    srv = NULL;
    app = NULL;
    stream = NULL;

    create = publisher || (lacf->idle_streams && s->relay_type == NGX_NONE_RELAY);

    ngx_log_debug1(NGX_LOG_DEBUG_RTMP, s->connection->log, 0,
                   "live: join '%s'", name);

    if (ngx_rtmp_remote_conf()) {
        stream = ngx_rtmp_live_get_stream_dynamic(s, create, &srv, &app);

    } else {
        stream = ngx_rtmp_live_get_stream(s, name, create);
    }

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
            ngx_log_error(NGX_LOG_WARN, s->connection->log, 0,
                          "live: '%V/%s', already publishing", &s->app, name);
            ngx_rtmp_send_status(s, "NetStream.Publish.BadName", "error",
                                 "Already publishing");

            return;
        }

        (*stream)->publishing = 1;
        ngx_rtmp_live_destory_check_timer(*stream);
    }

    if (ngx_rtmp_remote_conf()) {
        ctx->srv = *srv;
        ctx->app = *app;
    }

    ctx->stream = *stream;
    ctx->publishing = publisher;
    ctx->protocol = s->protocol;

    ngx_rtmp_live_ctx_link(ctx->stream, ctx, publisher);

    // first connection trigger stream timer
    if (publisher) {
        ngx_rtmp_live_create_flux_timer(*stream);
    }

    if (lacf->buflen) {
        s->out_buffer = 1;
    }

    ctx->cs[0].csid = NGX_RTMP_CSID_VIDEO;
    ctx->cs[1].csid = NGX_RTMP_CSID_AUDIO;

    if (!ctx->publishing && ctx->stream->active) {
        ngx_rtmp_live_start(s);
    }

    if (!publisher && !(*stream)->publishing) {
        ngx_str_t strname;
        strname.data = name;
        strname.len = ngx_strlen(name);

        if (ngx_rtmp_relay_get_publish(s, &strname) == NULL) {
            ngx_rtmp_live_create_check_timer(*stream);
        }
    }
}


static void
ngx_rtmp_live_empty_leave(ngx_rtmp_session_t *s, ngx_rtmp_live_stream_t **stream)
{
    ngx_rtmp_live_ctx_t            *ctx;
    ngx_rtmp_live_app_conf_t       *lacf;

    lacf = ngx_rtmp_get_module_app_conf(s, ngx_rtmp_live_module);
    if (lacf == NULL) {
        return;
    }

    ctx = ngx_rtmp_get_module_ctx(s, ngx_rtmp_live_module);
    if (ctx == NULL) {
        return;
    }

    *stream = (*stream)->next;

    ctx->stream->next = lacf->free_streams;
    lacf->free_streams = ctx->stream;
    ctx->stream = NULL;
}


static void
ngx_rtmp_live_empty_leave_dynamic(ngx_rtmp_session_t *s, ngx_rtmp_live_stream_t **stream, ngx_rtmp_live_dyn_srv_t **srv,
    ngx_rtmp_live_dyn_app_t **app)
{
    ngx_rtmp_live_ctx_t            *ctx;
    ngx_rtmp_live_app_conf_t       *lacf;
    ngx_rtmp_live_main_conf_t      *lmcf;

#if(NGX_DEBUG)
    ngx_rtmp_core_srv_conf_t       *cscf;
    ngx_str_t                       unique_name;

    cscf = ngx_rtmp_get_module_srv_conf(s, ngx_rtmp_core_module);
    unique_name = ngx_rtmp_get_attr_conf(cscf, unique_name);
#endif

    lacf = ngx_rtmp_get_module_app_conf(s, ngx_rtmp_live_module);
    if (lacf == NULL) {
        return;
    }

    lmcf = ngx_rtmp_get_module_main_conf(s, ngx_rtmp_live_module);
    if (lmcf == NULL) {
        return;
    }

    ctx = ngx_rtmp_get_module_ctx(s, ngx_rtmp_live_module);
    if (ctx == NULL) {
        return;
    }

    ngx_log_debug3(NGX_LOG_DEBUG_RTMP, s->connection->log, 0,
            "live_empty_leave: dynamic unique_name='%V' app='%V' stream='%V'",
            &unique_name, &s->app, &s->name);

    *stream = (*stream)->next;
    (*app)->nstream --;

    ngx_log_debug4(NGX_LOG_DEBUG_RTMP, s->connection->log, 0,
            "live_empty_leave: dynamic unique_name='%V' app='%V' stream='%V' nstream='%d'",
            &unique_name, &s->app, &s->name, (*app)->nstream);

    ctx->stream->next = lmcf->free_streams;
    lmcf->free_streams = ctx->stream;
    ctx->stream = NULL;

    if ((*app)->nstream == 0) {
        *app = (*app)->next;
        (*srv)->napp --;

        ngx_log_debug4(NGX_LOG_DEBUG_RTMP, s->connection->log, 0,
                "live_empty_leave: dynamic unique_name='%V' app='%V' stream='%V' napp='%d'",
                &unique_name, &s->app, &s->name, (*srv)->napp);

        ctx->app->next = lmcf->free_apps;
        lmcf->free_apps = ctx->app;
        ctx->app = NULL;

        if ((*srv)->napp == 0) {
            *srv = (*srv)->next;

            ctx->srv->next = lmcf->free_srvs;
            lmcf->free_srvs = ctx->srv;
            ctx->srv = NULL;
        }
    }
}


static void
ngx_rtmp_live_close(ngx_rtmp_session_t *s)
{
    ngx_rtmp_session_t             *ss;
    ngx_rtmp_live_ctx_t            *ctx, *pctx;
    ngx_rtmp_live_stream_t        **stream;
    ngx_rtmp_live_dyn_srv_t       **srv;
    ngx_rtmp_live_dyn_app_t       **app;
    ngx_rtmp_live_app_conf_t       *lacf;

    lacf = ngx_rtmp_get_module_app_conf(s, ngx_rtmp_live_module);
    if (lacf == NULL) {
        return;
    }

    ctx = ngx_rtmp_get_module_ctx(s, ngx_rtmp_live_module);
    if (ctx == NULL) {
        return;
    }

    if (ctx->stream == NULL) {
        ngx_log_debug0(NGX_LOG_DEBUG_RTMP, s->connection->log, 0,
                       "live: not joined");
        return;
    }

    ngx_log_debug3(NGX_LOG_DEBUG_RTMP, s->connection->log, 0,
                   "live: leave '%s', publisher=%i, ctx->stream->publishing=%i",
                   ctx->stream->name, ctx->publishing, ctx->stream->publishing);

    if (ctx->stream->publishing && ctx->publishing) {
        ctx->stream->publishing = 0;
    }

    ngx_rtmp_live_ctx_delink(ctx->stream, ctx, ctx->publishing);

    if (ctx->publishing || ctx->stream->active) {
        ngx_rtmp_set_fincode(s, NGX_RTMP_LOG_FINALIZE_DROP_IDLE_CODE);
        ngx_rtmp_live_stop(s);
    }

    if (ctx->publishing) {

        ngx_rtmp_send_status(s, "NetStream.Unpublish.Success",
                             "status", "Stop publishing");
        ctx->stream->bw_in_av.a_intl_bw = 0;
        ctx->stream->bw_in_av.v_intl_bw = 0;
        ctx->stream->bw_in_av.a_intl_bw_exp = 0;
        ctx->stream->bw_in_av.v_intl_bw_exp = 0;
        ctx->stream->bw_in_av.a_intl_last_pts = 0;
        ctx->stream->bw_in_av.v_intl_last_pts = 0;
        ctx->stream->bw_in_av.a_intl_first_pts = 0;
        ctx->stream->bw_in_av.v_intl_first_pts = 0;
        ctx->stream->bw_in_av.intl_start = 0;
        ctx->stream->bw_in_av.intl_end = 0;
		ctx->stream->bw_out.bandwidth = 0;
        if (ngx_rtmp_publishing > 0) {

            --ngx_rtmp_publishing;
        }

        if (!lacf->idle_streams) {
            for (pctx = ctx->stream->ctx; pctx; pctx = pctx->next) {
                if (pctx->publishing == 0) {
                    ss = pctx->session;
                    ngx_log_debug0(NGX_LOG_DEBUG_RTMP, ss->connection->log, 0,
                                   "live: no publisher");
                    ngx_rtmp_finalize_session(ss);
                }
            }
        } else {
            ngx_uint_t nplayer = 0;
            for (pctx = ctx->stream->ctx; pctx; pctx = pctx->next) {
                if (pctx->publishing == 0) {
                    ss = pctx->session;
                    if (ss->relay_type != NGX_NONE_RELAY) {
                        ngx_log_error(NGX_LOG_INFO, ss->connection->log, 0,
                                      "live: close relay session");
                        ngx_rtmp_finalize_session(ss);

                    } else {
                        nplayer++;
                    }
                }
            }

            if (nplayer > 0) {
                ngx_rtmp_live_create_check_timer(ctx->stream);
            }
        }

        ngx_rtmp_live_gop_cleanup(s);

    } else {

        if (ngx_rtmp_playing > 0) {

            --ngx_rtmp_playing;
        }

        if (ctx->stream->ctx != NULL &&
            ctx->stream->ctx->next == NULL &&
            ctx->stream->ctx->publishing) {

            if (ctx->stream->ctx->session->relay_type != NGX_NONE_RELAY) {

                ngx_rtmp_finalize_session(ctx->stream->ctx->session);
            }
        }
    }

    /** del flux timer and trigger write log when publish session disconnect**/
    if (ctx->publishing) {

    	ngx_rtmp_live_destory_flux_timer(s);
    }

    if (ctx->stream->ctx) {
        ctx->stream = NULL;
        return;

    } else {

    	ngx_rtmp_live_destory_check_timer(ctx->stream);
    }

    ngx_log_debug1(NGX_LOG_DEBUG_RTMP, s->connection->log, 0,
                   "live: delete empty stream '%s'",
                   ctx->stream->name);

    if (ngx_rtmp_remote_conf()) {
        stream = ngx_rtmp_live_get_stream_dynamic(s, 0, &srv, &app);

        if (stream == NULL) {
            return;
        }

        ngx_rtmp_live_empty_leave_dynamic(s, stream, srv, app);

    } else {
        stream = ngx_rtmp_live_get_stream(s, ctx->stream->name, 0);

        if (stream == NULL) {
            return;
        }

        ngx_rtmp_live_empty_leave(s, stream);
    }

    if (!ctx->silent && !ctx->publishing && !lacf->play_restart) {
        
        ngx_rtmp_send_status(s, "NetStream.Play.Stop", "status", "Stop live");
    }
}


static ngx_int_t
ngx_rtmp_live_close_stream(ngx_rtmp_session_t *s, ngx_rtmp_close_stream_t *v)
{
    ngx_rtmp_live_close(s);

    return next_close_stream(s, v);
}


static ngx_int_t
ngx_rtmp_live_delete_stream(ngx_rtmp_session_t *s, ngx_rtmp_delete_stream_t *v)
{
    ngx_rtmp_live_close(s);

    return next_delete_stream(s, v);
}


static ngx_int_t
ngx_rtmp_live_pause(ngx_rtmp_session_t *s, ngx_rtmp_pause_t *v)
{
    ngx_rtmp_live_ctx_t            *ctx;

    ctx = ngx_rtmp_get_module_ctx(s, ngx_rtmp_live_module);

    if (ctx == NULL ||
        ctx->stream == NULL) {

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
    if (lacf == NULL ||
        ngx_rtmp_get_attr_conf(lacf, gop_cache) == 0) {
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

    gop_cache_mintime = ngx_rtmp_get_attr_conf(lacf, gop_cache_mintime);
    gop_cache_maxtime = ngx_rtmp_get_attr_conf(lacf, gop_cache_maxtime);

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
    if (lacf == NULL) {
        return;
    }

    if (!ngx_rtmp_get_attr_conf(lacf, gop_cache)) {
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

    if (!ngx_rtmp_get_attr_conf(lacf, gop_cache)) {
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

            ss->log_bpos = ss->log_buf;
            *ngx_sprintf(ss->log_bpos, BLANK_SPACE"rtmp_msg_type:%d"BLANK_SPACE"amf_msg_name:%s",
                         NGX_RTMP_MSG_AMF_META, "onMetaData") = 0;
            ngx_rtmp_log_evt_out(ss);

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
    ngx_rtmp_codec_ctx_t           *codec_ctx = NULL;
    ngx_chain_t                    *header, *coheader, *meta,
                                   *apkt, *aapkt, *acopkt, *rpkt = NULL;
    ngx_rtmp_core_srv_conf_t       *cscf;
    ngx_rtmp_live_app_conf_t       *lacf;
    ngx_rtmp_session_t             *ss;
    ngx_rtmp_header_t               ch, lh, clh;
    ngx_int_t                       rc, mandatory, dummy_audio;
    ngx_uint_t                      prio;
    ngx_uint_t                      peers;
    ngx_uint_t                      meta_version;
    ngx_uint_t                      csidx;
    uint32_t                        delta = 0;
    ngx_rtmp_live_chunk_stream_t   *cs;
#ifdef NGX_DEBUG
    const char                     *type_s;

    type_s = (h->type == NGX_RTMP_MSG_VIDEO ? "video" : "audio");
#endif

    lacf = ngx_rtmp_get_module_app_conf(s, ngx_rtmp_live_module);
    if (lacf == NULL) {
        return NGX_ERROR;
    }

    if (!ngx_rtmp_get_attr_conf(lacf, live)) {
        return NGX_OK;
    }

    if (in == NULL || in->buf == NULL) {
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
        ngx_add_timer(&ctx->idle_evt, ngx_rtmp_get_attr_conf(lacf, idle_timeout));
    }

    if (ctx->dryup_evt.timer_set) {
        ngx_add_timer(&ctx->dryup_evt, lacf->dryup_timeout);
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

    codec_ctx = ngx_rtmp_get_module_ctx(s, ngx_rtmp_codec_module);

    if (codec_ctx) {

        if (h->type == NGX_RTMP_MSG_AUDIO) {
            header = codec_ctx->aac_header;

            if (lacf->interleave) {
                coheader = codec_ctx->video_header;
            }

            if (codec_ctx->audio_codec_id == NGX_RTMP_AUDIO_AAC &&
                ngx_rtmp_is_codec_header(in)) // is or not audio header
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
                 codec_ctx->video_codec_id == NGX_RTMP_VIDEO_H265)  &&
                ngx_rtmp_is_codec_header(in)) // is or not video header
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
    rpkt = ngx_rtmp_append_shared_bufs(cscf, NULL, in);

    ngx_rtmp_prepare_message(s, &ch, &lh, rpkt);

    if (!ngx_rtmp_is_codec_header(in)) {
        ngx_rtmp_update_recv_delay(s, h, in, rpkt);
    }

    ngx_rtmp_live_gop_cache_frame(s, prio, &ch, in);

    for (pctx = ctx->stream->ctx; pctx; pctx = pctx->next) {
        if (pctx == ctx || pctx->paused) {
            continue;
        }

        ss = pctx->session;
        cs = &pctx->cs[csidx];

        if (!ngx_rtmp_type(ss->protocol)) {
            continue;
        }

        /* send metadata */

        if (meta && meta_version != pctx->meta_version) {
            ngx_log_debug0(NGX_LOG_DEBUG_RTMP, ss->connection->log, 0,
                           "live: meta");

            ss->log_bpos = ss->log_buf;
            *ngx_sprintf(ss->log_bpos, BLANK_SPACE"rtmp_msg_type:%d"BLANK_SPACE"amf_msg_name:%s",
                    NGX_RTMP_MSG_AMF_META, "onMetaData") = 0;
            ngx_rtmp_log_evt_out(ss);

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
                ngx_log_debug0(NGX_LOG_DEBUG_RTMP, ss->connection->log, 0, "live: skipping header");
                continue;
            }

            if (lacf->wait_video && h->type == NGX_RTMP_MSG_AUDIO &&
               !pctx->cs[0].active && !ngx_rtmp_get_attr_conf(lacf, gop_cache))
            {
                ngx_log_debug0(NGX_LOG_DEBUG_RTMP, ss->connection->log, 0,
                               "live: waiting for video");
                continue;
            }

            if (lacf->wait_key && prio != NGX_RTMP_VIDEO_KEY_FRAME &&
               (lacf->interleave || h->type == NGX_RTMP_MSG_VIDEO) &&
               !ngx_rtmp_get_attr_conf(lacf, gop_cache))
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

        ngx_log_debug3(NGX_LOG_DEBUG_RTMP, ss->connection->log, 0,
                       "live: rel %s prio %d packet delta=%uD",
                       type_s, prio, delta);

        /* write event log */
        switch(h->type) {
            case NGX_RTMP_MSG_AUDIO:
            {
                if (!ss->audio_recved) {

                    ss->audio_recved = 1;
                    ss->log_bpos = ss->log_buf;
                    *ngx_sprintf(ss->log_bpos, BLANK_SPACE"rtmp_msg_type:%ui", h->type) = 0;
                    ngx_rtmp_log_evt_out(ss);
                }
                break;
            }
            case NGX_RTMP_MSG_VIDEO:
            {
                if (!ss->video_recved) {

                    ss->video_recved = 1;
                    ss->log_bpos = ss->log_buf;
                    *ngx_sprintf(ss->log_bpos, BLANK_SPACE"rtmp_msg_type:%ui", h->type) = 0;
                    ngx_rtmp_log_evt_out(ss);
                }
                break;
            }
        }

        if (ngx_rtmp_send_message(ss, rpkt, prio) != NGX_OK) {
            ++pctx->ndropped;

            cs->dropped += delta;

            if (mandatory) {
                ngx_log_debug0(NGX_LOG_DEBUG_RTMP, ss->connection->log, 0,
                               "live: mandatory packet failed");
                ngx_rtmp_set_fincode(s, NGX_RTMP_LOG_FINALIZE_MANDATORY_PACKET_ERR_CODE);
                ngx_rtmp_finalize_session(ss);
            }

            continue;
        }

        cs->timestamp += delta;
        ++peers;
        ss->current_time = cs->timestamp;

        /*update the out bandwidth*/
        ngx_rtmp_update_bandwidth(&pctx->bw_out, h->mlen);
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

    if (h->type == NGX_RTMP_MSG_VIDEO) {
        ngx_rtmp_live_update_fps(&ctx->stream->video_frame_rate, 1);
    } else {
        ngx_rtmp_live_update_fps(&ctx->stream->video_frame_rate, 0);
    }

    if (s->relay_type == NGX_NONE_RELAY) {
        ngx_rtmp_update_bandwidth(&ctx->stream->bw_billing_in, h->mlen);
        ngx_rtmp_update_bandwidth(&ctx->stream->bw_in_bytes, h->mlen);
    }

    ngx_rtmp_update_av_bandwidth(&ctx->stream->bw_in_av,
                                 h->type == NGX_RTMP_MSG_AUDIO,
                                 h->mlen,
                                 h->timestamp);
    s->stream_stat = NGX_RTMP_STREAM_PUBLISHING;

    return NGX_OK;

}

static ngx_int_t
ngx_rtmp_live_message(ngx_rtmp_session_t *s, ngx_rtmp_header_t *h,
                      ngx_chain_t *in)
{
    ngx_rtmp_live_ctx_t            *ctx, *pctx;
    ngx_rtmp_live_app_conf_t       *lacf;
    ngx_rtmp_core_srv_conf_t       *cscf;
    ngx_rtmp_session_t             *ss;
    ngx_rtmp_codec_ctx_t           *codec_ctx;
#ifdef NGX_DEBUG
    const char                     *type_s;

    type_s = (h->type == NGX_RTMP_MSG_VIDEO ? "video" : "audio");
#endif

    lacf = ngx_rtmp_get_module_app_conf(s, ngx_rtmp_live_module);
    if (lacf == NULL) {
        return NGX_ERROR;
    }

    if (!ngx_rtmp_get_attr_conf(lacf, live)) {
        return NGX_OK;
    }

    ctx = ngx_rtmp_get_module_ctx(s, ngx_rtmp_live_module);
    if (ctx == NULL || ctx->stream == NULL) {
        return NGX_OK;
    }

    cscf = ngx_rtmp_get_module_srv_conf(s, ngx_rtmp_core_module);
    if (cscf == NULL) {
        return NGX_OK;
    }

    codec_ctx = ngx_rtmp_get_module_ctx(s, ngx_rtmp_codec_module);
    if(codec_ctx == NULL || codec_ctx->msg == NULL) {
        return NGX_ERROR;
    }

    if (ctx->publishing == 0) {
        ngx_log_debug1(NGX_LOG_DEBUG_RTMP, s->connection->log, 0,
                       "live: %s from non-publisher", type_s);
        return NGX_OK;
    }

    if (ctx->idle_evt.timer_set) {
        ngx_add_timer(&ctx->idle_evt, ngx_rtmp_get_attr_conf(lacf, idle_timeout));
    }

    /* broadcast to all subscribers */
    for (pctx = ctx->stream->ctx; pctx; pctx = pctx->next) {
        if (pctx == ctx || pctx->paused) {
            continue;
        }

        ss = pctx->session;

        if(ngx_rtmp_send_message(ss, codec_ctx->msg, 0) == NGX_OK) {
        };
    }

    return NGX_OK;
}

static ngx_int_t
ngx_rtmp_live_connect(ngx_rtmp_session_t *s, ngx_rtmp_connect_t *v)
{
    return next_connect(s, v);
}


static ngx_int_t
ngx_rtmp_live_publish(ngx_rtmp_session_t *s, ngx_rtmp_publish_t *v)
{
    ngx_rtmp_live_app_conf_t       *lacf;
    ngx_rtmp_live_ctx_t            *ctx;

    lacf = ngx_rtmp_get_module_app_conf(s, ngx_rtmp_live_module);
    if (lacf == NULL) {
        goto next;
    }

    if (ngx_hls_type(s->protocol)) {
        goto next;
    }

    if (!ngx_rtmp_get_attr_conf(lacf, live)) {
        goto next;
    }

    ngx_log_error(NGX_LOG_INFO, s->connection->log, 0,
                   "live_publish: name='%s' type='%s', page_url[len=%i]='%V', addr_text='%V', tc_url='%V'",
                   v->name, v->type, s->page_url.len, &s->page_url, s->addr_text, &s->tc_url);

    /* join stream as publisher */
    ngx_rtmp_live_join(s, v->name, 1);

    ctx = ngx_rtmp_get_module_ctx(s, ngx_rtmp_live_module);
    if (ctx == NULL || !ctx->publishing) {
        goto next;
    }

    ngx_rtmp_live_idle_timer(s, 1);
    ngx_rtmp_live_dryup_timer(s, 1);

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
    if (lacf == NULL) {
        goto next;
    }

    if (!ngx_rtmp_get_attr_conf(lacf, live)) {
        goto next;
    }

    if (ngx_hls_type(s->protocol)) {
        goto next;
    }

    /* join stream as subscriber */
    ngx_rtmp_live_join(s, v->name, 0);

    ctx = ngx_rtmp_get_module_ctx(s, ngx_rtmp_live_module);
    if (ctx == NULL) {
        goto next;
    }

    ngx_log_error(NGX_LOG_INFO, s->connection->log, 0,
                   "live_play: name='%s' start=%uD duration=%uD reset=%d page_url='%V' addr_text='%V' tc_url='%V' flashver='%V'",
                   v->name, (uint32_t) v->start,
                   (uint32_t) v->duration, (uint32_t) v->reset, 
                   &s->page_url, s->addr_text, &s->tc_url, &s->flashver);

    ctx->silent = v->silent;
    ctx->bw_out.bandwidth = 0;

    if (!ctx->silent && !lacf->play_restart) {

        if (!ctx->sended) {

            ctx->sended = 1;
            ngx_rtmp_send_status(s, "NetStream.Play.Start",
                                 "status", "Start live");
            ngx_rtmp_send_sample_access(s);
        }

		s->start = v->start;
		s->duration = v->duration;
		s->reset = v->reset;
		s->silent = v->silent;
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

    h = ngx_array_push(&cmcf->events[NGX_RTMP_ON_MESSAGE]);
    *h = ngx_rtmp_live_message;

    /* chain handlers */
    next_connect = ngx_rtmp_connect;
    ngx_rtmp_connect = ngx_rtmp_live_connect;

    next_publish = ngx_rtmp_publish;
    ngx_rtmp_publish = ngx_rtmp_live_publish;

    next_play = ngx_rtmp_play;
    ngx_rtmp_play = ngx_rtmp_live_play;

    next_delete_stream = ngx_rtmp_delete_stream;
    ngx_rtmp_delete_stream = ngx_rtmp_live_delete_stream;

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
