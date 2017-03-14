
/*
 * Copyright (C) Roman Arutyunyan
 */


#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_md5.h>
#include "ngx_rtmp_notify_module.h"

static ngx_rtmp_connect_pt                      next_connect;
static ngx_rtmp_disconnect_pt                   next_disconnect;
static ngx_rtmp_publish_pt                      next_publish;
static ngx_rtmp_play_pt                         next_play;
static ngx_rtmp_close_stream_pt                 next_close_stream;
static ngx_rtmp_record_done_pt                  next_record_done;


static char *ngx_rtmp_notify_on_srv_event(ngx_conf_t *cf, ngx_command_t *cmd,
       void *conf);
static char *ngx_rtmp_notify_on_app_event(ngx_conf_t *cf, ngx_command_t *cmd,
       void *conf);
static char *ngx_rtmp_notify_method(ngx_conf_t *cf, ngx_command_t *cmd,
       void *conf);
static ngx_int_t ngx_rtmp_notify_postconfiguration(ngx_conf_t *cf);
static void * ngx_rtmp_notify_create_app_conf(ngx_conf_t *cf);
static char * ngx_rtmp_notify_merge_app_conf(ngx_conf_t *cf,
       void *parent, void *child);
static void * ngx_rtmp_notify_create_srv_conf(ngx_conf_t *cf);
static char * ngx_rtmp_notify_merge_srv_conf(ngx_conf_t *cf, void *parent,
       void *child);
static ngx_int_t ngx_rtmp_notify_done(ngx_rtmp_session_t *s, char *cbname,
       ngx_uint_t url_idx);
static ngx_int_t ngx_rtmp_notify_get_codec(ngx_rtmp_session_t *s, 
       codec_st *codec_data);
static ngx_int_t ngx_rtmp_notify_connect_json_decode(ngx_rtmp_session_t *s, char *jsonstr);


ngx_str_t   ngx_rtmp_notify_urlencoded =
            ngx_string("application/x-www-form-urlencoded");


const char * ngx_rtmp_notify_app_names[NGX_RTMP_NOTIFY_APP_MAX] = 
{
    "play",
    "publish",
    "play_done",
    "publish_done",
    "done",
    "record_done",
    "update"
};


const char * ngx_rtmp_notify_srv_names[NGX_RTMP_NOTIFY_SRV_MAX] = 
{
    "connect",
    "disconnect"
};


static ngx_command_t  ngx_rtmp_notify_commands[] = {

    { ngx_string("on_connect"),
      NGX_RTMP_MAIN_CONF|NGX_RTMP_SRV_CONF|NGX_CONF_TAKE1,
      ngx_rtmp_notify_on_srv_event,
      NGX_RTMP_SRV_CONF_OFFSET,
      0,
      NULL },

    { ngx_string("on_disconnect"),
      NGX_RTMP_MAIN_CONF|NGX_RTMP_SRV_CONF|NGX_CONF_TAKE1,
      ngx_rtmp_notify_on_srv_event,
      NGX_RTMP_SRV_CONF_OFFSET,
      0,
      NULL },

    { ngx_string("on_publish"),
      NGX_RTMP_MAIN_CONF|NGX_RTMP_SRV_CONF|NGX_RTMP_APP_CONF|NGX_CONF_TAKE1,
      ngx_rtmp_notify_on_app_event,
      NGX_RTMP_APP_CONF_OFFSET,
      0,
      NULL },

    { ngx_string("on_play"),
      NGX_RTMP_MAIN_CONF|NGX_RTMP_SRV_CONF|NGX_RTMP_APP_CONF|NGX_CONF_TAKE1,
      ngx_rtmp_notify_on_app_event,
      NGX_RTMP_APP_CONF_OFFSET,
      0,
      NULL },

    { ngx_string("on_publish_done"),
      NGX_RTMP_MAIN_CONF|NGX_RTMP_SRV_CONF|NGX_RTMP_APP_CONF|NGX_CONF_TAKE1,
      ngx_rtmp_notify_on_app_event,
      NGX_RTMP_APP_CONF_OFFSET,
      0,
      NULL },

    { ngx_string("on_play_done"),
      NGX_RTMP_MAIN_CONF|NGX_RTMP_SRV_CONF|NGX_RTMP_APP_CONF|NGX_CONF_TAKE1,
      ngx_rtmp_notify_on_app_event,
      NGX_RTMP_APP_CONF_OFFSET,
      0,
      NULL },

    { ngx_string("on_done"),
      NGX_RTMP_MAIN_CONF|NGX_RTMP_SRV_CONF|NGX_RTMP_APP_CONF|NGX_CONF_TAKE1,
      ngx_rtmp_notify_on_app_event,
      NGX_RTMP_APP_CONF_OFFSET,
      0,
      NULL },

    { ngx_string("on_record_done"),
      NGX_RTMP_MAIN_CONF|NGX_RTMP_SRV_CONF|NGX_RTMP_APP_CONF|NGX_RTMP_REC_CONF|
                         NGX_CONF_TAKE1,
      ngx_rtmp_notify_on_app_event,
      NGX_RTMP_APP_CONF_OFFSET,
      0,
      NULL },

    { ngx_string("on_update"),
      NGX_RTMP_MAIN_CONF|NGX_RTMP_SRV_CONF|NGX_RTMP_APP_CONF|NGX_CONF_TAKE1,
      ngx_rtmp_notify_on_app_event,
      NGX_RTMP_APP_CONF_OFFSET,
      0,
      NULL },

    { ngx_string("notify_method"),
      NGX_RTMP_MAIN_CONF|NGX_RTMP_SRV_CONF|NGX_RTMP_APP_CONF|NGX_CONF_TAKE1,
      ngx_rtmp_notify_method,
      NGX_RTMP_APP_CONF_OFFSET,
      0,
      NULL },

    { ngx_string("notify_update_timeout"),
      NGX_RTMP_MAIN_CONF|NGX_RTMP_SRV_CONF|NGX_RTMP_APP_CONF|NGX_CONF_TAKE1,
      ngx_conf_set_msec_slot,
      NGX_RTMP_APP_CONF_OFFSET,
      offsetof(ngx_rtmp_notify_app_conf_t, update_timeout),
      NULL },

    { ngx_string("notify_relay_redirect"),
      NGX_RTMP_MAIN_CONF|NGX_RTMP_SRV_CONF|NGX_RTMP_APP_CONF|NGX_CONF_TAKE1,
      ngx_conf_set_flag_slot,
      NGX_RTMP_APP_CONF_OFFSET,
      offsetof(ngx_rtmp_notify_app_conf_t, relay_redirect),
      NULL },

	{ ngx_string("rtmp_socket_dir"),
      NGX_RTMP_MAIN_CONF|NGX_RTMP_SRV_CONF|NGX_RTMP_APP_CONF|NGX_CONF_TAKE1,
      ngx_conf_set_str_slot,
      NGX_RTMP_APP_CONF_OFFSET,
      offsetof(ngx_rtmp_notify_app_conf_t, socket_dir),
      NULL },

      ngx_null_command
};


static ngx_rtmp_module_t  ngx_rtmp_notify_module_ctx = {
    NULL,                                   /* preconfiguration */
    ngx_rtmp_notify_postconfiguration,      /* postconfiguration */
    NULL,                                   /* create main configuration */
    NULL,                                   /* init main configuration */
    ngx_rtmp_notify_create_srv_conf,        /* create server configuration */
    ngx_rtmp_notify_merge_srv_conf,         /* merge server configuration */
    ngx_rtmp_notify_create_app_conf,        /* create app configuration */
    ngx_rtmp_notify_merge_app_conf          /* merge app configuration */
};


ngx_module_t  ngx_rtmp_notify_module = {
    NGX_MODULE_V1,
    &ngx_rtmp_notify_module_ctx,            /* module context */
    ngx_rtmp_notify_commands,               /* module directives */
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
ngx_rtmp_notify_create_app_conf(ngx_conf_t *cf)
{
    ngx_rtmp_notify_app_conf_t     *nacf;
    ngx_uint_t                      n;

    nacf = ngx_pcalloc(cf->pool, sizeof(ngx_rtmp_notify_app_conf_t));
    if (nacf == NULL) {
        return NULL;
    }

    for (n = 0; n < NGX_RTMP_NOTIFY_APP_MAX; ++n) {
        nacf->url[n] = NGX_CONF_UNSET_PTR;
    }

    nacf->method = NGX_CONF_UNSET_UINT;
    nacf->update_timeout = NGX_CONF_UNSET_MSEC;
    nacf->relay_redirect = NGX_CONF_UNSET;

    return nacf;
}


static char *
ngx_rtmp_notify_merge_app_conf(ngx_conf_t *cf, void *parent, void *child)
{
    ngx_rtmp_notify_app_conf_t *prev = parent;
    ngx_rtmp_notify_app_conf_t *conf = child;
    ngx_uint_t                  n;

    for (n = 0; n < NGX_RTMP_NOTIFY_APP_MAX; ++n) {
        ngx_conf_merge_ptr_value(conf->url[n], prev->url[n], NULL);
        if (conf->url[n]) {
            conf->active = 1;
        }
    }

    if (conf->active) {
        prev->active = 1;
    }

    ngx_conf_merge_uint_value(conf->method, prev->method, NGX_RTMP_NETCALL_HTTP_GET);
    ngx_conf_merge_msec_value(conf->update_timeout, prev->update_timeout, 10000);
    ngx_conf_merge_value(conf->relay_redirect, prev->relay_redirect, 0);
    ngx_conf_merge_str_value(conf->socket_dir, prev->socket_dir, "/dev/shm");

    return NGX_CONF_OK;
}


static void *
ngx_rtmp_notify_create_srv_conf(ngx_conf_t *cf)
{
    ngx_rtmp_notify_srv_conf_t     *nscf;
    ngx_uint_t                      n;

    nscf = ngx_pcalloc(cf->pool, sizeof(ngx_rtmp_notify_srv_conf_t));
    if (nscf == NULL) {
        return NULL;
    }

    for (n = 0; n < NGX_RTMP_NOTIFY_SRV_MAX; ++n) {
        nscf->url[n] = NGX_CONF_UNSET_PTR;
    }

    nscf->method = NGX_CONF_UNSET_UINT;

    return nscf;
}


static char *
ngx_rtmp_notify_merge_srv_conf(ngx_conf_t *cf, void *parent, void *child)
{
    ngx_rtmp_notify_srv_conf_t *prev = parent;
    ngx_rtmp_notify_srv_conf_t *conf = child;
    ngx_uint_t                  n;

    for (n = 0; n < NGX_RTMP_NOTIFY_SRV_MAX; ++n) {
        ngx_conf_merge_ptr_value(conf->url[n], prev->url[n], NULL);
    }

    ngx_conf_merge_uint_value(conf->method, prev->method, NGX_RTMP_NETCALL_HTTP_GET);

    return NGX_CONF_OK;
}


static ngx_chain_t *
ngx_rtmp_notify_create_request(ngx_rtmp_session_t *s, ngx_pool_t *pool,
                                   ngx_uint_t url_idx, ngx_chain_t *args, ngx_str_t *extra)
{
    ngx_rtmp_notify_app_conf_t *nacf;
    ngx_chain_t                *al, *bl, *cl, *ret;
    ngx_url_t                  *url;
    ngx_int_t                   method;

    nacf = ngx_rtmp_get_module_app_conf(s, ngx_rtmp_notify_module);

    url = nacf->url[url_idx];

    method = nacf->method;

    al = ngx_rtmp_netcall_http_format_session(s, pool);

    if (al == NULL) {
        return NULL;
    }

    al->next = args;

    bl = NULL;

    if (nacf->method == NGX_RTMP_NETCALL_HTTP_POST) {
        cl = al;
        al = bl;
        bl = cl;
    }

    ret = ngx_rtmp_netcall_http_format_request(method, &url->host, url->family,
                                                &url->uri, extra, al, s->x_forwarded_for, bl, pool,
                                                &ngx_rtmp_notify_urlencoded);
    return ret;
}


static ngx_chain_t *
ngx_rtmp_notify_connect_create(ngx_rtmp_session_t *s, void *arg,
        ngx_pool_t *pool)
{
    ngx_rtmp_notify_srv_conf_t     *nscf;
    ngx_url_t                      *url;
    ngx_chain_t                    *al, *bl;
    ngx_buf_t                      *b;
    ngx_str_t                      *addr_text;

    nscf = ngx_rtmp_get_module_srv_conf(s, ngx_rtmp_notify_module);

    al = ngx_alloc_chain_link(pool);
    if (al == NULL) {
        return NULL;
    }
    
    /* these values are still missing in session
     * so we have to construct the request from
     * connection struct */

    addr_text = &s->connection->addr_text;

    b = ngx_create_temp_buf(pool,
            sizeof("call=connect") - 1 +
            sizeof("&srv=") + s->host_in.len +
            sizeof("&app=") - 1 + s->app.len * 3 +
            sizeof("&tcurl=") - 1 + s->tc_url.len * 3 +
            sizeof("&nginxid=") - 1 + NGX_INT_T_LEN +
            sizeof("&clusterid=") - 1 + NGX_INT_T_LEN +
            sizeof("&clientid=") - 1 + NGX_INT_T_LEN +
            sizeof("&srcslot=") - 1 + NGX_INT_T_LEN +
            sizeof("&addr=") - 1 + addr_text->len * 3
        );

    if (b == NULL) {
        return NULL;
    }

    al->buf = b;
    al->next = NULL;

    b->last = ngx_cpymem(b->last, (u_char*) "app=", sizeof("app=") - 1);
    b->last = (u_char*) ngx_escape_uri(b->last, s->app.data, s->app.len, NGX_ESCAPE_ARGS);

    b->last = ngx_cpymem(b->last, (u_char*) "&srv=", sizeof("&srv=") - 1);
    b->last = (u_char*) ngx_escape_uri(b->last, s->host_in.data, s->host_in.len, NGX_ESCAPE_ARGS);

    b->last = ngx_cpymem(b->last, (u_char*) "&tcurl=", sizeof("&tcurl=") - 1);
    b->last = (u_char*) ngx_escape_uri(b->last, s->tc_url.data, s->tc_url.len, NGX_ESCAPE_ARGS);

    b->last = ngx_cpymem(b->last, (u_char*) "&clientid=", sizeof("&clientid=") - 1);
    b->last = ngx_sprintf(b->last, "%ui", (ngx_uint_t) s->connection->number);

    b->last = ngx_cpymem(b->last, (u_char*) "&srcslot=", sizeof("&srcslot=") - 1);
    b->last = ngx_sprintf(b->last, "%ui", (ngx_uint_t) ngx_process_slot);

    b->last = ngx_cpymem(b->last, (u_char*) "&addr=", sizeof("&addr=") -1);
    b->last = (u_char*) ngx_escape_uri(b->last, addr_text->data, addr_text->len, NGX_ESCAPE_ARGS);

    b->last = ngx_cpymem(b->last, (u_char*) "&call=connect", sizeof("&call=connect") - 1);

    url = nscf->url[NGX_RTMP_NOTIFY_CONNECT];

    bl = NULL;

    if (nscf->method == NGX_RTMP_NETCALL_HTTP_POST) {
        bl = al;
        al = NULL;
    }
   
    return ngx_rtmp_netcall_http_format_request(NGX_RTMP_NETCALL_HTTP_GET/*nscf->method*/, &url->host, url->family,
                                                &url->uri, &s->args, al, s->x_forwarded_for, bl, pool,
                                                &ngx_rtmp_notify_urlencoded);
}


static ngx_chain_t *
ngx_rtmp_notify_disconnect_create(ngx_rtmp_session_t *s, void *arg,
        ngx_pool_t *pool)
{
    ngx_rtmp_notify_srv_conf_t     *nscf;
    ngx_url_t                      *url;
    ngx_chain_t                    *al, *bl, *pl;
    ngx_buf_t                      *b;

    nscf = ngx_rtmp_get_module_srv_conf(s, ngx_rtmp_notify_module);

    pl = ngx_alloc_chain_link(pool);
    if (pl == NULL) {
        return NULL;
    }

    b = ngx_create_temp_buf(pool,
                            sizeof("&call=disconnect") +
                            sizeof("&app=") + s->app.len * 3);
    if (b == NULL) {
        return NULL;
    }

    pl->buf = b;
    pl->next = NULL;

    b->last = ngx_cpymem(b->last, (u_char*) "&call=disconnect",
                         sizeof("&call=disconnect") - 1);

    b->last = ngx_cpymem(b->last, (u_char*) "&app=", sizeof("&app=") - 1);
    b->last = (u_char*) ngx_escape_uri(b->last, s->app.data, s->app.len,
                                       NGX_ESCAPE_ARGS);

    url = nscf->url[NGX_RTMP_NOTIFY_DISCONNECT];

    al = ngx_rtmp_netcall_http_format_session(s, pool);
    if (al == NULL) {
        return NULL;
    }

    al->next = pl;

    bl = NULL;

    if (nscf->method == NGX_RTMP_NETCALL_HTTP_POST) {
        bl = al;
        al = NULL;
    }

    return ngx_rtmp_netcall_http_format_request(NGX_RTMP_NETCALL_HTTP_GET/*nscf->method*/, &url->host, url->family,
                                                &url->uri, &s->args, al, s->x_forwarded_for , bl, pool,
                                                &ngx_rtmp_notify_urlencoded);
}


static ngx_chain_t *
ngx_rtmp_notify_publish_create(ngx_rtmp_session_t *s, void *arg,
        ngx_pool_t *pool)
{
    ngx_chain_t                    *pl;
    ngx_buf_t                      *b;
    
    pl = ngx_alloc_chain_link(pool);
    if (pl == NULL) {
        return NULL;
    }

    b = ngx_create_temp_buf(pool,
                            sizeof("&call=publish") +
                            sizeof("&srv=") + s->host_in.len +
                            sizeof("&name=") + s->name.len * 3);
    if (b == NULL) {
        return NULL;
    }

    pl->buf = b;
    pl->next = NULL;

    b->last = ngx_cpymem(b->last, (u_char*) "&call=publish", sizeof("&call=publish") - 1);

    b->last = ngx_cpymem(b->last, (u_char*) "&srv=", sizeof("&srv=") - 1);
    b->last = ngx_cpymem(b->last, s->host_in.data, s->host_in.len);
	
    b->last = ngx_cpymem(b->last, (u_char*) "&name=", sizeof("&name=") - 1);
    b->last = (u_char*) ngx_escape_uri(b->last, s->name.data, s->name.len, NGX_ESCAPE_ARGS);
    /* end */

    return ngx_rtmp_notify_create_request(s, pool, NGX_RTMP_NOTIFY_PUBLISH, pl, &s->args);
}


static ngx_chain_t *
ngx_rtmp_notify_play_create(ngx_rtmp_session_t *s, void *arg,
        ngx_pool_t *pool)
{
    ngx_rtmp_play_t                *v = arg;

    ngx_chain_t                    *pl;
    ngx_buf_t                      *b;

    pl = ngx_alloc_chain_link(pool);
    if (pl == NULL) {
        return NULL;
    }

    b = ngx_create_temp_buf(pool,
                            sizeof("&call=play") +
                            sizeof("&srv=") + s->host_in.len +
                            sizeof("&name=") + s->name.len * 3 +
                            sizeof("&start=&duration=&reset=") +
                            NGX_INT32_LEN * 3);
    if (b == NULL) {
        return NULL;
    }

    pl->buf = b;
    pl->next = NULL;

    b->last = ngx_cpymem(b->last, (u_char*) "&call=play", sizeof("&call=play") - 1);

    b->last = ngx_cpymem(b->last, (u_char*) "&srv=", sizeof("&srv=") - 1);
    b->last = ngx_cpymem(b->last, s->host_in.data, s->host_in.len);

    b->last = ngx_cpymem(b->last, (u_char*) "&name=", sizeof("&name=") - 1);
    b->last = (u_char*) ngx_escape_uri(b->last, s->name.data, s->name.len, NGX_ESCAPE_ARGS);

    b->last = ngx_snprintf(b->last, b->end - b->last, "&start=%uD&duration=%uD&reset=%d",
                           (uint32_t) v->start, (uint32_t) v->duration,
                           v->reset & 1);

    return ngx_rtmp_notify_create_request(s, pool, NGX_RTMP_NOTIFY_PLAY, pl, &s->args);
}


static ngx_chain_t *
ngx_rtmp_notify_done_create(ngx_rtmp_session_t *s, void *arg,
        ngx_pool_t *pool)
{
    ngx_rtmp_notify_done_t         *ds = arg;

    ngx_chain_t                    *pl;
    ngx_buf_t                      *b;
    size_t                          cbname_len = 0, name_len = 0;
    ngx_rtmp_notify_ctx_t          *ctx;

    ctx = ngx_rtmp_get_module_ctx(s, ngx_rtmp_notify_module);

    pl = ngx_alloc_chain_link(pool);
    if (pl == NULL) {
        return NULL;
    }

    cbname_len = ngx_strlen(ds->cbname);
    name_len = ctx ? ngx_strlen(ctx->name) : 0;

    b = ngx_create_temp_buf(pool,
                            sizeof("&call=") + cbname_len +
                            sizeof("&srv=") + s->host_in.len +
                            sizeof("&fin_time=") - 1 + NGX_INT64_LEN +
                            sizeof("&name=") + name_len * 3);
    if (b == NULL) {
        return NULL;
    }

    pl->buf = b;
    pl->next = NULL;

    b->last = ngx_cpymem(b->last, (u_char*) "&call=", sizeof("&call=") - 1);
    b->last = ngx_cpymem(b->last, ds->cbname, cbname_len);

    b->last = ngx_cpymem(b->last, (u_char*) "&srv=", sizeof("&srv=") - 1);
    b->last = ngx_cpymem(b->last, s->host_in.data, s->host_in.len);

    b->last = ngx_cpymem(b->last, (u_char*) "&fin_time=",
                         sizeof("&fin_time=") - 1);
    b->last = ngx_sprintf(b->last, "%T", s->fin_time);

    if (name_len) {
        b->last = ngx_cpymem(b->last, (u_char*) "&name=", sizeof("&name=") - 1);
        b->last = (u_char*) ngx_escape_uri(b->last, ctx->name, name_len,
                                           NGX_ESCAPE_ARGS);
    }

    return ngx_rtmp_notify_create_request(s, pool, ds->url_idx, pl, &s->args);
}


static ngx_int_t
ngx_rtmp_notify_get_codec(ngx_rtmp_session_t *s, codec_st *codec_data)
{
    ngx_rtmp_codec_ctx_t    *codec;
    
    codec = ngx_rtmp_get_module_ctx(s, ngx_rtmp_codec_module);
	if (codec) {
        codec_data->width       = codec->width;
        codec_data->height      = codec->height;
        codec_data->frame_rate  = codec->frame_rate;
        codec_data->v_codec     = ngx_rtmp_get_video_codec_name(codec->video_codec_id);
        codec_data->v_profile   = ngx_rtmp_stat_get_avc_profile(codec->avc_profile);
        codec_data->a_profile   = ngx_rtmp_stat_get_aac_profile(codec->aac_profile, codec->aac_sbr, codec->aac_ps);
        codec_data->compat      = codec->avc_compat;
        codec_data->level       = codec->avc_level / 10.;
        codec_data->a_codec     = ngx_rtmp_get_audio_codec_name(codec->audio_codec_id);
        codec_data->channels    = codec->aac_chan_conf ? codec->aac_chan_conf : codec->audio_channels;
        codec_data->sample_rate = codec->sample_rate;
    }

    return NGX_OK;
}

static ngx_chain_t *
ngx_rtmp_notify_update_create(ngx_rtmp_session_t *s, void *arg,
        ngx_pool_t *pool)
{
    ngx_chain_t                    *pl;
    ngx_buf_t                      *b;
    size_t                          name_len;
    ngx_rtmp_notify_ctx_t          *ctx;
    ngx_str_t                       sfx;
    codec_st                       *codec_data;
    ngx_uint_t                      v_codec_len = 0;
    ngx_uint_t                      a_codec_len = 0;
    ngx_uint_t                      v_profile_len = 0;
    ngx_uint_t                      a_profile_len = 0;
    ngx_rtmp_live_stream_t         *stream = NULL;
    ngx_rtmp_live_ctx_t            *ctx_live;

    ctx = ngx_rtmp_get_module_ctx(s, ngx_rtmp_notify_module);

    pl = ngx_alloc_chain_link(pool);
    if (pl == NULL) {
        return NULL;
    }

    ctx_live = ngx_rtmp_get_module_ctx(s, ngx_rtmp_live_module);
    if (ctx_live) {
        stream = ctx_live->stream;
    }

    if (ctx->flags & NGX_RTMP_NOTIFY_PUBLISHING) {
        ngx_str_set(&sfx, "_publish");
    } else if (ctx->flags & NGX_RTMP_NOTIFY_PLAYING) {
        ngx_str_set(&sfx, "_play");
    } else {
        ngx_str_null(&sfx);
    }

    ++ ctx->update_cnt;

    /*get codec related args*/
    codec_data = ngx_pcalloc(pool, sizeof(codec_st));
    if (codec_data == NULL) {
        return NULL;
    }
    ngx_memzero(codec_data, sizeof(codec_st));
    ngx_rtmp_notify_get_codec(s, codec_data);

    name_len = ctx ? ngx_strlen(ctx->name) : 0;

    v_codec_len = codec_data->v_codec ? ngx_strlen(codec_data->v_codec)*3 : 0;
    a_codec_len = codec_data->a_codec ? ngx_strlen(codec_data->a_codec)*3 : 0;
    v_profile_len = codec_data->v_profile ? ngx_strlen(codec_data->v_profile)*3 : 0;
    a_profile_len = codec_data->a_profile ? ngx_strlen(codec_data->a_profile)*3 : 0;

    b = ngx_create_temp_buf(pool,
                            sizeof("&call=update") + sfx.len +
                            sizeof("&time=") + NGX_TIME_T_LEN +
                            sizeof("&timestamp=") + NGX_INT32_LEN +
                            sizeof("&srv=") + s->host_in.len +
                            sizeof("&name=") + name_len * 3 +
                            sizeof("&width=") + NGX_UINT32_LEN +
                            sizeof("&height=") + NGX_UINT32_LEN +
                            sizeof("&frame_rate=") + NGX_UINT32_LEN +
                            sizeof("&v_codec=") + v_codec_len +
                            sizeof("&v_profile=") + v_profile_len +
                            sizeof("&compat=") + NGX_UINT32_LEN +
                            sizeof("&level=") + NGX_UINT32_LEN +
                            sizeof("&a_codec=") + a_codec_len +
                            sizeof("&a_profile=") + a_profile_len +
                            sizeof("&update_cnt=") + NGX_UINT32_LEN +
                            sizeof("&channels=") + NGX_UINT32_LEN +
                            sizeof("&sample_rate=") + NGX_UINT32_LEN +
                            sizeof("&bw_in_audio=") + NGX_UINT64_LEN +
                            sizeof("&bw_in_video=") + NGX_UINT64_LEN +
                            sizeof("&bw_real=") + NGX_UINT64_LEN +
                            sizeof("&bw_in=") + NGX_UINT64_LEN +
                            sizeof("&real_framerate=") + NGX_UINT32_LEN +
                            sizeof("&npull=") + NGX_UINT64_LEN +
                            sizeof("&pre_npull=") + NGX_UINT64_LEN);
    if (b == NULL) {
        return NULL;
    }

    pl->buf = b;
    pl->next = NULL;

    b->last = ngx_cpymem(b->last, (u_char*) "&call=update",
                         sizeof("&call=update") - 1);
    b->last = ngx_cpymem(b->last, sfx.data, sfx.len);

    b->last = ngx_cpymem(b->last, (u_char *) "&time=",
                         sizeof("&time=") - 1);
    b->last = ngx_sprintf(b->last, "%T", ngx_cached_time->sec - ctx->start);

    b->last = ngx_cpymem(b->last, (u_char *) "&timestamp=",
                         sizeof("&timestamp=") - 1);
    b->last = ngx_sprintf(b->last, "%D", s->current_time);

    b->last = ngx_cpymem(b->last, (u_char *) "&srv=",
	 					 sizeof("&srv=") - 1);
    b->last = ngx_cpymem(b->last, (char *)s->host_in.data, s->host_in.len);

    if (name_len) {
        b->last = ngx_cpymem(b->last, (u_char*) "&name=", sizeof("&name=") - 1);
        b->last = (u_char*) ngx_escape_uri(b->last, ctx->name, name_len,
                                           NGX_ESCAPE_ARGS);
    }

    b->last = ngx_cpymem(b->last, (u_char*) "&width=",
                         sizeof("&width=") - 1);
    b->last = ngx_sprintf(b->last, "%ui", codec_data->width);

    b->last = ngx_cpymem(b->last, (u_char*) "&height=",
                         sizeof("&height=") - 1);
    b->last = ngx_sprintf(b->last, "%ui", codec_data->height);

    b->last = ngx_cpymem(b->last, (u_char*) "&frame_rate=",
                         sizeof("&frame_rate=") - 1);
    b->last = ngx_sprintf(b->last, "%ui", codec_data->frame_rate);

    b->last = ngx_cpymem(b->last, (u_char*) "&v_codec=", sizeof("&v_codec=") - 1);
    if (codec_data->v_codec) {

        b->last = (u_char*) ngx_escape_uri(b->last, codec_data->v_codec, ngx_strlen(codec_data->v_codec),
                                           NGX_ESCAPE_ARGS);
    }

    b->last = ngx_cpymem(b->last, (u_char*) "&v_profile=", sizeof("&v_profile=") - 1);
	if (codec_data->v_profile) {
        b->last = (u_char*) ngx_escape_uri(b->last, (u_char *)codec_data->v_profile, ngx_strlen(codec_data->v_profile),
                                       NGX_ESCAPE_ARGS);
    }

    b->last = ngx_cpymem(b->last, (u_char*) "&update_cnt=",
                         sizeof("&update_cnt=") - 1);
    b->last = ngx_sprintf(b->last, "%ui", ctx->update_cnt);

    b->last = ngx_cpymem(b->last, (u_char*) "&compat=",
                         sizeof("&compat=") - 1);
    b->last = ngx_sprintf(b->last, "%ui", codec_data->compat);

    b->last = ngx_cpymem(b->last, (u_char*) "&level=",
                         sizeof("&level=") - 1);
    b->last = ngx_sprintf(b->last, "%ui", codec_data->level);    

    b->last = ngx_cpymem(b->last, (u_char*) "&a_codec=", sizeof("&a_codec=") - 1);
    if (codec_data->a_codec) {
        b->last = (u_char*) ngx_escape_uri(b->last, codec_data->a_codec, ngx_strlen(codec_data->a_codec),
                                       NGX_ESCAPE_ARGS);
    }

    b->last = ngx_cpymem(b->last, (u_char*) "&a_profile=", sizeof("&a_profile=") - 1);
    if (codec_data->a_profile){
        b->last = (u_char*) ngx_escape_uri(b->last, (u_char *)codec_data->a_profile, ngx_strlen(codec_data->a_profile),
                                       NGX_ESCAPE_ARGS);
    }

    b->last = ngx_cpymem(b->last, (u_char*) "&channels=",
                         sizeof("&channels=") - 1);
    b->last = ngx_sprintf(b->last, "%ui", codec_data->channels);  

    b->last = ngx_cpymem(b->last, (u_char*) "&sample_rate=",
                         sizeof("&sample_rate=") - 1);
    b->last = ngx_sprintf(b->last, "%ui", codec_data->sample_rate);

    if (ctx_live && stream) {
        /*in audio bw*/
        b->last = ngx_cpymem(b->last, (u_char*) "&bw_in_audio=",
                             sizeof("&bw_in_audio=") - 1);
        b->last = ngx_sprintf(b->last, "%uL", stream->bw_in_av.a_intl_bw);

        /*in video bw*/
        b->last = ngx_cpymem(b->last, (u_char*) "&bw_in_video=",
                             sizeof("&bw_in_video=") - 1);
        b->last = ngx_sprintf(b->last, "%uL", stream->bw_in_av.v_intl_bw);

        /*in real video bw*/
        b->last = ngx_cpymem(b->last, (u_char*) "&bw_real=",
                             sizeof("&bw_real=") - 1);
        b->last = ngx_sprintf(b->last, "%uL", stream->bw_in_av.a_intl_bw_exp + stream->bw_in_av.v_intl_bw_exp);

        /*bw*/
        b->last = ngx_cpymem(b->last, (u_char*) "&bw_in=",
                             sizeof("&bw_in=") - 1);
        b->last = ngx_sprintf(b->last, "%uL", stream->bw_in_av.a_intl_bw + stream->bw_in_av.v_intl_bw);

        /*real frame rate*/
        b->last = ngx_cpymem(b->last, (u_char*) "&real_framerate=",
                             sizeof("&real_framerate=") - 1);
        b->last = ngx_sprintf(b->last, "%ui", stream->video_frame_rate.fps / 1000);

        /*npull*/
        b->last = ngx_cpymem(b->last, (u_char*) "&npull=",
                             sizeof("&npull=") - 1);
        b->last = ngx_sprintf(b->last, "%uL", stream->npull);

        /*pre_npull*/
        b->last = ngx_cpymem(b->last, (u_char*) "&pre_npull=",
                             sizeof("&pre_npull=") - 1);
        b->last = ngx_sprintf(b->last, "%uL", ctx->pre_npull);

        ctx->pre_npull = stream->npull;
    }
    
    return ngx_rtmp_notify_create_request(s, pool, NGX_RTMP_NOTIFY_UPDATE, pl, 
                                          &s->args);
}


static ngx_chain_t *
ngx_rtmp_notify_record_done_create(ngx_rtmp_session_t *s, void *arg,
                                   ngx_pool_t *pool)
{
    ngx_rtmp_record_done_t         *v = arg;

    ngx_rtmp_notify_ctx_t          *ctx;
    ngx_chain_t                    *pl;
    ngx_buf_t                      *b;
    size_t                          name_len;

    ctx = ngx_rtmp_get_module_ctx(s, ngx_rtmp_notify_module);

    pl = ngx_alloc_chain_link(pool);
    if (pl == NULL) {
        return NULL;
    }

    name_len  = ngx_strlen(ctx->name);

    b = ngx_create_temp_buf(pool,
                            sizeof("&call=record_done") +
                            sizeof("&recorder=") + v->recorder.len +
                            sizeof("&name=") + name_len * 3 +
                            sizeof("&path=") + v->path.len * 3);
    if (b == NULL) {
        return NULL;
    }

    pl->buf = b;
    pl->next = NULL;

    b->last = ngx_cpymem(b->last, (u_char*) "&call=record_done",
                         sizeof("&call=record_done") - 1);

    b->last = ngx_cpymem(b->last, (u_char *) "&recorder=",
                         sizeof("&recorder=") - 1);
    b->last = (u_char*) ngx_escape_uri(b->last, v->recorder.data,
                                       v->recorder.len, NGX_ESCAPE_ARGS);

    b->last = ngx_cpymem(b->last, (u_char*) "&name=", sizeof("&name=") - 1);
    b->last = (u_char*) ngx_escape_uri(b->last, ctx->name, name_len,
                                       NGX_ESCAPE_ARGS);

    b->last = ngx_cpymem(b->last, (u_char*) "&path=", sizeof("&path=") - 1);
    b->last = (u_char*) ngx_escape_uri(b->last, v->path.data, v->path.len,
                                       NGX_ESCAPE_ARGS);

    return ngx_rtmp_notify_create_request(s, pool, NGX_RTMP_NOTIFY_RECORD_DONE, pl, &s->args);
}


/**
 * retcode description:
 * NGX_OK for 2xx
 * NGX_AGAIN for 3xx
 * NGX_ERROR for 4xx
 * NGX_ABORT for 5xx
 * NGX_CUSTOM for empty or broken HTTP response
 **/
ngx_int_t
ngx_rtmp_notify_parse_http_retcode(ngx_rtmp_session_t *s,
        ngx_chain_t *in, u_char *retcode)
{
    ngx_buf_t      *b;
    ngx_int_t       n;
    u_char          c;
    ngx_int_t       i;

    /* find 10th character */
    n = 9;
    while (in) {
        b = in->buf;
        if (b->last - b->pos > n) {
            c = b->pos[n];
            if (c >= (u_char)'0' && c <= (u_char)'9') {

                if (b->last - b->pos - n >= 3) {

                    for (i = 0; i < 3; ++ i) {

                        *(retcode + i) = *(b->pos + n + i);
                    }
                }

                switch (c) {
                    case (u_char) '2':
                        return NGX_OK;
                    case (u_char) '3':
                        return NGX_AGAIN;
                    case (u_char) '5':
                        return NGX_ABORT;
                    default:
                        return NGX_ERROR;
                }
            }

            ngx_log_error(NGX_LOG_WARN, s->connection->log, 0,
                    "notify: invalid HTTP retcode: %d..", (int)c);

            return NGX_ABORT;
        }
        n -= (b->last - b->pos);
        in = in->next;
    }

    ngx_log_error(NGX_LOG_WARN, s->connection->log, 0,
            "notify: empty or broken HTTP response");
    /*
     * not enough data;
     * it can happen in case of empty or broken reply
     */

    return NGX_CUSTOME;
}


static ngx_int_t
ngx_rtmp_notify_parse_http_header(ngx_rtmp_session_t *s,
        ngx_chain_t *in, ngx_str_t *name, u_char *data, size_t len)
{
    ngx_buf_t      *b;
    ngx_int_t       matched;
    u_char         *p, c;
    ngx_uint_t      n;

    enum {
        parse_name,
        parse_space,
        parse_value,
        parse_value_newline
    } state = parse_name;

    n = 0;
    matched = 0;

    while (in) {
        b = in->buf;

        for (p = b->pos; p != b->last; ++p) {
            c = *p;

            if (c == '\r') {
                continue;
            }

            switch (state) {
                case parse_value_newline:
                    if (c == ' ' || c == '\t') {
                        state = parse_space;
                        break;
                    }

                    if (matched) {
                        return n;
                    }

                    if (c == '\n') {
                        return NGX_OK;
                    }

                    n = 0;
                    state = parse_name;

                case parse_name:
                    switch (c) {
                        case ':':
                            matched = (n == name->len);
                            n = 0;
                            state = parse_space;
                            break;
                        case '\n':
                            n = 0;
                            break;
                        default:
                            if (n < name->len &&
                                ngx_tolower(c) == ngx_tolower(name->data[n]))
                            {
                                ++n;
                                break;
                            }
                            n = name->len + 1;
                    }
                    break;

                case parse_space:
                    if (c == ' ' || c == '\t') {
                        break;
                    }
                    state = parse_value;

                case parse_value:
                    if (c == '\n') {
                        state = parse_value_newline;
                        break;
                    }

                    if (matched && n + 1 < len) {
                        data[n++] = c;
                    }

                    break;
            }
        }

        in = in->next;
    }

    return NGX_OK;
}
/*
static ngx_int_t
ngx_rtmp_notify_parse_http_body(ngx_rtmp_session_t *s,
        ngx_chain_t *in, ngx_str_t *body)
{
    ngx_buf_t      *b;
    ngx_int_t       matched;
    u_char         *p, c, pre;
    ngx_uint_t      n;
    


    n = 0;
    matched = 0;
    
    pre = '\0';

    while (in) {
        b = in->buf;

        for (p = b->pos; p != b->last; ++p) {
            if (4 == matched )
                break;
            c = *p;

            if ( c == '\r' || c == '\n' ) {
                if (pre != c){
                    matched ++;
                    pre = c; 
                    continue;
                }
            }
            matched = 0;
        }
        if (4 == matched )
            break;
        in = in->next;
    }

    if (4 == matched )
    {
        // FIXME: not confider mutliple in buffers 
        //p = (u_char *)ngx_strchr(p, '\n');
        body->data = p;
        body->len = in->buf->last - p;
    }
    

    return NGX_OK;
}
*/

static void
ngx_rtmp_notify_clear_flag(ngx_rtmp_session_t *s, ngx_uint_t flag)
{
    ngx_rtmp_notify_ctx_t  *ctx;

    ctx = ngx_rtmp_get_module_ctx(s, ngx_rtmp_notify_module);

    ctx->flags &= ~flag;
}


static ngx_int_t
ngx_rtmp_notify_connect_handle(ngx_rtmp_session_t *s,
        void *arg, ngx_chain_t *in)
{
    ngx_rtmp_connect_t *v = arg;

    ngx_str_t               http_ret;
    u_char                  str_result[NGX_RTMP_MAX_RESULT];
    u_char                  str_desc[NGX_RTMP_MAX_NAME];
    u_char                  ret_code[NGX_RTMP_MAX_NAME];
    u_char                  str_code[NGX_RTMP_MAX_NAME];
    ngx_rtmp_netcall_ctx_t *ctx = NULL;

    static ngx_str_t        desc = ngx_string("description");
    static ngx_str_t        result = ngx_string("result");
    static ngx_str_t        code = ngx_string("code");

    if (!in) {
        ngx_log_error(NGX_LOG_WARN, s->connection->log, 0,
                      "notify: connect received none!");
        goto disconnect;
    }

    http_ret.data = in->buf->start;
    http_ret.len = in->buf->last - in->buf->start;

    ngx_log_error(NGX_LOG_INFO, s->connection->log, 0,
                  "notify: connect received: %V", &http_ret);

    ctx = ngx_rtmp_get_module_ctx(s, ngx_rtmp_netcall_module);
    if (ctx == NULL) {
        goto disconnect;
    }

    // pick up code & result from http response.
    ngx_memzero(&str_code, sizeof(str_code));
    ngx_memzero(&str_desc, sizeof(str_desc));

    if (ngx_rtmp_notify_parse_http_header(s, in, &code,
            str_code, sizeof(str_code) - 1) > 0) {
        *ngx_snprintf(ctx->ret_code, sizeof(ctx->ret_code) - 1, "%s", str_code) = 0;
    }

    if (ngx_rtmp_notify_parse_http_header(s, in, &desc,
            str_desc, sizeof(str_desc) - 1) > 0) {
        *ngx_snprintf(ctx->description, sizeof(ctx->description) - 1, "%s", str_desc) = 0;
    }

    // if response code ~= 200 then go to disconnect case.
    ngx_memzero(&ret_code, sizeof(ret_code));
    if (ngx_rtmp_notify_parse_http_retcode(s, in, ret_code) != NGX_OK) {
        goto disconnect;
    }

    // parse conf from json string.
    ngx_memzero(&str_result, sizeof(str_result));
    if (ngx_rtmp_notify_parse_http_header(s, in, &result,
            str_result, sizeof(str_result) - 1) <= 0) {
        goto disconnect;
    }

    if (ngx_rtmp_notify_connect_json_decode(s, (char *)str_result) != NGX_OK) {
        ngx_log_error(NGX_LOG_ERR, s->connection->log, 0,
                      "notify: connect json decode failed");
        goto disconnect;
    }

    return next_connect(s, v);

disconnect:

    ngx_rtmp_set_fincode(s, NGX_RTMP_LOG_FINALIZE_DS_CLOSE_PUBLISHER);

    if (ctx) {
        ngx_rtmp_send_status(s, (char *)ctx->ret_code, "finish", (char *)ctx->description);
    }

    return NGX_ERROR;
}


static void
ngx_rtmp_notify_set_name(u_char *dst, size_t dst_len, u_char *src,
    size_t src_len)
{
    u_char     result[16], *p;
    ngx_md5_t  md5;

    ngx_md5_init(&md5);
    ngx_md5_update(&md5, src, src_len);
    ngx_md5_final(result, &md5);

    p = ngx_hex_dump(dst, result, ngx_min((dst_len - 1) / 2, 16));
    *p = '\0';
}


static ngx_int_t
ngx_rtmp_notify_publish_handle(ngx_rtmp_session_t *s,
        void *arg, ngx_chain_t *in)
{
    ngx_rtmp_publish_t         *v = arg;
    ngx_int_t                   rc;
    ngx_str_t                   local_name;
    ngx_rtmp_relay_target_t     target;
    ngx_url_t                  *u;
    ngx_rtmp_notify_app_conf_t *nacf;
    ngx_rtmp_core_srv_conf_t   *cscf;
    ngx_rtmp_netcall_ctx_t     *ctx = NULL;
    ngx_str_t                   http_ret;

    u_char                      name[NGX_RTMP_MAX_NAME];
    u_char                      str_desc[NGX_RTMP_MAX_NAME];
    u_char                      str_code[NGX_RTMP_MAX_NAME];
    u_char                      ret_code[NGX_RTMP_MAX_NAME];

    static ngx_str_t            location = ngx_string("location");
    static ngx_str_t            desc = ngx_string("description");
    static ngx_str_t            code = ngx_string("code");

    if (!in) {
        ngx_log_error(NGX_LOG_WARN, s->connection->log, 0,
                      "notify: publish received none!");
        goto disconnect;
    }

    http_ret.data = in->buf->start;
    http_ret.len = in->buf->last - in->buf->start;

    ngx_log_error(NGX_LOG_INFO, s->connection->log, 0,
                  "notify: publish received: %V", &http_ret);

    cscf = ngx_rtmp_get_module_srv_conf(s, ngx_rtmp_core_module);

    ctx = ngx_rtmp_get_module_ctx(s, ngx_rtmp_netcall_module);
    if (ctx == NULL) {
        goto disconnect;
    }

    // pick up code & result from http response.
    ngx_memzero(&str_code, sizeof(str_code));
    ngx_memzero(&str_desc, sizeof(str_desc));

    if (ngx_rtmp_notify_parse_http_header(s, in, &code,
            str_code, sizeof(str_code) - 1) > 0) {
        *ngx_snprintf(ctx->ret_code, sizeof(ctx->ret_code) - 1, "%s", str_code) = 0;
    }

    if (ngx_rtmp_notify_parse_http_header(s, in, &desc,
            str_desc, sizeof(str_desc) - 1) > 0) {
        *ngx_snprintf(ctx->description, sizeof(ctx->description) - 1, "%s", str_desc) = 0;
    }

    // if response code ~= 200 then go to disconnect case.
    ngx_memzero(&ret_code, sizeof(ret_code));
    if (ngx_rtmp_notify_parse_http_retcode(s, in, ret_code) != NGX_OK) {
        goto disconnect;
    }

    /* rtmp return code */
    if (s->relay_type == NGX_NONE_RELAY) {

        if (cscf->rtmp_status_code) {

            ngx_memzero(&str_desc, sizeof(str_desc));
            ngx_rtmp_notify_parse_http_header(s, in, &desc,
                                              str_desc, sizeof(str_desc) - 1);
            ngx_rtmp_notify_parse_http_header(s, in, &code,
                                              str_code, sizeof(str_code) - 1);
            ngx_rtmp_send_status(s, (char *)str_code,
                                 "status", (char *)str_desc);
        }
    }

    /* HTTP 3xx */
    ngx_memzero(&name, sizeof(name));
    rc = ngx_rtmp_notify_parse_http_header(s, in, &location, name,
                                           sizeof(name) - 1);
    if (rc <= 0) {
        goto next;
    }

    if (ngx_strncasecmp(name, (u_char *) "rtmp://", 7)) {
        *ngx_cpymem(v->name, name, ngx_strlen(name)) = 0;
        ngx_log_error(NGX_LOG_INFO, s->connection->log, 0,
                      "notify: publish redirect to '%s'", v->name);
        goto next;
    }

    /* push */

    nacf = ngx_rtmp_get_module_app_conf(s, ngx_rtmp_notify_module);
    if (nacf->relay_redirect) {
        ngx_rtmp_notify_set_name(v->name, NGX_RTMP_MAX_NAME, name, (size_t) rc);
    }

    ngx_log_error(NGX_LOG_INFO, s->connection->log, 0,
                  "notify: push '%s' to '%*s'", v->name, rc, name);

    local_name.data = v->name;
    local_name.len = ngx_strlen(v->name);

    ngx_memzero(&target, sizeof(target));

    target.name = s->name;
    target.app = s->app;
    target.args = s->args;
    target.conf = &s->conf;

    u = &target.url;
    u->url = local_name;
    u->url.data = name + 7;
    u->url.len = rc - 7;
    u->default_port = 1935;
    u->uri_part = 1;
    u->no_resolve = 0; /* want ip here */

    if (ngx_parse_url(s->connection->pool, u) != NGX_OK) {
        ngx_log_error(NGX_LOG_ERR, s->connection->log, 0,
                      "notify: push failed '%V'", &local_name);
        goto disconnect;
    }

    ngx_rtmp_relay_push(s, &local_name, &target);

next:
    return next_publish(s, v);

disconnect:

    ngx_rtmp_notify_clear_flag(s, NGX_RTMP_NOTIFY_PUBLISHING);

    ngx_rtmp_set_fincode(s, NGX_RTMP_LOG_FINALIZE_DS_CLOSE_PUBLISHER);

    if (ctx) {
        ngx_rtmp_send_status(s, (char *)ctx->ret_code, "finish", (char *)ctx->description);
    }
    return NGX_ERROR;
}


static ngx_int_t
ngx_rtmp_notify_json_decode(ngx_rtmp_session_t *s, const char *jsonstr, ngx_addr_t *local,
        ngx_url_t *url, const ngx_str_t *name)
{
	struct json_object          *obj;
	struct json_object          *root_obj;
	struct sockaddr_in          *local_addr_in;
    ngx_str_t                    str_remote_ip;
	ngx_int_t                    ret = NGX_OK;

	root_obj = json_tokener_parse(jsonstr);

	int32_t remote_rtmp_port;
	if (json_object_object_get_ex(root_obj, "remote_rtmp_port", &obj)) {
		remote_rtmp_port = json_object_get_int(obj);
		obj = NULL;
	} else {
		ret = NGX_ERROR;
		goto finally;
	}

	int32_t remote_http_port;
	if (json_object_object_get_ex(root_obj, "remote_http_port", &obj)) {
		remote_http_port = json_object_get_int(obj);
		obj = NULL;
	} else {
		ret = NGX_ERROR;
		goto finally;
	}

	const char *local_ip = NULL;
	if (json_object_object_get_ex(root_obj, "local_ip", &obj)) {
		local_ip = json_object_get_string(obj);
		obj = NULL;
	} else {
		ret = NGX_ERROR;
		goto finally;
	}

	const char *remote_ip = NULL;
	if (json_object_object_get_ex(root_obj, "remote_ip", &obj)) {
		remote_ip = json_object_get_string(obj);
		obj = NULL;
	} else {
		ret = NGX_ERROR;
		goto finally;
	}

	ngx_log_error(NGX_LOG_INFO, s->connection->log, 0,
            "slot=%i, json_decode: name='%V' app='%V' local_ip='%s' remote_ip='%s'",
            ngx_process_slot, name, &s->app, local_ip, remote_ip);

	// set local
	ngx_memzero(local->sockaddr, sizeof(*local->sockaddr));
	local_addr_in = (struct sockaddr_in *)local->sockaddr;
	local_addr_in->sin_family      = AF_INET;
	local_addr_in->sin_addr.s_addr = inet_addr(local_ip);

    if (ngx_hls_pull_type(s->protocol)) {

        ngx_set_str(&str_remote_ip, remote_ip);

        ngx_rtmp_http_hls_build_url(s, &str_remote_ip, (ngx_int_t) remote_http_port);
    } else {

        url->url.len = ngx_snprintf(url->url.data, url->url.len, "rtmp://%s:%d/%V/%V",
    		    remote_ip, remote_rtmp_port, &s->app, name) - url->url.data;
    }

finally:
	json_object_put(root_obj);
	return ret;
}


static ngx_int_t
ngx_rtmp_notify_play_handle(ngx_rtmp_session_t *s,
        void *arg, ngx_chain_t *in)
{
    ngx_rtmp_notify_app_conf_t *nacf;
    ngx_rtmp_play_t            *v = arg;
    ngx_int_t                   rc;
    ngx_str_t                   tmp_name;
    ngx_rtmp_relay_target_t     target;
    ngx_url_t                  *url;
    struct sockaddr             sockaddr;
    ngx_addr_t                  local_addr;
    u_char                      relay_url[NGX_RTMP_MAX_NAME];
    ngx_int_t                   relay_url_len = NGX_RTMP_MAX_NAME;
    u_char                      str_result[NGX_RTMP_MAX_NAME];
    u_char                      str_action[NGX_RTMP_MAX_NAME];
    u_char                      str_tcurl[NGX_RTMP_MAX_NAME];
    ngx_str_t                   http_ret;
    u_char                      ret_code[NGX_RTMP_MAX_NAME];
    u_char                      str_code[NGX_RTMP_MAX_NAME];

    ngx_rtmp_netcall_ctx_t     *ctx;

    static ngx_str_t            action = ngx_string("action");
    static ngx_str_t            result = ngx_string("result");
    static ngx_str_t            tcurl = ngx_string("tcurl");
    static ngx_str_t            code = ngx_string("code");

    ctx = ngx_rtmp_get_module_ctx(s, ngx_rtmp_netcall_module);

    if (!in) {
        ngx_log_error(NGX_LOG_WARN, s->connection->log, 0,
                      "notify: play received none!");
        goto disconnect;
    }

    http_ret.data = in->buf->start;
    http_ret.len = in->buf->last - in->buf->start;
    ngx_log_error(NGX_LOG_INFO, s->connection->log, 0,
                  "notify: play received: %V", &http_ret);

    nacf = ngx_rtmp_get_module_app_conf(s, ngx_rtmp_notify_module);

    ngx_memzero(ret_code, NGX_RTMP_MAX_NAME);
    ngx_memzero(relay_url, NGX_RTMP_MAX_NAME);
    rc = ngx_rtmp_notify_parse_http_retcode(s, in, ret_code);

    /* write the status code and */
    ngx_memzero(str_code, NGX_RTMP_MAX_NAME);
    ngx_rtmp_notify_parse_http_header(s, in, &code,
                                      str_code, sizeof(str_code) - 1);

    if (ctx) {
        *ngx_snprintf(ctx->ret_code, sizeof(ctx->ret_code) - 1, "%s", ret_code) = 0; 
        *ngx_snprintf(ctx->description, sizeof(ctx->description) - 1, "%s", str_code) = 0;
    }

    switch (rc) {
    case NGX_OK:    // 2xx goto next opt.
        goto next;
    case NGX_AGAIN: // 3xx ready to relay.
        break;
    default:        // 4xx or empty response, just disconnect it.
        goto disconnect;
    }

    ngx_memzero(&str_action, sizeof(str_action));
    rc = ngx_rtmp_notify_parse_http_header(s, in, &action, str_action,
                                           sizeof(str_action) - 1);
    if (rc <= 0) {
        goto disconnect;
    }

    ngx_memzero(&str_result, sizeof(str_result));
    rc = ngx_rtmp_notify_parse_http_header(s, in, &result, str_result,
                                           sizeof(str_result) - 1);
    if (rc <= 0) {
        goto disconnect;
    }

    ngx_memzero(&str_tcurl, sizeof(str_tcurl));
    rc = ngx_rtmp_notify_parse_http_header(s, in, &tcurl, str_tcurl,
                                           sizeof(str_tcurl) - 1);
    if (rc <= 0) {
        goto disconnect;
    }

    ngx_memzero(&target, sizeof(target));
    if (ngx_strcasecmp(str_action, (u_char *) "local") == 0) {    // Local relay
        target.relay_type = NGX_LOCAL_RELAY;
    } else if (ngx_strcasecmp(str_action, (u_char *) "remote") == 0) {    // Remote relay
        target.relay_type = NGX_REMOTE_RELAY;
    } else if (ngx_strcasecmp(str_action, (u_char *) "cluster") == 0) {
        target.relay_type = NGX_CLUSTER_RELAY;
    } else {
        goto disconnect;
    }

    target.tc_url.len  = ngx_strlen(str_tcurl);
    target.tc_url.data = str_tcurl;

    target.name = s->name;
    target.app = s->app;
    target.args = s->args;
    target.conf = &s->conf;
    tmp_name    = s->name;

    ngx_rtmp_cmd_fill_vhost(&target.tc_url, &target.host_in, &target.port_in);

    if (target.relay_type == NGX_LOCAL_RELAY) {

        ngx_int_t n = ngx_atoi(str_result, ngx_strlen(str_result));
        if (n < 0 || n >= NGX_MAX_PROCESSES || n == ngx_process_slot) {
            goto disconnect;
        }
        ngx_str_set(&target.page_url, "nginx-local-pull");
        target.tag  = &ngx_rtmp_notify_module;
        target.data = &ngx_processes[n];
        ngx_memzero(&target.url, sizeof(target.url));
        url = &target.url;

#define NGX_RTMP_NOTIFY_SOCKNAME "nginx-rtmp"
        ngx_file_info_t fi;
        u_char path[sizeof("unix:") + NGX_MAX_PATH];
        u_char *p = ngx_snprintf(path, sizeof(path) - 1,
                                 "unix:%V/" NGX_RTMP_NOTIFY_SOCKNAME ".%i",
                                 &nacf->socket_dir, n);
#undef NGX_RTMP_NOTIFY_SOCKNAME

        *p = 0;
        if (ngx_file_info(path + sizeof("unix:") - 1, &fi) != NGX_OK) {
            goto next;
        }
        url->url.data = path; // "unix:/tmp/nginx-rtmp.4"
        url->url.len = p - path;

    } else if (target.relay_type == NGX_REMOTE_RELAY) {

        ngx_str_set(&target.page_url, "nginx-remote-pull");
        ngx_memzero(&target.url, sizeof(target.url));
        url = &target.url;
        url->url.data = relay_url;
        url->url.len = relay_url_len;
        url->default_port = 1935;
        url->uri_part = 1;
        url->no_resolve = 1; /* want ip here */

        ngx_memzero(&sockaddr, sizeof(sockaddr));
        local_addr.sockaddr     = &sockaddr;
        local_addr.socklen      = sizeof(sockaddr);
        ngx_str_set(&local_addr.name, "nginx-remote-pull");
        target.local            = &local_addr;

        if (ngx_rtmp_notify_json_decode(s, (const char *)str_result, target.local,
                                        url, &tmp_name) != NGX_OK) {
            goto next;
        }

        url->url.data += 7;
        url->url.len  -= 7;
    } else if (target.relay_type == NGX_CLUSTER_RELAY) {

        ngx_str_set(&target.page_url, "nginx-cluster-pull");
        ngx_memzero(&target.url, sizeof(target.url));
        url = &target.url;
        url->url.data = relay_url;
        url->url.len = relay_url_len;
        url->default_port = 1935;
        url->uri_part = 1;
        url->no_resolve = 1; /* want ip here */

        ngx_memzero(&sockaddr, sizeof(sockaddr));
        local_addr.sockaddr     = &sockaddr;
        local_addr.socklen      = sizeof(sockaddr);
        ngx_str_set(&local_addr.name, "nginx-cluster-pull");
        target.local            = &local_addr;

        if (ngx_rtmp_notify_json_decode(s, (const char *)str_result, target.local,
                                        url, &tmp_name) != NGX_OK) {
            goto next;
        }

        url->url.data += 7;
        url->url.len  -= 7;
    } else {
        goto disconnect;
    }

    if (ngx_hls_type(s->protocol)) {
        goto next;
    }

    if (ngx_parse_url(s->connection->pool, &target.url) != NGX_OK) {
        goto next;
    }

    // We don't need to launch a relay again when previous relay was started.
    if (ngx_rtmp_relay_get_publish(s, &tmp_name) != NULL) {
        goto next;
    }

    if (ngx_rtmp_relay_pull(s, &tmp_name, &target) != NGX_OK) {
        goto disconnect;
    }

next:
    return next_play(s, v);

disconnect:
    ngx_rtmp_notify_clear_flag(s, NGX_RTMP_NOTIFY_PLAYING);

    ngx_rtmp_set_fincode(s, NGX_RTMP_LOG_FINALIZE_DS_CLOSE_PUBLISHER);
    return NGX_ERROR;
}


static ngx_int_t
ngx_rtmp_notify_update_handle(ngx_rtmp_session_t *s,
        void *arg, ngx_chain_t *in)
{
    ngx_rtmp_notify_app_conf_t *nacf;
    ngx_rtmp_notify_ctx_t      *ctx;
    ngx_int_t                   rc;
    ngx_rtmp_netcall_ctx_t     *nctx;
#ifdef NGX_DEBUG
    ngx_str_t                   http_ret;
#endif
    u_char                      str_desc[NGX_RTMP_MAX_NAME];
    u_char                      ret_code[NGX_RTMP_MAX_NAME];
    u_char                      str_code[NGX_RTMP_MAX_NAME];

    static ngx_str_t            desc = ngx_string("description");
    static ngx_str_t            code = ngx_string("code");

    nacf = ngx_rtmp_get_module_app_conf(s, ngx_rtmp_notify_module);

    nctx = ngx_rtmp_get_module_ctx(s, ngx_rtmp_netcall_module);

    ctx = ngx_rtmp_get_module_ctx(s, ngx_rtmp_notify_module);

    if (!in) {
        ngx_log_error(NGX_LOG_WARN, s->connection->log, 0,
                      "notify: update received none!");
        goto reconnect;
    }

#ifdef NGX_DEBUG
    http_ret.data = in->buf->start;
    http_ret.len = in->buf->last - in->buf->start;

    ngx_log_debug1(NGX_LOG_INFO, s->connection->log, 0,
                  "notify: update received: %V", &http_ret);
#endif

    // pick up code & result from http response.
    ngx_memzero(&str_code, sizeof(str_code));
    ngx_memzero(&str_desc, sizeof(str_desc));

    if (ngx_rtmp_notify_parse_http_header(s, in, &code,
            str_code, sizeof(str_code) - 1) > 0) {
        *ngx_snprintf(nctx->ret_code, sizeof(nctx->ret_code) - 1, "%s", str_code) = 0;
    }

    if (ngx_rtmp_notify_parse_http_header(s, in, &desc,
            str_desc, sizeof(str_desc) - 1) > 0) {
        *ngx_snprintf(nctx->description, sizeof(nctx->description) - 1, "%s", str_desc) = 0;
    }

    ngx_memzero(ret_code, NGX_RTMP_MAX_NAME);
    rc = ngx_rtmp_notify_parse_http_retcode(s, in, ret_code);
    if (rc == NGX_ABORT || rc == NGX_CUSTOME) {

        goto reconnect;
    } else if (rc == NGX_ERROR) {  // force to finalize the session when ss receive 4xx.

        goto disconnect;
    }

    ngx_log_debug1(NGX_LOG_DEBUG_RTMP, s->connection->log, 0,
                   "notify: schedule update %Mms",
                   nacf->update_timeout);

    ngx_add_timer(&ctx->update_evt, nacf->update_timeout);

    return NGX_OK;

reconnect: /* reconnect in any case, do not finalize the current session. */

    ngx_add_timer(&ctx->update_evt, nacf->update_timeout);

    return NGX_OK;

disconnect:

    ngx_rtmp_set_fincode(s, NGX_RTMP_LOG_FINALIZE_DS_CLOSE_PUBLISHER);

    if (nctx) {
        ngx_rtmp_send_status(s, (char *)nctx->ret_code, "finish", (char *)nctx->description);
    }

    return NGX_ERROR;
}


static void
ngx_rtmp_notify_update(ngx_event_t *e)
{
    ngx_connection_t            *c;
    ngx_rtmp_session_t          *s;
    ngx_rtmp_notify_app_conf_t  *nacf;
    ngx_rtmp_netcall_init_t      ci;
    ngx_url_t                   *url;

    c = e->data;
    s = !ngx_rtmp_type(c->protocol) ? c->http_data : c->data;

    nacf = ngx_rtmp_get_module_app_conf(s, ngx_rtmp_notify_module);
    url = nacf->url[NGX_RTMP_NOTIFY_UPDATE];

    ngx_log_debug1(NGX_LOG_DEBUG_RTMP, s->connection->log, 0,
                  "notify_update: url '%V'", &url->url);

    ngx_memzero(&ci, sizeof(ci));

    ci.name = (u_char*)ngx_rtmp_notify_app_names[NGX_RTMP_NOTIFY_UPDATE];
    ci.url = url;
    ci.create = ngx_rtmp_notify_update_create;
    ci.handle = ngx_rtmp_notify_update_handle;

    if (ngx_rtmp_netcall_create(s, &ci) == NGX_OK) {
        return;
    }

    /* schedule next update on connection error */

    ngx_rtmp_notify_update_handle(s, NULL, NULL);
}


static void
ngx_rtmp_notify_init(ngx_rtmp_session_t *s,
        u_char name[NGX_RTMP_MAX_NAME], u_char args[NGX_RTMP_MAX_ARGS],
        ngx_uint_t flags)
{
    ngx_rtmp_notify_ctx_t          *ctx;
    ngx_rtmp_notify_app_conf_t     *nacf;
    ngx_event_t                    *e;

    nacf = ngx_rtmp_get_module_app_conf(s, ngx_rtmp_notify_module);
    if (!nacf->active) {
        return;
    }

    ctx = ngx_rtmp_get_module_ctx(s, ngx_rtmp_notify_module);
    if (ctx == NULL) {
        ctx = ngx_pcalloc(s->connection->pool, sizeof(ngx_rtmp_notify_ctx_t));
        if (ctx == NULL) {
            return;
        }
        ngx_rtmp_set_ctx(s, ctx, ngx_rtmp_notify_module);
    }

    ngx_memcpy(ctx->name, name, NGX_RTMP_MAX_NAME);
    ngx_memcpy(ctx->args, args, NGX_RTMP_MAX_ARGS);

    ctx->flags |= flags;

    if (nacf->url[NGX_RTMP_NOTIFY_UPDATE] == NULL ||
        nacf->update_timeout == 0)
    {
        return;
    }

    // If update on playing, will cause to SIGSEGV.
    if (flags == NGX_RTMP_NOTIFY_PLAYING) {
        return;
    }

    if (ctx->update_evt.timer_set) {
        return;
    }

    ctx->start = ngx_cached_time->sec;

    e = &ctx->update_evt;

    e->data = s->connection;
    e->log = s->connection->log;
    e->handler = ngx_rtmp_notify_update;

    ngx_add_timer(e, ngx_max(nacf->update_timeout / 3, 3));

    ngx_log_debug1(NGX_LOG_DEBUG_RTMP, s->connection->log, 0,
                   "notify: schedule initial update %Mms",
                   nacf->update_timeout);
}


static ngx_int_t
ngx_rtmp_notify_connect(ngx_rtmp_session_t *s, ngx_rtmp_connect_t *v)
{
    ngx_rtmp_notify_srv_conf_t     *nscf;
    ngx_rtmp_netcall_init_t         ci;
    ngx_url_t                      *url;
    ngx_rtmp_notify_ctx_t          *ctx;

    ctx = ngx_rtmp_get_module_ctx(s, ngx_rtmp_notify_module);
    if (ctx == NULL) {
        ctx = ngx_pcalloc(s->connection->pool, sizeof(ngx_rtmp_notify_ctx_t));
        if (ctx) {
            ngx_rtmp_set_ctx(s, ctx, ngx_rtmp_notify_module);
        }
    }

    nscf = ngx_rtmp_get_module_srv_conf(s, ngx_rtmp_notify_module);

    url = nscf->url[NGX_RTMP_NOTIFY_CONNECT];
    if (url == NULL) {
        goto next;
    }

    ngx_log_error(NGX_LOG_INFO, s->connection->log, 0,
                  "notify_connect: url '%V'", &url->url);

    ngx_memzero(&ci, sizeof(ci));

    ci.name = (u_char*)ngx_rtmp_notify_srv_names[NGX_RTMP_NOTIFY_CONNECT];
    ci.url = url;
    ci.create = ngx_rtmp_notify_connect_create;
    ci.handle = ngx_rtmp_notify_connect_handle;
    ci.arg = v;
    ci.argsize = sizeof(*v);

    return ngx_rtmp_netcall_create(s, &ci);

next:
    return next_connect(s, v);
}


static ngx_int_t
ngx_rtmp_notify_disconnect(ngx_rtmp_session_t *s)
{
    ngx_rtmp_notify_srv_conf_t     *nscf;
    ngx_rtmp_netcall_init_t         ci;
    ngx_url_t                      *url;

    nscf = ngx_rtmp_get_module_srv_conf(s, ngx_rtmp_notify_module);

    url = nscf->url[NGX_RTMP_NOTIFY_DISCONNECT];
    if (url == NULL) {
        goto next;
    }

    ngx_log_error(NGX_LOG_INFO, s->connection->log, 0,
                  "notify_disconnect: url '%V'", &url->url);

    ngx_memzero(&ci, sizeof(ci));

    ci.name = (u_char*)ngx_rtmp_notify_srv_names[NGX_RTMP_NOTIFY_DISCONNECT];
    ci.url = url;
    ci.create = ngx_rtmp_notify_disconnect_create;

    ngx_rtmp_netcall_create(s, &ci);

next:
    return next_disconnect(s);
}


static ngx_int_t
ngx_rtmp_notify_publish(ngx_rtmp_session_t *s, ngx_rtmp_publish_t *v)
{
    ngx_rtmp_notify_app_conf_t     *nacf;
    ngx_rtmp_netcall_init_t         ci;
    ngx_url_t                      *url;

    nacf = ngx_rtmp_get_module_app_conf(s, ngx_rtmp_notify_module);
    if (nacf == NULL) {
        goto next;
    }

    url = nacf->url[NGX_RTMP_NOTIFY_PUBLISH];

    ngx_rtmp_notify_init(s, v->name, v->args, NGX_RTMP_NOTIFY_PUBLISHING);

    if (url == NULL) {
        goto next;
    }

    ngx_log_error(NGX_LOG_INFO, s->connection->log, 0,
                  "notify_publish: url '%V' relay_type '%i'", &url->url, s->relay_type);

    ngx_memzero(&ci, sizeof(ci));

    ci.name = (u_char*)ngx_rtmp_notify_app_names[NGX_RTMP_NOTIFY_PUBLISH];
    ci.url = url;
    ci.create = ngx_rtmp_notify_publish_create;
    ci.handle = ngx_rtmp_notify_publish_handle;
    ci.arg = v;
    ci.argsize = sizeof(*v);

    return ngx_rtmp_netcall_create(s, &ci);

next:
    return next_publish(s, v);
}


static ngx_int_t
ngx_rtmp_notify_play(ngx_rtmp_session_t *s, ngx_rtmp_play_t *v)
{
    ngx_rtmp_notify_app_conf_t     *nacf;
    ngx_rtmp_netcall_init_t         ci;
    ngx_url_t                      *url;

    nacf = ngx_rtmp_get_module_app_conf(s, ngx_rtmp_notify_module);
    if (nacf == NULL) {
        goto next;
    }

    url = nacf->url[NGX_RTMP_NOTIFY_PLAY];

    if (NULL == v && s->name.len == 0) {
        return NGX_ERROR;
    }

    if (v) {
        ngx_rtmp_notify_init(s, v->name, v->args, NGX_RTMP_NOTIFY_PLAYING);
    }

    if (url == NULL) {
        goto next;
    }

    ngx_log_error(NGX_LOG_INFO, s->connection->log, 0,
                  "notify_play: url '%V'", &url->url);

    ngx_memzero(&ci, sizeof(ci));

    ci.name = (u_char*)ngx_rtmp_notify_app_names[NGX_RTMP_NOTIFY_PLAY];
    ci.url = url;
    ci.create = ngx_rtmp_notify_play_create;
    ci.handle = ngx_rtmp_notify_play_handle;
    ci.arg = v;
    if (v) {
        ci.argsize = sizeof(*v);
    }

    return ngx_rtmp_netcall_create(s, &ci);

next:
    if (v)
        return next_play(s, v);
    return NGX_OK;
}


ngx_int_t
ngx_rtmp_notify_play1(ngx_rtmp_session_t *s, ngx_rtmp_play_t *v)
{
    ngx_rtmp_notify_app_conf_t     *nacf;
    ngx_rtmp_netcall_init_t         ci;
    ngx_url_t                      *url;

    nacf = ngx_rtmp_get_module_app_conf(s, ngx_rtmp_notify_module);
    if (nacf == NULL) {
        goto next;
    }

    url = nacf->url[NGX_RTMP_NOTIFY_PLAY];

    if (NULL == v && s->name.len == 0) {
        return NGX_ERROR;
    }

    if (v) {
        ngx_rtmp_notify_init(s, v->name, v->args, NGX_RTMP_NOTIFY_PLAYING);
    }

    if (url == NULL) {
        goto next;
    }

    ngx_log_error(NGX_LOG_INFO, s->connection->log, 0,
                  "notify_play: url '%V'", &url->url);

    ngx_memzero(&ci, sizeof(ci));

    ci.name = (u_char*)ngx_rtmp_notify_app_names[NGX_RTMP_NOTIFY_PLAY];
    ci.url = url;
    ci.create = ngx_rtmp_notify_play_create;
    ci.handle = ngx_rtmp_notify_play_handle;
    ci.arg = v;
    if (v) {
        ci.argsize = sizeof(*v);
    }

    return ngx_rtmp_netcall_create(s, &ci);

next:
    return NGX_OK;
}


static ngx_int_t
ngx_rtmp_notify_close_stream(ngx_rtmp_session_t *s,
                             ngx_rtmp_close_stream_t *v)
{
    ngx_rtmp_notify_ctx_t          *ctx;
    ngx_rtmp_notify_app_conf_t     *nacf;

    ctx = ngx_rtmp_get_module_ctx(s, ngx_rtmp_notify_module);

    if (ctx == NULL) {
        goto next;
    }

    nacf = ngx_rtmp_get_module_app_conf(s, ngx_rtmp_notify_module);

    if (nacf == NULL) {
        goto next;
    }

    if (ctx->update_evt.timer_set) {
        ngx_del_timer(&ctx->update_evt);
    }

    if (ctx->flags & NGX_RTMP_NOTIFY_PUBLISHING) {
        ngx_rtmp_notify_done(s, "publish_done", NGX_RTMP_NOTIFY_PUBLISH_DONE);
    }

    if (ctx->flags & NGX_RTMP_NOTIFY_PLAYING) {
        ngx_rtmp_notify_done(s, "play_done", NGX_RTMP_NOTIFY_PLAY_DONE);
    }

    if (ctx->flags) {
        ngx_rtmp_notify_done(s, "done", NGX_RTMP_NOTIFY_DONE);
    }

    ctx->flags = 0;

next:
    return next_close_stream(s, v);
}


static ngx_int_t
ngx_rtmp_notify_record_done(ngx_rtmp_session_t *s, ngx_rtmp_record_done_t *v)
{
    ngx_rtmp_netcall_init_t         ci;
    ngx_rtmp_notify_app_conf_t     *nacf;

    if (s->auto_pushed) {
        goto next;
    }

    nacf = ngx_rtmp_get_module_app_conf(s, ngx_rtmp_notify_module);
    if (nacf == NULL || nacf->url[NGX_RTMP_NOTIFY_RECORD_DONE] == NULL) {
        goto next;
    }

    ngx_log_error(NGX_LOG_INFO, s->connection->log, 0,
                  "notify: record_done recorder=%V path='%V' url='%V'",
                  &v->recorder, &v->path,
                  &nacf->url[NGX_RTMP_NOTIFY_RECORD_DONE]->url);

    ngx_memzero(&ci, sizeof(ci));

    ci.name = (u_char*)ngx_rtmp_notify_app_names[NGX_RTMP_NOTIFY_RECORD_DONE];
    ci.url    = nacf->url[NGX_RTMP_NOTIFY_RECORD_DONE];
    ci.create = ngx_rtmp_notify_record_done_create;
    ci.arg    = v;

    ngx_rtmp_netcall_create(s, &ci);

next:
    return next_record_done(s, v);
}


static ngx_int_t
ngx_rtmp_notify_done(ngx_rtmp_session_t *s, char *cbname, ngx_uint_t url_idx)
{
    ngx_rtmp_netcall_init_t         ci;
    ngx_rtmp_notify_done_t          ds;
    ngx_rtmp_notify_app_conf_t     *nacf;
    ngx_url_t                      *url;

    nacf = ngx_rtmp_get_module_app_conf(s, ngx_rtmp_notify_module);

    url = nacf->url[url_idx];
    if (url == NULL) {
        return NGX_OK;
    }

    ngx_log_error(NGX_LOG_INFO, s->connection->log, 0,
                  "notify: %s '%V' app='%V' streams=%V",
                  cbname, &url->url, &s->app, &s->name);

    ds.cbname = (u_char *) cbname;
    ds.url_idx = url_idx;

    ngx_memzero(&ci, sizeof(ci));

    ci.name = (u_char*)ngx_rtmp_notify_app_names[url_idx];
    ci.url = url;
    ci.arg = &ds;
    ci.create = ngx_rtmp_notify_done_create;

    return ngx_rtmp_netcall_create(s, &ci);
}


static ngx_url_t *
ngx_rtmp_notify_parse_url(ngx_conf_t *cf, ngx_str_t *url)
{
    ngx_url_t  *u;
    size_t      add;

    add = 0;

    u = ngx_pcalloc(cf->pool, sizeof(ngx_url_t));
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

    if (ngx_parse_url(cf->pool, u) != NGX_OK) {
        if (u->err) {
            ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                    "%s in url \"%V\"", u->err, &u->url);
        }
        return NULL;
    }

    return u;
}


static ngx_int_t
ngx_rtmp_notify_connect_json_decode(ngx_rtmp_session_t *s, char *jsonstr)
{
    ngx_str_t                    str;
    size_t                       len;
    u_char                      *p;
    struct json_object          *obj;
    struct json_object          *root_obj;

    root_obj = json_tokener_parse(jsonstr);
    if (root_obj == NULL) {
        ngx_log_error(NGX_LOG_ERR, s->connection->log, 0, "json root_obj is null and jsonstr is:%s",jsonstr);
    }
#define NGX_RTMP_NOTIFY_JSON_GET_INT(key, param) \
    do { \
        if (json_object_object_get_ex(root_obj, key, &obj)) { \
            s->conf.param = json_object_get_int(obj); \
            obj = NULL; \
        } else { \
            obj = NULL; \
            ngx_log_error(NGX_LOG_WARN, s->connection->log, 0, "json decode "key" failed"); \
        } \
    } while(0)

#define NGX_RTMP_NOTIFY_JSON_GET_STR(key, param) \
    do { \
        if (json_object_object_get_ex(root_obj, key, &obj)) { \
            p = (u_char *)json_object_get_string(obj); \
            len = json_object_get_string_len(obj); \
            s->conf.param.len = len; \
            s->conf.param.data = ngx_strdup(s->pool, p, len); \
            obj = NULL; \
        } else { \
            obj = NULL; \
            ngx_log_error(NGX_LOG_WARN, s->connection->log, 0, "json decode "key" failed"); \
        } \
    } while(0)

#define NGX_RTMP_NOTIFY_JSON_GET_TIME(key, param) \
    do { \
        if (json_object_object_get_ex(root_obj, key, &obj)) { \
            p = (u_char *)json_object_get_string(obj); \
            len = json_object_get_string_len(obj); \
            str.data = p; \
            str.len  = len; \
            s->conf.param = ngx_parse_time(&str, 0); \
            obj = NULL; \
        } else { \
            obj = NULL; \
            ngx_log_error(NGX_LOG_WARN, s->connection->log, 0, "json decode "key" failed"); \
        } \
    } while(0)

    NGX_RTMP_NOTIFY_JSON_GET_INT("user_id", user_id);
    NGX_RTMP_NOTIFY_JSON_GET_STR("unique_name", unique_name);
    NGX_RTMP_NOTIFY_JSON_GET_TIME("idle_timeout", idle_timeout);
    NGX_RTMP_NOTIFY_JSON_GET_INT("live", live);
    NGX_RTMP_NOTIFY_JSON_GET_INT("gop_cache", gop_cache);
    NGX_RTMP_NOTIFY_JSON_GET_TIME("gop_cache_mintime", gop_cache_mintime);
    NGX_RTMP_NOTIFY_JSON_GET_TIME("gop_cache_maxtime", gop_cache_maxtime);
    NGX_RTMP_NOTIFY_JSON_GET_INT("rtmp_status_code", rtmp_status_code);
    NGX_RTMP_NOTIFY_JSON_GET_INT("hdl", hdl);
    NGX_RTMP_NOTIFY_JSON_GET_INT("hls", hls);
    NGX_RTMP_NOTIFY_JSON_GET_TIME("hls_fragment", hls_fragment);
    NGX_RTMP_NOTIFY_JSON_GET_TIME("hls_playlist_length", hls_playlist_length);
    NGX_RTMP_NOTIFY_JSON_GET_INT("hls_vod", hls_vod);
    NGX_RTMP_NOTIFY_JSON_GET_TIME("hls_vod_fragment", hls_vod_fragment);
    NGX_RTMP_NOTIFY_JSON_GET_STR("hls_vod_bucket", hls_vod_bucket);
    NGX_RTMP_NOTIFY_JSON_GET_STR("hls_vod_url", hls_vod_url);
    NGX_RTMP_NOTIFY_JSON_GET_INT("hls_vod_is_public", hls_vod_is_public);
    NGX_RTMP_NOTIFY_JSON_GET_INT("screenshot", screenshot);
    NGX_RTMP_NOTIFY_JSON_GET_STR("screenshot_bucket", screenshot_bucket);
    NGX_RTMP_NOTIFY_JSON_GET_STR("screenshot_url", screenshot_url);
    NGX_RTMP_NOTIFY_JSON_GET_INT("screenshot_is_public", screenshot_is_public);
    NGX_RTMP_NOTIFY_JSON_GET_INT("screenshot_monitor", screenshot_monitor);
    NGX_RTMP_NOTIFY_JSON_GET_TIME("screenshot_interval", screenshot_interval);
    NGX_RTMP_NOTIFY_JSON_GET_INT("screenshot_is_cover", screenshot_is_cover);
    NGX_RTMP_NOTIFY_JSON_GET_INT("mp4_vod", mp4_vod);
    NGX_RTMP_NOTIFY_JSON_GET_STR("mp4_vod_bucket", mp4_vod_bucket);
    NGX_RTMP_NOTIFY_JSON_GET_STR("mp4_vod_url", mp4_vod_url);
    NGX_RTMP_NOTIFY_JSON_GET_INT("mp4_vod_is_public", mp4_vod_is_public);

    NGX_RTMP_NOTIFY_JSON_GET_STR("region_mp4", region_mp4);
    NGX_RTMP_NOTIFY_JSON_GET_STR("region_hls", region_hls);
    NGX_RTMP_NOTIFY_JSON_GET_STR("region_pic", region_pic);

    NGX_RTMP_NOTIFY_JSON_GET_STR("host_mp4", host_mp4);
    NGX_RTMP_NOTIFY_JSON_GET_STR("host_hls", host_hls);
    NGX_RTMP_NOTIFY_JSON_GET_STR("host_pic", host_pic);

    NGX_RTMP_NOTIFY_JSON_GET_INT("hls_vod_auto_merge", hls_vod_auto_merge);
    NGX_RTMP_NOTIFY_JSON_GET_INT("hls_vod_ts_zero", hls_vod_ts_zero);
    NGX_RTMP_NOTIFY_JSON_GET_INT("publish_extime_fix", publish_extime_fix);

    NGX_RTMP_NOTIFY_JSON_GET_INT("mp4_vod_name_format", mp4_vod_name_format);

    NGX_RTMP_NOTIFY_JSON_GET_INT("live_delay", live_delay);
    NGX_RTMP_NOTIFY_JSON_GET_TIME("live_delay_time", live_delay_time);
    NGX_RTMP_NOTIFY_JSON_GET_STR("live_delay_host", live_delay_host);
    NGX_RTMP_NOTIFY_JSON_GET_STR("live_delay_app", live_delay_app);

    if(s->conf.hls_vod_fragment <= 0) {
        s->conf.hls_vod_fragment = s->conf.hls_fragment;
    }

#undef NGX_RTMP_NOTIFY_JSON_GET_INT
#undef NGX_RTMP_NOTIFY_JSON_GET_STR
#undef NGX_RTMP_NOTIFY_JSON_GET_TIME

    json_object_put(root_obj);

    return NGX_OK;
}


static char *
ngx_rtmp_notify_on_srv_event(ngx_conf_t *cf, ngx_command_t *cmd, void *conf)
{
    ngx_rtmp_notify_srv_conf_t     *nscf = conf;

    ngx_str_t                      *name, *value;
    ngx_url_t                      *u;
    ngx_uint_t                      n;

    value = cf->args->elts;

    u = ngx_rtmp_notify_parse_url(cf, &value[1]);
    if (u == NULL) {
        return NGX_CONF_ERROR;
    }

    name = &value[0];

    n = 0;

    switch (name->len) {
        case sizeof("on_connect") - 1:
            n = NGX_RTMP_NOTIFY_CONNECT;
            break;

        case sizeof("on_disconnect") - 1:
            n = NGX_RTMP_NOTIFY_DISCONNECT;
            break;
    }

    nscf->url[n] = u;

    return NGX_CONF_OK;
}


static char *
ngx_rtmp_notify_on_app_event(ngx_conf_t *cf, ngx_command_t *cmd, void *conf)
{
    ngx_rtmp_notify_app_conf_t     *nacf = conf;

    ngx_str_t                      *name, *value;
    ngx_url_t                      *u;
    ngx_uint_t                      n;

    value = cf->args->elts;

    u = ngx_rtmp_notify_parse_url(cf, &value[1]);
    if (u == NULL) {
        return NGX_CONF_ERROR;
    }

    name = &value[0];

    n = 0;

    switch (name->len) {
        case sizeof("on_done") - 1: /* and on_play */
            if (name->data[3] == 'd') {
                n = NGX_RTMP_NOTIFY_DONE;
            } else {
                n = NGX_RTMP_NOTIFY_PLAY;
            }
            break;

        case sizeof("on_update") - 1:
            n = NGX_RTMP_NOTIFY_UPDATE;
            break;

        case sizeof("on_publish") - 1:
            n = NGX_RTMP_NOTIFY_PUBLISH;
            break;

        case sizeof("on_play_done") - 1:
            n = NGX_RTMP_NOTIFY_PLAY_DONE;
            break;

        case sizeof("on_record_done") - 1:
            n = NGX_RTMP_NOTIFY_RECORD_DONE;
            break;

        case sizeof("on_publish_done") - 1:
            n = NGX_RTMP_NOTIFY_PUBLISH_DONE;
            break;
    }

    nacf->url[n] = u;

    return NGX_CONF_OK;
}


static char *
ngx_rtmp_notify_method(ngx_conf_t *cf, ngx_command_t *cmd, void *conf)
{
    ngx_rtmp_notify_app_conf_t     *nacf = conf;

    ngx_rtmp_notify_srv_conf_t     *nscf;
    ngx_str_t                      *value;

    value = cf->args->elts;
    value++;

    if (value->len == sizeof("get") - 1 &&
        ngx_strncasecmp(value->data, (u_char *) "get", value->len) == 0)
    {
        nacf->method = NGX_RTMP_NETCALL_HTTP_GET;

    } else if (value->len == sizeof("post") - 1 &&
        ngx_strncasecmp(value->data, (u_char *) "post", value->len) == 0)
    {
        nacf->method = NGX_RTMP_NETCALL_HTTP_POST;

    } else {
        nacf->method = NGX_RTMP_NETCALL_HTTP_GET;
    }

    nscf = ngx_rtmp_conf_get_module_srv_conf(cf, ngx_rtmp_notify_module);
    nscf->method = nacf->method;

    return NGX_CONF_OK;
}


static ngx_int_t
ngx_rtmp_notify_postconfiguration(ngx_conf_t *cf)
{
    next_connect = ngx_rtmp_connect;
    ngx_rtmp_connect = ngx_rtmp_notify_connect;

    next_disconnect = ngx_rtmp_disconnect;
    ngx_rtmp_disconnect = ngx_rtmp_notify_disconnect;

    next_publish = ngx_rtmp_publish;
    ngx_rtmp_publish = ngx_rtmp_notify_publish;

    next_play = ngx_rtmp_play;
    ngx_rtmp_play = ngx_rtmp_notify_play;

    next_close_stream = ngx_rtmp_close_stream;
    ngx_rtmp_close_stream = ngx_rtmp_notify_close_stream;

    next_record_done = ngx_rtmp_record_done;
    ngx_rtmp_record_done = ngx_rtmp_notify_record_done;

    return NGX_OK;
}
