
/*
 * Copyright (C) Gino Hu
 */


#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_rtmp.h>
#include "ngx_rtmp_live_module.h"
#include "ngx_http_flv_module.h"
#include "ngx_rtmp_codec_module.h"


static ngx_rtmp_play_pt                 next_play;
static ngx_rtmp_close_stream_pt         next_close_stream;


extern ngx_uint_t ngx_rtmp_playing;
ngx_uint_t ngx_http_flv_naccepted;

typedef struct {
    ngx_flag_t                          http_flv;
} ngx_http_flv_httploc_conf_t;


/* http handler registered */
static ngx_int_t ngx_http_flv_http_init(ngx_conf_t *cf);
static void * ngx_http_flv_http_create_conf(ngx_conf_t *cf);
static char * ngx_http_flv_http_merge_conf(ngx_conf_t *cf, void *parent, void *child);

/* rtmp handler registered */
static ngx_int_t ngx_http_flv_rtmp_init(ngx_conf_t *cf);
static void * ngx_http_flv_rtmp_create_app_conf(ngx_conf_t *cf);
static char * ngx_http_flv_rtmp_merge_app_conf(ngx_conf_t *cf, void *parent, void *child);

static ngx_int_t ngx_http_flv_send_message(ngx_rtmp_session_t *s, ngx_chain_t *out, ngx_uint_t priority);
static ngx_int_t ngx_http_flv_connect_local(ngx_http_request_t *r, ngx_str_t *app, ngx_str_t *name);
static ngx_int_t ngx_http_flv_av(ngx_rtmp_session_t *s, ngx_rtmp_header_t *h, ngx_chain_t *in);
static ngx_int_t ngx_http_flv_gop_cache_send_message(ngx_rtmp_session_t *s, ngx_chain_t *in, ngx_uint_t priority);
static ngx_chain_t * ngx_http_flv_gop_cache_append_shared_bufs(ngx_rtmp_session_t *s, ngx_rtmp_header_t *h, ngx_rtmp_header_t *lh, ngx_chain_t *in);
static void ngx_http_flv_gop_cache_free_shared_chain(ngx_rtmp_session_t *s, ngx_chain_t *in);


ngx_rtmp_gop_cache_handler_t ngx_http_flv_gop_cache_handler = {
    ngx_http_flv_gop_cache_send_message,
    ngx_http_flv_gop_cache_append_shared_bufs,
    ngx_http_flv_gop_cache_free_shared_chain
};


static ngx_command_t ngx_http_flv_httpcommands[] = {

    { ngx_string("http_flv"),
      NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_TAKE1,
      ngx_conf_set_flag_slot,
      NGX_HTTP_LOC_CONF_OFFSET,
      offsetof(ngx_http_flv_httploc_conf_t, http_flv),
      NULL },

      ngx_null_command
};


static ngx_http_module_t ngx_http_flv_httpmodule_ctx = {
    NULL,                               /* preconfiguration */
    ngx_http_flv_http_init,             /* postconfiguration */
    NULL,                               /* create main configuration */
    NULL,                               /* init main configuration */
    NULL,                               /* create server configuration */
    NULL,                               /* merge server configuration */
    ngx_http_flv_http_create_conf,      /* create location configuration */
    ngx_http_flv_http_merge_conf        /* merge location configuration */
};


ngx_module_t ngx_http_flv_httpmodule = {
    NGX_MODULE_V1,
    &ngx_http_flv_httpmodule_ctx,       /* module context */
    ngx_http_flv_httpcommands,          /* module directives */
    NGX_HTTP_MODULE,                    /* module type */
    NULL,                               /* init master */
    NULL,                               /* init module */
    NULL,                               /* init process */
    NULL,                               /* init thread */
    NULL,                               /* exit thread */
    NULL,                               /* exit process */
    NULL,                               /* exit master */
    NGX_MODULE_V1_PADDING
};


static ngx_command_t ngx_http_flv_rtmpcommands[] = {

    { ngx_string("http_flv"),
      NGX_RTMP_MAIN_CONF|NGX_RTMP_SRV_CONF|NGX_RTMP_APP_CONF|NGX_CONF_TAKE1,
      ngx_conf_set_flag_slot,
      NGX_RTMP_APP_CONF_OFFSET,
      offsetof(ngx_http_flv_rtmp_app_conf_t, http_flv),
      NULL },

    ngx_null_command
};


static ngx_rtmp_module_t ngx_http_flv_rtmpmodule_ctx = {
    NULL,                               /* preconfiguration */
    ngx_http_flv_rtmp_init,             /* postconfiguration */
    NULL,                               /* create main configuration */
    NULL,                               /* init main configuration */
    NULL,                               /* create server configuration */
    NULL,                               /* merge server configuration */
    ngx_http_flv_rtmp_create_app_conf,  /* create application configuration */
    ngx_http_flv_rtmp_merge_app_conf,   /* merge application configuration */
};


ngx_module_t ngx_http_flv_rtmpmodule = {
    NGX_MODULE_V1,
    &ngx_http_flv_rtmpmodule_ctx,       /* module context */
    ngx_http_flv_rtmpcommands,          /* module directives */
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


static ngx_int_t
ngx_http_flv_send_message(ngx_rtmp_session_t *s, ngx_chain_t *out,
        ngx_uint_t priority)
{
    ngx_uint_t                      nmsg;

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

        ngx_http_flv_send(s->connection->write);
    }

    return NGX_OK;
}


static ngx_int_t
ngx_http_flv_get_info(ngx_str_t *uri, ngx_str_t *app, ngx_str_t *name)
{
    size_t    len;

    if (uri == NULL || uri->len == 0) {

        return NGX_ERROR;
    }

    len = 0;
    for(; uri->data[len] == '/' || uri->len == len; ++ len); // skip first '/'

    app->data = &uri->data[len];                             // we got app

    for(; uri->data[len] != '/' || uri->len == len; ++ len); // reach next '/'

    app->len = &uri->data[len ++] - app->data;

    name->data = &uri->data[len];
    name->len = &uri->data[uri->len] - name->data
        - ngx_strlen(".flv");                                // we got name

    return NGX_OK;
}


static ngx_int_t
ngx_http_flv_play_local(ngx_rtmp_session_t *s)
{
    static ngx_rtmp_play_t      v;

    ngx_rtmp_core_srv_conf_t   *cscf;

	ngx_memzero(&v, sizeof(ngx_rtmp_play_t));

    ngx_memcpy(v.name, s->name.data, ngx_min(s->name.len, sizeof(v.name) - 1));
    ngx_memcpy(v.args, s->args.data, ngx_min(s->args.len, sizeof(v.args) - 1));

    cscf = ngx_rtmp_get_module_srv_conf(s, ngx_rtmp_core_module);

    s->app_conf = cscf->ctx->app_conf;

	return ngx_rtmp_cmd_start_play(s, &v);
}


static void
ngx_http_flv_close_session_handler(ngx_rtmp_session_t *s)
{
    ngx_connection_t                   *c;
    ngx_rtmp_core_srv_conf_t           *cscf;

    c = s->connection;

    cscf = ngx_rtmp_get_module_srv_conf(s, ngx_rtmp_core_module);

    ngx_log_error(NGX_LOG_INFO, c->log, 0, "http_flv close session");

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


static ngx_int_t
ngx_http_flv_connect_local(ngx_http_request_t *r, ngx_str_t *app, ngx_str_t *name)
{
    static ngx_rtmp_connect_t   v;

    ngx_rtmp_session_t         *s;
    ngx_http_flv_rtmp_ctx_t    *rtmpctx;
    ngx_http_flv_http_ctx_t    *httpctx;

    httpctx = ngx_http_get_module_ctx(r, ngx_http_flv_httpmodule);

    s = httpctx->rs;

    ngx_memzero(&v, sizeof(ngx_rtmp_connect_t));

    ngx_memcpy(v.app, app->data, ngx_min(app->len, sizeof(v.app) - 1));
    ngx_memcpy(v.args, r->args.data, ngx_min(r->args.len, sizeof(v.args) - 1));
    ngx_memcpy(v.flashver, "HTTP FLV flashver", ngx_strlen("HTTP FLV flashver"));
    ngx_memcpy(v.swf_url, "HTTP FLV swf_url", ngx_strlen("HTTP FLV swf_url"));
    ngx_memcpy(v.tc_url, "HTTP FLV tc_url", ngx_strlen("HTTP FLV tc_url"));
    ngx_memcpy(v.page_url, "HTTP FLV page_url", ngx_strlen("HTTP FLV page_url"));

#define NGX_RTMP_SET_STRPAR(name)                                             \
    s->name.len = ngx_strlen(v.name);                                        \
    s->name.data = ngx_palloc(s->connection->pool, s->name.len);              \
    ngx_memcpy(s->name.data, v.name, s->name.len)

    NGX_RTMP_SET_STRPAR(app);
    NGX_RTMP_SET_STRPAR(args);
    NGX_RTMP_SET_STRPAR(flashver);
    NGX_RTMP_SET_STRPAR(swf_url);
    NGX_RTMP_SET_STRPAR(tc_url);
    NGX_RTMP_SET_STRPAR(page_url);

#undef NGX_RTMP_SET_STRPAR

    s->name.len = name->len;
    s->name.data = ngx_pstrdup(s->pool, name);

    rtmpctx = ngx_rtmp_get_module_ctx(s, ngx_http_flv_rtmpmodule);
    if (rtmpctx == NULL) {
        rtmpctx = ngx_pcalloc(s->pool, sizeof(ngx_http_flv_rtmp_ctx_t));
        ngx_rtmp_set_ctx(s, rtmpctx, ngx_http_flv_rtmpmodule);
    }

    return ngx_rtmp_cmd_start_connect(s, &v);
}


static void
ngx_http_flv_cleanup(void *data)
{
    ngx_http_request_t         *r = data;
    ngx_rtmp_session_t		   *s;
    ngx_http_flv_http_ctx_t    *httpctx;

    httpctx = ngx_http_get_module_ctx(r, ngx_http_flv_httpmodule);

    s = httpctx->rs;

    ngx_log_error(NGX_LOG_INFO, s->connection->log, 0, "http_flv close connection");

    -- ngx_http_flv_naccepted;

    ngx_http_flv_close_session_handler(s);
}


static ngx_int_t
ngx_http_flv_http_handler(ngx_http_request_t *r)
{
    ngx_http_flv_httploc_conf_t         *hlcf;
    ngx_http_flv_http_ctx_t             *httpctx;
    ngx_http_cleanup_t                  *cln;
    ngx_int_t                            protocol, rc = 0;
    ngx_str_t                            app, name;
    ngx_int_t                            nslash;
    size_t                               i;

    hlcf = ngx_http_get_module_loc_conf(r, ngx_http_flv_httpmodule);
    if (hlcf == NULL || !hlcf->http_flv) {
    	return NGX_DECLINED;
    }

    if (!(r->method & (NGX_HTTP_GET|NGX_HTTP_HEAD))
        || r->headers_in.host == NULL) {
        return NGX_HTTP_NOT_ALLOWED;
    }

    if (r->uri.data[r->uri.len - 1] == '/' &&
		r->uri.len > ngx_strlen(".flv")) {
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

    if (nslash != 2) {

        return NGX_DECLINED;
    }

	if (r->uri.data[r->uri.len - 1] == 'v' &&
		r->uri.data[r->uri.len - 2] == 'l' &&
		r->uri.data[r->uri.len - 3] == 'f' &&
		r->uri.data[r->uri.len - 4] == '.') {
		protocol = NGX_PROTO_TYPE_HTTP_FLV_PULL;
	} else {
		return NGX_DECLINED;
	}

    rc = ngx_http_discard_request_body(r);
    if (rc != NGX_OK) {
        return rc;
    }

    ngx_log_error(NGX_LOG_INFO, r->connection->log, 0,
        "http_flv handle uri: '%V' args: '%V'", &r->uri, &r->args);

    if (ngx_http_flv_get_info(&r->uri, &app, &name) != NGX_OK) {

        return NGX_DECLINED;
    }

    ngx_log_error(NGX_LOG_INFO, r->connection->log, 0,
              "http_flv handle app: '%V' name: '%V'", &app, &name);

    ngx_http_flv_init_connection(r, protocol);

    if (ngx_http_flv_connect_local(r, &app, &name) != NGX_OK) {

        return NGX_DECLINED;
    }

    cln = ngx_http_cleanup_add(r, 0);
    if (cln == NULL) {
        return NGX_DECLINED;
    }

    cln->handler = ngx_http_flv_cleanup;
    cln->data = r;

    return NGX_OK;
}


static ngx_int_t
ngx_http_flv_http_init(ngx_conf_t *cf)
{
    ngx_http_handler_pt        *h;
    ngx_http_core_main_conf_t  *cmcf;

    cmcf = ngx_http_conf_get_module_main_conf(cf, ngx_http_core_module);

    h = ngx_array_push(&cmcf->phases[NGX_HTTP_CONTENT_PHASE].handlers);
    if (h == NULL) {
        return NGX_ERROR;
    }

    *h = ngx_http_flv_http_handler;

    return NGX_OK;
}


static void *
ngx_http_flv_http_create_conf(ngx_conf_t *cf)
{
    ngx_http_flv_httploc_conf_t  *hlcf;

    hlcf = ngx_palloc(cf->pool, sizeof(ngx_http_flv_httploc_conf_t));
    if (hlcf == NULL) {
        return NULL;
    }

    hlcf->http_flv = NGX_CONF_UNSET;

    return hlcf;
}


static char *
ngx_http_flv_http_merge_conf(ngx_conf_t *cf, void *parent, void *child)
{
    ngx_http_flv_httploc_conf_t *prev = parent;
    ngx_http_flv_httploc_conf_t *conf = child;

    ngx_conf_merge_value(conf->http_flv, prev->http_flv, 0);

    return NGX_CONF_OK;
}


static void *
ngx_http_flv_rtmp_create_app_conf(ngx_conf_t *cf)
{
    ngx_http_flv_rtmp_app_conf_t      *hacf;

    hacf = ngx_pcalloc(cf->pool, sizeof(ngx_http_flv_rtmp_app_conf_t));
    if (hacf == NULL) {
        return NULL;
    }

    hacf->http_flv = NGX_CONF_UNSET;

    return hacf;
}


static char *
ngx_http_flv_rtmp_merge_app_conf(ngx_conf_t *cf, void *parent, void *child)
{
    ngx_http_flv_rtmp_app_conf_t    *prev = parent;
    ngx_http_flv_rtmp_app_conf_t    *conf = child;

    ngx_conf_merge_value(conf->http_flv, prev->http_flv, 0);

    return NGX_CONF_OK;
}


static ngx_int_t
ngx_http_flv_connect_end(ngx_rtmp_session_t *s, ngx_rtmp_header_t *h,
    ngx_chain_t *in)
{
    return ngx_http_flv_play_local(s);
}


ngx_chain_t *
ngx_http_flv_append_shared_bufs(ngx_rtmp_core_srv_conf_t *cscf, ngx_rtmp_header_t *h, ngx_chain_t *in)
{
    ngx_chain_t                    *tail, *head, *taghead, prepkt;
    ngx_chain_t                    *tag = in;
    ngx_buf_t                       prebuf;
    uint32_t                        presize, presizebuf;
    u_char                         *p, *ph;

    ngx_memzero(&prebuf, sizeof(prebuf));
    prebuf.start = prebuf.pos = (u_char*)&presizebuf;
    prebuf.end   = prebuf.last = (u_char*)(((u_char*)&presizebuf) + sizeof(presizebuf));
    prepkt.buf   = &prebuf;
    prepkt.next  = NULL;

    head = tag;
    tail = tag;
    taghead = NULL;

    for (presize = 0, tail = tag; tag; tail = tag, tag = tag->next) {
        presize += (tag->buf->last - tag->buf->pos);
    }

    presize += NGX_RTMP_MAX_FLV_TAG_HEADER;

    ph = (u_char*)&presizebuf;
    p  = (u_char*)&presize;

    *ph++ = p[3];
    *ph++ = p[2];
    *ph++ = p[1];
    *ph++ = p[0];

    /* Link chain of PreviousTagSize after the last packet. */
    tail->next = &prepkt;

    taghead = ngx_rtmp_append_shared_bufs(cscf, NULL, head);

    tail->next = NULL;
    presize -= NGX_RTMP_MAX_FLV_TAG_HEADER;

    /* tag header */
    taghead->buf->pos -= NGX_RTMP_MAX_FLV_TAG_HEADER;
    ph = taghead->buf->pos;

    *ph++ = (u_char)h->type;

    p = (u_char*)&presize;
    *ph++ = p[2];
    *ph++ = p[1];
    *ph++ = p[0];

    p = (u_char*)&h->timestamp;
    *ph++ = p[2];
    *ph++ = p[1];
    *ph++ = p[0];
    *ph++ = p[3];

    *ph++ = 0;
    *ph++ = 0;
    *ph++ = 0;

    return taghead;
}


static ngx_int_t
ngx_http_flv_gop_cache_send_message(ngx_rtmp_session_t *s, ngx_chain_t *in, ngx_uint_t priority)
{
    return ngx_http_flv_send_message(s, in, priority);
}


static ngx_chain_t *
ngx_http_flv_gop_cache_append_shared_bufs(ngx_rtmp_session_t *s, ngx_rtmp_header_t *h, ngx_rtmp_header_t *lh, ngx_chain_t *in)
{
    ngx_rtmp_core_srv_conf_t       *cscf;

    cscf = ngx_rtmp_get_module_srv_conf(s, ngx_rtmp_core_module);
    if (cscf == NULL) {
        return NULL;
    }

    return ngx_http_flv_append_shared_bufs(cscf, h, in);
}


static void
ngx_http_flv_gop_cache_free_shared_chain(ngx_rtmp_session_t *s, ngx_chain_t *in)
{
    ngx_rtmp_core_srv_conf_t       *cscf;

    cscf = ngx_rtmp_get_module_srv_conf(s, ngx_rtmp_core_module);
    if (cscf == NULL) {
        return;
    }

    ngx_rtmp_free_shared_chain(cscf, in);
}


static ngx_int_t
ngx_http_flv_av(ngx_rtmp_session_t *s, ngx_rtmp_header_t *h,
                 ngx_chain_t *in)
{
    ngx_rtmp_gop_cache_app_conf_t  *gacf;
    ngx_rtmp_live_app_conf_t       *lacf;
    ngx_http_flv_rtmp_app_conf_t   *hacf;
    ngx_rtmp_core_srv_conf_t       *cscf;
    ngx_rtmp_live_ctx_t            *ctx, *pctx;
    ngx_rtmp_codec_ctx_t           *codec_ctx = NULL;
    ngx_rtmp_header_t               ch, lh, mh;
    ngx_rtmp_session_t             *ss;
    ngx_int_t                       mandatory;
    ngx_uint_t                      csidx;
    ngx_uint_t                      prio;
    ngx_uint_t                      meta_version;
    ngx_chain_t                    *header, *fpkt, *apkt, *mpkt, *meta;
    ngx_rtmp_live_chunk_stream_t   *cs;
    uint32_t                        delta = 0;
#ifdef NGX_DEBUG
    const char                     *type_s;

    type_s = (h->type == NGX_RTMP_MSG_VIDEO ? "video" : "audio"); 
#endif

    lacf = ngx_rtmp_get_module_app_conf(s, ngx_rtmp_live_module);
    if (lacf == NULL) {
        return NGX_ERROR;
    }

    gacf = ngx_rtmp_get_module_app_conf(s, ngx_rtmp_gop_cache_module);
    if (gacf == NULL) {
        return NGX_ERROR;
    }

    hacf = ngx_rtmp_get_module_app_conf(s, ngx_http_flv_rtmpmodule);
    if (hacf == NULL) {
        return NGX_ERROR;
    }

    if (!lacf->live || !hacf->http_flv) {
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
                       "http_flv: %s from non-publisher", type_s);
        return NGX_OK;
    }

    apkt = NULL;
    fpkt = NULL;
    mpkt = NULL;
    header = NULL;
    meta = NULL;
    meta_version = 0;
    mandatory = 0;

    prio = (h->type == NGX_RTMP_MSG_VIDEO ?
            ngx_rtmp_get_video_frame_type(in) : 0);

    cscf = ngx_rtmp_get_module_srv_conf(s, ngx_rtmp_core_module);

    csidx = !(lacf->interleave || h->type == NGX_RTMP_MSG_VIDEO);

    cs = &ctx->cs[csidx];

    ngx_memzero(&ch, sizeof(ch));
    ngx_memzero(&mh, sizeof(mh));

    ch.timestamp = h->timestamp;
    ch.msid = NGX_RTMP_MSID;
    ch.csid = cs->csid;
    ch.type = h->type;

    lh = ch;

    if (cs->active) {
        lh.timestamp = cs->timestamp;
    }

    delta = ch.timestamp - lh.timestamp;

    codec_ctx = ngx_rtmp_get_module_ctx(s, ngx_rtmp_codec_module);

    if (codec_ctx) {

        if (h->type == NGX_RTMP_MSG_AUDIO) {
            header = codec_ctx->aac_header;

            if (codec_ctx->audio_codec_id == NGX_RTMP_AUDIO_AAC &&
                ngx_rtmp_is_codec_header(in)) // is or not audio header
            {
                prio = 0;
                mandatory = 1;
            }

        } else {
            header = codec_ctx->video_header;

            if (codec_ctx->video_codec_id == NGX_RTMP_VIDEO_H264 &&
                ngx_rtmp_is_codec_header(in)) // is or not video header
            {
                prio = 0;
                mandatory = 1;
            }
        }

        if (codec_ctx->meta) {
            mh = codec_ctx->meta_header;
            meta = codec_ctx->meta;
            meta_version = codec_ctx->meta_version;
        }
    }

    /* broadcast to all subscribers */
    fpkt = ngx_http_flv_append_shared_bufs(cscf, &ch, in);

    for (pctx = ctx->stream->hctx; pctx; pctx = pctx->next) {
        if (pctx == ctx || pctx->paused) {
            continue;
        }

        ss = pctx->session;
        cs = &pctx->cs[csidx];

        /* send metadata */

        if (meta && meta_version != pctx->meta_version) {
            ngx_log_debug0(NGX_LOG_DEBUG_RTMP, ss->connection->log, 0,
                           "http_flv: meta");

            mpkt = ngx_http_flv_append_shared_bufs(cscf, &mh, meta);

            if (ngx_http_flv_send_message(ss, mpkt, 0) == NGX_OK) {
                pctx->meta_version = meta_version;
            }

            if (mpkt) {
                ngx_rtmp_free_shared_chain(cscf, mpkt);
            }
        }

        /* sync stream */

        if (cs->active && (lacf->sync && cs->dropped > lacf->sync)) {
            ngx_log_debug2(NGX_LOG_DEBUG_RTMP, ss->connection->log, 0,
                           "http_flv: sync %s dropped=%uD", type_s, cs->dropped);

            cs->active = 0;
            cs->dropped = 0;
        }

        /* absolute packet */

        if (!cs->active) {

            if (mandatory) {
                ngx_log_debug0(NGX_LOG_DEBUG_RTMP, ss->connection->log, 0,
                               "http_flv: skipping header");
                continue;
            }

            if (lacf->wait_video && h->type == NGX_RTMP_MSG_AUDIO &&
                !pctx->cs[0].active && !gacf->gop_cache)
            {
                ngx_log_debug0(NGX_LOG_DEBUG_RTMP, ss->connection->log, 0,
                               "http_flv: waiting for video");
                continue;
            }

            if (lacf->wait_key && prio != NGX_RTMP_VIDEO_KEY_FRAME &&
               (lacf->interleave || h->type == NGX_RTMP_MSG_VIDEO) &&
               !gacf->gop_cache)
            {
                ngx_log_debug0(NGX_LOG_DEBUG_RTMP, ss->connection->log, 0,
                               "http_flv: skip non-key");
                continue;
            }

            if (header) {

                /* send absolute codec header */

                ngx_log_debug2(NGX_LOG_DEBUG_RTMP, ss->connection->log, 0,
                               "http_flv: abs %s header timestamp=%uD",
                               type_s, lh.timestamp);

                apkt = ngx_http_flv_append_shared_bufs(cscf, &lh, header);

                if (ngx_http_flv_send_message(ss, apkt, 0) != NGX_OK) {
                    continue;
                }

                cs->timestamp = lh.timestamp;
                cs->active = 1;
                ss->current_time = cs->timestamp;

                if (apkt) {
                    ngx_rtmp_free_shared_chain(cscf, apkt);
                    apkt = NULL;
                }
            }
        }

        /* send relative packet */

        ngx_log_debug3(NGX_LOG_DEBUG_RTMP, ss->connection->log, 0,
                       "http_flv: rel %s prio '%d' packet delta=%uD",
                       type_s, prio, delta);

        if (ngx_http_flv_send_message(ss, fpkt, prio) != NGX_OK) {
            ++pctx->ndropped;

            cs->dropped += delta;

            continue;
        }

        cs->timestamp += delta;
        ss->current_time = cs->timestamp;

        ngx_rtmp_update_bandwidth(&pctx->bw_out, h->mlen);
    }

    if (fpkt) {
        ngx_rtmp_free_shared_chain(cscf, fpkt);
        fpkt = NULL;
    }

    return NGX_OK;
}


static ngx_int_t
ngx_http_flv_message(ngx_rtmp_session_t *s, ngx_rtmp_header_t *h,
                     ngx_chain_t *in)
{
    ngx_rtmp_live_app_conf_t       *lacf;
    ngx_http_flv_rtmp_app_conf_t   *hacf;
    ngx_rtmp_core_srv_conf_t       *cscf;
    ngx_rtmp_live_ctx_t            *ctx, *pctx;
    ngx_chain_t                    *mpkt;
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

    hacf = ngx_rtmp_get_module_app_conf(s, ngx_http_flv_rtmpmodule);
    if (hacf == NULL) {
        return NGX_ERROR;
    }

    if (!lacf->live || !hacf->http_flv) {
        return NGX_OK;
    }

    cscf = ngx_rtmp_get_module_srv_conf(s, ngx_rtmp_core_module);
    if(cscf == NULL) {
        return NGX_ERROR;
    }

    codec_ctx = ngx_rtmp_get_module_ctx(s, ngx_rtmp_codec_module);
    if(codec_ctx == NULL || codec_ctx->msg == NULL) {
        return NGX_ERROR;
    }

    ctx = ngx_rtmp_get_module_ctx(s, ngx_http_flv_rtmpmodule);
    if (ctx == NULL || ctx->stream == NULL) {
        return NGX_OK;
    }

    if (ctx->publishing == 0) {
        ngx_log_debug1(NGX_LOG_DEBUG_RTMP, s->connection->log, 0,
                       "http_flv: %s from non-publisher", type_s);
        return NGX_OK;
    }

    mpkt = ngx_http_flv_append_shared_bufs(cscf, &codec_ctx->msgh, codec_ctx->msg);

    if(mpkt == NULL) {
        return NGX_ERROR;
    }

    /* broadcast to all subscribers */
    for (pctx = ctx->stream->hctx; pctx; pctx = pctx->next) {
        if (pctx == ctx || pctx->paused) {
            continue;
        }

        ss = pctx->session;

        ngx_http_flv_send_message(ss, mpkt, 0);
    }

    if (mpkt) {
        ngx_rtmp_free_shared_chain(cscf, mpkt);
    }

    return NGX_OK;
}


static ngx_int_t
ngx_http_flv_play_end(ngx_rtmp_session_t *s, ngx_rtmp_header_t *h,
    ngx_chain_t *in)
{
    static u_char httpheader[] = {
        "HTTP/1.1 200 OK\r\n"
        "Cache-Control: no-cache\r\n"
        "Content-Type: video/x-flv\r\n"
        "Connection: close\r\n"
        "Expires: -1\r\n"
        "Pragma: no-cache\r\n"
        "\r\n"
    };

    static u_char flvheader[] = {
        0x46, /* 'F' */
        0x4c, /* 'L' */
        0x56, /* 'V' */
        0x01, /* version = 1 */
        0x05, /* 00000 1 0 1 = has audio & video */
        0x00,
        0x00,
        0x00,
        0x09, /* header size */
        0x00,
        0x00,
        0x00,
        0x00  /* PreviousTagSize0 (not actually a header) */
    };

    ngx_http_flv_rtmp_ctx_t        *rtmpctx;
    ngx_rtmp_core_srv_conf_t       *cscf;
    ngx_http_flv_rtmp_app_conf_t   *lacf;
    ngx_chain_t                     c1, c2, *pkt;
    ngx_buf_t                       b1, b2;

    lacf = ngx_rtmp_get_module_app_conf(s, ngx_http_flv_rtmpmodule);
    if (lacf == NULL) {
        return NGX_ERROR;
    }

    if (!lacf->http_flv) {
        return NGX_OK;
    }

    cscf = ngx_rtmp_get_module_srv_conf(s, ngx_rtmp_core_module);

    rtmpctx = ngx_rtmp_get_module_ctx(s, ngx_http_flv_rtmpmodule);
    if (rtmpctx == NULL) {
        return NGX_OK;
    }

    if (rtmpctx->initialized) {
        return NGX_OK;
    }

    c1.buf = &b1;
    c2.buf = &b2;
    c1.next = &c2;
    c2.next = NULL;

    b1.start = b1.pos = &httpheader[0];
    b1.end = b1.last = b1.pos + sizeof(httpheader) - 1;

    b2.start = b2.pos = &flvheader[0];
    b2.end = b2.last = b2.pos + sizeof(flvheader);

    pkt = ngx_rtmp_append_shared_bufs(cscf, NULL, &c1);

    ngx_http_flv_send_message(s, pkt, 0);

    ngx_rtmp_free_shared_chain(cscf, pkt);

    if (!rtmpctx->initialized) {
        rtmpctx->initialized = 1;
    }

    return NGX_OK;
}


static void
ngx_http_flv_start(ngx_rtmp_session_t *s)
{
    ngx_rtmp_live_ctx_t        *ctx;

    ctx = ngx_rtmp_get_module_ctx(s, ngx_rtmp_live_module);

    ctx->active = 1;

    ctx->cs[0].active = 0;
    ctx->cs[0].dropped = 0;

    ctx->cs[1].active = 0;
    ctx->cs[1].dropped = 0;
}


static void
ngx_http_flv_stop(ngx_rtmp_session_t *s)
{
    ngx_rtmp_live_ctx_t        *ctx;

    ctx = ngx_rtmp_get_module_ctx(s, ngx_rtmp_live_module);

    ctx->active = 0;

    ctx->cs[0].active = 0;
    ctx->cs[0].dropped = 0;

    ctx->cs[1].active = 0;
    ctx->cs[1].dropped = 0;
}


static void
ngx_http_flv_join(ngx_rtmp_session_t *s, u_char *name, unsigned publisher)
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
                       "http flv: already joined");
        return;
    }

    if (ctx == NULL) {
        ctx = ngx_palloc(s->connection->pool, sizeof(ngx_rtmp_live_ctx_t));
        ngx_rtmp_set_ctx(s, ctx, ngx_rtmp_live_module);
    }

    ngx_memzero(ctx, sizeof(*ctx));

    ctx->session = s;

    ngx_log_debug1(NGX_LOG_DEBUG_RTMP, s->connection->log, 0,
                   "http flv: join '%s'", name);

    stream = ngx_rtmp_live_get_stream(s, name, lacf->idle_streams);

    if (stream == NULL ||
        !(publisher || (*stream)->publishing || lacf->idle_streams))
    {
        ngx_log_error(NGX_LOG_ERR, s->connection->log, 0,
                      "http flv: stream not found");

        ngx_rtmp_finalize_session(s);

        return;
    }

    ctx->stream = *stream;
    ctx->next = (*stream)->hctx;

    (*stream)->hctx = ctx;

    if (lacf->buflen) {
        s->out_buffer = 1;
    }

    ctx->cs[0].csid = NGX_RTMP_CSID_VIDEO;
    ctx->cs[1].csid = NGX_RTMP_CSID_AUDIO;

    if (!ctx->publishing && ctx->stream->active) {
        ngx_http_flv_start(s);
    }
}


static ngx_int_t
ngx_http_flv_close_stream(ngx_rtmp_session_t *s, ngx_rtmp_close_stream_t *v)
{
    ngx_rtmp_live_ctx_t            *ctx, **cctx;
    ngx_rtmp_live_stream_t        **stream;
    ngx_rtmp_live_app_conf_t       *lacf;

    if (s->protocol != NGX_PROTO_TYPE_HTTP_FLV_PULL) {
        goto next;
    }

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
                       "http flv: not joined");
        goto next;
    }

    ngx_log_debug1(NGX_LOG_DEBUG_RTMP, s->connection->log, 0,
                   "http flv: leave '%s'", ctx->stream->name);

    for (cctx = &ctx->stream->hctx; *cctx; cctx = &(*cctx)->next) {
        if (*cctx == ctx) {
            *cctx = ctx->next;
            break;
        }
    }

    if (ctx->publishing || ctx->stream->active) {
        ngx_http_flv_stop(s);
    }

    if (ctx->stream->hctx) {
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

next:
    return next_close_stream(s, v);
}


static ngx_int_t
ngx_http_flv_play(ngx_rtmp_session_t *s, ngx_rtmp_play_t *v)
{
    ngx_http_flv_rtmp_app_conf_t        *hacf;

    if (s->protocol != NGX_PROTO_TYPE_HTTP_FLV_PULL) {
        goto next;
    }

    hacf = ngx_rtmp_get_module_app_conf(s, ngx_http_flv_rtmpmodule);
    if (hacf == NULL || !hacf->http_flv) {
        goto next;
    }

    ngx_log_debug4(NGX_LOG_DEBUG_RTMP, s->connection->log, 0,
                   "http flv: play: name='%s' start=%uD duration=%uD reset=%d",
                   v->name, (uint32_t) v->start,
                   (uint32_t) v->duration, (uint32_t) v->reset);

    /* join stream as subscriber */

    ngx_http_flv_join(s, v->name, 0);

    ngx_rtmp_playing++;

next:
    return next_play(s, v);
}


static ngx_int_t
ngx_http_flv_rtmp_init(ngx_conf_t *cf)
{
    ngx_rtmp_core_main_conf_t   *cmcf;
    ngx_rtmp_handler_pt         *h;

    cmcf = ngx_rtmp_conf_get_module_main_conf(cf, ngx_rtmp_core_module);

    /* register raw event handlers */

    h = ngx_array_push(&cmcf->events[NGX_RTMP_MSG_AUDIO]);
    *h = ngx_http_flv_av;

    h = ngx_array_push(&cmcf->events[NGX_RTMP_MSG_VIDEO]);
    *h = ngx_http_flv_av;

    h = ngx_array_push(&cmcf->events[NGX_RTMP_CONNECT_END]);
    *h = ngx_http_flv_connect_end;

    h = ngx_array_push(&cmcf->events[NGX_RTMP_PLAY_END]);
    *h = ngx_http_flv_play_end;

    h = ngx_array_push(&cmcf->events[NGX_RTMP_ON_MESSAGE]);
    *h = ngx_http_flv_message;

    /* chain handlers */

    next_play = ngx_rtmp_play;
    ngx_rtmp_play = ngx_http_flv_play;

    next_close_stream = ngx_rtmp_close_stream;
    ngx_rtmp_close_stream = ngx_http_flv_close_stream;

    return NGX_OK;
}
