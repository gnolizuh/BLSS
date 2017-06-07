
/*
 * Copyright (C) 2017 Gnolizuh
 */


#include "ngx_rtmp_gop_cache_module.h"
#include "ngx_rtmp_codec_module.h"
#include "ngx_rtmp_live_module.h"
#include "ngx_http_flv_module.h"


static ngx_rtmp_publish_pt              next_publish;
static ngx_rtmp_play_pt                 next_play;
static ngx_rtmp_close_stream_pt         next_close_stream;

static ngx_int_t ngx_rtmp_gop_cache_postconfiguration(ngx_conf_t *cf);
static void * ngx_rtmp_gop_cache_create_app_conf(ngx_conf_t *cf);
static char * ngx_rtmp_gop_cache_merge_app_conf(ngx_conf_t *cf, void *parent, void *child);

extern ngx_rtmp_send_handler_t ngx_rtmp_live_send_handler;
extern ngx_rtmp_send_handler_t ngx_http_flv_send_handler;

ngx_rtmp_send_handler_t *ngx_rtmp_send_handlers[] = {
    &ngx_rtmp_live_send_handler,
    &ngx_http_flv_send_handler
};


static ngx_command_t  ngx_rtmp_gop_cache_commands[] = {

    { ngx_string("gop_cache"),
      NGX_RTMP_MAIN_CONF|NGX_RTMP_SRV_CONF|NGX_RTMP_SVI_CONF|NGX_RTMP_APP_CONF|NGX_CONF_TAKE1,
      ngx_conf_set_flag_slot,
      NGX_RTMP_APP_CONF_OFFSET,
      offsetof(ngx_rtmp_gop_cache_app_conf_t, gop_cache),
      NULL },

    { ngx_string("gop_cache_count"),
      NGX_RTMP_MAIN_CONF|NGX_RTMP_SRV_CONF|NGX_RTMP_SVI_CONF|NGX_RTMP_APP_CONF|NGX_CONF_TAKE1,
      ngx_conf_set_num_slot,
      NGX_RTMP_APP_CONF_OFFSET,
      offsetof(ngx_rtmp_gop_cache_app_conf_t, gop_cache_count),
      NULL },

    { ngx_string("gop_max_count"),
      NGX_RTMP_MAIN_CONF|NGX_RTMP_SRV_CONF|NGX_RTMP_SVI_CONF|NGX_RTMP_APP_CONF|NGX_CONF_TAKE1,
      ngx_conf_set_num_slot,
      NGX_RTMP_APP_CONF_OFFSET,
      offsetof(ngx_rtmp_gop_cache_app_conf_t, gop_max_count),
      NULL },

    { ngx_string("gop_max_acount"),
      NGX_RTMP_MAIN_CONF|NGX_RTMP_SRV_CONF|NGX_RTMP_SVI_CONF|NGX_RTMP_APP_CONF|NGX_CONF_TAKE1,
      ngx_conf_set_num_slot,
      NGX_RTMP_APP_CONF_OFFSET,
      offsetof(ngx_rtmp_gop_cache_app_conf_t, gop_max_acount),
      NULL },

    { ngx_string("gop_max_vcount"),
      NGX_RTMP_MAIN_CONF|NGX_RTMP_SRV_CONF|NGX_RTMP_SVI_CONF|NGX_RTMP_APP_CONF|NGX_CONF_TAKE1,
      ngx_conf_set_num_slot,
      NGX_RTMP_APP_CONF_OFFSET,
      offsetof(ngx_rtmp_gop_cache_app_conf_t, gop_max_vcount),
      NULL },

      ngx_null_command
};


static ngx_rtmp_module_t  ngx_rtmp_gop_cache_module_ctx = {
    NULL,                                   /* preconfiguration */
    ngx_rtmp_gop_cache_postconfiguration,   /* postconfiguration */
    NULL,                                   /* create main configuration */
    NULL,                                   /* init main configuration */
    NULL,                                   /* create server configuration */
    NULL,                                   /* merge server configuration */
    NULL,                                   /* create service configuration */
    NULL,                                   /* merge service configuration */
    ngx_rtmp_gop_cache_create_app_conf,     /* create app configuration */
    ngx_rtmp_gop_cache_merge_app_conf       /* merge app configuration */
};


ngx_module_t  ngx_rtmp_gop_cache_module = {
    NGX_MODULE_V1,
    &ngx_rtmp_gop_cache_module_ctx,         /* module context */
    ngx_rtmp_gop_cache_commands,            /* module directives */
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
ngx_rtmp_gop_cache_create_app_conf(ngx_conf_t *cf)
{
    ngx_rtmp_gop_cache_app_conf_t      *gacf;

    gacf = ngx_pcalloc(cf->pool, sizeof(ngx_rtmp_gop_cache_app_conf_t));
    if (gacf == NULL) {
        return NULL;
    }

    gacf->gop_cache = NGX_CONF_UNSET;
    gacf->gop_cache_count = NGX_CONF_UNSET;
    gacf->gop_max_count = NGX_CONF_UNSET;
    gacf->gop_max_acount = NGX_CONF_UNSET;
    gacf->gop_max_vcount = NGX_CONF_UNSET;

    return gacf;
}


static char *
ngx_rtmp_gop_cache_merge_app_conf(ngx_conf_t *cf, void *parent, void *child)
{
    ngx_rtmp_gop_cache_app_conf_t *prev = parent;
    ngx_rtmp_gop_cache_app_conf_t *conf = child;

    ngx_conf_merge_value(conf->gop_cache, prev->gop_cache, 1);
    ngx_conf_merge_value(conf->gop_cache_count, prev->gop_cache_count, 1);
    ngx_conf_merge_value(conf->gop_max_count, prev->gop_max_count, 2048);
    ngx_conf_merge_value(conf->gop_max_acount, prev->gop_max_acount, 1024);
    ngx_conf_merge_value(conf->gop_max_vcount, prev->gop_max_vcount, 1024);

    return NGX_CONF_OK;
}


static ngx_rtmp_gop_frame_t *
ngx_rtmp_gop_alloc_frame(ngx_rtmp_session_t *s)
{
    ngx_rtmp_gop_cache_ctx_t       *ctx;
    ngx_rtmp_gop_frame_t           *frame;

    ctx = ngx_rtmp_get_module_ctx(s, ngx_rtmp_gop_cache_module);
    if (ctx == NULL) {
        return NULL;
    }

    if (ctx->free_frame) {
        frame = ctx->free_frame;
        ctx->free_frame = frame->next;
        return frame;
    }

    if (ctx->pool == NULL) {
        ctx->pool = ngx_create_pool(4096, s->connection->log);
    }

    frame = ngx_pcalloc(ctx->pool, sizeof(ngx_rtmp_gop_frame_t));

    return frame;
}


static ngx_rtmp_gop_frame_t *
ngx_rtmp_gop_free_frame(ngx_rtmp_session_t *s, ngx_rtmp_gop_frame_t *frame)
{
    ngx_rtmp_core_srv_conf_t       *cscf;
    ngx_rtmp_gop_cache_ctx_t       *ctx;

    cscf = ngx_rtmp_get_module_srv_conf(s, ngx_rtmp_core_module);
    if (cscf == NULL) {
        return NULL;
    }

    ctx = ngx_rtmp_get_module_ctx(s, ngx_rtmp_gop_cache_module);
    if (ctx == NULL) {
        return NULL;
    }

    if (frame->frame) {
        ngx_rtmp_free_shared_chain(cscf, frame->frame);
        frame->frame = NULL;
    }

    if (frame->h.type == NGX_RTMP_MSG_VIDEO) {
        -- ctx->video_frame_cnt;
    } else if (frame->h.type == NGX_RTMP_MSG_AUDIO) {
        -- ctx->audio_frame_cnt;
    }

    ngx_log_debug3(NGX_LOG_DEBUG_RTMP, s->connection->log, 0,
                   "gop free frame: type=%s video_frame_cnt=%uD audio_frame_cnt=%uD",
                   frame->h.type == NGX_RTMP_MSG_VIDEO ? "video" : "audio",
                   ctx->video_frame_cnt, ctx->audio_frame_cnt);

    return frame->next;
}


static ngx_int_t
ngx_rtmp_gop_link_frame(ngx_rtmp_session_t *s, ngx_rtmp_gop_frame_t *frame)
{
    ngx_rtmp_gop_cache_ctx_t       *ctx;
    ngx_rtmp_gop_cache_t           *cache;

    ctx = ngx_rtmp_get_module_ctx(s, ngx_rtmp_gop_cache_module);
    if (ctx == NULL) {
        return NGX_ERROR;
    }

    // get tail gop cache.
    cache = ctx->tail;
    if (cache == NULL) {
        return NGX_ERROR;
    }

    // tail link to this cache.
    if(cache->head == NULL) {
        cache->head = cache->tail = frame;
    } else {
        cache->tail->next = frame;
        cache->tail = frame;
    }

    if (frame->h.type == NGX_RTMP_MSG_VIDEO) {
        ++ ctx->video_frame_cnt;
        ++ cache->video_frame_cnt;

        ctx->audio_after_last_video_cnt = 0;
    } else if(frame->h.type == NGX_RTMP_MSG_AUDIO) {
        ++ ctx->audio_frame_cnt;
        ++ cache->audio_frame_cnt;
    }

    ngx_log_debug5(NGX_LOG_DEBUG_RTMP, s->connection->log, 0,
                   "gop link frame: type=%s "
                   "ctx->video_frame_cnt=%uD ctx->audio_frame_cnt=%uD"
                   "cache->video_frame_cnt=%uD cache->audio_frame_cnt=%uD",
                   frame->h.type == NGX_RTMP_MSG_VIDEO ? "video" : "audio",
                   ctx->video_frame_cnt, ctx->audio_frame_cnt,
                   cache->video_frame_cnt, cache->audio_frame_cnt);

    return NGX_OK;
}


static ngx_int_t
ngx_rtmp_gop_alloc_cache(ngx_rtmp_session_t *s)
{
    ngx_rtmp_codec_ctx_t           *codec_ctx;
    ngx_rtmp_core_srv_conf_t       *cscf;
    ngx_rtmp_gop_cache_ctx_t       *ctx;
    ngx_rtmp_gop_cache_t           *cache;

    ctx = ngx_rtmp_get_module_ctx(s, ngx_rtmp_gop_cache_module);
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

    if (ctx->free_cache != NULL) {
        cache = ctx->free_cache;
        ctx->free_cache = cache->next;

        ngx_memzero(cache, sizeof(ngx_rtmp_gop_cache_t));
    } else {
        if (ctx->pool == NULL) {
            ctx->pool = ngx_create_pool(4096, s->connection->log);
        }

        cache = ngx_pcalloc(ctx->pool, sizeof(ngx_rtmp_gop_cache_t));
        if (cache == NULL) {
            return NGX_ERROR;
        }
    }

    // save video seq header.
    if (codec_ctx->video_header != NULL) {
        cache->video_seq_header_data = ngx_rtmp_append_shared_bufs(cscf, NULL, codec_ctx->video_header);
    }

    // save audio seq header.
    if (codec_ctx->aac_header != NULL) {
        cache->audio_seq_header_data = ngx_rtmp_append_shared_bufs(cscf, NULL, codec_ctx->aac_header);
    }

    // save metadata.
    if (codec_ctx->meta != NULL && codec_ctx->meta_flv != NULL) {
        cache->meta_header  = codec_ctx->meta_header;
        cache->meta_version = codec_ctx->meta_version;
        cache->meta_data = ngx_rtmp_append_shared_bufs(cscf, NULL, codec_ctx->meta);
        cache->meta_data_flv = ngx_rtmp_append_shared_bufs(cscf, NULL, codec_ctx->meta_flv);
    }

    if (ctx->head == NULL) {
        ctx->tail = ctx->head = cache;
    } else {
        ctx->tail->next = cache;
        ctx->tail = cache;
    }

    ++ ctx->cache_count;

    ngx_log_debug1(NGX_LOG_DEBUG_RTMP, s->connection->log, 0,
                   "gop alloc cache: cache_count=%uD",
                   ctx->cache_count);

    return NGX_OK;
}


static ngx_rtmp_gop_cache_t *
ngx_rtmp_gop_free_cache(ngx_rtmp_session_t *s, ngx_rtmp_gop_cache_t *cache)
{
    ngx_rtmp_core_srv_conf_t       *cscf;
    ngx_rtmp_gop_cache_ctx_t       *ctx;
    ngx_rtmp_gop_frame_t           *frame;

    ctx = ngx_rtmp_get_module_ctx(s, ngx_rtmp_gop_cache_module);
    if (ctx == NULL) {
        return NULL;
    }

    cscf = ngx_rtmp_get_module_srv_conf(s, ngx_rtmp_core_module);
    if (cscf == NULL) {
        return NULL;
    }

    if (cache->video_seq_header_data) {
        ngx_rtmp_free_shared_chain(cscf, cache->video_seq_header_data);
        cache->video_seq_header_data = NULL;
    }

    if (cache->audio_seq_header_data) {
        ngx_rtmp_free_shared_chain(cscf, cache->audio_seq_header_data);
        cache->audio_seq_header_data = NULL;
    }

    if (cache->meta_data) {
        ngx_rtmp_free_shared_chain(cscf, cache->meta_data);
        cache->meta_data = NULL;
    }

    if (cache->meta_data_flv) {
        ngx_rtmp_free_shared_chain(cscf, cache->meta_data_flv);
        cache->meta_data_flv = NULL;
    }

    for (frame = cache->head; frame; frame = frame->next) {
        ngx_rtmp_gop_free_frame(s, frame);
    }

    cache->video_frame_cnt = 0;
    cache->audio_frame_cnt = 0;

    // recycle mem of gop frame
    cache->tail->next = ctx->free_frame;
    ctx->free_frame = cache->head;

    -- ctx->cache_count;

    ngx_log_debug1(NGX_LOG_DEBUG_RTMP, s->connection->log, 0,
                   "gop free cache: cache_count=%uD",
                   ctx->cache_count);

    return cache->next;
}


static void
ngx_rtmp_gop_cleanup(ngx_rtmp_session_t *s)
{
    ngx_rtmp_core_srv_conf_t       *cscf;
    ngx_rtmp_gop_cache_ctx_t       *ctx;
    ngx_rtmp_gop_cache_t           *cache;

    ctx = ngx_rtmp_get_module_ctx(s, ngx_rtmp_gop_cache_module);
    if (ctx == NULL) {
        return;
    }

    cscf = ngx_rtmp_get_module_srv_conf(s, ngx_rtmp_core_module);
    if (cscf == NULL) {
        return;
    }

    for (cache = ctx->head; cache; cache = cache->next) {
        ngx_rtmp_gop_free_cache(s, cache);
    }

    if (ctx->pool != NULL) {
        ngx_destroy_pool(ctx->pool);
        ctx->pool = NULL;
    }

    ctx->tail = ctx->head = NULL;
    ctx->free_cache = NULL;
    ctx->free_frame = NULL;
    ctx->cache_count = 0;
    ctx->video_frame_cnt = 0;
    ctx->audio_frame_cnt = 0;
    ctx->audio_after_last_video_cnt = 0;
}


static void
ngx_rtmp_gop_cache_update(ngx_rtmp_session_t *s)
{
    ngx_rtmp_gop_cache_app_conf_t *gacf;
    ngx_rtmp_gop_cache_ctx_t      *ctx;
    ngx_rtmp_gop_cache_t          *next;

    gacf = ngx_rtmp_get_module_app_conf(s, ngx_rtmp_gop_cache_module);
    if (gacf == NULL) {
        return;
    }

    ctx = ngx_rtmp_get_module_ctx(s, ngx_rtmp_gop_cache_module);
    if (ctx == NULL) {
        return;
    }

    while (ctx->cache_count > (ngx_uint_t) gacf->gop_cache_count) {

        if (ctx->head) {

            /* remove 1'st gop of link list. */
            next = ngx_rtmp_gop_free_cache(s, ctx->head);

            ctx->head->next = ctx->free_cache;
            ctx->free_cache = ctx->head;

            ctx->head = next;
        } else {

            ngx_rtmp_gop_cleanup(s);
        }
    }
}


static void
ngx_rtmp_gop_cache_frame(ngx_rtmp_session_t *s, ngx_uint_t prio, ngx_rtmp_header_t *ch, ngx_chain_t *frame)
{
    ngx_rtmp_gop_cache_ctx_t       *ctx;
    ngx_rtmp_codec_ctx_t           *codec_ctx;
    ngx_rtmp_core_srv_conf_t       *cscf;
    ngx_rtmp_gop_cache_app_conf_t  *gacf;
    ngx_rtmp_gop_frame_t           *gop_frame;

    gacf = ngx_rtmp_get_module_app_conf(s, ngx_rtmp_gop_cache_module);
    if (gacf == NULL || !gacf->gop_cache) {
        return;
    }

    cscf = ngx_rtmp_get_module_srv_conf(s, ngx_rtmp_core_module);
    if (cscf == NULL) {
        return;
    }

    ctx = ngx_rtmp_get_module_ctx(s, ngx_rtmp_gop_cache_module);
    if (ctx == NULL) {
        return;
    }

    codec_ctx = ngx_rtmp_get_module_ctx(s, ngx_rtmp_codec_module);
    if (codec_ctx == NULL) {
        return;
    }

    if (ch->type == NGX_RTMP_MSG_VIDEO) {

        // drop video when not h.264 or h.265
        if (codec_ctx->video_codec_id != NGX_RTMP_VIDEO_H264 &&
            codec_ctx->video_codec_id != NGX_RTMP_VIDEO_H265) {

            return;
        }

        // drop non-key-video when 1'st keyframe wasn't arrived
        if (prio != NGX_RTMP_VIDEO_KEY_FRAME &&
            ctx->head == NULL) {

            ngx_log_debug1(NGX_LOG_DEBUG_RTMP, s->connection->log, 0,
                          "drop video non-keyframe timestamp='%uD'",
                          ch->timestamp);
            return;
        }
    }

    // pure audio?
    if (ctx->video_frame_cnt == 0 &&
        ch->type == NGX_RTMP_MSG_AUDIO) {
        return;
    }

    if (ch->type == NGX_RTMP_MSG_AUDIO) {
        ctx->audio_after_last_video_cnt ++;
    }

    if (ctx->audio_after_last_video_cnt > NGX_RTMP_LIVE_PURE_AUDIO_GUESS_CNT) {
        ngx_rtmp_gop_cleanup(s);
        return;
    }

    if (ch->type == NGX_RTMP_MSG_VIDEO && prio == NGX_RTMP_VIDEO_KEY_FRAME) {
        if (ngx_rtmp_gop_alloc_cache(s) != NGX_OK) {
            return;
        }
    }

    gop_frame = ngx_rtmp_gop_alloc_frame(s);
    if (gop_frame == NULL) {
        return;
    }

    gop_frame->h = *ch;
    gop_frame->prio = prio;
    gop_frame->next = NULL;
    gop_frame->frame = ngx_rtmp_append_shared_bufs(cscf, NULL, frame);

    if (ngx_rtmp_gop_link_frame(s, gop_frame) != NGX_OK) {
        ngx_rtmp_free_shared_chain(cscf, gop_frame->frame);
        return;
    }

    if (ctx->video_frame_cnt > (ngx_uint_t) gacf->gop_max_vcount ||
        ctx->audio_frame_cnt > (ngx_uint_t) gacf->gop_max_acount ||
        (ctx->video_frame_cnt + ctx->audio_frame_cnt) > (ngx_uint_t) gacf->gop_max_count) {
        ngx_rtmp_gop_cleanup(s);
        return;
    }

    ngx_rtmp_gop_cache_update(s);

    ngx_log_debug2(NGX_LOG_DEBUG_RTMP, s->connection->log, 0,
               "gop cache: cache packet type='%s' timestamp='%uD'",
               gop_frame->h.type == NGX_RTMP_MSG_AUDIO ? "audio" : "video",
               gop_frame->h.timestamp);
}


static void
ngx_rtmp_gop_cache_send(ngx_rtmp_session_t *ss)
{
    ngx_rtmp_session_t             *s;
    ngx_chain_t                    *pkt, *apkt, *meta, *header;
    ngx_rtmp_live_ctx_t            *ctx, *pctx;
    ngx_rtmp_gop_cache_ctx_t       *gctx;
    ngx_rtmp_live_app_conf_t       *lacf;
    ngx_rtmp_gop_cache_t           *cache;
    ngx_rtmp_gop_frame_t           *gop_frame;
    ngx_rtmp_send_handler_t        *handler;
    ngx_rtmp_header_t               ch, lh;
    ngx_uint_t                      meta_version;
    uint32_t                        delta;
    ngx_int_t                       csidx;
    ngx_rtmp_live_chunk_stream_t   *cs;

    lacf = ngx_rtmp_get_module_app_conf(ss, ngx_rtmp_live_module);
    if (lacf == NULL) {
        return;
    }

    ctx = ngx_rtmp_get_module_ctx(ss, ngx_rtmp_live_module);
    if (ctx == NULL || ctx->stream == NULL ||
        ctx->stream->pctx == NULL || !ctx->stream->publishing) {
        return;
    }

    pkt = NULL;
    apkt = NULL;
    meta = NULL;
    header = NULL;
    meta_version = 0;

    s = ctx->stream->pctx->session;

    gctx = ngx_rtmp_get_module_ctx(s, ngx_rtmp_gop_cache_module);
    if (gctx == NULL) {
        return;
    }

    pctx = ctx->stream->pctx;

    handler = ngx_rtmp_send_handlers[ss->proto == NGX_PROTO_TYPE_HTTP_FLV_PULL ? 1 : 0];

    for (cache = gctx->head; cache; cache = cache->next) {

        meta = (ss->proto == NGX_PROTO_TYPE_HTTP_FLV_PULL ? cache->meta_data_flv : cache->meta_data);
        if (meta) {
            meta_version = cache->meta_version;
        }

        /* send metadata */
        if (meta && meta_version != ctx->meta_version) {
            ngx_log_debug0(NGX_LOG_DEBUG_RTMP, ss->connection->log, 0,
                           "gop cache send: meta");

            if (handler->send_message(ss, meta, 0) == NGX_OK) {
                ctx->meta_version = meta_version;
            }
        }

        for (gop_frame = cache->head; gop_frame; gop_frame = gop_frame->next) {
            csidx = !(lacf->interleave || gop_frame->h.type == NGX_RTMP_MSG_VIDEO);

            cs = &ctx->cs[csidx];

            lh = ch = gop_frame->h;

            if (cs->active) {
                lh.timestamp = cs->timestamp;
            }

            delta = ch.timestamp - lh.timestamp;

            if (!cs->active) {

                header = gop_frame->h.type == NGX_RTMP_MSG_VIDEO ? cache->video_seq_header_data : cache->audio_seq_header_data;
                if (header) {
                    apkt = handler->append_shared_bufs(s, &lh, NULL, header);
                }

                if (apkt && handler->send_message(ss, apkt, 0) == NGX_OK) {
                    cs->timestamp = lh.timestamp;
                    cs->active = 1;
                    ss->current_time = cs->timestamp;
                }

                if (apkt) {
                    handler->free_shared_chain(ss, apkt);
                    apkt = NULL;
                }
            }

            pkt = handler->append_shared_bufs(s, &ch, &lh, gop_frame->frame);
            if (handler->send_message(ss, pkt, gop_frame->prio) != NGX_OK) {
                ++pctx->ndropped;

                cs->dropped += delta;

                return;
            }

            if (pkt) {
                handler->free_shared_chain(ss, pkt);
                pkt = NULL;
            }

            ngx_log_debug3(NGX_LOG_DEBUG_RTMP, ss->connection->log, 0,
                           "gop cache send: tag type='%s' prio='%d' ltimestamp='%uD'",
                           gop_frame->h.type == NGX_RTMP_MSG_AUDIO ? "audio" : "video",
                           gop_frame->prio,
                           lh.timestamp);

            cs->timestamp += delta;
            ss->current_time = cs->timestamp;
        }
    }
}


static ngx_int_t
ngx_rtmp_gop_cache_av(ngx_rtmp_session_t *s, ngx_rtmp_header_t *h,
                      ngx_chain_t *in)
{
    ngx_rtmp_live_ctx_t            *ctx;
    ngx_rtmp_gop_cache_app_conf_t  *gacf;
    ngx_rtmp_live_app_conf_t       *lacf;
    ngx_rtmp_header_t               ch;
    ngx_uint_t                      prio;
    ngx_uint_t                      csidx;
    ngx_rtmp_live_chunk_stream_t   *cs;

    gacf = ngx_rtmp_get_module_app_conf(s, ngx_rtmp_gop_cache_module);
    if (gacf == NULL || !gacf->gop_cache) {
        return NGX_OK;
    }

    lacf = ngx_rtmp_get_module_app_conf(s, ngx_rtmp_live_module);
    if (lacf == NULL) {
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
        return NGX_OK;
    }

    prio = (h->type == NGX_RTMP_MSG_VIDEO ?
            ngx_rtmp_get_video_frame_type(in) : 0);

    csidx = !(lacf->interleave || h->type == NGX_RTMP_MSG_VIDEO);

    cs = &ctx->cs[csidx];

    ngx_memzero(&ch, sizeof(ch));

    ch.timestamp = h->timestamp;
    ch.msid = NGX_RTMP_MSID;
    ch.csid = cs->csid;
    ch.type = h->type;

    ngx_rtmp_gop_cache_frame(s, prio, &ch, in);

    return NGX_OK;
}


static ngx_int_t
ngx_rtmp_gop_cache_publish(ngx_rtmp_session_t *s, ngx_rtmp_publish_t *v)
{
    ngx_rtmp_gop_cache_app_conf_t  *gacf;
    ngx_rtmp_gop_cache_ctx_t       *ctx;

    gacf = ngx_rtmp_get_module_app_conf(s, ngx_rtmp_gop_cache_module);
    if (gacf == NULL || !gacf->gop_cache) {
        goto next;
    }

    ngx_log_error(NGX_LOG_INFO, s->connection->log, 0,
                  "gop cache publish: name='%s' type='%s'",
                  v->name, v->type);

    ctx = ngx_rtmp_get_module_ctx(s, ngx_rtmp_gop_cache_module);
    if (ctx == NULL) {
        ctx = ngx_palloc(s->connection->pool, sizeof(ngx_rtmp_gop_cache_ctx_t));
        ngx_rtmp_set_ctx(s, ctx, ngx_rtmp_gop_cache_module);
    }

    ngx_memzero(ctx, sizeof(*ctx));

next:
    return next_publish(s, v);
}


static ngx_int_t
ngx_rtmp_gop_cache_play(ngx_rtmp_session_t *s, ngx_rtmp_play_t *v)
{
    ngx_rtmp_gop_cache_app_conf_t  *gacf;

    gacf = ngx_rtmp_get_module_app_conf(s, ngx_rtmp_gop_cache_module);
    if (gacf == NULL || !gacf->gop_cache) {
        goto next;
    }

    ngx_log_error(NGX_LOG_INFO, s->connection->log, 0,
                  "gop cache play: name='%s' start=%uD duration=%uD reset=%d",
                  v->name, (uint32_t) v->start,
                  (uint32_t) v->duration, (uint32_t) v->reset);

    ngx_rtmp_gop_cache_send(s);

next:
    return next_play(s, v);
}


static ngx_int_t
ngx_rtmp_gop_cache_close_stream(ngx_rtmp_session_t *s, ngx_rtmp_close_stream_t *v)
{
    ngx_rtmp_live_ctx_t            *ctx;
    ngx_rtmp_live_app_conf_t       *lacf;
    ngx_rtmp_gop_cache_app_conf_t  *gacf;

    ctx = ngx_rtmp_get_module_ctx(s, ngx_rtmp_live_module);
    if (ctx == NULL || ctx->stream == NULL) {
        goto next;
    }

    if (ctx->publishing == 0) {
        goto next;
    }

    lacf = ngx_rtmp_get_module_app_conf(s, ngx_rtmp_live_module);
    if (lacf == NULL || !lacf->live) {
        goto next;
    }

    gacf = ngx_rtmp_get_module_app_conf(s, ngx_rtmp_gop_cache_module);
    if (gacf == NULL || !gacf->gop_cache) {
        goto next;
    }

    ngx_rtmp_gop_cleanup(s);

next:
    return next_close_stream(s, v);
}


static ngx_int_t
ngx_rtmp_gop_cache_postconfiguration(ngx_conf_t *cf)
{
    ngx_rtmp_core_main_conf_t          *cmcf;
    ngx_rtmp_handler_pt                *h;

    cmcf = ngx_rtmp_conf_get_module_main_conf(cf, ngx_rtmp_core_module);

    /* register raw event handlers */

    h = ngx_array_push(&cmcf->events[NGX_RTMP_MSG_AUDIO]);
    *h = ngx_rtmp_gop_cache_av;

    h = ngx_array_push(&cmcf->events[NGX_RTMP_MSG_VIDEO]);
    *h = ngx_rtmp_gop_cache_av;

    next_publish = ngx_rtmp_publish;
    ngx_rtmp_publish = ngx_rtmp_gop_cache_publish;

    next_play = ngx_rtmp_play;
    ngx_rtmp_play = ngx_rtmp_gop_cache_play;

    next_close_stream = ngx_rtmp_close_stream;
    ngx_rtmp_close_stream = ngx_rtmp_gop_cache_close_stream;

    return NGX_OK;
}
