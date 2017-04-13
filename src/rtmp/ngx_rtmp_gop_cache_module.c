
/*
 * Copyright (C) Gnolizuh
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


extern ngx_rtmp_gop_cache_handler_t ngx_rtmp_gop_cache_handler;
extern ngx_rtmp_gop_cache_handler_t ngx_http_flv_gop_cache_handler;

ngx_rtmp_gop_cache_handler_t *ngx_rtmp_gop_cache_send_handler[] = {
    &ngx_rtmp_gop_cache_handler,
    &ngx_http_flv_gop_cache_handler
};


static ngx_command_t  ngx_rtmp_gop_cache_commands[] = {

    { ngx_string("gop_cache"),
      NGX_RTMP_MAIN_CONF|NGX_RTMP_SRV_CONF|NGX_RTMP_APP_CONF|NGX_CONF_TAKE1,
      ngx_conf_set_flag_slot,
      NGX_RTMP_APP_CONF_OFFSET,
      offsetof(ngx_rtmp_gop_cache_app_conf_t, gop_cache),
      NULL },

    { ngx_string("gop_cache_mintime"),
      NGX_RTMP_MAIN_CONF|NGX_RTMP_SRV_CONF|NGX_RTMP_APP_CONF|NGX_CONF_TAKE1,
      ngx_conf_set_msec_slot,
      NGX_RTMP_APP_CONF_OFFSET,
      offsetof(ngx_rtmp_gop_cache_app_conf_t, gop_cache_mintime),
      NULL },

    { ngx_string("gop_cache_maxtime"),
      NGX_RTMP_MAIN_CONF|NGX_RTMP_SRV_CONF|NGX_RTMP_APP_CONF|NGX_CONF_TAKE1,
      ngx_conf_set_msec_slot,
      NGX_RTMP_APP_CONF_OFFSET,
      offsetof(ngx_rtmp_gop_cache_app_conf_t, gop_cache_maxtime),
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
    gacf->gop_cache_mintime = NGX_CONF_UNSET_MSEC;
    gacf->gop_cache_maxtime = NGX_CONF_UNSET_MSEC;

    return gacf;
}


static char *
ngx_rtmp_gop_cache_merge_app_conf(ngx_conf_t *cf, void *parent, void *child)
{
    ngx_rtmp_gop_cache_app_conf_t *prev = parent;
    ngx_rtmp_gop_cache_app_conf_t *conf = child;

    ngx_conf_merge_value(conf->gop_cache, prev->gop_cache, 0);
    ngx_conf_merge_msec_value(conf->gop_cache_mintime, prev->gop_cache_mintime, 0);
    ngx_conf_merge_msec_value(conf->gop_cache_maxtime, prev->gop_cache_maxtime, NGX_RTMP_LIVE_PER_GOP_MAX_TIME);

    return NGX_CONF_OK;
}


static ngx_msec_t
ngx_rtmp_gop_cache_audio_duration(ngx_uint_t audio_cnt,
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
ngx_rtmp_gop_cache_video_duration(ngx_uint_t video_cnt,
                                  ngx_rtmp_live_frame_rate_t video_frame_rate)
{
    ngx_msec_t interval;

    interval = video_frame_rate.fps > 0
                ? video_cnt * 1000 * 1000 / video_frame_rate.fps
                : 0;

    return interval;
}


ngx_rtmp_gop_frame_t *
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


ngx_rtmp_gop_frame_t *
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

    return frame->next;
}


ngx_int_t
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

    return NGX_OK;
}


ngx_int_t
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
    if (codec_ctx->meta != NULL) {
        cache->meta_header  = codec_ctx->meta_header;
        cache->meta_version = codec_ctx->meta_version;
        cache->meta_data = ngx_rtmp_append_shared_bufs(cscf, NULL, codec_ctx->meta_orig);
        cache->meta_data_flv = ngx_http_flv_append_shared_bufs(cscf, &codec_ctx->meta_header, codec_ctx->meta_orig);

        ngx_rtmp_prepare_message(s, &codec_ctx->meta_header, NULL, cache->meta_data);
    }

    if (ctx->head == NULL) {
        ctx->tail = ctx->head = cache;
    } else {
        ctx->tail->next = cache;
        ctx->tail = cache;
    }

    ++ ctx->cache_cnt;

    return NGX_OK;
}


ngx_rtmp_gop_cache_t *
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

    // recycle mem of gop frame
    cache->tail->next = ctx->free_frame;
    ctx->free_frame = cache->head;

    -- ctx->cache_cnt;

    return cache->next;
}


void
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
    ctx->cache_cnt = 0;
    ctx->video_frame_cnt = 0;
    ctx->audio_frame_cnt = 0;
    ctx->audio_after_last_video_cnt = 0;
}


void
ngx_rtmp_gop_update(ngx_rtmp_session_t *s)
{
    ngx_rtmp_gop_cache_app_conf_t *gacf;
    ngx_rtmp_gop_cache_ctx_t      *ctx;
    ngx_rtmp_live_ctx_t           *lctx;
    ngx_rtmp_codec_ctx_t          *codec_ctx;
    ngx_msec_t                     max_time;
    ngx_msec_t                     catime, cvtime; // whole time duration in gop.
    ngx_msec_t                     dvtime, datime; // time duration expect first gop.
    ngx_msec_t                     rvtime, ratime, rtime; //remained duration after delete
    ngx_msec_t                     gop_cache_mintime;
    ngx_msec_t                     gop_cache_maxtime;
    ngx_rtmp_gop_clean_t           clean_status;
    ngx_rtmp_gop_cache_t          *next;

#if(NGX_DEBUG)
    ngx_rtmp_gop_cache_t          *cache;
#endif

    gacf = ngx_rtmp_get_module_app_conf(s, ngx_rtmp_gop_cache_module);
    if (gacf == NULL || gacf->gop_cache == 0) {
        return;
    }

    codec_ctx = ngx_rtmp_get_module_ctx(s, ngx_rtmp_codec_module);
    if (codec_ctx == NULL) {
        return;
    }

    lctx = ngx_rtmp_get_module_ctx(s, ngx_rtmp_live_module);
    if (lctx == NULL) {
        return;
    }

    ctx = ngx_rtmp_get_module_ctx(s, ngx_rtmp_gop_cache_module);
    if (ctx == NULL) {
        return;
    }

    gop_cache_mintime = gacf->gop_cache_mintime;
    gop_cache_maxtime = gacf->gop_cache_maxtime;

    clean_status = NGX_RTMP_GOP_CLEAN_NO;

    do {
        // each time remove one gop
        if (clean_status != NGX_RTMP_GOP_CLEAN_NO) {
#if(NGX_DEBUG)
            cache = ctx->head;
#endif
            next = ngx_rtmp_gop_free_cache(s, ctx->head);

            ctx->head->next = ctx->free_cache;
            ctx->free_cache = ctx->head;

            ctx->head = next;

            ngx_log_debug8(NGX_LOG_DEBUG_RTMP, s->connection->log, 0,
                          "clean_status:%uD,"
                          "freed video cnt %uD, time %uD, remained video cnt %D,"
                          "freed audio cnt %uD, time %uD, remained audio cnt %D,"
                          "remain gop cnt %uD",
                          clean_status,
                          cache->video_frame_cnt, dvtime, ctx->video_frame_cnt,
                          cache->audio_frame_cnt, datime, ctx->audio_frame_cnt,
                          ctx->cache_cnt);

            clean_status = NGX_RTMP_GOP_CLEAN_NO;
        }

        if (ctx->head == NULL) {
            ngx_rtmp_gop_cleanup(s);
            break;
        }

        catime = ngx_rtmp_gop_cache_audio_duration(
                              ctx->audio_frame_cnt,
                              codec_ctx->audio_codec_id,
                              codec_ctx->sample_rate);

        cvtime = ngx_rtmp_gop_cache_video_duration(
                              ctx->video_frame_cnt,
                              lctx->stream->video_frame_rate);

        max_time = ngx_max(catime, cvtime);

        datime = ngx_rtmp_gop_cache_audio_duration(
                              ctx->head->audio_frame_cnt,
                              codec_ctx->audio_codec_id,
                              codec_ctx->sample_rate);

        dvtime = ngx_rtmp_gop_cache_video_duration(
                              ctx->head->video_frame_cnt,
                              lctx->stream->video_frame_rate);

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
                          cvtime, ctx->video_frame_cnt,
                          catime, ctx->audio_frame_cnt,
                          ctx->cache_cnt);

    } while (clean_status);
}


void
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

    ngx_rtmp_gop_update(s);

    ngx_log_debug2(NGX_LOG_DEBUG_RTMP, s->connection->log, 0,
               "gop_cache: cache packet type='%s' timestamp='%uD'",
               gop_frame->h.type == NGX_RTMP_MSG_AUDIO ? "audio" : "video",
               gop_frame->h.timestamp);
}


static void
ngx_rtmp_gop_cache_send(ngx_rtmp_session_t *ss)
{
    ngx_rtmp_session_t             *s;
    ngx_chain_t                    *pkt, *apkt, *meta, *header;
    ngx_rtmp_live_ctx_t            *pctx, *publisher, *player;
    ngx_rtmp_gop_cache_ctx_t       *gctx;
    ngx_rtmp_core_srv_conf_t       *cscf;
    ngx_rtmp_live_app_conf_t       *lacf;
    ngx_rtmp_gop_cache_app_conf_t  *gacf;
    ngx_rtmp_gop_cache_t           *cache;
    ngx_rtmp_gop_frame_t           *gop_frame;
    ngx_rtmp_gop_cache_handler_t   *handler;
    ngx_rtmp_header_t               ch, lh;
    ngx_uint_t                      meta_version;
    uint32_t                        delta;
    ngx_int_t                       csidx;
    ngx_rtmp_live_chunk_stream_t   *cs;

    lacf = ngx_rtmp_get_module_app_conf(ss, ngx_rtmp_live_module);
    if (lacf == NULL) {
        return;
    }

    gacf = ngx_rtmp_get_module_app_conf(ss, ngx_rtmp_gop_cache_module);
    if (gacf == NULL) {
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

    gctx = ngx_rtmp_get_module_ctx(s, ngx_rtmp_gop_cache_module);
    if (gctx == NULL) {
        return;
    }

    handler = ngx_rtmp_gop_cache_send_handler[ss->protocol == NGX_RTMP_PULL_TYPE_HDL ? 1 : 0];

    if (!gacf->gop_cache) {
        return;
    }

    for (cache = gctx->head; cache; cache = cache->next) {

        if (cache->meta_data) {
            meta = cache->meta_data;
            meta_version = cache->meta_version;
        }

        /* send metadata */
        if (meta && meta_version != player->meta_version) {
            ngx_log_debug0(NGX_LOG_DEBUG_RTMP, ss->connection->log, 0,
                           "live: meta");

            if (handler->send_message(ss, meta, 0) == NGX_OK) {
                player->meta_version = meta_version;
            }
        }

        for (gop_frame = cache->head; gop_frame; gop_frame = gop_frame->next) {
            csidx = !(lacf->interleave || gop_frame->h.type == NGX_RTMP_MSG_VIDEO);

            cs = &player->cs[csidx];

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
                           "gop_send: send tag type='%s' prio='%d' ltimestamp='%uD'",
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
    ngx_rtmp_live_app_conf_t       *lacf;
    ngx_rtmp_header_t               ch;
    ngx_uint_t                      prio;
    ngx_uint_t                      csidx;
    ngx_rtmp_live_chunk_stream_t   *cs;

    lacf = ngx_rtmp_get_module_app_conf(s, ngx_rtmp_live_module);
    if (lacf == NULL) {
        return NGX_ERROR;
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

    ngx_log_debug2(NGX_LOG_DEBUG_RTMP, s->connection->log, 0,
                   "gop_cache: publish: name='%s' type='%s'",
                   v->name, v->type);

    ctx = ngx_rtmp_get_module_ctx(s, ngx_rtmp_gop_cache_module);
    if (ctx == NULL) {
        ctx = ngx_palloc(s->connection->pool, sizeof(ngx_rtmp_gop_cache_ctx_t));
        ngx_rtmp_set_ctx(s, ctx, ngx_rtmp_gop_cache_module);
    }

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

    ngx_log_debug4(NGX_LOG_DEBUG_RTMP, s->connection->log, 0,
                   "gop_cache: play: name='%s' start=%uD duration=%uD reset=%d",
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
