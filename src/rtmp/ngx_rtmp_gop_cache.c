
/*
 * Copyright (C) Gnolizuh
 */


#include "ngx_rtmp_gop_cache.h"
#include "ngx_rtmp_codec_module.h"
#include "ngx_rtmp_live_module.h"


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
    ngx_rtmp_live_ctx_t            *ctx;
    ngx_rtmp_gop_cache_ctx_t       *gop_cache_ctx;
    ngx_rtmp_gop_frame_t           *frame;

    ctx = ngx_rtmp_get_module_ctx(s, ngx_rtmp_live_module);
    if (ctx == NULL) {
        return NULL;
    }

    gop_cache_ctx = &ctx->gop_cache_ctx;

    if (gop_cache_ctx->free_frame) {
        frame = gop_cache_ctx->free_frame;
        gop_cache_ctx->free_frame = frame->next;
        return frame;
    }

    if (gop_cache_ctx->pool == NULL) {
        gop_cache_ctx->pool = ngx_create_pool(4096, s->connection->log);
    }

    frame = ngx_pcalloc(gop_cache_ctx->pool, sizeof(ngx_rtmp_gop_frame_t));

    return frame;
}


ngx_rtmp_gop_frame_t *
ngx_rtmp_gop_free_frame(ngx_rtmp_session_t *s, ngx_rtmp_gop_frame_t *frame)
{
    ngx_rtmp_core_srv_conf_t       *cscf;
    ngx_rtmp_live_ctx_t            *ctx;
    ngx_rtmp_gop_cache_ctx_t       *gop_cache_ctx;

    cscf = ngx_rtmp_get_module_srv_conf(s, ngx_rtmp_core_module);
    if (cscf == NULL) {
        return NULL;
    }

    ctx = ngx_rtmp_get_module_ctx(s, ngx_rtmp_live_module);
    if (ctx == NULL) {
        return NULL;
    }

    gop_cache_ctx = &ctx->gop_cache_ctx;

    if (frame->frame) {
        ngx_rtmp_free_shared_chain(cscf, frame->frame);
        frame->frame = NULL;
    }

    if (frame->h.type == NGX_RTMP_MSG_VIDEO) {
        -- gop_cache_ctx->video_frame_cnt;
    } else if (frame->h.type == NGX_RTMP_MSG_AUDIO) {
        -- gop_cache_ctx->audio_frame_cnt;
    }

    return frame->next;
}


ngx_int_t
ngx_rtmp_gop_link_frame(ngx_rtmp_session_t *s, ngx_rtmp_gop_frame_t *frame)
{
    ngx_rtmp_live_ctx_t            *ctx;
    ngx_rtmp_gop_cache_ctx_t       *gop_cache_ctx;
    ngx_rtmp_gop_cache_t           *cache;

    ctx = ngx_rtmp_get_module_ctx(s, ngx_rtmp_live_module);
    if (ctx == NULL) {
        return NGX_ERROR;
    }

    gop_cache_ctx = &ctx->gop_cache_ctx;

    // get tail gop cache.
    cache = gop_cache_ctx->tail;
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
        ++ gop_cache_ctx->video_frame_cnt;
        ++ cache->video_frame_cnt;

        gop_cache_ctx->audio_after_last_video_cnt = 0;
    } else if(frame->h.type == NGX_RTMP_MSG_AUDIO) {
        ++ gop_cache_ctx->audio_frame_cnt;
        ++ cache->audio_frame_cnt;
    }

    return NGX_OK;
}


ngx_int_t
ngx_rtmp_gop_alloc_cache(ngx_rtmp_session_t *s)
{
    ngx_rtmp_live_ctx_t            *ctx;
    ngx_rtmp_codec_ctx_t           *codec_ctx;
    ngx_rtmp_core_srv_conf_t       *cscf;
    ngx_rtmp_gop_cache_ctx_t       *gop_cache_ctx;
    ngx_rtmp_gop_cache_t           *cache;
    u_char                         *pos;
    ngx_chain_t                    *meta;

    ctx = ngx_rtmp_get_module_ctx(s, ngx_rtmp_live_module);
    if (ctx == NULL) {
        return NGX_ERROR;
    }

    gop_cache_ctx = &ctx->gop_cache_ctx;

    codec_ctx = ngx_rtmp_get_module_ctx(s, ngx_rtmp_codec_module);
    if (codec_ctx == NULL) {
        return NGX_ERROR;
    }

    cscf = ngx_rtmp_get_module_srv_conf(s, ngx_rtmp_core_module);
    if (cscf == NULL) {
        return NGX_ERROR;
    }

    if (gop_cache_ctx->free_cache != NULL) {
        cache = gop_cache_ctx->free_cache;
        gop_cache_ctx->free_cache = cache->next;

        ngx_memzero(cache, sizeof(ngx_rtmp_gop_cache_t));
    } else {
        if (gop_cache_ctx->pool == NULL) {
            gop_cache_ctx->pool = ngx_create_pool(4096, s->connection->log);
        }

        cache = ngx_pcalloc(gop_cache_ctx->pool, sizeof(ngx_rtmp_gop_cache_t));
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
        cache->meta_header  = codec_ctx->metah;
        cache->meta_version = codec_ctx->meta_version;

        meta = codec_ctx->meta;
        pos = meta->buf->pos;
        meta->buf->pos = meta->buf->start + NGX_RTMP_MAX_CHUNK_HEADER;

        cache->meta_data = ngx_rtmp_append_shared_bufs(cscf, NULL, meta);

        meta->buf->pos = pos;

        ngx_rtmp_prepare_message(s, &codec_ctx->metah, NULL, cache->meta_data);
    }

    if (gop_cache_ctx->head == NULL) {
        gop_cache_ctx->tail = gop_cache_ctx->head = cache;
    } else {
        gop_cache_ctx->tail->next = cache;
        gop_cache_ctx->tail = cache;
    }

    ++ gop_cache_ctx->cache_cnt;

    return NGX_OK;
}


ngx_rtmp_gop_cache_t *
ngx_rtmp_gop_free_cache(ngx_rtmp_session_t *s, ngx_rtmp_gop_cache_t *cache)
{
    ngx_rtmp_core_srv_conf_t       *cscf;
    ngx_rtmp_live_ctx_t            *ctx;
    ngx_rtmp_gop_cache_ctx_t       *gop_cache_ctx;
    ngx_rtmp_gop_frame_t           *frame;

    ctx = ngx_rtmp_get_module_ctx(s, ngx_rtmp_live_module);
    if (ctx == NULL) {
        return NULL;
    }

    gop_cache_ctx = &ctx->gop_cache_ctx;

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

    for (frame = cache->head; frame; frame = frame->next) {
        ngx_rtmp_gop_free_frame(s, frame);
    }

    // recycle mem of gop frame
    cache->tail->next = gop_cache_ctx->free_frame;
    gop_cache_ctx->free_frame = cache->head;

    -- gop_cache_ctx->cache_cnt;

    return cache->next;
}


void
ngx_rtmp_gop_cleanup(ngx_rtmp_session_t *s)
{
    ngx_rtmp_live_ctx_t            *ctx;
    ngx_rtmp_core_srv_conf_t       *cscf;
    ngx_rtmp_gop_cache_ctx_t       *gop_cache_ctx;
    ngx_rtmp_gop_cache_t           *cache;

    ctx = ngx_rtmp_get_module_ctx(s, ngx_rtmp_live_module);
    if (ctx == NULL) {
        return;
    }

    gop_cache_ctx = &ctx->gop_cache_ctx;

    cscf = ngx_rtmp_get_module_srv_conf(s, ngx_rtmp_core_module);
    if (cscf == NULL) {
        return;
    }

    for (cache = gop_cache_ctx->head; cache; cache = cache->next) {
        ngx_rtmp_gop_free_cache(s, cache);
    }

    if (gop_cache_ctx->pool != NULL) {
        ngx_destroy_pool(gop_cache_ctx->pool);
        gop_cache_ctx->pool = NULL;
    }

    gop_cache_ctx->tail = gop_cache_ctx->head = NULL;
    gop_cache_ctx->free_cache = NULL;
    gop_cache_ctx->free_frame = NULL;
    gop_cache_ctx->cache_cnt = 0;
    gop_cache_ctx->video_frame_cnt = 0;
    gop_cache_ctx->audio_frame_cnt = 0;
    gop_cache_ctx->audio_after_last_video_cnt = 0;
}


void
ngx_rtmp_gop_update(ngx_rtmp_session_t *s)
{
    ngx_rtmp_live_app_conf_t   *lacf;
    ngx_rtmp_live_ctx_t        *ctx;
    ngx_rtmp_codec_ctx_t       *codec_ctx;
    ngx_msec_t                  max_time;
    ngx_msec_t                  catime, cvtime; // whole time duration in gop.
    ngx_msec_t                  dvtime, datime; // time duration expect first gop.
    ngx_msec_t                  rvtime, ratime, rtime; //remained duration after delete
    ngx_msec_t                  gop_cache_mintime;
    ngx_msec_t                  gop_cache_maxtime;
    ngx_rtmp_gop_clean_t        clean_status;
    ngx_rtmp_gop_cache_ctx_t   *gop_cache_ctx;
    ngx_rtmp_gop_cache_t       *next;

#if(NGX_DEBUG)
    ngx_rtmp_gop_cache_t       *cache;
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

    gop_cache_ctx = &ctx->gop_cache_ctx;

    gop_cache_mintime = lacf->gop_cache_mintime;
    gop_cache_maxtime = lacf->gop_cache_maxtime;

    clean_status = NGX_RTMP_GOP_CLEAN_NO;

    do {
        // each time remove one gop
        if (clean_status != NGX_RTMP_GOP_CLEAN_NO) {
#if(NGX_DEBUG)
            cache = gop_cache_ctx->head;
#endif
            next = ngx_rtmp_gop_free_cache(s, gop_cache_ctx->head);

            gop_cache_ctx->head->next = gop_cache_ctx->free_cache;
            gop_cache_ctx->free_cache = gop_cache_ctx->head;

            gop_cache_ctx->head = next;

            ngx_log_debug8(NGX_LOG_DEBUG_RTMP, s->connection->log, 0,
                          "clean_status:%uD,"
                          "freed video cnt %uD, time %uD, remained video cnt %D,"
                          "freed audio cnt %uD, time %uD, remained audio cnt %D,"
                          "remain gop cnt %uD",
                          clean_status,
                          cache->video_frame_cnt, dvtime, gop_cache_ctx->video_frame_cnt,
                          cache->audio_frame_cnt, datime, gop_cache_ctx->audio_frame_cnt,
                          gop_cache_ctx->cache_cnt);

            clean_status = NGX_RTMP_GOP_CLEAN_NO;
        }

        if (gop_cache_ctx->head == NULL) {
            ngx_rtmp_gop_cleanup(s);
            break;
        }

        catime = ngx_rtmp_gop_cache_audio_duration(
                              gop_cache_ctx->audio_frame_cnt,
                              codec_ctx->audio_codec_id,
                              codec_ctx->sample_rate);

        cvtime = ngx_rtmp_gop_cache_video_duration(
                              gop_cache_ctx->video_frame_cnt,
                              ctx->stream->video_frame_rate);

        max_time = ngx_max(catime, cvtime);

        datime = ngx_rtmp_gop_cache_audio_duration(
                              gop_cache_ctx->head->audio_frame_cnt,
                              codec_ctx->audio_codec_id,
                              codec_ctx->sample_rate);

        dvtime = ngx_rtmp_gop_cache_video_duration(
                              gop_cache_ctx->head->video_frame_cnt,
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
                          cvtime, gop_cache_ctx->video_frame_cnt,
                          catime, gop_cache_ctx->audio_frame_cnt,
                          gop_cache_ctx->cache_cnt);

    } while (clean_status);
}


void
ngx_rtmp_gop_cache_frame(ngx_rtmp_session_t *s, ngx_uint_t prio, ngx_rtmp_header_t *ch, ngx_chain_t *frame)
{
    ngx_rtmp_live_ctx_t            *ctx;
    ngx_rtmp_codec_ctx_t           *codec_ctx;
    ngx_rtmp_core_srv_conf_t       *cscf;
    ngx_rtmp_live_app_conf_t       *lacf;
    ngx_rtmp_gop_cache_ctx_t       *gop_cache_ctx;
    ngx_rtmp_gop_frame_t           *gop_frame;

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
    if (codec_ctx == NULL) {
        return;
    }

    gop_cache_ctx = &ctx->gop_cache_ctx;

    if (ch->type == NGX_RTMP_MSG_VIDEO) {

        // drop video when not h.264 or h.265
        if (codec_ctx->video_codec_id != NGX_RTMP_VIDEO_H264 &&
            codec_ctx->video_codec_id != NGX_RTMP_VIDEO_H265) {

            return;
        }

        // drop non-key-video when 1'st keyframe wasn't arrived
        if (prio != NGX_RTMP_VIDEO_KEY_FRAME &&
            gop_cache_ctx->head == NULL) {

            ngx_log_error(NGX_LOG_ERR, s->connection->log, 0,
                          "drop video non-keyframe timestamp='%uD'",
                          ch->timestamp);
            return;
        }
    }

    // pure audio?
    if (gop_cache_ctx->video_frame_cnt == 0 &&
        ch->type == NGX_RTMP_MSG_AUDIO) {
        return;
    }

    if (ch->type == NGX_RTMP_MSG_AUDIO) {
        gop_cache_ctx->audio_after_last_video_cnt ++;
    }

    if (gop_cache_ctx->audio_after_last_video_cnt > NGX_RTMP_LIVE_PURE_AUDIO_GUESS_CNT) {
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


void
ngx_rtmp_gop_cache_send(ngx_rtmp_session_t *ss)
{
    ngx_rtmp_session_t             *s;
    ngx_chain_t                    *pkt, *apkt, *meta, *header;
    ngx_rtmp_live_ctx_t            *pctx, *publisher, *player;
    ngx_rtmp_gop_cache_ctx_t       *gop_cache_ctx;
    ngx_rtmp_core_srv_conf_t       *cscf;
    ngx_rtmp_live_app_conf_t       *lacf;
    ngx_rtmp_gop_cache_t           *cache;
    ngx_rtmp_gop_frame_t           *gop_frame;
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

    for (pctx = player->stream->ctx; pctx; pctx = pctx->next) {
        if (pctx->publishing) {
            break;
        }
    }

    if (pctx == NULL) {
        return;
    }

    gop_cache_ctx = &pctx->gop_cache_ctx;

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

    for (cache = publisher->gop_cache_ctx.head; cache; cache = cache->next) {

        if (cache->meta_data) {
            meta = cache->meta_data;
            meta_version = cache->meta_version;
        }

        /* send metadata */
        if (meta && meta_version != player->meta_version) {
            ngx_log_debug0(NGX_LOG_DEBUG_RTMP, ss->connection->log, 0,
                           "live: meta");

            if (ngx_rtmp_send_message(ss, meta, 0) == NGX_OK) {
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
                           "gop_send: send tag type='%s' prio='%d' ltimestamp='%uD'",
                           gop_frame->h.type == NGX_RTMP_MSG_AUDIO ? "audio" : "video",
                           gop_frame->prio,
                           lh.timestamp);

            cs->timestamp += delta;
            ss->current_time = cs->timestamp;
        }
    }
}
