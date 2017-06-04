
/*
 * Copyright (C) Gnolizuh
 */


#ifndef _NGX_RTMP_GOP_CACHE_H_INCLUDED_
#define _NGX_RTMP_GOP_CACHE_H_INCLUDED_


#include "ngx_rtmp.h"

#define NGX_RTMP_LIVE_PURE_AUDIO_GUESS_CNT 115   /* pure audio */


typedef struct ngx_rtmp_gop_frame_s ngx_rtmp_gop_frame_t;
typedef struct ngx_rtmp_gop_cache_s ngx_rtmp_gop_cache_t;


typedef struct {
    ngx_int_t                           (*send_message)(ngx_rtmp_session_t *s, ngx_chain_t *in, ngx_uint_t priority);
    ngx_chain_t                        *(*append_shared_bufs)(ngx_rtmp_session_t *s, ngx_rtmp_header_t *h, ngx_rtmp_header_t *lh, ngx_chain_t *in);
    void                                (*free_shared_chain)(ngx_rtmp_session_t *s, ngx_chain_t *in);
} ngx_rtmp_send_handler_t;


struct ngx_rtmp_gop_frame_s {
    ngx_rtmp_header_t                   h;
    ngx_uint_t                          prio;
    ngx_chain_t                        *frame;
    ngx_rtmp_gop_frame_t               *next;
};


struct ngx_rtmp_gop_cache_s {
    ngx_rtmp_gop_frame_t               *head;
    ngx_rtmp_gop_frame_t               *tail;
    ngx_rtmp_gop_cache_t               *next;
    ngx_chain_t                        *video_seq_header_data;
    ngx_chain_t                        *audio_seq_header_data;
    ngx_chain_t                        *meta_data;
    ngx_chain_t                        *meta_data_flv;
    ngx_uint_t                          meta_version;
    ngx_rtmp_header_t                   meta_header;
    ngx_int_t                           video_frame_cnt;
    ngx_int_t                           audio_frame_cnt;
};


typedef struct {
    ngx_pool_t                         *pool;
    ngx_rtmp_gop_cache_t               *head;
    ngx_rtmp_gop_cache_t               *tail;
    ngx_rtmp_gop_cache_t               *free_cache;
    ngx_rtmp_gop_frame_t               *free_frame;
    ngx_uint_t                          cache_count;
    ngx_uint_t                          video_frame_cnt;
    ngx_uint_t                          audio_frame_cnt;
    ngx_uint_t                          audio_after_last_video_cnt;
} ngx_rtmp_gop_cache_ctx_t;


typedef struct {
    ngx_flag_t                          gop_cache;
    ngx_int_t                           gop_cache_size;
    ngx_msec_t                          gop_cache_mintime;
} ngx_rtmp_gop_cache_app_conf_t;


extern ngx_module_t ngx_rtmp_gop_cache_module;
extern ngx_rtmp_send_handler_t *ngx_rtmp_send_handlers[2];

ngx_rtmp_gop_frame_t *ngx_rtmp_gop_alloc_frame(ngx_rtmp_session_t *s);
ngx_rtmp_gop_frame_t *ngx_rtmp_gop_free_frame(ngx_rtmp_session_t *s, ngx_rtmp_gop_frame_t *frame);
ngx_int_t ngx_rtmp_gop_link_frame(ngx_rtmp_session_t *s, ngx_rtmp_gop_frame_t *frame);
ngx_int_t ngx_rtmp_gop_alloc_cache(ngx_rtmp_session_t *s);
ngx_rtmp_gop_cache_t *ngx_rtmp_gop_free_cache(ngx_rtmp_session_t *s, ngx_rtmp_gop_cache_t *cache);
void ngx_rtmp_gop_cleanup(ngx_rtmp_session_t *s);
void ngx_rtmp_gop_cache_update(ngx_rtmp_session_t *s);
void ngx_rtmp_gop_cache_frame(ngx_rtmp_session_t *s, ngx_uint_t prio, ngx_rtmp_header_t *ch, ngx_chain_t *frame);

#endif /* _NGX_RTMP_LIVE_H_INCLUDED_ */
