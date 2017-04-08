
/*
 * Copyright (C) Gnolizuh
 */


#ifndef _NGX_RTMP_GOP_CACHE_H_INCLUDED_
#define _NGX_RTMP_GOP_CACHE_H_INCLUDED_


#define NGX_RTMP_LIVE_GOP_SIZE          100   /* gop cache */
#define NGX_RTMP_LIVE_PER_GOP_MAX_TIME  30000 /* per gop cache`s max time */


typedef enum {
    NGX_RTMP_GOP_CLEAN_NO,
    NGX_RTMP_GOP_CLEAN_UNIQUE,
    NGX_RTMP_GOP_CLEAN_MIN,
    NGX_RTMP_GOP_CLEAN_MAX
} ngx_rtmp_gop_clean_t;


typedef struct ngx_rtmp_gop_frame_s ngx_rtmp_gop_frame_t;
typedef struct ngx_rtmp_gop_cache_s ngx_rtmp_gop_cache_t;


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
    ngx_uint_t                          cache_cnt;
    ngx_uint_t                          video_frame_cnt;
    ngx_uint_t                          audio_frame_cnt;
    ngx_uint_t                          audio_after_last_video_cnt;
} ngx_rtmp_gop_cache_ctx_t;


ngx_rtmp_gop_frame_t *ngx_rtmp_gop_alloc_frame(ngx_rtmp_session_t *s);
ngx_rtmp_gop_frame_t *ngx_rtmp_gop_free_frame(ngx_rtmp_session_t *s, ngx_rtmp_gop_frame_t *frame);
ngx_int_t ngx_rtmp_gop_link_frame(ngx_rtmp_session_t *s, ngx_rtmp_gop_frame_t *frame);
ngx_int_t ngx_rtmp_gop_alloc_cache(ngx_rtmp_session_t *s);
ngx_rtmp_gop_cache_t *ngx_rtmp_gop_free_cache(ngx_rtmp_session_t *s, ngx_rtmp_gop_cache_t *cache);
void ngx_rtmp_gop_cleanup(ngx_rtmp_session_t *s);
void ngx_rtmp_gop_update(ngx_rtmp_session_t *s);
void ngx_rtmp_gop_cache_frame(ngx_rtmp_session_t *s, ngx_uint_t prio, ngx_rtmp_header_t *ch, ngx_chain_t *frame);
void ngx_rtmp_gop_cache_send(ngx_rtmp_session_t *ss);

#endif /* _NGX_RTMP_LIVE_H_INCLUDED_ */
