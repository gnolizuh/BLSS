
/*
 * Copyright (C) Gino Hu
 */


#ifndef _NGX_RTMP_HDL_H_INCLUDED_
#define _NGX_RTMP_HDL_H_INCLUDED_


#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_http.h>
#include "ngx_rtmp_cmd_module.h"
#include "ngx_rtmp_live_module.h"
#include "ngx_rtmp.h"


typedef struct ngx_http_flv_rtmp_ctx_s ngx_http_flv_rtmp_ctx_t;
typedef struct ngx_http_flv_stream_s ngx_http_flv_stream_t;


struct ngx_http_flv_stream_s {
    u_char                              name[NGX_RTMP_MAX_NAME];
    ngx_http_flv_stream_t              *next;
    ngx_http_flv_rtmp_ctx_t            *ctx;
    ngx_rtmp_bandwidth_t                bw_in;
    ngx_rtmp_bandwidth_t                bw_in_audio;
    ngx_rtmp_bandwidth_t                bw_in_video;
    ngx_rtmp_bandwidth_t                bw_out;
	ngx_rtmp_live_frame_rate_t          video_frame_rate;
    ngx_msec_t                          epoch;
    unsigned                            active:1;
    unsigned                            publishing:1;
};


struct ngx_http_flv_rtmp_ctx_s {
    ngx_rtmp_session_t                 *session;
    ngx_http_flv_stream_t              *stream;
    ngx_http_flv_rtmp_ctx_t            *next;
    ngx_rtmp_bandwidth_t                bw_out;
    ngx_uint_t                          ndropped;
    ngx_rtmp_live_chunk_stream_t        cs[2];
    ngx_uint_t                          meta_version;
    uint32_t                            epoch;
    unsigned                            initialized:1;
    unsigned                            publishing:1;
    unsigned                            paused:1;
};


typedef struct {
    ngx_int_t                           nbuckets;
    ngx_flag_t                          http_flv;
    ngx_http_flv_stream_t             **streams;
    ngx_pool_t                         *pool;
    ngx_http_flv_stream_t              *free_streams;
} ngx_http_flv_rtmp_app_conf_t;


typedef struct {
    ngx_rtmp_session_t                 *rs;
} ngx_http_flv_http_ctx_t;


ngx_chain_t *
ngx_http_flv_append_shared_bufs(ngx_rtmp_core_srv_conf_t *cscf, ngx_rtmp_header_t *h, ngx_chain_t *in);


#endif /* _NGX_RTMP_HDL_H_INCLUDED_ */

