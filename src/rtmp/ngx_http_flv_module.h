
/*
 * Copyright (C) Gino Hu
 */


#ifndef _NGX_RTMP_HDL_H_INCLUDED_
#define _NGX_RTMP_HDL_H_INCLUDED_


#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_http.h>
#include "ngx_rtmp_cmd_module.h"
#include "ngx_rtmp.h"


typedef struct {
    ngx_rtmp_session_t                 *session;
    ngx_rtmp_live_stream_t             *stream;
    ngx_rtmp_live_ctx_t                *next;
    uint32_t                            epoch;
    unsigned                            initialized:1;
    unsigned                            publishing:1;
} ngx_http_flv_rtmp_ctx_t;


typedef struct {
    ngx_int_t                           nbuckets;
    ngx_flag_t                          http_flv;
    ngx_rtmp_live_stream_t            **streams;
    ngx_rtmp_live_stream_t             *free_streams;
} ngx_http_flv_rtmp_app_conf_t;


typedef struct {
    ngx_rtmp_session_t                 *rs;
} ngx_http_flv_http_ctx_t;


ngx_chain_t *
ngx_http_flv_append_shared_bufs(ngx_rtmp_core_srv_conf_t *cscf, ngx_rtmp_header_t *h, ngx_chain_t *in);


#endif /* _NGX_RTMP_HDL_H_INCLUDED_ */

