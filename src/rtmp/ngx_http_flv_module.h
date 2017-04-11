
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
    uint32_t                            epoch;
    unsigned                            initialized:1;
} ngx_rtmp_hdl_ctx_t;


typedef struct {
    ngx_flag_t                          http_flv;
} ngx_rtmp_hdl_app_conf_t;


typedef struct {
    ngx_rtmp_session_t                 *s;
} ngx_rtmp_http_hdl_ctx_t;


#endif /* _NGX_RTMP_HDL_H_INCLUDED_ */

