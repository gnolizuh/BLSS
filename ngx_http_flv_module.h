
/*
 * Copyright (C) 2017 Gnolizuh
 */


#ifndef _NGX_RTMP_HTTP_FLV_H_INCLUDED_
#define _NGX_RTMP_HTTP_FLV_H_INCLUDED_


#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_http.h>
#include "ngx_rtmp_cmd_module.h"
#include "ngx_rtmp.h"


typedef struct {} ngx_http_flv_rtmp_ctx_t;


typedef struct {
    ngx_rtmp_session_t                 *rs;
} ngx_http_flv_http_ctx_t;


extern ngx_module_t  ngx_http_flv_rtmpmodule;

ngx_chain_t *
ngx_http_flv_append_shared_bufs(ngx_rtmp_core_srv_conf_t *cscf, ngx_chain_t *hd, ngx_chain_t *in);
void
ngx_http_flv_prepare_message(ngx_rtmp_session_t *s, ngx_rtmp_header_t *h, ngx_rtmp_header_t *lh, ngx_chain_t *out);


#endif /* _NGX_RTMP_HTTP_FLV_H_INCLUDED_ */

