
/*
 * Copyright (C) 2017 Gnolizuh
 */


#ifndef _NGX_RTMP_AUTO_RELAY_H_INCLUDED_
#define _NGX_RTMP_AUTO_RELAY_H_INCLUDED_


#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_http.h>
#include "ngx_rtmp_cmd_module.h"
#include "ngx_rtmp.h"


#define NGX_RTMP_RELAY_STREAM_OFF   0
#define NGX_RTMP_RELAY_STREAM_ALL   1
#define NGX_RTMP_RELAY_STREAM_HASH  2


typedef struct ngx_rtmp_auto_relay_ctx_s ngx_rtmp_auto_relay_ctx_t;


struct ngx_rtmp_auto_relay_ctx_s {
    ngx_int_t                      *slots; /* NGX_MAX_PROCESSES */
    u_char                          name[NGX_RTMP_MAX_NAME];
    u_char                          args[NGX_RTMP_MAX_ARGS];
    ngx_event_t                     push_evt;
};


typedef struct {
    ngx_uint_t                      relay_stream;
    ngx_str_t                       auto_relay_socket_dir;
    ngx_msec_t                      relay_reconnect_time;
} ngx_rtmp_auto_relay_conf_t;


extern ngx_module_t  ngx_rtmp_auto_relay_module;
extern ngx_module_t  ngx_rtmp_auto_relay_index_module;


#endif /* _NGX_RTMP_AUTO_RELAY_H_INCLUDED_ */
