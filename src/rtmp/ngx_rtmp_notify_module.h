
/*
 * Copyright (C) Roman Arutyunyan
 */


#ifndef _NGX_RTMP_NOTIFY_H_INCLUDED_
#define _NGX_RTMP_NOTIFY_H_INCLUDED_


#include <ngx_config.h>
#include <ngx_core.h>
#include "ngx_rtmp.h"
#include "ngx_rtmp_cmd_module.h"
#include "ngx_rtmp_netcall_module.h"
#include "ngx_rtmp_record_module.h"
#include "ngx_rtmp_relay_module.h"
#include "ngx_rtmp_live_module.h"
#include "ngx_rtmp_notify_module.h"
#include "ngx_rtmp_codec_module.h"
#include "json-c/json.h"


#define NGX_RTMP_NOTIFY_PUBLISHING              0x01
#define NGX_RTMP_NOTIFY_PLAYING                 0x02


enum {
    NGX_RTMP_NOTIFY_PLAY,
    NGX_RTMP_NOTIFY_PUBLISH,
    NGX_RTMP_NOTIFY_PLAY_DONE,
    NGX_RTMP_NOTIFY_PUBLISH_DONE,
    NGX_RTMP_NOTIFY_DONE,
    NGX_RTMP_NOTIFY_RECORD_DONE,
    NGX_RTMP_NOTIFY_UPDATE,
    NGX_RTMP_NOTIFY_APP_MAX
};


enum {
    NGX_RTMP_NOTIFY_CONNECT,
    NGX_RTMP_NOTIFY_DISCONNECT,
    NGX_RTMP_NOTIFY_SRV_MAX
};


enum {
     RTMP_NOTIFY_EVENT_CONN = 0,
     RTMP_NOTIFY_EVENT_PUBLISH,
     RTMP_NOTIFY_EVENT_PLAY,
     RTMP_NOTIFY_EVENT_UPTATE
} rtmp_notify_event_type;


typedef struct {
    ngx_url_t                                  *url[NGX_RTMP_NOTIFY_APP_MAX];
    ngx_flag_t                                  active;
    ngx_uint_t                                  method;
    ngx_msec_t                                  update_timeout;
    ngx_flag_t                                  relay_redirect;
	ngx_str_t                                   socket_dir;
} ngx_rtmp_notify_app_conf_t;


typedef struct {
    ngx_url_t                                  *url[NGX_RTMP_NOTIFY_SRV_MAX];
    ngx_uint_t                                  method;
} ngx_rtmp_notify_srv_conf_t;

typedef struct {
    ngx_uint_t                                  flags;
    ngx_uint_t                                  update_cnt;
    uint64_t                                    pre_npull;
    u_char                                      name[NGX_RTMP_MAX_NAME];
    u_char                                      args[NGX_RTMP_MAX_ARGS];
    ngx_event_t                                 update_evt;
    time_t                                      start;
} ngx_rtmp_notify_ctx_t;


typedef struct {
    u_char                                     *cbname;
    ngx_uint_t                                  url_idx;
} ngx_rtmp_notify_done_t;


typedef struct {

    u_char        *v_codec;
    u_char        *a_codec;
    char          *v_profile;
    char          *a_profile;
	
    ngx_uint_t     level;
    ngx_uint_t     width;
    ngx_uint_t     height;
    ngx_uint_t     frame_rate;
    ngx_uint_t     compat;
    ngx_uint_t     channels;
    ngx_uint_t     sample_rate;
} codec_st;


ngx_int_t ngx_rtmp_notify_play1(ngx_rtmp_session_t *s, ngx_rtmp_play_t *v);
ngx_int_t ngx_rtmp_notify_parse_http_retcode(ngx_rtmp_session_t *s, ngx_chain_t *in, u_char *retcode);


#endif /* _NGX_RTMP_NOTIFY_H_INCLUDED_ */
