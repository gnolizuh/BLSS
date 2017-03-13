
/*
 * Copyright (C) Roman Arutyunyan
 */


#ifndef _NGX_RTMP_LOG_MODULE_H_INCLUDED_
#define _NGX_RTMP_LOG_MODULE_H_INCLUDED_


#include "ngx_rtmp_netcall_module.h"
#include "ngx_rtmp_live_module.h"


#define NGX_RTMP_LOG_EVENT_NOTIFY_LATENCY 			0
#define NGX_RTMP_LOG_EVENT_BW_IN          			1
#define NGX_RTMP_LOG_EVENT_BW_OUT         			2
#define NGX_RTMP_LOG_EVENT_EVT_IN         			3
#define NGX_RTMP_LOG_EVENT_EVT_RTMP_OUT  			4
#define NGX_RTMP_LOG_EVENT_EVT_HDL_OUT    			5
#define NGX_RTMP_LOG_EVENT_EVT_HLS_OUT    			6
#define NGX_RTMP_LOG_EVENT_FLUX           			7
#define NGX_RTMP_LOG_EVENT_DELAY          			8
#define NGX_RTMP_LOG_EVENT_PUBLISHER_FINALIZE                   9
#define NGX_RTMP_LOG_EVENT_MAX            			10

typedef struct ngx_rtmp_log_op_s ngx_rtmp_log_op_t;


typedef size_t (*ngx_rtmp_log_op_getlen_pt)(ngx_rtmp_session_t *s,
        ngx_rtmp_log_op_t *op);
typedef u_char * (*ngx_rtmp_log_op_getdata_pt)(ngx_rtmp_session_t *s,
        u_char *buf, ngx_rtmp_log_op_t *log);


struct ngx_rtmp_log_op_s {
    ngx_rtmp_log_op_getlen_pt   getlen;
    ngx_rtmp_log_op_getdata_pt  getdata;
    ngx_str_t                   value;
    ngx_uint_t                  offset;
};


typedef struct {
    ngx_str_t                   name;
    ngx_rtmp_log_op_getlen_pt   getlen;
    ngx_rtmp_log_op_getdata_pt  getdata;
    ngx_uint_t                  offset;
} ngx_rtmp_log_var_t;


typedef struct {
    ngx_str_t                   name;
    ngx_flag_t                  on;
    ngx_array_t                *ops; /* ngx_rtmp_log_op_t */
} ngx_rtmp_log_fmt_t;


typedef struct {
    ngx_open_file_t            *file;
    time_t                      disk_full_time;
    time_t                      error_log_time;
    ngx_rtmp_log_fmt_t         *standards[NGX_RTMP_LOG_EVENT_MAX];
} ngx_rtmp_log_t;


typedef struct {
    ngx_array_t                *logs; /* ngx_rtmp_log_t */
    ngx_uint_t                  off;
    ngx_msec_t                  log_sample_interval;
} ngx_rtmp_log_app_conf_t;


typedef struct {
    ngx_array_t                 formats; /* ngx_rtmp_log_fmt_t */
    ngx_msec_t                  flux_interval;
} ngx_rtmp_log_main_conf_t;


typedef struct {
    unsigned                    play:1;
    unsigned                    publish:1;
    ngx_event_t                 timer;
    ngx_msec_t                  timer_msec;
    uint32_t                    event;
    u_char                      name[NGX_RTMP_MAX_NAME];
    u_char                      args[NGX_RTMP_MAX_ARGS];
    ngx_event_t                 delay_timer;
    ngx_msec_t                  delay_timer_msec;
} ngx_rtmp_log_ctx_t;


void ngx_rtmp_log_evt_in(ngx_rtmp_session_t *s);
void ngx_rtmp_log_evt_out(ngx_rtmp_session_t *s);
void ngx_rtmp_log_evt_hdl_out(ngx_rtmp_session_t *s);
void ngx_rtmp_log_evt_hls_out(ngx_rtmp_session_t *s);
void ngx_rtmp_log_flux(ngx_rtmp_session_t *s);


#endif /* _NGX_RTMP_LOG_MODULE_H_INCLUDED_ */
