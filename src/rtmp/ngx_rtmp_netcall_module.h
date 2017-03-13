
/*
 * Copyright (C) Roman Arutyunyan
 */


#ifndef _NGX_RTMP_NETCALL_H_INCLUDED_
#define _NGX_RTMP_NETCALL_H_INCLUDED_


#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_http.h>
#include "ngx_rtmp.h"
#include "ngx_rtmp_notify_module.h"


typedef ngx_chain_t * (*ngx_rtmp_netcall_create_pt)(ngx_rtmp_session_t *s,
        void *arg, ngx_pool_t *pool);
typedef ngx_int_t (*ngx_rtmp_netcall_filter_pt)(ngx_chain_t *in);
typedef ngx_int_t (*ngx_rtmp_netcall_sink_pt)(ngx_rtmp_session_t *s,
        ngx_chain_t *in);
typedef ngx_int_t (*ngx_rtmp_netcall_handle_pt)(ngx_rtmp_session_t *s,
        void *arg, ngx_chain_t *in);

#define NGX_RTMP_NETCALL_HTTP_GET   0
#define NGX_RTMP_NETCALL_HTTP_POST  1


/* If handle is NULL then netcall is created detached
 * which means it's completely independent of RTMP
 * session and its result is never visible to anyone.
 *
 * WARNING: It's not recommended to create non-detached
 * netcalls from disconect handlers. Netcall disconnect
 * handler which detaches active netcalls is executed
 * BEFORE your handler. It leads to a crash
 * after netcall connection is closed */
typedef struct {
    ngx_url_t                      *url;
    u_char                         *name;
    ngx_rtmp_netcall_create_pt      create;
    ngx_rtmp_netcall_filter_pt      filter;
    ngx_rtmp_netcall_sink_pt        sink;
    ngx_rtmp_netcall_handle_pt      handle;
    void                           *arg;
    size_t                          argsize;
} ngx_rtmp_netcall_init_t;


typedef struct {
    ngx_msec_t                                  timeout;
    size_t                                      bufsize;
    ngx_log_t                                  *log;
} ngx_rtmp_netcall_srv_conf_t;


typedef struct ngx_rtmp_netcall_session_s {
    ngx_rtmp_session_t                         *session;
    ngx_peer_connection_t                      *pc;
    ngx_url_t                                  *url;
    struct ngx_rtmp_netcall_session_s          *next;
    u_char                                     *name;
    void                                       *arg;
    ngx_rtmp_netcall_handle_pt                  handle;
    ngx_rtmp_netcall_filter_pt                  filter;
    ngx_rtmp_netcall_sink_pt                    sink;
    ngx_chain_t                                *in;
    ngx_chain_t                                *inlast;
    ngx_chain_t                                *out;
    ngx_msec_t                                  timeout;
    ngx_msec_t                                  epoch;
    unsigned                                    detached:1;
    size_t                                      bufsize;
} ngx_rtmp_netcall_session_t;


typedef struct {
    ngx_rtmp_netcall_session_t     *cs;
    ngx_rtmp_netcall_init_t         ci;
    u_char                         *name;
    ngx_msec_t                      start;
    ngx_msec_t                      end;
    ngx_flag_t                      ret;
    u_char                          ret_code[NGX_BUFF_LEN];
    u_char                          description[NGX_BUFF_LEN];
} ngx_rtmp_netcall_ctx_t;


ngx_int_t ngx_rtmp_netcall_create(ngx_rtmp_session_t *s,
        ngx_rtmp_netcall_init_t *ci);


/* HTTP handling */

ngx_chain_t * ngx_rtmp_netcall_http_user_format_session(ngx_rtmp_session_t *s,
        ngx_pool_t *pool,ngx_uint_t url_idx);

ngx_chain_t * ngx_rtmp_netcall_http_format_session(ngx_rtmp_session_t *s,
        ngx_pool_t *pool);
ngx_chain_t * ngx_rtmp_netcall_http_format_request(ngx_int_t method,
        ngx_str_t *host, int family, ngx_str_t *uri, ngx_str_t *extra, ngx_chain_t *args,
        ngx_str_t x_forwarded_for, ngx_chain_t *body, ngx_pool_t *pool, ngx_str_t *content_type);
ngx_chain_t * ngx_rtmp_netcall_http_skip_header(ngx_chain_t *in);


/* Memcache handling */
ngx_chain_t * ngx_rtmp_netcall_memcache_set(ngx_rtmp_session_t *s,
        ngx_pool_t *pool, ngx_str_t *key, ngx_str_t *value,
        ngx_uint_t flags, ngx_uint_t sec);

#endif /* _NGX_RTMP_NETCALL_H_INCLUDED_ */
