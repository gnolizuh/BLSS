
/*
 * Copyright (C) 2017 Gnolizuh
 */


#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_rtmp.h>
#include "ngx_rtmp_live_module.h"
#include "ngx_http_flv_module.h"
#include "ngx_rtmp_codec_module.h"


typedef struct ngx_rtmp_header_val_s  ngx_rtmp_header_val_t;

typedef ngx_int_t (*ngx_rtmp_set_header_pt)(ngx_http_request_t *r,
    ngx_rtmp_header_val_t *hv, ngx_str_t *value);


typedef enum {
    NGX_RTMP_EXPIRES_OFF,
    NGX_RTMP_EXPIRES_EPOCH,
    NGX_RTMP_EXPIRES_MAX,
    NGX_RTMP_EXPIRES_ACCESS,
    NGX_RTMP_EXPIRES_MODIFIED,
    NGX_RTMP_EXPIRES_DAILY,
    NGX_RTMP_EXPIRES_UNSET
} ngx_rtmp_expires_t;


struct ngx_rtmp_header_val_s {
    ngx_http_complex_value_t   value;
    ngx_str_t                  key;
    ngx_rtmp_set_header_pt     handler;
    ngx_uint_t                 offset;
    ngx_uint_t                 always;  /* unsigned  always:1 */
};


typedef struct {
    ngx_rtmp_expires_t         expires;
    time_t                     expires_time;
    ngx_http_complex_value_t  *expires_value;
    ngx_array_t               *headers;
} ngx_rtmp_headers_conf_t;


static ngx_rtmp_play_pt                 next_play;
static ngx_rtmp_close_stream_pt         next_close_stream;


extern ngx_module_t   ngx_http_headers_filter_module;
extern ngx_uint_t ngx_rtmp_playing;
ngx_uint_t ngx_http_flv_naccepted;

typedef struct {
    ngx_flag_t                          http_flv;
} ngx_http_flv_httploc_conf_t;


/* http handler registered */
static ngx_int_t ngx_http_flv_http_init(ngx_conf_t *cf);
static void * ngx_http_flv_http_create_conf(ngx_conf_t *cf);
static char * ngx_http_flv_http_merge_conf(ngx_conf_t *cf, void *parent, void *child);

/* rtmp handler registered */
static ngx_int_t ngx_http_flv_rtmp_init(ngx_conf_t *cf);

static ngx_int_t ngx_http_flv_send_message(ngx_rtmp_session_t *s, ngx_chain_t *out, ngx_uint_t priority);
static ngx_int_t ngx_http_flv_connect_local(ngx_rtmp_session_t *s);
static void ngx_http_flv_http_send_header(ngx_rtmp_session_t *s, ngx_rtmp_session_t *ps);
static ngx_int_t ngx_http_flv_http_send_message(ngx_rtmp_session_t *s, ngx_chain_t *in, ngx_uint_t priority);
static ngx_chain_t * ngx_http_flv_http_append_shared_bufs(ngx_rtmp_session_t *s, ngx_rtmp_header_t *h, ngx_rtmp_header_t *lh, ngx_chain_t *in);
static void ngx_http_flv_http_free_shared_chain(ngx_rtmp_session_t *s, ngx_chain_t *in);


static char ngx_http_server_string[] = "Server: nginx" CRLF;
static char ngx_http_server_full_string[] = "Server: " NGINX_VER CRLF;


static ngx_str_t ngx_http_status_lines[] = {

    ngx_string("200 OK"),
    ngx_string("201 Created"),
    ngx_string("202 Accepted"),
    ngx_null_string,  /* "203 Non-Authoritative Information" */
    ngx_string("204 No Content"),
    ngx_null_string,  /* "205 Reset Content" */
    ngx_string("206 Partial Content"),

    /* ngx_null_string, */  /* "207 Multi-Status" */

#define NGX_HTTP_LAST_2XX  207
#define NGX_HTTP_OFF_3XX   (NGX_HTTP_LAST_2XX - 200)

    /* ngx_null_string, */  /* "300 Multiple Choices" */

    ngx_string("301 Moved Permanently"),
    ngx_string("302 Moved Temporarily"),
    ngx_string("303 See Other"),
    ngx_string("304 Not Modified"),
    ngx_null_string,  /* "305 Use Proxy" */
    ngx_null_string,  /* "306 unused" */
    ngx_string("307 Temporary Redirect"),

#define NGX_HTTP_LAST_3XX  308
#define NGX_HTTP_OFF_4XX   (NGX_HTTP_LAST_3XX - 301 + NGX_HTTP_OFF_3XX)

    ngx_string("400 Bad Request"),
    ngx_string("401 Unauthorized"),
    ngx_string("402 Payment Required"),
    ngx_string("403 Forbidden"),
    ngx_string("404 Not Found"),
    ngx_string("405 Not Allowed"),
    ngx_string("406 Not Acceptable"),
    ngx_null_string,  /* "407 Proxy Authentication Required" */
    ngx_string("408 Request Time-out"),
    ngx_string("409 Conflict"),
    ngx_string("410 Gone"),
    ngx_string("411 Length Required"),
    ngx_string("412 Precondition Failed"),
    ngx_string("413 Request Entity Too Large"),
    ngx_string("414 Request-URI Too Large"),
    ngx_string("415 Unsupported Media Type"),
    ngx_string("416 Requested Range Not Satisfiable"),

    /* ngx_null_string, */  /* "417 Expectation Failed" */
    /* ngx_null_string, */  /* "418 unused" */
    /* ngx_null_string, */  /* "419 unused" */
    /* ngx_null_string, */  /* "420 unused" */
    /* ngx_null_string, */  /* "421 unused" */
    /* ngx_null_string, */  /* "422 Unprocessable Entity" */
    /* ngx_null_string, */  /* "423 Locked" */
    /* ngx_null_string, */  /* "424 Failed Dependency" */

#define NGX_HTTP_LAST_4XX  417
#define NGX_HTTP_OFF_5XX   (NGX_HTTP_LAST_4XX - 400 + NGX_HTTP_OFF_4XX)

    ngx_string("500 Internal Server Error"),
    ngx_string("501 Not Implemented"),
    ngx_string("502 Bad Gateway"),
    ngx_string("503 Service Temporarily Unavailable"),
    ngx_string("504 Gateway Time-out"),

    ngx_null_string,        /* "505 HTTP Version Not Supported" */
    ngx_null_string,        /* "506 Variant Also Negotiates" */
    ngx_string("507 Insufficient Storage"),
    /* ngx_null_string, */  /* "508 unused" */
    /* ngx_null_string, */  /* "509 unused" */
    /* ngx_null_string, */  /* "510 Not Extended" */

#define NGX_HTTP_LAST_5XX  508

};


ngx_http_header_out_t  ngx_http_headers_out[] = {
    { ngx_string("Server"), offsetof(ngx_http_headers_out_t, server) },
    { ngx_string("Date"), offsetof(ngx_http_headers_out_t, date) },
    { ngx_string("Content-Length"),
                 offsetof(ngx_http_headers_out_t, content_length) },
    { ngx_string("Content-Encoding"),
                 offsetof(ngx_http_headers_out_t, content_encoding) },
    { ngx_string("Location"), offsetof(ngx_http_headers_out_t, location) },
    { ngx_string("Last-Modified"),
                 offsetof(ngx_http_headers_out_t, last_modified) },
    { ngx_string("Accept-Ranges"),
                 offsetof(ngx_http_headers_out_t, accept_ranges) },
    { ngx_string("Expires"), offsetof(ngx_http_headers_out_t, expires) },
    { ngx_string("Cache-Control"),
                 offsetof(ngx_http_headers_out_t, cache_control) },
    { ngx_string("ETag"), offsetof(ngx_http_headers_out_t, etag) },

    { ngx_null_string, 0 }
};


ngx_rtmp_send_handler_t ngx_http_flv_send_handler = {
    ngx_http_flv_http_send_header,
    ngx_http_flv_http_send_message,
    ngx_http_flv_http_append_shared_bufs,
    ngx_http_flv_http_free_shared_chain
};


static ngx_command_t ngx_http_flv_httpcommands[] = {

    { ngx_string("http_flv"),
      NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_TAKE1,
      ngx_conf_set_flag_slot,
      NGX_HTTP_LOC_CONF_OFFSET,
      offsetof(ngx_http_flv_httploc_conf_t, http_flv),
      NULL },

      ngx_null_command
};


static ngx_http_module_t ngx_http_flv_httpmodule_ctx = {
    NULL,                               /* preconfiguration */
    ngx_http_flv_http_init,             /* postconfiguration */
    NULL,                               /* create main configuration */
    NULL,                               /* init main configuration */
    NULL,                               /* create server configuration */
    NULL,                               /* merge server configuration */
    ngx_http_flv_http_create_conf,      /* create location configuration */
    ngx_http_flv_http_merge_conf        /* merge location configuration */
};


ngx_module_t ngx_http_flv_httpmodule = {
    NGX_MODULE_V1,
    &ngx_http_flv_httpmodule_ctx,       /* module context */
    ngx_http_flv_httpcommands,          /* module directives */
    NGX_HTTP_MODULE,                    /* module type */
    NULL,                               /* init master */
    NULL,                               /* init module */
    NULL,                               /* init process */
    NULL,                               /* init thread */
    NULL,                               /* exit thread */
    NULL,                               /* exit process */
    NULL,                               /* exit master */
    NGX_MODULE_V1_PADDING
};


static ngx_rtmp_module_t ngx_http_flv_rtmpmodule_ctx = {
    NULL,                                   /* preconfiguration */
    ngx_http_flv_rtmp_init,                 /* postconfiguration */
    NULL,                                   /* create main configuration */
    NULL,                                   /* init main configuration */
    NULL,                                   /* create server configuration */
    NULL,                                   /* merge server configuration */
    NULL,                                   /* create service configuration */
    NULL,                                   /* merge service configuration */
    NULL,                                   /* create application configuration */
    NULL,                                   /* merge application configuration */
};


ngx_module_t ngx_http_flv_rtmpmodule = {
    NGX_MODULE_V1,
    &ngx_http_flv_rtmpmodule_ctx,           /* module context */
    NULL,                                   /* module directives */
    NGX_RTMP_MODULE,                        /* module type */
    NULL,                                   /* init master */
    NULL,                                   /* init module */
    NULL,                                   /* init process */
    NULL,                                   /* init thread */
    NULL,                                   /* exit thread */
    NULL,                                   /* exit process */
    NULL,                                   /* exit master */
    NGX_MODULE_V1_PADDING
};


static ngx_int_t
ngx_http_flv_send_message(ngx_rtmp_session_t *s, ngx_chain_t *out,
        ngx_uint_t priority)
{
    ngx_uint_t                      nmsg;

    nmsg = (s->out_last - s->out_pos) % s->out_queue + 1;

    if (priority > 3) {
        priority = 3;
    }

    /* drop packet?
     * Note we always leave 1 slot free */
    if (nmsg + priority * s->out_queue / 4 >= s->out_queue) {
    /*
        ngx_log_debug2(NGX_LOG_DEBUG_RTMP, s->connection->log, 0,
                "RTMP drop message bufs=%ui, priority=%ui",
                nmsg, priority);
    */
        ngx_log_error(NGX_LOG_WARN, s->connection->log, 0,
            "HTTP FLV drop message bufs=%ui, priority=%ui, s->out_last=%d, s->out_pos=%d, s->out_queue=%d ",
            nmsg, priority, s->out_last, s->out_pos, s->out_queue);
        return NGX_AGAIN;
    }

    s->out[s->out_last++] = out;
    s->out_last %= s->out_queue;

    ngx_rtmp_acquire_shared_chain(out);

    ngx_log_debug3(NGX_LOG_DEBUG_RTMP, s->connection->log, 0,
            "HTTP FLV send nmsg=%ui, priority=%ui #%ui",
            nmsg, priority, s->out_last);

    if (priority && s->out_buffer && nmsg < s->out_cork) {
        return NGX_OK;
    }

    if (!s->connection->write->active) {

        ngx_http_flv_send(s->connection->write);
    }

    return NGX_OK;
}


static ngx_int_t
ngx_http_flv_play_local(ngx_rtmp_session_t *s)
{
    static ngx_rtmp_play_t      v;

    ngx_memzero(&v, sizeof(ngx_rtmp_play_t));

    ngx_memcpy(v.name, s->name.data, ngx_min(s->name.len, sizeof(v.name) - 1));
    ngx_memcpy(v.args, s->args.data, ngx_min(s->args.len, sizeof(v.args) - 1));

    return ngx_rtmp_cmd_play_local(s, &v);
}


static void
ngx_http_flv_close_session_handler(ngx_rtmp_session_t *s)
{
    ngx_connection_t                   *c;
    ngx_rtmp_core_srv_conf_t           *cscf;

    c = s->connection;

    cscf = ngx_rtmp_get_module_srv_conf(s, ngx_rtmp_core_module);

    ngx_log_error(NGX_LOG_INFO, c->log, 0, "http_flv close session");

    ngx_rtmp_fire_event(s, NGX_RTMP_DISCONNECT, NULL, NULL);

    if (s->ping_evt.timer_set) {
        ngx_del_timer(&s->ping_evt);
    }

    if (s->in_old_pool) {
        ngx_destroy_pool(s->in_old_pool);
    }

    if (s->in_pool) {
        ngx_destroy_pool(s->in_pool);
    }

    ngx_rtmp_free_handshake_buffers(s);

    while (s->out_pos != s->out_last) {
        ngx_rtmp_free_shared_chain(cscf, s->out[s->out_pos++]);
        s->out_pos %= s->out_queue;
    }
}


static ngx_int_t
ngx_http_flv_connect_local(ngx_rtmp_session_t *s)
{
    static ngx_rtmp_connect_t   v;

    ngx_http_flv_rtmp_ctx_t    *rtmpctx;

    ngx_memzero(&v, sizeof(ngx_rtmp_connect_t));

    ngx_memcpy(v.host, s->host.data, ngx_min(s->host.len, sizeof(v.host) - 1));
    ngx_memcpy(v.app, s->app.data, ngx_min(s->app.len, sizeof(v.app) - 1));

    *ngx_snprintf(v.tc_url, NGX_RTMP_MAX_URL, "http://%V/%V", &s->host, &s->app) = 0;

#define NGX_RTMP_SET_STRPAR(name)                                             \
    s->name.len = ngx_strlen(v.name);                                         \
    s->name.data = ngx_palloc(s->connection->pool, s->name.len);              \
    ngx_memcpy(s->name.data, v.name, s->name.len)

    NGX_RTMP_SET_STRPAR(args);
    NGX_RTMP_SET_STRPAR(tc_url);

#undef NGX_RTMP_SET_STRPAR

    rtmpctx = ngx_rtmp_get_module_ctx(s, ngx_http_flv_rtmpmodule);
    if (rtmpctx == NULL) {
        rtmpctx = ngx_pcalloc(s->pool, sizeof(ngx_http_flv_rtmp_ctx_t));
        ngx_rtmp_set_ctx(s, rtmpctx, ngx_http_flv_rtmpmodule);
    }

    return ngx_rtmp_cmd_connect_local(s, &v);
}


static void
ngx_http_flv_cleanup(void *data)
{
    ngx_http_request_t         *r = data;
    ngx_rtmp_session_t		   *s;
    ngx_http_flv_http_ctx_t    *httpctx;

    httpctx = ngx_http_get_module_ctx(r, ngx_http_flv_httpmodule);

    s = httpctx->rs;

    ngx_log_error(NGX_LOG_INFO, s->connection->log, 0, "http_flv close connection");

    -- ngx_http_flv_naccepted;

    ngx_http_flv_close_session_handler(s);
}


static ngx_int_t
ngx_http_flv_http_handler(ngx_http_request_t *r)
{
    ngx_http_flv_httploc_conf_t         *hlcf;
    ngx_http_cleanup_t                  *cln;
    ngx_http_flv_http_ctx_t             *httpctx;
    ngx_rtmp_session_t                  *s;
    ngx_int_t                            rc = 0;
    ngx_int_t                            nslash;
    u_char                              *p;
    size_t                               i;

    hlcf = ngx_http_get_module_loc_conf(r, ngx_http_flv_httpmodule);
    if (hlcf == NULL || !hlcf->http_flv) {
    	return NGX_DECLINED;
    }

    if (!(r->method & (NGX_HTTP_GET|NGX_HTTP_HEAD))
        || r->headers_in.host == NULL) {
        return NGX_HTTP_NOT_ALLOWED;
    }

    if (r->uri.data[r->uri.len - 1] == '/' &&
		r->uri.len > ngx_strlen(".flv")) {
        return NGX_DECLINED;
    }

    nslash = 0;
    for (i = 0; i < r->uri.len; ++ i) {
        if (r->uri.data[i] == '/') {
            ++ nslash;
        } else if (r->uri.data[i] == '?') {
            break;
        }
    }

    if (nslash > 3 || nslash < 2) {
        return NGX_DECLINED;
    }

    if (!(r->uri.data[r->uri.len - 1] == 'v' &&
          r->uri.data[r->uri.len - 2] == 'l' &&
          r->uri.data[r->uri.len - 3] == 'f' &&
          r->uri.data[r->uri.len - 4] == '.')) {
        return NGX_DECLINED;
    }

    rc = ngx_http_discard_request_body(r);
    if (rc != NGX_OK) {
        return rc;
    }

    ngx_log_error(NGX_LOG_INFO, r->connection->log, 0,
        "http_flv handle uri: '%V' args: '%V'", &r->uri, &r->args);

    // init session
    ngx_http_flv_init_connection(r);

    httpctx = ngx_http_get_module_ctx(r, ngx_http_flv_httpmodule);
    if (httpctx == NULL) {
        return NGX_DECLINED;
    }

    // get rtmp session
    s = httpctx->rs;

    s->proto = NGX_PROTO_TYPE_HTTP_FLV_PULL;
    s->host_mask = NGX_RTMP_HOSTNAME_HTTP_FLV|NGX_RTMP_HOSTNAME_SUB;

    p = ngx_strrlchr(r->uri.data + r->uri.len, r->uri.data + 1, '/');
    if (!p) {
        return NGX_DECLINED;
    }

    // get app
    s->app.data = r->uri.data + 1;
    s->app.len = p - s->app.data;

    // get name
    s->name.data = p + 1;
    s->name.len = r->uri.data + r->uri.len - s->name.data - 4;

    // get host
    s->host = r->headers_in.host->value;
    p = ngx_strlchr(s->host.data, s->host.data + s->host.len, ':');
    if (p) {
        s->host.len = p - s->host.data;
    }

    // restructure app & host
    p = ngx_strlchr(s->app.data, s->app.data + s->app.len, '/');
    if (p) {
        s->host.data = s->app.data;
        s->host.len = p - s->host.data;

        s->app.data = p + 1;
        s->app.len = s->app.len - s->host.len - 1;
    }

    // get args
    s->args.len = r->args.len;
    s->args.data = ngx_palloc(s->connection->pool, s->args.len);
    ngx_memcpy(s->args.data, r->args.data, s->args.len);

    ngx_log_error(NGX_LOG_INFO, r->connection->log, 0,
              "http_flv handle host: '%V' app: '%V' name: '%V' args: '%V'",
              &s->host, &s->app, &s->name, &s->args);

    if (ngx_http_flv_connect_local(s) != NGX_OK) {
        return NGX_DECLINED;
    }

    cln = ngx_http_cleanup_add(r, 0);
    if (cln == NULL) {
        return NGX_DECLINED;
    }

    cln->handler = ngx_http_flv_cleanup;
    cln->data = r;

    return NGX_OK;
}


static ngx_int_t
ngx_http_flv_http_init(ngx_conf_t *cf)
{
    ngx_http_handler_pt        *h;
    ngx_http_core_main_conf_t  *cmcf;

    cmcf = ngx_http_conf_get_module_main_conf(cf, ngx_http_core_module);

    h = ngx_array_push(&cmcf->phases[NGX_HTTP_CONTENT_PHASE].handlers);
    if (h == NULL) {
        return NGX_ERROR;
    }

    *h = ngx_http_flv_http_handler;

    return NGX_OK;
}


static void *
ngx_http_flv_http_create_conf(ngx_conf_t *cf)
{
    ngx_http_flv_httploc_conf_t  *hlcf;

    hlcf = ngx_palloc(cf->pool, sizeof(ngx_http_flv_httploc_conf_t));
    if (hlcf == NULL) {
        return NULL;
    }

    hlcf->http_flv = NGX_CONF_UNSET;

    return hlcf;
}


static char *
ngx_http_flv_http_merge_conf(ngx_conf_t *cf, void *parent, void *child)
{
    ngx_http_flv_httploc_conf_t *prev = parent;
    ngx_http_flv_httploc_conf_t *conf = child;

    ngx_conf_merge_value(conf->http_flv, prev->http_flv, 0);

    return NGX_CONF_OK;
}


static ngx_int_t
ngx_http_flv_connect_end(ngx_rtmp_session_t *s, ngx_rtmp_header_t *h,
    ngx_chain_t *in)
{
    if (s->proto != NGX_PROTO_TYPE_HTTP_FLV_PULL) {
        return NGX_OK;
    }

    return ngx_http_flv_play_local(s);
}


ngx_chain_t *
ngx_http_flv_append_shared_bufs(ngx_rtmp_core_srv_conf_t *cscf, ngx_rtmp_header_t *h, ngx_chain_t *in)
{
    ngx_chain_t                    *tail, *head, *taghead, prepkt;
    ngx_chain_t                    *tag = in;
    ngx_buf_t                       prebuf;
    uint32_t                        presize, presizebuf;
    u_char                         *p, *ph;

    ngx_memzero(&prebuf, sizeof(prebuf));
    prebuf.start = prebuf.pos = (u_char*)&presizebuf;
    prebuf.end   = prebuf.last = (u_char*)(((u_char*)&presizebuf) + sizeof(presizebuf));
    prepkt.buf   = &prebuf;
    prepkt.next  = NULL;

    head = tag;
    tail = tag;
    taghead = NULL;

    for (presize = 0, tail = tag; tag; tail = tag, tag = tag->next) {
        presize += (tag->buf->last - tag->buf->pos);
    }

    presize += NGX_RTMP_MAX_FLV_TAG_HEADER;

    ph = (u_char*)&presizebuf;
    p  = (u_char*)&presize;

    *ph++ = p[3];
    *ph++ = p[2];
    *ph++ = p[1];
    *ph++ = p[0];

    /* Link chain of PreviousTagSize after the last packet. */
    tail->next = &prepkt;

    taghead = ngx_rtmp_append_shared_bufs(cscf, NULL, head);

    tail->next = NULL;
    presize -= NGX_RTMP_MAX_FLV_TAG_HEADER;

    /* tag header */
    taghead->buf->pos -= NGX_RTMP_MAX_FLV_TAG_HEADER;
    ph = taghead->buf->pos;

    *ph++ = (u_char)h->type;

    p = (u_char*)&presize;
    *ph++ = p[2];
    *ph++ = p[1];
    *ph++ = p[0];

    p = (u_char*)&h->timestamp;
    *ph++ = p[2];
    *ph++ = p[1];
    *ph++ = p[0];
    *ph++ = p[3];

    *ph++ = 0;
    *ph++ = 0;
    *ph++ = 0;

    return taghead;
}


static void
ngx_http_flv_http_send_header(ngx_rtmp_session_t *s, ngx_rtmp_session_t *ps)
{
    ngx_rtmp_core_srv_conf_t       *cscf;
    // ngx_rtmp_headers_conf_t        *rhcf;
    ngx_http_request_t             *r;
    // ngx_rtmp_codec_ctx_t           *codec_ctx;
    ngx_chain_t                     /*c1, c2, */*pkt;
    // ngx_buf_t                       b1, b2;

    u_char                    *p;
    size_t                     len;
    ngx_str_t                  host, *status_line;
    ngx_buf_t                 *b;
    ngx_uint_t                 status, i, port;
    ngx_chain_t                out;
    ngx_list_part_t           *part;
    ngx_table_elt_t           *header;
    ngx_connection_t          *c;
    ngx_http_core_loc_conf_t  *clcf;
    ngx_http_core_srv_conf_t  *hcscf;
    struct sockaddr_in        *sin;
#if (NGX_HAVE_INET6)
    struct sockaddr_in6       *sin6;
#endif
    u_char                     addr[NGX_SOCKADDR_STRLEN];

    // u_char flv_header[] = "FLV\x1\0\0\0\0\x9\0\0\0\0";

    r = s->connection->data;

    if (r->header_sent) {
        return;
    }

    r->header_sent = 1;

    if (r != r->main) {
        return;
    }

    if (r->http_version < NGX_HTTP_VERSION_10) {
        return;
    }

    if (r->method == NGX_HTTP_HEAD) {
        r->header_only = 1;
    }

    if (r->headers_out.last_modified_time != -1) {
        if (r->headers_out.status != NGX_HTTP_OK
            && r->headers_out.status != NGX_HTTP_PARTIAL_CONTENT
            && r->headers_out.status != NGX_HTTP_NOT_MODIFIED)
        {
            r->headers_out.last_modified_time = -1;
            r->headers_out.last_modified = NULL;
        }
    }

    len = sizeof("HTTP/1.x ") - 1 + sizeof(CRLF) - 1
              /* the end of the header */
              + sizeof(CRLF) - 1;

    /* status line */

    if (r->headers_out.status_line.len) {
        len += r->headers_out.status_line.len;
        status_line = &r->headers_out.status_line;
#if (NGX_SUPPRESS_WARN)
        status = 0;
#endif

    } else {

        status = r->headers_out.status;

        if (status >= NGX_HTTP_OK
            && status < NGX_HTTP_LAST_2XX)
        {
            /* 2XX */

            if (status == NGX_HTTP_NO_CONTENT) {
                r->header_only = 1;
                ngx_str_null(&r->headers_out.content_type);
                r->headers_out.last_modified_time = -1;
                r->headers_out.last_modified = NULL;
                r->headers_out.content_length = NULL;
                r->headers_out.content_length_n = -1;
            }

            status -= NGX_HTTP_OK;
            status_line = &ngx_http_status_lines[status];
            len += ngx_http_status_lines[status].len;

        } else if (status >= NGX_HTTP_MOVED_PERMANENTLY
                   && status < NGX_HTTP_LAST_3XX)
        {
            /* 3XX */

            if (status == NGX_HTTP_NOT_MODIFIED) {
                r->header_only = 1;
            }

            status = status - NGX_HTTP_MOVED_PERMANENTLY + NGX_HTTP_OFF_3XX;
            status_line = &ngx_http_status_lines[status];
            len += ngx_http_status_lines[status].len;

        } else if (status >= NGX_HTTP_BAD_REQUEST
                   && status < NGX_HTTP_LAST_4XX)
        {
            /* 4XX */
            status = status - NGX_HTTP_BAD_REQUEST
                            + NGX_HTTP_OFF_4XX;

            status_line = &ngx_http_status_lines[status];
            len += ngx_http_status_lines[status].len;

        } else if (status >= NGX_HTTP_INTERNAL_SERVER_ERROR
                   && status < NGX_HTTP_LAST_5XX)
        {
            /* 5XX */
            status = status - NGX_HTTP_INTERNAL_SERVER_ERROR
                            + NGX_HTTP_OFF_5XX;

            status_line = &ngx_http_status_lines[status];
            len += ngx_http_status_lines[status].len;

        } else {
            len += NGX_INT_T_LEN + 1 /* SP */;
            status_line = NULL;
        }

        if (status_line && status_line->len == 0) {
            status = r->headers_out.status;
            len += NGX_INT_T_LEN + 1 /* SP */;
            status_line = NULL;
        }
    }

    clcf = ngx_http_get_module_loc_conf(r, ngx_http_core_module);

    if (r->headers_out.server == NULL) {
        len += clcf->server_tokens ? sizeof(ngx_http_server_full_string) - 1:
                                     sizeof(ngx_http_server_string) - 1;
    }

    if (r->headers_out.date == NULL) {
        len += sizeof("Date: Mon, 28 Sep 1970 06:00:00 GMT" CRLF) - 1;
    }

    if (r->headers_out.content_type.len) {
        len += sizeof("Content-Type: ") - 1
               + r->headers_out.content_type.len + 2;

        if (r->headers_out.content_type_len == r->headers_out.content_type.len
            && r->headers_out.charset.len)
        {
            len += sizeof("; charset=") - 1 + r->headers_out.charset.len;
        }
    }

    if (r->headers_out.content_length == NULL
        && r->headers_out.content_length_n >= 0)
    {
        len += sizeof("Content-Length: ") - 1 + NGX_OFF_T_LEN + 2;
    }

    if (r->headers_out.last_modified == NULL
        && r->headers_out.last_modified_time != -1)
    {
        len += sizeof("Last-Modified: Mon, 28 Sep 1970 06:00:00 GMT" CRLF) - 1;
    }

    c = r->connection;

    if (r->headers_out.location
        && r->headers_out.location->value.len
        && r->headers_out.location->value.data[0] == '/')
    {
        r->headers_out.location->hash = 0;

        if (clcf->server_name_in_redirect) {
            hcscf = ngx_http_get_module_srv_conf(r, ngx_http_core_module);
            host = hcscf->server_name;

        } else if (r->headers_in.server.len) {
            host = r->headers_in.server;

        } else {
            host.len = NGX_SOCKADDR_STRLEN;
            host.data = addr;

            if (ngx_connection_local_sockaddr(c, &host, 0) != NGX_OK) {
                return;
            }
        }

        switch (c->local_sockaddr->sa_family) {

#if (NGX_HAVE_INET6)
        case AF_INET6:
            sin6 = (struct sockaddr_in6 *) c->local_sockaddr;
            port = ntohs(sin6->sin6_port);
            break;
#endif
#if (NGX_HAVE_UNIX_DOMAIN)
        case AF_UNIX:
            port = 0;
            break;
#endif
        default: /* AF_INET */
            sin = (struct sockaddr_in *) c->local_sockaddr;
            port = ntohs(sin->sin_port);
            break;
        }

        len += sizeof("Location: https://") - 1
               + host.len
               + r->headers_out.location->value.len + 2;

        if (clcf->port_in_redirect) {

#if (NGX_HTTP_SSL)
            if (c->ssl)
                port = (port == 443) ? 0 : port;
            else
#endif
                port = (port == 80) ? 0 : port;

        } else {
            port = 0;
        }

        if (port) {
            len += sizeof(":65535") - 1;
        }

    } else {
        ngx_str_null(&host);
        port = 0;
    }

    if (r->chunked) {
        len += sizeof("Transfer-Encoding: chunked" CRLF) - 1;
    }

    if (r->headers_out.status == NGX_HTTP_SWITCHING_PROTOCOLS) {
        len += sizeof("Connection: upgrade" CRLF) - 1;

    } else if (r->keepalive) {
        len += sizeof("Connection: keep-alive" CRLF) - 1;

        /*
         * MSIE and Opera ignore the "Keep-Alive: timeout=<N>" header.
         * MSIE keeps the connection alive for about 60-65 seconds.
         * Opera keeps the connection alive very long.
         * Mozilla keeps the connection alive for N plus about 1-10 seconds.
         * Konqueror keeps the connection alive for about N seconds.
         */

        if (clcf->keepalive_header) {
            len += sizeof("Keep-Alive: timeout=") - 1 + NGX_TIME_T_LEN + 2;
        }

    } else {
        len += sizeof("Connection: close" CRLF) - 1;
    }

#if (NGX_HTTP_GZIP)
    if (r->gzip_vary) {
        if (clcf->gzip_vary) {
            len += sizeof("Vary: Accept-Encoding" CRLF) - 1;

        } else {
            r->gzip_vary = 0;
        }
    }
#endif

    part = &r->headers_out.headers.part;
    header = part->elts;

    for (i = 0; /* void */; i++) {

        if (i >= part->nelts) {
            if (part->next == NULL) {
                break;
            }

            part = part->next;
            header = part->elts;
            i = 0;
        }

        if (header[i].hash == 0) {
            continue;
        }

        len += header[i].key.len + sizeof(": ") - 1 + header[i].value.len
               + sizeof(CRLF) - 1;
    }

    b = ngx_create_temp_buf(r->pool, len);
    if (b == NULL) {
        return;
    }

    /* "HTTP/1.x " */
    b->last = ngx_cpymem(b->last, "HTTP/1.1 ", sizeof("HTTP/1.x ") - 1);

    /* status line */
    if (status_line) {
        b->last = ngx_copy(b->last, status_line->data, status_line->len);

    } else {
        b->last = ngx_sprintf(b->last, "%03ui ", status);
    }
    *b->last++ = CR; *b->last++ = LF;

    if (r->headers_out.server == NULL) {
        if (clcf->server_tokens) {
            p = (u_char *) ngx_http_server_full_string;
            len = sizeof(ngx_http_server_full_string) - 1;

        } else {
            p = (u_char *) ngx_http_server_string;
            len = sizeof(ngx_http_server_string) - 1;
        }

        b->last = ngx_cpymem(b->last, p, len);
    }

    if (r->headers_out.date == NULL) {
        b->last = ngx_cpymem(b->last, "Date: ", sizeof("Date: ") - 1);
        b->last = ngx_cpymem(b->last, ngx_cached_http_time.data,
                             ngx_cached_http_time.len);

        *b->last++ = CR; *b->last++ = LF;
    }

    if (r->headers_out.content_type.len) {
        b->last = ngx_cpymem(b->last, "Content-Type: ",
                             sizeof("Content-Type: ") - 1);
        p = b->last;
        b->last = ngx_copy(b->last, r->headers_out.content_type.data,
                           r->headers_out.content_type.len);

        if (r->headers_out.content_type_len == r->headers_out.content_type.len
            && r->headers_out.charset.len)
        {
            b->last = ngx_cpymem(b->last, "; charset=",
                                 sizeof("; charset=") - 1);
            b->last = ngx_copy(b->last, r->headers_out.charset.data,
                               r->headers_out.charset.len);

            /* update r->headers_out.content_type for possible logging */

            r->headers_out.content_type.len = b->last - p;
            r->headers_out.content_type.data = p;
        }

        *b->last++ = CR; *b->last++ = LF;
    }

    if (r->headers_out.content_length == NULL
        && r->headers_out.content_length_n >= 0)
    {
        b->last = ngx_sprintf(b->last, "Content-Length: %O" CRLF,
                              r->headers_out.content_length_n);
    }

    if (r->headers_out.last_modified == NULL
        && r->headers_out.last_modified_time != -1)
    {
        b->last = ngx_cpymem(b->last, "Last-Modified: ",
                             sizeof("Last-Modified: ") - 1);
        b->last = ngx_http_time(b->last, r->headers_out.last_modified_time);

        *b->last++ = CR; *b->last++ = LF;
    }

    if (host.data) {

        p = b->last + sizeof("Location: ") - 1;

        b->last = ngx_cpymem(b->last, "Location: http",
                             sizeof("Location: http") - 1);

#if (NGX_HTTP_SSL)
        if (c->ssl) {
            *b->last++ ='s';
        }
#endif

        *b->last++ = ':'; *b->last++ = '/'; *b->last++ = '/';
        b->last = ngx_copy(b->last, host.data, host.len);

        if (port) {
            b->last = ngx_sprintf(b->last, ":%ui", port);
        }

        b->last = ngx_copy(b->last, r->headers_out.location->value.data,
                           r->headers_out.location->value.len);

        /* update r->headers_out.location->value for possible logging */

        r->headers_out.location->value.len = b->last - p;
        r->headers_out.location->value.data = p;
        ngx_str_set(&r->headers_out.location->key, "Location");

        *b->last++ = CR; *b->last++ = LF;
    }

    if (r->chunked) {
        b->last = ngx_cpymem(b->last, "Transfer-Encoding: chunked" CRLF,
                             sizeof("Transfer-Encoding: chunked" CRLF) - 1);
    }

    if (r->headers_out.status == NGX_HTTP_SWITCHING_PROTOCOLS) {
        b->last = ngx_cpymem(b->last, "Connection: upgrade" CRLF,
                             sizeof("Connection: upgrade" CRLF) - 1);

    } else if (r->keepalive) {
        b->last = ngx_cpymem(b->last, "Connection: keep-alive" CRLF,
                             sizeof("Connection: keep-alive" CRLF) - 1);

        if (clcf->keepalive_header) {
            b->last = ngx_sprintf(b->last, "Keep-Alive: timeout=%T" CRLF,
                                  clcf->keepalive_header);
        }

    } else {
        b->last = ngx_cpymem(b->last, "Connection: close" CRLF,
                             sizeof("Connection: close" CRLF) - 1);
    }

#if (NGX_HTTP_GZIP)
    if (r->gzip_vary) {
        b->last = ngx_cpymem(b->last, "Vary: Accept-Encoding" CRLF,
                             sizeof("Vary: Accept-Encoding" CRLF) - 1);
    }
#endif

    part = &r->headers_out.headers.part;
    header = part->elts;

    for (i = 0; /* void */; i++) {

        if (i >= part->nelts) {
            if (part->next == NULL) {
                break;
            }

            part = part->next;
            header = part->elts;
            i = 0;
        }

        if (header[i].hash == 0) {
            continue;
        }

        b->last = ngx_copy(b->last, header[i].key.data, header[i].key.len);
        *b->last++ = ':'; *b->last++ = ' ';

        b->last = ngx_copy(b->last, header[i].value.data, header[i].value.len);
        *b->last++ = CR; *b->last++ = LF;
    }

    ngx_log_debug2(NGX_LOG_DEBUG_HTTP, c->log, 0,
                   "%*s", (size_t) (b->last - b->pos), b->pos);

    /* the end of HTTP header */
    *b->last++ = CR; *b->last++ = LF;

    r->header_size = b->last - b->pos;

    if (r->header_only) {
        b->last_buf = 1;
    }

    out.buf = b;
    out.next = NULL;

    cscf = ngx_rtmp_get_module_srv_conf(s, ngx_rtmp_core_module);

    pkt = ngx_rtmp_append_shared_bufs(cscf, NULL, &out);

    ngx_http_flv_send_message(s, pkt, 0);

    ngx_rtmp_free_shared_chain(cscf, pkt);
}


static ngx_int_t
ngx_http_flv_http_send_message(ngx_rtmp_session_t *s, ngx_chain_t *in, ngx_uint_t priority)
{
    return ngx_http_flv_send_message(s, in, priority);
}


static ngx_chain_t *
ngx_http_flv_http_append_shared_bufs(ngx_rtmp_session_t *s, ngx_rtmp_header_t *h, ngx_rtmp_header_t *lh, ngx_chain_t *in)
{
    ngx_rtmp_core_srv_conf_t       *cscf;

    cscf = ngx_rtmp_get_module_srv_conf(s, ngx_rtmp_core_module);
    if (cscf == NULL) {
        return NULL;
    }

    return ngx_http_flv_append_shared_bufs(cscf, h, in);
}


static void
ngx_http_flv_http_free_shared_chain(ngx_rtmp_session_t *s, ngx_chain_t *in)
{
    ngx_rtmp_core_srv_conf_t       *cscf;

    cscf = ngx_rtmp_get_module_srv_conf(s, ngx_rtmp_core_module);
    if (cscf == NULL) {
        return;
    }

    ngx_rtmp_free_shared_chain(cscf, in);
}


static void
ngx_http_flv_start(ngx_rtmp_session_t *s)
{
    ngx_rtmp_live_ctx_t        *ctx;

    ctx = ngx_rtmp_get_module_ctx(s, ngx_rtmp_live_module);

    ctx->active = 1;

    ctx->cs[0].active = 0;
    ctx->cs[0].dropped = 0;

    ctx->cs[1].active = 0;
    ctx->cs[1].dropped = 0;
}


static void
ngx_http_flv_stop(ngx_rtmp_session_t *s)
{
    ngx_rtmp_live_ctx_t        *ctx;

    ctx = ngx_rtmp_get_module_ctx(s, ngx_rtmp_live_module);

    ctx->active = 0;

    ctx->cs[0].active = 0;
    ctx->cs[0].dropped = 0;

    ctx->cs[1].active = 0;
    ctx->cs[1].dropped = 0;
}


static void
ngx_http_flv_join(ngx_rtmp_session_t *s, u_char *name, unsigned publisher)
{
    ngx_rtmp_live_ctx_t            *ctx;
    ngx_rtmp_live_stream_t        **stream;
    ngx_rtmp_live_app_conf_t       *lacf;

    lacf = ngx_rtmp_get_module_app_conf(s, ngx_rtmp_live_module);
    if (lacf == NULL) {
        return;
    }

    ctx = ngx_rtmp_get_module_ctx(s, ngx_rtmp_live_module);
    if (ctx && ctx->stream) {
        ngx_log_debug0(NGX_LOG_DEBUG_RTMP, s->connection->log, 0,
                       "http flv: already joined");
        return;
    }

    if (ctx == NULL) {
        ctx = ngx_palloc(s->connection->pool, sizeof(ngx_rtmp_live_ctx_t));
        ngx_rtmp_set_ctx(s, ctx, ngx_rtmp_live_module);
    }

    ngx_memzero(ctx, sizeof(*ctx));

    ctx->session = s;

    ngx_log_debug1(NGX_LOG_DEBUG_RTMP, s->connection->log, 0,
                   "http flv: join '%s'", name);

    stream = ngx_rtmp_live_get_stream(s, name, lacf->idle_streams);

    if (stream == NULL ||
        !(publisher || (*stream)->publishing || lacf->idle_streams))
    {
        ngx_log_error(NGX_LOG_ERR, s->connection->log, 0,
                      "http flv: stream not found");

        ngx_rtmp_finalize_session(s);

        return;
    }

    ctx->stream = *stream;
    ctx->next = (*stream)->ctx[NGX_RTMP_LIVE_TYPE_HTTP_FLV];

    (*stream)->ctx[NGX_RTMP_LIVE_TYPE_HTTP_FLV] = ctx;

    if (lacf->buflen) {
        s->out_buffer = 1;
    }

    ctx->cs[0].csid = NGX_RTMP_CSID_VIDEO;
    ctx->cs[1].csid = NGX_RTMP_CSID_AUDIO;

    if (!ctx->publishing && ctx->stream->active) {
        ngx_http_flv_start(s);
    }
}


static ngx_int_t
ngx_http_flv_close_stream(ngx_rtmp_session_t *s, ngx_rtmp_close_stream_t *v)
{
    ngx_rtmp_live_ctx_t            *ctx, **cctx;
    ngx_rtmp_live_stream_t        **stream;
    ngx_rtmp_live_app_conf_t       *lacf;

    if (s->proto != NGX_PROTO_TYPE_HTTP_FLV_PULL) {
        goto next;
    }

    lacf = ngx_rtmp_get_module_app_conf(s, ngx_rtmp_live_module);
    if (lacf == NULL) {
        goto next;
    }

    ctx = ngx_rtmp_get_module_ctx(s, ngx_rtmp_live_module);
    if (ctx == NULL) {
        goto next;
    }

    if (ctx->stream == NULL) {
        ngx_log_debug0(NGX_LOG_DEBUG_RTMP, s->connection->log, 0,
                       "http flv: not joined");
        goto next;
    }

    ngx_log_debug1(NGX_LOG_DEBUG_RTMP, s->connection->log, 0,
                   "http flv: leave '%s'", ctx->stream->name);

    for (cctx = &ctx->stream->ctx[NGX_RTMP_LIVE_TYPE_HTTP_FLV]; *cctx; cctx = &(*cctx)->next) {
        if (*cctx == ctx) {
            *cctx = ctx->next;
            break;
        }
    }

    if (ctx->publishing || ctx->stream->active) {
        ngx_http_flv_stop(s);
    }

    if (ctx->stream->ctx[NGX_RTMP_LIVE_TYPE_RTMP] ||
        ctx->stream->ctx[NGX_RTMP_LIVE_TYPE_HTTP_FLV] ||
        ctx->stream->pctx) {
        ctx->stream = NULL;
        goto next;
    }

    ngx_log_debug1(NGX_LOG_DEBUG_RTMP, s->connection->log, 0,
                   "live: delete empty stream '%s'",
                   ctx->stream->name);

    stream = ngx_rtmp_live_get_stream(s, ctx->stream->name, 0);
    if (stream == NULL) {
        goto next;
    }
    *stream = (*stream)->next;

    ctx->stream->next = lacf->free_streams;
    lacf->free_streams = ctx->stream;
    ctx->stream = NULL;

next:
    return next_close_stream(s, v);
}


static ngx_int_t
ngx_http_flv_play(ngx_rtmp_session_t *s, ngx_rtmp_play_t *v)
{
    ngx_http_flv_rtmp_ctx_t             *ctx;

    if (s->proto != NGX_PROTO_TYPE_HTTP_FLV_PULL) {
        goto next;
    }

    ctx = ngx_rtmp_get_module_ctx(s, ngx_http_flv_rtmpmodule);
    if (ctx == NULL) {
        goto next;
    }

    ngx_log_error(NGX_LOG_INFO, s->connection->log, 0,
                  "http flv play: name='%s' start=%uD duration=%uD reset=%d",
                  v->name, (uint32_t) v->start,
                  (uint32_t) v->duration, (uint32_t) v->reset);

    /* join stream as subscriber */

    ngx_http_flv_join(s, v->name, 0);

    ngx_rtmp_playing++;

next:
    return next_play(s, v);
}


static ngx_int_t
ngx_http_flv_rtmp_init(ngx_conf_t *cf)
{
    ngx_rtmp_core_main_conf_t   *cmcf;
    ngx_rtmp_handler_pt         *h;

    cmcf = ngx_rtmp_conf_get_module_main_conf(cf, ngx_rtmp_core_module);

    /* register raw event handlers */

    h = ngx_array_push(&cmcf->events[NGX_RTMP_CONNECT_END]);
    *h = ngx_http_flv_connect_end;

    /* chain handlers */

    next_play = ngx_rtmp_play;
    ngx_rtmp_play = ngx_http_flv_play;

    next_close_stream = ngx_rtmp_close_stream;
    ngx_rtmp_close_stream = ngx_http_flv_close_stream;

    return NGX_OK;
}
