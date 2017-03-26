
/*
 * Copyright (C) Gino Hu
 */


#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_rtmp.h>
#include "ngx_rtmp_hdl_module.h"


extern ngx_uint_t ngx_rtmp_playing;
ngx_uint_t  ngx_rtmp_hdl_naccepted;

typedef struct {
    ngx_flag_t                          hdl;
} ngx_rtmp_http_hdl_loc_conf_t;


static ngx_int_t ngx_rtmp_hdl_send_message(ngx_rtmp_session_t *s, ngx_chain_t *out, ngx_uint_t priority);
static ngx_int_t ngx_rtmp_http_hdl_handler(ngx_http_request_t *r);
static ngx_int_t ngx_rtmp_http_hdl_init(ngx_conf_t *cf);
static void * ngx_rtmp_http_hdl_create_conf(ngx_conf_t *cf);
static char * ngx_rtmp_http_hdl_merge_conf(ngx_conf_t *cf, void *parent, void *child);
static ngx_int_t ngx_rtmp_hdl_postconfiguration(ngx_conf_t *cf);
static void * ngx_rtmp_hdl_create_app_conf(ngx_conf_t *cf);
static char * ngx_rtmp_hdl_merge_app_conf(ngx_conf_t *cf, void *parent, void *child);
static ngx_int_t ngx_rtmp_http_hdl_get_info(ngx_str_t *uri, ngx_str_t *app, ngx_str_t *name);
static ngx_int_t ngx_rtmp_http_hdl_connect_local(ngx_http_request_t *r, ngx_str_t *app, ngx_str_t *name, ngx_int_t protocol);
static ngx_rtmp_session_t *ngx_rtmp_http_hdl_init_session(ngx_http_request_t *r, ngx_rtmp_addr_conf_t *addr_conf);
static ngx_int_t ngx_rtmp_http_hdl_init_connection(ngx_http_request_t *r, ngx_rtmp_conf_port_t *cf_port);
static ngx_int_t ngx_rtmp_hdl_connect_done(ngx_rtmp_session_t *s, ngx_rtmp_header_t *h, ngx_chain_t *in);
static ngx_int_t ngx_rtmp_hdl_av(ngx_rtmp_session_t *s, ngx_rtmp_header_t *h, ngx_chain_t *in);
static ngx_int_t ngx_rtmp_hdl_play_done(ngx_rtmp_session_t *s, ngx_rtmp_header_t *h, ngx_chain_t *in);


static ngx_command_t  ngx_rtmp_http_hdl_commands[] = {

    { ngx_string("hdl"),
      NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_TAKE1,
      ngx_conf_set_flag_slot,
      NGX_HTTP_LOC_CONF_OFFSET,
      offsetof(ngx_rtmp_http_hdl_loc_conf_t, hdl),
      NULL },

      ngx_null_command
};


static ngx_http_module_t  ngx_rtmp_http_hdl_module_ctx = {
    NULL,                          /* preconfiguration */
    ngx_rtmp_http_hdl_init,        /* postconfiguration */

    NULL,                          /* create main configuration */
    NULL,                          /* init main configuration */

    NULL,                          /* create server configuration */
    NULL,                          /* merge server configuration */

    ngx_rtmp_http_hdl_create_conf, /* create location configuration */
    ngx_rtmp_http_hdl_merge_conf   /* merge location configuration */
};


ngx_module_t  ngx_rtmp_http_hdl_module = {
    NGX_MODULE_V1,
    &ngx_rtmp_http_hdl_module_ctx, /* module context */
    ngx_rtmp_http_hdl_commands,    /* module directives */
    NGX_HTTP_MODULE,               /* module type */
    NULL,                          /* init master */
    NULL,                          /* init module */
    NULL,                          /* init process */
    NULL,                          /* init thread */
    NULL,                          /* exit thread */
    NULL,                          /* exit process */
    NULL,                          /* exit master */
    NGX_MODULE_V1_PADDING
};


static ngx_command_t ngx_rtmp_hdl_commands[] = {

    { ngx_string("hdl"),
      NGX_RTMP_MAIN_CONF|NGX_RTMP_SRV_CONF|NGX_RTMP_APP_CONF|NGX_CONF_TAKE1,
      ngx_conf_set_flag_slot,
      NGX_RTMP_APP_CONF_OFFSET,
      offsetof(ngx_rtmp_hdl_app_conf_t, hdl),
      NULL },

    ngx_null_command
};


static ngx_rtmp_module_t  ngx_rtmp_hdl_module_ctx = {
    NULL,                               /* preconfiguration */
    ngx_rtmp_hdl_postconfiguration,     /* postconfiguration */

    NULL,                               /* create main configuration */
    NULL,                               /* init main configuration */

    NULL,                               /* create server configuration */
    NULL,                               /* merge server configuration */

    ngx_rtmp_hdl_create_app_conf,       /* create application configuration */
    ngx_rtmp_hdl_merge_app_conf,        /* merge application configuration */
};


ngx_module_t  ngx_rtmp_hdl_module = {
    NGX_MODULE_V1,
    &ngx_rtmp_hdl_module_ctx,           /* module context */
    ngx_rtmp_hdl_commands,              /* module directives */
    NGX_RTMP_MODULE,                    /* module type */
    NULL,                               /* init master */
    NULL,                               /* init module */
    NULL,                               /* init process */
    NULL,                               /* init thread */
    NULL,                               /* exit thread */
    NULL,                               /* exit process */
    NULL,                               /* exit master */
    NGX_MODULE_V1_PADDING
};


static void
ngx_rtmp_hdl_send(ngx_event_t *wev)
{
    ngx_connection_t           *c;
    ngx_http_request_t         *r;
    ngx_rtmp_session_t         *s;
    ngx_int_t                   n;
    ngx_rtmp_core_srv_conf_t   *cscf;
    ngx_rtmp_http_hdl_ctx_t    *httpctx;
    ngx_rtmp_live_ctx_t 	   *ctx;

    c = wev->data;
    r = c->data;

    httpctx = ngx_http_get_module_ctx(r, ngx_rtmp_http_hdl_module);

    s = httpctx->s;

    if (c->destroyed) {
        return;
    }

    if (wev->timedout) {
        ngx_log_error(NGX_LOG_ERR, c->log, NGX_ETIMEDOUT,
                "client timed out");
        c->timedout = 1;
        ngx_rtmp_finalize_session(s);
        return;
    }

    if (wev->timer_set) {
        ngx_del_timer(wev);
    }

    if (s->out_chain == NULL && s->out_pos != s->out_last) {
        s->out_chain = s->out[s->out_pos];
        s->out_bpos = s->out_chain->buf->pos;
    }

    ctx = ngx_rtmp_get_module_ctx(s, ngx_rtmp_live_module);
    while (s->out_chain) {
        n = c->send(c, s->out_bpos, s->out_chain->buf->last - s->out_bpos);

        if (n == NGX_AGAIN || n == 0) {
            ngx_add_timer(c->write, s->timeout);
            if (ngx_handle_write_event(c->write, 0) != NGX_OK) {
                ngx_rtmp_finalize_session(s);
            }
            return;
        }

        if (n < 0) {
            ngx_rtmp_finalize_session(s);
            return;
        }

        s->out_bytes += n;
        s->ping_reset = 1;
        s->out_bpos += n;

        if (s->out_bpos == s->out_chain->buf->last) {
            s->out_chain = s->out_chain->next;
            if (s->out_chain == NULL) {
                cscf = ngx_rtmp_get_module_srv_conf(s, ngx_rtmp_core_module);
                ngx_rtmp_free_shared_chain(cscf, s->out[s->out_pos]);
                s->out[s->out_pos] = NULL;
                ++s->out_pos;
                s->out_pos %= s->out_queue;
                if (s->out_pos == s->out_last) {
                    break;
                }
                s->out_chain = s->out[s->out_pos];
            }
            s->out_bpos = s->out_chain->buf->pos;
        }
    }

    if (wev->active) {
        ngx_del_event(wev, NGX_WRITE_EVENT, 0);
    }

    ngx_event_process_posted((ngx_cycle_t *) ngx_cycle, &s->posted_dry_events);
}


static ngx_int_t
ngx_rtmp_hdl_send_message(ngx_rtmp_session_t *s, ngx_chain_t *out,
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
            "RTMP drop message bufs=%ui, priority=%ui, s->out_last=%d, s->out_pos=%d, s->out_queue=%d ",
            nmsg, priority, s->out_last, s->out_pos, s->out_queue);
        return NGX_AGAIN;
    }

    s->out[s->out_last++] = out;
    s->out_last %= s->out_queue;

    ngx_rtmp_acquire_shared_chain(out);

    ngx_log_debug3(NGX_LOG_DEBUG_RTMP, s->connection->log, 0,
            "RTMP send nmsg=%ui, priority=%ui #%ui",
            nmsg, priority, s->out_last);

    if (priority && s->out_buffer && nmsg < s->out_cork) {
        return NGX_OK;
    }

    if (!s->connection->write->active) {

        ngx_rtmp_hdl_send(s->connection->write);
    }

    return NGX_OK;
}


static ngx_int_t
ngx_rtmp_http_hdl_get_info(ngx_str_t *uri, ngx_str_t *app, ngx_str_t *name)
{
    size_t    len;

    if (uri == NULL || uri->len == 0) {

        return NGX_ERROR;
    }

    len = 0;
    for(; uri->data[len] == '/' || uri->len == len; ++ len); // skip first '/'

    app->data = &uri->data[len];                             // we got app

    for(; uri->data[len] != '/' || uri->len == len; ++ len); // reach next '/'

    app->len = &uri->data[len ++] - app->data;

    name->data = &uri->data[len];
    name->len = &uri->data[uri->len] - name->data
        - ngx_strlen(".flv");                                // we got name

    return NGX_OK;
}


static ngx_int_t
ngx_rtmp_http_hdl_play_local(ngx_http_request_t *r)
{
    static ngx_rtmp_play_t      v;

	ngx_rtmp_session_t         *s;
    ngx_rtmp_hdl_ctx_t         *ctx;
    ngx_rtmp_http_hdl_ctx_t    *httpctx;
    ngx_rtmp_core_srv_conf_t   *cscf;

    httpctx = ngx_http_get_module_ctx(r, ngx_rtmp_http_hdl_module);

    s = httpctx->s;

	ngx_memzero(&v, sizeof(ngx_rtmp_play_t));

    ngx_memcpy(v.name, s->name.data, ngx_min(s->name.len, sizeof(v.name) - 1));
    ngx_memcpy(v.args, s->args.data, ngx_min(s->args.len, sizeof(v.args) - 1));

    cscf = ngx_rtmp_get_module_srv_conf(s, ngx_rtmp_core_module);

    s->app_conf = cscf->ctx->app_conf;

    ctx = ngx_rtmp_get_module_ctx(s, ngx_rtmp_hdl_module);
    if (ctx == NULL) {
        ctx = ngx_pcalloc(s->pool, sizeof(ngx_rtmp_hdl_ctx_t));
        ngx_rtmp_set_ctx(s, ctx, ngx_rtmp_hdl_module);
    }

	return ngx_rtmp_cmd_start_play(s, &v);
}

static void
ngx_rtmp_hdl_close_session_handler(ngx_rtmp_session_t *s)
{
    ngx_connection_t                   *c;
    ngx_rtmp_core_srv_conf_t           *cscf;

    c = s->connection;

    cscf = ngx_rtmp_get_module_srv_conf(s, ngx_rtmp_core_module);

    ngx_log_error(NGX_LOG_INFO, c->log, 0, "hdl close session");

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
ngx_rtmp_http_hdl_connect_local(ngx_http_request_t *r, ngx_str_t *app, ngx_str_t *name, ngx_int_t protocol)
{
    static ngx_rtmp_connect_t   v;

    ngx_rtmp_session_t         *s;
    ngx_connection_t           *c;
    ngx_rtmp_hdl_ctx_t         *ctx;
    ngx_rtmp_http_hdl_ctx_t    *httpctx;

    httpctx = ngx_http_get_module_ctx(r, ngx_rtmp_http_hdl_module);

    s = httpctx->s;
    c = r->connection;

    ngx_memzero(&v, sizeof(ngx_rtmp_connect_t));

    ngx_memcpy(v.app, app->data, ngx_min(app->len, sizeof(v.app) - 1));
    ngx_memcpy(v.args, r->args.data, ngx_min(r->args.len, sizeof(v.args) - 1));
    ngx_memcpy(v.flashver, "HDL flashver", ngx_strlen("HDL flashver"));
    ngx_memcpy(v.swf_url, "HDL swf_url", ngx_strlen("HDL swf_url"));
    ngx_memcpy(v.tc_url, "HDL tc_url", ngx_strlen("HDL tc_url"));
    ngx_memcpy(v.page_url, "HDL page_url", ngx_strlen("HDL page_url"));

#define NGX_RTMP_SET_STRPAR(name) \
    do { \
        s->name.len = ngx_strlen(v.name); \
        if (s->name.len > 0) { \
            s->name.data = ngx_palloc(s->pool, s->name.len); \
            ngx_memcpy(s->name.data, v.name, s->name.len); \
        } \
    }while(0)

    NGX_RTMP_SET_STRPAR(app);
    NGX_RTMP_SET_STRPAR(args);
    NGX_RTMP_SET_STRPAR(flashver);
    NGX_RTMP_SET_STRPAR(swf_url);
    NGX_RTMP_SET_STRPAR(tc_url);
    NGX_RTMP_SET_STRPAR(page_url);

#undef NGX_RTMP_SET_STRPAR

    s->name.len = name->len;
    s->name.data = ngx_pstrdup(s->pool, name);

    s->protocol = protocol;

    ctx = ngx_rtmp_get_module_ctx(s, ngx_rtmp_hdl_module);
    if (ctx == NULL) {
        ctx = ngx_pcalloc(s->pool, sizeof(ngx_rtmp_hdl_ctx_t));
        ngx_rtmp_set_ctx(s, ctx, ngx_rtmp_hdl_module);
    }

    return ngx_rtmp_cmd_start_connect(s, &v);
}


static void
ngx_rtmp_http_hdl_cleanup(void *data)
{
    ngx_http_request_t         *r = data;
    ngx_rtmp_session_t		   *s;
    ngx_rtmp_http_hdl_ctx_t    *httpctx;

    httpctx = ngx_http_get_module_ctx(r, ngx_rtmp_http_hdl_module);

    s = httpctx->s;

    ngx_log_error(NGX_LOG_INFO, s->connection->log, 0, "hdl close connection");

    -- ngx_rtmp_hdl_naccepted;

    ngx_rtmp_hdl_close_session_handler(s);
}


static ngx_rtmp_session_t *
ngx_rtmp_http_hdl_init_session(ngx_http_request_t *r, ngx_rtmp_addr_conf_t *addr_conf)
{
    ngx_rtmp_core_srv_conf_t       *cscf;
    ngx_http_cleanup_t             *cln;
    ngx_rtmp_http_hdl_ctx_t        *httpctx;
    ngx_rtmp_session_t             *s;
    ngx_connection_t               *c;

    c = r->connection;

    s = ngx_pcalloc(r->pool, sizeof(ngx_rtmp_session_t) +
                    sizeof(ngx_chain_t *) * ((ngx_rtmp_core_srv_conf_t *)
                    addr_conf->ctx->srv_conf[ngx_rtmp_core_module
                    .ctx_index])->out_queue);
    if (s == NULL) {
        ngx_http_finalize_request(r, NGX_DECLINED);
        return NULL;
    }

    httpctx = ngx_pcalloc(r->pool, sizeof(ngx_rtmp_http_hdl_ctx_t));
    if (httpctx == NULL) {
        return NULL;
    }

    ngx_http_set_ctx(r, httpctx, ngx_rtmp_http_hdl_module);

    // attach rtmp session to http ctx.
    httpctx->s = s;

    s->pool = r->pool;

    s->r = r;

    s->addr_conf = addr_conf;

    s->main_conf = addr_conf->ctx->main_conf;
    s->srv_conf = addr_conf->ctx->srv_conf;

    s->addr_text = &addr_conf->addr_text;

    s->connection = c;

    cln = ngx_http_cleanup_add(r, 0);
    if (cln == NULL) {
        return NULL;
    }

    cln->handler = ngx_rtmp_http_hdl_cleanup;
    cln->data = r;

    s->ctx = ngx_pcalloc(s->pool, sizeof(void *) * ngx_rtmp_max_module);
    if (s->ctx == NULL) {
        ngx_rtmp_finalize_session(s);
        return NULL;
    }

    cscf = ngx_rtmp_get_module_srv_conf(s, ngx_rtmp_core_module);

    s->out_queue = cscf->out_queue;
    s->out_cork = cscf->out_cork;
    s->in_streams = ngx_pcalloc(s->pool, sizeof(ngx_rtmp_stream_t)
                                * cscf->max_streams);
    if (s->in_streams == NULL) {
        ngx_rtmp_finalize_session(s);
        return NULL;
    }
    
#if (nginx_version >= 1007005)
    ngx_queue_init(&s->posted_dry_events);
#endif

   s->epoch = ngx_current_msec;
   s->timeout = cscf->timeout;
   s->buflen = cscf->buflen;
   ngx_rtmp_set_chunk_size(s, NGX_RTMP_DEFAULT_CHUNK_SIZE);

   if (ngx_rtmp_fire_event(s, NGX_RTMP_CONNECT, NULL, NULL) != NGX_OK) {

       ngx_rtmp_finalize_session(s);
       return NULL;
   }

    return s;
}


static ngx_int_t
ngx_rtmp_http_hdl_init_connection(ngx_http_request_t *r, ngx_rtmp_conf_port_t *cf_port)
{
	ngx_uint_t             i;
	ngx_rtmp_port_t       *port;
    ngx_rtmp_session_t    *s;
	ngx_rtmp_addr_conf_t  *addr_conf;
	ngx_connection_t      *c;
	struct sockaddr       *sa;
	struct sockaddr_in    *sin;
    ngx_rtmp_in_addr_t    *addr;
	ngx_int_t              unix_socket;
#if (NGX_HAVE_INET6)
    struct sockaddr_in6   *sin6;
    ngx_rtmp_in6_addr_t   *addr6;
#endif

	c = r->connection;

	++ngx_rtmp_hdl_naccepted;

	port = cf_port->ports.elts;
    unix_socket = 0;

    if (port->naddrs > 1) {

        /*
         * There are several addresses on this port and one of them
         * is the "*:port" wildcard so getsockname() is needed to determine
         * the server address.
         *
         * AcceptEx() already gave this address.
         */

        if (ngx_connection_local_sockaddr(c, NULL, 0) != NGX_OK) {
            ngx_rtmp_close_connection(c);
            return NGX_ERROR;
        }

        sa = c->local_sockaddr;

        switch (sa->sa_family) {

#if (NGX_HAVE_INET6)
        case AF_INET6:
            sin6 = (struct sockaddr_in6 *) sa;

            addr6 = port->addrs;

            /* the last address is "*" */

            for (i = 0; i < port->naddrs - 1; i++) {
                if (ngx_memcmp(&addr6[i].addr6, &sin6->sin6_addr, 16) == 0) {
                    break;
                }
            }

            addr_conf = &addr6[i].conf;

            break;
#endif

        case AF_UNIX:
            unix_socket = 1;

        default: /* AF_INET */
            sin = (struct sockaddr_in *) sa;

            addr = port->addrs;

            /* the last address is "*" */

            for (i = 0; i < port->naddrs - 1; i++) {
                if (addr[i].addr == sin->sin_addr.s_addr) {
                    break;
                }
            }

            addr_conf = &addr[i].conf;

            break;
        }

    } else {
        switch (c->local_sockaddr->sa_family) {

#if (NGX_HAVE_INET6)
        case AF_INET6:
            addr6 = port->addrs;
            addr_conf = &addr6[0].conf;
            break;
#endif

        case AF_UNIX:
            unix_socket = 1;

        default: /* AF_INET */
            addr = port->addrs;
            addr_conf = &addr[0].conf;
            break;
        }
    }

	ngx_log_error(NGX_LOG_INFO, c->log, 0, "hdl client connected '%V'", &c->addr_text);

    s = ngx_rtmp_http_hdl_init_session(r, addr_conf);
    if (s == NULL) {
        return NGX_ERROR;
    }

    r->read_event_handler = ngx_http_test_reading;
    r->blocked = 1;

    c->write->handler = ngx_rtmp_hdl_send;
	// c->read->handler = ngx_rtmp_http_flv_recv;  TODO: We do not need to be careful of http read handler.

	s->auto_pushed = unix_socket;

	return NGX_OK;
}


static ngx_int_t
ngx_rtmp_http_hdl_handler(ngx_http_request_t *r)
{
    ngx_rtmp_http_hdl_loc_conf_t        *hlcf;
    ngx_rtmp_core_main_conf_t           *cmcf;
    ngx_rtmp_conf_port_t                *port;
    ngx_int_t                            protocol, rc = 0;
    ngx_str_t                            app, name;
    ngx_int_t                            nslash;
    size_t                               i;

    cmcf = ngx_rtmp_core_main_conf;
    if (cmcf == NULL || cmcf->ports.nelts == 0) {
        return NGX_ERROR;
    }

    hlcf = ngx_http_get_module_loc_conf(r, ngx_rtmp_http_hdl_module);
    if (hlcf == NULL || !hlcf->hdl) {
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

    if (nslash != 2) {

        return NGX_DECLINED;
    }

	if (r->uri.data[r->uri.len - 1] == 'v' &&
		r->uri.data[r->uri.len - 2] == 'l' &&
		r->uri.data[r->uri.len - 3] == 'f' &&
		r->uri.data[r->uri.len - 4] == '.') {
		protocol = NGX_RTMP_PULL_TYPE_HDL;
	} else {
		return NGX_DECLINED;
	}

    rc = ngx_http_discard_request_body(r);
    if (rc != NGX_OK) {
        return rc;
    }

    ngx_log_error(NGX_LOG_INFO, r->connection->log, 0,
        "http_hdl handle uri: '%V' args: '%V'", &r->uri, &r->args);

    if (ngx_rtmp_http_hdl_get_info(&r->uri, &app, &name) != NGX_OK) {

        return NGX_DECLINED;
    }

    ngx_log_error(NGX_LOG_INFO, r->connection->log, 0,
              "http_hdl handle app: '%V' name: '%V'", &app, &name);

    port = cmcf->ports.elts;

    if (ngx_rtmp_http_hdl_init_connection(r, &port[0]) != NGX_OK) {

        return NGX_DECLINED;
    }

    if (ngx_rtmp_http_hdl_connect_local(r, &app, &name, protocol) != NGX_OK) {

        return NGX_DECLINED;
    }

    return NGX_OK;
}


static ngx_int_t
ngx_rtmp_http_hdl_init(ngx_conf_t *cf)
{
    ngx_http_handler_pt        *h;
    ngx_http_core_main_conf_t  *cmcf;

    cmcf = ngx_http_conf_get_module_main_conf(cf, ngx_http_core_module);

    h = ngx_array_push(&cmcf->phases[NGX_HTTP_CONTENT_PHASE].handlers);
    if (h == NULL) {
        return NGX_ERROR;
    }

    *h = ngx_rtmp_http_hdl_handler;

    return NGX_OK;
}


static void *
ngx_rtmp_http_hdl_create_conf(ngx_conf_t *cf)
{
    ngx_rtmp_http_hdl_loc_conf_t  *hlcf;

    hlcf = ngx_palloc(cf->pool, sizeof(ngx_rtmp_http_hdl_loc_conf_t));
    if (hlcf == NULL) {
        return NULL;
    }

    hlcf->hdl = NGX_CONF_UNSET;

    return hlcf;
}


static char *
ngx_rtmp_http_hdl_merge_conf(ngx_conf_t *cf, void *parent, void *child)
{
    ngx_rtmp_http_hdl_loc_conf_t *prev = parent;
    ngx_rtmp_http_hdl_loc_conf_t *conf = child;

    ngx_conf_merge_value(conf->hdl, prev->hdl, 0);

    return NGX_CONF_OK;
}


static void *
ngx_rtmp_hdl_create_app_conf(ngx_conf_t *cf)
{
    ngx_rtmp_hdl_app_conf_t *conf;

    conf = ngx_pcalloc(cf->pool, sizeof(ngx_rtmp_hdl_app_conf_t));
    if (conf == NULL) {
        return NULL;
    }

    conf->hdl = NGX_CONF_UNSET;

    return conf;
}


static char *
ngx_rtmp_hdl_merge_app_conf(ngx_conf_t *cf, void *parent, void *child)
{
    ngx_rtmp_hdl_app_conf_t    *prev = parent;
    ngx_rtmp_hdl_app_conf_t    *conf = child;

    ngx_conf_merge_value(conf->hdl, prev->hdl, 1);

    return NGX_CONF_OK;
}


static ngx_int_t
ngx_rtmp_hdl_connect_done(ngx_rtmp_session_t *s, ngx_rtmp_header_t *h,
    ngx_chain_t *in)
{
    ngx_http_request_t    *r;

    r = s->r;

    return ngx_rtmp_http_hdl_play_local(r);
}


static ngx_chain_t *
ngx_rtmp_hdl_append_tag_bufs(ngx_rtmp_session_t *s, ngx_chain_t *tag,
    ngx_rtmp_header_t *ch)
{
    ngx_chain_t                    *tail, *head, *taghead, prepkt;
    ngx_buf_t                       prebuf;
    uint32_t                        presize, presizebuf;
    u_char                         *p, *ph;
    ngx_rtmp_core_srv_conf_t       *cscf;

    cscf = ngx_rtmp_get_module_srv_conf(s, ngx_rtmp_core_module);

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

    *ph++ = (u_char)ch->type;

    p = (u_char*)&presize;
    *ph++ = p[2];
    *ph++ = p[1];
    *ph++ = p[0];

    p = (u_char*)&ch->timestamp;
    *ph++ = p[2];
    *ph++ = p[1];
    *ph++ = p[0];
    *ph++ = p[3];

    *ph++ = 0;
    *ph++ = 0;
    *ph++ = 0;

    return taghead;
}

#ifdef NGX_DEBUG
static void
ngx_rtmp_hdl_dump_message(ngx_rtmp_session_t *s, const char *type,
    ngx_chain_t *in)
{
    u_char buf[256], *p, *pp;
    u_char hex[] = "0123456789abcdef";

    for (pp = buf, p = in->buf->pos;
         p < in->buf->last && pp < buf + sizeof(buf) - 1;
         ++p)
    {
        *pp++ = hex[*p >> 4];
        *pp++ = hex[*p & 0x0f];
    }

    *pp = 0;

    ngx_log_error(NGX_LOG_ERR, s->connection->log, 0,
                   "hdl: %s message %s", type, buf);
}
#endif

static void
ngx_rtmp_hdl_gop_cache_send(ngx_rtmp_session_t *ss)
{
    ngx_rtmp_session_t             *s;
    ngx_chain_t                    *pkt, *apkt, *mpkt, *meta, *header;
    ngx_rtmp_live_ctx_t            *pctx, *pushctx, *pullctx;
    ngx_rtmp_codec_ctx_t           *codec_ctx;
    ngx_rtmp_core_srv_conf_t       *cscf;
    ngx_rtmp_live_app_conf_t       *lacf;
    ngx_rtmp_live_gop_cache_t      *cache;
    ngx_rtmp_live_gop_frame_t       *gop_frame;
    ngx_rtmp_header_t               ch, lh, mh;
    ngx_uint_t                      meta_version;
    uint32_t                        delta;
    u_char                         *pos;
    ngx_int_t                       csidx;
    ngx_rtmp_live_chunk_stream_t   *cs;

    lacf = ngx_rtmp_get_module_app_conf(ss, ngx_rtmp_live_module);
    if (lacf == NULL) {
        return;
    }

    cscf = ngx_rtmp_get_module_srv_conf(ss, ngx_rtmp_core_module);
    if (cscf == NULL) {
        return;
    }

    pullctx = ngx_rtmp_get_module_ctx(ss, ngx_rtmp_live_module);
    if (pullctx == NULL || pullctx->stream == NULL) {
        return;
    }

    if (!ngx_hdl_pull_type(ss->protocol)) {
        return;
    }

    for (pctx = pullctx->stream->ctx; pctx; pctx = pctx->next) {
        if (pctx->publishing) {
            break;
        }
    }

    if (pctx == NULL) {
        return;
    }

    pkt = NULL;
    apkt = NULL;
    mpkt = NULL;
    header = NULL;
    meta = NULL;
    meta_version = 0;

    ngx_memzero(&ch, sizeof(ch));
    ngx_memzero(&mh, sizeof(mh));

    pushctx = pctx;
    s       = pushctx->session;
    ss      = pullctx->session;

    if (!lacf->gop_cache) {
        return;
    }

    codec_ctx = ngx_rtmp_get_module_ctx(s, ngx_rtmp_codec_module);
    if (codec_ctx == NULL) {
        return;
    }

    for (cache = pushctx->gop_cache; cache; cache = cache->next) {
        if (cache->gop_codec_info.meta) {
            mh = cache->gop_codec_info.metah;
            meta = cache->gop_codec_info.meta;
            meta_version = cache->gop_codec_info.meta_version;
        }

        /* send metadata */
        if (meta && meta->buf && meta_version != pullctx->meta_version) {
            ngx_log_debug0(NGX_LOG_DEBUG_RTMP, ss->connection->log, 0,
                           "hdl: meta");

            pos = meta->buf->pos;
            meta->buf->pos = meta->buf->start + NGX_RTMP_MAX_CHUNK_HEADER;

            mpkt = ngx_rtmp_hdl_append_tag_bufs(ss, meta, &mh);

            meta->buf->pos = pos;

            if (ngx_rtmp_hdl_send_message(ss, mpkt, 0) == NGX_OK) {
#ifdef NGX_DEBUG
                ngx_rtmp_hdl_dump_message(ss, "Send Meta", mpkt);
#endif
                pullctx->meta_version = meta_version;
            }

            if (mpkt) {
                ngx_rtmp_free_shared_chain(cscf, mpkt);
            }
        }


        for (gop_frame = cache->gop_frame_head; gop_frame; gop_frame = gop_frame->next) {
            csidx = !(lacf->interleave || gop_frame->h.type == NGX_RTMP_MSG_VIDEO);

            cs = &pullctx->cs[csidx];

            lh = ch = gop_frame->h;

            if (cs->active) {

                lh.timestamp = cs->timestamp;
            }

            delta = ch.timestamp - lh.timestamp;

            if (!cs->active) {

                header = gop_frame->h.type == NGX_RTMP_MSG_VIDEO ? cache->gop_codec_info.video_header : codec_ctx->aac_header;
                if (header) {

                    apkt = ngx_rtmp_hdl_append_tag_bufs(s, header, &lh);
                }

                if (apkt && ngx_rtmp_hdl_send_message(ss, apkt, 0) == NGX_OK) {

                    cs->timestamp = lh.timestamp;
                    cs->active = 1;
                    ss->current_time = cs->timestamp;
                }
            }

            pkt = ngx_rtmp_hdl_append_tag_bufs(s, gop_frame->frame, &ch);

            if (ngx_rtmp_hdl_send_message(ss, pkt, gop_frame->prio) != NGX_OK) {
                ++pctx->ndropped;

                cs->dropped += delta;

                return;
            }

            if (pkt) {
                ngx_rtmp_free_shared_chain(cscf, pkt);
                pkt = NULL;
            }

            if (apkt) {
                ngx_rtmp_free_shared_chain(cscf, apkt);
                apkt = NULL;
            }

            ngx_log_debug3(NGX_LOG_DEBUG_RTMP, ss->connection->log, 0,
                           "hdl_gop_send: send tag type='%s' prio='%d' ltimestamp='%uD'",
                           gop_frame->h.type == NGX_RTMP_MSG_AUDIO ? "audio" : "video",
                           gop_frame->prio,
                           lh.timestamp);

            cs->timestamp += delta;
            ss->current_time = cs->timestamp;
        }
    }
}

static ngx_int_t
ngx_rtmp_hdl_av(ngx_rtmp_session_t *s, ngx_rtmp_header_t *h,
                 ngx_chain_t *in)
{
    ngx_rtmp_live_app_conf_t       *lacf;
    ngx_rtmp_hdl_app_conf_t        *hacf;
    ngx_rtmp_core_srv_conf_t       *cscf;
    ngx_rtmp_live_ctx_t            *ctx, *pctx;
    ngx_rtmp_codec_ctx_t           *codec_ctx = NULL;
    ngx_rtmp_header_t               ch, lh, mh;
    ngx_rtmp_session_t             *ss;
    ngx_int_t                       mandatory;
    u_char                         *pos;
    ngx_uint_t                      csidx;
    ngx_uint_t                      prio;
    ngx_uint_t                      meta_version;
    ngx_chain_t                    *header, *fpkt, *apkt, *mpkt, *meta;
    ngx_rtmp_live_chunk_stream_t   *cs;
    uint32_t                        delta = 0;
#ifdef NGX_DEBUG
    const char                     *type_s;

    type_s = (h->type == NGX_RTMP_MSG_VIDEO ? "video" : "audio"); 
#endif

    lacf = ngx_rtmp_get_module_app_conf(s, ngx_rtmp_live_module);
    if (lacf == NULL) {
        return NGX_ERROR;
    }

    hacf = ngx_rtmp_get_module_app_conf(s, ngx_rtmp_hdl_module);
    if (hacf == NULL) {
        return NGX_ERROR;
    }

    if (!lacf->live || !hacf->hdl) {
        return NGX_OK;
    }

    if (in == NULL || in->buf == NULL) {
        return NGX_OK;
    }

    ctx = ngx_rtmp_get_module_ctx(s, ngx_rtmp_live_module);
    if (ctx == NULL || ctx->stream == NULL) {
        return NGX_OK;
    }

    if (ctx->publishing == 0) {
        ngx_log_debug1(NGX_LOG_DEBUG_RTMP, s->connection->log, 0,
                       "live_hdl: %s from non-publisher", type_s);
        return NGX_OK;
    }

    apkt = NULL;
    fpkt = NULL;
    mpkt = NULL;
    header = NULL;
    meta = NULL;
    meta_version = 0;
    mandatory = 0;

    prio = (h->type == NGX_RTMP_MSG_VIDEO ?
            ngx_rtmp_get_video_frame_type(in) : 0);

    cscf = ngx_rtmp_get_module_srv_conf(s, ngx_rtmp_core_module);

    csidx = !(lacf->interleave || h->type == NGX_RTMP_MSG_VIDEO);

    cs = &ctx->cs[csidx];

    ngx_memzero(&ch, sizeof(ch));
    ngx_memzero(&mh, sizeof(mh));

    ch.timestamp = h->timestamp;
    ch.msid = NGX_RTMP_MSID;
    ch.csid = cs->csid;
    ch.type = h->type;

    lh = ch;

    if (cs->active) {
        lh.timestamp = cs->timestamp;
    }

    delta = ch.timestamp - lh.timestamp;

    codec_ctx = ngx_rtmp_get_module_ctx(s, ngx_rtmp_codec_module);

    if (codec_ctx) {

        if (h->type == NGX_RTMP_MSG_AUDIO) {
            header = codec_ctx->aac_header;

            if (codec_ctx->audio_codec_id == NGX_RTMP_AUDIO_AAC &&
                ngx_rtmp_is_codec_header(in)) // is or not audio header
            {
                prio = 0;
                mandatory = 1;
            }

        } else {
            header = codec_ctx->video_header;

            if (codec_ctx->video_codec_id == NGX_RTMP_VIDEO_H264 &&
                ngx_rtmp_is_codec_header(in)) // is or not video header
            {
                prio = 0;
                mandatory = 1;
            }
        }

        if (codec_ctx->meta) {
            mh = codec_ctx->metah;
            meta = codec_ctx->meta;
            meta_version = codec_ctx->meta_version;
        }
    }

    /* broadcast to all subscribers */
    fpkt = ngx_rtmp_hdl_append_tag_bufs(s, in, &ch);

    for (pctx = ctx->stream->ctx; pctx; pctx = pctx->next) {
        if (pctx == ctx || pctx->paused) {
            continue;
        }

        ss = pctx->session;
        cs = &pctx->cs[csidx];

        if (!ngx_hdl_pull_type(ss->protocol)) {
            continue;
        }

        /* send metadata */

        if (meta && meta_version != pctx->meta_version) {
            ngx_log_debug0(NGX_LOG_DEBUG_RTMP, ss->connection->log, 0,
                           "live_hdl: meta");

            pos = meta->buf->pos;
            meta->buf->pos = meta->buf->start + NGX_RTMP_MAX_CHUNK_HEADER;

            mpkt = ngx_rtmp_hdl_append_tag_bufs(ss, meta, &mh);

            meta->buf->pos = pos;

            if (ngx_rtmp_hdl_send_message(ss, mpkt, 0) == NGX_OK) {
                pctx->meta_version = meta_version;
#ifdef NGX_DEBUG
                ngx_rtmp_hdl_dump_message(ss, "Send Meta", mpkt);
#endif
            }

            if (mpkt) {
                ngx_rtmp_free_shared_chain(cscf, mpkt);
            }
        }

        /* sync stream */

        if (cs->active && (lacf->sync && cs->dropped > lacf->sync)) {
            ngx_log_debug2(NGX_LOG_DEBUG_RTMP, ss->connection->log, 0,
                           "live_hdl: sync %s dropped=%uD", type_s, cs->dropped);

            cs->active = 0;
            cs->dropped = 0;
        }

        /* absolute packet */

        if (!cs->active) {

            if (mandatory) {
                ngx_log_debug0(NGX_LOG_DEBUG_RTMP, ss->connection->log, 0,
                               "live_hdl: skipping header");
                continue;
            }

            if (lacf->wait_video && h->type == NGX_RTMP_MSG_AUDIO &&
                !pctx->cs[0].active && !lacf->gop_cache)
            {
                ngx_log_debug0(NGX_LOG_DEBUG_RTMP, ss->connection->log, 0,
                               "live_hdl: waiting for video");
                continue;
            }

            if (lacf->wait_key && prio != NGX_RTMP_VIDEO_KEY_FRAME &&
               (lacf->interleave || h->type == NGX_RTMP_MSG_VIDEO) &&
               !lacf->gop_cache)
            {
                ngx_log_debug0(NGX_LOG_DEBUG_RTMP, ss->connection->log, 0,
                               "live_hdl: skip non-key");
                continue;
            }

            if (header) {

                /* send absolute codec header */

                ngx_log_debug2(NGX_LOG_DEBUG_RTMP, ss->connection->log, 0,
                               "live_hdl: abs %s header timestamp=%uD",
                               type_s, lh.timestamp);

                apkt = ngx_rtmp_hdl_append_tag_bufs(s, header, &lh);

                if (ngx_rtmp_hdl_send_message(ss, apkt, 0) != NGX_OK) {
                    continue;
                }

                cs->timestamp = lh.timestamp;
                cs->active = 1;
                ss->current_time = cs->timestamp;

                if (apkt) {
                    ngx_rtmp_free_shared_chain(cscf, apkt);
                    apkt = NULL;
                }
            }
        }

        /* send relative packet */

        ngx_log_debug3(NGX_LOG_DEBUG_RTMP, ss->connection->log, 0,
                       "live_hdl: rel %s prio '%d' packet delta=%uD",
                       type_s, prio, delta);

        if (ngx_rtmp_hdl_send_message(ss, fpkt, prio) != NGX_OK) {
            ++pctx->ndropped;

            cs->dropped += delta;

            continue;
        }

        cs->timestamp += delta;
        ss->current_time = cs->timestamp;

        ngx_rtmp_update_bandwidth(&pctx->bw_out, h->mlen);
    }

    if (fpkt) {
        ngx_rtmp_free_shared_chain(cscf, fpkt);
        fpkt = NULL;
    }

    return NGX_OK;
}

static ngx_int_t
ngx_rtmp_hdl_message(ngx_rtmp_session_t *s, ngx_rtmp_header_t *h,
                     ngx_chain_t *in)
{
    ngx_rtmp_live_app_conf_t       *lacf;
    ngx_rtmp_hdl_app_conf_t        *hacf;
    ngx_rtmp_core_srv_conf_t       *cscf;
    ngx_rtmp_live_ctx_t            *ctx, *pctx;
    ngx_chain_t                    *mpkt;
    ngx_rtmp_session_t             *ss;
    ngx_rtmp_codec_ctx_t           *codec_ctx;
    ngx_chain_t                    *msg;
    u_char                         *pos;
#ifdef NGX_DEBUG
    const char                     *type_s; 

    type_s = (h->type == NGX_RTMP_MSG_VIDEO ? "video" : "audio"); 
#endif

    lacf = ngx_rtmp_get_module_app_conf(s, ngx_rtmp_live_module);
    if (lacf == NULL) {
        return NGX_ERROR;
    }

    hacf = ngx_rtmp_get_module_app_conf(s, ngx_rtmp_hdl_module);
    if (hacf == NULL) {
        return NGX_ERROR;
    }

    if (!lacf->live || !hacf->hdl) {
        return NGX_OK;
    }

    cscf = ngx_rtmp_get_module_srv_conf(s, ngx_rtmp_core_module);
    if(cscf == NULL) {
        return NGX_ERROR;
    }

    codec_ctx = ngx_rtmp_get_module_ctx(s, ngx_rtmp_codec_module);
    if(codec_ctx == NULL || codec_ctx->msg == NULL) {
        return NGX_ERROR;
    }

    ctx = ngx_rtmp_get_module_ctx(s, ngx_rtmp_live_module);
    if (ctx == NULL || ctx->stream == NULL) {
        return NGX_OK;
    }

    if (ctx->publishing == 0) {
        ngx_log_debug1(NGX_LOG_DEBUG_RTMP, s->connection->log, 0,
                       "live_hdl: %s from non-publisher", type_s);
        return NGX_OK;
    }

    msg = codec_ctx->msg;
    pos = msg->buf->pos;
    msg->buf->pos = msg->buf->start + NGX_RTMP_MAX_CHUNK_HEADER;

    mpkt = ngx_rtmp_hdl_append_tag_bufs(s, codec_ctx->msg, &codec_ctx->msgh);

    msg->buf->pos = pos;

    if(mpkt == NULL) {
        return NGX_ERROR;
    }

    /* broadcast to all subscribers */
    for (pctx = ctx->stream->ctx; pctx; pctx = pctx->next) {
        if (pctx == ctx || pctx->paused) {
            continue;
        }

        ss = pctx->session;

        if (!ngx_hdl_pull_type(ss->protocol)) {
            continue;
        }

        if (ngx_rtmp_hdl_send_message(ss, mpkt, 0) == NGX_OK) {
#if (NGX_DEBUG)
            ngx_rtmp_hdl_dump_message(s, "onMessage", mpkt);
#endif
        }
    }

    if (mpkt) {
        ngx_rtmp_free_shared_chain(cscf, mpkt);
    }

    return NGX_OK;
}

static ngx_int_t
ngx_rtmp_hdl_play_done(ngx_rtmp_session_t *s, ngx_rtmp_header_t *h,
    ngx_chain_t *in)
{
    static u_char httpheader[] = {
        "HTTP/1.1 200 OK\r\n"
        "Cache-Control: no-cache\r\n"
        "Content-Type: video/x-flv\r\n"
        "Connection: close\r\n"
        "Expires: -1\r\n"
        "Pragma: no-cache\r\n"
        "\r\n"
    };

    static u_char flvheader[] = {
        0x46, /* 'F' */
        0x4c, /* 'L' */
        0x56, /* 'V' */
        0x01, /* version = 1 */
        0x05, /* 00000 1 0 1 = has audio & video */
        0x00,
        0x00,
        0x00,
        0x09, /* header size */
        0x00,
        0x00,
        0x00,
        0x00  /* PreviousTagSize0 (not actually a header) */
    };

    ngx_rtmp_hdl_ctx_t             *hctx;
    ngx_rtmp_core_srv_conf_t       *cscf;
    ngx_rtmp_hdl_app_conf_t        *lacf;
    ngx_chain_t                     c1, c2, *pkt;
    ngx_buf_t                       b1, b2;

    lacf = ngx_rtmp_get_module_app_conf(s, ngx_rtmp_hdl_module);
    if (lacf == NULL) {
        return NGX_ERROR;
    }

    if (!lacf->hdl) {
        return NGX_OK;
    }

    cscf = ngx_rtmp_get_module_srv_conf(s, ngx_rtmp_core_module);

    hctx = ngx_rtmp_get_module_ctx(s, ngx_rtmp_hdl_module);
    if (hctx == NULL) {
        return NGX_OK;
    }

    if (hctx->initialized) {
        return NGX_OK;
    }

    c1.buf = &b1;
    c2.buf = &b2;
    c1.next = &c2;
    c2.next = NULL;

    b1.start = b1.pos = &httpheader[0];
    b1.end = b1.last = b1.pos + sizeof(httpheader) - 1;

    b2.start = b2.pos = &flvheader[0];
    b2.end = b2.last = b2.pos + sizeof(flvheader);

    pkt = ngx_rtmp_append_shared_bufs(cscf, NULL, &c1);

    ngx_rtmp_hdl_send_message(s, pkt, 0);

    ngx_rtmp_free_shared_chain(cscf, pkt);

    ngx_rtmp_hdl_gop_cache_send(s);

    if (!hctx->initialized) { 
        hctx->initialized = 1;
    }

    return NGX_OK;
}


static ngx_int_t
ngx_rtmp_hdl_postconfiguration(ngx_conf_t *cf)
{
    ngx_rtmp_core_main_conf_t   *cmcf;
    ngx_rtmp_handler_pt         *h;

    cmcf = ngx_rtmp_conf_get_module_main_conf(cf, ngx_rtmp_core_module);

    /* register raw event handlers */

    h = ngx_array_push(&cmcf->events[NGX_RTMP_MSG_AUDIO]);
    *h = ngx_rtmp_hdl_av;

    h = ngx_array_push(&cmcf->events[NGX_RTMP_MSG_VIDEO]);
    *h = ngx_rtmp_hdl_av;

    h = ngx_array_push(&cmcf->events[NGX_RTMP_CONNECT_DONE]);
    *h = ngx_rtmp_hdl_connect_done;

    h = ngx_array_push(&cmcf->events[NGX_RTMP_PLAY_DONE]);
    *h = ngx_rtmp_hdl_play_done;

    h = ngx_array_push(&cmcf->events[NGX_RTMP_ON_MESSAGE]);
    *h = ngx_rtmp_hdl_message;

    return NGX_OK;
}
