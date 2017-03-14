
/*
 * Copyright (C) Roman Arutyunyan
 */


#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_event.h>
#include <nginx.h>
#include "ngx_rtmp.h"


static char *ngx_rtmp_block(ngx_conf_t *cf, ngx_command_t *cmd, void *conf);
static ngx_int_t ngx_rtmp_add_server(ngx_conf_t *cf, ngx_rtmp_core_srv_conf_t *cscf,
    ngx_rtmp_conf_addr_t *addr);
static char *ngx_rtmp_optimize_servers(ngx_conf_t *cf, ngx_rtmp_core_main_conf_t *cmcf, ngx_array_t *ports);
static ngx_int_t ngx_rtmp_hls_play_domains(ngx_conf_t *cf, ngx_rtmp_core_main_conf_t *cmcf,
    ngx_rtmp_conf_addr_t *addr);
static ngx_int_t ngx_rtmp_rtmp_play_domains(ngx_conf_t *cf, ngx_rtmp_core_main_conf_t *cmcf,
    ngx_rtmp_conf_addr_t *addr);
static ngx_int_t ngx_rtmp_hdl_play_domains(ngx_conf_t *cf, ngx_rtmp_core_main_conf_t *cmcf,
    ngx_rtmp_conf_addr_t *addr);
static ngx_int_t ngx_rtmp_rtmp_publish_domains(ngx_conf_t *cf, ngx_rtmp_core_main_conf_t *cmcf,
    ngx_rtmp_conf_addr_t *addr);
static ngx_int_t ngx_rtmp_add_addrs(ngx_conf_t *cf, ngx_rtmp_port_t *mport,
    ngx_rtmp_conf_addr_t *addr);
#if (NGX_HAVE_INET6)
static ngx_int_t ngx_rtmp_add_addrs6(ngx_conf_t *cf, ngx_rtmp_port_t *mport,
    ngx_rtmp_conf_addr_t *addr);
#endif
static ngx_int_t ngx_rtmp_cmp_conf_addrs(const void *one, const void *two);
static int ngx_libc_cdecl ngx_rtmp_cmp_dns_wildcards(const void *one,
    const void *two);
static ngx_int_t ngx_rtmp_init_events(ngx_conf_t *cf,
        ngx_rtmp_core_main_conf_t *cmcf);
static ngx_int_t ngx_rtmp_init_event_handlers(ngx_conf_t *cf,
        ngx_rtmp_core_main_conf_t *cmcf);
static char * ngx_rtmp_merge_applications(ngx_conf_t *cf,
        ngx_array_t *applications, void **app_conf, ngx_rtmp_module_t *module,
        ngx_uint_t ctx_index);
static ngx_int_t ngx_rtmp_add_addresses(ngx_conf_t *cf, ngx_rtmp_core_srv_conf_t *cscf,
    ngx_rtmp_conf_port_t *port, ngx_rtmp_listen_t *lsopt);
static ngx_int_t ngx_rtmp_add_address(ngx_conf_t *cf, ngx_rtmp_core_srv_conf_t *cscf,
    ngx_rtmp_conf_port_t *port, ngx_rtmp_listen_t *lsopt);

static ngx_int_t ngx_rtmp_init_listening(ngx_conf_t *cf, ngx_rtmp_conf_port_t *port);

static ngx_listening_t * ngx_rtmp_add_listening(ngx_conf_t *cf, ngx_rtmp_conf_addr_t *addr);

static void ngx_rtmp_time_update_handle_http_response(ngx_rtmp_core_main_conf_t *cmcf,
        ngx_connection_t* c);
static ngx_chain_t* ngx_rtmp_time_update_gen_http_request(ngx_peer_connection_t* pc,
        ngx_rtmp_core_main_conf_t *cmcf);
static void ngx_rtmp_time_update_read_event_handler(ngx_event_t* rev);
static void ngx_rtmp_time_update_write_event_handler(ngx_event_t *wev);
static void ngx_rtmp_time_update(ngx_resolver_ctx_t* ctx); 
static ngx_int_t ngx_rtmp_init_process(ngx_cycle_t *cycle);


#if (nginx_version >= 1007011)
ngx_queue_t                         ngx_rtmp_init_queue;
#elif (nginx_version >= 1007005)
ngx_thread_volatile ngx_queue_t     ngx_rtmp_init_queue;
#else
ngx_thread_volatile ngx_event_t    *ngx_rtmp_init_queue;
#endif


ngx_uint_t  ngx_rtmp_max_module;


static ngx_command_t  ngx_rtmp_commands[] = {

    { ngx_string("rtmp"),
      NGX_MAIN_CONF|NGX_CONF_BLOCK|NGX_CONF_NOARGS,
      ngx_rtmp_block,
      0,
      0,
      NULL },

      ngx_null_command
};


static ngx_core_module_t  ngx_rtmp_module_ctx = {
    ngx_string("rtmp"),
    NULL,
    NULL
};


ngx_module_t  ngx_rtmp_module = {
    NGX_MODULE_V1,
    &ngx_rtmp_module_ctx,                  /* module context */
    ngx_rtmp_commands,                     /* module directives */
    NGX_CORE_MODULE,                       /* module type */
    NULL,                                  /* init master */
    NULL,                                  /* init module */
    ngx_rtmp_init_process,                 /* init process */
    NULL,                                  /* init thread */
    NULL,                                  /* exit thread */
    NULL,                                  /* exit process */
    NULL,                                  /* exit master */
    NGX_MODULE_V1_PADDING
};


static char *
ngx_rtmp_block(ngx_conf_t *cf, ngx_command_t *cmd, void *conf)
{
    char                        *rv;
    ngx_uint_t                   m, mi, s;
    ngx_conf_t                   pcf;
    ngx_rtmp_module_t           *module;
    ngx_rtmp_conf_ctx_t         *ctx;
    ngx_rtmp_core_srv_conf_t    *cscf, **cscfp;
    ngx_rtmp_core_main_conf_t   *cmcf;

    ctx = ngx_pcalloc(cf->pool, sizeof(ngx_rtmp_conf_ctx_t));
    if (ctx == NULL) {
        return NGX_CONF_ERROR;
    }

    *(ngx_rtmp_conf_ctx_t **) conf = ctx;

    /* count the number of the rtmp modules and set up their indices */

    ngx_rtmp_max_module = 0;
    for (m = 0; ngx_modules[m]; m++) {
        if (ngx_modules[m]->type != NGX_RTMP_MODULE) {
            continue;
        }

        ngx_modules[m]->ctx_index = ngx_rtmp_max_module++;
    }


    /* the rtmp main_conf context, it is the same in the all rtmp contexts */

    ctx->main_conf = ngx_pcalloc(cf->pool,
                                 sizeof(void *) * ngx_rtmp_max_module);
    if (ctx->main_conf == NULL) {
        return NGX_CONF_ERROR;
    }


    /*
     * the rtmp null srv_conf context, it is used to merge
     * the server{}s' srv_conf's
     */

    ctx->srv_conf = ngx_pcalloc(cf->pool, sizeof(void *) * ngx_rtmp_max_module);
    if (ctx->srv_conf == NULL) {
        return NGX_CONF_ERROR;
    }


    /*
     * the rtmp null app_conf context, it is used to merge
     * the server{}s' app_conf's
     */

    ctx->app_conf = ngx_pcalloc(cf->pool, sizeof(void *) * ngx_rtmp_max_module);
    if (ctx->app_conf == NULL) {
        return NGX_CONF_ERROR;
    }


    /*
     * create the main_conf's, the null srv_conf's, and the null app_conf's
     * of the all rtmp modules
     */

    for (m = 0; ngx_modules[m]; m++) {
        if (ngx_modules[m]->type != NGX_RTMP_MODULE) {
            continue;
        }

        module = ngx_modules[m]->ctx;
        mi = ngx_modules[m]->ctx_index;

        if (module->create_main_conf) {
            ctx->main_conf[mi] = module->create_main_conf(cf);
            if (ctx->main_conf[mi] == NULL) {
                return NGX_CONF_ERROR;
            }
        }

        if (module->create_srv_conf) {
            ctx->srv_conf[mi] = module->create_srv_conf(cf);
            if (ctx->srv_conf[mi] == NULL) {
                return NGX_CONF_ERROR;
            }
        }

        if (module->create_app_conf) {
            ctx->app_conf[mi] = module->create_app_conf(cf);
            if (ctx->app_conf[mi] == NULL) {
                return NGX_CONF_ERROR;
            }
        }
    }

    pcf = *cf;
    cf->ctx = ctx;

    for (m = 0; ngx_modules[m]; m++) {
        if (ngx_modules[m]->type != NGX_RTMP_MODULE) {
            continue;
        }

        module = ngx_modules[m]->ctx;

        if (module->preconfiguration) {
            if (module->preconfiguration(cf) != NGX_OK) {
                return NGX_CONF_ERROR;
            }
        }
    }

    /* parse inside the rtmp{} block */

    cf->module_type = NGX_RTMP_MODULE;
    cf->cmd_type = NGX_RTMP_MAIN_CONF;
    rv = ngx_conf_parse(cf, NULL);

    if (rv != NGX_CONF_OK) {
        *cf = pcf;
        return rv;
    }


    /* init rtmp{} main_conf's, merge the server{}s' srv_conf's */

    cmcf = ctx->main_conf[ngx_rtmp_core_module.ctx_index];
    cscfp = cmcf->servers.elts;

    for (m = 0; ngx_modules[m]; m++) {
        if (ngx_modules[m]->type != NGX_RTMP_MODULE) {
            continue;
        }

        module = ngx_modules[m]->ctx;
        mi = ngx_modules[m]->ctx_index;

        /* init rtmp{} main_conf's */

        cf->ctx = ctx;

        if (module->init_main_conf) {
            rv = module->init_main_conf(cf, ctx->main_conf[mi]);
            if (rv != NGX_CONF_OK) {
                *cf = pcf;
                return rv;
            }
        }

        for (s = 0; s < cmcf->servers.nelts; s++) {

            /* merge the server{}s' srv_conf's */

            cf->ctx = cscfp[s]->ctx;

            if (module->merge_srv_conf) {
                rv = module->merge_srv_conf(cf,
                                            ctx->srv_conf[mi],
                                            cscfp[s]->ctx->srv_conf[mi]);
                if (rv != NGX_CONF_OK) {
                    *cf = pcf;
                    return rv;
                }
            }

            if (module->merge_app_conf) {

                /* merge the server{}'s app_conf */

                /*ctx->app_conf = cscfp[s]->ctx->loc_conf;*/

                rv = module->merge_app_conf(cf,
                                            ctx->app_conf[mi],
                                            cscfp[s]->ctx->app_conf[mi]);
                if (rv != NGX_CONF_OK) {
                    *cf = pcf;
                    return rv;
                }

                /* merge the applications{}' app_conf's */

                cscf = cscfp[s]->ctx->srv_conf[ngx_rtmp_core_module.ctx_index];

                rv = ngx_rtmp_merge_applications(cf, &cscf->applications,
                                            cscfp[s]->ctx->app_conf,
                                            module, mi);
                if (rv != NGX_CONF_OK) {
                    *cf = pcf;
                    return rv;
                }
            }

        }
    }


    if (ngx_rtmp_init_events(cf, cmcf) != NGX_OK) {
        return NGX_CONF_ERROR;
    }

    for (m = 0; ngx_modules[m]; m++) {
        if (ngx_modules[m]->type != NGX_RTMP_MODULE) {
            continue;
        }

        module = ngx_modules[m]->ctx;

        if (module->postconfiguration) {
            if (module->postconfiguration(cf) != NGX_OK) {
                return NGX_CONF_ERROR;
            }
        }
    }

    *cf = pcf;

    if (ngx_rtmp_init_event_handlers(cf, cmcf) != NGX_OK) {
        return NGX_CONF_ERROR;
    }

    return ngx_rtmp_optimize_servers(cf, cmcf, &cmcf->ports);
}


static char *
ngx_rtmp_merge_applications(ngx_conf_t *cf, ngx_array_t *applications,
            void **app_conf, ngx_rtmp_module_t *module, ngx_uint_t ctx_index)
{
    char                           *rv;
    ngx_rtmp_conf_ctx_t            *ctx, saved;
    ngx_rtmp_core_app_conf_t      **cacfp;
    ngx_uint_t                      n;
    ngx_rtmp_core_app_conf_t       *cacf;

    if (applications == NULL) {
        return NGX_CONF_OK;
    }

    ctx = (ngx_rtmp_conf_ctx_t *) cf->ctx;
    saved = *ctx;

    cacfp = applications->elts;
    for (n = 0; n < applications->nelts; ++n, ++cacfp) {

        ctx->app_conf = (*cacfp)->app_conf;

        rv = module->merge_app_conf(cf, app_conf[ctx_index],
                (*cacfp)->app_conf[ctx_index]);
        if (rv != NGX_CONF_OK) {
            return rv;
        }

        cacf = (*cacfp)->app_conf[ngx_rtmp_core_module.ctx_index];
        rv = ngx_rtmp_merge_applications(cf, &cacf->applications,
                                         (*cacfp)->app_conf,
                                         module, ctx_index);
        if (rv != NGX_CONF_OK) {
            return rv;
        }
    }

    *ctx = saved;

    return NGX_CONF_OK;
}


static ngx_int_t
ngx_rtmp_init_events(ngx_conf_t *cf, ngx_rtmp_core_main_conf_t *cmcf)
{
    size_t                      n;

    for(n = 0; n < NGX_RTMP_MAX_EVENT; ++n) {
        if (ngx_array_init(&cmcf->events[n], cf->pool, 1,
                sizeof(ngx_rtmp_handler_pt)) != NGX_OK)
        {
            return NGX_ERROR;
        }
    }

    if (ngx_array_init(&cmcf->amf, cf->pool, 1,
                sizeof(ngx_rtmp_amf_handler_t)) != NGX_OK)
    {
        return NGX_ERROR;
    }

    return NGX_OK;
}


static int ngx_libc_cdecl
ngx_rtmp_cmp_dns_wildcards(const void *one, const void *two)
{
    ngx_hash_key_t  *first, *second;

    first = (ngx_hash_key_t *) one;
    second = (ngx_hash_key_t *) two;

    return ngx_dns_strcmp(first->key.data, second->key.data);
}


static ngx_int_t
ngx_rtmp_init_event_handlers(ngx_conf_t *cf, ngx_rtmp_core_main_conf_t *cmcf)
{
    ngx_hash_init_t             calls_hash;
    ngx_rtmp_handler_pt        *eh;
    ngx_rtmp_amf_handler_t     *h;
    ngx_hash_key_t             *ha;
    size_t                      n, m;

    static size_t               pm_events[] = {
        NGX_RTMP_MSG_CHUNK_SIZE,
        NGX_RTMP_MSG_ABORT,
        NGX_RTMP_MSG_ACK,
        NGX_RTMP_MSG_ACK_SIZE,
        NGX_RTMP_MSG_BANDWIDTH
    };

    static size_t               amf_events[] = {
        NGX_RTMP_MSG_AMF_CMD,
        NGX_RTMP_MSG_AMF_META,
        NGX_RTMP_MSG_AMF_SHARED,
        NGX_RTMP_MSG_AMF3_CMD,
        NGX_RTMP_MSG_AMF3_META,
        NGX_RTMP_MSG_AMF3_SHARED
    };

    /* init standard protocol events */
    for(n = 0; n < sizeof(pm_events) / sizeof(pm_events[0]); ++n) {
        eh = ngx_array_push(&cmcf->events[pm_events[n]]);
        *eh = ngx_rtmp_protocol_message_handler;
    }

    /* init amf events */
    for(n = 0; n < sizeof(amf_events) / sizeof(amf_events[0]); ++n) {
        eh = ngx_array_push(&cmcf->events[amf_events[n]]);
        *eh = ngx_rtmp_amf_message_handler;
    }

    /* init user protocol events */
    eh = ngx_array_push(&cmcf->events[NGX_RTMP_MSG_USER]);
    *eh = ngx_rtmp_user_message_handler;

    /* aggregate to audio/video map */
    eh = ngx_array_push(&cmcf->events[NGX_RTMP_MSG_AGGREGATE]);
    *eh = ngx_rtmp_aggregate_message_handler;

    /* init amf callbacks */
    ngx_array_init(&cmcf->amf_arrays, cf->pool, 1, sizeof(ngx_hash_key_t));

    h = cmcf->amf.elts;
    for(n = 0; n < cmcf->amf.nelts; ++n, ++h) {
        ha = cmcf->amf_arrays.elts;
        for(m = 0; m < cmcf->amf_arrays.nelts; ++m, ++ha) {
            if (h->name.len == ha->key.len
                    && !ngx_strncmp(h->name.data, ha->key.data, ha->key.len))
            {
                break;
            }
        }
        if (m == cmcf->amf_arrays.nelts) {
            ha = ngx_array_push(&cmcf->amf_arrays);
            ha->key = h->name;
            ha->key_hash = ngx_hash_key_lc(ha->key.data, ha->key.len);
            ha->value = ngx_array_create(cf->pool, 1,
                    sizeof(ngx_rtmp_handler_pt));
            if (ha->value == NULL) {
                return NGX_ERROR;
            }
        }

        eh = ngx_array_push((ngx_array_t*)ha->value);
        *eh = h->handler;
    }

    calls_hash.hash = &cmcf->amf_hash;
    calls_hash.key = ngx_hash_key_lc;
    calls_hash.max_size = 512;
    calls_hash.bucket_size = ngx_cacheline_size;
    calls_hash.name = "amf_hash";
    calls_hash.pool = cf->pool;
    calls_hash.temp_pool = NULL;

    if (ngx_hash_init(&calls_hash, cmcf->amf_arrays.elts, cmcf->amf_arrays.nelts)
            != NGX_OK)
    {
        return NGX_ERROR;
    }

    return NGX_OK;
}


static ngx_int_t
ngx_rtmp_add_addresses(ngx_conf_t *cf, ngx_rtmp_core_srv_conf_t *cscf,
    ngx_rtmp_conf_port_t *port, ngx_rtmp_listen_t *lsopt)
{
    u_char                *p;
    size_t                 len, off;
    ngx_uint_t             i, default_server;
    struct sockaddr       *sa;
    ngx_rtmp_conf_addr_t  *addr;
#if (NGX_HAVE_UNIX_DOMAIN)
    struct sockaddr_un    *saun;
#endif

    /*
     * we cannot compare whole sockaddr struct's as kernel
     * may fill some fields in inherited sockaddr struct's
     */

    sa = &lsopt->u.sockaddr;

    switch (sa->sa_family) {

#if (NGX_HAVE_INET6)
    case AF_INET6:
        off = offsetof(struct sockaddr_in6, sin6_addr);
        len = 16;
        break;
#endif

#if (NGX_HAVE_UNIX_DOMAIN)
    case AF_UNIX:
        off = offsetof(struct sockaddr_un, sun_path);
        len = sizeof(saun->sun_path);
        break;
#endif

    default: /* AF_INET */
        off = offsetof(struct sockaddr_in, sin_addr);
        len = 4;
        break;
    }

    p = lsopt->u.sockaddr_data + off;

    addr = port->addrs.elts;

    for (i = 0; i < port->addrs.nelts; i++) {

        if (ngx_memcmp(p, addr[i].opt.u.sockaddr_data + off, len) != 0) {
            continue;
        }

        /* the address is already in the address list */

        if (ngx_rtmp_add_server(cf, cscf, &addr[i]) != NGX_OK) {
            return NGX_ERROR;
        }

        /* preserve default_server bit during listen options overwriting */
        default_server = addr[i].opt.default_server;

        /* check the duplicate "default" server for this address:port */

        if (lsopt->default_server) {

            if (default_server) {
                ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                        "a duplicate default server for %s", addr[i].opt.sockaddr);
                return NGX_ERROR;
            }

            default_server = 1;
            addr[i].default_server = cscf;
        }

        addr[i].opt.default_server = default_server;

        return NGX_OK;
    }

    /* add the address to the addresses list that bound to this port */

    return ngx_rtmp_add_address(cf, cscf, port, lsopt);
}


/*
 * add the server address, the server names and the server core module
 * configurations to the port list
 */
static ngx_int_t
ngx_rtmp_add_address(ngx_conf_t *cf, ngx_rtmp_core_srv_conf_t *cscf,
    ngx_rtmp_conf_port_t *port, ngx_rtmp_listen_t *lsopt)
{
    ngx_rtmp_conf_addr_t  *addr;

    if (port->addrs.elts == NULL) {
        if (ngx_array_init(&port->addrs, cf->temp_pool, 4,
                           sizeof(ngx_rtmp_conf_addr_t))
            != NGX_OK)
        {
            return NGX_ERROR;
        }
    }

    addr = ngx_array_push(&port->addrs);
    if (addr == NULL) {
        return NGX_ERROR;
    }

    addr->ctx = lsopt->ctx;
    addr->opt = *lsopt;
    addr->hls_play_hash.buckets = NULL;
    addr->hls_play_hash.size = 0;
    addr->hls_play_wc_head = NULL;
    addr->hls_play_wc_tail = NULL;
    addr->rtmp_play_hash.buckets = NULL;
    addr->rtmp_play_hash.size = 0;
    addr->rtmp_play_wc_head = NULL;
    addr->rtmp_play_wc_tail = NULL;
    addr->rtmp_publish_hash.buckets = NULL;
    addr->rtmp_publish_hash.size = 0;
    addr->rtmp_publish_wc_head = NULL;
    addr->rtmp_publish_wc_tail = NULL;

    addr->default_server = cscf;
    addr->servers.elts = NULL;

    return ngx_rtmp_add_server(cf, cscf, addr);
}


static ngx_int_t
ngx_rtmp_add_server(ngx_conf_t *cf, ngx_rtmp_core_srv_conf_t *cscf,
    ngx_rtmp_conf_addr_t *addr)
{
    ngx_uint_t                  i;
    ngx_rtmp_core_srv_conf_t  **server;

    if (addr->servers.elts == NULL) {
        if (ngx_array_init(&addr->servers, cf->temp_pool, 4,
                           sizeof(ngx_rtmp_core_srv_conf_t *))
            != NGX_OK)
        {
            return NGX_ERROR;
        }

    } else {
        server = addr->servers.elts;
        for (i = 0; i < addr->servers.nelts; i++) {
            if (server[i] == cscf) {
                ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                                   "a duplicate listen %s", addr->opt.sockaddr);
                return NGX_ERROR;
            }
        }
    }

    server = ngx_array_push(&addr->servers);
    if (server == NULL) {
        return NGX_ERROR;
    }

    *server = cscf;

    return NGX_OK;
}

static char *
ngx_rtmp_optimize_servers(ngx_conf_t *cf, ngx_rtmp_core_main_conf_t *cmcf, ngx_array_t *ports)
{
    ngx_uint_t             p, a;
    ngx_rtmp_conf_port_t  *port;
    ngx_rtmp_conf_addr_t  *addr;

    port = ports->elts;
    for (p = 0; p < ports->nelts; p++) {

        ngx_sort(port[p].addrs.elts, (size_t) port[p].addrs.nelts,
                 sizeof(ngx_rtmp_conf_addr_t), ngx_rtmp_cmp_conf_addrs);

        addr = port[p].addrs.elts;

        for (a = 0; a < port[p].addrs.nelts; a++) {

            if (addr[a].servers.nelts > 0) {

                if (ngx_rtmp_hls_play_domains(cf, cmcf, &addr[a]) != NGX_OK ||
                    ngx_rtmp_rtmp_play_domains(cf, cmcf, &addr[a]) != NGX_OK ||
                    ngx_rtmp_hdl_play_domains(cf, cmcf, &addr[a]) != NGX_OK ||
                    ngx_rtmp_rtmp_publish_domains(cf, cmcf, &addr[a]) != NGX_OK) {

                    return NGX_CONF_ERROR;
                }
            }
        }

        if (ngx_rtmp_init_listening(cf, &port[p]) != NGX_OK) {
            return NGX_CONF_ERROR;
        }
    }

    return NGX_CONF_OK;
}


static ngx_int_t
ngx_rtmp_add_addrs(ngx_conf_t *cf, ngx_rtmp_port_t *mport,
    ngx_rtmp_conf_addr_t *addr)
{
    ngx_rtmp_virtual_names_t *vn;
    ngx_rtmp_in_addr_t       *addrs;
    struct sockaddr_in       *sin;
    ngx_uint_t                i;
    u_char                   *p;
    size_t                    len;
    u_char                    buf[NGX_SOCKADDR_STRLEN];

    mport->addrs = ngx_pcalloc(cf->pool, mport->naddrs * sizeof(ngx_rtmp_in_addr_t));
    if (mport->addrs == NULL) {
        return NGX_ERROR;
    }

    addrs = mport->addrs;

    for (i = 0; i < mport->naddrs; i++) {

        sin = &addr[i].opt.u.sockaddr_in;
        addrs[i].addr = sin->sin_addr.s_addr;

        addrs[i].conf.ctx = addr[i].ctx;
        addrs[i].conf.default_server = addr[i].default_server;
        
        len = ngx_sock_ntop(&addr[i].opt.u.sockaddr,
#if (nginx_version >= 1005003)
                            addr[i].opt.socklen,
#endif
                            buf, NGX_SOCKADDR_STRLEN, 1);

        p = ngx_pnalloc(cf->pool, len);
        if (p == NULL) {
            return NGX_ERROR;
        }

        ngx_memcpy(p, buf, len);

        addrs[i].conf.addr_text.len = len;
        addrs[i].conf.addr_text.data = p;
        addrs[i].conf.proxy_protocol = addr->opt.proxy_protocol;

        if (addr[i].hls_play_hash.buckets == NULL
            && (addr[i].hls_play_wc_head == NULL
                || addr[i].hls_play_wc_head->hash.buckets == NULL)
            && (addr[i].hls_play_wc_tail == NULL
                || addr[i].hls_play_wc_tail->hash.buckets == NULL)
            )
        {
            continue;
        }

        if (addr[i].rtmp_play_hash.buckets == NULL
            && (addr[i].rtmp_play_wc_head == NULL
                || addr[i].rtmp_play_wc_head->hash.buckets == NULL)
            && (addr[i].rtmp_play_wc_tail == NULL
                || addr[i].rtmp_play_wc_tail->hash.buckets == NULL)
            )
        {
            continue;
        }

        if (addr[i].rtmp_publish_hash.buckets == NULL
            && (addr[i].rtmp_publish_wc_head == NULL
                || addr[i].rtmp_publish_wc_head->hash.buckets == NULL)
            && (addr[i].rtmp_publish_wc_tail == NULL
                || addr[i].rtmp_publish_wc_tail->hash.buckets == NULL)
            )
        {
            continue;
        }

        vn = ngx_palloc(cf->pool, sizeof(ngx_rtmp_virtual_names_t));
        if (vn == NULL) {
            return NGX_ERROR;
        }

        addrs[i].conf.vnames = vn;

        vn->hls_play_names.hash = addr[i].hls_play_hash;
        vn->hls_play_names.wc_head = addr[i].hls_play_wc_head;
        vn->hls_play_names.wc_tail = addr[i].hls_play_wc_tail;

        vn->rtmp_play_names.hash = addr[i].rtmp_play_hash;
        vn->rtmp_play_names.wc_head = addr[i].rtmp_play_wc_head;
        vn->rtmp_play_names.wc_tail = addr[i].rtmp_play_wc_tail;

        vn->hdl_play_names.hash = addr[i].hdl_play_hash;
        vn->hdl_play_names.wc_head = addr[i].hdl_play_wc_head;
        vn->hdl_play_names.wc_tail = addr[i].hdl_play_wc_tail;

        vn->rtmp_publish_names.hash = addr[i].rtmp_publish_hash;
        vn->rtmp_publish_names.wc_head = addr[i].rtmp_publish_wc_head;
        vn->rtmp_publish_names.wc_tail = addr[i].rtmp_publish_wc_tail;
    }

    return NGX_OK;
}


#if (NGX_HAVE_INET6)

static ngx_int_t
ngx_rtmp_add_addrs6(ngx_conf_t *cf, ngx_rtmp_port_t *mport,
    ngx_rtmp_conf_addr_t *addr)
{
    u_char               *p;
    size_t                len;
    ngx_uint_t            i;
    ngx_rtmp_in6_addr_t  *addrs6;
    struct sockaddr_in6  *sin6;
    u_char                buf[NGX_SOCKADDR_STRLEN];

    mport->addrs = ngx_pcalloc(cf->pool,
                               mport->naddrs * sizeof(ngx_rtmp_in6_addr_t));
    if (mport->addrs == NULL) {
        return NGX_ERROR;
    }

    addrs6 = mport->addrs;

    for (i = 0; i < mport->naddrs; i++) {

        sin6 = (struct sockaddr_in6 *) addr[i].sockaddr;
        addrs6[i].addr6 = sin6->sin6_addr;

        addrs6[i].conf.ctx = addr[i].ctx;
        addrs6[i].conf.default_server = addr[i].default_server;
        len = ngx_sock_ntop(addr[i].sockaddr,
#if (nginx_version >= 1005003)
                            addr[i].socklen,
#endif
                            buf, NGX_SOCKADDR_STRLEN, 1);

        p = ngx_pnalloc(cf->pool, len);
        if (p == NULL) {
            return NGX_ERROR;
        }

        ngx_memcpy(p, buf, len);

        addrs6[i].conf.addr_text.len = len;
        addrs6[i].conf.addr_text.data = p;
        addrs6[i].conf.proxy_protocol = addr->proxy_protocol;
    }

    return NGX_OK;
}

#endif


static ngx_int_t
ngx_rtmp_cmp_conf_addrs(const void *one, const void *two)
{
    ngx_rtmp_conf_addr_t  *first, *second;

    first = (ngx_rtmp_conf_addr_t *) one;
    second = (ngx_rtmp_conf_addr_t *) two;

    if (first->wildcard) {
        /* a wildcard must be the last resort, shift it to the end */
        return 1;
    }

    if (first->bind && !second->bind) {
        /* shift explicit bind()ed addresses to the start */
        return -1;
    }

    if (!first->bind && second->bind) {
        /* shift explicit bind()ed addresses to the start */
        return 1;
    }

    /* do not sort by default */

    return 0;
}


ngx_int_t
ngx_rtmp_fire_event(ngx_rtmp_session_t *s, ngx_uint_t evt,
        ngx_rtmp_header_t *h, ngx_chain_t *in)
{
    ngx_rtmp_core_main_conf_t      *cmcf;
    ngx_array_t                    *ch;
    ngx_rtmp_handler_pt            *hh;
    size_t                          n;

    cmcf = ngx_rtmp_get_module_main_conf(s, ngx_rtmp_core_module);

    ch = &cmcf->events[evt];
    hh = ch->elts;
    for(n = 0; n < ch->nelts; ++n, ++hh) {
        if (*hh && (*hh)(s, h, in) != NGX_OK) {
            return NGX_ERROR;
        }
    }
    return NGX_OK;
}


void *
ngx_rtmp_rmemcpy(void *dst, const void* src, size_t n)
{
    u_char     *d, *s;

    d = dst;
    s = (u_char*)src + n - 1;

    while(s >= (u_char*)src) {
        *d++ = *s--;
    }

    return dst;
}


static ngx_int_t
ngx_rtmp_hls_play_domains(ngx_conf_t *cf, ngx_rtmp_core_main_conf_t *cmcf,
    ngx_rtmp_conf_addr_t *addr)
{
    ngx_int_t                   rc;
    ngx_uint_t                  n, s;
    ngx_hash_init_t             hash;
    ngx_hash_keys_arrays_t      ha;
    ngx_rtmp_server_name_t     *name = NULL;
    ngx_rtmp_core_srv_conf_t  **cscfp;

    ngx_memzero(&ha, sizeof(ngx_hash_keys_arrays_t));

    ha.temp_pool = ngx_create_pool(NGX_DEFAULT_POOL_SIZE, cf->log);
    if (ha.temp_pool == NULL) {
        return NGX_ERROR;
    }

    ha.pool = cf->pool;

    if (ngx_hash_keys_array_init(&ha, NGX_HASH_LARGE) != NGX_OK) {
        goto failed;
    }

    cscfp = addr->servers.elts;
    for (s = 0; s < addr->servers.nelts; s++) {

        name = cscfp[s]->hls_play_domains.elts;
        for (n = 0; n < cscfp[s]->hls_play_domains.nelts; n++) {

            rc = ngx_hash_add_key(&ha, &name[n].name, name[n].server,
                                  NGX_HASH_WILDCARD_KEY);

            if (rc == NGX_ERROR) {
                return NGX_ERROR;
            }

            if (rc == NGX_DECLINED) {
                ngx_log_error(NGX_LOG_EMERG, cf->log, 0,
                              "invalid hls_play_domains name or wildcard \"%V\" on %s",
                              &name[n].name, addr->opt.sockaddr);
                return NGX_ERROR;
            }

            if (rc == NGX_BUSY) {
                ngx_log_error(NGX_LOG_EMERG, cf->log, 0,
                              "conflicting hls_play_domains name \"%V\" on %s, ignored",
                              &name[n].name, addr->opt.sockaddr);
            }
        }
    }

    hash.key = ngx_hash_key_lc;
    hash.max_size = cmcf->server_names_hash_max_size;
    hash.bucket_size = cmcf->server_names_hash_bucket_size;
    hash.name = "server_names_hash";
    hash.pool = cf->pool;

    if (ha.keys.nelts) {
        hash.hash = &addr->hls_play_hash;
        hash.temp_pool = NULL;

        if (ngx_hash_init(&hash, ha.keys.elts, ha.keys.nelts) != NGX_OK) {
            goto failed;
        }
    }

    if (ha.dns_wc_head.nelts) {

        ngx_qsort(ha.dns_wc_head.elts, (size_t) ha.dns_wc_head.nelts,
                  sizeof(ngx_hash_key_t), ngx_rtmp_cmp_dns_wildcards);

        hash.hash = NULL;
        hash.temp_pool = ha.temp_pool;

        if (ngx_hash_wildcard_init(&hash, ha.dns_wc_head.elts,
                                   ha.dns_wc_head.nelts)
            != NGX_OK)
        {
            goto failed;
        }

        addr->hls_play_wc_head = (ngx_hash_wildcard_t *) hash.hash;
    }

    if (ha.dns_wc_tail.nelts) {

        ngx_qsort(ha.dns_wc_tail.elts, (size_t) ha.dns_wc_tail.nelts,
                  sizeof(ngx_hash_key_t), ngx_rtmp_cmp_dns_wildcards);

        hash.hash = NULL;
        hash.temp_pool = ha.temp_pool;

        if (ngx_hash_wildcard_init(&hash, ha.dns_wc_tail.elts,
                                   ha.dns_wc_tail.nelts)
            != NGX_OK)
        {
            goto failed;
        }

        addr->hls_play_wc_tail = (ngx_hash_wildcard_t *) hash.hash;
    }

    ngx_destroy_pool(ha.temp_pool);

    return NGX_OK;

failed:

    ngx_destroy_pool(ha.temp_pool);

    return NGX_ERROR;
}


static ngx_int_t
ngx_rtmp_rtmp_play_domains(ngx_conf_t *cf, ngx_rtmp_core_main_conf_t *cmcf,
    ngx_rtmp_conf_addr_t *addr)
{
    ngx_int_t                   rc;
    ngx_uint_t                  n, s;
    ngx_hash_init_t             hash;
    ngx_hash_keys_arrays_t      ha;
    ngx_rtmp_server_name_t     *name = NULL;
    ngx_rtmp_core_srv_conf_t  **cscfp;

    ngx_memzero(&ha, sizeof(ngx_hash_keys_arrays_t));

    ha.temp_pool = ngx_create_pool(NGX_DEFAULT_POOL_SIZE, cf->log);
    if (ha.temp_pool == NULL) {
        return NGX_ERROR;
    }

    ha.pool = cf->pool;

    if (ngx_hash_keys_array_init(&ha, NGX_HASH_LARGE) != NGX_OK) {
        goto failed;
    }

    cscfp = addr->servers.elts;
    for (s = 0; s < addr->servers.nelts; s++) {

        name = cscfp[s]->rtmp_play_domains.elts;
        for (n = 0; n < cscfp[s]->rtmp_play_domains.nelts; n++) {

            rc = ngx_hash_add_key(&ha, &name[n].name, name[n].server,
                                  NGX_HASH_WILDCARD_KEY);
            
            if (rc == NGX_ERROR) {
                return NGX_ERROR;
            }

            if (rc == NGX_DECLINED) {
                ngx_log_error(NGX_LOG_EMERG, cf->log, 0,
                              "invalid rtmp_play_domains name or wildcard \"%V\" on %s",
                              &name[n].name, addr->opt.sockaddr);
                return NGX_ERROR;
            }

            if (rc == NGX_BUSY) {
                ngx_log_error(NGX_LOG_EMERG, cf->log, 0,
                              "conflicting rtmp_play_domains name \"%V\" on %s, ignored",
                              &name[n].name, addr->opt.sockaddr);
            }
        }
    }

    hash.key = ngx_hash_key_lc;
    hash.max_size = cmcf->server_names_hash_max_size;
    hash.bucket_size = cmcf->server_names_hash_bucket_size;
    hash.name = "server_names_hash";
    hash.pool = cf->pool;

    if (ha.keys.nelts) {
        hash.hash = &addr->rtmp_play_hash;
        hash.temp_pool = NULL;

        if (ngx_hash_init(&hash, ha.keys.elts, ha.keys.nelts) != NGX_OK) {
            goto failed;
        }
    }

    if (ha.dns_wc_head.nelts) {

        ngx_qsort(ha.dns_wc_head.elts, (size_t) ha.dns_wc_head.nelts,
                  sizeof(ngx_hash_key_t), ngx_rtmp_cmp_dns_wildcards);

        hash.hash = NULL;
        hash.temp_pool = ha.temp_pool;

        if (ngx_hash_wildcard_init(&hash, ha.dns_wc_head.elts,
                                   ha.dns_wc_head.nelts)
            != NGX_OK)
        {
            goto failed;
        }

        addr->rtmp_play_wc_head = (ngx_hash_wildcard_t *) hash.hash;
    }

    if (ha.dns_wc_tail.nelts) {

        ngx_qsort(ha.dns_wc_tail.elts, (size_t) ha.dns_wc_tail.nelts,
                  sizeof(ngx_hash_key_t), ngx_rtmp_cmp_dns_wildcards);

        hash.hash = NULL;
        hash.temp_pool = ha.temp_pool;

        if (ngx_hash_wildcard_init(&hash, ha.dns_wc_tail.elts,
                                   ha.dns_wc_tail.nelts)
            != NGX_OK)
        {
            goto failed;
        }

        addr->rtmp_play_wc_tail = (ngx_hash_wildcard_t *) hash.hash;
    }

    ngx_destroy_pool(ha.temp_pool);

    return NGX_OK;

failed:

    ngx_destroy_pool(ha.temp_pool);

    return NGX_ERROR;
}


static ngx_int_t
ngx_rtmp_hdl_play_domains(ngx_conf_t *cf, ngx_rtmp_core_main_conf_t *cmcf,
    ngx_rtmp_conf_addr_t *addr)
{
    ngx_int_t                   rc;
    ngx_uint_t                  n, s;
    ngx_hash_init_t             hash;
    ngx_hash_keys_arrays_t      ha;
    ngx_rtmp_server_name_t     *name = NULL;
    ngx_rtmp_core_srv_conf_t  **cscfp;

    ngx_memzero(&ha, sizeof(ngx_hash_keys_arrays_t));

    ha.temp_pool = ngx_create_pool(NGX_DEFAULT_POOL_SIZE, cf->log);
    if (ha.temp_pool == NULL) {
        return NGX_ERROR;
    }

    ha.pool = cf->pool;

    if (ngx_hash_keys_array_init(&ha, NGX_HASH_LARGE) != NGX_OK) {
        goto failed;
    }

    cscfp = addr->servers.elts;
    for (s = 0; s < addr->servers.nelts; s++) {

        name = cscfp[s]->hdl_play_domains.elts;
        for (n = 0; n < cscfp[s]->hdl_play_domains.nelts; n++) {

            rc = ngx_hash_add_key(&ha, &name[n].name, name[n].server,
                                  NGX_HASH_WILDCARD_KEY);
            
            if (rc == NGX_ERROR) {
                return NGX_ERROR;
            }

            if (rc == NGX_DECLINED) {
                ngx_log_error(NGX_LOG_EMERG, cf->log, 0,
                              "invalid hdl_play_domains name or wildcard \"%V\" on %s",
                              &name[n].name, addr->opt.sockaddr);
                return NGX_ERROR;
            }

            if (rc == NGX_BUSY) {
                ngx_log_error(NGX_LOG_EMERG, cf->log, 0,
                              "conflicting hdl_play_domains name \"%V\" on %s, ignored",
                              &name[n].name, addr->opt.sockaddr);
            }
        }
    }

    hash.key = ngx_hash_key_lc;
    hash.max_size = cmcf->server_names_hash_max_size;
    hash.bucket_size = cmcf->server_names_hash_bucket_size;
    hash.name = "server_names_hash";
    hash.pool = cf->pool;

    if (ha.keys.nelts) {
        hash.hash = &addr->hdl_play_hash;
        hash.temp_pool = NULL;

        if (ngx_hash_init(&hash, ha.keys.elts, ha.keys.nelts) != NGX_OK) {
            goto failed;
        }
    }

    if (ha.dns_wc_head.nelts) {

        ngx_qsort(ha.dns_wc_head.elts, (size_t) ha.dns_wc_head.nelts,
                  sizeof(ngx_hash_key_t), ngx_rtmp_cmp_dns_wildcards);

        hash.hash = NULL;
        hash.temp_pool = ha.temp_pool;

        if (ngx_hash_wildcard_init(&hash, ha.dns_wc_head.elts,
                                   ha.dns_wc_head.nelts)
            != NGX_OK)
        {
            goto failed;
        }

        addr->hdl_play_wc_head = (ngx_hash_wildcard_t *) hash.hash;
    }

    if (ha.dns_wc_tail.nelts) {

        ngx_qsort(ha.dns_wc_tail.elts, (size_t) ha.dns_wc_tail.nelts,
                  sizeof(ngx_hash_key_t), ngx_rtmp_cmp_dns_wildcards);

        hash.hash = NULL;
        hash.temp_pool = ha.temp_pool;

        if (ngx_hash_wildcard_init(&hash, ha.dns_wc_tail.elts,
                                   ha.dns_wc_tail.nelts)
            != NGX_OK)
        {
            goto failed;
        }

        addr->hdl_play_wc_tail = (ngx_hash_wildcard_t *) hash.hash;
    }

    ngx_destroy_pool(ha.temp_pool);

    return NGX_OK;

failed:

    ngx_destroy_pool(ha.temp_pool);

    return NGX_ERROR;
}


static ngx_int_t
ngx_rtmp_rtmp_publish_domains(ngx_conf_t *cf, ngx_rtmp_core_main_conf_t *cmcf,
    ngx_rtmp_conf_addr_t *addr)
{
    ngx_int_t                   rc;
    ngx_uint_t                  n, s;
    ngx_hash_init_t             hash;
    ngx_hash_keys_arrays_t      ha;
    ngx_rtmp_server_name_t     *name = NULL;
    ngx_rtmp_core_srv_conf_t  **cscfp;

    ngx_memzero(&ha, sizeof(ngx_hash_keys_arrays_t));

    ha.temp_pool = ngx_create_pool(NGX_DEFAULT_POOL_SIZE, cf->log);
    if (ha.temp_pool == NULL) {
        return NGX_ERROR;
    }

    ha.pool = cf->pool;

    if (ngx_hash_keys_array_init(&ha, NGX_HASH_LARGE) != NGX_OK) {
        goto failed;
    }

    cscfp = addr->servers.elts;
    for (s = 0; s < addr->servers.nelts; s++) {

        name = cscfp[s]->rtmp_publish_domains.elts;
        for (n = 0; n < cscfp[s]->rtmp_publish_domains.nelts; n++) {

            rc = ngx_hash_add_key(&ha, &name[n].name, name[n].server,
                                  NGX_HASH_WILDCARD_KEY);

            if (rc == NGX_ERROR) {
                return NGX_ERROR;
            }

            if (rc == NGX_DECLINED) {
                ngx_log_error(NGX_LOG_EMERG, cf->log, 0,
                              "invalid rtmp_publish_domains name or wildcard \"%V\" on %s",
                              &name[n].name, addr->opt.sockaddr);
                return NGX_ERROR;
            }

            if (rc == NGX_BUSY) {
                ngx_log_error(NGX_LOG_EMERG, cf->log, 0,
                              "conflicting rtmp_publish_domains name \"%V\" on %s, ignored",
                              &name[n].name, addr->opt.sockaddr);
            }
        }
    }

    hash.key = ngx_hash_key_lc;
    hash.max_size = cmcf->server_names_hash_max_size;
    hash.bucket_size = cmcf->server_names_hash_bucket_size;
    hash.name = "server_names_hash";
    hash.pool = cf->pool;

    if (ha.keys.nelts) {
        hash.hash = &addr->rtmp_publish_hash;
        hash.temp_pool = NULL;

        if (ngx_hash_init(&hash, ha.keys.elts, ha.keys.nelts) != NGX_OK) {
            goto failed;
        }
    }

    if (ha.dns_wc_head.nelts) {

        ngx_qsort(ha.dns_wc_head.elts, (size_t) ha.dns_wc_head.nelts,
                  sizeof(ngx_hash_key_t), ngx_rtmp_cmp_dns_wildcards);

        hash.hash = NULL;
        hash.temp_pool = ha.temp_pool;

        if (ngx_hash_wildcard_init(&hash, ha.dns_wc_head.elts,
                                   ha.dns_wc_head.nelts)
            != NGX_OK)
        {
            goto failed;
        }

        addr->rtmp_publish_wc_head = (ngx_hash_wildcard_t *) hash.hash;
    }

    if (ha.dns_wc_tail.nelts) {

        ngx_qsort(ha.dns_wc_tail.elts, (size_t) ha.dns_wc_tail.nelts,
                  sizeof(ngx_hash_key_t), ngx_rtmp_cmp_dns_wildcards);

        hash.hash = NULL;
        hash.temp_pool = ha.temp_pool;

        if (ngx_hash_wildcard_init(&hash, ha.dns_wc_tail.elts,
                                   ha.dns_wc_tail.nelts)
            != NGX_OK)
        {
            goto failed;
        }

        addr->rtmp_publish_wc_tail = (ngx_hash_wildcard_t *) hash.hash;
    }

    ngx_destroy_pool(ha.temp_pool);

    return NGX_OK;

failed:

    ngx_destroy_pool(ha.temp_pool);

    return NGX_ERROR;
}


static ngx_int_t
ngx_rtmp_init_listening(ngx_conf_t *cf, ngx_rtmp_conf_port_t *port)
{
    ngx_uint_t                 i, last, bind_wildcard;
    ngx_listening_t           *ls;
    ngx_rtmp_port_t           *mport, *pport;
    ngx_rtmp_conf_addr_t      *addr;

    addr = port->addrs.elts;
    last = port->addrs.nelts;

    if (ngx_array_init(&port->ports, cf->pool, port->addrs.nelts,
                sizeof(ngx_rtmp_port_t)) != NGX_OK) {
                
        //modify for warning
        return NGX_ERROR;
    }
    
    /*
         * if there is the binding to the "*:port" then we need to bind()
         * to the "*:port" only and ignore the other bindings
         */

    if (addr[last - 1].wildcard) {
        addr[last - 1].bind = 1;
        bind_wildcard = 1;

    } else {
        bind_wildcard = 0;
    }

    i = 0;

    while (i < last) {

        if (bind_wildcard && !addr[i].bind) {
            i++;
            continue;
        }

        ls = ngx_rtmp_add_listening(cf, &addr[i]);

        if (ls == NULL) {
            return NGX_ERROR;
        }

        mport = ngx_palloc(cf->pool, sizeof(ngx_rtmp_port_t));
        if (mport == NULL) {
            return NGX_ERROR;
        }

        pport = ngx_array_push(&port->ports);
        if (pport == NULL) {
            return NGX_ERROR;
        }

        ls->servers = mport;

        if (i == last - 1) {
            mport->naddrs = last;
            pport->naddrs = last;

        } else {
            mport->naddrs = 1;
            pport->naddrs = 1;
            i = 0;
        }

        switch (ls->sockaddr->sa_family) {
#if (NGX_HAVE_INET6)
        case AF_INET6:
            if (ngx_rtmp_add_addrs6(cf, mport, addr) != NGX_OK) {
                return NGX_ERROR;
            }

            if (ngx_rtmp_add_addrs6(cf, pport, addr) != NGX_OK) {
                return NGX_ERROR;
            }
            break;
#endif
        default: /* AF_INET */
            if (ngx_rtmp_add_addrs(cf, mport, addr) != NGX_OK) {
                return NGX_ERROR;
            }

            if(ngx_rtmp_add_addrs(cf, pport, addr) != NGX_OK){
                return NGX_ERROR;
            }
            break;
        }
        
        if (ngx_clone_listening(cf, ls) != NGX_OK) {
            return NGX_ERROR;
        }

        addr++;
        last--;
    }

    return NGX_OK;
}
static ngx_listening_t *
ngx_rtmp_add_listening(ngx_conf_t *cf, ngx_rtmp_conf_addr_t *addr)
{
    ngx_listening_t           *ls;

    ls = ngx_create_listening(cf, &addr->opt.u.sockaddr, addr->opt.socklen);
    if (ls == NULL) {
        return NULL;
    }

    ls->addr_ntop = 1;
    ls->handler = ngx_rtmp_init_connection;
    ls->pool_size = 4096;

    /* TODO: error_log directive */
    ls->logp = &cf->cycle->new_log;
    ls->log.data = &ls->addr_text;
    ls->log.handler = ngx_accept_log_error;

    ls->keepalive = addr->opt.so_keepalive;
#if (NGX_HAVE_KEEPALIVE_TUNABLE)
    ls->keepidle = addr->opt.tcp_keepidle;
    ls->keepintvl = addr->opt.tcp_keepintvl;
    ls->keepcnt = addr->opt.tcp_keepcnt;
#endif

#if (NGX_HAVE_INET6 && defined IPV6_V6ONLY)
    ls->ipv6only = addr.ipv6only;
#endif

#if (NGX_HAVE_REUSEPORT)
    ls->reuseport = addr->opt.reuseport;
#endif

    return ls;
}


ngx_int_t
ngx_rtmp_add_listen(ngx_conf_t *cf, ngx_rtmp_core_srv_conf_t *cscf,
    ngx_rtmp_listen_t *lsopt)
{
    in_port_t                   p;
    ngx_uint_t                  i;
    struct sockaddr            *sa;
    struct sockaddr_in         *sin;
    ngx_rtmp_conf_port_t       *port;
    ngx_rtmp_core_main_conf_t  *cmcf;
#if (NGX_HAVE_INET6)
    struct sockaddr_in6        *sin6;
#endif

    cmcf = ngx_rtmp_conf_get_module_main_conf(cf, ngx_rtmp_core_module);

    if (cmcf->ports.elts == NULL) {
        if (ngx_array_init(&cmcf->ports, cf->pool, 4,
                    sizeof(ngx_rtmp_conf_port_t))
            != NGX_OK)
        {
            //modify for warning
            return NGX_ERROR;
        }
    }

    sa = &lsopt->u.sockaddr;

    switch (sa->sa_family) {

#if (NGX_HAVE_INET6)
    case AF_INET6:
        sin6 = &lsopt->u.sockaddr_in6;
        p = sin6->sin6_port;
        break;
#endif

#if (NGX_HAVE_UNIX_DOMAIN)
    case AF_UNIX:
        p = 0;
        break;
#endif

    default: /* AF_INET */
        sin = &lsopt->u.sockaddr_in;
        p = sin->sin_port;
        break;
    }

    port = cmcf->ports.elts;
    for (i = 0; i < cmcf->ports.nelts; i++) {

        if (p != port[i].port || sa->sa_family != port[i].family) {
            continue;
        }

        /* a port is already in the port list */

        return ngx_rtmp_add_addresses(cf, cscf, &port[i], lsopt);
    }

    /* add a port to the port list */

    port = ngx_array_push(&cmcf->ports);
    if (port == NULL) {
        return NGX_ERROR;
    }

    port->family = sa->sa_family;
    port->port = p;
    port->addrs.elts = NULL;

    return ngx_rtmp_add_address(cf, cscf, port, lsopt);
}

static void
ngx_rtmp_time_update_no_resolver(struct sockaddr *sockaddr,
        socklen_t socklen)
{
    ngx_rtmp_core_main_conf_t  *cmcf;
    ngx_peer_connection_t      *pc;
    ngx_connection_t           *cc;
    ngx_int_t                   rc, len;
    ngx_pool_t                 *pool;
    u_char                     *p;
    ngx_log_t                  *log;
    struct sockaddr            *sockaddr_p;

    pool = NULL;
    cc = NULL;
    pc = NULL;
    cmcf = ngx_rtmp_core_main_conf;
    log = cmcf->time_update_evt.log;

    pool = ngx_create_pool(4096, log);
    if (pool == NULL) {
        ngx_log_error(NGX_LOG_ERR, log, 0,
                "pool alloc fail");
        goto fail;
    }

    sockaddr_p = ngx_palloc(pool, socklen);
    if (sockaddr_p == NULL) {
        goto fail;
    }

    ngx_memzero(sockaddr_p, socklen);
    ngx_memcpy(sockaddr_p, sockaddr, socklen);

    switch(sockaddr->sa_family) {
#if (NGX_HAVE_INET6)
        case AF_INET6:
            ((struct sockaddr_in6 *) sockaddr_p)->sin6_port = htons(cmcf->time_server_url.port);
            break;
#endif
        default:
            ((struct sockaddr_in *) sockaddr_p)->sin_port = htons(cmcf->time_server_url.port);

    }

    p = ngx_palloc(pool, NGX_SOCKADDR_STRLEN);
    if (p == NULL) {
        goto fail;
    }
    ngx_memzero(p, NGX_SOCKADDR_STRLEN);

    len = ngx_sock_ntop(sockaddr_p, socklen, p, NGX_SOCKADDR_STRLEN, 1);

    pc = ngx_palloc(pool, sizeof(ngx_peer_connection_t));
    if (pc == NULL) {
        ngx_log_error(NGX_LOG_ERR, log, 0,
                "peer conn alloc fail");
        goto fail;
    }

    ngx_memzero(pc, sizeof(ngx_peer_connection_t));
    pc->sockaddr = sockaddr_p;
    pc->socklen = socklen;

    pc->name = ngx_palloc(pool, sizeof(ngx_str_t));
    if (pc->name == NULL) {
        ngx_log_error(NGX_LOG_ERR, log, 0,
                "peer name alloc fail");
        goto fail;
    }
    pc->name->len = len;
    pc->name->data = p;
    pc->get = ngx_event_get_peer;
    pc->log = log;

    /*connect remote server and register write and read event*/
    rc = ngx_event_connect_peer(pc);
    if(rc != NGX_OK && rc != NGX_AGAIN) {
        ngx_log_error(NGX_LOG_ERR, log, 0,
                "connect peer fail, peer: %V, errno: %i",
                pc->name, ngx_socket_errno);
        goto fail;
    }

    cc = pc->connection;
    cc->pool = pool;

    cc->data = pc;
    cc->log = pc->log;


    /*register request and response handler*/
    cc->write->handler = ngx_rtmp_time_update_write_event_handler;
    cc->read->handler = ngx_rtmp_time_update_read_event_handler;

    pc->data = ngx_rtmp_time_update_gen_http_request(pc, cmcf);
    if (NGX_AGAIN == rc) {
        ngx_add_timer(cc->write, 10000);
        if (ngx_handle_write_event(cc->write, 0) != NGX_OK) {
            ngx_log_error(NGX_LOG_ERR, cc->log, 0,
                    "time update send fail, errno: %i, server: %V",
                    ngx_socket_errno, pc->name);
            goto fail;
        }
    }

    return;
fail:
    if (cc && cc->write->timer_set) {
        ngx_del_timer(cc->write);
    }
    if (pc && pc->connection) {
        ngx_close_connection(pc->connection);
        pc->connection->pool = NULL;
    }
    if (pool) {
        ngx_destroy_pool(pool);
    }
    cmcf->cur_time_update = 0;
}

void
ngx_rtmp_time_update_timer(ngx_event_t *ev)
{
    ngx_rtmp_core_main_conf_t  *cmcf;
    ngx_resolver_ctx_t   *rsctx, temp;

    cmcf = ngx_rtmp_core_main_conf;
    if (cmcf == NULL) {
        ngx_log_error(NGX_LOG_ERR, ev->log, 0,
                "ngx_rtmp_core_main_conf is null");
        return;
    }

    if(cmcf->time_server_url.url.len == 0) {
        return;
    }

    if ((cmcf->resolver == NULL
                || cmcf->resolver == NGX_CONF_UNSET_PTR) 
            && cmcf->time_server_url.naddrs <= 0) {
        return;
    }

    if (ev->timer_set) {
        ngx_del_timer(ev);
    }

    /*do not need resolve*/
    if (cmcf->resolver == NULL
                || cmcf->resolver == NGX_CONF_UNSET_PTR) {
        ngx_rtmp_time_update_no_resolver(cmcf->time_server_url.addrs[0].sockaddr,
                cmcf->time_server_url.addrs[0].socklen);
        goto last;
    }

    /*resolve dns first*/
    temp.name = cmcf->time_server_url.host;
    rsctx = ngx_resolve_start(cmcf->resolver, &temp);
    if (!rsctx || rsctx == NGX_NO_RESOLVER) {
        ngx_log_error(NGX_LOG_ERR, cmcf->resolver->log, 0,
                "resolver start fail! ctx: %p", rsctx);
        goto last;
    }
    rsctx->name = cmcf->time_server_url.host;
    rsctx->data = cmcf;
    rsctx->handler = ngx_rtmp_time_update;/*on finish resolve*/
    rsctx->timeout = cmcf->resolver_timeout;

    if (ngx_resolve_name(rsctx) != NGX_OK) {
        ngx_log_error(NGX_LOG_ERR, cmcf->resolver->log, 0,
                "resolver name faile! url: %V", &rsctx->name);
        goto last;
    }

last:
    ev->data = cmcf;
    ev->handler = ngx_rtmp_time_update_timer;
    ngx_add_timer(ev, cmcf->time_update_evt_msec);
}

static void
ngx_rtmp_time_update(ngx_resolver_ctx_t* ctx)
{
    ngx_rtmp_core_main_conf_t  *cmcf;
    ngx_log_t                  *log;

    cmcf = ctx->data;
    log = cmcf->resolver->log;
    
    if (cmcf->cur_time_update) {
        goto finish;
    }

    if (ctx->state || ctx->naddrs <= 0) {
        ngx_log_error(NGX_LOG_ERR, log, 0, 
                "'%V' couldn't be resolve (%i:%s)",
                &ctx->name, ctx->state, ngx_resolver_strerror(ctx->state));
        goto fail;
    }

    ngx_rtmp_time_update_no_resolver(ctx->addrs[0].sockaddr, ctx->addrs[0].socklen);

finish:
fail:
    ngx_resolve_name_done(ctx);
}

static void
ngx_rtmp_time_update_write_event_handler(ngx_event_t *wev)
{
    ngx_connection_t            *c;
    ngx_peer_connection_t       *pc;
    ngx_rtmp_core_main_conf_t   *cmcf;
    ngx_chain_t                 *out, *remain;

    c = wev->data;
    pc = c->data;
    out = pc->data;
    cmcf = ngx_rtmp_core_main_conf;

    if (wev->timer_set) {
        ngx_del_timer(wev);
    }

    if (c->destroyed) {
        return;
    }

    if (wev->timedout) {
        ngx_log_error(NGX_LOG_ERR, c->log, NGX_ETIMEDOUT,
                "time update: send time out, server: %V",
                pc->name);
        c->timedout = 1;
        goto fail;
    }

    remain = c->send_chain(c, out, 0);

    if (remain == NGX_CHAIN_ERROR) {
        ngx_log_error(NGX_LOG_ERR, c->log, 0,
                "time update send chain errno, errno: %i, server: %V",
                ngx_socket_errno, pc->name);
        goto fail;
    }

    pc->data = remain;

    if (remain) {
        ngx_add_timer(wev, 10000);
        if (ngx_handle_write_event(wev, 0) != NGX_OK) {
            ngx_log_error(NGX_LOG_ERR, c->log, 0,
                    "time update send fail, errno: %i, server: %V",
                    ngx_socket_errno, pc->name);
            goto fail;
        }

        return;

    } else {
        ngx_del_event(wev, NGX_WRITE_EVENT, 0);
        if (!cmcf->cur_time_update) {
            cmcf->cur_time_update = ngx_current_msec;
        }
    }
    return;
fail:
    if (wev->timer_set) {
        ngx_del_timer(wev);
    }
    if (c) {
        ngx_close_connection(c);
    }
    if (c && c->pool) {
        ngx_destroy_pool(c->pool);
        c->pool = NULL;
    }
    cmcf->cur_time_update = 0;
}

static void
ngx_rtmp_time_update_read_event_handler(ngx_event_t* rev)
{
    ngx_connection_t           *c;
    ngx_peer_connection_t      *pc;
    ngx_rtmp_core_main_conf_t  *cmcf;
    ngx_chain_t                *in;
    ngx_int_t                   n;
    ngx_buf_t                  *b;

    c = rev->data;
    pc = c->data;
    in = pc->data;
    cmcf = ngx_rtmp_core_main_conf;

    if (rev->timer_set) {
        ngx_del_timer(rev);
    }

    if (c->destroyed) {
        return;
    }

    if (rev->timedout) {
        c->timedout = 1;
        ngx_log_error(NGX_LOG_ERR, c->log, NGX_ETIMEDOUT,
                "time update: send time out, server: %V",
                pc->name);
        goto fail;
    }

    if (!in) {
        in = ngx_alloc_chain_link(c->pool);
        if (in == NULL) {
            ngx_log_error(NGX_LOG_ERR, c->log, 0,
                    "alloc recv chain fail");
            goto fail;
        }
        in->next = NULL;
        in->buf = ngx_create_temp_buf(c->pool, NGX_RTMP_MAX_BUF_SIZE);
        if (in->buf == NULL) {
            ngx_log_error(NGX_LOG_ERR, c->log, 0,
                    "alloc recv buf fail");
            goto fail;
        }
        pc->data = in;
    }

    b = in->buf;
    /*goto tail*/
    while(b->last == b->end && in->next != NULL) {
        in = in->next;
    }
    for ( ;; ) {
        /*last time chain is full*/
        if (b->last == b->end && in->next == NULL) {
            in->next = ngx_alloc_chain_link(c->pool);
            if (!in->next) {
                ngx_log_error(NGX_LOG_ERR, c->log, 0,
                        "alloc recv chain fail");
                goto fail;
            }
            in->next->buf = ngx_create_temp_buf(c->pool, NGX_RTMP_MAX_BUF_SIZE);
            if (in->next->buf == NULL) {
                ngx_log_error(NGX_LOG_ERR, c->log, 0,
                        "alloc recv buf fail");
                goto fail;
            }
        }
        /*move to next chain*/
        if(b->last == b->end) {
            in = in->next;
            in->next = NULL;
            b = in->buf;
        }

        n = c->recv(c, b->last, b->end - b->last);

        if (n == NGX_ERROR || n == 0) {
            ngx_rtmp_time_update_handle_http_response(cmcf, c);
            goto finish;
        }

        if (n == NGX_AGAIN) {
            ngx_add_timer(rev, 10000);
            if (ngx_handle_read_event(rev, 0) != NGX_OK) {
                ngx_log_error(NGX_LOG_ERR, c->log, 0,
                        "time update recv fail, errno: %i, server: %V",
                        ngx_socket_errno, pc->name);
                goto fail;
            }
            return;
        }

        b->last += n;
    }
    return;
finish:
fail:
    if (rev->timer_set) {
        ngx_del_timer(rev);
    }

    if (c) {
        ngx_close_connection(c);
    }

    if(c && c->pool) {
        ngx_destroy_pool(c->pool);
        c->pool = NULL;
    }
    cmcf->cur_time_update = 0;
}

static ngx_chain_t*
ngx_rtmp_time_update_gen_http_request(ngx_peer_connection_t* pc,
        ngx_rtmp_core_main_conf_t *cmcf)
{
    ngx_connection_t    *c;
    ngx_url_t           *u;
    ngx_chain_t         *out_chain;
    static const char   req_header[] = "GET %V HTTP/1.0\r\n"
                                        "Host: %V\r\n"
                                        "Connection: close\r\n"
                                        "\r\n";

    u = &cmcf->time_server_url;
    c = pc->connection;
    out_chain = ngx_alloc_chain_link(c->pool);

    if (out_chain == NULL) {
        return NULL;
    }

    out_chain->next = NULL;
    out_chain->buf = ngx_create_temp_buf(c->pool, ngx_strlen(req_header) + u->uri.len + u->host.len);
    if(out_chain->buf == NULL) {
        return NULL;
    }
    out_chain->buf->last = ngx_slprintf(out_chain->buf->pos, out_chain->buf->end, req_header, &u->uri, &u->host);
    return out_chain; 
}

static void
ngx_rtmp_time_update_handle_http_response(ngx_rtmp_core_main_conf_t *cmcf,
        ngx_connection_t* c)
{
    ngx_chain_t            *in;
    ngx_uint_t              content_length;
    u_char                 *content, ret;
    ngx_int_t               server_time, rc;
    ngx_str_t               content_str;
    ngx_peer_connection_t  *pc;

    pc = c->data;
    in = pc->data;
    if (!in || in->buf->last == in->buf->start) {
        return;
    }

    rc = ngx_rtmp_parse_http_body(c->pool, c->log, in, &ret, &content, &content_length);
    if (rc != NGX_OK) {
        ngx_log_error(NGX_LOG_ERR, c->log, 0,
                "time update: parse http error, remote HTTP response %cxx, server: %V", 
                ret, pc->name);
        return;
    }

    if (content_length == 0) {
        ngx_log_error(NGX_LOG_ERR, c->log, 0, 
                "time update: remote HTTP response has no content, server: %V",
                pc->name);
        return;
    }

    if (content_length < NGX_RTMP_UNIX_TIME_LEN_MIN
            || content_length > NGX_RTMP_UNIX_TIME_LEN_MAX) {
        ngx_log_error(NGX_LOG_ERR, c->log, 0, 
                "time update: remote HTTP response has too long or too short content, len: %i, server: %V",
                content_length, pc->name);
        return;
    }
    content_str.data = content;
    content_str.len = content_length;
    /*skip illegel char*/
    for (; content && content_length > 0
            && (*content < '0' || *content > '9');
            content++, content_length--) {
    }

    for(; content && content_length > 0
            && (content[content_length-1] < '0' || content[content_length-1] > '9');
            content_length--) {
    }

    server_time = ngx_atofp(content, content_length, 6);//us
    if (server_time == NGX_ERROR) {
        ngx_log_error(NGX_LOG_ERR, c->log, 0,
                "utc time format from server is illegal, content: %V, len: %i, server: %V",
                &content_str, content_str.len, pc->name);
        return;
    }
    server_time = (server_time + 500) / 1000;//ms
    ngx_log_error(NGX_LOG_INFO, c->log, 0, 
            "receive utc time: %ui, recv delay: %i, diff: %i, content: %V,  server: %V",
            server_time, ngx_current_msec - cmcf->cur_time_update,
            server_time - ngx_current_msec, &content_str,  pc->name);
    cmcf->last_time_update = ngx_current_msec;
    cmcf->cur_utc_time = server_time + (cmcf->last_time_update - cmcf->cur_time_update)/2;
    cmcf->cur_time_update = 0;
}

static ngx_int_t
ngx_rtmp_init_process(ngx_cycle_t *cycle)
{
#if (nginx_version >= 1007005)
    ngx_queue_init(&ngx_rtmp_init_queue);
#endif
    return NGX_OK;
}

