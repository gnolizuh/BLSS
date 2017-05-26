
/*
 * Copyright (C) Roman Arutyunyan
 */


#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_event.h>
#include <nginx.h>
#include "ngx_rtmp.h"


static void *ngx_rtmp_core_create_main_conf(ngx_conf_t *cf);
static char *ngx_rtmp_core_init_main_conf(ngx_conf_t *cf, void *conf);
static void *ngx_rtmp_core_create_srv_conf(ngx_conf_t *cf);
static char *ngx_rtmp_core_merge_srv_conf(ngx_conf_t *cf, void *parent,
    void *child);
static void *ngx_rtmp_core_create_svi_conf(ngx_conf_t *cf);
static char *ngx_rtmp_core_merge_svi_conf(ngx_conf_t *cf, void *parent,
    void *child);
static void *ngx_rtmp_core_create_app_conf(ngx_conf_t *cf);
static char *ngx_rtmp_core_merge_app_conf(ngx_conf_t *cf, void *parent,
    void *child);
static char *ngx_rtmp_core_server(ngx_conf_t *cf, ngx_command_t *cmd,
    void *conf);
static char *ngx_rtmp_core_listen(ngx_conf_t *cf, ngx_command_t *cmd,
    void *conf);
static char *ngx_rtmp_core_service(ngx_conf_t *cf, ngx_command_t *cmd,
    void *conf);
static char *ngx_rtmp_core_application(ngx_conf_t *cf, ngx_command_t *cmd,
    void *conf);
static char *ngx_rtmp_core_hostname(ngx_conf_t *cf, ngx_command_t *cmd,
    void *conf);


ngx_rtmp_core_main_conf_t      *ngx_rtmp_core_main_conf;


static ngx_conf_deprecated_t  ngx_conf_deprecated_so_keepalive = {
    ngx_conf_deprecated, "so_keepalive",
    "so_keepalive\" parameter of the \"listen"
};


static ngx_conf_bitmask_t  ngx_rtmp_hostname_mask[] = {
    { ngx_string("direct"),             NGX_RTMP_HOSTNAME_SUB       |
                                        NGX_RTMP_HOSTNAME_PUB       },
    { ngx_string("sub"),                NGX_RTMP_HOSTNAME_SUB       },
    { ngx_string("pub"),                NGX_RTMP_HOSTNAME_PUB       },
    { ngx_string("proto"),              NGX_RTMP_HOSTNAME_RTMP      |
                                        NGX_RTMP_HOSTNAME_HTTP_FLV  |
                                        NGX_RTMP_HOSTNAME_HLS       },
    { ngx_string("rtmp"),               NGX_RTMP_HOSTNAME_RTMP      },
    { ngx_string("http_flv"),           NGX_RTMP_HOSTNAME_HTTP_FLV  },
    { ngx_string("hls"),                NGX_RTMP_HOSTNAME_HLS       },
    { ngx_null_string,                  0                           }
};


static ngx_command_t  ngx_rtmp_core_commands[] = {

    { ngx_string("server"),
      NGX_RTMP_MAIN_CONF|NGX_CONF_BLOCK|NGX_CONF_NOARGS,
      ngx_rtmp_core_server,
      0,
      0,
      NULL },

    { ngx_string("host_names_hash_max_size"),
      NGX_RTMP_MAIN_CONF|NGX_CONF_TAKE1,
      ngx_conf_set_num_slot,
      NGX_RTMP_MAIN_CONF_OFFSET,
      offsetof(ngx_rtmp_core_main_conf_t, host_names_hash_max_size),
      NULL },

    { ngx_string("host_names_hash_bucket_size"),
      NGX_RTMP_MAIN_CONF|NGX_CONF_TAKE1,
      ngx_conf_set_num_slot,
      NGX_RTMP_MAIN_CONF_OFFSET,
      offsetof(ngx_rtmp_core_main_conf_t, host_names_hash_bucket_size),
      NULL },

    { ngx_string("listen"),
      NGX_RTMP_SRV_CONF|NGX_CONF_TAKE12,
      ngx_rtmp_core_listen,
      NGX_RTMP_SRV_CONF_OFFSET,
      0,
      NULL },

    { ngx_string("service"),
      NGX_RTMP_SRV_CONF|NGX_CONF_BLOCK|NGX_CONF_TAKE1,
      ngx_rtmp_core_service,
      NGX_RTMP_SRV_CONF_OFFSET,
      0,
      NULL },

    { ngx_string("application"),
      NGX_RTMP_SVI_CONF|NGX_CONF_BLOCK|NGX_CONF_TAKE1,
      ngx_rtmp_core_application,
      NGX_RTMP_SVI_CONF_OFFSET,
      0,
      NULL },

    { ngx_string("hostname"),
      NGX_RTMP_SVI_CONF|NGX_CONF_1MORE,
      ngx_rtmp_core_hostname,
      NGX_RTMP_SVI_CONF_OFFSET,
      offsetof(ngx_rtmp_core_svi_conf_t, host_range),
      ngx_rtmp_hostname_mask },

    { ngx_string("so_keepalive"),
      NGX_RTMP_MAIN_CONF|NGX_RTMP_SRV_CONF|NGX_RTMP_SVI_CONF|NGX_CONF_FLAG,
      ngx_conf_set_flag_slot,
      NGX_RTMP_SRV_CONF_OFFSET,
      offsetof(ngx_rtmp_core_srv_conf_t, so_keepalive),
      &ngx_conf_deprecated_so_keepalive },

    { ngx_string("timeout"),
      NGX_RTMP_MAIN_CONF|NGX_RTMP_SRV_CONF|NGX_RTMP_SVI_CONF|NGX_CONF_TAKE1,
      ngx_conf_set_msec_slot,
      NGX_RTMP_SRV_CONF_OFFSET,
      offsetof(ngx_rtmp_core_srv_conf_t, timeout),
      NULL },

    { ngx_string("ping"),
      NGX_RTMP_MAIN_CONF|NGX_RTMP_SRV_CONF|NGX_RTMP_SVI_CONF|NGX_CONF_TAKE1,
      ngx_conf_set_msec_slot,
      NGX_RTMP_SRV_CONF_OFFSET,
      offsetof(ngx_rtmp_core_srv_conf_t, ping),
      NULL },

    { ngx_string("ping_timeout"),
      NGX_RTMP_MAIN_CONF|NGX_RTMP_SRV_CONF|NGX_RTMP_SVI_CONF|NGX_CONF_TAKE1,
      ngx_conf_set_msec_slot,
      NGX_RTMP_SRV_CONF_OFFSET,
      offsetof(ngx_rtmp_core_srv_conf_t, ping_timeout),
      NULL },

    { ngx_string("max_streams"),
      NGX_RTMP_MAIN_CONF|NGX_RTMP_SRV_CONF|NGX_RTMP_SVI_CONF|NGX_CONF_TAKE1,
      ngx_conf_set_num_slot,
      NGX_RTMP_SRV_CONF_OFFSET,
      offsetof(ngx_rtmp_core_srv_conf_t, max_streams),
      NULL },

    { ngx_string("ack_window"),
      NGX_RTMP_MAIN_CONF|NGX_RTMP_SRV_CONF|NGX_RTMP_SVI_CONF|NGX_CONF_TAKE1,
      ngx_conf_set_num_slot,
      NGX_RTMP_SRV_CONF_OFFSET,
      offsetof(ngx_rtmp_core_srv_conf_t, ack_window),
      NULL },

    { ngx_string("chunk_size"),
      NGX_RTMP_MAIN_CONF|NGX_RTMP_SRV_CONF|NGX_RTMP_SVI_CONF|NGX_CONF_TAKE1,
      ngx_conf_set_num_slot,
      NGX_RTMP_SRV_CONF_OFFSET,
      offsetof(ngx_rtmp_core_srv_conf_t, chunk_size),
      NULL },

    { ngx_string("max_message"),
      NGX_RTMP_MAIN_CONF|NGX_RTMP_SRV_CONF|NGX_RTMP_SVI_CONF|NGX_CONF_TAKE1,
      ngx_conf_set_size_slot,
      NGX_RTMP_SRV_CONF_OFFSET,
      offsetof(ngx_rtmp_core_srv_conf_t, max_message),
      NULL },

    { ngx_string("out_queue"),
      NGX_RTMP_MAIN_CONF|NGX_RTMP_SRV_CONF|NGX_RTMP_SVI_CONF|NGX_CONF_TAKE1,
      ngx_conf_set_size_slot,
      NGX_RTMP_SRV_CONF_OFFSET,
      offsetof(ngx_rtmp_core_srv_conf_t, out_queue),
      NULL },

    { ngx_string("out_cork"),
      NGX_RTMP_MAIN_CONF|NGX_RTMP_SRV_CONF|NGX_RTMP_SVI_CONF|NGX_CONF_TAKE1,
      ngx_conf_set_size_slot,
      NGX_RTMP_SRV_CONF_OFFSET,
      offsetof(ngx_rtmp_core_srv_conf_t, out_cork),
      NULL },

    { ngx_string("busy"),
      NGX_RTMP_MAIN_CONF|NGX_RTMP_SRV_CONF|NGX_RTMP_SVI_CONF|NGX_CONF_TAKE1,
      ngx_conf_set_flag_slot,
      NGX_RTMP_SRV_CONF_OFFSET,
      offsetof(ngx_rtmp_core_srv_conf_t, busy),
      NULL },

    /* time fixes are needed for flash clients */
    { ngx_string("play_time_fix"),
      NGX_RTMP_MAIN_CONF|NGX_RTMP_SRV_CONF|NGX_RTMP_SVI_CONF|NGX_RTMP_APP_CONF|NGX_CONF_TAKE1,
      ngx_conf_set_flag_slot,
      NGX_RTMP_SRV_CONF_OFFSET,
      offsetof(ngx_rtmp_core_srv_conf_t, play_time_fix),
      NULL },

    { ngx_string("publish_time_fix"),
      NGX_RTMP_MAIN_CONF|NGX_RTMP_SRV_CONF|NGX_RTMP_SVI_CONF|NGX_RTMP_APP_CONF|NGX_CONF_TAKE1,
      ngx_conf_set_flag_slot,
      NGX_RTMP_SRV_CONF_OFFSET,
      offsetof(ngx_rtmp_core_srv_conf_t, publish_time_fix),
      NULL },

    { ngx_string("buflen"),
      NGX_RTMP_MAIN_CONF|NGX_RTMP_SRV_CONF|NGX_RTMP_SVI_CONF|NGX_CONF_TAKE1,
      ngx_conf_set_msec_slot,
      NGX_RTMP_SRV_CONF_OFFSET,
      offsetof(ngx_rtmp_core_srv_conf_t, buflen),
      NULL },

      ngx_null_command
};


static ngx_rtmp_module_t  ngx_rtmp_core_module_ctx = {
    NULL,                                   /* preconfiguration */
    NULL,                                   /* postconfiguration */
    ngx_rtmp_core_create_main_conf,         /* create main configuration */
    ngx_rtmp_core_init_main_conf,           /* init main configuration */
    ngx_rtmp_core_create_srv_conf,          /* create server configuration */
    ngx_rtmp_core_merge_srv_conf,           /* merge server configuration */
    ngx_rtmp_core_create_svi_conf,          /* create service configuration */
    ngx_rtmp_core_merge_svi_conf,           /* merge service configuration */
    ngx_rtmp_core_create_app_conf,          /* create app configuration */
    ngx_rtmp_core_merge_app_conf            /* merge app configuration */
};


ngx_module_t  ngx_rtmp_core_module = {
    NGX_MODULE_V1,
    &ngx_rtmp_core_module_ctx,             /* module context */
    ngx_rtmp_core_commands,                /* module directives */
    NGX_RTMP_MODULE,                       /* module type */
    NULL,                                  /* init master */
    NULL,                                  /* init module */
    NULL,                                  /* init process */
    NULL,                                  /* init thread */
    NULL,                                  /* exit thread */
    NULL,                                  /* exit process */
    NULL,                                  /* exit master */
    NGX_MODULE_V1_PADDING
};


static void *
ngx_rtmp_core_create_main_conf(ngx_conf_t *cf)
{
    ngx_rtmp_core_main_conf_t  *cmcf;

    cmcf = ngx_pcalloc(cf->pool, sizeof(ngx_rtmp_core_main_conf_t));
    if (cmcf == NULL) {
        return NULL;
    }

    ngx_rtmp_core_main_conf = cmcf;

    if (ngx_array_init(&cmcf->servers, cf->pool, 4,
                       sizeof(ngx_rtmp_core_srv_conf_t *))
        != NGX_OK)
    {
        return NULL;
    }

    if (ngx_array_init(&cmcf->listen, cf->pool, 4, sizeof(ngx_rtmp_listen_opt_t))
        != NGX_OK)
    {
        return NULL;
    }

    cmcf->host_names_hash_max_size = NGX_CONF_UNSET_UINT;
    cmcf->host_names_hash_bucket_size = NGX_CONF_UNSET_UINT;

    return cmcf;
}


static char *
ngx_rtmp_core_init_main_conf(ngx_conf_t *cf, void *conf)
{
    ngx_rtmp_core_main_conf_t *cmcf = conf;

    ngx_conf_init_uint_value(cmcf->host_names_hash_max_size, 512);
    ngx_conf_init_uint_value(cmcf->host_names_hash_bucket_size,
                             ngx_cacheline_size);

    cmcf->host_names_hash_max_size =
            ngx_align(cmcf->host_names_hash_max_size, ngx_cacheline_size);

    if (cmcf->ncaptures) {
        cmcf->ncaptures = (cmcf->ncaptures + 1) * 3;
    }

    return NGX_CONF_OK;
}


static void *
ngx_rtmp_core_create_srv_conf(ngx_conf_t *cf)
{
    ngx_rtmp_core_srv_conf_t   *cscf;

    cscf = ngx_pcalloc(cf->pool, sizeof(ngx_rtmp_core_srv_conf_t));
    if (cscf == NULL) {
        return NULL;
    }

    if (ngx_array_init(&cscf->services, cf->pool, 4,
                       sizeof(ngx_rtmp_core_svi_conf_t *))
        != NGX_OK)
    {
        return NULL;
    }

    cscf->timeout = NGX_CONF_UNSET_MSEC;
    cscf->ping = NGX_CONF_UNSET_MSEC;
    cscf->ping_timeout = NGX_CONF_UNSET_MSEC;
    cscf->so_keepalive = NGX_CONF_UNSET;
    cscf->max_streams = NGX_CONF_UNSET;
    cscf->chunk_size = NGX_CONF_UNSET;
    cscf->ack_window = NGX_CONF_UNSET_UINT;
    cscf->max_message = NGX_CONF_UNSET_SIZE;
    cscf->out_queue = NGX_CONF_UNSET_SIZE;
    cscf->out_cork = NGX_CONF_UNSET_SIZE;
    cscf->play_time_fix = NGX_CONF_UNSET;
    cscf->publish_time_fix = NGX_CONF_UNSET;
    cscf->buflen = NGX_CONF_UNSET_MSEC;
    cscf->busy = NGX_CONF_UNSET;

    return cscf;
}


static char *
ngx_rtmp_core_merge_srv_conf(ngx_conf_t *cf, void *parent, void *child)
{
    ngx_rtmp_core_srv_conf_t *prev = parent;
    ngx_rtmp_core_srv_conf_t *conf = child;

    ngx_conf_merge_msec_value(conf->timeout, prev->timeout, 60000);
    ngx_conf_merge_msec_value(conf->ping, prev->ping, 60000);
    ngx_conf_merge_msec_value(conf->ping_timeout, prev->ping_timeout, 30000);

    ngx_conf_merge_value(conf->so_keepalive, prev->so_keepalive, 0);
    ngx_conf_merge_value(conf->max_streams, prev->max_streams, 32);
    ngx_conf_merge_value(conf->chunk_size, prev->chunk_size, 4096);
    ngx_conf_merge_uint_value(conf->ack_window, prev->ack_window, 5000000);
    ngx_conf_merge_size_value(conf->max_message, prev->max_message,
            1 * 1024 * 1024);
    ngx_conf_merge_size_value(conf->out_queue, prev->out_queue, 256);
    ngx_conf_merge_size_value(conf->out_cork, prev->out_cork,
            conf->out_queue / 8);
    ngx_conf_merge_value(conf->play_time_fix, prev->play_time_fix, 1);
    ngx_conf_merge_value(conf->publish_time_fix, prev->publish_time_fix, 1);
    ngx_conf_merge_msec_value(conf->buflen, prev->buflen, 1000);
    ngx_conf_merge_value(conf->busy, prev->busy, 0);

    if (prev->pool == NULL) {
        prev->pool = ngx_create_pool(4096, &cf->cycle->new_log);
        if (prev->pool == NULL) {
            return NGX_CONF_ERROR;
        }
    }

    conf->pool = prev->pool;

    return NGX_CONF_OK;
}


static void *
ngx_rtmp_core_create_svi_conf(ngx_conf_t *cf)
{
    ngx_rtmp_core_svi_conf_t   *conf;

    conf = ngx_pcalloc(cf->pool, sizeof(ngx_rtmp_core_svi_conf_t));
    if (conf == NULL) {
        return NULL;
    }

    if (ngx_array_init(&conf->applications, cf->pool, 4,
                       sizeof(ngx_rtmp_core_app_conf_t *))
        != NGX_OK)
    {
        return NULL;
    }

    return conf;
}


static char *
ngx_rtmp_core_merge_svi_conf(ngx_conf_t *cf, void *parent, void *child)
{
    ngx_rtmp_core_svi_conf_t *prev = parent;
    ngx_rtmp_core_svi_conf_t *conf = child;

    (void)prev;
    (void)conf;

    return NGX_CONF_OK;
}


static void *
ngx_rtmp_core_create_app_conf(ngx_conf_t *cf)
{
    ngx_rtmp_core_app_conf_t   *conf;

    conf = ngx_pcalloc(cf->pool, sizeof(ngx_rtmp_core_app_conf_t));
    if (conf == NULL) {
        return NULL;
    }

    if (ngx_array_init(&conf->applications, cf->pool, 1,
                       sizeof(ngx_rtmp_core_app_conf_t *))
        != NGX_OK)
    {
        return NULL;
    }

    return conf;
}


static char *
ngx_rtmp_core_merge_app_conf(ngx_conf_t *cf, void *parent, void *child)
{
    ngx_rtmp_core_app_conf_t *prev = parent;
    ngx_rtmp_core_app_conf_t *conf = child;

    (void)prev;
    (void)conf;

    return NGX_CONF_OK;
}


static char *
ngx_rtmp_core_server(ngx_conf_t *cf, ngx_command_t *cmd, void *conf)
{
    char                       *rv;
    void                       *mconf;
    ngx_uint_t                  m;
    ngx_conf_t                  pcf;
    ngx_module_t              **modules;
    ngx_rtmp_module_t          *module;
    ngx_rtmp_conf_ctx_t        *ctx, *rtmp_ctx;
    ngx_rtmp_core_srv_conf_t   *cscf, **cscfp;
    ngx_rtmp_core_main_conf_t  *cmcf;
    ngx_rtmp_listen_opt_t       lsopt;
    struct sockaddr_in         *sin;

    ctx = ngx_pcalloc(cf->pool, sizeof(ngx_rtmp_conf_ctx_t));
    if (ctx == NULL) {
        return NGX_CONF_ERROR;
    }

    rtmp_ctx = cf->ctx;
    ctx->main_conf = rtmp_ctx->main_conf;

    /* the server{}'s srv_conf */

    ctx->srv_conf = ngx_pcalloc(cf->pool, sizeof(void *) * ngx_rtmp_max_module);
    if (ctx->srv_conf == NULL) {
        return NGX_CONF_ERROR;
    }

    /* the server{}'s loc_conf */

    ctx->svi_conf = ngx_pcalloc(cf->pool, sizeof(void *) * ngx_rtmp_max_module);
    if (ctx->svi_conf == NULL) {
        return NGX_CONF_ERROR;
    }

    /* the server{}'s loc_conf */

    ctx->app_conf = ngx_pcalloc(cf->pool, sizeof(void *) * ngx_rtmp_max_module);
    if (ctx->app_conf == NULL) {
        return NGX_CONF_ERROR;
    }

#if (nginx_version >= 1009011)
    modules = cf->cycle->modules;
#else
    modules = ngx_modules;
#endif

    for (m = 0; modules[m]; m++) {
        if (modules[m]->type != NGX_RTMP_MODULE) {
            continue;
        }

        module = modules[m]->ctx;

        if (module->create_srv_conf) {
            mconf = module->create_srv_conf(cf);
            if (mconf == NULL) {
                return NGX_CONF_ERROR;
            }

            ctx->srv_conf[modules[m]->ctx_index] = mconf;
        }

        if (module->create_svi_conf) {
            mconf = module->create_svi_conf(cf);
            if (mconf == NULL) {
                return NGX_CONF_ERROR;
            }

            ctx->svi_conf[modules[m]->ctx_index] = mconf;
        }

        if (module->create_app_conf) {
            mconf = module->create_app_conf(cf);
            if (mconf == NULL) {
                return NGX_CONF_ERROR;
            }

            ctx->app_conf[modules[m]->ctx_index] = mconf;
        }
    }

    /* the server configuration context */

    cscf = ctx->srv_conf[ngx_rtmp_core_module.ctx_index];
    cscf->ctx = ctx;

    cmcf = ctx->main_conf[ngx_rtmp_core_module.ctx_index];

    cscfp = ngx_array_push(&cmcf->servers);
    if (cscfp == NULL) {
        return NGX_CONF_ERROR;
    }

    *cscfp = cscf;


    /* parse inside server{} */

    pcf = *cf;
    cf->ctx = ctx;
    cf->cmd_type = NGX_RTMP_SRV_CONF;

    rv = ngx_conf_parse(cf, NULL);

    *cf = pcf;

    if (rv == NGX_CONF_OK && !cscf->listen) {
        ngx_memzero(&lsopt, sizeof(ngx_rtmp_listen_opt_t));

        sin = &lsopt.u.sockaddr_in;

        sin->sin_family = AF_INET;
        sin->sin_port = htons(1935);
        sin->sin_addr.s_addr = INADDR_ANY;

        lsopt.socklen = sizeof(struct sockaddr_in);

        lsopt.wildcard = 1;

        (void) ngx_sock_ntop(&lsopt.u.sockaddr, lsopt.socklen, lsopt.sockaddr,
                NGX_SOCKADDR_STRLEN, 1);

        if (ngx_rtmp_add_listen(cf, cscf, &lsopt) != NGX_OK) {
            return NGX_CONF_ERROR;
        }
    }
    return rv;
}


static char *
ngx_rtmp_core_service(ngx_conf_t *cf, ngx_command_t *cmd, void *conf)
{
    char                       *rv;
    ngx_int_t                   i;
    ngx_str_t                  *value;
    ngx_conf_t                  save;
    ngx_module_t              **modules;
    ngx_rtmp_module_t          *module;
    ngx_rtmp_conf_ctx_t        *ctx, *pctx;
    ngx_rtmp_core_srv_conf_t   *cscf;
    ngx_rtmp_core_svi_conf_t   *csicf, **csicfp;

    ctx = ngx_pcalloc(cf->pool, sizeof(ngx_rtmp_conf_ctx_t));
    if (ctx == NULL) {
        return NGX_CONF_ERROR;
    }

    pctx = cf->ctx;
    ctx->main_conf = pctx->main_conf;
    ctx->srv_conf = pctx->srv_conf;

    ctx->svi_conf = ngx_pcalloc(cf->pool, sizeof(void *) * ngx_rtmp_max_module);
    if (ctx->svi_conf == NULL) {
        return NGX_CONF_ERROR;
    }

    ctx->app_conf = ngx_pcalloc(cf->pool, sizeof(void *) * ngx_rtmp_max_module);
    if (ctx->app_conf == NULL) {
        return NGX_CONF_ERROR;
    }

#if (nginx_version >= 1009011)
    modules = cf->cycle->modules;
#else
    modules = ngx_modules;
#endif

    for (i = 0; modules[i]; i++) {
        if (modules[i]->type != NGX_RTMP_MODULE) {
            continue;
        }

        module = modules[i]->ctx;

        if (module->create_svi_conf) {
            ctx->svi_conf[modules[i]->ctx_index] = module->create_svi_conf(cf);
            if (ctx->svi_conf[modules[i]->ctx_index] == NULL) {
                return NGX_CONF_ERROR;
            }
        }

        if (module->create_app_conf) {
            ctx->app_conf[modules[i]->ctx_index] = module->create_app_conf(cf);
            if (ctx->app_conf[modules[i]->ctx_index] == NULL) {
                return NGX_CONF_ERROR;
            }
        }
    }

    csicf = ctx->svi_conf[ngx_rtmp_core_module.ctx_index];
    csicf->ctx = ctx;
    csicf->svi_conf = ctx->svi_conf;

    value = cf->args->elts;

    csicf->name = value[1];
    cscf = pctx->srv_conf[ngx_rtmp_core_module.ctx_index];

    csicfp = ngx_array_push(&cscf->services);
    if (csicfp == NULL) {
        return NGX_CONF_ERROR;
    }

    if (ngx_array_init(&csicf->host_names, cf->pool, 4,
                       sizeof(ngx_rtmp_host_name_t))
        != NGX_OK)
    {
        return NGX_CONF_ERROR;
    }

    *csicfp = csicf;

    save = *cf;
    cf->ctx = ctx;
    cf->cmd_type = NGX_RTMP_SVI_CONF;

    rv = ngx_conf_parse(cf, NULL);

    *cf= save;

    return rv;
}


static char *
ngx_rtmp_core_application(ngx_conf_t *cf, ngx_command_t *cmd, void *conf)
{
    char                       *rv;
    ngx_int_t                   i;
    ngx_str_t                  *value;
    ngx_conf_t                  save;
    ngx_module_t              **modules;
    ngx_rtmp_module_t          *module;
    ngx_rtmp_conf_ctx_t        *ctx, *pctx;
    ngx_rtmp_core_svi_conf_t   *csicf;
    ngx_rtmp_core_app_conf_t   *cacf, **cacfp;

    ctx = ngx_pcalloc(cf->pool, sizeof(ngx_rtmp_conf_ctx_t));
    if (ctx == NULL) {
        return NGX_CONF_ERROR;
    }

    pctx = cf->ctx;
    ctx->main_conf = pctx->main_conf;
    ctx->srv_conf = pctx->srv_conf;
    ctx->svi_conf = pctx->svi_conf;

    ctx->app_conf = ngx_pcalloc(cf->pool, sizeof(void *) * ngx_rtmp_max_module);
    if (ctx->app_conf == NULL) {
        return NGX_CONF_ERROR;
    }

#if (nginx_version >= 1009011)
    modules = cf->cycle->modules;
#else
    modules = ngx_modules;
#endif

    for (i = 0; modules[i]; i++) {
        if (modules[i]->type != NGX_RTMP_MODULE) {
            continue;
        }

        module = modules[i]->ctx;

        if (module->create_app_conf) {
            ctx->app_conf[modules[i]->ctx_index] = module->create_app_conf(cf);
            if (ctx->app_conf[modules[i]->ctx_index] == NULL) {
                return NGX_CONF_ERROR;
            }
        }
    }

    cacf = ctx->app_conf[ngx_rtmp_core_module.ctx_index];
    cacf->app_conf = ctx->app_conf;

    value = cf->args->elts;

    cacf->name = value[1];
    csicf = pctx->svi_conf[ngx_rtmp_core_module.ctx_index];

    cacfp = ngx_array_push(&csicf->applications);
    if (cacfp == NULL) {
        return NGX_CONF_ERROR;
    }

    *cacfp = cacf;

    save = *cf;
    cf->ctx = ctx;
    cf->cmd_type = NGX_RTMP_APP_CONF;

    rv = ngx_conf_parse(cf, NULL);

    *cf= save;

    return rv;
}


static char *
ngx_rtmp_core_listen(ngx_conf_t *cf, ngx_command_t *cmd, void *conf)
{
    ngx_rtmp_core_srv_conf_t   *cscf = conf;

    size_t                      len, off;
    in_port_t                   port;
    ngx_str_t                  *value;
    ngx_url_t                   u;
    ngx_uint_t                  i, m;
    ngx_module_t              **modules;
    struct sockaddr            *sa;
    ngx_rtmp_listen_opt_t      *lsopt;
    struct sockaddr_in         *sin;
    ngx_rtmp_core_main_conf_t  *cmcf;
#if (NGX_HAVE_INET6)
    struct sockaddr_in6        *sin6;
#endif

    cscf->listen = 1;

    value = cf->args->elts;

    ngx_memzero(&u, sizeof(ngx_url_t));

    u.url = value[1];
    u.listen = 1;
    u.default_port = 1935;

    if (ngx_parse_url(cf->pool, &u) != NGX_OK) {
        if (u.err) {
            ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                    "%s in \"%V\" of the \"listen\" directive",
                    u.err, &u.url);
        }

        return NGX_CONF_ERROR;
    }

    cmcf = ngx_rtmp_conf_get_module_main_conf(cf, ngx_rtmp_core_module);

    lsopt = cmcf->listen.elts;

    for (i = 0; i < cmcf->listen.nelts; i++) {

        sa = (struct sockaddr *) lsopt[i].sockaddr;

        if (sa->sa_family != u.family) {
            continue;
        }

        switch (sa->sa_family) {

#if (NGX_HAVE_INET6)
            case AF_INET6:
                off = offsetof(struct sockaddr_in6, sin6_addr);
                len = 16;
                sin6 = (struct sockaddr_in6 *) sa;
                port = sin6->sin6_port;
                break;
#endif

            default: /* AF_INET */
                off = offsetof(struct sockaddr_in, sin_addr);
                len = 4;
                sin = (struct sockaddr_in *) sa;
                port = sin->sin_port;
                break;
        }

        if (ngx_memcmp(lsopt[i].sockaddr + off, (u_char *) &u.sockaddr + off, len)
            != 0)
        {
            continue;
        }

        if (port != u.port) {
            continue;
        }

        ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                "duplicate \"%V\" address and port pair", &u.url);
        return NGX_CONF_ERROR;
    }

    lsopt = ngx_array_push(&cmcf->listen);
    if (lsopt == NULL) {
        return NGX_CONF_ERROR;
    }

    ngx_memzero(lsopt, sizeof(ngx_rtmp_listen_opt_t));

    ngx_memcpy(&lsopt->u.sockaddr, &u.sockaddr, u.socklen);

    lsopt->socklen = u.socklen;
    lsopt->wildcard = u.wildcard;
    lsopt->ctx = cf->ctx;

#if (nginx_version >= 1009011)
    modules = cf->cycle->modules;
#else
    modules = ngx_modules;
#endif

    (void) ngx_sock_ntop(&lsopt->u.sockaddr, lsopt->socklen, lsopt->sockaddr,
            NGX_SOCKADDR_STRLEN, 1);

    for (m = 0; modules[m]; m++) {
        if (modules[m]->type != NGX_RTMP_MODULE) {
            continue;
        }
    }

    for (i = 2; i < cf->args->nelts; i++) {

        if (ngx_strcmp(value[i].data, "default_server") == 0
                || ngx_strcmp(value[i].data, "default") == 0)
        {
            lsopt->default_server = 1;
            continue;
        }

        if (ngx_strcmp(value[i].data, "bind") == 0) {
            lsopt->bind = 1;
            continue;
        }

        if (ngx_strncmp(value[i].data, "ipv6only=o", 10) == 0) {
#if (NGX_HAVE_INET6 && defined IPV6_V6ONLY)
            struct sockaddr  *sa;
            u_char            buf[NGX_SOCKADDR_STRLEN];

            sa = (struct sockaddr *) lsopt->sockaddr;

            if (sa->sa_family == AF_INET6) {

                if (ngx_strcmp(&value[i].data[10], "n") == 0) {
                    lsopt->ipv6only = 1;

                } else if (ngx_strcmp(&value[i].data[10], "ff") == 0) {
                    lsopt->ipv6only = 0;

                } else {
                    ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                            "invalid ipv6only flags \"%s\"",
                            &value[i].data[9]);
                    return NGX_CONF_ERROR;
                }

                lsopt->bind = 1;

            } else {
                len = ngx_sock_ntop(sa,
#if (nginx_version >= 1005003)
                        lsopt->socklen,
#endif
                        buf, NGX_SOCKADDR_STRLEN, 1);

                ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                        "ipv6only is not supported "
                        "on addr \"%*s\", ignored", len, buf);
            }

            continue;
#else
            ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                    "bind ipv6only is not supported "
                    "on this platform");
            return NGX_CONF_ERROR;
#endif
        }
        
        if (ngx_strcmp(value[i].data, "reuseport") == 0) {
#if (NGX_HAVE_REUSEPORT)
            lsopt->reuseport = 1;
            lsopt->bind = 1;
#else
            ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                           "reuseport is not supported "
                           "on this platform, ignored");
#endif
            continue;
        }

        if (ngx_strncmp(value[i].data, "so_keepalive=", 13) == 0) {

            if (ngx_strcmp(&value[i].data[13], "on") == 0) {
                lsopt->so_keepalive = 1;

            } else if (ngx_strcmp(&value[i].data[13], "off") == 0) {
                lsopt->so_keepalive = 2;

            } else {

#if (NGX_HAVE_KEEPALIVE_TUNABLE)
                u_char     *p, *end;
                ngx_str_t   s;

                end = value[i].data + value[i].len;
                s.data = value[i].data + 13;

                p = ngx_strlchr(s.data, end, ':');
                if (p == NULL) {
                    p = end;
                }

                if (p > s.data) {
                    s.len = p - s.data;

                    lsopt->tcp_keepidle = ngx_parse_time(&s, 1);
                    if (lsopt->tcp_keepidle == (time_t) NGX_ERROR) {
                        goto invalid_so_keepalive;
                    }
                }

                s.data = (p < end) ? (p + 1) : end;

                p = ngx_strlchr(s.data, end, ':');
                if (p == NULL) {
                    p = end;
                }

                if (p > s.data) {
                    s.len = p - s.data;

                    lsopt->tcp_keepintvl = ngx_parse_time(&s, 1);
                    if (lsopt->tcp_keepintvl == (time_t) NGX_ERROR) {
                        goto invalid_so_keepalive;
                    }
                }

                s.data = (p < end) ? (p + 1) : end;

                if (s.data < end) {
                    s.len = end - s.data;

                    lsopt->tcp_keepcnt = ngx_atoi(s.data, s.len);
                    if (lsopt->tcp_keepcnt == NGX_ERROR) {
                        goto invalid_so_keepalive;
                    }
                }

                if (lsopt->tcp_keepidle == 0 && lsopt->tcp_keepintvl == 0
                        && lsopt->tcp_keepcnt == 0)
                {
                    goto invalid_so_keepalive;
                }

                lsopt->so_keepalive = 1;

#else

                ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                        "the \"so_keepalive\" parameter accepts "
                        "only \"on\" or \"off\" on this platform");
                return NGX_CONF_ERROR;

#endif
            }

            lsopt->bind = 1;

            continue;

#if (NGX_HAVE_KEEPALIVE_TUNABLE)
invalid_so_keepalive:

            ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                    "invalid so_keepalive value: \"%s\"",
                    &value[i].data[13]);
            return NGX_CONF_ERROR;
#endif
        }

        if (ngx_strcmp(value[i].data, "proxy_protocol") == 0) {
            lsopt->proxy_protocol = 1;
            continue;
        }

        ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                "the invalid \"%V\" parameter", &value[i]);
        return NGX_CONF_ERROR;
    }

    if (ngx_rtmp_add_listen(cf, cscf, lsopt) == NGX_OK) {
        return NGX_CONF_OK;
    }

    return NGX_CONF_OK;
}


static char *
ngx_rtmp_core_hostname(ngx_conf_t *cf, ngx_command_t *cmd, void *conf)
{
    ngx_uint_t               *np, i, m;
    ngx_str_t                *value;
    u_char                    ch;
    ngx_rtmp_host_name_t     *hn;
    ngx_conf_bitmask_t       *mask;

    ngx_rtmp_core_svi_conf_t *csicf = conf;
    char                     *p = conf;


    np = (ngx_uint_t *) (p + cmd->offset);
    value = cf->args->elts;
    mask = cmd->post;

    if (cf->args->nelts < 4) {
        ngx_conf_log_error(NGX_LOG_WARN, cf, 0,
                           "invalid syntax, usage: hostname direct proto $hostname");
        return NGX_CONF_ERROR;
    }

#define NGX_RTMP_CORE_HOSTNAME_MIN_NETLS 3

    for (i = 1; i < NGX_RTMP_CORE_HOSTNAME_MIN_NETLS; i++) {
        for (m = 0; mask[m].name.len != 0; m++) {

            if (mask[m].name.len != value[i].len
                || ngx_strcasecmp(mask[m].name.data, value[i].data) != 0)
            {
                continue;
            }

            if (*np & mask[m].mask) {
                ngx_conf_log_error(NGX_LOG_WARN, cf, 0,
                                   "duplicate value \"%s\"", value[i].data);

            } else {
                *np |= mask[m].mask;
            }

            break;
        }

        if (mask[m].name.len == 0) {
            ngx_conf_log_error(NGX_LOG_WARN, cf, 0,
                               "invalid value \"%s\"", value[i].data);

            return NGX_CONF_ERROR;
        }
    }

    for (; i < cf->args->nelts; i++) {

        ch = value[i].data[0];

        if ((ch == '*' && (value[i].len < 3 || value[i].data[1] != '.'))
            || (ch == '.' && value[i].len < 2))
        {
            ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                               "host name \"%V\" is invalid", &value[i]);
            return NGX_CONF_ERROR;
        }

        if (ngx_strchr(value[i].data, '/')) {
            ngx_conf_log_error(NGX_LOG_WARN, cf, 0,
                               "host name \"%V\" has suspicious symbols",
                               &value[i]);
        }

        hn = ngx_array_push(&csicf->host_names);
        if (hn == NULL) {
             return NGX_CONF_ERROR;
        }

#if (NGX_PCRE)
        hn->regex = NULL;
#endif
        hn->service = csicf;

        if (ngx_strcasecmp(value[i].data, (u_char *) "$hostname") == 0) {
            hn->name = cf->cycle->hostname;

        } else {
            hn->name = value[i];
        }

        if (value[i].data[0] != '~') {
            ngx_strlow(hn->name.data, hn->name.data, hn->name.len);
            continue;
        }

#if (NGX_PCRE)
        {
        u_char               *p;
        ngx_regex_compile_t   rc;
        u_char                errstr[NGX_MAX_CONF_ERRSTR];

        if (value[i].len == 1) {
            ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                               "empty regex in host name \"%V\"", &value[i]);
            return NGX_CONF_ERROR;
        }

        value[i].len--;
        value[i].data++;

        ngx_memzero(&rc, sizeof(ngx_regex_compile_t));

        rc.pattern = value[i];
        rc.err.len = NGX_MAX_CONF_ERRSTR;
        rc.err.data = errstr;

        for (p = value[i].data; p < value[i].data + value[i].len; p++) {
            if (*p >= 'A' && *p <= 'Z') {
                rc.options = NGX_REGEX_CASELESS;
                break;
            }
        }

        hn->regex = ngx_rtmp_regex_compile(cf, &rc);
        if (hn->regex == NULL) {
            return NGX_CONF_ERROR;
        }

        hn->name = value[i];
        csicf->captures = (rc.captures > 0);
        }
#else
        ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                           "using regex \"%V\" "
                           "requires PCRE library", &value[i]);

        return NGX_CONF_ERROR;
#endif
    }

    return NGX_CONF_OK;
}
