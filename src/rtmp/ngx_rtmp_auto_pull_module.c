
/*
 * Copyright (C) Roman Arutyunyan
 */


#include <ngx_config.h>
#include <ngx_core.h>
#include "ngx_rtmp_cmd_module.h"
#include "ngx_rtmp_relay_module.h"
#include "ngx_rtmp_live_module.h"
#include "ngx_rtmp_auto_pull_module.h"

static ngx_int_t ngx_rtmp_auto_pull_init_process(ngx_cycle_t *cycle);
static void ngx_rtmp_auto_pull_exit_process(ngx_cycle_t *cycle);
static void * ngx_rtmp_auto_pull_create_conf(ngx_cycle_t *cf);
static char * ngx_rtmp_auto_pull_init_conf(ngx_cycle_t *cycle, void *conf);

typedef struct ngx_rtmp_auto_pull_ctx_s ngx_rtmp_auto_pull_ctx_t;

struct ngx_rtmp_auto_pull_ctx_s {
    ngx_int_t                      *slots; /* NGX_MAX_PROCESSES */
    u_char                          name[NGX_RTMP_MAX_NAME];
    u_char                          args[NGX_RTMP_MAX_ARGS];
    ngx_event_t                     pull_evt;
};


typedef struct {
    ngx_str_t                       socket_dir;
} ngx_rtmp_auto_pull_conf_t;


static ngx_command_t  ngx_rtmp_auto_pull_commands[] = {

    { ngx_string("rtmp_socket_dir"),
      NGX_MAIN_CONF|NGX_DIRECT_CONF|NGX_CONF_TAKE1,
      ngx_conf_set_str_slot,
      0,
      offsetof(ngx_rtmp_auto_pull_conf_t, socket_dir),
      NULL },

      ngx_null_command
};


static ngx_core_module_t  ngx_rtmp_auto_pull_module_ctx = {
    ngx_string("rtmp_auto_pull"),
    ngx_rtmp_auto_pull_create_conf,         /* create conf */
    ngx_rtmp_auto_pull_init_conf            /* init conf */
};


ngx_module_t  ngx_rtmp_auto_pull_module = {
    NGX_MODULE_V1,
    &ngx_rtmp_auto_pull_module_ctx,         /* module context */
    ngx_rtmp_auto_pull_commands,            /* module directives */
    NGX_CORE_MODULE,                        /* module type */
    NULL,                                   /* init master */
    NULL,                                   /* init module */
    ngx_rtmp_auto_pull_init_process,        /* init process */
    NULL,                                   /* init thread */
    NULL,                                   /* exit thread */
    ngx_rtmp_auto_pull_exit_process,        /* exit process */
    NULL,                                   /* exit master */
    NGX_MODULE_V1_PADDING
};


#define NGX_RTMP_AUTO_PULL_SOCKNAME         "nginx-rtmp"


static ngx_int_t
ngx_rtmp_auto_pull_init_process(ngx_cycle_t *cycle)
{
#if (NGX_HAVE_UNIX_DOMAIN)
    ngx_rtmp_auto_pull_conf_t  *apcf;
    ngx_listening_t            *ls, *lss;
    struct sockaddr_un         *saun;
    int                         reuseaddr;
    ngx_socket_t                s;
    size_t                      n;
    ngx_file_info_t             fi;

    if (ngx_process != NGX_PROCESS_WORKER) {
        return NGX_OK;
    }

    apcf = (ngx_rtmp_auto_pull_conf_t *) ngx_get_conf(cycle->conf_ctx,
                                                    ngx_rtmp_auto_pull_module);

    reuseaddr = 1;
    s = (ngx_socket_t) -1;

    ngx_log_debug0(NGX_LOG_DEBUG_RTMP, cycle->log, 0,
            "auto_pull: creating sockets");

    /*TODO: clone all RTMP listenings? */
    ls = cycle->listening.elts;
    lss = NULL;
    for (n = 0; n < cycle->listening.nelts; ++n, ++ls) {
        if (ls->handler == ngx_rtmp_init_connection) {
            lss = ls;
            break;
        }
    }

    if (lss == NULL) {
        return NGX_OK;
    }

    ls = ngx_array_push(&cycle->listening);
    if (ls == NULL) {
        return NGX_ERROR;
    }

    *ls = *lss;

    /* Disable unix socket client address extraction
     * from accept call
     * Nginx generates bad addr_text with this enabled */
    ls->addr_ntop = 0;
    ls->reuseport = 0;
    
    ls->socklen = sizeof(struct sockaddr_un);
    saun = ngx_pcalloc(cycle->pool, ls->socklen);
    ls->sockaddr = (struct sockaddr *) saun;
    if (ls->sockaddr == NULL) {
        return NGX_ERROR;
    }

    saun->sun_family = AF_UNIX;
    *ngx_snprintf((u_char *) saun->sun_path, sizeof(saun->sun_path),
                  "%V/" NGX_RTMP_AUTO_PULL_SOCKNAME ".%i",
                  &apcf->socket_dir, ngx_process_slot)
        = 0;

    ngx_log_debug1(NGX_LOG_DEBUG_RTMP, cycle->log, 0,
                   "auto_pull: create socket '%s'",
                   saun->sun_path);

    if (ngx_file_info(saun->sun_path, &fi) != ENOENT) {
        ngx_log_debug1(NGX_LOG_DEBUG_RTMP, cycle->log, 0,
                       "auto_pull: delete existing socket '%s'",
                       saun->sun_path);
        ngx_delete_file(saun->sun_path);
    }

    ngx_str_set(&ls->addr_text, "worker_socket");

    s = ngx_socket(AF_UNIX, SOCK_STREAM, 0);
    if (s == -1) {
        ngx_log_error(NGX_LOG_EMERG, cycle->log, ngx_socket_errno,
                      ngx_socket_n " worker_socket failed");
        return NGX_ERROR;
    }

    if (setsockopt(s, SOL_SOCKET, SO_REUSEADDR,
                   (const void *) &reuseaddr, sizeof(int))
        == -1)
    {
        ngx_log_error(NGX_LOG_EMERG, cycle->log, ngx_socket_errno,
                "setsockopt(SO_REUSEADDR) worker_socket failed");
        goto sock_error;
    }

    if (!(ngx_event_flags & NGX_USE_AIO_EVENT)) {
        if (ngx_nonblocking(s) == -1) {
            ngx_log_error(NGX_LOG_EMERG, cycle->log, ngx_socket_errno,
                          ngx_nonblocking_n " worker_socket failed");
            return NGX_ERROR;
        }
    }

    if (bind(s, (struct sockaddr *) saun, sizeof(*saun)) == -1) {
        ngx_log_error(NGX_LOG_EMERG, cycle->log, ngx_socket_errno,
                      ngx_nonblocking_n " worker_socket bind failed");
        goto sock_error;
    }

    if (listen(s, NGX_LISTEN_BACKLOG) == -1) {
        ngx_log_error(NGX_LOG_EMERG, cycle->log, ngx_socket_errno,
                      "listen() to worker_socket, backlog %d failed",
                      NGX_LISTEN_BACKLOG);
        goto sock_error;
    }

    ls->fd = s;
    ls->listen = 1;

    return NGX_OK;

sock_error:
    if (s != (ngx_socket_t) -1 && ngx_close_socket(s) == -1) {
        ngx_log_error(NGX_LOG_EMERG, cycle->log, ngx_socket_errno,
                ngx_close_socket_n " worker_socket failed");
    }
    ngx_delete_file(saun->sun_path);

    return NGX_ERROR;

#else  /* NGX_HAVE_UNIX_DOMAIN */

    return NGX_OK;

#endif /* NGX_HAVE_UNIX_DOMAIN */
}


static void
ngx_rtmp_auto_pull_exit_process(ngx_cycle_t *cycle)
{
#if (NGX_HAVE_UNIX_DOMAIN)
    ngx_rtmp_auto_pull_conf_t  *apcf;
    u_char                      path[NGX_MAX_PATH];

    apcf = (ngx_rtmp_auto_pull_conf_t *) ngx_get_conf(cycle->conf_ctx,
                                                    ngx_rtmp_auto_pull_module);

    *ngx_snprintf(path, sizeof(path),
                  "%V/" NGX_RTMP_AUTO_PULL_SOCKNAME ".%i",
                  &apcf->socket_dir, ngx_process_slot)
         = 0;

    ngx_delete_file(path);

#endif
}


static void *
ngx_rtmp_auto_pull_create_conf(ngx_cycle_t *cycle)
{
    ngx_rtmp_auto_pull_conf_t       *apcf;

    apcf = ngx_pcalloc(cycle->pool, sizeof(ngx_rtmp_auto_pull_conf_t));
    if (apcf == NULL) {
        return NULL;
    }

    return apcf;
}


static char *
ngx_rtmp_auto_pull_init_conf(ngx_cycle_t *cycle, void *conf)
{
    ngx_rtmp_auto_pull_conf_t      *apcf = conf;


    if (apcf->socket_dir.len == 0) {
        ngx_str_set(&apcf->socket_dir, "/tmp");
    }

    return NGX_CONF_OK;
}

