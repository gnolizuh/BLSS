
/*
 * Copyright (C) Roman Arutyunyan
 */


#include <ngx_config.h>
#include <ngx_core.h>
#include "ngx_rtmp.h"
#include "ngx_rtmp_cmd_module.h"
#include "ngx_rtmp_netcall_module.h"
#include "ngx_rtmp_codec_module.h"
#include "ngx_rtmp_record_module.h"
#include "ngx_rtmp_log_module.h"


ngx_rtmp_record_done_pt             ngx_rtmp_record_done;


static ngx_rtmp_publish_pt          next_publish;
static ngx_rtmp_close_stream_pt     next_close_stream;
static ngx_rtmp_stream_begin_pt     next_stream_begin;
static ngx_rtmp_stream_eof_pt       next_stream_eof;


static char *ngx_rtmp_record_recorder(ngx_conf_t *cf, ngx_command_t *cmd,
       void *conf);
static ngx_int_t ngx_rtmp_record_postconfiguration(ngx_conf_t *cf);
static void * ngx_rtmp_record_create_app_conf(ngx_conf_t *cf);
static char * ngx_rtmp_record_merge_app_conf(ngx_conf_t *cf,
       void *parent, void *child);
static ngx_int_t ngx_rtmp_record_write_frame(ngx_rtmp_session_t *s,
       ngx_rtmp_record_rec_ctx_t *rctx,
       ngx_rtmp_header_t *h, ngx_chain_t *in, ngx_int_t inc_nframes);
static ngx_int_t ngx_rtmp_record_av(ngx_rtmp_session_t *s,
       ngx_rtmp_header_t *h, ngx_chain_t *in);
static ngx_int_t ngx_rtmp_record_node_av(ngx_rtmp_session_t *s,
       ngx_rtmp_record_rec_ctx_t *rctx, ngx_rtmp_header_t *h, ngx_chain_t *in);

static ngx_int_t ngx_rtmp_record_node_open(ngx_rtmp_session_t *s,
       ngx_rtmp_record_rec_ctx_t *rctx, ngx_rtmp_record_ctx_t  *ctx);

static ngx_int_t ngx_rtmp_record_node_close(ngx_rtmp_session_t *s,
       ngx_rtmp_record_rec_ctx_t *rctx);
static void  ngx_rtmp_record_make_path(ngx_rtmp_session_t *s,
       ngx_rtmp_record_rec_ctx_t *rctx, ngx_rtmp_record_ctx_t *ctx, ngx_str_t *path);

static ngx_int_t ngx_rtmp_record_init(ngx_rtmp_session_t *s);
static ngx_int_t ngx_rtmp_record_init_remote(ngx_rtmp_session_t *s);

static void  ngx_rtmp_record_start(ngx_rtmp_session_t *s);
static void  ngx_rtmp_record_start_remote(ngx_rtmp_session_t *s);


static ngx_int_t ngx_rtmp_record_create_dir(ngx_rtmp_session_t *s,  u_char *path, ngx_file_info_t *fi);

static ngx_int_t ngx_rtmp_record_ensure_directory(ngx_rtmp_session_t *s, ngx_rtmp_record_rec_ctx_t  *rctx);

static ngx_int_t ngx_rtmp_record_init_indexfile(ngx_rtmp_session_t *s, 
    ngx_rtmp_record_rec_ctx_t *rctx);
static ngx_int_t ngx_rtmp_record_init_indexfile_remote(ngx_rtmp_session_t *s, 
    ngx_rtmp_record_rec_ctx_t  *rctx);

static ngx_int_t ngx_rtmp_record_write_over_file(ngx_rtmp_session_t *s, ngx_rtmp_record_ctx_t *ctx,
ngx_rtmp_record_rec_ctx_t *rctx);

static ngx_conf_bitmask_t  ngx_rtmp_record_mask[] = {
    { ngx_string("off"),                NGX_RTMP_RECORD_OFF         },
    { ngx_string("all"),                NGX_RTMP_RECORD_AUDIO       |
                                        NGX_RTMP_RECORD_VIDEO       },
    { ngx_string("audio"),              NGX_RTMP_RECORD_AUDIO       },
    { ngx_string("video"),              NGX_RTMP_RECORD_VIDEO       },
    { ngx_string("keyframes"),          NGX_RTMP_RECORD_KEYFRAMES   },
    { ngx_string("manual"),             NGX_RTMP_RECORD_MANUAL      },
    { ngx_null_string,                  0                           }
};


static ngx_command_t  ngx_rtmp_record_commands[] = {

    { ngx_string("record"),
      NGX_RTMP_MAIN_CONF|NGX_RTMP_SRV_CONF|NGX_RTMP_APP_CONF|
                         NGX_RTMP_REC_CONF|NGX_CONF_1MORE,
      ngx_conf_set_bitmask_slot,
      NGX_RTMP_APP_CONF_OFFSET,
      offsetof(ngx_rtmp_record_app_conf_t, flags),
      ngx_rtmp_record_mask },

    { ngx_string("record_path"),
      NGX_RTMP_MAIN_CONF|NGX_RTMP_SRV_CONF|NGX_RTMP_APP_CONF|
                         NGX_RTMP_REC_CONF|NGX_CONF_TAKE1,
      ngx_conf_set_str_slot,
      NGX_RTMP_APP_CONF_OFFSET,
      offsetof(ngx_rtmp_record_app_conf_t, path),
      NULL },

    { ngx_string("record_suffix"),
      NGX_RTMP_MAIN_CONF|NGX_RTMP_SRV_CONF|NGX_RTMP_APP_CONF|
                         NGX_RTMP_REC_CONF|NGX_CONF_TAKE1,
      ngx_conf_set_str_slot,
      NGX_RTMP_APP_CONF_OFFSET,
      offsetof(ngx_rtmp_record_app_conf_t, suffix),
      NULL },

    { ngx_string("record_unique"),
      NGX_RTMP_MAIN_CONF|NGX_RTMP_SRV_CONF|NGX_RTMP_APP_CONF|
                         NGX_RTMP_REC_CONF|NGX_CONF_TAKE1,
      ngx_conf_set_flag_slot,
      NGX_RTMP_APP_CONF_OFFSET,
      offsetof(ngx_rtmp_record_app_conf_t, unique),
      NULL },

    { ngx_string("record_append"),
      NGX_RTMP_MAIN_CONF|NGX_RTMP_SRV_CONF|NGX_RTMP_APP_CONF|
                         NGX_RTMP_REC_CONF|NGX_CONF_TAKE1,
      ngx_conf_set_flag_slot,
      NGX_RTMP_APP_CONF_OFFSET,
      offsetof(ngx_rtmp_record_app_conf_t, append),
      NULL },

    { ngx_string("record_lock"),
      NGX_RTMP_MAIN_CONF|NGX_RTMP_SRV_CONF|NGX_RTMP_APP_CONF|
                         NGX_RTMP_REC_CONF|NGX_CONF_TAKE1,
      ngx_conf_set_flag_slot,
      NGX_RTMP_APP_CONF_OFFSET,
      offsetof(ngx_rtmp_record_app_conf_t, lock_file),
      NULL },

    { ngx_string("record_max_size"),
      NGX_RTMP_MAIN_CONF|NGX_RTMP_SRV_CONF|NGX_RTMP_APP_CONF|
                         NGX_RTMP_REC_CONF|NGX_CONF_TAKE1,
      ngx_conf_set_size_slot,
      NGX_RTMP_APP_CONF_OFFSET,
      offsetof(ngx_rtmp_record_app_conf_t, max_size),
      NULL },

    { ngx_string("record_max_frames"),
      NGX_RTMP_MAIN_CONF|NGX_RTMP_SRV_CONF|NGX_RTMP_APP_CONF|
                         NGX_RTMP_REC_CONF|NGX_CONF_TAKE1,
      ngx_conf_set_size_slot,
      NGX_RTMP_APP_CONF_OFFSET,
      offsetof(ngx_rtmp_record_app_conf_t, max_frames),
      NULL },

    { ngx_string("record_interval"),
      NGX_RTMP_MAIN_CONF|NGX_RTMP_SRV_CONF|NGX_RTMP_APP_CONF|
                         NGX_RTMP_REC_CONF|NGX_CONF_TAKE1,
      ngx_conf_set_msec_slot,
      NGX_RTMP_APP_CONF_OFFSET,
      offsetof(ngx_rtmp_record_app_conf_t, interval),
      NULL },

    { ngx_string("record_usr_id"),
      NGX_RTMP_MAIN_CONF|NGX_RTMP_SRV_CONF|NGX_RTMP_APP_CONF|
                         NGX_RTMP_REC_CONF|NGX_CONF_TAKE1,
      ngx_conf_set_str_slot,
      NGX_RTMP_APP_CONF_OFFSET,
      offsetof(ngx_rtmp_record_app_conf_t, user_id),
      NULL },

    { ngx_string("record_is_public"),
      NGX_RTMP_MAIN_CONF|NGX_RTMP_SRV_CONF|NGX_RTMP_APP_CONF|
                         NGX_RTMP_REC_CONF|NGX_CONF_TAKE1,
      ngx_conf_set_str_slot,
      NGX_RTMP_APP_CONF_OFFSET,
      offsetof(ngx_rtmp_record_app_conf_t, is_public),
      NULL },

    { ngx_string("record_vod_id"),
      NGX_RTMP_MAIN_CONF|NGX_RTMP_SRV_CONF|NGX_RTMP_APP_CONF|
                         NGX_RTMP_REC_CONF|NGX_CONF_TAKE1,
      ngx_conf_set_size_slot,
      NGX_RTMP_APP_CONF_OFFSET,
      offsetof(ngx_rtmp_record_app_conf_t, vdoid),
      NULL },

    { ngx_string("record_bucket"),
      NGX_RTMP_MAIN_CONF|NGX_RTMP_SRV_CONF|NGX_RTMP_APP_CONF|
                         NGX_RTMP_REC_CONF|NGX_CONF_TAKE1,
      ngx_conf_set_str_slot,
      NGX_RTMP_APP_CONF_OFFSET,
      offsetof(ngx_rtmp_record_app_conf_t, bucket),
      NULL },
      
    { ngx_string("record_notify_url"),
      NGX_RTMP_MAIN_CONF|NGX_RTMP_SRV_CONF|NGX_RTMP_APP_CONF|
    				     NGX_RTMP_REC_CONF|NGX_CONF_TAKE1,
      ngx_conf_set_str_slot,
      NGX_RTMP_APP_CONF_OFFSET,
      offsetof(ngx_rtmp_record_app_conf_t, notify_url),
      NULL },
          
    { ngx_string("screenshot_is_cover"),
      NGX_RTMP_MAIN_CONF|NGX_RTMP_SRV_CONF|NGX_RTMP_APP_CONF|
                         NGX_RTMP_REC_CONF|NGX_CONF_TAKE1,
      ngx_conf_set_flag_slot,
      NGX_RTMP_APP_CONF_OFFSET,
      offsetof(ngx_rtmp_record_app_conf_t, screenshot_is_cover),
      NULL },

    { ngx_string("screenshot_monitor"),
      NGX_RTMP_MAIN_CONF|NGX_RTMP_SRV_CONF|NGX_RTMP_APP_CONF|
                         NGX_RTMP_REC_CONF|NGX_CONF_TAKE1,
      ngx_conf_set_num_slot,
      NGX_RTMP_APP_CONF_OFFSET,
      offsetof(ngx_rtmp_record_app_conf_t, screenshot_monitor),
      NULL },

     { ngx_string("region_pic"),
      NGX_RTMP_MAIN_CONF|NGX_RTMP_SRV_CONF|NGX_RTMP_APP_CONF|
    				     NGX_RTMP_REC_CONF|NGX_CONF_TAKE1,
      ngx_conf_set_str_slot,
      NGX_RTMP_APP_CONF_OFFSET,
      offsetof(ngx_rtmp_record_app_conf_t, region_pic),
      NULL },
      
    { ngx_string("host_pic"),
      NGX_RTMP_MAIN_CONF|NGX_RTMP_SRV_CONF|NGX_RTMP_APP_CONF|
                         NGX_RTMP_REC_CONF|NGX_CONF_TAKE1,
      ngx_conf_set_str_slot,
      NGX_RTMP_APP_CONF_OFFSET,
      offsetof(ngx_rtmp_record_app_conf_t, host_pic),
      NULL },

    { ngx_string("record_notify"),
      NGX_RTMP_MAIN_CONF|NGX_RTMP_SRV_CONF|NGX_RTMP_APP_CONF|
                         NGX_RTMP_REC_CONF|NGX_CONF_TAKE1,
      ngx_conf_set_flag_slot,
      NGX_RTMP_APP_CONF_OFFSET,
      offsetof(ngx_rtmp_record_app_conf_t, notify),
      NULL },

    { ngx_string("recorder"),
      NGX_RTMP_APP_CONF|NGX_CONF_BLOCK|NGX_CONF_TAKE1,
      ngx_rtmp_record_recorder,
      NGX_RTMP_APP_CONF_OFFSET,
      0,
      NULL },


      ngx_null_command
};


static ngx_rtmp_module_t  ngx_rtmp_record_module_ctx = {
    NULL,                                   /* preconfiguration */
    ngx_rtmp_record_postconfiguration,      /* postconfiguration */
    NULL,                                   /* create main configuration */
    NULL,                                   /* init main configuration */
    NULL,                                   /* create server configuration */
    NULL,                                   /* merge server configuration */
    ngx_rtmp_record_create_app_conf,        /* create app configuration */
    ngx_rtmp_record_merge_app_conf          /* merge app configuration */
};


ngx_module_t  ngx_rtmp_record_module = {
    NGX_MODULE_V1,
    &ngx_rtmp_record_module_ctx,            /* module context */
    ngx_rtmp_record_commands,               /* module directives */
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


static void *
ngx_rtmp_record_create_app_conf(ngx_conf_t *cf)
{
    ngx_rtmp_record_app_conf_t      *racf;

    racf = ngx_pcalloc(cf->pool, sizeof(ngx_rtmp_record_app_conf_t));

    if (racf == NULL) {
        return NULL;
    }

    racf->max_size = NGX_CONF_UNSET_SIZE;
    racf->max_frames = NGX_CONF_UNSET_SIZE;
    racf->vdoid = NGX_CONF_UNSET_SIZE;
    racf->interval = NGX_CONF_UNSET_MSEC;
    racf->unique = NGX_CONF_UNSET;
    racf->append = NGX_CONF_UNSET;
    racf->lock_file = NGX_CONF_UNSET;
    racf->notify = NGX_CONF_UNSET;
    racf->url = NGX_CONF_UNSET_PTR;
    racf->screenshot_monitor = NGX_CONF_UNSET_UINT;
	
    if (ngx_array_init(&racf->rec, cf->pool, 1, sizeof(void *)) != NGX_OK) {
        return NULL;
    }

    return racf;
}


static char *
ngx_rtmp_record_merge_app_conf(ngx_conf_t *cf, void *parent, void *child)
{
    ngx_rtmp_record_app_conf_t     *prev = parent;
    ngx_rtmp_record_app_conf_t     *conf = child;
    ngx_rtmp_record_app_conf_t    **rracf;

    ngx_conf_merge_str_value(conf->path, prev->path, "");
    ngx_conf_merge_str_value(conf->suffix, prev->suffix, ".flv.bak");
    ngx_conf_merge_size_value(conf->max_size, prev->max_size, 0);
    ngx_conf_merge_size_value(conf->max_frames, prev->max_frames, 0);
    ngx_conf_merge_value(conf->unique, prev->unique, 1);
    ngx_conf_merge_value(conf->append, prev->append, 0);
    ngx_conf_merge_value(conf->lock_file, prev->lock_file, 0);
    ngx_conf_merge_value(conf->notify, prev->notify, 0);
    ngx_conf_merge_value(conf->screenshot_is_cover, prev->screenshot_is_cover, 0);
    ngx_conf_merge_uint_value(conf->screenshot_monitor, prev->screenshot_monitor, 0);
    ngx_conf_merge_msec_value(conf->interval, prev->interval,
                              (ngx_msec_t) NGX_CONF_UNSET);
	
    ngx_conf_merge_str_value(conf->user_id, prev->user_id, "");
    ngx_conf_merge_str_value(conf->is_public, prev->is_public, "");
    ngx_conf_merge_str_value(conf->bucket, prev->bucket, "");
    ngx_conf_merge_str_value(conf->notify_url, prev->notify_url, "");
    ngx_conf_merge_size_value(conf->vdoid, prev->vdoid, 0);

    ngx_conf_merge_str_value(conf->region_pic, prev->region_pic, "");
    ngx_conf_merge_str_value(conf->host_pic, prev->host_pic, ""); 
    
    ngx_conf_merge_bitmask_value(conf->flags, prev->flags, 0);
    ngx_conf_merge_ptr_value(conf->url, prev->url, NULL);

    if (conf->flags) {
        rracf = ngx_array_push(&conf->rec);
        if (rracf == NULL) {
            return NGX_CONF_ERROR;
        }

        *rracf = conf;
    }

    return NGX_CONF_OK;
}


static ngx_int_t
ngx_rtmp_record_write_header(ngx_file_t *file)
{
    static u_char       flv_header[] = {
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

    return ngx_write_file(file, flv_header, sizeof(flv_header), 0) == NGX_ERROR
           ? NGX_ERROR
           : NGX_OK;
}


static ngx_rtmp_record_rec_ctx_t *
ngx_rtmp_record_get_node_ctx(ngx_rtmp_session_t *s, ngx_uint_t n)
{
    ngx_rtmp_record_ctx_t          *ctx;
    ngx_rtmp_record_rec_ctx_t      *rctx;

    if (ngx_rtmp_record_init(s) != NGX_OK) {
        return NULL;
    }

    ctx = ngx_rtmp_get_module_ctx(s, ngx_rtmp_record_module);

    if (n >= ctx->rec.nelts) {
        return NULL;
    }

    rctx = ctx->rec.elts;

    return &rctx[n];
}


ngx_int_t
ngx_rtmp_record_open(ngx_rtmp_session_t *s, ngx_uint_t n, ngx_str_t *path)
{
    ngx_rtmp_record_rec_ctx_t      *rctx;
    ngx_int_t                       rc;
    ngx_rtmp_record_ctx_t           *ctx;

    ngx_log_debug1(NGX_LOG_DEBUG_RTMP, s->connection->log, 0,
                   "record: #%ui manual open", n);

    rctx = ngx_rtmp_record_get_node_ctx(s, n);
    ctx = ngx_rtmp_get_module_ctx(s, ngx_rtmp_record_module);
	
    if (rctx == NULL || ctx == NULL) {
        return NGX_ERROR;
    }

    rc = ngx_rtmp_record_node_open(s, rctx, ctx);
    if (rc != NGX_OK) {
        return rc;
    }
	
    if (path) {
        ngx_rtmp_record_make_path(s, rctx, ctx, path);
    }

    return NGX_OK;
}


ngx_int_t
ngx_rtmp_record_close(ngx_rtmp_session_t *s, ngx_uint_t n, ngx_str_t *path)
{
    ngx_rtmp_record_rec_ctx_t      *rctx;
    ngx_int_t                       rc;
    ngx_rtmp_record_ctx_t          *ctx;

    ngx_log_debug1(NGX_LOG_DEBUG_RTMP, s->connection->log, 0,
                   "record: #%ui manual close", n);
    
    rctx = ngx_rtmp_record_get_node_ctx(s, n);
    ctx = ngx_rtmp_get_module_ctx(s, ngx_rtmp_record_module);

    if (rctx == NULL || ctx ==  NULL) {
        return NGX_ERROR;
    }

    rc = ngx_rtmp_record_node_close(s, rctx);
    if (rc != NGX_OK) {
        return rc;
    }

    if (path) {
        ngx_rtmp_record_make_path(s, rctx, ctx, path);
    }

    return NGX_OK;
}


ngx_uint_t
ngx_rtmp_record_find(ngx_rtmp_record_app_conf_t *racf, ngx_str_t *id)
{
    ngx_rtmp_record_app_conf_t    **pracf, *rracf;
    ngx_uint_t                      n;

    pracf = racf->rec.elts;

    for (n = 0; n < racf->rec.nelts; ++n, ++pracf) {
        rracf = *pracf;

        if (rracf->id.len == id->len &&
            ngx_strncmp(rracf->id.data, id->data, id->len) == 0)
        {
            return n;
        }
    }

    return NGX_CONF_UNSET_UINT;
}


/* This funcion returns pointer to a static buffer */
static void
ngx_rtmp_record_make_path(ngx_rtmp_session_t *s,
                          ngx_rtmp_record_rec_ctx_t *rctx, ngx_rtmp_record_ctx_t *ctx, ngx_str_t *path)
{
    //ngx_rtmp_record_ctx_t          *ctx;
    ngx_rtmp_record_app_conf_t     *rracf, *racf;
    u_char                         *p, *l;
    struct tm                       tm;

    static u_char                   buf[NGX_TIME_T_LEN + 1];
    static u_char                   pbuf[NGX_MAX_PATH + 1];

    racf = ngx_rtmp_get_module_app_conf(s, ngx_rtmp_record_module);
    if (racf == NULL){
        return;
    }

    if (ctx == NULL){
        return;
    }

    if (ngx_rtmp_remote_conf()) {
        rracf = racf;
    }else {
        rracf = rctx->conf;
    }

    /* create file path */
    p = pbuf;
    l = pbuf + sizeof(pbuf) - 1;

    p = ngx_cpymem(p, rctx->record_path.data,
    			ngx_min(rctx->record_path.len, (size_t)(l - p - 1)));

    p = (u_char *)ngx_escape_uri(p, ctx->name, ngx_min(ngx_strlen(ctx->name),
                (size_t)(l - p)), NGX_ESCAPE_URI_COMPONENT);

    /* append timestamp */
    if (rracf->unique) {
        p = ngx_cpymem(p, buf, ngx_min(ngx_sprintf(buf, "-%T",
                       rctx->timestamp) - buf, l - p));
    }

    if (ngx_strchr(rracf->suffix.data, '%')) {
        ngx_libc_localtime(rctx->timestamp, &tm);
        p += strftime((char *) p, l - p, (char *) rracf->suffix.data, &tm);
    } else {
        p = ngx_cpymem(p, rracf->suffix.data,
                ngx_min(rracf->suffix.len, (size_t)(l - p)));
    }

    *p = 0;
    path->data = pbuf;
    path->len  = p - pbuf;

    ngx_log_debug2(NGX_LOG_DEBUG_RTMP, s->connection->log, 0,
                   "record: %V path: '%V'", &rracf->id, path);
}

static void
ngx_rtmp_record_notify_error(ngx_rtmp_session_t *s,
                             ngx_rtmp_record_rec_ctx_t *rctx)
{
    ngx_rtmp_record_app_conf_t *rracf, *racf = NULL; 

    racf = ngx_rtmp_get_module_app_conf(s, ngx_rtmp_record_module);
    if(racf == NULL) {
        return;
    }

    rctx->failed = 1;

    if (ngx_rtmp_remote_conf()) {

        rracf = racf;
    }else{
        rracf = rctx->conf;
    }
    if (!rracf->notify) {
        return;
    }

    ngx_rtmp_send_status(s, "NetStream.Record.Failed", "error",
                         rracf->id.data ? (char *) rracf->id.data : "");
}


static ngx_int_t
ngx_rtmp_record_node_open(ngx_rtmp_session_t *s,
                          ngx_rtmp_record_rec_ctx_t *rctx, ngx_rtmp_record_ctx_t *ctx)
{
    ngx_rtmp_record_app_conf_t *rracf, *racf;
    ngx_err_t                   err;
    ngx_str_t                   path;
    ngx_int_t                   mode, create_mode;
    u_char                      buf[8], *p;
    off_t                       file_size;
    uint32_t                    tag_size, mlen, timestamp;
    ngx_str_t                   record_path;
    ngx_str_t                   index_path;

    ngx_rtmp_rec_ctx_type_e     type;
    ngx_int_t                   interval;
    unsigned                    first_cutpic;

    racf = ngx_rtmp_get_module_app_conf(s, ngx_rtmp_record_module);
    if (racf == NULL){
        return NGX_ERROR;
    }

    if(ngx_rtmp_record_ensure_directory(s, rctx) != NGX_OK) {
        return NGX_ERROR;
    }

    if (rctx->file.fd != NGX_INVALID_FILE) {
        return NGX_AGAIN;
    }
    if (ngx_rtmp_remote_conf()) {

        rracf = racf;
    }else {

        rracf = rctx->conf;
    }

    record_path = rctx->record_path;
    index_path = rctx->index_path;
    type = rctx->type;
    interval = rctx->interval;
    first_cutpic = rctx->first_cutpic;
    tag_size = 0;

    ngx_log_debug1(NGX_LOG_DEBUG_RTMP, s->connection->log, 0,
                   "record: %V opening", &rracf->id);

    ngx_memzero(rctx, sizeof(*rctx));
    rctx->conf = rracf;
    rctx->record_path = record_path;
    rctx->index_path = index_path;
    rctx->type = type;
    rctx->interval = interval;
    rctx->first_cutpic = first_cutpic;

    rctx->last = *ngx_cached_time;
    rctx->timestamp = ngx_cached_time->sec;

    ngx_rtmp_record_make_path(s, rctx, ctx, &path);

    mode = rracf->append ? NGX_FILE_RDWR : NGX_FILE_WRONLY;
    create_mode = rracf->append ? NGX_FILE_CREATE_OR_OPEN : NGX_FILE_TRUNCATE;

    ngx_memzero(&rctx->file, sizeof(rctx->file));
    rctx->file.offset = 0;
    rctx->file.log = s->connection->log;
    rctx->file.fd = ngx_open_file(path.data, mode, create_mode,
                                  NGX_FILE_DEFAULT_ACCESS);
    ngx_str_set(&rctx->file.name, "recorded");

    if (rctx->file.fd == NGX_INVALID_FILE) {
        err = ngx_errno;
        ngx_log_error(NGX_LOG_CRIT, s->connection->log, err,
                      "record: %V failed to open file '%V', err:%D",
                      &rracf->id, &path, err);

        ngx_rtmp_record_notify_error(s, rctx);

        return NGX_OK;
    }

#if !(NGX_WIN32)
    if (rracf->lock_file) {
        err = ngx_lock_fd(rctx->file.fd);
        if (err) {
            ngx_log_error(NGX_LOG_CRIT, s->connection->log, err,
                          "record: %V lock failed", &rracf->id);
        }
    }
#endif

    ngx_log_debug2(NGX_LOG_DEBUG_RTMP, s->connection->log, 0,
                   "record: %V opened '%V'", &rracf->id, &path);

    if (rracf->notify) {

        ngx_rtmp_send_status(s, "NetStream.Record.Start", "status",
                             rracf->id.data ? (char *) rracf->id.data : "");
    }

    if (rracf->append) {

        file_size = 0;
        timestamp = 0;

#if (NGX_WIN32)
        {
            LONG  lo, hi;

            lo = 0;
            hi = 0;
            lo = SetFilePointer(rctx->file.fd, lo, &hi, FILE_END);
            file_size = (lo == INVALID_SET_FILE_POINTER ?
                         (off_t) -1 : (off_t) hi << 32 | (off_t) lo);
        }
#else
        file_size = lseek(rctx->file.fd, 0, SEEK_END);
#endif
        if (file_size == (off_t) -1) {
            ngx_log_error(NGX_LOG_ERR, s->connection->log, ngx_errno,
                          "record: %V seek failed", &rracf->id);
            goto done;
        }

        if (file_size < 4) {
            goto done;
        }

        if (ngx_read_file(&rctx->file, buf, 4, file_size - 4) != 4) {
            ngx_log_error(NGX_LOG_CRIT, s->connection->log, ngx_errno,
                          "record: %V tag size read failed", &rracf->id);
            goto done;
        }

        p = (u_char *) &tag_size;
        p[0] = buf[3];
        p[1] = buf[2];
        p[2] = buf[1];
        p[3] = buf[0];

        if (tag_size == 0 || tag_size + 4 > file_size) {
            file_size = 0;
            goto done;
        }

        if (ngx_read_file(&rctx->file, buf, 8, file_size - tag_size - 4) != 8)
        {
            ngx_log_error(NGX_LOG_CRIT, s->connection->log, ngx_errno,
                          "record: %V tag read failed", &rracf->id);
            goto done;
        }

        p = (u_char *) &mlen;
        p[0] = buf[3];
        p[1] = buf[2];
        p[2] = buf[1];
        p[3] = 0;

        if (tag_size != mlen + 11) {
            ngx_log_error(NGX_LOG_CRIT, s->connection->log, ngx_errno,
                          "record: %V tag size mismatch: "
                          "tag_size=%uD, mlen=%uD", &rracf->id, tag_size, mlen);
            goto done;
        }

        p = (u_char *) &timestamp;
        p[3] = buf[7];
        p[0] = buf[6];
        p[1] = buf[5];
        p[2] = buf[4];

done:
        rctx->file.offset = file_size;
        rctx->time_shift = timestamp;

        ngx_log_debug3(NGX_LOG_DEBUG_RTMP, s->connection->log, 0,
                       "record: append offset=%O, time=%uD, tag_size=%uD",
                       file_size, timestamp, tag_size);
    }

    return NGX_OK;
}


static ngx_int_t
ngx_rtmp_record_init(ngx_rtmp_session_t *s)
{
    ngx_rtmp_record_app_conf_t     *racf, **rracf;
    ngx_rtmp_record_rec_ctx_t      *rctx;
    ngx_rtmp_record_ctx_t          *ctx;
    ngx_uint_t                      n;

#define     PATH_BUFF_LEN       1024
#define     TIME_BUFF_LEN        256

    ctx = ngx_rtmp_get_module_ctx(s, ngx_rtmp_record_module);

    if (ctx) {
        return NGX_OK;
    }

    racf = ngx_rtmp_get_module_app_conf(s, ngx_rtmp_record_module);

    if (racf == NULL || racf->rec.nelts == 0) {
        return NGX_OK;
    }

    ctx = ngx_pcalloc(s->pool, sizeof(ngx_rtmp_record_ctx_t));

    if (ctx == NULL) {
        return NGX_ERROR;
    }

    ngx_rtmp_set_ctx(s, ctx, ngx_rtmp_record_module);

    if (ngx_array_init(&ctx->rec, s->pool, racf->rec.nelts,
                       sizeof(ngx_rtmp_record_rec_ctx_t))
        != NGX_OK)
    {
        return NGX_ERROR;
    }

    rracf = racf->rec.elts;

    rctx = ngx_array_push_n(&ctx->rec, racf->rec.nelts);

    if (rctx == NULL) {
        return NGX_ERROR;
    }

    for (n = 0; n < racf->rec.nelts; ++n, ++rracf, ++rctx) {
        ngx_memzero(rctx, sizeof(*rctx));
        rctx->conf = *rracf;
        rctx->file.fd = NGX_INVALID_FILE;
    }

    return NGX_OK;
}


static ngx_int_t
ngx_rtmp_record_init_remote(ngx_rtmp_session_t *s)
{
    ngx_rtmp_record_app_conf_t    *racf;
    ngx_rtmp_record_ctx_t         *ctx;
    ngx_rtmp_record_rec_ctx_t     *rctx;

#define     PATH_BUFF_LEN       1024
#define     TIME_BUFF_LEN        256

    ctx = ngx_rtmp_get_module_ctx(s, ngx_rtmp_record_module);
    if (ctx) {
        return NGX_OK;
    }

    racf = ngx_rtmp_get_module_app_conf(s, ngx_rtmp_record_module);
    if (racf == NULL) {
        return NGX_ERROR;
    }

    ctx = ngx_pcalloc(s->pool, sizeof(ngx_rtmp_record_ctx_t));
    if (ctx == NULL) {
        return NGX_ERROR;
    }

    ngx_rtmp_set_ctx(s, ctx, ngx_rtmp_record_module);

    if (!s->conf.screenshot) {
        return NGX_OK;
    }

    if (ngx_array_init(&ctx->rec, s->pool, 4,
                       sizeof(ngx_rtmp_record_rec_ctx_t))
        != NGX_OK)
    {
        return NGX_ERROR;
    }

    rctx = ngx_array_push(&ctx->rec);
    if (rctx == NULL) {
        return NGX_ERROR;
    }

    ngx_memzero(rctx, sizeof(*rctx));
    rctx->type = NGX_RTMP_REC_CTX_TYPE_PIC;
    rctx->interval = s->conf.screenshot_interval;

    rctx->file.fd = NGX_INVALID_FILE;

    return NGX_OK;
}


static ngx_int_t
ngx_rtmp_record_create_dir(ngx_rtmp_session_t *s, u_char *path, ngx_file_info_t *fi)
{
    if (!s || !path || !fi) {

        return NGX_ERROR;
    }

    if (ngx_file_info(path, fi) == NGX_FILE_ERROR) {

        if (ngx_errno != NGX_ENOENT) {
            ngx_log_debug1(NGX_LOG_DEBUG_RTMP, s->connection->log, ngx_errno,
                           "record_create_indexfile: " ngx_file_info_n " failed on '%s'", path);
            return NGX_ERROR;
        }

        /* ENOENT */
        if (ngx_create_full_path(path, 0777) == NGX_FILE_ERROR) {
            ngx_log_error(NGX_LOG_ERR, s->connection->log, ngx_errno,
                          "record create directory " ngx_create_dir_n " failed on '%s'", path);
            return NGX_ERROR;
        }
        ngx_log_debug1(NGX_LOG_DEBUG_RTMP, s->connection->log, 0,
                       "record_create_indexfile: directory '%s' created", path);

    } else {

        if (!ngx_is_dir(fi)) {
            ngx_log_error(NGX_LOG_ERR, s->connection->log, 0,
                          "pic: '%s' exists and is not a directory", path);
            return  NGX_ERROR;
        }

        ngx_log_debug1(NGX_LOG_DEBUG_RTMP, s->connection->log, 0,
                       "pic: '%s' exists", path);
    }

    return NGX_OK;
}


static ngx_int_t
ngx_rtmp_record_ensure_directory(ngx_rtmp_session_t *s, ngx_rtmp_record_rec_ctx_t  *rctx)
{
    ngx_str_t                                 path;
    ngx_str_t                                 unique_name;
    ngx_rtmp_core_srv_conf_t                 *cscf;
    ngx_file_info_t                           fi;
    u_char                                    num[NGX_INT32_LEN];
    u_char                                   *p;
    u_char                                   index_path[NGX_MAX_PATH];
    u_char                                   record_path[NGX_MAX_PATH];
    u_char                                   publish_time[NGX_UINT32_LEN];

#define NGX_RTMP_RECORD_MERGE_PATH(p, unique_name, app, sname, time, num) \
    do {\
        p = ngx_cpymem(p, unique_name.data, unique_name.len); \
        *p++ = '/'; \
        p  = ngx_cpymem(p, app.data, app.len); \
        *p++ = '/'; \
        p = ngx_cpymem(p, sname.data, sname.len); \
        *p++ = '/'; \
        p = ngx_cpymem(p, time, ngx_strlen(time));  \
        p = ngx_cpymem(p, "_", ngx_strlen("_"));  \
        p = ngx_cpymem(p, num, ngx_strlen((char *)num));  \
        *p++ = '/'; \
    } while(0)

    /*first time to create directory*/
    if (rctx->index_path.len == 0 || rctx->record_path.len == 0) {

        ngx_memzero(num, NGX_INT32_LEN);
        *ngx_sprintf(num, "%ui", (ngx_uint_t)s->connection->number) = 0;

        ngx_sprintf(publish_time, "%T", ngx_current_msec);

        cscf = ngx_rtmp_get_module_srv_conf(s, ngx_rtmp_core_module);
        unique_name = ngx_rtmp_get_attr_conf(cscf, unique_name);

        ngx_str_set(&path, "/data/picture/index");

        ngx_memzero(index_path, NGX_MAX_PATH);
        if (path.data[path.len - 1] != '/') {
            p = ngx_snprintf(index_path, NGX_MAX_PATH, "%V/", &path);
        } else {
            p = ngx_snprintf(index_path, NGX_MAX_PATH, "%V", &path);
        }

        NGX_RTMP_RECORD_MERGE_PATH(p, unique_name, s->app, s->name, publish_time, num);

        rctx->index_path.len = ngx_strlen(index_path);
        rctx->index_path.data = ngx_pcalloc(s->pool, rctx->index_path.len);
        ngx_sprintf(rctx->index_path.data, "%s", index_path);
        if (ngx_rtmp_record_create_dir(s, index_path, &fi) == NGX_ERROR) {
            return NGX_ERROR;
        }

        ngx_str_set(&path, "/data/picture/data");
        ngx_memzero(record_path, NGX_MAX_PATH);
        if (path.data[path.len - 1] != '/') {
            p = ngx_snprintf(record_path, NGX_MAX_PATH, "%V/", &path);
        } else {
            p = ngx_snprintf(record_path, NGX_MAX_PATH, "%V", &path);
        }

        NGX_RTMP_RECORD_MERGE_PATH(p, unique_name, s->app, s->name, publish_time, num);

        rctx->record_path.len = ngx_strlen(record_path);
        rctx->record_path.data = ngx_pcalloc(s->pool, rctx->record_path.len);
        ngx_sprintf(rctx->record_path.data, "%s", record_path);

        if (ngx_rtmp_record_create_dir(s, record_path, &fi) == NGX_ERROR) {
            return NGX_ERROR;
        }

    } else {
        ngx_memzero(index_path, sizeof(index_path));
        p = ngx_cpymem(index_path, rctx->index_path.data, rctx->index_path.len);
        if (p[-1] != '/') {
            *p++ = '/';
        }

        if (ngx_file_info(index_path, &fi) == NGX_FILE_ERROR) {
            if (ngx_errno != NGX_ENOENT) {
                ngx_log_error(NGX_LOG_ERR, s->connection->log, ngx_errno,
                              "pic: " ngx_file_info_n " failed on '%V'",
                              &rctx->index_path);
                return NGX_ERROR;
            }

            if (ngx_rtmp_record_create_dir(s, index_path, &fi) == NGX_ERROR) {
                ngx_log_error(NGX_LOG_ERR, s->connection->log, ngx_errno,
                               "pic: " ngx_create_dir_n " failed on '%V'",
                               &rctx->index_path);
                return NGX_ERROR;
            }

            ngx_log_error(NGX_LOG_ERR, s->connection->log, 0,
                           "pic: directory '%V' created", &rctx->index_path);
        }

        ngx_memzero(record_path, sizeof(record_path));
        p = ngx_cpymem(record_path, rctx->record_path.data, rctx->record_path.len);
        if (p[-1] != '/') {
            *p++ = '/';
        }

        if (ngx_file_info(record_path, &fi) == NGX_FILE_ERROR) {
            if (ngx_errno != NGX_ENOENT) {
                ngx_log_error(NGX_LOG_ERR, s->connection->log, ngx_errno,
                              "pic: " ngx_file_info_n " failed on '%V'",
                              &rctx->record_path);
                return NGX_ERROR;
            }

            if (ngx_rtmp_record_create_dir(s, record_path, &fi) == NGX_ERROR) {
                ngx_log_error(NGX_LOG_ERR, s->connection->log, ngx_errno,
                              "pic: " ngx_create_dir_n " failed on '%V'",
                              &rctx->record_path);
                return NGX_ERROR;
            }

            ngx_log_error(NGX_LOG_ERR, s->connection->log, 0,
                          "pic: directory '%V' created", &rctx->record_path);
        }
    }

    if(ngx_rtmp_remote_conf()) {
        ngx_rtmp_record_init_indexfile_remote(s, rctx);
    } else {
        ngx_rtmp_record_init_indexfile(s, rctx);
    }

    return NGX_OK;

#undef NGX_RTMP_RECORD_MERGE_PATH
}

#define   INDEX_BUFF_LEN              1024
#define   NGX_RTMP_RECORD_CRLF        "\r\n"

static ngx_int_t
ngx_rtmp_record_init_indexfile(ngx_rtmp_session_t *s, ngx_rtmp_record_rec_ctx_t  *rctx)
{
    u_char                         path[NGX_MAX_PATH], *p;
    u_char                         buffer[INDEX_BUFF_LEN];
    ngx_int_t                      n;
    ngx_uint_t                     is_picture;
    ngx_file_t                     index_file;
    ngx_file_info_t                fi;

    ngx_memzero(path, NGX_MAX_PATH);
    p = ngx_snprintf(path, NGX_MAX_PATH, "%Vindex.txt", &rctx->index_path);

    if(ngx_file_info(path, &fi)) {
        if(!ngx_is_file(&fi)) {
            ngx_log_error(NGX_LOG_ERR, s->connection->log, 0,
                          "pic: '%s' exists and is not a file", path);
            return  NGX_ERROR;
        } else {
            return NGX_OK;
        }
    }

    ngx_memzero(&index_file, sizeof(index_file));
    ngx_str_set(&index_file.name, "index.txt");
    index_file.log = s->connection->log;
    index_file.fd = ngx_open_file(path, NGX_FILE_WRONLY, NGX_FILE_TRUNCATE, NGX_FILE_DEFAULT_ACCESS);

    if (index_file.fd == NGX_INVALID_FILE) {
        ngx_log_error(NGX_LOG_ERR, s->connection->log, ngx_errno,
                      "init_indexfile: error creating index file");
        return NGX_ERROR;
    }

    if((rctx->conf->flags & NGX_RTMP_RECORD_VIDEO) &&
    	(rctx->conf->flags & NGX_RTMP_RECORD_KEYFRAMES)) {

        is_picture = 1;
    } else {

        is_picture = 0;
    }

    if (s->vdoid.len > 0) {
    	p = ngx_snprintf(buffer, sizeof(buffer),
                 "usr_id %V"NGX_RTMP_RECORD_CRLF
                 "vdoid %V"NGX_RTMP_RECORD_CRLF
                 "is_public %V"NGX_RTMP_RECORD_CRLF
                 "bucket %V"NGX_RTMP_RECORD_CRLF
                 "notify_url %V"NGX_RTMP_RECORD_CRLF
                 "interval %ui"NGX_RTMP_RECORD_CRLF
                 "is_picture %ui"NGX_RTMP_RECORD_CRLF
                 "screenshot_is_cover %ui"NGX_RTMP_RECORD_CRLF
                 "screenshot_monitor %ui"NGX_RTMP_RECORD_CRLF
                 "region_pic %V"NGX_RTMP_RECORD_CRLF
                 "host_pic %V"NGX_RTMP_RECORD_CRLF
                 NGX_RTMP_RECORD_CRLF,
                 &rctx->conf->user_id, &s->vdoid, &rctx->conf->is_public,
	    	     &rctx->conf->bucket, &rctx->conf->notify_url,
	    	     rctx->conf->interval/1000, is_picture, rctx->conf->screenshot_is_cover,
                 rctx->conf->screenshot_monitor,
	    	     &rctx->conf->region_pic,
	    	     &rctx->conf->host_pic);
    } else {
    	p = ngx_snprintf(buffer, sizeof(buffer),
                 "usr_id %V"NGX_RTMP_RECORD_CRLF
                 "is_public %V"NGX_RTMP_RECORD_CRLF
                 "bucket %V"NGX_RTMP_RECORD_CRLF
                 "notify_url %V"NGX_RTMP_RECORD_CRLF
                 "interval %ui"NGX_RTMP_RECORD_CRLF
                 "is_picture %ui"NGX_RTMP_RECORD_CRLF
                 "screenshot_is_cover %ui"NGX_RTMP_RECORD_CRLF
                 "screenshot_monitor %ui"NGX_RTMP_RECORD_CRLF
                 "region_pic %V"NGX_RTMP_RECORD_CRLF
                 "host_pic %V"NGX_RTMP_RECORD_CRLF
                 NGX_RTMP_RECORD_CRLF,
                 &rctx->conf->user_id, &rctx->conf->is_public,
	    	     &rctx->conf->bucket, &rctx->conf->notify_url, 
	    	     rctx->conf->interval/1000, is_picture, rctx->conf->screenshot_is_cover,
                 rctx->conf->screenshot_monitor,
	    	     &rctx->conf->region_pic,
	    	     &rctx->conf->host_pic);
    }

    n = ngx_write_fd(index_file.fd, buffer, p - buffer);
    if (n < 0) {

        ngx_log_error(NGX_LOG_ERR, s->connection->log, ngx_errno,
                  "init_indexfile: " ngx_write_fd_n " failed: '%V'",
                  &rctx->index_path);
        ngx_close_file(index_file.fd);
        return NGX_ERROR;
    }

    ngx_close_file(index_file.fd);

    return NGX_OK;
}

static ngx_int_t
ngx_rtmp_record_init_indexfile_remote(ngx_rtmp_session_t *s, ngx_rtmp_record_rec_ctx_t  *rctx)
{
    u_char                        path[NGX_MAX_PATH], *p;
    static u_char                 buffer[INDEX_BUFF_LEN];
    ngx_int_t                     n;
    ngx_file_t                    index_file;
    ngx_file_info_t               fi;

    ngx_memzero(path, NGX_MAX_PATH);
    p = ngx_snprintf(path, NGX_MAX_PATH, "%Vindex.txt", &rctx->index_path);

    if(!ngx_file_info(path, &fi)) {
        if(!ngx_is_file(&fi)) {
            ngx_log_error(NGX_LOG_ERR, s->connection->log, 0,
                          "pic: '%s' exists and is not a file", path);
            return  NGX_ERROR;
        } else {
            return NGX_OK;
        }
    }

    ngx_memzero(&index_file, sizeof(index_file));
    ngx_str_set(&index_file.name, "index.txt");
    index_file.log = s->connection->log;
    index_file.fd = ngx_open_file(path, NGX_FILE_WRONLY, NGX_FILE_TRUNCATE, NGX_FILE_DEFAULT_ACCESS);

    if (index_file.fd == NGX_INVALID_FILE) {
        ngx_log_error(NGX_LOG_ERR, s->connection->log, ngx_errno,
                      "init_indexfile: error creating index file");
        return NGX_ERROR;
    }

    p   = buffer;
    p = ngx_snprintf(p, INDEX_BUFF_LEN - (p - buffer) - 1,
            "usr_id %i"NGX_RTMP_RECORD_CRLF, s->conf.user_id);

    if (s->vdoid.len > 0) {
        p = ngx_snprintf(p, INDEX_BUFF_LEN - (p - buffer) - 1,
                "vdoid %V"NGX_RTMP_RECORD_CRLF, &s->vdoid);
    }

    p = ngx_snprintf(p, INDEX_BUFF_LEN - (p - buffer) - 1,
            "is_public %ui"NGX_RTMP_RECORD_CRLF
            "bucket %V"NGX_RTMP_RECORD_CRLF
            "notify_url %V"NGX_RTMP_RECORD_CRLF
            "interval %ui"NGX_RTMP_RECORD_CRLF
            "is_picture %ui"NGX_RTMP_RECORD_CRLF
            "screenshot_is_cover %ui"NGX_RTMP_RECORD_CRLF
            "region_pic %V"NGX_RTMP_RECORD_CRLF
            "host_pic %V"NGX_RTMP_RECORD_CRLF
            "screenshot_monitor %ui"NGX_RTMP_RECORD_CRLF
            NGX_RTMP_RECORD_CRLF,
            s->conf.screenshot_is_public,
            &s->conf.screenshot_bucket,
            &s->conf.screenshot_url,
            s->conf.screenshot_interval,
            rctx->type == NGX_RTMP_REC_CTX_TYPE_PIC,
            s->conf.screenshot_is_cover,
            &s->conf.region_pic,
            &s->conf.host_pic,
            s->conf.screenshot_monitor);

    n = ngx_write_fd(index_file.fd, buffer, p - buffer);
    if (n < 0) {

        ngx_log_error(NGX_LOG_ERR, s->connection->log, ngx_errno,
            "init_indexfile: " ngx_write_fd_n " failed: '%V'", &rctx->index_path);
        ngx_close_file(index_file.fd);
        return NGX_ERROR;
    }

    ngx_close_file(index_file.fd);

    return NGX_OK;
}

#undef NGX_RTMP_RECORD_CRLF
#undef INDEX_BUFF_LEN

static ngx_int_t
ngx_rtmp_record_write_over_file(ngx_rtmp_session_t *s, ngx_rtmp_record_ctx_t *ctx,
ngx_rtmp_record_rec_ctx_t *rctx)
{
    u_char          	path[NGX_MAX_PATH], *p;
    ngx_file_t          file;

    ngx_memzero(path, NGX_MAX_PATH);

    p = ngx_snprintf(path, NGX_MAX_PATH, "%Vend", &rctx->record_path);
    if(p == NULL) {
        return NGX_ERROR;
    }

    ngx_memzero(&file, sizeof(file));
    ngx_str_set(&file.name, "end");
    file.offset = 0;
    file.log = s->connection->log;
    file.fd = ngx_open_file(path, NGX_FILE_WRONLY,
                                 NGX_FILE_TRUNCATE, NGX_FILE_DEFAULT_ACCESS);

    if (file.fd == NGX_INVALID_FILE) {

    	return NGX_ERROR;
    }

    ngx_close_file(file.fd);

    return NGX_OK;
}

static void
ngx_rtmp_record_start(ngx_rtmp_session_t *s)
{
    ngx_rtmp_record_app_conf_t     *racf;
    ngx_rtmp_record_rec_ctx_t      *rctx;
    ngx_rtmp_record_ctx_t          *ctx;
    ngx_uint_t                      n;

    racf = ngx_rtmp_get_module_app_conf(s, ngx_rtmp_record_module);
    if (racf == NULL || racf->rec.nelts == 0) {
        return;
    }

    ctx = ngx_rtmp_get_module_ctx(s, ngx_rtmp_record_module);
    if (ctx == NULL) {
        return;
    }

    ngx_log_debug0(NGX_LOG_DEBUG_RTMP, s->connection->log, 0,
                   "record: start");

    rctx = ctx->rec.elts;
    for (n = 0; n < ctx->rec.nelts; ++n, ++rctx) {
        if (rctx->conf->flags & (NGX_RTMP_RECORD_OFF|NGX_RTMP_RECORD_MANUAL)) {
            continue;
        }

        ngx_rtmp_record_ensure_directory(s, rctx);
    }
}

static void
ngx_rtmp_record_start_remote(ngx_rtmp_session_t *s)
{
    ngx_rtmp_record_app_conf_t     *racf;
    ngx_rtmp_record_ctx_t          *ctx;
    ngx_rtmp_record_rec_ctx_t      *rctx;
    ngx_uint_t                      n;

    racf = ngx_rtmp_get_module_app_conf(s, ngx_rtmp_record_module);
    if (racf == NULL) {
        return;
    }

    ctx = ngx_rtmp_get_module_ctx(s, ngx_rtmp_record_module);
    if (ctx == NULL) {
        return;
    }

    ngx_log_debug0(NGX_LOG_DEBUG_RTMP, s->connection->log, 0,
                   "record: start");

    rctx = ctx->rec.elts;
    for (n = 0; n < ctx->rec.nelts; ++n,++rctx) {
        ngx_rtmp_record_ensure_directory(s, rctx);
    }
}


static void
ngx_rtmp_record_stop(ngx_rtmp_session_t *s)
{
    ngx_rtmp_record_app_conf_t     *racf;
    ngx_rtmp_record_rec_ctx_t      *rctx;
    ngx_rtmp_record_ctx_t          *ctx;
    ngx_uint_t                      n;

    racf = ngx_rtmp_get_module_app_conf(s, ngx_rtmp_record_module);
    if(racf == NULL) {
        return;
    }

    if (!ngx_rtmp_remote_conf()) {
        if (racf->rec.nelts == 0) {
            return;
        }
    }

    ctx = ngx_rtmp_get_module_ctx(s, ngx_rtmp_record_module);
    if (ctx == NULL) {
        return;
    }

    ngx_log_debug0(NGX_LOG_DEBUG_RTMP, s->connection->log, 0,
                   "record: stop");

    rctx = ctx->rec.elts;
    for (n = 0; n < ctx->rec.nelts; ++n, ++rctx) {
        ngx_rtmp_record_node_close(s, rctx);
    }
}


static ngx_int_t
ngx_rtmp_record_publish(ngx_rtmp_session_t *s, ngx_rtmp_publish_t *v)
{
    ngx_rtmp_record_app_conf_t     *racf;
    ngx_rtmp_record_ctx_t          *ctx;
    u_char                         *p;

    if (s->relay_type != NGX_NONE_RELAY) {
        goto next;
    }

    racf = ngx_rtmp_get_module_app_conf(s, ngx_rtmp_record_module);

    if (ngx_rtmp_remote_conf()) {

        if (racf == NULL) {
            goto next;
        }

        if (ngx_rtmp_record_init_remote(s) != NGX_OK) {
            return NGX_ERROR;
        }
    } else {

        if (racf == NULL || racf->rec.nelts == 0) {
            goto next;
        }

        if (ngx_rtmp_record_init(s) != NGX_OK) {
            return NGX_ERROR;
        }

        ngx_log_debug1(NGX_LOG_DEBUG_RTMP, s->connection->log, 0,
                       "record: publish %ui nodes",
                       racf->rec.nelts);
    }

    ctx = ngx_rtmp_get_module_ctx(s, ngx_rtmp_record_module);

    ngx_memcpy(ctx->name, v->name, sizeof(ctx->name));
    ngx_memcpy(ctx->args, v->args, sizeof(ctx->args));

    /* terminate name on /../ */
    for (p = ctx->name; *p; ++p) {
        if (ngx_path_separator(p[0]) &&
            p[1] == '.' && p[2] == '.' &&
            ngx_path_separator(p[3]))
        {
            *p = 0;
            break;
        }
    }

    if (ngx_rtmp_remote_conf()) {
        ngx_rtmp_record_start_remote(s);
    } else {
        ngx_rtmp_record_start(s);
    }

next:
    return next_publish(s, v);
}


static ngx_int_t
ngx_rtmp_record_stream_begin(ngx_rtmp_session_t *s, ngx_rtmp_stream_begin_t *v)
{
    if (s->relay_type != NGX_NONE_RELAY) {
        goto next;
    }

    ngx_log_debug0(NGX_LOG_DEBUG_RTMP, s->connection->log, 0,
                   "record: stream_begin");

    if (ngx_rtmp_remote_conf()) {  //remote conf

        ngx_rtmp_record_start_remote(s);

    } else {   //local conf
        ngx_rtmp_record_start(s);
    }

next:
    return next_stream_begin(s, v);
}


static ngx_int_t
ngx_rtmp_record_stream_eof(ngx_rtmp_session_t *s, ngx_rtmp_stream_begin_t *v)
{
    if (s->relay_type != NGX_NONE_RELAY) {
        goto next;
    }

    ngx_log_debug0(NGX_LOG_DEBUG_RTMP, s->connection->log, 0,
                   "record: stream_eof");

    ngx_rtmp_record_stop(s);

next:
    return next_stream_eof(s, v);
}


static ngx_int_t
ngx_rtmp_record_node_close(ngx_rtmp_session_t *s,
                           ngx_rtmp_record_rec_ctx_t *rctx)
{
    ngx_rtmp_record_app_conf_t  *rracf, *racf = NULL;
    ngx_err_t                   err;
    void                        **app_conf;
    ngx_int_t                   rc;
    ngx_rtmp_record_done_t      v;
    u_char                      av;
    char                        *p2;
    ngx_rtmp_record_ctx_t       *ctx;
    u_char                      node_path[NGX_MAX_PATH];

    racf = ngx_rtmp_get_module_app_conf(s, ngx_rtmp_record_module);
    if (racf == NULL) {
		
        return NGX_ERROR;
    }

    if (ngx_rtmp_remote_conf()) {
		
        rracf = racf;
    } else {
        rracf = rctx->conf;
    }
 
    ctx = ngx_rtmp_get_module_ctx(s, ngx_rtmp_record_module);
	
    if (rctx->file.fd == NGX_INVALID_FILE) {
        return NGX_AGAIN;
    }

    if (rctx->initialized) {
        av = 0;

        if (rctx->video) {
            av |= 0x01;
        }

        if (rctx->audio) {
            av |= 0x04;
        }

        if (ngx_write_file(&rctx->file, &av, 1, 4) == NGX_ERROR) {
            ngx_log_error(NGX_LOG_CRIT, s->connection->log, ngx_errno,
                          "record: %V error writing av mask", &rracf->id);
        }
    }

    if (ngx_close_file(rctx->file.fd) == NGX_FILE_ERROR) {
        err = ngx_errno;
        ngx_log_error(NGX_LOG_CRIT, s->connection->log, err,
                      "record: %V error closing file", &rracf->id);

        ngx_rtmp_record_notify_error(s, rctx);
    }

    rctx->file.fd = NGX_INVALID_FILE;

    ngx_log_debug1(NGX_LOG_DEBUG_RTMP, s->connection->log, 0,
                   "record: %V closed", &rracf->id);

    if (rracf->notify) {

        ngx_rtmp_send_status(s, "NetStream.Record.Stop", "status",
                             rracf->id.data ? (char *) rracf->id.data : "");
    }

    app_conf = s->app_conf;

    if (rracf->rec_conf) {
        s->app_conf = rracf->rec_conf;
    }

    v.recorder = rracf->id;
    ngx_memzero(node_path, NGX_MAX_PATH);
    ngx_rtmp_record_make_path(s, rctx, ctx, &v.path);
    p2 = ngx_strstr((char *)v.path.data, ".bak");
    ngx_memcpy(node_path, v.path.data, (size_t)(p2 - (char *)v.path.data));
    ngx_rename_file(v.path.data, node_path);

    if (!rctx->initialized || !rctx->avc_header_sent || !rctx->video_key_sent) {
        if (ngx_delete_file(node_path) == NGX_FILE_ERROR) {
            ngx_log_error(NGX_LOG_ERR, s->connection->log, ngx_errno,
                          "record: cleanup " ngx_delete_file_n " failed on '%V'",
                          &(v.path));
        }
    }

    rc = ngx_rtmp_record_done(s, &v);

    s->app_conf = app_conf;

    ngx_log_debug1(NGX_LOG_DEBUG_RTMP, s->connection->log, 0,
                  "record %s successed", node_path);

    return rc;
}


static ngx_int_t
ngx_rtmp_record_close_stream(ngx_rtmp_session_t *s,
                             ngx_rtmp_close_stream_t *v)
{
    ngx_rtmp_record_rec_ctx_t      *rctx;
    ngx_rtmp_record_ctx_t          *ctx;
    ngx_uint_t                      n;


    if (s->relay_type != NGX_NONE_RELAY) {
        goto next;
    }

    ctx = ngx_rtmp_get_module_ctx(s, ngx_rtmp_record_module);
    if (ctx == NULL) {
        return NGX_ERROR;
    }

    ngx_log_debug0(NGX_LOG_DEBUG_RTMP, s->connection->log, 0,
                   "record: close_stream");

    ngx_rtmp_record_stop(s);
	
    rctx = ctx->rec.elts;
    for (n = 0; n < ctx->rec.nelts; ++n, ++rctx) {
        ngx_rtmp_record_write_over_file(s, ctx, rctx);
    }
	
next:
    return next_close_stream(s, v);
}


static ngx_int_t
ngx_rtmp_record_write_frame(ngx_rtmp_session_t *s,
                            ngx_rtmp_record_rec_ctx_t *rctx,
                            ngx_rtmp_header_t *h, ngx_chain_t *in,
                            ngx_int_t inc_nframes)
{
    ngx_rtmp_record_app_conf_t *rracf, *racf;
    u_char                      hdr[11], *p, *ph;
    uint32_t                    timestamp, tag_size;
    size_t                      max_frames;

    racf = ngx_rtmp_get_module_app_conf(s, ngx_rtmp_record_module);
    if (racf == NULL) {
         return NGX_ERROR;
    }

    if(ngx_rtmp_remote_conf()) {
        rracf = racf;
    } else {
        rracf = rctx->conf;
    }

    ngx_log_debug2(NGX_LOG_DEBUG_RTMP, s->connection->log, 0,
                   "record: %V frame: mlen=%uD",
                   &rracf->id, h->mlen);

    if (h->type == NGX_RTMP_MSG_VIDEO) {
        rctx->video = 1;
    } else {
        rctx->audio = 1;
    }

    timestamp = h->timestamp - rctx->epoch;
    max_frames = 0;

    if ((int32_t) timestamp < 0) {
        ngx_log_debug2(NGX_LOG_DEBUG_RTMP, s->connection->log, 0,
                       "record: %V cut timestamp=%D", &rracf->id, timestamp);

        timestamp = 0;
    }

    /* write tag header */
    ph = hdr;

    *ph++ = (u_char)h->type;

    p = (u_char*)&h->mlen;
    *ph++ = p[2];
    *ph++ = p[1];
    *ph++ = p[0];

    p = (u_char*)&timestamp;
    *ph++ = p[2];
    *ph++ = p[1];
    *ph++ = p[0];
    *ph++ = p[3];

    *ph++ = 0;
    *ph++ = 0;
    *ph++ = 0;

    tag_size = (ph - hdr) + h->mlen;

    if (ngx_write_file(&rctx->file, hdr, ph - hdr, rctx->file.offset)
        == NGX_ERROR)
    {
        ngx_rtmp_record_notify_error(s, rctx);

        ngx_close_file(rctx->file.fd);

        return NGX_ERROR;
    }

    /* write tag body
     * FIXME: NGINX
     * ngx_write_chain seems to fit best
     * but it suffers from uncontrollable
     * allocations.
     * we're left with plain writing */
    for(; in; in = in->next) {
        if (in->buf->pos == in->buf->last) {
            continue;
        }

        if (ngx_write_file(&rctx->file, in->buf->pos, in->buf->last
                           - in->buf->pos, rctx->file.offset)
            == NGX_ERROR)
        {
            return NGX_ERROR;
        }
    }

    /* write tag size */
    ph = hdr;
    p = (u_char*)&tag_size;

    *ph++ = p[3];
    *ph++ = p[2];
    *ph++ = p[1];
    *ph++ = p[0];

    if (ngx_write_file(&rctx->file, hdr, ph - hdr,
                       rctx->file.offset)
        == NGX_ERROR)
    {
        return NGX_ERROR;
    }

    rctx->nframes += inc_nframes;

    /* watch max size */
    if (ngx_rtmp_remote_conf())  {

        if (rctx->type == NGX_RTMP_REC_CTX_TYPE_PIC) {

           max_frames = 1;
	    }

        if ((rracf->max_size && rctx->file.offset >= (ngx_int_t) rracf->max_size) ||
            (max_frames && rctx->nframes >= max_frames))
        {
            ngx_rtmp_record_node_close(s, rctx);
        }
    } else {
        if ((rracf->max_size && rctx->file.offset >= (ngx_int_t) rracf->max_size) ||
            (rracf->max_frames && rctx->nframes >= rracf->max_frames))
        {
            ngx_rtmp_record_node_close(s, rctx);
        }
    }

    return NGX_OK;
}


static size_t
ngx_rtmp_record_get_chain_mlen(ngx_chain_t *in)
{
    size_t                          ret;

    for (ret = 0; in; in = in->next) {
        ret += (in->buf->last - in->buf->pos);
    }

    return ret;
}


static ngx_int_t
ngx_rtmp_record_av(ngx_rtmp_session_t *s, ngx_rtmp_header_t *h,
                   ngx_chain_t *in)
{
    ngx_rtmp_record_ctx_t          *ctx;
    ngx_rtmp_record_rec_ctx_t      *rctx;
    ngx_uint_t                      n;

    ctx = ngx_rtmp_get_module_ctx(s, ngx_rtmp_record_module);

    if (ctx == NULL) {
        return NGX_OK;
    }

    rctx = ctx->rec.elts;

    for (n = 0; n < ctx->rec.nelts; ++n, ++rctx) {
        ngx_rtmp_record_node_av(s, rctx, h, in);
    }

    return NGX_OK;
}


static ngx_int_t
ngx_rtmp_record_node_av(ngx_rtmp_session_t *s, ngx_rtmp_record_rec_ctx_t *rctx,
                        ngx_rtmp_header_t *h, ngx_chain_t *in)
{
    ngx_time_t                         next;
    ngx_rtmp_header_t                  ch;
    ngx_rtmp_codec_ctx_t              *codec_ctx;
    ngx_int_t                          keyframe, brkframe;
    ngx_rtmp_record_app_conf_t        *rracf, *racf;
    ngx_rtmp_record_ctx_t             *ctx;

    racf = ngx_rtmp_get_module_app_conf(s, ngx_rtmp_record_module);
    if(racf == NULL) {
        return NGX_ERROR;
    }

    if(ngx_rtmp_remote_conf()) {

        rracf = racf;
        rracf->interval = rctx->interval;
        if (rctx->type == NGX_RTMP_REC_CTX_TYPE_PIC) {

            rracf->flags = NGX_RTMP_RECORD_VIDEO|NGX_RTMP_RECORD_KEYFRAMES;
            rracf->max_frames = 1;
        }
    } else {
        rracf = rctx->conf;
    }

    ctx = ngx_rtmp_get_module_ctx(s, ngx_rtmp_record_module);
    if (ctx == NULL) {

        return NGX_ERROR;
    }

    if (rracf->flags & NGX_RTMP_RECORD_OFF) {
        ngx_rtmp_record_node_close(s, rctx);
        return NGX_OK;
    }

    keyframe = (h->type == NGX_RTMP_MSG_VIDEO)
             ? (ngx_rtmp_get_video_frame_type(in) == NGX_RTMP_VIDEO_KEY_FRAME)
             : 0;

    brkframe = (h->type == NGX_RTMP_MSG_VIDEO)
             ? keyframe
             : (rracf->flags & NGX_RTMP_RECORD_VIDEO) == 0;

    if (brkframe && (rracf->flags & NGX_RTMP_RECORD_MANUAL) == 0) {

        if (rracf->interval != (ngx_msec_t) NGX_CONF_UNSET) {

            next = rctx->last;
            next.msec += rracf->interval;
            next.sec  += (next.msec / 1000);
            next.msec %= 1000;

            if (ngx_cached_time->sec  > next.sec ||
               (ngx_cached_time->sec == next.sec &&
                ngx_cached_time->msec > next.msec)||
                rctx->first_cutpic == 0)
            {
                rctx->first_cutpic = 1;
                ngx_rtmp_record_node_close(s, rctx);
                ngx_rtmp_record_node_open(s, rctx, ctx);

            }

        } else if (!rctx->failed) {
            ngx_rtmp_record_node_open(s, rctx, ctx);
        }
    }

    if ((rracf->flags & NGX_RTMP_RECORD_MANUAL) &&
        !brkframe && rctx->nframes == 0)
    {
        return NGX_OK;
    }

    if (rctx->file.fd == NGX_INVALID_FILE) {
        return NGX_OK;
    }

    if (h->type == NGX_RTMP_MSG_AUDIO &&
       (rracf->flags & NGX_RTMP_RECORD_AUDIO) == 0)
    {
        return NGX_OK;
    }

    if (h->type == NGX_RTMP_MSG_VIDEO &&
       (rracf->flags & NGX_RTMP_RECORD_VIDEO) == 0 &&
       ((rracf->flags & NGX_RTMP_RECORD_KEYFRAMES) == 0 || !keyframe))
    {
        return NGX_OK;
    }

    if (!rctx->initialized) {

        rctx->initialized = 1;
        rctx->epoch = h->timestamp - rctx->time_shift;

        if (rctx->file.offset == 0 &&
            ngx_rtmp_record_write_header(&rctx->file) != NGX_OK)
        {
            ngx_rtmp_record_node_close(s, rctx);
            return NGX_OK;
        }
    }

    codec_ctx = ngx_rtmp_get_module_ctx(s, ngx_rtmp_codec_module);
    if (codec_ctx) {
        ch = *h;

        /* AAC header */
        if (!rctx->aac_header_sent && codec_ctx->aac_header &&
           (rracf->flags & NGX_RTMP_RECORD_AUDIO))
        {
            ngx_log_debug1(NGX_LOG_DEBUG_RTMP, s->connection->log, 0,
                           "record: %V writing AAC header", &rracf->id);

            ch.type = NGX_RTMP_MSG_AUDIO;
            ch.mlen = ngx_rtmp_record_get_chain_mlen(codec_ctx->aac_header);

            if (ngx_rtmp_record_write_frame(s, rctx, &ch,
                                            codec_ctx->aac_header, 0)
                != NGX_OK)
            {
                return NGX_OK;
            }

            rctx->aac_header_sent = 1;
        }

        /* AVC header */
        if (!rctx->avc_header_sent && codec_ctx->video_header &&
           (rracf->flags & (NGX_RTMP_RECORD_VIDEO|
                            NGX_RTMP_RECORD_KEYFRAMES)))
        {
            ngx_log_debug1(NGX_LOG_DEBUG_RTMP, s->connection->log, 0,
                           "record: %V writing AVC header", &rracf->id);

            ch.type = NGX_RTMP_MSG_VIDEO;
            ch.mlen = ngx_rtmp_record_get_chain_mlen(codec_ctx->video_header);

            if (ngx_rtmp_record_write_frame(s, rctx, &ch,
                                            codec_ctx->video_header, 0)
                != NGX_OK)
            {
                return NGX_OK;
            }

            rctx->avc_header_sent = 1;
        }
    }

    if (h->type == NGX_RTMP_MSG_VIDEO) {
        if (codec_ctx && (codec_ctx->video_codec_id == NGX_RTMP_VIDEO_H264 || 
             codec_ctx->video_codec_id == NGX_RTMP_VIDEO_H265) &&
            !rctx->avc_header_sent)
        {
            ngx_log_debug1(NGX_LOG_DEBUG_RTMP, s->connection->log, 0,
                           "record: %V skipping until H264 header", &rracf->id);
            return NGX_OK;
        }

        if (ngx_rtmp_get_video_frame_type(in) == NGX_RTMP_VIDEO_KEY_FRAME &&
            ((codec_ctx && codec_ctx->video_codec_id != NGX_RTMP_VIDEO_H264 
              && codec_ctx->video_codec_id != NGX_RTMP_VIDEO_H265) ||
             !ngx_rtmp_is_codec_header(in)))
        {
            rctx->video_key_sent = 1;
        }

        if (!rctx->video_key_sent) {
            ngx_log_debug1(NGX_LOG_DEBUG_RTMP, s->connection->log, 0,
                           "record: %V skipping until keyframe", &rracf->id);
            return NGX_OK;
        }

    } else {
        if (codec_ctx && codec_ctx->audio_codec_id == NGX_RTMP_AUDIO_AAC &&
            !rctx->aac_header_sent)
        {
            ngx_log_debug1(NGX_LOG_DEBUG_RTMP, s->connection->log, 0,
                           "record: %V skipping until AAC header", &rracf->id);
            return NGX_OK;
        }
    }

    return ngx_rtmp_record_write_frame(s, rctx, h, in, 1);
}


static ngx_int_t
ngx_rtmp_record_done_init(ngx_rtmp_session_t *s, ngx_rtmp_record_done_t *v)
{
    return NGX_OK;
}


static char *
ngx_rtmp_record_recorder(ngx_conf_t *cf, ngx_command_t *cmd, void *conf)
{
    char                       *rv;
    ngx_int_t                   i;
    ngx_str_t                  *value;
    ngx_conf_t                  save;
    ngx_rtmp_module_t          *module;
    ngx_rtmp_core_app_conf_t   *cacf, **pcacf, *rcacf;
    ngx_rtmp_record_app_conf_t *racf, **pracf, *rracf;
    ngx_rtmp_conf_ctx_t        *ctx, *pctx;

    value = cf->args->elts;

    cacf = ngx_rtmp_conf_get_module_app_conf(cf, ngx_rtmp_core_module);

    racf = ngx_rtmp_conf_get_module_app_conf(cf, ngx_rtmp_record_module);

    ctx = ngx_pcalloc(cf->pool, sizeof(ngx_rtmp_conf_ctx_t));
    if (ctx == NULL) {
        return NGX_CONF_ERROR;
    }

    pctx = cf->ctx;

    ctx->main_conf = pctx->main_conf;
    ctx->srv_conf  = pctx->srv_conf;

    ctx->app_conf = ngx_pcalloc(cf->pool, sizeof(void *) * ngx_rtmp_max_module);
    if (ctx->app_conf == NULL) {
        return NGX_CONF_ERROR;
    }

    for (i = 0; ngx_modules[i]; i++) {
        if (ngx_modules[i]->type != NGX_RTMP_MODULE) {
            continue;
        }

        module = ngx_modules[i]->ctx;

        if (module->create_app_conf) {
            ctx->app_conf[ngx_modules[i]->ctx_index] =
                                module->create_app_conf(cf);
            if (ctx->app_conf[ngx_modules[i]->ctx_index] == NULL) {
                return NGX_CONF_ERROR;
            }
        }
    }

    /* add to sub-applications */
    rcacf = ctx->app_conf[ngx_rtmp_core_module.ctx_index];
    rcacf->app_conf = ctx->app_conf;
    pcacf = ngx_array_push(&cacf->applications);
    if (pcacf == NULL) {
        return NGX_CONF_ERROR;
    }
    *pcacf = rcacf;

    /* add to recorders */
    rracf = ctx->app_conf[ngx_rtmp_record_module.ctx_index];
    rracf->rec_conf = ctx->app_conf;
    pracf = ngx_array_push(&racf->rec);
    if (pracf == NULL) {
        return NGX_CONF_ERROR;
    }
    *pracf = rracf;

    rracf->id = value[1];

    save = *cf;
    cf->ctx = ctx;
    cf->cmd_type = NGX_RTMP_REC_CONF;

    rv = ngx_conf_parse(cf, NULL);
    *cf= save;

    return rv;
}


static ngx_int_t
ngx_rtmp_record_postconfiguration(ngx_conf_t *cf)
{
    ngx_rtmp_core_main_conf_t          *cmcf;
    ngx_rtmp_handler_pt                *h;

    ngx_rtmp_record_done = ngx_rtmp_record_done_init;

    cmcf = ngx_rtmp_conf_get_module_main_conf(cf, ngx_rtmp_core_module);

    h = ngx_array_push(&cmcf->events[NGX_RTMP_MSG_AUDIO]);
    *h = ngx_rtmp_record_av;

    h = ngx_array_push(&cmcf->events[NGX_RTMP_MSG_VIDEO]);
    *h = ngx_rtmp_record_av;

    next_publish = ngx_rtmp_publish;
    ngx_rtmp_publish = ngx_rtmp_record_publish;

    next_close_stream = ngx_rtmp_close_stream;
    ngx_rtmp_close_stream = ngx_rtmp_record_close_stream;

    next_stream_begin = ngx_rtmp_stream_begin;
    ngx_rtmp_stream_begin = ngx_rtmp_record_stream_begin;

    next_stream_eof = ngx_rtmp_stream_eof;
    ngx_rtmp_stream_eof = ngx_rtmp_record_stream_eof;

    return NGX_OK;
}
