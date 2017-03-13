#include <ngx_rtmp_cmd_module.h>
#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_rtmp.h>

#include "ngx_rtmp_hls_vod_module.h"
#include "ngx_rtmp_hls_module.h"
#include "ngx_rtmp_mpegts.h"

static ngx_rtmp_publish_pt              next_publish;
static ngx_rtmp_close_stream_pt         next_close_stream;
static ngx_rtmp_stream_begin_pt         next_stream_begin;
static ngx_rtmp_stream_eof_pt           next_stream_eof;

static ngx_int_t ngx_rtmp_hls_vod_postconfiguration(ngx_conf_t *cf);
static void * ngx_rtmp_hls_vod_create_app_conf(ngx_conf_t *cf);
static char * ngx_rtmp_hls_vod_merge_app_conf(ngx_conf_t *cf,
                                              void *parent, void *child);
static ngx_int_t ngx_rtmp_hls_vod_create_dir(ngx_rtmp_session_t *s, ngx_str_t *path);
static ngx_int_t ngx_rtmp_hls_vod_init_index_file(ngx_rtmp_session_t *s, ngx_str_t *dir);
static ngx_int_t ngx_rtmp_hls_vod_flush_audio(ngx_rtmp_session_t *s);

#define NGX_RTMP_HLS_VOD_NAMING_SEQUENTIAL         1
#define NGX_RTMP_HLS_VOD_NAMING_TIMESTAMP          2
#define NGX_RTMP_HLS_VOD_NAMING_SYSTEM             3
#define NGX_RTMP_HLS_VOD_NAMING_TIMESTAMP_SEQ      4

#define NGX_RTMP_HLS_VOD_SLICING_PLAIN             1
#define NGX_RTMP_HLS_VOD_SLICING_ALIGNED           2

#define NGX_RTMP_HLS_VOD_TYPE_LIVE                 1
#define NGX_RTMP_HLS_VOD_TYPE_EVENT                2

static ngx_conf_enum_t                  ngx_rtmp_hls_vod_naming_slots[] = {
    { ngx_string("sequential"),         NGX_RTMP_HLS_VOD_NAMING_SEQUENTIAL    },
    { ngx_string("timestamp"),          NGX_RTMP_HLS_VOD_NAMING_TIMESTAMP     },
    { ngx_string("system"),             NGX_RTMP_HLS_VOD_NAMING_SYSTEM        },
    { ngx_string("timestamp_seq"),      NGX_RTMP_HLS_VOD_NAMING_TIMESTAMP_SEQ },
    { ngx_null_string,                  0 }
};

static ngx_conf_enum_t                  ngx_rtmp_hls_vod_slicing_slots[] = {
    { ngx_string("plain"),              NGX_RTMP_HLS_VOD_SLICING_PLAIN },
    { ngx_string("aligned"),            NGX_RTMP_HLS_VOD_SLICING_ALIGNED },
    { ngx_null_string,                  0 }
};

static ngx_conf_enum_t                  ngx_rtmp_hls_vod_type_slots[] = {
    { ngx_string("live"),               NGX_RTMP_HLS_VOD_TYPE_LIVE  },
    { ngx_string("event"),              NGX_RTMP_HLS_VOD_TYPE_EVENT },
    { ngx_null_string,                  0 }
};

static ngx_command_t ngx_rtmp_hls_vod_commands[] = {
    { ngx_string("hls_vod"),
        NGX_RTMP_MAIN_CONF|NGX_RTMP_SRV_CONF|NGX_RTMP_APP_CONF|NGX_CONF_TAKE1,
        ngx_conf_set_flag_slot,
        NGX_RTMP_APP_CONF_OFFSET,
        offsetof(ngx_rtmp_hls_vod_app_conf_t, hls_vod),
        NULL },

    { ngx_string("hls_vod_fragment"),
        NGX_RTMP_MAIN_CONF|NGX_RTMP_SRV_CONF|NGX_RTMP_APP_CONF|NGX_CONF_TAKE1,
        ngx_conf_set_msec_slot,
        NGX_RTMP_APP_CONF_OFFSET,
        offsetof(ngx_rtmp_hls_vod_app_conf_t, hls_vod_fragment),
        NULL },

    { ngx_string("hls_vod_ts_zero"),
        NGX_RTMP_MAIN_CONF|NGX_RTMP_SRV_CONF|NGX_RTMP_APP_CONF|NGX_CONF_TAKE1,
        ngx_conf_set_flag_slot,
        NGX_RTMP_APP_CONF_OFFSET,
        offsetof(ngx_rtmp_hls_vod_app_conf_t, hls_vod_ts_zero),
        NULL },

    { ngx_string("hls_max_fragment"),
        NGX_RTMP_MAIN_CONF|NGX_RTMP_SRV_CONF|NGX_RTMP_APP_CONF|NGX_CONF_TAKE1,
        ngx_conf_set_msec_slot,
        NGX_RTMP_APP_CONF_OFFSET,
        offsetof(ngx_rtmp_hls_vod_app_conf_t, max_fraglen),
        NULL },

    { ngx_string("hls_sync"),
        NGX_RTMP_MAIN_CONF|NGX_RTMP_SRV_CONF|NGX_RTMP_APP_CONF|NGX_CONF_TAKE1,
        ngx_conf_set_msec_slot,
        NGX_RTMP_APP_CONF_OFFSET,
        offsetof(ngx_rtmp_hls_vod_app_conf_t, sync),
        NULL },

    { ngx_string("hls_vod_path"),
        NGX_RTMP_MAIN_CONF|NGX_RTMP_SRV_CONF|NGX_RTMP_APP_CONF|NGX_CONF_TAKE1,
        ngx_conf_set_str_slot,
        NGX_RTMP_APP_CONF_OFFSET,
        offsetof(ngx_rtmp_hls_vod_app_conf_t, path),
        NULL },

    { ngx_string("hls_vod_fragment_naming"),
        NGX_RTMP_MAIN_CONF|NGX_RTMP_SRV_CONF|NGX_RTMP_APP_CONF|NGX_CONF_TAKE1,
        ngx_conf_set_enum_slot,
        NGX_RTMP_APP_CONF_OFFSET,
        offsetof(ngx_rtmp_hls_vod_app_conf_t, naming),
        &ngx_rtmp_hls_vod_naming_slots },

    { ngx_string("hls_vod_fragment_slicing"),
        NGX_RTMP_MAIN_CONF|NGX_RTMP_SRV_CONF|NGX_RTMP_APP_CONF|NGX_CONF_TAKE1,
        ngx_conf_set_enum_slot,
        NGX_RTMP_APP_CONF_OFFSET,
        offsetof(ngx_rtmp_hls_vod_app_conf_t, slicing),
        &ngx_rtmp_hls_vod_slicing_slots },

    { ngx_string("hls_type"),
        NGX_RTMP_MAIN_CONF|NGX_RTMP_SRV_CONF|NGX_RTMP_APP_CONF|NGX_CONF_TAKE1,
        ngx_conf_set_enum_slot,
        NGX_RTMP_APP_CONF_OFFSET,
        offsetof(ngx_rtmp_hls_vod_app_conf_t, type),
        &ngx_rtmp_hls_vod_type_slots },

    { ngx_string("hls_max_audio_delay"),
        NGX_RTMP_MAIN_CONF|NGX_RTMP_SRV_CONF|NGX_RTMP_APP_CONF|NGX_CONF_TAKE1,
        ngx_conf_set_msec_slot,
        NGX_RTMP_APP_CONF_OFFSET,
        offsetof(ngx_rtmp_hls_vod_app_conf_t, max_audio_delay),
        NULL },

    { ngx_string("hls_audio_buffer_size"),
        NGX_RTMP_MAIN_CONF|NGX_RTMP_SRV_CONF|NGX_RTMP_APP_CONF|NGX_CONF_TAKE1,
        ngx_conf_set_size_slot,
        NGX_RTMP_APP_CONF_OFFSET,
        offsetof(ngx_rtmp_hls_vod_app_conf_t, audio_buffer_size),
        NULL },

    { ngx_string("hls_vod_usr_id"),
        NGX_RTMP_MAIN_CONF|NGX_RTMP_SRV_CONF|NGX_RTMP_APP_CONF|
            NGX_RTMP_REC_CONF|NGX_CONF_TAKE1,
        ngx_conf_set_num_slot,
        NGX_RTMP_APP_CONF_OFFSET,
        offsetof(ngx_rtmp_hls_vod_app_conf_t, user_id),
        NULL },

    { ngx_string("hls_vod_is_public"),
        NGX_RTMP_MAIN_CONF|NGX_RTMP_SRV_CONF|NGX_RTMP_APP_CONF|
            NGX_RTMP_REC_CONF|NGX_CONF_TAKE1,
        ngx_conf_set_num_slot,
        NGX_RTMP_APP_CONF_OFFSET,
        offsetof(ngx_rtmp_hls_vod_app_conf_t, hls_vod_is_public),
        NULL },

    { ngx_string("hls_vod_bucket"),
        NGX_RTMP_MAIN_CONF|NGX_RTMP_SRV_CONF|NGX_RTMP_APP_CONF|
            NGX_RTMP_REC_CONF|NGX_CONF_TAKE1,
        ngx_conf_set_str_slot,
        NGX_RTMP_APP_CONF_OFFSET,
        offsetof(ngx_rtmp_hls_vod_app_conf_t, hls_vod_bucket),
        NULL },

    { ngx_string("hls_vod_url"),
        NGX_RTMP_MAIN_CONF|NGX_RTMP_SRV_CONF|NGX_RTMP_APP_CONF|
            NGX_RTMP_REC_CONF|NGX_CONF_TAKE1,
        ngx_conf_set_str_slot,
        NGX_RTMP_APP_CONF_OFFSET,
        offsetof(ngx_rtmp_hls_vod_app_conf_t, hls_vod_url),
        NULL },

    { ngx_string("mp4_vod_name_format"),
        NGX_RTMP_MAIN_CONF|NGX_RTMP_SRV_CONF|NGX_RTMP_APP_CONF|
            NGX_RTMP_REC_CONF|NGX_CONF_TAKE1,
        ngx_conf_set_num_slot,
        NGX_RTMP_APP_CONF_OFFSET,
        offsetof(ngx_rtmp_hls_vod_app_conf_t, mp4_vod_name_format),
        NULL },

    { ngx_string("mp4_vod"),
        NGX_RTMP_MAIN_CONF|NGX_RTMP_SRV_CONF|NGX_RTMP_APP_CONF|
            NGX_RTMP_REC_CONF|NGX_CONF_TAKE1,
        ngx_conf_set_flag_slot,
        NGX_RTMP_APP_CONF_OFFSET,
        offsetof(ngx_rtmp_hls_vod_app_conf_t, mp4_vod),
        NULL },

    { ngx_string("mp4_vod_is_public"),
        NGX_RTMP_MAIN_CONF|NGX_RTMP_SRV_CONF|NGX_RTMP_APP_CONF|
            NGX_RTMP_REC_CONF|NGX_CONF_TAKE1,
        ngx_conf_set_num_slot,
        NGX_RTMP_APP_CONF_OFFSET,
        offsetof(ngx_rtmp_hls_vod_app_conf_t, mp4_vod_is_public),
        NULL },

    { ngx_string("mp4_vod_bucket"),
        NGX_RTMP_MAIN_CONF|NGX_RTMP_SRV_CONF|NGX_RTMP_APP_CONF|
            NGX_RTMP_REC_CONF|NGX_CONF_TAKE1,
        ngx_conf_set_str_slot,
        NGX_RTMP_APP_CONF_OFFSET,
        offsetof(ngx_rtmp_hls_vod_app_conf_t, mp4_vod_bucket),
        NULL },

    { ngx_string("mp4_vod_url"),
        NGX_RTMP_MAIN_CONF|NGX_RTMP_SRV_CONF|NGX_RTMP_APP_CONF|
            NGX_RTMP_REC_CONF|NGX_CONF_TAKE1,
        ngx_conf_set_str_slot,
        NGX_RTMP_APP_CONF_OFFSET,
        offsetof(ngx_rtmp_hls_vod_app_conf_t, mp4_vod_url),
        NULL },

    { ngx_string("region_mp4"),
        NGX_RTMP_MAIN_CONF|NGX_RTMP_SRV_CONF|NGX_RTMP_APP_CONF|
            NGX_RTMP_REC_CONF|NGX_CONF_TAKE1,
        ngx_conf_set_str_slot,
        NGX_RTMP_APP_CONF_OFFSET,
        offsetof(ngx_rtmp_hls_vod_app_conf_t, region_mp4),
        NULL },

    { ngx_string("region_hls"),
        NGX_RTMP_MAIN_CONF|NGX_RTMP_SRV_CONF|NGX_RTMP_APP_CONF|
            NGX_RTMP_REC_CONF|NGX_CONF_TAKE1,
        ngx_conf_set_str_slot,
        NGX_RTMP_APP_CONF_OFFSET,
        offsetof(ngx_rtmp_hls_vod_app_conf_t, region_hls),
        NULL },

    { ngx_string("host_mp4"),
        NGX_RTMP_MAIN_CONF|NGX_RTMP_SRV_CONF|NGX_RTMP_APP_CONF|
            NGX_RTMP_REC_CONF|NGX_CONF_TAKE1,
        ngx_conf_set_str_slot,
        NGX_RTMP_APP_CONF_OFFSET,
        offsetof(ngx_rtmp_hls_vod_app_conf_t, host_mp4),
        NULL },

    { ngx_string("host_hls"),
        NGX_RTMP_MAIN_CONF|NGX_RTMP_SRV_CONF|NGX_RTMP_APP_CONF|
            NGX_RTMP_REC_CONF|NGX_CONF_TAKE1,
        ngx_conf_set_str_slot,
        NGX_RTMP_APP_CONF_OFFSET,
        offsetof(ngx_rtmp_hls_vod_app_conf_t, host_hls),
        NULL },

    { ngx_string("hls_vod_auto_merge"),
        NGX_RTMP_MAIN_CONF|NGX_RTMP_SRV_CONF|NGX_RTMP_APP_CONF|
            NGX_RTMP_REC_CONF|NGX_CONF_TAKE1,
        ngx_conf_set_flag_slot,
        NGX_RTMP_APP_CONF_OFFSET,
        offsetof(ngx_rtmp_hls_vod_app_conf_t, hls_vod_auto_merge),
        NULL },

    { ngx_string("live_delay"),
        NGX_RTMP_MAIN_CONF|NGX_RTMP_SRV_CONF|NGX_RTMP_APP_CONF|NGX_CONF_TAKE1,
        ngx_conf_set_flag_slot,
        NGX_RTMP_APP_CONF_OFFSET,
        offsetof(ngx_rtmp_hls_vod_app_conf_t, live_delay),
        NULL },

    { ngx_string("live_delay_time"),
        NGX_RTMP_MAIN_CONF|NGX_RTMP_SRV_CONF|NGX_RTMP_APP_CONF|NGX_CONF_TAKE1,
        ngx_conf_set_msec_slot,
        NGX_RTMP_APP_CONF_OFFSET,
        offsetof(ngx_rtmp_hls_vod_app_conf_t, live_delay_time),
        NULL },

    { ngx_string("live_delay_host"),
        NGX_RTMP_MAIN_CONF|NGX_RTMP_SRV_CONF|NGX_RTMP_APP_CONF|
            NGX_RTMP_REC_CONF|NGX_CONF_TAKE1,
        ngx_conf_set_str_slot,
        NGX_RTMP_APP_CONF_OFFSET,
        offsetof(ngx_rtmp_hls_vod_app_conf_t, live_delay_host),
        NULL },

    { ngx_string("live_delay_app"),
        NGX_RTMP_MAIN_CONF|NGX_RTMP_SRV_CONF|NGX_RTMP_APP_CONF|
            NGX_RTMP_REC_CONF|NGX_CONF_TAKE1,
        ngx_conf_set_str_slot,
        NGX_RTMP_APP_CONF_OFFSET,
        offsetof(ngx_rtmp_hls_vod_app_conf_t, live_delay_app),
        NULL },

    ngx_null_command
};

static ngx_rtmp_module_t  ngx_rtmp_hls_vod_module_ctx = {
    NULL,                               /* preconfiguration */
    ngx_rtmp_hls_vod_postconfiguration, /* postconfiguration */

    NULL,                               /* create main configuration */
    NULL,                               /* init main configuration */

    NULL,                               /* create server configuration */
    NULL,                               /* merge server configuration */

    ngx_rtmp_hls_vod_create_app_conf,   /* create application configuration */
    ngx_rtmp_hls_vod_merge_app_conf,    /* merge application configuration */
};


ngx_module_t  ngx_rtmp_hls_vod_module = {
    NGX_MODULE_V1,
    &ngx_rtmp_hls_vod_module_ctx,       /* module context */
    ngx_rtmp_hls_vod_commands,          /* module directives */
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

static ngx_rtmp_hls_vod_frag_t *
ngx_rtmp_hls_vod_get_frag(ngx_rtmp_session_t *s, ngx_int_t n)
{
    ngx_rtmp_hls_vod_ctx_t         *ctx;

    ctx = ngx_rtmp_get_module_ctx(s, ngx_rtmp_hls_vod_module);

    return &ctx->frags[(ctx->frag + n) % (ctx->winfrags * 2 + 1)];
}


static void
ngx_rtmp_hls_vod_next_frag(ngx_rtmp_session_t *s)
{
    ngx_rtmp_hls_vod_ctx_t         *ctx;

    ctx = ngx_rtmp_get_module_ctx(s, ngx_rtmp_hls_vod_module);

    if (ctx->nfrags == ctx->winfrags) {
        ctx->frag++;
    } else {
        ctx->nfrags++;
    }
}


static ngx_int_t
ngx_rtmp_hls_write_vod_m3u8bak(ngx_rtmp_session_t *s, uint64_t ts)
{
    static u_char                   buffer[1024];
    ngx_rtmp_hls_vod_ctx_t          *ctx;
    ngx_rtmp_hls_vod_app_conf_t     *hacf;
    ngx_rtmp_hls_vod_frag_t         *f;
    ngx_uint_t                      max_frag;
    ngx_file_info_t                 fi;
    ssize_t                         size, rc;
    ngx_file_t                      m3u8_bak_file;

    hacf = ngx_rtmp_get_module_app_conf(s, ngx_rtmp_hls_vod_module);
    if (hacf == NULL) {

        return NGX_ERROR;
    }

    ctx = ngx_rtmp_get_module_ctx(s, ngx_rtmp_hls_vod_module);
    if (ctx == NULL) {

        return NGX_ERROR;
    }

    ngx_memzero(&m3u8_bak_file, sizeof(m3u8_bak_file));
    ngx_str_set(&m3u8_bak_file.name, "m3u8.bak");
    m3u8_bak_file.offset = 0;
    m3u8_bak_file.log = s->connection->log;

    ngx_memzero(buffer, 1024);

    max_frag = ngx_rtmp_get_attr_conf(hacf, hls_vod_fragment) / 1000;
    if (ctx->nfrags > 0) {

        f = ngx_rtmp_hls_vod_get_frag(s, ctx->nfrags - 1);
        if (f->duration > max_frag) {

            max_frag = (ngx_uint_t)(f->duration + .5);
        }
    }
    ctx->vod_max_frag = ngx_max(ctx->vod_max_frag, max_frag);

    if (!ctx->m3u8_header) {

        /*write m3u8 header*/
        m3u8_bak_file.fd = ngx_open_file(ctx->vod_m3u8_bak.data, NGX_FILE_WRONLY, NGX_FILE_TRUNCATE,
                                            NGX_FILE_DEFAULT_ACCESS);
        if (m3u8_bak_file.fd == NGX_INVALID_FILE) {

            ngx_log_error(NGX_LOG_ERR, s->connection->log, 0,
                          "hls vod write m3u8.bak first '%V' failed",
                          &ctx->vod_m3u8_bak);
            return NGX_ERROR;
        }

        if (ngx_link_info((char *)ctx->vod_m3u8_bak.data, &fi) == NGX_FILE_ERROR) {

            ngx_close_file(m3u8_bak_file.fd);
            return NGX_ERROR;
        }
        size = ngx_file_size(&fi);
        m3u8_bak_file.offset = size;

        /*write m3u8 EXTINF*/
        if (ctx->nfrags > 0) {

            f = ngx_rtmp_hls_vod_get_frag(s, ctx->nfrags - 1);
            if (s->vdoid.len > 0) {

                *ngx_snprintf(buffer, sizeof(buffer),
                              "#EXTINF:%.3f,\n"
                              "%V-%uL.ts\n",
                              f->duration, &s->vdoid, f->id) = 0;

                rc = ngx_write_file(&m3u8_bak_file, buffer, ngx_strlen(buffer), m3u8_bak_file.offset);
                if (rc == NGX_ERROR) {

                    ngx_log_error(NGX_LOG_ERR, s->connection->log, 0,
                                  "hls vod  write the m3u8_bak_file file: '%V' failed", 
                                  &ctx->vod_m3u8_bak);
                    ngx_close_file(m3u8_bak_file.fd);
                    return NGX_ERROR;
                }

            } else {
                *ngx_snprintf(buffer, sizeof(buffer),
                              "#EXTINF:%.3f,\n"
                              "%uL.ts\n",
                              f->duration, f->id) = 0;
                rc = ngx_write_file(&m3u8_bak_file, buffer, ngx_strlen(buffer), m3u8_bak_file.offset); 
                if (rc == NGX_ERROR) {

                    ngx_log_error(NGX_LOG_ERR, s->connection->log, 0,
                                  "hls vod first vdoid write the m3u8_bak_file file: '%V' failed", 
                                  &ctx->vod_m3u8_bak);
                    ngx_close_file(m3u8_bak_file.fd);
                    return NGX_ERROR;
                }
            }
        }
        ctx->m3u8_header = 1;
    } else {

        /*write m3u8 EXTINF*/
        m3u8_bak_file.fd = ngx_open_file(ctx->vod_m3u8_bak.data, NGX_FILE_WRONLY,  NGX_FILE_APPEND,
                                            NGX_FILE_DEFAULT_ACCESS);
        if (m3u8_bak_file.fd == NGX_INVALID_FILE) {

            ngx_log_error(NGX_LOG_ERR, s->connection->log, 0,
                          "hls vod write the m3u8_bak_file '%V' failed", &ctx->vod_m3u8_bak);

            m3u8_bak_file.fd = ngx_open_file(ctx->vod_m3u8_bak.data, NGX_FILE_WRONLY, NGX_FILE_TRUNCATE,
        					NGX_FILE_DEFAULT_ACCESS);
            if (m3u8_bak_file.fd == NGX_INVALID_FILE) {

                ngx_log_error(NGX_LOG_ERR, s->connection->log, 0,
		              "hls vod again open the m3u8_bak_file '%V' failed", &ctx->vod_m3u8_bak);
        	    return NGX_ERROR;
            }
        }

        if (ngx_link_info((char *)ctx->vod_m3u8_bak.data, &fi) == NGX_FILE_ERROR) {

            ngx_close_file(m3u8_bak_file.fd);
            return NGX_ERROR;
        }

        size = ngx_file_size(&fi);
        m3u8_bak_file.offset = size;
        if (ctx->nfrags > 0) {

            if (s->vdoid.len > 0) {

                f = ngx_rtmp_hls_vod_get_frag(s, ctx->nfrags - 1);
                *ngx_snprintf(buffer, sizeof(buffer),
                              "%s"
                              "#EXTINF:%.3f,\n"
                              "%V-%uL.ts\n",
                              f->discont ? "#EXT-X-DISCONTINUITY\n" : "",
                              f->duration, &s->vdoid, f->id) = 0;

                rc = ngx_write_file(&m3u8_bak_file, buffer, ngx_strlen(buffer), m3u8_bak_file.offset);
                if (rc == NGX_ERROR) {

                    ngx_log_error(NGX_LOG_ERR, s->connection->log, 0,
                                  "vdoid write the m3u8_bak_file file: '%V' failed", 
                                  &ctx->vod_m3u8_bak);
                    ngx_close_file(m3u8_bak_file.fd);
                    return NGX_ERROR;
                }
            } else {

                f = ngx_rtmp_hls_vod_get_frag(s, ctx->nfrags - 1);
                *ngx_snprintf(buffer, sizeof(buffer),
                              "%s"
                              "#EXTINF:%.3f,\n"
                              "%uL.ts\n",
                              f->discont ? "#EXT-X-DISCONTINUITY\n" : "",
                              f->duration, f->id) = 0;
                rc = ngx_write_file(&m3u8_bak_file, buffer, ngx_strlen(buffer), m3u8_bak_file.offset);
                if (rc == NGX_ERROR) {

                    ngx_log_error(NGX_LOG_ERR, s->connection->log, 0,
                                  "ngx_rtmp_hls_write_vod_m3u8bak write the m3u8_bak_file file: '%V' failed",
                                  &ctx->vod_m3u8_bak);
                    ngx_close_file(m3u8_bak_file.fd);
                    return NGX_ERROR;
                }
            }
        }
    }

    ngx_close_file(m3u8_bak_file.fd);
    return NGX_OK;
}


#define TMP_BUFF_LEN 1024

static ngx_int_t
ngx_rtmp_hls_vod_write_end(ngx_rtmp_session_t *s)
{
    ngx_rtmp_hls_vod_ctx_t   *ctx;
    u_char                   buff[TMP_BUFF_LEN], *p;
    ngx_file_t               file;

    ctx = ngx_rtmp_get_module_ctx(s, ngx_rtmp_hls_vod_module);
    if (ctx == NULL) {
        return NGX_ERROR;
    }

    ngx_memzero(buff, TMP_BUFF_LEN);
    p = ngx_cpymem(buff, ctx->vod_path.data, ctx->vod_path.len);

    *ngx_cpymem(p, "end", sizeof("end")) = 0;

    ngx_memzero(&file, sizeof(file));
    file.log = s->connection->log;
    ngx_str_set(&file.name, "end");

    file.fd = ngx_open_file(buff, NGX_FILE_WRONLY,
                                 NGX_FILE_TRUNCATE, NGX_FILE_DEFAULT_ACCESS);

    if (file.fd == NGX_INVALID_FILE) {
        ngx_log_error(NGX_LOG_ERR, s->connection->log, ngx_errno,
                      "hls vod: error creating vod end file");
        return NGX_ERROR;
    }

    ngx_close_file(file.fd);
    file.fd = NGX_INVALID_FILE;

    return NGX_OK;
}

static ngx_int_t ngx_rtmp_hls_write_vod_m3u8(ngx_rtmp_session_t *s)
{
    ngx_rtmp_hls_vod_ctx_t             *ctx;
    ngx_rtmp_hls_vod_app_conf_t        *hacf;
    ngx_file_info_t                    fi;
    u_char                             *tmp, *cur;
    ssize_t                            rc;
    ssize_t                            body_len, header_len;
    u_char                             buffer[TMP_BUFF_LEN];
    ngx_pool_t                         *pool;
    ngx_uint_t                         type;
    ngx_file_t                         m3u8_tmp_file;
    ngx_file_t                         m3u8_bak_file;

    hacf = ngx_rtmp_get_module_app_conf(s, ngx_rtmp_hls_vod_module);
    if (hacf == NULL) {
        return NGX_ERROR;
    }

    ctx = ngx_rtmp_get_module_ctx(s, ngx_rtmp_hls_vod_module);
    if (ctx == NULL) {
        return NGX_ERROR;
    }

    if (ngx_rtmp_remote_conf()) {
        type = NGX_RTMP_HLS_VOD_TYPE_LIVE;
    } else {
        type = hacf->type;
    }

    tmp    = NULL;
    pool   = NULL;
    m3u8_tmp_file.fd = NGX_INVALID_FILE;
    m3u8_bak_file.fd = NGX_INVALID_FILE;

    ngx_memzero(buffer, sizeof(buffer));

    *ngx_snprintf(buffer, sizeof(buffer),
                  "#EXTM3U\n"
                  "#EXT-X-VERSION:3\n"
                  "#EXT-X-MEDIA-SEQUENCE:%uL\n"
                  "#EXT-X-TARGETDURATION:%ui\n"
                  "%s",
                  0,
                  ctx->vod_max_frag,
                  type == NGX_RTMP_HLS_VOD_TYPE_EVENT ?
                  "#EXT-X-PLAYLIST-TYPE: EVENT\n" : "") = 0;

    /*get m3u8 header length*/
    header_len = ngx_strlen((char *)buffer);

    /*get m3u8 body length*/
    ngx_memzero(&m3u8_bak_file, sizeof(m3u8_bak_file));
    ngx_str_set(&m3u8_bak_file.name, "m3u8.bak");
    m3u8_bak_file.offset = 0;
    m3u8_bak_file.log = s->connection->log;
    m3u8_bak_file.fd = ngx_open_file(ctx->vod_m3u8_bak.data, NGX_FILE_RDONLY,
                                        NGX_FILE_OPEN, NGX_FILE_DEFAULT_ACCESS);

    if (m3u8_bak_file.fd == NGX_INVALID_FILE) {

        ngx_log_error(NGX_LOG_ERR, s->connection->log, ngx_errno,
                    "hls vod open the m3u8.bak '%V' failed",
                    &ctx->vod_m3u8_bak);
        goto failed;
    }

    if (ngx_link_info((char *)ctx->vod_m3u8_bak.data, &fi) == NGX_FILE_ERROR) {

        ngx_log_error(NGX_LOG_ERR, s->connection->log, 0,
                    "hls vod link info the m3u8.bak failed");

        goto failed;
    }

    body_len = ngx_file_size(&fi);

    pool = ngx_create_pool(4096, s->connection->log);
    if (pool == NULL) {

        ngx_log_error(NGX_LOG_ERR, s->connection->log, 0,
                    "hls vod create pool failed");
        goto failed;
    }

    tmp = ngx_palloc(pool, header_len + body_len + ngx_strlen("#EXT-X-ENDLIST\n"));
    if (tmp == NULL){
        ngx_log_error(NGX_LOG_ERR, s->connection->log, 0,
                    "hls vod create tmp failed");
        goto failed;
    }

    /*write  m3u8 header and m3u8bak to buffer*/
    cur = ngx_cpymem(tmp, buffer, header_len);
    ngx_read_file(&m3u8_bak_file, cur, body_len, m3u8_bak_file.offset);
    ngx_close_file(m3u8_bak_file.fd);
    m3u8_bak_file.fd = NGX_INVALID_FILE;

    cur = ngx_cpymem(cur + body_len, "#EXT-X-ENDLIST\n", ngx_strlen("#EXT-X-ENDLIST\n"));

    /*write vod m3u8 file*/
    ngx_memzero(&m3u8_tmp_file, sizeof(m3u8_tmp_file));
    ngx_str_set(&m3u8_tmp_file.name, "m3u8.tmp");
    m3u8_tmp_file.offset = 0;
    m3u8_tmp_file.log = s->connection->log;
    m3u8_tmp_file.fd = ngx_open_file(ctx->vod_m3u8_tmp.data, NGX_FILE_WRONLY, NGX_FILE_TRUNCATE,
                                     NGX_FILE_DEFAULT_ACCESS);
    
    if (m3u8_tmp_file.fd == NGX_INVALID_FILE) {

        ngx_log_error(NGX_LOG_ERR, s->connection->log, 0, 
                    "hls vod open m3u8.tmp file: '%V' failed", 
                    &ctx->vod_m3u8_tmp);
       goto failed;
    }

    rc = ngx_write_file(&m3u8_tmp_file, tmp, header_len + body_len + ngx_strlen("#EXT-X-ENDLIST\n"), 0); 
    if (rc == NGX_ERROR) {

        ngx_log_error(NGX_LOG_ERR, s->connection->log, 0,
                    "hls vod write m3u8.tmp file failed");
        
        goto failed;
    }

    ngx_close_file(m3u8_tmp_file.fd);
    m3u8_tmp_file.fd = NGX_INVALID_FILE;

    if (ngx_rtmp_hls_rename_file(ctx->vod_m3u8_tmp.data, ctx->vod_m3u8.data) == NGX_FILE_ERROR) {
        
        ngx_log_error(NGX_LOG_ERR, s->connection->log, 0,
                      "hls vod  rename m3u8 tmp '%V' to m3u8 :'%V' failed",
                      &ctx->vod_m3u8_tmp, &ctx->vod_m3u8);
        goto failed;
    }

    if(pool != NULL) {
        ngx_destroy_pool(pool);
        pool = NULL;
    }

    return NGX_OK;

failed:
    
    if(m3u8_bak_file.fd != NGX_INVALID_FILE) {
        ngx_close_file(m3u8_bak_file.fd);
    }

    if(pool != NULL) {
        ngx_destroy_pool(pool);
    }

    if(m3u8_tmp_file.fd != NGX_INVALID_FILE) {
        ngx_close_file(m3u8_tmp_file.fd);
    }

    return NGX_ERROR;
}

#undef TMP_BUFF_LEN

static ngx_int_t
ngx_rtmp_hls_vod_create_dir(ngx_rtmp_session_t *s, ngx_str_t *path)
{
    ngx_rtmp_hls_vod_app_conf_t        *hacf;
    ngx_rtmp_hls_vod_ctx_t             *ctx;
    ngx_file_info_t                 fi;
    u_char                          tmp_path[NGX_MAX_PATH + 1];

    hacf = ngx_rtmp_get_module_app_conf(s, ngx_rtmp_hls_vod_module);
    if (hacf == NULL) {
        return NGX_ERROR;
    }

    ctx = ngx_rtmp_get_module_ctx(s, ngx_rtmp_hls_vod_module);
    if (ctx == NULL) {
        return NGX_ERROR;
    }

    *ngx_cpymem(tmp_path, path->data, path->len) = 0;
    if (ngx_file_info(tmp_path, &fi) == NGX_FILE_ERROR) {
        if (ngx_errno != NGX_ENOENT) {
            return NGX_ERROR;
        }

        /* ENOENT */
        if (ngx_create_full_path(tmp_path, NGX_RTMP_HLS_DIR_ACCESS) == NGX_FILE_ERROR) {
            return NGX_ERROR;
        }
    } else {
        if (!ngx_is_dir(&fi)) {
            return NGX_ERROR;
        }
    }

    return NGX_OK;
}


static ngx_int_t
ngx_rtmp_hls_vod_init_index_file(ngx_rtmp_session_t *s, ngx_str_t *dir)
{
    u_char                         path[1024], *p, *last;
    u_char                         buffer[1024];

    ngx_rtmp_hls_vod_app_conf_t    *hacf;
    ngx_rtmp_hls_vod_ctx_t         *ctx;
    ngx_str_t                       bucket, url, mp4_bucket, mp4_url;
    ngx_str_t                       region_mp4_tmp, region_hls_tmp;
    ngx_str_t                       live_delay_host,live_delay_app;
    ngx_str_t                       host_mp4_tmp, host_hls_tmp;
    ngx_int_t                       n;
    ngx_file_t                      index_file;

    ctx = ngx_rtmp_get_module_ctx(s, ngx_rtmp_hls_vod_module);
    if (ctx == NULL) {
        return NGX_OK;
    }

    hacf = ngx_rtmp_get_module_app_conf(s, ngx_rtmp_hls_vod_module);
    if (hacf == NULL) {
        return NGX_OK;
    }

    ngx_memzero(path, 1024);
    *ngx_cpymem(path, dir->data, dir->len) = 0;
    if (path[dir->len - 1] != '/') {
        path[dir->len] = '/';
        *ngx_cpymem(path + dir->len + 1, "index.txt", sizeof("index.txt")) = 0;
    } else {
        *ngx_cpymem(path + dir->len, "index.txt", sizeof("index.txt")) = 0;
    }

    ngx_memzero(&index_file, sizeof(index_file));
    ngx_str_set(&index_file.name, "index.txt");

    index_file.log = s->connection->log;
    index_file.fd = ngx_open_file(path, NGX_FILE_WRONLY,
                                      NGX_FILE_TRUNCATE, NGX_FILE_DEFAULT_ACCESS);

    if (index_file.fd == NGX_INVALID_FILE) {
        ngx_log_error(NGX_LOG_ERR, s->connection->log, ngx_errno,
                      "init hls vod index_file: error creating hls index file");
        return NGX_ERROR;
    }

    last = buffer + sizeof(buffer);

    bucket          =   ngx_rtmp_get_attr_conf(hacf, hls_vod_bucket);
    url             =   ngx_rtmp_get_attr_conf(hacf, hls_vod_url);
    mp4_bucket      =   ngx_rtmp_get_attr_conf(hacf, mp4_vod_bucket);
    mp4_url         =   ngx_rtmp_get_attr_conf(hacf, mp4_vod_url);
    region_mp4_tmp  =   ngx_rtmp_get_attr_conf(hacf, region_mp4);
    region_hls_tmp  =   ngx_rtmp_get_attr_conf(hacf, region_hls);
    host_mp4_tmp    =   ngx_rtmp_get_attr_conf(hacf, host_mp4);
    host_hls_tmp    =   ngx_rtmp_get_attr_conf(hacf, host_hls);
    live_delay_host =   ngx_rtmp_get_attr_conf(hacf, live_delay_host);
    live_delay_app  =   ngx_rtmp_get_attr_conf(hacf, live_delay_app);

    #define NGX_RTMP_HLS_CRLF "\r\n"

    p = ngx_snprintf(buffer, sizeof(buffer),
           "usr_id %i"NGX_RTMP_HLS_CRLF
           "live_delay %i"NGX_RTMP_HLS_CRLF
           "live_delay_time %ui"NGX_RTMP_HLS_CRLF
           "live_delay_host %V"NGX_RTMP_HLS_CRLF
           "live_delay_app %V"NGX_RTMP_HLS_CRLF
           "vhost %V"NGX_RTMP_HLS_CRLF
           "is_public %i"NGX_RTMP_HLS_CRLF
           "bucket %V"NGX_RTMP_HLS_CRLF
           "notify_url %V"NGX_RTMP_HLS_CRLF
           "interval %ui"NGX_RTMP_HLS_CRLF
           "mp4 %i"NGX_RTMP_HLS_CRLF
           "mp4_bucket %V"NGX_RTMP_HLS_CRLF
           "mp4_is_public %i"NGX_RTMP_HLS_CRLF
           "mp4_notify_url %V"NGX_RTMP_HLS_CRLF
           "mp4_vod_name_format %i"NGX_RTMP_HLS_CRLF
           "region_mp4 %V"NGX_RTMP_HLS_CRLF
           "region_hls %V"NGX_RTMP_HLS_CRLF
           "host_mp4 %V"NGX_RTMP_HLS_CRLF
           "host_hls %V"NGX_RTMP_HLS_CRLF
           "hls_vod_auto_merge %ui"NGX_RTMP_HLS_CRLF,
           ngx_rtmp_get_attr_conf(hacf, user_id),
           ngx_rtmp_get_attr_conf(hacf, live_delay),
           ngx_rtmp_get_attr_conf(hacf, live_delay_time) / 1000,
           &live_delay_host,
           &live_delay_app,
           &s->host_in,
           ngx_rtmp_get_attr_conf(hacf, hls_vod_is_public),
           &bucket,
           &url,
           ngx_rtmp_get_attr_conf(hacf, hls_vod_fragment) / 1000,
           ngx_rtmp_get_attr_conf(hacf, mp4_vod),
           &mp4_bucket,
           ngx_rtmp_get_attr_conf(hacf, mp4_vod_is_public),
           &mp4_url,
           ngx_rtmp_get_attr_conf(hacf, mp4_vod_name_format),
           &region_mp4_tmp,
           &region_hls_tmp,
           &host_mp4_tmp,
           &host_hls_tmp,
           ngx_rtmp_get_attr_conf(hacf, hls_vod_auto_merge)
           );

    if (s->vdoid.len > 0) {
        p = ngx_snprintf(p, last - p - 1, "vdoid %V\r\n", &s->vdoid);
    } else {
        ngx_log_debug0(NGX_LOG_DEBUG_RTMP, s->connection->log, 0, "vod_init_index_file: vdoid is NULL");
    }

    p = ngx_snprintf(p, last - p - 1, "\r\n\r\n");

    n = ngx_write_fd(index_file.fd, buffer, p - buffer);
    if (n < 0) {
        ngx_log_error(NGX_LOG_ERR, s->connection->log, ngx_errno,
                      "init_ index file: " ngx_write_fd_n " failed: '%V'",
                      path);
        ngx_close_file(index_file.fd);

        return NGX_ERROR;
    }

    ngx_close_file(index_file.fd);
    
    if (!ctx->index_file_name.len) {
        ctx->index_file_name.len = ngx_strlen(path);
        ctx->index_file_name.data = ngx_pcalloc(s->pool, ctx->index_file_name.len);
        ngx_memcpy(ctx->index_file_name.data, path, ngx_strlen(path));
    }

    return NGX_OK;
}


static uint64_t
ngx_rtmp_hls_vod_get_fragment_id(ngx_rtmp_session_t *s, uint64_t ts)
{
    ngx_rtmp_hls_vod_ctx_t         *ctx;
    ngx_rtmp_hls_vod_app_conf_t    *hacf;

    ctx = ngx_rtmp_get_module_ctx(s, ngx_rtmp_hls_vod_module);

    hacf = ngx_rtmp_get_module_app_conf(s, ngx_rtmp_hls_vod_module);

    switch (hacf->naming) {

        case NGX_RTMP_HLS_VOD_NAMING_TIMESTAMP:
            return ts;

        case NGX_RTMP_HLS_VOD_NAMING_SYSTEM:
            return (uint64_t) ngx_cached_time->sec * 1000 + ngx_cached_time->msec;

        case NGX_RTMP_HLS_VOD_NAMING_TIMESTAMP_SEQ:
            return ctx->frag_seq;

        default: /* NGX_RTMP_HLS_NAMING_SEQUENTIAL */
            return ctx->frag + ctx->nfrags;
    }
}


static ngx_int_t
ngx_rtmp_hls_vod_ensure_directory(ngx_rtmp_session_t *s)
{
    ngx_file_info_t              fi;
    ngx_rtmp_hls_vod_ctx_t       *ctx;
    ngx_rtmp_hls_vod_app_conf_t  *hacf;
    static u_char                path[NGX_MAX_PATH + 1];

    hacf = ngx_rtmp_get_module_app_conf(s, ngx_rtmp_hls_vod_module);

    ctx = ngx_rtmp_get_module_ctx(s, ngx_rtmp_hls_vod_module);

    if (!(ngx_rtmp_get_attr_conf(hacf, hls_vod) && ctx->vod_path.len > 0 &&
        (s->relay_type == NGX_NONE_RELAY)))
    {
        return NGX_OK;
    }

    ngx_memzero(&fi, sizeof(fi));
    ngx_memzero(path, sizeof(path));
    *ngx_cpymem(path, ctx->vod_path.data, ctx->vod_path.len) = 0;

    if (ngx_file_info(path, &fi) == NGX_FILE_ERROR) {

        if (ngx_errno != NGX_ENOENT) {

            return NGX_ERROR;
        }
        /* ENOENT */
        if (ngx_create_full_path(path, NGX_RTMP_HLS_DIR_ACCESS) == NGX_FILE_ERROR) {

            return NGX_ERROR;
        }
    } else {
        if (!ngx_is_dir(&fi)) {
            return  NGX_ERROR;
        }
    }

    ngx_memzero(&fi, sizeof(fi));
    ngx_memzero(path, sizeof(path));
    *ngx_cpymem(path, ctx->index_file_name.data, ctx->index_file_name.len) = 0;

    if (ngx_file_info(path, &fi) == NGX_FILE_ERROR) {

        if (ngx_errno != NGX_ENOENT) {

            return NGX_ERROR;
        }

        ngx_memzero(&fi, sizeof(fi));
        ngx_memzero(path, sizeof(path));
        *ngx_cpymem(path, ctx->index_path.data, ctx->index_path.len) = 0;

        if (ngx_file_info(path, &fi) == NGX_FILE_ERROR) {

            if (ngx_errno != NGX_ENOENT) {

                return NGX_ERROR;
            }

	    if (ngx_create_full_path(path, NGX_RTMP_HLS_DIR_ACCESS) == NGX_FILE_ERROR) {
	        ngx_log_error(NGX_LOG_ERR, s->connection->log, ngx_errno,
			      "hls vod: " ngx_create_dir_n " failed on '%s'", path);
	        return NGX_ERROR;
	    }

	} else {
            if (!ngx_is_dir(&fi)) {
                return  NGX_ERROR;
            }
	}

        ngx_rtmp_hls_vod_init_index_file(s, &ctx->index_path);
    }

    return NGX_OK;
}

static ngx_int_t
ngx_rtmp_hls_vod_open_fragment(ngx_rtmp_session_t *s, uint64_t ts,
    ngx_int_t discont, ngx_rtmp_header_t *h)
{
    uint64_t                     id;
    ngx_uint_t                   psi_cc;
    ngx_rtmp_hls_vod_ctx_t       *ctx;
    ngx_rtmp_codec_ctx_t         *codec_ctx;
    ngx_rtmp_hls_vod_frag_t      *f;
    ngx_rtmp_hls_vod_app_conf_t  *hacf;

    hacf = ngx_rtmp_get_module_app_conf(s, ngx_rtmp_hls_vod_module);
    if (hacf == NULL) {
        return NGX_OK;
    }

    ctx = ngx_rtmp_get_module_ctx(s, ngx_rtmp_hls_vod_module);
    if (ctx->opened) {
        return NGX_OK;
    }

    codec_ctx = ngx_rtmp_get_module_ctx(s, ngx_rtmp_codec_module);
    if(codec_ctx == NULL) {
        return NGX_OK;
    }

    if (ngx_rtmp_hls_vod_ensure_directory(s) != NGX_OK) {
        return NGX_ERROR;
    }

    if (!(ngx_rtmp_get_attr_conf(hacf, hls_vod) &&
          (s->relay_type == NGX_NONE_RELAY)))
    {
        return NGX_OK;
    }

    ctx->frag_seq = ts / (ngx_rtmp_get_attr_conf(hacf, hls_vod_fragment) * 90);

    id = ngx_rtmp_hls_vod_get_fragment_id(s, ts);

    if (s->vdoid.len > 0) {

        *ngx_sprintf(ctx->vod_stream.data + ctx->vod_path.len + s->vdoid.len + ngx_strlen("-"), "%uL.ts.bak", id) = 0;
    } else {

        *ngx_sprintf(ctx->vod_stream.data + ctx->vod_path.len, "%uL.ts.bak", id) = 0;
    }

    ngx_memzero(&ctx->vod_file, sizeof(ctx->vod_file));

    ctx->vod_file.log = s->connection->log;

    ngx_str_set(&ctx->vod_file.name, "vodhls");

    ctx->vod_file.fd = ngx_open_file(ctx->vod_stream.data, NGX_FILE_WRONLY,
                                    NGX_FILE_TRUNCATE, NGX_FILE_DEFAULT_ACCESS);

    if (ctx->vod_file.fd == NGX_INVALID_FILE) {

        ngx_log_error(NGX_LOG_ERR, s->connection->log, ngx_errno,
                      "vod hls: error creating fragment file '%V'",
                      &ctx->vod_stream);
        return NGX_ERROR;
    }

    psi_cc = ctx->psi_cc ++;

    if (ngx_rtmp_mpegts_write_header(&ctx->vod_file, psi_cc & 0x0F,
            codec_ctx->video_codec_id == NGX_RTMP_VIDEO_H265) != NGX_OK) {

        ngx_log_error(NGX_LOG_ERR, s->connection->log, ngx_errno,
                      "vodhls: error writing fragment header");
        ctx->psi_cc --;
        ngx_close_file(ctx->vod_file.fd);
        return NGX_ERROR;
    }

    ctx->opened = 1;

    f = ngx_rtmp_hls_vod_get_frag(s, ctx->nfrags);

    ngx_memzero(f, sizeof(*f));

    f->active = 1;
    f->discont = discont;
    f->id = id;
    f->duration = 0.;

    h->type == NGX_RTMP_MSG_AUDIO ? (ctx->last_audio_ts = ts) : (ctx->last_video_ts = ts);
    ctx->frag_ts = ts;
    ctx->frag_ts_system = ngx_current_msec;

    /* start fragment with audio to make iPhone happy */

    ngx_rtmp_hls_vod_flush_audio(s);

    return NGX_OK;
}


static ngx_int_t
ngx_rtmp_hls_vod_close_fragment(ngx_rtmp_session_t *s, uint64_t ts)
{
    ngx_rtmp_hls_vod_ctx_t         *ctx;
    ngx_rtmp_hls_vod_app_conf_t    *hacf;
    u_char                         buff[1024];
    char                           *p;

    ctx = ngx_rtmp_get_module_ctx(s, ngx_rtmp_hls_vod_module);
    if (ctx == NULL || !ctx->opened) {
        return NGX_OK;
    }

    hacf = ngx_rtmp_get_module_app_conf(s, ngx_rtmp_hls_vod_module);
    if (hacf == NULL) {
        return NGX_OK;
    }

    if (!(ngx_rtmp_get_attr_conf(hacf, hls_vod) && (s->relay_type == NGX_NONE_RELAY))) {
        return NGX_OK;
    }

    ctx->opened = 0;

    ngx_log_debug2(NGX_LOG_DEBUG_RTMP, s->connection->log, 0,
                   "hls vod: close fragment n=%uL, %V", ctx->frag, &ctx->vod_stream);

    ngx_rtmp_hls_vod_next_frag(s);

    /*close ts file*/
    ngx_close_file(ctx->vod_file.fd);
    ctx->vod_file.fd = NGX_INVALID_FILE;

    ngx_memzero(buff, 1024);
    ngx_memcpy(buff, ctx->vod_stream.data, ngx_min(ctx->vod_stream.len, sizeof(buff) - 1));
    p = ngx_strstr((char *)buff, ".bak");
    *p= 0;

    ngx_rtmp_hls_rename_file(ctx->vod_stream.data, buff);

    /*generate vod m3u8 file*/
    ngx_rtmp_hls_write_vod_m3u8bak(s, ts);
    ngx_rtmp_hls_write_vod_m3u8(s);

    return NGX_OK;
}


static void
ngx_rtmp_hls_vod_update_fragment(ngx_rtmp_session_t *s, uint64_t ts,
    ngx_int_t boundary, ngx_uint_t flush_rate, ngx_rtmp_header_t *h)
{
    ngx_rtmp_hls_vod_ctx_t            *ctx;
    ngx_rtmp_hls_vod_app_conf_t       *hacf;
    ngx_rtmp_hls_vod_frag_t           *f;
    ngx_msec_t                        ts_frag_len;
    ngx_int_t                         same_frag, force, discont;
    ngx_buf_t                         *b;
    int64_t                           d, d1, system_duration;

    hacf = ngx_rtmp_get_module_app_conf(s, ngx_rtmp_hls_vod_module);
    ctx = ngx_rtmp_get_module_ctx(s, ngx_rtmp_hls_vod_module);
    f = NULL;
    force = 0;
    discont = 1;
    system_duration = 0;

    if (ctx->opened) {

        if (ngx_current_msec > ctx->frag_ts_system) {

            system_duration = ngx_current_msec - ctx->frag_ts_system;
        }

        f = ngx_rtmp_hls_vod_get_frag(s, ctx->nfrags);
        d = (int64_t) (ts - ctx->frag_ts);
        d1 = (h->type == NGX_RTMP_MSG_AUDIO) ?
                    (int64_t) (ts - ctx->last_audio_ts) : (int64_t) (ts - ctx->last_video_ts);

        if (d > (int64_t) hacf->max_fraglen * 90) {

            force = 1;
        } else if (d > 0) {

            // Only ascending dts frames having a right to alter f->duration.
            f->duration = (ts - ctx->frag_ts) / 90000.;
            discont = 0;
        } else if (system_duration > 0 && system_duration > (int64_t) hacf->max_fraglen) {

            f->duration = system_duration / 1000.;
            force = 1;
        }

        if (d1 < 0) {

            ngx_log_error(NGX_LOG_WARN, s->connection->log, 0,
                          "hls vod %s curr timestamp(%uL) less then last timestamp(%uL)",
                          h->type == NGX_RTMP_MSG_AUDIO ? "audio" : "video", ts,
                          h->type == NGX_RTMP_MSG_AUDIO ? ctx->last_audio_ts : ctx->last_video_ts);
            f->discont = 1;
        }

        h->type == NGX_RTMP_MSG_AUDIO ? (ctx->last_audio_ts = ts) : (ctx->last_video_ts = ts);

        if (force) {
            ngx_log_error(NGX_LOG_ERR, s->connection->log, 0,
                          "hls vod force to reap a hls fragment %uL.ts by ts %uL",
                          f->id, ts);
        }
    }

    same_frag = 0;
    switch (hacf->slicing) {

    case NGX_RTMP_HLS_VOD_SLICING_PLAIN:

        if (f && f->duration < (uint32_t) (ngx_rtmp_get_attr_conf(hacf, hls_vod_fragment) / 1000.)) {

            boundary = 0;
        }

        break;

    case NGX_RTMP_HLS_VOD_SLICING_ALIGNED:

        ts_frag_len = ngx_rtmp_get_attr_conf(hacf, hls_vod_fragment) * 90;
        same_frag   = (ctx->frag_ts / ts_frag_len) == (ts / ts_frag_len);
        if (f && same_frag) {

            boundary = 0;
        }

        if (f == NULL && (ctx->frag_ts == 0 || same_frag)) {

            ctx->frag_ts = ts;
            if (s->relay_type != NGX_NONE_RELAY) {

                boundary = 0;
            }
        }

        break;
    }

    if (boundary || force) {

        ngx_rtmp_hls_vod_close_fragment(s, ts);
        ngx_rtmp_hls_vod_open_fragment(s, ts, discont, h);
    }

    b = ctx->aframe;
    if (ctx->opened && b && b->last > b->pos &&
        ctx->aframe_pts + (uint64_t) hacf->max_audio_delay * 90 / flush_rate
        < ts)
    {
        ngx_rtmp_hls_vod_flush_audio(s);
    }
}


static ngx_int_t
ngx_rtmp_hls_vod_publish(ngx_rtmp_session_t *s, ngx_rtmp_publish_t *v)
{
    ngx_rtmp_core_srv_conf_t            *cscf;
    ngx_rtmp_hls_vod_app_conf_t         *hacf;
    ngx_rtmp_hls_vod_ctx_t              *ctx;
    ngx_rtmp_hls_vod_frag_t             *f;
    ngx_buf_t                           *b;
    ngx_str_t                           unique_name;
    u_char                              num[NGX_BUFF_LEN];
    u_char                              *p1,*p2;
    size_t                              len;

    hacf = ngx_rtmp_get_module_app_conf(s, ngx_rtmp_hls_vod_module);
    if (hacf == NULL) {
        goto next;
    }

    if (!ngx_rtmp_get_attr_conf(hacf, hls_vod)) {
        goto next;
    }

    cscf = ngx_rtmp_get_module_srv_conf(s, ngx_rtmp_core_module);
    if (cscf == NULL) {
        goto next;
    }

    if (!ngx_rtmp_get_attr_conf(hacf, hls_vod)) {
        goto next;
    }

    // reap fragment by NGX_NONE_RELAY.
    if (s->relay_type != NGX_NONE_RELAY) {
        goto next;
    }

    ngx_log_debug2(NGX_LOG_DEBUG_RTMP, s->connection->log, 0,
                  "hls_vod_publish: name='%s' type='%s'",
                  v->name, v->type);

    ctx = ngx_rtmp_get_module_ctx(s, ngx_rtmp_hls_vod_module);

    if (ctx == NULL) {
        ctx = ngx_pcalloc(s->pool, sizeof(ngx_rtmp_hls_vod_ctx_t));
        ngx_rtmp_set_ctx(s, ctx, ngx_rtmp_hls_vod_module);

    } else {

        f = ctx->frags;
        b = ctx->aframe;

        ngx_memzero(ctx, sizeof(ngx_rtmp_hls_vod_ctx_t));
        ctx->frags = f;
        ctx->aframe = b;

        if (b) {
            b->pos = b->last = b->start;
        }
    }

    ctx->publisher = 1;
    ctx->winfrags = hacf->winfrags;

    if (ctx->frags == NULL) {
        ctx->frags = ngx_pcalloc(s->pool,
                                 sizeof(ngx_rtmp_hls_vod_frag_t) *
                                 (ctx->winfrags * 2 + 1));
        if (ctx->frags == NULL) {
            return NGX_ERROR;
        }
    }

    if (ngx_strstr(v->name, "..")) {
        ngx_log_error(NGX_LOG_ERR, s->connection->log, 0, "hls_vod: bad stream name: '%s'", v->name);
        return NGX_ERROR;
    }

    *ngx_sprintf(ctx->time, "%T", ngx_current_msec) = 0;
    ngx_memzero(num, NGX_BUFF_LEN);
    *ngx_sprintf(num, "%ui", (ngx_uint_t)s->connection->number) = 0;

    unique_name = ngx_rtmp_get_attr_conf(cscf, unique_name);

    //create vod_path path
    ctx->vod_path.len = hacf->path.len
        + (hacf->path.data[hacf->path.len - 1] == '/' ? 0 : 1)
        + ngx_strlen("data/")
        + unique_name.len + 1
        + s->app.len + 1
        + s->name.len + 1
        + ngx_strlen(ctx->time) + 1
        + ngx_strlen((char *)num) + 1;

    ctx->vod_path.data = ngx_palloc(s->pool, ctx->vod_path.len);
    ngx_memzero(ctx->vod_path.data, ctx->vod_path.len);

    // vod_path = /data/vod_hls/data/unique_name/app/stream/time_0/
    p1 = ngx_cpymem(ctx->vod_path.data, hacf->path.data, hacf->path.len);
    if (p1[-1] != '/') {
        *p1++ = '/';
    }

    p1 = ngx_cpymem(p1, "data/", ngx_strlen("data/"));

#define NGX_RTMP_HLS_MERGE_PATH(p, unique_name, app, sname, time, num) \
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

    NGX_RTMP_HLS_MERGE_PATH(p1, unique_name, s->app, s->name, ctx->time, num);

    //create index file path
    ctx->index_path.len = hacf->path.len
        + (hacf->path.data[hacf->path.len - 1] == '/' ? 0 : 1)
        + ngx_strlen("index/")
        + unique_name.len + 1
        + s->app.len + 1
        + s->name.len + 1
        + ngx_strlen(ctx->time) + 1
        + ngx_strlen((char *)num) + 1;

    ctx->index_path.data = ngx_palloc(s->pool, ctx->index_path.len);
    ngx_memzero(ctx->index_path.data, ctx->index_path.len);

    //index_path = /data/vod_hls/index/unique_name/streamname/stream/time_0/
    p1 = ngx_cpymem(ctx->index_path.data, hacf->path.data, hacf->path.len);
    if (p1[-1] != '/') {
        *p1++ = '/';
    }
    p1 = ngx_cpymem(p1, "index/", ngx_strlen("index/"));

    NGX_RTMP_HLS_MERGE_PATH(p1, unique_name, s->app, s->name, ctx->time, num);

    // stream = /data/vod_hls/data/unique_name/app/stream/time_0/videoid-
    if (s->vdoid.len > 0) {
        ctx->vod_stream.len = ctx->vod_path.len
            + s->vdoid.len
            + ngx_strlen("-")
            + NGX_INT64_LEN
            + ngx_strlen(".ts");

        ctx->vod_stream.data = ngx_palloc(s->pool, ctx->vod_stream.len);

        ngx_memzero(ctx->vod_stream.data, ctx->vod_stream.len);

        p2 = ngx_cpymem(ctx->vod_stream.data, ctx->vod_path.data, ctx->vod_path.len);
        p2 = ngx_cpymem(p2, s->vdoid.data, s->vdoid.len);
        p2 = ngx_cpymem(p2, "-", ngx_strlen("-"));

    } else {
        ctx->vod_stream.len = ctx->vod_path.len
            + NGX_INT64_LEN
            + ngx_strlen(".ts.bak");

        ctx->vod_stream.data = ngx_palloc(s->pool, ctx->vod_stream.len);

        ngx_memzero(ctx->vod_stream.data, ctx->vod_stream.len);
        p2 = ngx_cpymem(ctx->vod_stream.data, ctx->vod_path.data, ctx->vod_path.len);
    }

    //genetate vod m3u8 path = /data/vod_hls/unique_name/app/stream/time_0/streamname[-videoid].m3u8.tmp
    len = ctx->vod_path.len
        + s->vdoid.len
        + ngx_strlen("-")
        + s->name.len
        + ngx_strlen(".m3u8.tmp") + 1;

    ctx->vod_m3u8_tmp.data = ngx_palloc(s->pool, len);
    ngx_memzero(ctx->vod_m3u8_tmp.data, len);

    p2 = ngx_cpymem(ctx->vod_m3u8_tmp.data, ctx->vod_path.data, ctx->vod_path.len);
    if (s->vdoid.len > 0){
        p2 = ngx_cpymem(p2, s->name.data, s->name.len);
        p2 = ngx_cpymem(p2, "-", ngx_strlen("-"));
        p2 = ngx_cpymem(p2, s->vdoid.data, s->vdoid.len);
    } else {
        p2 = ngx_cpymem(p2, s->name.data, s->name.len);
    }

    *ngx_cpymem(p2, ".m3u8.tmp", ngx_strlen(".m3u8.tmp")) = 0;
    if (s->vdoid.len > 0) {
        ctx->vod_m3u8_tmp.len = ctx->vod_path.len
            + s->vdoid.len
            + ngx_strlen("-")
            + s->name.len
            + ngx_strlen(".m3u8.tmp");
    } else {
        ctx->vod_m3u8_tmp.len = ctx->vod_path.len
            + s->name.len
            + ngx_strlen(".m3u8.tmp");
    }

    ctx->m3u8_header = 0;

    // generate m3u8.bak file, path = /data/vod_hls/test/app/test/time/vdoid-time.m3u8
    len = ctx->vod_path.len
        + s->vdoid.len
        + ngx_strlen("-")
        + s->name.len
        + ngx_strlen(".m3u8.bak") + 1;

    ctx->vod_m3u8_bak.data = ngx_palloc(s->pool, len);
    ngx_memzero(ctx->vod_m3u8_bak.data, len);
    p2 = ngx_cpymem(ctx->vod_m3u8_bak.data, ctx->vod_path.data, ctx->vod_path.len);

    if (s->vdoid.len > 0) {
        p2 = ngx_cpymem(p2, s->name.data, s->name.len);
        p2 = ngx_cpymem(p2, "-", ngx_strlen("-"));
        p2 = ngx_cpymem(p2, s->vdoid.data, s->vdoid.len);
    } else {
        p2 = ngx_cpymem(p2, s->name.data, s->name.len);
    }

    *ngx_cpymem(p2, ".m3u8.bak", ngx_strlen(".m3u8.bak")) =0;
    if (s->vdoid.len > 0) {
        ctx->vod_m3u8_bak.len = ctx->vod_path.len
            + s->vdoid.len
            + ngx_strlen("-")
            + s->name.len
            + ngx_strlen(".m3u8.bak");
    } else {
        ctx->vod_m3u8_bak.len = ctx->vod_path.len
            + s->name.len
            + ngx_strlen(".m3u8.bak");
    }

    ctx->vod_m3u8.len = ctx->vod_m3u8_tmp.len - ngx_strlen(".tmp");
    ctx->vod_m3u8.data = ngx_palloc(s->pool, ctx->vod_m3u8.len + 1);
    *ngx_cpymem(ctx->vod_m3u8.data, ctx->vod_m3u8_tmp.data, ctx->vod_m3u8.len) = 0;

    if (ngx_rtmp_hls_vod_create_dir(s, &ctx->vod_path) ==  NGX_ERROR) {
        ngx_log_error(NGX_LOG_ERR, s->connection->log, 0,
                      "create hls vod dir failed, unique_name:%V, app:%V, name:%V",
                      &unique_name, &s->app, &s->name);
    }

    if (ngx_rtmp_hls_vod_create_dir(s, &ctx->index_path) == NGX_OK) {
        ngx_rtmp_hls_vod_init_index_file(s, &ctx->index_path);
    } else {
        ngx_log_error(NGX_LOG_ERR, s->connection->log, 0,
                      "create hls vod index dir failed, unique_name:%V, app:%V, name:%V",
                      &unique_name, &s->app, &s->name);
    }

next:
    return next_publish(s, v);
}

static ngx_int_t
ngx_rtmp_hls_vod_flush_audio(ngx_rtmp_session_t *s)
{
    ngx_rtmp_hls_vod_ctx_t           *ctx;
    ngx_rtmp_mpegts_frame_t          frame;
    ngx_buf_t                        *b;
    ngx_rtmp_hls_vod_app_conf_t      *hacf;

    ctx = ngx_rtmp_get_module_ctx(s, ngx_rtmp_hls_vod_module);

    if (ctx == NULL || !ctx->opened) {
        return NGX_OK;
    }

    hacf = ngx_rtmp_get_module_app_conf(s, ngx_rtmp_hls_vod_module);
    if (hacf == NULL) {
        return NGX_OK;
    }

    b = ctx->aframe;

    if (b == NULL || b->pos == b->last) {
        return NGX_OK;
    }

    ngx_memzero(&frame, sizeof(frame));

    frame.dts = ctx->aframe_pts;
    frame.pts = frame.dts;
    frame.cc  = ctx->audio_cc;
    frame.pid = 0x101;
    frame.sid = 0xc0;

    ngx_log_debug1(NGX_LOG_DEBUG_RTMP, s->connection->log, 0,
                   "hls vod: flush audio pts=%uL", frame.pts);

    if (ngx_rtmp_mpegts_write_frame(&ctx->vod_file, &frame, b) != NGX_OK) {

        ngx_log_error(NGX_LOG_ERR, s->connection->log, 0, "hls vod: audio flush failed");
    }

    ctx->audio_cc = frame.cc;
    b->pos = b->last = b->start;

    return NGX_OK;
}

static ngx_int_t
ngx_rtmp_hls_vod_audio(ngx_rtmp_session_t *s, ngx_rtmp_header_t *h,
    ngx_chain_t *in)
{
    ngx_rtmp_hls_vod_app_conf_t        *hacf;
    ngx_rtmp_hls_vod_ctx_t             *ctx;
    ngx_rtmp_codec_ctx_t               *codec_ctx;
    uint64_t                            pts, est_pts;
    int64_t                             dpts;
    ngx_buf_t                           *b;
    u_char                              *p;
    uint32_t                            timestamp;
    size_t                              bsize;
    ngx_uint_t                          objtype, srindex, chconf, size;

    hacf = ngx_rtmp_get_module_app_conf(s, ngx_rtmp_hls_vod_module);

    ctx = ngx_rtmp_get_module_ctx(s, ngx_rtmp_hls_vod_module);

    codec_ctx = ngx_rtmp_get_module_ctx(s, ngx_rtmp_codec_module);

    if (hacf == NULL || ctx == NULL || codec_ctx == NULL  || h->mlen < 2) {
        return NGX_OK;
    }

    if (!ngx_rtmp_get_attr_conf(hacf, hls_vod)) {
        return NGX_OK;
    }

    if (s->relay_type != NGX_NONE_RELAY) {
        return NGX_OK;
    }

    if (codec_ctx->audio_codec_id != NGX_RTMP_AUDIO_AAC ||
        codec_ctx->aac_header == NULL || ngx_rtmp_is_codec_header(in))
    {
        return NGX_OK;
    }

    b = ctx->aframe;

    if (b == NULL) {

        b = ngx_pcalloc(s->pool, sizeof(ngx_buf_t));
        if (b == NULL) {
            return NGX_ERROR;
        }

        ctx->aframe = b;

        b->start = ngx_palloc(s->pool, hacf->audio_buffer_size);
        if (b->start == NULL) {
            return NGX_ERROR;
        }

        b->end = b->start + hacf->audio_buffer_size;
        b->pos = b->last = b->start;
    }

    if (ngx_rtmp_get_attr_conf(hacf, hls_vod_ts_zero)) {

        if (!ctx->first_frame) {
            timestamp = 0;
            ctx->base_timestamp = h->timestamp;
            ctx->first_frame = 1;

        } else {
            timestamp = (h->timestamp > ctx->base_timestamp) ?
                (h->timestamp - ctx->base_timestamp) : 0;
        }

    } else {

        timestamp = h->timestamp;
    }

    size = h->mlen - 2 + 7;
    pts = (uint64_t) timestamp * 90;

    if (b->start + size > b->end) {
        ngx_log_error(NGX_LOG_ERR, s->connection->log, 0,
                      "hls vod: too big audio frame");
        return NGX_OK;
    }

    /*
     * start new fragment here if
     * there's no video at all, otherwise
     * do it in video handler
     */

    ngx_rtmp_hls_vod_update_fragment(s, pts, codec_ctx->video_header == NULL, 2, h);

    if (b->last + size > b->end) {
        ngx_rtmp_hls_vod_flush_audio(s);
    }

    ngx_log_debug1(NGX_LOG_DEBUG_RTMP, s->connection->log, 0,
                   "hls vod: audio pts=%uL", pts);

    if (b->last + 7 > b->end) {
        ngx_log_error(NGX_LOG_ERR, s->connection->log, 0,
                      "hls vod: not enough buffer for audio header");
        return NGX_OK;
    }

    p = b->last;
    b->last += 5;

    /* copy payload */
    for (; in && b->last < b->end; in = in->next) {

        bsize = in->buf->last - in->buf->pos;
        if (b->last + bsize > b->end) {
            bsize = b->end - b->last;
        }

        b->last = ngx_cpymem(b->last, in->buf->pos, bsize);
    }

    /* make up ADTS header */
    if (ngx_rtmp_hls_parse_aac_header(s, &objtype, &srindex, &chconf)
        != NGX_OK)
    {
        ngx_log_error(NGX_LOG_ERR, s->connection->log, 0,
                      "hls vod: aac header error");
        return NGX_OK;
    }

    /* we have 5 free bytes + 2 bytes of RTMP frame header */
    p[0] = 0xff;
    p[1] = 0xf1;
    p[2] = (u_char) (((objtype - 1) << 6) | (srindex << 2) |
                     ((chconf & 0x04) >> 2));
    p[3] = (u_char) (((chconf & 0x03) << 6) | ((size >> 11) & 0x03));
    p[4] = (u_char) (size >> 3);
    p[5] = (u_char) ((size << 5) | 0x1f);
    p[6] = 0xfc;

    if (p != b->start) {
        ctx->aframe_num++;
        return NGX_OK;
    }

    ctx->aframe_pts = pts;

    if (!hacf->sync || codec_ctx->sample_rate == 0) {
        return NGX_OK;
    }

    /* align audio frames */

    /* TODO: We assume here AAC frame size is 1024
     *      *       Need to handle AAC frames with frame size of 960 */

    est_pts = ctx->aframe_base + ctx->aframe_num * 90000 * 1024 /
              codec_ctx->sample_rate;
    dpts = (int64_t) (est_pts - pts);

    ngx_log_debug2(NGX_LOG_DEBUG_RTMP, s->connection->log, 0,
                   "hls: audio sync dpts=%L (%.5fs)",
                   dpts, dpts / 90000.);

    if (dpts <= (int64_t) hacf->sync * 90 &&
        dpts >= (int64_t) hacf->sync * -90)
    {
        ctx->aframe_num++;
        ctx->aframe_pts = est_pts;
        return NGX_OK;
    }

    ctx->aframe_base = pts;
    ctx->aframe_num  = 1;

    ngx_log_debug2(NGX_LOG_DEBUG_RTMP, s->connection->log, 0,
                   "hls: audio sync gap dpts=%L (%.5fs)",
                   dpts, dpts / 90000.);

    return NGX_OK;
}


static ngx_int_t
ngx_rtmp_hls_vod_video(ngx_rtmp_session_t *s, ngx_rtmp_header_t *h,
    ngx_chain_t *in)
{
    ngx_rtmp_hls_vod_app_conf_t        *hacf;
    ngx_rtmp_hls_vod_ctx_t             *ctx;
    ngx_rtmp_codec_ctx_t               *codec_ctx;
    u_char                             *p;
    uint8_t                             fmt, ftype, htype, nal_type, src_nal_type;
    uint32_t                            len, rlen;
    ngx_buf_t                           out, *b;
    int32_t                             cts;
    ngx_rtmp_mpegts_frame_t             frame;
    ngx_uint_t                          nal_bytes;
    ngx_int_t                           aud_sent, sps_pps_sent, boundary;
    uint32_t                            timestamp;
    u_char                              buffer[NGX_RTMP_HLS_BUFSIZE];

    hacf = ngx_rtmp_get_module_app_conf(s, ngx_rtmp_hls_vod_module);

    ctx = ngx_rtmp_get_module_ctx(s, ngx_rtmp_hls_vod_module);

    codec_ctx = ngx_rtmp_get_module_ctx(s, ngx_rtmp_codec_module);

    if (hacf == NULL || ctx == NULL || codec_ctx->video_header == NULL ||
        h->mlen < 1)
    {
        return NGX_OK;
    }

    if (!ngx_rtmp_get_attr_conf(hacf, hls_vod)) {
        return NGX_OK;
    }

    // reap fragment by NGX_NONE_RELAY.
    if (s->relay_type != NGX_NONE_RELAY) {
        return NGX_OK;
    }

    /* Only H264/H265 are supported */
    if (codec_ctx->video_codec_id != NGX_RTMP_VIDEO_H264 &&
        codec_ctx->video_codec_id != NGX_RTMP_VIDEO_H265) {
        return NGX_OK;
    }

    if(!codec_ctx->avc_nal_bytes) {
        ngx_log_error(NGX_LOG_WARN, s->connection->log, 0,
                      "hls vod: avc_nal_bytes occurs zero, name:%V, codec id=%uD",
                      &s->name, codec_ctx->video_codec_id);

        ngx_rtmp_codec_dump_header(s, "hls_video", codec_ctx->video_header);

        return NGX_OK;
    }

    p = in->buf->pos;
    if (ngx_rtmp_hls_copy(s, &fmt, &p, 1, &in) != NGX_OK) {
        return NGX_ERROR;
    }

    /* 1: keyframe (IDR)
     * 2: inter frame
     * 3: disposable inter frame
     * 4: generated keyframe
     * 5: video info/command frame
     */

    ftype = (fmt & 0xf0) >> 4;

    /* H264 HDR/PICT */

    if (ngx_rtmp_hls_copy(s, &htype, &p, 1, &in) != NGX_OK) {
        return NGX_ERROR;
    }

    /* proceed only with PICT.
     *
     * 0: AVC sequence header
     * 1: AVC NALU
     * 2: AVC end of sequence
     */

    if (htype != 1) {
        return NGX_OK;
    }

    /* 3 bytes: decoder delay */

    if (ngx_rtmp_hls_copy(s, &cts, &p, 3, &in) != NGX_OK) {
        return NGX_ERROR;
    }

    cts = ((cts & 0x00FF0000) >> 16) | ((cts & 0x000000FF) << 16) |
        (cts & 0x0000FF00);

    ngx_memzero(&out, sizeof(out));

    out.start = buffer;
    out.end = buffer + sizeof(buffer);
    out.pos = out.start;
    out.last = out.pos;

    nal_bytes = codec_ctx->avc_nal_bytes;
    aud_sent = 0;
    sps_pps_sent = 0;

    /* h264 nal -> len + body */
    /* body: nal_type(1) +  */
    while (in) {
        if (ngx_rtmp_hls_copy(s, &rlen, &p, nal_bytes, &in) != NGX_OK) {
            return NGX_OK;
        }

        len = 0;
        ngx_rtmp_rmemcpy(&len, &rlen, nal_bytes);

        if (len == 0) {
            continue;
        }

        if (ngx_rtmp_hls_copy(s, &src_nal_type, &p, 1, &in) != NGX_OK) {
            return NGX_OK;
        }

        nal_type = (codec_ctx->video_codec_id == NGX_RTMP_VIDEO_H264) ? (src_nal_type & 0x1f) : ((src_nal_type & 0x7e) >> 1);

        ngx_log_debug3(NGX_LOG_DEBUG_RTMP, s->connection->log, 0,
                       "hls vod: (%s) NAL type=%ui, len=%uD",
                       ((codec_ctx->video_codec_id == NGX_RTMP_VIDEO_H264) ? "avc" : "hevc"),
                       (ngx_uint_t) nal_type, len);

        if (codec_ctx->video_codec_id == NGX_RTMP_VIDEO_H264 &&
            !(nal_type >= AVC_NAL_SPS && nal_type <= AVC_NAL_PPS)) {
            // avc sps/pps
        } else if (codec_ctx->video_codec_id == NGX_RTMP_VIDEO_H265 &&
                   !(nal_type >= HEVC_NAL_VPS && nal_type <= HEVC_NAL_PPS)) {
            // hevc vps/sps/pps
        } else {
            // ignore
            if (ngx_rtmp_hls_copy(s, NULL, &p, len - 1, &in) != NGX_OK) {
                return NGX_ERROR;
            }
            continue;
        }

        if (codec_ctx->video_codec_id == NGX_RTMP_VIDEO_H264) {
            if (!aud_sent) {
                switch (nal_type) {
                case AVC_NAL_SLICE:
                case AVC_NAL_IDR_SLICE:
                case AVC_NAL_SEI:
                    if (ngx_rtmp_hls_append_aud_h264(s, &out) != NGX_OK) {
                        ngx_log_error(NGX_LOG_ERR, s->connection->log, 0,
                                      "hls vod: error appending AUD NAL");
                    }
                case AVC_NAL_AUD:
                    aud_sent = 1;
                    break;
                }
            }

            switch (nal_type) {
            case AVC_NAL_SLICE:
                sps_pps_sent = 0;
                break;
            case AVC_NAL_IDR_SLICE:
                if (sps_pps_sent) {
                    break;
                }
                if (ngx_rtmp_hls_append_sps_pps_h264(s, &out) != NGX_OK) {
                    ngx_log_error(NGX_LOG_ERR, s->connection->log, 0,
                                  "hls vod: error appending AVC SPS/PPS NALs");
                }
                sps_pps_sent = 1;
                break;
            }
        } else if (codec_ctx->video_codec_id == NGX_RTMP_VIDEO_H265) {
            if (!aud_sent) {
                switch (nal_type) {
                case HEVC_NAL_TRAIL_N:
                case HEVC_NAL_TRAIL_R:
                case HEVC_NAL_IDR_W_RADL:
                case HEVC_NAL_RASL_N:
                case HEVC_NAL_RASL_R:
                case HEVC_NAL_CRA_NUT:
                    if (ngx_rtmp_hls_append_aud_h265(s, &out) != NGX_OK) {
                        ngx_log_error(NGX_LOG_ERR, s->connection->log, 0,
                                      "hls vod: error appending AUD NAL");
                    }
                case HEVC_NAL_AUD:
                    aud_sent = 1;
                    break;
                }
            }

            switch (nal_type) {
            case HEVC_NAL_TRAIL_N:
            case HEVC_NAL_TRAIL_R:
                sps_pps_sent = 0;
                break;
            case HEVC_NAL_CRA_NUT:
            case HEVC_NAL_IDR_W_RADL:
                if(sps_pps_sent) {
                    break;
                }
                if (ngx_rtmp_hls_append_sps_pps_h265(s, &out) != NGX_OK) {
                    ngx_log_error(NGX_LOG_ERR, s->connection->log, 0,
                                  "hls vod: error appending HEVC SPS/PPS NALs");
                }
                sps_pps_sent = 1;
                break;
            }
        } else {
            // do nothing.
        }

        /* AnnexB prefix */

        if (out.end - out.last < 5) {
            ngx_log_error(NGX_LOG_ERR, s->connection->log, 0,
                          "hls vod: not enough buffer for AnnexB prefix");
            return NGX_OK;
        }

        /* first AnnexB prefix is long (4 bytes) */

        if (out.last == out.pos) {
            *out.last++ = 0;
        }

        *out.last++ = 0;
        *out.last++ = 0;
        *out.last++ = 1;
        *out.last++ = src_nal_type;

        /* NAL body */

        if (out.end - out.last < (ngx_int_t) len) {
            ngx_log_error(NGX_LOG_ERR, s->connection->log, 0,
                          "hls vod: not enough buffer for NAL");
            return NGX_OK;
        }

        if (ngx_rtmp_hls_copy(s, out.last, &p, len - 1, &in) != NGX_OK) {
            return NGX_ERROR;
        }

        out.last += (len - 1);
    }

    /*hls timstamp clear zero*/
    if (ngx_rtmp_get_attr_conf(hacf, hls_vod_ts_zero)){

        if (!ctx->first_frame) {

            timestamp = 0;
            ctx->base_timestamp = h->timestamp;
            ctx->first_frame = 1;
        } else {

            timestamp = (h->timestamp > ctx->base_timestamp) ? (h->timestamp - ctx->base_timestamp) : 0;
        }

        cts = (int32_t) ((cts << 8) >> 8);
    } else {

        timestamp = h->timestamp;
    }

    /*set frame value*/
    ngx_memzero(&frame, sizeof(frame));
    frame.cc = ctx->video_cc;
    frame.dts = (uint64_t) timestamp * 90;
    frame.pts = (uint64_t)((int64_t)frame.dts + cts * 90);
    frame.pid = 0x100;
    frame.sid = 0xe0;
    frame.key = (ftype == 1);

    /*
     * start new fragment if
     * - we have video key frame AND
     * - we have audio buffered or have no audio at all or stream is closed
     */

    b = ctx->aframe;
    boundary = frame.key && (codec_ctx->aac_header == NULL || !ctx->opened ||
                             (b && b->last > b->pos));

    ngx_rtmp_hls_vod_update_fragment(s, frame.dts, boundary, 1, h);

    if (!ctx->opened) {
        return NGX_OK;
    }

    ngx_log_debug3(NGX_LOG_DEBUG_RTMP, s->connection->log, 0,
                   "hls vod: video pts=%uL, dts=%uL, cts=%D", frame.pts, frame.dts, cts);

    if (ngx_rtmp_mpegts_write_frame(&ctx->vod_file, &frame, &out) != NGX_OK) {

        ngx_log_error(NGX_LOG_ERR, s->connection->log, 0, "hls vod: video frame failed");
    }

    ctx->video_cc = frame.cc;

    return NGX_OK;
}

static ngx_int_t
ngx_rtmp_hls_vod_close_stream(ngx_rtmp_session_t *s, ngx_rtmp_close_stream_t *v)
{
    ngx_rtmp_hls_vod_app_conf_t        *hacf;
    ngx_rtmp_hls_vod_ctx_t             *ctx;

    hacf = ngx_rtmp_get_module_app_conf(s, ngx_rtmp_hls_vod_module);
    if (hacf == NULL) {
        goto next;
    }

    if (!(ngx_rtmp_get_attr_conf(hacf, hls_vod)  &&
          (s->relay_type == NGX_NONE_RELAY)))
    {
        goto next;
    }

    ctx = ngx_rtmp_get_module_ctx(s, ngx_rtmp_hls_vod_module);
    if (ctx == NULL) {
        goto next;
    }

    ngx_log_debug2(NGX_LOG_DEBUG_RTMP, s->connection->log, 0,
                   "hls vod: leave '%V', publisher=%i",
                   &s->name, ctx->publisher);

    if (ctx->publisher && ctx->closed == 0) {

        ngx_rtmp_hls_vod_close_fragment(s, 0);

        ngx_delete_file(ctx->vod_m3u8_bak.data);

        ngx_rtmp_hls_vod_write_end(s);

        ctx->closed = 1;
    }

next:
    return next_close_stream(s, v);
}

static ngx_int_t
ngx_rtmp_hls_vod_stream_begin(ngx_rtmp_session_t *s, ngx_rtmp_stream_begin_t *v)
{
    return next_stream_begin(s, v);
}

static ngx_int_t
ngx_rtmp_hls_vod_stream_eof(ngx_rtmp_session_t *s, ngx_rtmp_stream_eof_t *v)
{
    ngx_rtmp_hls_vod_flush_audio(s);

    ngx_rtmp_hls_vod_close_fragment(s, 0);

    return next_stream_eof(s, v);
}

static void *
ngx_rtmp_hls_vod_create_app_conf (ngx_conf_t *cf)
{
    ngx_rtmp_hls_vod_app_conf_t *conf;

    conf = ngx_pcalloc(cf->pool, sizeof(ngx_rtmp_hls_vod_app_conf_t));
    if (conf == NULL) {
        return NULL;
    }

    conf->hls_vod = NGX_CONF_UNSET;
    conf->hls_vod_fragment = NGX_CONF_UNSET_MSEC;
    conf->max_fraglen = NGX_CONF_UNSET_MSEC;
    conf->sync = NGX_CONF_UNSET_MSEC;
    conf->winfrags = NGX_CONF_UNSET_UINT;
    conf->naming = NGX_CONF_UNSET_UINT;
    conf->slicing = NGX_CONF_UNSET_UINT;
    conf->type = NGX_CONF_UNSET_UINT;
    conf->max_audio_delay = NGX_CONF_UNSET_MSEC;
    conf->audio_buffer_size = NGX_CONF_UNSET_SIZE;

    conf->user_id = NGX_CONF_UNSET;
    conf->hls_vod_is_public = NGX_CONF_UNSET;
    conf->mp4_vod_name_format = NGX_CONF_UNSET_UINT;
    conf->mp4_vod = NGX_CONF_UNSET;
    conf->mp4_vod_is_public = NGX_CONF_UNSET;
    conf->hls_vod_auto_merge = NGX_CONF_UNSET;

    conf->live_delay = NGX_CONF_UNSET;
    conf->live_delay_time = NGX_CONF_UNSET_MSEC;

    return conf;
}

static char *
ngx_rtmp_hls_vod_merge_app_conf(ngx_conf_t *cf,
                                void *parent, void *child)
{
    ngx_rtmp_hls_vod_app_conf_t    *prev = parent;
    ngx_rtmp_hls_vod_app_conf_t    *conf = child;

    ngx_conf_merge_value(conf->hls_vod, prev->hls_vod, 0);
    ngx_conf_merge_msec_value(conf->hls_vod_fragment, prev->hls_vod_fragment, 10000);
    ngx_conf_merge_value(conf->hls_vod_ts_zero, prev->hls_vod_ts_zero, 0);
    ngx_conf_merge_msec_value(conf->max_fraglen, prev->max_fraglen,
                              conf->hls_vod_fragment * 3);
    ngx_conf_merge_msec_value(conf->sync, prev->sync, 2);

    if (conf->hls_vod_fragment) {
        conf->winfrags = 3;
    }

    ngx_conf_merge_str_value(conf->path, prev->path, "/data/vod_hls");
    ngx_conf_merge_uint_value(conf->naming, prev->naming,
                              NGX_RTMP_HLS_VOD_NAMING_SYSTEM);
    ngx_conf_merge_uint_value(conf->slicing, prev->slicing,
                              NGX_RTMP_HLS_VOD_SLICING_PLAIN);
    ngx_conf_merge_uint_value(conf->type, prev->type,
                              NGX_RTMP_HLS_VOD_TYPE_LIVE);
    ngx_conf_merge_msec_value(conf->max_audio_delay, prev->max_audio_delay,
                              300);
    ngx_conf_merge_size_value(conf->audio_buffer_size, prev->audio_buffer_size,
                              NGX_RTMP_HLS_BUFSIZE);
    ngx_conf_merge_value(conf->user_id, prev->user_id, 0);
    ngx_conf_merge_value(conf->hls_vod_is_public, prev->hls_vod_is_public, 1);
    ngx_conf_merge_str_value(conf->hls_vod_bucket, prev->hls_vod_bucket, "");
    ngx_conf_merge_str_value(conf->hls_vod_url, prev->hls_vod_url, "");
    ngx_conf_merge_uint_value(conf->mp4_vod_name_format, prev->mp4_vod_name_format, 0);
    ngx_conf_merge_value(conf->mp4_vod, prev->mp4_vod, 0);
    ngx_conf_merge_value(conf->mp4_vod_is_public, prev->mp4_vod_is_public, 1);
    ngx_conf_merge_str_value(conf->mp4_vod_bucket, prev->mp4_vod_bucket, "");
    ngx_conf_merge_str_value(conf->mp4_vod_url, prev->mp4_vod_url, "");
    ngx_conf_merge_str_value(conf->region_mp4, prev->region_mp4, "");
    ngx_conf_merge_str_value(conf->region_hls, prev->region_hls, "");
    ngx_conf_merge_str_value(conf->host_mp4, prev->host_mp4, "");
    ngx_conf_merge_str_value(conf->host_hls, prev->host_hls, "");
    ngx_conf_merge_value(conf->hls_vod_auto_merge, prev->hls_vod_auto_merge, 0);
    ngx_conf_merge_value(conf->live_delay, prev->live_delay, 0);
    ngx_conf_merge_msec_value(conf->live_delay_time, prev->live_delay_time, 60000);
    ngx_conf_merge_str_value(conf->live_delay_host, prev->live_delay_host, "");
    ngx_conf_merge_str_value(conf->live_delay_app, prev->live_delay_app, "");

    return NGX_CONF_OK;
}

static ngx_int_t
ngx_rtmp_hls_vod_postconfiguration(ngx_conf_t *cf)
{
    ngx_rtmp_core_main_conf_t   *cmcf;
    ngx_rtmp_handler_pt         *h;

    cmcf = ngx_rtmp_conf_get_module_main_conf(cf, ngx_rtmp_core_module);

    h = ngx_array_push(&cmcf->events[NGX_RTMP_MSG_VIDEO]);
    *h = ngx_rtmp_hls_vod_video;

    h = ngx_array_push(&cmcf->events[NGX_RTMP_MSG_AUDIO]);
    *h = ngx_rtmp_hls_vod_audio;

    next_publish = ngx_rtmp_publish;
    ngx_rtmp_publish = ngx_rtmp_hls_vod_publish;

    next_close_stream = ngx_rtmp_close_stream;
    ngx_rtmp_close_stream = ngx_rtmp_hls_vod_close_stream;

    next_stream_begin = ngx_rtmp_stream_begin;
    ngx_rtmp_stream_begin = ngx_rtmp_hls_vod_stream_begin;

    next_stream_eof = ngx_rtmp_stream_eof;
    ngx_rtmp_stream_eof = ngx_rtmp_hls_vod_stream_eof;

    return NGX_OK;
}
