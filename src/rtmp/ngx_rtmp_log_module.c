
/*
 * Copyright (C) Roman Arutyunyan
 */


#include <ngx_config.h>
#include <ngx_core.h>
#include "ngx_rtmp_cmd_module.h"
#include "ngx_rtmp_log_module.h"


static ngx_rtmp_publish_pt    next_publish;
static ngx_rtmp_play_pt       next_play;
static ngx_rtmp_disconnect_pt next_disconnect;

static ngx_int_t ngx_rtmp_log_postconfiguration(ngx_conf_t *cf);
static void *ngx_rtmp_log_create_main_conf(ngx_conf_t *cf);
static char *ngx_rtmp_log_init_main_conf(ngx_conf_t *cf, void *conf);
static void * ngx_rtmp_log_create_app_conf(ngx_conf_t *cf);
static char * ngx_rtmp_log_merge_app_conf(ngx_conf_t *cf,
       void *parent, void *child);
static char * ngx_rtmp_log_set_log(ngx_conf_t *cf, ngx_command_t *cmd,
       void *conf);
static char * ngx_rtmp_log_set_format(ngx_conf_t *cf, ngx_command_t *cmd,
       void *conf);
static char * ngx_rtmp_log_compile_format(ngx_conf_t *cf, ngx_array_t *ops,
       ngx_array_t *args, ngx_uint_t s);
static void ngx_rtmp_log_write(ngx_rtmp_session_t *s, ngx_rtmp_log_t *log,
       ngx_rtmp_log_fmt_t *fmt);
static ngx_rtmp_log_ctx_t *ngx_rtmp_log_pcalloc_ctx(ngx_rtmp_session_t *s);


static const char * ngx_rtmp_log_standards[NGX_RTMP_LOG_EVENT_MAX] = 
{
    "notify_latency",
    "bw_in",
    "bw_out",
    "evt_in",
    "evt_rtmp_out",
    "evt_hdl_out",
    "evt_hls_out",
    "flux",
    "delay",
    "publisher_finalize"
};


static const char * ngx_rtmp_log_finalize_desc[NGX_RTMP_LOG_FINALIZE_MAX_CODE] =
{
    "rtmp_client_close_session",
    "rtmp_handshake_recv_err",
    "rtmp_handshake_send_err",
    "rtmp_publisher_client_close_session",
    "rtmp_recv_msg_err",
    "rtmp_parse_head_msg_failed",
    "rtmp_ping_err",
    "rtmp_drop_idle_publisher",
    "rtmp_live_parse_mandatory_packet_err",
    "rtmp_connect_app_name_illegal",
    "rtmp_publish_stream_name_illegal",
    "rtmp_ds_close_publisher",
    "rtmp_publish_vdoid_illegal",
};

static ngx_str_t ngx_rtmp_access_log = ngx_string(NGX_HTTP_LOG_PATH);


static ngx_command_t  ngx_rtmp_log_commands[] = {

    { ngx_string("access_log"),
      NGX_RTMP_MAIN_CONF|NGX_RTMP_SRV_CONF|NGX_RTMP_APP_CONF|NGX_CONF_2MORE,
      ngx_rtmp_log_set_log,
      NGX_RTMP_APP_CONF_OFFSET,
      0,
      NULL },

    { ngx_string("log_format"),
      NGX_RTMP_MAIN_CONF|NGX_RTMP_SRV_CONF|NGX_RTMP_APP_CONF|NGX_CONF_2MORE,
      ngx_rtmp_log_set_format,
      NGX_RTMP_MAIN_CONF_OFFSET,
      0,
      NULL },

    { ngx_string("flux_interval"),
      NGX_RTMP_MAIN_CONF|NGX_CONF_TAKE1,
      ngx_conf_set_msec_slot,
      NGX_RTMP_MAIN_CONF_OFFSET,
      offsetof(ngx_rtmp_log_main_conf_t, flux_interval),
      NULL },
      
    { ngx_string("log_sample_interval"),
      NGX_RTMP_MAIN_CONF|NGX_RTMP_SRV_CONF|NGX_RTMP_APP_CONF|NGX_CONF_TAKE1,
      ngx_conf_set_msec_slot,
      NGX_RTMP_APP_CONF_OFFSET,
      offsetof(ngx_rtmp_log_app_conf_t, log_sample_interval),
      NULL },

      ngx_null_command
};


static ngx_rtmp_module_t  ngx_rtmp_log_module_ctx = {
    NULL,                                   /* preconfiguration */
    ngx_rtmp_log_postconfiguration,         /* postconfiguration */
    ngx_rtmp_log_create_main_conf,          /* create main configuration */
    ngx_rtmp_log_init_main_conf,            /* init main configuration */
    NULL,                                   /* create server configuration */
    NULL,                                   /* merge server configuration */
    ngx_rtmp_log_create_app_conf,           /* create app configuration */
    ngx_rtmp_log_merge_app_conf             /* merge app configuration */
};


ngx_module_t  ngx_rtmp_log_module = {
    NGX_MODULE_V1,
    &ngx_rtmp_log_module_ctx,               /* module context */
    ngx_rtmp_log_commands,                  /* module directives */
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

static size_t
ngx_rtmp_log_var_stream_duration_sec_getlen(ngx_rtmp_session_t *s, ngx_rtmp_log_op_t *op)
{
    return NGX_INT_T_LEN;
}


static u_char *
ngx_rtmp_log_var_stream_duration_sec_getdata(ngx_rtmp_session_t *s, u_char *buf,
    ngx_rtmp_log_op_t *op)
{
    return ngx_snprintf(buf, NGX_INT_T_LEN, "%L", (int64_t)(ngx_time() - s->connect_time));
}


static size_t
ngx_rtmp_log_var_finalize_desc_getlen(ngx_rtmp_session_t *s, ngx_rtmp_log_op_t *op)
{
    return ngx_strlen(ngx_rtmp_log_finalize_desc[s->finalize_code]);
}


static u_char *
ngx_rtmp_log_var_finalize_desc_getdata(ngx_rtmp_session_t *s, u_char *buf,
    ngx_rtmp_log_op_t *op)
{
    return ngx_snprintf(buf, ngx_strlen(ngx_rtmp_log_finalize_desc[s->finalize_code]),
            "%s", ngx_rtmp_log_finalize_desc[s->finalize_code]);
}


static size_t
ngx_rtmp_log_var_tcurl_getlen(ngx_rtmp_session_t *s, ngx_rtmp_log_op_t *op)
{
    return s->tc_url.len;
}


static u_char *
ngx_rtmp_log_var_tcurl_getdata(ngx_rtmp_session_t *s, u_char *buf,
    ngx_rtmp_log_op_t *op)
{
    return ngx_snprintf(buf, s->tc_url.len, "%s", s->tc_url.data);
}


static size_t
ngx_rtmp_log_var_connect_time_getlen(ngx_rtmp_session_t *s, ngx_rtmp_log_op_t *op)
{
    return NGX_INT_T_LEN;
}


static u_char *
ngx_rtmp_log_var_connect_time_getdata(ngx_rtmp_session_t *s, u_char *buf,
    ngx_rtmp_log_op_t *op)
{
    return ngx_snprintf(buf, NGX_INT_T_LEN, "%L", (int64_t)(s->epoch / 1000));
}


static size_t
ngx_rtmp_log_var_log_version_string_getlen(ngx_rtmp_session_t *s, ngx_rtmp_log_op_t *op)
{
    return ngx_strlen("v2");
}
 
 
static u_char *
ngx_rtmp_log_var_log_version_string_getdata(ngx_rtmp_session_t *s, u_char *buf,
    ngx_rtmp_log_op_t *op)
{
    return ngx_snprintf(buf, ngx_strlen("v2"), "%s", "v2");
}
 
static size_t
ngx_rtmp_log_var_product_info_string_getlen(ngx_rtmp_session_t *s, ngx_rtmp_log_op_t *op)
{
    return ngx_strlen("kls");
}
 
static u_char *
ngx_rtmp_log_var_product_info_string_getdata(ngx_rtmp_session_t *s, u_char *buf,
    ngx_rtmp_log_op_t *op)
{
    return ngx_snprintf(buf, ngx_strlen("kls"), "%s", "kls");
}
 
static size_t
ngx_rtmp_log_var_hostname_string_getlen(ngx_rtmp_session_t *s, ngx_rtmp_log_op_t *op)
{
    return ngx_cycle->hostname.len;
}
 
 
static u_char *
ngx_rtmp_log_var_hostname_string_getdata(ngx_rtmp_session_t *s, u_char *buf,
    ngx_rtmp_log_op_t *op)
{
    return ngx_snprintf(buf, ngx_cycle->hostname.len,
                        "%s", ngx_cycle->hostname.data);
}
 
static size_t
ngx_rtmp_log_var_log_time_ms_getlen(ngx_rtmp_session_t *s,
    ngx_rtmp_log_op_t *op)
{
    return NGX_INT_T_LEN;
}
 
 
static u_char *
ngx_rtmp_log_var_log_time_ms_getdata(ngx_rtmp_session_t *s, u_char *buf,
    ngx_rtmp_log_op_t *op)
{
    ngx_uint_t   *v;
    u_char       *p;
 
    v = (ngx_uint_t *) ((uint8_t *) s + op->offset);
 
    if (!(*v)) {
 
        return buf;    
 
    } else {
 
        p = ngx_sprintf(buf, "%ui", *v);
        return p;
    }
}
 
static size_t
ngx_rtmp_log_var_refer_string_getlen(ngx_rtmp_session_t *s,
    ngx_rtmp_log_op_t *op)
{
    return ((ngx_str_t *) ((u_char *) s + op->offset))->len;
}
 
 
static u_char *
ngx_rtmp_log_var_refer_string_getdata(ngx_rtmp_session_t *s, u_char *buf,
    ngx_rtmp_log_op_t *op)
{
    ngx_str_t  *str;
 
    str = (ngx_str_t *) ((u_char *) s + op->offset);
    if (!str->len) {

        return ngx_cpymem(buf, "-", 1); 
    }
 
    return ngx_cpymem(buf, str->data, str->len);
}
 
static size_t
ngx_rtmp_log_var_bw_in_bytes_getlen(ngx_rtmp_session_t *s, ngx_rtmp_log_op_t *op)
{
    return NGX_INT64_LEN;
}
 
static u_char *
ngx_rtmp_log_var_bw_in_bytes_getdata(ngx_rtmp_session_t *s, u_char * buf,
    ngx_rtmp_log_op_t *op)
{
    ngx_rtmp_live_ctx_t  *ctx;
    uint64_t             value;
 
    ctx = ngx_rtmp_get_module_ctx(s, ngx_rtmp_live_module);
    if (ctx == NULL || ctx->stream == NULL) {
        value = 0;
 
    } else {
 
        value = ctx->stream->bw_in_bytes.bytes;
        ctx->stream->bw_in_bytes.bytes = 0;
    }
 
    return ngx_snprintf(buf, NGX_INT_T_LEN, "%uL", value);
}
 
static size_t
ngx_rtmp_log_var_bw_out_bytes_getlen(ngx_rtmp_session_t *s, ngx_rtmp_log_op_t *op)
{
    return NGX_INT64_LEN;
}
 
 
static u_char *
ngx_rtmp_log_var_bw_out_bytes_getdata(ngx_rtmp_session_t *s, u_char * buf,
    ngx_rtmp_log_op_t *op)
{
    ngx_rtmp_live_ctx_t  *ctx;
    uint64_t             value;
 
    ctx = ngx_rtmp_get_module_ctx(s, ngx_rtmp_live_module);
    if (ctx == NULL || ctx->stream == NULL) {
        value = 0;
 
    } else {
 
        value = ctx->stream->bw_out_bytes.bytes;
        ctx->stream->bw_out_bytes.bytes = 0;
    }
 
    return ngx_snprintf(buf, NGX_INT_T_LEN, "%uL", value);
}
 
static size_t
ngx_rtmp_log_var_curfps_uint_getlen(ngx_rtmp_session_t *s,
    ngx_rtmp_log_op_t *op)
{
    return NGX_INT_T_LEN;
}
 
 
static u_char *
ngx_rtmp_log_var_curfps_uint_getdata(ngx_rtmp_session_t *s, u_char *buf,
    ngx_rtmp_log_op_t *op)
{
    ngx_rtmp_live_ctx_t    *ctx;
    ngx_uint_t             value;
 
    ctx = ngx_rtmp_get_module_ctx(s, ngx_rtmp_live_module);
    if (ctx == NULL || ctx->stream == NULL) {
        value = 0;
 
    } else {
 
        value = ctx->stream->video_frame_rate.fps / 1000;
    }
 
    return ngx_sprintf(buf, "%ui", value);
}
 
static size_t
ngx_rtmp_log_var_start_time_ms_getlen(ngx_rtmp_session_t *s,
    ngx_rtmp_log_op_t *op)
{
    return NGX_INT_T_LEN;
}
 
 
static u_char *
ngx_rtmp_log_var_start_time_ms_getdata(ngx_rtmp_session_t *s, u_char *buf,
    ngx_rtmp_log_op_t *op)
{
    ngx_uint_t   *v;
    u_char       *p;
 
    v = (ngx_uint_t *) ((uint8_t *) s + op->offset);
 
    if (!(*v)) {
 
        return buf;    
 
    } else {
 
        p = ngx_sprintf(buf, "%ui", *v);
        return p;
    }
}
 
static size_t
ngx_rtmp_log_var_end_time_ms_getlen(ngx_rtmp_session_t *s,
    ngx_rtmp_log_op_t *op)
{
    return NGX_INT_T_LEN;
}
 
 
static u_char *
ngx_rtmp_log_var_end_time_ms_getdata(ngx_rtmp_session_t *s, u_char *buf,
    ngx_rtmp_log_op_t *op)
{
    ngx_uint_t   *v;
    u_char       *p;
 
    v = (ngx_uint_t *) ((uint8_t *) s + op->offset);
 
    if (!(*v)) {
        
        p = ngx_sprintf(buf, "%s", "-1");
        return p;    
 
    } else {
 
        p = ngx_sprintf(buf, "%ui", *v);
        return p;
    }
}
 
static size_t
ngx_rtmp_log_var_stream_stat_uint_getlen(ngx_rtmp_session_t *s,
    ngx_rtmp_log_op_t *op)
{
    return NGX_INT32_LEN;
}
 
 
static u_char *
ngx_rtmp_log_var_stream_stat_uint_getdata(ngx_rtmp_session_t *s, u_char *buf,
    ngx_rtmp_log_op_t *op)
{
    ngx_uint_t   *v;
 
    v = (ngx_uint_t *) ((uint8_t *) s + op->offset);
 
    return ngx_sprintf(buf, "%ui", *v);
}
 
static size_t
ngx_rtmp_log_var_extend1_string_getlen(ngx_rtmp_session_t *s, ngx_rtmp_log_op_t *op)
{
    return ngx_strlen("-");
}
 
static u_char *
ngx_rtmp_log_var_extend1_string_getdata(ngx_rtmp_session_t *s, u_char *buf,
    ngx_rtmp_log_op_t *op)
{
    return ngx_snprintf(buf, ngx_strlen("-"), "%s", "-");
}
 
static size_t
ngx_rtmp_log_var_extend2_string_getlen(ngx_rtmp_session_t *s, ngx_rtmp_log_op_t *op)
{
    return ngx_strlen("-");
}
 
static u_char *
ngx_rtmp_log_var_extend2_string_getdata(ngx_rtmp_session_t *s, u_char *buf,
    ngx_rtmp_log_op_t *op)
{
    return ngx_snprintf(buf, ngx_strlen("-"), "%s", "-");
}
 
static size_t
ngx_rtmp_log_var_extend3_string_getlen(ngx_rtmp_session_t *s, ngx_rtmp_log_op_t *op)
{
    return ngx_strlen("-");
}
 
static u_char *
ngx_rtmp_log_var_extend3_string_getdata(ngx_rtmp_session_t *s, u_char *buf,
    ngx_rtmp_log_op_t *op)
{
    return ngx_snprintf(buf, ngx_strlen("-"), "%s", "-");
}
 
static size_t
ngx_rtmp_log_var_extend4_string_getlen(ngx_rtmp_session_t *s, ngx_rtmp_log_op_t *op)
{
    return ngx_strlen("-");
}
 
static u_char *
ngx_rtmp_log_var_extend4_string_getdata(ngx_rtmp_session_t *s, u_char *buf,
    ngx_rtmp_log_op_t *op)
{
    return ngx_snprintf(buf, ngx_strlen("-"), "%s", "-");
}
 
static size_t
ngx_rtmp_log_var_extend5_string_getlen(ngx_rtmp_session_t *s, ngx_rtmp_log_op_t *op)
{
    return ngx_strlen("-");
}
 
static u_char *
ngx_rtmp_log_var_extend5_string_getdata(ngx_rtmp_session_t *s, u_char *buf,
    ngx_rtmp_log_op_t *op)
{
	
    return ngx_snprintf(buf, ngx_strlen("-"), "%s", "-");
}
 
static size_t
ngx_rtmp_log_var_online_players_getlen(ngx_rtmp_session_t *s ,ngx_rtmp_log_op_t *op)
{
    return NGX_INT_T_LEN;
}


static u_char *
ngx_rtmp_log_var_online_players_getdata(ngx_rtmp_session_t *s, u_char *buf,
    ngx_rtmp_log_op_t *op)
{
    ngx_rtmp_live_ctx_t       *ctx;
    ngx_rtmp_live_ctx_t       *pctx;
    ngx_rtmp_live_stream_t    *stream;
    ngx_uint_t                 online_num = 0;

    ctx = ngx_rtmp_get_module_ctx(s, ngx_rtmp_live_module);
    if (ctx) {
        stream = ctx->stream;
        pctx = stream->ctx;
        while (pctx) {
            if (!pctx->publishing && !pctx->session->relay_type) {
                online_num ++;
            }
            pctx = pctx->next;
        }
    }

    return ngx_snprintf(buf, NGX_INT_T_LEN, "%ui", online_num);
}


static size_t
ngx_rtmp_log_var_default_getlen(ngx_rtmp_session_t *s, ngx_rtmp_log_op_t *op)
{
    return op->value.len;
}


static u_char *
ngx_rtmp_log_var_default_getdata(ngx_rtmp_session_t *s, u_char *buf,
    ngx_rtmp_log_op_t *op)
{
    return ngx_cpymem(buf, op->value.data, op->value.len);
}


static size_t
ngx_rtmp_log_var_connection_getlen(ngx_rtmp_session_t *s, ngx_rtmp_log_op_t *op)
{
    return NGX_INT_T_LEN;
}


static u_char *
ngx_rtmp_log_var_connection_getdata(ngx_rtmp_session_t *s, u_char *buf,
    ngx_rtmp_log_op_t *op)
{
    return ngx_sprintf(buf, "%ui", (ngx_uint_t) s->connection->number);
}


#define NGX_RTMP_UNIX_SOCKET_NAME "worker_socket"
static size_t
ngx_rtmp_log_var_remote_addr_getlen(ngx_rtmp_session_t *s,
    ngx_rtmp_log_op_t *op)
{
    return s->connection->addr_text.len == 0 ?
            sizeof(NGX_RTMP_UNIX_SOCKET_NAME) - 1 : s->connection->addr_text.len;
}


static u_char *
ngx_rtmp_log_var_remote_addr_getdata(ngx_rtmp_session_t *s, u_char *buf,
    ngx_rtmp_log_op_t *op)
{
    if (s->connection->addr_text.len == 0) {
        return ngx_cpymem(buf, (u_char*)NGX_RTMP_UNIX_SOCKET_NAME,
                sizeof(NGX_RTMP_UNIX_SOCKET_NAME) - 1);
    } else {
        return ngx_cpymem(buf, s->connection->addr_text.data,
                s->connection->addr_text.len);
    }
}


static size_t
ngx_rtmp_log_var_remote_port_getlen(ngx_rtmp_session_t *s,
    ngx_rtmp_log_op_t *op)
{
    return NGX_INT_T_LEN;
}


static u_char *
ngx_rtmp_log_var_remote_port_getdata(ngx_rtmp_session_t *s, u_char *buf,
    ngx_rtmp_log_op_t *op)
{
    return ngx_sprintf(buf, "%ui", ngx_rtmp_get_remote_port(s));
}


static size_t
ngx_rtmp_log_var_cid_getlen(ngx_rtmp_session_t *s,
    ngx_rtmp_log_op_t *op)
{
    return NGX_INT_T_LEN;
}


static u_char *
ngx_rtmp_log_var_cid_getdata(ngx_rtmp_session_t *s, u_char *buf,
    ngx_rtmp_log_op_t *op)
{
    ngx_rtmp_core_main_conf_t *cmcf = ngx_rtmp_core_main_conf;

    return ngx_sprintf(buf, "%ui", cmcf->cluster_id);
}


static size_t
ngx_rtmp_log_var_lid_getlen(ngx_rtmp_session_t *s,
    ngx_rtmp_log_op_t *op)
{
    return NGX_INT_T_LEN;
}


static u_char *
ngx_rtmp_log_var_lid_getdata(ngx_rtmp_session_t *s, u_char *buf,
    ngx_rtmp_log_op_t *op)
{
    ngx_rtmp_core_main_conf_t *cmcf = ngx_rtmp_core_main_conf;

    return ngx_sprintf(buf, "%ui", cmcf->nginx_id);
}


static size_t
ngx_rtmp_log_var_pid_getlen(ngx_rtmp_session_t *s,
    ngx_rtmp_log_op_t *op)
{
    return NGX_INT_T_LEN;
}


static u_char *
ngx_rtmp_log_var_pid_getdata(ngx_rtmp_session_t *s, u_char *buf,
    ngx_rtmp_log_op_t *op)
{
    return ngx_sprintf(buf, "%P", ngx_log_pid);
}


static size_t
ngx_rtmp_log_var_slot_getlen(ngx_rtmp_session_t *s,
    ngx_rtmp_log_op_t *op)
{
    return NGX_INT_T_LEN;
}


static u_char *
ngx_rtmp_log_var_slot_getdata(ngx_rtmp_session_t *s, u_char *buf,
    ngx_rtmp_log_op_t *op)
{
    return ngx_sprintf(buf, "%i", ngx_process_slot);
}


static size_t
ngx_rtmp_log_var_session_sid_getlen(ngx_rtmp_session_t *s,
    ngx_rtmp_log_op_t *op)
{
    return NGX_INT_T_LEN;
}


static u_char *
ngx_rtmp_log_var_session_sid_getdata(ngx_rtmp_session_t *s, u_char *buf,
    ngx_rtmp_log_op_t *op)
{
    return ngx_sprintf(buf, "%ui", s->connection->log->connection);
}


static size_t
ngx_rtmp_log_var_unique_name_getlen(ngx_rtmp_session_t *s,
    ngx_rtmp_log_op_t *op)
{
    ngx_rtmp_core_srv_conf_t *cscf;
    ngx_str_t                 unique_name;

    cscf = ngx_rtmp_get_module_srv_conf(s, ngx_rtmp_core_module);

    unique_name = ngx_rtmp_get_attr_conf(cscf, unique_name);

    return unique_name.len;
}


static u_char *
ngx_rtmp_log_var_unique_name_getdata(ngx_rtmp_session_t *s, u_char *buf,
    ngx_rtmp_log_op_t *op)
{
    ngx_rtmp_core_srv_conf_t *cscf;
    ngx_str_t                 unique_name;

    cscf = ngx_rtmp_get_module_srv_conf(s, ngx_rtmp_core_module);

    unique_name = ngx_rtmp_get_attr_conf(cscf, unique_name);

    return ngx_cpymem(buf, unique_name.data, unique_name.len);
}


static size_t
ngx_rtmp_log_var_ntype_getlen(ngx_rtmp_session_t *s,
    ngx_rtmp_log_op_t *op)
{
    ngx_rtmp_netcall_ctx_t   *ctx;

    ctx = ngx_rtmp_get_module_ctx(s, ngx_rtmp_netcall_module);

    return ctx && ctx->name ? ngx_strlen(ctx->name) : 0;
}


static u_char *
ngx_rtmp_log_var_ntype_getdata(ngx_rtmp_session_t *s, u_char *buf,
    ngx_rtmp_log_op_t *op)
{
    ngx_rtmp_netcall_ctx_t   *ctx;

    ctx = ngx_rtmp_get_module_ctx(s, ngx_rtmp_netcall_module);

    return ctx && ctx->name ? ngx_cpymem(buf, ctx->name, ngx_strlen(ctx->name)) : buf;
}


static size_t
ngx_rtmp_log_var_notify_stime_ms_getlen(ngx_rtmp_session_t *s,
    ngx_rtmp_log_op_t *op)
{
    return NGX_INT_T_LEN;
}


static u_char *
ngx_rtmp_log_var_notify_stime_ms_getdata(ngx_rtmp_session_t *s, u_char *buf,
    ngx_rtmp_log_op_t *op)
{
    ngx_rtmp_netcall_ctx_t   *ctx;

    ctx = ngx_rtmp_get_module_ctx(s, ngx_rtmp_netcall_module);

    return ctx ? ngx_sprintf(buf, "%ui", ctx->start) : buf;
}


static size_t
ngx_rtmp_log_var_notify_etime_ms_getlen(ngx_rtmp_session_t *s,
    ngx_rtmp_log_op_t *op)
{
    return NGX_INT_T_LEN;
}


static u_char *
ngx_rtmp_log_var_notify_etime_ms_getdata(ngx_rtmp_session_t *s, u_char *buf,
    ngx_rtmp_log_op_t *op)
{
    ngx_rtmp_netcall_ctx_t   *ctx;

    ctx = ngx_rtmp_get_module_ctx(s, ngx_rtmp_netcall_module);

    return ctx ? ngx_sprintf(buf, "%ui", ctx->end) : buf;
}


static size_t
ngx_rtmp_log_var_notify_diff_ms_getlen(ngx_rtmp_session_t *s,
    ngx_rtmp_log_op_t *op)
{
    return NGX_INT_T_LEN;
}


static u_char *
ngx_rtmp_log_var_notify_diff_ms_getdata(ngx_rtmp_session_t *s, u_char *buf,
    ngx_rtmp_log_op_t *op)
{
    ngx_rtmp_netcall_ctx_t   *ctx;

    ctx = ngx_rtmp_get_module_ctx(s, ngx_rtmp_netcall_module);

    return ctx ? ngx_sprintf(buf, "%i", ((ngx_int_t) ctx->end) - ctx->start) : buf;
}


static size_t
ngx_rtmp_log_var_notify_result_getlen(ngx_rtmp_session_t *s,
    ngx_rtmp_log_op_t *op)
{
    return NGX_INT_T_LEN;
}


static u_char *
ngx_rtmp_log_var_notify_result_getdata(ngx_rtmp_session_t *s, u_char *buf,
    ngx_rtmp_log_op_t *op)
{
    ngx_rtmp_netcall_ctx_t   *ctx;

    ctx = ngx_rtmp_get_module_ctx(s, ngx_rtmp_netcall_module);

    return ctx ? ngx_sprintf(buf, "%i", ctx->ret): buf;
}


static size_t
ngx_rtmp_log_var_hls_stime_ms_getlen(ngx_rtmp_session_t *s,
    ngx_rtmp_log_op_t *op)
{
    return NGX_INT_T_LEN;
}


static u_char *
ngx_rtmp_log_var_hls_stime_ms_getdata(ngx_rtmp_session_t *s, u_char *buf,
    ngx_rtmp_log_op_t *op)
{
    ngx_uint_t   *v;
    u_char       *p;

    v = (ngx_uint_t *) ((uint8_t *) s + op->offset);

    if (!(*v)) {

        return buf;    

    } else {

        p = ngx_sprintf(buf, "%ui", *v);
        return p;
    }
}


static size_t
ngx_rtmp_log_var_hls_etime_ms_getlen(ngx_rtmp_session_t *s,
    ngx_rtmp_log_op_t *op)
{
    return NGX_INT_T_LEN;
}


static u_char *
ngx_rtmp_log_var_hls_etime_ms_getdata(ngx_rtmp_session_t *s, u_char *buf,
    ngx_rtmp_log_op_t *op)
{
    ngx_uint_t   *v;
    u_char       *p;

    v = (ngx_uint_t *) ((uint8_t *) s + op->offset);

    if (!(*v)) {

        return buf;   

    } else {

        p = ngx_sprintf(buf, "%ui", *v);
        return p;
    }
}


static size_t
ngx_rtmp_log_var_hls_diff_ms_getlen(ngx_rtmp_session_t *s,
    ngx_rtmp_log_op_t *op)
{
    return NGX_INT_T_LEN;
}


static u_char *
ngx_rtmp_log_var_hls_diff_ms_getdata(ngx_rtmp_session_t *s, u_char *buf,
    ngx_rtmp_log_op_t *op)
{
    if (s->hls_stime_ms && s->hls_etime_ms) {

        return ngx_sprintf(buf, "%ui", (ngx_uint_t)s->hls_etime_ms - (ngx_uint_t)s->hls_stime_ms);

    } else {
       
        return buf; 
    }
}


static size_t
ngx_rtmp_log_var_bw_in_video_kb_getlen(ngx_rtmp_session_t *s,
    ngx_rtmp_log_op_t *op)
{
    return NGX_INT64_LEN;
}


static u_char *
ngx_rtmp_log_var_bw_in_video_kb_getdata(ngx_rtmp_session_t *s, u_char *buf,
    ngx_rtmp_log_op_t *op)
{
    ngx_rtmp_live_ctx_t    *ctx;
    uint64_t                value;

    ctx = ngx_rtmp_get_module_ctx(s, ngx_rtmp_live_module);
    if (ctx == NULL || ctx->stream == NULL) {
        value = 0;
    } else {
        value = (uint64_t)((ctx->stream->bw_in_av.v_intl_bw * 8) / 1024);
    }

    return ngx_sprintf(buf, "%uL", value);
}


static size_t
ngx_rtmp_log_var_bw_in_audio_kb_getlen(ngx_rtmp_session_t *s,
    ngx_rtmp_log_op_t *op)
{
    return NGX_INT64_LEN;
}


static u_char *
ngx_rtmp_log_var_bw_in_audio_kb_getdata(ngx_rtmp_session_t *s, u_char *buf,
    ngx_rtmp_log_op_t *op)
{
    ngx_rtmp_live_ctx_t    *ctx;
    uint64_t                value;

    ctx = ngx_rtmp_get_module_ctx(s, ngx_rtmp_live_module);
    if (ctx == NULL || ctx->stream == NULL) {
        value = 0;
    } else {
        value = (uint64_t)((ctx->stream->bw_in_av.a_intl_bw * 8) / 1024);
    }

    return ngx_sprintf(buf, "%uL", value);
}

static size_t
ngx_rtmp_log_var_bw_in_real_kb_getlen(ngx_rtmp_session_t *s,
    ngx_rtmp_log_op_t *op)
{
    return NGX_INT64_LEN;
}

static u_char *
ngx_rtmp_log_var_bw_in_real_kb_getdata(ngx_rtmp_session_t *s, u_char *buf,
    ngx_rtmp_log_op_t *op)
{
    ngx_rtmp_live_ctx_t    *ctx;
    uint64_t                value;

    ctx = ngx_rtmp_get_module_ctx(s, ngx_rtmp_live_module);
    if (ctx == NULL || ctx->stream == NULL) {
        value = 0;
    } else {
        value = ctx->stream->bw_in_av.a_intl_bw + ctx->stream->bw_in_av.v_intl_bw;
        value = (value * 8) / 1024;
    }

    return ngx_sprintf(buf, "%uL", value);
}

static size_t
ngx_rtmp_log_var_bw_in_video_exp_kb_getlen(ngx_rtmp_session_t *s,
    ngx_rtmp_log_op_t *op)
{
    return NGX_INT64_LEN;
}


static u_char *
ngx_rtmp_log_var_bw_in_video_exp_kb_getdata(ngx_rtmp_session_t *s, u_char *buf,
    ngx_rtmp_log_op_t *op)
{
    ngx_rtmp_live_ctx_t    *ctx;
    uint64_t                value;

    ctx = ngx_rtmp_get_module_ctx(s, ngx_rtmp_live_module);
    if (ctx == NULL || ctx->stream == NULL) {
        value = 0;
    } else {
        value = (uint64_t)((ctx->stream->bw_in_av.v_intl_bw_exp * 8) / 1024);
    }

    return ngx_sprintf(buf, "%uL", value);
}


static size_t
ngx_rtmp_log_var_bw_in_audio_exp_kb_getlen(ngx_rtmp_session_t *s,
    ngx_rtmp_log_op_t *op)
{
    return NGX_INT64_LEN;
}


static u_char *
ngx_rtmp_log_var_bw_in_audio_exp_kb_getdata(ngx_rtmp_session_t *s, u_char *buf,
    ngx_rtmp_log_op_t *op)
{
    ngx_rtmp_live_ctx_t    *ctx;
    uint64_t                value;

    ctx = ngx_rtmp_get_module_ctx(s, ngx_rtmp_live_module);
    if (ctx == NULL || ctx->stream == NULL) {
        value = 0;
    } else {
        value = (uint64_t)((ctx->stream->bw_in_av.a_intl_bw_exp * 8) / 1024);
    }

    return ngx_sprintf(buf, "%uL", value);
}


static size_t
ngx_rtmp_log_var_bw_in_exp_kb_getlen(ngx_rtmp_session_t *s,
    ngx_rtmp_log_op_t *op)
{
    return NGX_INT64_LEN;
}


static u_char *
ngx_rtmp_log_var_bw_in_exp_kb_getdata(ngx_rtmp_session_t *s, u_char *buf,
    ngx_rtmp_log_op_t *op)
{
    ngx_rtmp_live_ctx_t    *ctx;
    uint64_t                value;

    ctx = ngx_rtmp_get_module_ctx(s, ngx_rtmp_live_module);
    if (ctx == NULL || ctx->stream == NULL) {
        value = 0;
    } else {
        value = ctx->stream->bw_in_av.a_intl_bw_exp + ctx->stream->bw_in_av.v_intl_bw_exp;
        value = (value * 8) / 1024;
    }

    return ngx_sprintf(buf, "%uL", value);
}


static size_t
ngx_rtmp_log_var_bw_diff_kb_getlen(ngx_rtmp_session_t *s,
    ngx_rtmp_log_op_t *op)
{
    return NGX_INT64_LEN;
}


static u_char *
ngx_rtmp_log_var_bw_diff_kb_getdata(ngx_rtmp_session_t *s, u_char *buf,
    ngx_rtmp_log_op_t *op)
{
    ngx_rtmp_live_ctx_t    *ctx;
    int64_t                 value;

    ctx = ngx_rtmp_get_module_ctx(s, ngx_rtmp_live_module);
    if (ctx == NULL || ctx->stream == NULL) {
        value = 0;
    } else {
        value = (ctx->stream->bw_in_av.a_intl_bw_exp + ctx->stream->bw_in_av.v_intl_bw_exp) -
                (ctx->stream->bw_in_av.a_intl_bw + ctx->stream->bw_in_av.v_intl_bw);
        value = (value * 8) / 1024;
    }

    return ngx_sprintf(buf, "%L", value);
}


static size_t
ngx_rtmp_log_var_bw_total_diff_kb_getlen(ngx_rtmp_session_t *s,
    ngx_rtmp_log_op_t *op)
{
    return NGX_INT64_LEN;
}


static u_char *
ngx_rtmp_log_var_bw_total_diff_kb_getdata(ngx_rtmp_session_t *s, u_char *buf,
    ngx_rtmp_log_op_t *op)
{
    ngx_rtmp_live_ctx_t    *ctx;
    int64_t                 value;

    ctx = ngx_rtmp_get_module_ctx(s, ngx_rtmp_live_module);
    if (ctx == NULL || ctx->stream == NULL) {
        value = 0;
    } else {
        value = ctx->stream->bw_in_av.total_diff_bytes;
        value = (value * 8) / 1024;
    }

    return ngx_sprintf(buf, "%L", value);
}


static size_t
ngx_rtmp_log_var_bw_out_kb_getlen(ngx_rtmp_session_t *s,
    ngx_rtmp_log_op_t *op)
{
    return NGX_INT64_LEN;
}


static u_char *
ngx_rtmp_log_var_bw_out_kb_getdata(ngx_rtmp_session_t *s, u_char *buf,
    ngx_rtmp_log_op_t *op)
{
    ngx_rtmp_live_ctx_t    *ctx;
    uint64_t                value;

    ctx = ngx_rtmp_get_module_ctx(s, ngx_rtmp_live_module);
    if (ctx == NULL) {
        value = 0;
    } else {
        value = (uint64_t)((ctx->bw_out.bandwidth * 8) / 1024);
    }
    return ngx_sprintf(buf, "%uL", value);
}


static size_t
ngx_rtmp_log_var_bw_out_buf_kb_getlen(ngx_rtmp_session_t *s,
    ngx_rtmp_log_op_t *op)
{
    return NGX_INT64_LEN;
}


static u_char *
ngx_rtmp_log_var_bw_out_buf_kb_getdata(ngx_rtmp_session_t *s, u_char *buf,
    ngx_rtmp_log_op_t *op)
{
    ngx_rtmp_live_ctx_t    *ctx;
    size_t                  out_pos;
    ngx_chain_t            *out_chain;
    u_char                 *out_bpos;
    uint64_t                buf_size;

    ctx = ngx_rtmp_get_module_ctx(s, ngx_rtmp_live_module);
    if (ctx == NULL || ctx->stream == NULL) {
        return ngx_sprintf(buf, "%uL", 0);
    }

    out_pos = s->out_pos;
    out_chain = s->out_chain;
    out_bpos = s->out_bpos;

    if (s->out_chain == NULL && s->out_pos != s->out_last) {
        out_chain = s->out[s->out_pos];
        out_bpos = out_chain->buf->pos;
    }

    buf_size = 0;

    while(out_chain) {

        buf_size += (out_chain->buf->last - out_bpos);
        out_chain = out_chain->next;

        if (out_chain == NULL) {

            ++out_pos;
            out_pos %= s->out_queue;
            if (out_pos == s->out_last) {
                break;
            }
            out_chain = s->out[out_pos];
        }

        out_bpos = out_chain->buf->pos;
    }

    return ngx_sprintf(buf, "%uL", (uint64_t)((buf_size * 8) / 1024));
}


static size_t
ngx_rtmp_log_var_last_av_ts_diff_getlen(ngx_rtmp_session_t *s,
    ngx_rtmp_log_op_t *op)
{
    return NGX_INT64_LEN;
}


static u_char *
ngx_rtmp_log_var_last_av_ts_diff_getdata(ngx_rtmp_session_t *s, u_char *buf,
    ngx_rtmp_log_op_t *op)
{
    if (s->last_video_ts == NGX_RTMP_INVALID_TIMESTAMP
            || s->last_audio_ts == NGX_RTMP_INVALID_TIMESTAMP) {
        return ngx_sprintf(buf, "%L", -1);
    }

    return ngx_sprintf(buf, "%L",
        (int64_t)s->last_video_ts - (int64_t)s->last_audio_ts);
}

static size_t
ngx_rtmp_log_var_audio_ts_diff_getlen(ngx_rtmp_session_t *s,
    ngx_rtmp_log_op_t *op)
{
    return NGX_INT64_LEN;
}

static u_char *
ngx_rtmp_log_var_audio_ts_diff_getdata(ngx_rtmp_session_t *s, u_char *buf,
    ngx_rtmp_log_op_t *op)
{
    if (s->audio_ts_max == NGX_RTMP_INVALID_TIMESTAMP
            || s->audio_ts_min == NGX_RTMP_INVALID_TIMESTAMP) {
        return ngx_sprintf(buf, "%L", -1);
    }

    return ngx_sprintf(buf, "%L",
        (int64_t)s->audio_ts_max - (int64_t)s->audio_ts_min);
}

static size_t
ngx_rtmp_log_var_video_ts_diff_getlen(ngx_rtmp_session_t *s,
    ngx_rtmp_log_op_t *op)
{
    return NGX_INT64_LEN;
}

static u_char *
ngx_rtmp_log_var_video_ts_diff_getdata(ngx_rtmp_session_t *s, u_char *buf,
    ngx_rtmp_log_op_t *op)
{
    if (s->video_ts_max == NGX_RTMP_INVALID_TIMESTAMP
            || s->video_ts_min == NGX_RTMP_INVALID_TIMESTAMP) {
        return ngx_sprintf(buf, "%L", -1);
    }

    return ngx_sprintf(buf, "%L",
        (int64_t)s->video_ts_max - (int64_t)s->video_ts_min);
}

static size_t
ngx_rtmp_log_var_ret_code_getlen(ngx_rtmp_session_t *s,
    ngx_rtmp_log_op_t *op)
{
    ngx_rtmp_netcall_ctx_t   *ctx;

    ctx = ngx_rtmp_get_module_ctx(s, ngx_rtmp_netcall_module);

    return ctx ? ngx_strlen(ctx->ret_code) : 0;
}


static u_char *
ngx_rtmp_log_var_ret_code_getdata(ngx_rtmp_session_t *s, u_char *buf,
    ngx_rtmp_log_op_t *op)
{
    ngx_rtmp_netcall_ctx_t   *ctx;

    ctx = ngx_rtmp_get_module_ctx(s, ngx_rtmp_netcall_module);

    return ctx ? ngx_cpymem(buf, ctx->ret_code, ngx_strlen(ctx->ret_code)) : buf;
}


static size_t
ngx_rtmp_log_var_status_code_getlen(ngx_rtmp_session_t *s,
    ngx_rtmp_log_op_t *op)
{
    return NGX_INT_T_LEN;
}


static u_char *
ngx_rtmp_log_var_status_code_getdata(ngx_rtmp_session_t *s, u_char *buf,
    ngx_rtmp_log_op_t *op)
{
    return ngx_sprintf(buf, "%i", s->status_code);
}


static size_t
ngx_rtmp_log_var_description_getlen(ngx_rtmp_session_t *s,
    ngx_rtmp_log_op_t *op)
{
    ngx_rtmp_netcall_ctx_t   *ctx;

    ctx = ngx_rtmp_get_module_ctx(s, ngx_rtmp_netcall_module);

    return ctx ? ngx_strlen(ctx->description) : 0;
}


static u_char *
ngx_rtmp_log_var_description_getdata(ngx_rtmp_session_t *s, u_char *buf,
    ngx_rtmp_log_op_t *op)
{
    ngx_rtmp_netcall_ctx_t   *ctx;

    ctx = ngx_rtmp_get_module_ctx(s, ngx_rtmp_netcall_module);

    return ctx ? ngx_cpymem(buf, ctx->description, ngx_strlen(ctx->description)) : buf;
}


static size_t
ngx_rtmp_log_var_msec_getlen(ngx_rtmp_session_t *s,
    ngx_rtmp_log_op_t *op)
{
    return NGX_TIME_T_LEN + 4;
}


static u_char *
ngx_rtmp_log_var_msec_getdata(ngx_rtmp_session_t *s, u_char *buf,
    ngx_rtmp_log_op_t *op)
{
    ngx_time_t  *tp;

    tp = ngx_timeofday();
    
    return ngx_sprintf(buf, "%T.%03M", tp->sec, tp->msec);
}


static size_t
ngx_rtmp_log_var_session_string_getlen(ngx_rtmp_session_t *s,
    ngx_rtmp_log_op_t *op)
{
    return ((ngx_str_t *) ((u_char *) s + op->offset))->len;
}


static u_char *
ngx_rtmp_log_var_session_string_getdata(ngx_rtmp_session_t *s, u_char *buf,
    ngx_rtmp_log_op_t *op)
{
    ngx_str_t  *str;

    str = (ngx_str_t *) ((u_char *) s + op->offset);

    return ngx_cpymem(buf, str->data, str->len);
}


static size_t
ngx_rtmp_log_var_session_cstring_getlen(ngx_rtmp_session_t *s,
    ngx_rtmp_log_op_t *op)
{
    return NGX_RTMP_MAX_BUF_SIZE;
}


static u_char *
ngx_rtmp_log_var_session_cstring_getdata(ngx_rtmp_session_t *s, u_char *buf,
    ngx_rtmp_log_op_t *op)
{
    u_char             *p;

    p = (u_char *) s + op->offset;
    while (*p) {
        *buf++ = *p++;
    }

    return buf;
}


static size_t
ngx_rtmp_log_var_command_getlen(ngx_rtmp_session_t *s,
    ngx_rtmp_log_op_t *op)
{
    return sizeof("PLAY+PUBLISH") - 1;
}


static u_char *
ngx_rtmp_log_var_command_getdata(ngx_rtmp_session_t *s, u_char *buf,
    ngx_rtmp_log_op_t *op)
{
    ngx_rtmp_log_ctx_t *ctx;
    ngx_str_t          *cmd;
    ngx_uint_t          n;

    static ngx_str_t    commands[] = {
        ngx_string("NONE"),
        ngx_string("PLAY"),
        ngx_string("PUBLISH"),
        ngx_string("PLAY+PUBLISH")
    };

    ctx = ngx_rtmp_get_module_ctx(s, ngx_rtmp_log_module);

    n = ctx ? (ctx->play + ctx->publish * 2) : 0;

    cmd = &commands[n];

    return ngx_cpymem(buf, cmd->data, cmd->len);
}


static size_t
ngx_rtmp_log_var_context_cstring_getlen(ngx_rtmp_session_t *s,
    ngx_rtmp_log_op_t *op)
{
    return ngx_max(NGX_RTMP_MAX_NAME, NGX_RTMP_MAX_ARGS);
}

static u_char *
ngx_rtmp_log_var_context_cstring_getdata(ngx_rtmp_session_t *s, u_char *buf,
    ngx_rtmp_log_op_t *op)
{
    ngx_rtmp_log_ctx_t *ctx;
    u_char             *p;

    ctx = ngx_rtmp_get_module_ctx(s, ngx_rtmp_log_module);
    if (ctx == NULL) {
        return buf;
    }

    p = (u_char *) ctx + op->offset;
    while (*p) {
        *buf++ = *p++;
    }

    return buf;
}

static u_char *
ngx_rtmp_log_var_context_cstring2_getdata(ngx_rtmp_session_t *s, u_char *buf,
    ngx_rtmp_log_op_t *op)
{
    ngx_rtmp_log_ctx_t *ctx;
    u_char             *p;

    ctx = ngx_rtmp_get_module_ctx(s, ngx_rtmp_log_module);
    if (ctx == NULL) {
        return buf;
    }

    p = (u_char *) ctx + op->offset;
    if (!ngx_strlen(p)) {

        return ngx_cpymem(buf, "-", 1); 
    }

    while (*p) {
        *buf++ = *p++;
    }

    return buf;
}


static size_t
ngx_rtmp_log_var_context_uint32_getlen(ngx_rtmp_session_t *s,
    ngx_rtmp_log_op_t *op)
{
    return NGX_INT32_LEN;
}


static u_char *
ngx_rtmp_log_var_context_uint32_getdata(ngx_rtmp_session_t *s, u_char *buf,
    ngx_rtmp_log_op_t *op)
{
    ngx_rtmp_log_ctx_t *ctx;
    uint32_t           *v;

    ctx = ngx_rtmp_get_module_ctx(s, ngx_rtmp_log_module);
    if (ctx == NULL) {
        return buf;
    }

    v = (uint32_t *) ((uint8_t *) ctx + op->offset);

    return ngx_sprintf(buf, "%uD", *v);
}


static size_t
ngx_rtmp_log_var_session_uint32_getlen(ngx_rtmp_session_t *s,
    ngx_rtmp_log_op_t *op)
{
    return NGX_INT32_LEN;
}


static u_char *
ngx_rtmp_log_var_session_uint32_getdata(ngx_rtmp_session_t *s, u_char *buf,
    ngx_rtmp_log_op_t *op)
{
    uint32_t   *v;

    v = (uint32_t *) ((uint8_t *) s + op->offset);

    return ngx_sprintf(buf, "%uD", *v);
}


static size_t
ngx_rtmp_log_var_session_uint_getlen(ngx_rtmp_session_t *s,
    ngx_rtmp_log_op_t *op)
{
    return NGX_INT32_LEN;
}


static u_char *
ngx_rtmp_log_var_session_uint_getdata(ngx_rtmp_session_t *s, u_char *buf,
    ngx_rtmp_log_op_t *op)
{
    ngx_uint_t   *v;

    v = (ngx_uint_t *) ((uint8_t *) s + op->offset);

    return ngx_sprintf(buf, "%ui", *v);
}

static size_t
ngx_rtmp_log_var_session_ts_getlen(ngx_rtmp_session_t *s,
    ngx_rtmp_log_op_t *op)
{
    return NGX_INT64_LEN;
}

static u_char *
ngx_rtmp_log_var_session_ts_getdata(ngx_rtmp_session_t *s, u_char *buf,
    ngx_rtmp_log_op_t *op)
{
    ngx_uint_t   *v;
    u_char       *p;

    v = (ngx_uint_t *) ((uint8_t *) s + op->offset);

    if (*v == NGX_RTMP_INVALID_TIMESTAMP) {
        p = ngx_sprintf(buf, "%i", -1);
    } else {
        p = ngx_sprintf(buf, "%ui", *v);
    }

    return p;
}

static size_t
ngx_rtmp_log_var_session_cts_getlen(ngx_rtmp_session_t *s,
    ngx_rtmp_log_op_t *op)
{
    return NGX_INT32_LEN;
}

static u_char *
ngx_rtmp_log_var_session_cts_getdata(ngx_rtmp_session_t *s, u_char *buf,
    ngx_rtmp_log_op_t *op)
{
    ngx_int_t   *v;
    u_char       *p;

    v = (ngx_int_t *) ((int8_t *) s + op->offset);

    if (*v == NGX_RTMP_INVALID_CTS_TIMESTAMP) {
        p = ngx_sprintf(buf, "%i", 0);
    } else {
        p = ngx_sprintf(buf, "%i", *v);
    }

    return p;
}

static size_t
ngx_rtmp_log_var_time_local_getlen(ngx_rtmp_session_t *s,
    ngx_rtmp_log_op_t *op)
{
    return ngx_cached_http_log_time.len;
}


static u_char *
ngx_rtmp_log_var_time_local_getdata(ngx_rtmp_session_t *s, u_char *buf,
    ngx_rtmp_log_op_t *op)
{
    return ngx_cpymem(buf, ngx_cached_http_log_time.data,
                      ngx_cached_http_log_time.len);
}


static size_t
ngx_rtmp_log_var_session_time_getlen(ngx_rtmp_session_t *s,
    ngx_rtmp_log_op_t *op)
{
    return NGX_INT64_LEN;
}


static u_char *
ngx_rtmp_log_var_session_time_getdata(ngx_rtmp_session_t *s, u_char *buf,
    ngx_rtmp_log_op_t *op)
{
    return ngx_sprintf(buf, "%L",
                       (int64_t) (ngx_current_msec - s->epoch) / 1000);
}


static size_t
ngx_rtmp_log_var_session_readable_time_getlen(ngx_rtmp_session_t *s,
    ngx_rtmp_log_op_t *op)
{
    return NGX_INT_T_LEN + sizeof("d 23h 59m 59s") - 1;
}


static u_char *
ngx_rtmp_log_var_session_readable_time_getdata(ngx_rtmp_session_t *s,
    u_char *buf, ngx_rtmp_log_op_t *op)
{
    int64_t     v;
    ngx_uint_t  days, hours, minutes, seconds;

    v = (ngx_current_msec - s->epoch) / 1000;

    days = (ngx_uint_t) (v / (60 * 60 * 24));
    hours = (ngx_uint_t) (v / (60 * 60) % 24);
    minutes = (ngx_uint_t) (v / 60 % 60);
    seconds = (ngx_uint_t) (v % 60);

    if (days) {
        buf = ngx_sprintf(buf, "%uid ", days);
    }

    if (days || hours) {
        buf = ngx_sprintf(buf, "%uih ", hours);
    }

    if (days || hours || minutes) {
        buf = ngx_sprintf(buf, "%uim ", minutes);
    }

    buf = ngx_sprintf(buf, "%uis", seconds);

    return buf;
}


static ngx_rtmp_codec_ctx_t *
ngx_rtmp_log_get_codec_ctx(ngx_rtmp_session_t *s)
{
    ngx_rtmp_live_ctx_t     *ctx, *pctx;

    ctx = ngx_rtmp_get_module_ctx(s, ngx_rtmp_live_module);
    if (ctx == NULL){
        return NULL;
    }

    if (ctx->publishing) {
        pctx = ctx;
    } else {
        if (NULL == ctx->stream) {
            return NULL;
        }

        for(pctx = ctx->stream->ctx; pctx; pctx = pctx->next) {
            if (pctx->publishing) {
                break;
            }
        }
    }

    if (!pctx) {
        return NULL;
    }

    return ngx_rtmp_get_module_ctx(pctx->session, ngx_rtmp_codec_module);
}

static ngx_rtmp_log_var_t ngx_rtmp_log_vars[] = {
    { ngx_string("cid"),
      ngx_rtmp_log_var_cid_getlen,
      ngx_rtmp_log_var_cid_getdata,
      0 },

    { ngx_string("lid"),
      ngx_rtmp_log_var_lid_getlen,
      ngx_rtmp_log_var_lid_getdata,
      0 },

    { ngx_string("pid"),
      ngx_rtmp_log_var_pid_getlen,
      ngx_rtmp_log_var_pid_getdata,
      0 },

    { ngx_string("sid"),
      ngx_rtmp_log_var_session_sid_getlen,
      ngx_rtmp_log_var_session_sid_getdata,
      0 },

    { ngx_string("slot"),
      ngx_rtmp_log_var_slot_getlen,
      ngx_rtmp_log_var_slot_getdata,
      0 },

    { ngx_string("unique_name"),
      ngx_rtmp_log_var_unique_name_getlen,
      ngx_rtmp_log_var_unique_name_getdata,
      0 },

    { ngx_string("vhost"),
      ngx_rtmp_log_var_session_string_getlen,
      ngx_rtmp_log_var_session_string_getdata,
      offsetof(ngx_rtmp_session_t, host_in) },

    { ngx_string("app"),
      ngx_rtmp_log_var_session_string_getlen,
      ngx_rtmp_log_var_session_string_getdata,
      offsetof(ngx_rtmp_session_t, app) },

    { ngx_string("name"),
      ngx_rtmp_log_var_context_cstring_getlen,
      ngx_rtmp_log_var_context_cstring_getdata,
      offsetof(ngx_rtmp_log_ctx_t, name) },

    { ngx_string("sname"),
      ngx_rtmp_log_var_context_cstring_getlen,
      ngx_rtmp_log_var_context_cstring2_getdata,
      offsetof(ngx_rtmp_log_ctx_t, name) },

    { ngx_string("remote_addr"),
      ngx_rtmp_log_var_remote_addr_getlen,
      ngx_rtmp_log_var_remote_addr_getdata,
      0 },

    { ngx_string("remote_port"),
      ngx_rtmp_log_var_remote_port_getlen,
      ngx_rtmp_log_var_remote_port_getdata,
      0 },

    { ngx_string("rtype"),
      ngx_rtmp_log_var_session_uint_getlen,
      ngx_rtmp_log_var_session_uint_getdata,
      offsetof(ngx_rtmp_session_t, relay_type) },

    { ngx_string("protocol"),
      ngx_rtmp_log_var_session_uint_getlen,
      ngx_rtmp_log_var_session_uint_getdata,
      offsetof(ngx_rtmp_session_t, protocol) },

    { ngx_string("event"),
      ngx_rtmp_log_var_context_uint32_getlen,
      ngx_rtmp_log_var_context_uint32_getdata,
      offsetof(ngx_rtmp_log_ctx_t, event) },

    { ngx_string("ntype"),
      ngx_rtmp_log_var_ntype_getlen,
      ngx_rtmp_log_var_ntype_getdata,
      0 },

    { ngx_string("notify_stime_ms"),
      ngx_rtmp_log_var_notify_stime_ms_getlen,
      ngx_rtmp_log_var_notify_stime_ms_getdata,
      0 },

    { ngx_string("notify_etime_ms"),
      ngx_rtmp_log_var_notify_etime_ms_getlen,
      ngx_rtmp_log_var_notify_etime_ms_getdata,
      0 },

    { ngx_string("notify_diff_ms"),
      ngx_rtmp_log_var_notify_diff_ms_getlen,
      ngx_rtmp_log_var_notify_diff_ms_getdata,
      0 },

    { ngx_string("hls_stime_ms"),
      ngx_rtmp_log_var_hls_stime_ms_getlen,
      ngx_rtmp_log_var_hls_stime_ms_getdata,
      offsetof(ngx_rtmp_session_t, hls_stime_ms) },

    { ngx_string("hls_etime_ms"),
      ngx_rtmp_log_var_hls_etime_ms_getlen,
      ngx_rtmp_log_var_hls_etime_ms_getdata,
      offsetof(ngx_rtmp_session_t, hls_etime_ms) },

    { ngx_string("hls_diff_ms"),
      ngx_rtmp_log_var_hls_diff_ms_getlen,
      ngx_rtmp_log_var_hls_diff_ms_getdata,
      0 },

    { ngx_string("notify_result"),
      ngx_rtmp_log_var_notify_result_getlen,
      ngx_rtmp_log_var_notify_result_getdata,
      0 },

    { ngx_string("bw_in_video_kb"),
      ngx_rtmp_log_var_bw_in_video_kb_getlen,
      ngx_rtmp_log_var_bw_in_video_kb_getdata,
      0 },

    { ngx_string("bw_in_audio_kb"),
      ngx_rtmp_log_var_bw_in_audio_kb_getlen,
      ngx_rtmp_log_var_bw_in_audio_kb_getdata,
      0 },

    { ngx_string("bw_in_real_kb"),
      ngx_rtmp_log_var_bw_in_real_kb_getlen,
      ngx_rtmp_log_var_bw_in_real_kb_getdata,
      0 },

    { ngx_string("bw_in_video_exp_kb"),
      ngx_rtmp_log_var_bw_in_video_exp_kb_getlen,
      ngx_rtmp_log_var_bw_in_video_exp_kb_getdata,
      0 },

    { ngx_string("bw_in_audio_exp_kb"),
      ngx_rtmp_log_var_bw_in_audio_exp_kb_getlen,
      ngx_rtmp_log_var_bw_in_audio_exp_kb_getdata,
      0 },

    { ngx_string("bw_in_exp_kb"),
      ngx_rtmp_log_var_bw_in_exp_kb_getlen,
      ngx_rtmp_log_var_bw_in_exp_kb_getdata,
      0 },

    { ngx_string("bw_in_diff_kb"),
      ngx_rtmp_log_var_bw_diff_kb_getlen,
      ngx_rtmp_log_var_bw_diff_kb_getdata,
      0 },

    { ngx_string("bw_in_total_diff_kb"),
      ngx_rtmp_log_var_bw_total_diff_kb_getlen,
      ngx_rtmp_log_var_bw_total_diff_kb_getdata,
      0 },

    { ngx_string("bw_out_kb"),
      ngx_rtmp_log_var_bw_out_kb_getlen,
      ngx_rtmp_log_var_bw_out_kb_getdata,
      0 },

    { ngx_string("bw_out_buf_kb"),
      ngx_rtmp_log_var_bw_out_buf_kb_getlen,
      ngx_rtmp_log_var_bw_out_buf_kb_getdata,
      0 },

    { ngx_string("last_audio_ts"),
      ngx_rtmp_log_var_session_ts_getlen,
      ngx_rtmp_log_var_session_ts_getdata,
      offsetof(ngx_rtmp_session_t, last_audio_ts) },

    { ngx_string("last_video_ts"),
      ngx_rtmp_log_var_session_ts_getlen,
      ngx_rtmp_log_var_session_ts_getdata,
      offsetof(ngx_rtmp_session_t, last_video_ts) },

    { ngx_string("last_video_cts"),
      ngx_rtmp_log_var_session_cts_getlen,
      ngx_rtmp_log_var_session_cts_getdata,
      offsetof(ngx_rtmp_session_t, last_video_cts) },

    { ngx_string("last_av_ts_diff"),
      ngx_rtmp_log_var_last_av_ts_diff_getlen,
      ngx_rtmp_log_var_last_av_ts_diff_getdata,
      0 },

    { ngx_string("audio_ts_min"),
      ngx_rtmp_log_var_session_ts_getlen,
      ngx_rtmp_log_var_session_ts_getdata,
      offsetof(ngx_rtmp_session_t, audio_ts_min) },

    { ngx_string("audio_ts_max"),
      ngx_rtmp_log_var_session_ts_getlen,
      ngx_rtmp_log_var_session_ts_getdata,
      offsetof(ngx_rtmp_session_t, audio_ts_max) },

    { ngx_string("audio_ts_diff"),
      ngx_rtmp_log_var_audio_ts_diff_getlen,
      ngx_rtmp_log_var_audio_ts_diff_getdata,
      0 },

    { ngx_string("video_ts_min"),
      ngx_rtmp_log_var_session_ts_getlen,
      ngx_rtmp_log_var_session_ts_getdata,
      offsetof(ngx_rtmp_session_t, video_ts_min) },

    { ngx_string("video_ts_max"),
      ngx_rtmp_log_var_session_ts_getlen,
      ngx_rtmp_log_var_session_ts_getdata,
      offsetof(ngx_rtmp_session_t, video_ts_max) },

    { ngx_string("video_ts_diff"),
      ngx_rtmp_log_var_video_ts_diff_getlen,
      ngx_rtmp_log_var_video_ts_diff_getdata,
      0 },

    { ngx_string("ret_code"),
       ngx_rtmp_log_var_ret_code_getlen,
       ngx_rtmp_log_var_ret_code_getdata,
     0 },

    { ngx_string("status_code"),
       ngx_rtmp_log_var_status_code_getlen,
       ngx_rtmp_log_var_status_code_getdata,
     0 },

    { ngx_string("description"),
       ngx_rtmp_log_var_description_getlen,
       ngx_rtmp_log_var_description_getdata,
     0 },

    { ngx_string("rtmp_stage"),
      ngx_rtmp_log_var_session_uint_getlen,
      ngx_rtmp_log_var_session_uint_getdata,
      offsetof(ngx_rtmp_session_t, hs_stage) },

    { ngx_string("rtmp_args"),
      ngx_rtmp_log_var_session_cstring_getlen,
      ngx_rtmp_log_var_session_cstring_getdata,
      offsetof(ngx_rtmp_session_t, log_buf) },

    { ngx_string("connection"),
      ngx_rtmp_log_var_connection_getlen,
      ngx_rtmp_log_var_connection_getdata,
      0 },

    { ngx_string("flashver"),
      ngx_rtmp_log_var_session_string_getlen,
      ngx_rtmp_log_var_session_string_getdata,
      offsetof(ngx_rtmp_session_t, flashver) },

    { ngx_string("swfurl"),
      ngx_rtmp_log_var_session_string_getlen,
      ngx_rtmp_log_var_session_string_getdata,
      offsetof(ngx_rtmp_session_t, swf_url) },

    { ngx_string("tcurl"),
      ngx_rtmp_log_var_session_string_getlen,
      ngx_rtmp_log_var_session_string_getdata,
      offsetof(ngx_rtmp_session_t, tc_url) },

    { ngx_string("pageurl"),
      ngx_rtmp_log_var_session_string_getlen,
      ngx_rtmp_log_var_session_string_getdata,
      offsetof(ngx_rtmp_session_t, page_url) },
      
    { ngx_string("hls_name"),
      ngx_rtmp_log_var_session_string_getlen,
      ngx_rtmp_log_var_session_string_getdata,
      offsetof(ngx_rtmp_session_t, hls_name) },

    { ngx_string("command"),
      ngx_rtmp_log_var_command_getlen,
      ngx_rtmp_log_var_command_getdata,
      0 },

    { ngx_string("args"),
      ngx_rtmp_log_var_context_cstring_getlen,
      ngx_rtmp_log_var_context_cstring_getdata,
      offsetof(ngx_rtmp_log_ctx_t, args) },

    { ngx_string("bytes_sent"),
      ngx_rtmp_log_var_session_uint32_getlen,
      ngx_rtmp_log_var_session_uint32_getdata,
      offsetof(ngx_rtmp_session_t, out_bytes) },

    { ngx_string("bytes_received"),
      ngx_rtmp_log_var_session_uint32_getlen,
      ngx_rtmp_log_var_session_uint32_getdata,
      offsetof(ngx_rtmp_session_t, in_bytes) },

    { ngx_string("time_local"),
      ngx_rtmp_log_var_time_local_getlen,
      ngx_rtmp_log_var_time_local_getdata,
      0 },

    { ngx_string("msec"),
      ngx_rtmp_log_var_msec_getlen,
      ngx_rtmp_log_var_msec_getdata,
      0 },

    { ngx_string("session_time"),
      ngx_rtmp_log_var_session_time_getlen,
      ngx_rtmp_log_var_session_time_getdata,
      0 },

    { ngx_string("session_readable_time"),
      ngx_rtmp_log_var_session_readable_time_getlen,
      ngx_rtmp_log_var_session_readable_time_getdata,
      0 },

    { ngx_string("tcurl"),
      ngx_rtmp_log_var_tcurl_getlen,
      ngx_rtmp_log_var_tcurl_getdata,
      0 },

    { ngx_string("connect_time"),
      ngx_rtmp_log_var_connect_time_getlen,
      ngx_rtmp_log_var_connect_time_getdata,
      0 },

    { ngx_string("log_version"),
      ngx_rtmp_log_var_log_version_string_getlen,
      ngx_rtmp_log_var_log_version_string_getdata,
      0 },
 
    { ngx_string("product_info"),
      ngx_rtmp_log_var_product_info_string_getlen,
      ngx_rtmp_log_var_product_info_string_getdata,
      0 },
 
    { ngx_string("hostname"),
      ngx_rtmp_log_var_hostname_string_getlen,
      ngx_rtmp_log_var_hostname_string_getdata,
      0 },
 
    { ngx_string("log_time"),
      ngx_rtmp_log_var_log_time_ms_getlen,
      ngx_rtmp_log_var_log_time_ms_getdata,
      offsetof(ngx_rtmp_session_t, log_time) },
 
    { ngx_string("refer"),
      ngx_rtmp_log_var_refer_string_getlen,
      ngx_rtmp_log_var_refer_string_getdata,
      offsetof(ngx_rtmp_session_t, refer_in) },
 
    { ngx_string("bw_in_bytes"),
      ngx_rtmp_log_var_bw_in_bytes_getlen,
      ngx_rtmp_log_var_bw_in_bytes_getdata,
      0 },
 
    { ngx_string("bw_out_bytes"),
      ngx_rtmp_log_var_bw_out_bytes_getlen,
      ngx_rtmp_log_var_bw_out_bytes_getdata,
      0 },
     
    { ngx_string("curfps"),
      ngx_rtmp_log_var_curfps_uint_getlen,
      ngx_rtmp_log_var_curfps_uint_getdata,
      0 },
 
    { ngx_string("start_time"),
      ngx_rtmp_log_var_start_time_ms_getlen,
      ngx_rtmp_log_var_start_time_ms_getdata,
      offsetof(ngx_rtmp_session_t, epoch) },
 
    { ngx_string("end_time"),
      ngx_rtmp_log_var_end_time_ms_getlen,
      ngx_rtmp_log_var_end_time_ms_getdata,
      offsetof(ngx_rtmp_session_t, end_time) },
     
    { ngx_string("stream_stat"),
      ngx_rtmp_log_var_stream_stat_uint_getlen,
      ngx_rtmp_log_var_stream_stat_uint_getdata,
      offsetof(ngx_rtmp_session_t, stream_stat) },
 
    { ngx_string("extend1"),
      ngx_rtmp_log_var_extend1_string_getlen,
      ngx_rtmp_log_var_extend1_string_getdata,
      0 },
 
    { ngx_string("extend2"),
      ngx_rtmp_log_var_extend2_string_getlen,
      ngx_rtmp_log_var_extend2_string_getdata,
      0 },
 
    { ngx_string("extend3"),
      ngx_rtmp_log_var_extend3_string_getlen,
      ngx_rtmp_log_var_extend3_string_getdata,
      0 },
 
    { ngx_string("extend4"),
      ngx_rtmp_log_var_extend4_string_getlen,
      ngx_rtmp_log_var_extend4_string_getdata,
      0 },
 
    { ngx_string("extend5"),
      ngx_rtmp_log_var_extend5_string_getlen,
	
      ngx_rtmp_log_var_extend5_string_getdata,
      0 },

    { ngx_string("online_players"),
      ngx_rtmp_log_var_online_players_getlen,
      ngx_rtmp_log_var_online_players_getdata,
      0 },

	{ ngx_string("finalize_code"),
	  ngx_rtmp_log_var_session_uint32_getlen,
	  ngx_rtmp_log_var_session_uint32_getdata,
	  offsetof(ngx_rtmp_session_t, finalize_code) },

	{ ngx_string("finalize_desc"),
	  ngx_rtmp_log_var_finalize_desc_getlen,
	  ngx_rtmp_log_var_finalize_desc_getdata,
	  0 },

    { ngx_string("stream_duration_sec"),
      ngx_rtmp_log_var_stream_duration_sec_getlen,
      ngx_rtmp_log_var_stream_duration_sec_getdata,
      0 },

    { ngx_null_string, NULL, NULL, 0 }
};


static void *
ngx_rtmp_log_create_main_conf(ngx_conf_t *cf)
{
    ngx_rtmp_log_main_conf_t   *lmcf;
    ngx_rtmp_log_fmt_t         *fmt;

    lmcf = ngx_pcalloc(cf->pool, sizeof(ngx_rtmp_log_main_conf_t));
    if (lmcf == NULL) {
        return NULL;
    }

    if (ngx_array_init(&lmcf->formats, cf->pool, 4, sizeof(ngx_rtmp_log_fmt_t))
            != NGX_OK)
    {
        return NULL;
    }

    fmt = ngx_array_push(&lmcf->formats);
    if (fmt == NULL) {
        return NULL;
    }

    ngx_str_set(&fmt->name, "combined");

    fmt->ops = ngx_array_create(cf->pool, 16, sizeof(ngx_rtmp_log_op_t));
    if (fmt->ops == NULL) {
        return NULL;
    }

    lmcf->flux_interval = NGX_CONF_UNSET_MSEC;

    return lmcf;

}


static char *
ngx_rtmp_log_init_main_conf(ngx_conf_t *cf, void *conf)
{
    ngx_rtmp_log_main_conf_t *lmcf = conf;

    ngx_conf_init_msec_value(lmcf->flux_interval, 60 * 1000 /* default 60s */);

    return NGX_CONF_OK;
}


static void *
ngx_rtmp_log_create_app_conf(ngx_conf_t *cf)
{
    ngx_rtmp_log_app_conf_t *lacf;

    lacf = ngx_pcalloc(cf->pool, sizeof(ngx_rtmp_log_app_conf_t));
    if (lacf == NULL) {
        return NULL;
    }

    lacf->log_sample_interval = NGX_CONF_UNSET_MSEC;

    return lacf;
}


static char *
ngx_rtmp_log_merge_app_conf(ngx_conf_t *cf, void *parent, void *child)
{
    ngx_rtmp_log_app_conf_t    *prev = parent;
    ngx_rtmp_log_app_conf_t    *conf = child;
    ngx_rtmp_log_t             *log;

    ngx_conf_merge_msec_value(conf->log_sample_interval, prev->log_sample_interval, 5000); 
    
    if (conf->logs || conf->off) {
        return NGX_OK;
    }

    conf->logs = prev->logs;
    conf->off = prev->off;

    if (conf->logs || conf->off) {
        return NGX_OK;
    }

    conf->logs = ngx_array_create(cf->pool, 2, sizeof(ngx_rtmp_log_t));
    if (conf->logs == NULL) {
        return NGX_CONF_ERROR;
    }

    log = ngx_array_push(conf->logs);
    if (log == NULL) {
        return NGX_CONF_ERROR;
    }

    log->file = ngx_conf_open_file(cf->cycle, &ngx_rtmp_access_log);
    if (log->file == NULL) {
        return NGX_CONF_ERROR;
    }

    log->disk_full_time = 0;
    log->error_log_time = 0;

    return NGX_CONF_OK;
}


static char *
ngx_rtmp_log_set_log(ngx_conf_t *cf, ngx_command_t *cmd, void *conf)
{
    ngx_rtmp_log_app_conf_t    *lacf = conf;

    ngx_rtmp_log_main_conf_t   *lmcf;
    ngx_rtmp_log_fmt_t         *fmt;
    ngx_rtmp_log_t             *log;
    ngx_str_t                  *value;
    ngx_uint_t                  n, m, i;

    value = cf->args->elts;

    if (ngx_strcmp(value[1].data, "off") == 0) {
        lacf->off = 1;
        return NGX_CONF_OK;
    }

    if (lacf->logs == NULL) {
        lacf->logs = ngx_array_create(cf->pool, 2, sizeof(ngx_rtmp_log_t));
        if (lacf->logs == NULL) {
            return NGX_CONF_ERROR;
        }
    }

    log = ngx_array_push(lacf->logs);
    if (log == NULL) {
        return NGX_CONF_ERROR;
    }

    ngx_memzero(log, sizeof(*log));

    lmcf = ngx_rtmp_conf_get_module_main_conf(cf, ngx_rtmp_log_module);

    log->file = ngx_conf_open_file(cf->cycle, &value[1]);
    if (log->file == NULL) {
        return NGX_CONF_ERROR;
    }

    for (m = 2; m < cf->args->nelts; ++m) {

        fmt = lmcf->formats.elts;
        for (n = 0; n < lmcf->formats.nelts; ++n, ++fmt) {

            if (fmt->name.len == value[m].len &&
                ngx_strncasecmp(fmt->name.data, value[m].data, value[m].len) == 0) {

                for (i = 0; i < NGX_RTMP_LOG_EVENT_MAX; ++i) {

                    if (value[m].len == ngx_strlen(ngx_rtmp_log_standards[i]) &&
                        ngx_strcasecmp(value[m].data, (u_char*)ngx_rtmp_log_standards[i]) == 0) {

                        log->standards[i] = fmt;
                        break;
                    }
                }

                break;
            }
        }
    }

    return NGX_CONF_OK;
}


static char *
ngx_rtmp_log_set_format(ngx_conf_t *cf, ngx_command_t *cmd, void *conf)
{
    ngx_rtmp_log_main_conf_t   *lmcf = conf;
    ngx_rtmp_log_fmt_t         *fmt;
    ngx_str_t                  *value;
    ngx_uint_t                  i;

    value = cf->args->elts;

    if (cf->cmd_type != NGX_RTMP_MAIN_CONF) {
        ngx_conf_log_error(NGX_LOG_WARN, cf, 0,
                           "\"log_format\" directive can only be used on "
                           "\"rtmp\" level");
    }

    fmt = lmcf->formats.elts;
    for (i = 0; i < lmcf->formats.nelts; i++) {
        if (fmt[i].name.len == value[1].len &&
            ngx_strcmp(fmt[i].name.data, value[1].data) == 0)
        {
            ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                               "duplicate \"log_format\" name \"%V\"",
                               &value[1]);
            return NGX_CONF_ERROR;
        }
    }

    fmt = ngx_array_push(&lmcf->formats);
    if (fmt == NULL) {
        return NGX_CONF_ERROR;
    }

    fmt->name = value[1];

    fmt->ops = ngx_array_create(cf->pool, 16, sizeof(ngx_rtmp_log_op_t));
    if (fmt->ops == NULL) {
        return NGX_CONF_ERROR;
    }

    return ngx_rtmp_log_compile_format(cf, fmt->ops, cf->args, 2);
}


static char *
ngx_rtmp_log_compile_format(ngx_conf_t *cf, ngx_array_t *ops, ngx_array_t *args,
                            ngx_uint_t s)
{
    size_t              i, len;
    u_char             *data, *d, c;
    ngx_uint_t          bracket;
    ngx_str_t          *value, var;
    ngx_rtmp_log_op_t  *op;
    ngx_rtmp_log_var_t *v;

    value = args->elts;

    for (; s < args->nelts; ++s) {
        i = 0;

        len = value[s].len;
        d = value[s].data;

        while (i < len) {

            op = ngx_array_push(ops);
            if (op == NULL) {
                return NGX_CONF_ERROR;
            }

            ngx_memzero(op, sizeof(*op));

            data = &d[i];

            if (d[i] == '$') {
                if (++i == len) {
                    goto invalid;
                }

                if (d[i] == '{') {
                    bracket = 1;
                    if (++i == len) {
                        goto invalid;
                    }
                } else {
                    bracket = 0;
                }

                var.data = &d[i];

                for (var.len = 0; i < len; ++i, ++var.len) {
                    c = d[i];

                    if (c == '}' && bracket) {
                        ++i;
                        bracket = 0;
                        break;
                    }

                    if ((c >= 'A' && c <= 'Z') ||
                        (c >= 'a' && c <= 'z') ||
                        (c >= '0' && c <= '9') ||
                        (c == '_'))
                    {
                        continue;
                    }

                    break;
                }

                if (bracket) {
                    ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                                       "missing closing bracket in \"%V\"",
                                       &var);
                    return NGX_CONF_ERROR;
                }

                if (var.len == 0) {
                    goto invalid;
                }

                for (v = ngx_rtmp_log_vars; v->name.len; ++v) {
                    if (v->name.len == var.len &&
                        ngx_strncmp(v->name.data, var.data, var.len) == 0)
                    {
                        op->getlen = v->getlen;
                        op->getdata = v->getdata;
                        op->offset = v->offset;
                        break;
                    }
                }

                if (v->name.len == 0) {
                    ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                                       "unknown variable \"%V\"", &var);
                    return NGX_CONF_ERROR;
                }

                continue;
            }

            ++i;

            while (i < len && d[i] != '$') {
                ++i;
            }

            op->getlen = ngx_rtmp_log_var_default_getlen;
            op->getdata = ngx_rtmp_log_var_default_getdata;

            op->value.len = &d[i] - data;

            op->value.data = ngx_pnalloc(cf->pool, op->value.len);
            if (op->value.data == NULL) {
                return NGX_CONF_ERROR;
            }

            ngx_memcpy(op->value.data, data, op->value.len);
        }
    }

    return NGX_CONF_OK;

invalid:

    ngx_conf_log_error(NGX_LOG_EMERG, cf, 0, "invalid parameter \"%s\"", data);

    return NGX_CONF_ERROR;
}


static void
ngx_rtmp_log_bw_in_timer(ngx_event_t *e)
{
    ngx_rtmp_log_app_conf_t    *lacf;
    ngx_rtmp_log_t             *log;
    ngx_rtmp_log_fmt_t         *fmt;
    ngx_uint_t                  n;
    ngx_rtmp_session_t         *s;
    ngx_rtmp_log_ctx_t         *ctx;

    s = e->data;

    lacf = ngx_rtmp_get_module_app_conf(s, ngx_rtmp_log_module);
    if (lacf == NULL || lacf->off || lacf->logs == NULL) {
        return;
    }

    ctx = ngx_rtmp_get_module_ctx(s, ngx_rtmp_log_module);
    if (ctx == NULL) {
        return;
    }

    e = &ctx->timer;
    e->data = s;
    e->log = s->connection->log;
    e->handler = ngx_rtmp_log_bw_in_timer;

    if (!ctx->timer.timer_set) {

        ngx_add_timer(&ctx->timer, ctx->timer_msec);
    }
    
    ctx->event = NGX_RTMP_LOG_EVENT_BW_IN;
    log = lacf->logs->elts;
    for (n = 0; n < lacf->logs->nelts; ++n, ++log) {

        fmt = log->standards[NGX_RTMP_LOG_EVENT_BW_IN];
        if (fmt) {
            ngx_rtmp_log_write(s, log, fmt);
        }
    }
    
    s->last_audio_ts = NGX_RTMP_INVALID_TIMESTAMP;
    s->last_video_ts = NGX_RTMP_INVALID_TIMESTAMP;
    s->audio_ts_min = NGX_RTMP_INVALID_TIMESTAMP;
    s->audio_ts_max = NGX_RTMP_INVALID_TIMESTAMP;
    s->video_ts_min = NGX_RTMP_INVALID_TIMESTAMP;
    s->video_ts_max = NGX_RTMP_INVALID_TIMESTAMP;
}


static void
ngx_rtmp_log_bw_out_timer(ngx_event_t *e)
{
    ngx_rtmp_log_app_conf_t    *lacf;
    ngx_rtmp_log_t             *log;
    ngx_rtmp_log_fmt_t         *fmt;
    ngx_uint_t                  n;
    ngx_rtmp_session_t         *s;
    ngx_rtmp_log_ctx_t         *ctx;

    s = e->data;

    lacf = ngx_rtmp_get_module_app_conf(s, ngx_rtmp_log_module);
    if (lacf == NULL || lacf->off || lacf->logs == NULL) {
        return;
    }

    ctx = ngx_rtmp_get_module_ctx(s, ngx_rtmp_log_module);
    if (ctx == NULL) {
        return;
    }

    e = &ctx->timer;
    e->data = s;
    e->log = s->connection->log;
    e->handler = ngx_rtmp_log_bw_out_timer;

    if (!ctx->timer.timer_set) {

        ngx_add_timer(&ctx->timer, ctx->timer_msec);
    }

    ctx->event = NGX_RTMP_LOG_EVENT_BW_OUT;
    log = lacf->logs->elts;
    for (n = 0; n < lacf->logs->nelts; ++n, ++log) {

        fmt = log->standards[NGX_RTMP_LOG_EVENT_BW_OUT];
        if (fmt) {
            ngx_rtmp_log_write(s, log, fmt);
        }
    }

    s->last_audio_ts = NGX_RTMP_INVALID_TIMESTAMP;
    s->last_video_ts = NGX_RTMP_INVALID_TIMESTAMP;
    s->audio_ts_min = NGX_RTMP_INVALID_TIMESTAMP;
    s->audio_ts_max = NGX_RTMP_INVALID_TIMESTAMP;
    s->video_ts_min = NGX_RTMP_INVALID_TIMESTAMP;
    s->video_ts_max = NGX_RTMP_INVALID_TIMESTAMP;
}


void
ngx_rtmp_log_evt_in(ngx_rtmp_session_t *s)
{
    ngx_rtmp_log_app_conf_t    *lacf;
    ngx_rtmp_log_t             *log;
    ngx_rtmp_log_fmt_t         *fmt;
    ngx_uint_t                  n;
    ngx_rtmp_log_ctx_t         *ctx;

    lacf = ngx_rtmp_get_module_app_conf(s, ngx_rtmp_log_module);
    if (lacf == NULL || lacf->off || lacf->logs == NULL) {
        return;
    }

    ctx = ngx_rtmp_log_pcalloc_ctx(s);
    if (ctx == NULL) {
        return;
    }

    ctx->event = NGX_RTMP_LOG_EVENT_EVT_IN;
    log = lacf->logs->elts;
    for (n = 0; n < lacf->logs->nelts; ++n, ++log) {

        fmt = log->standards[NGX_RTMP_LOG_EVENT_EVT_IN];
        if (fmt) {
            ngx_rtmp_log_write(s, log, fmt);
        }
    }
}


void 
ngx_rtmp_log_evt_out(ngx_rtmp_session_t *s)
{
    ngx_rtmp_log_app_conf_t    *lacf;
    ngx_rtmp_log_t             *log;
    ngx_rtmp_log_fmt_t         *fmt;
    ngx_uint_t                  n;
    ngx_rtmp_log_ctx_t         *ctx;

    lacf = ngx_rtmp_get_module_app_conf(s, ngx_rtmp_log_module);
    if (lacf == NULL || lacf->off || lacf->logs == NULL) {
        return;
    }

    ctx = ngx_rtmp_log_pcalloc_ctx(s);
    if (ctx == NULL) {
        return;
    }
    
    ctx->event = NGX_RTMP_LOG_EVENT_EVT_RTMP_OUT;
    log = lacf->logs->elts;
    for (n = 0; n < lacf->logs->nelts; ++n, ++log) {

        fmt = log->standards[NGX_RTMP_LOG_EVENT_EVT_RTMP_OUT];
        if (fmt) {
            ngx_rtmp_log_write(s, log, fmt);
        }
    }
}


void 
ngx_rtmp_log_evt_hdl_out(ngx_rtmp_session_t *s)
{
    ngx_rtmp_log_app_conf_t    *lacf;
    ngx_rtmp_log_t             *log;
    ngx_rtmp_log_fmt_t         *fmt;
    ngx_uint_t                  n;
    ngx_rtmp_log_ctx_t         *ctx;

    lacf = ngx_rtmp_get_module_app_conf(s, ngx_rtmp_log_module);
    if (lacf == NULL || lacf->off || lacf->logs == NULL) {
        return;
    }

    ctx = ngx_rtmp_log_pcalloc_ctx(s);
    if (ctx == NULL) {
        return;
    }
    
    ctx->event = NGX_RTMP_LOG_EVENT_EVT_HDL_OUT;
    log = lacf->logs->elts;
    for (n = 0; n < lacf->logs->nelts; ++n, ++log) {

        fmt = log->standards[NGX_RTMP_LOG_EVENT_EVT_HDL_OUT];
        if (fmt) {
            ngx_rtmp_log_write(s, log, fmt);
        }
    }
}


void 
ngx_rtmp_log_evt_hls_out(ngx_rtmp_session_t *s)
{
    ngx_rtmp_log_app_conf_t    *lacf;
    ngx_rtmp_log_t             *log;
    ngx_rtmp_log_fmt_t         *fmt;
    ngx_uint_t                  n;
    ngx_rtmp_log_ctx_t         *ctx;

    lacf = ngx_rtmp_get_module_app_conf(s, ngx_rtmp_log_module);
    if (lacf == NULL || lacf->off || lacf->logs == NULL) {
        return;
    }

    ctx = ngx_rtmp_log_pcalloc_ctx(s);
    if (ctx == NULL) {
        return;
    }
    
    ctx->event = NGX_RTMP_LOG_EVENT_EVT_HLS_OUT;
    log = lacf->logs->elts;
    for (n = 0; n < lacf->logs->nelts; ++n, ++log) {

        fmt = log->standards[NGX_RTMP_LOG_EVENT_EVT_HLS_OUT];
        if (fmt) {
            ngx_rtmp_log_write(s, log, fmt);
        }
    }
}


void
ngx_rtmp_log_flux(ngx_rtmp_session_t *s)
{
    ngx_rtmp_log_app_conf_t    *lacf;
    ngx_rtmp_log_t             *log;
    ngx_rtmp_log_fmt_t         *fmt;
    ngx_uint_t                  n;
    ngx_rtmp_log_ctx_t         *ctx;

    lacf = ngx_rtmp_get_module_app_conf(s, ngx_rtmp_log_module);
    if (lacf == NULL || lacf->off || lacf->logs == NULL) {
        return;
    }

    ctx = ngx_rtmp_log_pcalloc_ctx(s);
    if (ctx == NULL) {
        return;
    }
    
    ctx->event = NGX_RTMP_LOG_EVENT_FLUX;
    log = lacf->logs->elts;
    for (n = 0; n < lacf->logs->nelts; ++n, ++log) {

        fmt = log->standards[NGX_RTMP_LOG_EVENT_FLUX];
        if (fmt) {
            ngx_rtmp_log_write(s, log, fmt);
        }
    }
}


static ngx_rtmp_log_ctx_t *
ngx_rtmp_log_pcalloc_ctx(ngx_rtmp_session_t *s)
{
    ngx_rtmp_log_ctx_t         *ctx;
    ngx_rtmp_log_app_conf_t    *lacf;

    lacf = ngx_rtmp_get_module_app_conf(s, ngx_rtmp_log_module);
    if (lacf == NULL){
        return NULL;
    }
    
    ctx = ngx_rtmp_get_module_ctx(s, ngx_rtmp_log_module);
    if (ctx == NULL) {
        ctx = ngx_pcalloc(s->pool, sizeof(ngx_rtmp_log_ctx_t));
        if (ctx == NULL) {
            return NULL;
        }

        ctx->timer_msec = lacf->log_sample_interval;

        ngx_rtmp_set_ctx(s, ctx, ngx_rtmp_log_module);
    }

    return ctx;
}


static ngx_int_t
ngx_rtmp_log_publish(ngx_rtmp_session_t *s, ngx_rtmp_publish_t *v)
{
    ngx_rtmp_log_ctx_t    *ctx;
    ngx_event_t           *e;

    ctx = ngx_rtmp_log_pcalloc_ctx(s);
    if (ctx == NULL) {
        goto next;
    }

    ngx_memcpy(ctx->name, v->name, NGX_RTMP_MAX_NAME);
    ngx_memcpy(ctx->args, v->args, NGX_RTMP_MAX_ARGS);

    if (!ngx_rtmp_push_type((s->protocol))) {

        goto next;
    }

    ctx->publish = 1;

    if (!ctx->timer.timer_set) {

        e = &ctx->timer;
        e->data = s;
        e->log = s->connection->log;
        e->handler = ngx_rtmp_log_bw_in_timer;

        ngx_add_timer(&ctx->timer, ctx->timer_msec);
    }

next:
    return next_publish(s, v);
}


static ngx_int_t
ngx_rtmp_log_play(ngx_rtmp_session_t *s, ngx_rtmp_play_t *v)
{
    ngx_rtmp_log_ctx_t    *ctx;
    ngx_event_t           *e;

    ctx = ngx_rtmp_log_pcalloc_ctx(s);
    if (ctx == NULL) {
        goto next;
    }

    ngx_memcpy(ctx->name, v->name, NGX_RTMP_MAX_NAME);
    ngx_memcpy(ctx->args, v->args, NGX_RTMP_MAX_ARGS);

    if (ngx_hls_pull_type((s->protocol))) {

        goto next;
    }

    ctx->play = 1;

    if (!ctx->timer.timer_set) {

        e = &ctx->timer;
        e->data = s;
        e->log = s->connection->log;
        e->handler = ngx_rtmp_log_bw_out_timer;

        ngx_add_timer(&ctx->timer, ctx->timer_msec);
    }

next:
    return next_play(s, v);
}


static ngx_int_t
ngx_rtmp_log_disconnect(ngx_rtmp_session_t *s)
{
    ngx_rtmp_log_ctx_t    *ctx;

    ctx = ngx_rtmp_get_module_ctx(s, ngx_rtmp_log_module);
    if (ctx == NULL) {
        goto next;
    }

    if (ngx_hls_pull_type((s->protocol))) {

        goto next;
    }

    if (ctx->timer.timer_set) {

        ngx_del_timer(&ctx->timer);
    }

next:
    return next_disconnect(s);
}


static void
ngx_rtmp_log_write(ngx_rtmp_session_t *s, ngx_rtmp_log_t *log, ngx_rtmp_log_fmt_t *fmt)
{
    static u_char buf[NGX_RTMP_MAX_LOG_SIZE];

    ngx_rtmp_log_op_t          *op;
    u_char                     *name, *p;
    time_t                      now;
    ngx_uint_t                  n;
    ssize_t                     nsize;
    size_t                      len;
    int                         err;

    if (ngx_time() == log->disk_full_time) {
        /* FreeBSD full disk protection;
         * nginx http logger does the same */
        return;
    }

    len = 0;
    p = buf;
    ngx_memzero(buf, sizeof(buf));

    op = fmt->ops->elts;
    for (n = 0; n < fmt->ops->nelts; ++n, ++op) {

        p = op->getdata(s, p, op);
    }

    ngx_linefeed(p);

    err = 0;
    len = ngx_strlen(buf);
    name = log->file->name.data;
    nsize = ngx_write_fd(log->file->fd, buf, len);

    if (nsize == (ssize_t) len) {
        return;
    }

    now = ngx_time();

    if (nsize == -1) {
        err = ngx_errno;

        if (err == NGX_ENOSPC) {
            log->disk_full_time = now;
        }

        if (now - log->error_log_time > 59) {
            ngx_log_error(NGX_LOG_ALERT, s->connection->log, err,
                          ngx_write_fd_n " to \"%s\" failed", name);
            log->error_log_time = now;
        }
    }

    if (now - log->error_log_time > 59) {
        ngx_log_error(NGX_LOG_ALERT, s->connection->log, err,
                      ngx_write_fd_n " to \"%s\" was incomplete: %z of %uz",
                      name, nsize, len);
        log->error_log_time = now;
    }
}


static ngx_int_t
ngx_rtmp_log_notify_latency(ngx_rtmp_session_t *s, ngx_rtmp_header_t *h,
    ngx_chain_t *in)
{
    ngx_rtmp_log_app_conf_t    *lacf;
    ngx_rtmp_log_t             *log;
    ngx_rtmp_log_fmt_t         *fmt;
    ngx_uint_t                  n;
    ngx_rtmp_log_ctx_t         *ctx;

    lacf = ngx_rtmp_get_module_app_conf(s, ngx_rtmp_log_module);
    if (lacf == NULL || lacf->off || lacf->logs == NULL) {
        return NGX_OK;
    }

    ctx = ngx_rtmp_get_module_ctx(s, ngx_rtmp_log_module);
    if (ctx == NULL) {
        return NGX_OK;
    }

    ctx->event = NGX_RTMP_LOG_EVENT_NOTIFY_LATENCY;
    log = lacf->logs->elts;
    for (n = 0; n < lacf->logs->nelts; ++n, ++log) {

        fmt = log->standards[NGX_RTMP_LOG_EVENT_NOTIFY_LATENCY];
        if (fmt) {
            ngx_rtmp_log_write(s, log, fmt);
        }
    }

    return NGX_OK;
}


static ngx_int_t
ngx_rtmp_log_postconfiguration(ngx_conf_t *cf)
{
    ngx_rtmp_core_main_conf_t   *cmcf;
    ngx_rtmp_handler_pt         *h;

    cmcf = ngx_rtmp_conf_get_module_main_conf(cf, ngx_rtmp_core_module);

    /* register raw event handlers */

    h = ngx_array_push(&cmcf->events[NGX_RTMP_NOTIFY_LATENCY]);
    *h = ngx_rtmp_log_notify_latency;

    next_disconnect = ngx_rtmp_disconnect;
    ngx_rtmp_disconnect = ngx_rtmp_log_disconnect;

    next_publish = ngx_rtmp_publish;
    ngx_rtmp_publish = ngx_rtmp_log_publish;

    next_play = ngx_rtmp_play;
    ngx_rtmp_play = ngx_rtmp_log_play;

    return NGX_OK;
}
