
/*
 * Copyright (C) Roman Arutyunyan
 */


#include <ngx_config.h>
#include <ngx_core.h>
#include "ngx_rtmp.h"
#include "ngx_rtmp_cmd_module.h"
#include "ngx_rtmp_streams.h"

#define NGX_RTMP_FMS_VERSION        "FMS/3,0,1,123"
#define NGX_RTMP_CAPABILITIES       31


static ngx_int_t ngx_rtmp_cmd_connect(ngx_rtmp_session_t *s,
       ngx_rtmp_connect_t *v);
static ngx_int_t ngx_rtmp_cmd_disconnect(ngx_rtmp_session_t *s);
static ngx_int_t ngx_rtmp_cmd_create_stream(ngx_rtmp_session_t *s,
       ngx_rtmp_create_stream_t *v);
static ngx_int_t ngx_rtmp_cmd_close_stream(ngx_rtmp_session_t *s,
       ngx_rtmp_close_stream_t *v);
static ngx_int_t ngx_rtmp_cmd_delete_stream(ngx_rtmp_session_t *s,
       ngx_rtmp_delete_stream_t *v);
static ngx_int_t ngx_rtmp_cmd_publish(ngx_rtmp_session_t *s,
       ngx_rtmp_publish_t *v);
static ngx_int_t ngx_rtmp_cmd_play(ngx_rtmp_session_t *s,
       ngx_rtmp_play_t *v);
static ngx_int_t ngx_rtmp_cmd_seek(ngx_rtmp_session_t *s,
       ngx_rtmp_seek_t *v);
static ngx_int_t ngx_rtmp_cmd_pause(ngx_rtmp_session_t *s,
       ngx_rtmp_pause_t *v);


static ngx_int_t ngx_rtmp_cmd_stream_begin(ngx_rtmp_session_t *s,
       ngx_rtmp_stream_begin_t *v);
static ngx_int_t ngx_rtmp_cmd_stream_eof(ngx_rtmp_session_t *s,
       ngx_rtmp_stream_eof_t *v);
static ngx_int_t ngx_rtmp_cmd_stream_dry(ngx_rtmp_session_t *s,
       ngx_rtmp_stream_dry_t *v);
static ngx_int_t ngx_rtmp_cmd_recorded(ngx_rtmp_session_t *s,
       ngx_rtmp_recorded_t *v);
static ngx_int_t ngx_rtmp_cmd_set_buflen(ngx_rtmp_session_t *s,
       ngx_rtmp_set_buflen_t *v);


ngx_rtmp_connect_pt         ngx_rtmp_connect;
ngx_rtmp_disconnect_pt      ngx_rtmp_disconnect;
ngx_rtmp_create_stream_pt   ngx_rtmp_create_stream;
ngx_rtmp_close_stream_pt    ngx_rtmp_close_stream;
ngx_rtmp_delete_stream_pt   ngx_rtmp_delete_stream;
ngx_rtmp_publish_pt         ngx_rtmp_publish;
ngx_rtmp_play_pt            ngx_rtmp_play;
ngx_rtmp_seek_pt            ngx_rtmp_seek;
ngx_rtmp_pause_pt           ngx_rtmp_pause;


ngx_rtmp_stream_begin_pt    ngx_rtmp_stream_begin;
ngx_rtmp_stream_eof_pt      ngx_rtmp_stream_eof;
ngx_rtmp_stream_dry_pt      ngx_rtmp_stream_dry;
ngx_rtmp_recorded_pt        ngx_rtmp_recorded;
ngx_rtmp_set_buflen_pt      ngx_rtmp_set_buflen;
ngx_rtmp_start_hls_slice_pt ngx_rtmp_start_hls_slice;


static ngx_int_t ngx_rtmp_cmd_postconfiguration(ngx_conf_t *cf);


static ngx_rtmp_module_t  ngx_rtmp_cmd_module_ctx = {
    NULL,                                   /* preconfiguration */
    ngx_rtmp_cmd_postconfiguration,         /* postconfiguration */
    NULL,                                   /* create main configuration */
    NULL,                                   /* init main configuration */
    NULL,                                   /* create server configuration */
    NULL,                                   /* merge server configuration */
    NULL,                                   /* create app configuration */
    NULL                                    /* merge app configuration */
};


ngx_module_t  ngx_rtmp_cmd_module = {
    NGX_MODULE_V1,
    &ngx_rtmp_cmd_module_ctx,               /* module context */
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


void
ngx_rtmp_cmd_fill_args(u_char name[NGX_RTMP_MAX_NAME],
        u_char args[NGX_RTMP_MAX_ARGS])
{
    u_char      *p;

    p = (u_char *)ngx_strchr(name, '?');
    if (p == NULL) {
        return;
    }

    *p++ = 0;
    ngx_cpystrn(args, p, NGX_RTMP_MAX_ARGS);
}

void
ngx_rtmp_cmd_get_args(ngx_str_t * tc_url,
                      ngx_str_t *args)
{
    u_char      *p;

    p = (u_char *)ngx_strchr(tc_url->data, '?');
    if (p == NULL) {
        return;
    }

    args->len = tc_url->len - (p - tc_url->data + 1);
    args->data = p + 1;
}

void
ngx_rtmp_cmd_fill_vhost(ngx_str_t *tc_url,
                        ngx_str_t *host_in, ngx_int_t *port_in)
{
    ngx_str_t    args;

    ngx_str_null(&args);

    ngx_rtmp_cmd_get_args(tc_url, &args);

    ngx_rtmp_parse_tcurl(args, *tc_url, host_in, port_in);
}

static ngx_int_t
ngx_rtmp_cmd_connect_init(ngx_rtmp_session_t *s, ngx_rtmp_header_t *h,
        ngx_chain_t *in)
{
    static ngx_rtmp_connect_t     v;

    ngx_str_t                     host;
    ngx_int_t                     found; // found host/app style or not.
    u_char                        *p;
    size_t                        len;

    static ngx_rtmp_amf_elt_t  in_cmd[] = {

        { NGX_RTMP_AMF_STRING,
          ngx_string("app"),
          v.app, sizeof(v.app) },

        { NGX_RTMP_AMF_STRING,
          ngx_string("flashVer"),
          v.flashver, sizeof(v.flashver) },

        { NGX_RTMP_AMF_STRING,
          ngx_string("swfUrl"),
          v.swf_url, sizeof(v.swf_url) },

        { NGX_RTMP_AMF_STRING,
          ngx_string("tcUrl"),
          v.tc_url, sizeof(v.tc_url) },

        { NGX_RTMP_AMF_NUMBER,
          ngx_string("audioCodecs"),
          &v.acodecs, sizeof(v.acodecs) },

        { NGX_RTMP_AMF_NUMBER,
          ngx_string("videoCodecs"),
          &v.vcodecs, sizeof(v.vcodecs) },

        { NGX_RTMP_AMF_STRING,
          ngx_string("pageUrl"),
          v.page_url, sizeof(v.page_url) },

        { NGX_RTMP_AMF_NUMBER,
          ngx_string("objectEncoding"),
          &v.object_encoding, 0},

        { NGX_RTMP_AMF_NUMBER,
          ngx_string("relayType"),
          &v.relay_type, 0},

        { NGX_RTMP_AMF_STRING,
          ngx_string("x_forwarded_for"),
          v.x_forwarded_for, sizeof(v.x_forwarded_for) },
    };

    static ngx_rtmp_amf_elt_t  in_elts[] = {

        { NGX_RTMP_AMF_NUMBER,
          ngx_null_string,
          &v.trans, 0 },

        { NGX_RTMP_AMF_OBJECT,
          ngx_null_string,
          in_cmd, sizeof(in_cmd) },
    };

    ngx_memzero(&v, sizeof(v));
    if (ngx_rtmp_receive_amf(s, in, in_elts,
                             sizeof(in_elts) / sizeof(in_elts[0])))
    {
        return NGX_ERROR;
    }

    found = 0;
    len = ngx_strlen(v.app);

    if (len > 10 && !ngx_memcmp(v.app + len - 10, "/_definst_", 10)) {
        v.app[len - 10] = 0;

    } else if (len && v.app[len - 1] == '/') {
        v.app[len - 1] = 0;
    }

    ngx_str_set(&s->host_in, "default_host");
    ngx_str_set(&host, "default_host");
    s->port_in = 1935;

    ngx_rtmp_cmd_fill_args(v.app, v.args);

    NGX_RTMP_SET_STRPAR(app);
    NGX_RTMP_SET_STRPAR(args);
    NGX_RTMP_SET_STRPAR(flashver);
    NGX_RTMP_SET_STRPAR(swf_url);
    NGX_RTMP_SET_STRPAR(tc_url);
    NGX_RTMP_SET_STRPAR(page_url);
    NGX_RTMP_SET_STRPAR(x_forwarded_for);

    p = ngx_strlchr(s->app.data, s->app.data + s->app.len, '?');
    if (p) {
        s->app.len = (p - s->app.data);
    }

    // host/app
    p = ngx_strlchr(s->app.data, s->app.data + s->app.len, '/');
    if (p) {

        // host part.
        s->host_in.data = s->app.data;
        s->host_in.len = (p - s->app.data);

        // app part.
        s->app.data += (s->host_in.len + 1);
        s->app.len -= (s->host_in.len + 1);

        host = s->host_in;
        found = 1;
    }

    s->acodecs = (uint32_t) v.acodecs;
    s->vcodecs = (uint32_t) v.vcodecs;
    s->relay_type = v.relay_type;

    if (s->app.len > NGX_RTMP_MAX_NAME_LEN || s->app.len == 0) {

        ngx_log_error(NGX_LOG_ERR, s->connection->log, 0, 
                      "error: app name len is bigger 128 bytes or is 0");
        ngx_rtmp_set_fincode(s, NGX_RTMP_LOG_FINALIZE_CONNECT_APP_NAME_ILLEGAL);
        return NGX_ERROR;
    }

    if (ngx_rtmp_string_check(&s->app) == NGX_ERROR) {
        
        ngx_log_error(NGX_LOG_ERR, s->connection->log, 0, 
                      "error: app name contains illegal char, app name is:%s", v.app);
        ngx_rtmp_set_fincode(s, NGX_RTMP_LOG_FINALIZE_CONNECT_APP_NAME_ILLEGAL);
        return NGX_ERROR;
    }

    ngx_log_error(NGX_LOG_INFO, s->connection->log, 0,
                  "slot=%i, connect: app='%s' args='%s' flashver='%s' swf_url='%s' "
                  "tc_url='%s' page_url='%s' acodecs='%uD' vcodecs='%uD' "
                  "object_encoding='%ui' relay_type='%d'",
                  ngx_process_slot, v.app, v.args, v.flashver, v.swf_url, v.tc_url, v.page_url,
                  (uint32_t)v.acodecs, (uint32_t)v.vcodecs,
                  (ngx_int_t)v.object_encoding, v.relay_type);

    if (ngx_rtmp_parse_tcurl(s->args, s->tc_url, &s->host_in, &s->port_in) != NGX_OK) {

        ngx_log_error(NGX_LOG_ERR, s->connection->log, 0,
                      "slot=%i, tc_url='%s' connect: parse tcurl failed.",
                      ngx_process_slot, v.tc_url);

        return NGX_ERROR;
    }

    if (found) {
        s->host_in = host;
    }

    ngx_rtmp_arg(s->args, (u_char *)"vhost", 5, &s->host_in);
    ngx_rtmp_arg(s->args, (u_char *)"refer", 5, &s->refer_in);

    return ngx_rtmp_connect(s, &v);
}


static ngx_int_t
ngx_rtmp_cmd_connect(ngx_rtmp_session_t *s, ngx_rtmp_connect_t *v)
{
    ngx_rtmp_core_srv_conf_t   *cscf;
    ngx_rtmp_header_t           h;
    ngx_rtmp_core_main_conf_t   *cmcf;

    static double               trans;
    static double               capabilities = NGX_RTMP_CAPABILITIES;
    static double               object_encoding = 0;

    static ngx_rtmp_amf_elt_t  out_obj[] = {

        { NGX_RTMP_AMF_STRING,
          ngx_string("fmsVer"),
          NGX_RTMP_FMS_VERSION, 0 },

        { NGX_RTMP_AMF_NUMBER,
          ngx_string("capabilities"),
          &capabilities, 0 },
    };

    static ngx_rtmp_amf_elt_t  out_inf[] = {

        { NGX_RTMP_AMF_STRING,
          ngx_string("level"),
          "status", 0 },

        { NGX_RTMP_AMF_STRING,
          ngx_string("code"),
          "NetConnection.Connect.Success", 0 },

        { NGX_RTMP_AMF_STRING,
          ngx_string("description"),
          "Connection succeeded.", 0 },

        { NGX_RTMP_AMF_NUMBER,
          ngx_string("objectEncoding"),
          &object_encoding, 0 }
    };


    static ngx_rtmp_amf_elt_t  out_elts[] = {

        { NGX_RTMP_AMF_STRING,
          ngx_null_string,
          "_result", 0 },

        { NGX_RTMP_AMF_NUMBER,
          ngx_null_string,
          &trans, 0 },

        { NGX_RTMP_AMF_OBJECT,
          ngx_null_string,
          out_obj, sizeof(out_obj) },

        { NGX_RTMP_AMF_OBJECT,
          ngx_null_string,
          out_inf, sizeof(out_inf) },

        { NGX_RTMP_AMF_STRING,
          ngx_null_string,
          "ksy_live_server", 0 },
    };

    if (s->connected) {
        ngx_log_error(NGX_LOG_WARN, s->connection->log, 0,
                "connect: duplicate connection");
        return NGX_ERROR;
    }

    cmcf = ngx_rtmp_core_main_conf;
    if (!cmcf->time_update_active) {
        ngx_rtmp_time_update_timer(&cmcf->time_update_evt);
        cmcf->time_update_active = 1;
    }

    cscf = ngx_rtmp_get_module_srv_conf(s, ngx_rtmp_core_module);
    if (cscf == NULL) {
        return NGX_ERROR;
    }

    trans = v->trans;

    s->connected = 1;

    ngx_memzero(&h, sizeof(h));
    h.csid = NGX_RTMP_CSID_AMF_INI;
    h.type = NGX_RTMP_MSG_AMF_CMD;

    object_encoding = v->object_encoding;

    if (ngx_rtmp_send_ack_size(s, cscf->ack_window) != NGX_OK ||
           ngx_rtmp_send_bandwidth(s, cscf->ack_window,
                                   NGX_RTMP_LIMIT_DYNAMIC) != NGX_OK ||
           ngx_rtmp_send_chunk_size(s, cscf->chunk_size) != NGX_OK ||
           ngx_rtmp_send_amf(s, &h, out_elts, sizeof(out_elts) / sizeof(out_elts[0])) != NGX_OK ) {

           return NGX_ERROR;
    }

    if (ngx_rtmp_fire_event(s, NGX_RTMP_CONNECT_DONE, NULL, NULL) != NGX_OK)
    {
        ngx_rtmp_finalize_session(s);
        return NGX_ERROR;
    }

    return NGX_OK;
}


static ngx_int_t
ngx_rtmp_cmd_create_stream_init(ngx_rtmp_session_t *s, ngx_rtmp_header_t *h,
                                ngx_chain_t *in)
{
    static ngx_rtmp_create_stream_t     v;

    static ngx_rtmp_amf_elt_t  in_elts[] = {

        { NGX_RTMP_AMF_NUMBER,
          ngx_null_string,
          &v.trans, sizeof(v.trans) },
    };

    if (ngx_rtmp_receive_amf(s, in, in_elts,
                sizeof(in_elts) / sizeof(in_elts[0])))
    {
        return NGX_ERROR;
    }

    ngx_log_error(NGX_LOG_INFO, s->connection->log, 0, "createStream: vhost='%V' app='%V'",&s->host_in ,&s->app);

    return ngx_rtmp_create_stream(s, &v);
}


static ngx_int_t
ngx_rtmp_cmd_create_stream(ngx_rtmp_session_t *s, ngx_rtmp_create_stream_t *v)
{
    /* support one message stream per connection */
    static double               stream;
    static double               trans;
    ngx_rtmp_header_t           h;

    static ngx_rtmp_amf_elt_t  out_elts[] = {

        { NGX_RTMP_AMF_STRING,
          ngx_null_string,
          "_result", 0 },

        { NGX_RTMP_AMF_NUMBER,
          ngx_null_string,
          &trans, 0 },

        { NGX_RTMP_AMF_NULL,
          ngx_null_string,
          NULL, 0 },

        { NGX_RTMP_AMF_NUMBER,
          ngx_null_string,
          &stream, sizeof(stream) },
    };

    trans = v->trans;
    stream = NGX_RTMP_MSID;

    ngx_memzero(&h, sizeof(h));

    h.csid = NGX_RTMP_CSID_AMF_INI;
    h.type = NGX_RTMP_MSG_AMF_CMD;

    return ngx_rtmp_send_amf(s, &h, out_elts,
                             sizeof(out_elts) / sizeof(out_elts[0])) == NGX_OK ?
           NGX_DONE : NGX_ERROR;
}


static ngx_int_t
ngx_rtmp_cmd_close_stream_init(ngx_rtmp_session_t *s, ngx_rtmp_header_t *h,
                               ngx_chain_t *in)
{
    static ngx_rtmp_close_stream_t     v;

    static ngx_rtmp_amf_elt_t  in_elts[] = {

        { NGX_RTMP_AMF_NUMBER,
          ngx_null_string,
          &v.stream, 0 },
    };

    if (ngx_rtmp_receive_amf(s, in, in_elts,
                             sizeof(in_elts) / sizeof(in_elts[0])))
    {
        return NGX_ERROR;
    }

    ngx_log_error(NGX_LOG_INFO, s->connection->log, 0,
                  "closeStream: vhost='%V' app='%V' name=%V", 
                  &s->host_in, &s->app, &s->name);

    s->fin_time = ngx_time();
    s->end_time = ngx_current_msec;
    s->stream_stat = NGX_RTMP_STREAM_END;

    return ngx_rtmp_close_stream(s, &v);
}


static ngx_int_t
ngx_rtmp_cmd_close_stream(ngx_rtmp_session_t *s, ngx_rtmp_close_stream_t *v)
{
    return NGX_OK;
}


static ngx_int_t
ngx_rtmp_cmd_delete_stream_init(ngx_rtmp_session_t *s, ngx_rtmp_header_t *h,
                                ngx_chain_t *in)
{
    static ngx_rtmp_delete_stream_t     v;

    static ngx_rtmp_amf_elt_t  in_elts[] = {

        { NGX_RTMP_AMF_NUMBER,
          ngx_null_string,
          NULL, 0 },

        { NGX_RTMP_AMF_NULL,
          ngx_null_string,
          NULL, 0 },

        { NGX_RTMP_AMF_NUMBER,
          ngx_null_string,
          &v.stream, 0 },
    };

    if (ngx_rtmp_receive_amf(s, in, in_elts,
                             sizeof(in_elts) / sizeof(in_elts[0])))
    {
        return NGX_ERROR;
    }

    s->fin_time = ngx_time();
    s->end_time = ngx_current_msec;
    s->stream_stat = NGX_RTMP_STREAM_END;

    return ngx_rtmp_delete_stream(s, &v);
}


static ngx_int_t
ngx_rtmp_cmd_delete_stream(ngx_rtmp_session_t *s, ngx_rtmp_delete_stream_t *v)
{
    ngx_rtmp_close_stream_t         cv;

    ngx_log_error(NGX_LOG_INFO, s->connection->log, 0,
		"deleteStream: vhost='%V' app='%V' name='%V'", 
		&s->host_in, &s->app, &s->name);

    cv.stream = 0;

    return ngx_rtmp_close_stream(s, &cv);
}


static ngx_int_t
ngx_rtmp_cmd_publish_init(ngx_rtmp_session_t *s, ngx_rtmp_header_t *h,
        ngx_chain_t *in)
{
    static ngx_rtmp_publish_t      v;
    ngx_str_t                      args;
    ngx_rtmp_core_srv_conf_t      *cscf;
    ngx_rtmp_core_app_conf_t      *cacf;

    static ngx_rtmp_amf_elt_t      in_elts[] = {

        /* transaction is always 0 */
        { NGX_RTMP_AMF_NUMBER,
          ngx_null_string,
          NULL, 0 },

        { NGX_RTMP_AMF_NULL,
          ngx_null_string,
          NULL, 0 },

        { NGX_RTMP_AMF_STRING,
          ngx_null_string,
          &v.name, sizeof(v.name) },

        { NGX_RTMP_AMF_OPTIONAL | NGX_RTMP_AMF_STRING,
          ngx_null_string,
          &v.type, sizeof(v.type) },
    };

    ngx_memzero(&v, sizeof(v));

    if (ngx_rtmp_receive_amf(s, in, in_elts,
                  sizeof(in_elts) / sizeof(in_elts[0]))) {
        return NGX_ERROR;
    }

    ngx_rtmp_cmd_fill_args(v.name, v.args);

    NGX_RTMP_SET_STRPAR(name);

    // append args to s->args.
    if (s->args.len == 0) {

        NGX_RTMP_SET_STRPAR(args);

    } else if (ngx_strlen(v.args) > 0) {

        args = s->args;
        s->args.len = args.len + 1 + ngx_strlen(v.args);
        s->args.data = ngx_palloc(s->pool, s->args.len);

        ngx_snprintf(s->args.data, s->args.len, "%V&%s", &args, v.args);
    }

    if (s->name.len > NGX_RTMP_MAX_NAME_LEN || s->name.len == 0) {
        ngx_log_error(NGX_LOG_ERR, s->connection->log, 0,
                      "error: publish stream name len is bigger than 128 or is null");
        ngx_rtmp_set_fincode(s, NGX_RTMP_LOG_FINALIZE_PUBLISH_STREAM_NAME_ILLEGAL);
        return NGX_ERROR;
    }

    //check app wether contains illegal char
    if (ngx_rtmp_string_check(&s->name) == NGX_ERROR) {
        ngx_log_error(NGX_LOG_ERR, s->connection->log, 0,
                      "error: publish stream name contains illegal char, name is:%V",
                      &s->name);
        ngx_rtmp_set_fincode(s, NGX_RTMP_LOG_FINALIZE_PUBLISH_STREAM_NAME_ILLEGAL);
        return NGX_ERROR;
    }

    //get and check vdoid wether contains illegal char
    ngx_rtmp_arg(s->args, (u_char *)"vdoid", 5, &s->vdoid);
    if (s->vdoid.len > 0) {
        if (s->vdoid.len > NGX_RTMP_MAX_NAME_LEN) {
            ngx_log_error(NGX_LOG_ERR, s->connection->log, 0,
                          "error: publish vdoid parameter len is bigger than 128 or is null");
            ngx_rtmp_set_fincode(s, NGX_RTMP_LOG_FINALIZE_PUBLISH_VDOID_ILLEGAL);
            return NGX_ERROR;
        }

        if (ngx_rtmp_string_check(&s->vdoid) == NGX_ERROR) {
            ngx_log_error(NGX_LOG_ERR, s->connection->log, 0,
                          "error: publish vdoid parameter contains illegal char, name is:%V",
                          &s->vdoid);
            ngx_rtmp_set_fincode(s, NGX_RTMP_LOG_FINALIZE_PUBLISH_VDOID_ILLEGAL);
            return NGX_ERROR;
        }
    }

    ngx_rtmp_arg(s->args, (u_char *)"preset", 6, &s->preset);
    ngx_rtmp_arg(s->args, (u_char *)"refer", 5, &s->refer_in);

    ngx_log_error(NGX_LOG_INFO, s->connection->log, 0,
                  "publish: vhost='%V' app='%V' name='%s' args='%s' type='%s' silent='%d'",
                   &s->host_in, &s->app, v.name, v.args, v.type, v.silent);

    if (!ngx_rtmp_remote_conf()) {

        if (ngx_rtmp_cmd_get_core_srv_conf(s, NGX_RTMP_CMD_RTMP_PUBLISH, &s->host_in,
                                           &s->app, &cscf, &cacf) != NGX_OK) {

            ngx_log_error(NGX_LOG_INFO, s->connection->log, 0, "publish: forbidden");
            return NGX_ERROR;
        }

    } else {

        cscf = ngx_rtmp_get_module_srv_conf(s, ngx_rtmp_core_module);
    }

    if (!ngx_rtmp_remote_conf()) {

        s->app_conf = cacf->app_conf;

    } else {

        cscf = ngx_rtmp_get_module_srv_conf(s, ngx_rtmp_core_module);

        s->app_conf = cscf->ctx->app_conf;
    }

    s->protocol = NGX_RTMP_PUSH_TYPE_RTMP;

    return ngx_rtmp_publish(s, &v);
}


static ngx_int_t
ngx_rtmp_cmd_publish(ngx_rtmp_session_t *s, ngx_rtmp_publish_t *v)
{
    return NGX_OK;
}


ngx_int_t
ngx_rtmp_cmd_start_connect(ngx_rtmp_session_t *s, ngx_rtmp_connect_t *v)
{
    ngx_log_error(NGX_LOG_INFO, s->connection->log, 0,
            "slot=%i, connect: app='%s' args='%s' flashver='%s' swf_url='%s' "
            "tc_url='%s' page_url='%s' acodecs=%uD vcodecs=%uD "
            "object_encoding=%ui relay_type='%d'",
            ngx_process_slot, v->app, v->args, v->flashver, v->swf_url, v->tc_url, v->page_url,
            (uint32_t)v->acodecs, (uint32_t)v->vcodecs,
            (ngx_int_t)v->object_encoding, v->relay_type);

    return ngx_rtmp_connect(s, v);
}


ngx_int_t
ngx_rtmp_cmd_start_play(ngx_rtmp_session_t *s, ngx_rtmp_play_t *v)
{
	ngx_log_debug7(NGX_LOG_DEBUG_RTMP, s->connection->log, 0,
                  "slot=%i, cmd_start_play: name='%s' args='%s' start=%i duration=%i "
                  "reset=%i silent=%i",
                  ngx_process_slot, v->name, v->args, (ngx_int_t) v->start,
                  (ngx_int_t) v->duration, (ngx_int_t) v->reset,
                  (ngx_int_t) v->silent);

    return ngx_rtmp_play(s, v);
}


static ngx_int_t
ngx_rtmp_cmd_play_init(ngx_rtmp_session_t *s, ngx_rtmp_header_t *h,
        ngx_chain_t *in)
{
    static ngx_rtmp_play_t         v;
    ngx_str_t                      args;
    ngx_rtmp_core_srv_conf_t      *cscf;
    ngx_rtmp_core_app_conf_t      *cacf;

    static ngx_rtmp_amf_elt_t      in_elts[] = {

        /* transaction is always 0 */
        { NGX_RTMP_AMF_NUMBER,
          ngx_null_string,
          NULL, 0 },

        { NGX_RTMP_AMF_NULL,
          ngx_null_string,
          NULL, 0 },

        { NGX_RTMP_AMF_STRING,
          ngx_null_string,
          &v.name, sizeof(v.name) },

        { NGX_RTMP_AMF_OPTIONAL | NGX_RTMP_AMF_NUMBER,
          ngx_null_string,
          &v.start, 0 },

        { NGX_RTMP_AMF_OPTIONAL | NGX_RTMP_AMF_NUMBER,
          ngx_null_string,
          &v.duration, 0 },

        { NGX_RTMP_AMF_OPTIONAL | NGX_RTMP_AMF_BOOLEAN,
          ngx_null_string,
          &v.reset, 0 }
    };

    ngx_memzero(&v, sizeof(v));

    if (ngx_rtmp_receive_amf(s, in, in_elts,
                             sizeof(in_elts) / sizeof(in_elts[0]))) {
        return NGX_ERROR;
    }

    ngx_rtmp_cmd_fill_args(v.name, v.args);

    NGX_RTMP_SET_STRPAR(name);

    if (s->args.len == 0) {

        NGX_RTMP_SET_STRPAR(args);
    } else if (ngx_strlen(v.args) > 0) {

        args = s->args;
        s->args.len = args.len + 1 + ngx_strlen(v.args);
        s->args.data = ngx_palloc(s->pool, s->args.len);

        ngx_snprintf(s->args.data, s->args.len, "%V&%s", &args, v.args);
    }

    if (s->name.len > NGX_RTMP_MAX_NAME_LEN || s->name.len == 0) {

        ngx_log_error(NGX_LOG_ERR, s->connection->log, 0,
                      "error: play stream name len is bigger than 128 or is null");
        return NGX_ERROR;
    }

    //check app wether contains illegal char
    if (ngx_rtmp_string_check(&s->name) == NGX_ERROR) {

        ngx_log_error(NGX_LOG_ERR, s->connection->log, 0,
                      "error: stream name contains illegal char, name is:%V", &s->name);
        return NGX_ERROR;
    }

    ngx_log_error(NGX_LOG_INFO, s->connection->log, 0,
                  "play: vhost='%V' app='%V' name='%s' args='%s' start=%i duration=%i "
                  "reset=%i silent=%i",
                  &s->host_in, &s->app, v.name, v.args, (ngx_int_t) v.start,
                  (ngx_int_t) v.duration, (ngx_int_t) v.reset,
                  (ngx_int_t) v.silent);

    if (!ngx_rtmp_remote_conf()) {

        if (s->relay_type == NGX_NONE_RELAY) {

            if (ngx_rtmp_cmd_get_core_srv_conf(s, NGX_RTMP_CMD_RTMP_PLAY,
                                 &s->host_in, &s->app, &cscf, &cacf) != NGX_OK) {

                ngx_log_error(NGX_LOG_INFO, s->connection->log, 0, "play: forbidden");
                return NGX_ERROR;
            }

        } else {

            if (ngx_rtmp_cmd_get_core_srv_conf(s, NGX_RTMP_CMD_HLS_PLAY, &s->host_in, &s->app, &cscf, &cacf) != NGX_OK &&
                ngx_rtmp_cmd_get_core_srv_conf(s, NGX_RTMP_CMD_HDL_PLAY, &s->host_in, &s->app, &cscf, &cacf) != NGX_OK &&
                ngx_rtmp_cmd_get_core_srv_conf(s, NGX_RTMP_CMD_RTMP_PLAY, &s->host_in, &s->app, &cscf, &cacf) != NGX_OK) {

                ngx_log_error(NGX_LOG_INFO, s->connection->log, 0,
                              "play: forbidden");
                return NGX_ERROR;
            }

        }

        s->app_conf = cacf->app_conf;
    } else {

        cscf = ngx_rtmp_get_module_srv_conf(s, ngx_rtmp_core_module);

        s->app_conf = cscf->ctx->app_conf;
    }

    s->protocol = NGX_RTMP_PULL_TYPE_RTMP;

    return ngx_rtmp_play(s, &v);
}


static ngx_int_t
ngx_rtmp_cmd_play(ngx_rtmp_session_t *s, ngx_rtmp_play_t *v)
{
    if (ngx_rtmp_fire_event(s, NGX_RTMP_PLAY_DONE, NULL, NULL) != NGX_OK)
    {
        ngx_rtmp_finalize_session(s);
        return NGX_ERROR;
    }

    return NGX_OK;
}


static ngx_int_t
ngx_rtmp_cmd_play2_init(ngx_rtmp_session_t *s, ngx_rtmp_header_t *h,
        ngx_chain_t *in)
{
    static ngx_rtmp_play_t          v;
    static ngx_rtmp_close_stream_t  vc;

    static ngx_rtmp_amf_elt_t       in_obj[] = {

        { NGX_RTMP_AMF_NUMBER,
          ngx_string("start"),
          &v.start, 0 },

        { NGX_RTMP_AMF_STRING,
          ngx_string("streamName"),
          &v.name, sizeof(v.name) },
    };

    static ngx_rtmp_amf_elt_t       in_elts[] = {

        /* transaction is always 0 */
        { NGX_RTMP_AMF_NUMBER,
          ngx_null_string,
          NULL, 0 },

        { NGX_RTMP_AMF_NULL,
          ngx_null_string,
          NULL, 0 },

        { NGX_RTMP_AMF_OBJECT,
          ngx_null_string,
          &in_obj, sizeof(in_obj) }
    };

    ngx_memzero(&v, sizeof(v));

    if (ngx_rtmp_receive_amf(s, in, in_elts,
                             sizeof(in_elts) / sizeof(in_elts[0])))
    {
        return NGX_ERROR;
    }

    ngx_rtmp_cmd_fill_args(v.name, v.args);

    ngx_log_error(NGX_LOG_INFO, s->connection->log, 0,
                  "play2: vhost='%V' app='%V' name='%s' args='%s' start=%i",
                  &s->host_in, &s->app, v.name, v.args, (ngx_int_t) v.start);

    /* continue from current timestamp */

    if (v.start < 0) {
        v.start = s->current_time;
    }

    ngx_memzero(&vc, sizeof(vc));

    /* close_stream should be synchronous */
    ngx_rtmp_close_stream(s, &vc);

    return ngx_rtmp_play(s, &v);
}


static ngx_int_t
ngx_rtmp_cmd_pause_init(ngx_rtmp_session_t *s, ngx_rtmp_header_t *h,
        ngx_chain_t *in)
{
    static ngx_rtmp_pause_t     v;

    static ngx_rtmp_amf_elt_t   in_elts[] = {

        { NGX_RTMP_AMF_NUMBER,
          ngx_null_string,
          NULL, 0 },

        { NGX_RTMP_AMF_NULL,
          ngx_null_string,
          NULL, 0 },

        { NGX_RTMP_AMF_BOOLEAN,
          ngx_null_string,
          &v.pause, 0 },

        { NGX_RTMP_AMF_NUMBER,
          ngx_null_string,
          &v.position, 0 },
    };

    ngx_memzero(&v, sizeof(v));

    if (ngx_rtmp_receive_amf(s, in, in_elts,
                sizeof(in_elts) / sizeof(in_elts[0])))
    {
        return NGX_ERROR;
    }

    ngx_log_error(NGX_LOG_INFO, s->connection->log, 0,
                   "pause: vhost='%V' app='%V' name='%V' pause='%i' position='%i'",
                    &s->host_in, &s->app, &s->name,(ngx_int_t) v.pause, (ngx_int_t) v.position);

    return ngx_rtmp_pause(s, &v);
}


static ngx_int_t
ngx_rtmp_cmd_pause(ngx_rtmp_session_t *s, ngx_rtmp_pause_t *v)
{
    return NGX_OK;
}


static ngx_int_t
ngx_rtmp_cmd_disconnect_init(ngx_rtmp_session_t *s, ngx_rtmp_header_t *h,
                        ngx_chain_t *in)
{
    ngx_log_error(NGX_LOG_INFO, s->connection->log, 0, "disconnect: vhost='%V' app='%V' name='%V'",
                  &s->host_in, &s->app, &s->name);

    s->fin_time = ngx_time();
    s->end_time = ngx_current_msec;
    s->stream_stat = NGX_RTMP_STREAM_END;

    return ngx_rtmp_disconnect(s);
}


static ngx_int_t
ngx_rtmp_cmd_disconnect(ngx_rtmp_session_t *s)
{
    return ngx_rtmp_delete_stream(s, NULL);
}


static ngx_int_t
ngx_rtmp_cmd_seek_init(ngx_rtmp_session_t *s, ngx_rtmp_header_t *h,
        ngx_chain_t *in)
{
    static ngx_rtmp_seek_t         v;

    static ngx_rtmp_amf_elt_t      in_elts[] = {

        /* transaction is always 0 */
        { NGX_RTMP_AMF_NUMBER,
          ngx_null_string,
          NULL, 0 },

        { NGX_RTMP_AMF_NULL,
          ngx_null_string,
          NULL, 0 },

        { NGX_RTMP_AMF_NUMBER,
          ngx_null_string,
          &v.offset, sizeof(v.offset) },
    };

    ngx_memzero(&v, sizeof(v));

    if (ngx_rtmp_receive_amf(s, in, in_elts,
                             sizeof(in_elts) / sizeof(in_elts[0])))
    {
        return NGX_ERROR;
    }

    ngx_log_error(NGX_LOG_INFO, s->connection->log, 0,
        "seek: vhost='%V' app='%V' name='%V' offset='%i'", &s->host_in, &s->app, &s->name, (ngx_int_t)v.offset);

    return ngx_rtmp_seek(s, &v);
}


static ngx_int_t
ngx_rtmp_cmd_seek(ngx_rtmp_session_t *s, ngx_rtmp_seek_t *v)
{
    return NGX_OK;
}


static ngx_int_t
ngx_rtmp_cmd_stream_begin(ngx_rtmp_session_t *s, ngx_rtmp_stream_begin_t *v)
{
    ngx_log_error(NGX_LOG_INFO, s->connection->log, 0,
		"stream_begin: vhost='%V' app='%V' name='%V'", &s->host_in, &s->app, &s->name);
    return NGX_OK;
}


static ngx_int_t
ngx_rtmp_cmd_stream_eof(ngx_rtmp_session_t *s, ngx_rtmp_stream_eof_t *v)
{
    ngx_log_error(NGX_LOG_INFO, s->connection->log, 0,
		"stream_eof: vhost='%V' app='%V' name='%V'", &s->host_in, &s->app, &s->name);
    return NGX_OK;
}


static ngx_int_t
ngx_rtmp_cmd_stream_dry(ngx_rtmp_session_t *s, ngx_rtmp_stream_dry_t *v)
{
    ngx_log_error(NGX_LOG_INFO, s->connection->log, 0,
		"stream_dry: vhost='%V' app='%V' name='%V'", &s->host_in, &s->app, &s->name);
    return NGX_OK;
}


static ngx_int_t
ngx_rtmp_cmd_recorded(ngx_rtmp_session_t *s,
                      ngx_rtmp_recorded_t *v)
{
    ngx_log_error(NGX_LOG_INFO, s->connection->log, 0,
		"recorded: vhost='%V' app='%V' name='%V'", &s->host_in, &s->app, &s->name);
    return NGX_OK;
}


static ngx_int_t
ngx_rtmp_cmd_set_buflen(ngx_rtmp_session_t *s, ngx_rtmp_set_buflen_t *v)
{
    ngx_log_error(NGX_LOG_INFO, s->connection->log, 0,
		"set_buflen: vhost='%V' app='%V' name='%V'", &s->host_in, &s->app, &s->name);
    return NGX_OK;
}


static ngx_rtmp_amf_handler_t ngx_rtmp_cmd_map[] = {
    { ngx_string("connect"),            ngx_rtmp_cmd_connect_init           },
    { ngx_string("createStream"),       ngx_rtmp_cmd_create_stream_init     },
    { ngx_string("closeStream"),        ngx_rtmp_cmd_close_stream_init      },
    { ngx_string("deleteStream"),       ngx_rtmp_cmd_delete_stream_init     },
    { ngx_string("publish"),            ngx_rtmp_cmd_publish_init           },
    { ngx_string("play"),               ngx_rtmp_cmd_play_init              },
    { ngx_string("play2"),              ngx_rtmp_cmd_play2_init             },
    { ngx_string("seek"),               ngx_rtmp_cmd_seek_init              },
    { ngx_string("pause"),              ngx_rtmp_cmd_pause_init             },
    { ngx_string("pauseraw"),           ngx_rtmp_cmd_pause_init             },
};


static ngx_int_t
ngx_rtmp_cmd_postconfiguration(ngx_conf_t *cf)
{
    ngx_rtmp_core_main_conf_t          *cmcf;
    ngx_rtmp_handler_pt                *h;
    ngx_rtmp_amf_handler_t             *ch, *bh;
    size_t                              n, ncalls;

    cmcf = ngx_rtmp_conf_get_module_main_conf(cf, ngx_rtmp_core_module);

    /* redirect disconnects to deleteStream
     * to free client modules from registering
     * disconnect callback */

    h = ngx_array_push(&cmcf->events[NGX_RTMP_DISCONNECT]);
    if (h == NULL) {
        return NGX_ERROR;
    }

    *h = ngx_rtmp_cmd_disconnect_init;

    /* register AMF callbacks */

    ncalls = sizeof(ngx_rtmp_cmd_map) / sizeof(ngx_rtmp_cmd_map[0]);

    ch = ngx_array_push_n(&cmcf->amf, ncalls);
    if (ch == NULL) {
        return NGX_ERROR;
    }

    bh = ngx_rtmp_cmd_map;

    for(n = 0; n < ncalls; ++n, ++ch, ++bh) {
        *ch = *bh;
    }

    ngx_rtmp_connect = ngx_rtmp_cmd_connect;
    ngx_rtmp_disconnect = ngx_rtmp_cmd_disconnect;
    ngx_rtmp_create_stream = ngx_rtmp_cmd_create_stream;
    ngx_rtmp_close_stream = ngx_rtmp_cmd_close_stream;
    ngx_rtmp_delete_stream = ngx_rtmp_cmd_delete_stream;
    ngx_rtmp_publish = ngx_rtmp_cmd_publish;
    ngx_rtmp_play = ngx_rtmp_cmd_play;
    ngx_rtmp_seek = ngx_rtmp_cmd_seek;
    ngx_rtmp_pause = ngx_rtmp_cmd_pause;

    ngx_rtmp_stream_begin = ngx_rtmp_cmd_stream_begin;
    ngx_rtmp_stream_eof = ngx_rtmp_cmd_stream_eof;
    ngx_rtmp_stream_dry = ngx_rtmp_cmd_stream_dry;
    ngx_rtmp_recorded = ngx_rtmp_cmd_recorded;
    ngx_rtmp_set_buflen = ngx_rtmp_cmd_set_buflen;

    return NGX_OK;
}


ngx_int_t
ngx_rtmp_cmd_get_core_srv_conf(ngx_rtmp_session_t *s, ngx_int_t type, ngx_str_t *host, ngx_str_t *app,
    ngx_rtmp_core_srv_conf_t **pcscf, ngx_rtmp_core_app_conf_t **pcacf)
{
    ngx_rtmp_core_app_conf_t **cacfp;
    ngx_rtmp_core_srv_conf_t  *cscf;
    ngx_hash_combined_t       *hash;
    ngx_uint_t                 n;

    if (s == NULL || s->addr_conf == NULL || host == NULL) {
        return NGX_ERROR;
    }

    if (type == NGX_RTMP_CMD_HLS_PLAY) {
        hash = &s->addr_conf->vnames->hls_play_names;
    } else if (type == NGX_RTMP_CMD_RTMP_PLAY) {
        hash = &s->addr_conf->vnames->rtmp_play_names;
    } else if (type == NGX_RTMP_CMD_HDL_PLAY) {
        hash = &s->addr_conf->vnames->hdl_play_names;
    } else if (type == NGX_RTMP_CMD_RTMP_PUBLISH) {
        hash = &s->addr_conf->vnames->rtmp_publish_names;
    } else {
        return NGX_ERROR;
    }

    cscf = ngx_hash_find_combined(hash, ngx_hash_key(host->data, host->len),
               host->data, host->len);

    if (cscf == NULL) {
        return NGX_ERROR;
    }

    cacfp = cscf->applications.elts;
    for(n = 0; n < cscf->applications.nelts; ++n, ++cacfp) {
        if ((*cacfp)->name.len == app->len &&
            ngx_strncmp((*cacfp)->name.data, app->data, app->len) == 0) {

            *pcscf = cscf;
            *pcacf = *cacfp;
            return NGX_OK;
        }
    }

    return NGX_ERROR;
}

