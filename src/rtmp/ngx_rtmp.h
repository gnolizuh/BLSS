
/*
 * Copyright (C) Roman Arutyunyan
 */


#ifndef _NGX_RTMP_H_INCLUDED_
#define _NGX_RTMP_H_INCLUDED_


#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_event.h>
#include <ngx_inet.h>
#include <ngx_event_connect.h>

#include "ngx_rtmp_amf.h"
#include "ngx_rtmp_bandwidth.h"


#if (NGX_WIN32)
typedef __int8              int8_t;
typedef unsigned __int8     uint8_t;
#endif


typedef struct {
    void                  **main_conf;
    void                  **srv_conf;
    void                  **app_conf;
} ngx_rtmp_conf_ctx_t;


typedef struct {
    union {
        struct sockaddr        sockaddr;
        struct sockaddr_in     sockaddr_in;
#if (NGX_HAVE_INET6)
        struct sockaddr_in6    sockaddr_in6;
#endif
#if (NGX_HAVE_UNIX_DOMAIN)
        struct sockaddr_un     sockaddr_un;
#endif
        u_char                 sockaddr_data[NGX_SOCKADDRLEN];
    } u;
    u_char                  sockaddr[NGX_SOCKADDRLEN];
    socklen_t               socklen;

    /* server ctx */
    ngx_rtmp_conf_ctx_t    *ctx;

    unsigned                default_server:1;
    unsigned                bind:1;
    unsigned                wildcard:1;
#if (NGX_HAVE_INET6 && defined IPV6_V6ONLY)
    unsigned                ipv6only:2;
#endif

#if (NGX_HAVE_REUSEPORT)
    unsigned                reuseport:1;
#endif

    unsigned                so_keepalive:2;
    unsigned                proxy_protocol:1;
#if (NGX_HAVE_KEEPALIVE_TUNABLE)
    int                     tcp_keepidle;
    int                     tcp_keepintvl;
    int                     tcp_keepcnt;
#endif
} ngx_rtmp_listen_t;


typedef struct {
    void                   *addrs;
    ngx_uint_t              naddrs;
} ngx_rtmp_port_t;


typedef struct {
    int                     family;
    in_port_t               port;
    ngx_array_t             ports;
    ngx_array_t             addrs;       /* array of ngx_rtmp_conf_addr_t */
} ngx_rtmp_conf_port_t;

#define NGX_BUFF_LEN             1024

#define NGX_RTMP_LOG_DIR_ACCESS        	 0744
#define NGX_RTMP_LOG_FILE_ACCESS         0777

#define NGX_RTMP_RELAY_NAME             "ngx-relay"

#define NGX_RTMP_SERVER_TYPE            "ORI"

#define NGX_RTMP_VERSION                3

#define NGX_LOG_DEBUG_RTMP              NGX_LOG_DEBUG_CORE

#define NGX_RTMP_DEFAULT_CHUNK_SIZE     128

#define NGX_NONE_RELAY                  0
#define NGX_CLUSTER_RELAY               1
#define NGX_REMOTE_RELAY                2
#define NGX_LOCAL_RELAY                 3
#define	NGX_ERROR_RELAY					4

#define NGX_RTMP_PULL_TYPE_RTMP         0
#define NGX_RTMP_PULL_TYPE_HLS_TS       1
#define NGX_RTMP_PULL_TYPE_HLS_M3U8     2
#define NGX_RTMP_PULL_TYPE_HDL          3
#define NGX_RTMP_PUSH_TYPE_RTMP         4
#define NGX_RTMP_PUSH_TYPE_HDL          5

#define NGX_RTMP_STREAM_PRIVATE			0
#define NGX_RTMP_STREAM_PUBLIC			1
#define NGX_RTMP_ERROR_PUBLIC			2

#define	NGX_RTMP_STREAM_NDRM			0
#define NGX_RTMP_STREAM_DRM				1
#define NGX_RTMP_ERROR_DRM				2

/* RTMP message types */
#define NGX_RTMP_MSG_CHUNK_SIZE         1
#define NGX_RTMP_MSG_ABORT              2
#define NGX_RTMP_MSG_ACK                3
#define NGX_RTMP_MSG_USER               4
#define NGX_RTMP_MSG_ACK_SIZE           5
#define NGX_RTMP_MSG_BANDWIDTH          6
#define NGX_RTMP_MSG_EDGE               7
#define NGX_RTMP_MSG_AUDIO              8
#define NGX_RTMP_MSG_VIDEO              9
#define NGX_RTMP_MSG_AMF3_META          15
#define NGX_RTMP_MSG_AMF3_SHARED        16
#define NGX_RTMP_MSG_AMF3_CMD           17
#define NGX_RTMP_MSG_AMF_META           18
#define NGX_RTMP_MSG_AMF_SHARED         19
#define NGX_RTMP_MSG_AMF_CMD            20
#define NGX_RTMP_MSG_AGGREGATE          22
#define NGX_RTMP_MSG_MAX                22

#define NGX_RTMP_CONNECT                NGX_RTMP_MSG_MAX + 1
#define NGX_RTMP_DISCONNECT             NGX_RTMP_MSG_MAX + 2
#define NGX_RTMP_HANDSHAKE_DONE         NGX_RTMP_MSG_MAX + 3
#define NGX_RTMP_CONNECT_DONE           NGX_RTMP_MSG_MAX + 4
#define NGX_RTMP_PLAY_DONE              NGX_RTMP_MSG_MAX + 5
#define NGX_RTMP_NOTIFY_LATENCY         NGX_RTMP_MSG_MAX + 6
#define NGX_RTMP_ON_MESSAGE             NGX_RTMP_MSG_MAX + 7
#define NGX_RTMP_MAX_EVENT              NGX_RTMP_MSG_MAX + 8


/* RMTP control message types */
#define NGX_RTMP_USER_STREAM_BEGIN      0
#define NGX_RTMP_USER_STREAM_EOF        1
#define NGX_RTMP_USER_STREAM_DRY        2
#define NGX_RTMP_USER_SET_BUFLEN        3
#define NGX_RTMP_USER_RECORDED          4
#define NGX_RTMP_USER_PING_REQUEST      6
#define NGX_RTMP_USER_PING_RESPONSE     7
#define NGX_RTMP_USER_UNKNOWN           8
#define NGX_RTMP_USER_BUFFER_END        31

#define NGX_RTMP_INVALID_TIMESTAMP      ((ngx_uint_t)(-1)) /* 2^63*/
#define NGX_RTMP_INVALID_CTS_TIMESTAMP  ((ngx_int_t)(0)) /*0*/

/** publish finalize log **/

typedef enum {
    NGX_RTMP_LOG_FINALIZE_CLIENT_CLOSE_SESSION_CODE,
    NGX_RTMP_LOG_FINALIZE_HANDSHAKE_RECV_ERR_CODE,
    NGX_RTMP_LOG_FINALIZE_HANDSHAKE_SEND_ERR_CODE,
    NGX_RTMP_LOG_FINALIZE_RTMP_PUBLISHER_CLOSE_CODE,
    NGX_RTMP_LOG_FINALIZE_RTMP_RECV_ERR_CODE,
    NGX_RTMP_LOG_FINALIZE_PARSE_RTMP_HEAD_ERR_CODE,
    NGX_RTMP_LOG_FINALIZE_RTMP_PING_ERR_CODE,
    NGX_RTMP_LOG_FINALIZE_DROP_IDLE_CODE,
    NGX_RTMP_LOG_FINALIZE_MANDATORY_PACKET_ERR_CODE,
    NGX_RTMP_LOG_FINALIZE_CONNECT_APP_NAME_ILLEGAL,
    NGX_RTMP_LOG_FINALIZE_PUBLISH_STREAM_NAME_ILLEGAL,
    NGX_RTMP_LOG_FINALIZE_DS_CLOSE_PUBLISHER,
    NGX_RTMP_LOG_FINALIZE_PUBLISH_VDOID_ILLEGAL,
    NGX_RTMP_LOG_FINALIZE_MAX_CODE
} ngx_rtmp_log_finalize_code_t;


/* stream_stat */
typedef enum {
    NGX_RTMP_STREAM_BEGIN,
    NGX_RTMP_STREAM_END,
    NGX_RTMP_STREAM_PUBLISHING
} ngx_rtmp_stream_stat_t;


/* NGX_RTMP_MAX_CHUNK_HEADER > NGX_RTMP_MAX_FLV_TAG_HEADER */

#define NGX_RTMP_MAX_LOG_SIZE           4096

/* Chunk header:
 *   max 3  basic header
 * + max 11 message header
 * + max 4  extended header (timestamp) */
#define NGX_RTMP_MAX_CHUNK_HEADER       18

/* FLV tag header:
 *   max 1  type
 * + max 3  body length
 * + max 3  timestamp
 * + max 1  extend timestamp
 * + max 3  streamid
 * .....[body] */
#define NGX_RTMP_MAX_FLV_TAG_HEADER     11

#define NGX_RTMP_MAX_FLV_TAG_SIZE_HEADER 4


#define NGX_RTMP_CORE_LOAD_CONF_LOCAL   1
#define NGX_RTMP_CORE_LOAD_CONF_REMOTE  2

#define NGX_RTMP_MAX_BUF_SIZE       1024

#define NGX_RTMP_MAX_NAME_LEN       128  

#define BLANK_SPACE " "


typedef struct {
    ngx_int_t               user_id;
    ngx_str_t               unique_name;
    ngx_uint_t              live:1;
    ngx_uint_t              auth:1;
    ngx_uint_t              gop_cache:1;
    ngx_uint_t              gop_cache_mintime;
    ngx_uint_t              gop_cache_maxtime;
    ngx_uint_t              rtmp_status_code:1;
    ngx_msec_t              idle_timeout;
    ngx_uint_t              hdl:1;
    ngx_uint_t              hls:1;
    ngx_msec_t              hls_fragment;
    ngx_msec_t              hls_playlist_length;

    ngx_uint_t              screenshot:1;
    ngx_uint_t              screenshot_is_public:1;
    ngx_uint_t              screenshot_monitor;
    ngx_str_t               screenshot_bucket;
    ngx_str_t               screenshot_url;
    ngx_uint_t              screenshot_is_cover;
    ngx_msec_t              screenshot_interval;

    ngx_uint_t              hls_vod:1;
    ngx_msec_t              hls_vod_fragment;
    ngx_uint_t              hls_vod_ts_zero:1;
    ngx_uint_t              hls_vod_is_public:1;
    ngx_str_t               hls_vod_bucket;
    ngx_str_t               hls_vod_url;

    ngx_uint_t              mp4_vod:1;
    ngx_uint_t              mp4_vod_is_public:1;
    ngx_str_t               mp4_vod_bucket;
    ngx_str_t               mp4_vod_url;
    ngx_uint_t              mp4_vod_name_format;

    ngx_str_t               region_hls;
    ngx_str_t               region_pic;
    ngx_str_t               region_mp4;

    ngx_str_t               host_hls;
    ngx_str_t               host_pic;
    ngx_str_t               host_mp4;

    ngx_flag_t              hls_vod_auto_merge;
    ngx_uint_t              publish_extime_fix:1;

    ngx_uint_t              live_delay:1;
    ngx_msec_t              live_delay_time;
    ngx_str_t               live_delay_host;
    ngx_str_t               live_delay_app;
} ngx_rtmp_conf_t;

typedef struct {
    uint32_t                csid;       /* chunk stream id */
    uint32_t                timestamp;  /* timestamp (delta) */
    uint32_t                mlen;       /* message length */
    uint8_t                 type;       /* message type id */
    uint32_t                msid;       /* message stream id */
} ngx_rtmp_header_t;


typedef struct {
    ngx_rtmp_header_t       hdr;
    uint32_t                dtime;
    uint32_t                len;        /* current fragment length */
    uint8_t                 ext;
    ngx_chain_t            *in;
} ngx_rtmp_stream_t;


/* disable zero-sized array warning by msvc */

#if (NGX_WIN32)
#pragma warning(push)
#pragma warning(disable:4200)
#endif


#if (NGX_WIN32)
#pragma warning(pop)
#endif

#define NGX_RTMP_MAX_SRV_NBUCKET    64
#define NGX_RTMP_MAX_APP_NBUCKET    8
#define NGX_RTMP_MAX_STREAM_NBUCKET 1024

#define NGX_RTMP_UNIX_TIME_LEN_MIN  10
#define NGX_RTMP_UNIX_TIME_LEN_MAX  20

typedef struct {
    ngx_array_t             servers;    /* ngx_rtmp_core_srv_conf_t */
    ngx_array_t             listen;     /* ngx_rtmp_listen_t */

    ngx_array_t             events[NGX_RTMP_MAX_EVENT];

    ngx_hash_t              amf_hash;
    ngx_array_t             amf_arrays;
    ngx_array_t             amf;
	ngx_array_t 			ports;

    ngx_uint_t              server_names_hash_max_size;
    ngx_uint_t              server_names_hash_bucket_size;
    ngx_uint_t              load_conf_from;          /* load configure from local or remote */
} ngx_rtmp_core_main_conf_t;

extern ngx_rtmp_core_main_conf_t   *ngx_rtmp_core_main_conf;

typedef struct ngx_rtmp_core_srv_conf_s {
    ngx_array_t             applications;

    ngx_array_t             hls_play_domains;
    ngx_array_t             rtmp_play_domains;
    ngx_array_t             hdl_play_domains;
    ngx_array_t             rtmp_publish_domains;
    ngx_str_t               unique_name;

    ngx_msec_t              timeout;
    ngx_msec_t              ping;
    ngx_msec_t              ping_timeout;
    ngx_flag_t              so_keepalive;
    ngx_int_t               max_streams;

    ngx_uint_t              ack_window;

    ngx_int_t               chunk_size;
    ngx_pool_t             *pool;
    ngx_chain_t            *free;
    ngx_chain_t            *free_hs;
    size_t                  max_message;
    ngx_flag_t              play_time_fix;
    ngx_flag_t              publish_time_fix;
    ngx_flag_t              publish_extime_fix;
    ngx_flag_t              rtmp_status_code;
    ngx_flag_t              busy;
    size_t                  out_queue;
    size_t                  out_cork;
    ngx_msec_t              buflen;

    ngx_rtmp_conf_ctx_t    *ctx;
    unsigned                listen:1;     /*liten flag*/
} ngx_rtmp_core_srv_conf_t;

typedef struct {
    ngx_array_t             applications; /* ngx_rtmp_core_app_conf_t */
    ngx_str_t               name;
    void                  **app_conf;
} ngx_rtmp_core_app_conf_t;

typedef struct {
    ngx_rtmp_core_srv_conf_t  *server;    /* virtual name server conf */
    ngx_str_t                  name;
} ngx_rtmp_server_name_t;

typedef struct {
     ngx_hash_combined_t       hls_play_names;
     ngx_hash_combined_t       rtmp_play_names;
     ngx_hash_combined_t       hdl_play_names;
     ngx_hash_combined_t       rtmp_publish_names;
     ngx_uint_t                nregex;
     ngx_rtmp_server_name_t   *regex;
} ngx_rtmp_virtual_names_t;

typedef struct {
    ngx_rtmp_conf_ctx_t    *ctx;
    ngx_str_t               addr_text;

/*added by andrew, for srver_name
  * the default server configuration for this address:port */
    ngx_rtmp_core_srv_conf_t  *default_server;
    ngx_rtmp_virtual_names_t  *vnames;

    unsigned                proxy_protocol:1;
} ngx_rtmp_addr_conf_t;

typedef struct {
    in_addr_t               addr;
    ngx_rtmp_addr_conf_t    conf;
} ngx_rtmp_in_addr_t;
#if (NGX_HAVE_INET6)

typedef struct {
    struct in6_addr         addr6;
    ngx_rtmp_addr_conf_t    conf;
} ngx_rtmp_in6_addr_t;

#endif
typedef struct {
    ngx_rtmp_listen_t       opt; /*added by andrew, for server_name*/

    struct sockaddr        *sockaddr;
    socklen_t               socklen;

    ngx_rtmp_conf_ctx_t    *ctx;

    ngx_hash_t                 hls_play_hash;
    ngx_hash_wildcard_t       *hls_play_wc_head;
    ngx_hash_wildcard_t       *hls_play_wc_tail;

    ngx_hash_t                 rtmp_play_hash;
    ngx_hash_wildcard_t       *rtmp_play_wc_head;
    ngx_hash_wildcard_t       *rtmp_play_wc_tail;

    ngx_hash_t                 hdl_play_hash;
    ngx_hash_wildcard_t       *hdl_play_wc_head;
    ngx_hash_wildcard_t       *hdl_play_wc_tail;

    ngx_hash_t                 rtmp_publish_hash;
    ngx_hash_wildcard_t       *rtmp_publish_wc_head;
    ngx_hash_wildcard_t       *rtmp_publish_wc_tail;

	ngx_rtmp_core_srv_conf_t  *default_server;
    ngx_array_t                servers;       /* array of ngx_rtmp_core_srv_conf_t */

    unsigned                bind:1;
    unsigned                wildcard:1;
#if (NGX_HAVE_INET6 && defined IPV6_V6ONLY)
    unsigned                ipv6only:2;
#endif
    unsigned                so_keepalive:2;
    unsigned                proxy_protocol:1;
#if (NGX_HAVE_KEEPALIVE_TUNABLE)
    int                     tcp_keepidle;
    int                     tcp_keepintvl;
    int                     tcp_keepcnt;
#endif
} ngx_rtmp_conf_addr_t;

typedef struct {
    ngx_uint_t              recv_time;      /*utc time (ms)*/
    uint8_t                 type;           /*should be 8(audio) or 9(video)*/
    uint8_t                 is_raw;
    uint32_t                timestamp;
} ngx_rtmp_chunk_info_t;


typedef struct {
    uint32_t                signature;  /* "RTMP" */ /* <-- FIXME wtf */

    ngx_event_t             close;

    void                  **ctx;
    void                  **main_conf;
    void                  **srv_conf;
    void                  **app_conf;
    ngx_rtmp_addr_conf_t   *addr_conf;
    ngx_rtmp_conf_ctx_t    *conf_ctx;

    ngx_str_t              *addr_text;
    int                     connected;

#if (nginx_version >= 1007005)
        ngx_queue_t             posted_dry_events;
#else
        ngx_event_t            *posted_dry_events;
#endif

    /* client buffer time in msec */
    uint32_t                buflen;
    uint32_t                ack_size;

    /* connection parameters */
    ngx_str_t               app;
    ngx_str_t               name;

    ngx_str_t               args;
    ngx_str_t               flashver;
    ngx_str_t               swf_url;
    ngx_str_t               tc_url;
    ngx_str_t               hls_name;
    uint32_t                acodecs;
    uint32_t                vcodecs;
    ngx_str_t               page_url;

    double                  start;
    double                  duration;
    int                     reset;
    int                     silent;

    ngx_str_t               x_forwarded_for;

    /* host_in: input vhost  port_in: input port */
    ngx_str_t               host_in;
    ngx_int_t               port_in;
    ngx_str_t               refer_in;

    /* dynamic configuration */
    ngx_rtmp_conf_t         conf;

    /* standard parameters */
    ngx_str_t               vdoid;
    ngx_str_t               preset;

    /* handshake data */
    ngx_buf_t              *hs_buf;
    u_char                 *hs_digest;
    unsigned                hs_old:1;
    ngx_uint_t              hs_stage;

    /* connection timestamps */
    ngx_msec_t              epoch;
    ngx_msec_t              peer_epoch;
    ngx_msec_t              base_time;
    ngx_msec_t              end_time;
    time_t                  connect_time;
    time_t                  fin_time;
    uint32_t                current_time;

    /**  flux last stat time **/
    ngx_msec_t              last_time;
    ngx_msec_t              log_time;
    ngx_uint_t              stream_stat;

    /**  publish finalize code **/
    ngx_uint_t              finalize_code;

    /* ping */
    ngx_event_t             ping_evt;
    unsigned                ping_active:1;
    unsigned                ping_reset:1;

    /* auto-pushed? */
    unsigned                auto_pushed:1;
    unsigned                relay:1;
    unsigned                static_relay:1;

    ngx_uint_t              protocol;

    /* hls play */
    ngx_pool_t             *pool;
    void                   *r;
    ngx_int_t               rc;
    ngx_int_t               status_code;
    ngx_msec_t              hls_stime_ms;
    ngx_msec_t              hls_etime_ms;

    /* auto-pull? */
    ngx_uint_t              relay_type;

    /* input stream 0 (reserved by RTMP spec)
     * is used as free chain link */

    ngx_rtmp_stream_t      *in_streams;
    uint32_t                in_csid;
    ngx_uint_t              in_chunk_size;
    ngx_pool_t             *in_pool;
    uint32_t                in_bytes;
    uint32_t                in_last_ack;

    ngx_pool_t             *in_old_pool;
    ngx_int_t               in_chunk_size_changing;

    ngx_connection_t       *connection;

    /* circular buffer of RTMP message pointers */
    ngx_msec_t              timeout;
    uint32_t                out_bytes;
    size_t                  out_pos, out_last;
    ngx_chain_t            *out_chain;
    u_char                 *out_bpos;
    unsigned                out_buffer:1;
    size_t                  out_queue;
    size_t                  out_cork;

    /* static buffer for log printing */
    unsigned                audio_recved:1;
    unsigned                video_recved:1;
    u_char                 *log_bpos;
    u_char                  log_buf[NGX_RTMP_MAX_BUF_SIZE];

    /* timestamp log print*/
    ngx_uint_t              last_audio_ts;
    ngx_uint_t              last_video_ts;
    ngx_uint_t              audio_ts_min;
    ngx_uint_t              audio_ts_max;
    ngx_uint_t              video_ts_min;
    ngx_uint_t              video_ts_max;
    ngx_int_t               last_video_cts;

    ngx_chain_t            *out[0];

} ngx_rtmp_session_t;


/* handler result code:
 *  NGX_ERROR - error
 *  NGX_OK    - success, may continue
 *  NGX_DONE  - success, input parsed, reply sent; need no
 *      more calls on this event */
typedef ngx_int_t (*ngx_rtmp_handler_pt)(ngx_rtmp_session_t *s,
        ngx_rtmp_header_t *h, ngx_chain_t *in);


typedef struct {
    ngx_str_t               name;
    ngx_rtmp_handler_pt     handler;
} ngx_rtmp_amf_handler_t;


typedef struct {
    ngx_str_t              *client;
    ngx_rtmp_session_t     *session;
} ngx_rtmp_error_log_ctx_t;


typedef struct {
    ngx_int_t             (*preconfiguration)(ngx_conf_t *cf);
    ngx_int_t             (*postconfiguration)(ngx_conf_t *cf);

    void                 *(*create_main_conf)(ngx_conf_t *cf);
    char                 *(*init_main_conf)(ngx_conf_t *cf, void *conf);

    void                 *(*create_srv_conf)(ngx_conf_t *cf);
    char                 *(*merge_srv_conf)(ngx_conf_t *cf, void *prev,
                                    void *conf);

    void                 *(*create_app_conf)(ngx_conf_t *cf);
    char                 *(*merge_app_conf)(ngx_conf_t *cf, void *prev,
                                    void *conf);
} ngx_rtmp_module_t;

extern ngx_module_t  ngx_rtmp_module;

#define NGX_RTMP_MODULE                 0x504D5452     /* "RTMP" */

#define NGX_RTMP_MAIN_CONF              0x02000000
#define NGX_RTMP_SRV_CONF               0x04000000
#define NGX_RTMP_APP_CONF               0x08000000
#define NGX_RTMP_REC_CONF               0x10000000


#define NGX_RTMP_MAIN_CONF_OFFSET  offsetof(ngx_rtmp_conf_ctx_t, main_conf)
#define NGX_RTMP_SRV_CONF_OFFSET   offsetof(ngx_rtmp_conf_ctx_t, srv_conf)
#define NGX_RTMP_APP_CONF_OFFSET   offsetof(ngx_rtmp_conf_ctx_t, app_conf)


#define ngx_rtmp_get_module_ctx(s, module)     (s)->ctx[module.ctx_index]
#define ngx_rtmp_set_ctx(s, c, module)         s->ctx[module.ctx_index] = c;
#define ngx_rtmp_delete_ctx(s, module)         s->ctx[module.ctx_index] = NULL;


#define ngx_rtmp_get_module_main_conf(s, module)                             \
    (s)->main_conf[module.ctx_index]
#define ngx_rtmp_get_module_srv_conf(s, module)  (s)->srv_conf[module.ctx_index]
#define ngx_rtmp_get_module_app_conf(s, module)  ((s)->app_conf ? \
    (s)->app_conf[module.ctx_index] : NULL)

#define ngx_rtmp_conf_get_module_main_conf(cf, module)                       \
    ((ngx_rtmp_conf_ctx_t *) cf->ctx)->main_conf[module.ctx_index]
#define ngx_rtmp_conf_get_module_srv_conf(cf, module)                        \
    ((ngx_rtmp_conf_ctx_t *) cf->ctx)->srv_conf[module.ctx_index]
#define ngx_rtmp_conf_get_module_app_conf(cf, module)                        \
    ((ngx_rtmp_conf_ctx_t *) cf->ctx)->app_conf[module.ctx_index]
#define ngx_rtmp_cycle_get_module_main_conf(cycle, module)                   \
	(cycle->conf_ctx[ngx_rtmp_module.index] ?							     \
		((ngx_rtmp_conf_ctx_t *) cycle->conf_ctx[ngx_rtmp_module.index])	 \
			->main_conf[module.ctx_index]:									 \
		NULL)

#define ngx_rtmp_get_attr_conf(cf, attr) \
    ((ngx_rtmp_core_main_conf->load_conf_from != NGX_RTMP_CORE_LOAD_CONF_LOCAL) ? (s->conf).attr : (cf)->attr)

#define ngx_rtmp_get_attr_conf1(s, cf, attr) \
    ((ngx_rtmp_core_main_conf->load_conf_from != NGX_RTMP_CORE_LOAD_CONF_LOCAL) ? ((s)->conf).attr : (cf)->attr)

#define ngx_rtmp_remote_conf() (ngx_rtmp_core_main_conf->load_conf_from != NGX_RTMP_CORE_LOAD_CONF_LOCAL)

#define ngx_rtmp_pull_type(type) ((type) == NGX_RTMP_PULL_TYPE_RTMP)
#define ngx_hls_pull_type(type)  ((type) == NGX_RTMP_PULL_TYPE_HLS_TS || (type) == NGX_RTMP_PULL_TYPE_HLS_M3U8)
#define ngx_hls_type(type) (ngx_hls_pull_type(type))
#define ngx_hdl_pull_type(type)  ((type) == NGX_RTMP_PULL_TYPE_HDL)
#define ngx_hdl_push_type(type)  ((type) == NGX_RTMP_PUSH_TYPE_HDL)
#define ngx_hdl_type(type)  (ngx_hdl_push_type(type) || ngx_hdl_pull_type(type))
#define ngx_rtmp_push_type(type)  ((type) == NGX_RTMP_PUSH_TYPE_RTMP)
#define ngx_rtmp_type(type) (ngx_rtmp_push_type(type) || ngx_rtmp_pull_type(type))

ngx_int_t ngx_rtmp_add_listen(ngx_conf_t *cf, ngx_rtmp_core_srv_conf_t *cscf,
    ngx_rtmp_listen_t *lsopt);
#ifdef NGX_DEBUG
char *ngx_rtmp_message_type(uint8_t type);
char *ngx_rtmp_user_message_type(uint16_t evt);
#endif

void ngx_rtmp_init_connection(ngx_connection_t *c);
ngx_rtmp_session_t * ngx_rtmp_init_session(ngx_connection_t *c,
     ngx_rtmp_addr_conf_t *addr_conf);
void ngx_rtmp_finalize_session(ngx_rtmp_session_t *s);
void ngx_rtmp_handshake(ngx_rtmp_session_t *s);
void ngx_rtmp_client_handshake(ngx_rtmp_session_t *s, unsigned async);
void ngx_rtmp_free_handshake_buffers(ngx_rtmp_session_t *s);
void ngx_rtmp_cycle(ngx_rtmp_session_t *s);
void ngx_rtmp_reset_ping(ngx_rtmp_session_t *s);
ngx_int_t ngx_rtmp_fire_event(ngx_rtmp_session_t *s, ngx_uint_t evt,
        ngx_rtmp_header_t *h, ngx_chain_t *in);
void ngx_rtmp_recv(ngx_event_t *rev);
void ngx_rtmp_send(ngx_event_t *rev);

ngx_int_t ngx_rtmp_set_chunk_size(ngx_rtmp_session_t *s, ngx_uint_t size);


/* Bit reverse: we need big-endians in many places  */
void * ngx_rtmp_rmemcpy(void *dst, const void* src, size_t n);

#define ngx_rtmp_rcpymem(dst, src, n) \
    (((u_char*)ngx_rtmp_rmemcpy(dst, src, n)) + (n))


static ngx_inline uint16_t
ngx_rtmp_r16(uint16_t n)
{
    return (n << 8) | (n >> 8);
}


static ngx_inline uint32_t
ngx_rtmp_r32(uint32_t n)
{
    return (n << 24) | ((n << 8) & 0xff0000) | ((n >> 8) & 0xff00) | (n >> 24);
}


static ngx_inline uint64_t
ngx_rtmp_r64(uint64_t n)
{
    return (uint64_t) ngx_rtmp_r32((uint32_t) n) << 32 |
                      ngx_rtmp_r32((uint32_t) (n >> 32));
}


/* Receiving messages */
ngx_int_t ngx_rtmp_receive_message(ngx_rtmp_session_t *s,
        ngx_rtmp_header_t *h, ngx_chain_t *in);
ngx_int_t ngx_rtmp_protocol_message_handler(ngx_rtmp_session_t *s,
        ngx_rtmp_header_t *h, ngx_chain_t *in);
ngx_int_t ngx_rtmp_user_message_handler(ngx_rtmp_session_t *s,
        ngx_rtmp_header_t *h, ngx_chain_t *in);
ngx_int_t ngx_rtmp_aggregate_message_handler(ngx_rtmp_session_t *s,
        ngx_rtmp_header_t *h, ngx_chain_t *in);
ngx_int_t ngx_rtmp_amf_message_handler(ngx_rtmp_session_t *s,
        ngx_rtmp_header_t *h, ngx_chain_t *in);
ngx_int_t ngx_rtmp_amf_shared_object_handler(ngx_rtmp_session_t *s,
        ngx_rtmp_header_t *h, ngx_chain_t *in);


/* Shared output buffers */

/* Store refcount in negative bytes of shared buffer */

#define NGX_RTMP_REFCOUNT_TYPE              uint32_t
#define NGX_RTMP_REFCOUNT_BYTES             sizeof(NGX_RTMP_REFCOUNT_TYPE)

#define ngx_rtmp_ref(b)                     \
    *((NGX_RTMP_REFCOUNT_TYPE*)(b) - 1)

#define ngx_rtmp_ref_set(b, v)              \
    ngx_rtmp_ref(b) = v

#define ngx_rtmp_ref_get(b)                 \
    ++ngx_rtmp_ref(b)

#define ngx_rtmp_ref_put(b)                 \
    --ngx_rtmp_ref(b)

#define ngx_rtmp_get_chunk_info(b)          \
    ((ngx_rtmp_chunk_info_t*)&ngx_rtmp_ref(b) - 1)

ngx_chain_t * ngx_rtmp_alloc_shared_buf(ngx_rtmp_core_srv_conf_t *cscf);
void ngx_rtmp_free_shared_chain(ngx_rtmp_core_srv_conf_t *cscf,
        ngx_chain_t *in);
ngx_chain_t * ngx_rtmp_append_shared_bufs(ngx_rtmp_core_srv_conf_t *cscf,
        ngx_chain_t *head, ngx_chain_t *in);

#define ngx_rtmp_acquire_shared_chain(in)   \
    ngx_rtmp_ref_get(in);                   \


/* Sending messages */
void ngx_rtmp_prepare_message(ngx_rtmp_session_t *s, ngx_rtmp_header_t *h,
        ngx_rtmp_header_t *lh, ngx_chain_t *out);
ngx_int_t ngx_rtmp_send_message(ngx_rtmp_session_t *s, ngx_chain_t *out,
        ngx_uint_t priority);

/* Note on priorities:
 * the bigger value the lower the priority.
 * priority=0 is the highest */


#define NGX_RTMP_LIMIT_SOFT         0
#define NGX_RTMP_LIMIT_HARD         1
#define NGX_RTMP_LIMIT_DYNAMIC      2

char * ngx_rtmp_stat_get_aac_profile(ngx_uint_t p, ngx_uint_t sbr, ngx_uint_t ps);
char * ngx_rtmp_stat_get_avc_profile(ngx_uint_t p);
ngx_int_t  ngx_rtmp_parse_tcurl(ngx_str_t args, ngx_str_t tcurl, ngx_str_t *host_in, ngx_int_t *port_in);
ngx_int_t  ngx_rtmp_arg(ngx_str_t args, u_char *name, size_t len, ngx_str_t *value);
ngx_int_t  ngx_rtmp_parse_host(ngx_pool_t *pool, ngx_str_t hosts, ngx_str_t *host_in, ngx_int_t *port_in);
ngx_int_t  ngx_rtmp_parse_http_body(ngx_pool_t *pool, ngx_log_t *log, ngx_chain_t* in,
        u_char *ret, u_char **content, ngx_uint_t *length);


/* Protocol control messages */
ngx_chain_t * ngx_rtmp_create_chunk_size(ngx_rtmp_session_t *s,
        uint32_t chunk_size);
ngx_chain_t * ngx_rtmp_create_abort(ngx_rtmp_session_t *s,
        uint32_t csid);
ngx_chain_t * ngx_rtmp_create_ack(ngx_rtmp_session_t *s,
        uint32_t seq);
ngx_chain_t * ngx_rtmp_create_ack_size(ngx_rtmp_session_t *s,
        uint32_t ack_size);
ngx_chain_t * ngx_rtmp_create_bandwidth(ngx_rtmp_session_t *s,
        uint32_t ack_size, uint8_t limit_type);

ngx_int_t ngx_rtmp_send_chunk_size(ngx_rtmp_session_t *s,
        uint32_t chunk_size);
ngx_int_t ngx_rtmp_send_abort(ngx_rtmp_session_t *s,
        uint32_t csid);
ngx_int_t ngx_rtmp_send_ack(ngx_rtmp_session_t *s,
        uint32_t seq);
ngx_int_t ngx_rtmp_send_ack_size(ngx_rtmp_session_t *s,
        uint32_t ack_size);
ngx_int_t ngx_rtmp_send_bandwidth(ngx_rtmp_session_t *s,
        uint32_t ack_size, uint8_t limit_type);

/* User control messages */
ngx_chain_t * ngx_rtmp_create_stream_begin(ngx_rtmp_session_t *s,
        uint32_t msid);
ngx_chain_t * ngx_rtmp_create_stream_eof(ngx_rtmp_session_t *s,
        uint32_t msid);
ngx_chain_t * ngx_rtmp_create_stream_dry(ngx_rtmp_session_t *s,
        uint32_t msid);
ngx_chain_t * ngx_rtmp_create_set_buflen(ngx_rtmp_session_t *s,
        uint32_t msid, uint32_t buflen_msec);
ngx_chain_t * ngx_rtmp_create_recorded(ngx_rtmp_session_t *s,
        uint32_t msid);
ngx_chain_t * ngx_rtmp_create_ping_request(ngx_rtmp_session_t *s,
        uint32_t timestamp);
ngx_chain_t * ngx_rtmp_create_ping_response(ngx_rtmp_session_t *s,
        uint32_t timestamp);

ngx_int_t ngx_rtmp_send_stream_begin(ngx_rtmp_session_t *s,
        uint32_t msid);
ngx_int_t ngx_rtmp_send_stream_eof(ngx_rtmp_session_t *s,
        uint32_t msid);
ngx_int_t ngx_rtmp_send_stream_dry(ngx_rtmp_session_t *s,
        uint32_t msid);
ngx_int_t ngx_rtmp_send_set_buflen(ngx_rtmp_session_t *s,
        uint32_t msid, uint32_t buflen_msec);
ngx_int_t ngx_rtmp_send_recorded(ngx_rtmp_session_t *s,
        uint32_t msid);
ngx_int_t ngx_rtmp_send_ping_request(ngx_rtmp_session_t *s,
        uint32_t timestamp);
ngx_int_t ngx_rtmp_send_ping_response(ngx_rtmp_session_t *s,
        uint32_t timestamp);

/* AMF sender/receiver */
ngx_int_t ngx_rtmp_append_amf(ngx_rtmp_session_t *s,
        ngx_chain_t **first, ngx_chain_t **last,
        ngx_rtmp_amf_elt_t *elts, size_t nelts);
ngx_int_t ngx_rtmp_receive_amf(ngx_rtmp_session_t *s, ngx_chain_t *in,
        ngx_rtmp_amf_elt_t *elts, size_t nelts);

ngx_chain_t * ngx_rtmp_create_amf(ngx_rtmp_session_t *s, ngx_rtmp_header_t *h,
        ngx_rtmp_amf_elt_t *elts, size_t nelts);
ngx_int_t ngx_rtmp_send_amf(ngx_rtmp_session_t *s, ngx_rtmp_header_t *h,
        ngx_rtmp_amf_elt_t *elts, size_t nelts);

/* AMF status sender */
ngx_chain_t * ngx_rtmp_create_status(ngx_rtmp_session_t *s, char *code,
        char* level, char *desc);
ngx_chain_t * ngx_rtmp_create_play_status(ngx_rtmp_session_t *s, char *code,
        char* level, ngx_uint_t duration, ngx_uint_t bytes);
ngx_chain_t * ngx_rtmp_create_sample_access(ngx_rtmp_session_t *s);

ngx_int_t ngx_rtmp_send_status(ngx_rtmp_session_t *s, char *code,
        char* level, char *desc);
ngx_int_t ngx_rtmp_send_play_status(ngx_rtmp_session_t *s, char *code,
        char* level, ngx_uint_t duration, ngx_uint_t bytes);
ngx_int_t ngx_rtmp_send_sample_access(ngx_rtmp_session_t *s);
ngx_chain_t * ngx_rtmp_create_ret_status(ngx_rtmp_session_t *s, char *code, char *desc);
ngx_int_t ngx_rtmp_send_ret_status(ngx_rtmp_session_t *s, char *code, char *desc);


/* Frame types */
#define NGX_RTMP_VIDEO_KEY_FRAME            1
#define NGX_RTMP_VIDEO_INTER_FRAME          2
#define NGX_RTMP_VIDEO_DISPOSABLE_FRAME     3


static ngx_inline ngx_int_t
ngx_rtmp_get_video_frame_type(ngx_chain_t *in)
{
    return (in->buf->pos[0] & 0xf0) >> 4;
}


static ngx_inline ngx_int_t
ngx_rtmp_is_codec_header(ngx_chain_t *in)
{
    return in->buf->pos + 1 < in->buf->last && in->buf->pos[1] == 0;
}


static ngx_inline ngx_uint_t
ngx_rtmp_get_remote_port(ngx_rtmp_session_t *s)
{
    ngx_uint_t            port;
    struct sockaddr_in   *sin;
#if (NGX_HAVE_INET6)
    struct sockaddr_in6  *sin6;
#endif

    if (s->connection != NULL &&
        s->connection->sockaddr != NULL) {

        switch (s->connection->sockaddr->sa_family) {

#if (NGX_HAVE_INET6)
            case AF_INET6:
                sin6 = (struct sockaddr_in6 *) s->connection->sockaddr;
                port = ntohs(sin6->sin6_port);
                break;
#endif

#if (NGX_HAVE_UNIX_DOMAIN)
            case AF_UNIX:
                port = 0;
                break;
#endif

            default: /* AF_INET */
                sin = (struct sockaddr_in *) s->connection->sockaddr;
                port = ntohs(sin->sin_port);
                break;
        }
    } else {
        port = 0;
    }

    return port;
}


static inline ngx_int_t
ngx_rtmp_set_fincode(ngx_rtmp_session_t *s, ngx_uint_t fincode)
{
    s->finalize_code = fincode;
    return NGX_OK;
}


static ngx_inline ngx_int_t
ngx_rtmp_string_check(ngx_str_t *str)
{
    ngx_uint_t          i;
    char               *table;

#define ASCII_TABLE_LEN 256
    // 1 for especial char; 0 for normal char
    static char ascii_table[ASCII_TABLE_LEN] = {
        1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1,
        1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1,
        1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 0, 0, 1,
        0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 1, 1, 1, 1, 1,
        1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
        0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 1, 1, 1, 0,
        1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
        0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
        0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
        0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
        0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
        0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
        0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
        0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
        0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
        0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    };
#undef ASCII_TABLE_LEN

    for (i = 0, table = ascii_table; i < str->len; ++ i) {
        if (*(table + str->data[i]) == 1) {
            return NGX_ERROR;
        }
    }

    return NGX_OK;
}


void ngx_rtmp_time_update_timer(ngx_event_t *ev);

extern ngx_rtmp_bandwidth_t                 ngx_rtmp_bw_out;
extern ngx_rtmp_bandwidth_t                 ngx_rtmp_bw_in;

extern ngx_uint_t                           ngx_rtmp_naccepted;
extern ngx_uint_t                           ngx_rtmp_hls_naccepted;
extern ngx_uint_t                           ngx_rtmp_hdl_naccepted;

#if (nginx_version >= 1007011)
extern ngx_queue_t                          ngx_rtmp_init_queue;
#elif (nginx_version >= 1007005)
extern ngx_thread_volatile ngx_queue_t      ngx_rtmp_init_queue;
#else
extern ngx_thread_volatile ngx_event_t     *ngx_rtmp_init_queue;
#endif


extern ngx_uint_t                           ngx_rtmp_max_module;
extern ngx_module_t                         ngx_rtmp_core_module;
extern ngx_module_t                         ngx_rtmp_netcall_module;
extern ngx_module_t                         ngx_rtmp_notify_module;
extern ngx_module_t                         ngx_rtmp_live_module;
extern ngx_module_t                         ngx_rtmp_hdl_module;
extern ngx_module_t                         ngx_rtmp_log_module;


#endif /* _NGX_RTMP_H_INCLUDED_ */
