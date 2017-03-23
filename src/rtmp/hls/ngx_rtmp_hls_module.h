
/*
 * Copyright (C) Gino Hu
 */


#ifndef _NGX_RTMP_HLS_H_INCLUDED_
#define _NGX_RTMP_HLS_H_INCLUDED_


#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_http.h>
#include <ngx_rtmp_cmd_module.h>
#include <ngx_rtmp_relay_module.h>
#include <ngx_rtmp_netcall_module.h>
#include <ngx_rtmp.h>

#define NGX_RTMP_HLS_EXIPRE_FILE_NAME     ".expinfo"
#define NGX_RTMP_HLS_EXIPRE_FILE_NAME_BAK NGX_RTMP_HLS_EXIPRE_FILE_NAME".bak"
#define NGX_RTMP_HLS_DIR_ACCESS           0744
#define ngx_rtmp_hls_get_module_app_conf(app_conf, module)  (app_conf ? \
					app_conf[module.ctx_index] : NULL)

/* AVC NAL unit types */
enum {
    AVC_NAL_SLICE           = 1,
    AVC_NAL_DPA             = 2,
    AVC_NAL_DPB             = 3,
    AVC_NAL_DPC             = 4,
    AVC_NAL_IDR_SLICE       = 5,
    AVC_NAL_SEI             = 6,
    AVC_NAL_SPS             = 7,
    AVC_NAL_PPS             = 8,
    AVC_NAL_AUD             = 9,
    AVC_NAL_END_SEQUENCE    = 10,
    AVC_NAL_END_STREAM      = 11,
    AVC_NAL_FILLER_DATA     = 12,
    AVC_NAL_SPS_EXT         = 13,
    AVC_NAL_AUXILIARY_SLICE = 19,
    AVC_NAL_FF_IGNORE       = 0xff0f001,
};


/* HEVC NAL unit types */
enum NALUnitType {
    HEVC_NAL_TRAIL_N    = 0,
    HEVC_NAL_TRAIL_R    = 1,
    HEVC_NAL_TSA_N      = 2,
    HEVC_NAL_TSA_R      = 3,
    HEVC_NAL_STSA_N     = 4,
    HEVC_NAL_STSA_R     = 5,
    HEVC_NAL_RADL_N     = 6,
    HEVC_NAL_RADL_R     = 7,
    HEVC_NAL_RASL_N     = 8,
    HEVC_NAL_RASL_R     = 9,
    HEVC_NAL_BLA_W_LP   = 16,
    HEVC_NAL_BLA_W_RADL = 17,
    HEVC_NAL_BLA_N_LP   = 18,
    HEVC_NAL_IDR_W_RADL = 19,
    HEVC_NAL_IDR_N_LP   = 20,
    HEVC_NAL_CRA_NUT    = 21,
    HEVC_NAL_VPS        = 32,
    HEVC_NAL_SPS        = 33,
    HEVC_NAL_PPS        = 34,
    HEVC_NAL_AUD        = 35,
    HEVC_NAL_EOS_NUT    = 36,
    HEVC_NAL_EOB_NUT    = 37,
    HEVC_NAL_FD_NUT     = 38,
    HEVC_NAL_SEI_PREFIX = 39,
    HEVC_NAL_SEI_SUFFIX = 40,
};


typedef struct ngx_rtmp_hls_ctx_s ngx_rtmp_hls_ctx_t;

typedef struct {
    uint64_t                            id;
    double                              duration;
    unsigned                            active:1;
    unsigned                            discont:1; /* before */
} ngx_rtmp_hls_frag_t;


typedef struct {
    ngx_str_t                           suffix;
    ngx_array_t                         args;
} ngx_rtmp_hls_variant_t;


struct ngx_rtmp_hls_ctx_s {
    ngx_file_t                          file, indexfile, m3u8file, m3u8filebak;
    ngx_file_t                          expire_file;
    u_char                              time[128];
    uint64_t                            ts_time;
    ngx_str_t                           upstream_url;
    ngx_str_t                           playlist;

    ngx_str_t                           index_path;
    ngx_str_t                           index_file_name;
    ngx_str_t                           playlist_bak;
    ngx_str_t                           var_playlist;
    ngx_str_t                           var_playlist_bak;
    ngx_str_t                           stream;
    ngx_str_t                           expire;
    uint64_t                            frag;
    uint64_t                            frag_ts;
    uint64_t                            frag_ts_system;
    uint64_t                            frag_seq;
    uint64_t                            last_video_ts;
    uint64_t                            last_audio_ts;
    ngx_uint_t                          nfrags;
    ngx_uint_t                          winfrags;
    ngx_rtmp_hls_frag_t                *frags; /* circular 2 * winfrags + 1 */
    ngx_uint_t                          audio_cc;
    ngx_uint_t                          video_cc;
    ngx_uint_t                          psi_cc;
    uint64_t                            aframe_base;
    uint64_t                            aframe_num;
    ngx_buf_t                          *aframe;
    uint64_t                            aframe_pts;
    ngx_rtmp_hls_variant_t             *var;
    ngx_event_handler_pt                write_handler_backup;
    unsigned                            m3u8_header:1;
    unsigned                            publisher:1;
    unsigned                            opened:1;
    unsigned                            closed:1;
    unsigned                            got_first_frame:1;
    uint32_t                            base_timestamp;
};


typedef struct {
    ngx_flag_t                          hls;
    ngx_msec_t                          hls_fragment;
    ngx_uint_t                          hls_fragment_wave;
    ngx_msec_t                          hls_playlist_length;
    ngx_msec_t                          max_fraglen;
    ngx_msec_t                          muxdelay;
    ngx_msec_t                          sync;
    ngx_uint_t                          winfrags;
    ngx_flag_t                          continuous;
    ngx_flag_t                          nested;
    ngx_str_t                           path;
    ngx_uint_t                          naming;
    ngx_uint_t                          slicing;
    ngx_uint_t                          type;
    ngx_path_t                         *slot;
    ngx_msec_t                          max_audio_delay;
    size_t                              audio_buffer_size;
    ngx_flag_t                          cleanup;
    ngx_array_t                        *variant;
    ngx_str_t                           base_url;

    ngx_int_t                           granularity;
} ngx_rtmp_hls_app_conf_t;


typedef struct {
    ngx_rtmp_session_t                 *s;
} ngx_rtmp_http_hls_ctx_t;


ngx_int_t ngx_rtmp_http_hls_build_url(ngx_rtmp_session_t *s, ngx_str_t *remote_ip,
    ngx_int_t remote_port);
ngx_int_t ngx_rtmp_hls_copy(ngx_rtmp_session_t *s, void *dst, u_char **src, size_t n,
    ngx_chain_t **in);
ngx_int_t ngx_rtmp_hls_parse_aac_header(ngx_rtmp_session_t *s, ngx_uint_t *objtype,
    ngx_uint_t *srindex, ngx_uint_t *chconf);
ngx_int_t ngx_rtmp_hls_append_aud_h264(ngx_rtmp_session_t *s, ngx_buf_t *out);
ngx_int_t ngx_rtmp_hls_append_aud_h265(ngx_rtmp_session_t *s, ngx_buf_t *out);
ngx_int_t ngx_rtmp_hls_append_sps_pps_h264(ngx_rtmp_session_t *s, ngx_buf_t *out);
ngx_int_t ngx_rtmp_hls_append_sps_pps_h265(ngx_rtmp_session_t *s, ngx_buf_t *out);
ngx_int_t ngx_rtmp_hls_rename_file(u_char *src, u_char *dst);

#endif /* _NGX_RTMP_HLS_H_INCLUDED_ */
