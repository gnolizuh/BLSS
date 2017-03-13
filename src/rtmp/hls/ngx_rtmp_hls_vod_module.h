#ifndef _NGX_RTMP_HLS_VOD_H_INCLUDED_
#define _NGX_RTMP_HLS_VOD_H_INCLUDED_

#include <ngx_config.h>
#include <ngx_core.h>

typedef struct ngx_rtmp_hls_vod_ctx_s ngx_rtmp_hls_vod_ctx_t;

typedef struct {
    uint64_t                            id;
    double                              duration;
    unsigned                            active:1;
    unsigned                            discont:1; /* before */
} ngx_rtmp_hls_vod_frag_t;

struct ngx_rtmp_hls_vod_ctx_s {
    ngx_file_t                          vod_file;

    u_char                              time[128];
    uint64_t                            ts_time;
    ngx_uint_t                          vod_max_frag;

    ngx_str_t                           index_path;
    ngx_str_t                           index_file_name;
    ngx_str_t                           vod_path;
    ngx_str_t                           vod_stream;
    ngx_str_t                           vod_m3u8_tmp;
    ngx_str_t                           vod_m3u8_bak;
    ngx_str_t                           vod_m3u8;

    uint64_t                            frag;
    uint64_t                            frag_ts;
    uint64_t                            frag_ts_system;
    uint64_t                            frag_seq;
    uint64_t                            last_ts;
    uint64_t                            last_video_ts;
    uint64_t                            last_audio_ts;
    ngx_uint_t                          nfrags;
    ngx_uint_t                          winfrags;
    ngx_rtmp_hls_vod_frag_t             *frags; /* circular 2 * winfrags + 1 */
    ngx_uint_t                          audio_cc;
    ngx_uint_t                          video_cc;
    ngx_uint_t                          psi_cc;
    uint64_t                            aframe_base;
    uint64_t                            aframe_num;
    ngx_buf_t                          *aframe;
    uint64_t                            aframe_pts;
    unsigned                            m3u8_header:1;
    unsigned                            publisher:1;
    unsigned                            opened:1;
    unsigned                            closed:1;

    unsigned                            first_frame:1;
    uint32_t                            base_timestamp;
};

typedef struct {
    ngx_flag_t                          hls_vod;
    ngx_msec_t                          hls_vod_fragment;
    ngx_flag_t                          hls_vod_ts_zero;
    ngx_msec_t                          max_fraglen;
    ngx_msec_t                          sync;
    ngx_uint_t                          winfrags;
    ngx_str_t                           path;
    ngx_uint_t                          naming;
    ngx_uint_t                          slicing;
    ngx_uint_t                          type;
    ngx_msec_t                          max_audio_delay;
    size_t                              audio_buffer_size;

    ngx_int_t                           user_id;
    ngx_int_t                           hls_vod_is_public;
    ngx_str_t                           hls_vod_bucket;
    ngx_str_t                           hls_vod_url;
    ngx_uint_t                          mp4_vod_name_format;
    ngx_flag_t                          mp4_vod;
    ngx_int_t                           mp4_vod_is_public;
    ngx_str_t                           mp4_vod_bucket;
    ngx_str_t                           mp4_vod_url;
    ngx_str_t                           region_mp4;
    ngx_str_t                           region_hls;
    ngx_str_t                           host_mp4;
    ngx_str_t                           host_hls;

    ngx_flag_t                          hls_vod_auto_merge;

    ngx_flag_t                          live_delay;
    ngx_msec_t                          live_delay_time;
    ngx_str_t                           live_delay_host;
    ngx_str_t                           live_delay_app;
} ngx_rtmp_hls_vod_app_conf_t;

#endif
