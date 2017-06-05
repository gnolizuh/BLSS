
/*
 * Original work Copyright (C) Roman Arutyunyan
 * Modified work Copyright (C) 2017 Gnolizuh
 */


#ifndef _NGX_RTMP_CODEC_H_INCLUDED_
#define _NGX_RTMP_CODEC_H_INCLUDED_


#include <ngx_config.h>
#include <ngx_core.h>
#include "ngx_rtmp.h"


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

/* Audio codecs */
enum {
    /* Uncompressed codec id is actually 0,
     * but we use another value for consistency */
    NGX_RTMP_AUDIO_UNCOMPRESSED     = 16,
    NGX_RTMP_AUDIO_ADPCM            = 1,
    NGX_RTMP_AUDIO_MP3              = 2,
    NGX_RTMP_AUDIO_LINEAR_LE        = 3,
    NGX_RTMP_AUDIO_NELLY16          = 4,
    NGX_RTMP_AUDIO_NELLY8           = 5,
    NGX_RTMP_AUDIO_NELLY            = 6,
    NGX_RTMP_AUDIO_G711A            = 7,
    NGX_RTMP_AUDIO_G711U            = 8,
    NGX_RTMP_AUDIO_AAC              = 10,
    NGX_RTMP_AUDIO_SPEEX            = 11,
    NGX_RTMP_AUDIO_MP3_8            = 14,
    NGX_RTMP_AUDIO_DEVSPEC          = 15,
};

enum {
    NGX_RTMP_AUDIO_FRAME_SIZE_AAC   = 1024,
    NGX_RTMP_AUDIO_FRAME_SIZE_MP3   = 1152,
};


/* Video codecs */
enum {
    NGX_RTMP_VIDEO_JPEG             = 1,
    NGX_RTMP_VIDEO_SORENSON_H263    = 2,
    NGX_RTMP_VIDEO_SCREEN           = 3,
    NGX_RTMP_VIDEO_ON2_VP6          = 4,
    NGX_RTMP_VIDEO_ON2_VP6_ALPHA    = 5,
    NGX_RTMP_VIDEO_SCREEN2          = 6,
    NGX_RTMP_VIDEO_H264             = 7,
    NGX_RTMP_VIDEO_H265             = 12
};


u_char * ngx_rtmp_get_audio_codec_name(ngx_uint_t id);
u_char * ngx_rtmp_get_video_codec_name(ngx_uint_t id);

#define NGX_RTMP_STREAM_ID_LEN  32
#define NGX_RTMP_SPS_MAX_LENGTH 256

typedef struct {
    ngx_uint_t                  width;
    ngx_uint_t                  height;
    ngx_uint_t                  duration;
    ngx_uint_t                  frame_rate;
    ngx_uint_t                  video_data_rate;
    ngx_uint_t                  video_codec_id;
    ngx_uint_t                  audio_data_rate;
    ngx_uint_t                  audio_codec_id;
    ngx_uint_t                  aac_profile;
    ngx_uint_t                  aac_chan_conf;
    ngx_uint_t                  aac_sbr;
    ngx_uint_t                  aac_ps;
    ngx_uint_t                  avc_profile;
    ngx_uint_t                  avc_compat;
    ngx_uint_t                  avc_level;
    u_char                      avc_conf_record[21]; /* TODO */
    ngx_uint_t                  avc_nal_bytes;
    ngx_uint_t                  avc_ref_frames;
    ngx_uint_t                  sample_rate;    /* 5512, 11025, 22050, 44100 */
    ngx_uint_t                  sample_size;    /* 1=8bit, 2=16bit */
    ngx_uint_t                  audio_channels; /* 1, 2 */
    u_char                      profile[32];
    u_char                      level[32];

    ngx_chain_t                *video_header;
    ngx_chain_t                *aac_header;

    ngx_rtmp_header_t           meta_header;
    ngx_rtmp_header_t           msgh;

    ngx_chain_t                *meta;
    ngx_chain_t                *meta_flv;
    ngx_chain_t                *msg;
    ngx_uint_t                  meta_version;
} ngx_rtmp_codec_ctx_t;


extern ngx_module_t  ngx_rtmp_codec_module;


#endif /* _NGX_RTMP_LIVE_H_INCLUDED_ */
