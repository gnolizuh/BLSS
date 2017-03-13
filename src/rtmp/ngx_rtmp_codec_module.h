
/*
 * Copyright (C) Roman Arutyunyan
 */


#ifndef _NGX_RTMP_CODEC_H_INCLUDED_
#define _NGX_RTMP_CODEC_H_INCLUDED_


#include <ngx_config.h>
#include <ngx_core.h>
#include <nginx.h>
#include "ngx_rtmp.h"


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
    u_char                      avc_conf_record[21];
    ngx_uint_t                  avc_nal_bytes;
    ngx_uint_t                  avc_ref_frames;
    ngx_uint_t                  sample_rate;    /* 5512, 11025, 22050, 44100 */
    ngx_uint_t                  sample_size;    /* 1=8bit, 2=16bit */
    ngx_uint_t                  audio_channels; /* 1, 2 */
    u_char                      profile[32];
    u_char                      level[32];
    //userdefine for delay record
    u_char                      stream_id[NGX_RTMP_STREAM_ID_LEN + 1];//md5 of push url + current time
    ngx_uint_t                  utc_start_time;//first audio frame pts
    u_char                      x[128]; //x-forword-for
    ngx_uint_t                  interval;//delay record interval(ms)
    ngx_uint_t                  first_audio_pts;//first audio pts
    //userdefine for delay record end

    ngx_chain_t                *video_header;
    ngx_chain_t                *aac_header;

    ngx_rtmp_header_t           metah;
    ngx_rtmp_header_t           msgh;

    ngx_chain_t                *meta;
    ngx_chain_t                *msg;
    ngx_uint_t                  meta_version;
} ngx_rtmp_codec_ctx_t;

extern ngx_module_t  ngx_rtmp_codec_module;

void ngx_rtmp_codec_dump_header(ngx_rtmp_session_t *s, const char *type,
       ngx_chain_t *in);

#endif /* _NGX_RTMP_LIVE_H_INCLUDED_ */
