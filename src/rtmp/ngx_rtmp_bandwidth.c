
/*
 * Copyright (C) Roman Arutyunyan
 */


#include <ngx_config.h>
#include <ngx_core.h>
#include "ngx_rtmp_bandwidth.h"

void
ngx_rtmp_update_bandwidth(ngx_rtmp_bandwidth_t *bw, uint32_t bytes)
{
    if (ngx_cached_time->sec > bw->intl_end) {

        bw->bandwidth = ngx_cached_time->sec > bw->last_timestamp
            ? bw->intl_bytes / (ngx_cached_time->sec - bw->last_timestamp) : 0;

        bw->intl_bytes = 0;
        bw->intl_end = ngx_cached_time->sec + NGX_RTMP_BANDWIDTH_INTERVAL;
        bw->last_timestamp = ngx_cached_time->sec; // system timestamp.
    }

    bw->bytes += bytes;
    bw->intl_bytes += bytes;
}

void
ngx_rtmp_update_av_bandwidth(ngx_rtmp_av_bandwidth_t *bw, uint8_t audio, uint32_t bytes, uint32_t timestamp)
{
    if (ngx_cached_time->sec > bw->intl_end) {

        bw->a_intl_bw = ngx_cached_time->sec > bw->intl_start ?
            bw->a_intl_bytes / (ngx_cached_time->sec - bw->intl_start) : 0;
        bw->v_intl_bw = ngx_cached_time->sec > bw->intl_start ?
            bw->v_intl_bytes / (ngx_cached_time->sec - bw->intl_start) : 0;

        bw->a_intl_bw_exp = bw->a_intl_last_pts > bw->a_intl_first_pts ?
            (bw->a_intl_bytes * 1000) / (bw->a_intl_last_pts - bw->a_intl_first_pts) : 0;
        bw->v_intl_bw_exp = bw->v_intl_last_pts > bw->v_intl_first_pts ?
            (bw->v_intl_bytes * 1000) / (bw->v_intl_last_pts - bw->v_intl_first_pts) : 0;

        bw->a_intl_bytes = 0;
        bw->v_intl_bytes = 0;

        bw->intl_end = ngx_cached_time->sec + NGX_RTMP_BANDWIDTH_INTERVAL;
        bw->intl_start = ngx_cached_time->sec; // system timestamp.

        bw->a_intl_first_pts = bw->a_intl_last_pts;
        bw->v_intl_first_pts = bw->v_intl_last_pts;

        bw->total_diff_bytes += (bw->a_intl_bw_exp + bw->v_intl_bw_exp) - (bw->a_intl_bw + bw->v_intl_bw);
    }

    if (audio) {
        bw->a_bytes += bytes;
        bw->a_intl_bytes += bytes;
        bw->a_intl_last_pts = timestamp;
    } else {
        bw->v_bytes += bytes;
        bw->v_intl_bytes += bytes;
        bw->v_intl_last_pts = timestamp;
    }
}

void
ngx_rtmp_cal_av_bandwidth(ngx_rtmp_av_bandwidth_t *bw)
{
    if (ngx_cached_time->sec > bw->intl_end) {

        bw->a_intl_bw = ngx_cached_time->sec - bw->intl_start ?
            bw->a_intl_bytes / (ngx_cached_time->sec - bw->intl_start) : 0;
        bw->v_intl_bw = ngx_cached_time->sec - bw->intl_start ?
            bw->v_intl_bytes / (ngx_cached_time->sec - bw->intl_start) : 0;

        bw->a_intl_bw_exp = bw->a_intl_last_pts > bw->a_intl_first_pts ?
            (bw->a_intl_bytes * 1000) / (bw->a_intl_last_pts - bw->a_intl_first_pts) : 0;
        bw->v_intl_bw_exp = bw->v_intl_last_pts > bw->v_intl_first_pts ?
            (bw->v_intl_bytes * 1000) / (bw->v_intl_last_pts - bw->v_intl_first_pts) : 0;

        bw->a_intl_bytes = 0;
        bw->v_intl_bytes = 0;

        bw->intl_end = ngx_cached_time->sec + NGX_RTMP_BANDWIDTH_INTERVAL;
        bw->intl_start = ngx_cached_time->sec; // system timestamp.

        bw->a_intl_first_pts = bw->a_intl_last_pts;
        bw->v_intl_first_pts = bw->v_intl_last_pts;

        bw->total_diff_bytes += (bw->a_intl_bw_exp + bw->v_intl_bw_exp) - (bw->a_intl_bw + bw->v_intl_bw);
    }
}
