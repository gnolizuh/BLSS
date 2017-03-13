
/*
 * Copyright (C) Roman Arutyunyan
 */


#ifndef _NGX_RTMP_BANDWIDTH_H_INCLUDED_
#define _NGX_RTMP_BANDWIDTH_H_INCLUDED_


#include <ngx_config.h>
#include <ngx_core.h>


/* Bandwidth update interval in seconds */
#define NGX_RTMP_BANDWIDTH_INTERVAL     1

typedef struct {
    uint64_t            bytes;
    uint64_t            bandwidth;           /* bytes/sec */

    time_t              intl_end;
    uint32_t            intl_end_timestamp;
    uint32_t            last_timestamp;
    uint64_t            intl_bytes;
} ngx_rtmp_bandwidth_t;

typedef struct {
    uint64_t            a_bytes;
    uint64_t            a_intl_bytes;
    uint64_t            a_intl_bw;           /* bytes/sec */
    uint64_t            a_intl_bw_exp;       /* bytes/sec */
    uint32_t            a_intl_last_pts;
    uint32_t            a_intl_first_pts;

    uint64_t            v_bytes;
    uint64_t            v_intl_bytes;
    uint64_t            v_intl_bw;           /* bytes/sec */
    uint64_t            v_intl_bw_exp;       /* bytes/sec */
    uint32_t            v_intl_last_pts;
    uint32_t            v_intl_first_pts;

    uint64_t            total_diff_bytes;

    time_t              intl_end;
    uint32_t            intl_start;
} ngx_rtmp_av_bandwidth_t;

void ngx_rtmp_update_bandwidth(ngx_rtmp_bandwidth_t *bw, uint32_t bytes);
void ngx_rtmp_update_bandwidth_real(ngx_rtmp_bandwidth_t *bw, uint32_t bytes, uint32_t timestamp);
void ngx_rtmp_update_av_bandwidth(ngx_rtmp_av_bandwidth_t *bw, uint8_t audio, uint32_t bytes, uint32_t timestamp);
void ngx_rtmp_cal_av_bandwidth(ngx_rtmp_av_bandwidth_t *bw);

#endif /* _NGX_RTMP_BANDWIDTH_H_INCLUDED_ */
