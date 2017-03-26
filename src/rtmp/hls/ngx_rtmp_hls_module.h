
/*
 * Copyright (C) Gino Hu
 */


#ifndef _NGX_RTMP_HLS_H_INCLUDED_
#define _NGX_RTMP_HLS_H_INCLUDED_


ngx_int_t ngx_rtmp_hls_copy(ngx_rtmp_session_t *s, void *dst, u_char **src, size_t n,
    ngx_chain_t **in);


#endif /* _NGX_RTMP_HLS_H_INCLUDED_ */
