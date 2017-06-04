
/*
 * Copyright (C) 2017 Gnolizuh
 */

#include <ngx_core.h>
#include <ngx_rtmp.h>


ngx_int_t
ngx_rtmp_parse_tcurl(ngx_str_t tcurl, ngx_str_t *host, ngx_uint_t *host_mask)
{
    u_char                     *port, *last;

    if (ngx_strncmp(tcurl.data, "rtmp://", 7) == 0) {
        *host_mask |= NGX_RTMP_HOSTNAME_RTMP;
    } else if (ngx_strncmp(tcurl.data, "http://", 7) == 0) {
        *host_mask |= NGX_RTMP_HOSTNAME_HTTP_FLV;
    } else {
        return NGX_ERROR;
    }

    tcurl.data += 7;
    tcurl.len  -= 7;

    last = ngx_strlchr(tcurl.data, tcurl.data + tcurl.len, '/');
    if (last == NULL) {
        return NGX_ERROR;
    }

    port = ngx_strlchr(tcurl.data, last, ':');

    host->data = tcurl.data;
    host->len = (port ? port : last) - host->data;

    return NGX_OK;
}
