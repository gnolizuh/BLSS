
/*
 * Copyright (C) Gnolizuh
 */

#include <ngx_core.h>

ngx_int_t
ngx_rtmp_parse_tcurl(ngx_str_t tcurl, ngx_str_t *host)
{
    u_char                     *port, *last;

    if (tcurl.len == 7 &&
        ngx_strncmp(tcurl.data, "rtmp://", 7) == 0) {
        tcurl.data += 7;
        tcurl.len  -= 7;
    } else {
        return NGX_ERROR;
    }

    last = ngx_strlchr(tcurl.data, tcurl.data + tcurl.len, '/');
    if (last == NULL) {
        return NGX_ERROR;
    }

    port = ngx_strlchr(tcurl.data, last, ':');

    host->data = tcurl.data;
    host->len = (port ? port : last) - host->data;

    return NGX_OK;
}
