
#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_http.h>
#include "ngx_rtmp.h"

ngx_int_t
ngx_rtmp_arg(ngx_str_t args, u_char *name, size_t len, ngx_str_t *value)
{
    u_char  *p, *last;

    if (args.len == 0) {
        return NGX_DECLINED;
    }

    p = args.data;
    last = p + args.len;

    for ( /* void */ ; p < last; p++) {

        /* we need '=' after name, so drop one char from last */

        p = ngx_strlcasestrn(p, last - 1, name, len - 1);

        if (p == NULL) {
            return NGX_DECLINED;
        }

        if ((p == args.data || *(p - 1) == '&') && *(p + len) == '=') {

            value->data = p + len + 1;

            p = ngx_strlchr(p, last, '&');

            if (p == NULL) {
                p = args.data + args.len;
            }

            value->len = p - value->data;

            return NGX_OK;
        }
    }

    return NGX_DECLINED;
}


ngx_int_t
ngx_rtmp_parse_tcurl(ngx_str_t args, ngx_str_t tcurl, ngx_str_t *host_in, ngx_int_t *port_in)
{
    u_char  *port, *slash, *last;

    if (tcurl.len == 0 || !host_in || !port_in) {
        return NGX_DECLINED;
    }

    if (ngx_strncmp(tcurl.data, "rtmp://", 7) == 0) {
        tcurl.data += 7;
        tcurl.len  -= 7;
    } else {
        return NGX_DECLINED;
    }

    last = tcurl.data + tcurl.len;

    slash = ngx_strlchr(tcurl.data, tcurl.data + tcurl.len, '/');
    if (slash != NULL) {
        last = slash;
    } else {
        return NGX_DECLINED;
    }

    port = ngx_strlchr(tcurl.data, last, ':');
    if (port != NULL) {
        *port_in = ngx_atoi(port + 1, last - port - 1);
    }

    if (ngx_rtmp_arg(args, (u_char *)"vhost", 5, host_in) != NGX_OK) {
        host_in->data = tcurl.data;
        host_in->len  = (port ? port : slash) - tcurl.data;
    }

    return NGX_OK;
}

ngx_int_t
ngx_rtmp_parse_host(ngx_pool_t *pool, ngx_str_t hosts, ngx_str_t *host_in, ngx_int_t *port_in)
{
    u_char  *port, *last;

    if (hosts.len == 0 || !host_in || !port_in) {
        return NGX_DECLINED;
    }

    last = hosts.data + hosts.len;

    port = ngx_strlchr(hosts.data, last, ':');
    if (port != NULL) {

        hosts.len = port - hosts.data;

        *port_in = ngx_atoi(port + 1, last - port - 1);
    }

    host_in->len = hosts.len;
    host_in->data = ngx_pstrdup(pool, &hosts);

    return NGX_OK;
}

ngx_int_t
ngx_rtmp_parse_http_body(ngx_pool_t *pool, ngx_log_t *log, ngx_chain_t* in,
        u_char *ret, u_char **content, ngx_uint_t *content_length)
{
    ngx_uint_t      ncrs;
    ngx_uint_t      nheader;
    ngx_buf_t      *b;
    ngx_chain_t    *in_tmp;
    u_char         *p;

    if (pool == NULL || ret == NULL || in == NULL
            || content_length == NULL || content == NULL) {
        return NGX_ERROR;
    }
    //skip header
    ncrs = 0;
    nheader = 0;
    b = NULL;
    while (in && ncrs != 2) {
        b = in->buf;

        for (; b->pos != b->last && ncrs != 2; ++b->pos) {
            switch (*b->pos) {
                case '\n':
                    ++ncrs;
                case '\r':
                    break;
                default:
                    ncrs = 0;
            }
            if (++nheader == 10) {
                *ret = *b->pos;
                switch (*b->pos) {
                    case (u_char) '2':
                        break;
                    case (u_char) '3':
                        return NGX_AGAIN;
                    default:
                        return NGX_ERROR;
                }
            }
        }
        if (b->pos == b->last) {
            in = in->next;
        }
    }
    
    if (b->pos == b->last && in) {
        in = in->next;
    }

    in_tmp = in;
    //countent length
    *content_length = 0;
    while (in_tmp) {
        *content_length += in_tmp->buf->last - in_tmp->buf->pos;
        in_tmp = in_tmp->next;
    }

    if (*content_length == 0) {
        return NGX_OK;
    }

    *content = ngx_palloc(pool, *content_length);
    p = *content;

    //copy content
    while (in) {
        p = ngx_cpymem(p, in->buf->pos, (in->buf->last - in->buf->pos));
        in = in->next;
    }
    return NGX_OK;
}
