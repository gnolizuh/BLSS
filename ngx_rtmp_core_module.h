
/*
 * Copyright (C) Gnolizuh
 */


#ifndef _NGX_RTMP_CORE_H_INCLUDED_
#define _NGX_RTMP_CORE_H_INCLUDED_


#include <ngx_rtmp_variables.h>
#include <ngx_rtmp.h>


typedef struct {
#if (NGX_PCRE)
    ngx_rtmp_regex_t          *regex;
#endif
    ngx_rtmp_core_srv_conf_t  *server;   /* virtual name server conf */
    ngx_str_t                  name;
} ngx_rtmp_server_name_t;


#endif /* _NGX_RTMP_CORE_H_INCLUDED_ */