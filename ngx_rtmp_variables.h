
/*
 * Copyright (C) Gnolizuh
 */


#ifndef _NGX_RTMP_VARIABLES_H_INCLUDED_
#define _NGX_RTMP_VARIABLES_H_INCLUDED_


#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_http.h>

#if (NGX_PCRE)

typedef struct {
    ngx_uint_t                 capture;
    ngx_int_t                  index;
} ngx_rtmp_regex_variable_t;


typedef struct {
    ngx_regex_t               *regex;
    ngx_uint_t                 ncaptures;
    ngx_rtmp_regex_variable_t *variables;
    ngx_uint_t                 nvariables;
    ngx_str_t                  name;
} ngx_rtmp_regex_t;

#endif


#endif /* _NGX_RTMP_VARIABLES_H_INCLUDED_ */
