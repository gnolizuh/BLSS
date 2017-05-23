
/*
 * Copyright (C) Gnolizuh
 */

 #include <ngx_rtmp_variables.h>


 ngx_rtmp_regex_t *
 ngx_rtmp_regex_compile(ngx_conf_t *cf, ngx_regex_compile_t *rc)
 {
     u_char                     *p;
     size_t                      size;
     ngx_str_t                   name;
     ngx_uint_t                  i, n;
     ngx_rtmp_variable_t        *v;
     ngx_rtmp_regex_t           *re;
     ngx_rtmp_regex_variable_t  *rv;
     ngx_rtmp_core_main_conf_t  *cmcf;

     rc->pool = cf->pool;

     if (ngx_regex_compile(rc) != NGX_OK) {
         ngx_conf_log_error(NGX_LOG_EMERG, cf, 0, "%V", &rc->err);
         return NULL;
     }

     re = ngx_pcalloc(cf->pool, sizeof(ngx_rtmp_regex_t));
     if (re == NULL) {
         return NULL;
     }

     re->regex = rc->regex;
     re->ncaptures = rc->captures;
     re->name = rc->pattern;

     cmcf = ngx_rtmp_conf_get_module_main_conf(cf, ngx_rtmp_core_module);
     cmcf->ncaptures = ngx_max(cmcf->ncaptures, re->ncaptures);

     n = (ngx_uint_t) rc->named_captures;

     if (n == 0) {
         return re;
     }

     rv = ngx_palloc(rc->pool, n * sizeof(ngx_rtmp_regex_variable_t));
     if (rv == NULL) {
         return NULL;
     }

     re->variables = rv;
     re->nvariables = n;

     size = rc->name_size;
     p = rc->names;

     for (i = 0; i < n; i++) {
         rv[i].capture = 2 * ((p[0] << 8) + p[1]);

         name.data = &p[2];
         name.len = ngx_strlen(name.data);

         v = ngx_rtmp_add_variable(cf, &name, NGX_RTMP_VAR_CHANGEABLE);
         if (v == NULL) {
             return NULL;
         }

         rv[i].index = ngx_rtmp_get_variable_index(cf, &name);
         if (rv[i].index == NGX_ERROR) {
             return NULL;
         }

         v->get_handler = ngx_rtmp_variable_not_found;

         p += size;
     }

     return re;
 }


 static char *
 ngx_rtmp_core_server_name(ngx_conf_t *cf, ngx_command_t *cmd, void *conf)
 {
     ngx_rtmp_core_srv_conf_t *cscf = conf;

     u_char                   ch;
     ngx_str_t               *value;
     ngx_uint_t               i;
     ngx_rtmp_server_name_t  *sn;

     value = cf->args->elts;

     for (i = 1; i < cf->args->nelts; i++) {

         ch = value[i].data[0];

         if ((ch == '*' && (value[i].len < 3 || value[i].data[1] != '.'))
             || (ch == '.' && value[i].len < 2))
         {
             ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                                "server name \"%V\" is invalid", &value[i]);
             return NGX_CONF_ERROR;
         }

         if (ngx_strchr(value[i].data, '/')) {
             ngx_conf_log_error(NGX_LOG_WARN, cf, 0,
                                "server name \"%V\" has suspicious symbols",
                                &value[i]);
         }

         sn = ngx_array_push(&cscf->server_names);
         if (sn == NULL) {
             return NGX_CONF_ERROR;
         }

 #if (NGX_PCRE)
         sn->regex = NULL;
 #endif
         sn->server = cscf;

         if (ngx_strcasecmp(value[i].data, (u_char *) "$hostname") == 0) {
             sn->name = cf->cycle->hostname;

         } else {
             sn->name = value[i];
         }

         if (value[i].data[0] != '~') {
             ngx_strlow(sn->name.data, sn->name.data, sn->name.len);
             continue;
         }

 #if (NGX_PCRE)
         {
         u_char               *p;
         ngx_regex_compile_t   rc;
         u_char                errstr[NGX_MAX_CONF_ERRSTR];

         if (value[i].len == 1) {
             ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                                "empty regex in server name \"%V\"", &value[i]);
             return NGX_CONF_ERROR;
         }

         value[i].len--;
         value[i].data++;

         ngx_memzero(&rc, sizeof(ngx_regex_compile_t));

         rc.pattern = value[i];
         rc.err.len = NGX_MAX_CONF_ERRSTR;
         rc.err.data = errstr;

         for (p = value[i].data; p < value[i].data + value[i].len; p++) {
             if (*p >= 'A' && *p <= 'Z') {
                 rc.options = NGX_REGEX_CASELESS;
                 break;
             }
         }

         sn->regex = ngx_rtmp_regex_compile(cf, &rc);
         if (sn->regex == NULL) {
             return NGX_CONF_ERROR;
         }

         sn->name = value[i];
         cscf->captures = (rc.captures > 0);
         }
 #else
         ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                            "using regex \"%V\" "
                            "requires PCRE library", &value[i]);

         return NGX_CONF_ERROR;
 #endif
     }

     return NGX_CONF_OK;
 }
