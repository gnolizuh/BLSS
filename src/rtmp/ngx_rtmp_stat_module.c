
/*
 * Copyright (C) Roman Arutyunyan
 */


#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_http.h>
#include <nginx.h>
#include "ngx_rtmp.h"
#include "ngx_rtmp_version.h"
#include "ngx_rtmp_live_module.h"
#include "ngx_rtmp_play_module.h"
#include "ngx_rtmp_codec_module.h"


static ngx_int_t ngx_rtmp_stat_init_process(ngx_cycle_t *cycle);
static char *ngx_rtmp_stat(ngx_conf_t *cf, ngx_command_t *cmd, void *conf);
static ngx_int_t ngx_rtmp_stat_postconfiguration(ngx_conf_t *cf);
static void * ngx_rtmp_stat_create_loc_conf(ngx_conf_t *cf);
static char * ngx_rtmp_stat_merge_loc_conf(ngx_conf_t *cf,
        void *parent, void *child);


extern ngx_uint_t ngx_rtmp_publishing;
extern ngx_uint_t ngx_rtmp_playing;

static time_t                       start_time;


#define NGX_RTMP_STAT_ALL           0xff
#define NGX_RTMP_STAT_GLOBAL        0x01
#define NGX_RTMP_STAT_LIVE          0x02
#define NGX_RTMP_STAT_CLIENTS       0x04
#define NGX_RTMP_STAT_PLAY          0x08

/*
 * global: stat-{bufs-{total,free,used}, total bytes in/out, bw in/out} - cscf
*/


typedef struct {
    ngx_uint_t                      stat;
    ngx_str_t                       stylesheet;
} ngx_rtmp_stat_loc_conf_t;

typedef struct {
	
    ngx_rtmp_bandwidth_t vhost_bd_in;
    ngx_rtmp_bandwidth_t vhost_bd_out;
    ngx_rtmp_bandwidth_t vhost_bd_real;
    ngx_uint_t           vhost_nclients;
    ngx_uint_t           vhost_publish_clients;
    ngx_uint_t           vhost_play_clients;
}ngx_rtmp_vost_stat_t;

typedef struct {
    ngx_rtmp_bandwidth_t total_bd_in;
    ngx_rtmp_bandwidth_t total_bd_out;
    ngx_rtmp_bandwidth_t total_bd_real;
}ngx_rtmp_total_stat_t;


typedef struct {   
	
	ngx_str_t  vhost;
	ngx_str_t  app;
	ngx_str_t  stream;
}ngx_rtmp_stat_para_t;

static ngx_conf_bitmask_t           ngx_rtmp_stat_masks[] = {
    { ngx_string("all"),            NGX_RTMP_STAT_ALL           },
    { ngx_string("global"),         NGX_RTMP_STAT_GLOBAL        },
    { ngx_string("live"),           NGX_RTMP_STAT_LIVE          },
    { ngx_string("clients"),        NGX_RTMP_STAT_CLIENTS       },
    { ngx_null_string,              0 }
};


static ngx_command_t  ngx_rtmp_stat_commands[] = {

    { ngx_string("rtmp_stat"),
        NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_1MORE,
        ngx_rtmp_stat,
        NGX_HTTP_LOC_CONF_OFFSET,
        offsetof(ngx_rtmp_stat_loc_conf_t, stat),
        ngx_rtmp_stat_masks },

    { ngx_string("rtmp_stat_stylesheet"),
        NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_TAKE1,
        ngx_conf_set_str_slot,
        NGX_HTTP_LOC_CONF_OFFSET,
        offsetof(ngx_rtmp_stat_loc_conf_t, stylesheet),
        NULL },

    ngx_null_command
};


static ngx_http_module_t  ngx_rtmp_stat_module_ctx = {
    NULL,                               /* preconfiguration */
    ngx_rtmp_stat_postconfiguration,    /* postconfiguration */

    NULL,                               /* create main configuration */
    NULL,                               /* init main configuration */

    NULL,                               /* create server configuration */
    NULL,                               /* merge server configuration */

    ngx_rtmp_stat_create_loc_conf,      /* create location configuration */
    ngx_rtmp_stat_merge_loc_conf,       /* merge location configuration */
};


ngx_module_t  ngx_rtmp_stat_module = {
    NGX_MODULE_V1,
    &ngx_rtmp_stat_module_ctx,          /* module context */
    ngx_rtmp_stat_commands,             /* module directives */
    NGX_HTTP_MODULE,                    /* module type */
    NULL,                               /* init master */
    NULL,                               /* init module */
    ngx_rtmp_stat_init_process,         /* init process */
    NULL,                               /* init thread */
    NULL,                               /* exit thread */
    NULL,                               /* exit process */
    NULL,                               /* exit master */
    NGX_MODULE_V1_PADDING
};


#define NGX_RTMP_STAT_BUFSIZE           256


static ngx_int_t
ngx_rtmp_stat_init_process(ngx_cycle_t *cycle)
{
    /*
     * HTTP process initializer is called
     * after event module initializer
     * so we can run posted events here
     */

    ngx_event_process_posted(cycle, &ngx_rtmp_init_queue);

    return NGX_OK;
}


/* ngx_escape_html does not escape characters out of ASCII range
 * which are bad for xslt */

static void *
ngx_rtmp_stat_escape(ngx_http_request_t *r, void *data, size_t len)
{
    u_char *p, *np;
    void   *new_data;
    size_t  n;

    p = data;

    for (n = 0; n < len; ++n, ++p) {
        if (*p < 0x20 || *p >= 0x7f) {
            break;
        }
    }

    if (n == len) {
        return data;
    }

    new_data = ngx_palloc(r->pool, len);
    if (new_data == NULL) {
        return NULL;
    }

    p  = data;
    np = new_data;

    for (n = 0; n < len; ++n, ++p, ++np) {
        *np = (*p < 0x20 || *p >= 0x7f) ? (u_char) ' ' : *p;
    }

    return new_data;
}

#if (NGX_WIN32)
/*
 * Fix broken MSVC memcpy optimization for 4-byte data
 * when this function is inlined
 */
__declspec(noinline)
#endif

static void
ngx_rtmp_stat_output(ngx_http_request_t *r, ngx_chain_t ***lll,
        void *data, size_t len, ngx_uint_t escape)
{
    ngx_chain_t        *cl;
    ngx_buf_t          *b;
    size_t              real_len;

    if (len == 0) {
        return;
    }

    if (escape) {
        data = ngx_rtmp_stat_escape(r, data, len);
        if (data == NULL) {
            return;
        }
    }

    real_len = escape
        ? len + ngx_escape_html(NULL, data, len)
        : len;

    cl = **lll;
    if (cl && cl->buf->last + real_len > cl->buf->end) {
        *lll = &cl->next;
    }

    if (**lll == NULL) {
        cl = ngx_alloc_chain_link(r->pool);
        if (cl == NULL) {
            return;
        }
        b = ngx_create_temp_buf(r->pool,
                ngx_max(NGX_RTMP_STAT_BUFSIZE, real_len));
        if (b == NULL || b->pos == NULL) {
            return;
        }
        cl->next = NULL;
        cl->buf = b;
        **lll = cl;
    }

    b = (**lll)->buf;

    if (escape) {
        b->last = (u_char *)ngx_escape_html(b->last, data, len);
    } else {
        b->last = ngx_cpymem(b->last, data, len);
    }
}


/* These shortcuts assume 2 variables exist in current context:
 *   ngx_http_request_t    *r
 *   ngx_chain_t         ***lll */

/* plain data */
#define NGX_RTMP_STAT(data, len)    ngx_rtmp_stat_output(r, lll, data, len, 0)

/* escaped data */
#define NGX_RTMP_STAT_E(data, len)  ngx_rtmp_stat_output(r, lll, data, len, 1)

/* literal */
#define NGX_RTMP_STAT_L(s)          NGX_RTMP_STAT((s), sizeof(s) - 1)

/* ngx_str_t */
#define NGX_RTMP_STAT_S(s)          NGX_RTMP_STAT((s)->data, (s)->len)

/* escaped ngx_str_t */
#define NGX_RTMP_STAT_ES(s)         NGX_RTMP_STAT_E((s)->data, (s)->len)

/* C string */
#define NGX_RTMP_STAT_CS(s)         NGX_RTMP_STAT((s), ngx_strlen(s))

/* escaped C string */
#define NGX_RTMP_STAT_ECS(s)        NGX_RTMP_STAT_E((s), ngx_strlen(s))


#define NGX_RTMP_STAT_BW            0x01
#define NGX_RTMP_STAT_BYTES         0x02
#define NGX_RTMP_STAT_BW_BYTES      0x03


static void
ngx_rtmp_stat_bw(ngx_http_request_t *r, ngx_chain_t ***lll,
                 ngx_rtmp_bandwidth_t *bw, char *name,
                 ngx_uint_t flags)
{
    u_char  buf[NGX_INT64_LEN + 9];

    if (flags & NGX_RTMP_STAT_BW) {
        NGX_RTMP_STAT_L("<bw_");
        NGX_RTMP_STAT_CS(name);
        NGX_RTMP_STAT(buf, ngx_snprintf(buf, sizeof(buf), ">%uL</bw_",
                                        bw->bandwidth * 8)
                           - buf);
        NGX_RTMP_STAT_CS(name);
        NGX_RTMP_STAT_L(">\r\n");
    }

    if (flags & NGX_RTMP_STAT_BYTES) {
        NGX_RTMP_STAT_L("<bytes_");
        NGX_RTMP_STAT_CS(name);
        NGX_RTMP_STAT(buf, ngx_snprintf(buf, sizeof(buf), ">%uL</bytes_",
                                        bw->bytes)
                           - buf);
        NGX_RTMP_STAT_CS(name);
        NGX_RTMP_STAT_L(">\r\n");
    }
}


static void
ngx_rtmp_stat_av_bw(ngx_http_request_t *r, ngx_chain_t ***lll,
                 uint64_t bandwidth, uint64_t bytes, char *name,
                 ngx_uint_t flags)
{
    u_char  buf[NGX_INT64_LEN + 9];

    if (flags & NGX_RTMP_STAT_BW) {
        NGX_RTMP_STAT_L("<bw_");
        NGX_RTMP_STAT_CS(name);
        NGX_RTMP_STAT(buf, ngx_snprintf(buf, sizeof(buf), ">%uL</bw_",
                                        bandwidth * 8)
                           - buf);
        NGX_RTMP_STAT_CS(name);
        NGX_RTMP_STAT_L(">\r\n");
    }

    if (flags & NGX_RTMP_STAT_BYTES) {
        NGX_RTMP_STAT_L("<bytes_");
        NGX_RTMP_STAT_CS(name);
        NGX_RTMP_STAT(buf, ngx_snprintf(buf, sizeof(buf), ">%uL</bytes_",
                                        bytes)
                           - buf);
        NGX_RTMP_STAT_CS(name);
        NGX_RTMP_STAT_L(">\r\n");
    }
}


#ifdef NGX_RTMP_POOL_DEBUG
static void
ngx_rtmp_stat_get_pool_size(ngx_pool_t *pool, ngx_uint_t *nlarge,
        ngx_uint_t *size)
{
    ngx_pool_large_t       *l;
    ngx_pool_t             *p, *n;

    *nlarge = 0;
    for (l = pool->large; l; l = l->next) {
        ++*nlarge;
    }

    *size = 0;
    for (p = pool, n = pool->d.next; /* void */; p = n, n = n->d.next) {
        *size += (p->d.last - (u_char *)p);
        if (n == NULL) {
            break;
        }
    }
}


static void
ngx_rtmp_stat_dump_pool(ngx_http_request_t *r, ngx_chain_t ***lll,
        ngx_pool_t *pool)
{
    ngx_uint_t  nlarge, size;
    u_char      buf[NGX_INT_T_LEN];

    size = 0;
    nlarge = 0;
    ngx_rtmp_stat_get_pool_size(pool, &nlarge, &size);
    NGX_RTMP_STAT_L("<pool><nlarge>");
    NGX_RTMP_STAT(buf, ngx_snprintf(buf, sizeof(buf), "%ui", nlarge) - buf);
    NGX_RTMP_STAT_L("</nlarge><size>");
    NGX_RTMP_STAT(buf, ngx_snprintf(buf, sizeof(buf), "%ui", size) - buf);
    NGX_RTMP_STAT_L("</size></pool>\r\n");
}
#endif



static void
ngx_rtmp_stat_client(ngx_http_request_t *r, ngx_chain_t ***lll,
    ngx_rtmp_session_t *s)
{
    u_char  buf[NGX_INT_T_LEN];

#ifdef NGX_RTMP_POOL_DEBUG
    ngx_rtmp_stat_dump_pool(r, lll, s->pool);
#endif
    NGX_RTMP_STAT_L("<id>");
    NGX_RTMP_STAT(buf, ngx_snprintf(buf, sizeof(buf), "%ui",
                  (ngx_uint_t) s->connection->number) - buf);
    NGX_RTMP_STAT_L("</id>");

    NGX_RTMP_STAT_L("<address>");
    NGX_RTMP_STAT_ES(&s->connection->addr_text);
    NGX_RTMP_STAT_L("</address>");

    NGX_RTMP_STAT_L("<time>");
    NGX_RTMP_STAT(buf, ngx_snprintf(buf, sizeof(buf), "%i",
                  (ngx_int_t) (ngx_current_msec - s->epoch)) - buf);
    NGX_RTMP_STAT_L("</time>");

    if (s->flashver.len) {
        NGX_RTMP_STAT_L("<flashver>");
        NGX_RTMP_STAT_ES(&s->flashver);
        NGX_RTMP_STAT_L("</flashver>");
    }

    if (s->page_url.len) {
        NGX_RTMP_STAT_L("<pageurl>");
        NGX_RTMP_STAT_ES(&s->page_url);
        NGX_RTMP_STAT_L("</pageurl>");
    }

    if (s->swf_url.len) {
        NGX_RTMP_STAT_L("<swfurl>");
        NGX_RTMP_STAT_ES(&s->swf_url);
        NGX_RTMP_STAT_L("</swfurl>");
    }
}


char *
ngx_rtmp_stat_get_aac_profile(ngx_uint_t p, ngx_uint_t sbr, ngx_uint_t ps) {
    switch (p) {
        case 1:
            return "Main";
        case 2:
            if (ps) {
                return "HEv2";
            }
            if (sbr) {
                return "HE";
            }
            return "LC";
        case 3:
            return "SSR";
        case 4:
            return "LTP";
        case 5:
            return "SBR";
        default:
            return "";
    }
}


char *
ngx_rtmp_stat_get_avc_profile(ngx_uint_t p) {
    switch (p) {
        case 66:
            return "Baseline";
        case 77:
            return "Main";
        case 100:
            return "High";
        case 1:
            return "Hevc Main";
        case 2:
            return "Hevc Main 10";
        case 3:
            return "Hevc Main Still Picture";
        case 4:
            return "Hevc Range Extension";
        default:
            return "";
    }
}


static void
ngx_rtmp_stat_live_one(ngx_http_request_t *r, ngx_chain_t ***lll,
        ngx_rtmp_live_app_conf_t *lacf, ngx_rtmp_live_dyn_app_t *lacf_r, ngx_str_t *stream_live, ngx_str_t *type,
        ngx_rtmp_vost_stat_t *vhost_stat, ngx_rtmp_stat_para_t *para)
{
    ngx_rtmp_live_stream_t         *stream = NULL;
    ngx_rtmp_codec_ctx_t           *codec;
    ngx_rtmp_live_ctx_t            *ctx;
    ngx_rtmp_session_t             *s;
    ngx_int_t                       n;
    ngx_uint_t                      nclients, total_nclients;
    ngx_uint_t                      publish_clients=0;
    u_char                          buf[NGX_INT_T_LEN];
    u_char                          bbuf[NGX_INT32_LEN];
    ngx_rtmp_stat_loc_conf_t       *slcf;
    u_char                         *cname;
    ngx_int_t                       nbuckets=0;

  //  if (!ngx_rtmp_get_attr_conf(lacf, live)) {
  //      return;
  //  }

#define ngx_rtmp_set_stat_tream(lacf, n) ((lacf)->streams[n])

    slcf = ngx_http_get_module_loc_conf(r, ngx_rtmp_stat_module);

    if (lacf && !lacf_r) {   //local configure

        nbuckets = lacf->nbuckets;
    } else if(!lacf && lacf_r) {  //remote configure

        nbuckets = NGX_RTMP_MAX_STREAM_NBUCKET;
    } else {  //error
    
        ngx_log_error(NGX_LOG_ERR, r->connection->log, 0, "ngx_rtmp_stat_live:  lacf and lacf_r is error!");
        return;
    }

    NGX_RTMP_STAT_L("<live>\r\n");

    total_nclients = 0;
    for (n = 0; n < nbuckets; ++n) {

        if (lacf && !lacf_r) {
        
            stream = ngx_rtmp_set_stat_tream(lacf, n);
        } else if(!lacf && lacf_r) {
        
            stream = ngx_rtmp_set_stat_tream(lacf_r, n);
        }     
		
        for (; stream; stream = stream->next) {

	  		if (ngx_strlen(stream->name) == stream_live->len &&
					0 == ngx_strncmp(stream->name, stream_live->data, stream_live->len)) {
		      publish_clients = 0;
	            NGX_RTMP_STAT_L("<stream>\r\n");

	            NGX_RTMP_STAT_L("<name>");
	            NGX_RTMP_STAT_ECS(stream->name);
	            NGX_RTMP_STAT_L("</name>\r\n");

	            NGX_RTMP_STAT_L("<time>");
	            NGX_RTMP_STAT(buf, ngx_snprintf(buf, sizeof(buf), "%i",
	                          (ngx_int_t) (ngx_current_msec - stream->epoch))
	                          - buf);
	            NGX_RTMP_STAT_L("</time>");


	            ngx_rtmp_stat_bw(r, lll, &stream->bw_out, "out",
	                             NGX_RTMP_STAT_BW_BYTES);
                ngx_rtmp_stat_av_bw(r, lll,
                                 stream->bw_in_av.a_intl_bw + stream->bw_in_av.v_intl_bw,
                                 stream->bw_in_av.a_intl_bytes + stream->bw_in_av.v_intl_bytes,
                                 "in", NGX_RTMP_STAT_BW_BYTES);
                ngx_rtmp_stat_av_bw(r, lll,
                                 stream->bw_in_av.a_intl_bw_exp + stream->bw_in_av.v_intl_bw_exp,
                                 stream->bw_in_av.a_intl_bytes + stream->bw_in_av.v_intl_bytes,
                                 "real", NGX_RTMP_STAT_BW_BYTES);
	            ngx_rtmp_stat_av_bw(r, lll,
                                 stream->bw_in_av.a_intl_bw,
                                 stream->bw_in_av.a_intl_bytes,
                                 "audio", NGX_RTMP_STAT_BW);
                ngx_rtmp_stat_av_bw(r, lll,
                                 stream->bw_in_av.v_intl_bw,
                                 stream->bw_in_av.v_intl_bytes,
                                 "video", NGX_RTMP_STAT_BW);

	            nclients = 0;
	            codec = NULL;
	            for (ctx = stream->ctx; ctx; ctx = ctx->next) {
	                s = ctx->session;
	                if (slcf->stat & NGX_RTMP_STAT_CLIENTS) {
	                    NGX_RTMP_STAT_L("<client>");

	                    ngx_rtmp_stat_client(r, lll, s);

	                    NGX_RTMP_STAT_L("<dropped>");
	                    NGX_RTMP_STAT(buf, ngx_snprintf(buf, sizeof(buf),
	                                  "%ui", ctx->ndropped) - buf);
	                    NGX_RTMP_STAT_L("</dropped>");

	                    NGX_RTMP_STAT_L("<avsync>");
                          NGX_RTMP_STAT(bbuf, ngx_snprintf(bbuf, sizeof(bbuf),
                                      "%D", ctx->cs[1].timestamp -
                                      ctx->cs[0].timestamp) - bbuf);
	                    NGX_RTMP_STAT_L("</avsync>");

	                    NGX_RTMP_STAT_L("<timestamp>");
	                    NGX_RTMP_STAT(bbuf, ngx_snprintf(bbuf, sizeof(bbuf),
	                                  "%D", s->current_time) - bbuf);
	                    NGX_RTMP_STAT_L("</timestamp>");

	                    if (ctx->publishing) {
	                        NGX_RTMP_STAT_L("<publishing/>");
	                    }

	                    if (ctx->active) {
	                        NGX_RTMP_STAT_L("<active/>");
	                    }

	                    NGX_RTMP_STAT_L("</client>\r\n");
		            }
							
                        if (ctx->publishing) {
                        				
                            publish_clients++;
                            codec = ngx_rtmp_get_module_ctx(s, ngx_rtmp_codec_module);
                        }

		           nclients++;
	        	}
	        total_nclients += nclients;

            if (codec) {

	                NGX_RTMP_STAT_L("<meta>");

	                NGX_RTMP_STAT_L("<video>");
	                NGX_RTMP_STAT_L("<width>");
	                NGX_RTMP_STAT(buf, ngx_snprintf(buf, sizeof(buf),
	                              "%ui", codec->width) - buf);
	                NGX_RTMP_STAT_L("</width><height>");
	                NGX_RTMP_STAT(buf, ngx_snprintf(buf, sizeof(buf),
	                              "%ui", codec->height) - buf);
	                NGX_RTMP_STAT_L("</height><frame_rate>");
	                NGX_RTMP_STAT(buf, ngx_snprintf(buf, sizeof(buf),
	                              "%ui", codec->frame_rate) - buf);
	                NGX_RTMP_STAT_L("</frame_rate>");

	                cname = ngx_rtmp_get_video_codec_name(codec->video_codec_id);
	                if (*cname) {
	                    NGX_RTMP_STAT_L("<codec>");
	                    NGX_RTMP_STAT_ECS(cname);
	                    NGX_RTMP_STAT_L("</codec>");
	                }
	                if (codec->avc_profile) {
	                    NGX_RTMP_STAT_L("<profile>");
	                    NGX_RTMP_STAT_CS(
	                            ngx_rtmp_stat_get_avc_profile(codec->avc_profile));
	                    NGX_RTMP_STAT_L("</profile>");
	                }
	                if (codec->avc_level) {
	                    NGX_RTMP_STAT_L("<compat>");
	                    NGX_RTMP_STAT(buf, ngx_snprintf(buf, sizeof(buf),
	                                  "%ui", codec->avc_compat) - buf);
	                    NGX_RTMP_STAT_L("</compat>");
	                }
	                if (codec->avc_level) {
	                    NGX_RTMP_STAT_L("<level>");
	                    NGX_RTMP_STAT(buf, ngx_snprintf(buf, sizeof(buf),
	                                  "%.1f", codec->avc_level / 10.) - buf);
	                    NGX_RTMP_STAT_L("</level>");
	                }
	                NGX_RTMP_STAT_L("</video>");

	                NGX_RTMP_STAT_L("<audio>");
	                cname = ngx_rtmp_get_audio_codec_name(codec->audio_codec_id);
	                if (*cname) {
	                    NGX_RTMP_STAT_L("<codec>");
	                    NGX_RTMP_STAT_ECS(cname);
	                    NGX_RTMP_STAT_L("</codec>");
	                }
	                if (codec->aac_profile) {
	                    NGX_RTMP_STAT_L("<profile>");
	                    NGX_RTMP_STAT_CS(
                                ngx_rtmp_stat_get_aac_profile(codec->aac_profile,
                                                              codec->aac_sbr,
                                                              codec->aac_ps));
	                    NGX_RTMP_STAT_L("</profile>");
	                }
	                if (codec->aac_chan_conf) {
	                    NGX_RTMP_STAT_L("<channels>");
	                    NGX_RTMP_STAT(buf, ngx_snprintf(buf, sizeof(buf),
	                                  "%ui", codec->aac_chan_conf) - buf);
	                    NGX_RTMP_STAT_L("</channels>");
	                } else if (codec->audio_channels) {
	                    NGX_RTMP_STAT_L("<channels>");
	                    NGX_RTMP_STAT(buf, ngx_snprintf(buf, sizeof(buf),
	                                  "%ui", codec->audio_channels) - buf);
	                    NGX_RTMP_STAT_L("</channels>");
	                }
	                if (codec->sample_rate) {
	                    NGX_RTMP_STAT_L("<sample_rate>");
	                    NGX_RTMP_STAT(buf, ngx_snprintf(buf, sizeof(buf),
	                                  "%ui", codec->sample_rate) - buf);
	                    NGX_RTMP_STAT_L("</sample_rate>");
	                }
	                NGX_RTMP_STAT_L("</audio>");

		            NGX_RTMP_STAT_L("</meta>\r\n");
	       		}

	            NGX_RTMP_STAT_L("<nclients>");
	            NGX_RTMP_STAT(buf, ngx_snprintf(buf, sizeof(buf),
	                          "%ui", nclients) - buf);
	            NGX_RTMP_STAT_L("</nclients>\r\n");
	            if (0 == ngx_strncasecmp(type->data, (u_char *)"xml", type->len)) {

	                NGX_RTMP_STAT_L("<publish_clients>");
	                NGX_RTMP_STAT(buf, ngx_snprintf(buf, sizeof(buf),
	                              "%ui", publish_clients) - buf);
	                NGX_RTMP_STAT_L("</publish_clients>\r\n");
	                    
	                NGX_RTMP_STAT_L("<play_clients>");
	                NGX_RTMP_STAT(buf, ngx_snprintf(buf, sizeof(buf),
	                              "%ui", nclients - publish_clients) - buf);
	                NGX_RTMP_STAT_L("</play_clients>\r\n");
	            }
	            vhost_stat->vhost_bd_in.bandwidth += (stream->bw_in_av.a_intl_bw +
                    stream->bw_in_av.v_intl_bw);
	            vhost_stat->vhost_bd_in.bytes += (stream->bw_in_av.a_intl_bytes +
                    stream->bw_in_av.v_intl_bytes);
	            vhost_stat->vhost_bd_out.bandwidth += stream->bw_out.bandwidth;
	            vhost_stat->vhost_bd_out.bytes += stream->bw_out.bytes;
	            vhost_stat->vhost_bd_real.bandwidth += (stream->bw_in_av.a_intl_bw_exp +
                    stream->bw_in_av.v_intl_bw_exp);
	            vhost_stat->vhost_bd_real.bytes += (stream->bw_in_av.a_intl_bytes +
                    stream->bw_in_av.v_intl_bytes);
	            vhost_stat->vhost_nclients += nclients;
	            vhost_stat->vhost_publish_clients += publish_clients;
	            if (stream->publishing) {
	                NGX_RTMP_STAT_L("<publishing/>\r\n");
	            }

	            if (stream->active) {
	                NGX_RTMP_STAT_L("<active/>\r\n");
	            }

	            NGX_RTMP_STAT_L("</stream>\r\n");
		        break;
	        }
        }
  	}

    NGX_RTMP_STAT_L("<nclients>");
    NGX_RTMP_STAT(buf, ngx_snprintf(buf, sizeof(buf),
               "%ui", total_nclients) - buf);
    NGX_RTMP_STAT_L("</nclients>\r\n");

    NGX_RTMP_STAT_L("</live>\r\n");

}

static void
ngx_rtmp_stat_live(ngx_http_request_t *r, ngx_chain_t ***lll,
        ngx_rtmp_live_app_conf_t *lacf, ngx_rtmp_live_dyn_app_t *lacf_r, ngx_str_t *type, ngx_rtmp_vost_stat_t *vhost_stat,
        ngx_rtmp_stat_para_t *para)
{
    ngx_rtmp_live_stream_t          *stream = NULL;
    ngx_rtmp_codec_ctx_t            *codec;
    ngx_rtmp_live_ctx_t             *ctx;
    ngx_rtmp_session_t              *s;
    ngx_int_t                        n;
    ngx_uint_t                       nclients, total_nclients;
    ngx_uint_t                       publish_clients=0;
    u_char                           buf[NGX_INT_T_LEN];
    u_char                           bbuf[NGX_INT32_LEN];
    u_char                           stream_name[512];
    ngx_rtmp_stat_loc_conf_t        *slcf;
    u_char                          *cname;
    ngx_int_t                        nbuckets = 0;

    slcf = ngx_http_get_module_loc_conf(r, ngx_rtmp_stat_module);

#define ngx_rtmp_set_stat_tream(lacf, n) ((lacf)->streams[n])
    
    if (lacf && !lacf_r) {   // local configure

        nbuckets = lacf->nbuckets;
    } else if(!lacf && lacf_r) {  //remote configure

        nbuckets = NGX_RTMP_MAX_STREAM_NBUCKET;
    } else {                 // error
    
        ngx_log_error(NGX_LOG_ERR, r->connection->log, 0, "ngx_rtmp_stat_live:  lacf and lacf_r is error!");
        return;
    }

    NGX_RTMP_STAT_L("<live>\r\n");

    total_nclients = 0;
    for (n = 0; n < nbuckets; ++n) {

        if (lacf && !lacf_r){

            stream = ngx_rtmp_set_stat_tream(lacf, n);
        }else if(!lacf && lacf_r){

            stream = ngx_rtmp_set_stat_tream(lacf_r, n);
        }
		
        for (; stream; stream = stream->next) {
				
            publish_clients=0;
            *ngx_snprintf(stream_name, 512, "%s", stream->name) = 0;
				
            NGX_RTMP_STAT_L("<stream>\r\n");

            NGX_RTMP_STAT_L("<name>");
            NGX_RTMP_STAT_ECS(stream_name);
            NGX_RTMP_STAT_L("</name>\r\n");

            NGX_RTMP_STAT_L("<time>");
            NGX_RTMP_STAT(buf, ngx_snprintf(buf, sizeof(buf), "%i",
                          (ngx_int_t) (ngx_current_msec - stream->epoch))
                          - buf);
            NGX_RTMP_STAT_L("</time>");
            ngx_rtmp_stat_bw(r, lll, &stream->bw_out, "out",
                             NGX_RTMP_STAT_BW_BYTES);
            ngx_rtmp_stat_av_bw(r, lll,
                                 stream->bw_in_av.a_intl_bw + stream->bw_in_av.v_intl_bw,
                                 stream->bw_in_av.a_intl_bytes + stream->bw_in_av.v_intl_bytes,
                                 "in", NGX_RTMP_STAT_BW_BYTES);
            ngx_rtmp_stat_av_bw(r, lll,
                             stream->bw_in_av.a_intl_bw_exp + stream->bw_in_av.v_intl_bw_exp,
                             stream->bw_in_av.a_intl_bytes + stream->bw_in_av.v_intl_bytes,
                             "real", NGX_RTMP_STAT_BW_BYTES);
            ngx_rtmp_stat_av_bw(r, lll,
                             stream->bw_in_av.a_intl_bw,
                             stream->bw_in_av.a_intl_bytes,
                             "audio", NGX_RTMP_STAT_BW);
            ngx_rtmp_stat_av_bw(r, lll,
                             stream->bw_in_av.v_intl_bw,
                             stream->bw_in_av.v_intl_bytes,
                             "video", NGX_RTMP_STAT_BW);
            nclients = 0;
            codec = NULL;
            for (ctx = stream->ctx; ctx; ctx = ctx->next) {

                s = ctx->session;

                if (!ngx_rtmp_get_attr_conf(lacf, live)) {
                    continue;
                }

                if (slcf->stat & NGX_RTMP_STAT_CLIENTS) {

                    NGX_RTMP_STAT_L("<client>");

                    ngx_rtmp_stat_client(r, lll, s);

                    NGX_RTMP_STAT_L("<dropped>");
                    NGX_RTMP_STAT(buf, ngx_snprintf(buf, sizeof(buf),
                                  "%ui", ctx->ndropped) - buf);
                    NGX_RTMP_STAT_L("</dropped>");

                    NGX_RTMP_STAT_L("<avsync>");
								
                    NGX_RTMP_STAT(bbuf, ngx_snprintf(bbuf, sizeof(bbuf),
                        "%D", ctx->cs[1].timestamp - ctx->cs[0].timestamp) - bbuf);
                    NGX_RTMP_STAT_L("</avsync>");

                    NGX_RTMP_STAT_L("<timestamp>");
                    NGX_RTMP_STAT(bbuf, ngx_snprintf(bbuf, sizeof(bbuf),
                                  "%D", s->current_time) - bbuf);
                    NGX_RTMP_STAT_L("</timestamp>");

                    if (ctx->publishing) {

                        NGX_RTMP_STAT_L("<publishing/>");
                    }

                    if (ctx->active) {

                        NGX_RTMP_STAT_L("<active/>");
                    }

                    NGX_RTMP_STAT_L("</client>\r\n");
                }

                if (ctx->publishing) {

                    publish_clients++;
                    codec = ngx_rtmp_get_module_ctx(s, ngx_rtmp_codec_module);
                }
	                    
                nclients++;
            }
				
            total_nclients += nclients;
            if (codec) {
					
                NGX_RTMP_STAT_L("<meta>");

                NGX_RTMP_STAT_L("<video>");
                NGX_RTMP_STAT_L("<width>");
                NGX_RTMP_STAT(buf, ngx_snprintf(buf, sizeof(buf),
                              "%ui", codec->width) - buf);
                NGX_RTMP_STAT_L("</width><height>");
                NGX_RTMP_STAT(buf, ngx_snprintf(buf, sizeof(buf),
                              "%ui", codec->height) - buf);
                NGX_RTMP_STAT_L("</height><frame_rate>");
                NGX_RTMP_STAT(buf, ngx_snprintf(buf, sizeof(buf),
                              "%ui", codec->frame_rate) - buf);
                NGX_RTMP_STAT_L("</frame_rate>");

                cname = ngx_rtmp_get_video_codec_name(codec->video_codec_id);
					
                if (*cname) {
						
                    NGX_RTMP_STAT_L("<codec>");
                    NGX_RTMP_STAT_ECS(cname);
                    NGX_RTMP_STAT_L("</codec>");
                }
					
                if (codec->avc_profile) {
						
                    NGX_RTMP_STAT_L("<profile>");
                    NGX_RTMP_STAT_CS(
                            ngx_rtmp_stat_get_avc_profile(codec->avc_profile));
                    NGX_RTMP_STAT_L("</profile>");
                }
					
                if (codec->avc_level) {
						
                    NGX_RTMP_STAT_L("<compat>");
                    NGX_RTMP_STAT(buf, ngx_snprintf(buf, sizeof(buf),
                                  "%ui", codec->avc_compat) - buf);
                    NGX_RTMP_STAT_L("</compat>");
                }
					
                if (codec->avc_level) {
						
                    NGX_RTMP_STAT_L("<level>");
                    NGX_RTMP_STAT(buf, ngx_snprintf(buf, sizeof(buf),
                                  "%.1f", codec->avc_level / 10.) - buf);
                    NGX_RTMP_STAT_L("</level>");
                }
					
                NGX_RTMP_STAT_L("</video>");

                NGX_RTMP_STAT_L("<audio>");
                cname = ngx_rtmp_get_audio_codec_name(codec->audio_codec_id);
					
                if (*cname) {
						
                    NGX_RTMP_STAT_L("<codec>");
                    NGX_RTMP_STAT_ECS(cname);
                    NGX_RTMP_STAT_L("</codec>");
                }
					
                if (codec->aac_profile) {
						
                    NGX_RTMP_STAT_L("<profile>");
                    NGX_RTMP_STAT_CS(
                            ngx_rtmp_stat_get_aac_profile(codec->aac_profile,
                                                          codec->aac_sbr,
                                                          codec->aac_ps));
                    NGX_RTMP_STAT_L("</profile>");
                }
					
                if (codec->aac_chan_conf) {
						
                    NGX_RTMP_STAT_L("<channels>");
                    NGX_RTMP_STAT(buf, ngx_snprintf(buf, sizeof(buf),
                                  "%ui", codec->aac_chan_conf) - buf);
                    NGX_RTMP_STAT_L("</channels>");
                } else if (codec->audio_channels) {
	                
                    NGX_RTMP_STAT_L("<channels>");
                    NGX_RTMP_STAT(buf, ngx_snprintf(buf, sizeof(buf),
                                  "%ui", codec->audio_channels) - buf);
                    NGX_RTMP_STAT_L("</channels>");
                }
					
                if (codec->sample_rate) {
						
                    NGX_RTMP_STAT_L("<sample_rate>");
                    NGX_RTMP_STAT(buf, ngx_snprintf(buf, sizeof(buf),
                                  "%ui", codec->sample_rate) - buf);
                    NGX_RTMP_STAT_L("</sample_rate>");
                }
					
                NGX_RTMP_STAT_L("</audio>");

                NGX_RTMP_STAT_L("</meta>\r\n");
            }

            NGX_RTMP_STAT_L("<nclients>");
            NGX_RTMP_STAT(buf, ngx_snprintf(buf, sizeof(buf),
                          "%ui", nclients) - buf);
            NGX_RTMP_STAT_L("</nclients>\r\n");
				
            if (0 == ngx_strncasecmp(type->data, (u_char *)"xml", type->len)) {

                NGX_RTMP_STAT_L("<publish_clients>");
                NGX_RTMP_STAT(buf, ngx_snprintf(buf, sizeof(buf),
                              "%ui", publish_clients) - buf);
                NGX_RTMP_STAT_L("</publish_clients>\r\n");
	                
                NGX_RTMP_STAT_L("<play_clients>");
                NGX_RTMP_STAT(buf, ngx_snprintf(buf, sizeof(buf),
                              "%ui", nclients - publish_clients) - buf);
                NGX_RTMP_STAT_L("</play_clients>\r\n");
            }

            //calculate vhost bandwidth
            vhost_stat->vhost_bd_in.bandwidth += (stream->bw_in_av.a_intl_bw +
                    stream->bw_in_av.v_intl_bw);
	        vhost_stat->vhost_bd_in.bytes += (stream->bw_in_av.a_intl_bytes +
                    stream->bw_in_av.v_intl_bytes);
            vhost_stat->vhost_bd_out.bandwidth += stream->bw_out.bandwidth;
            vhost_stat->vhost_bd_out.bytes += stream->bw_out.bytes;
            vhost_stat->vhost_bd_real.bandwidth += (stream->bw_in_av.a_intl_bw_exp +
                    stream->bw_in_av.v_intl_bw_exp);
	        vhost_stat->vhost_bd_real.bytes += (stream->bw_in_av.a_intl_bytes +
                    stream->bw_in_av.v_intl_bytes);
            vhost_stat->vhost_nclients += nclients;
            vhost_stat->vhost_publish_clients += publish_clients;

            if (vhost_stat->vhost_nclients - vhost_stat->vhost_publish_clients == 0) {
					
                vhost_stat->vhost_bd_out.bandwidth = 0; 
            }

            if (stream->publishing) {
					
                NGX_RTMP_STAT_L("<publishing/>\r\n");
            }

            if (stream->active) {
					
                NGX_RTMP_STAT_L("<active/>\r\n");
            }

            NGX_RTMP_STAT_L("</stream>\r\n");
        }
    }

    NGX_RTMP_STAT_L("<nclients>");
    NGX_RTMP_STAT(buf, ngx_snprintf(buf, sizeof(buf),
                  "%ui", total_nclients) - buf);
    NGX_RTMP_STAT_L("</nclients>\r\n");

    NGX_RTMP_STAT_L("</live>\r\n");
}


static void
ngx_rtmp_stat_play(ngx_http_request_t *r, ngx_chain_t ***lll,
        ngx_rtmp_play_app_conf_t *pacf)
{
    ngx_rtmp_play_ctx_t            *ctx, *sctx;
    ngx_rtmp_session_t             *s;
    ngx_uint_t                      n, nclients, total_nclients;
    u_char                          buf[NGX_INT_T_LEN];
    u_char                          bbuf[NGX_INT32_LEN];
    ngx_rtmp_stat_loc_conf_t       *slcf;

    if (pacf->entries.nelts == 0) {
        return;
    }

    slcf = ngx_http_get_module_loc_conf(r, ngx_rtmp_stat_module);

    NGX_RTMP_STAT_L("<play>\r\n");

    total_nclients = 0;
    for (n = 0; n < pacf->nbuckets; ++n) {
        for (ctx = pacf->ctx[n]; ctx; ) {
            NGX_RTMP_STAT_L("<stream>\r\n");

            NGX_RTMP_STAT_L("<name>");
            NGX_RTMP_STAT_ECS(ctx->name);
            NGX_RTMP_STAT_L("</name>\r\n");

            nclients = 0;
            sctx = ctx;
            for (; ctx; ctx = ctx->next) {
                if (ngx_strcmp(ctx->name, sctx->name)) {
                    break;
                }

                nclients++;

                s = ctx->session;
                if (slcf->stat & NGX_RTMP_STAT_CLIENTS) {
                    NGX_RTMP_STAT_L("<client>");

                    ngx_rtmp_stat_client(r, lll, s);

                    NGX_RTMP_STAT_L("<timestamp>");
                    NGX_RTMP_STAT(bbuf, ngx_snprintf(bbuf, sizeof(bbuf),
                                  "%D", s->current_time) - bbuf);
                    NGX_RTMP_STAT_L("</timestamp>");

                    NGX_RTMP_STAT_L("</client>\r\n");
                }
            }
            total_nclients += nclients;

            NGX_RTMP_STAT_L("<active/>");
            NGX_RTMP_STAT_L("<nclients>");
            NGX_RTMP_STAT(buf, ngx_snprintf(buf, sizeof(buf),
                          "%ui", nclients) - buf);
            NGX_RTMP_STAT_L("</nclients>\r\n");

            NGX_RTMP_STAT_L("</stream>\r\n");
        }
    }

    NGX_RTMP_STAT_L("<nclients>");
    NGX_RTMP_STAT(buf, ngx_snprintf(buf, sizeof(buf),
                  "%ui", total_nclients) - buf);
    NGX_RTMP_STAT_L("</nclients>\r\n");

    NGX_RTMP_STAT_L("</play>\r\n");
}


static void
ngx_rtmp_stat_application(ngx_http_request_t *r, ngx_chain_t ***lll,
        ngx_rtmp_core_app_conf_t *cacf, ngx_str_t *type, ngx_str_t *stream, ngx_rtmp_vost_stat_t *vhost_stat, ngx_rtmp_stat_para_t *para)
{
    ngx_rtmp_stat_loc_conf_t       *slcf;

    NGX_RTMP_STAT_L("<application>\r\n");
    NGX_RTMP_STAT_L("<name>");
    NGX_RTMP_STAT_ES(&cacf->name);
    NGX_RTMP_STAT_L("</name>\r\n");

    slcf = ngx_http_get_module_loc_conf(r, ngx_rtmp_stat_module);

    para->app = cacf->name;
    if(slcf->stat & NGX_RTMP_STAT_LIVE) {
		
        if(stream->len == 0) {
			
            ngx_rtmp_stat_live(r, lll,
                cacf->app_conf[ngx_rtmp_live_module.ctx_index], NULL, type, vhost_stat, para);
        } else {
        
            ngx_rtmp_stat_live_one(r, lll,
                cacf->app_conf[ngx_rtmp_live_module.ctx_index], NULL, stream, type, vhost_stat, para);
        }
    }
    if(slcf->stat & NGX_RTMP_STAT_PLAY) {
		
        ngx_rtmp_stat_play(r, lll,
                cacf->app_conf[ngx_rtmp_play_module.ctx_index]);
    }

    NGX_RTMP_STAT_L("</application>\r\n");
}


static void
ngx_rtmp_stat_app_r(ngx_http_request_t *r, ngx_chain_t ***lll, ngx_rtmp_live_main_conf_t *lmcf,
        ngx_rtmp_live_dyn_app_t *cacf, ngx_str_t *type, ngx_str_t *stream, ngx_rtmp_vost_stat_t *vhost_stat, ngx_rtmp_stat_para_t *para)
{
    ngx_rtmp_stat_loc_conf_t       *slcf;
    ngx_str_t   name;
    name.data = cacf->name;
    name.len = ngx_strlen(cacf->name);
	
    NGX_RTMP_STAT_L("<application>\r\n");
    NGX_RTMP_STAT_L("<name>");
    NGX_RTMP_STAT_ES(&name);
    NGX_RTMP_STAT_L("</name>\r\n");

    slcf = ngx_http_get_module_loc_conf(r, ngx_rtmp_stat_module);

    para->app = name;
    if(slcf->stat & NGX_RTMP_STAT_LIVE){
		
        if(stream->len == 0){
			
            ngx_rtmp_stat_live(r, lll, NULL, cacf, type, vhost_stat, para);
        }else{

            ngx_rtmp_stat_live_one(r, lll,
                NULL, cacf, stream, type, vhost_stat, para);
        }
    }
	
#if 0
    if(slcf->stat & NGX_RTMP_STAT_PLAY){
		
        ngx_rtmp_stat_play(r, lll,
                cacf->app_conf[ngx_rtmp_play_module.ctx_index]);
    }
#endif

    NGX_RTMP_STAT_L("</application>\r\n");    
}

static void
ngx_rtmp_stat_server(ngx_http_request_t *r, ngx_chain_t ***lll,
        ngx_rtmp_core_srv_conf_t *cscf, ngx_str_t *type, ngx_str_t *app, 
        ngx_str_t *stream, ngx_rtmp_total_stat_t *total_stat)
{
    ngx_rtmp_core_app_conf_t      **cacf;
    size_t                          n;
    u_char                          buf[NGX_INT_T_LEN];
    ngx_rtmp_vost_stat_t            vost_stat;
    ngx_rtmp_stat_para_t            para;

    ngx_memset(&vost_stat, 0, sizeof(vost_stat));
	
    NGX_RTMP_STAT_L("<server>\r\n");
    NGX_RTMP_STAT_L("<name>");
    NGX_RTMP_STAT_ES(&(cscf->unique_name));
    NGX_RTMP_STAT_L("</name>\r\n");

    para.vhost = cscf->unique_name;
#ifdef NGX_RTMP_POOL_DEBUG
    ngx_rtmp_stat_dump_pool(r, lll, cscf->pool);
#endif

    cacf = cscf->applications.elts;
    if(app->len == 0){
		
        for(n = 0; n < cscf->applications.nelts; ++n, ++cacf){
			
            ngx_rtmp_stat_application(r, lll, *cacf, type, stream, &vost_stat, &para);
        }
    }else{
    
        for(n = 0; n < cscf->applications.nelts; ++n, ++cacf){
			
            if(0 == ngx_memcmp(app->data, (*cacf)->name.data, app->len)){
				
                ngx_rtmp_stat_application(r, lll, *cacf, type, stream, &vost_stat, &para);
                break;
            } 
        }    
    }
    if(type->len == ngx_strlen("xml")
		&& 0 == ngx_memcmp(type->data, (u_char *)"xml", type->len)
        &&app->len ==0
        &&stream->len ==0){

            ngx_rtmp_stat_bw(r, lll, &vost_stat.vhost_bd_in, "in",
                             NGX_RTMP_STAT_BW_BYTES);
            ngx_rtmp_stat_bw(r, lll, &vost_stat.vhost_bd_out, "out",
                             NGX_RTMP_STAT_BW_BYTES);
            ngx_rtmp_stat_bw(r, lll, &vost_stat.vhost_bd_real, "real",
                             NGX_RTMP_STAT_BW_BYTES);
            NGX_RTMP_STAT_L("<nclients>");
            NGX_RTMP_STAT(buf, ngx_snprintf(buf, sizeof(buf),
                          "%ui", vost_stat.vhost_nclients) - buf);
            NGX_RTMP_STAT_L("</nclients>\r\n");

            NGX_RTMP_STAT_L("<publish_clients>");
            NGX_RTMP_STAT(buf, ngx_snprintf(buf, sizeof(buf),
                          "%ui", vost_stat.vhost_publish_clients) - buf);
            NGX_RTMP_STAT_L("</publish_clients>\r\n");
            
            NGX_RTMP_STAT_L("<play_clients>");
            NGX_RTMP_STAT(buf, ngx_snprintf(buf, sizeof(buf),
                          "%ui", vost_stat.vhost_nclients -
                          vost_stat.vhost_publish_clients) - buf);
            NGX_RTMP_STAT_L("</play_clients>\r\n");
            
    }
    total_stat->total_bd_real.bandwidth += vost_stat.vhost_bd_real.bandwidth;
    total_stat->total_bd_real.bytes += vost_stat.vhost_bd_real.bytes;
    NGX_RTMP_STAT_L("</server>\r\n");
}


static void
ngx_rtmp_stat_server_r(ngx_http_request_t *r, ngx_chain_t ***lll, ngx_rtmp_live_main_conf_t *lmcf,
        ngx_rtmp_live_dyn_srv_t *cscf, ngx_str_t *type, ngx_str_t *app, 
        ngx_str_t *stream, ngx_rtmp_total_stat_t *total_stat)
{
    ngx_uint_t                      i = 0;
    ngx_str_t                       name;
    ngx_rtmp_live_dyn_app_t       **app_dyn;
    u_char                          buf[NGX_INT_T_LEN];
    ngx_rtmp_vost_stat_t            vost_stat;
    ngx_rtmp_stat_para_t            para;

    ngx_memset(&vost_stat, 0, sizeof(vost_stat));
    name.data = cscf->name;
    name.len = ngx_strlen(cscf->name);
	
    NGX_RTMP_STAT_L("<server>\r\n");
    NGX_RTMP_STAT_L("<name>");
    NGX_RTMP_STAT_ES(&name);
    NGX_RTMP_STAT_L("</name>\r\n");

    para.vhost = name;
	
    if (app->len == 0) {

        for (i =0; i< NGX_RTMP_MAX_APP_NBUCKET; i++){

            app_dyn =  &cscf->apps[i];
            for(; *app_dyn; app_dyn = &(*app_dyn)->next){

                ngx_rtmp_stat_app_r(r, lll, lmcf, *app_dyn, type, stream, &vost_stat, &para);
            }
        }
        
    }else{

        app_dyn = ngx_rtmp_live_get_app_dynamic(lmcf, &cscf, app, 0);
	  if (app_dyn && *app_dyn) {
            ngx_rtmp_stat_app_r(r, lll, lmcf, *app_dyn, type, stream, &vost_stat, &para);
	  }else{
            //do nothing
	  } 
    }
	
    if(type->len == ngx_strlen("xml")
		&& 0 == ngx_memcmp(type->data, (u_char *)"xml", type->len)
        &&app->len ==0
        &&stream->len ==0){

            ngx_rtmp_stat_bw(r, lll, &vost_stat.vhost_bd_in, "in",
                             NGX_RTMP_STAT_BW_BYTES);
            ngx_rtmp_stat_bw(r, lll, &vost_stat.vhost_bd_out, "out",
                             NGX_RTMP_STAT_BW_BYTES);
            ngx_rtmp_stat_bw(r, lll, &vost_stat.vhost_bd_real, "real",
                             NGX_RTMP_STAT_BW_BYTES);
            NGX_RTMP_STAT_L("<nclients>");
            NGX_RTMP_STAT(buf, ngx_snprintf(buf, sizeof(buf),
                          "%ui", vost_stat.vhost_nclients) - buf);
            NGX_RTMP_STAT_L("</nclients>\r\n");

            NGX_RTMP_STAT_L("<publish_clients>");
            NGX_RTMP_STAT(buf, ngx_snprintf(buf, sizeof(buf),
                          "%ui", vost_stat.vhost_publish_clients) - buf);
            NGX_RTMP_STAT_L("</publish_clients>\r\n");
            
            NGX_RTMP_STAT_L("<play_clients>");
            NGX_RTMP_STAT(buf, ngx_snprintf(buf, sizeof(buf),
                          "%ui", vost_stat.vhost_nclients -
                          vost_stat.vhost_publish_clients) - buf);
            NGX_RTMP_STAT_L("</play_clients>\r\n");
            
    }
    total_stat->total_bd_real.bandwidth += vost_stat.vhost_bd_real.bandwidth;
    total_stat->total_bd_real.bytes += vost_stat.vhost_bd_real.bytes;
    NGX_RTMP_STAT_L("</server>\r\n");

    return;
}


static void
ngx_rtmp_stat_main(ngx_http_request_t *r, ngx_chain_t ***lll,
        ngx_rtmp_core_main_conf_t *cmcf, ngx_str_t *type, ngx_str_t *unique_name, ngx_str_t *app, 
        ngx_str_t *stream, ngx_rtmp_total_stat_t *total_stat)
{
    ngx_rtmp_core_srv_conf_t    **cscf;
    ngx_uint_t                             found =0, n, j;
    ngx_rtmp_server_name_t        *names = NULL;

    cscf = cmcf->servers.elts;
    if(unique_name->len == 0) {
		
        for(n = 0; n < cmcf->servers.nelts; ++n, ++cscf) {

            ngx_rtmp_stat_server(r, lll, *cscf, type, app, stream, total_stat);
        }
    } else {

        for(n = 0; n < cmcf->servers.nelts; ++n, ++cscf) {

            for(j = 0; j < (*cscf)->rtmp_publish_domains.nelts; j++) {

                names = (*cscf)->rtmp_publish_domains.elts;
                if(0 == ngx_memcmp(unique_name->data, names->name.data, names->name.len)) {

                    ngx_rtmp_stat_server(r, lll, *cscf, type, app, stream, total_stat);
                    found = 1;
                    break;
                }
            }
		if (found == 1) {

			break;
		}
        }
    }
}


static void
ngx_rtmp_stat_main_r(ngx_http_request_t *r, ngx_chain_t ***lll,
        ngx_rtmp_live_main_conf_t  *lmcf, ngx_str_t *type, ngx_str_t *unique_name, ngx_str_t *app, 
        ngx_str_t *stream, ngx_rtmp_total_stat_t *total_stat)
{
    ngx_uint_t                  i;
    ngx_rtmp_live_dyn_srv_t   **srv;
	
    if (unique_name->len == 0) {

        for(i =0; i< NGX_RTMP_MAX_SRV_NBUCKET; i++){
            srv = &lmcf->srvs[i];
            for (; *srv; srv = &(*srv)->next) {

                if (*srv) {
                    ngx_rtmp_stat_server_r(r, lll, lmcf, *srv, type, app, stream, total_stat);
                }
            }
	    }
    } else {

        srv = ngx_rtmp_live_get_srv_dynamic(lmcf, unique_name, 0); 
        ngx_rtmp_stat_server_r(r, lll, lmcf, *srv, type, app, stream, total_stat);
    }

    return;
}



static ngx_int_t
ngx_rtmp_stat_handler(ngx_http_request_t *r)
{
    ngx_rtmp_stat_loc_conf_t         *slcf;
    ngx_rtmp_core_main_conf_t        *cmcf;
    ngx_rtmp_live_main_conf_t        *cmcf_r;
    ngx_chain_t                      *cl, *l, **ll, ***lll;
    off_t                             len;
    static u_char                     tbuf[NGX_TIME_T_LEN];
    static u_char                     nbuf[NGX_INT_T_LEN];
    ngx_str_t 				          type, unique_name, app, stream;
    ngx_rtmp_total_stat_t             total_stat;
	
    ngx_memset(&total_stat, 0, sizeof(ngx_rtmp_total_stat_t));
    slcf = ngx_http_get_module_loc_conf(r, ngx_rtmp_stat_module);
    if (slcf->stat == 0) {
        return NGX_DECLINED;
    }

    cmcf = ngx_rtmp_core_main_conf;
    if (cmcf == NULL) {
        goto error;
    }

    cl = NULL;
    ll = &cl;
    lll = &ll;

    if (ngx_http_arg(r, (u_char *)"type", 
        sizeof("type") - 1, &type) != NGX_OK) {
        
        type.len = 0;
    }

    if (ngx_http_arg(r, (u_char *)"unique_name", 
        sizeof("vhost") - 1, &unique_name) != NGX_OK) {
        
        unique_name.len = 0;
    }

    if (ngx_http_arg(r, (u_char *)"app", 
        sizeof("app") - 1, &app) != NGX_OK){
        
        app.len = 0;
    }

    if (ngx_http_arg(r, (u_char *)"stream", 
        sizeof("stream") - 1, &stream) != NGX_OK) {
        
        stream.len = 0;
    } 
   
    NGX_RTMP_STAT_L("<?xml version=\"1.0\" encoding=\"utf-8\" ?>\r\n");
    if (type.len ==0 
        ||ngx_strncasecmp(type.data, 
        (u_char*)"all", sizeof("all")-1)==0
        ||ngx_strncasecmp(type.data, 
        (u_char*)"html", sizeof("html")-1)==0) {

            if (slcf->stylesheet.len) {
				
                NGX_RTMP_STAT_L("<?xml-stylesheet type=\"text/xsl\" href=\"");
                NGX_RTMP_STAT_ES(&slcf->stylesheet);
                NGX_RTMP_STAT_L("\" ?>\r\n");
            }
    }

    NGX_RTMP_STAT_L("<rtmp>\r\n");

#ifdef NGINX_VERSION
    NGX_RTMP_STAT_L("<nginx_version>" NGINX_VERSION "</nginx_version>\r\n");
#endif

#ifdef NGINX_RTMP_VERSION
    NGX_RTMP_STAT_L("<nginx_rtmp_version>" NGINX_RTMP_VERSION "</nginx_rtmp_version>\r\n");
#endif

#ifdef NGX_COMPILER
    NGX_RTMP_STAT_L("<compiler>" NGX_COMPILER "</compiler>\r\n");
#endif
    NGX_RTMP_STAT_L("<built>" __DATE__ " " __TIME__ "</built>\r\n");

    NGX_RTMP_STAT_L("<pid>");
    NGX_RTMP_STAT(nbuf, ngx_snprintf(nbuf, sizeof(nbuf),
                  "%ui", (ngx_uint_t) ngx_getpid()) - nbuf);
    NGX_RTMP_STAT_L("</pid>\r\n");

    NGX_RTMP_STAT_L("<uptime>");
    NGX_RTMP_STAT(tbuf, ngx_snprintf(tbuf, sizeof(tbuf),
                  "%T", ngx_cached_time->sec - start_time) - tbuf);
    NGX_RTMP_STAT_L("</uptime>\r\n");

    NGX_RTMP_STAT_L("<naccepted>");
    NGX_RTMP_STAT(nbuf, ngx_snprintf(nbuf, sizeof(nbuf),
                  "%ui", ngx_rtmp_naccepted) - nbuf);
    NGX_RTMP_STAT_L("</naccepted>\r\n");
	
    if(type.len == ngx_strlen("xml")
		&& 0 == ngx_memcmp(type.data, (u_char *)"xml", ngx_strlen("xml"))){

        //total connected counts
        NGX_RTMP_STAT_L("<nclients>");
        NGX_RTMP_STAT(nbuf, ngx_snprintf(nbuf, sizeof(nbuf),
                      "%ui", ngx_rtmp_publishing + ngx_rtmp_playing
                      /*ngx_rtmp_naccepted*/) - nbuf);
        NGX_RTMP_STAT_L("</nclients>\r\n");
        //total publish counts
        NGX_RTMP_STAT_L("<publish_clients>");
        NGX_RTMP_STAT(nbuf, ngx_snprintf(nbuf, sizeof(nbuf),
                      "%ui", ngx_rtmp_publishing) - nbuf);
        NGX_RTMP_STAT_L("</publish_clients>\r\n");
        //total play counts
        NGX_RTMP_STAT_L("<play_clients>");
        NGX_RTMP_STAT(nbuf, ngx_snprintf(nbuf, sizeof(nbuf),
                      "%ui", ngx_rtmp_playing) - nbuf);
        NGX_RTMP_STAT_L("</play_clients>\r\n");
    }

    if (ngx_rtmp_remote_conf()) {

        if (ngx_rtmp_live_main_conf) {
			
            cmcf_r = ngx_rtmp_live_main_conf;
            ngx_rtmp_stat_main_r(r, lll, cmcf_r, &type, &unique_name, &app, &stream, &total_stat);
	  } else {
	  
            ngx_log_error(NGX_LOG_ERR, r->connection->log, 0, "ngx_rtmp_stat_handler:  ngx_rtmp_live_main_conf is NULL!");
      }
    } else {
        ngx_rtmp_stat_main(r, lll, cmcf, &type, &unique_name, &app, &stream, &total_stat);
    }
	
    ngx_rtmp_stat_bw(r, lll, &ngx_rtmp_bw_in, "in", NGX_RTMP_STAT_BW_BYTES);
    ngx_rtmp_stat_bw(r, lll, &ngx_rtmp_bw_out, "out", NGX_RTMP_STAT_BW_BYTES);
    ngx_rtmp_stat_bw(r, lll, &total_stat.total_bd_real/*ngx_rtmp_bw_real*/, "real", NGX_RTMP_STAT_BW_BYTES);
    NGX_RTMP_STAT_L("</rtmp>\r\n");

    len = 0;
    for (l = cl; l; l = l->next) {
        len += (l->buf->last - l->buf->pos);
    }
    ngx_str_set(&r->headers_out.content_type, "text/xml");
    r->headers_out.content_length_n = len;
    r->headers_out.status = NGX_HTTP_OK;
    ngx_http_send_header(r);
    (*ll)->buf->last_buf = 1;
    return ngx_http_output_filter(r, cl);

error:
    r->headers_out.status = NGX_HTTP_INTERNAL_SERVER_ERROR;
    r->headers_out.content_length_n = 0;
    return ngx_http_send_header(r);
}


static void *
ngx_rtmp_stat_create_loc_conf(ngx_conf_t *cf)
{
    ngx_rtmp_stat_loc_conf_t       *conf;

    conf = ngx_pcalloc(cf->pool, sizeof(ngx_rtmp_stat_loc_conf_t));
    if (conf == NULL) {
        return NULL;
    }

    conf->stat = 0;

    return conf;
}


static char *
ngx_rtmp_stat_merge_loc_conf(ngx_conf_t *cf, void *parent, void *child)
{
    ngx_rtmp_stat_loc_conf_t       *prev = parent;
    ngx_rtmp_stat_loc_conf_t       *conf = child;

    ngx_conf_merge_bitmask_value(conf->stat, prev->stat, 0);
    ngx_conf_merge_str_value(conf->stylesheet, prev->stylesheet, "");

    return NGX_CONF_OK;
}


static char *
ngx_rtmp_stat(ngx_conf_t *cf, ngx_command_t *cmd, void *conf)
{
    ngx_http_core_loc_conf_t  *clcf;

    clcf = ngx_http_conf_get_module_loc_conf(cf, ngx_http_core_module);
    clcf->handler = ngx_rtmp_stat_handler;

    return ngx_conf_set_bitmask_slot(cf, cmd, conf);
}


static ngx_int_t
ngx_rtmp_stat_postconfiguration(ngx_conf_t *cf)
{
    start_time = ngx_cached_time->sec;

    return NGX_OK;
}
