
/*
 * Copyright (C) Roman Arutyunyan
 */


#include <ngx_config.h>
#include <ngx_core.h>
#include "ngx_rtmp.h"
#include "ngx_rtmp_amf.h"
#include "ngx_rtmp_live_module.h"
#include "ngx_rtmp_log_module.h"


static void ngx_rtmp_ping(ngx_event_t *rev);
static ngx_int_t ngx_rtmp_finalize_set_chunk_size(ngx_rtmp_session_t *s);
static void ngx_rtmp_update_send_delay(ngx_rtmp_session_t *s);
static void ngx_rtmp_live_update_delay(ngx_rtmp_session_t* s,
        ngx_uint_t type, ngx_uint_t timestamp, ngx_uint_t recv_time);
static void ngx_rtmp_update_timestamp_record(ngx_rtmp_session_t* s,
        ngx_uint_t type, ngx_uint_t timestamp);



ngx_uint_t                  ngx_rtmp_naccepted;
ngx_uint_t                  ngx_rtmp_publishing;
ngx_uint_t                  ngx_rtmp_playing;


ngx_rtmp_bandwidth_t        ngx_rtmp_bw_out;
ngx_rtmp_bandwidth_t        ngx_rtmp_bw_in;


#ifdef NGX_DEBUG
char*
ngx_rtmp_message_type(uint8_t type)
{
    static char*    types[] = {
        "?",
        "chunk_size",
        "abort",
        "ack",
        "user",
        "ack_size",
        "bandwidth",
        "edge",
        "audio",
        "video",
        "?",
        "?",
        "?",
        "?",
        "?",
        "amf3_meta",
        "amf3_shared",
        "amf3_cmd",
        "amf_meta",
        "amf_shared",
        "amf_cmd",
        "?",
        "aggregate"
    };

    return type < sizeof(types) / sizeof(types[0])
        ? types[type]
        : "?";
}


char*
ngx_rtmp_user_message_type(uint16_t evt)
{
    static char*    evts[] = {
        "stream_begin",
        "stream_eof",
        "stream dry",
        "set_buflen",
        "recorded",
        "",
        "ping_request",
        "ping_response",
    };

    return evt < sizeof(evts) / sizeof(evts[0])
        ? evts[evt]
        : "?";
}
#endif


void
ngx_rtmp_cycle(ngx_rtmp_session_t *s)
{
    ngx_connection_t           *c;

    c = s->connection;
    c->read->handler =  ngx_rtmp_recv;
    c->write->handler = ngx_rtmp_send;

    s->ping_evt.data = c;
    s->ping_evt.log = c->log;
    s->ping_evt.handler = ngx_rtmp_ping;
    ngx_rtmp_reset_ping(s);

    ngx_rtmp_recv(c->read);
}


static ngx_chain_t *
ngx_rtmp_alloc_in_buf(ngx_rtmp_session_t *s)
{
    ngx_chain_t        *cl;
    ngx_buf_t          *b;
    size_t              size;

    if ((cl = ngx_alloc_chain_link(s->in_pool)) == NULL
       || (cl->buf = ngx_calloc_buf(s->in_pool)) == NULL)
    {
        return NULL;
    }

    cl->next = NULL;
    b = cl->buf;
    size = s->in_chunk_size + NGX_RTMP_MAX_CHUNK_HEADER;

    b->start = b->last = b->pos = ngx_palloc(s->in_pool, size);
    if (b->start == NULL) {
        return NULL;
    }
    b->end = b->start + size;

    return cl;
}


void
ngx_rtmp_reset_ping(ngx_rtmp_session_t *s)
{
    ngx_rtmp_core_srv_conf_t   *cscf;

    cscf = ngx_rtmp_get_module_srv_conf(s, ngx_rtmp_core_module);
    if (cscf->ping == 0) {
        return;
    }

    s->ping_active = 0;
    s->ping_reset = 0;
    ngx_add_timer(&s->ping_evt, cscf->ping);

    ngx_log_debug1(NGX_LOG_DEBUG_RTMP, s->connection->log, 0,
            "ping: wait %Mms", cscf->ping);
}


static void
ngx_rtmp_ping(ngx_event_t *pev)
{
    ngx_connection_t           *c;
    ngx_rtmp_session_t         *s;
    ngx_rtmp_core_srv_conf_t   *cscf;

    c = pev->data;
    s = !ngx_rtmp_pull_type(c->protocol) ? c->http_data : c->data;

    cscf = ngx_rtmp_get_module_srv_conf(s, ngx_rtmp_core_module);

    /* i/o event has happened; no need to ping */
    if (s->ping_reset) {
        ngx_rtmp_reset_ping(s);
        return;
    }

    ngx_rtmp_set_fincode(s, NGX_RTMP_LOG_FINALIZE_RTMP_PING_ERR_CODE);

    if (s->ping_active) {
        ngx_log_error(NGX_LOG_ERR, c->log, 0,
                "ping: unresponded");
        ngx_rtmp_finalize_session(s);
        return;
    }

    if (cscf->busy) {
        ngx_log_error(NGX_LOG_ERR, c->log, 0,
                "ping: not busy between pings");
        ngx_rtmp_finalize_session(s);
        return;
    }

    ngx_log_debug1(NGX_LOG_DEBUG_RTMP, s->connection->log, 0,
            "ping: schedule %Mms", cscf->ping_timeout);

    if (ngx_rtmp_send_ping_request(s, (uint32_t)ngx_current_msec) != NGX_OK) {
        ngx_rtmp_finalize_session(s);
        return;
    }

    ngx_rtmp_set_fincode(s, NGX_RTMP_LOG_FINALIZE_CLIENT_CLOSE_SESSION_CODE);

    s->ping_active = 1;
    ngx_add_timer(pev, cscf->ping_timeout);
}


void
ngx_rtmp_recv(ngx_event_t *rev)
{
    ngx_int_t                   n;
    ngx_connection_t           *c;
    ngx_rtmp_session_t         *s;
    ngx_rtmp_core_srv_conf_t   *cscf;
    ngx_rtmp_header_t          *h;
    ngx_rtmp_stream_t          *st, *st0;
    ngx_chain_t                *in, *head;
    ngx_buf_t                  *b;
    u_char                     *p, *pp, *old_pos;
    size_t                      size, fsize, old_size;
    uint8_t                     fmt, ext;
    uint32_t                    csid, timestamp;

    c = rev->data;
    s = !ngx_rtmp_type(c->protocol) ? c->http_data : c->data;
    b = NULL;
    old_pos = NULL;
    old_size = 0;
    cscf = ngx_rtmp_get_module_srv_conf(s, ngx_rtmp_core_module);

    if (c->destroyed) {
        return;
    }

    for( ;; ) {

        st = &s->in_streams[s->in_csid];

        /* allocate new buffer */
        if (st->in == NULL) {
            st->in = ngx_rtmp_alloc_in_buf(s);
            if (st->in == NULL) {
                ngx_log_error(NGX_LOG_ERR, c->log, 0,
                        "in buf alloc failed");
                ngx_rtmp_set_fincode(s, NGX_RTMP_LOG_FINALIZE_RTMP_RECV_ERR_CODE);
                ngx_rtmp_finalize_session(s);
                return;
            }
        }

        h  = &st->hdr;
        in = st->in;
        b  = in->buf;

        if (old_size) {

            ngx_log_debug1(NGX_LOG_DEBUG_RTMP, c->log, 0,
                    "reusing formerly read data: %d", old_size);

            b->pos = b->start;
            b->last = ngx_movemem(b->pos, old_pos, old_size);

            if (s->in_chunk_size_changing) {
                ngx_rtmp_finalize_set_chunk_size(s);
            }

        } else {

            if (old_pos) {
                b->pos = b->last = b->start;
            }

            n = c->recv(c, b->last, b->end - b->last);

            if (n == NGX_ERROR || n == 0) {
                ngx_rtmp_set_fincode(s, NGX_RTMP_LOG_FINALIZE_RTMP_PUBLISHER_CLOSE_CODE);
                ngx_rtmp_finalize_session(s);
                return;
            }

            if (n == NGX_AGAIN) {
                if (ngx_handle_read_event(c->read, 0) != NGX_OK) {
                    ngx_rtmp_set_fincode(s, NGX_RTMP_LOG_FINALIZE_RTMP_RECV_ERR_CODE);
                    ngx_rtmp_finalize_session(s);
                }
                return;
            }

            s->ping_reset = 1;

            ngx_rtmp_update_bandwidth(&ngx_rtmp_bw_in, n);

            b->last += n;
            s->in_bytes += n;

            if (s->in_bytes >= 0xf0000000) {
                ngx_log_debug0(NGX_LOG_DEBUG_RTMP, c->log, 0,
                               "resetting byte counter");
                s->in_bytes = 0;
                s->in_last_ack = 0;
            }

            if (s->ack_size && s->in_bytes - s->in_last_ack >= s->ack_size) {

                s->in_last_ack = s->in_bytes;

                ngx_log_debug1(NGX_LOG_DEBUG_RTMP, c->log, 0,
                        "sending RTMP ACK(%uD)", s->in_bytes);

                if (ngx_rtmp_send_ack(s, s->in_bytes)) {
                    ngx_rtmp_set_fincode(s, NGX_RTMP_LOG_FINALIZE_RTMP_RECV_ERR_CODE);
                    ngx_rtmp_finalize_session(s);
                    return;
                }
            }
        }

        old_pos = NULL;
        old_size = 0;

        /* parse headers */
        if (b->pos == b->start) {
            p = b->pos;

            /* chunk basic header */
            fmt  = (*p >> 6) & 0x03;
            csid = *p++ & 0x3f;

            if (csid == 0) {
                if (b->last - p < 1)
                    continue;
                csid = 64;
                csid += *(uint8_t*)p++;

            } else if (csid == 1) {
                if (b->last - p < 2)
                    continue;
                csid = 64;
                csid += *(uint8_t*)p++;
                csid += (uint32_t)256 * (*(uint8_t*)p++);
            }

            ngx_log_debug2(NGX_LOG_DEBUG_RTMP, c->log, 0,
                    "RTMP bheader fmt=%d csid=%D",
                    (int)fmt, csid);

            if (csid >= (uint32_t)cscf->max_streams) {
                ngx_log_error(NGX_LOG_ERR, c->log, 0,
                    "RTMP in chunk stream too big: %D >= %D",
                    csid, cscf->max_streams);
                ngx_rtmp_set_fincode(s, NGX_RTMP_LOG_FINALIZE_PARSE_RTMP_HEAD_ERR_CODE);
                ngx_rtmp_finalize_session(s);
                return;
            }

            /* link orphan */
            if (s->in_csid == 0) {

                /* unlink from stream #0 */
                st->in = st->in->next;

                /* link to new stream */
                s->in_csid = csid;
                st = &s->in_streams[csid];
                if (st->in == NULL) {
                    in->next = in;
                } else {
                    in->next = st->in->next;
                    st->in->next = in;
                }
                st->in = in;
                h = &st->hdr;
                h->csid = csid;
            }

            ext = st->ext;
            timestamp = st->dtime;
            if (fmt <= 2 ) {
                if (b->last - p < 3)
                    continue;
                /* timestamp:
                 *  big-endian 3b -> little-endian 4b */
                pp = (u_char*)&timestamp;
                pp[2] = *p++;
                pp[1] = *p++;
                pp[0] = *p++;
                pp[3] = 0;

                ext = (timestamp == 0x00ffffff);

                if (fmt <= 1) {
                    if (b->last - p < 4)
                        continue;
                    /* size:
                     *  big-endian 3b -> little-endian 4b
                     * type:
                     *  1b -> 1b*/
                    pp = (u_char*)&h->mlen;
                    pp[2] = *p++;
                    pp[1] = *p++;
                    pp[0] = *p++;
                    pp[3] = 0;
                    h->type = *(uint8_t*)p++;

                    if (fmt == 0) {
                        if (b->last - p < 4)
                            continue;
                        /* stream:
                         *  little-endian 4b -> little-endian 4b */
                        pp = (u_char*)&h->msid;
                        pp[0] = *p++;
                        pp[1] = *p++;
                        pp[2] = *p++;
                        pp[3] = *p++;
                    }
                }
            }

            /* extended header */
            if (ext) {
                if (b->last - p < 4)
                    continue;
                pp = (u_char*)&timestamp;
                pp[3] = *p++;
                pp[2] = *p++;
                pp[1] = *p++;
                pp[0] = *p++;

                /* When fmt == 3, after chunk header may not
                 * have 4 bytes for ext timestamp */
                if (3 == fmt) {
                    if (timestamp != h->timestamp &&
                        !ngx_rtmp_get_attr_conf(cscf, publish_extime_fix)) {
                        p = p - 4;
                        ngx_log_debug0(NGX_LOG_DEBUG_RTMP, c->log, 0, " fmt == 3 , dont have ext timestamp for old protocol");
                    }
                }
            }

            if (st->len == 0) {
                /* Messages with type=3 should
                 * never have ext timestamp field
                 * according to standard.
                 * However that's not always the case
                 * in real life */
                st->ext = (ext && cscf->publish_time_fix);
                if (fmt) {
                    st->dtime = timestamp;
                } else {
                    h->timestamp = timestamp;
                    st->dtime = 0;
                }
            }

            ngx_log_debug8(NGX_LOG_DEBUG_RTMP, c->log, 0,
                    "RTMP mheader fmt=%d %s (%d) "
                    "time=%uD+%uD mlen=%D len=%D msid=%D",
                    (int)fmt, ngx_rtmp_message_type(h->type), (int)h->type,
                    h->timestamp, st->dtime, h->mlen, st->len, h->msid);

            /* header done */
            b->pos = p;

            if (h->mlen > cscf->max_message) {
                ngx_log_error(NGX_LOG_ERR, c->log, 0,
                        "too big message: %uz mlen: %D", cscf->max_message, h->mlen);
                ngx_rtmp_set_fincode(s, NGX_RTMP_LOG_FINALIZE_PARSE_RTMP_HEAD_ERR_CODE);
                ngx_rtmp_finalize_session(s);
                return;
            }
        }

        size = b->last - b->pos;
        fsize = h->mlen - st->len;

        if (size < ngx_min(fsize, s->in_chunk_size))
            continue;

        /* buffer is ready */

        if (fsize > s->in_chunk_size) {
            /* collect fragmented chunks */
            st->len += s->in_chunk_size;
            b->last = b->pos + s->in_chunk_size;
            old_pos = b->last;
            old_size = size - s->in_chunk_size;

        } else {
            /* handle! */
            head = st->in->next;
            st->in->next = NULL;
            b->last = b->pos + fsize;
            old_pos = b->last;
            old_size = size - fsize;
            st->len = 0;
            h->timestamp += st->dtime;

            if (ngx_rtmp_receive_message(s, h, head) != NGX_OK) {
                if (s->finalize_code == NGX_RTMP_LOG_FINALIZE_CLIENT_CLOSE_SESSION_CODE){
                    ngx_rtmp_set_fincode(s, NGX_RTMP_LOG_FINALIZE_RTMP_RECV_ERR_CODE);
                }
                ngx_rtmp_finalize_session(s);
                return;
            }

            if (s->in_chunk_size_changing) {
                /* copy old data to a new buffer */
                if (!old_size) {
                    ngx_rtmp_finalize_set_chunk_size(s);
                }

            } else {
                /* add used bufs to stream #0 */
                st0 = &s->in_streams[0];
                st->in->next = st0->in;
                st0->in = head;
                st->in = NULL;
            }
        }

        s->in_csid = 0;
    }
}


void
ngx_rtmp_send(ngx_event_t *wev)
{
    ngx_connection_t           *c;
    ngx_rtmp_session_t         *s;
    ngx_int_t                   n;
    ngx_rtmp_core_srv_conf_t   *cscf;
    ngx_rtmp_live_ctx_t 	   *ctx; 

    c = wev->data;
    s = !ngx_rtmp_type(c->protocol) ? c->http_data : c->data;

    if (c->destroyed) {
        return;
    }

    if (wev->timedout) {
        ngx_log_error(NGX_LOG_ERR, c->log, NGX_ETIMEDOUT,
                "client timed out");
        c->timedout = 1;
        ngx_rtmp_finalize_session(s);
        return;
    }

    if (wev->timer_set) {
        ngx_del_timer(wev);
    }

    if (s->out_chain == NULL && s->out_pos != s->out_last) {
        s->out_chain = s->out[s->out_pos];
        s->out_bpos = s->out_chain->buf->pos;
    }

    ctx = ngx_rtmp_get_module_ctx(s, ngx_rtmp_live_module); 
    while (s->out_chain) {
        n = c->send(c, s->out_bpos, s->out_chain->buf->last - s->out_bpos);

        if (n == NGX_AGAIN || n == 0) {
            ngx_add_timer(c->write, s->timeout);
            if (ngx_handle_write_event(c->write, 0) != NGX_OK) {
                ngx_rtmp_finalize_session(s);
            }
            return;
        }

        if (n < 0) {
            ngx_rtmp_finalize_session(s);
            return;
        }

        s->out_bytes += n;
        s->ping_reset = 1;

      	ngx_rtmp_update_bandwidth(&ngx_rtmp_bw_out, n);

      	if(ctx && ctx->stream){ 
            ngx_rtmp_update_bandwidth(&ctx->stream->bw_out, n);

            if (s->relay_type == NGX_NONE_RELAY) {

                ngx_rtmp_update_bandwidth(&ctx->stream->bw_out_bytes, n);
            }
      	}

        s->out_bpos += n;
        if (s->out_bpos == s->out_chain->buf->last) {
            s->out_chain = s->out_chain->next;
            if (s->out_chain == NULL) {
                cscf = ngx_rtmp_get_module_srv_conf(s, ngx_rtmp_core_module);
                ngx_rtmp_update_send_delay(s);
                ngx_rtmp_free_shared_chain(cscf, s->out[s->out_pos]);
                s->out[s->out_pos] = NULL;
                ++s->out_pos;
                s->out_pos %= s->out_queue;
                if (s->out_pos == s->out_last) {
                    break;
                }
                s->out_chain = s->out[s->out_pos];
            }
            s->out_bpos = s->out_chain->buf->pos;
        }
    }

    if (wev->active) {
        ngx_del_event(wev, NGX_WRITE_EVENT, 0);
    }

    ngx_event_process_posted((ngx_cycle_t *) ngx_cycle, &s->posted_dry_events);
}


void
ngx_rtmp_prepare_message(ngx_rtmp_session_t *s, ngx_rtmp_header_t *h,
        ngx_rtmp_header_t *lh, ngx_chain_t *out)
{
    ngx_chain_t                *l;
    u_char                     *p, *pp;
    ngx_int_t                   hsize, thsize, nbufs;
    uint32_t                    mlen, timestamp, ext_timestamp;
    static uint8_t              hdrsize[] = { 12, 8, 4, 1 };
    u_char                      th[7];
    ngx_rtmp_core_srv_conf_t   *cscf;
    uint8_t                     fmt;
    ngx_connection_t           *c;

    c = s->connection;
    cscf = ngx_rtmp_get_module_srv_conf(s, ngx_rtmp_core_module);

    if (h->csid >= (uint32_t)cscf->max_streams) {
        ngx_log_error(NGX_LOG_ERR, c->log, 0,
                "RTMP out chunk stream too big: %D >= %D",
                h->csid, cscf->max_streams);
        ngx_rtmp_set_fincode(s, NGX_RTMP_LOG_FINALIZE_PARSE_RTMP_HEAD_ERR_CODE);
        ngx_rtmp_finalize_session(s);
        return;
    }

    /* detect packet size */
    mlen = 0;
    nbufs = 0;
    for(l = out; l; l = l->next) {
        mlen += (l->buf->last - l->buf->pos);
        ++nbufs;
    }

    fmt = 0;
    /*if (lh && lh->csid && h->msid == lh->msid) {
        ++fmt;
        if (h->type == lh->type && mlen && mlen == lh->mlen) {
            ++fmt;
            if (h->timestamp == lh->timestamp) {
                ++fmt;
            }
        }
        timestamp = h->timestamp - lh->timestamp;
    } else {*/
        timestamp = h->timestamp;
    /*}*/

    /*if (lh) {
        *lh = *h;
        lh->mlen = mlen;
    }*/

    hsize = hdrsize[fmt];

    ngx_log_debug8(NGX_LOG_DEBUG_RTMP, s->connection->log, 0,
            "RTMP prep %s (%d) fmt=%d csid=%uD timestamp=%uD "
            "mlen=%uD msid=%uD nbufs=%d",
            ngx_rtmp_message_type(h->type), (int)h->type, (int)fmt,
            h->csid, timestamp, mlen, h->msid, nbufs);

    ext_timestamp = 0;
    if (timestamp >= 0x00ffffff) {
        ext_timestamp = timestamp;
        timestamp = 0x00ffffff;
        hsize += 4;
    }

    if (h->csid >= 64) {
        ++hsize;
        if (h->csid >= 320) {
            ++hsize;
        }
    }

    /* fill initial header */
    out->buf->pos -= hsize;
    p = out->buf->pos;

    /* basic header */
    *p = (fmt << 6);
    if (h->csid >= 2 && h->csid <= 63) {
        *p++ |= (((uint8_t)h->csid) & 0x3f);
    } else if (h->csid >= 64 && h->csid < 320) {
        ++p;
        *p++ = (uint8_t)(h->csid - 64);
    } else {
        *p++ |= 1;
        *p++ = (uint8_t)(h->csid - 64);
        *p++ = (uint8_t)((h->csid - 64) >> 8);
    }

    /* create fmt3 header for successive fragments */
    thsize = p - out->buf->pos;
    ngx_memcpy(th, out->buf->pos, thsize);
    th[0] |= 0xc0;

    /* message header */
    if (fmt <= 2) {
        pp = (u_char*)&timestamp;
        *p++ = pp[2];
        *p++ = pp[1];
        *p++ = pp[0];
        if (fmt <= 1) {
            pp = (u_char*)&mlen;
            *p++ = pp[2];
            *p++ = pp[1];
            *p++ = pp[0];
            *p++ = h->type;
            if (fmt == 0) {
                pp = (u_char*)&h->msid;
                *p++ = pp[0];
                *p++ = pp[1];
                *p++ = pp[2];
                *p++ = pp[3];
            }
        }
    }

    /* extended header */
    if (ext_timestamp) {
        pp = (u_char*)&ext_timestamp;
        *p++ = pp[3];
        *p++ = pp[2];
        *p++ = pp[1];
        *p++ = pp[0];

        /* This CONTRADICTS the standard
         * but that's the way flash client
         * wants data to be encoded;
         * ffmpeg complains */
        if (cscf->play_time_fix) {
            ngx_memcpy(&th[thsize], p - 4, 4);
            thsize += 4;
        }
    }

    /* append headers to successive fragments */
    for(out = out->next; out; out = out->next) {
        out->buf->pos -= thsize;
        ngx_memcpy(out->buf->pos, th, thsize);
    }
}


ngx_int_t
ngx_rtmp_send_message(ngx_rtmp_session_t *s, ngx_chain_t *out,
        ngx_uint_t priority)
{
    ngx_uint_t                      nmsg;

    if (!ngx_rtmp_type(s->protocol)) {

        return NGX_OK;
    }

    nmsg = (s->out_last - s->out_pos) % s->out_queue + 1;

    if (priority > 3) {
        priority = 3;
    }

    /* drop packet?
     * Note we always leave 1 slot free */
    if (nmsg + priority * s->out_queue / 4 >= s->out_queue) {
    /*
        ngx_log_debug2(NGX_LOG_DEBUG_RTMP, s->connection->log, 0,
                "RTMP drop message bufs=%ui, priority=%ui",
                nmsg, priority);
    */
        ngx_log_error(NGX_LOG_WARN, s->connection->log, 0,
            "RTMP drop message bufs=%ui, priority=%ui, s->out_last=%d, s->out_pos=%d, s->out_queue=%d ",
            nmsg, priority, s->out_last, s->out_pos, s->out_queue);
        return NGX_AGAIN;
    }

    s->out[s->out_last++] = out;
    s->out_last %= s->out_queue;

    ngx_rtmp_acquire_shared_chain(out);

    ngx_log_debug3(NGX_LOG_DEBUG_RTMP, s->connection->log, 0,
            "RTMP send nmsg=%ui, priority=%ui #%ui",
            nmsg, priority, s->out_last);

    if (priority && s->out_buffer && nmsg < s->out_cork) {
        return NGX_OK;
    }

    if (!s->connection->write->active) {

        ngx_rtmp_send(s->connection->write);
    }

    return NGX_OK;
}


ngx_int_t
ngx_rtmp_receive_message(ngx_rtmp_session_t *s,
        ngx_rtmp_header_t *h, ngx_chain_t *in)
{
    ngx_rtmp_core_main_conf_t  *cmcf;
    ngx_array_t                *evhs;
    size_t                      n;
    ngx_rtmp_handler_pt        *evh;

    cmcf = ngx_rtmp_get_module_main_conf(s, ngx_rtmp_core_module);

#ifdef NGX_DEBUG
    {
        int             nbufs;
        ngx_chain_t    *ch;

        for(nbufs = 1, ch = in;
                ch->next;
                ch = ch->next, ++nbufs);

        ngx_log_debug7(NGX_LOG_DEBUG_RTMP, s->connection->log, 0,
                "RTMP recv %s (%d) csid=%D timestamp=%D "
                "mlen=%D msid=%D nbufs=%d",
                ngx_rtmp_message_type(h->type), (int)h->type,
                h->csid, h->timestamp, h->mlen, h->msid, nbufs);
    }
#endif

    if (h->type > NGX_RTMP_MSG_MAX) {
        ngx_log_debug1(NGX_LOG_DEBUG_RTMP, s->connection->log, 0,
                "unexpected RTMP message type: %d", (int)h->type);
        return NGX_OK;
    }

    evhs = &cmcf->events[h->type];
    evh = evhs->elts;

    s->log_bpos = s->log_buf;
    s->log_bpos = ngx_sprintf(s->log_bpos, BLANK_SPACE"rtmp_msg_type:%d", h->type);

    ngx_log_debug1(NGX_LOG_DEBUG_RTMP, s->connection->log, 0,
            "nhandlers: %d", evhs->nelts);

    for(n = 0; n < evhs->nelts; ++n, ++evh) {
        if (!evh) {
            continue;
        }
        ngx_log_debug1(NGX_LOG_DEBUG_RTMP, s->connection->log, 0,
                "calling handler %d", n);

        switch ((*evh)(s, h, in)) {
            case NGX_ERROR:
                ngx_log_debug1(NGX_LOG_DEBUG_RTMP, s->connection->log, 0,
                        "handler %d failed", n);
                return NGX_ERROR;
            case NGX_DONE:
                return NGX_OK;
        }
    }

    *s->log_bpos++ = 0;

    switch(h->type) {
        case NGX_RTMP_MSG_AUDIO:
        {
            if (!s->audio_recved) {
                s->audio_recved = 1;
                ngx_rtmp_log_evt_in(s);
            }
            break;
        }
        case NGX_RTMP_MSG_VIDEO:
        {
            if (!s->video_recved) {
                s->video_recved = 1;
                ngx_rtmp_log_evt_in(s);
            }
            break;
        }
        default:
            ngx_rtmp_log_evt_in(s);
    }

    return NGX_OK;
}


ngx_int_t
ngx_rtmp_set_chunk_size(ngx_rtmp_session_t *s, ngx_uint_t size)
{
    ngx_rtmp_core_srv_conf_t           *cscf;
    ngx_chain_t                        *li, *fli, *lo, *flo;
    ngx_buf_t                          *bi, *bo;
    ngx_int_t                           n;

    ngx_log_debug1(NGX_LOG_DEBUG_RTMP, s->connection->log, 0,
        "setting chunk_size=%ui", size);

    cscf = ngx_rtmp_get_module_srv_conf(s, ngx_rtmp_core_module);

    s->in_old_pool = s->in_pool;
    s->in_chunk_size = size;
    s->in_pool = ngx_create_pool(4096, s->connection->log);

    /* copy existing chunk data */
    if (s->in_old_pool) {
        s->in_chunk_size_changing = 1;
        s->in_streams[0].in = NULL;

        for(n = 1; n < cscf->max_streams; ++n) {
            /* stream buffer is circular
             * for all streams except for the current one
             * (which caused this chunk size change);
             * we can simply ignore it */
            li = s->in_streams[n].in;
            if (li == NULL || li->next == NULL) {
                s->in_streams[n].in = NULL;
                continue;
            }
            /* move from last to the first */
            li = li->next;
            fli = li;
            lo = ngx_rtmp_alloc_in_buf(s);
            if (lo == NULL) {
                return NGX_ERROR;
            }
            flo = lo;
            for ( ;; ) {
                bi = li->buf;
                bo = lo->buf;

                if (bo->end - bo->last >= bi->last - bi->pos) {
                    bo->last = ngx_cpymem(bo->last, bi->pos,
                            bi->last - bi->pos);
                    li = li->next;
                    if (li == fli)  {
                        lo->next = flo;
                        s->in_streams[n].in = lo;
                        break;
                    }
                    continue;
                }

                bi->pos += (ngx_cpymem(bo->last, bi->pos,
                            bo->end - bo->last) - bo->last);
                lo->next = ngx_rtmp_alloc_in_buf(s);
                lo = lo->next;
                if (lo == NULL) {
                    return NGX_ERROR;
                }
            }
        }
    }

    return NGX_OK;
}


/*record last audio/video timestamp and min/max timestamp*/
static void
ngx_rtmp_update_timestamp_record(ngx_rtmp_session_t* s,
        ngx_uint_t type, ngx_uint_t timestamp)
{
    if (type == NGX_RTMP_MSG_AUDIO) {

        s->last_audio_ts = timestamp;
        if (s->audio_ts_min == NGX_RTMP_INVALID_TIMESTAMP
                || timestamp < s->audio_ts_min) {

            s->audio_ts_min = timestamp;
        }

        if (s->audio_ts_max == NGX_RTMP_INVALID_TIMESTAMP
                || timestamp > s->audio_ts_max) {

            s->audio_ts_max = timestamp;
        }
    } else if (type == NGX_RTMP_MSG_VIDEO) {

        s->last_video_ts = timestamp;
        if (s->video_ts_min == NGX_RTMP_INVALID_TIMESTAMP
                || timestamp < s->video_ts_min) {

            s->video_ts_min = timestamp;
        }
        if (s->video_ts_max == NGX_RTMP_INVALID_TIMESTAMP
                || timestamp > s->video_ts_max) {

            s->video_ts_max = timestamp;
        }
    }
}


static ngx_int_t
ngx_rtmp_finalize_set_chunk_size(ngx_rtmp_session_t *s)
{
    if (s->in_chunk_size_changing && s->in_old_pool) {
        ngx_destroy_pool(s->in_old_pool);
        s->in_old_pool = NULL;
        s->in_chunk_size_changing = 0;
    }
    return NGX_OK;
}

void
ngx_rtmp_update_recv_delay(ngx_rtmp_session_t *s,
        ngx_rtmp_header_t *h, ngx_chain_t* in, ngx_chain_t *rpkt)
{
    ngx_uint_t              recv_time;
    ngx_rtmp_chunk_info_t   *ci;
    u_char                  *p;
    int32_t                 cts;

    if (h->type != NGX_RTMP_MSG_AUDIO && h->type != NGX_RTMP_MSG_VIDEO) {
        return;
    }

    recv_time = ngx_rtmp_get_utc_time();

    ci = ngx_rtmp_get_chunk_info(rpkt);
    ci->type = h->type;
    ci->timestamp = h->timestamp;
    ci->is_raw = 1;
    ci->recv_time = recv_time;

    p = in->buf->pos;
    if (h->type == NGX_RTMP_MSG_VIDEO && p + 5 <= in->buf->last) {
        ngx_memcpy(&cts, p + 2, 3);
        cts = ((cts & 0x00FF0000) >> 16) | ((cts & 0x000000FF) << 16) |
                (cts & 0x0000FF00);

        cts = (int32_t) ((cts << 8) >> 8);

        s->last_video_cts = cts;
    }

    ngx_rtmp_live_update_delay(s, h->type, h->timestamp, recv_time);
}

static void
ngx_rtmp_update_send_delay(ngx_rtmp_session_t *s)
{
    ngx_rtmp_chunk_info_t   *ci;
    ngx_chain_t             *out;

    out = s->out[s->out_pos];
    ci = ngx_rtmp_get_chunk_info(out);

    if (ci->type != NGX_RTMP_MSG_AUDIO && ci->type != NGX_RTMP_MSG_VIDEO) {
        return;
    }

    if (!ci->is_raw) {
        return;
    }

    ngx_rtmp_live_update_delay(s, ci->type, ci->timestamp, ci->recv_time);
}

static void
ngx_rtmp_append_delay(ngx_rtmp_session_t *s)
{
    ngx_rtmp_delay_t    *d;
    
    if (s->delay == NULL) {
        s->delay = s->delay_cur;
        s->delay_cur = NULL;
        return;
    }

    for (d = s->delay; d->next != NULL; d = d->next);

    d->next = s->delay_cur;
    s->delay_cur = NULL;
}

static ngx_rtmp_delay_t*
ngx_rtmp_alloc_delay(ngx_rtmp_session_t *s)
{
    ngx_rtmp_delay_t    *delay;

    if (s->delay_cur) return s->delay_cur;
    
    if (s->delay_free) {
        delay = s->delay_free;
        s->delay_free = s->delay_free->next;
        ngx_memzero(delay, sizeof(ngx_rtmp_delay_t));
        s->delay_cur = delay;
        return delay;
    }
    
    delay = ngx_palloc(s->connection->pool, sizeof(ngx_rtmp_delay_t));
    if (delay == NULL) {
        return NULL;
    }

    ngx_memzero(delay, sizeof(ngx_rtmp_delay_t));
    s->delay_cur = delay;
    return delay;
}

static void
ngx_rtmp_live_update_delay(ngx_rtmp_session_t* s,
        ngx_uint_t type, ngx_uint_t timestamp,
        ngx_uint_t recv_time)
{
    ngx_rtmp_delay_t               *delay;
    ngx_int_t                       cur_utc;
    ngx_rtmp_codec_ctx_t           *codec_ctx;
    ngx_rtmp_live_stream_t         *stream;
    ngx_rtmp_live_ctx_t            *ctx, *orictx, *pubctx;
    ngx_int_t                       audio_delay;
    ngx_uint_t                      audio_frame_size;

    ngx_rtmp_update_timestamp_record(s, type, timestamp);

    orictx = ngx_rtmp_get_module_ctx(s, ngx_rtmp_live_module);
    if (orictx == NULL || orictx->stream == NULL) {
        return;
    }

    stream = orictx->stream;
    if (!stream->publishing) {
        return;
    }

    pubctx = NULL;
    if (orictx->publishing) {

        pubctx = orictx;
    } else {

        for (ctx = stream->ctx; ctx; ctx = ctx->next) {

            if (ctx->publishing) {

                pubctx = ctx;
                break;
            }
        }
    }

    if (pubctx == NULL) {

        return;
    }

    codec_ctx = ngx_rtmp_get_module_ctx(pubctx->session, ngx_rtmp_codec_module);
    if (codec_ctx == NULL || !(codec_ctx->interval > 0)) {

        return;
    }

    delay = ngx_rtmp_alloc_delay(s);
    if (delay == NULL) {
        return;
    }

    cur_utc = (ngx_int_t)ngx_rtmp_get_utc_time();

    if (type == NGX_RTMP_MSG_VIDEO) { // video

        ++ delay->video_frame_num;
        return;
    }

    if (codec_ctx->first_audio_pts == NGX_MAX_INT32_VALUE) { // first audio frame

        codec_ctx->first_audio_pts = timestamp;
        ngx_log_debug(NGX_LOG_DEBUG, s->connection->log, 0,
                "count first audio frame, time: %i, pts: %i", cur_utc, timestamp);
    }
    
    if (delay->start_time == 0) {

        delay->last_audio_pts = timestamp;
        delay->start_time = cur_utc;
        delay->audio_delay_min = ((ngx_uint_t)(-1)) >>1 ;
        delay->audio_delay_max = ~ delay->audio_delay_min;
        ngx_log_debug(NGX_LOG_DEBUG,  s->connection->log, 0,
                "log delay start, time: %i, pts: %i", cur_utc, timestamp);
    } else {

        /* real time delta minus pts delta */
        audio_delay =  (cur_utc - delay->start_time) - (timestamp - delay->last_audio_pts);

        if (delay->audio_delay_min > audio_delay) {
            delay->audio_delay_min = audio_delay;
        }

        if (delay->audio_delay_max < audio_delay) {
            delay->audio_delay_max = audio_delay;
        }
    }

    /* time to log */
    if (timestamp / codec_ctx->interval  >  delay->last_audio_pts / codec_ctx->interval) {
        ngx_log_debug(NGX_LOG_DEBUG,  s->connection->log, 0,
                "time to log delay, time: %i, pts: %i", cur_utc, timestamp);
        /* last delay */
        delay->cur_audio_pts = timestamp;
        delay->audio_recv_time = cur_utc;
        delay->time_cost = cur_utc - delay->start_time;
        if (orictx->publishing) { // publisher

            delay->send_delay = 0;
            delay->recv_delay = (cur_utc - codec_ctx->utc_start_time) - timestamp;
        } else { // player

            delay->recv_delay = 0;
            delay->send_delay = cur_utc - recv_time;
        }

        delay->audio_duration /= 1000; // us -> ms
        ngx_rtmp_append_delay(s);

        // new delay
        delay = ngx_rtmp_alloc_delay(s);
        if (delay == NULL) {
            return;
        }

        delay->start_time = cur_utc;
        delay->audio_duration = 0;
        delay->last_audio_pts = timestamp;
        delay->video_frame_num = 0;
    }
    audio_frame_size = NGX_RTMP_AUDIO_FRAME_SIZE_AAC;
    switch (codec_ctx->audio_codec_id) {
        case NGX_RTMP_AUDIO_MP3:
            audio_frame_size = NGX_RTMP_AUDIO_FRAME_SIZE_MP3;
            break;
        case NGX_RTMP_AUDIO_AAC:
            audio_frame_size = NGX_RTMP_AUDIO_FRAME_SIZE_AAC;
            break;
        default:
            break; 
    }
    delay->audio_duration += codec_ctx->sample_rate > 0
        ? audio_frame_size * 1000 * 1000 / codec_ctx->sample_rate//us 
        : 0;
}

