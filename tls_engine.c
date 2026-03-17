/*
 * tls_engine.c - abstract TLS engine I/O behind tlswrapper buffers
 *
 * This module provides the tlswrapper-facing abstraction over the TLS
 * engine layer. The current backend is BearSSL, but the interface is
 * shaped so the same higher-level buffer and state handling can be reused
 * with other TLS library implementations later. In delayed-encryption mode
 * it also acts as the buffer-management layer responsible for copying
 * data between the child side and the network until TLS (STARTTLS) is enabled.
 */

#include "writeall.h"
#include "log.h"
#include "tls.h"

/*
 * tls_engine_sendapp_buf - return writable plaintext output space
 *
 * @ctx: TLS session state
 * @len: returns the available buffer length
 *
 * Returns a buffer where application data for the peer can be queued.
 * In delayed-encryption mode this is tlswrapper's pending network buffer.
 * Otherwise the buffer comes directly from the BearSSL engine.
 *
 * Constraints:
 *   - ctx and len must be valid pointers
 *   - the returned buffer becomes invalid after the next engine call
 */
unsigned char *tls_engine_sendapp_buf(struct tls_context *ctx, size_t *len) {
    if (ctx->flagdelayedenc) {
        if (ctx->childclosed) return 0;
        *len = sizeof ctx->tonetbuf - ctx->tonetbuflen;
        if (!*len) return 0;
        return ctx->tonetbuf + ctx->tonetbuflen;
    }
    return br_ssl_engine_sendapp_buf(&ctx->cc.eng, len);
}

/*
 * tls_engine_sendapp_ack - publish plaintext bytes queued for sending
 *
 * @ctx: TLS session state
 * @len: number of bytes written into the sendapp buffer
 *
 * Commits application bytes previously obtained from
 * tls_engine_sendapp_buf(). In delayed-encryption mode this only advances
 * the local pending-buffer length.
 */
void tls_engine_sendapp_ack(struct tls_context *ctx, size_t len) {
    if (ctx->flagdelayedenc) {
        ctx->tonetbuflen += len;
        return;
    }
    br_ssl_engine_sendapp_ack(&ctx->cc.eng, len);
}

/*
 * tls_engine_recvapp_buf - return readable plaintext input data
 *
 * @ctx: TLS session state
 * @len: returns the available buffer length
 *
 * Returns application data already decoded for the child side. In
 * delayed-encryption mode this exposes the buffered plaintext accumulated
 * from the network. Otherwise the data comes from the BearSSL engine.
 */
unsigned char *tls_engine_recvapp_buf(struct tls_context *ctx, size_t *len) {
    if (ctx->flagdelayedenc) {
        if (ctx->childclosed) return 0;
        *len = ctx->tochildbuflen;
        if (!*len) return 0;
        return ctx->tochildbuf;
    }
    return br_ssl_engine_recvapp_buf(&ctx->cc.eng, len);
}

/*
 * tls_engine_recvapp_ack - consume plaintext bytes delivered to the child
 *
 * @ctx: TLS session state
 * @len: number of bytes consumed from the recvapp buffer
 *
 * Acknowledges plaintext returned by tls_engine_recvapp_buf(). In
 * delayed-encryption mode the unread tail is compacted to the front
 * of the local buffer.
 */
void tls_engine_recvapp_ack(struct tls_context *ctx, size_t len) {
    if (ctx->flagdelayedenc) {
        memmove(ctx->tochildbuf, ctx->tochildbuf + len,
                ctx->tochildbuflen - len);
        ctx->tochildbuflen -= len;
        return;
    }
    br_ssl_engine_recvapp_ack(&ctx->cc.eng, len);
}

/*
 * tls_engine_sendrec_buf - return readable TLS records for the network
 *
 * @ctx: TLS session state
 * @len: returns the available buffer length
 *
 * Returns encoded TLS records ready to be written to the peer. In
 * delayed-encryption mode this exposes the local record buffer instead of
 * the BearSSL engine's transmit buffer.
 */
unsigned char *tls_engine_sendrec_buf(struct tls_context *ctx, size_t *len) {
    if (ctx->flagdelayedenc) {
        if (ctx->netclosed) return 0;
        *len = ctx->tonetbuflen;
        if (!*len) return 0;
        return ctx->tonetbuf;
    }
    return br_ssl_engine_sendrec_buf(&ctx->cc.eng, len);
}

/*
 * tls_engine_sendrec_ack - consume TLS records written to the network
 *
 * @ctx: TLS session state
 * @len: number of bytes consumed from the sendrec buffer
 *
 * Removes records previously returned by tls_engine_sendrec_buf(). In
 * delayed-encryption mode remaining bytes are shifted to preserve a
 * contiguous pending buffer.
 */
void tls_engine_sendrec_ack(struct tls_context *ctx, size_t len) {
    if (ctx->flagdelayedenc) {
        memmove(ctx->tonetbuf, ctx->tonetbuf + len, ctx->tonetbuflen - len);
        ctx->tonetbuflen -= len;
        return;
    }
    br_ssl_engine_sendrec_ack(&ctx->cc.eng, len);
}

/*
 * tls_engine_recvrec_buf - return writable space for incoming TLS records
 *
 * @ctx: TLS session state
 * @len: returns the available buffer length
 *
 * Returns storage for raw TLS records read from the peer. In
 * delayed-encryption mode this points at free space in the local plaintext
 * buffer used before deferred processing.
 */
unsigned char *tls_engine_recvrec_buf(struct tls_context *ctx, size_t *len) {
    if (ctx->flagdelayedenc) {
        if (ctx->netclosed) return 0;
        *len = sizeof ctx->tochildbuf - ctx->tochildbuflen;
        if (!*len) return 0;
        return ctx->tochildbuf + ctx->tochildbuflen;
    }
    return br_ssl_engine_recvrec_buf(&ctx->cc.eng, len);
}

/*
 * tls_engine_recvrec_ack - publish newly received TLS record bytes
 *
 * @ctx: TLS session state
 * @len: number of bytes stored into the recvrec buffer
 *
 * Commits bytes written into the buffer returned by
 * tls_engine_recvrec_buf(). In delayed-encryption mode this only extends
 * the buffered input length.
 */
void tls_engine_recvrec_ack(struct tls_context *ctx, size_t len) {
    if (ctx->flagdelayedenc) {
        ctx->tochildbuflen += len;
        return;
    }
    br_ssl_engine_recvrec_ack(&ctx->cc.eng, len);
}

/*
 * tls_engine_sendapp5_buf - return writable space for delayed plaintext
 *
 * @ctx: TLS session state
 * @len: returns the available buffer length
 *
 * Exposes the auxiliary plaintext buffer used by delayed-encryption mode.
 * This is the extra staging area layered on top of the normal plaintext
 * copying path before deferred encryption is turned off. Outside that
 * mode no buffer is available and the function returns null.
 */
unsigned char *tls_engine_sendapp5_buf(struct tls_context *ctx, size_t *len) {
    if (ctx->flagdelayedenc) {
        if (ctx->childclosed) return 0;
        *len = sizeof ctx->tonet5buf - ctx->tonet5buflen;
        if (!*len) return 0;
        return ctx->tonet5buf + ctx->tonet5buflen;
    }
    return 0;
}

/*
 * tls_engine_sendapp5_ack - publish bytes written to the auxiliary buffer
 *
 * @ctx: TLS session state
 * @len: number of bytes written into the sendapp5 buffer
 *
 * Commits plaintext queued through tls_engine_sendapp5_buf(). The call is
 * ignored when delayed encryption is not active.
 */
void tls_engine_sendapp5_ack(struct tls_context *ctx, size_t len) {
    if (ctx->flagdelayedenc) {
        ctx->tonet5buflen += len;
        return;
    }
    return;
}

/*
 * tls_engine_flush - request record emission from the TLS engine
 *
 * @ctx: TLS session state
 * @force: non-zero to force emission of a partial record
 *
 * For active BearSSL sessions this forwards the flush request to the
 * engine. Delayed-encryption mode does not emit records here.
 */
void tls_engine_flush(struct tls_context *ctx, int force) {
    if (ctx->flagdelayedenc) return;
    br_ssl_engine_flush(&ctx->cc.eng, force);
}

/*
 * tls_engine_close - initiate an orderly TLS shutdown
 *
 * @ctx: TLS session state
 *
 * Starts connection closure. In delayed-encryption mode this only marks
 * the child side as closed so local buffered data can drain first.
 */
void tls_engine_close(struct tls_context *ctx) {
    if (ctx->flagdelayedenc) {
        ctx->childclosed = 1;
        return;
    }
    br_ssl_engine_close(&ctx->cc.eng);
}

/*
 * tls_engine_handshakedone - report the first transition to app-data state
 *
 * @ctx: TLS session state
 *
 * Returns 1 exactly once when the BearSSL engine first reports that
 * application data can be sent. Returns 0 before that point and on all
 * later calls.
 */
int tls_engine_handshakedone(struct tls_context *ctx) {
    if (!ctx->flagdelayedenc && !ctx->flaghandshakedone) {
        unsigned int st = tls_engine_current_state(ctx);
        if (st & BR_SSL_SENDAPP) {
            ctx->flaghandshakedone = 1;
            return 1;
        }
    }
    return 0;
}

/*
 * tls_engine_current_state - compute the current engine readiness flags
 *
 * @ctx: TLS session state
 *
 * Returns BearSSL state flags for either the native engine or the local
 * delayed-encryption buffers. When the connection reaches a closed state,
 * the function logs whether shutdown was normal, caused by an alert, or
 * caused by another TLS error.
 */
unsigned int tls_engine_current_state(struct tls_context *ctx) {
    unsigned int st = 0;
    size_t len;

    if (ctx->flagdelayedenc) {
        if (ctx->childclosed && !tls_engine_sendrec_buf(ctx, &len)) {
            st |= BR_SSL_CLOSED;
            log_d1("TCP closed normally, child closed the connection");
        }
        if (ctx->netclosed && !tls_engine_recvapp_buf(ctx, &len)) {
            st |= BR_SSL_CLOSED;
            log_d1("TCP closed normally, remote closed the connection");
        }
        if (tls_engine_sendrec_buf(ctx, &len) != 0) st |= BR_SSL_SENDREC;
        if (tls_engine_recvrec_buf(ctx, &len) != 0) st |= BR_SSL_RECVREC;
        if (tls_engine_sendapp_buf(ctx, &len) != 0) st |= BR_SSL_SENDAPP;
        if (tls_engine_recvapp_buf(ctx, &len) != 0) st |= BR_SSL_RECVAPP;
        goto ret;
    }
    else { st = br_ssl_engine_current_state(&ctx->cc.eng); }

    if (st & BR_SSL_CLOSED) {
        int err;
        err = br_ssl_engine_last_error(&ctx->cc.eng);
        if (err == BR_ERR_OK) { log_d1("SSL closed normally"); }
        else {
            if (err >= BR_ERR_SEND_FATAL_ALERT) {
                err -= BR_ERR_SEND_FATAL_ALERT;
                if (ctx->flaghandshakedone) {
                    log_e2("SSL closed abnormally, sent alert: ",
                           tls_error_str(err));
                }
                else {
                    log_d2("SSL closed abnormally, sent alert: ",
                           tls_error_str(err));
                }
            }
            else if (err >= BR_ERR_RECV_FATAL_ALERT) {
                err -= BR_ERR_RECV_FATAL_ALERT;
                if (ctx->flaghandshakedone) {
                    log_e2("SSL closed abnormally, received alert: ",
                           tls_error_str(err));
                }
                else {
                    log_d2("SSL closed abnormally, received alert: ",
                           tls_error_str(err));
                }
            }
            else {
                if (ctx->flaghandshakedone) {
                    log_e2("SSL closed abnormally: ", tls_error_str(err));
                }
                else { log_d2("SSL closed abnormally: ", tls_error_str(err)); }
            }
        }
    }
ret:
    log_t2("br_ssl_engine_current_state(&ctx->cc.eng) = ", log_num(st));
    return st;
}
