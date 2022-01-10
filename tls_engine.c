#include "writeall.h"
#include "log.h"
#include "tls.h"

/* sendapp */
unsigned char *tls_engine_sendapp_buf(struct tls_context *ctx, size_t *len) {
    if (ctx->flagdelayedenc) {
        if (ctx->childclosed) return 0;
        *len = sizeof ctx->tonetbuf - ctx->tonetbuflen;
        if (!*len) return 0;
        return ctx->tonetbuf + ctx->tonetbuflen;
    }
    return br_ssl_engine_sendapp_buf(&ctx->cc.eng, len);
}
void tls_engine_sendapp_ack(struct tls_context *ctx, size_t len) {
    if (ctx->flagdelayedenc) {
        ctx->tonetbuflen += len;
        return;
    }
    br_ssl_engine_sendapp_ack(&ctx->cc.eng, len);
}

/* recvapp */
unsigned char *tls_engine_recvapp_buf(struct tls_context *ctx, size_t *len) {
    if (ctx->flagdelayedenc) {
        if (ctx->childclosed) return 0;
        *len = ctx->tochildbuflen;
        if (!*len) return 0;
        return ctx->tochildbuf;
    }
    return br_ssl_engine_recvapp_buf(&ctx->cc.eng, len);
}
void tls_engine_recvapp_ack(struct tls_context *ctx, size_t len) {
    if (ctx->flagdelayedenc) {
        memmove(ctx->tochildbuf, ctx->tochildbuf + len,
                ctx->tochildbuflen - len);
        ctx->tochildbuflen -= len;
        return;
    }
    br_ssl_engine_recvapp_ack(&ctx->cc.eng, len);
}

/* sendrec */
unsigned char *tls_engine_sendrec_buf(struct tls_context *ctx, size_t *len) {
    if (ctx->flagdelayedenc) {
        if (ctx->netclosed) return 0;
        *len = ctx->tonetbuflen;
        if (!*len) return 0;
        return ctx->tonetbuf;
    }
    return br_ssl_engine_sendrec_buf(&ctx->cc.eng, len);
}
void tls_engine_sendrec_ack(struct tls_context *ctx, size_t len) {
    if (ctx->flagdelayedenc) {
        memmove(ctx->tonetbuf, ctx->tonetbuf + len, ctx->tonetbuflen - len);
        ctx->tonetbuflen -= len;
        return;
    }
    br_ssl_engine_sendrec_ack(&ctx->cc.eng, len);
}

/* recvrec */
unsigned char *tls_engine_recvrec_buf(struct tls_context *ctx, size_t *len) {
    if (ctx->flagdelayedenc) {
        if (ctx->netclosed) return 0;
        *len = sizeof ctx->tochildbuf - ctx->tochildbuflen;
        if (!*len) return 0;
        return ctx->tochildbuf + ctx->tochildbuflen;
    }
    return br_ssl_engine_recvrec_buf(&ctx->cc.eng, len);
}
void tls_engine_recvrec_ack(struct tls_context *ctx, size_t len) {
    if (ctx->flagdelayedenc) {
        ctx->tochildbuflen += len;
        return;
    }
    br_ssl_engine_recvrec_ack(&ctx->cc.eng, len);
}

/* sendapp5 */
unsigned char *tls_engine_sendapp5_buf(struct tls_context *ctx, size_t *len) {
    if (ctx->flagdelayedenc) {
        if (ctx->childclosed) return 0;
        *len = sizeof ctx->tonet5buf - ctx->tonet5buflen;
        if (!*len) return 0;
        return ctx->tonet5buf + ctx->tonet5buflen;
    }
    return 0;
}
void tls_engine_sendapp5_ack(struct tls_context *ctx, size_t len) {
    if (ctx->flagdelayedenc) {
        ctx->tonet5buflen += len;
        return;
    }
    return;
}

void tls_engine_flush(struct tls_context *ctx, int force) {
    if (ctx->flagdelayedenc) return;
    br_ssl_engine_flush(&ctx->cc.eng, force);
}

void tls_engine_close(struct tls_context *ctx) {
    if (ctx->flagdelayedenc) {
        ctx->childclosed = 1;
        return;
    }
    br_ssl_engine_close(&ctx->cc.eng);
}

int tls_engine_handshakedone(struct tls_context *ctx) {
    if (!ctx->flagdelayedenc) {
        unsigned int st = tls_engine_current_state(ctx);
        if ((st & BR_SSL_SENDAPP) && !ctx->flaghandshakedone) {
            ctx->flaghandshakedone = 1;
            return 1;
        }
    }
    return 0;
}

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
        return st;
    }
    else {
        st = br_ssl_engine_current_state(&ctx->cc.eng);
    }

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
                else {
                    log_d2("SSL closed abnormally: ", tls_error_str(err));
                }
            }
        }
    }
    return st;
}
