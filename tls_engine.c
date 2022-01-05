#include "tls.h"
#include "log.h"

unsigned char tochildbuf[1024];
size_t tochildbuflen = 0;
unsigned char tonetbuf[1024];
size_t tonetbuflen = 0;

/* sendapp */
unsigned char *tls_engine_sendapp_buf(struct tls_context *ctx, size_t *len) {
    if (ctx->flagdelayedencryption) {
        *len = sizeof tonetbuf - tonetbuflen;
        if (!*len) return 0;
        return tonetbuf + tonetbuflen;
    }
    return br_ssl_engine_sendapp_buf(&ctx->cc.eng, len);
}
void tls_engine_sendapp_ack(struct tls_context *ctx, size_t len) {
    if (ctx->flagdelayedencryption) {
        tonetbuflen += len;
        return;
    }
    br_ssl_engine_sendapp_ack(&ctx->cc.eng, len);
}

/* recvapp */
unsigned char *tls_engine_recvapp_buf(struct tls_context *ctx, size_t *len) {
    if (ctx->flagdelayedencryption) {
        *len = tochildbuflen;
        if (!*len) return 0;
        return tochildbuf;
    }
    return br_ssl_engine_recvapp_buf(&ctx->cc.eng, len);
}
void tls_engine_recvapp_ack(struct tls_context *ctx, size_t len) {
    if (ctx->flagdelayedencryption) {
        memmove(tochildbuf, tochildbuf + len, tochildbuflen - len);
        tochildbuflen -= len;
        return;
    }
    br_ssl_engine_recvapp_ack(&ctx->cc.eng, len);
}

/* sendrec */
unsigned char *tls_engine_sendrec_buf(struct tls_context *ctx, size_t *len) {
    if (ctx->flagdelayedencryption) {
        *len = tonetbuflen;
        if (!*len) return 0;
        return tonetbuf;
    }
    return br_ssl_engine_sendrec_buf(&ctx->cc.eng, len);
}
void tls_engine_sendrec_ack(struct tls_context *ctx, size_t len) {
    if (ctx->flagdelayedencryption) {
        memmove(tonetbuf, tonetbuf + len, tonetbuflen - len);
        tonetbuflen -= len;
    }
    br_ssl_engine_sendrec_ack(&ctx->cc.eng, len);
}

/* recvrec */
unsigned char *tls_engine_recvrec_buf(struct tls_context *ctx, size_t *len) {
    if (ctx->flagdelayedencryption) {
        *len = sizeof tochildbuf - tochildbuflen;
        if (!*len) return 0;
        return tochildbuf + tochildbuflen;
    }
    return br_ssl_engine_recvrec_buf(&ctx->cc.eng, len);
}
void tls_engine_recvrec_ack(struct tls_context *ctx, size_t len) {
    if (ctx->flagdelayedencryption) {
        tochildbuflen += len;
        return;
    }
    br_ssl_engine_recvrec_ack(&ctx->cc.eng, len);
}

void tls_engine_flush(struct tls_context *ctx, int force) {
    if (ctx->flagdelayedencryption) {
        return;
    }
    br_ssl_engine_flush(&ctx->cc.eng, force);
}

void tls_engine_close(struct tls_context *ctx) {
    if (ctx->flagdelayedencryption) {
        return;
    }
    br_ssl_engine_close(&ctx->cc.eng);
}

unsigned int tls_engine_current_state(struct tls_context *ctx) {
    if (ctx->flagdelayedencryption) {
        unsigned int s = 0;
        size_t len;
        if (tls_engine_sendrec_buf(ctx, &len) != 0) {
            s |= BR_SSL_SENDREC;
        }
        if (tls_engine_recvrec_buf(ctx, &len) != 0) {
            s |= BR_SSL_RECVREC;
        }
        if (tls_engine_sendapp_buf(ctx, &len) != 0) {
            s |= BR_SSL_SENDAPP;
        }
        if (tls_engine_recvapp_buf(ctx, &len) != 0) {
            s |= BR_SSL_RECVAPP;
        }
        return s;
    }
    return br_ssl_engine_current_state(&ctx->cc.eng);
}

int tls_engine_handshakedone(struct tls_context *ctx) {
    if (!ctx->flagdelayedencryption) {
        unsigned int st = tls_engine_current_state(ctx);
        if ((st & BR_SSL_SENDAPP) && !ctx->flaghandshakedone) {
            ctx->flaghandshakedone = 1;
            return 1;
        }
    }
    return 0;
}
