#include "tls.h"

unsigned char *tls_engine_sendapp_buf(struct tls_context *ctx, size_t *len) {
    return br_ssl_engine_sendapp_buf(&ctx->cc.eng, len);
}

unsigned char *tls_engine_recvapp_buf(struct tls_context *ctx, size_t *len) {
    return br_ssl_engine_recvapp_buf(&ctx->cc.eng, len);
}

unsigned char *tls_engine_sendrec_buf(struct tls_context *ctx, size_t *len) {
    return br_ssl_engine_sendrec_buf(&ctx->cc.eng, len);
}

unsigned char *tls_engine_recvrec_buf(struct tls_context *ctx, size_t *len) {
    return br_ssl_engine_recvrec_buf(&ctx->cc.eng, len);
}

void tls_engine_sendapp_ack(struct tls_context *ctx, size_t len) {
    br_ssl_engine_sendapp_ack(&ctx->cc.eng, len);
}

void tls_engine_recvapp_ack(struct tls_context *ctx, size_t len) {
    br_ssl_engine_recvapp_ack(&ctx->cc.eng, len);
}

void tls_engine_sendrec_ack(struct tls_context *ctx, size_t len) {
    br_ssl_engine_sendrec_ack(&ctx->cc.eng, len);
}

void tls_engine_recvrec_ack(struct tls_context *ctx, size_t len) {
    br_ssl_engine_recvrec_ack(&ctx->cc.eng, len);
}

void tls_engine_flush(struct tls_context *ctx, int force) {
    br_ssl_engine_flush(&ctx->cc.eng, force);
}

void tls_engine_close(struct tls_context *ctx) {
    br_ssl_engine_close(&ctx->cc.eng);
}
