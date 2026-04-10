/*
 * tls_engine.c - thin wrapper around the active TLS backend
 *
 * This module keeps the tlswrapper-facing TLS engine API small and focused
 * on the real TLS session. Plaintext STARTTLS staging now lives in
 * main_tlswrapper.c so the engine wrapper only forwards calls into BearSSL
 * and centralizes closed-state logging.
 */

#include "log.h"
#include "tls.h"

/*
 * tls_engine_sendapp_buf - return writable plaintext output space
 *
 * @ctx: TLS session state
 * @len: returns the available buffer length
 *
 * Returns a buffer where application data for the peer can be queued.
 * The storage comes directly from the BearSSL engine.
 *
 * Constraints:
 *   - ctx and len must be valid pointers
 *   - the returned buffer becomes invalid after the next engine call
 */
unsigned char *tls_engine_sendapp_buf(struct tls_context *ctx, size_t *len) {
    return br_ssl_engine_sendapp_buf(&ctx->cc.eng, len);
}

/*
 * tls_engine_sendapp_ack - publish plaintext bytes queued for sending
 *
 * @ctx: TLS session state
 * @len: number of bytes written into the sendapp buffer
 *
 * Commits application bytes previously obtained from
 * tls_engine_sendapp_buf().
 */
void tls_engine_sendapp_ack(struct tls_context *ctx, size_t len) {
    br_ssl_engine_sendapp_ack(&ctx->cc.eng, len);
}

/*
 * tls_engine_recvapp_buf - return readable plaintext input data
 *
 * @ctx: TLS session state
 * @len: returns the available buffer length
 *
 * Returns application data already decoded for the child side.
 */
unsigned char *tls_engine_recvapp_buf(struct tls_context *ctx, size_t *len) {
    return br_ssl_engine_recvapp_buf(&ctx->cc.eng, len);
}

/*
 * tls_engine_recvapp_ack - consume plaintext bytes delivered to the child
 *
 * @ctx: TLS session state
 * @len: number of bytes consumed from the recvapp buffer
 *
 * Acknowledges plaintext returned by tls_engine_recvapp_buf().
 */
void tls_engine_recvapp_ack(struct tls_context *ctx, size_t len) {
    br_ssl_engine_recvapp_ack(&ctx->cc.eng, len);
}

/*
 * tls_engine_sendrec_buf - return readable TLS records for the network
 *
 * @ctx: TLS session state
 * @len: returns the available buffer length
 *
 * Returns encoded TLS records ready to be written to the peer.
 */
unsigned char *tls_engine_sendrec_buf(struct tls_context *ctx, size_t *len) {
    return br_ssl_engine_sendrec_buf(&ctx->cc.eng, len);
}

/*
 * tls_engine_sendrec_ack - consume TLS records written to the network
 *
 * @ctx: TLS session state
 * @len: number of bytes consumed from the sendrec buffer
 *
 * Removes records previously returned by tls_engine_sendrec_buf().
 */
void tls_engine_sendrec_ack(struct tls_context *ctx, size_t len) {
    br_ssl_engine_sendrec_ack(&ctx->cc.eng, len);
}

/*
 * tls_engine_recvrec_buf - return writable space for incoming TLS records
 *
 * @ctx: TLS session state
 * @len: returns the available buffer length
 *
 * Returns storage for raw TLS records read from the peer.
 */
unsigned char *tls_engine_recvrec_buf(struct tls_context *ctx, size_t *len) {
    return br_ssl_engine_recvrec_buf(&ctx->cc.eng, len);
}

/*
 * tls_engine_recvrec_ack - publish newly received TLS record bytes
 *
 * @ctx: TLS session state
 * @len: number of bytes stored into the recvrec buffer
 *
 * Commits bytes written into the buffer returned by
 * tls_engine_recvrec_buf().
 */
void tls_engine_recvrec_ack(struct tls_context *ctx, size_t len) {
    br_ssl_engine_recvrec_ack(&ctx->cc.eng, len);
}

/*
 * tls_engine_flush - request record emission from the TLS engine
 *
 * @ctx: TLS session state
 * @force: non-zero to force emission of a partial record
 *
 * For active BearSSL sessions this forwards the flush request to the
 * engine.
 */
void tls_engine_flush(struct tls_context *ctx, int force) {
    br_ssl_engine_flush(&ctx->cc.eng, force);
}

/*
 * tls_engine_close - initiate an orderly TLS shutdown
 *
 * @ctx: TLS session state
 *
 * Starts connection closure inside the TLS engine.
 */
void tls_engine_close(struct tls_context *ctx) {
    br_ssl_engine_close(&ctx->cc.eng);
}

/*
 * tls_engine_current_state - compute backend-independent readiness flags
 *
 * @ctx: TLS session state
 *
 * Queries the BearSSL engine and translates its flags into the
 * backend-independent tls_state_* constants defined in tls.h.
 * When the connection reaches a closed state, the function logs
 * whether shutdown was normal, caused by an alert, or caused by
 * another TLS error.
 */
unsigned int tls_engine_current_state(struct tls_context *ctx) {
    static unsigned int prev_st = ~0u;
    unsigned int st;

    st = br_ssl_engine_current_state(&ctx->cc.eng);

    if (log_level >= log_level_TRACING && st != prev_st) {
        const char *recvrec = "recvrec,";
        const char *sendrec = "sendrec,";
        const char *recvapp = "recvapp,";
        const char *sendapp = "sendapp,";
        const char *closed = "closed";
        if (!(st & tls_state_RECVREC)) recvrec = "";
        if (!(st & tls_state_SENDREC)) sendrec = "";
        if (!(st & tls_state_RECVAPP)) recvapp = "";
        if (!(st & tls_state_SENDAPP)) sendapp = "";
        if (!(st & tls_state_CLOSED)) closed = "";
        log_t8("tls state=", log_num(st), ", flags=", recvrec, sendrec, recvapp,
               sendapp, closed);
        prev_st = st;
    }

    return st;
}

/*
 * tls_engine_close_reason - describe why the SSL engine closed
 *
 * @ctx: TLS session state
 *
 * Returns a static string describing the SSL close reason.  The caller
 * must only invoke this after tls_engine_current_state() returned the
 * CLOSED flag.  When the close was abnormal after a completed handshake
 * the function also emits a log_e line; otherwise only the returned
 * string carries the detail so the caller can place it into a summary.
 */
const char *tls_engine_close_reason(struct tls_context *ctx) {
    int err = br_ssl_engine_last_error(&ctx->cc.eng);

    if (err == BR_ERR_OK) return "TLS closed normally";

    if (err >= BR_ERR_SEND_FATAL_ALERT) {
        int alert = err - BR_ERR_SEND_FATAL_ALERT;
        if (ctx->flaghandshakedone) {
            log_e2("TLS sent alert: ", tls_alert_str(alert));
        }
        return tls_alert_str(alert);
    }
    if (err >= BR_ERR_RECV_FATAL_ALERT) {
        int alert = err - BR_ERR_RECV_FATAL_ALERT;
        if (ctx->flaghandshakedone) {
            log_e2("TLS received alert: ", tls_alert_str(alert));
        }
        return tls_alert_str(alert);
    }
    if (ctx->flaghandshakedone) { log_e2("TLS error: ", tls_error_str(err)); }
    return tls_error_str(err);
}

/*
 * tls_engine_get_version - return negotiated TLS version
 */
unsigned int tls_engine_get_version(struct tls_context *ctx) {
    return br_ssl_engine_get_version(&ctx->cc.eng);
}

/*
 * tls_engine_get_cipher - return negotiated cipher suite identifier
 */
uint16_t tls_engine_get_cipher(struct tls_context *ctx) {
    return ctx->cc.eng.session.cipher_suite;
}

/*
 * tls_engine_get_ecdhe_curve - return negotiated ECDHE curve
 */
unsigned char tls_engine_get_ecdhe_curve(struct tls_context *ctx) {
    return br_ssl_engine_get_ecdhe_curve(&ctx->cc.eng);
}

/*
 * tls_engine_get_server_name - return SNI server name from the client
 */
const char *tls_engine_get_server_name(struct tls_context *ctx) {
    return br_ssl_engine_get_server_name(&ctx->cc.eng);
}

/*
 * tls_engine_last_error - return the last engine error code
 */
int tls_engine_last_error(struct tls_context *ctx) {
    return br_ssl_engine_last_error(&ctx->cc.eng);
}

/*
 * tls_pipe_set_engine - set the pipe engine pointer from a tls_context
 */
void tls_pipe_set_engine(struct tls_context *ctx) {
    tls_pipe_eng = &ctx->cc.eng;
}
