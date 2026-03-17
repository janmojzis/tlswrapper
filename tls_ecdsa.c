/*
 * tls_ecdsa.c - route ECDSA verification through the default EC backend
 *
 * This module adapts BearSSL's ECDSA verification entry point so X.509
 * verification keeps using the default EC implementation even when the
 * handshake EC hooks are replaced for keyjail operation.
 */

#include "tls.h"

/*
 * tls_ecdsa_vrfy_asn1 - verify an ASN.1 ECDSA signature
 *
 * @impl: requested EC implementation, ignored
 * @hash: message digest bytes
 * @hash_len: size of @hash in bytes
 * @pk: public key used for verification
 * @sig: ASN.1-encoded signature
 * @sig_len: size of @sig in bytes
 *
 * Verifies the signature with BearSSL's default EC implementation instead
 * of the caller-provided implementation.
 */
uint32_t tls_ecdsa_vrfy_asn1(const br_ec_impl *impl, const void *hash,
                             size_t hash_len, const br_ec_public_key *pk,
                             const void *sig, size_t sig_len) {
    br_ecdsa_vrfy vrfy = br_ecdsa_vrfy_asn1_get_default();
    (void) impl;

    return vrfy(br_ec_get_default(), hash, hash_len, pk, sig, sig_len);
}
