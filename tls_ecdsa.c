#include "tls.h"

uint32_t tls_ecdsa_vrfy_asn1(const br_ec_impl *impl, const void *hash,
                             size_t hash_len, const br_ec_public_key *pk,
                             const void *sig, size_t sig_len) {
    (void) impl;
    br_ecdsa_vrfy vrfy = br_ecdsa_vrfy_asn1_get_default();

    return vrfy(br_ec_get_default(), hash, hash_len, pk, sig, sig_len);
}
