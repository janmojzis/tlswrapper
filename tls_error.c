#include "tls.h"

static struct {
    int err;
    const char *comment;
} errors[] = {
    {
        BR_ERR_BAD_PARAM,
        "Caller-provided parameter is incorrect."
    }, {
        BR_ERR_BAD_STATE,
        "Operation requested by the caller cannot be applied with"
        " the current context state (e.g. reading data while"
        " outgoing data is waiting to be sent)."
    }, {
        BR_ERR_UNSUPPORTED_VERSION,
        "Incoming protocol or record version is unsupported."
    }, {
        BR_ERR_BAD_VERSION,
        "Incoming record version does not match the expected version."
    }, {
        BR_ERR_BAD_LENGTH,
        "Incoming record length is invalid."
    }, {
        BR_ERR_TOO_LARGE,
        "Incoming record is too large to be processed, or buffer"
        " is too small for the handshake message to send."
    }, {
        BR_ERR_BAD_MAC,
        "Decryption found an invalid padding, or the record MAC is"
        " not correct."
    }, {
        BR_ERR_NO_RANDOM,
        "No initial entropy was provided, and none can be obtained"
        " from the OS."
    }, {
        BR_ERR_UNKNOWN_TYPE,
        "Incoming record type is unknown."
    }, {
        BR_ERR_UNEXPECTED,
        "Incoming record or message has wrong type with regards to"
        " the current engine state."
    }, {
        BR_ERR_BAD_CCS,
        "ChangeCipherSpec message from the peer has invalid contents."
    }, {
        BR_ERR_BAD_ALERT,
        "Alert message from the peer has invalid contents"
        " (odd length)."
    }, {
        BR_ERR_BAD_HANDSHAKE,
        "Incoming handshake message decoding failed."
    }, {
        BR_ERR_OVERSIZED_ID,
        "ServerHello contains a session ID which is larger than"
        " 32 bytes."
    }, {
        BR_ERR_BAD_CIPHER_SUITE,
        "Server wants to use a cipher suite that we did not claim"
        " to support. This is also reported if we tried to advertise"
        " a cipher suite that we do not support."
    }, {
        BR_ERR_BAD_COMPRESSION,
        "Server wants to use a compression that we did not claim"
        " to support."
    }, {
        BR_ERR_BAD_FRAGLEN,
        "Server's max fragment length does not match client's."
    }, {
        BR_ERR_BAD_SECRENEG,
        "Secure renegotiation failed."
    }, {
        BR_ERR_EXTRA_EXTENSION,
        "Server sent an extension type that we did not announce,"
        " or used the same extension type several times in a"
        " single ServerHello."
    }, {
        BR_ERR_BAD_SNI,
        "Invalid Server Name Indication contents (when used by"
        " the server, this extension shall be empty)."
    }, {
        BR_ERR_BAD_HELLO_DONE,
        "Invalid ServerHelloDone from the server (length is not 0)."
    }, {
        BR_ERR_LIMIT_EXCEEDED,
        "Internal limit exceeded (e.g. server's public key is too"
        " large)."
    }, {
        BR_ERR_BAD_FINISHED,
        "Finished message from peer does not match the expected"
        " value."
    }, {
        BR_ERR_RESUME_MISMATCH,
        "Session resumption attempt with distinct version or cipher"
        " suite."
    }, {
        BR_ERR_INVALID_ALGORITHM,
        "Unsupported or invalid algorithm (ECDHE curve, signature"
        " algorithm, hash function)."
    }, {
        BR_ERR_BAD_SIGNATURE,
        "Invalid signature in ServerKeyExchange or"
        " CertificateVerify message."
    }, {
        BR_ERR_WRONG_KEY_USAGE,
        "Peer's public key does not have the proper type or is"
        " not allowed for the requested operation."
    }, {
        BR_ERR_NO_CLIENT_AUTH,
        "Client did not send a certificate upon request, or the"
        " client certificate could not be validated."
    }, {
        BR_ERR_IO,
        "I/O error or premature close on transport stream."
    }, {
        BR_ERR_X509_INVALID_VALUE,
        "Invalid value in an ASN.1 structure."
    },
    {
        BR_ERR_X509_TRUNCATED,
        "Truncated certificate or other ASN.1 object."
    },
    {
        BR_ERR_X509_EMPTY_CHAIN,
        "Empty certificate chain (no certificate at all)."
    },
    {
        BR_ERR_X509_INNER_TRUNC,
        "Decoding error: inner element extends beyond outer element"
        " size."
    },
    {
        BR_ERR_X509_BAD_TAG_CLASS,
        "Decoding error: unsupported tag class (application or"
        " private)."
    },
    {
        BR_ERR_X509_BAD_TAG_VALUE,
        "Decoding error: unsupported tag value."
    },
    {
        BR_ERR_X509_INDEFINITE_LENGTH,
        "Decoding error: indefinite length."
    },
    {
        BR_ERR_X509_EXTRA_ELEMENT,
        "Decoding error: extraneous element."
    },
    {
        BR_ERR_X509_UNEXPECTED,
        "Decoding error: unexpected element."
    },
    {
        BR_ERR_X509_NOT_CONSTRUCTED,
        "Decoding error: expected constructed element, but is"
        " primitive."
    },
    {
        BR_ERR_X509_NOT_PRIMITIVE,
        "Decoding error: expected primitive element, but is"
        " constructed."
    },
    {
        BR_ERR_X509_PARTIAL_BYTE,
        "Decoding error: BIT STRING length is not multiple of 8."
    },
    {
        BR_ERR_X509_BAD_BOOLEAN,
        "Decoding error: BOOLEAN value has invalid length."
    },
    {
        BR_ERR_X509_OVERFLOW,
        "Decoding error: value is off-limits."
    },
    {
        BR_ERR_X509_BAD_DN,
        "Invalid distinguished name."
    },
    {
        BR_ERR_X509_BAD_TIME,
        "Invalid date/time representation."
    },
    {
        BR_ERR_X509_UNSUPPORTED,
        "Certificate contains unsupported features that cannot be"
        " ignored."
    },
    {
        BR_ERR_X509_LIMIT_EXCEEDED,
        "Key or signature size exceeds internal limits."
    },
    {
        BR_ERR_X509_WRONG_KEY_TYPE,
        "Key type does not match that which was expected."
    },
    {
        BR_ERR_X509_BAD_SIGNATURE,
        "Signature is invalid."
    },
    {
        BR_ERR_X509_TIME_UNKNOWN,
        "Validation time is unknown."
    },
    {
        BR_ERR_X509_EXPIRED,
        "Certificate is expired or not yet valid."
    },
    {
        BR_ERR_X509_DN_MISMATCH,
        "Issuer/Subject DN mismatch in the chain."
    },
    {
        BR_ERR_X509_BAD_SERVER_NAME,
        "Expected server name was not found in the chain."
    },
    {
        BR_ERR_X509_CRITICAL_EXTENSION,
        "Unknown critical extension in certificate."
    },
    {
        BR_ERR_X509_NOT_CA,
        "Not a CA, or path length constraint violation."
    },
    {
        BR_ERR_X509_FORBIDDEN_KEY_USAGE,
        "Key Usage extension prohibits intended usage."
    },
    {
        BR_ERR_X509_WEAK_PUBLIC_KEY,
        "Public key found in certificate is too small."
    },
    {
        BR_ERR_X509_NOT_TRUSTED,
        "Chain could not be linked to a trust anchor."
    },
    { 0, 0 }
};

const char *tls_error_str(int err) {

    size_t u;

    for (u = 0; errors[u].comment; ++u) {
        if (errors[u].err == err) {
            return errors[u].comment;
        }
    }
    return "unknown";
}
