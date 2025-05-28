pragma circom 2.2.2;

include "keyless.circom";

component main { public [public_inputs_hash] } = keyless(
    /* JWT */
    192*8,      // MAX_B64U_JWT_NO_SIG_LEN
    300,        // MAX_B64U_JWT_HEADER_W_DOT_LEN
    192*8-64,   // MAX_B64U_JWT_PAYLOAD_SHA2_PADDED_LEN
    /* aud field */
    140,        // maxAudKVPairLen
    40,         // maxAudNameLen
    120,        // maxAudValueLen
    /* iss field */
    140,        // maxIssKVPairLen
    40,         // maxIssNameLen
    120,        // maxIssValueLen
    /* iat field */
    50,         // maxIatKVPairLen
    10,         // maxIatNameLen
    45,         // maxIatValueLen
    /* nonce field */
    105,        // maxNonceKVPairLen
    10,         // maxNonceNameLen
    100,        // maxNonceValueLen
    /* email_verified field */
    30,         // maxEVKVPairLen
    20,         // maxEVNameLen
    10,         // maxEVValueLen
    /* the user ID field (i.e., sub or email) */
    350,        // maxUIDKVPairLen
    30,         // maxUIDNameLen
    330,        // maxUIDValueLen
    /* any extra field (e.g., the name field) */
    350         // maxEFKVPairLen
);
