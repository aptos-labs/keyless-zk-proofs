pragma circom 2.2.2;

include "keyless.circom";

component main { public [public_inputs_hash] } = keyless(
    /* JWT */
    192*8,      // MAX_B64U_JWT_NO_SIG_LEN
    300,        // MAX_B64U_JWT_HEADER_W_DOT_LEN
    192*8-64,   // MAX_B64U_JWT_PAYLOAD_SHA2_PADDED_LEN
    /* aud field */
    140,        // MAX_AUD_KV_PAIR_LEN
    40,         // MAX_AUD_NAME_LEN
    120,        // MAX_AUD_VALUE_LEN
    /* iss field */
    140,        // MAX_ISS_KV_PAIR_LEN
    40,         // MAX_ISS_NAME_LEN
    120,        // MAX_ISS_VALUE_LEN
    /* iat field */
    50,         // MAX_IAT_KV_PAIR_LEN
    10,         // MAX_IAT_NAME_LEN
    45,         // MAX_IAT_VALUE_LEN
    /* nonce field */
    105,        // MAX_NONCE_KV_PAIR_LEN
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
    350         // MAX_EXTRA_FIELD_KV_PAIR_LEN
);
