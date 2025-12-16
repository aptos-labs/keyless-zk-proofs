pragma circom 2.2.2;

include "keyless.circom";
include "helpers/base64url/Base64UrlDecode.circom";
include "helpers/base64url/Base64UrlDecodedLength.circom";
include "helpers/jwt/StringBodies.circom";

template keyless_sanitizer(
    MAX_B64U_JWT_NO_SIG_LEN,               // ...full base64url JWT without the signature, but with SHA2 padding
    MAX_B64U_JWT_HEADER_W_DOT_LEN,         // ...full base64url JWT header with a dot at the end
    MAX_B64U_JWT_PAYLOAD_SHA2_PADDED_LEN,  // ...full base64url JWT payload with SHA2 padding
    MAX_AUD_KV_PAIR_LEN,                   // ...ASCII aud field
    MAX_AUD_NAME_LEN,                      // ...ASCII aud name
    MAX_AUD_VALUE_LEN,                     // ...ASCII aud value
    MAX_ISS_KV_PAIR_LEN,                   // ...ASCII iss field
    MAX_ISS_NAME_LEN,                      // ...ASCII iss name
    MAX_ISS_VALUE_LEN,                     // ...ASCII iss value
    MAX_IAT_KV_PAIR_LEN,                   // ...ASCII iat field
    MAX_IAT_NAME_LEN,                      // ...ASCII iat name
    MAX_IAT_VALUE_LEN,                     // ...ASCII iat value
    MAX_NONCE_KV_PAIR_LEN,                 // ...ASCII nonce field
    MAX_NONCE_NAME_LEN,                    // ...ASCII nonce name
    MAX_NONCE_VALUE_LEN,                   // ...ASCII nonce value
    MAX_EMAIL_VERIFIED_KV_PAIR_LEN,        // ...ASCII email verified field
    MAX_EMAIL_VERIFIED_NAME_LEN,           // ...ASCII email verified name
    MAX_EMAIL_VERIFIED_VALUE_LEN,          // ...ASCII email verified value
    MAX_UID_KV_PAIR_LEN,                   // ...ASCII uid field
    MAX_UID_NAME_LEN,                      // ...ASCII uid name
    MAX_UID_VALUE_LEN,                     // ...ASCII uid value
    MAX_EXTRA_FIELD_KV_PAIR_LEN            // ...ASCII extra field
) {
    signal input b64u_jwt_no_sig_sha2_padded[MAX_B64U_JWT_NO_SIG_LEN]; // base64url format
    signal input b64u_jwt_header_w_dot[MAX_B64U_JWT_HEADER_W_DOT_LEN];
    signal input b64u_jwt_header_w_dot_len;
    signal input b64u_jwt_payload_sha2_padded[MAX_B64U_JWT_PAYLOAD_SHA2_PADDED_LEN];
    signal input b64u_jwt_payload_sha2_padded_len;
    // TODO: Is this correct? Shouldn't this be smaller by ~512 bits?
    signal input b64u_jwt_payload[MAX_B64U_JWT_PAYLOAD_SHA2_PADDED_LEN];

    signal input sha2_num_blocks;
    signal input sha2_num_bits[8];
    signal input sha2_padding[64];

    // Note: The RSA-2048 signature verification circuit only supports 64-bit limbs => 2048/64 = 32 of them
    var SIGNATURE_NUM_LIMBS = 32;
    signal input signature[SIGNATURE_NUM_LIMBS];
    signal input pubkey_modulus[SIGNATURE_NUM_LIMBS];

    signal input aud_field[MAX_AUD_KV_PAIR_LEN]; // ASCII
    signal input aud_field_string_bodies[MAX_AUD_KV_PAIR_LEN]; // ASCII
    signal input aud_field_len; // ASCII
    signal input aud_index; // index of aud field in JWT payload
    signal input aud_value_index;
    signal input aud_colon_index;
    signal input aud_name[MAX_AUD_NAME_LEN];
    signal input use_aud_override;
    signal input private_aud_value[MAX_AUD_VALUE_LEN];
    signal input override_aud_value[MAX_AUD_VALUE_LEN];
    signal input private_aud_value_len;
    signal input override_aud_value_len;
    signal input skip_aud_checks;

    signal input uid_field[MAX_UID_KV_PAIR_LEN];
    signal input uid_field_string_bodies[MAX_UID_KV_PAIR_LEN];
    signal input uid_field_len;
    signal input uid_index;
    signal input uid_name_len;
    signal input uid_value_index;
    signal input uid_value_len;
    signal input uid_colon_index;
    signal input uid_name[MAX_UID_NAME_LEN];
    signal input uid_value[MAX_UID_VALUE_LEN];

    signal input extra_field[MAX_EXTRA_FIELD_KV_PAIR_LEN];
    signal input extra_field_len;
    signal input extra_index;
    signal input use_extra_field;

    signal input ev_field[MAX_EMAIL_VERIFIED_KV_PAIR_LEN];
    signal input ev_field_len;
    signal input ev_index;
    signal input ev_value_index;
    signal input ev_value_len;
    signal input ev_colon_index;
    signal input ev_name[MAX_EMAIL_VERIFIED_NAME_LEN];
    signal input ev_value[MAX_EMAIL_VERIFIED_VALUE_LEN];

    signal input iss_field[MAX_ISS_KV_PAIR_LEN];
    signal input iss_field_string_bodies[MAX_ISS_KV_PAIR_LEN];
    signal input iss_field_len;
    signal input iss_index;
    signal input iss_value_index;
    signal input iss_value_len;
    signal input iss_colon_index;
    signal input iss_name[MAX_ISS_NAME_LEN];
    signal input iss_value[MAX_ISS_VALUE_LEN];

    signal input iat_field[MAX_IAT_KV_PAIR_LEN];
    signal input iat_field_len;
    signal input iat_index;
    signal input iat_value_index;
    signal input iat_value_len;
    signal input iat_colon_index;
    signal input iat_name[MAX_IAT_NAME_LEN];
    signal input iat_value[MAX_IAT_VALUE_LEN];

    signal input exp_date;
    signal input exp_horizon;

    signal input nonce_field[MAX_NONCE_KV_PAIR_LEN];
    signal input nonce_field_string_bodies[MAX_NONCE_KV_PAIR_LEN];
    signal input nonce_field_len;
    signal input nonce_index;
    signal input nonce_value_index;
    signal input nonce_value_len;
    signal input nonce_colon_index;
    signal input nonce_name[MAX_NONCE_NAME_LEN];
    signal input nonce_value[MAX_NONCE_VALUE_LEN];

    signal input epk[3];
    signal input epk_len;
    signal input epk_blinder;
    signal input pepper;

    signal input public_inputs_hash;

    //
    // Sanitizing inputs & tagging them
    //

    // TODO(Soundness): Assert this property holds
    signal {maxbits} b64u_jwt_no_sig_sha2_padded_tagged[MAX_B64U_JWT_NO_SIG_LEN];
    b64u_jwt_no_sig_sha2_padded_tagged.maxbits = 8;
    b64u_jwt_no_sig_sha2_padded_tagged <== b64u_jwt_no_sig_sha2_padded;

    // TODO(Soundness): Assert this property holds
    signal {maxbits} b64u_jwt_header_w_dot_tagged[MAX_B64U_JWT_HEADER_W_DOT_LEN];
    b64u_jwt_header_w_dot_tagged.maxbits = 8;
    b64u_jwt_header_w_dot_tagged <== b64u_jwt_header_w_dot;

    // TODO(Soundness): Assert this property holds
    signal {maxbits} b64u_jwt_payload_sha2_padded_tagged[MAX_B64U_JWT_PAYLOAD_SHA2_PADDED_LEN];
    b64u_jwt_payload_sha2_padded_tagged.maxbits = 8;
    b64u_jwt_payload_sha2_padded_tagged <== b64u_jwt_payload_sha2_padded;

    // TODO(Soundness): Assert this property holds
    signal {maxbits} b64u_jwt_payload_tagged[MAX_B64U_JWT_PAYLOAD_SHA2_PADDED_LEN];
    b64u_jwt_payload_tagged.maxbits = 8;
    b64u_jwt_payload_tagged <== b64u_jwt_payload;

    // TODO(Soundness): Assert this property holds
    signal {maxbits} sha2_num_bits_tagged[8];
    sha2_num_bits_tagged.maxbits = 8;
    sha2_num_bits_tagged <== sha2_num_bits;

    // TODO(Soundness): Assert this property holds
    signal {maxbits} sha2_padding_tagged[64];
    sha2_padding_tagged.maxbits = 8;
    sha2_padding_tagged <== sha2_padding;

    AssertIs64BitLimbs(SIGNATURE_NUM_LIMBS)(pubkey_modulus);
    signal {maxbits} pubkey_modulus_tagged[SIGNATURE_NUM_LIMBS];
    pubkey_modulus_tagged.maxbits = 64;
    pubkey_modulus_tagged <== pubkey_modulus;

    // TODO(Soundness): Assert this property holds
    signal {maxbits} aud_field_tagged[MAX_AUD_KV_PAIR_LEN];
    aud_field_tagged.maxbits = 8;
    aud_field_tagged <== aud_field;

    // TODO(Soundness): Assert this property holds
    signal {maxbits} aud_field_string_bodies_tagged[MAX_AUD_KV_PAIR_LEN];
    aud_field_string_bodies_tagged.maxbits = 1;
    aud_field_string_bodies_tagged <== aud_field_string_bodies;

    // TODO(Soundness): Assert this property holds
    signal {maxbits} aud_name_tagged[MAX_AUD_NAME_LEN];
    aud_name_tagged.maxbits = 8;
    aud_name_tagged <== aud_name;

    // TODO(Soundness): Assert this property holds
    signal {maxbits} private_aud_value_tagged[MAX_AUD_VALUE_LEN];
    private_aud_value_tagged.maxbits = 8;
    private_aud_value_tagged <== private_aud_value;

    // TODO(Soundness): Assert this property holds
    signal {maxbits} override_aud_value_tagged[MAX_AUD_VALUE_LEN];
    override_aud_value_tagged.maxbits = 8;
    override_aud_value_tagged <== override_aud_value;

    // TODO(Soundness): Assert this property holds
    signal {maxbits} uid_field_tagged[MAX_UID_KV_PAIR_LEN];
    uid_field_tagged.maxbits = 8;
    uid_field_tagged <== uid_field;

    // TODO(Soundness): Assert this property holds
    signal {maxbits} uid_field_string_bodies_tagged[MAX_UID_KV_PAIR_LEN];
    uid_field_string_bodies_tagged.maxbits = 1;
    uid_field_string_bodies_tagged <== uid_field_string_bodies;

    // TODO(Soundness): Assert this property holds
    signal {maxbits} uid_name_tagged[MAX_UID_NAME_LEN];
    uid_name_tagged.maxbits = 8;
    uid_name_tagged <== uid_name;

    // TODO(Soundness): Assert this property holds
    signal {maxbits} uid_value_tagged[MAX_UID_VALUE_LEN];
    uid_value_tagged.maxbits = 8;
    uid_value_tagged <== uid_value;

    // TODO(Soundness): Assert this property holds
    signal {maxbits} extra_field_tagged[MAX_EXTRA_FIELD_KV_PAIR_LEN];
    extra_field_tagged.maxbits = 8;
    extra_field_tagged <== extra_field;

    // TODO(Soundness): Assert this property holds
    signal {maxbits} ev_field_tagged[MAX_EMAIL_VERIFIED_KV_PAIR_LEN];
    ev_field_tagged.maxbits = 8;
    ev_field_tagged <== ev_field;

    // TODO(Soundness): Assert this property holds
    signal {maxbits} ev_name_tagged[MAX_EMAIL_VERIFIED_NAME_LEN];
    ev_name_tagged.maxbits = 8;
    ev_name_tagged <== ev_name;

    // TODO(Soundness): Assert this property holds
    signal {maxbits} ev_value_tagged[MAX_EMAIL_VERIFIED_VALUE_LEN];
    ev_value_tagged.maxbits = 8;
    ev_value_tagged <== ev_value;

    // TODO(Soundness): Assert this property holds
    signal {maxbits} iss_field_tagged[MAX_ISS_KV_PAIR_LEN];
    iss_field_tagged.maxbits = 8;
    iss_field_tagged <== iss_field;

    // TODO(Soundness): Assert this property holds
    signal {maxbits} iss_field_string_bodies_tagged[MAX_ISS_KV_PAIR_LEN];
    iss_field_string_bodies_tagged.maxbits = 1;
    iss_field_string_bodies_tagged <== iss_field_string_bodies;

    // TODO(Soundness): Assert this property holds
    signal {maxbits} iss_name_tagged[MAX_ISS_NAME_LEN];
    iss_name_tagged.maxbits = 8;
    iss_name_tagged <== iss_name;

    // TODO(Soundness): Assert this property holds
    signal {maxbits} iss_value_tagged[MAX_ISS_VALUE_LEN];
    iss_value_tagged.maxbits = 8;
    iss_value_tagged <== iss_value;

    // TODO(Soundness): Assert this property holds
    signal {maxbits} iat_field_tagged[MAX_IAT_KV_PAIR_LEN];
    iat_field_tagged.maxbits = 8;
    iat_field_tagged <== iat_field;

    // TODO(Soundness): Assert this property holds
    signal {maxbits} iat_name_tagged[MAX_IAT_NAME_LEN];
    iat_name_tagged.maxbits = 8;
    iat_name_tagged <== iat_name;

    // TODO(Soundness): Assert this property holds
    signal {maxbits} iat_value_tagged[MAX_IAT_VALUE_LEN];
    iat_value_tagged.maxbits = 8;
    iat_value_tagged <== iat_value;

    // TODO(Soundness): Assert this property holds
    signal {maxbits} nonce_field_tagged[MAX_NONCE_KV_PAIR_LEN];
    nonce_field_tagged.maxbits = 8;
    nonce_field_tagged <== nonce_field;

    // TODO(Soundness): Assert this property holds
    signal {maxbits} nonce_field_string_bodies_tagged[MAX_NONCE_KV_PAIR_LEN];
    nonce_field_string_bodies_tagged.maxbits = 1;
    nonce_field_string_bodies_tagged <== nonce_field_string_bodies;

    // TODO(Soundness): Assert this property holds
    signal {maxbits} nonce_name_tagged[MAX_NONCE_NAME_LEN];
    nonce_name_tagged.maxbits = 8;
    nonce_name_tagged <== nonce_name;

    // TODO(Soundness): Assert this property holds
    signal {maxbits} nonce_value_tagged[MAX_NONCE_VALUE_LEN];
    nonce_value_tagged.maxbits = 8;
    nonce_value_tagged <== nonce_value;

    keyless(
        MAX_B64U_JWT_NO_SIG_LEN,
        MAX_B64U_JWT_HEADER_W_DOT_LEN,
        MAX_B64U_JWT_PAYLOAD_SHA2_PADDED_LEN,
        //
        MAX_AUD_KV_PAIR_LEN,
        MAX_AUD_NAME_LEN,
        MAX_AUD_VALUE_LEN,
        //
        MAX_ISS_KV_PAIR_LEN,
        MAX_ISS_NAME_LEN,
        MAX_ISS_VALUE_LEN,
        //
        MAX_IAT_KV_PAIR_LEN,
        MAX_IAT_NAME_LEN,
        MAX_IAT_VALUE_LEN,
        //
        MAX_NONCE_KV_PAIR_LEN,
        MAX_NONCE_NAME_LEN,
        MAX_NONCE_VALUE_LEN,
        //
        MAX_EMAIL_VERIFIED_KV_PAIR_LEN,
        MAX_EMAIL_VERIFIED_NAME_LEN,
        MAX_EMAIL_VERIFIED_VALUE_LEN,
        //
        MAX_UID_KV_PAIR_LEN,
        MAX_UID_NAME_LEN,
        MAX_UID_VALUE_LEN,
        //
        MAX_EXTRA_FIELD_KV_PAIR_LEN,
        //
        SIGNATURE_NUM_LIMBS
    )(
        b64u_jwt_no_sig_sha2_padded <== b64u_jwt_no_sig_sha2_padded_tagged,
        b64u_jwt_header_w_dot <== b64u_jwt_header_w_dot_tagged,
        b64u_jwt_header_w_dot_len <== b64u_jwt_header_w_dot_len,
        b64u_jwt_payload_sha2_padded <== b64u_jwt_payload_sha2_padded_tagged,
        b64u_jwt_payload_sha2_padded_len <== b64u_jwt_payload_sha2_padded_len,
        b64u_jwt_payload <== b64u_jwt_payload_tagged,
        //
        sha2_num_blocks <== sha2_num_blocks,
        sha2_num_bits <== sha2_num_bits_tagged,
        sha2_padding <== sha2_padding_tagged,
        //
        signature <== signature,
        pubkey_modulus <== pubkey_modulus_tagged,
        //
        exp_date <== exp_date,
        exp_horizon <== exp_horizon,
        //
        aud_field <== aud_field_tagged,
        aud_field_string_bodies <== aud_field_string_bodies_tagged,
        aud_field_len <== aud_field_len,
        aud_index <== aud_index,
        aud_value_index <== aud_value_index,
        aud_colon_index <== aud_colon_index,
        aud_name <== aud_name_tagged,
        //
        use_aud_override <== use_aud_override,
        private_aud_value <== private_aud_value_tagged,
        override_aud_value <== override_aud_value_tagged,
        private_aud_value_len <== private_aud_value_len,
        override_aud_value_len <== override_aud_value_len,
        skip_aud_checks <== skip_aud_checks,
        //
        uid_field <== uid_field_tagged,
        uid_field_string_bodies <== uid_field_string_bodies_tagged,
        uid_field_len <== uid_field_len,
        uid_index <== uid_index,
        uid_name_len <== uid_name_len,
        uid_value_index <== uid_value_index,
        uid_value_len <== uid_value_len,
        uid_colon_index <== uid_colon_index,
        uid_name <== uid_name_tagged,
        uid_value <== uid_value_tagged,
        //
        iss_field <== iss_field_tagged,
        iss_field_string_bodies <== iss_field_string_bodies_tagged,
        iss_field_len <== iss_field_len,
        iss_index <== iss_index,
        iss_value_index <== iss_value_index,
        iss_value_len <== iss_value_len,
        iss_colon_index <== iss_colon_index,
        iss_name <== iss_name_tagged,
        iss_value <== iss_value_tagged,
        //
        nonce_field <== nonce_field_tagged,
        nonce_field_string_bodies <== nonce_field_string_bodies_tagged,
        nonce_field_len <== nonce_field_len,
        nonce_index <== nonce_index,
        nonce_value_index <== nonce_value_index,
        nonce_value_len <== nonce_value_len,
        nonce_colon_index <== nonce_colon_index,
        nonce_name <== nonce_name_tagged,
        nonce_value <== nonce_value_tagged,
        //
        ev_field <== ev_field_tagged,
        ev_field_len <== ev_field_len,
        ev_index <== ev_index,
        ev_value_index <== ev_value_index,
        ev_value_len <== ev_value_len,
        ev_colon_index <== ev_colon_index,
        ev_name <== ev_name_tagged,
        ev_value <== ev_value_tagged,
        //
        iat_field <== iat_field_tagged,
        iat_field_len <== iat_field_len,
        iat_index <== iat_index,
        iat_value_index <== iat_value_index,
        iat_value_len <== iat_value_len,
        iat_colon_index <== iat_colon_index,
        iat_name <== iat_name_tagged,
        iat_value <== iat_value_tagged,
        //
        extra_field <== extra_field_tagged,
        extra_field_len <== extra_field_len,
        extra_index <== extra_index,
        use_extra_field <== use_extra_field,
        //
        epk <== epk,
        epk_len <== epk_len,
        epk_blinder <== epk_blinder,
        pepper <== pepper,
        //
        public_inputs_hash <== public_inputs_hash
    );
}

component main { public [public_inputs_hash] } = keyless_sanitizer(
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
    10,         // MAX_NONCE_NAME_LEN
    100,        // MAX_NONCE_VALUE_LEN

    /* email_verified field */
    30,         // MAX_EMAIL_VERIFIED_KV_PAIR_LEN
    20,         // MAX_EMAIL_VERIFIED_NAME_LEN
    10,         // MAX_EMAIL_VERIFIED_VALUE_LEN

    /* the user ID field (i.e., sub or email) */
    350,        // MAX_UID_KV_PAIR_LEN
    30,         // MAX_UID_NAME_LEN
    330,        // MAX_UID_VALUE_LEN

    /* any extra field (e.g., the name field) */
    350         // MAX_EXTRA_FIELD_KV_PAIR_LEN
);
