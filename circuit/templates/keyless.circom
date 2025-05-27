/**
 * It generally helps to be familiar with the design and terminology from AIP-61:
 *
 *   https://github.com/aptos-foundation/AIPs/blob/main/aips/aip-61.md
 *
 * It would also help to generally be familiar with the principles and ideas
 * behind keyless accounts:
 *
 *   https://alinush.org/keyless
 *
 * (Of course, circom expertise is a must: https://alinush.org/circom)
 *
 * Conventions:
 *  - When we say JWT, we typically mean base64url-decoded JWT data
 *     + When the JWT is base64url encoded, we specifically refer to it as base64url-encoded JWT
 *       and name circom variables / signals appropriately; e.g., b64u_jwt_payload
 */
pragma circom 2.2.2;

include "circomlib/circuits/poseidon.circom";
include "circomlib/circuits/bitify.circom";

include "./helpers/arrays/AssertIsConcatenation.circom";

include "./helpers/base64url/Base64UrlDecode.circom";
include "./helpers/base64url/Base64UrlDecodedLength.circom";

include "./helpers/bigint/BigLessThan.circom";

include "./helpers/hashtofield/Hash64BitLimbsToFieldWithLen.circom";

include "./helpers/jwt_field_parsing.circom";
include "./helpers/misc.circom";

include "./helpers/packing/BigEndianBitsToScalars.circom";

include "./helpers/rsa/RSA_PKCS1_v1_5_Verify.circom";

include "./helpers/sha/SHA2_256_PaddingVerify.circom";
include "./helpers/sha/SHA2_256_Prepadded_Hash.circom";

include "./helpers/strings/AsciiDigitsToScalar.circom";

include "./stdlib/circuits/ElementwiseMul.circom";
include "./stdlib/circuits/InvertBinaryArray.circom";

// The main Aptos Keyless circuit. The parameters below are max lengths, 
// in bytes, for the...
template keyless(
    MAX_B64U_JWT_NO_SIG_LEN,    // ...full base64url JWT without the signature, but with SHA2 padding
    MAX_B64U_JWT_HEADER_W_DOT_LEN,  // ...full base64url JWT header with a dot at the end
    MAX_B64U_JWT_PAYLOAD_SHA2_PADDED_LEN,   // ...full base64url JWT payload with SHA2 padding
    maxAudKVPairLen,    // ...ASCII aud field
    maxAudNameLen,      // ...ASCII aud name
    maxAudValueLen,     // ...ASCII aud value
    maxIssKVPairLen,    // ...ASCII iss field
    maxIssNameLen,      // ...ASCII iss name
    maxIssValueLen,     // ...ASCII iss value
    maxIatKVPairLen,    // ...ASCII iat field
    maxIatNameLen,      // ...ASCII iat name
    maxIatValueLen,     // ...ASCII iat value
    maxNonceKVPairLen,  // ...ASCII nonce field
    maxNonceNameLen,    // ...ASCII nonce name
    maxNonceValueLen,   // ...ASCII nonce value
    maxEVKVPairLen,     // ...ASCII email verified field
    maxEVNameLen,       // ...ASCII email verified name
    maxEVValueLen,      // ...ASCII email verified value
    maxUIDKVPairLen,    // ...ASCII uid field
    maxUIDNameLen,      // ...ASCII uid name
    maxUIDValueLen,     // ...ASCII uid value
    maxEFKVPairLen      // ...ASCII extra field
) {
    // Several templates (e.g., Poseidon-BN254 templates, LessThan) assume the
    // BN254 curve is used, whose scalar field can represent any 253-bit number
    // (but not necessarily any 254-bit one). Here, we check that the scalar
    // field satisfies this assumption.
    _ = assert_bits_fit_scalar(253);

    //
    // Global variables
    //

    // RSA signatures and pubkeys are stored as 64-bit (8-byte) limbs
    var SIGNATURE_NUM_LIMBS = 32;

    // The maximum length of a base64url-decoded JWT payload.
    // Note: Recall that base64url encoding adds about 33% overhead.
    var MAX_JWT_PAYLOAD_LEN = (3 * MAX_B64U_JWT_PAYLOAD_SHA2_PADDED_LEN) \ 4;

    //
    // JWT splitting into header and payload
    //

    // base64url-encoded JWT header + payload + SHA2 padding, but without RSA signature:
    //   i.e., SHA2Pad( base64Url(JWT header) + "." + base64Url(JWT payload) )
    // TODO: Why does this need to be an input signal?
    //   Can't it be an intermediate signal produced as an output from some kind of `Concatenate` template?
    signal input b64u_jwt_no_sig_sha2_padded[MAX_B64U_JWT_NO_SIG_LEN]; // base64url format

    // base64url-encoded JWT header + the ASCII dot following it
    // TODO: We need to check 0-padding for the last `MAX_B64U_JWT_HEADER_W_DOT_LEN - b64u_jwt_header_w_dot_len` bytes
    //   But right now this is done implicitly in AssertIsConcatenation (a bit dangerous)
    // TODO: Can we leverage tags / buses here to propagate information about having checked the padding?
    signal input b64u_jwt_header_w_dot[MAX_B64U_JWT_HEADER_W_DOT_LEN];
    signal input b64u_jwt_header_w_dot_len;

    // base64url-encoded JWT payload with SHA2 padding
    // TODO: We need to check 0-padding for the last `MAX_B64U_JWT_PAYLOAD_SHA2_PADDED_LEN - b64u_jwt_payload_sha2_padded_len` bytes?
    //   But right now this is done implicitly in AssertIsConcatenation (a bit dangerous)
    signal input b64u_jwt_payload_sha2_padded[MAX_B64U_JWT_PAYLOAD_SHA2_PADDED_LEN];
    signal input b64u_jwt_payload_sha2_padded_len;

    // Checks that the base64url-encoded JWT payload & header are correctly concatenated:
    //   i.e., that `b64u_jwt_no_sig_sha2_padded` is the concatenation of `b64u_jwt_header_w_dot` with` b64u_jwt_payload_sha2_padded`
    AssertIsConcatenation(MAX_B64U_JWT_NO_SIG_LEN, MAX_B64U_JWT_HEADER_W_DOT_LEN, MAX_B64U_JWT_PAYLOAD_SHA2_PADDED_LEN)(
        b64u_jwt_no_sig_sha2_padded,
        b64u_jwt_header_w_dot,
        b64u_jwt_payload_sha2_padded,
        b64u_jwt_header_w_dot_len,
        b64u_jwt_payload_sha2_padded_len
    );

    // TODO(Perf): Why not perform this check on `b64u_jwt_header_w_dot`, which is shorter & should save
    //   some constraints? (Since the concatenation check makes it irrelevant where we check this.)
    //
    // Note: We need this to ensure the circuit cannot be tricked in terms of where the base64url-encoded
    //   JWT payload starts. Even though the circuit does not care about what's in the header, it 
    //   needs to ensure it's looking at the right payload (e.g., if it misinterprets the header
    //   as part of the payload *and* the header is adversarially-controlled, the circuit could be
    //   tricked into parsing an `email` field maliciously placed in the header).
    var dot = SelectArrayValue(MAX_B64U_JWT_NO_SIG_LEN)(
        b64u_jwt_no_sig_sha2_padded,
        b64u_jwt_header_w_dot_len - 1
    );

    dot === 46; // '.'

    // Removes the padding from the base64url-encoded JWT payload
    signal input b64u_jwt_payload[MAX_B64U_JWT_PAYLOAD_SHA2_PADDED_LEN];
    log("b64u_jwt_payload: ");

    AssertIsSubstring(MAX_B64U_JWT_PAYLOAD_SHA2_PADDED_LEN, MAX_B64U_JWT_PAYLOAD_SHA2_PADDED_LEN)(
        str <== b64u_jwt_payload_sha2_padded,
        // TODO(Perf): Unnecessarily hashing this a 2nd time here (already hashed for AssertIsConcatenation)
        str_hash <== HashBytesToFieldWithLen(MAX_B64U_JWT_PAYLOAD_SHA2_PADDED_LEN)(
            b64u_jwt_payload_sha2_padded,
            b64u_jwt_payload_sha2_padded_len
        ),
        substr <== b64u_jwt_payload,
        substr_len <== b64u_jwt_payload_sha2_padded_len,
        start_index <== 0
    );

    //
    // SHA2-256 hashing
    //

    signal input sha2_num_blocks;

    // The length of `b64u_jwt_no_sig_sha2_padded` in bits, denoted by `L` and
    //   encoded as a byte array of size 8.
    // (=> max length in bits must be expressible in 8*8 = 64 bits)
    signal input sha2_num_bits[8];

    // SHA2-256 padding: up to 512 bits as per https://www.rfc-editor.org/rfc/rfc4634.html#section-4.1:
    //   i.e., a 1-bit followed by `K` 0 bits, where `K` is the smallest
    //   integer >= 0 s.t. `L + 1 + K = 448 (mod 512)`
    // Note: The padding is stored as a byte array of size 8.
    // Note: By "padding" here we just mean the "10000..." bits *without* the length L appended to them
    signal input sha2_padding[64];

    SHA2_256_PaddingVerify(MAX_B64U_JWT_NO_SIG_LEN)(
        b64u_jwt_no_sig_sha2_padded,
        sha2_num_blocks,
        b64u_jwt_header_w_dot_len + b64u_jwt_payload_sha2_padded_len,
        sha2_num_bits,
        sha2_padding
    );

    // Computes the SHA2-256 hash of the JWT.
    // Recall that:
    //  - A SHA2 block is 512 bits
    //  - '\' performs division rounded up to an integer
    var SHA2_MAX_NUM_BLOCKS = (MAX_B64U_JWT_NO_SIG_LEN * 8) \ 512;
    signal jwt_hash[256] <== SHA2_256_Prepadded_Hash(SHA2_MAX_NUM_BLOCKS)(
        in <== Bytes2BigEndianBits(MAX_B64U_JWT_NO_SIG_LEN)(b64u_jwt_no_sig_sha2_padded),
        tBlock <== sha2_num_blocks - 1
    );

    //
    // JWT RSA signature verification
    //

    // An RSA signature will be represented as a size-32 array of 64-bit limbs.
    signal input signature[SIGNATURE_NUM_LIMBS];
    signal input pubkey_modulus[SIGNATURE_NUM_LIMBS];

    var SIGNATURE_LIMB_BIT_WIDTH = 64;
    RSA_2048_e_65537_PKCS1_V1_5_Verify(SIGNATURE_LIMB_BIT_WIDTH, SIGNATURE_NUM_LIMBS)(
        signature, pubkey_modulus, jwt_hash
    );

    //
    // Decoding the base64url-encoded JWT
    //

    signal jwt_payload[MAX_JWT_PAYLOAD_LEN] <== Base64UrlDecode(MAX_JWT_PAYLOAD_LEN)(
        b64u_jwt_payload
    );

    signal jwt_payload_len <== Base64UrlDecodedLength(MAX_B64U_JWT_PAYLOAD_SHA2_PADDED_LEN)(
        b64u_jwt_payload_sha2_padded_len
    );

    // TODO(Perf): If we are hashing a (collision-resistant) base64url-encoding of the payload above for the
    //   concatenation check, we could avoid this extra hashing here, perhaps?
    signal jwt_payload_hash <== HashBytesToFieldWithLen(MAX_JWT_PAYLOAD_LEN)(
        jwt_payload,
        jwt_payload_len
    );

    //
    // Computing hints for securing our JWT parsing
    //

    // Contains 1s between unescaped quotes, and 0s everywhere else. Used to prevent a fake field inside quotes from
    // being accepted as valid
    signal string_bodies[MAX_JWT_PAYLOAD_LEN] <== StringBodies(MAX_JWT_PAYLOAD_LEN)(jwt_payload);

    // To prevent attacks involving fields inside nested brackets, we perform the following steps:
    // 1. Take the inverse of the string bodies array, turning each `1` into `0`, and each `0` into `1`
    // 2. Create an array marking open brackets (1) and closed brackets (-1) in the ASCII JWT payload, with 0 elsewhere
    // 3. Use the array from 1 to eliminate quoted brackets in 2 with element-wise multiplication
    // 4. Use the array from 3 to make an array with 1+ inside brackets and 0 everywhere else, not including the outermost brackets of the JWT payload
    // 5. Use the array from 4 to check there are no characters of a given field (such as aud) inside of nested brackets. This is done per field
    signal inverted_string_bodies[MAX_JWT_PAYLOAD_LEN] <== InvertBinaryArray(MAX_JWT_PAYLOAD_LEN)(string_bodies);
    signal brackets_map[MAX_JWT_PAYLOAD_LEN] <== BracketsMap(MAX_JWT_PAYLOAD_LEN)(jwt_payload);
    signal unquoted_brackets_map[MAX_JWT_PAYLOAD_LEN] <== ElementwiseMul(MAX_JWT_PAYLOAD_LEN)(inverted_string_bodies, brackets_map);
    signal unquoted_brackets_depth_map[MAX_JWT_PAYLOAD_LEN] <== BracketsDepthMap(MAX_JWT_PAYLOAD_LEN)(unquoted_brackets_map);

    //
    // JWT field matching
    //

    // Check aud field is in the JWT
    signal input aud_field[maxAudKVPairLen]; // ASCII
    signal input aud_field_string_bodies[maxAudKVPairLen]; // ASCII
    signal input aud_field_len; // ASCII
    signal input aud_index; // index of aud field in JWT payload
    AssertIsSubstring(MAX_JWT_PAYLOAD_LEN, maxAudKVPairLen)(jwt_payload, jwt_payload_hash, aud_field, aud_field_len, aud_index);
    AssertIsSubstring(MAX_JWT_PAYLOAD_LEN, maxAudKVPairLen)(string_bodies, jwt_payload_hash, aud_field_string_bodies, aud_field_len, aud_index);
    EnforceNotNested(MAX_JWT_PAYLOAD_LEN)(aud_index, aud_field_len, unquoted_brackets_depth_map);

    // Perform necessary checks on aud field
    var aud_name_len = 3;
    signal input aud_value_index;
    signal input aud_colon_index;
    signal input aud_name[maxAudNameLen];
    signal input use_aud_override;
    use_aud_override * (1 - use_aud_override) === 0;

    signal aud_value[maxAudValueLen];
    signal input private_aud_value[maxAudValueLen];
    signal input override_aud_value[maxAudValueLen];
    signal input private_aud_value_len;
    signal input override_aud_value_len;
    signal input skip_aud_checks;

    // We never want to skip aud checks in the JWT while using aud override - the aud override value should always
    // be checked against the JWT when `use_aud_override` is equal to 1
    signal skip_aud_checks_and_use_aud_override <== AND()(skip_aud_checks, use_aud_override);
    skip_aud_checks_and_use_aud_override === 0;

    skip_aud_checks * (skip_aud_checks - 1) === 0; // Ensure equal to 0 or 1
    for (var i = 0; i < maxAudValueLen; i++) {
        aud_value[i] <== (override_aud_value[i] - private_aud_value[i]) * use_aud_override + private_aud_value[i];
    }

    signal aud_value_len <== (override_aud_value_len - private_aud_value_len) * use_aud_override + private_aud_value_len;

    ParseJWTFieldWithQuotedValue(maxAudKVPairLen, maxAudNameLen, maxAudValueLen)(aud_field, aud_name, aud_value, aud_field_string_bodies, aud_field_len, aud_name_len, aud_value_index, aud_value_len, aud_colon_index, skip_aud_checks);


    // Check aud name is correct
    signal perform_aud_checks <== NOT()(skip_aud_checks);
    var required_aud_name[aud_name_len] = [97, 117, 100]; // aud
    for (var i = 0; i < aud_name_len; i++) {
        aud_name[i] * perform_aud_checks === required_aud_name[i] * perform_aud_checks;
    }

    // Check user id field is in the JWT
    signal input uid_field[maxUIDKVPairLen];
    signal input uid_field_string_bodies[maxUIDKVPairLen];
    signal input uid_field_len;
    signal input uid_index;
    AssertIsSubstring(MAX_JWT_PAYLOAD_LEN, maxUIDKVPairLen)(jwt_payload, jwt_payload_hash, uid_field, uid_field_len, uid_index);
    AssertIsSubstring(MAX_JWT_PAYLOAD_LEN, maxUIDKVPairLen)(string_bodies, jwt_payload_hash, uid_field_string_bodies, uid_field_len, uid_index);
    EnforceNotNested(MAX_JWT_PAYLOAD_LEN)(uid_index, uid_field_len, unquoted_brackets_depth_map);

    // Perform necessary checks on user id field. Some fields this might be in practice are "sub" or "email"
    signal input uid_name_len;
    signal input uid_value_index;
    signal input uid_value_len;
    signal input uid_colon_index;
    signal input uid_name[maxUIDNameLen];
    signal input uid_value[maxUIDValueLen];

    ParseJWTFieldWithQuotedValue(maxUIDKVPairLen, maxUIDNameLen, maxUIDValueLen)(uid_field, uid_name, uid_value, uid_field_string_bodies, uid_field_len, uid_name_len, uid_value_index, uid_value_len, uid_colon_index, 0);

    // Check extra field is in the JWT
    signal input extra_field[maxEFKVPairLen];
    signal input extra_field_len;
    signal input extra_index;
    signal input use_extra_field;
    use_extra_field * (use_extra_field - 1) === 0; // Ensure 0 or 1

    signal ef_passes <== IsSubstring(MAX_JWT_PAYLOAD_LEN, maxEFKVPairLen)(jwt_payload, jwt_payload_hash, extra_field, extra_field_len, extra_index);
    EnforceNotNested(MAX_JWT_PAYLOAD_LEN)(extra_index, extra_field_len, unquoted_brackets_depth_map);

    // Fail if use_extra_field = 1 and ef_passes = 0
    signal not_ef_passes <== NOT()(ef_passes);
    signal ef_fail <== AND()(use_extra_field, not_ef_passes);
    ef_fail === 0;

    // Check that ef is not inside a string body
    signal ef_start_char <== SelectArrayValue(MAX_JWT_PAYLOAD_LEN)(string_bodies, extra_index);
    ef_start_char === 0;

    // Check email verified field
    signal input ev_field[maxEVKVPairLen];
    signal input ev_field_len;
    signal input ev_index;

    var ev_name_len = 14;
    signal input ev_value_index;
    signal input ev_value_len;
    signal input ev_colon_index;
    signal input ev_name[maxEVNameLen];
    signal input ev_value[maxEVValueLen];

    // Boolean truth table for checking whether we should fail on the results of 'EmailVerifiedCheck'
    // and `IsSubstring`. We must fail if the uid name is 'email', and the provided
    // `ev_field` is not in the full JWT according to the substring check
    // uid_is_email | ev_in_jwt | ev_fail
    //     1        |     1     |   1 
    //     1        |     0     |   0
    //     0        |     1     |   1
    //     0        |     0     |   1
    signal uid_is_email <== EmailVerifiedCheck(maxEVNameLen, maxEVValueLen, maxUIDNameLen)(ev_name, ev_value, ev_value_len, uid_name, uid_name_len);
    signal ev_in_jwt <== IsSubstring(MAX_JWT_PAYLOAD_LEN, maxEVKVPairLen)(jwt_payload, jwt_payload_hash, ev_field, ev_field_len, ev_index);
    signal not_ev_in_jwt <== NOT()(ev_in_jwt);
    signal ev_fail <== AND()(uid_is_email, not_ev_in_jwt);
    ev_fail === 0;

    EnforceNotNested(MAX_JWT_PAYLOAD_LEN)(ev_index, ev_field_len, unquoted_brackets_depth_map);

    // Need custom logic here because some providers apparently do not follow the OIDC spec and put the email_verified value in quotes
    ParseEmailVerifiedField(maxEVKVPairLen, maxEVNameLen, maxEVValueLen)(ev_field, ev_name, ev_value, ev_field_len, ev_name_len, ev_value_index, ev_value_len, ev_colon_index);

    // Check iss field is in the JWT
    // Note that because `iss_field` is a public input, we assume the verifier will perform correctness checks on it outside of the circuit. 
    signal input iss_field[maxIssKVPairLen];
    signal input iss_field_string_bodies[maxIssKVPairLen];
    signal input iss_field_len;
    signal input iss_index;
    AssertIsSubstring(MAX_JWT_PAYLOAD_LEN, maxIssKVPairLen)(jwt_payload, jwt_payload_hash, iss_field, iss_field_len, iss_index);
    AssertIsSubstring(MAX_JWT_PAYLOAD_LEN, maxIssKVPairLen)(string_bodies, jwt_payload_hash, iss_field_string_bodies, iss_field_len, iss_index);
    EnforceNotNested(MAX_JWT_PAYLOAD_LEN)(iss_index, iss_field_len, unquoted_brackets_depth_map);

    // Perform necessary checks on iss field
    var iss_name_len = 3; // iss
    signal input iss_value_index;
    signal input iss_value_len;
    signal input iss_colon_index;
    signal input iss_name[maxIssNameLen];
    signal input iss_value[maxIssValueLen];

    ParseJWTFieldWithQuotedValue(maxIssKVPairLen, maxIssNameLen, maxIssValueLen)(iss_field, iss_name, iss_value, iss_field_string_bodies, iss_field_len, iss_name_len, iss_value_index, iss_value_len, iss_colon_index, 0);

    // Check name of the iss field is correct
    var required_iss_name[iss_name_len] = [105, 115, 115]; // iss
    for (var i = 0; i < iss_name_len; i++) {
        iss_name[i] === required_iss_name[i];
    }

    // Check iat field is in the JWT
    signal input iat_field[maxIatKVPairLen];
    signal input iat_field_len;
    signal input iat_index;
    AssertIsSubstring(MAX_JWT_PAYLOAD_LEN, maxIatKVPairLen)(jwt_payload, jwt_payload_hash, iat_field, iat_field_len, iat_index);

    // Perform necessary checks on iat field
    var iat_name_len = 3; // iat
    signal input iat_value_index;
    signal input iat_value_len;
    signal input iat_colon_index;
    signal input iat_name[maxIatNameLen];
    signal input iat_value[maxIatValueLen];

    ParseJWTFieldWithUnquotedValue(maxIatKVPairLen, maxIatNameLen, maxIatValueLen)(iat_field, iat_name, iat_value, iat_field_len, iat_name_len, iat_value_index, iat_value_len, iat_colon_index, 0);
    EnforceNotNested(MAX_JWT_PAYLOAD_LEN)(iss_index, iss_field_len, unquoted_brackets_depth_map);

    // Check that iat is not inside a string body
    signal iat_start_char <== SelectArrayValue(MAX_JWT_PAYLOAD_LEN)(string_bodies, iat_index);
    iat_start_char === 0;

    // Check name of the iat field is correct
    var required_iat_name[iat_name_len] = [105, 97, 116]; // iat
    for (var i = 0; i < iat_name_len; i++) {
        iat_name[i] === required_iat_name[i];
    }
    
    signal iat_field_elem <== AsciiDigitsToScalar(maxIatValueLen)(iat_value, iat_value_len);
    
    signal input exp_date;
    signal input exp_horizon;
    signal jwt_not_expired <== LessThan(252)([exp_date, iat_field_elem + exp_horizon]);
    jwt_not_expired === 1;

    // Check nonce field is in the JWT
    signal input nonce_field[maxNonceKVPairLen];
    signal input nonce_field_string_bodies[maxNonceKVPairLen];
    signal input nonce_field_len;
    signal input nonce_index;
    AssertIsSubstring(MAX_JWT_PAYLOAD_LEN, maxNonceKVPairLen)(jwt_payload, jwt_payload_hash, nonce_field, nonce_field_len, nonce_index);
    AssertIsSubstring(MAX_JWT_PAYLOAD_LEN, maxNonceKVPairLen)(string_bodies, jwt_payload_hash, nonce_field_string_bodies, nonce_field_len, nonce_index);
    EnforceNotNested(MAX_JWT_PAYLOAD_LEN)(nonce_index, nonce_field_len, unquoted_brackets_depth_map);

    // Perform necessary checks on nonce field
    var nonce_name_len = 5; // nonce
    signal input nonce_value_index;
    signal input nonce_value_len;
    signal input nonce_colon_index;
    signal input nonce_name[maxNonceNameLen];
    signal input nonce_value[maxNonceValueLen];

    ParseJWTFieldWithQuotedValue(maxNonceKVPairLen, maxNonceNameLen, maxNonceValueLen)(nonce_field, nonce_name, nonce_value, nonce_field_string_bodies, nonce_field_len, nonce_name_len, nonce_value_index, nonce_value_len, nonce_colon_index, 0);

    // Check name of the nonce field is correct
    var required_nonce_name[nonce_name_len] = [110, 111, 110, 99, 101]; // nonce
    for (var i = 0; i < nonce_name_len; i++) {
        nonce_name[i] === required_nonce_name[i];
    }

    //
    // Calculate nonce
    //

    // The ephemeral pubkey, as 3 elements of up to 31 bytes each, to allow for pubkeys of up to 64 bytes each.
    signal input epk[3];
    // The ephemeral pubkey length in bytes.
    signal input epk_len;
    signal input epk_blinder;
    signal computed_nonce <== Poseidon(6)([epk[0], epk[1], epk[2], epk_len, exp_date, epk_blinder]);
    log("computed nonce is: ", computed_nonce);

    // Check nonce is correct
    signal nonce_field_elem <== AsciiDigitsToScalar(maxNonceValueLen)(nonce_value, nonce_value_len);
    
    nonce_field_elem === computed_nonce;

    //
    // Compute the identity commitment (IDC)
    //

    signal input pepper;
    signal hashable_private_aud_value[maxAudValueLen];
    for (var i = 0; i < maxAudValueLen; i++) {
        hashable_private_aud_value[i] <== private_aud_value[i] * perform_aud_checks;
    }
    signal private_aud_val_hashed <== HashBytesToFieldWithLen(maxAudValueLen)(hashable_private_aud_value, private_aud_value_len);
    signal uid_value_hashed <== HashBytesToFieldWithLen(maxUIDValueLen)(uid_value, uid_value_len);
    signal uid_name_hashed <== HashBytesToFieldWithLen(maxUIDNameLen)(uid_name, uid_name_len);
    signal idc <== Poseidon(4)([
        pepper,
        private_aud_val_hashed,
        uid_value_hashed,
        uid_name_hashed
    ]);

    log("private aud val hash is: ", private_aud_val_hashed);
    log("uid val hash is: ", uid_value_hashed);
    log("uid name hash is: ", uid_name_hashed);
    log("IDC is: ", idc);

    //
    // Check public inputs are correct
    //

    signal override_aud_val_hashed <== HashBytesToFieldWithLen(maxAudValueLen)(override_aud_value, override_aud_value_len);
    signal hashed_jwt_header <== HashBytesToFieldWithLen(MAX_B64U_JWT_HEADER_W_DOT_LEN)(b64u_jwt_header_w_dot, b64u_jwt_header_w_dot_len);
    signal hashed_pubkey_modulus <== Hash64BitLimbsToFieldWithLen(SIGNATURE_NUM_LIMBS)(pubkey_modulus, 256); // 256 bytes per signature
    signal hashed_iss_value <== HashBytesToFieldWithLen(maxIssValueLen)(iss_value, iss_value_len);
    signal hashed_extra_field <== HashBytesToFieldWithLen(maxEFKVPairLen)(extra_field, extra_field_len);
    signal computed_public_inputs_hash <== Poseidon(14)([
        epk[0], epk[1], epk[2], epk_len,
        idc,
        exp_date,
        exp_horizon,
        hashed_iss_value,
        use_extra_field,
        hashed_extra_field,
        hashed_jwt_header,
        hashed_pubkey_modulus,
        override_aud_val_hashed,
        use_aud_override
    ]);

    log("override aud val hash is: ", override_aud_val_hashed);
    log("JWT header hash is: ", hashed_jwt_header);
    log("pubkey hash is: ", hashed_pubkey_modulus);
    log("iss field hash is: ", hashed_iss_value);
    log("extra field hash is: ", hashed_extra_field);
    log("public inputs hash is: ", computed_public_inputs_hash);
    
    signal input public_inputs_hash;
    public_inputs_hash === computed_public_inputs_hash;
}

// Assumes the public key `e = 65537`
// Assumes messages are 256-sized bit arrays
template RSA_2048_e_65537_PKCS1_V1_5_Verify(SIGNATURE_LIMB_BIT_WIDTH, SIGNATURE_NUM_LIMBS) {
    signal input signature[SIGNATURE_NUM_LIMBS];
    signal input pubkey_modulus[SIGNATURE_NUM_LIMBS];
    signal input message_bits[256];   // typicall, this is a hash of a larger message (in our case a SHA2-256 hash)

    // Pack the 256-bit hashed message bits into 4 limbs
    signal message_limbs[4] <== BigEndianBitsToScalars(256, SIGNATURE_LIMB_BIT_WIDTH)(message_bits);

    // Note: pubkey_modulus has its AssertIs64BitLimbs() check done as part of Hash64BitLimbsToFieldWithLen
    AssertIs64BitLimbs(SIGNATURE_NUM_LIMBS)(signature);
    signal sig_ok <== BigLessThan(252, SIGNATURE_NUM_LIMBS)(signature, pubkey_modulus);
    sig_ok === 1;

    var message_limbs_le[4];
    for (var i = 0; i < 4; i++) {
        message_limbs_le[i] = message_limbs[3 - i];
    }

    RSA_PKCS1_v1_5_Verify(SIGNATURE_LIMB_BIT_WIDTH, SIGNATURE_NUM_LIMBS)(
        signature, pubkey_modulus, message_limbs_le
    );
}
