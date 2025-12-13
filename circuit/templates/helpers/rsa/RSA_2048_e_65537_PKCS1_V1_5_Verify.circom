pragma circom 2.2.2;

include "../packing/AssertIs64BitLimbs.circom";
include "../packing/BigEndianBitsToScalars.circom";
include "../bigint/BigLessThan.circom";

include "RSA_PKCS1_v1_5_Verify.circom";

// Assumes the public key `e = 65537`
// Assumes messages are 256-sized bit arrays
template RSA_2048_e_65537_PKCS1_V1_5_Verify(SIGNATURE_LIMB_BIT_WIDTH, SIGNATURE_NUM_LIMBS) {
    signal input signature[SIGNATURE_NUM_LIMBS];
    signal input modulus[SIGNATURE_NUM_LIMBS];
    signal input hash_bits_be[256];

    // Pack the 256-bit hashed message bits into 4 limbs
    signal hash_limbs_be[4] <== BigEndianBitsToScalars(256, SIGNATURE_LIMB_BIT_WIDTH)(hash_bits_be);

    // Note: modulus has its AssertIs64BitLimbs() check done as part of Hash64BitLimbsToFieldWithLen
    AssertIs64BitLimbs(SIGNATURE_NUM_LIMBS)(signature);
    signal sig_ok <== BigLessThan(252, SIGNATURE_NUM_LIMBS)(signature, modulus);
    sig_ok === 1;

    var hash_limbs_le[4];
    for (var i = 0; i < 4; i++) {
        hash_limbs_le[i] = hash_limbs_be[3 - i];
    }

    RSA_PKCS1_v1_5_Verify(SIGNATURE_LIMB_BIT_WIDTH, SIGNATURE_NUM_LIMBS)(
        signature, modulus, hash_limbs_le
    );
}
