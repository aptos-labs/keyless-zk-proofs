pragma circom 2.2.2;

include "../packing/AssertIs64BitLimbs.circom";
include "../packing/BigEndianBitsToScalars.circom";
include "../bigint/BigLessThan.circom";

include "FpPow65537Mod.circom";

// Assumes the public key `e = 65537`
// Assumes messages are 256-sized bit arrays
// TODO: This template is a mess: it does not actually support different limb widths than 64-bits, even though it takes the parameters.
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

    // (signature ^ 65537) mod modulus
    component pm = FpPow65537Mod(SIGNATURE_LIMB_BIT_WIDTH, SIGNATURE_NUM_LIMBS);
    for (var i  = 0; i < SIGNATURE_NUM_LIMBS; i++) {
        pm.base[i] <== signature[i];
        //pm.exp[i] <== exp[i];
        pm.modulus[i] <== modulus[i];
    }

    // 1. Check hash_limbs_le data
    // 64 * 4 = 256 bit. the first 4 numbers
    for (var i = 0; i < 4; i++) {
        hash_limbs_le[i] === pm.out[i];
    }
    
    // 2. Check hash prefix and 1 byte 0x00
    // sha256/152 bit
    // 0b00110000001100010011000000001101000001100000100101100000100001100100100000000001011001010000001100000100000000100000000100000101000000000000010000100000
    pm.out[4] === 217300885422736416;
    pm.out[5] === 938447882527703397;
    // // remain 24 bit
    component num2bits_6 = Num2Bits(SIGNATURE_LIMB_BIT_WIDTH);
    num2bits_6.in <== pm.out[6];
    var REMAINS_BITS[32] = [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 1, 0, 0, 0, 0, 0, 0, 1, 1, 0, 0, 0, 1, 0, 0, 1, 1, 0, 0, 0, 0];
    for (var i = 0; i < 32; i++) {
        num2bits_6.out[i] === REMAINS_BITS[31 - i];
    }

    // 3. Check PS and em[1] = 1. the same code like golang std lib rsa.VerifyPKCS1v15
    for (var i = 32; i < SIGNATURE_LIMB_BIT_WIDTH; i++) {
        num2bits_6.out[i] === 1;
    }

    for (var i = 7; i < 31; i++) {
        // 0b1111111111111111111111111111111111111111111111111111111111111111
        pm.out[i] === 18446744073709551615;
    }
    // 0b1111111111111111111111111111111111111111111111111
    pm.out[31] === 562949953421311;
}
