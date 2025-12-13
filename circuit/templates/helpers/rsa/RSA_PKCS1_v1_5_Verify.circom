pragma circom 2.2.2;

// File copied and modified from https://github.com/zkp-application/circom-rsa-verify/blob/main/circuits/rsa_verify.circom,
// except we are using the `FpPow65537Mod` for exponentiation instead, as it is more efficient.

include "./FpMul.circom";
include "./FpPow65537Mod.circom";

include "circomlib/circuits/bitify.circom";

template RSA_PKCS1_v1_5_Verify(LIMB_BIT_WIDTH, NUM_LIMBS) {
    signal input signature[NUM_LIMBS]; // least-significant-limb first
    signal input modulus[NUM_LIMBS];   // least-significant-limb first
    signal input hash_limbs_le[4];     // least-significant-limb first

    // (signature ^ 65537) mod modulus
    component pm = FpPow65537Mod(LIMB_BIT_WIDTH, NUM_LIMBS);
    for (var i  = 0; i < NUM_LIMBS; i++) {
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
    component num2bits_6 = Num2Bits(LIMB_BIT_WIDTH);
    num2bits_6.in <== pm.out[6];
    var REMAINS_BITS[32] = [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 1, 0, 0, 0, 0, 0, 0, 1, 1, 0, 0, 0, 1, 0, 0, 1, 1, 0, 0, 0, 0];
    for (var i = 0; i < 32; i++) {
        num2bits_6.out[i] === REMAINS_BITS[31 - i];
    }

    // 3. Check PS and em[1] = 1. the same code like golang std lib rsa.VerifyPKCS1v15
    for (var i = 32; i < LIMB_BIT_WIDTH; i++) {
        num2bits_6.out[i] === 1;
    }

    for (var i = 7; i < 31; i++) {
        // 0b1111111111111111111111111111111111111111111111111111111111111111
        pm.out[i] === 18446744073709551615;
    }
    // 0b1111111111111111111111111111111111111111111111111
    pm.out[31] === 562949953421311;
}