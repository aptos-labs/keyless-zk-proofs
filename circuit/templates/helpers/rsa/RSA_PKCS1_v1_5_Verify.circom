pragma circom 2.2.2;

// File copied and modified from https://github.com/zkp-application/circom-rsa-verify/blob/main/circuits/rsa_verify.circom,
// except we are using the `FpPow65537Mod` for exponentiation instead, as it is more efficient.

include "./FpMul.circom";
include "./FpPow65537Mod.circom";

include "circomlib/circuits/bitify.circom";

// Pkcs1v15 + Sha256
// exp 65537
template RSA_PKCS1_v1_5_Verify(w, nb) {
    //signal input exp[nb];
    signal input sign[nb];      // least-significant-limb first
    signal input modulus[nb];   // least-significant-limb first

    signal input hashed[4];     // least-significant-limb first

    // sign ** exp mod modulus
    component pm = FpPow65537Mod(w, nb);
    for (var i  = 0; i < nb; i++) {
        pm.base[i] <== sign[i];
        //pm.exp[i] <== exp[i];
        pm.modulus[i] <== modulus[i];
    }

    // 1. Check hashed data
    // 64 * 4 = 256 bit. the first 4 numbers
    for (var i = 0; i < 4; i++) {
        hashed[i] === pm.out[i];
    }
    
    // 2. Check hash prefix and 1 byte 0x00
    // sha256/152 bit
    // 0b00110000001100010011000000001101000001100000100101100000100001100100100000000001011001010000001100000100000000100000000100000101000000000000010000100000
    pm.out[4] === 217300885422736416;
    pm.out[5] === 938447882527703397;
    // // remain 24 bit
    component num2bits_6 = Num2Bits(w);
    num2bits_6.in <== pm.out[6];
    var remainsBits[32] = [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 1, 0, 0, 0, 0, 0, 0, 1, 1, 0, 0, 0, 1, 0, 0, 1, 1, 0, 0, 0, 0];
    for (var i = 0; i < 32; i++) {
        num2bits_6.out[i] === remainsBits[31 - i];
    }

    // 3. Check PS and em[1] = 1. the same code like golang std lib rsa.VerifyPKCS1v15
    for (var i = 32; i < w; i++) {
        num2bits_6.out[i] === 1;
    }

    for (var i = 7; i < 31; i++) {
        // 0b1111111111111111111111111111111111111111111111111111111111111111
        pm.out[i] === 18446744073709551615;
    }
    // 0b1111111111111111111111111111111111111111111111111
    pm.out[31] === 562949953421311;
}

