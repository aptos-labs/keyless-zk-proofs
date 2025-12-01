pragma circom 2.2.2;

include "./FpMul.circom";

// Template copied from https://github.com/doubleblind-xyz/circom-rsa/blob/master/circuits/rsa.circom
template FpPow65537Mod(n, K) {
    signal input base[K];
    // Exponent is hardcoded at 65537
    signal input modulus[K];
    signal output out[K];

    component doublers[16];
    component adder = FpMul(n, K);
    for (var i = 0; i < 16; i++) {
        doublers[i] = FpMul(n, K);
    }

    for (var j = 0; j < K; j++) {
        adder.p[j] <== modulus[j];
        for (var i = 0; i < 16; i++) {
            doublers[i].p[j] <== modulus[j];
        }
    }
    for (var j = 0; j < K; j++) {
        doublers[0].a[j] <== base[j];
        doublers[0].b[j] <== base[j];
    }
    for (var i = 0; i + 1 < 16; i++) {
        for (var j = 0; j < K; j++) {
            doublers[i + 1].a[j] <== doublers[i].out[j];
            doublers[i + 1].b[j] <== doublers[i].out[j];
        }
    }
    for (var j = 0; j < K; j++) {
        adder.a[j] <== base[j];
        adder.b[j] <== doublers[15].out[j];
    }
    for (var j = 0; j < K; j++) {
        out[j] <== adder.out[j];
    }
}
