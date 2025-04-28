pragma circom 2.2.2;

include "helpers/arrays.circom";

template elementwise_mul_test(len) {
    signal input left[len];
    signal input right[len];
    signal input expected_out[len];

    signal out[len] <== ElementwiseMul(len)(left, right);
    for (var i = 0; i < len; i++) {
        out[i] === expected_out[i];
    }
}

component main = elementwise_mul_test(
   4
);
