pragma circom 2.2.2;

include "stdlib/circuits/InvertBinaryArray.circom";

template invert_binary_array_test(len) {
    signal input in[len];
    signal input expected_out[len];

    signal {binary} tagged[len];
    for (var i = 0; i < len; i++) {
        tagged[i] <== in[i];
    }
    
    signal out[len] <== InvertBinaryArray(len)(tagged);
    for (var i = 0; i < len; i++) {
        out[i] === expected_out[i];
    }
}

component main = invert_binary_array_test(
   4
);
