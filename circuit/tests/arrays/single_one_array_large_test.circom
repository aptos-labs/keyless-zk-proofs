pragma circom 2.2.2;

include "helpers/arrays/SingleOneArray.circom";

template single_one_array_test(len) {
    signal input index;
    signal input expected_output[len];
    
    signal out[len] <== SingleOneArray(len)(index);
    out === expected_output;
}

component main = single_one_array_test(
   2000
);
