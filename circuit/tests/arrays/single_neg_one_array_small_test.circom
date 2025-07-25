pragma circom 2.2.2;

include "helpers/arrays/SingleNegOneArray.circom";

template single_neg_one_array_test(len) {
    signal input index;
    signal input expected_output[len];
    
    signal out[len] <== SingleNegOneArray(len)(index);
    out === expected_output;
}

component main = single_neg_one_array_test(
   1
);
