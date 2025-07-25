pragma circom 2.2.2;

include "helpers/arrays/LeftArraySelector.circom";

template left_array_selector_test(len) {
    signal input index;
    signal input expected_output[len];
    
    signal out[len] <== LeftArraySelector(len)(index);
    out === expected_output;
}

component main = left_array_selector_test(
   2000
);
