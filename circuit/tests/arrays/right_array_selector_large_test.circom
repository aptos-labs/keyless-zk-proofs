pragma circom 2.2.2;

include "helpers/arrays/RightArraySelector.circom";

template right_array_selector_test(len) {
    signal input index;
    signal input expected_output[len];
    
    signal out[len] <== RightArraySelector(len)(index);
    out === expected_output;
}

component main = right_array_selector_test(
   2000
);
