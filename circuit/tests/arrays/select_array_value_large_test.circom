pragma circom 2.2.2;

include "helpers/arrays/SelectArrayValue.circom";

template select_array_value_test(len) {
    signal input array[len];
    signal input index;
    signal input expected_output;
    
    signal out <== SelectArrayValue(len)(array, index);
    out === expected_output;
}

component main = select_array_value_test(
   2000
);
