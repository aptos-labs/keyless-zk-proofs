pragma circom 2.2.2;

include "helpers/strings/AssertIsConcatenation.circom";

template concatenation_check_test(maxFullStringLen, maxLeftStringLen, maxRightStringLen) {
    signal input full_string[maxFullStringLen];
    signal input left[maxLeftStringLen];
    signal input right[maxRightStringLen];
    signal input left_len;
    signal input right_len;
    
    AssertIsConcatenation(maxFullStringLen, maxLeftStringLen, maxRightStringLen)(full_string, left, right, left_len, right_len);
}

component main = concatenation_check_test(
   100, 70, 70
);
