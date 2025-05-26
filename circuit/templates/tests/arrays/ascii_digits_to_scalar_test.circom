pragma circom 2.2.2;

include "helpers/arrays.circom";

template check_are_ascii_digits_test(maxLen) {
    signal input digits[maxLen];
    signal input len;
    signal input expected_output;
    
    signal out <== AsciiDigitsToScalar(maxLen)(digits, len);
    expected_output === out;
}

component main = check_are_ascii_digits_test(
   20
);
