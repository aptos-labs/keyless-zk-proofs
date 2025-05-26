pragma circom 2.2.2;

include "helpers/strings/AsciiDigitsToScalar.circom";

template ascii_digits_test(maxLen) {
    signal input digits[maxLen];
    signal input len;
    signal input expected_output;
    
    signal out <== AsciiDigitsToScalar(maxLen)(digits, len);
    expected_output === out;
}

component main = ascii_digits_test(
   20
);
