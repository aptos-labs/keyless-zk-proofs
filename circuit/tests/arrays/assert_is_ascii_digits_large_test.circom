pragma circom 2.2.2;

include "helpers/strings/AssertIsAsciiDigits.circom";

template ascii_digits_test(maxNumDigits) {
    signal input in[maxNumDigits];
    signal input len;
    
    AssertIsAsciiDigits(maxNumDigits)(in, len);
}

component main = ascii_digits_test(
   2000
);
