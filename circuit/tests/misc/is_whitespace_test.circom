
pragma circom 2.2.2;

include "helpers/strings/IsWhitespace.circom";

template is_whitespace_test() {
    signal input char;
    signal input result;
    component is_whitespace = IsWhitespace();
    is_whitespace.char <== char;
    is_whitespace.is_whitespace === result;

}

component main = is_whitespace_test(
);
