pragma circom 2.2.2;

include "helpers/bigint/BigLessThan.circom";

template big_less_than_test() {
    signal input a[32];
    signal input b[32];
    signal input expected_output;
    component c1 = BigLessThan(252, 32); // `keyless` circom template's usage
    c1.a <== a;
    c1.b <== b;
    expected_output === c1.out;
    log("hi", c1.out);
}

component main = big_less_than_test();
