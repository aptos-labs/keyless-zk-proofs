
pragma circom 2.2.2;

include "stdlib/circuits/ConditionallyAssertEqual.circom";

template Test() {
    signal input in[2];
    signal input bool;

    signal {binary} bool_tagged <== bool;

    ConditionallyAssertEqual()(in, bool_tagged);
}

component main = Test();
