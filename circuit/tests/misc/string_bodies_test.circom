

pragma circom 2.2.2;

include "helpers/jwt/StringBodies.circom";

template string_bodies_test() {
    var len = 13;
    signal input in[len];
    signal input out[len];
    component string_bodies = StringBodies(len);
    string_bodies.in <== in;
    string_bodies.out === out;

}

component main = string_bodies_test(
);
