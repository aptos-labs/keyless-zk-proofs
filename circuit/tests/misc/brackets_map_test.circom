pragma circom 2.2.2;

include "helpers/jwt/BracketsMap.circom";

template brackets_map_test() {
    var len = 13;
    signal input in[len];
    signal input brackets[len];
    component brackets_map = BracketsMap(len);
    brackets_map.arr <== in;
    for (var i = 0; i < len; i++) {
        brackets[i] === brackets_map.brackets[i];
    }
}

component main = brackets_map_test();
