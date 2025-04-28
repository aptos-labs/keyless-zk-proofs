pragma circom 2.2.2;

include "helpers/misc.circom";

template brackets_depth_map_test() {
    var len = 15;
    signal input in[len];
    signal input brackets[len];
    component brackets_depth_map = BracketsDepthMap(len);
    brackets_depth_map.arr <== in;
    for (var i = 0; i < len; i++) {
        log("out ", i, ": ", brackets_depth_map.out[i]);
    }
    for (var i = 0; i < len; i++) {
        log("in ", i, ": ", in[i]);
    }
    for (var i = 0; i < len; i++) {
        log("expected result ", i, ": ", brackets[i]);
    }
    for (var i = 0; i < len; i++) {
        brackets[i] === brackets_depth_map.out[i];
    }
}

component main = brackets_depth_map_test();
