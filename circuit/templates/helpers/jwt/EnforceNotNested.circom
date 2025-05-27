pragma circom 2.2.2;

include "../arrays/ArraySelector.circom";

include "circomlib/circuits/multiplexer.circom";

// Given an input `brackets_depth_map`, which must be an output of `BracketsDepthMap` and
// corresponds to the nested brackets depth of the original JWT, and a `start_index` and `field_len`
// corresponding to the first index and length of a full field in the JWT, fails if the given field
// contains any indices inside nested brackets in the original JWT, and succeeds otherwise
template EnforceNotNested(len) {
    signal input start_index;
    signal input field_len;
    signal input brackets_depth_map[len];

    signal brackets_selector[len] <== ArraySelector(len)(start_index, start_index + field_len);
    signal is_nested <== EscalarProduct(len)(brackets_depth_map, brackets_selector);
    is_nested === 0;
}