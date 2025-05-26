pragma circom 2.2.2;

include "./LeftArraySelector.circom";
include "./RightArraySelector.circom";

include "circomlib/circuits/comparators.circom";

// Like ArraySelector, but works when end_idx > start_idx is not satisfied, in which
// case an array of all 0s is returned. Does NOT work when start_idx is 0.
//
// TODO: Rename to something more clear
// TODO: "Does not work when start_idx = 0" is just an artifact or something done on purpose?
template ArraySelectorComplex(LEN) {
    signal input start_idx;
    signal input end_idx;
    signal output out[LEN];

    signal start_idx_is_zero <== IsZero()(start_idx);
    start_idx_is_zero === 0;

    signal right_bits[LEN] <== RightArraySelector(LEN)(start_idx - 1);
    signal left_bits[LEN] <== LeftArraySelector(LEN)(end_idx);

    for (var i = 0; i < LEN; i++) {
        out[i] <== right_bits[i] * left_bits[i]; 
    }
}