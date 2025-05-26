pragma circom 2.2.2;

include "../../stdlib/functions/assert_bits_fit_scalar.circom";
include "../../stdlib/functions/min_num_bits.circom";

include "circomlib/circuits/comparators.circom";

// Returns a "minus-one-hot" bit mask with a -1 at index `idx`, and 0s everywhere else.
// Returns a vector of all zeros when idx >= LEN.
//
// @param   LEN       the length of the mask
//
// @input   idx       the index \in [0, LEN) where the bitmask should be 1
// @output  out[LEN]  the "one-hot" bit mask
//
// @warning behaves differently than SingleOneArray: i.e., remains satisfiable even when
//          idx > LEN
//
// TODO: Rename this to make returning all 0s when out of bounds more clear
template SingleNegOneArray(LEN) {
    signal input idx;
    signal output out[LEN];
    signal success;

    var lc = 0;
    for (var i = 0; i < LEN; i++) {
        out[i] <-- (idx == i) ? -1 : 0;
        out[i] * (idx - i) === 0;
        lc = lc + out[i];
    }
    lc ==> success;

    // Allows this template to return all zeros, when idx > LEN
    var B = min_num_bits(LEN);
    _ = assert_bits_fit_scalar(B);
    _ <== Num2Bits(B)(idx);
    signal idx_is_bounded <== LessThan(B)([idx, LEN]);
    success === -1 * idx_is_bounded;

    // Old equivalent code:
    // signal is_out_of_bounds <== GreaterEqThan(20)([idx, LEN]);
    // success === -1 * (1 - is_out_of_bounds);
}