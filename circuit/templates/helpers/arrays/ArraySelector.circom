pragma circom 2.2.2;

include "./SingleOneArray.circom";
include "./SingleNegOneArray.circom";

include "../../stdlib/functions/assert_bits_fit_scalar.circom";
include "../../stdlib/functions/min_num_bits.circom";

include "circomlib/circuits/bitify.circom";
include "circomlib/circuits/comparators.circom";

// Outputs a bit array with 1s at [start_idx, end_idx) and 0s everywhere else.
//
// If end_idx >= LEN, the bit array will have 1s at [start_idx, LEN) and 0s at [0, start_idx)
//
// The output array can never be all zeros because the worst case is start_idx = LEN - 1.
//
// @param  LEN          the length of outputted bit array
//
// @input  start_idx    the start index
// @input  end_idx      the end index
//
// @output out          the output bit array
//
// @notes
//    ArraySelector(4)(0, 1):
//    [ positions        0  1 2 3 ]
//                       |  | | |
//      start_selector = 1  0 0 0
//      end_selector   = 0 -1 0 0
//      out[0] = 1
//      out[1] = out[0] + start_selector[1] + end_selector[1]
//             = 1 + 0 - 1 = 0
//      out[2] = 0
//      out[3] = 0
//    [       0 1 2 3 positions ]
//            | | | |
//      out = 1 0 0 0
//
//    ArraySelector(4)(0, 0): unsatisfiable
//
//    ArraySelector(4)(1, 3):
//    [ positions        0  1 2 3 ]
//                       |  | | |
//      start_selector = 0  1 0 0
//      end_selector   = 0  0 0 -1
//      out[0] = 0
//      out[1] = out[0] + start_selector[1] + end_selector[1]
//             = 0 + 1 + 0 = 1
//      out[2] = out[1] + start_selector[2] + end_selector[2]
//             = 1 + 0 + 0 = 1
//      out[3] = out[2] + start_selector[3] + end_selector[3]
//             = 1 + 0 - 1 = 0
//    [       0 1 2 3 positions ]
//            | | | |
//      out = 0 1 1 0
//
//    ArraySelector(4)(3, 4):
//      [ positions      0 1 2 3 ]
//                       | | | |
//      start_selector = 0 0 0 1
//      end_selector   = 0 0 0 0 (b.c. SingleNegOneArray returns all
//                                zeros when idx >= LEN)
//    [       0 1 2 3 positions ]
//            | | | |
//      out = 0 0 0 1
//
// @postconditions
//    start_idx < LEN
//    start_idx < end_idx
//
// TODO(Buses): I think we will need a bus to indicate various types of ranges.
// The range here can have end_idx > LEN for example.
template ArraySelector(LEN) {
    signal input start_idx;
    signal input end_idx;
    signal output out[LEN];

    var B = min_num_bits(LEN);
    _ = assert_bits_fit_scalar(B);

    _ <== Num2Bits(B)(start_idx);
    _ <== Num2Bits(B)(end_idx);
    var start_is_less_than_end = LessThan(B)([start_idx, end_idx]);
    start_is_less_than_end === 1;

    signal start_selector[LEN] <== SingleOneArray(LEN)(start_idx);
    signal end_selector[LEN] <== SingleNegOneArray(LEN)(end_idx);

    out[0] <== start_selector[0];
    for (var i = 1; i < LEN; i++) {
        out[i] <== out[i - 1] + start_selector[i] + end_selector[i];
    }
}