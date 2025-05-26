pragma circom 2.2.2;

include "./SingleOneArray.circom";

// Outputs a `LEN`-bit array `out`, where:
//   out[i] = 0, \forall i \in [0, idx]
//   out[i] = 1, \forall i \in (idx, LEN)
//
// @preconditions
//    0 <= idx < LEN
//
// @param  LEN  the length of the array
//
// @input  idx  the index after which everything is 1; assumed to be < LEN
//              (i.e., out[idx+1..] = 1 and out[..idx] =0)
// @output out  the bit array
//
// @notes
//    RightArraySelector(4)(0) -> 0111
//    RightArraySelector(4)(1) -> 0011
//    RightArraySelector(4)(2) -> 0001
//    RightArraySelector(4)(3) -> 0000
//
// TODO(Buses): Assert precondition holds via buses or tags
template RightArraySelector(LEN) {
    signal input idx;
    signal output out[LEN];

    // SingleOneArray is not satisfiable when idx >= LEN
    signal bits[LEN] <== SingleOneArray(LEN)(idx);

    out[0] <== 0;
    for (var i = 1; i < LEN; i++) {
        out[i] <== out[i - 1] + bits[i - 1];
    }
}