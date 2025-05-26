pragma circom 2.2.2;

include "./SingleOneArray.circom";

// Outputs a `LEN`-bit array `out`, where:
//   out[i] = 1, \forall i \in [0, idx)
//   out[i] = 0, \forall i \in [idx, LEN)
//
// @preconditions
//    LEN > 1
//    0 <= idx < LEN
//
// @param  LEN  the length of the array
//
// @input  idx  the index after which everything is 0; assumed to be < LEN
//              (i.e., out[idx..] = 0 and out[..idx-1] = 1)
// @output out  the bit array
//
// @notes
//    LeftArraySelector(4)(0) -> 0000
//    LeftArraySelector(4)(1) -> 1000
//    LeftArraySelector(4)(2) -> 1100
//    LeftArraySelector(4)(3) -> 1110
//
// TODO(Buses): Assert precondition holds via buses or tags
template LeftArraySelector(LEN) {
    signal input idx;
    signal output out[LEN];

    // SingleOneArray is not satisfiable when idx >= LEN
    signal bits[LEN] <== SingleOneArray(LEN)(idx);
    var sum = 0;
    for (var i = 0; i < LEN; i++) {
        sum = sum + bits[i];
    }

    // TODO: Sum will always be 1 when idx is in bounds, which SingleOneArray enforces,
    // so out[LEN - 1] will always be 0. Confused.
    out[LEN - 1] <== 1 - sum;
    for (var i = LEN - 2; i >= 0; i--) {
        out[i] <== out[i + 1] + bits[i + 1];
    }
}