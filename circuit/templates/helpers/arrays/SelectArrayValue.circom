pragma circom 2.2.2;

include "./SingleOneArray.circom";

include "circomlib/circuits/multiplexer.circom";

// Indexes into an array of signals, returning the value at that index.
//
// @param  LEN      the length of the array 
//
// @input  arr[LEN] the array of length `LEN`
// @input  i        the location in the array to be fetched; must have i \in [0, LEN)
// @output out      arr[i]
//
// TODO(Buses): Use an Index(LEN) bus here to ensure `0 <= i < LEN`.
// TODO: Rename to ArrayGet
template SelectArrayValue(LEN) {
    signal input arr[LEN];
    signal input i;
    signal output out;

    signal mask[LEN] <== SingleOneArray(LEN)(i);

    out <== EscalarProduct(LEN)(arr, mask);
}