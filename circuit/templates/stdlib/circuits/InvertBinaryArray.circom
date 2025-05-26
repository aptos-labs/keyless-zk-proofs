pragma circom 2.2.2;

// Given a binary array, returns an "inverted" array where where bits are flipped.
//
// @param   LEN                 the length of the array
//
// @input   in[LEN]  {binary}   the input array of bits
// @output  out[LEN] {binary}   the output array of flipped bits
//
// @notes
//   Enforces at compile time that `in` contains only 1s and 0s via the {binary} tag.
template InvertBinaryArray(LEN) {
    signal input {binary} in[LEN];
    signal output {binary} out[LEN];

    for (var i = 0; i < LEN; i++) {
        out[i] <== 1 - in[i];
    }
}