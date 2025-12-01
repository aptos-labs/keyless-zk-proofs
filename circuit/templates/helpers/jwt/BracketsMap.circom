pragma circom 2.2.2;

include "circomlib/circuits/comparators.circom";

// Given an array of ASCII characters `arr`, returns an array `brackets` with
// a 1 in the position of each open bracket `{`, a -1 in the position of each closed bracket `}`
// and 0 everywhere else.
//
// See an example below. The real string is `arr` but we re-display it with "fake" spaces in `align_arr` 
// to more easily showcase which character in `arr` corresponds to the `-1` in `brackets`.
// arr:       {he{llo{}world!}}
// align_arr: {he{llo{ }world! } }
// brackets:  10010001-1000000-1-1
//
// where `arr` is represented by its ASCII encoding, i.e. `{` = 123
template BracketsMap(LEN) {
    signal input arr[LEN];
    signal output brackets[LEN];

    for (var i = 0; i < LEN; i++) {
        var is_open_bracket = IsEqual()([arr[i], 123]); // 123 = `{`
        var is_closed_bracket = IsEqual()([arr[i], 125]); // 125 = '}'
        brackets[i] <== is_open_bracket + (0 - is_closed_bracket);
    }
}
