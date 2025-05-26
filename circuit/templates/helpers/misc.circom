pragma circom 2.2.2;

include "./strings/IsWhitespace.circom";

include "./arrays.circom";
include "./hashtofield.circom";
include "./packing.circom";
include "circomlib/circuits/gates.circom";
include "circomlib/circuits/bitify.circom";

include "../stdlib/circuits/Sum.circom";

// Given input `in`, enforces that `in[0] === in[1]` if `bool` is 1
template AssertEqualIfTrue() {
    signal input in[2];
    signal input bool;

    (in[0]-in[1]) * bool === 0;
}

// Given an input `brackets_depth_map`, which must be an output of `BracketsDepthMap` and
// corresponds to the nested brackets depth of the original JWT, and a `start_index` and `field_len`
// corresponding to the first index and length of a full field in the JWT, fails if the given field
// contains any indices inside nested brackets in the original JWT, and succeeds otherwise
template EnforceNotNested(len) {
    signal input start_index;
    signal input field_len;
    signal input brackets_depth_map[len];

    signal brackets_selector[len] <== ArraySelector(len)(start_index, start_index+field_len);
    signal is_nested <== EscalarProduct(len)(brackets_depth_map, brackets_selector);
    is_nested === 0;
}

// Given an array of ascii characters representing a JSON object, output a binary array demarquing
// the spaces in between quotes, so that the indices in between quotes in `in` are given the value
// `1` in `out`, and are 0 otherwise. Escaped quotes are not considered quotes in this subcircuit
// input =  { asdfsdf "as\"df" }
// output = 00000000000111111000
template StringBodies(len) {
  signal input in[len];
  // TODO(Tags): Enforce binarity in a more type-safe way, rather than just declaring it here.
  signal output {binary} out[len];


  signal quotes[len];
  signal quote_parity[len];
  signal quote_parity_1[len];
  signal quote_parity_2[len];

  signal backslashes[len];
  signal adjacent_backslash_parity[len];

  quotes[0] <== IsEqual()([in[0], 34]); 
  quote_parity[0] <== IsEqual()([in[0], 34]); 

  backslashes[0] <== IsEqual()([in[0], 92]);
  adjacent_backslash_parity[0] <== IsEqual()([in[0], 92]);

  for (var i = 1; i < len; i++) {
    backslashes[i] <== IsEqual()([in[i], 92]);
    adjacent_backslash_parity[i] <== backslashes[i] * (1 - adjacent_backslash_parity[i-1]);
  }

  for (var i = 1; i < len; i++) {
    var is_quote = IsEqual()([in[i], 34]); 
    var prev_is_odd_backslash = adjacent_backslash_parity[i-1];
    quotes[i] <== is_quote * (1 - prev_is_odd_backslash); // 1 iff there is a non-escaped quote at this position
    quote_parity[i] <== XOR()(quotes[i], quote_parity[i-1]);
  }
  // input =               { asdfsdf "asdf" }
  // intermediate output = 000000000011111000
  // i.e., still has offset-by-one error

  out[0] <== 0;

  for (var i = 1; i < len; i++) {
    out[i] <== AND()(quote_parity[i-1], quote_parity[i]); // remove offset error
  }
}

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
template BracketsMap(len) {
    signal input arr[len];
    signal output brackets[len];

    for (var i = 0; i < len; i++) {
        var is_open_bracket = IsEqual()([arr[i], 123]); // 123 = `{`
        var is_closed_bracket = IsEqual()([arr[i], 125]); // 125 = '}'
        brackets[i] <== is_open_bracket + (0-is_closed_bracket);
    }
}

// Given an input array `arr` of length `len` containing `1`s corresponding to open
// brackets `{`, `-1`s corresponding to closed brackets `}`, and 0s everywhere else, outputs an array
// containing a positive integer in each index between nested brackets which indicates the depth
// of the brackets nesting at that index, and 0 everywhere else. The outermost open and
// closed bracket are both ignored. The open and closed brackets are not considered to be inside
// their bracketed area. It is assumed that the input will contain an equal
// number of closed and open brackets, and that a closed bracket will not appear while there are no unclosed open brackets
// The basic algorithm is:
// 1. Compute an intermediate array where each index is a running sum of all previous indices in the input
// 2. Subtract 1 from each index in the result of step 1 to get a new array. This corresponds to ignoring the single pair of outermost brackets in the running sum from step 1
// 3. For each negative value in the result of step 2, change that value to 0
// 4. For each value greater than 1 compared to the previous value in the result of step 3, decrement that value by 1. This is to fix an off-by-1 error with step 1 in computing nested brackets depth, so that each depth excludes its open bracket. I.e.
// step 4 in:  001112233332100
// step 4 out: 000111223332100
// Example input/output for the entire subcircuit, plus intermediate values
// To preserve alignment, we use * to represent -1:
// str:           a{aaa{a{aaa}aa}aaaa}
// arr:           01000101000*00*0000*
// prelim_out1:   01111223333222111110   full depth map incorrectly including open brackets inside bracket depth counts
// prelim_out2:   *000011222211100000*   removes outermost brackets from depth map
// prelim_out3:   00000112222111000000   replaces negative values with 0s
// out:           00000011222111000000   correctly represents open brackets as being outside of bracket nesting
// out: 0000001122 11 0000 0
template BracketsDepthMap(len) {
    signal input arr[len];
    signal output out[len];

    signal prelim_out1[len];
    signal prelim_out2[len];
    signal prelim_out3[len];
    prelim_out1[0] <== arr[0];
    for (var i = 1; i < len; i++) {
        prelim_out1[i] <== prelim_out1[i-1] + arr[i];
    }

    // Subtracting 1 here from every index amounts to ignoring the outermost
    // open and closed brackets, which is what we want
    for (var i = 0; i < len; i++) {
        prelim_out2[i] <== prelim_out1[i]-1;
    }
    // Remove all negative numbers from the array and set their indices to 0
    for (var i = 0; i < len; i++) {
        var is_neg = LessThan(20)([prelim_out2[i], 0]);
        prelim_out3[i] <== prelim_out2[i] * (1-is_neg);
    }
    // Decrement the positions of open brackets by 1 to remove offset
    for (var i = 1; i < len; i++) {
        var is_inc = IsEqual()([prelim_out3[i], prelim_out3[i-1]+1]);
        out[i] <== prelim_out3[i] - is_inc;
    }
}
