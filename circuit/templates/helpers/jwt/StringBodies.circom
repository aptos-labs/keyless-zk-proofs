pragma circom 2.2.2;

include "circomlib/circuits/comparators.circom";
include "circomlib/circuits/gates.circom";

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