pragma circom 2.2.2;

include "circomlib/circuits/comparators.circom";

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
