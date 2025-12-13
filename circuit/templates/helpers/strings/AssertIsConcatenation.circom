pragma circom 2.2.2;

include "../arrays/RightArraySelector.circom";
include "../arrays/SelectArrayValue.circom";

include "../../stdlib/circuits/Sum.circom";

include "circomlib/circuits/comparators.circom";
include "circomlib/circuits/poseidon.circom";

// Given `full_string`, `left`, and `right`, checks that full_string = left || right 
// `random_challenge` is expected to be computed by the Fiat-Shamir transform
// Assumes `right_len` has been validated to be correct outside of this subcircuit, i.e. that
// `right` is 0-padded after `right_len` values
// Enforces:
// - that `left` is 0-padded after `left_len` values
// - full_string = left || right where || is concatenation
template AssertIsConcatenation(MAX_FULL_STR_LEN, MAX_LEFT_STR_LEN, MAX_RIGHT_STR_LEN) {
    signal input full_string[MAX_FULL_STR_LEN];
    signal input full_hash;
    signal input left[MAX_LEFT_STR_LEN];
    signal input left_len;
    signal input left_hash;
    signal input right[MAX_RIGHT_STR_LEN];
    signal input right_len;
    signal input right_hash;
    
    signal random_challenge <== Poseidon(4)([left_hash, right_hash, full_hash, left_len]);

    // Enforce that all values to the right of `left_len` in `left` are 0-padding. Otherwise an attacker could place the leftmost part of `right` at the end of `left` and still have the polynomial check pass
    signal left_selector[MAX_LEFT_STR_LEN] <== RightArraySelector(MAX_LEFT_STR_LEN)(left_len-1);
    for (var i = 0; i < MAX_LEFT_STR_LEN; i++) {
        left_selector[i] * left[i] === 0;
    }
        
    signal challenge_powers[MAX_FULL_STR_LEN];
    challenge_powers[0] <== 1;
    challenge_powers[1] <== random_challenge;
    for (var i = 2; i < MAX_FULL_STR_LEN; i++) {
       challenge_powers[i] <== challenge_powers[i-1] * random_challenge; 
    }
    
    signal left_poly[MAX_LEFT_STR_LEN];
    for (var i = 0; i < MAX_LEFT_STR_LEN; i++) {
       left_poly[i] <== left[i] * challenge_powers[i];
    }

    signal right_poly[MAX_RIGHT_STR_LEN];
    for (var i = 0; i < MAX_RIGHT_STR_LEN; i++) {
        right_poly[i] <== right[i] * challenge_powers[i];
    }

    signal full_poly[MAX_FULL_STR_LEN];
    for (var i = 0; i < MAX_FULL_STR_LEN; i++) {
        full_poly[i] <== full_string[i] * challenge_powers[i];
    }

    signal left_poly_eval <== Sum(MAX_LEFT_STR_LEN)(left_poly);
    signal right_poly_eval <== Sum(MAX_RIGHT_STR_LEN)(right_poly);
    signal full_poly_eval <== Sum(MAX_FULL_STR_LEN)(full_poly);

    var distinguishing_value = SelectArrayValue(MAX_FULL_STR_LEN)(challenge_powers, left_len);

    full_poly_eval === left_poly_eval + distinguishing_value * right_poly_eval;
}
