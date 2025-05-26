pragma circom 2.2.2;

// for EscalarProduct
include "circomlib/circuits/multiplexer.circom";
include "circomlib/circuits/comparators.circom";
include "./hashtofield.circom";
include "./misc.circom";

include "./arrays/SingleOneArray.circom";
include "./arrays/SingleNegOneArray.circom";
include "./arrays/ArraySelector.circom";
include "./arrays/LeftArraySelector.circom";
include "./arrays/RightArraySelector.circom";
include "./arrays/ArraySelectorComplex.circom";
include "./arrays/SelectArrayValue.circom";
include "./arrays/IsSubstring.circom";

include "../stdlib/circuits/ElementwiseMul.circom";
include "../stdlib/circuits/InvertBinaryArray.circom";

include "../stdlib/functions/assert_bits_fit_scalar.circom";
include "../stdlib/functions/min_num_bits.circom";

// Given `full_string`, `left`, and `right`, checks that full_string = left || right 
// `random_challenge` is expected to be computed by the Fiat-Shamir transform
// Assumes `right_len` has been validated to be correct outside of this subcircuit, i.e. that
// `right` is 0-padded after `right_len` values
// Enforces:
// - that `left` is 0-padded after `left_len` values
// - full_string = left || right where || is concatenation
template AssertIsConcatenation(maxFullStringLen, maxLeftStringLen, maxRightStringLen) {
    signal input full_string[maxFullStringLen];
    signal input left[maxLeftStringLen];
    signal input right[maxRightStringLen];
    signal input left_len;
    signal input right_len;
    
    signal left_hash <== HashBytesToFieldWithLen(maxLeftStringLen)(left, left_len); 
    signal right_hash <== HashBytesToFieldWithLen(maxRightStringLen)(right, right_len);
    signal full_hash <== HashBytesToFieldWithLen(maxFullStringLen)(full_string, left_len+right_len);
    signal random_challenge <== Poseidon(4)([left_hash, right_hash, full_hash, left_len]);

    // Enforce that all values to the right of `left_len` in `left` are 0-padding. Otherwise an attacker could place the leftmost part of `right` at the end of `left` and still have the polynomial check pass
    signal left_selector[maxLeftStringLen] <== RightArraySelector(maxLeftStringLen)(left_len-1);
    for (var i = 0; i < maxLeftStringLen; i++) {
        left_selector[i] * left[i] === 0;
    }
        

    signal challenge_powers[maxFullStringLen];
    challenge_powers[0] <== 1;
    challenge_powers[1] <== random_challenge;
    for (var i = 2; i < maxFullStringLen; i++) {
       challenge_powers[i] <== challenge_powers[i-1] * random_challenge; 
    }
    
    signal left_poly[maxLeftStringLen];
    for (var i = 0; i < maxLeftStringLen; i++) {
       left_poly[i] <== left[i] * challenge_powers[i];
    }

    signal right_poly[maxRightStringLen];
    for (var i = 0; i < maxRightStringLen; i++) {
        right_poly[i] <== right[i] * challenge_powers[i];
    }

    signal full_poly[maxFullStringLen];
    for (var i = 0; i < maxFullStringLen; i++) {
        full_poly[i] <== full_string[i] * challenge_powers[i];
    }

    signal left_poly_eval <== Sum(maxLeftStringLen)(left_poly);
    signal right_poly_eval <== Sum(maxRightStringLen)(right_poly);
    signal full_poly_eval <== Sum(maxFullStringLen)(full_poly);

    var distinguishing_value = SelectArrayValue(maxFullStringLen)(challenge_powers, left_len);

    full_poly_eval === left_poly_eval + distinguishing_value * right_poly_eval;
}

// Enforces that every value in `in` between 0 and len-1 are valid ASCII digits, i.e. are between
// 48 and 57 inclusive
template CheckAreASCIIDigits(maxNumDigits) {
    signal input in[maxNumDigits];
    signal input len;

    signal selector[maxNumDigits] <== ArraySelector(maxNumDigits)(0, len);
    for (var i = 0; i < maxNumDigits; i++) {
        // TODO(Perf): Since numbers are in [48, 58) and 58 is less than 64 = 2^6,
        //   we could use 6 bits below. But the Num2Bits(6) call would be applied
        //   to elements after in[len-1], which may not necessarily be 6 bits anymore.
        //   So, we need extra conditional logic here.
        _ <== Num2Bits(9)(in[i]);
        var is_less_than_max = LessThan(9)([in[i], 58]);
        var is_greater_than_min = GreaterThan(9)([in[i], 47]);
        var is_ascii_digit = AND()(is_less_than_max, is_greater_than_min);
        (1 - is_ascii_digit) * selector[i] === 0;
    }
}

// Given a string of digits in ASCII format, returns the digits represented as a single field element
// Assumes:
// - the number represented by the ASCII `digits` is smaller than the scalar field used by the circuit
// - `digits` contains only ASCII digit values between 48 and 57 inclusive
// Does not work when maxLen = 1
template ASCIIDigitsToField(maxLen) {
    signal input digits[maxLen]; 
    signal input len; 
    signal output out;

    CheckAreASCIIDigits(maxLen)(digits, len);
    // Set to 0 everywhere except len-1, which is 1
    signal index_eq[maxLen - 1];

    // For ASCII digits ['1','2','3','4','5'], acc_shifts[0..3] is [12,123,1234]
    signal acc_shifts[maxLen - 1];
    // accumulators[i] = acc_shifts[i-1] for all i < len, otherwise accumulators[i] = accumulators[i-1]
    signal accumulators[maxLen];

    signal success;
    var index_eq_sum = 0;
    // `s` is initially set to 1 and is 0 after len == i
    var s = 1; 

    accumulators[0] <== digits[0]-48;
    for (var i=1; i<maxLen; i++) {
        index_eq[i-1] <-- (len == i) ? 1 : 0;
        index_eq[i-1] * (len-i) === 0;

        s = s - index_eq[i-1];
        index_eq_sum = index_eq_sum + index_eq[i-1];

        acc_shifts[i-1] <== 10 * accumulators[i-1] + (digits[i]-48);
        // // This implements a conditional assignment: accumulators[i] = (s == 0 ? accumulators[i-1] : acc_shifts[i-1]);
        accumulators[i] <== (acc_shifts[i-1] - accumulators[i-1])*s + accumulators[i-1];
    }

    index_eq_sum ==> success;
    // Guarantee at most one element of index_eq is equal to 1
    success === 1;

    out <== accumulators[maxLen - 1];
}

