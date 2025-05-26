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

include "../stdlib/circuits/ElementwiseMul.circom";
include "../stdlib/circuits/InvertBinaryArray.circom";

include "../stdlib/functions/assert_bits_fit_scalar.circom";
include "../stdlib/functions/min_num_bits.circom";

// Checks that `substr` of length `substr_len` matches `str` beginning at `start_index`
// Assumes `random_challenge` is computed by the Fiat-Shamir (FS) transform
// Takes in hash of the full string as an optimization, to prevent it being hashed 
// multiple times if the template is invoked on that string more than once, which
// is very expensive in terms of constraints
// Assumes that:
// - `str_hash` is the hash of `str`
// - `substr` is 0-padded after `substr_len` characters
// Enforces that:
// - `str[start_index:substr_len]` = `substr[0:substr_len]`
// TODO: Rename to AssertIsSubstrFromPos()
template AssertIsSubstring(maxStrLen, maxSubstrLen) {
    signal input str[maxStrLen];
    signal input str_hash;
    signal input substr[maxSubstrLen];
    signal input substr_len;
    signal input start_index;

    signal success <== IsSubstring(maxStrLen, maxSubstrLen)(
        str, str_hash, substr, substr_len, start_index
    );

    success === 1;
}

// Checks that `substr` is a substring of `str`.
//
// TODO: Rename to IsSubstrFromPos()
//
// Parameters:
//   maxStrLen      the maximum length of `str`
//   maxSubStrLen   the maximum length of `substr`
//
// Input signals:
//   str            the string, 0-padded; note that we do not take its length as a
//                  parameter since the 0-padding serves all our needs here.
//   str_hash       its pre-computed hash (for Fiat-Shamir), to avoid  re-hashing
//                  when repeatedly calling this template on `str`
//                  ( i.e., `HashBytesToFieldWithLen(maxStrLen)(str, str_len)` )
//   substr         the substring, also 0-padded; will be searched for within `str`
//   substr_len     the substring's length in bytes; the bytes after this will be 0
//   start_index    the starting index of `substr` in `str`
//
// Output signals
//   success        1 if `substr` starts at `start_index` in `str` and ends at
//                  `start_index + substr_len - 1`. Otherwise, 0.
//
template IsSubstring(maxStrLen, maxSubstrLen) {
    // Note: It does make sense to call this when maxStrLen == maxSubstrLen because
    // we may still have len(substr) < len(str) even though they have the same max
    // length
    assert(maxSubstrLen <= maxStrLen);

    signal input str[maxStrLen];
    signal input str_hash;

    signal input substr[maxSubstrLen];
    signal input substr_len;

    // The index of `substr` in `str`:
    //
    //   str[start_index]                    = substr[0]
    //   str[start_index + 1]                = substr[1]
    //   ...............................................
    //   str[start_index + (substr_len - 1)] = substr[substr_len - 1]
    signal input start_index;

    signal output success;

    // H(substr[0], substr[1], ..., substr[maxSubstrLen], 0, 0, ..., 0, substr_len)
    signal substr_hash <== HashBytesToFieldWithLen(maxSubstrLen)(substr, substr_len);

    // Computes the Fiat-Shamir (FS) transform challenge.
    // `random_challenge = H(str_hash, substr_hash, substr_len, start_index)`
    // TODO(Perf): Unnecessary to hash substr_len here, since substr_hash already contains it.
    signal random_challenge <== Poseidon(4)([str_hash, substr_hash, substr_len, start_index]);

    // \alpha^0, \alpha^1, \ldots, \alpha^N (where N = maxStrLen)
    signal challenge_powers[maxStrLen];
    challenge_powers[0] <== 1;
    challenge_powers[1] <== random_challenge;
    for (var i = 2; i < maxStrLen; i++) {
        challenge_powers[i] <== challenge_powers[i-1] * random_challenge;
    }

    // TODO(Buses): Exactly the place where we would want an Index(N) bus that stores an `index` and guarantees `0 <= index < N`.
    signal selector_bits[maxStrLen] <== ArraySelector(maxStrLen)(start_index, start_index+substr_len); 

    // Set all characters to zero, and leave `str[start_index : start_index + (substr_len - 1)]` the same.
    signal selected_str[maxStrLen];
    for (var i = 0; i < maxStrLen; i++) {
        selected_str[i] <== selector_bits[i] * str[i];
    }
    
    // Let \hat{s}(X) be a polynomial whose coefficients are in `selected_str`
    signal str_poly[maxStrLen];
    for (var i = 0; i < maxStrLen; i++) {
        str_poly[i] <== selected_str[i] * challenge_powers[i];
    }

    // Let t(X) be a polynomial whose coefficients are in `substr`.
    signal substr_poly[maxSubstrLen];
    for (var i = 0; i < maxSubstrLen; i++) {
        substr_poly[i] <== substr[i] * challenge_powers[i];
    }

    // Computes \hat{s}(\alpha)
    signal str_poly_eval <== Sum(maxStrLen)(str_poly);

    // Computes t(\alpha)
    signal substr_poly_eval <== Sum(maxSubstrLen)(substr_poly);

    // Returns \alpha^{start_index}
    // TODO: rename to shift_value
    signal distinguishing_value <== SelectArrayValue(maxStrLen)(challenge_powers, start_index);

    // Fail if ArraySelector returns all 0s
    //
    // assert str_poly_eval != 0 && str_poly_eval == distinguishing_value * substr_poly_eval
    success <== AND()(
        NOT()(IsZero()(str_poly_eval)),
        // \hat{s}(\alpha) == \alpha^{start_index} t(\alpha)
        IsEqual()([
            str_poly_eval,
            distinguishing_value * substr_poly_eval
        ])
    );
}

// Given `full_string`, `left`, and `right`, checks that full_string = left || right 
// `random_challenge` is expected to be computed by the Fiat-Shamir transform
// Assumes `right_len` has been validated to be correct outside of this subcircuit, i.e. that
// `right` is 0-padded after `right_len` values
// Enforces:
// - that `left` is 0-padded after `left_len` values
// - full_string = left || right where || is concatenation
template ConcatenationCheck(maxFullStringLen, maxLeftStringLen, maxRightStringLen) {
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

