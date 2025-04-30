pragma circom 2.2.2;

// for EscalarProduct
include "circomlib/circuits/multiplexer.circom";
include "circomlib/circuits/comparators.circom";
include "./hashtofield.circom";
include "./misc.circom";

include "../stdlib/functions/assert_bits_fit_scalar.circom";
include "../stdlib/functions/min_num_bits.circom";

// Outputs a bit array where indices [start_index, end_index) (inclusive of start_index, exclusive of end_index) are all 1, and all other bits are 0.
// If end_index >= len, returns a bit array where start_index and all indices after it are 1, and all other bits are 0.
template ArraySelector(len) {
    signal input start_index;
    signal input end_index;
    signal output out[len];
    var start_less_than_end = LessThan(20)([start_index, end_index]);
    start_less_than_end === 1;

    signal start_selector[len] <== SingleOneArray(len)(start_index);
    signal end_selector[len] <== SingleNegOneArray(len)(end_index);

    out[0] <== start_selector[0];
    for (var i = 1; i < len; i++) {
        out[i] <== out[i-1] + start_selector[i] + end_selector[i];
    }
}

// Similar to ArraySelector, but works when end_index > start_index is not satisfied, in which
// case an array of all 0s is returned. Does NOT work when start_index is 0
template ArraySelectorComplex(len) {
    signal input start_index;
    signal input end_index;
    signal output out[len];
    signal should_fail <== IsEqual()([start_index, 0]);
    should_fail === 0;

    signal right_bits[len] <== RightArraySelector(len)(start_index-1);
    signal left_bits[len] <== LeftArraySelector(len)(end_index);

    for (var i = 0; i < len; i++) {
        out[i] <== right_bits[i] * left_bits[i]; 
    }
}

// Outputs a bit array where all bits to the right of `index` are 0, and all other bits including `index` are 1
// Assumes that 0 <= index < len, and that len > 1
template LeftArraySelector(len) {
    signal input index;
    signal output out[len];

    // SingleOneArray will fail if index >= len
    signal bits[len] <== SingleOneArray(len)(index);
    var sum = 0;
    for (var i = 0; i < len; i++) {
        sum = sum + bits[i];
    }

    out[len-1] <== 1 - sum;
    for (var i = len-2; i >= 0; i--) {
        out[i] <== out[i+1] + bits[i+1];
    }
}

// Outputs a bit array where all bits to the left of `index` are 0, and all other bits are 1 including `index`
// Assumes that 0 <= index < len
template RightArraySelector(len) {
    signal input index;
    signal output out[len];

    // SingleOneArray fails if index >= len
    signal bits[len] <== SingleOneArray(len)(index);

    out[0] <== 0;
    for (var i = 1; i < len; i++) {
        out[i] <== out[i-1] + bits[i-1];
    }
}

// Returns the elementwise (Hadamard) product of two arrays: i.e., another array whose
// ith entry is the product of the ith entries in the two arrays.
//
// @param  LEN  the length of the two input arrays
//
// @input  lhs  the first input array
// @input  rhs  the second input array
//
// @output out  the Hadamard product of the two arrays
//
// @warning  this could cause integer overflow if the product of any two multiplied
//           elements exceeds the field modulus
//
// TODO: rename to HadamardProduct or ElementwiseProduct
template ElementwiseMul(LEN) {
    signal input lhs[LEN];
    signal input rhs[LEN];
    signal output out[LEN];

    for (var i = 0; i < LEN; i++) {
        out[i] <== lhs[i] * rhs[i];
    }
}

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

// Returns a "one-hot" bit mask with a 1 at index `idx`, and 0s everywhere else.
// Only satisfiable when 0 <= idx < LEN.
//
// @param   LEN       the length of the mask
//
// @input   idx       the index \in [0, LEN) where the bitmask should be 1
// @output  out[LEN]  the "one-hot" bit mask
//
// @notes
//   Similar to Decoder template from [circomlib](https://github.com/iden3/circomlib/blob/35e54ea21da3e8762557234298dbb553c175ea8d/circuits/multiplexer.circom#L78), except
//   it does NOT return all zeros when idx > LEN.
template SingleOneArray(LEN) {
    signal input idx;
    signal output out[LEN];

    signal success;
    var lc = 0;

    for (var i = 0; i < LEN; i++) {
        out[i] <-- (idx == i) ? 1 : 0;
        // Enforces that either: out[i] == 0, or idx == i
        out[i] * (idx - i) === 0;
        lc = lc + out[i];
    }
    lc ==> success;

    // Enforces that `lc` is equal to 1, when idx \in [0, LEN)
    success === 1;
}

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

// Returns a "minus-one-hot" bit mask with a -1 at index `idx`, and 0s everywhere else.
// Returns a vector of all zeros when idx >= LEN.
//
// @param   LEN       the length of the mask
//
// @input   idx       the index \in [0, LEN) where the bitmask should be 1
// @output  out[LEN]  the "one-hot" bit mask
//
// @warning behaves differently than SingleOneArray: i.e., remains satisfiable even when
//          idx > LEN
//
// TODO: Rename this to make returning all 0s when out of bounds more clear
template SingleNegOneArray(LEN) {
    signal input idx;
    signal output out[LEN];
    signal success;

    var lc = 0;
    for (var i = 0; i < LEN; i++) {
        out[i] <-- (idx == i) ? -1 : 0;
        out[i] * (idx - i) === 0;
        lc = lc + out[i];
    }
    lc ==> success;

    // Allows this template to return all zeros, when idx > LEN
    var B = min_num_bits(LEN);
    _ = assert_bits_fit_scalar(B);
    _ <== Num2Bits(B)(idx);
    signal idx_is_bounded <== LessThan(B)([idx, LEN]);
    success === -1 * idx_is_bounded;

    // Old equivalent code:
    // signal is_out_of_bounds <== GreaterEqThan(20)([idx, LEN]);
    // success === -1 * (1 - is_out_of_bounds);
}

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
template CheckSubstrInclusionPoly(maxStrLen, maxSubstrLen) {
    signal input str[maxStrLen];
    signal input str_hash;
    signal input substr[maxSubstrLen];
    signal input substr_len;
    signal input start_index;

    signal success <== CheckSubstrInclusionPolyBoolean(maxStrLen, maxSubstrLen)(
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
template CheckSubstrInclusionPolyBoolean(maxStrLen, maxSubstrLen) {
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
    signal str_poly_eval <== CalculateTotal(maxStrLen)(str_poly);

    // Computes t(\alpha)
    signal substr_poly_eval <== CalculateTotal(maxSubstrLen)(substr_poly);

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

    signal left_poly_eval <== CalculateTotal(maxLeftStringLen)(left_poly);
    signal right_poly_eval <== CalculateTotal(maxRightStringLen)(right_poly);
    signal full_poly_eval <== CalculateTotal(maxFullStringLen)(full_poly);

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
        var is_less_than_max = LessThan(9)([in[i], 58]);
        var is_greater_than_min = GreaterThan(9)([in[i], 47]);
        var is_ascii_digit = AND()(is_less_than_max, is_greater_than_min);
        (1-is_ascii_digit) * selector[i] === 0;
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

