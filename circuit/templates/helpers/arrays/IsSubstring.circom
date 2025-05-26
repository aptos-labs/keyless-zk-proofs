// TODO: Although initially only used to check for substrings, I think this should
// be renamed to IsSubarray, since it works for any array, I believe (modulo the hashing
// which may enforce that the input be bytes).
pragma circom 2.2.2;

include "../hashtofield/HashBytesToFieldWithLen.circom";

include "./ArraySelector.circom";
include "./SelectArrayValue.circom";

include "circomlib/circuits/comparators.circom";
include "circomlib/circuits/poseidon.circom";

// Checks that `substr` is a substring of `str`.
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