pragma circom 2.2.2;

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
        // C1: Enforces that either: out[i] == 0, or idx == i
        out[i] * (idx - i) === 0;
        lc = lc + out[i];
    }
    lc ==> success;

    // C2: Enforces that `lc` is equal to 1
    success === 1;
}