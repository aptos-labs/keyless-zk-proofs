/**
 * Author: Michael Straka, Alin Tomescu
 */
pragma circom 2.2.2;

include "../packing/ChunksToFieldElems.circom";
include "../packing/AssertIs64BitLimbs.circom";

include "circomlib/circuits/poseidon.circom";

// Hashes multiple 64-bit limbs to a field element using a Poseidon hash.
//
// We hash the length of the input as well to avoid collisions.
//
// Assumes `len` is the length [in bytes?] of the provided input. It is used only for hashing and is not
// verified by this template.
//
// @param   NUM_LIMBS     the max number of limbs in the input array
//
// @input   in {maxbits}  an array of already-range-checked, 64-bit limbs
// @input   len           the total # of bytes in the limbs (TODO: NUM_LIMBS*8 ==> redundant, so remove)
//
// @output  hash          a collision-resistant hash of the 64-bit limbs
template Hash64BitLimbsToFieldWithLen(NUM_LIMBS) {
    assert(NUM_LIMBS != 0);

    signal input {maxbits} in[NUM_LIMBS];
    signal input len;

    assert(in.maxbits <= 64);

    var NUM_ELEMS = NUM_LIMBS % 3 == 0 ? NUM_LIMBS \ 3 : NUM_LIMBS \ 3 + 1;

    // Pack 3 64-bit limbs per field element
    signal input_packed[NUM_ELEMS] <== ChunksToFieldElems(NUM_LIMBS, 3, 64)(in);

    signal input_with_len[NUM_ELEMS + 1];
    for (var i = 0; i < NUM_ELEMS; i++) {
        input_with_len[i] <== input_packed[i];
    }
    input_with_len[NUM_ELEMS] <== len;

    signal output hash <== Poseidon(NUM_ELEMS + 1)(input_with_len);
}

