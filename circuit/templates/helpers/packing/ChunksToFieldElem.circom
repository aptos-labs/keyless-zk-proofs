/**
 * Author: Michael Straka, Alin Tomescu
 */
pragma circom 2.2.2;

include "../../stdlib/functions/assert_bits_fit_scalar.circom";

// Tightly-packs many chunks into a single scalar. (Inspired by `Bits2Num` in
// circomlib.)
//
// @param  NUM_CHUNKS       the number of chunks
// @param  BITS_PER_CHUNK   the max size of each chunk in bits, such that a field
//                          element can fit NUM_CHUNKS * BITS_PER_CHUNK bits
//
// @input  in[NUM_CHUNKS]   the chunks themselves
// @output out              \sum_{i = 0}^{NUM_CHUNKS} in[i] 2^{BITS_PER_CHUNK}
//
// TODO(Tags): `in` should be tagged with maxbits = BITS_PER_CHUNK
// TODO: Rename to ChunksToScalar
template ChunksToFieldElem(NUM_CHUNKS, BITS_PER_CHUNK) {
    // Ensure we don't exceed circom's field size here
    _ = assert_bits_fit_scalar(NUM_CHUNKS * BITS_PER_CHUNK);
    var BASE = 2**BITS_PER_CHUNK;

    signal input in[NUM_CHUNKS];
    signal output out;

    var elem = in[0];
    var pow = BASE;
    for (var i = 1; i < NUM_CHUNKS; i++) {
        elem += in[i] * pow;
        pow *= BASE;            // (2^{BITS_PER_CHUNK})^i --> (2^{BITS_PER_CHUNK})^{i+1}
    }

    elem ==> out;
}