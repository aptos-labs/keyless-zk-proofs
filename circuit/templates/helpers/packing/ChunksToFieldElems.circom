/**
 * Author: Michael Straka, Alin Tomescu
 */
pragma circom 2.2.2;

include "ChunksToFieldElem.circom";

// Tightly-packs many chunks into a many scalars.
//
// @param   NUM_CHUNKS         the number of chunks to pack; cannot be 0
// @param   BITS_PER_CHUNK     the max size of each chunk in bits
// @param   CHUNKS_PER_SCALAR  a scalar can fit at most
//                             CHUNKS_PER_SCALAR * BITS_PER_CHUNK bits
//
// @input   in                  the chunks to be packed
// @output  out[NUM_SCALARS]    array of NUM_SCALARS scalars packing the chunks, where
//                              NUM_SCALARS = ceil(NUM_CHUNKS / CHUNKS_PER_SCALAR)
//
// TODO: Rename to ChunksToScalars
template ChunksToFieldElems(NUM_CHUNKS, CHUNKS_PER_SCALAR, BITS_PER_CHUNK) {
    assert(NUM_CHUNKS != 0);

    var NUM_CHUNKS_IN_LAST_SCALAR;
    var NUM_SCALARS;

    if (NUM_CHUNKS % CHUNKS_PER_SCALAR == 0) {
        // The chunks can be spread evenly across the scalars
        NUM_CHUNKS_IN_LAST_SCALAR = CHUNKS_PER_SCALAR;
        NUM_SCALARS = NUM_CHUNKS \ CHUNKS_PER_SCALAR;
    } else {
        // The chunks CANNOT be spread evenly across the scalars
        // => the last scalar will have < CHUNKS_PER_SCALAR chunks
        NUM_CHUNKS_IN_LAST_SCALAR = NUM_CHUNKS % CHUNKS_PER_SCALAR; // in [0, CHUNKS_PER_SCALAR)
        NUM_SCALARS = 1 + NUM_CHUNKS \ CHUNKS_PER_SCALAR;
    }

    signal input in[NUM_CHUNKS];
    signal output out[NUM_SCALARS];

    component chunksToScalar[NUM_SCALARS]; 
    for (var i = 0; i < NUM_SCALARS - 1; i++) {
        chunksToScalar[i] = ChunksToFieldElem(CHUNKS_PER_SCALAR, BITS_PER_CHUNK);
    }

    chunksToScalar[NUM_SCALARS - 1] = ChunksToFieldElem(NUM_CHUNKS_IN_LAST_SCALAR, BITS_PER_CHUNK);

    // Assign all but the last field element
    for (var i = 0; i < NUM_SCALARS - 1; i++) {
        for (var j = 0; j < CHUNKS_PER_SCALAR; j++) {
            var index = (i * CHUNKS_PER_SCALAR) + j;
            chunksToScalar[i].in[j] <== in[index];
        }
        chunksToScalar[i].out ==> out[i];
    }

    // Assign the last field element
    for (var j = 0; j < NUM_CHUNKS_IN_LAST_SCALAR; j++) {
        var index = (NUM_SCALARS - 1) * CHUNKS_PER_SCALAR + j;
        chunksToScalar[NUM_SCALARS - 1].in[j] <== in[index];
    }
    chunksToScalar[NUM_SCALARS - 1].out ==> out[NUM_SCALARS - 1];
}