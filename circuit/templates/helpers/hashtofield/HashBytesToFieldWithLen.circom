/**
 * Author: Michael Straka, Alin Tomescu
 */
pragma circom 2.2.2;

include "../packing/AssertIsBytes.circom";
include "../packing/ChunksToFieldElems.circom";

include "PoseidonBN254Hash.circom";
include "HashElemsToField.circom";

/**
 * Hashes multiple bytes to one field element using Poseidon.
 * We hash the length `len` of the input as well to prevent collisions.
 *
 * Currently, does not work for inputs larger than $64 \times 31 = 1984$ bytes.
 * because `HashElemsToField` only handles <= 64 field elements (but can be extended).
 *
 * Parameters:
 *   NUM_BYTES      the max number of bytes this can handle; is > 0 and <= 1984 (64 * 31)
 *
 * Input signals:
 *   in[NUM_BYTES]  array to be hashed, but only in[0], in[1], ..., in[len-1] prefix is actually hashed
 *   len            the number of bytes that will be actually hashed;
 *                  bytes `in[len], in[len+1]..., in[NUM_BYTES-1]` are ignored
 *
 * Output signals:
 *   hash           the Poseidon-BN254 hash of these bytes
 *
 * Notes:
 *   There is no way to meaningfully ensure that `len` is the actual length of the bytes in `in`.
 */
template HashBytesToFieldWithLen(NUM_BYTES) {
    assert(NUM_BYTES > 0);
    assert(NUM_BYTES <= 1984);
    signal input {maxbits} in[NUM_BYTES];
    signal input len;
    signal output hash;

    assert(in.maxbits <= 8);

    var NUM_ELEMS = NUM_BYTES % 31 == 0 ? NUM_BYTES\31 : NUM_BYTES\31 + 1;

    // Pack 31 bytes per field element
    signal input_packed[NUM_ELEMS] <== ChunksToFieldElems(
        NUM_BYTES,  // inputLen (i.e., max input len)
        31,         // chunksPerFieldElem
        8           // bitsPerChunk
    )(in);

    var elems[NUM_ELEMS + 1];
    for (var i = 0; i < NUM_ELEMS; i++) {
        elems[i] = input_packed[i];
    }
    elems[NUM_ELEMS] = len;

    PoseidonBN254Hash() poseidonHash <== HashElemsToField(NUM_ELEMS + 1)(elems);

    hash <== poseidonHash.value;
}
