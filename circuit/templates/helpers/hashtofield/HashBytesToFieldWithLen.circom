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
 * TODO(Comment): Why?
 *
 * TODO(Buses): If `in` is `Bytes(MAX_LEN)` bus, then we can remove the `AssertIsBytes`
 * constraint here, since it may be unnecessarily repeated if this gets called for the
 * same byte sub-sequence repeatedly.
 *
 * Parameters:
 *   NUM_BYTES       the max number of bytes this can handle; is > 0 and <= 1984 (64 * 31)
 *
 * Input signals:
 *   in[NUM_BYTES]  array to be hashed, although only in[0], in[1], ..., in[len-1];
 *                  constrained to ensure elements are actually bytes
 *                  are actually hashed
 *   len            the number of bytes that will be actually hashed;
 *                  bytes `in[len], in[len+1]..., in[NUM_BYTES-1]` are ignored
 *
 * Output signals:
 *   hash           the Poseidon-BN254 hash of these bytes
 *
 * Notes:
 *   There is no way to meaningfully ensure that `len` is the actual length of the bytes in `in`.
 *   TODO(Buses): Some type-safety via a `Bytes(MAX_LEN)` bus may be useful here?
 */
template HashBytesToFieldWithLen(NUM_BYTES) {
    assert(NUM_BYTES > 0);
    signal input in[NUM_BYTES];
    signal input len;
    signal output hash;

    AssertIsBytes(NUM_BYTES)(in);

    var NUM_ELEMS = NUM_BYTES % 31 == 0 ? NUM_BYTES\31 : NUM_BYTES\31 + 1;

    // Pack 31 bytes per field element
    signal input_packed[NUM_ELEMS] <== ChunksToFieldElems(
        NUM_BYTES,  // inputLen (i.e., max input len)
        31,         // chunksPerFieldElem
        8           // bitsPerChunk
    )(in);

    // TODO(Cleanup): Can't we use a var here? We are simply re-assigning signals, it seems.
    signal input_with_len[NUM_ELEMS + 1];
    for (var i = 0; i < NUM_ELEMS; i++) {
        input_with_len[i] <== input_packed[i];
    }
    input_with_len[NUM_ELEMS] <== len;

    PoseidonBN254Hash() poseidonHash <== HashElemsToField(NUM_ELEMS + 1)(input_with_len);

    hash <== poseidonHash.value;
}
