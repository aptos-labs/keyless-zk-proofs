/**
 * Let \F denote circom's finite field of prime order p.
 * Let #B denote the number of bytes that can be fit into an element of \F (e.g., #B = 31
 * for BN254).
 * Let H_n : \F^n -> \F (e.g., Poseidon) denote a hash function family.
 *
 * This file implements templates for hashing various objects (byte arrays, strings, etc.),
 * using \F and H_n as building blocks.
 *
 * WARNING: Some of these algorithms are used in the keyless TXN validation logic on-chain
 * on Aptos. Changing them haphazardly will break backwards compatibility, so exercise
 * caution!
 *
 * # Preliminaries
 *
 * ## Zero-padding
 *
 * ```
 *  ZeroPad_{max}(b) => pb:
 *   - (b_1, ..., b_n) <- b
 *   - pb <- (b_1, ..., b_n, 0, ... , 0) s.t. |pb| = max
 * ```
 *
 * Zero-pads an array of `n` bytes `b = [b_1, ..., b_n]` up to `max` bytes.
 *
 * ## Packing bytes to scalar(s)
 *
 * ```
 *  PackBytesToScalars_{max}(b) => (e_1, e_2, \ldots, e_k)
 * ```
 *
 * Packs n bytes into k = ceil(n/#B) field elements, zero-padding the last element
 * when #B does not divide n. Since circom fields will typically be prime-order, even
 * after fitting max #B bytes into a field element, we may be left with some extra
 * unused *bits* at the end. This function always sets those bits to zero!
 *
 * WARNING: Not injective, since when there is room in a field element, we pad
 * it with zero bytes.
 * This is fine for our purposes, because we either hash length-suffixed byte arrays
 * or null-terminated strings. So the non-injectiveness of this can accounted for.
 * (Note to self: EPK *is* packed via this but its length in bytes is appended.)
 *
 * TODO(Docs): Continue
 */

pragma circom 2.2.2;

include "circomlib/circuits/poseidon.circom";
include "circomlib/circuits/comparators.circom";

include "./packing.circom";

/**
 * A bus to denote a PoseidonBN254 hash in a type-safe way.
 */
bus PoseidonBN254Hash() {
    signal value;
}

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
 *   numBytes       the max number of bytes this can handle; is > 0 and <= 1984 (64 * 31)
 *
 * Input signals:
 *   in[numBytes]   array to be hashed, although only in[0], in[1], ..., in[len-1];
 *                  constrained to ensure elements are actually bytes
 *                  are actually hashed
 *   len            the number of bytes that will be actually hashed;
 *                  bytes `in[len], in[len+1]..., in[numBytes-1]` are ignored
 *
 * Output signals:
 *   hash           the Poseidon-BN254 hash of these bytes
 *
 * Notes:
 *   There is no way to meaningfully ensure that `len` is the actual length of the bytes in `in`.
 *   TODO(Buses): Some type-safety via a `Bytes(MAX_LEN)` bus may be useful here?
 */
template HashBytesToFieldWithLen(numBytes) {
    assert(numBytes > 0);
    signal input in[numBytes];
    signal input len;
    signal output hash;

    AssertIsBytes(numBytes)(in);

    var num_elems = numBytes % 31 == 0 ? numBytes\31 : numBytes\31 + 1;

    // Pack 31 bytes per field element
    signal input_packed[num_elems] <== ChunksToFieldElems(
        numBytes,   // inputLen (i.e., max input len)
        31,         // chunksPerFieldElem
        8           // bitsPerChunk
    )(in);

    // TODO(Cleanup): Can't we use a var here? We are simply re-assigning signals, it seems.
    signal input_with_len[num_elems + 1];
    for (var i = 0; i < num_elems; i++) {
        input_with_len[i] <== input_packed[i];
    }
    input_with_len[num_elems] <== len;

    PoseidonBN254Hash() poseidonHash <== HashElemsToField(num_elems + 1)(input_with_len);

    hash <== poseidonHash.value;
}

// (Merkle-)hashes a vector of field elements using Poseidon-BN254. 
//
// @param   numElems  the number of elements to be hashed; must be <= 64
//
// @input  in         the `numElems`-sized vector of field elements
// @output hash : PoseidonBN254Hash   the (Merkle) hash of the vector
//
// @notes:
//   When numElems <= 16, returns H_{numElems}(in[0], ..., in[numElems-1])
//   When 16 < numElems <= 64, returns an (incomplete) hex-ary Merkle tree.
//
//   Used by HashBytesToFieldWithLen.
template HashElemsToField(numElems) {
    signal input in[numElems];
    output PoseidonBN254Hash() hash;

    if (numElems <= 16) { 
        hash.value <== Poseidon(numElems)(in);
    } else if (numElems <= 32) {
        //          h_2
        //        /     \
        //  h_{16}       h_{numElems - 16}
        signal inputs_one[16];
        for (var i = 0; i < 16; i++) {
            inputs_one[i] <== in[i];
        }
        signal inputs_two[numElems-16];
        for (var i = 16; i < numElems; i++) {
            inputs_two[i-16] <== in[i];
        }
        signal h1 <== Poseidon(16)(inputs_one);
        signal h2 <== Poseidon(numElems-16)(inputs_two);
        hash.value <== Poseidon(2)([h1, h2]);
    } else if (numElems <= 48) {
        //            h_3
        //          /  |  \
        //        /    |    \
        //  h_{16}   h_{16}  h_{numElems - 32}
        signal inputs_one[16];
        for (var i = 0; i < 16; i++) {
            inputs_one[i] <== in[i];
        }
        signal inputs_two[16];
        for (var i = 16; i < 32; i++) {
            inputs_two[i-16] <== in[i];
        }
        signal inputs_three[numElems-32];
        for (var i = 32; i < numElems; i++) {
            inputs_three[i-32] <== in[i];
        }
        signal h1 <== Poseidon(16)(inputs_one);
        signal h2 <== Poseidon(16)(inputs_two);
        signal h3 <== Poseidon(numElems-32)(inputs_three);
        hash.value <== Poseidon(3)([h1, h2, h3]);
    } else if (numElems <= 64) {
        //                h_4
        //              / / \ \
        //            /  /   \  \
        //          /   |     |   \
        //        /     |     |     \
        //  h_{16}   h_{16}  h_{16}  h_{numElems - 32}
        signal inputs_one[16];
        for (var i = 0; i < 16; i++) {
            inputs_one[i] <== in[i];
        }
        signal inputs_two[16];
        for (var i = 16; i < 32; i++) {
            inputs_two[i-16] <== in[i];
        }
        signal inputs_three[16];
        for (var i = 32; i < 48; i++) {
            inputs_three[i-32] <== in[i];
        }
        signal inputs_four[numElems-48];
        for (var i = 48; i < numElems; i++) {
            inputs_four[i-48] <== in[i];
        }
        signal h1 <== Poseidon(16)(inputs_one);
        signal h2 <== Poseidon(16)(inputs_two);
        signal h3 <== Poseidon(16)(inputs_three);
        signal h4 <== Poseidon(numElems-48)(inputs_four);
        hash.value <== Poseidon(4)([h1, h2, h3, h4]);
    } else {
        1 === 0;
    }

}

// Hashes multiple 64-bit limbs to a field element using a Poseidon hash.
//
// We hash the length of the input as well to avoid collisions.
//
// Assumes `len` is the length [in bytes?] of the provided input. It is used only for hashing and is not
// verified by this template.
//
// Warning: `NUM_LIMBS` cannot be 0.
template Hash64BitLimbsToFieldWithLen(NUM_LIMBS) {
    assert(NUM_LIMBS != 0);

    signal input in[NUM_LIMBS];
    signal input len;

    CheckAre64BitLimbs(NUM_LIMBS)(in);

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

