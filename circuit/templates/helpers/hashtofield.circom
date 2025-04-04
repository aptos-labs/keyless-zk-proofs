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

pragma circom 2.1.3;

include "circomlib/circuits/poseidon.circom";
include "circomlib/circuits/comparators.circom";

include "./packing.circom";

/**
 * Hashes multiple bytes to one field element using Poseidon.
 * We hash the length `len` of the input as well to prevent collisions.
 *
 * Currently, does not work for inputs larger than $64 \times 31 = 1984$ bytes.
 * TODO(Comment): Why?
 *
 * TODO(Buses): If `in` is `Bytes(MAX_LEN)` bus, then we can remove the `CheckAreBytes`
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

    CheckAreBytes(numBytes)(in);

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

    hash <== HashElemsToField(num_elems + 1)(input_with_len);
}

// Hashes multiple bytes to one field element using a Poseidon hash
// Currently does not work with greater than 64*31=1984 bytes
//
// Warning: `numBytes` cannot be 0.
template HashBytesToField(numBytes) {
    signal input in[numBytes];
    signal output hash;

    CheckAreBytes(numBytes)(in);

    var num_elems = numBytes%31 == 0 ? numBytes\31 : numBytes\31 + 1; 

    signal input_packed[num_elems] <== ChunksToFieldElems(numBytes, 31, 8)(in); // Pack 31 bytes per field element

    hash <== HashElemsToField(num_elems)(input_packed);
}

// Hashes multiple field elements to one using Poseidon. Works with up to 64 input elements
// For more than 16 elements, multiple Poseidon hashes are used before being combined in a final
// hash. This is because the template we use supports only 16 input elements at most
//
// Notes:
//   TODO(Comment): Looks like this is doing an incomplete hex-ary Merkle tree.
//   Used by HashBytesToField and HashBytesToFieldWithLen.
template HashElemsToField(numElems) {
    signal input in[numElems];
    signal output hash;

    if (numElems <= 16) { 
        hash <== Poseidon(numElems)(in);
    } else if (numElems <= 32) {
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
        hash <== Poseidon(2)([h1, h2]);
    } else if (numElems <= 48) {
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
        hash <== Poseidon(3)([h1, h2, h3]); 
    } else if (numElems <= 64) {
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
        hash <== Poseidon(4)([h1, h2, h3, h4]);  
    } else {
        1 === 0;
    }

}

// Hashes multiple 64 bit limbs to one field element using a Poseidon hash
// We hash the length of the input as well to avoid collisions
//
// Assumes `len` is the length of the provided input. It is used only for hashing and is not
// verified by this template
//
// Warning: `numLimbs` cannot be 0.
template Hash64BitLimbsToFieldWithLen(numLimbs) {
    signal input in[numLimbs];
    signal input len;

    CheckAre64BitLimbs(numLimbs)(in);

    var num_elems = numLimbs%3 == 0 ? numLimbs\3 : numLimbs\3 + 1; 

    signal input_packed[num_elems] <== ChunksToFieldElems(numLimbs, 3, 64)(in); // Pack 3 64-bit limbs per field element

    signal input_with_len[num_elems+1];
    for (var i = 0; i < num_elems; i++) {
        input_with_len[i] <== input_packed[i];
    }
    input_with_len[num_elems] <== len;

    signal output hash <== Poseidon(num_elems+1)(input_with_len);
}

