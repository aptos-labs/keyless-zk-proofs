/**
 * Author: Michael Straka, Alin Tomescu
 */
pragma circom 2.2.2;

include "PoseidonBN254Hash.circom";

// for Poseidon(N)
include "circomlib/circuits/poseidon.circom";

// (Merkle-)hashes a vector of field elements using Poseidon-BN254. 
//
// @param   NUM_ELEMS  the number of elements to be hashed; must be <= 64
//
// @input  in         the `NUM_ELEMS`-sized vector of field elements
// @output hash : PoseidonBN254Hash   the (Merkle) hash of the vector
//
// @notes:
//   When NUM_ELEMS <= 16, returns H_{NUM_ELEMS}(in[0], ..., in[NUM_ELEMS-1])
//   When 16 < NUM_ELEMS <= 64, returns an (incomplete) hex-ary Merkle tree.
//
//   Used by HashBytesToFieldWithLen.
template HashElemsToField(NUM_ELEMS) {
    signal input in[NUM_ELEMS];
    output PoseidonBN254Hash() hash;

    if (NUM_ELEMS <= 16) { 
        hash.value <== Poseidon(NUM_ELEMS)(in);
    } else if (NUM_ELEMS <= 32) {
        //          h_2
        //        /     \
        //  h_{16}       h_{NUM_ELEMS - 16}
        signal inputs_one[16];
        for (var i = 0; i < 16; i++) {
            inputs_one[i] <== in[i];
        }
        signal inputs_two[NUM_ELEMS-16];
        for (var i = 16; i < NUM_ELEMS; i++) {
            inputs_two[i-16] <== in[i];
        }
        signal h1 <== Poseidon(16)(inputs_one);
        signal h2 <== Poseidon(NUM_ELEMS-16)(inputs_two);
        hash.value <== Poseidon(2)([h1, h2]);
    } else if (NUM_ELEMS <= 48) {
        //            h_3
        //          /  |  \
        //        /    |    \
        //  h_{16}   h_{16}  h_{NUM_ELEMS - 32}
        signal inputs_one[16];
        for (var i = 0; i < 16; i++) {
            inputs_one[i] <== in[i];
        }
        signal inputs_two[16];
        for (var i = 16; i < 32; i++) {
            inputs_two[i-16] <== in[i];
        }
        signal inputs_three[NUM_ELEMS-32];
        for (var i = 32; i < NUM_ELEMS; i++) {
            inputs_three[i-32] <== in[i];
        }
        signal h1 <== Poseidon(16)(inputs_one);
        signal h2 <== Poseidon(16)(inputs_two);
        signal h3 <== Poseidon(NUM_ELEMS-32)(inputs_three);
        hash.value <== Poseidon(3)([h1, h2, h3]);
    } else if (NUM_ELEMS <= 64) {
        //                h_4
        //              / / \ \
        //            /  /   \  \
        //          /   |     |   \
        //        /     |     |     \
        //  h_{16}   h_{16}  h_{16}  h_{NUM_ELEMS - 32}
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
        signal inputs_four[NUM_ELEMS-48];
        for (var i = 48; i < NUM_ELEMS; i++) {
            inputs_four[i-48] <== in[i];
        }
        signal h1 <== Poseidon(16)(inputs_one);
        signal h2 <== Poseidon(16)(inputs_two);
        signal h3 <== Poseidon(16)(inputs_three);
        signal h4 <== Poseidon(NUM_ELEMS-48)(inputs_four);
        hash.value <== Poseidon(4)([h1, h2, h3, h4]);
    } else {
        1 === 0;
    }
}
