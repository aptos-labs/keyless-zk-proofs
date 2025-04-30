/**
 * Author: Michael Straka, Alin Tomescu
 */
pragma circom 2.2.2;

include "PoseidonBN254Hash.circom";

// for Poseidon(N)
include "circomlib/circuits/poseidon.circom";

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