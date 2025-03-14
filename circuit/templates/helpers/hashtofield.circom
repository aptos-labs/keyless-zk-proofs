pragma circom 2.1.3;

include "circomlib/circuits/poseidon.circom";
include "circomlib/circuits/comparators.circom";

include "./packing.circom";

// Hashes multiple bytes to one field element using a Poseidon hash
// We hash the length `len` of the input as well to prevent collisions
// Currently does not work with greater than 64*31=1984 bytes
//
// Warning: `numBytes` cannot be 0.
//
// Assumes `len` is the length of the input hash. This is only used in hashing and is not verified
// by this template
template HashBytesToFieldWithLen(numBytes) {
    signal input in[numBytes];
    signal input len;
    signal output hash;

    CheckAreBytes(numBytes)(in);

    var num_elems = numBytes%31 == 0 ? numBytes\31 : numBytes\31 + 1; 

    signal input_packed[num_elems] <== ChunksToFieldElems(numBytes, 31, 8)(in); // Pack 31 bytes per field element

    signal input_with_len[num_elems+1];
    for (var i = 0; i < num_elems; i++) {
        input_with_len[i] <== input_packed[i];
    }
    input_with_len[num_elems] <== len;

    hash <== HashElemsToField(num_elems+1)(input_with_len);
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

