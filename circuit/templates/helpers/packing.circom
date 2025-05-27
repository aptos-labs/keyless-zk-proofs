/**
 * TODO(Buses): We definitely need a ZeroPaddedBytes(MAX) that has an (1) array of signals, each storing a byte and (2) an actual length signal.
 *
 * TODO(Buses): We also need a PackedBytes(MAX) that can be obtained from a ZeroPaddedBytes
 * (MAX) and once again has (1) an array of signals, each storing a bunch of packed bytes,
 * and (2) an actual length signal. (This length could be stored as the last element of the
 * array of signals in (1)).
 */
pragma circom 2.2.2;

include "../stdlib/functions/assert_bits_fit_scalar.circom";

include "packing/AssertIs64BitLimbs.circom";
include "packing/AssertIsBytes.circom";
include "packing/ChunksToFieldElem.circom";
include "packing/ChunksToFieldElems.circom";
include "packing/BigEndianBits2Num.circom";
include "packing/Bytes2BigEndianBits.circom";
include "packing/Num2BigEndianBits.circom";

// Converts bit array 'in' into an array of field elements of size `BITS_PER_SCALAR` each
// Example: with NUM_BITS=11, BITS_PER_SCALAR=4, [0,0,0,0, 0,0,0,1, 0,1,1,] ==> [0, 1, 6]
// Assumes all values in `in` are 0 or 1
template BitsToFieldElems(NUM_BITS, BITS_PER_SCALAR) {
    var NUM_SCALARS;
    var NUM_BITS_IN_LAST_SCALAR;
    if (NUM_BITS % BITS_PER_SCALAR == 0) {
        NUM_BITS_IN_LAST_SCALAR = BITS_PER_SCALAR; // The last field element is full
        NUM_SCALARS = NUM_BITS \ BITS_PER_SCALAR;
    } else {
        NUM_BITS_IN_LAST_SCALAR = NUM_BITS % BITS_PER_SCALAR;
        NUM_SCALARS = 1 + (NUM_BITS \ BITS_PER_SCALAR);
    }

    signal input in[NUM_BITS];
    signal output elems[NUM_SCALARS];

    component beBits2Num[NUM_SCALARS];
    for (var i = 0; i < NUM_SCALARS - 1; i++) {
        beBits2Num[i] = BigEndianBits2Num(BITS_PER_SCALAR); // assign circuit component
    }

    // Assign all but the last field element
    for (var i = 0; i < NUM_SCALARS - 1; i++) {
        for (var j = 0; j < BITS_PER_SCALAR; j++) {
            var index = (i * BITS_PER_SCALAR) + j;
            beBits2Num[i].in[j] <== in[index];
        }
        beBits2Num[i].out ==> elems[i];
    }

    // Assign the last field element
    beBits2Num[NUM_SCALARS - 1] = BigEndianBits2Num(NUM_BITS_IN_LAST_SCALAR);
    for (var j = 0; j < NUM_BITS_IN_LAST_SCALAR; j++) {
        var index = ((NUM_SCALARS - 1) * BITS_PER_SCALAR) + j;
        beBits2Num[NUM_SCALARS - 1].in[j] <== in[index];
    }
    beBits2Num[NUM_SCALARS - 1].out ==> elems[NUM_SCALARS - 1];
}