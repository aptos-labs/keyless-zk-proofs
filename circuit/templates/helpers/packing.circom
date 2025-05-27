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

include "packing/Num2BigEndianBits.circom";
include "packing/BigEndianBits2Num.circom";

include "packing/AssertIsBytes.circom";
include "packing/AssertIs64BitLimbs.circom";
include "packing/ChunksToFieldElem.circom";
include "packing/ChunksToFieldElems.circom";

// Converts byte array `in` into a bit array. All values in `in` are
// assumed to be one byte each, i.e. between 0 and 255 inclusive.
// These bytes are also assumed to be in big endian order
template BytesToBits(inputLen) {
    signal input in[inputLen];
    var byte_len = 8;
    signal output bits[byte_len*inputLen];
    component num2bits[inputLen];
    for (var i = 0; i < inputLen; i++) {
        num2bits[i] = Num2BigEndianBits(byte_len);
        num2bits[i].in <== in[i];
        for (var j = 0; j < byte_len; j++) {
            var index = (i*byte_len)+j;
            num2bits[i].out[j] ==> bits[index];
        }
    }
}


// Converts bit array 'in' into an array of field elements of size `bitsPerFieldElem` each
// Example: with inputLen=11, bitsPerFieldElem=4, [0,0,0,0, 0,0,0,1, 0,1,1,] ==> [0, 1, 6]
// Assumes all values in `in` are 0 or 1
template BitsToFieldElems(inputLen, bitsPerFieldElem) {
    signal input in[inputLen];
    var num_elems = inputLen%bitsPerFieldElem == 0 ? inputLen \ bitsPerFieldElem : (inputLen\bitsPerFieldElem) + 1; // '\' is the quotient operation - we add 1 if there are extra bits past the full bytes
    signal output elems[num_elems];
    component bits_2_num_be[num_elems]; 
    for (var i = 0; i < num_elems-1; i++) {
        bits_2_num_be[i] = BigEndianBits2Num(bitsPerFieldElem); // assign circuit component
    }

    // If we have an extra byte that isn't full of bits, we truncate the BigEndianBits2Num component size for that byte. This is equivalent to 0 padding the end of the array
    var num_extra_bits = inputLen % bitsPerFieldElem;
    if (num_extra_bits == 0) {
        num_extra_bits = bitsPerFieldElem; // The last field element is full
        bits_2_num_be[num_elems-1] = BigEndianBits2Num(bitsPerFieldElem);
    } else {
        bits_2_num_be[num_elems-1] = BigEndianBits2Num(num_extra_bits);
    }

    // Assign all but the last field element
    for (var i = 0; i < num_elems-1; i++) {
        for (var j = 0; j < bitsPerFieldElem; j++) {
            var index = (i * bitsPerFieldElem) + j;
            bits_2_num_be[i].in[j] <== in[index];
        }
        bits_2_num_be[i].out ==> elems[i];
    }

    // Assign the last field element
    for (var j = 0; j < num_extra_bits; j++) {
        var i = num_elems-1;
        var index = (i*bitsPerFieldElem) + j;
        bits_2_num_be[num_elems-1].in[j] <== in[index];
    }
    bits_2_num_be[num_elems-1].out ==> elems[num_elems-1];
}