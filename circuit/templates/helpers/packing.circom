/**
 * TODO(Buses): We definitely need a ZeroPaddedBytes(MAX) that has an (1) array of signals, each storing a byte and (2) an actual length signal.
 *
 * TODO(Buses): We also need a PackedBytes(MAX) that can be obtained from a ZeroPaddedBytes
 * (MAX) and once again has (1) an array of signals, each storing a bunch of packed bytes,
 * and (2) an actual length signal. (This length could be stored as the last element of the
 * array of signals in (1)).
 */
pragma circom 2.2.2;

include "./arrays.circom";

// Based on `Num2Bits` in circomlib
// Converts a field element `in` into an array `out` of
// `n` bits which are all 0 or 1, in big endian order
template Num2BitsBE(n) {
    signal input in;
    signal output out[n];
    var lc1 = 0;
   
    var e2 = 1;
    for (var i = 0; i < n; i++) {
        var idx = (n - 1) - i;
        out[idx] <-- (in >> i) & 1;
        out[idx] * (out[idx] - 1 ) === 0;
        lc1 += out[idx] * e2;
        e2 = e2 + e2;
    }
    lc1 === in;
}

// Converts a bit array of size `n` into a big endian integer in `out`
// Assumes `in` contains only 1s and 0s
// Inspired by Bits2Num in https://github.com/iden3/circomlib/blob/master/circuits/bitify.circom
template Bits2NumBigEndian(n) { 
    signal input in[n];
    signal output out;
    var lc1=0;
    
    var e2 = 1;
    for (var i = 0; i < n; i++) {
        var index = n-1-i;
        lc1 += in[index] * e2;
        e2 = e2 + e2;
    }
    lc1 ==> out;
}


// Converts byte array `in` into a bit array. All values in `in` are
// assumed to be one byte each, i.e. between 0 and 255 inclusive.
// These bytes are also assumed to be in big endian order
template BytesToBits(inputLen) {
    signal input in[inputLen];
    var byte_len = 8;
    signal output bits[byte_len*inputLen];
    component num2bits[inputLen];
    for (var i = 0; i < inputLen; i++) {
        num2bits[i] = Num2BitsBE(byte_len);
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
        bits_2_num_be[i] = Bits2NumBigEndian(bitsPerFieldElem); // assign circuit component
    }

    // If we have an extra byte that isn't full of bits, we truncate the Bits2NumBigEndian component size for that byte. This is equivalent to 0 padding the end of the array
    var num_extra_bits = inputLen % bitsPerFieldElem;
    if (num_extra_bits == 0) {
        num_extra_bits = bitsPerFieldElem; // The last field element is full
        bits_2_num_be[num_elems-1] = Bits2NumBigEndian(bitsPerFieldElem);
    } else {
        bits_2_num_be[num_elems-1] = Bits2NumBigEndian(num_extra_bits);
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

// Enforces that each scalar in the input array `in` is a byte (i.e., \in [0, 256))
//
// @param   NUM_BYTES   the size of the input array
//
// @input   in          the input array of NUM_BYTES signals
//
// @postconditions      in[i] \in [0, 256), \forall i \in [0, NUM_BYTES)
template AssertIsBytes(NUM_BYTES) {
    signal input in[NUM_BYTES];

    for (var i = 0; i < NUM_BYTES; i++) {
        _ <== Num2Bits(8)(in[i]);
    }
}


// Enforces that each scalar in the input array `in` is 64-bit (i.e., \in [0, 2^{64}))
//
// @param   NUM_LIMBS   the size of the input array
//
// @input   in          the input array of NUM_LIMBS signals
//
// @postconditions      in[i] \in [0, 2^{64}), \forall i \in [0, NUM_LIMBS)
template AssertIs64BitLimbs(NUM_LIMBS) {
    signal input in[NUM_LIMBS];

    for (var i = 0; i < NUM_LIMBS; i++) {
        _ <== Num2Bits(64)(in[i]);
    }
}

// Inspired by `Bits2Num` in circomlib. Packs chunks of bits into a single field element
// Assumes that each value in `in` encodes `bitsPerChunk` bits of a single field element
// TODO(Tags): `in` should be tagged with maxbits = bitsPerChunk
template ChunksToFieldElem(numChunks, bitsPerChunk) {
    // TODO: What ensures that we don't exceed circom's field size here?
    signal input in[numChunks];
    signal output out;

    var lc1 = in[0];

    var e2 = 2**bitsPerChunk;
    for (var i = 1; i<numChunks; i++) {
        lc1 += in[i] * e2;
        e2 = e2 * (2**bitsPerChunk);
    }

    lc1 ==> out;
}

// Packs chunks into multiple field elements
// `inputLen` cannot be 0.
// Assumes each element in `in` contains `bitsPerChunk` bits of information of a field element
// Each field element is assumed to be `chunksPerFieldElem` * `bitsPerChunk` bits. The final field element may be less than this
// There are assumed to be `inputLen` / `chunksPerFieldElem` field elements, rounded up to the nearest whole number.
//
// TODO(Cleanup): `chunksPerFieldElem` is backend-specific! Need a compile-time check.
template ChunksToFieldElems(inputLen, chunksPerFieldElem, bitsPerChunk) {
    signal input in[inputLen];
    var num_elems = inputLen%chunksPerFieldElem == 0 ? inputLen \ chunksPerFieldElem : (inputLen\chunksPerFieldElem) + 1; // '\' is the quotient operation - we add 1 if there are extra bits past the full chunks
    signal output elems[num_elems];
    component chunks_2_field[num_elems]; 
    for (var i = 0; i < num_elems-1; i++) {
        chunks_2_field[i] = ChunksToFieldElem(chunksPerFieldElem, bitsPerChunk); // assign circuit component
    }

    // If we have an extra chunk that isn't full of bits, we truncate the Bits2NumBigEndian component size for that chunk. This is equivalent to 0 padding the end of the array
    var num_extra_chunks = inputLen % chunksPerFieldElem;
    if (num_extra_chunks == 0) {
        num_extra_chunks = chunksPerFieldElem; // The last field element is full
        chunks_2_field[num_elems-1] = ChunksToFieldElem(chunksPerFieldElem, bitsPerChunk);
    } else {
        chunks_2_field[num_elems-1] = ChunksToFieldElem(num_extra_chunks, bitsPerChunk);
    }

    // Assign all but the last field element
    for (var i = 0; i < num_elems-1; i++) {
        for (var j = 0; j < chunksPerFieldElem; j++) {
            var index = (i * chunksPerFieldElem) + j;
            chunks_2_field[i].in[j] <== in[index];
        }
        chunks_2_field[i].out ==> elems[i];
    }

    // Assign the last field element
    var i = num_elems-1;
    for (var j = 0; j < num_extra_chunks; j++) {
        var index = (i*chunksPerFieldElem) + j;
        chunks_2_field[num_elems-1].in[j] <== in[index];
    }
    chunks_2_field[i].out ==> elems[i];
}
