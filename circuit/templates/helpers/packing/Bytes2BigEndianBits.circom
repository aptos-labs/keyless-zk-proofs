pragma circom 2.2.2;

include "./Num2BigEndianBits.circom";

// Converts a byte array to a bit array, where the each byte is converted into a 
// big-endian bits.
//
// @input  bytes   an array of bytes
//
// @output bits    an array of bits, where bits[i * 8], ..., bits[(i * 8) + 7] 
//                 are the bits in bytes[i], with bits[i * 8] being the MSB
template Bytes2BigEndianBits(LEN) {
    signal input bytes[LEN];
    signal output bits[8 * LEN];

    component num2bits[LEN];
    for (var i = 0; i < LEN; i++) {
        num2bits[i] = Num2BigEndianBits(8);
        num2bits[i].in <== bytes[i];

        for (var j = 0; j < 8; j++) {
            var IDX = (i * 8) + j;
            num2bits[i].out[j] ==> bits[IDX];
        }
    }
}
