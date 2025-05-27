pragma circom 2.2.2;

include "../arrays/IsSubstring.circom";
include "../hashtofield/HashBytesToFieldWithLen.circom";
include "../packing/Bytes2BigEndianBits.circom";
include "../packing/BigEndianBits2Num.circom";

include "circomlib/circuits/bitify.circom";

// Verifies SHA2_256 input padding according to https://www.rfc-editor.org/rfc/rfc4634.html#section-4.1
template SHA2_256_PaddingVerify(maxInputLen) {
    signal input in[maxInputLen]; // byte array
    signal input num_blocks; // Number of 512-bit blocks in `in` including sha padding
    signal input padding_start; // equivalent to L/8, where L is the length of the unpadded message in bits as specified in RFC4634
    signal input L_byte_encoded[8]; // 64-bit encoding of L
    signal input padding_without_len[64]; // padding_without_len[0] = 1, followed by K 0s. Length K+1, max length 512 bits. Does not include the 64-bit encoding of L

    var len_bits = num_blocks * 512;
    var padding_start_bits = padding_start * 8;
    var K = len_bits - padding_start_bits - 1 - 64; 

    // Ensure K is 9-bits (i.e., < 2^9 = 512)
    _ <== Num2Bits(9)(K);

    signal in_hash <== HashBytesToFieldWithLen(maxInputLen)(in, num_blocks*64);
    // 4.1.a
    AssertIsSubstring(maxInputLen, 64)(in, in_hash, padding_without_len, (1+K)/8, padding_start);
    padding_without_len[0] === 128; // in binary, 1_000_0000b

    // 4.1.b
    for (var i = 1; i < 64; i++) {
        padding_without_len[i] === 0;
    }

    // 4.1.c
    AssertIsSubstring(maxInputLen, 8)(in, in_hash, L_byte_encoded, 8, padding_start+(K+1)/8);
    signal L_bits[64] <== Bytes2BigEndianBits(8)(L_byte_encoded);
    signal L_decoded <== BigEndianBits2Num(64)(L_bits);
    L_decoded === 8*padding_start;
}
