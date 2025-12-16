pragma circom 2.2.2;

include "../strings/IsSubstring.circom";
include "../hashtofield/HashBytesToFieldWithLen.circom";
include "../packing/Bytes2BigEndianBits.circom";
include "../packing/BigEndianBits2Num.circom";

include "circomlib/circuits/bitify.circom";

// Verifies SHA2_256 input padding according to https://www.rfc-editor.org/rfc/rfc4634.html#section-4.1
template SHA2_256_PaddingVerify(MAX_INPUT_LEN) {
    signal input {maxbits} msg[MAX_INPUT_LEN]; // byte array representing the message being hashed (and padded)
    signal input num_blocks; // Number of 512-bit blocks in `msg` including sha padding
    signal input padding_start; // equivalent to L/8, where L is the length of the unpadded message, in bits, as specified in RFC4634
    signal input {maxbits} L_byte_encoded[8]; // byte-array; 64-bit encoding of L
    signal input {maxbits} padding_without_len[64]; // byte-array; padding_without_len[0] = 1, followed by K 0s. Length K+1, max length 512 bits. Does not include the 64-bit encoding of L

    var K = (num_blocks * 512) - (padding_start * 8) - 1 - 64; 

    assert(msg.maxbits == 8);
    assert(L_byte_encoded.maxbits == 8);
    assert(padding_without_len.maxbits == 8);

    // Ensure K is 9-bits (i.e., < 2^9 = 512)
    _ <== Num2Bits(9)(K);

    // Note: This is a Fiat-Shamir hash, not the SHA2-256 hash
    signal msg_hash <== HashBytesToFieldWithLen(MAX_INPUT_LEN)(msg, num_blocks * 64);
    // 4.1.a
    AssertIsSubstring(MAX_INPUT_LEN, 64)(
        str <== msg, 
        str_hash <== msg_hash, 
        substr <== padding_without_len, 
        substr_len <== (K+1)/8, 
        start_index <== padding_start
    );
    padding_without_len[0] === 128; // in binary, 1_000_0000b

    // 4.1.b
    for (var i = 1; i < 64; i++) {
        padding_without_len[i] === 0;
    }

    // 4.1.c
    AssertIsSubstring(MAX_INPUT_LEN, 8)(
        str <== msg, 
        str_hash <== msg_hash,
        substr <== L_byte_encoded, 
        substr_len <== 8, 
        start_index <== padding_start + (K+1)/8
    );

    // TODO(Perf): Can't we just go from bytes to num directly?
    signal L_bits[64] <== Bytes2BigEndianBits(8)(L_byte_encoded);
    signal L_decoded <== BigEndianBits2Num(64)(L_bits);

    L_decoded === 8 * padding_start;
}
