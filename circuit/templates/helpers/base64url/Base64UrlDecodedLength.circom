pragma circom 2.2.2;

include "../../stdlib/functions/min_num_bits.circom";

include "circomlib/circuits/bitify.circom";

// Returns the length of the decoded data, given a base64url (unpadded) encoded length `m`.
//
// @param   MAX_ENCODED_LEN the maximum length of a base64url output, in bytes
//
// @input   m               the length of the encoded base64url data, in bytes
//
// @output  decoded_len     the length of the corresponding decoded data, in bytes
//
// @notes
//   explanation why decoded length = \floor{3 * encoded length / 4}
//
//   encoding works as follows:
//   suppose plaintext is length \ell
//   every 24 bits chunk (3 bytes) is encoded into 32 bits (4 base64url characters)
//     specifically, each 6-bit subchunk is mapped to a base64url character
//   last chunk could be 1 or 2 bytes though
//     case 1: \ell mod 3 = 1
//     if it's 1 byte (8 bits), then pad it with 4 zero bits to get 12 bits
//     now, encode these 12 bits to 2 base64url characters
//       normally, would add another 2 padding characters (i.e., ==), but not for JWTs
//     case 2: \ell mod 3 = 2
//     if it's 2 bytes (16 bits), then pad it with 2 zero bits to get 18 bits
//     now, encode these 18 bits to 3 base64url characters
//       normally, would add another 1 padding characters (i.e., =), but not for JWTs
//
//   decoding works as follows:
//   suppose encoded length is m
//   suppose plaintext is length \ell
//   from the algorithm above, 
//   if m mod 4 = 0, then the input was evenly divisible into 3 byte chunks
//     so \ell = 3 * m / 4
//   if m mod 4 = 2, then we are in case 1 above, where \ell mod 3 = 1
//     so \ell = \floor{3 * m / 4}
//       e.g., \ell = 1 => m = 2 => \floor{3 * 2 / 4} = \floor{6/4} = \floor{3/2} = 1
//       e.g., \ell = 3 + 1 => m = 4 + 2 => \floor{3 * 6 / 4} = \floor{9/2} = 4
//       e.g., \ell = k*3 + 1 => m = k*4 + 2 => \floor{3 * (k*4 + 2) / 4} =
//                                            = 3*k + \floor{6/4} = 3*k + 1
//   if m mod 4 = 3, then we are in case 2 above, where \ell mod 3 = 2
//      e.g., \ell = 2 => m = 3 => \floor{3 * 3 / 4} = \floor{9/4} = 2
//      e.g., \ell = 3 + 2 => m = 4 + 3 => \floor{3 * 7 / 4} = \floor{21/4} = 5
//      e.g., \ell = k*3 + 2 => m = k*4 + 3 => \floor{3 * (k*4 + 3) / 4} = 
//                                           = 3*k + \floor{9/4} = 3*k + 2
template Base64UrlDecodedLength(MAX_ENCODED_LEN) {
    assert(MAX_ENCODED_LEN > 0);
    var MAX_QUO = (3 * MAX_ENCODED_LEN) \ 4;
    var MAX_QUO_BITS = min_num_bits(MAX_QUO);

    signal input m; // encoded length
    
    signal q <-- 3*m \ 4;
    signal r <-- 3*m % 4;

    // Step 1: Check Euclidean division holds over \Zp
    3*m === 4*q + r;

    // Step 2: Checks that the remainder is less than the divisor (i.e., less than 4 <=> 2-bit)
    _ <== Num2Bits(2)(r);

    // TODO: May want to do another division to enforce m % 4 != 1

    // Step 3: Check that the quotient is bounded appropriately.
    _ <== Num2Bits(MAX_QUO_BITS)(q);
    
    // The decoded length is the quotient: i.e., \floor{3 * m / 4}
    signal output decoded_len <== q;
}