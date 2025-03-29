/**
 * This file implements the base64url scheme as per RFC 7515 (see https://datatracker.ietf.org/doc/html/rfc7515#appendix-C).
 *
 * Most importantly, this base64url flavor does not append = padding characters at the end.
 *
 * For more details, see: http://alinush.org/keyless#base64url.
 *
 * This file started as a modification of zkEmail's base64 libraries:
 *
 *   https://github.com/zkemail/zk-email-verify/blob/main/packages/circuits/helpers/base64.circom
 *
 */

pragma circom 2.1.3;

include "circomlib/circuits/comparators.circom";

include "../stdlib/functions/min_num_bits.circom";

// http://0x80.pl/notesen/2016-01-17-sse-base64-decoding.html#vector-lookup-base
// Modified to support base64url format instead.
// Also accepts zero padding, which is not in the base64url format.
// TODO(Comment): Seems to take an 8-bit base64 character and return its 6 bit decoding?
template Base64URLLookup() {
    signal input in;
    signal output out;

    // ['A', 'Z']
    component le_Z = LessThan(8);
    le_Z.in[0] <== in;
    le_Z.in[1] <== 90+1;

    component ge_A = GreaterThan(8);
    ge_A.in[0] <== in;
    ge_A.in[1] <== 65-1;

    signal range_AZ <== ge_A.out * le_Z.out;
    signal sum_AZ <== range_AZ * (in - 65);

    // ['a', 'z']
    component le_z = LessThan(8);
    le_z.in[0] <== in;
    le_z.in[1] <== 122+1;

    component ge_a = GreaterThan(8);
    ge_a.in[0] <== in;
    ge_a.in[1] <== 97-1;

    signal range_az <== ge_a.out * le_z.out;
    signal sum_az <== sum_AZ + range_az * (in - 71);

    // ['0', '9']
    component le_9 = LessThan(8);
    le_9.in[0] <== in;
    le_9.in[1] <== 57+1;

    component ge_0 = GreaterThan(8);
    ge_0.in[0] <== in;
    ge_0.in[1] <== 48-1;

    signal range_09 <== ge_0.out * le_9.out;
    signal sum_09 <== sum_az + range_09 * (in + 4);

    // '-'
    component equal_minus = IsZero();
    equal_minus.in <== in - 45;
    // https://www.cs.cmu.edu/~pattis/15-1XX/common/handouts/ascii.html ascii '-' (45)
    // https://base64.guru/learn/base64-characters  == 62 in base64
    signal sum_minus <== sum_09 + equal_minus.out * 62;

    // '_'
    component equal_underscore = IsZero();
    equal_underscore.in <== in - 95;
    // https://www.cs.cmu.edu/~pattis/15-1XX/common/handouts/ascii.html ascii '_' (95)
    // https://base64.guru/learn/base64-characters == 63 in base64
    signal sum_underscore <== sum_minus + equal_underscore.out * 63;

    out <== sum_underscore;
    //log("sum_underscore (out): ", out);

    // '='
    component equal_eqsign = IsZero();
    equal_eqsign.in <== in - 61;

    // Also decode zero padding as zero padding
    component zero_padding = IsZero();
    zero_padding.in <== in;


    //log("zero_padding.out: ", zero_padding.out);
    //log("equal_eqsign.out: ", equal_eqsign.out);
    //log("equal_underscore.out: ", equal_underscore.out);
    //log("equal_minus.out: ", equal_minus.out);
    //log("range_09: ", range_09);
    //log("range_az: ", range_az);
    //log("range_AZ: ", range_AZ);
    //log("< end Base64URLLookup");

    signal result <== range_AZ + range_az + range_09 + equal_minus.out + equal_underscore.out + equal_eqsign.out + zero_padding.out;
    1 === result;
}

// Takes in an array `in` of base64url characters and decodes it to ASCII characters in `out`. 
// `in` may be 0-padded after its base64 elements.
// Assumes `in` contains only base64url characters followed by 0-padding.
template Base64UrlDecode(N) {
    //var N = ((3*M)\4)+2; // Rough inverse of the computation performed to compute M
    var M = 4*((N+2)\3);
    signal input in[M];
    signal output out[N];

    component bits_in[M\4][4];
    component bits_out[M\4][3];
    component translate[M\4][4];

    var idx = 0;
    for (var i = 0; i < M; i += 4) {
        for (var j = 0; j < 3; j++) {
            bits_out[i\4][j] = Bits2Num(8);
        }


        //     log("range_AZ: ", range_AZ);
        for (var j = 0; j < 4; j++) {
            bits_in[i\4][j] = Num2Bits(6);

            //log(">> calling into Base64URLLookup");
            //log("translate[i\\4][j].in: ", in[i+j]);

            translate[i\4][j] = Base64URLLookup();
            translate[i\4][j].in <== in[i+j];
            translate[i\4][j].out ==> bits_in[i\4][j].in;
        }

        // Do the re-packing from four 6-bit words to three 8-bit words.
        for (var j = 0; j < 6; j++) {
            bits_out[i\4][0].in[j+2] <== bits_in[i\4][0].out[j];
        }
        bits_out[i\4][0].in[0] <== bits_in[i\4][1].out[4];
        bits_out[i\4][0].in[1] <== bits_in[i\4][1].out[5];

        for (var j = 0; j < 4; j++) {
            bits_out[i\4][1].in[j+4] <== bits_in[i\4][1].out[j];
        }
        for (var j = 0; j < 4; j++) {
            bits_out[i\4][1].in[j] <== bits_in[i\4][2].out[j+2];
        }

        bits_out[i\4][2].in[6] <== bits_in[i\4][2].out[0];
        bits_out[i\4][2].in[7] <== bits_in[i\4][2].out[1];
        for (var j = 0; j < 6; j++) {
            bits_out[i\4][2].in[j] <== bits_in[i\4][3].out[j];
        }

        for (var j = 0; j < 3; j++) {
            if (idx+j < N) {
                out[idx+j] <== bits_out[i\4][j].out;
            }
        }
        idx += 3;
    }
}

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
    3*m === q * 4 + r;

    // Step 2: Checks that the remainder is less than the divisor (i.e., less than 4 <=> 2-bit)
    _ <== Num2Bits(2)(r);

    // TODO: May want to do another division to enforce m % 4 != 1

    // Step 3: Check that the quotient is bounded appropriately.
    _ <== Num2Bits(MAX_QUO_BITS)(q);
    
    // The decoded length is the quotient: i.e., \floor{3 * m / 4}
    signal output decoded_len <== q;
}
