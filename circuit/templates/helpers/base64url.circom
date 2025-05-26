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

pragma circom 2.2.2;

include "base64url/Base64UrlLookup.circom";

include "circomlib/circuits/bitify.circom";

// Base64url-decodes an array of bytes into an array.
//
// @param   N    the maximum length of the *decoded* output, in bytes
//
// @input   in   the base64url-encoded input, as an array of zero-padded bytes
//
// @output  out  the decoded output, as an array of bytes
//
// @notes
//    Assumes `in` contains only base64url characters followed by 0-padding.
template Base64UrlDecode(N) {
    // If this was padded base64url, then the encoded input's maximum length is 4 * \ceil{N / 3}.
    // (We previously implemented it as: 4 * \floor{(N + 2) / 3}.)
    // Examples:
    //   N = 0 => M = 0
    //   N = 1 => M = 4
    //   N = 2 => M = 4
    //   N = 3 => M = 4
    //   N = 4 => M = 8
    //
    // If this was *un*padded, as is the case for JWTs, the max encoded length is \ceil{4N / 3}.
    // Examples:
    //   N = 0 => M = 0
    //   N = 1 => M = 2
    //   N = 2 => M = 3
    //   N = 3 => M = 4
    //   N = 4 => M = 6
    // (We implement this as: \floor{(4*N + 2) / 3}.)
    var M = (4*N + 2) \ 3;
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

        //log("range_AZ: ", range_AZ);
        for (var j = 0; j < 4; j++) {
            bits_in[i\4][j] = Num2Bits(6);

            //log("translate[i\\4][j].in: ", in[i+j]);

            translate[i\4][j] = Base64UrlLookup();
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