pragma circom 2.2.2;

include "circomlib/circuits/comparators.circom";

// Given an 8-bit base64 character, returns its 6-bit decoding.
// Handles the '=' base64 padding character, even though it is not needed for JWTs.
//
// @input   in   the 8-bit base64 alphabet character
//
// @output  out  the 6-bit decoded bits corresponding to `in`
//
// @notes
//    From [here](http://0x80.pl/notesen/2016-01-17-sse-base64-decoding.html#vector-lookup-base), but
//    modified to support base64url instead.
template Base64UrlLookup() {
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

    signal result <== range_AZ + range_az + range_09 + equal_minus.out + equal_underscore.out + equal_eqsign.out + zero_padding.out;
    1 === result;
}