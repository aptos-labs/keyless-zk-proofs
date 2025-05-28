pragma circom 2.2.2;

include "helpers/strings/AssertIsConcatenation.circom";

component main = AssertIsConcatenation(
    192*8,      // MAX_B64U_JWT_NO_SIG_LEN
    300,        // MAX_B64U_JWT_HEADER_W_DOT_LEN
    192*8-64    // MAX_B64U_JWT_PAYLOAD_SHA2_PADDED_LEN
);