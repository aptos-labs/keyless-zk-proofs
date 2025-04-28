pragma circom 2.2.2;

include "helpers/rsa/rsa_verify.circom";

component main = RsaVerifyPkcs1v15(64, 32);
