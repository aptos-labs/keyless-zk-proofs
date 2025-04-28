pragma circom 2.2.2;

include "helpers/sha.circom";

component main = Sha2PaddingVerify(256); // 4 blocks
