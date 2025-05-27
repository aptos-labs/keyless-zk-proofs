pragma circom 2.2.2;

include "helpers/sha/SHA2_256_PaddingVerify.circom";

component main = SHA2_256_PaddingVerify(256); // 4 blocks
