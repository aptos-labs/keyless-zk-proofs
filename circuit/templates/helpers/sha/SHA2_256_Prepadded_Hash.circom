pragma circom 2.2.2;

include "../arrays/SingleOneArray.circom";

include "../../stdlib/circuits/Sum.circom";

include "circomlib/circuits/sha256/constants.circom";
include "circomlib/circuits/sha256/sha256compression.circom";
include "circomlib/circuits/comparators.circom";

// Similar to `sha256_unsafe` in https://github.com/TheFrozenFire/snark-jwt-verify/blob/master/circuits/sha256.circom
// Hashes a bit array message using SHA2_256, hashing every block up to and including `tBlock`. All blocks after `tBlock` are ignored in the output
// Expects the bit array input to be padded according to https://www.rfc-editor.org/rfc/rfc4634.html#section-4.1 up to tBlock. 
template SHA2_256_Prepadded_Hash(maxNumBlocks) {
    signal input in[maxNumBlocks * 512];
    signal input tBlock;
    
    signal output out[256];

    component ha0 = H(0);
    component hb0 = H(1);
    component hc0 = H(2);
    component hd0 = H(3);
    component he0 = H(4);
    component hf0 = H(5);
    component hg0 = H(6);
    component hh0 = H(7);

    component sha256compression[maxNumBlocks];

    for(var i=0; i < maxNumBlocks; i++) {

        sha256compression[i] = Sha256compression();

        if (i==0) {
            for(var k = 0; k < 32; k++) {
                sha256compression[i].hin[0*32+k] <== ha0.out[k];
                sha256compression[i].hin[1*32+k] <== hb0.out[k];
                sha256compression[i].hin[2*32+k] <== hc0.out[k];
                sha256compression[i].hin[3*32+k] <== hd0.out[k];
                sha256compression[i].hin[4*32+k] <== he0.out[k];
                sha256compression[i].hin[5*32+k] <== hf0.out[k];
                sha256compression[i].hin[6*32+k] <== hg0.out[k];
                sha256compression[i].hin[7*32+k] <== hh0.out[k];
            }
        } else {
            for(var k = 0; k < 32; k++) {
                sha256compression[i].hin[32*0+k] <== sha256compression[i-1].out[32*0+31-k];
                sha256compression[i].hin[32*1+k] <== sha256compression[i-1].out[32*1+31-k];
                sha256compression[i].hin[32*2+k] <== sha256compression[i-1].out[32*2+31-k];
                sha256compression[i].hin[32*3+k] <== sha256compression[i-1].out[32*3+31-k];
                sha256compression[i].hin[32*4+k] <== sha256compression[i-1].out[32*4+31-k];
                sha256compression[i].hin[32*5+k] <== sha256compression[i-1].out[32*5+31-k];
                sha256compression[i].hin[32*6+k] <== sha256compression[i-1].out[32*6+31-k];
                sha256compression[i].hin[32*7+k] <== sha256compression[i-1].out[32*7+31-k];
            }
        }

        for (var k = 0; k < 512; k++) {
            sha256compression[i].inp[k] <== in[i*512 + k];
        }
    }
    
    // Collapse the hashing result at the terminating data block
    component calcTotal[256];
    signal eqs[maxNumBlocks] <== SingleOneArray(maxNumBlocks)(tBlock);

    // For each bit of the output
    for(var k = 0; k < 256; k++) {
        calcTotal[k] = Sum(maxNumBlocks);
        
        // For each possible block
        for (var i = 0; i < maxNumBlocks; i++) {

            // eqs[i] is 1 if the index matches. As such, at most one input to calcTotal is not 0.
            // The bit corresponding to the terminating data block will be raised
            calcTotal[k].nums[i] <== eqs[i] * sha256compression[i].out[k];
        }
        
        out[k] <== calcTotal[k].sum;
    }
}
