pragma circom 2.2.2;

// Template originally from https://github.com/doubleblind-xyz/circom-rsa/blob/master/circuits/bigint.circom

include "circomlib/circuits/bitify.circom";
include "circomlib/circuits/comparators.circom";
include "circomlib/circuits/gates.circom";

template CheckCarryToZero(N, M, K) {
    assert(K >= 2);

    var EPSILON = 3;

    assert(M + EPSILON <= 253);

    signal input in[K];

    signal carry[K];
    component carryRangeChecks[K];
    for (var i = 0; i < K-1; i++){
        carryRangeChecks[i] = Num2Bits(M + EPSILON - N);
        if( i == 0 ){
            carry[i] <-- in[i] / (1<<N);
            in[i] === carry[i] * (1<<N);
        }
        else{
            carry[i] <-- (in[i]+carry[i-1]) / (1<<N);
            in[i] + carry[i-1] === carry[i] * (1<<N);
        }
        // checking carry is in the range of - 2^(M-N-1+eps), 2^(M+-N-1+eps)
        carryRangeChecks[i].in <== carry[i] + ( 1<< (M + EPSILON - N - 1));
    }
    in[K-1] + carry[K-2] === 0;
}
