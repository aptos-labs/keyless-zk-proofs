pragma circom 2.2.2;

// Template originally from https://github.com/doubleblind-xyz/circom-rsa/blob/master/circuits/bigint.circom

include "circomlib/circuits/bitify.circom";
include "circomlib/circuits/comparators.circom";
include "circomlib/circuits/gates.circom";

template CheckCarryToZero(n, m, k) {
    assert(k >= 2);

    var EPSILON = 3;

    assert(m + EPSILON <= 253);

    signal input in[k];

    signal carry[k];
    component carryRangeChecks[k];
    for (var i = 0; i < k-1; i++){
        carryRangeChecks[i] = Num2Bits(m + EPSILON - n);
        if( i == 0 ){
            carry[i] <-- in[i] / (1<<n);
            in[i] === carry[i] * (1<<n);
        }
        else{
            carry[i] <-- (in[i]+carry[i-1]) / (1<<n);
            in[i] + carry[i-1] === carry[i] * (1<<n);
        }
        // checking carry is in the range of - 2^(m-n-1+eps), 2^(m+-n-1+eps)
        carryRangeChecks[i].in <== carry[i] + ( 1<< (m + EPSILON - n - 1));
    }
    in[k-1] + carry[k-2] === 0;
}
