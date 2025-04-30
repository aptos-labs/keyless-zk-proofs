/**
 * Author: Michael Straka, Alin Tomescu
 */
pragma circom 2.2.2;

// for Num2Bits
include "circomlib/circuits/bitify.circom";

// Enforces that each scalar in an array is 64-bits.
//
// @param   NUM_LIMBS   the size of the input array
//
// @input   in          the input array of NUM_LIMBS signals
//
// @postconditions      in[i] \in [0, 2^{64}), \forall i \in [0, NUM_LIMBS)
template AssertIs64BitLimbs(NUM_LIMBS) {
    signal input in[NUM_LIMBS];

    for (var i = 0; i < NUM_LIMBS; i++) {
        _ <== Num2Bits(64)(in[i]);
    }
}