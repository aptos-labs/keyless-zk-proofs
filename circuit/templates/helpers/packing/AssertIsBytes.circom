/**
 * Author: Michael Straka, Alin Tomescu
 */
pragma circom 2.2.2;

// for Num2Bits
include "circomlib/circuits/bitify.circom";

// Enforces that each scalar in an array is a byte.
//
// @param   NUM_BYTES   the size of the input array
//
// @input   in          the input array of NUM_BYTES signals
//
// @postconditions      in[i] \in [0, 256), \forall i \in [0, NUM_BYTES)
template AssertIsBytes(NUM_BYTES) {
    signal input in[NUM_BYTES];

    for (var i = 0; i < NUM_BYTES; i++) {
        _ <== Num2Bits(8)(in[i]);
    }
}