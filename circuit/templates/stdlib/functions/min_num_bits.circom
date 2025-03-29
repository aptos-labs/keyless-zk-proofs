pragma circom 2.1.3;

include "./log2_floor.circom";

/**
 * Returns the minimum # of bits needed to represent n.
 * 
 * Note: Representing 0 is assumed to be done via 1 (zero) bit.
 *
 * Examples:
 *   n = 0                --> 1
 *   n = 1                --> 1
 *   n = 2,3              --> 2
 *   n = 4,5,6,7          --> 3
 *   n \in [2^k, 2^{k+1}) --> k + 1
 */
function min_num_bits(n) {
    if(n == 0) {
        return 1;
    }

    return log2_floor(n) + 1;
}