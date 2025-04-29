/**
 * Author: Alin Tomescu
 */
pragma circom 2.2.2;

include "MAX_BITS.circom";

/**
 * Utility method used to make sure an N-bit *unsigned* number will fit in a scalar, * for the curently-selected circom scalar field.
 */
function assert_bits_fit_scalar(N) {
    var max_bits = MAX_BITS();
    log("N: ", N);
    log("MAX_BITS(): ", max_bits);

    assert(N <= max_bits);

    return 0;   // circom needs you to return!
}
