pragma circom 2.2.2;

/**
 * Outputs an array of bits containing the N-bit representation of the input number, with
 * the most significant bit first and the least signficant last (opposite of Num2Bits).
 *
 * This effectively acts as a range check for the input number being in [0, 2^N).
 *
 * @param   N   correctness only holds if the number is in [0, 2^N)
 *              soundness is unconditional, but only when 2^N - 1 "fits" in a scalar
 *              (i.e, numbers >= 2^N cannot satisfy this template if 2^N - 1 "fits")
 *
 * @preconditions
 *   $2^N - 1 < p$
 *
 * @input   num             the number to be converted to binary
 *
 * @output  bits {binary}   an array bits[N-1], ..., bits[0] of the N bits representing
 *                          `num` with bits[N-1] being the least significant one
 *
 * @postconditions
 *    $bits[i] \in \{0, 1\}$
 *    $num = \sum_{i = 0}^{N-1} 2^{(N-1)-i} bits[i]$
 */
template Num2BigEndianBits(n) {
    signal input in;
    signal output out[n];

    // incrementally-updated to eventually store the symbolic expression:
    //
    //   bits[0] * 2^{N-1} + bits[1] * 2^{N-2} + bits[2] * 2^{N-3} + ... + bits[N-2] * 2^1 + bits[N-1] * 2^0
    //
    var num = 0;
    var pow2 = 1;

    for (var i = 0; i < n; i++) {
        var idx = (n - 1) - i;

        out[idx] <-- (in >> i) & 1;
        out[idx] * (out[idx] - 1) === 0;

        num += out[idx] * pow2;

        pow2 = pow2 + pow2;
    }

    num === in;
}
