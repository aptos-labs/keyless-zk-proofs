/**
 * Author: Alin Tomescu
 */
pragma circom 2.2.2;

/**
 * Computes the maximum bit-width $b$ such that an *unsigned* $2^b - 1$ value can
 * be always stored in a circom scalar in $\mathbb{Z}_p$, without it wrapping around
 * after being reduced modulo $p$.
 *
 * Leverages the fact that circom comparison operators treat scalars in $[0, p/2]$
 * as positive, while every $v \in (p/2, p)$ is treated as negative (i.e., as
 * $v - p$ instead of as $v$).
 */
function MAX_BITS() {
    var n = 1;
    var b = 1;

    while (2 * n > n) {
        n = n * 2;
        b = b + 1;
    }

    return b;
}