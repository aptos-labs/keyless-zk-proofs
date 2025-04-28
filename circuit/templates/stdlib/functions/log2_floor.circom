pragma circom 2.2.2;

/**
 * Given a natural number n > 0, returns \floor{\log_2{n}}.
 *
 * Arguments:
 *   n  non-zero, natural number 
 *      (presumed not to have been >= p and thus not to have been wrapped around)
 *
 * Returns:
 *   \floor{\log_2{n}}
 *
 * Examples:
 *   n = 0                     --> undefined
 *   n = 1                     --> 0
 *   n = 2,3                   --> 1
 *   n = 4,5,6,7               --> 2
 *   n = 8,9,10,11,12,13,14,15 --> 3
 */
function log2_floor(n) {
	assert(n != 0);

    var log2 = 0;

    // WARNING: Do not use <, >, <=, >= comparison operators here or you will
    // suffer from circom's signed numbers semantics!
    while (n != 1) {
        log2 += 1;
        n \= 2;
    }

    return log2;
}