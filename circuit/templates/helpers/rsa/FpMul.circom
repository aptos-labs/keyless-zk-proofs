pragma circom 2.2.2;

// File copied from https://github.com/doubleblind-xyz/circom-rsa/blob/master/circuits/fp.circom

include "circomlib/circuits/bitify.circom";

include "../bigint/CheckCarryToZero.circom";
include "../bigint/functions/all.circom";

// These functions operate over values in Z/Zp for some integer p (typically,
// but not necessarily prime). Values are stored as standard bignums with K
// chunks of N bits, but intermediate values often have "overflow" bits inside
// various chunks.
//
// These Fp functions will always correctly generate witnesses mod p, but they
// do not *check* that values are normalized to < p; they only check that
// values are correct mod p. This is to save the comparison circuit.
// They *will* always check for intended results mod p (soundness), but it may
// not have a unique intermediate signal.
//
// Conversely, some templates may not be satisfiable if the input witnesses are
// not < p. This does not break completeness, as honest provers will always
// generate witnesses which are canonical (between 0 and p).

// a * b = r mod p
// a * b - p * q - r for some q
template FpMul(N, K) {
    assert(N + N + log_ceil(K) + 2 <= 252);
    signal input a[K];
    signal input b[K];
    signal input p[K];

    signal output out[K];

    signal v_ab[2*K-1];
    for (var x = 0; x < 2*K-1; x++) {
        var v_a = poly_eval(K, a, x);
        var v_b = poly_eval(K, b, x);
        v_ab[x] <== v_a * v_b;
    }

    var ab[200] = poly_interp(2*K-1, v_ab);
    // ab_proper has length 2*K
    var ab_proper[200] = getProperRepresentation(N + N + log_ceil(K), N, 2*K-1, ab);

    var long_div_out[2][100] = long_div(N, K, K, ab_proper, p);

    // Since we're only computing a*b, we know that q < p will suffice, so we
    // know it fits into K chunks and can do size N range checks.
    signal q[K];
    component q_range_check[K];
    signal r[K];
    component r_range_check[K];
    for (var i = 0; i < K; i++) {
        q[i] <-- long_div_out[0][i];
        q_range_check[i] = Num2Bits(N);
        q_range_check[i].in <== q[i];

        r[i] <-- long_div_out[1][i];
        r_range_check[i] = Num2Bits(N);
        r_range_check[i].in <== r[i];
    }

    signal v_pq_r[2*K-1];
    for (var x = 0; x < 2*K-1; x++) {
        var v_p = poly_eval(K, p, x);
        var v_q = poly_eval(K, q, x);
        var v_r = poly_eval(K, r, x);
        v_pq_r[x] <== v_p * v_q + v_r;
    }

    signal v_t[2*K-1];
    for (var x = 0; x < 2*K-1; x++) {
        v_t[x] <== v_ab[x] - v_pq_r[x];
    }

    var t[200] = poly_interp(2*K-1, v_t);
    component tCheck = CheckCarryToZero(N, N + N + log_ceil(K) + 2, 2*K-1);
    for (var i = 0; i < 2*K-1; i++) {
        tCheck.in[i] <== t[i];
    }

    for (var i = 0; i < K; i++) {
        out[i] <== r[i];
    }
}
