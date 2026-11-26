pragma circom 2.2.2;

/*
 * Faithful circom translation of the SHA-256 gadget set from the zkGolf
 * `sha256-hash` challenge leader (https://zk.golf/challenges/sha256-hash),
 * originally written in Lean 4 / Clean.
 *
 * All words are carried LSB-first: a `w[32]` array has numeric value
 * sum_i w[i] * 2^i.  This matches Clean's `valueBits`.
 *
 * Techniques translated (no new optimizations introduced):
 *
 *  1. `Xor3Row32`   - 3-input XOR in ONE rank-1 row per lane instead of the
 *                     two rows circomlib's `XOR3` needs.
 *  2. `SigmaTrunc`  - the upper-Sigma gadget drops its top lane's XOR row,
 *                     leaving `a31+b31+c31` unreduced.  Consumers only read
 *                     the packed value mod 2^32, and the slack is exactly
 *                     2^32*m, so 31 rows suffice.
 *  3. `PackedCh32` / `PackedMaj32`
 *                   - ONE witness + ONE row per lane pins BOTH rounds of a
 *                     round-pair, by placing the second round's bit at the
 *                     offset lambda = 2^40 (and, for Maj, using a quadratic
 *                     row whose spurious root is Omega = 2^80 away).
 *  4. `FusedE` / `FusedA`
 *                   - the two rounds' 32-bit additions are checked by a single
 *                     fused carry row each, the second round again lifted by
 *                     lambda = 2^40.
 *  5. `SchedStep`   - message schedule: sigma0/sigma1 3-input lanes get one row
 *                     each; the 2-input top lanes are packed in pairs whose
 *                     packing weight coincides with their positional weight;
 *                     the four-word addition is one fused row.
 *  6. `CarryAdd32`  - 32-bit addition as a carry chain: 32 rows, no separate
 *                     carry witnesses.
 */

// ROTR^k on an LSB-first word: out[i] = in[(i+k) % 32]
function rotrIdx(i, k) { return (i + k) % 32; }

// ---------------------------------------------------------------------------
// 3-input XOR, one rank-1 row per lane.
//
//   6a + 6b - 24c - (z + 2a + 2b + 7c)*(a + b - 4c + 1) = 0
//
// For boolean a,b,c the second factor takes values in {+-1,+-2,+-3}, never 0
// in F, so the row pins z to the parity a^b^c (and forces z boolean).
// ---------------------------------------------------------------------------
template Xor3Row32() {
    signal input a[32];
    signal input b[32];
    signal input c[32];
    signal output z[32];

    for (var i = 0; i < 32; i++) {
        z[i] <-- (a[i] + b[i] + c[i]) % 2;
        6*a[i] + 6*b[i] - 24*c[i]
            === (z[i] + 2*a[i] + 2*b[i] + 7*c[i]) * (a[i] + b[i] - 4*c[i] + 1);
    }
}

// ---------------------------------------------------------------------------
// Truncated upper Sigma: 31 XOR rows, top lane left unreduced.
// `out` is NOT bit-normalized: out[31] in {0,1,2,3}.  Its packed value is
// Sigma(x) + 2^32*m for m in {0,1} (Clean's `Numeric33`).
// ---------------------------------------------------------------------------
template SigmaTrunc(r0, r1, r2) {
    signal input x[32];
    signal output out[32];

    signal a[32];
    signal b[32];
    signal c[32];
    for (var i = 0; i < 32; i++) {
        a[i] <== x[rotrIdx(i, r0)];
        b[i] <== x[rotrIdx(i, r1)];
        c[i] <== x[rotrIdx(i, r2)];
    }
    for (var i = 0; i < 31; i++) {
        out[i] <-- (a[i] + b[i] + c[i]) % 2;
        6*a[i] + 6*b[i] - 24*c[i]
            === (out[i] + 2*a[i] + 2*b[i] + 7*c[i]) * (a[i] + b[i] - 4*c[i] + 1);
    }
    // top lane: free affine form, no row emitted
    out[31] <== a[31] + b[31] + c[31];
}

// Full (untruncated) upper Sigma0: ROTR2 ^ ROTR13 ^ ROTR22, all 32 rows.
// `FusedA` requires a bit-normalized sigma0, so this one is NOT truncated.
template Sigma0Full() {
    signal input x[32];
    signal output out[32];

    component t = Xor3Row32();
    for (var i = 0; i < 32; i++) {
        t.a[i] <== x[rotrIdx(i, 2)];
        t.b[i] <== x[rotrIdx(i, 13)];
        t.c[i] <== x[rotrIdx(i, 22)];
    }
    for (var i = 0; i < 32; i++) { out[i] <== t.z[i]; }
}

// Booleanity assertion on a 32-lane word.
template Bool32() {
    signal input v[32];
    for (var i = 0; i < 32; i++) { v[i] * (v[i] - 1) === 0; }
}

// ---------------------------------------------------------------------------
// Packed Ch for two consecutive rounds, one witness + one row per lane.
//
//   z[j] = Ch(e,f,g)[j] + lambda * Ch(u,e,f)[j],   lambda = 2^40
//
// Row (Lean `PackedCh.packedCh`):
//   (-3e + 2f + 4g + 2*lam*u) * (e - 2f + 4g - 2*lam*u)
//     + (3e + (8*lam+4)f - 8g + 4*lam^2*u - 8z) = 0
// ---------------------------------------------------------------------------
template PackedCh32() {
    signal input e[32];
    signal input f[32];
    signal input g[32];
    signal input u[32];
    signal output z[32];

    var lam = 2 ** 40;

    for (var j = 0; j < 32; j++) {
        // chBit(e,f,g) = g + e*(f-g)
        z[j] <-- (g[j] + e[j]*(f[j] - g[j]))
               + lam * (f[j] + u[j]*(e[j] - f[j]));
        (-3*e[j] + 2*f[j] + 4*g[j] + 2*lam*u[j])
          * (e[j] - 2*f[j] + 4*g[j] - 2*lam*u[j])
          + (3*e[j] + (8*lam + 4)*f[j] - 8*g[j] + 4*lam*lam*u[j] - 8*z[j]) === 0;
    }
}

// ---------------------------------------------------------------------------
// Packed Maj for two consecutive rounds, one witness + one row per lane.
//
//   z[j] = Maj(a,b,c)[j] + lambda * Maj(u,a,b)[j],  lambda = 2^40
//
// Row (Lean `PackedMaj.packedMaj`), with Omega = 2^80:
//   (z - ((1+lam)a + Om*(a-b))) * (z - (c + lam*u + Om*(1-a-b))) = 0
//
// The honest packed value is always one of the two roots; the other root is
// Omega-far, which the 35-bit addition window in `FusedA` cannot absorb.
// ---------------------------------------------------------------------------
template PackedMaj32() {
    signal input a[32];
    signal input b[32];
    signal input c[32];
    signal input u[32];
    signal output z[32];

    var lam = 2 ** 40;
    var om  = 2 ** 80;

    for (var j = 0; j < 32; j++) {
        // majBit(a,b,c) = a*b + c*(a + b - 2ab)
        z[j] <-- (a[j]*b[j] + c[j]*(a[j] + b[j] - 2*a[j]*b[j]))
               + lam * (u[j]*a[j] + b[j]*(u[j] + a[j] - 2*u[j]*a[j]));
        (z[j] - ((1 + lam)*a[j] + om*(a[j] - b[j])))
          * (z[j] - (c[j] + lam*u[j] + om*(1 - a[j] - b[j]))) === 0;
    }
}

// ---------------------------------------------------------------------------
// Fused E-adder: checks BOTH rounds' e-updates with 6 rows total.
//
//   newE  = d + h + sig1t  + Ch(e,f,g)    + k0 + w0   (mod 2^32)
//   newEp = c + g + sig1tp + Ch(newE,e,f) + k1 + w1   (mod 2^32)
//
// The Ch terms arrive packed in `z` (PackedCh32): value(z) = Ch_t + lam*Ch_tp.
// Lean asserts `lowCarry * (lowCarry - 1) === 0` where lowCarry is the
// 2^-32-scaled residue.  We scale by 2^32 to avoid a field inverse: with
// L = 2^32 * lowCarry the row is L * (L - 2^32) === 0.
// ---------------------------------------------------------------------------
template FusedE() {
    signal input newE[32];
    signal input newEp[32];
    signal input z[32];      // packed Ch
    signal input e[32];
    signal input f[32];
    signal input g[32];
    signal input sig1t[32];  // Numeric33
    signal input sig1tp[32]; // Numeric33
    signal input d[32];
    signal input h[32];
    signal input c[32];
    signal input w0[32];
    signal input w1[32];
    signal input k0;
    signal input k1;

    var lam = 2 ** 40;
    var W32 = 2 ** 32;

    signal ce_t[2];   // high carry bits of round t   (weights 2, 4)
    signal ce_tp[3];  // carry bits of round t+1      (weights 1, 2, 4)

    // ---- witness generation (numeric) ----
    var vd = 0; var vh = 0; var vs1t = 0; var vs1tp = 0;
    var vc = 0; var vg = 0; var vw0 = 0; var vw1 = 0;
    var ve = 0; var vf = 0; var vnewE = 0;
    for (var i = 0; i < 32; i++) {
        vd    += d[i]      * 2**i;
        vh    += h[i]      * 2**i;
        vs1t  += sig1t[i]  * 2**i;
        vs1tp += sig1tp[i] * 2**i;
        vc    += c[i]      * 2**i;
        vg    += g[i]      * 2**i;
        vw0   += w0[i]     * 2**i;
        vw1   += w1[i]     * 2**i;
        ve    += e[i]      * 2**i;
        vf    += f[i]      * 2**i;
        vnewE += newE[i]   * 2**i;
    }
    var chT  = (vg ^ (ve & (vf ^ vg)));
    var chTp = (vf ^ (vnewE & (ve ^ vf)));

    var st  = vd + vh + vs1t + chT  + k0 + vw0;
    var stp = vc + vg + vs1tp + chTp + k1 + vw1;

    for (var j = 0; j < 2; j++) { ce_t[j]  <-- (st  \ W32 \ (2**(j+1))) % 2; }
    for (var j = 0; j < 3; j++) { ce_tp[j] <-- (stp \ W32 \ (2**j))     % 2; }

    // ---- rows ----
    for (var j = 0; j < 2; j++) { ce_t[j]  * (ce_t[j]  - 1) === 0; }
    for (var j = 0; j < 3; j++) { ce_tp[j] * (ce_tp[j] - 1) === 0; }

    var L = k0 + lam * k1;
    for (var i = 0; i < 32; i++) {
        L += (d[i] + h[i] + sig1t[i] + w0[i]) * 2**i;
        L += z[i] * 2**i;
        L += lam * (c[i] + g[i] + sig1tp[i] + w1[i]) * 2**i;
        L -= newE[i] * 2**i;
        L -= lam * newEp[i] * 2**i;
    }
    L -= lam * W32 * (ce_tp[0] + 2*ce_tp[1] + 4*ce_tp[2]);
    L -= W32 * (2*ce_t[0] + 4*ce_t[1]);

    L * (L - W32) === 0;
}

// ---------------------------------------------------------------------------
// Fused A-adder: checks BOTH rounds' a-updates with 4 rows total.
//
//   newA  = newE  + sig0t  + Maj(a,b,c)    + (2^32-1-d) + 1  (mod 2^32)
//   newAp = newEp + sig0tp + Maj(newA,a,b) + (2^32-1-c) + 1  (mod 2^32)
//
// (`- d` is written as `+ NOT d + 1` so the row stays over the naturals.)
// The Maj terms arrive packed in `z` (PackedMaj32).
// ---------------------------------------------------------------------------
template FusedA() {
    signal input newA[32];
    signal input newAp[32];
    signal input newE[32];
    signal input newEp[32];
    signal input sig0t[32];
    signal input sig0tp[32];
    signal input z[32];   // packed Maj
    signal input a[32];
    signal input b[32];
    signal input c[32];
    signal input d[32];

    var lam = 2 ** 40;
    var W32 = 2 ** 32;

    signal ca_t[1];
    signal ca_tp[2];

    var vnewE = 0; var vnewEp = 0; var vs0t = 0; var vs0tp = 0;
    var va = 0; var vb = 0; var vc = 0; var vd = 0; var vnewA = 0;
    for (var i = 0; i < 32; i++) {
        vnewE  += newE[i]   * 2**i;
        vnewEp += newEp[i]  * 2**i;
        vs0t   += sig0t[i]  * 2**i;
        vs0tp  += sig0tp[i] * 2**i;
        va     += a[i]      * 2**i;
        vb     += b[i]      * 2**i;
        vc     += c[i]      * 2**i;
        vd     += d[i]      * 2**i;
        vnewA  += newA[i]   * 2**i;
    }
    var majT  = ((va & vb) ^ (va & vc) ^ (vb & vc));
    var majTp = ((vnewA & va) ^ (vnewA & vb) ^ (va & vb));

    var st  = vnewE  + vs0t  + majT  + (W32 - 1 - vd) + 1;
    var stp = vnewEp + vs0tp + majTp + (W32 - 1 - vc) + 1;

    ca_t[0] <-- (st \ W32 \ 2) % 2;
    for (var j = 0; j < 2; j++) { ca_tp[j] <-- (stp \ W32 \ (2**j)) % 2; }

    ca_t[0] * (ca_t[0] - 1) === 0;
    for (var j = 0; j < 2; j++) { ca_tp[j] * (ca_tp[j] - 1) === 0; }

    var L = 1 + lam;   // the two "+1"s
    for (var i = 0; i < 32; i++) {
        L += (newE[i] + sig0t[i] + (1 - d[i])) * 2**i;
        L += z[i] * 2**i;
        L += lam * (newEp[i] + sig0tp[i] + (1 - c[i])) * 2**i;
        L -= newA[i] * 2**i;
        L -= lam * newAp[i] * 2**i;
    }
    L -= lam * W32 * (ca_tp[0] + 2*ca_tp[1]);
    L -= W32 * (2*ca_t[0]);

    L * (L - W32) === 0;
}

// ---------------------------------------------------------------------------
// 32-bit addition as a carry chain: 32 rows, no explicit carry witnesses.
//
//   c_0 = 0,  c_{i+1} = (a_i + b_i + c_i - z_i)/2
//
// each row being the Maj-style relation pinning c_{i+1} = maj(a_i,b_i,c_i):
//   (c_{i+1} + a_i + b_i - 9 c_i + 3) * (a_i + b_i + 6 c_i - 4) + 12 = 0
//
// Unrolling the recursion gives c_i = 2^{-i} * sum_{j<i} (a_j+b_j-z_j) 2^j, so
// the row is emitted scaled by 2^{2i+1} to stay free of field inverses.
// ---------------------------------------------------------------------------
template CarryAdd32() {
    signal input a[32];
    signal input b[32];
    signal output z[32];

    var va = 0; var vb = 0;
    for (var i = 0; i < 32; i++) { va += a[i]*2**i; vb += b[i]*2**i; }
    var s = (va + vb) % (2**32);
    for (var i = 0; i < 32; i++) { z[i] <-- (s \ (2**i)) % 2; }

    for (var i = 0; i < 32; i++) {
        // ci  = 2^i     * c_i
        // cn  = 2^{i+1} * c_{i+1}
        var ci = 0;
        for (var j = 0; j < i; j++) { ci += (a[j] + b[j] - z[j]) * (2 ** j); }
        var cn = ci + (a[i] + b[i] - z[i]) * (2 ** i);

        // F1 = 2^{i+1} * (c_{i+1} + a_i + b_i - 9 c_i + 3)
        // F2 = 2^{i}   * (a_i + b_i + 6 c_i - 4)
        var F1 = cn - 18*ci + (a[i] + b[i] + 3) * (2 ** (i + 1));
        var F2 = 6*ci + (a[i] + b[i] - 4) * (2 ** i);

        F1 * F2 + 12 * (2 ** (2*i + 1)) === 0;
    }
}
