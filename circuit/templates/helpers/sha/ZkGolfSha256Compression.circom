pragma circom 2.2.2;

include "./ZkGolfSha256Gadgets.circom";

/*
 * SHA-256 message schedule step and block compression, translated from the
 * zkGolf `sha256-hash` Lean solution.  See ZkGolfSha256Gadgets.circom.
 *
 * `Sha256compressionZkGolf()` is a drop-in replacement for circomlib's
 * `Sha256compression()`: same big-endian-per-word bit interface.
 */

function shaK(t) {
    var K[64] = [
        0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5,
        0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
        0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3,
        0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
        0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc,
        0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
        0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7,
        0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
        0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13,
        0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
        0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3,
        0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
        0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5,
        0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
        0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208,
        0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2
    ];
    return K[t];
}

// ---------------------------------------------------------------------------
// One message-schedule step:
//   w = sigma1(wm2) + wm7 + sigma0(wm15) + wm16   (mod 2^32)
//
// sigma0(x) = ROTR7 ^ ROTR18 ^ SHR3   -> lanes 0..28 are 3-input, 29..31 2-input
// sigma1(x) = ROTR17 ^ ROTR19 ^ SHR10 -> lanes 0..21 are 3-input, 22..31 2-input
//
// The 3-input lanes get one `Xor3Row32`-style row each (29 + 22 rows).
// The 2-input lanes are packed in pairs whose packing weight coincides with
// their positional weight, so one witness + one row covers two lanes:
//   u0 = s1[22] + 4*s1[24]   placed at lane 22  (4*2^22 = 2^24)
//   u1 = s1[23] + 4*s1[25]   placed at lane 23
//   u2 = s1[26] + 4*s1[28]   placed at lane 26
//   u3 = s1[27] + 4*s1[29]   placed at lane 27
//   u4 = s1[30] +   s0[30]   placed at lane 30  (both already weight 2^30)
//   u5 = s1[31] +   s0[31]   placed at lane 31
//   v  = s0[29]              placed at lane 29  (its own 2-input row)
// The four-word sum is then a single fused carry row.
//
// Total: 91 witnesses, 92 rows.
// ---------------------------------------------------------------------------
template SchedStep() {
    signal input wm2[32];
    signal input wm7[32];
    signal input wm15[32];
    signal input wm16[32];
    signal output w[32];

    var W32 = 2 ** 32;

    // rotated / shifted views (pure rewiring)
    signal r7[32];  signal r18[32]; signal sh3[32];
    signal r17[32]; signal r19[32]; signal sh10[32];
    for (var i = 0; i < 32; i++) {
        r7[i]  <== wm15[rotrIdx(i, 7)];
        r18[i] <== wm15[rotrIdx(i, 18)];
        sh3[i] <== (i + 3 < 32) ? wm15[i + 3] : 0;
        r17[i] <== wm2[rotrIdx(i, 17)];
        r19[i] <== wm2[rotrIdx(i, 19)];
        sh10[i]<== (i + 10 < 32) ? wm2[i + 10] : 0;
    }

    signal s0[29];
    signal s1[22];
    signal u[6];
    signal v;
    signal z[32];
    signal c1;

    // --- sigma0 3-input lanes 0..28 ---
    for (var i = 0; i < 29; i++) {
        s0[i] <-- (r7[i] + r18[i] + sh3[i]) % 2;
        6*r7[i] + 6*r18[i] - 24*sh3[i]
            === (s0[i] + 2*r7[i] + 2*r18[i] + 7*sh3[i])
                * (r7[i] + r18[i] - 4*sh3[i] + 1);
    }

    // --- sigma1 3-input lanes 0..21 ---
    for (var i = 0; i < 22; i++) {
        s1[i] <-- (r17[i] + r19[i] + sh10[i]) % 2;
        6*r17[i] + 6*r19[i] - 24*sh10[i]
            === (s1[i] + 2*r17[i] + 2*r19[i] + 7*sh10[i])
                * (r17[i] + r19[i] - 4*sh10[i] + 1);
    }

    // --- packed 2-input pair lanes ---
    // Row shape for u = (A^B) + m*(C^D), with X = 1 - A + B and Y = m'*(C+D):
    //   2A - 2B + 2m'*(C+D)... expanded below exactly as in Lean's ScheduleStep.
    //
    // weight-4 pairs (m = 4, i.e. Y = 2*(C+D))
    var pl[4] = [22, 23, 26, 27];
    var ph[4] = [24, 25, 28, 29];
    for (var t = 0; t < 4; t++) {
        var lo = pl[t];
        var hi = ph[t];
        u[t] <-- ((r17[lo] + r19[lo]) % 2) + 4 * ((r17[hi] + r19[hi]) % 2);
        2*r17[lo] - 2*r19[lo] + 8*(r17[hi] + r19[hi]) - 1 - u[t]
          === (2*(r17[hi] + r19[hi]) - (1 - r17[lo] + r19[lo]))
            * (2*(r17[hi] + r19[hi]) + (1 - r17[lo] + r19[lo]));
    }
    // weight-1 pairs: sigma1 lane j with sigma0 lane j, j = 30, 31
    for (var t = 0; t < 2; t++) {
        var j = 30 + t;
        u[4 + t] <-- ((r17[j] + r19[j]) % 2) + ((r7[j] + r18[j]) % 2);
        2*r17[j] - 2*r19[j] + 2*(r7[j] + r18[j]) - 1 - u[4 + t]
          === ((r7[j] + r18[j]) - (1 - r17[j] + r19[j]))
            * ((r7[j] + r18[j]) + (1 - r17[j] + r19[j]));
    }
    // --- sigma0 lane 29: plain determined 2-input XOR row ---
    v <-- (r7[29] + r18[29]) % 2;
    v - r7[29] - r18[29] + 2*r7[29]*r18[29] === 0;

    // --- the combined sigma word `tVec` (lane-wise, possibly unreduced) ---
    // value(tVec) = sigma0(wm15) + sigma1(wm2)
    var tVal = 0;
    for (var i = 0; i < 22; i++)  { tVal += (s0[i] + s1[i]) * 2**i; }
    tVal += (s0[22] + u[0]) * 2**22;
    tVal += (s0[23] + u[1]) * 2**23;
    tVal += s0[24] * 2**24;
    tVal += s0[25] * 2**25;
    tVal += (s0[26] + u[2]) * 2**26;
    tVal += (s0[27] + u[3]) * 2**27;
    tVal += s0[28] * 2**28;
    tVal += v      * 2**29;
    tVal += u[4]   * 2**30;
    tVal += u[5]   * 2**31;

    var vwm7 = 0; var vwm16 = 0;
    for (var i = 0; i < 32; i++) { vwm7 += wm7[i]*2**i; vwm16 += wm16[i]*2**i; }
    var S = tVal + vwm7 + vwm16;

    for (var i = 0; i < 32; i++) { z[i] <-- ((S % W32) \ (2**i)) % 2; }
    c1 <-- (S \ W32 \ 2) % 2;

    for (var i = 0; i < 32; i++) { z[i] * (z[i] - 1) === 0; }
    c1 * (c1 - 1) === 0;

    // fused low-carry booleanity + recomposition, scaled by 2^32
    var L = tVal;
    for (var i = 0; i < 32; i++) { L += (wm7[i] + wm16[i] - z[i]) * 2**i; }
    L -= 2 * W32 * c1;
    L * (L - W32) === 0;

    for (var i = 0; i < 32; i++) { w[i] <== z[i]; }
}

// ---------------------------------------------------------------------------
// Two consecutive SHA-256 rounds, sharing packed Ch/Maj and fused adders.
// 328 rows for two rounds (circomlib needs ~522).
// ---------------------------------------------------------------------------
template RoundPair(t) {
    signal input st[8][32];   // a,b,c,d,e,f,g,h  (LSB-first words)
    signal input w0[32];
    signal input w1[32];
    signal output out[8][32];

    var W32 = 2 ** 32;
    var k0 = shaK(t);
    var k1 = shaK(t + 1);

    signal a[32]; signal b[32]; signal c[32]; signal d[32];
    signal e[32]; signal f[32]; signal g[32]; signal h[32];
    for (var i = 0; i < 32; i++) {
        a[i] <== st[0][i]; b[i] <== st[1][i]; c[i] <== st[2][i]; d[i] <== st[3][i];
        e[i] <== st[4][i]; f[i] <== st[5][i]; g[i] <== st[6][i]; h[i] <== st[7][i];
    }

    // --- round t sigmas ---
    component sig1t = SigmaTrunc(6, 11, 25);
    for (var i = 0; i < 32; i++) { sig1t.x[i] <== e[i]; }
    component sig0t = Sigma0Full();
    for (var i = 0; i < 32; i++) { sig0t.x[i] <== a[i]; }

    // --- witness new_e_t, new_a_t ---
    signal newE[32];
    signal newA[32];

    var va = 0; var vb = 0; var vc = 0; var vd = 0;
    var ve = 0; var vf = 0; var vg = 0; var vh = 0;
    var vs1t = 0; var vs0t = 0; var vw0 = 0; var vw1 = 0;
    for (var i = 0; i < 32; i++) {
        va += a[i]*2**i; vb += b[i]*2**i; vc += c[i]*2**i; vd += d[i]*2**i;
        ve += e[i]*2**i; vf += f[i]*2**i; vg += g[i]*2**i; vh += h[i]*2**i;
        vs1t += sig1t.out[i]*2**i; vs0t += sig0t.out[i]*2**i;
        vw0 += w0[i]*2**i; vw1 += w1[i]*2**i;
    }
    var chT  = vg ^ (ve & (vf ^ vg));
    var sE   = (vd + vh + vs1t + chT + k0 + vw0) % W32;
    for (var i = 0; i < 32; i++) { newE[i] <-- (sE \ (2**i)) % 2; }

    var vnewE = sE;
    var majT = (va & vb) ^ (va & vc) ^ (vb & vc);
    var sA   = (vnewE + vs0t + majT + (W32 - 1 - vd) + 1) % W32;
    for (var i = 0; i < 32; i++) { newA[i] <-- (sA \ (2**i)) % 2; }

    component bE = Bool32();  for (var i = 0; i < 32; i++) { bE.v[i] <== newE[i]; }
    component bA = Bool32();  for (var i = 0; i < 32; i++) { bA.v[i] <== newA[i]; }

    // --- round t+1 sigmas ---
    component sig1tp = SigmaTrunc(6, 11, 25);
    for (var i = 0; i < 32; i++) { sig1tp.x[i] <== newE[i]; }
    component sig0tp = Sigma0Full();
    for (var i = 0; i < 32; i++) { sig0tp.x[i] <== newA[i]; }

    signal newEp[32];
    signal newAp[32];

    var vs1tp = 0; var vs0tp = 0;
    for (var i = 0; i < 32; i++) {
        vs1tp += sig1tp.out[i]*2**i; vs0tp += sig0tp.out[i]*2**i;
    }
    var chTp = vf ^ (vnewE & (ve ^ vf));
    var sEp  = (vc + vg + vs1tp + chTp + k1 + vw1) % W32;
    for (var i = 0; i < 32; i++) { newEp[i] <-- (sEp \ (2**i)) % 2; }

    var vnewA  = sA;
    var majTp  = (vnewA & va) ^ (vnewA & vb) ^ (va & vb);
    var sAp    = (sEp + vs0tp + majTp + (W32 - 1 - vc) + 1) % W32;
    for (var i = 0; i < 32; i++) { newAp[i] <-- (sAp \ (2**i)) % 2; }

    component bEp = Bool32(); for (var i = 0; i < 32; i++) { bEp.v[i] <== newEp[i]; }
    component bAp = Bool32(); for (var i = 0; i < 32; i++) { bAp.v[i] <== newAp[i]; }

    // --- packed Ch / Maj covering both rounds ---
    component pch = PackedCh32();
    component pmj = PackedMaj32();
    for (var i = 0; i < 32; i++) {
        pch.e[i] <== e[i]; pch.f[i] <== f[i]; pch.g[i] <== g[i]; pch.u[i] <== newE[i];
        pmj.a[i] <== a[i]; pmj.b[i] <== b[i]; pmj.c[i] <== c[i]; pmj.u[i] <== newA[i];
    }

    // --- fused adders ---
    component fe = FusedE();
    for (var i = 0; i < 32; i++) {
        fe.newE[i]  <== newE[i];   fe.newEp[i] <== newEp[i];
        fe.z[i]     <== pch.z[i];
        fe.e[i]     <== e[i];      fe.f[i]     <== f[i];     fe.g[i] <== g[i];
        fe.sig1t[i] <== sig1t.out[i];
        fe.sig1tp[i]<== sig1tp.out[i];
        fe.d[i]     <== d[i];      fe.h[i]     <== h[i];     fe.c[i] <== c[i];
        fe.w0[i]    <== w0[i];     fe.w1[i]    <== w1[i];
    }
    fe.k0 <== k0;
    fe.k1 <== k1;

    component fa = FusedA();
    for (var i = 0; i < 32; i++) {
        fa.newA[i]  <== newA[i];   fa.newAp[i] <== newAp[i];
        fa.newE[i]  <== newE[i];   fa.newEp[i] <== newEp[i];
        fa.sig0t[i] <== sig0t.out[i];
        fa.sig0tp[i]<== sig0tp.out[i];
        fa.z[i]     <== pmj.z[i];
        fa.a[i]     <== a[i];      fa.b[i] <== b[i];
        fa.c[i]     <== c[i];      fa.d[i] <== d[i];
    }

    // new state: (a,b,c,d,e,f,g,h) <- (newAp, newA, a, b, newEp, newE, e, f)
    for (var i = 0; i < 32; i++) {
        out[0][i] <== newAp[i];
        out[1][i] <== newA[i];
        out[2][i] <== a[i];
        out[3][i] <== b[i];
        out[4][i] <== newEp[i];
        out[5][i] <== newE[i];
        out[6][i] <== e[i];
        out[7][i] <== f[i];
    }
}

// ---------------------------------------------------------------------------
// Drop-in replacement for circomlib's `Sha256compression()`.
// `hin` / `inp` / `out` are big-endian bits within each 32-bit word, exactly
// as circomlib uses them.
// ---------------------------------------------------------------------------
template Sha256compressionZkGolf() {
    signal input hin[256];
    signal input inp[512];
    signal output out[256];

    // to LSB-first words
    signal H[8][32];
    signal W[64][32];
    for (var j = 0; j < 8; j++) {
        for (var i = 0; i < 32; i++) { H[j][i] <== hin[j*32 + i]; }
    }
    for (var j = 0; j < 16; j++) {
        for (var i = 0; i < 32; i++) { W[j][i] <== inp[j*32 + 31 - i]; }
    }

    // message schedule
    component ss[48];
    for (var j = 16; j < 64; j++) {
        ss[j - 16] = SchedStep();
        for (var i = 0; i < 32; i++) {
            ss[j - 16].wm2[i]  <== W[j - 2][i];
            ss[j - 16].wm7[i]  <== W[j - 7][i];
            ss[j - 16].wm15[i] <== W[j - 15][i];
            ss[j - 16].wm16[i] <== W[j - 16][i];
        }
        for (var i = 0; i < 32; i++) { W[j][i] <== ss[j - 16].w[i]; }
    }

    // 32 round pairs
    component rp[32];
    signal state[33][8][32];
    for (var j = 0; j < 8; j++) {
        for (var i = 0; i < 32; i++) { state[0][j][i] <== H[j][i]; }
    }
    for (var t = 0; t < 32; t++) {
        rp[t] = RoundPair(2*t);
        for (var j = 0; j < 8; j++) {
            for (var i = 0; i < 32; i++) { rp[t].st[j][i] <== state[t][j][i]; }
        }
        for (var i = 0; i < 32; i++) {
            rp[t].w0[i] <== W[2*t][i];
            rp[t].w1[i] <== W[2*t + 1][i];
        }
        for (var j = 0; j < 8; j++) {
            for (var i = 0; i < 32; i++) { state[t+1][j][i] <== rp[t].out[j][i]; }
        }
    }

    // Merkle-Damgard feed-forward
    component ff[8];
    for (var j = 0; j < 8; j++) {
        ff[j] = CarryAdd32();
        for (var i = 0; i < 32; i++) {
            ff[j].a[i] <== H[j][i];
            ff[j].b[i] <== state[32][j][i];
        }
        for (var i = 0; i < 32; i++) { out[j*32 + 31 - i] <== ff[j].z[i]; }
    }
}
