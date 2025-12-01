pragma circom 2.2.2;

// Like Bits2Num in [circomlib](https://github.com/iden3/circomlib/blob/master/circuits/bitify.circom),
// except assumes bits[0] is the MSB while bits[N-1] is the LSB.
template BigEndianBits2Num(N) { 
    signal input in[N];
    signal output out;

    var acc = 0;
    var pow2 = 1;

    for (var i = 0; i < N; i++) {
        var index = (N-1) - i;

        acc += in[index] * pow2;

        pow2 = pow2 + pow2;
    }

    acc ==> out;
}
