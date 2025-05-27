pragma circom 2.2.2;

// Like Bits2Num in [circomlib](https://github.com/iden3/circomlib/blob/master/circuits/bitify.circom),
// except assumes bits[0] is the MSB while bits[n-1] is the LSB.
template BigEndianBits2Num(n) { 
    signal input in[n];
    signal output out;

    var acc = 0;
    var pow2 = 1;

    for (var i = 0; i < n; i++) {
        var index = (n-1) - i;

        acc += in[index] * pow2;

        pow2 = pow2 + pow2;
    }

    acc ==> out;
}