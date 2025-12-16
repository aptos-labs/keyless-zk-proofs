pragma circom 2.2.2;

template BinaryToMaxBitsArray(LEN) {
    signal input {binary} in[LEN];
    signal output {maxbits} out[LEN];
    out.maxbits = 1;
    out <== in;
}
