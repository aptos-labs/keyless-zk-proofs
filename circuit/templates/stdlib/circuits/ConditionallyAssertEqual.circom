pragma circom 2.2.2;

// Asserts that `in[0] === in[1]` only when `bool` is 1.
template ConditionallyAssertEqual() {
    signal input in[2];
    signal input {binary} bool;

    (in[0]-in[1]) * bool === 0;
}