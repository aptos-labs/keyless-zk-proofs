pragma circom 2.2.2;

// Returns the elementwise (Hadamard) product of two arrays: i.e., another array whose
// ith entry is the product of the ith entries in the two arrays.
//
// @param  LEN  the length of the two input arrays
//
// @input  lhs  the first input array
// @input  rhs  the second input array
//
// @output out  the Hadamard product of the two arrays
//
// @warning  this could cause integer overflow if the product of any two multiplied
//           elements exceeds the field modulus
//
// TODO: rename to HadamardProduct or ElementwiseProduct
template ElementwiseMul(LEN) {
    signal input lhs[LEN];
    signal input rhs[LEN];
    signal output out[LEN];

    for (var i = 0; i < LEN; i++) {
        out[i] <== lhs[i] * rhs[i];
    }
}