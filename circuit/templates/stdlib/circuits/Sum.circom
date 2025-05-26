pragma circom 2.2.2;

// This circuit returns the sum of an array of signals.
//
// @param  N        the size of the array
//
// @input  nums[N]  the array of signals
// @output sum      the sum of the signals in the array
//
// @notes:
//   Originally, Michael implemented it like [this](https://github.com/TheFrozenFire/snark-jwt-verify/blob/master/circuits/calculate_total.circom). But this seems really
//   inefficient (famous last words) I am not sure that the compiler optimizes it away.
//   The circom paper clearly shows that a var suffices here (see the MultiAND example
//   in Section 3.12 of  [the paper](https://www.techrxiv.org/articles/preprint/CIRCOM_A_Robust_and_Scalable_Language_for_Building_Complex_Zero-Knowledge_Circuits/19374986))
template Sum(N) {
    signal input nums[N];
    signal output sum;

    var lc = 0;

    for (var i = 0; i < N; i++) {
        lc += nums[i];
    }

    sum <== lc;
}