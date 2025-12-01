pragma circom 2.2.2;

include "./AssertIsAsciiDigits.circom";

// Given a string of digits in ASCII format, returns the digits represented as a single field element
// Assumes:
// - the number represented by the ASCII `digits` is smaller than the scalar field used by the circuit
// - `digits` contains only ASCII digit values between 48 and 57 inclusive
// Does not work when MAX_LEN = 1
template AsciiDigitsToScalar(MAX_LEN) {
    signal input digits[MAX_LEN]; 
    signal input len; 
    signal output out;

    AssertIsAsciiDigits(MAX_LEN)(digits, len);
    // Set to 0 everywhere except len-1, which is 1
    signal index_eq[MAX_LEN - 1];

    // For ASCII digits ['1','2','3','4','5'], acc_shifts[0..3] is [12,123,1234]
    signal acc_shifts[MAX_LEN - 1];
    // accumulators[i] = acc_shifts[i-1] for all i < len, otherwise accumulators[i] = accumulators[i-1]
    signal accumulators[MAX_LEN];

    signal success;
    var index_eq_sum = 0;
    // `s` is initially set to 1 and is 0 after len == i
    var s = 1; 

    accumulators[0] <== digits[0]-48;
    for (var i=1; i < MAX_LEN; i++) {
        index_eq[i-1] <-- (len == i) ? 1 : 0;
        index_eq[i-1] * (len-i) === 0;

        s = s - index_eq[i - 1];
        index_eq_sum = index_eq_sum + index_eq[i - 1];

        acc_shifts[i - 1] <== 10 * accumulators[i - 1] + (digits[i] - 48);
        // // This implements a conditional assignment: accumulators[i] = (s == 0 ? accumulators[i-1] : acc_shifts[i-1]);
        accumulators[i] <== (acc_shifts[i - 1] - accumulators[i - 1])*s + accumulators[i - 1];
    }

    index_eq_sum ==> success;
    // Guarantee at most one element of index_eq is equal to 1
    success === 1;

    out <== accumulators[MAX_LEN - 1];
}
