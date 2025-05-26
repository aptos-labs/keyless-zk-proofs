pragma circom 2.2.2;

include "circomlib/circuits/bitify.circom";
include "circomlib/circuits/comparators.circom";
include "circomlib/circuits/gates.circom";

// Enforces that every value in `in` between 0 and len - 1 are valid ASCII digits:
//   i.e. are in [48, 57] (inclusive on both ends)
template AssertIsAsciiDigits(MAX_DIGITS) {
    signal input in[MAX_DIGITS];
    signal input len;

    signal selector[MAX_DIGITS] <== ArraySelector(MAX_DIGITS)(0, len);
    for (var i = 0; i < MAX_DIGITS; i++) {
        // TODO(Perf): Since numbers are in [48, 58) and 58 is less than 64 = 2^6,
        //   we could use 6 bits below. But the Num2Bits(6) call would be applied
        //   to elements after in[len-1], which may not necessarily be 6 bits anymore.
        //   So, we need extra conditional logic here.
        _ <== Num2Bits(9)(in[i]);

        var is_ascii_digit = AND()(
            GreaterThan(9)([in[i], 47]),
            LessThan(9)([in[i], 58])
        );

        (1 - is_ascii_digit) * selector[i] === 0;
    }
}
