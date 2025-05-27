pragma circom 2.2.2;

include "stdlib/circuits/Sum.circom";

template sum_test() {
    var len = 10;
    signal input nums[len];
    signal input sum;
    var result = Sum(len)(nums);

    sum === result;
}

component main = sum_test(
);
