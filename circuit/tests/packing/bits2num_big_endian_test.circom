

pragma circom 2.2.2;

include "helpers/packing/BigEndianBits2Num.circom";

template bits2num_big_endian_test() {
    var max_bits_len = 64;
    signal input bits_in[max_bits_len];
    signal input num_out;
    component num2bits_be = BigEndianBits2Num(max_bits_len);
    num2bits_be.in <== bits_in;
    for (var i = 0; i < max_bits_len; i++ ) {
      log(num2bits_be.in[i]);
    }
    log("output:", num2bits_be.out);
    num2bits_be.out === num_out;

}

component main = bits2num_big_endian_test();
