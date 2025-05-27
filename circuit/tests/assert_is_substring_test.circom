
pragma circom 2.2.2;

include "helpers/arrays/IsSubstring.circom";

template assert_is_substring_test() {
    var max_str_len = 256;
    var max_substr_len = 8;

    signal input str[max_str_len];
    signal input str_hash;
    signal input substr[max_substr_len];
    signal input substr_len;
    signal input start_index;

    component assert_is_substring = AssertIsSubstring(max_str_len, max_substr_len);

    assert_is_substring.str <== str;
    assert_is_substring.str_hash <== str_hash;
    assert_is_substring.substr <== substr;
    assert_is_substring.substr_len <== substr_len;
    assert_is_substring.start_index <== start_index;
}

component main = assert_is_substring_test();
