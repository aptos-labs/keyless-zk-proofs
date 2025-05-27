pragma circom 2.2.2;

include "helpers/strings/IsSubstring.circom";

template assert_is_substring_test(maxStrLen, maxSubstrLen) {
    signal input str[maxStrLen];
    signal input str_hash;
    signal input substr[maxSubstrLen];
    signal input substr_len;
    signal input start_index;
    
    AssertIsSubstring(maxStrLen, maxSubstrLen)(str, str_hash, substr, substr_len, start_index);
}

component main = assert_is_substring_test(
   100, 20
);
