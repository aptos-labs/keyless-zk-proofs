pragma circom 2.2.2;

include "helpers/strings/IsSubstring.circom";

template is_substring_test(maxStrLen, maxSubstrLen) {
    signal input str[maxStrLen];
    signal input str_hash;
    signal input substr[maxSubstrLen];
    signal input substr_len;
    signal input start_index;
    signal input expected_output;
    
    signal out <== IsSubstring(maxStrLen, maxSubstrLen)(str, str_hash, substr, substr_len, start_index);
    expected_output === out;
}

component main = is_substring_test(
   2000, 1000
);
