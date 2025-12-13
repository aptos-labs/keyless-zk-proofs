pragma circom 2.2.2;

include "helpers/strings/AssertIsConcatenation.circom";
include "helpers/hashtofield/HashBytesToFieldWithLen.circom";

template concatenation_check_test(maxFullStringLen, maxLeftStringLen, maxRightStringLen) {
    signal input full_string[maxFullStringLen];
    signal input left[maxLeftStringLen];
    signal input right[maxRightStringLen];
    signal input left_len;
    signal input right_len;
    
    signal full_hash <== HashBytesToFieldWithLen(maxFullStringLen)(full_string, left_len + right_len);
    signal left_hash <== HashBytesToFieldWithLen(maxLeftStringLen)(left, left_len);
    signal right_hash <== HashBytesToFieldWithLen(maxRightStringLen)(right, right_len);
    
    log("silly test string");
    AssertIsConcatenation(maxFullStringLen, maxLeftStringLen, maxRightStringLen)(
        full_string,
        full_hash,
        left,
        left_len,
        left_hash,
        right,
        right_len,
        right_hash
    );
}

component main = concatenation_check_test(
   1600, 1000, 1000
);
