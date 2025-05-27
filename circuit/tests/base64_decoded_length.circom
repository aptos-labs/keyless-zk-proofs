pragma circom 2.2.2;

include "helpers/base64url/Base64UrlDecodedLength.circom";

template base64url_decoded_length_test() {
    signal input encoded_len;
    signal input expected_decoded_len;

    signal result <== Base64UrlDecodedLength(512)(encoded_len);
    result === expected_decoded_len;
}

component main = base64url_decoded_length_test();
