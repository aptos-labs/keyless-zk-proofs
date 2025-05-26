
pragma circom 2.2.2;

include "helpers/base64url/Base64UrlLookup.circom";

template base64url_lookup_test() {
    signal input in_b64_char;
    signal input out_num;
    component base64url_lookup = Base64UrlLookup();
    base64url_lookup.in <== in_b64_char;
    out_num === base64url_lookup.out;

}

component main = base64url_lookup_test();
