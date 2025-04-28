pragma circom 2.2.2;

include "helpers/base64url.circom";

template base64url_decode_test(maxJWTPayloadLen) {
    var max_ascii_jwt_payload_len = (3*maxJWTPayloadLen)\4;
    signal input jwt_payload[maxJWTPayloadLen];
    signal input ascii_jwt_payload[max_ascii_jwt_payload_len];
    component base64urldecode = Base64UrlDecode(max_ascii_jwt_payload_len);
    base64urldecode.in <== jwt_payload;
    ascii_jwt_payload === base64urldecode.out;

}

component main = base64url_decode_test(
    192*8-64   // maxJWTPayloadLen
);
