# base64url templates

This file implements the base64url scheme from [RFC 7515](https://datatracker.ietf.org/doc/html/rfc7515#appendix-C), which has **no padding**: it does not append `=` padding characters to the encoded text.

A few more details are discussed [here](http://alinush.org/keyless#base64url).

This file started as a modification of [zkEmail's base64 libraries](https://github.com/zkemail/zk-email-verify/blob/main/packages/circuits/helpers/base64.circom).