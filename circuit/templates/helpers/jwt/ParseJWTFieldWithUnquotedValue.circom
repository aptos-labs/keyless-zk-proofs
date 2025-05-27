pragma circom 2.2.2;

include "../arrays/ArraySelector.circom";
include "../arrays/ArraySelectorComplex.circom";
include "../strings/IsWhitespace.circom";

include "./ParseJWTFieldSharedLogic.circom";

include "circomlib/circuits/comparators.circom";
include "circomlib/circuits/gates.circom";

// Takes as input a string `field` corresponding to the field of a JSON name+value pair.
// It is enforced that `field` has the structure: []name[]':'[]value[](','|'}'),
// where [] refers to arbitrary whitespace characters, name and value refer to the
// input fields with the same names, 'x' denotes a specific character, and | denotes
// that either character may be included
//
// Assumes `field_len` is the length of `field` followed by 0-padding, `name_len` is
// the length of `name` before 0-padding, `value_len` is the length of `value` before 0-padding
//
// It is assumed that `skip_checks` is equal to 0 or to 1. If it is 1, all
// checks enforced by this template will be skipped, and it will function as
// a no-op. If it is set to 0, failing one check will fail proof generation
template ParseJWTFieldWithUnquotedValue(maxKVPairLen, maxNameLen, maxValueLen) {
    signal input field[maxKVPairLen]; // ASCII
    signal input name[maxNameLen];
    signal input value[maxValueLen];
    signal input field_len; // ASCII
    signal input name_len;
    signal input value_index; // index of value within `field`
    signal input value_len;
    signal input colon_index; // index of colon within `field`
    signal input skip_checks;

    ParseJWTFieldSharedLogic(maxKVPairLen, maxNameLen, maxValueLen)(field, name, value, field_len, name_len, value_index, value_len, colon_index, skip_checks);

    signal checks[2];
    // Verify whitespace is in right places
    signal is_whitespace[maxKVPairLen];
    for (var i = 0; i < maxKVPairLen; i++) {
        is_whitespace[i] <== IsWhitespace()(field[i]);
    }

    signal whitespace_selector_one[maxKVPairLen] <== ArraySelectorComplex(maxKVPairLen)(name_len+2, colon_index); // Skip 2 quotes around name, stop 1 index before the colon
    signal whitespace_selector_two[maxKVPairLen] <== ArraySelectorComplex(maxKVPairLen)(colon_index+1, value_index); // no quote this time, so check whitespace until the value start
    signal whitespace_selector_three[maxKVPairLen] <== ArraySelectorComplex(maxKVPairLen)(value_index+value_len, field_len-1); // and directly after the value end

    signal whitespace_checks[maxKVPairLen];
    for (var i = 0; i < maxKVPairLen; i++) {
        whitespace_checks[i] <== IsEqual()([(whitespace_selector_one[i] + whitespace_selector_two[i] + whitespace_selector_three[i]) * (1 - is_whitespace[i]), 0]);
    }
    checks[0] <== MultiAND(maxKVPairLen)(whitespace_checks);

    // Verify value does not contain comma, end brace, or quote
    signal value_selector[maxKVPairLen] <== ArraySelector(maxKVPairLen)(value_index, value_index+value_len);

    signal value_checks[maxKVPairLen];
    for (var i = 0; i < maxKVPairLen; i++) {
        var is_comma = IsEqual()([field[i], 44]);
        var is_end_brace = IsEqual()([field[i], 125]);
        var is_quote = IsEqual()([field[i], 34]);
        value_checks[i] <== IsEqual()([value_selector[i] * (is_comma + is_end_brace + is_quote), 0]);
    }
    checks[1] <== MultiAND(maxKVPairLen)(value_checks);
    signal checks_pass <== AND()(checks[0], checks[1]);
    signal success <== OR()(checks_pass, skip_checks);
    success === 1;
}