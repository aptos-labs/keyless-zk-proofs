pragma circom 2.2.2;

include "../arrays/ArraySelector.circom";
include "../arrays/ArraySelectorComplex.circom";
include "../arrays/SelectArrayValue.circom";
include "../strings/IsWhitespace.circom";

include "./ParseJWTFieldSharedLogic.circom";

include "circomlib/circuits/comparators.circom";
include "circomlib/circuits/gates.circom";

// Assumes `field_len` is the length of `field` followed by 0-padding, `name_len` is
// the length of `name` before 0-padding, `value_len` is the length of `value` before 0-padding
// Takes as input a string `field` corresponding to the field of a JSON name+value pair.
// It is enforced that `field` has the structure: []name[]':'([]value[]|[]"value"[])(','|'}'),
// where [] refers to arbitrary whitespace characters, name and value refer to the
// input fields with the same names, 'x' denotes a specific character, and | denotes
// that either character or string may be included
//
// Assumes `field_len` is the length of `field` followed by 0-padding, `name_len` is
// the length of `name` before 0-padding, `value_len` is the length of `value` before 0-padding
//
// This template exists specifically for the email_verified JWT field, as some providers
// do not follow the OIDC spec and instead enclose the value of this field in quotes
template ParseEmailVerifiedField(maxKVPairLen, maxNameLen, maxValueLen) {
    signal input field[maxKVPairLen]; // ASCII
    signal input name[maxNameLen];
    signal input value[maxValueLen];
    signal input field_len; // ASCII
    signal input name_len;
    signal input value_index; // index of value within `field`
    signal input value_len;
    signal input colon_index; // index of colon within `field`

    ParseJWTFieldSharedLogic(maxKVPairLen, maxNameLen, maxValueLen)(field, name, value, field_len, name_len, value_index, value_len, colon_index, 0); // `skip_checks` is set to 0


    signal char_before_value <== SelectArrayValue(maxKVPairLen)(field, value_index-1);
    signal before_is_quote      <== IsEqual()([char_before_value, 34]);
    signal before_is_whitespace <== IsWhitespace()(char_before_value);
    signal before_is_whitespace_or_quote <== OR()(before_is_quote, before_is_whitespace);

    // Check the char before `value` is either quote or whitespace, OR that it is the colon
    (1 - before_is_whitespace_or_quote)*(value_index-1-colon_index) === 0;
    signal char_after_value <== SelectArrayValue(maxKVPairLen)(field, value_index+value_len);
    signal after_is_quote       <== IsEqual()([char_after_value, 34]);
    signal after_is_whitespace  <== IsWhitespace()(char_after_value);
    // check OR(after_is_quote, after_is_whitespace) === 1.
    signal after_is_whitespace_or_quote <== OR()(after_is_quote, after_is_whitespace);
    // Check the char after is either quote or whitespace, OR that it is the field delimiter
    (1 - after_is_whitespace_or_quote)*(field_len-1-value_index-value_len) === 0;

    // Check that field value doesn't have mismatched quotes
    signal and_1 <== AND()(before_is_quote,after_is_whitespace);
    signal and_2 <== AND()(before_is_whitespace,after_is_quote);
    and_1 + and_2 === 0;


    signal is_whitespace[maxKVPairLen];
    for (var i = 0; i < maxKVPairLen; i++) {
        is_whitespace[i] <== IsWhitespace()(field[i]);
    }

    signal whitespace_selector_one[maxKVPairLen] <== ArraySelectorComplex(maxKVPairLen)(name_len+2, colon_index); // Skip 2 quotes around name, stop 1 index before the colon
    signal whitespace_selector_two[maxKVPairLen] <== ArraySelectorComplex(maxKVPairLen)(colon_index+1, value_index-1); // There could potentially be quotes around the value, so we don't contstrain the character before value_index to be whitespace
    signal whitespace_selector_three[maxKVPairLen] <== ArraySelectorComplex(maxKVPairLen)(value_index+value_len+1, field_len-1); // similarly to before, don't constrain character just after value end


    signal name_selector[maxKVPairLen] <== ArraySelector(maxKVPairLen)(1, name_len+1);
    signal value_selector[maxKVPairLen] <== ArraySelector(maxKVPairLen)(value_index, value_index+value_len);


    for (var i = 0; i < maxKVPairLen; i++) {
        (whitespace_selector_one[i] + whitespace_selector_two[i] + whitespace_selector_three[i]) * (1 - is_whitespace[i]) === 0;
    }
}
