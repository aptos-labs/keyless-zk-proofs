pragma circom 2.2.2;

include "../arrays/ArraySelector.circom";
include "../arrays/ArraySelectorComplex.circom";
include "../strings/IsWhitespace.circom";

include "./ParseJWTFieldSharedLogic.circom";

include "circomlib/circuits/comparators.circom";
include "circomlib/circuits/gates.circom";

// Takes as input a string `field` corresponding to the field of a JSON name+value pair.
// It is enforced that `field` has the structure: []name[]':'[]'"'value'"'[](','|'}'),
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
template ParseJWTFieldWithQuotedValue(MAX_KV_PAIR_LEN, MAX_NAME_LEN, MAX_VALUE_LEN) {
    signal input {maxbits} field[MAX_KV_PAIR_LEN]; // ASCII
    signal input {maxbits} name[MAX_NAME_LEN]; // ASCII
    signal input {maxbits} value[MAX_VALUE_LEN]; // ASCII
    signal input field_string_bodies[MAX_KV_PAIR_LEN];
    signal input field_len;
    signal input name_len;
    signal input value_index; // index of value within `field`
    signal input value_len;
    signal input colon_index; // index of colon within `field`
    signal input skip_checks;

    ParseJWTFieldSharedLogic(MAX_KV_PAIR_LEN, MAX_NAME_LEN, MAX_VALUE_LEN)(field, name, value, field_len, name_len, value_index, value_len, colon_index, skip_checks);

    signal checks[3];
    signal value_first_quote <== SelectArrayValue(MAX_KV_PAIR_LEN)(field, value_index-1);
    checks[0] <== IsEqual()([value_first_quote, 34]);

    signal value_second_quote <== SelectArrayValue(MAX_KV_PAIR_LEN)(field, value_index+value_len);
    checks[1] <== IsEqual()([value_second_quote, 34]);

    // Verify whitespace is in right places, and that only name and value are inside string bodies
    signal is_whitespace[MAX_KV_PAIR_LEN];
    for (var i = 0; i < MAX_KV_PAIR_LEN; i++) {
        is_whitespace[i] <== IsWhitespace()(field[i]);
    }

    signal whitespace_selector_one[MAX_KV_PAIR_LEN] <== ArraySelectorComplex(MAX_KV_PAIR_LEN)(name_len+2, colon_index); // Skip 2 quotes around name, stop 1 index before the colon
    signal whitespace_selector_two[MAX_KV_PAIR_LEN] <== ArraySelectorComplex(MAX_KV_PAIR_LEN)(colon_index+1, value_index-1); // Skip 2 quotes around value, stop 1 index before the value
    signal whitespace_selector_three[MAX_KV_PAIR_LEN] <== ArraySelectorComplex(MAX_KV_PAIR_LEN)(value_index+value_len+1, field_len-1); // Skip 2 quotes in the value, stop just before the comma/end brace
    signal name_selector[MAX_KV_PAIR_LEN] <== ArraySelector(MAX_KV_PAIR_LEN)(1, name_len+1);
    signal value_selector[MAX_KV_PAIR_LEN] <== ArraySelector(MAX_KV_PAIR_LEN)(value_index, value_index+value_len);


    signal whitespace_checks[3*MAX_KV_PAIR_LEN];
    for (var i = 0; i < MAX_KV_PAIR_LEN; i++) {
        whitespace_checks[3*i] <== IsEqual()([(whitespace_selector_one[i] + whitespace_selector_two[i] + whitespace_selector_three[i]) * (1 - is_whitespace[i]), 0]);

        // Check that only the name and value parts of the field are inside string bodies, and nothing else is
        whitespace_checks[3*i+1] <== IsEqual()([(name_selector[i] + value_selector[i]) * (1 - field_string_bodies[i]), 0]);

        whitespace_checks[3*i+2] <== IsEqual()([(1 - (name_selector[i] + value_selector[i])) * field_string_bodies[i],0]);

    }
    checks[2] <== MultiAND(3*MAX_KV_PAIR_LEN)(whitespace_checks);

    signal checks_pass <== MultiAND(3)(checks);
    signal succeed <== OR()(checks_pass, skip_checks);
    succeed === 1;
}
