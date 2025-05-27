pragma circom 2.2.2;

include "../arrays/SelectArrayValue.circom";
include "../arrays/IsSubstring.circom";
include "../hashtofield/HashBytesToFieldWithLen.circom";

include "circomlib/circuits/comparators.circom";
include "circomlib/circuits/gates.circom";

// Takes as input a string `field` corresponding to the field of a JSON name+value pair.
// It is enforced that `field` has the structure: []name[]':'[]value[](','|'}'),
// where [] refers to arbitrary characters, name and value refer to the
// input fields with the same names, 'x' denotes a specific character, and | denotes
// that either character may be included
//
// It is assumed that `skip_checks` is equal to 0 or to 1. If it is 1, all
// checks enforced by this template will be skipped, and it will function as
// a no-op. If it is set to 0, failing one check will fail proof generation
//
// Assumes `field_len` is the length of `field` followed by 0-padding, `name_len` is
// the length of `name` before 0-padding, `value_len` is the length of `value` before 0-padding
//
// Note that this template is NOT secure on its own, but must be called from
// `ParseJWTFieldWithQuotedValue` or `ParseJWTFieldWithUnquotedValue`
template ParseJWTFieldSharedLogic(maxKVPairLen, maxNameLen, maxValueLen) {
    signal input field[maxKVPairLen]; // ASCII
    signal input name[maxNameLen]; // ASCII
    signal input value[maxValueLen]; // ASCII
    signal input field_len;
    signal input name_len;
    signal input value_index; // index of value within `field`
    signal input value_len;
    signal input colon_index; // index of colon within `field`
    signal input skip_checks; // don't fail if any checks fail in this subcircuit

    signal checks[9];
    // Enforce that end of name < colon < start of value and that field_len >=
    // name_len + value_len + 1 (where the +1 is for the colon), so that the
    // parts of the JWT field are in the correct order
    signal colon_greater_name <== LessThan(20)([name_len, colon_index]);
    checks[0] <== IsEqual()([colon_greater_name, 1]);

    signal colon_less_value <== LessThan(20)([colon_index, value_index]);
    checks[1] <== IsEqual()([colon_less_value, 1]);

    signal field_len_ok <== GreaterThan(20)([field_len, name_len + value_len]);
    checks[2] <== IsEqual()([field_len_ok, 1]);

    signal field_hash <== HashBytesToFieldWithLen(maxKVPairLen)(field, field_len);

    signal name_first_quote <== SelectArrayValue(maxKVPairLen)(field, 0);
    checks[3] <== IsEqual()([name_first_quote, 34]); // '"'

    checks[4] <== IsSubstring(maxKVPairLen, maxNameLen)(field, field_hash, name, name_len, 1);

    signal name_second_quote <== SelectArrayValue(maxKVPairLen)(field, name_len+1);
    checks[5] <== IsEqual()([name_second_quote, 34]); // '"'

    signal colon <== SelectArrayValue(maxKVPairLen)(field, colon_index);
    checks[6] <== IsEqual()([colon, 58]); // ':'

    checks[7] <== IsSubstring(maxKVPairLen, maxValueLen)(field, field_hash, value, value_len, value_index);

    // Enforce last character of `field` is comma or end brace
    signal last_char <== SelectArrayValue(maxKVPairLen)(field, field_len-1);
    checks[8] <== IsEqual()([(last_char - 44) * (last_char - 125),0]); // ',' or '}'

    signal checks_pass <== MultiAND(9)(checks);
    signal success <== OR()(checks_pass, skip_checks);
    success === 1;
}