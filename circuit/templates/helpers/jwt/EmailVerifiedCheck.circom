pragma circom 2.2.2;

include "../../stdlib/circuits/ConditionallyAssertEqual.circom";

include "circomlib/circuits/comparators.circom";
include "circomlib/circuits/gates.circom";

// Enforce that if uid name is "email", the email verified field is either true or "true"
template EmailVerifiedCheck(maxEVNameLen, maxEVValueLen, maxUIDNameLen) {
    signal input ev_name[maxEVNameLen];
    signal input ev_value[maxEVValueLen];
    signal input ev_value_len;
    signal input uid_name[maxUIDNameLen];
    signal input uid_name_len;
    signal output {binary} uid_is_email;

    var email[5] = [101, 109, 97, 105, 108]; // email

    var uid_starts_with_email_0 = IsEqual()([email[0], uid_name[0]]);
    var uid_starts_with_email_1 = IsEqual()([email[1], uid_name[1]]);
    var uid_starts_with_email_2 = IsEqual()([email[2], uid_name[2]]);
    var uid_starts_with_email_3 = IsEqual()([email[3], uid_name[3]]);
    var uid_starts_with_email_4 = IsEqual()([email[4], uid_name[4]]);

    var uid_starts_with_email = MultiAND(5)([uid_starts_with_email_0, uid_starts_with_email_1, uid_starts_with_email_2, uid_starts_with_email_3, uid_starts_with_email_4]);


    signal uid_name_len_is_5 <== IsEqual()([uid_name_len, 5]);
    uid_is_email <== AND()(uid_starts_with_email, uid_name_len_is_5); // '1' if uid_name is "email" with length 5. This guarantees uid_name is in fact "email" (with quotes) combined with the logic in `JWTFieldCheck`

    var required_ev_name[14] = [101, 109, 97, 105, 108, 95, 118, 101, 114, 105, 102, 105, 101, 100];    // email_verified

    // If uid name is "email", enforce ev_name is "email_verified"
    for (var i = 0; i < 14; i++) {
        ConditionallyAssertEqual()([ev_name[i], required_ev_name[i]], uid_is_email);
    }

    signal ev_val_len_is_4 <== IsEqual()([ev_value_len, 4]);
    signal ev_val_len_is_6 <== IsEqual()([ev_value_len, 6]);
    var ev_val_len_is_correct = OR()(ev_val_len_is_4, ev_val_len_is_6);

    signal not_uid_is_email <== NOT()(uid_is_email);
    signal is_ok <== OR()(not_uid_is_email, ev_val_len_is_correct);
    is_ok === 1;
    
    var required_ev_val_len_4[4] = [116, 114, 117, 101]; // true
    signal {binary} check_ev_val_bool <== AND()(ev_val_len_is_4, uid_is_email);
    for (var i = 0; i < 4; i ++) {
        ConditionallyAssertEqual()([required_ev_val_len_4[i], ev_value[i]], check_ev_val_bool);
    }

    var required_ev_val_len_6[6] = [34, 116, 114, 117, 101, 34]; // "true"
    signal {binary} check_ev_val_str <== AND()(ev_val_len_is_6, uid_is_email);
    for (var i = 0; i < 6; i++) {
        ConditionallyAssertEqual()([required_ev_val_len_6[i], ev_value[i]], check_ev_val_str);
    }
}
