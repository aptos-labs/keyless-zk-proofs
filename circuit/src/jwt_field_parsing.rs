// Copyright © Aptos Foundation
// SPDX-License-Identifier: Apache-2.0

use crate::{misc::calc_string_bodies, TestCircuitHandle};
use aptos_keyless_common::input_processing::{
    circuit_input_signals::CircuitInputSignals, config::CircuitConfig,
};

#[derive(Clone)]
struct JWTField<T> {
    whole_field: T,
    name: T,
    value: T,
}

#[derive(Clone)]
struct JWTFieldMaliciousIndices<T> {
    whole_field: T,
    name: T,
    value: T,
    whole_field_len: usize,
    name_len: usize,
    value_index: usize,
    value_len: usize,
    colon_index: usize,
}

trait JWTFieldIndices {
    fn whole_field_len(&self) -> usize;
    fn name_len(&self) -> usize;
    fn value_index(&self) -> usize;
    fn value_len(&self) -> usize;
    fn colon_index(&self) -> usize;
}

trait JWTFieldStr {
    fn whole_field(&self) -> &str;
    fn name(&self) -> &str;
    fn value(&self) -> &str;
}

impl JWTFieldIndices for JWTField<String> {
    fn whole_field_len(&self) -> usize {
        self.whole_field.len()
    }

    fn name_len(&self) -> usize {
        self.name.len()
    }

    fn value_index(&self) -> usize {
        self.whole_field.find(&self.value).unwrap()
    }

    fn value_len(&self) -> usize {
        self.value.len()
    }

    fn colon_index(&self) -> usize {
        self.whole_field.find(':').unwrap()
    }
}

impl JWTFieldStr for JWTField<String> {
    fn whole_field(&self) -> &str {
        &self.whole_field
    }

    fn name(&self) -> &str {
        &self.name
    }

    fn value(&self) -> &str {
        &self.value
    }
}

impl JWTFieldIndices for JWTFieldMaliciousIndices<String> {
    fn whole_field_len(&self) -> usize {
        self.whole_field_len
    }

    fn name_len(&self) -> usize {
        self.name_len
    }

    fn value_index(&self) -> usize {
        self.value_index
    }

    fn value_len(&self) -> usize {
        self.value_len
    }

    fn colon_index(&self) -> usize {
        self.colon_index
    }
}

impl JWTFieldStr for JWTFieldMaliciousIndices<String> {
    fn whole_field(&self) -> &str {
        &self.whole_field
    }

    fn name(&self) -> &str {
        &self.name
    }

    fn value(&self) -> &str {
        &self.value
    }
}

fn jwt_field_str(whole_field: &str, name: &str, value: &str) -> JWTField<String> {
    JWTField {
        whole_field: String::from(whole_field),
        name: String::from(name),
        value: String::from(value),
    }
}

fn jwt_field_str_malicious_indices(
    whole_field: &str,
    name: &str,
    value: &str,
) -> JWTFieldMaliciousIndices<String> {
    JWTFieldMaliciousIndices {
        whole_field: String::from(whole_field),
        name: String::from(name),
        value: String::from(value),
        whole_field_len: whole_field.len(),
        name_len: name.len(),
        value_index: whole_field.find(value).unwrap_or(0),
        value_len: value.len(),
        colon_index: whole_field.find(':').unwrap(),
    }
}

fn email_verified_test<T: JWTFieldIndices + JWTFieldStr>(
    field: T,
    test_circom_file: &str,
) -> Result<tempfile::NamedTempFile, anyhow::Error> {
    let circuit_handle = TestCircuitHandle::new(test_circom_file).unwrap();

    let config = CircuitConfig::new()
        .max_length("field", 30)
        .max_length("name", 20)
        .max_length("value", 10);

    let circuit_input_signals = CircuitInputSignals::new()
        .str_input("field", field.whole_field())
        .str_input("name", field.name())
        .str_input("value", field.value())
        .usize_input("field_len", field.whole_field_len())
        .usize_input("name_len", field.name_len())
        .usize_input("value_index", field.value_index())
        .usize_input("value_len", field.value_len())
        .usize_input("colon_index", field.colon_index())
        .pad(&config)
        .unwrap();

    let result = circuit_handle.gen_witness(circuit_input_signals);
    println!("{:?}", result);
    result
}

#[test]
fn email_verified_check_test() {
    let circuit_handle =
        TestCircuitHandle::new("jwt_field_parsing/email_verified_check_test.circom").unwrap();

    let testcases = [
        ("email_verified", "true", "email", true, true),
        // Note that this template doesn't actually check that ev_name is exactly equal to
        // "email_verified". It only checks that it starts with this string. I believe that this
        // is not an issue because ParseEmailVerifiedField enforces that ev_name has len == 14.
        ("email_verified000", "true", "email", true, true),
        ("email_verified", "false", "email", true, false),
        ("email_verified", "true", "sub", false, true),
        ("email_verified", "false", "sub", false, true),
    ];

    for t in testcases {
        let ev_name = t.0;
        let ev_value = t.1;
        let uid_name = t.2;
        let expected_uid_is_email = t.3;
        let test_should_pass = t.4;

        let config = CircuitConfig::new()
            .max_length("ev_name", 20)
            .max_length("ev_value", 10)
            .max_length("uid_name", 30);

        let circuit_input_signals = CircuitInputSignals::new()
            .str_input("ev_name", ev_name)
            .str_input("ev_value", ev_value)
            .str_input("uid_name", uid_name)
            .usize_input("ev_value_len", ev_value.len())
            .usize_input("uid_name_len", uid_name.len())
            .bool_input("uid_is_email", expected_uid_is_email)
            .pad(&config)
            .unwrap();

        let result = circuit_handle.gen_witness(circuit_input_signals);
        println!("{:?}", result);
        if test_should_pass {
            assert!(result.is_ok());
        } else {
            assert!(result.is_err());
        }
    }
}

fn unquoted_test<T: JWTFieldIndices + JWTFieldStr>(
    field: T,
    test_circom_file: &str,
    skip_checks: bool,
) -> Result<tempfile::NamedTempFile, anyhow::Error> {
    let circuit_handle = TestCircuitHandle::new(test_circom_file).unwrap();

    let config = CircuitConfig::new()
        .max_length("field", 60)
        .max_length("name", 30)
        .max_length("value", 30);

    let circuit_input_signals = CircuitInputSignals::new()
        .str_input("field", field.whole_field())
        .str_input("name", field.name())
        .str_input("value", field.value())
        .usize_input("field_len", field.whole_field_len())
        .usize_input("name_len", field.name_len())
        .usize_input("value_index", field.value_index())
        .usize_input("value_len", field.value_len())
        .usize_input("colon_index", field.colon_index())
        .usize_input("skip_checks", skip_checks as usize)
        .pad(&config)
        .unwrap();

    let result = circuit_handle.gen_witness(circuit_input_signals);
    println!("{:?}", result);
    result
}

fn quoted_test<T: JWTFieldIndices + JWTFieldStr>(
    field: T,
    test_circom_file: &str,
    skip_checks: bool,
) -> Result<tempfile::NamedTempFile, anyhow::Error> {
    let circuit_handle = TestCircuitHandle::new(test_circom_file).unwrap();

    let config = CircuitConfig::new()
        .max_length("field", 60)
        .max_length("field_string_bodies", 60)
        .max_length("name", 30)
        .max_length("value", 30);

    let circuit_input_signals = CircuitInputSignals::new()
        .str_input("field", field.whole_field())
        .str_input("name", field.name())
        .str_input("value", field.value())
        .usize_input("field_len", field.whole_field_len())
        .bools_input(
            "field_string_bodies",
            &calc_string_bodies(field.whole_field()),
        )
        .usize_input("name_len", field.name_len())
        .usize_input("value_index", field.value_index())
        .usize_input("value_len", field.value_len())
        .usize_input("colon_index", field.colon_index())
        .usize_input("skip_checks", skip_checks as usize)
        .pad(&config)
        .unwrap();

    let result = circuit_handle.gen_witness(circuit_input_signals);
    println!("{:?}", result);
    result
}

fn should_pass_quoted<T: JWTFieldIndices + JWTFieldStr>(field: T) {
    assert!(quoted_test(field, "jwt_field_parsing/parse_quoted_test.circom", false).is_ok());
}

fn should_pass_quoted_skip_checks<T: JWTFieldIndices + JWTFieldStr>(field: T) {
    assert!(quoted_test(field, "jwt_field_parsing/parse_quoted_test.circom", true).is_ok());
}

fn should_pass_unquoted<T: JWTFieldIndices + JWTFieldStr>(field: T) {
    assert!(unquoted_test(field, "jwt_field_parsing/parse_unquoted_test.circom", false).is_ok());
}

fn should_pass_unquoted_skip_checks<T: JWTFieldIndices + JWTFieldStr>(field: T) {
    assert!(unquoted_test(field, "jwt_field_parsing/parse_unquoted_test.circom", true).is_ok());
}

fn should_pass_ev<T: JWTFieldIndices + JWTFieldStr>(field: T) {
    assert!(email_verified_test(
        field,
        "jwt_field_parsing/parse_email_verified_field_test.circom"
    )
    .is_ok());
}

fn should_fail_quoted<T: JWTFieldIndices + JWTFieldStr>(field: T) {
    assert!(quoted_test(field, "jwt_field_parsing/parse_quoted_test.circom", false).is_err());
}

fn should_fail_unquoted<T: JWTFieldIndices + JWTFieldStr>(field: T) {
    assert!(unquoted_test(field, "jwt_field_parsing/parse_unquoted_test.circom", false).is_err());
}

#[allow(dead_code)]
fn should_fail_ev<T: JWTFieldIndices + JWTFieldStr>(field: T) {
    assert!(email_verified_test(
        field,
        "jwt_field_parsing/parse_email_verified_field_test.circom"
    )
    .is_err());
}

// The tests

#[test]
fn simple_quoted() {
    should_pass_quoted(jwt_field_str("\"name\": \"value\",", "name", "value"));
}

#[test]
fn simple_unquoted() {
    should_pass_unquoted(jwt_field_str("\"name\": value,", "name", "value"));
}

#[test]
fn no_whitespace_quoted() {
    should_pass_quoted(jwt_field_str("\"name\":\"value\",", "name", "value"));
}

#[test]
fn no_whitespace_unquoted() {
    should_pass_unquoted(jwt_field_str("\"name\":value,", "name", "value"));
}

// fails to parse now with StringBodies logic
#[test]
fn malicious_value_1() {
    let mut field = jwt_field_str_malicious_indices("\"sub\": \"a\\\",b\",", "sub", "a\\");
    field.whole_field_len = field.whole_field.find(',').unwrap() + 1;
    should_fail_quoted(field.clone());
    should_pass_quoted_skip_checks(field);
}

// fails to parse now with StringBodies logic
#[test]
fn malicious_value_2() {
    let field = jwt_field_str(
        "\"name1\":\"value1\",\"name2\":\"value2\",",
        "name1",
        "value1\",\"name2\":\"value2",
    );
    should_fail_quoted(field.clone());
    should_pass_quoted_skip_checks(field);
}

#[test]
fn end_with_curly_bracket() {
    should_pass_quoted(jwt_field_str("\"name\": \"value\"}", "name", "value"));
}

#[test]
fn end_with_curly_bracket_unquoted() {
    should_pass_unquoted(jwt_field_str("\"name\": value}", "name", "value"));
}

#[test]
fn should_fail_when_name_has_no_first_quote() {
    let field = jwt_field_str("name\": \"value\",", "name", "value");
    should_fail_quoted(field.clone());
    should_pass_quoted_skip_checks(field);
}

#[test]
fn should_fail_when_name_has_no_second_quote() {
    let field = jwt_field_str("\"name: \"value\",", "name", "value");
    should_fail_quoted(field.clone());
    should_pass_quoted_skip_checks(field);
}

#[test]
fn should_fail_when_name_has_no_quotes() {
    let field = jwt_field_str("name: \"value\",", "name", "value");
    should_fail_quoted(field.clone());
    should_pass_quoted_skip_checks(field);
}

#[test]
fn should_fail_when_name_not_equal_quoted() {
    let field = jwt_field_str("\"name\": \"value\",", "fake", "value");
    should_fail_quoted(field.clone());
    should_pass_quoted_skip_checks(field);
}

#[test]
fn should_fail_when_name_not_equal_unquoted() {
    let field = jwt_field_str("\"name\": value,", "fake", "value");
    should_fail_unquoted(field.clone());
    should_pass_unquoted_skip_checks(field);
}

#[test]
fn should_fail_when_value_not_equal_quoted() {
    let mut field = jwt_field_str_malicious_indices("\"name\": \"value\",", "name", "fake");
    field.whole_field_len = field.whole_field.len();
    field.value_index = field.whole_field.find("value").unwrap();
    should_fail_quoted(field.clone());
    should_pass_quoted_skip_checks(field);
}

#[test]
fn should_fail_when_value_not_equal_unquoted() {
    let mut field = jwt_field_str_malicious_indices("\"name\": value,", "name", "fake");
    field.whole_field_len = field.whole_field.len();
    field.value_index = field.whole_field.find("value").unwrap();
    should_fail_unquoted(field.clone());
    should_pass_unquoted_skip_checks(field);
}

// ref: Circuit Bug #3, https://www.notion.so/aptoslabs/JWTFieldCheck-does-not-properly-constrain-field_len-which-can-cause-the-circuit-to-accept-field-val-9943c152e7274f35a1669a6cb416c7bf?pvs=4
#[test]
fn malicious_field_len() {
    let mut field = jwt_field_str_malicious_indices("\"name\":\",value\"", "name", ",value");
    field.whole_field_len = field.whole_field.find(',').unwrap() + 1;
    field.value_index = field.whole_field.find(',').unwrap();
    assert_ne!(field.whole_field_len, field.whole_field.len());

    should_fail_quoted(field.clone());
    should_pass_quoted_skip_checks(field);
}

// ref: Circuit Bug #4, https://www.notion.so/aptoslabs/JWTFieldCheck-allows-for-maliciously-truncating-field-values-at-any-character-f8695dcd397a4bc2b66d52349388499f?pvs=4
#[test]
fn malicious_value_len_1() {
    let mut field = jwt_field_str_malicious_indices("\"sub\":\"user,fake\",", "sub", "user");

    field.whole_field_len = field.whole_field.find(',').unwrap() + 1;

    should_fail_quoted(field.clone());
    should_pass_quoted_skip_checks(field);
}

#[test]
fn malicious_value_len_2() {
    let mut field = jwt_field_str_malicious_indices("\"sub\":user,fake,", "sub", "user");

    field.whole_field_len = field.whole_field.find(',').unwrap() + 1;

    should_pass_unquoted(field);

    let field = jwt_field_str_malicious_indices("\"sub\":user,fake,", "sub", "user,fake");

    should_fail_unquoted(field.clone());
    should_pass_unquoted_skip_checks(field);
}

#[test]
fn ev_unquoted_no_spaces() {
    should_pass_ev(jwt_field_str(
        "\"email_verified\":true,",
        "email_verified",
        "true",
    ));
}

#[test]
fn ev_unquoted_spaces() {
    should_pass_ev(jwt_field_str(
        "\"email_verified\": true ,",
        "email_verified",
        "true",
    ));
}

#[test]
fn ev_unquoted_spaces_2() {
    should_pass_ev(jwt_field_str(
        "\"email_verified\":  true  ,",
        "email_verified",
        "true",
    ));
}

#[test]
fn ev_quoted_no_spaces() {
    should_pass_ev(jwt_field_str(
        "\"email_verified\":\"true\",",
        "email_verified",
        "true",
    ));
}

#[test]
fn ev_quoted_spaces() {
    should_pass_ev(jwt_field_str(
        "\"email_verified\": \"true\" ,",
        "email_verified",
        "true",
    ));
}

#[test]
fn ev_quoted_spaces_2() {
    should_pass_ev(jwt_field_str(
        "\"email_verified\":  \"true\"  ,",
        "email_verified",
        "true",
    ));
}
