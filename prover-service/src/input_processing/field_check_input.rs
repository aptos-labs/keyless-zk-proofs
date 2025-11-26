// Copyright (c) Aptos Foundation

use super::field_parser::ParsedField;
use crate::input_processing::field_parser::FieldParser;
use crate::request_handler::types::VerifiedInput;
use anyhow::{bail, Result};
use aptos_keyless_common::input_processing::circuit_input_signals::{
    CircuitInputSignals, Unpadded,
};

/// Calculates which bytes in the string are inside string bodies
fn calc_string_bodies(string: &str) -> Vec<bool> {
    let bytes = string.as_bytes();
    let mut string_bodies = vec![false; string.len()];

    string_bodies[0] = false;
    string_bodies[1] = bytes[0] == b'"';

    for i in 2..bytes.len() {
        // should we start a string body?
        if !string_bodies[i - 2] && bytes[i - 1] == b'"' && bytes[i - 2] != b'\\' {
            string_bodies[i] = true;
        // should we end a string body?
        } else if string_bodies[i - 1] && bytes[i] == b'"' && bytes[i - 1] != b'\\' {
            string_bodies[i] = false;
        } else {
            string_bodies[i] = string_bodies[i - 1];
        }
    }

    string_bodies
}

/// Generates the field check input signals for the given verified input
pub fn field_check_input_signals(
    verified_input: &VerifiedInput,
) -> Result<CircuitInputSignals<Unpadded>> {
    let result = CircuitInputSignals::new()
        // "Default" behavior
        .merge(signals_for_field(verified_input, "iss")?)?
        .merge(signals_for_field(verified_input, "nonce")?)?
        .merge(signals_for_field(verified_input, "iat")?)?
        // "Default" behavior except that the jwt field will have a key that is input.uid_key
        .merge(signals_for_field_with_key(
            verified_input,
            "uid",
            &verified_input.uid_key,
        )?)?
        // Custom behavior
        .merge(extra_field_signals(verified_input)?)?
        .merge(email_verified_signals(verified_input)?)?
        .merge(aud_signals(verified_input)?)?;

    Ok(result)
}

/// Generates the whole field signals for the given parsed field
fn whole_field_signals(
    parsed_field: &ParsedField<usize>,
    field_name: &str,
) -> Result<CircuitInputSignals<Unpadded>> {
    let mut result = CircuitInputSignals::new()
        .str_input(
            &(String::from(field_name) + "_field"),
            &parsed_field.whole_field,
        )
        .usize_input(
            &(String::from(field_name) + "_field_len"),
            parsed_field.whole_field.len(),
        )
        .usize_input(&(String::from(field_name) + "_index"), parsed_field.index);

    if field_name == "nonce" || field_name == "iss" || field_name == "aud" || field_name == "uid" {
        result = result.bools_input(
            &(String::from(field_name) + "_field_string_bodies"),
            &calc_string_bodies(&parsed_field.whole_field),
        );
    }

    Ok(result)
}

/// Generates the field component signals for the given parsed field
fn field_components_signals(
    parsed_field: &ParsedField<usize>,
    field_name: &str,
) -> Result<CircuitInputSignals<Unpadded>> {
    let result = CircuitInputSignals::new()
        .usize_input(
            &(String::from(field_name) + "_colon_index"),
            parsed_field.colon_index,
        )
        .str_input(&(String::from(field_name) + "_name"), &parsed_field.key)
        .usize_input(
            &(String::from(field_name) + "_value_index"),
            parsed_field.value_index,
        )
        .usize_input(
            &(String::from(field_name) + "_value_len"),
            parsed_field.value.len(),
        )
        .str_input(&(String::from(field_name) + "_value"), &parsed_field.value);

    Ok(result)
}

/// Generates the field check input signals for the given field name
fn signals_for_field(
    verified_input: &VerifiedInput,
    field_name: &str,
) -> Result<CircuitInputSignals<Unpadded>> {
    let parsed_field = FieldParser::find_and_parse_field(
        verified_input.jwt_parts.payload_decoded()?.as_str(),
        field_name,
    )?;

    let result = CircuitInputSignals::new()
        .merge(whole_field_signals(&parsed_field, field_name)?)?
        .merge(field_components_signals(&parsed_field, field_name)?)?;

    Ok(result)
}

/// Generates the field check input signals for the given field name and key in JWT
fn signals_for_field_with_key(
    verified_input: &VerifiedInput,
    field_name: &str,
    key_in_jwt: &str,
) -> Result<CircuitInputSignals<Unpadded>> {
    let parsed_field = FieldParser::find_and_parse_field(
        verified_input.jwt_parts.payload_decoded()?.as_str(),
        key_in_jwt,
    )?;

    let result = CircuitInputSignals::new()
        .merge(whole_field_signals(&parsed_field, field_name)?)?
        .merge(field_components_signals(&parsed_field, field_name)?)?
        .usize_input(&(String::from(field_name) + "_name_len"), key_in_jwt.len());

    Ok(result)
}

/// Determines the private aud value based on the verified input
pub fn private_aud_value(verified_input: &VerifiedInput) -> Result<String> {
    match (verified_input.skip_aud_checks, &verified_input.idc_aud) {
        (true, Some(_)) => bail!("there is no aud-based recovery in aud-less mode"),
        (true, None) => Ok("".to_string()),
        (false, Some(v)) => Ok(v.clone()),
        (false, None) => {
            let aud = verified_input.jwt.payload.aud.clone();
            Ok(aud)
        }
    }
}

/// Determines the override aud value based on the verified input
pub fn override_aud_value(verified_input: &VerifiedInput) -> String {
    if verified_input.idc_aud.is_some() {
        verified_input.jwt.payload.aud.clone()
    } else {
        String::from("")
    }
}

/// Generates the aud field check input signals
fn aud_signals(verified_input: &VerifiedInput) -> Result<CircuitInputSignals<Unpadded>> {
    let parsed_field = FieldParser::find_and_parse_field(
        verified_input.jwt_parts.payload_decoded()?.as_str(),
        "aud",
    )?;

    let private_aud_value = private_aud_value(verified_input)?;
    let override_aud_value = override_aud_value(verified_input);

    let mut result = CircuitInputSignals::new()
        .merge(whole_field_signals(&parsed_field, "aud")?)?
        .usize_input("aud_colon_index", parsed_field.colon_index)
        .str_input("aud_name", &parsed_field.key)
        .usize_input("aud_value_index", parsed_field.value_index)
        .usize_input("private_aud_value_len", private_aud_value.len())
        .str_input("private_aud_value", &private_aud_value)
        .usize_input("override_aud_value_len", override_aud_value.len())
        .str_input("override_aud_value", &override_aud_value);

    let signal_value = verified_input.idc_aud.is_some();
    result = result.bool_input("use_aud_override", signal_value);

    Ok(result)
}

/// Generates the email verified field check input signals
fn email_verified_signals(verified_input: &VerifiedInput) -> Result<CircuitInputSignals<Unpadded>> {
    let parsed_field = parsed_email_verified_field_or_default(verified_input)?;

    let result = CircuitInputSignals::new()
        .merge(whole_field_signals(&parsed_field, "ev")?)?
        .merge(field_components_signals(&parsed_field, "ev")?)?;

    Ok(result)
}

/// Generates the extra field check input signals
fn extra_field_signals(verified_input: &VerifiedInput) -> Result<CircuitInputSignals<Unpadded>> {
    let parsed_field = parsed_extra_field_or_default(verified_input)?;

    let result = CircuitInputSignals::new().merge(whole_field_signals(&parsed_field, "extra")?)?;

    Ok(result)
}

/// Parses the email verified field or returns the default value
fn parsed_email_verified_field_or_default(
    verified_input: &VerifiedInput,
) -> Result<ParsedField<usize>> {
    let result = if verified_input.uid_key == "email" {
        FieldParser::find_and_parse_field(
            verified_input.jwt_parts.payload_decoded()?.as_str(),
            "email_verified",
        )?
    } else {
        ParsedField {
            index: 1,
            key: String::from("email_verified"),
            value: String::from("true"),
            colon_index: 16,
            value_index: 17,
            whole_field: String::from("\"email_verified\":true,"),
        }
    };

    Ok(result)
}

/// Parses the extra field or returns the default value
pub fn parsed_extra_field_or_default(verified_input: &VerifiedInput) -> Result<ParsedField<usize>> {
    let result = if let Some(extra_field_key) = &verified_input.extra_field {
        FieldParser::find_and_parse_field(
            verified_input.jwt_parts.payload_decoded()?.as_str(),
            extra_field_key,
        )?
    } else {
        ParsedField {
            index: 1,
            key: String::from(""),
            value: String::from(""),
            colon_index: 0,
            value_index: 0,
            whole_field: String::from(" "),
        }
    };

    Ok(result)
}
