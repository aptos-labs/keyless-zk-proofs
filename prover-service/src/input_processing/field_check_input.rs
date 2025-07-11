// Copyright © Aptos Foundation

use super::{field_parser::ParsedField, types::VerifiedInput};
use crate::input_processing::field_parser::FieldParser;
use anyhow::{bail, Result};
use aptos_keyless_common::input_processing::circuit_input_signals::{
    CircuitInputSignals, Unpadded,
};

fn calc_string_bodies(s: &str) -> Vec<bool> {
    let bytes = s.as_bytes();
    let mut string_bodies = vec![false; s.len()];
    let _quotes = vec![false; s.len()];

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

pub fn field_check_input_signals(input: &VerifiedInput) -> Result<CircuitInputSignals<Unpadded>> {
    let result = CircuitInputSignals::new()
        // "default" behavior
        .merge(signals_for_field(input, "iss")?)?
        .merge(signals_for_field(input, "nonce")?)?
        .merge(signals_for_field(input, "iat")?)?
        // "default" behavior except that the jwt field will have a key that is input.uid_key
        .merge(signals_for_field_with_key(input, "uid", &input.uid_key)?)?
        // custom behavior
        .merge(extra_field_signals(input)?)?
        .merge(email_verified_signals(input)?)?
        .merge(aud_signals(input)?)?;

    Ok(result)
}

pub fn whole_field_signals(
    parsed_field: &ParsedField<usize>,
    name: &str,
) -> Result<CircuitInputSignals<Unpadded>> {
    let mut result = CircuitInputSignals::new()
        .str_input(&(String::from(name) + "_field"), &parsed_field.whole_field)
        .usize_input(
            &(String::from(name) + "_field_len"),
            parsed_field.whole_field.len(),
        )
        .usize_input(&(String::from(name) + "_index"), parsed_field.index);

    if name == "nonce" || name == "iss" || name == "aud" || name == "uid" {
        result = result.bools_input(
            &(String::from(name) + "_field_string_bodies"),
            &calc_string_bodies(&parsed_field.whole_field),
        );
    }

    Ok(result)
}

pub fn field_components_signals(
    parsed_field: &ParsedField<usize>,
    name: &str,
) -> Result<CircuitInputSignals<Unpadded>> {
    let result = CircuitInputSignals::new()
        .usize_input(
            &(String::from(name) + "_colon_index"),
            parsed_field.colon_index,
        )
        .str_input(&(String::from(name) + "_name"), &parsed_field.key)
        .usize_input(
            &(String::from(name) + "_value_index"),
            parsed_field.value_index,
        )
        .usize_input(
            &(String::from(name) + "_value_len"),
            parsed_field.value.len(),
        )
        .str_input(&(String::from(name) + "_value"), &parsed_field.value);

    Ok(result)
}

pub fn signals_for_field(
    input: &VerifiedInput,
    name: &str,
) -> Result<CircuitInputSignals<Unpadded>> {
    let parsed_field =
        FieldParser::find_and_parse_field(input.jwt_parts.payload_decoded()?.as_str(), name)?;

    let result = CircuitInputSignals::new()
        .merge(whole_field_signals(&parsed_field, name)?)?
        .merge(field_components_signals(&parsed_field, name)?)?;

    Ok(result)
}

pub fn signals_for_field_with_key(
    input: &VerifiedInput,
    name: &str,
    key_in_jwt: &str,
) -> Result<CircuitInputSignals<Unpadded>> {
    let parsed_field =
        FieldParser::find_and_parse_field(input.jwt_parts.payload_decoded()?.as_str(), key_in_jwt)?;

    let result = CircuitInputSignals::new()
        .merge(whole_field_signals(&parsed_field, name)?)?
        .merge(field_components_signals(&parsed_field, name)?)?
        .usize_input(&(String::from(name) + "_name_len"), key_in_jwt.len());

    Ok(result)
}

// These signals have custom logic
//

pub fn private_aud_value(input: &VerifiedInput) -> Result<String> {
    match (input.skip_aud_checks, &input.idc_aud) {
        (true, Some(_)) => bail!("there is no aud-based recovery in aud-less mode"),
        (true, None) => Ok("".to_string()),
        (false, Some(v)) => Ok(v.clone()),
        (false, None) => {
            let aud = input.jwt.payload.aud.clone();
            Ok(aud)
        }
    }
}

pub fn override_aud_value(input: &VerifiedInput) -> String {
    if let Some(_v) = &input.idc_aud {
        input.jwt.payload.aud.clone()
    } else {
        String::from("")
    }
}

pub fn aud_signals(input: &VerifiedInput) -> Result<CircuitInputSignals<Unpadded>> {
    let parsed_field =
        FieldParser::find_and_parse_field(input.jwt_parts.payload_decoded()?.as_str(), "aud")?;

    let private_aud_value = private_aud_value(input)?;
    let override_aud_value = override_aud_value(input);

    let mut result = CircuitInputSignals::new()
        .merge(whole_field_signals(&parsed_field, "aud")?)?
        .usize_input("aud_colon_index", parsed_field.colon_index)
        .str_input("aud_name", &parsed_field.key)
        .usize_input("aud_value_index", parsed_field.value_index)
        .usize_input("private_aud_value_len", private_aud_value.len())
        .str_input("private_aud_value", &private_aud_value)
        .usize_input("override_aud_value_len", override_aud_value.len())
        .str_input("override_aud_value", &override_aud_value);

    result = match &input.idc_aud {
        Some(_idc_aud_value) => result.bool_input("use_aud_override", true),
        None => result.bool_input("use_aud_override", false),
    };

    Ok(result)
}

pub fn email_verified_signals(input: &VerifiedInput) -> Result<CircuitInputSignals<Unpadded>> {
    let parsed_field = parsed_email_verified_field_or_default(input)?;

    let result = CircuitInputSignals::new()
        .merge(whole_field_signals(&parsed_field, "ev")?)?
        .merge(field_components_signals(&parsed_field, "ev")?)?;

    Ok(result)
}

pub fn extra_field_signals(input: &VerifiedInput) -> Result<CircuitInputSignals<Unpadded>> {
    let parsed_field = parsed_extra_field_or_default(input)?;

    let result = CircuitInputSignals::new().merge(whole_field_signals(&parsed_field, "extra")?)?;

    Ok(result)
}

pub fn parsed_email_verified_field_or_default(input: &VerifiedInput) -> Result<ParsedField<usize>> {
    if input.uid_key == "email" {
        Ok(FieldParser::find_and_parse_field(
            input.jwt_parts.payload_decoded()?.as_str(),
            "email_verified",
        )?)
    } else {
        Ok(email_verified_field_default_value())
    }
}

pub fn parsed_extra_field_or_default(input: &VerifiedInput) -> Result<ParsedField<usize>> {
    if let Some(extra_field_key) = &input.extra_field {
        Ok(FieldParser::find_and_parse_field(
            input.jwt_parts.payload_decoded()?.as_str(),
            extra_field_key,
        )?)
    } else {
        Ok(extra_field_default_value())
    }
}

pub fn extra_field_default_value() -> ParsedField<usize> {
    ParsedField {
        index: 1,
        key: String::from(""),
        value: String::from(""),
        colon_index: 0,
        value_index: 0,
        whole_field: String::from(" "),
    }
}

pub fn email_verified_field_default_value() -> ParsedField<usize> {
    ParsedField {
        index: 1,
        key: String::from("email_verified"),
        value: String::from("true"),
        colon_index: 16,
        value_index: 17,
        whole_field: String::from("\"email_verified\":true,"),
    }
}
