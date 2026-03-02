// Copyright (c) Aptos Foundation

use std::{iter::Peekable, str::CharIndices};
use thiserror::Error;

/// A parsed field from a JWT
#[derive(Debug, PartialEq, Eq)]
pub struct ParsedField<IndexInJwt> {
    pub index: IndexInJwt,
    pub key: String,
    pub value: String,
    pub colon_index: usize,
    pub value_index: usize,
    pub whole_field: String,
}

/// A simple struct to indicate that the index in the JWT is not set
#[derive(Debug, PartialEq, Eq)]
pub struct IndexInJwtNotSet {}

// Useful type annotations
pub type ConsumeResultStr = Result<(usize, String), FieldParserError>;
pub type ConsumeResultChar = Result<(usize, char), FieldParserError>;
pub type ConsumeResultEmpty = Result<(usize, ()), FieldParserError>;

/// An error that occurred while parsing a field
#[derive(Debug, PartialEq, Eq, Error)]
#[error(
    "Parse error. {}. Occurred at index {} of {}",
    explanation,
    index,
    whole_str
)]
pub struct FieldParserError {
    explanation: String,
    index: usize,
    whole_str: String,
}

/// A simple field parser for JWT fields
#[derive(Debug)]
pub struct FieldParser<'a> {
    char_indices: Peekable<CharIndices<'a>>,
    whole_str: String,
}

impl<'a> FieldParser<'a> {
    pub fn new(whole_str: &'a str) -> Self {
        let char_indices = whole_str.char_indices().peekable();
        Self {
            char_indices,
            whole_str: whole_str.into(),
        }
    }

    /// Creates and returns a field parser error with the given explanation
    fn error(&mut self, explanation: &str) -> FieldParserError {
        FieldParserError {
            explanation: explanation.into(),
            index: match self.char_indices.peek() {
                Some((i, _)) => *i,
                None => self.whole_str.len(),
            },
            whole_str: self.whole_str.clone(),
        }
    }

    /// Creates and returns an end-of-stream error
    fn eos_error(&mut self) -> FieldParserError {
        self.error("Unexpected end of stream")
    }

    /// Parses a field from the input string
    pub fn parse(&mut self) -> Result<ParsedField<IndexInJwtNotSet>, FieldParserError> {
        let (_, key) = self.consume_string()?;
        let (colon_index, _) = self.consume_non_whitespace_char(&[':'])?;
        let (value_index, value) = self.consume_value()?;
        let (field_end_delimiter_index, _) = self.consume_non_whitespace_char(&[',', '}'])?;
        let whole_field = String::from(&self.whole_str[..field_end_delimiter_index + 1]);

        Ok(ParsedField {
            index: IndexInJwtNotSet {},
            key,
            value,
            colon_index,
            value_index,
            whole_field,
        })
    }

    /// Peeks at the next character without consuming it
    fn peek(&mut self) -> ConsumeResultChar {
        match self.char_indices.peek() {
            Some(p) => Ok(*p),
            None => Err(self.eos_error()),
        }
    }

    /// Pops and returns the next character
    fn pop(&mut self) -> ConsumeResultChar {
        self.char_indices.next().ok_or_else(|| self.eos_error())
    }

    /// Consumes whitespace characters from the input
    fn consume_whitespace(&mut self) -> ConsumeResultEmpty {
        let (index, _) = self.peek()?;
        while self.peek()?.1 == ' ' {
            self.pop().map_err(|_| self.eos_error())?;
        }
        Ok((index, ()))
    }

    /// Consumes the first non-whitespace character from the input (must be in char_options)
    fn consume_non_whitespace_char(&mut self, char_options: &[char]) -> ConsumeResultChar {
        while self.peek()?.1 == ' ' {
            self.pop().map_err(|_| self.eos_error())?;
        }

        let c = self.peek()?.1;
        if char_options.contains(&c) {
            self.pop().map_err(|_| self.eos_error())
        } else {
            Err(self.error(&format!(
                "Expected a character in {:?}, got {}",
                char_options, c
            )))
        }
    }

    /// Consumes a value (either quoted string or unquoted)
    fn consume_value(&mut self) -> ConsumeResultStr {
        self.consume_whitespace()?;
        match self.peek()?.1 {
            '"' => self.consume_string(),
            _ => self.consume_unquoted(),
        }
    }

    // TODO: should this handle escaped characters (e.g., quotes, newlines)? It doesn't currently.
    /// Consumes a quoted string from the input
    fn consume_string(&mut self) -> ConsumeResultStr {
        if self.peek()?.1 != '"' {
            Err(self.error("Expected a string here"))
        } else {
            self.pop()?; // ignore the '"'

            let (index, _) = self.peek()?;
            let mut result = String::new();

            result.push(self.pop()?.1); // push the '"'

            while self.peek()?.1 != '"' {
                result.push(self.pop()?.1);
            }

            self.pop()?; // ignore the '"'

            // The circuit requires the value_index to be for the first character after the quote
            Ok((index, result))
        }
    }

    /// Consumes an unquoted value from the input
    fn consume_unquoted(&mut self) -> ConsumeResultStr {
        let (index, _) = self.peek()?;
        let mut result = String::new();

        while self.peek()?.1 != ' ' && self.peek()?.1 != ',' && self.peek()?.1 != '}' {
            result.push(self.pop()?.1);
        }

        Ok((index, result))
    }

    /// Finds and parses the field with the given key from the JWT payload
    pub fn find_and_parse_field(
        jwt_payload: &'a str,
        key: &str,
    ) -> Result<ParsedField<usize>, FieldParserError> {
        let key_in_quotes = String::from("\"") + key + "\"";

        let index = jwt_payload
            .find(&key_in_quotes)
            .ok_or_else(|| FieldParserError {
                explanation: format!(
                    "Could not find {} in jwt payload: {}",
                    key_in_quotes, jwt_payload
                ),
                index: 0,
                whole_str: String::from(jwt_payload),
            })?;

        let field_check_input = Self::new(&jwt_payload[index..]).parse()?;

        Ok(ParsedField {
            index,
            key: field_check_input.key,
            value: field_check_input.value,
            colon_index: field_check_input.colon_index,
            value_index: field_check_input.value_index,
            whole_field: field_check_input.whole_field,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::{IndexInJwtNotSet, ParsedField};
    use crate::input_processing::field_parser::FieldParser;

    #[test]
    fn test_parse_iss() {
        // Parse the iss field
        let result = FieldParser::new("\"iss\": \"https://accounts.google.com\",").parse();
        let parsed_field = result.expect("Failed to parse iss field");

        // Verify the parsed field
        let expected_parsed_field = create_parsed_field(
            "iss",
            "https://accounts.google.com",
            5,
            8,
            "\"iss\": \"https://accounts.google.com\",",
        );
        assert_eq!(parsed_field, expected_parsed_field);
    }

    #[test]
    fn test_parse_email_extra_chars() {
        // Parse the email field
        let result =
            FieldParser::new("\"email\": \"michael@aptoslabs.com\" , DONTINCLUDETHISINRESULT")
                .parse();
        let parsed_field = result.expect("Failed to parse email field");

        // Verify the parsed field
        let expected_parsed_field = create_parsed_field(
            "email",
            "michael@aptoslabs.com",
            7,
            10,
            "\"email\": \"michael@aptoslabs.com\" ,",
        );
        assert_eq!(parsed_field, expected_parsed_field);
    }

    /// Creates a parsed field using the given values (for testing)
    fn create_parsed_field(
        key: &str,
        value: &str,
        colon_index: usize,
        value_index: usize,
        whole_field: &str,
    ) -> ParsedField<IndexInJwtNotSet> {
        ParsedField {
            index: IndexInJwtNotSet {},
            key: key.into(),
            value: value.into(),
            colon_index,
            value_index,
            whole_field: whole_field.into(),
        }
    }
}
