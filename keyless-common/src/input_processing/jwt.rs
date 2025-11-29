// Copyright (c) Aptos Foundation

use crate::input_processing::encoding::{As64BitLimbs, FromB64};
use anyhow::{anyhow, ensure, Result};
use num_bigint::BigUint;
use serde::{Deserialize, Serialize};

// Type alias for RSA signature (represented as a big integer)
type RsaSignature = BigUint;

impl FromB64 for RsaSignature {
    fn from_b64(s: &str) -> Result<Self> {
        // JWT signature is encoded in big-endian
        Ok(BigUint::from_bytes_be(&base64::decode_config(
            s,
            base64::URL_SAFE_NO_PAD,
        )?))
    }
}

impl As64BitLimbs for RsaSignature {
    fn as_64bit_limbs(&self) -> Vec<u64> {
        self.to_u64_digits()
    }
}

/// Struct representing the sub-parts of a JWT
#[derive(Debug)]
pub struct JwtParts {
    header: String,
    payload: String,
    signature: String,
}

/// Struct representing the JWT header
#[derive(Serialize, Deserialize, Debug)]
pub struct JwtHeader {
    pub kid: String,
}

impl JwtHeader {
    pub fn from_b64url(s: &str) -> Result<Self> {
        let bytes = base64::decode_config(s, base64::URL_SAFE_NO_PAD)?;
        let json = String::from_utf8(bytes)?;
        let header: JwtHeader = serde_json::from_str(&json)?;
        Ok(header)
    }
}

/// Struct representing the JWT payload
#[derive(Serialize, Deserialize, Debug)]
pub struct JwtPayload {
    pub iss: String,
    pub iat: u64,
    pub nonce: String,
    pub sub: Option<String>,
    pub email: Option<String>,
    pub email_verified: Option<bool>,
    pub aud: String,
}

impl JwtPayload {
    pub fn from_b64(s: &str) -> Result<Self> {
        let bytes = base64::decode_config(s, base64::URL_SAFE_NO_PAD)?;
        let json = String::from_utf8(bytes)?;
        let payload: JwtPayload = serde_json::from_str(&json)?;
        Ok(payload)
    }
}

/// Struct representing a fully decoded JWT
#[derive(Debug)]
pub struct DecodedJWT {
    pub header: JwtHeader,
    pub payload: JwtPayload,
    pub signature: RsaSignature,
}

impl DecodedJWT {
    pub fn from_b64(s: &str) -> Result<Self> {
        let jwt_parts: Vec<&str> = s.split('.').collect();
        ensure!(jwt_parts.len() == 3);
        let header_b64 = jwt_parts[0];
        let payload_b64 = jwt_parts[1];
        let signature_b64 = jwt_parts[2];
        let header = JwtHeader::from_b64url(header_b64)?;
        let payload = JwtPayload::from_b64(payload_b64)?;
        let signature = RsaSignature::from_b64(signature_b64)?;
        Ok(Self {
            header,
            payload,
            signature,
        })
    }
}

impl FromB64 for JwtParts {
    fn from_b64(s: &str) -> Result<Self>
    where
        Self: Sized,
    {
        let jwt_parts: Vec<&str> = s.split('.').collect();
        Ok(Self {
            header: String::from(
                *jwt_parts
                    .first()
                    .ok_or_else(|| anyhow!("JWT did not parse correctly"))?,
            ),
            payload: String::from(
                *jwt_parts
                    .get(1)
                    .ok_or_else(|| anyhow!("JWT did not parse correctly"))?,
            ),
            signature: String::from(
                *jwt_parts
                    .get(2)
                    .ok_or_else(|| anyhow!("JWT did not parse correctly"))?,
            ),
        })
    }
}

impl JwtParts {
    pub fn unsigned_undecoded(&self) -> String {
        String::from(&self.header) + "." + &self.payload
    }

    pub fn payload_undecoded(&self) -> String {
        String::from(&self.payload)
    }

    pub fn header_undecoded_with_dot(&self) -> String {
        String::from(&self.header) + "."
    }

    pub fn header_decoded(&self) -> Result<String> {
        Ok(String::from_utf8(base64::decode_config(
            &self.header,
            base64::URL_SAFE_NO_PAD,
        )?)?)
    }

    pub fn payload_decoded(&self) -> Result<String> {
        Ok(String::from_utf8(base64::decode_config(
            &self.payload,
            base64::URL_SAFE_NO_PAD,
        )?)?)
    }

    pub fn signature(&self) -> Result<RsaSignature> {
        RsaSignature::from_b64(&self.signature)
    }
}

/// Struct representing the unsigned parts of a JWT with padding
pub struct UnsignedJwtPartsWithPadding {
    b: Vec<u8>,
}

impl UnsignedJwtPartsWithPadding {
    pub fn from_b64_bytes_with_padding(b: &[u8]) -> Self {
        Self { b: Vec::from(b) }
    }

    pub fn payload_with_padding(&self) -> Result<Vec<u8>> {
        let first_dot = self
            .b
            .iter()
            .position(|c| c == &b'.')
            .ok_or_else(|| anyhow!("Not a valid jwt; has no \".\""))?;

        Ok(Vec::from(&self.b[first_dot + 1..]))
    }
}
