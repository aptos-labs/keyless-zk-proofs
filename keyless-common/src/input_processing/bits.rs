// Copyright (c) Aptos Foundation

use anyhow::{bail, Result};
use std::ops::{self, Add, AddAssign};

/// A type for bit representation. Represents bits using strings, for easy
/// manipulation. This struct is mainly used for the sha padding computation.
#[derive(Debug, Eq, PartialEq)]
pub struct Bits {
    bits: String,
}

impl Default for Bits {
    fn default() -> Self {
        Self::new()
    }
}

impl Bits {
    pub fn new() -> Self {
        Bits {
            bits: String::new(),
        }
    }

    /// Creates a Bits instance from the given bit string
    pub fn new_with_bits(bits: &str) -> Self {
        Bits {
            bits: bits.to_string(),
        }
    }

    /// Converts the bits to bytes. The input is bits in BIG-ENDIAN
    /// order, and the output is bytes in BIG-ENDIAN order.
    pub fn as_bytes(&self) -> Result<Vec<u8>> {
        if self.bits.len() % 8 != 0 {
            bail!("Tried to convert bits to bytes, where the bit length is not divisible by 8! Bits: {}", self.bits);
        } else {
            let mut bytes = Vec::new();

            for i in 0..(self.bits.len() / 8) {
                let idx = i * 8;
                let bits_for_chunk: &str = &self[idx..idx + 8];
                let chunk_byte =
                    u8::from_str_radix(bits_for_chunk, 2).expect("Binary string failed to parse!");

                bytes.push(chunk_byte);
            }

            Ok(bytes)
        }
    }

    /// Creates a Bits instance from a byte slice, converting each byte
    /// to its corresponding 8-bit binary representation.
    pub fn bit_representation_of_bytes(s: &[u8]) -> Self {
        let mut bits = Bits::new();
        for byte in s {
            bits.bits += &format!("{byte:08b}");
        }
        bits
    }
}

impl ops::Index<ops::Range<usize>> for Bits {
    type Output = str;

    fn index(&self, index: ops::Range<usize>) -> &str {
        self.bits.index(index)
    }
}

impl AddAssign<Bits> for Bits {
    fn add_assign(&mut self, rhs: Bits) {
        self.bits += &rhs.bits;
    }
}

impl Add<Bits> for Bits {
    type Output = Bits;

    fn add(self, rhs: Bits) -> Self::Output {
        Bits {
            bits: self.bits + &rhs.bits,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::Bits;

    #[test]
    fn test_bits_to_bytes() {
        let b = Bits::new_with_bits("00001111");
        assert_eq!(b.as_bytes().unwrap()[0], 15u8);

        let b = Bits::new_with_bits("0000000000001111");
        let bytes = b.as_bytes().unwrap();
        assert_eq!(bytes.len(), 2);
        assert_eq!(bytes[0], 0u8);
        assert_eq!(bytes[1], 15u8);

        let b = Bits::new_with_bits("1111111100000000");
        let bytes = b.as_bytes().unwrap();
        assert_eq!(bytes.len(), 2);
        assert_eq!(bytes[0], 255u8);
        assert_eq!(bytes[1], 0u8);
    }
}
