//! # sha3-hash
//!
//! This library provides an easy-to-use SHA-3 hash type. It can be serialized and
//! deserialized via [Serde](serde), and supports all expected operations.
//!
//! Here is an example of how you might use this library to compute a SHA-3 hash:
//!
//! ```
//! let data = "Hello World!";
//! let hash = sha3_hash::Hash::hash_bytes(data.as_bytes());
//!
//! // Prints: d0e47486bbf4c16acac26f8b653592973c1362909f90262877089f9c8a4536af
//! println!("{}", hash);
//!
//! // Serializing the hash to a JSON string using `serde_json`
//! let json_string = serde_json::to_string(&hash).unwrap();
//! ```
//!
//! Adding this library to `Cargo.toml`:
//!
//! ```toml
//! [dependencies]
//! sha3-hash = "0.1"
//! ```
//!

#![no_std]

use core::{convert::TryInto, fmt};
use serde::{de::Unexpected, Deserialize, Serialize};
use sha3::{Digest, Sha3_256};

/// Represents a SHA-3 hash (256 bits)
///
/// This struct implements the [Serialize](serde::Serialize) and
/// [Deserialize](serde::Deserialize) traits with a hexadecimal string representation.
#[derive(Copy, Clone, Eq, PartialEq, Ord, PartialOrd, Hash)]
pub struct Hash {
    bytes: [u8; 32],
}

fn hex_to_int(c: char) -> Result<u8, ()> {
    Ok(match c {
        '0' => 0,
        '1' => 1,
        '2' => 2,
        '3' => 3,
        '4' => 4,
        '5' => 5,
        '6' => 6,
        '7' => 7,
        '8' => 8,
        '9' => 9,
        'a' => 10,
        'b' => 11,
        'c' => 12,
        'd' => 13,
        'e' => 14,
        'f' => 15,
        'A' => 10,
        'B' => 11,
        'C' => 12,
        'D' => 13,
        'E' => 14,
        'F' => 15,
        _ => return Err(()),
    })
}

fn byte_to_hex(b: u8) -> (u8, u8) {
    let upper = b >> 4;
    let lower = b & 0xf;
    (
        if upper < 10 {
            upper + b'0'
        } else {
            upper - 10 + b'a'
        },
        if lower < 10 {
            lower + b'0'
        } else {
            lower - 10 + b'a'
        },
    )
}

impl fmt::Debug for Hash {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        let mut buf = [0; 64];
        self.write_hex(&mut buf);
        core::fmt::Write::write_str(f, core::str::from_utf8(&buf[..]).unwrap())
    }
}

impl fmt::Display for Hash {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        fmt::Debug::fmt(self, f)
    }
}

impl Serialize for Hash {
    fn serialize<S: serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        let mut buf = [0; 64];
        self.write_hex(&mut buf);
        serializer.serialize_str(core::str::from_utf8(&buf[..]).unwrap())
    }
}

struct HashStringVisitor;

impl<'de> serde::de::Visitor<'de> for HashStringVisitor {
    type Value = Hash;

    fn expecting(&self, formatter: &mut fmt::Formatter) -> fmt::Result {
        formatter.write_str("a string containing 64 hexadecimal characters")
    }

    fn visit_str<E: serde::de::Error>(self, v: &str) -> Result<Self::Value, E> {
        let mut chars = v.chars();
        let mut arr = [0; 32];
        for byte in &mut arr {
            let first_char = chars
                .next()
                .ok_or_else(|| E::invalid_length(v.len(), &self))?;
            let second_char = chars
                .next()
                .ok_or_else(|| E::invalid_length(v.len(), &self))?;
            let first = hex_to_int(first_char)
                .map_err(|()| E::invalid_value(Unexpected::Char(first_char), &self))?;
            let second = hex_to_int(second_char)
                .map_err(|()| E::invalid_value(Unexpected::Char(second_char), &self))?;
            *byte = first * 16 + second;
        }
        if chars.next().is_some() {
            return Err(E::invalid_length(v.len(), &self));
        }
        Ok(Hash { bytes: arr })
    }
}

impl<'de> Deserialize<'de> for Hash {
    fn deserialize<D: serde::Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        deserializer.deserialize_str(HashStringVisitor {})
    }
}

#[derive(Debug, Clone)]
pub struct TryFromHexError;

impl Hash {
    /// Compute the SHA-3 hash of the provided bytes
    pub fn hash_bytes(data: &[u8]) -> Self {
        let mut hasher = Sha3_256::new();
        hasher.update(data);
        let result = hasher.finalize();
        Hash {
            bytes: result.as_slice().try_into().expect("Wrong length"),
        }
    }

    /// Convert this hash to a byte slice
    pub fn as_bytes(&self) -> &[u8; 32] {
        &self.bytes
    }

    /// Create a hash from a given byte array
    pub fn from_bytes(bytes: [u8; 32]) -> Self {
        Self { bytes }
    }

    fn write_hex(self, buf: &mut [u8; 64]) {
        for i in 0..32 {
            let (a, b) = byte_to_hex(self.bytes[i]);
            buf[i * 2] = a;
            buf[i * 2 + 1] = b;
        }
    }

    /// Convert a hex string to a hash
    ///
    /// The string can be uppercase or lowercase (or mixed), and must be exactly 64
    /// characters long.
    pub fn try_from_hex(hex: &str) -> Result<Self, TryFromHexError> {
        let mut hex = hex.trim().chars();
        let mut bytes = [0; 32];
        for byte in &mut bytes {
            let a = hex_to_int(hex.next().ok_or(TryFromHexError)?).map_err(|_| TryFromHexError)?;
            let b = hex_to_int(hex.next().ok_or(TryFromHexError)?).map_err(|_| TryFromHexError)?;
            *byte = a * 16 + b
        }
        if hex.next().is_some() {
            return Err(TryFromHexError);
        }
        Ok(Self { bytes })
    }
}

#[cfg(test)]
mod tests {
    use super::Hash;
    use serde_json;

    extern crate std;
    use std::format;
    use std::string::ToString;

    #[test]
    fn test_empty_sha3() {
        let actual = Hash::hash_bytes(&[]);
        let expected: Hash = serde_json::from_str(
            "\"a7ffc6f8bf1ed76651c14756a061d662f580ff4de43b49fa82d80a4b80f8434a\"",
        )
        .unwrap();
        assert_eq!(actual, expected);
    }

    #[test]
    fn test_roundtrip_serialisation() {
        let json = "\"7f9c2ba4e88f827d616045507605853ed73b8093f6efbc88eb1a6eacfa66ef26\"";
        let hash: Hash = serde_json::from_str(json).unwrap();
        let json2 = serde_json::to_string(&hash).unwrap();
        assert_eq!(json, json2);
    }

    #[test]
    fn hash_to_string() {
        let hash = Hash::hash_bytes(&[]);
        let expected = "a7ffc6f8bf1ed76651c14756a061d662f580ff4de43b49fa82d80a4b80f8434a";
        assert_eq!(hash.to_string(), expected);
        assert_eq!(Hash::from_bytes(*hash.as_bytes()), hash);
    }

    #[test]
    fn hash_debug() {
        let hash = Hash::hash_bytes(&[]);
        let expected = "a7ffc6f8bf1ed76651c14756a061d662f580ff4de43b49fa82d80a4b80f8434a";
        assert_eq!(format!("{:?}", hash), expected);
    }

    #[test]
    fn deserialize_invalid_string() {
        let json = "\"xf9c2ba4e88f827d616045507605853ed73b8093f6efbc88eb1a6eacfa66ef26\"";
        assert!(serde_json::from_str::<Hash>(json).is_err());
    }

    #[test]
    fn deserialize_too_long_string() {
        let json = "\"ae7ffc6f8bf1ed76651c14756a061d662f580ff4de43b49fa82d80a4b80f8434a\"";
        assert!(serde_json::from_str::<Hash>(json).is_err());
    }

    #[test]
    fn try_from_hex() {
        assert!(Hash::try_from_hex("abc").is_err());
        assert!(Hash::try_from_hex(
            "a7ffc6f8bf1ed76651c14756a061d662f580ff4de43b49fa82d80a4b80f8434a"
        )
        .is_ok());
        assert!(Hash::try_from_hex(
            "A7FFC6F8BF1ED76651C14756A061D662F580FF4DE43B49FA82D80A4B80F8434A"
        )
        .is_ok());
        assert!(Hash::try_from_hex(
            "a7FFC6F8BF1ED76651c14756A061D662F580FF4DE43B49FA82D80A4B80F8434A"
        )
        .is_ok());
        assert!(Hash::try_from_hex(
            "  A7FFC6F8BF1ED76651C14756A061D662F580FF4DE43B49FA82D80A4B80F8434A\r\n"
        )
        .is_ok());
        assert!(Hash::try_from_hex("").is_err());

        let json = "\"A7FFC6F8BF1ED76651C14756A061D662F580FF4DE43B49FA82D80A4B80F8434A\"";
        let hash: Hash = serde_json::from_str(json).unwrap();

        assert_eq!(
            Hash::try_from_hex(
                "  A7FFC6F8BF1ED76651C14756A061D662F580FF4DE43B49FA82D80A4B80F8434A\r\n"
            )
            .unwrap(),
            hash
        );
    }
}
