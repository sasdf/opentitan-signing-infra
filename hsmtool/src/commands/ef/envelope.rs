// Copyright lowRISC contributors (OpenTitan project).
// Licensed under the Apache License, Version 2.0, see LICENSE for details.
// SPDX-License-Identifier: Apache-2.0

use anyhow::{Context, Result, ensure};
use base64ct::{Base64, Encoding};
use cryptoki::mechanism::Mechanism;
use cryptoki::object::{Attribute, ObjectHandle};
use cryptoki::session::Session;
use serde::{Deserialize, Serialize};

use crate::util::attribute::{KeyType, ObjectClass};
use crate::util::helper;
use crate::util::kwp::{kwp_unwrap, kwp_wrap};

/// Default setting for private elementary files.
fn default_private() -> bool {
    true
}

/// Structured JSON envelope for elementary file export and import.
///
/// Encapsulates the elementary file's metadata along with base64-encoded raw contents.
/// The entire JSON document is wrapped via KWP, cryptographically authenticating the
/// metadata fields against tampering.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ElementaryFileEnvelope {
    pub label: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub application: Option<String>,
    #[serde(default = "default_private")]
    pub private: bool,
    pub contents: String,
}

impl ElementaryFileEnvelope {
    /// Create a new envelope from metadata and raw byte contents.
    pub fn new(
        label: String,
        application: Option<String>,
        private: bool,
        raw_contents: &[u8],
    ) -> Self {
        Self {
            label,
            application,
            private,
            contents: Base64::encode_string(raw_contents),
        }
    }

    /// Decode the base64 contents into raw bytes.
    pub fn decode_contents(&self) -> Result<Vec<u8>> {
        Base64::decode_vec(&self.contents)
            .context("Failed to decode base64 elementary file contents")
    }

    /// Serialize the envelope to JSON bytes.
    pub fn to_json_bytes(&self) -> Result<Vec<u8>> {
        serde_json::to_vec(self).context("Failed to serialize ElementaryFileEnvelope to JSON")
    }

    /// Deserialize an envelope from JSON bytes.
    pub fn from_json_bytes(data: &[u8]) -> Result<Self> {
        serde_json::from_slice(data)
            .context("Failed to deserialize ElementaryFileEnvelope from JSON")
    }
}

/// Wraps plaintext using KWP with hardware-backed AES-CBC (IV=0) via a PKCS#11 session.
pub fn kwp_wrap_session(
    session: &Session,
    wrapping_key: &str,
    plaintext: &[u8],
) -> Result<Vec<u8>> {
    let key_handle = find_wrapping_key(session, wrapping_key)?;
    let mechanism = Mechanism::AesCbc([0u8; 16]);
    kwp_wrap(plaintext, |block| {
        let ct = session
            .encrypt(&mechanism, key_handle, block)
            .context("PKCS#11 AES-CBC single-block encryption failed")?;
        ensure!(
            ct.len() == 16,
            "Expected 16-byte block from AES-CBC, got {} bytes",
            ct.len()
        );
        let mut out = [0u8; 16];
        out.copy_from_slice(&ct);
        Ok(out)
    })
}

/// Unwraps ciphertext using KWP with hardware-backed AES-CBC (IV=0) via a PKCS#11 session.
pub fn kwp_unwrap_session(
    session: &Session,
    unwrapping_key: &str,
    ciphertext: &[u8],
) -> Result<Vec<u8>> {
    let key_handle = find_wrapping_key(session, unwrapping_key)?;
    let mechanism = Mechanism::AesCbc([0u8; 16]);
    kwp_unwrap(ciphertext, |block| {
        let pt = session
            .decrypt(&mechanism, key_handle, block)
            .context("PKCS#11 AES-CBC single-block decryption failed")?;
        ensure!(
            pt.len() == 16,
            "Expected 16-byte block from AES-CBC, got {} bytes",
            pt.len()
        );
        let mut out = [0u8; 16];
        out.copy_from_slice(&pt);
        Ok(out)
    })
}

/// Locate the AES wrapping key handle by label or ID.
fn find_wrapping_key(session: &Session, key_name: &str) -> Result<ObjectHandle> {
    match helper::search_spec(None, Some(key_name)) {
        Ok(attrs) => {
            let mut key_attrs = attrs;
            key_attrs.push(Attribute::KeyType(KeyType::Aes.try_into()?));
            key_attrs.push(Attribute::Class(ObjectClass::SecretKey.try_into()?));
            helper::find_one_object(session, &key_attrs)
        }
        Err(e) => Err(e),
    }
    .or_else(|_| {
        let mut key_attrs = helper::search_spec(Some(key_name), None)?;
        key_attrs.push(Attribute::KeyType(KeyType::Aes.try_into()?));
        key_attrs.push(Attribute::Class(ObjectClass::SecretKey.try_into()?));
        helper::find_one_object(session, &key_attrs)
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_envelope_serde_roundtrip() {
        let raw = vec![0xDE, 0xAD, 0xBE, 0xEF, 0xCA, 0xFE];
        let envelope = ElementaryFileEnvelope::new(
            "test-ef-label".to_string(),
            Some("test-application".to_string()),
            true,
            &raw,
        );

        let json_bytes = envelope.to_json_bytes().unwrap();
        let decoded = ElementaryFileEnvelope::from_json_bytes(&json_bytes).unwrap();
        assert_eq!(envelope, decoded);
        assert_eq!(decoded.decode_contents().unwrap(), raw);
    }
}
