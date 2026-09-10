// Copyright lowRISC contributors (OpenTitan project).
// Licensed under the Apache License, Version 2.0, see LICENSE for details.
// SPDX-License-Identifier: Apache-2.0

use anyhow::{Result, ensure};
use cryptoki::session::{Session, UserType};
use serde::{Deserialize, Serialize};
use std::any::Any;
use std::fs;
use std::path::PathBuf;

use crate::commands::ef::envelope::{ElementaryFileEnvelope, kwp_unwrap_session};
use crate::commands::{BasicResult, Dispatch};
use crate::error::HsmError;
use crate::module::Module;
use crate::util::attribute::AttrData;
use crate::util::ef::ElementaryFile;

/// Unwrap and import an Elementary File envelope onto the token using RFC 5649 KWP.
///
/// Unwraps the KWP envelope using the hardware AES wrapping key, verifies ICV
/// integrity and padding, and restores the Elementary File (such as SPX private key
/// or ML-DSA private seed) onto the token.
///
/// Because native AES key wrap (CKM_AES_KEY_WRAP_PAD) is not supported on Nitrokey /
/// SmartCard-HSM, KWP is constructed using hardware-backed AES-CBC operations (with IV=0
/// which is equivalent to AES-ECB). The AES wrapping key is kept securely inside the HSM.
/// Target EF label and metadata are strictly enforced from the authenticated envelope.
#[derive(clap::Args, Debug, Serialize, Deserialize)]
pub struct Import {
    /// Label or ID of the AES wrapping key.
    #[arg(short = 'k', long)]
    wrapping_key: String,
    /// Separate PKCS#11 module for AES unwrapping (e.g. for SmartCard-HSM where OpenSC handles EF and libsc-hsm-pkcs11 handles AES).
    #[arg(long, env = "HSMTOOL_AES_MODULE")]
    aes_module: Option<PathBuf>,
    /// User PIN for the AES module if separate.
    #[arg(long, env = "HSMTOOL_PIN")]
    pin: Option<String>,
    /// Path to the wrapped envelope file to import.
    filename: PathBuf,
}

#[typetag::serde(name = "ef-import")]
impl Dispatch for Import {
    fn run(
        &self,
        _context: &dyn Any,
        hsm: &Module,
        session: Option<&Session>,
    ) -> Result<Box<dyn erased_serde::Serialize>> {
        let session = session.ok_or(HsmError::SessionRequired)?;

        // Read wrapped ciphertext from file
        let ciphertext = fs::read(&self.filename)?;

        // Unwrap and authenticate payload via hardware-backed KWP
        let plaintext_json = if let Some(aes_mod_path) = &self.aes_module {
            let mut aes_hsm = Module::initialize(aes_mod_path.to_str().unwrap())?;
            let token = hsm
                .token
                .as_deref()
                .ok_or(HsmError::TokenNotFound("<none>".into()))?;
            aes_hsm.connect(token, Some(UserType::User), self.pin.as_deref())?;
            let aes_session = aes_hsm.get_session().ok_or(HsmError::SessionRequired)?;

            kwp_unwrap_session(aes_session, &self.wrapping_key, &ciphertext)?
        } else {
            kwp_unwrap_session(session, &self.wrapping_key, &ciphertext)?
        };

        // Parse authenticated envelope JSON
        let envelope = ElementaryFileEnvelope::from_json_bytes(&plaintext_json)?;

        // Collision protection: ensure no object already exists with this label
        let ef_check = ElementaryFile::new(envelope.label.clone());
        let ef_check = if let Some(app) = &envelope.application {
            ef_check.application(app.clone())
        } else {
            ef_check
        };
        ensure!(
            !ef_check.exists(session)?,
            "Elementary file '{}' already exists on target token",
            envelope.label
        );

        // Decode raw byte contents
        let raw_contents = envelope.decode_contents()?;

        // Write new Elementary File to token with authenticated metadata
        let mut ef = ElementaryFile::new(envelope.label.clone()).private(envelope.private);
        if let Some(app) = envelope.application {
            ef = ef.application(app);
        }
        ef.write(session, &raw_contents)?;

        Ok(Box::new(BasicResult {
            label: AttrData::Str(envelope.label),
            ..Default::default()
        }))
    }
}
