// Copyright lowRISC contributors (OpenTitan project).
// Licensed under the Apache License, Version 2.0, see LICENSE for details.
// SPDX-License-Identifier: Apache-2.0

use anyhow::Result;
use cryptoki::session::{Session, UserType};
use serde::{Deserialize, Serialize};
use std::any::Any;
use std::fs;
use std::path::PathBuf;

use crate::commands::ef::envelope::{ElementaryFileEnvelope, kwp_wrap_session};
use crate::commands::{BasicResult, Dispatch};
use crate::error::HsmError;
use crate::module::Module;
use crate::util::attribute::{AttrData, AttributeMap, AttributeType};
use crate::util::ef::ElementaryFile;

/// Export an Elementary File wrapped with an AES key using RFC 5649 KWP.
///
/// Reads the Elementary File (such as SPX private key or ML-DSA private seed) from the
/// token and wraps the data along with authenticated metadata (label, application, private
/// flag) into a secure envelope.
///
/// Because native AES key wrap (CKM_AES_KEY_WRAP_PAD) is not supported on Nitrokey /
/// SmartCard-HSM, KWP is constructed using hardware-backed AES-CBC operations (with IV=0
/// which is equivalent to AES-ECB) using the token's AES wrapping key. The wrapping key
/// is kept securely inside the HSM.
#[derive(clap::Args, Debug, Serialize, Deserialize)]
pub struct Export {
    /// Label of the elementary file to export.
    #[arg(short, long)]
    label: String,
    /// Optional application filter for the elementary file.
    #[arg(short, long)]
    application: Option<String>,
    /// Label or ID of the AES wrapping key.
    #[arg(short = 'k', long)]
    wrapping_key: String,
    /// Separate PKCS#11 module for AES wrapping (e.g. for SmartCard-HSM where OpenSC handles EF and libsc-hsm-pkcs11 handles AES).
    #[arg(long, env = "HSMTOOL_AES_MODULE")]
    aes_module: Option<PathBuf>,
    /// User PIN for the AES module if separate.
    #[arg(long, env = "HSMTOOL_PIN")]
    pin: Option<String>,
    /// Output file where wrapped envelope will be saved.
    filename: PathBuf,
}

#[typetag::serde(name = "ef-export")]
impl Dispatch for Export {
    fn run(
        &self,
        _context: &dyn Any,
        hsm: &Module,
        session: Option<&Session>,
    ) -> Result<Box<dyn erased_serde::Serialize>> {
        let session = session.ok_or(HsmError::SessionRequired)?;

        // Find the elementary file object on the token
        let mut search = AttributeMap::default();
        search.insert(AttributeType::Label, AttrData::Str(self.label.clone()));
        if let Some(app) = &self.application {
            search.insert(AttributeType::Application, AttrData::Str(app.clone()));
        }
        let mut matching_efs = ElementaryFile::find(session, search)?;
        if matching_efs.is_empty() {
            return Err(HsmError::ObjectNotFound(self.label.clone()).into());
        } else if matching_efs.len() > 1 {
            return Err(HsmError::TooManyObjects(matching_efs.len(), self.label.clone()).into());
        }
        let ef = matching_efs.remove(0);

        // Read raw data from the elementary file
        let raw_data = ef.clone().read(session)?;

        // Build authenticated JSON envelope containing metadata and base64 contents
        let envelope = ElementaryFileEnvelope::new(
            ef.name.clone(),
            ef.application.clone(),
            ef.private,
            &raw_data,
        );
        let json_bytes = envelope.to_json_bytes()?;

        // Perform wrapping either on a dedicated AES module or on the primary session
        let wrapped = if let Some(aes_mod_path) = &self.aes_module {
            let mut aes_hsm = Module::initialize(aes_mod_path.to_str().unwrap())?;
            let token = hsm
                .token
                .as_deref()
                .ok_or(HsmError::TokenNotFound("<none>".into()))?;
            aes_hsm.connect(token, Some(UserType::User), self.pin.as_deref())?;
            let aes_session = aes_hsm.get_session().ok_or(HsmError::SessionRequired)?;

            kwp_wrap_session(aes_session, &self.wrapping_key, &json_bytes)?
        } else {
            kwp_wrap_session(session, &self.wrapping_key, &json_bytes)?
        };

        fs::write(&self.filename, &wrapped)?;

        Ok(Box::new(BasicResult {
            label: AttrData::Str(self.label.clone()),
            ..Default::default()
        }))
    }
}
