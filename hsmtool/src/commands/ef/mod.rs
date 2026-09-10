// Copyright lowRISC contributors (OpenTitan project).
// Licensed under the Apache License, Version 2.0, see LICENSE for details.
// SPDX-License-Identifier: Apache-2.0

use anyhow::Result;
use cryptoki::session::Session;
use serde::{Deserialize, Serialize};
use std::any::Any;

use crate::commands::Dispatch;
use crate::module::Module;

pub mod envelope;
pub mod export;
pub mod import;

/// Export and import Elementary Files (CKO_DATA).
///
/// Elementary Files store raw provisioning assets, such as SPX private key or
/// ML-DSA private seed, on smart cards and HSMs. They are protected in transit
/// using NIST SP 800-38F / RFC 5649 AES Key Wrap with Padding (KWP).
///
/// Because native AES key wrap (CKM_AES_KEY_WRAP_PAD) is not supported on Nitrokey /
/// SmartCard-HSM, KWP is constructed using hardware-backed AES-CBC operations (with IV=0
/// which is equivalent to AES-ECB). The AES wrapping key is kept securely inside the HSM
/// and never leaves it, while the Elementary File plaintext is read from or written to
/// the token by the host.
#[derive(clap::Subcommand, Debug, Serialize, Deserialize)]
pub enum Ef {
    /// Export an Elementary File wrapped with an AES key using RFC 5649 KWP.
    ///
    /// Reads the Elementary File (such as SPX private key or ML-DSA private seed)
    /// from the token and wraps it into a JSON envelope authenticated with RFC 5649 KWP.
    ///
    /// Because native AES key wrap (CKM_AES_KEY_WRAP_PAD) is not supported on Nitrokey /
    /// SmartCard-HSM, KWP is constructed using hardware-backed AES-CBC operations (with IV=0
    /// which is equivalent to AES-ECB). The AES wrapping key never leaves the HSM.
    Export(export::Export),

    /// Unwrap and import an Elementary File envelope onto the token using RFC 5649 KWP.
    ///
    /// Unwraps the KWP envelope using the hardware AES wrapping key, verifies ICV integrity,
    /// and restores the Elementary File (such as SPX private key or ML-DSA private seed)
    /// onto the token.
    ///
    /// Because native AES key wrap (CKM_AES_KEY_WRAP_PAD) is not supported on Nitrokey /
    /// SmartCard-HSM, KWP is constructed using hardware-backed AES-CBC operations (with IV=0
    /// which is equivalent to AES-ECB). The AES wrapping key never leaves the HSM. Target EF
    /// label and metadata are strictly enforced from the authenticated envelope.
    Import(import::Import),
}

#[typetag::serde(name = "__ef__")]
impl Dispatch for Ef {
    fn run(
        &self,
        context: &dyn Any,
        hsm: &Module,
        session: Option<&Session>,
    ) -> Result<Box<dyn erased_serde::Serialize>> {
        match self {
            Ef::Export(x) => x.run(context, hsm, session),
            Ef::Import(x) => x.run(context, hsm, session),
        }
    }
    fn leaf(&self) -> &dyn Dispatch
    where
        Self: Sized,
    {
        match self {
            Ef::Export(x) => x.leaf(),
            Ef::Import(x) => x.leaf(),
        }
    }
}
