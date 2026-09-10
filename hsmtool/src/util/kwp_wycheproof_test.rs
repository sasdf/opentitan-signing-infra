// Copyright lowRISC contributors (OpenTitan project).
// Licensed under the Apache License, Version 2.0, see LICENSE for details.
// SPDX-License-Identifier: Apache-2.0

use anyhow::{Context, Result, bail, ensure};
use openssl::symm::{Cipher, Crypter, Mode};
use serde::Deserialize;
use std::fs;

use crate::util::kwp::{kwp_unwrap, kwp_wrap};

#[derive(Debug, Deserialize)]
struct WycheproofFile {
    algorithm: String,
    #[serde(rename = "numberOfTests")]
    number_of_tests: usize,
    #[serde(rename = "testGroups")]
    test_groups: Vec<TestGroup>,
}

#[derive(Debug, Deserialize)]
#[allow(dead_code)]
struct TestGroup {
    #[serde(rename = "keySize")]
    key_size: usize,
    tests: Vec<TestCase>,
}

#[derive(Debug, Deserialize)]
#[allow(dead_code)]
struct TestCase {
    #[serde(rename = "tcId")]
    tc_id: usize,
    comment: String,
    key: String,
    msg: String,
    ct: String,
    result: String,
    #[serde(default)]
    flags: Vec<String>,
}

struct AesCipher {
    cipher: Cipher,
    key: Vec<u8>,
}

impl AesCipher {
    fn new(key: &[u8]) -> Result<Self> {
        let cipher = match key.len() {
            16 => Cipher::aes_128_ecb(),
            24 => Cipher::aes_192_ecb(),
            32 => Cipher::aes_256_ecb(),
            len => bail!("Unsupported AES key length: {} bytes", len),
        };
        Ok(Self {
            cipher,
            key: key.to_vec(),
        })
    }

    fn encrypt_block(&self, block: &[u8; 16]) -> Result<[u8; 16]> {
        let mut crypter = Crypter::new(self.cipher, Mode::Encrypt, &self.key, None)
            .context("Failed to initialize OpenSSL AES encryptor")?;
        crypter.pad(false);
        let mut out = [0u8; 32];
        let n = crypter
            .update(block, &mut out)
            .context("OpenSSL AES block encrypt update failed")?;
        let rest = crypter
            .finalize(&mut out[n..])
            .context("OpenSSL AES block encrypt finalize failed")?;
        ensure!(
            n + rest == 16,
            "Expected 16 encrypted bytes, got {}",
            n + rest
        );
        let mut res = [0u8; 16];
        res.copy_from_slice(&out[..16]);
        Ok(res)
    }

    fn decrypt_block(&self, block: &[u8; 16]) -> Result<[u8; 16]> {
        let mut crypter = Crypter::new(self.cipher, Mode::Decrypt, &self.key, None)
            .context("Failed to initialize OpenSSL AES decryptor")?;
        crypter.pad(false);
        let mut out = [0u8; 32];
        let n = crypter
            .update(block, &mut out)
            .context("OpenSSL AES block decrypt update failed")?;
        let rest = crypter
            .finalize(&mut out[n..])
            .context("OpenSSL AES block decrypt finalize failed")?;
        ensure!(
            n + rest == 16,
            "Expected 16 decrypted bytes, got {}",
            n + rest
        );
        let mut res = [0u8; 16];
        res.copy_from_slice(&out[..16]);
        Ok(res)
    }
}

#[test]
fn test_wycheproof_aes_kwp_vectors() -> Result<()> {
    let testvector_path = crate::util::wycheproof_testvector("aes_kwp_test.json");

    let json_content = fs::read_to_string(&testvector_path).with_context(|| {
        format!(
            "Failed to read Wycheproof test vectors from {}",
            testvector_path.display()
        )
    })?;

    let file: WycheproofFile =
        serde_json::from_str(&json_content).context("Failed to parse Wycheproof test vectors")?;

    ensure!(
        file.algorithm == "AES-KWP",
        "Unexpected algorithm in test vector file: {}",
        file.algorithm
    );

    let mut total_tested = 0;
    let mut valid_tested = 0;
    let mut invalid_tested = 0;

    for group in &file.test_groups {
        for tc in &group.tests {
            total_tested += 1;
            let key = hex::decode(&tc.key)
                .with_context(|| format!("tcId {}: invalid hex in key", tc.tc_id))?;
            let msg = hex::decode(&tc.msg)
                .with_context(|| format!("tcId {}: invalid hex in msg", tc.tc_id))?;
            let ct = hex::decode(&tc.ct)
                .with_context(|| format!("tcId {}: invalid hex in ct", tc.tc_id))?;

            let cipher = AesCipher::new(&key)?;

            match tc.result.as_str() {
                "valid" => {
                    // 1. Verify wrapping msg produces expected ct
                    let wrapped =
                        kwp_wrap(&msg, |b| cipher.encrypt_block(b)).with_context(|| {
                            format!("tcId {}: kwp_wrap failed ({})", tc.tc_id, tc.comment)
                        })?;
                    assert_eq!(
                        wrapped, ct,
                        "tcId {}: wrapped ciphertext does not match expected ({})",
                        tc.tc_id, tc.comment
                    );

                    // 2. Verify unwrapping ct recovers expected msg
                    let unwrapped =
                        kwp_unwrap(&ct, |b| cipher.decrypt_block(b)).with_context(|| {
                            format!("tcId {}: kwp_unwrap failed ({})", tc.tc_id, tc.comment)
                        })?;
                    assert_eq!(
                        unwrapped, msg,
                        "tcId {}: unwrapped plaintext does not match expected ({})",
                        tc.tc_id, tc.comment
                    );
                    valid_tested += 1;
                }
                "invalid" => {
                    // Verify unwrapping invalid ct fails with an error
                    let unwrap_result = kwp_unwrap(&ct, |b| cipher.decrypt_block(b));
                    assert!(
                        unwrap_result.is_err(),
                        "tcId {}: expected unwrap to fail, but succeeded with: {:?} ({})",
                        tc.tc_id,
                        unwrap_result.unwrap(),
                        tc.comment
                    );
                    invalid_tested += 1;
                }
                other => {
                    bail!(
                        "tcId {}: unexpected test result status '{}'",
                        tc.tc_id,
                        other
                    );
                }
            }
        }
    }

    assert_eq!(total_tested, file.number_of_tests);
    eprintln!(
        "Wycheproof AES-KWP passed: {} total tests ({} valid, {} invalid) across key sizes [128, 192, 256]",
        total_tested, valid_tested, invalid_tested
    );

    Ok(())
}
