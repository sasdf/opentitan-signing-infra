// Copyright lowRISC contributors (OpenTitan project).
// Licensed under the Apache License, Version 2.0, see LICENSE for details.
// SPDX-License-Identifier: Apache-2.0

use anyhow::{Result, bail, ensure};

/// Fixed 32-bit prefix of the Integrity Check Value (ICV) defined in RFC 5649 Section 3.
const KWP_ICV_MAGIC: [u8; 4] = [0xA6, 0x59, 0x59, 0xA6];

/// Wraps a plaintext payload using RFC 5649 Key Wrap with Padding (KWP).
///
/// Accepts a single-block encryption callback `encrypt_block: &[u8; 16] -> Result<[u8; 16]>`.
pub fn kwp_wrap<F>(plaintext: &[u8], mut encrypt_block: F) -> Result<Vec<u8>>
where
    F: FnMut(&[u8; 16]) -> Result<[u8; 16]>,
{
    let mli = plaintext.len();
    ensure!(mli > 0, "Plaintext for KWP wrap must not be empty");
    ensure!(
        mli <= u32::MAX as usize,
        "Plaintext length exceeds RFC 5649 maximum (2^32 - 1)"
    );

    // Form the 64-bit ICV: 0xA65959A6 || [MLI]_32
    let mut a = [0u8; 8];
    a[0..4].copy_from_slice(&KWP_ICV_MAGIC);
    a[4..8].copy_from_slice(&(mli as u32).to_be_bytes());

    // Pad plaintext with zeros to an 8-byte boundary
    let pad_len = (8 - (mli % 8)) % 8;
    let mut padded = Vec::with_capacity(mli + pad_len);
    padded.extend_from_slice(plaintext);
    padded.resize(mli + pad_len, 0u8);

    let n = padded.len() / 8;

    if n == 1 {
        // Single semi-block case (MLI between 1 and 8 octets)
        let mut b = [0u8; 16];
        b[0..8].copy_from_slice(&a);
        b[8..16].copy_from_slice(&padded[0..8]);
        let c = encrypt_block(&b)?;
        return Ok(c.to_vec());
    }

    // Multi semi-block case (n > 1)
    // Initialize R[1..n] as 8-byte chunks
    let mut r: Vec<[u8; 8]> = padded
        .chunks_exact(8)
        .map(|chunk| {
            let mut arr = [0u8; 8];
            arr.copy_from_slice(chunk);
            arr
        })
        .collect();

    for j in 0..6 {
        for i in 1..=n {
            let t = (n * j + i) as u64;

            // Form 16-byte block: A || R[i]
            let mut b_in = [0u8; 16];
            b_in[0..8].copy_from_slice(&a);
            b_in[8..16].copy_from_slice(&r[i - 1]);

            let b_out = encrypt_block(&b_in)?;

            // A = MSB_64(B) ^ [t]_64
            let mut msb = [0u8; 8];
            msb.copy_from_slice(&b_out[0..8]);
            let msb_val = u64::from_be_bytes(msb);
            a = (msb_val ^ t).to_be_bytes();

            // R[i] = LSB_64(B)
            r[i - 1].copy_from_slice(&b_out[8..16]);
        }
    }

    // Output: A || R[1] || ... || R[n]
    let mut ciphertext = Vec::with_capacity(8 + n * 8);
    ciphertext.extend_from_slice(&a);
    for chunk in &r {
        ciphertext.extend_from_slice(chunk);
    }

    Ok(ciphertext)
}

/// Unwraps a ciphertext payload using RFC 5649 Key Wrap with Padding (KWP).
///
/// Accepts a single-block decryption callback `decrypt_block: &[u8; 16] -> Result<[u8; 16]>`.
/// Returns an error if ciphertext length is invalid, ICV magic check fails, MLI is out
/// of range, or any padding octet is non-zero.
pub fn kwp_unwrap<F>(ciphertext: &[u8], mut decrypt_block: F) -> Result<Vec<u8>>
where
    F: FnMut(&[u8; 16]) -> Result<[u8; 16]>,
{
    let ct_len = ciphertext.len();
    ensure!(
        ct_len >= 16,
        "KWP ciphertext must be at least 16 bytes, got {}",
        ct_len
    );
    ensure!(
        ct_len.is_multiple_of(8),
        "KWP ciphertext length must be a multiple of 8, got {}",
        ct_len
    );

    let n = (ct_len / 8) - 1;

    let (a, padded) = if n == 1 {
        // Single semi-block case
        let mut b_in = [0u8; 16];
        b_in.copy_from_slice(&ciphertext[0..16]);
        let b_out = decrypt_block(&b_in)?;

        let mut a = [0u8; 8];
        a.copy_from_slice(&b_out[0..8]);
        let mut p_prime = [0u8; 8];
        p_prime.copy_from_slice(&b_out[8..16]);
        (a, p_prime.to_vec())
    } else {
        // Multi semi-block case (n > 1)
        let mut a = [0u8; 8];
        a.copy_from_slice(&ciphertext[0..8]);

        let mut r: Vec<[u8; 8]> = ciphertext[8..]
            .chunks_exact(8)
            .map(|chunk| {
                let mut arr = [0u8; 8];
                arr.copy_from_slice(chunk);
                arr
            })
            .collect();

        for j in (0..6).rev() {
            for i in (1..=n).rev() {
                let t = (n * j + i) as u64;

                // Form MSB_64 = A ^ [t]_64
                let a_val = u64::from_be_bytes(a);
                let msb = (a_val ^ t).to_be_bytes();

                // Form 16-byte block: (A ^ [t]_64) || R[i]
                let mut b_in = [0u8; 16];
                b_in[0..8].copy_from_slice(&msb);
                b_in[8..16].copy_from_slice(&r[i - 1]);

                let b_out = decrypt_block(&b_in)?;

                // A = MSB_64(B), R[i] = LSB_64(B)
                a.copy_from_slice(&b_out[0..8]);
                r[i - 1].copy_from_slice(&b_out[8..16]);
            }
        }

        let mut padded = Vec::with_capacity(n * 8);
        for chunk in &r {
            padded.extend_from_slice(chunk);
        }
        (a, padded)
    };

    // Integrity check 1: ICV magic (0xA65959A6)
    if a[0..4] != KWP_ICV_MAGIC {
        bail!("KWP authentication failed: ICV magic mismatch");
    }

    // Integrity check 2: MLI range verification: 8*(n-1) < MLI <= 8*n
    let mut mli_bytes = [0u8; 4];
    mli_bytes.copy_from_slice(&a[4..8]);
    let mli = u32::from_be_bytes(mli_bytes) as usize;

    let min_mli = 8 * (n - 1) + 1;
    let max_mli = 8 * n;
    if mli < min_mli || mli > max_mli {
        bail!(
            "KWP authentication failed: MLI ({}) out of valid range [{}..{}]",
            mli,
            min_mli,
            max_mli
        );
    }

    // Integrity check 3: Padding octets must all be strictly zero
    for (idx, &byte) in padded[mli..].iter().enumerate() {
        if byte != 0 {
            bail!(
                "KWP authentication failed: non-zero padding octet at offset {}",
                mli + idx
            );
        }
    }

    Ok(padded[..mli].to_vec())
}
