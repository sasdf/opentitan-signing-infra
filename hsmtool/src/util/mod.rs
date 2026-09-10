// Copyright lowRISC contributors (OpenTitan project).
// Licensed under the Apache License, Version 2.0, see LICENSE for details.
// SPDX-License-Identifier: Apache-2.0

pub mod attribute;
pub mod ef;
pub mod escape;
pub mod helper;
pub mod key;
pub mod kwp;
pub mod secret;
pub mod signing;
pub mod wrap;

#[cfg(test)]
mod kwp_wycheproof_test;

/// The `testdata` function can be used in tests to reference testdata directories.
#[cfg(test)]
pub fn testdata(test: &str) -> std::path::PathBuf {
    let mut path: std::path::PathBuf = std::env::var_os("TESTDATA").unwrap().into();
    // TESTDATA points an arbitrary test, remove two levels to get the directory.
    path.pop();
    path.pop();
    path.push(test);
    path
}

/// The `wycheproof_testvector` function can be used in tests to reference Wycheproof test vectors.
#[cfg(test)]
pub fn wycheproof_testvector(filename: &str) -> std::path::PathBuf {
    use runfiles::{Runfiles, rlocation};
    let r = Runfiles::create().expect("Failed to create Runfiles instance");
    let path = std::path::PathBuf::from("wycheproof/testvectors_v1").join(filename);
    rlocation!(r, &path)
        .filter(|p| p.exists())
        .unwrap_or_else(|| panic!("Wycheproof test vector '{filename}' not found in runfiles"))
}
