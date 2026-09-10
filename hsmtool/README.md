[//]: # (Copyright lowRISC contributors \(OpenTitan project\).)
[//]: # (Licensed under the Apache License, Version 2.0, see LICENSE for details.)
[//]: # (SPDX-License-Identifier: Apache-2.0)

# OpenTitan Hardware Security Module Tool

*[Click here for the generated documentation of `hsmtool`.](https://opentitan.org/gen/rustdoc/hsmtool)*

The OpenTitan Hardware Security Module (HSM) tool can be used to generate and manage keys that will be installed into OpenTitan devices during manufacturing.

This tool is still a work-in-progress, but its requirements can be found [here](./doc/requirements.md).

HSMTool currently supports several different features, including:
* AES key generation, and importing & exporting.
* KDF key generation, and importing & exporting.
* ECDSA key generation, importing & exporting, and signing & verification.
* MLDSA key generation, importing & exporting, and signing & verification.
* RSA key generation, importing & exporting, signing & verification, and encryption & decryption.
* Elementary File (EF) export & import wrapped with hardware AES Key Wrap with Padding (KWP).
* SPHINCS+ (SPX) key generation, importing & exporting, and signing & verification.
* Commands for listing tokens, and for writing / updating / destroying objects in the HSM session.

You can find more information about using `hsmtool` from its command-line help menu:

```sh
bazelisk run //hsmtool:hsmtool -- --help
```

