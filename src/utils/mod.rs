/// crypto_utils contains cryptographic utilities for the project
/// including AES and Secp256k1 helpers
pub mod crypto_utils;

/// response_utils contains utilities for handling HTTP responses
pub mod response_utils;

#[cfg(test)]
pub mod test_utils;

/// tdx_evidence_helpers contains helpers for dealing with Vec<u8> evidence
/// and converting it to a human readable format. It is mainly used for debugging
/// the logic is mostly copied and pasted from https://github.com/confidential-containers/trustee/tree/main/deps/verifier/src/tdx
#[allow(dead_code)]
pub mod tdx_evidence_helpers;
