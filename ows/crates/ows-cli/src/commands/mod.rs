#[cfg(feature = "passkey")]
pub mod auth;
pub mod config;
pub mod derive;
pub mod generate;
pub mod info;
pub mod send_transaction;
pub mod sign_message;
pub mod sign_transaction;
pub mod uninstall;
pub mod update;
pub mod wallet;

use crate::{vault, CliError};
use ows_core::KeyType;
use ows_signer::process_hardening::clear_env_var;
use ows_signer::{CryptoEnvelope, SecretBytes};
use std::io::{self, BufRead, IsTerminal, Write};
use zeroize::{Zeroize, Zeroizing};

/// Read mnemonic from OWS_MNEMONIC env var (or LWS_MNEMONIC fallback) or stdin.
pub fn read_mnemonic() -> Result<Zeroizing<String>, CliError> {
    if let Some(value) = clear_env_var("OWS_MNEMONIC").or_else(|| clear_env_var("LWS_MNEMONIC")) {
        let trimmed = value.trim().to_string();
        if !trimmed.is_empty() {
            return Ok(Zeroizing::new(trimmed));
        }
    }

    let stdin = io::stdin();
    if stdin.is_terminal() {
        eprint!("Enter mnemonic: ");
        io::stderr().flush().ok();
    }

    let mut line = String::new();
    stdin.lock().read_line(&mut line)?;
    let trimmed = line.trim().to_string();

    if trimmed.is_empty() {
        return Err(CliError::InvalidArgs(
            "no mnemonic provided (set OWS_MNEMONIC or pipe via stdin)".into(),
        ));
    }

    Ok(Zeroizing::new(trimmed))
}

/// Read a hex-encoded private key from OWS_PRIVATE_KEY env var (or LWS_PRIVATE_KEY fallback) or stdin.
pub fn read_private_key() -> Result<Zeroizing<String>, CliError> {
    if let Some(value) =
        clear_env_var("OWS_PRIVATE_KEY").or_else(|| clear_env_var("LWS_PRIVATE_KEY"))
    {
        let trimmed = value.trim().to_string();
        if !trimmed.is_empty() {
            return Ok(Zeroizing::new(trimmed));
        }
    }

    let stdin = io::stdin();
    if stdin.is_terminal() {
        eprint!("Enter private key (hex): ");
        io::stderr().flush().ok();
    }

    let mut line = String::new();
    stdin.lock().read_line(&mut line)?;
    let trimmed = line.trim().to_string();

    if trimmed.is_empty() {
        return Err(CliError::InvalidArgs(
            "no private key provided (set OWS_PRIVATE_KEY or pipe via stdin)".into(),
        ));
    }

    Ok(Zeroizing::new(trimmed))
}

/// Resolved wallet secret — either a mnemonic phrase or a key pair (JSON).
pub enum WalletSecret {
    Mnemonic(Zeroizing<String>),
    /// JSON key pair: `{"secp256k1":"hex","ed25519":"hex"}`
    PrivateKeys(SecretBytes),
}

/// Read a passphrase from OWS_PASSPHRASE env var (or LWS_PASSPHRASE fallback) or prompt interactively.
pub fn read_passphrase() -> Zeroizing<String> {
    if let Some(value) = clear_env_var("OWS_PASSPHRASE").or_else(|| clear_env_var("LWS_PASSPHRASE"))
    {
        return Zeroizing::new(value);
    }
    let stdin = io::stdin();
    if stdin.is_terminal() {
        eprint!("Passphrase (empty for none): ");
        io::stderr().flush().ok();
        let mut line = String::new();
        stdin.lock().read_line(&mut line).unwrap_or(0);
        Zeroizing::new(line.trim().to_string())
    } else {
        Zeroizing::new(String::new())
    }
}

/// Look up a wallet by name or ID, decrypt it, and return the secret.
/// If the wallet uses passkey auth, runs passkey verification first (unless skip_passkey is true).
pub fn resolve_wallet_secret(
    wallet_name: &str,
    skip_passkey: bool,
) -> Result<WalletSecret, CliError> {
    let wallet = vault::load_wallet_by_name_or_id(wallet_name)?;
    let envelope: CryptoEnvelope = serde_json::from_value(wallet.crypto.clone())?;

    #[cfg(feature = "passkey")]
    let is_passkey = auth::get_auth_method(&wallet) == "passkey";
    #[cfg(not(feature = "passkey"))]
    let is_passkey = {
        let _ = skip_passkey;
        false
    };

    if is_passkey {
        #[cfg(feature = "passkey")]
        auth::require_passkey_for_wallet(&wallet, skip_passkey)?;

        // Passkey wallets are encrypted with empty passphrase
        let secret = ows_signer::decrypt(&envelope, "")?;
        return to_wallet_secret(secret, &wallet);
    }

    // Passphrase wallet: try empty passphrase first, then prompt
    let secret = match ows_signer::decrypt(&envelope, "") {
        Ok(s) => s,
        Err(_) => {
            let passphrase = read_passphrase();
            ows_signer::decrypt(&envelope, &passphrase)?
        }
    };

    to_wallet_secret(secret, &wallet)
}

fn to_wallet_secret(
    secret: SecretBytes,
    wallet: &ows_core::EncryptedWallet,
) -> Result<WalletSecret, CliError> {
    match wallet.key_type {
        KeyType::Mnemonic => {
            let phrase =
                Zeroizing::new(String::from_utf8(secret.expose().to_vec()).map_err(|_| {
                    CliError::InvalidArgs("wallet contains invalid mnemonic".into())
                })?);
            Ok(WalletSecret::Mnemonic(phrase))
        }
        KeyType::PrivateKey => Ok(WalletSecret::PrivateKeys(secret)),
    }
}

/// Extract a private key for a specific curve from a JSON key pair.
fn extract_key_for_curve(
    json_bytes: &[u8],
    curve: ows_signer::Curve,
) -> Result<SecretBytes, CliError> {
    let s = String::from_utf8(json_bytes.to_vec())
        .map_err(|_| CliError::InvalidArgs("invalid key data".into()))?;
    let obj: serde_json::Value = serde_json::from_str(&s)?;
    let field = match curve {
        ows_signer::Curve::Secp256k1 => "secp256k1",
        ows_signer::Curve::Ed25519 => "ed25519",
    };
    let hex_key = obj[field]
        .as_str()
        .ok_or_else(|| CliError::InvalidArgs(format!("missing {field} key in wallet")))?;
    let bytes = hex::decode(hex_key)
        .map_err(|e| CliError::InvalidArgs(format!("invalid {field} hex: {e}")))?;
    Ok(SecretBytes::from_slice(&bytes))
}

/// Resolve a wallet secret into the private key bytes for a specific chain.
pub fn resolve_signing_key(
    wallet_name: &str,
    chain_type: ows_core::ChainType,
    index: u32,
    skip_passkey: bool,
) -> Result<SecretBytes, CliError> {
    let wallet_secret = resolve_wallet_secret(wallet_name, skip_passkey)?;
    let signer = ows_signer::signer_for_chain(chain_type);

    match wallet_secret {
        WalletSecret::Mnemonic(mut phrase) => {
            let mnemonic = ows_signer::Mnemonic::from_phrase(&phrase)?;
            phrase.zeroize();
            let path = signer.default_derivation_path(index);
            let curve = signer.curve();
            Ok(ows_signer::HdDeriver::derive_from_mnemonic_cached(
                &mnemonic, "", &path, curve,
            )?)
        }
        WalletSecret::PrivateKeys(secret) => extract_key_for_curve(secret.expose(), signer.curve()),
    }
}
