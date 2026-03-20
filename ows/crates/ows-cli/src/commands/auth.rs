use crate::{vault, CliError};
use ows_signer::CryptoEnvelope;

/// Register a new passkey for a wallet, switching it from passphrase to passkey auth.
pub fn setup(wallet_name: &str, label: &str) -> Result<(), CliError> {
    let label = if label.is_empty() {
        "default".to_string()
    } else {
        label.to_string()
    };

    let mut wallet = vault::load_wallet_by_name_or_id(wallet_name)?;

    if get_auth_method(&wallet) == "passkey" {
        return Err(CliError::InvalidArgs(
            "wallet already uses passkey authentication — use `ows auth status` to view".into(),
        ));
    }

    // Decrypt with current passphrase first
    let envelope: CryptoEnvelope = serde_json::from_value(wallet.crypto.clone())?;
    let secret = match ows_signer::decrypt(&envelope, "") {
        Ok(s) => s,
        Err(_) => {
            let passphrase = super::read_passphrase();
            ows_signer::decrypt(&envelope, &passphrase)?
        }
    };

    // Register passkey
    match ows_auth::run_registration(&wallet.id, &label) {
        Ok(ows_auth::AuthResult::Registered {
            credential_id,
            label,
        }) => {
            // Re-encrypt with empty passphrase (passkey is now the gate)
            let new_envelope = ows_signer::encrypt(secret.expose(), "")?;
            let crypto_json = serde_json::to_value(&new_envelope)?;

            wallet.crypto = crypto_json;
            wallet.metadata = serde_json::json!({ "auth_method": "passkey" });
            ows_lib::vault::save_encrypted_wallet(&wallet, None)?;

            eprintln!("Passkey registered for wallet '{}'", wallet.name);
            eprintln!("  Label: {label}");
            eprintln!("  Credential ID: {credential_id}");
            eprintln!();
            eprintln!("This wallet now requires passkey verification instead of a passphrase.");
            Ok(())
        }
        Ok(_) => {
            eprintln!("Registration completed.");
            Ok(())
        }
        Err(e) => Err(CliError::InvalidArgs(format!(
            "passkey registration failed: {e}"
        ))),
    }
}

/// Remove passkey from a wallet, switching it back to passphrase auth.
pub fn remove(wallet_name: &str, confirm: bool) -> Result<(), CliError> {
    if !confirm {
        return Err(CliError::InvalidArgs(
            "pass --confirm to remove the passkey".into(),
        ));
    }

    let mut wallet = vault::load_wallet_by_name_or_id(wallet_name)?;

    if get_auth_method(&wallet) != "passkey" {
        return Err(CliError::InvalidArgs(
            "wallet does not use passkey authentication".into(),
        ));
    }

    // Verify passkey first
    verify_passkey(&wallet.id)?;

    // Decrypt (empty passphrase since it's passkey-protected)
    let envelope: CryptoEnvelope = serde_json::from_value(wallet.crypto.clone())?;
    let secret = ows_signer::decrypt(&envelope, "")?;

    // Prompt for new passphrase
    eprintln!("Set a passphrase for this wallet (empty for none):");
    let passphrase = super::read_passphrase();

    // Re-encrypt with new passphrase
    let new_envelope = ows_signer::encrypt(secret.expose(), &passphrase)?;
    let crypto_json = serde_json::to_value(&new_envelope)?;

    wallet.crypto = crypto_json;
    wallet.metadata = serde_json::json!({ "auth_method": "passphrase" });
    ows_lib::vault::save_encrypted_wallet(&wallet, None)?;

    // Remove passkey credentials
    let mut store = ows_auth::store::load_or_create_store()
        .map_err(|e| CliError::InvalidArgs(format!("failed to load passkey store: {e}")))?;
    ows_auth::store::remove_wallet_passkeys(&mut store, &wallet.id)
        .map_err(|e| CliError::InvalidArgs(format!("failed to remove passkeys: {e}")))?;

    eprintln!(
        "Passkey removed. Wallet '{}' now uses passphrase authentication.",
        wallet.name
    );
    Ok(())
}

/// Show auth method and passkey info for a wallet.
pub fn status(wallet_name: &str) -> Result<(), CliError> {
    let wallet = vault::load_wallet_by_name_or_id(wallet_name)?;
    let method = get_auth_method(&wallet);

    eprintln!("Wallet: {} ({})", wallet.name, wallet.id);
    eprintln!("Auth:   {method}");

    if method == "passkey" {
        let store = ows_auth::store::load_store()
            .map_err(|e| CliError::InvalidArgs(format!("failed to load passkey store: {e}")))?;

        if let Some(s) = store {
            if let Some(entry) = ows_auth::store::get_wallet_entry(&s, &wallet.id) {
                for p in &entry.passkeys {
                    eprintln!(
                        "  - {} (ID: {}, created: {})",
                        p.label, p.credential_id, p.created_at
                    );
                }
            }
        }
    }
    Ok(())
}

/// Test passkey authentication for a wallet.
pub fn verify(wallet_name: &str) -> Result<(), CliError> {
    let wallet = vault::load_wallet_by_name_or_id(wallet_name)?;

    if get_auth_method(&wallet) != "passkey" {
        return Err(CliError::InvalidArgs(
            "wallet does not use passkey authentication".into(),
        ));
    }

    verify_passkey(&wallet.id)?;
    eprintln!(
        "Passkey verification successful for wallet '{}'",
        wallet.name
    );
    Ok(())
}

/// Internal: run passkey verification for a wallet. Hard-fails on error.
fn verify_passkey(wallet_id: &str) -> Result<(), CliError> {
    if !ows_auth::has_passkeys_for_wallet(wallet_id) {
        return Err(CliError::InvalidArgs(
            "wallet requires passkey but none are registered".into(),
        ));
    }

    match ows_auth::run_authentication(wallet_id) {
        Ok(ows_auth::AuthResult::Authenticated) => {
            eprintln!("Passkey verified.");
            Ok(())
        }
        Ok(_) => Ok(()),
        Err(e) => Err(CliError::InvalidArgs(format!(
            "passkey verification failed: {e}"
        ))),
    }
}

/// Check the auth method of a wallet from its metadata.
pub fn get_auth_method(wallet: &ows_core::EncryptedWallet) -> &str {
    wallet
        .metadata
        .get("auth_method")
        .and_then(|v| v.as_str())
        .unwrap_or("passphrase")
}

/// Run passkey verification if the wallet uses passkey auth.
/// Called from resolve_wallet_secret and wallet export.
/// Hard-fails if passkey is required but verification fails.
pub fn require_passkey_for_wallet(
    wallet: &ows_core::EncryptedWallet,
    skip_passkey: bool,
) -> Result<(), CliError> {
    if skip_passkey || get_auth_method(wallet) != "passkey" {
        return Ok(());
    }
    verify_passkey(&wallet.id)
}
