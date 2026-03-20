use std::collections::BTreeMap;
use std::fs;
use std::path::{Path, PathBuf};

use chrono::Utc;
use webauthn_rs::prelude::Passkey;

use crate::error::OwsAuthError;
use crate::types::{PasskeyStore, StoredPasskey, WalletPasskeys};

/// Returns the auth directory path (~/.ows/auth/).
pub fn auth_dir() -> PathBuf {
    dirs_path().join("auth")
}

/// Returns the passkeys file path (~/.ows/auth/passkeys.json).
pub fn passkeys_path() -> PathBuf {
    auth_dir().join("passkeys.json")
}

fn dirs_path() -> PathBuf {
    dirs::home_dir()
        .expect("could not determine home directory")
        .join(".ows")
}

#[cfg(unix)]
fn set_dir_permissions(path: &Path) {
    use std::os::unix::fs::PermissionsExt;
    let perms = fs::Permissions::from_mode(0o700);
    if let Err(e) = fs::set_permissions(path, perms) {
        eprintln!(
            "warning: failed to set permissions on {}: {e}",
            path.display()
        );
    }
}

#[cfg(unix)]
fn set_file_permissions(path: &Path) {
    use std::os::unix::fs::PermissionsExt;
    let perms = fs::Permissions::from_mode(0o600);
    if let Err(e) = fs::set_permissions(path, perms) {
        eprintln!(
            "warning: failed to set permissions on {}: {e}",
            path.display()
        );
    }
}

#[cfg(not(unix))]
fn set_dir_permissions(_path: &Path) {}

#[cfg(not(unix))]
fn set_file_permissions(_path: &Path) {}

/// Load the passkey store from disk, or return None if it doesn't exist.
pub fn load_store() -> Result<Option<PasskeyStore>, OwsAuthError> {
    let path = passkeys_path();
    if !path.exists() {
        return Ok(None);
    }
    let contents = fs::read_to_string(&path)?;
    let store: PasskeyStore = serde_json::from_str(&contents)?;
    Ok(Some(store))
}

/// Save the passkey store to disk with strict permissions.
pub fn save_store(store: &PasskeyStore) -> Result<(), OwsAuthError> {
    let dir = auth_dir();
    fs::create_dir_all(&dir)?;
    set_dir_permissions(&dir);

    let path = passkeys_path();
    let json = serde_json::to_string_pretty(store)?;
    fs::write(&path, json)?;
    set_file_permissions(&path);
    Ok(())
}

/// Load existing store or create a new empty one.
pub fn load_or_create_store() -> Result<PasskeyStore, OwsAuthError> {
    match load_store()? {
        Some(store) => Ok(store),
        None => Ok(PasskeyStore {
            version: 2,
            wallets: BTreeMap::new(),
        }),
    }
}

/// Get or create the WalletPasskeys entry for a given wallet ID.
pub fn get_or_create_wallet_entry<'a>(
    store: &'a mut PasskeyStore,
    wallet_id: &str,
) -> &'a mut WalletPasskeys {
    store
        .wallets
        .entry(wallet_id.to_string())
        .or_insert_with(|| WalletPasskeys {
            user_id: uuid::Uuid::new_v4().to_string(),
            user_name: "ows-user".to_string(),
            passkeys: Vec::new(),
        })
}

/// Add a passkey to a wallet's entry and persist.
pub fn add_passkey(
    store: &mut PasskeyStore,
    wallet_id: &str,
    passkey: Passkey,
    label: &str,
) -> Result<String, OwsAuthError> {
    let credential_id = base64_url_encode(passkey.cred_id().as_ref());
    let stored = StoredPasskey {
        credential_id: credential_id.clone(),
        passkey,
        created_at: Utc::now(),
        label: label.to_string(),
    };
    let entry = get_or_create_wallet_entry(store, wallet_id);
    entry.passkeys.push(stored);
    save_store(store)?;
    Ok(credential_id)
}

/// Remove all passkeys for a wallet. Returns true if any were removed.
pub fn remove_wallet_passkeys(
    store: &mut PasskeyStore,
    wallet_id: &str,
) -> Result<bool, OwsAuthError> {
    let removed = store.wallets.remove(wallet_id).is_some();
    if removed {
        if store.wallets.is_empty() {
            let path = passkeys_path();
            if path.exists() {
                fs::remove_file(&path)?;
            }
        } else {
            save_store(store)?;
        }
    }
    Ok(removed)
}

/// Check whether a specific wallet has stored passkeys.
pub fn has_passkeys_for_wallet(wallet_id: &str) -> bool {
    match load_store() {
        Ok(Some(store)) => store
            .wallets
            .get(wallet_id)
            .is_some_and(|w| !w.passkeys.is_empty()),
        _ => false,
    }
}

/// Get all stored passkeys for a wallet as Passkey objects.
pub fn get_wallet_passkeys(store: &PasskeyStore, wallet_id: &str) -> Vec<Passkey> {
    store
        .wallets
        .get(wallet_id)
        .map(|w| w.passkeys.iter().map(|s| s.passkey.clone()).collect())
        .unwrap_or_default()
}

/// Get the WalletPasskeys entry for a wallet, if it exists.
pub fn get_wallet_entry<'a>(
    store: &'a PasskeyStore,
    wallet_id: &str,
) -> Option<&'a WalletPasskeys> {
    store.wallets.get(wallet_id)
}

fn base64_url_encode(bytes: &[u8]) -> String {
    use base64::engine::general_purpose::URL_SAFE_NO_PAD;
    use base64::Engine;
    URL_SAFE_NO_PAD.encode(bytes)
}
