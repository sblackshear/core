use std::collections::BTreeMap;

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use webauthn_rs::prelude::Passkey;

/// Operating mode for the local auth server.
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
pub enum AuthMode {
    Register,
    Authenticate,
}

/// Result of a completed passkey ceremony.
#[derive(Debug)]
pub enum AuthResult {
    Registered {
        credential_id: String,
        label: String,
    },
    Authenticated,
}

/// On-disk format for stored passkeys, indexed by wallet ID.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PasskeyStore {
    pub version: u32,
    pub wallets: BTreeMap<String, WalletPasskeys>,
}

/// Passkey credentials associated with a single wallet.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WalletPasskeys {
    pub user_id: String,
    pub user_name: String,
    pub passkeys: Vec<StoredPasskey>,
}

/// A single stored passkey credential.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StoredPasskey {
    pub credential_id: String,
    pub passkey: Passkey,
    pub created_at: DateTime<Utc>,
    pub label: String,
}

/// Status response sent to the browser page.
#[derive(Serialize)]
pub struct StatusResponse {
    pub mode: AuthMode,
}
