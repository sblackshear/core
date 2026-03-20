pub mod error;
pub mod server;
pub mod store;
pub mod types;
pub mod webauthn;

pub use error::OwsAuthError;
pub use store::has_passkeys_for_wallet;
pub use types::{AuthMode, AuthResult};

/// Register a new passkey for a wallet. Opens the browser for the WebAuthn ceremony.
pub fn run_registration(wallet_id: &str, label: &str) -> Result<AuthResult, OwsAuthError> {
    server::run_server(AuthMode::Register, wallet_id, label)
}

/// Authenticate with a stored passkey for a wallet. Opens the browser for the WebAuthn ceremony.
pub fn run_authentication(wallet_id: &str) -> Result<AuthResult, OwsAuthError> {
    server::run_server(AuthMode::Authenticate, wallet_id, "")
}
