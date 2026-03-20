use thiserror::Error;

#[derive(Debug, Error)]
pub enum OwsAuthError {
    #[error("WebAuthn error: {0}")]
    WebAuthn(#[from] webauthn_rs::prelude::WebauthnError),

    #[error("Server error: {0}")]
    Server(String),

    #[error("IO error: {0}")]
    Io(#[from] std::io::Error),

    #[error("JSON error: {0}")]
    Json(#[from] serde_json::Error),

    #[error("Timeout: passkey ceremony did not complete within {0} seconds")]
    Timeout(u64),

    #[error("No passkeys registered")]
    NoPasskeys,

    #[error("Credential not found: {0}")]
    CredentialNotFound(String),

    #[error("Browser failed to open: {0}")]
    BrowserOpen(String),

    #[error("Authentication cancelled")]
    Cancelled,
}
