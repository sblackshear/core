use url::Url;
use webauthn_rs::prelude::*;
use webauthn_rs::WebauthnBuilder;

use crate::error::OwsAuthError;
use crate::store;
use crate::types::PasskeyStore;

/// Create a Webauthn instance for the given localhost port.
pub fn build_webauthn(port: u16) -> Result<webauthn_rs::Webauthn, OwsAuthError> {
    let rp_id = "localhost";
    let rp_origin = Url::parse(&format!("http://localhost:{port}"))
        .map_err(|e| OwsAuthError::Server(format!("invalid origin URL: {e}")))?;

    let builder = WebauthnBuilder::new(rp_id, &rp_origin)
        .map_err(|e| OwsAuthError::Server(format!("WebauthnBuilder error: {e}")))?;

    builder
        .build()
        .map_err(|e| OwsAuthError::Server(format!("Webauthn build error: {e}")))
}

/// Begin a registration ceremony.
pub fn begin_registration(
    webauthn: &webauthn_rs::Webauthn,
    user_id: &str,
    user_name: &str,
    existing_credentials: &[Passkey],
) -> Result<(CreationChallengeResponse, PasskeyRegistration), OwsAuthError> {
    let user_unique_id = uuid::Uuid::parse_str(user_id).unwrap_or_else(|_| uuid::Uuid::new_v4());

    let exclude: Vec<CredentialID> = existing_credentials
        .iter()
        .map(|pk| pk.cred_id().clone())
        .collect();

    let (ccr, reg_state) =
        webauthn.start_passkey_registration(user_unique_id, user_name, user_name, Some(exclude))?;

    Ok((ccr, reg_state))
}

/// Complete a registration ceremony. Returns the new Passkey.
pub fn complete_registration(
    webauthn: &webauthn_rs::Webauthn,
    reg: &RegisterPublicKeyCredential,
    state: &PasskeyRegistration,
) -> Result<Passkey, OwsAuthError> {
    let passkey = webauthn.finish_passkey_registration(reg, state)?;
    Ok(passkey)
}

/// Begin an authentication ceremony.
pub fn begin_authentication(
    webauthn: &webauthn_rs::Webauthn,
    passkeys: &[Passkey],
) -> Result<(RequestChallengeResponse, PasskeyAuthentication), OwsAuthError> {
    if passkeys.is_empty() {
        return Err(OwsAuthError::NoPasskeys);
    }
    let (rcr, auth_state) = webauthn.start_passkey_authentication(passkeys)?;
    Ok((rcr, auth_state))
}

/// Complete an authentication ceremony. Updates the credential if needed.
pub fn complete_authentication(
    webauthn: &webauthn_rs::Webauthn,
    auth: &PublicKeyCredential,
    state: &PasskeyAuthentication,
    store: &mut PasskeyStore,
    wallet_id: &str,
) -> Result<(), OwsAuthError> {
    let result = webauthn.finish_passkey_authentication(auth, state)?;

    // Update the stored credential counter if it changed
    if let Some(wallet_entry) = store.wallets.get_mut(wallet_id) {
        for stored in &mut wallet_entry.passkeys {
            if stored.passkey.cred_id() == result.cred_id() {
                stored.passkey.update_credential(&result);
                break;
            }
        }
    }
    store::save_store(store)?;

    Ok(())
}
