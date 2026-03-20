use std::future::IntoFuture;
use std::sync::Arc;

use axum::extract::State;
use axum::http::StatusCode;
use axum::http::{HeaderValue, Method};
use axum::response::{Html, Json};
use axum::routing::{get, post};
use axum::Router;
use tokio::net::TcpListener;
use tokio::sync::{oneshot, Mutex};
use tower_http::cors::CorsLayer;
use webauthn_rs::prelude::*;

use crate::error::OwsAuthError;
use crate::types::{AuthMode, AuthResult, PasskeyStore, StatusResponse};
use crate::{store, webauthn as wa};

const AUTH_HTML: &str = include_str!("../assets/auth.html");

/// Shared state for the axum server.
struct AppState {
    mode: AuthMode,
    label: String,
    wallet_id: String,
    webauthn: webauthn_rs::Webauthn,
    passkey_store: Mutex<PasskeyStore>,
    reg_state: Mutex<Option<PasskeyRegistration>>,
    auth_state: Mutex<Option<PasskeyAuthentication>>,
    completion_tx: Mutex<Option<oneshot::Sender<AuthResult>>>,
}

/// Start the local auth server, open the browser, and wait for the ceremony to complete.
pub fn run_server(
    mode: AuthMode,
    wallet_id: &str,
    label: &str,
) -> Result<AuthResult, OwsAuthError> {
    let rt = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .map_err(|e| OwsAuthError::Server(format!("failed to create tokio runtime: {e}")))?;

    rt.block_on(async { run_server_async(mode, wallet_id, label).await })
}

async fn run_server_async(
    mode: AuthMode,
    wallet_id: &str,
    label: &str,
) -> Result<AuthResult, OwsAuthError> {
    let listener = TcpListener::bind("127.0.0.1:0").await?;
    let addr = listener.local_addr()?;
    let port = addr.port();

    let webauthn = wa::build_webauthn(port)?;
    let passkey_store = store::load_or_create_store()?;

    let (tx, rx) = oneshot::channel();

    let state = Arc::new(AppState {
        mode,
        label: label.to_string(),
        wallet_id: wallet_id.to_string(),
        webauthn,
        passkey_store: Mutex::new(passkey_store),
        reg_state: Mutex::new(None),
        auth_state: Mutex::new(None),
        completion_tx: Mutex::new(Some(tx)),
    });

    let app = Router::new()
        .route("/", get(serve_page))
        .route("/api/status", get(get_status))
        .route("/api/register/begin", post(register_begin))
        .route("/api/register/complete", post(register_complete))
        .route("/api/authenticate/begin", post(authenticate_begin))
        .route("/api/authenticate/complete", post(authenticate_complete))
        .layer(
            CorsLayer::new()
                .allow_origin([
                    format!("http://127.0.0.1:{port}")
                        .parse::<HeaderValue>()
                        .unwrap(),
                    format!("http://localhost:{port}")
                        .parse::<HeaderValue>()
                        .unwrap(),
                ])
                .allow_methods([Method::GET, Method::POST])
                .allow_headers([axum::http::header::CONTENT_TYPE]),
        )
        .with_state(state);

    // Try to open browser, but don't fail if it doesn't work
    let url = format!("http://localhost:{port}");
    if let Err(e) = open_browser(port) {
        eprintln!("warning: could not open browser: {e}");
        eprintln!("Open this URL manually: {url}");
    }

    eprintln!(
        "Waiting for passkey {} in browser...",
        match mode {
            AuthMode::Register => "registration",
            AuthMode::Authenticate => "verification",
        }
    );

    let server = axum::serve(listener, app);

    tokio::select! {
        result = rx => {
            match result {
                Ok(auth_result) => Ok(auth_result),
                Err(_) => Err(OwsAuthError::Cancelled),
            }
        }
        _ = tokio::time::sleep(std::time::Duration::from_secs(120)) => {
            Err(OwsAuthError::Timeout(120))
        }
        server_result = server.into_future() => {
            let _: Result<(), _> = server_result.map_err(|e| OwsAuthError::Server(format!("server error: {e}")));
            Err(OwsAuthError::Cancelled)
        }
    }
}

async fn serve_page() -> Html<&'static str> {
    Html(AUTH_HTML)
}

async fn get_status(State(state): State<Arc<AppState>>) -> Json<StatusResponse> {
    Json(StatusResponse { mode: state.mode })
}

async fn register_begin(
    State(state): State<Arc<AppState>>,
) -> Result<Json<CreationChallengeResponse>, (StatusCode, String)> {
    let ps = state.passkey_store.lock().await;
    let existing = store::get_wallet_passkeys(&ps, &state.wallet_id);
    let entry = store::get_wallet_entry(&ps, &state.wallet_id);

    let user_id = entry
        .map(|e| e.user_id.as_str())
        .unwrap_or("00000000-0000-0000-0000-000000000000");
    let user_name = entry.map(|e| e.user_name.as_str()).unwrap_or("ows-user");

    let (ccr, reg_state) = wa::begin_registration(&state.webauthn, user_id, user_name, &existing)
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;

    drop(ps);
    *state.reg_state.lock().await = Some(reg_state);

    Ok(Json(ccr))
}

async fn register_complete(
    State(state): State<Arc<AppState>>,
    Json(reg): Json<RegisterPublicKeyCredential>,
) -> Result<Json<serde_json::Value>, (StatusCode, String)> {
    let reg_state = state.reg_state.lock().await.take().ok_or((
        StatusCode::BAD_REQUEST,
        "no registration in progress".to_string(),
    ))?;

    let passkey = wa::complete_registration(&state.webauthn, &reg, &reg_state)
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;

    let mut ps = state.passkey_store.lock().await;
    let credential_id = store::add_passkey(&mut ps, &state.wallet_id, passkey, &state.label)
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;

    if let Some(tx) = state.completion_tx.lock().await.take() {
        let _ = tx.send(AuthResult::Registered {
            credential_id,
            label: state.label.clone(),
        });
    }

    Ok(Json(serde_json::json!({ "status": "ok" })))
}

async fn authenticate_begin(
    State(state): State<Arc<AppState>>,
) -> Result<Json<RequestChallengeResponse>, (StatusCode, String)> {
    let ps = state.passkey_store.lock().await;
    let passkeys = store::get_wallet_passkeys(&ps, &state.wallet_id);

    let (rcr, auth_state) = wa::begin_authentication(&state.webauthn, &passkeys)
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;

    drop(ps);
    *state.auth_state.lock().await = Some(auth_state);

    Ok(Json(rcr))
}

async fn authenticate_complete(
    State(state): State<Arc<AppState>>,
    Json(auth): Json<PublicKeyCredential>,
) -> Result<Json<serde_json::Value>, (StatusCode, String)> {
    let auth_state = state.auth_state.lock().await.take().ok_or((
        StatusCode::BAD_REQUEST,
        "no authentication in progress".to_string(),
    ))?;

    let mut ps = state.passkey_store.lock().await;
    wa::complete_authentication(
        &state.webauthn,
        &auth,
        &auth_state,
        &mut ps,
        &state.wallet_id,
    )
    .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;

    if let Some(tx) = state.completion_tx.lock().await.take() {
        let _ = tx.send(AuthResult::Authenticated);
    }

    Ok(Json(serde_json::json!({ "status": "ok" })))
}

fn open_browser(port: u16) -> Result<(), OwsAuthError> {
    let url = format!("http://localhost:{port}");

    #[cfg(target_os = "macos")]
    let result = std::process::Command::new("open").arg(&url).status();

    #[cfg(target_os = "linux")]
    let result = std::process::Command::new("xdg-open").arg(&url).status();

    #[cfg(target_os = "windows")]
    let result = std::process::Command::new("cmd")
        .args(["/C", "start", &url])
        .status();

    #[cfg(not(any(target_os = "macos", target_os = "linux", target_os = "windows")))]
    let result: Result<std::process::ExitStatus, std::io::Error> = Err(std::io::Error::new(
        std::io::ErrorKind::Unsupported,
        "unsupported platform",
    ));

    match result {
        Ok(status) if status.success() => Ok(()),
        Ok(_) => Err(OwsAuthError::BrowserOpen(format!(
            "browser exited with error — open {url} manually"
        ))),
        Err(e) => Err(OwsAuthError::BrowserOpen(format!(
            "{e} — open {url} manually"
        ))),
    }
}
