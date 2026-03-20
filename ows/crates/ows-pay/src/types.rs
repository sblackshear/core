use serde::{Deserialize, Serialize};

// ---------------------------------------------------------------------------
// x402 protocol types
// ---------------------------------------------------------------------------

/// A single payment option returned by an x402-enabled server in its 402 response.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct PaymentRequirements {
    /// Payment scheme – currently only "exact" is specified.
    pub scheme: String,
    /// CAIP-2 network identifier (e.g. "eip155:8453" for Base mainnet).
    pub network: String,
    /// Required payment amount in the token's smallest unit (e.g. "10000" = $0.01 USDC).
    #[serde(alias = "maxAmountRequired")]
    pub amount: String,
    /// ERC-20 token contract address (e.g. USDC).
    pub asset: String,
    /// Recipient address that should receive the payment.
    #[serde(alias = "payTo")]
    pub pay_to: String,
    /// Maximum seconds the server will wait for settlement.
    #[serde(default = "default_timeout")]
    pub max_timeout_seconds: u64,
    /// Optional extra metadata (token name, version for EIP-712 domain).
    #[serde(default)]
    pub extra: serde_json::Value,
    /// Optional human-readable description.
    #[serde(default)]
    pub description: Option<String>,
    /// Optional resource path.
    #[serde(default)]
    pub resource: Option<String>,
}

fn default_timeout() -> u64 {
    30
}

/// The full 402 response body from an x402-enabled server.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct X402Response {
    pub x402_version: Option<u32>,
    pub accepts: Vec<PaymentRequirements>,
}

/// The payload the client sends back after signing.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct PaymentPayload {
    pub x402_version: u32,
    pub scheme: String,
    pub network: String,
    pub payload: Eip3009Payload,
}

/// EIP-3009 `transferWithAuthorization` payload.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Eip3009Payload {
    pub signature: String,
    pub authorization: Eip3009Authorization,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Eip3009Authorization {
    pub from: String,
    pub to: String,
    pub value: String,
    pub valid_after: String,
    pub valid_before: String,
    pub nonce: String,
}

// ---------------------------------------------------------------------------
// Service discovery types
// ---------------------------------------------------------------------------

/// A discovered x402 service from the Bazaar.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct DiscoveredService {
    /// The payable endpoint URL.
    pub resource: String,
    /// Protocol type (e.g. "http").
    #[serde(default)]
    pub r#type: Option<String>,
    /// x402 version.
    #[serde(default)]
    pub x402_version: Option<u32>,
    /// Payment options.
    #[serde(default)]
    pub accepts: Vec<PaymentRequirements>,
    /// Optional metadata.
    #[serde(default)]
    pub metadata: Option<ServiceMetadata>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ServiceMetadata {
    pub description: Option<String>,
    #[serde(default)]
    pub input: Option<serde_json::Value>,
    #[serde(default)]
    pub output: Option<serde_json::Value>,
}

/// Paginated response from the Bazaar discovery API.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DiscoveryResponse {
    pub items: Vec<DiscoveredService>,
    #[serde(default)]
    pub pagination: Option<Pagination>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Pagination {
    pub limit: u64,
    pub offset: u64,
    pub total: u64,
}

// ---------------------------------------------------------------------------
// Result types
// ---------------------------------------------------------------------------

/// The result of a successful payment + request.
#[derive(Debug, Clone)]
pub struct PayResult {
    /// HTTP status of the paid response.
    pub status: u16,
    /// Response body.
    pub body: String,
    /// How much was paid (human-readable, e.g. "$0.01").
    pub amount_display: String,
    /// The protocol used ("x402" or "mpp").
    pub protocol: String,
    /// Network the payment was made on.
    pub network: String,
}
