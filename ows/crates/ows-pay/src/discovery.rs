use crate::error::PayError;
use crate::types::{DiscoveredService, DiscoveryResponse};

/// Coinbase CDP facilitator discovery endpoint.
const CDP_DISCOVERY_URL: &str =
    "https://api.cdp.coinbase.com/platform/v2/x402/discovery/resources";

/// Fetch the x402 service directory from the Bazaar.
pub async fn discover_services(
    limit: Option<u64>,
    offset: Option<u64>,
) -> Result<Vec<DiscoveredService>, PayError> {
    let client = reqwest::Client::new();
    let limit = limit.unwrap_or(100);
    let offset = offset.unwrap_or(0);

    let resp = client
        .get(CDP_DISCOVERY_URL)
        .query(&[
            ("limit", limit.to_string()),
            ("offset", offset.to_string()),
        ])
        .send()
        .await
        .map_err(|e| PayError::Http(format!("discovery request failed: {e}")))?;

    if !resp.status().is_success() {
        return Err(PayError::Http(format!(
            "discovery returned {}",
            resp.status()
        )));
    }

    let body: DiscoveryResponse = resp
        .json()
        .await
        .map_err(|e| PayError::Protocol(format!("failed to parse discovery response: {e}")))?;

    Ok(body.items)
}

/// Search discovered services by keyword (matches against URL and description).
pub async fn search_services(query: &str) -> Result<Vec<DiscoveredService>, PayError> {
    let all = discover_services(Some(100), None).await?;
    let query_lower = query.to_lowercase();

    Ok(all
        .into_iter()
        .filter(|s| {
            let url_match = s.resource.to_lowercase().contains(&query_lower);
            let desc_match = s
                .metadata
                .as_ref()
                .and_then(|m| m.description.as_ref())
                .map(|d| d.to_lowercase().contains(&query_lower))
                .unwrap_or(false);
            url_match || desc_match
        })
        .collect())
}

/// Format a token amount for human display.
/// USDC has 6 decimals, so "10000" = "$0.01".
pub fn format_amount(amount_str: &str, decimals: u8) -> String {
    let amount: u128 = amount_str.parse().unwrap_or(0);
    let divisor = 10u128.pow(decimals as u32);
    let whole = amount / divisor;
    let frac = amount % divisor;
    format!("${whole}.{frac:0>width$}", width = decimals as usize)
}
