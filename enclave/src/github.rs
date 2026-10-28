//! GitHub sign-in: trade an authorization code for the account it belongs to.

use anyhow::{Context, Result};
use serde::Deserialize;

use crate::failure::Failure;
use crate::protocol::GithubGrant;

const TOKEN_URL: &str = "https://github.com/login/oauth/access_token";
const USER_URL: &str = "https://api.github.com/user";

#[derive(Debug, Deserialize)]
pub struct GithubUser {
    pub id: u64,
    pub login: String,
    pub name: Option<String>,
}

#[derive(Deserialize)]
struct AccessToken {
    access_token: String,
}

/// Redeem `grant.code` with the client's PKCE `code_verifier` and return the
/// account GitHub says it belongs to.
///
/// GitHub does not document the shape of its error bodies, so none is parsed:
/// anything but a token is a rejection. The code, secret, verifier and access
/// token are never logged.
pub async fn user_for_code(
    http: &reqwest::Client,
    grant: &GithubGrant,
    code_verifier: &str,
) -> Result<GithubUser> {
    let response = http
        .post(TOKEN_URL)
        .header("Accept", "application/json")
        .form(&[
            ("client_id", grant.client_id.as_str()),
            ("client_secret", grant.client_secret.as_str()),
            ("code", grant.code.as_str()),
            ("redirect_uri", grant.redirect_uri.as_str()),
            ("code_verifier", code_verifier),
        ])
        .send()
        .await
        .map_err(|_| anyhow::anyhow!("github.com request failed"))
        .context(Failure::GithubUnreachable)?;
    let token: AccessToken = response
        .error_for_status()
        .map_err(|_| anyhow::anyhow!("github.com refused the code"))
        .context(Failure::GithubRejected)?
        .json()
        .await
        .map_err(|_| anyhow::anyhow!("github.com returned no access token"))
        .context(Failure::GithubRejected)?;

    let response = http
        .get(USER_URL)
        .bearer_auth(&token.access_token)
        .header("Accept", "application/vnd.github+json")
        .header("User-Agent", "cavos-enclave")
        .header("X-GitHub-Api-Version", "2022-11-28")
        .send()
        .await
        .map_err(|_| anyhow::anyhow!("api.github.com request failed"))
        .context(Failure::GithubUnreachable)?;
    response
        .error_for_status()
        .map_err(|_| anyhow::anyhow!("api.github.com refused the access token"))
        .context(Failure::GithubRejected)?
        .json()
        .await
        .map_err(|_| anyhow::anyhow!("api.github.com returned no user"))
        .context(Failure::GithubRejected)
}
