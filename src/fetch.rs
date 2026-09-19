//! The only module that touches the network. Everything it produces is a
//! plain `Headers` value, so the grading rules never see an HTTP type and
//! stay testable without a socket.

use std::time::Duration;

use anyhow::{Context, Result};

use crate::headers::Headers;

pub const USER_AGENT: &str = concat!("headersec/", env!("CARGO_PKG_VERSION"));

#[derive(Debug, Clone)]
pub struct Fetched {
    /// The URL actually graded — after redirects, which is the whole point:
    /// grading the headers on a 301 rather than the page it points at is
    /// the classic way to get a wrong answer for an `http://` input.
    pub final_url: String,
    pub status: u16,
    pub https: bool,
    pub headers: Headers,
    /// Populated when the final URL differs from the requested one.
    pub redirected_from: Option<String>,
}

/// Adds a scheme if the user typed a bare hostname. `https` first, because
/// that's what anyone checking security headers means.
pub fn normalize_url(input: &str) -> String {
    let t = input.trim();
    if t.starts_with("http://") || t.starts_with("https://") {
        t.to_string()
    } else {
        format!("https://{t}")
    }
}

/// Issues a real GET and returns the response headers.
///
/// GET rather than HEAD on purpose: a fair number of servers, CDNs and
/// frameworks attach security headers only on the HTML response path and
/// answer HEAD from a different, barer code path — grading that would
/// report headers no browser ever sees.
pub fn fetch(url: &str, timeout: Duration, follow_redirects: bool) -> Result<Fetched> {
    let requested = normalize_url(url);
    // Parse up front so `https://example.com` and the `https://example.com/`
    // the client actually requests compare equal — otherwise every bare
    // hostname would be reported as having "followed a redirect" when the
    // only thing that changed was URL normalisation.
    let requested = reqwest::Url::parse(&requested)
        .with_context(|| format!("not a usable URL: {requested}"))?;

    let policy = if follow_redirects {
        reqwest::redirect::Policy::limited(10)
    } else {
        reqwest::redirect::Policy::none()
    };

    let client = reqwest::blocking::Client::builder()
        .timeout(timeout)
        .redirect(policy)
        .user_agent(USER_AGENT)
        .build()
        .context("building HTTP client")?;

    let resp = client
        .get(requested.clone())
        .send()
        .with_context(|| format!("requesting {requested}"))?;

    let final_url = resp.url().to_string();
    let https = resp.url().scheme() == "https";
    let status = resp.status().as_u16();

    let mut headers = Headers::new();
    for (name, value) in resp.headers().iter() {
        // Non-UTF-8 header values are legal on the wire but not something
        // any of these headers should ever contain; show the lossy form
        // rather than dropping the header silently.
        headers.insert(name.as_str(), &String::from_utf8_lossy(value.as_bytes()));
    }

    let redirected_from = (final_url != requested.as_str()).then(|| requested.to_string());

    Ok(Fetched {
        final_url,
        status,
        https,
        headers,
        redirected_from,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn bare_hostname_gets_https() {
        assert_eq!(normalize_url("example.com"), "https://example.com");
        assert_eq!(normalize_url("  example.com/a "), "https://example.com/a");
    }

    #[test]
    fn an_explicit_scheme_is_never_rewritten() {
        // Checking an http-only host is a legitimate thing to want, so a
        // typed `http://` must be honoured rather than silently upgraded.
        assert_eq!(
            normalize_url("http://info.cern.ch/"),
            "http://info.cern.ch/"
        );
        assert_eq!(normalize_url("https://a.test"), "https://a.test");
    }
}
