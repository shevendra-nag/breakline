//! A public-HTTPS-only probe policy. No redirects, proxies, userinfo or private
//! addresses. DNS is validated and pinned for each request to avoid rebinding.
use std::{net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr}, time::Duration};
use reqwest::Url;
use crate::error::ApiError;

pub fn validate_url(input: &str) -> Result<String, ApiError> {
    let input = input.trim();
    if input.len() > 1024 || input.chars().any(char::is_control) {
        return Err(ApiError::bad_request("Monitor URL is too long or invalid"));
    }
    let url = Url::parse(input).map_err(|_| ApiError::bad_request("Enter a valid HTTPS URL"))?;
    if url.scheme() != "https" || url.host_str().is_none() || !url.username().is_empty()
        || url.password().is_some() || url.fragment().is_some() || url.query().is_some()
        || url.port_or_known_default() != Some(443) {
        return Err(ApiError::bad_request("Only public HTTPS URLs on port 443 without credentials, query or fragment are supported"));
    }
    let host = url.host_str().unwrap_or_default();
    if host.eq_ignore_ascii_case("localhost") || host.ends_with(".local") || host.ends_with(".internal") {
        return Err(ApiError::bad_request("Private hostnames cannot be monitored"));
    }
    let literal = host.trim_matches(|ch| ch == '[' || ch == ']');
    if let Ok(ip) = literal.parse::<IpAddr>() {
        if !public_ip(ip) { return Err(ApiError::bad_request("Private and reserved IP addresses are not allowed")); }
    }
    Ok(url.to_string())
}

pub fn public_ip(ip: IpAddr) -> bool {
    match ip {
        IpAddr::V4(v) => public_v4(v),
        IpAddr::V6(v) => public_v6(v),
    }
}

fn public_v4(ip: Ipv4Addr) -> bool {
    let o = ip.octets();
    // Disallow IANA-reserved, non-routable, documentation, shared, benchmarking,
    // loopback, multicast and broadcast ranges. Conservative by design.
    if o[0] == 0 || o[0] == 10 || o[0] == 127 || o[0] >= 224
        || (o[0] == 100 && (64..=127).contains(&o[1]))
        || (o[0] == 169 && o[1] == 254)
        || (o[0] == 172 && (16..=31).contains(&o[1]))
        || (o[0] == 192 && (o[1] == 168 || o[1] == 0 || (o[1] == 88 && o[2] == 99)))
        || (o[0] == 198 && ((o[1] == 18 || o[1] == 19) || o[1] == 51 && o[2] == 100))
        || (o[0] == 192 && o[1] == 0 && o[2] == 2)
        || (o[0] == 203 && o[1] == 0 && o[2] == 113)
    { return false; }
    true
}

fn public_v6(ip: Ipv6Addr) -> bool {
    let segments = ip.segments();
    // Only globally routable unicast 2000::/3; exclude documentation and
    // well-known special-use blocks (including IPv4-mapped addresses).
    (segments[0] & 0xe000) == 0x2000
        && !(segments[0] == 0x2001 && (segments[1] == 0x0000 || segments[1] == 0x0db8))
        && segments[0] != 0x2002
        && !(segments[0] == 0x2001 && (segments[1] & 0xfff0) == 0x0010)
}

pub async fn probe(url: &str, method: &str, expected: i32, timeout_seconds: i32) -> ProbeResult {
    let start = std::time::Instant::now();
    let result = async {
        let allowed = validate_url(url).map_err(|_| "Monitor URL was rejected by security policy")?;
        let parsed = Url::parse(&allowed).map_err(|_| "Invalid URL")?;
        let host = parsed.host_str().ok_or("Missing hostname")?;
        let literal = host.trim_matches(|ch| ch == '[' || ch == ']');
        let resolved: Vec<SocketAddr> = if let Ok(ip) = literal.parse::<IpAddr>() {
            vec![SocketAddr::new(ip, 443)]
        } else {
            tokio::net::lookup_host((host, 443)).await
                .map_err(|_| "DNS lookup failed")?.collect()
        };
        if resolved.is_empty() || resolved.iter().any(|addr| !public_ip(addr.ip())) {
            return Err("DNS returned an unsafe or reserved address");
        }
        let client = reqwest::Client::builder()
            .https_only(true).no_proxy().redirect(reqwest::redirect::Policy::none())
            .resolve_to_addrs(host, &resolved)
            .timeout(Duration::from_secs(timeout_seconds as u64))
            .user_agent("BreaklineMonitor/0.2")
            .build().map_err(|_| "Probe client configuration failed")?;
        let verb = if method == "HEAD" { reqwest::Method::HEAD } else { reqwest::Method::GET };
        let response = client.request(verb, parsed).send().await
            .map_err(|_| "Connection, TLS handshake or timeout failure")?;
        Ok::<i32, &'static str>(i32::from(response.status().as_u16()))
    }.await;
    let elapsed = start.elapsed().as_millis().min(i32::MAX as u128) as i32;
    match result {
        Ok(code) => ProbeResult { status: if code == expected { "up" } else { "down" }, http_status: Some(code), latency_ms: Some(elapsed), error_message: None },
        Err(reason) => ProbeResult { status: "down", http_status: None, latency_ms: Some(elapsed), error_message: Some(reason.to_owned()) },
    }
}

pub struct ProbeResult {
    pub status: &'static str,
    pub http_status: Option<i32>,
    pub latency_ms: Option<i32>,
    pub error_message: Option<String>,
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn url_policy() {
        assert!(validate_url("https://example.com/health").is_ok());
        for input in ["http://example.com", "https://localhost", "https://user:pass@example.com", "https://example.com:8443", "https://example.com/ok?key=secret", "https://example.com/#foo"] {
            assert!(validate_url(input).is_err(), "accepted: {input}");
        }
    }
    #[test]
    fn address_policy() {
        for input in ["127.0.0.1", "10.1.2.3", "169.254.169.254", "172.18.0.1", "192.168.1.2", "100.64.1.1", "192.0.2.1", "::1", "fc00::1", "fe80::1", "2001:db8::1", "::ffff:8.8.8.8"] {
            assert!(!public_ip(input.parse().unwrap()), "allowed: {input}");
        }
        assert!(public_ip("8.8.8.8".parse().unwrap()));
        assert!(public_ip("2606:4700:4700::1111".parse().unwrap()));
    }
}
