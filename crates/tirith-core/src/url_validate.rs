//! URL validation for outbound HTTP requests — SSRF protection.

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr, ToSocketAddrs};

type HostResolver = dyn Fn(&str, u16) -> Result<Vec<IpAddr>, String>;

#[derive(Clone, Copy)]
enum UrlValidationMode {
    Server,
    Fetch,
}

/// Validate a server URL for outbound requests: HTTPS unless `TIRITH_ALLOW_HTTP=1`,
/// and block private / loopback / link-local / metadata / non-public targets.
pub fn validate_server_url(url: &str) -> Result<(), String> {
    validate_outbound_url_with_resolver(url, UrlValidationMode::Server, &resolve_host).map(|_| ())
}

/// Validate a fetch/cloaking URL: allows http/https but blocks embedded
/// credentials and non-public destinations (after DNS resolution).
pub fn validate_fetch_url(url: &str) -> Result<url::Url, String> {
    validate_outbound_url_with_resolver(url, UrlValidationMode::Fetch, &resolve_host)
}

fn validate_outbound_url_with_resolver(
    url: &str,
    mode: UrlValidationMode,
    resolver: &HostResolver,
) -> Result<url::Url, String> {
    let parsed = url::Url::parse(url).map_err(|e| format!("invalid URL: {e}"))?;
    validate_parsed_url_with_resolver(&parsed, mode, resolver)?;
    Ok(parsed)
}

fn validate_parsed_url_with_resolver(
    parsed: &url::Url,
    mode: UrlValidationMode,
    resolver: &HostResolver,
) -> Result<(), String> {
    validate_scheme(parsed, mode)?;

    if !parsed.username().is_empty() || parsed.password().is_some() {
        return Err("refusing to connect to URLs with embedded credentials".to_string());
    }

    let host = parsed
        .host()
        .ok_or_else(|| "URL is missing a host".to_string())?;
    let host_label = parsed
        .host_str()
        .ok_or_else(|| "URL is missing a host".to_string())?
        .trim_end_matches('.')
        .to_ascii_lowercase();

    // Cloud metadata HOST NAMES are rejected first, BEFORE resolution and BEFORE
    // the private-fetch carve-out, so the opt-in can never reach a metadata host
    // (and so the rejection works offline, without a DNS lookup). These
    // endpoints expose IAM credentials and instance config — never a legitimate
    // "internal dev" target.
    if is_cloud_metadata_host(&host_label) {
        return Err(format!(
            "refusing to connect to cloud metadata endpoint: {host_label}"
        ));
    }

    let port = parsed
        .port_or_known_default()
        .ok_or_else(|| format!("unsupported URL scheme: {}", parsed.scheme()))?;

    // Resolve the host (or take the literal IP) once, up front, so the metadata
    // and forbidden-IP screens below see the same address set.
    let addrs: Vec<IpAddr> = match host {
        url::Host::Ipv4(ip) => vec![IpAddr::V4(ip)],
        url::Host::Ipv6(ip) => vec![IpAddr::V6(ip)],
        url::Host::Domain(domain) => {
            let resolved = resolver(domain, port)?;
            if resolved.is_empty() {
                return Err(format!("failed to resolve host: {host_label}"));
            }
            resolved
        }
    };

    // Cloud metadata IP addresses are likewise rejected BEFORE the carve-out —
    // the opt-in relaxes private/loopback/link-local, but a metadata IP
    // (169.254.169.254, 100.100.100.200, fd00:ec2::254, or any encoded form) is
    // never permitted. Screening the resolved set also catches a domain that
    // resolves to a metadata IP (DNS-rebind into IMDS).
    for ip in &addrs {
        if is_cloud_metadata_ip(ip) {
            return Err(format!(
                "refusing to connect to cloud metadata endpoint: {host_label} -> {ip}"
            ));
        }
    }

    // Fetch paths honor an explicit opt-in to reach private/loopback/RFC1918/
    // link-local destinations (fetching a command card or script from an
    // internal registry, and tests that serve from 127.0.0.1). It is gated
    // behind a user-set env var, so an attacker who only controls the URL
    // cannot enable it. Server paths and the default fetch path stay locked to
    // public destinations. The scheme, embedded-credential, and cloud-metadata
    // checks above still apply — the carve-out only relaxes the remaining
    // private/loopback/link-local classification, never metadata.
    if matches!(mode, UrlValidationMode::Fetch) && allow_private_fetch() {
        return Ok(());
    }

    if host_label == "localhost" || host_label.ends_with(".localhost") {
        return Err(format!(
            "refusing to connect to localhost destination: {host_label}"
        ));
    }

    for ip in &addrs {
        validate_resolved_ip(&host_label, ip)?;
    }

    Ok(())
}

fn validate_scheme(parsed: &url::Url, mode: UrlValidationMode) -> Result<(), String> {
    match mode {
        UrlValidationMode::Server => {
            if parsed.scheme() != "https" {
                if parsed.scheme() == "http"
                    && std::env::var("TIRITH_ALLOW_HTTP").ok().as_deref() == Some("1")
                {
                    eprintln!(
                        "tirith: warning: connecting to server over plain HTTP (TIRITH_ALLOW_HTTP=1)"
                    );
                } else {
                    return Err(format!(
                        "server URL must use HTTPS (got {}://). Set TIRITH_ALLOW_HTTP=1 to override.",
                        parsed.scheme()
                    ));
                }
            }
        }
        UrlValidationMode::Fetch => {
            if parsed.scheme() != "http" && parsed.scheme() != "https" {
                return Err(format!(
                    "fetch URL must use http:// or https:// (got {}://)",
                    parsed.scheme()
                ));
            }
        }
    }

    Ok(())
}

fn resolve_host(host: &str, port: u16) -> Result<Vec<IpAddr>, String> {
    let addrs = (host, port)
        .to_socket_addrs()
        .map_err(|e| format!("failed to resolve host {host}: {e}"))?;

    let mut ips = Vec::new();
    for addr in addrs {
        let ip = addr.ip();
        if !ips.contains(&ip) {
            ips.push(ip);
        }
    }
    Ok(ips)
}

fn validate_resolved_ip(host: &str, ip: &IpAddr) -> Result<(), String> {
    if is_forbidden_ip(ip) {
        Err(format!(
            "refusing to connect to non-public address: {host} -> {ip}"
        ))
    } else {
        Ok(())
    }
}

/// Whether a resolved socket address points at a routable, public destination.
///
/// This is the single source of truth for the private/loopback/link-local/
/// metadata/reserved CIDR classification used by both the URL validators (which
/// resolve via `to_socket_addrs`) and the connect-time DNS guard in
/// [`crate::ssrf_guard`]. Returns `false` for any address the validators would
/// reject as non-public.
pub fn is_public_addr(addr: &SocketAddr) -> bool {
    !is_forbidden_ip(&addr.ip())
}

/// Whether a resolved socket address is a cloud-metadata (IMDS) endpoint.
///
/// `SocketAddr` adapter over [`is_cloud_metadata_ip`], used by the connect-time
/// DNS guard in [`crate::ssrf_guard`] to drop metadata addresses even on the
/// `TIRITH_ALLOW_PRIVATE_FETCH`-relaxed path (where [`is_public_addr`] is not
/// applied). Metadata is never reachable, carve-out or not.
pub fn is_cloud_metadata_addr(addr: &SocketAddr) -> bool {
    is_cloud_metadata_ip(&addr.ip())
}

/// Whether fetch paths may reach private/loopback/link-local destinations, gated
/// behind an explicit `TIRITH_ALLOW_PRIVATE_FETCH=1` opt-in (mirrors
/// `TIRITH_ALLOW_HTTP`). Only honored for [`UrlValidationMode::Fetch`]; server
/// paths stay locked. An attacker controls the fetched URL, not the user's
/// environment, so a malicious command card or instruction cannot enable it.
///
/// This opt-in NEVER relaxes the cloud-metadata block (see
/// `is_cloud_metadata_host` / `is_cloud_metadata_ip`): those endpoints expose
/// instance credentials and are rejected ahead of the carve-out regardless.
pub fn allow_private_fetch() -> bool {
    std::env::var("TIRITH_ALLOW_PRIVATE_FETCH").ok().as_deref() == Some("1")
}

/// Canonical cloud-metadata host names. Reused by both the URL validators and
/// the connect-time DNS guard so the carve-out can never reach a metadata host.
pub(crate) fn is_cloud_metadata_host(host: &str) -> bool {
    matches!(
        host.trim_end_matches('.').to_ascii_lowercase().as_str(),
        "metadata.google.internal"
            | "metadata.google.com"
            | "instance-data"
            | "instance-data.ec2.internal"
    )
}

/// Canonical cloud-metadata IP addresses (the link-local/ULA IMDS endpoints that
/// expose instance credentials). This is the single source of truth reused by
/// both the URL validators and the connect-time DNS guard so the
/// `TIRITH_ALLOW_PRIVATE_FETCH` carve-out — which otherwise relaxes private /
/// loopback / link-local destinations — can never reach a metadata IP.
///
/// Mirrors the IPv4 set in `rules::command::METADATA_ENDPOINTS`
/// (`169.254.169.254` AWS/GCP/Azure, `100.100.100.200` Alibaba) and adds the AWS
/// IPv6 IMDS address `fd00:ec2::254`. IPv4-mapped / NAT64 / 6to4 / Teredo
/// encodings of those IPv4 metadata addresses are decoded via
/// [`embedded_ipv4_in_v6`] so a translated form can't slip past.
pub(crate) fn is_cloud_metadata_ip(ip: &IpAddr) -> bool {
    match ip {
        IpAddr::V4(v4) => {
            matches!(v4.octets(), [169, 254, 169, 254] | [100, 100, 100, 200])
        }
        IpAddr::V6(v6) => {
            if let Some(v4) = embedded_ipv4_in_v6(v6) {
                return is_cloud_metadata_ip(&IpAddr::V4(v4));
            }
            // AWS IPv6 instance metadata service: fd00:ec2::254.
            v6.segments() == [0xfd00, 0x0ec2, 0, 0, 0, 0, 0, 0x0254]
        }
    }
}

fn is_forbidden_ip(ip: &IpAddr) -> bool {
    match ip {
        IpAddr::V4(v4) => {
            // IANA's IPv4 special-purpose registry marks the whole
            // 192.0.0.0/24 block non-global except the PCP/TURN anycast
            // addresses. 192.88.99.0/24 is the deprecated 6to4 relay block and
            // remains non-global, including the 192.88.99.2 6a44 anycast entry.
            if matches!(v4.octets(), [192, 0, 0, 9] | [192, 0, 0, 10]) {
                return false;
            }
            ipv4_in_prefix(*v4, [0, 0, 0, 0], 8)
                || ipv4_in_prefix(*v4, [10, 0, 0, 0], 8)
                || ipv4_in_prefix(*v4, [100, 64, 0, 0], 10)
                || ipv4_in_prefix(*v4, [127, 0, 0, 0], 8)
                || ipv4_in_prefix(*v4, [169, 254, 0, 0], 16)
                || ipv4_in_prefix(*v4, [172, 16, 0, 0], 12)
                || ipv4_in_prefix(*v4, [192, 0, 0, 0], 24)
                || ipv4_in_prefix(*v4, [192, 0, 2, 0], 24)
                || ipv4_in_prefix(*v4, [192, 88, 99, 0], 24)
                || ipv4_in_prefix(*v4, [192, 168, 0, 0], 16)
                || ipv4_in_prefix(*v4, [198, 18, 0, 0], 15)
                || ipv4_in_prefix(*v4, [198, 51, 100, 0], 24)
                || ipv4_in_prefix(*v4, [203, 0, 113, 0], 24)
                || ipv4_in_prefix(*v4, [224, 0, 0, 0], 4)
                || ipv4_in_prefix(*v4, [240, 0, 0, 0], 4)
        }
        IpAddr::V6(v6) => {
            // The well-known NAT64 prefix is globally routed when its embedded
            // IPv4 destination is. Other translated/transition ranges (mapped,
            // local-use NAT64, 6to4, Teredo) are not accepted as global socket
            // destinations by this server-side boundary.
            let octets = v6.octets();
            const NAT64_WELL_KNOWN_PREFIX: [u8; 12] =
                [0x00, 0x64, 0xff, 0x9b, 0, 0, 0, 0, 0, 0, 0, 0];
            if octets.starts_with(&NAT64_WELL_KNOWN_PREFIX) {
                let embedded = Ipv4Addr::new(octets[12], octets[13], octets[14], octets[15]);
                return is_forbidden_ip(&IpAddr::V4(embedded));
            }
            // IANA globally reachable exceptions inside the otherwise special
            // 2001::/23 protocol-assignment block.
            if *v6 == Ipv6Addr::new(0x2001, 1, 0, 0, 0, 0, 0, 1)
                || *v6 == Ipv6Addr::new(0x2001, 1, 0, 0, 0, 0, 0, 2)
                || *v6 == Ipv6Addr::new(0x2001, 1, 0, 0, 0, 0, 0, 3)
                || ipv6_in_prefix(*v6, Ipv6Addr::new(0x2001, 3, 0, 0, 0, 0, 0, 0), 32)
                || ipv6_in_prefix(*v6, Ipv6Addr::new(0x2001, 4, 0x0112, 0, 0, 0, 0, 0), 48)
                || ipv6_in_prefix(*v6, Ipv6Addr::new(0x2001, 0x20, 0, 0, 0, 0, 0, 0), 28)
                || ipv6_in_prefix(*v6, Ipv6Addr::new(0x2001, 0x30, 0, 0, 0, 0, 0, 0), 28)
            {
                return false;
            }
            // Default-deny unallocated/reserved IPv6 space: ordinary global
            // unicast is 2000::/3. Then subtract every current non-global
            // special-purpose subrange in that allocation.
            !ipv6_in_prefix(*v6, Ipv6Addr::new(0x2000, 0, 0, 0, 0, 0, 0, 0), 3)
                || ipv6_in_prefix(*v6, Ipv6Addr::new(0x2001, 0, 0, 0, 0, 0, 0, 0), 23)
                || ipv6_in_prefix(*v6, Ipv6Addr::new(0x2001, 0x0db8, 0, 0, 0, 0, 0, 0), 32)
                || ipv6_in_prefix(*v6, Ipv6Addr::new(0x2002, 0, 0, 0, 0, 0, 0, 0), 16)
                || ipv6_in_prefix(*v6, Ipv6Addr::new(0x3fff, 0, 0, 0, 0, 0, 0, 0), 20)
        }
    }
}

fn ipv4_in_prefix(address: Ipv4Addr, network: [u8; 4], prefix: u32) -> bool {
    let address = u32::from(address);
    let network = u32::from_be_bytes(network);
    let mask = if prefix == 0 {
        0
    } else {
        u32::MAX << (32 - prefix)
    };
    address & mask == network & mask
}

fn ipv6_in_prefix(address: Ipv6Addr, network: Ipv6Addr, prefix: u32) -> bool {
    let address = u128::from(address);
    let network = u128::from(network);
    let mask = if prefix == 0 {
        0
    } else {
        u128::MAX << (128 - prefix)
    };
    address & mask == network & mask
}

fn embedded_ipv4_in_v6(v6: &Ipv6Addr) -> Option<Ipv4Addr> {
    if let Some(v4) = v6.to_ipv4_mapped() {
        return Some(v4);
    }

    let octets = v6.octets();
    if octets[..12].iter().all(|&b| b == 0) {
        return Some(Ipv4Addr::new(
            octets[12], octets[13], octets[14], octets[15],
        ));
    }

    const NAT64_WELL_KNOWN_PREFIX: [u8; 12] = [
        0x00, 0x64, 0xff, 0x9b, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    ];
    if octets.starts_with(&NAT64_WELL_KNOWN_PREFIX) {
        return Some(Ipv4Addr::new(
            octets[12], octets[13], octets[14], octets[15],
        ));
    }

    // 6to4 (`2002::/16`, RFC 3056): the embedded IPv4 is octets [2..6]. A
    // literal like `2002:7f00:1::` tunnels 127.0.0.1. Decode it so callers that
    // inspect embedded addresses cannot miss that identity; the global-address
    // classifier independently blanket-blocks the deprecated 2002::/16 range.
    if octets[0] == 0x20 && octets[1] == 0x02 {
        return Some(Ipv4Addr::new(octets[2], octets[3], octets[4], octets[5]));
    }

    // Teredo (`2001:0000::/32`, RFC 4380): the server (client external) IPv4 is
    // the LAST 4 octets, each XORed with 0xFF (obfuscated). Decode and apply the
    // same IPv4 check so a Teredo address embedding a private/loopback IPv4
    // can't be used as an SSRF bounce.
    if octets[0] == 0x20 && octets[1] == 0x01 && octets[2] == 0x00 && octets[3] == 0x00 {
        return Some(Ipv4Addr::new(
            octets[12] ^ 0xff,
            octets[13] ^ 0xff,
            octets[14] ^ 0xff,
            octets[15] ^ 0xff,
        ));
    }

    None
}

#[cfg(test)]
mod tests {
    use super::*;

    fn resolver_with(ip: IpAddr) -> impl Fn(&str, u16) -> Result<Vec<IpAddr>, String> {
        move |_, _| Ok(vec![ip])
    }

    #[test]
    fn test_rejects_http() {
        let result = validate_server_url("http://example.com/api");
        assert!(result.is_err());
        assert!(result.unwrap_err().contains("HTTPS"));
    }

    #[test]
    fn test_accepts_https() {
        let result = validate_outbound_url_with_resolver(
            "https://policy.tirith.dev/api",
            UrlValidationMode::Server,
            &resolver_with("93.184.216.34".parse().unwrap()),
        );
        assert!(result.is_ok());
    }

    #[test]
    fn test_rejects_loopback() {
        let result = validate_server_url("https://127.0.0.1/api");
        assert!(result.is_err());
        assert!(result.unwrap_err().contains("non-public"));
    }

    #[test]
    fn test_rejects_private_10() {
        let result = validate_server_url("https://10.0.0.1/api");
        assert!(result.is_err());
    }

    #[test]
    fn test_rejects_private_172() {
        let result = validate_server_url("https://172.16.0.1/api");
        assert!(result.is_err());
    }

    #[test]
    fn test_rejects_private_192() {
        let result = validate_server_url("https://192.168.1.1/api");
        assert!(result.is_err());
    }

    #[test]
    fn test_rejects_metadata() {
        let result = validate_server_url("https://169.254.169.254/latest/meta-data/");
        assert!(result.is_err());
    }

    #[test]
    fn test_rejects_cloud_metadata_hostname() {
        let result = validate_server_url("https://metadata.google.internal/");
        assert!(result.is_err());
    }

    #[test]
    fn test_rejects_invalid_url() {
        let result = validate_server_url("not a url");
        assert!(result.is_err());
    }

    #[test]
    fn test_rejects_embedded_credentials() {
        let result = validate_outbound_url_with_resolver(
            "https://user:pass@example.com/path",
            UrlValidationMode::Fetch,
            &resolver_with("93.184.216.34".parse().unwrap()),
        );
        assert!(result.is_err());
        assert!(result.unwrap_err().contains("embedded credentials"));
    }

    #[test]
    fn test_rejects_localhost_name() {
        let result = validate_outbound_url_with_resolver(
            "https://localhost/path",
            UrlValidationMode::Fetch,
            &resolver_with("93.184.216.34".parse().unwrap()),
        );
        assert!(result.is_err());
        assert!(result.unwrap_err().contains("localhost"));
    }

    #[test]
    fn test_rejects_localhost_subdomain() {
        let result = validate_outbound_url_with_resolver(
            "https://api.localhost/path",
            UrlValidationMode::Fetch,
            &resolver_with("93.184.216.34".parse().unwrap()),
        );
        assert!(result.is_err());
        assert!(result.unwrap_err().contains("localhost"));
    }

    #[test]
    fn test_rejects_hostname_resolving_to_private_ip() {
        let result = validate_outbound_url_with_resolver(
            "https://example.com/path",
            UrlValidationMode::Server,
            &resolver_with("127.0.0.1".parse().unwrap()),
        );
        assert!(result.is_err());
        assert!(result.unwrap_err().contains("127.0.0.1"));
    }

    #[test]
    fn test_rejects_hostname_resolving_to_documentation_range() {
        let result = validate_outbound_url_with_resolver(
            "https://example.com/path",
            UrlValidationMode::Fetch,
            &resolver_with("203.0.113.10".parse().unwrap()),
        );
        assert!(result.is_err());
        assert!(result.unwrap_err().contains("203.0.113.10"));
    }

    #[test]
    fn test_fetch_allows_http_when_public() {
        let result = validate_outbound_url_with_resolver(
            "http://example.com/path",
            UrlValidationMode::Fetch,
            &resolver_with("93.184.216.34".parse().unwrap()),
        );
        assert!(result.is_ok());
    }

    #[test]
    fn test_fetch_rejects_non_http_scheme() {
        let result = validate_outbound_url_with_resolver(
            "ftp://example.com/file",
            UrlValidationMode::Fetch,
            &resolver_with("93.184.216.34".parse().unwrap()),
        );
        assert!(result.is_err());
        assert!(result.unwrap_err().contains("http:// or https://"));
    }

    #[test]
    fn test_accepts_public_ipv6_literal_without_dns_lookup() {
        let result = validate_outbound_url_with_resolver(
            "https://[2606:2800:220:1:248:1893:25c8:1946]",
            UrlValidationMode::Server,
            &|_, _| Err("resolver should not be called".to_string()),
        );
        assert!(result.is_ok());
    }

    #[test]
    fn test_rejects_ipv4_mapped_ipv6_literal() {
        let result = validate_outbound_url_with_resolver(
            "https://[::ffff:127.0.0.1]/api",
            UrlValidationMode::Server,
            &|_, _| Err("resolver should not be called".to_string()),
        );
        assert!(result.is_err());
        assert!(result.unwrap_err().contains("non-public"));
    }

    #[test]
    fn test_rejects_hostname_resolving_to_ipv4_mapped_ipv6() {
        let result = validate_outbound_url_with_resolver(
            "https://example.com/api",
            UrlValidationMode::Fetch,
            &resolver_with("::ffff:169.254.169.254".parse().unwrap()),
        );
        assert!(result.is_err());
        assert!(result.unwrap_err().contains("169.254.169.254"));
    }

    // Adversarial bypass attempts: embedded IPv4 / translated IPv6.

    #[test]
    fn test_bypass_mapped_cloud_metadata() {
        // AWS metadata endpoint via IPv4-mapped IPv6.
        let result = validate_outbound_url_with_resolver(
            "https://[::ffff:169.254.169.254]/latest/meta-data/",
            UrlValidationMode::Server,
            &|_, _| Err("resolver should not be called".to_string()),
        );
        assert!(result.is_err(), "IPv4-mapped metadata must be blocked");
    }

    #[test]
    fn test_bypass_mapped_private_10() {
        let result = validate_outbound_url_with_resolver(
            "https://[::ffff:10.0.0.1]/admin",
            UrlValidationMode::Server,
            &|_, _| Err("resolver should not be called".to_string()),
        );
        assert!(result.is_err(), "IPv4-mapped 10.x must be blocked");
    }

    #[test]
    fn test_bypass_mapped_private_192() {
        let result = validate_outbound_url_with_resolver(
            "https://[::ffff:192.168.1.1]/config",
            UrlValidationMode::Server,
            &|_, _| Err("resolver should not be called".to_string()),
        );
        assert!(result.is_err(), "IPv4-mapped 192.168.x must be blocked");
    }

    #[test]
    fn test_bypass_mapped_private_172() {
        let result = validate_outbound_url_with_resolver(
            "https://[::ffff:172.16.0.1]/",
            UrlValidationMode::Server,
            &|_, _| Err("resolver should not be called".to_string()),
        );
        assert!(result.is_err(), "IPv4-mapped 172.16.x must be blocked");
    }

    #[test]
    fn test_bypass_mapped_unspecified() {
        let result = validate_outbound_url_with_resolver(
            "https://[::ffff:0.0.0.0]/",
            UrlValidationMode::Server,
            &|_, _| Err("resolver should not be called".to_string()),
        );
        assert!(result.is_err(), "IPv4-mapped 0.0.0.0 must be blocked");
    }

    #[test]
    fn test_bypass_mapped_broadcast() {
        let result = validate_outbound_url_with_resolver(
            "https://[::ffff:255.255.255.255]/",
            UrlValidationMode::Server,
            &|_, _| Err("resolver should not be called".to_string()),
        );
        assert!(result.is_err(), "IPv4-mapped broadcast must be blocked");
    }

    #[test]
    fn test_bypass_resolved_mapped_loopback() {
        // DNS returns ::ffff:127.0.0.1 for a hostname
        let result = validate_outbound_url_with_resolver(
            "https://attacker.example.com/",
            UrlValidationMode::Server,
            &resolver_with("::ffff:127.0.0.1".parse().unwrap()),
        );
        assert!(
            result.is_err(),
            "Resolved IPv4-mapped loopback must be blocked"
        );
    }

    #[test]
    fn test_bypass_resolved_mapped_private() {
        // DNS returns ::ffff:10.0.0.1 for a hostname
        let result = validate_outbound_url_with_resolver(
            "https://attacker.example.com/api",
            UrlValidationMode::Fetch,
            &resolver_with("::ffff:10.0.0.1".parse().unwrap()),
        );
        assert!(
            result.is_err(),
            "Resolved IPv4-mapped private must be blocked"
        );
    }

    #[test]
    fn test_rejects_nat64_encoded_loopback() {
        let result = validate_outbound_url_with_resolver(
            "https://[64:ff9b::127.0.0.1]/",
            UrlValidationMode::Server,
            &|_, _| Err("resolver should not be called".to_string()),
        );
        assert!(result.is_err(), "NAT64-encoded loopback must be blocked");
    }

    #[test]
    fn test_rejects_resolved_nat64_encoded_metadata() {
        let result = validate_outbound_url_with_resolver(
            "https://example.com/api",
            UrlValidationMode::Fetch,
            &resolver_with("64:ff9b::169.254.169.254".parse().unwrap()),
        );
        assert!(
            result.is_err(),
            "NAT64-encoded metadata address must be blocked"
        );
    }

    #[test]
    fn test_rejects_ipv4_compatible_loopback() {
        let result = validate_outbound_url_with_resolver(
            "https://[::127.0.0.1]/",
            UrlValidationMode::Server,
            &|_, _| Err("resolver should not be called".to_string()),
        );
        assert!(
            result.is_err(),
            "IPv4-compatible loopback form must be blocked"
        );
    }

    #[test]
    fn test_allows_nat64_encoded_public_ipv4() {
        let result = validate_outbound_url_with_resolver(
            "https://[64:ff9b::0808:0808]/",
            UrlValidationMode::Server,
            &|_, _| Err("resolver should not be called".to_string()),
        );
        assert!(
            result.is_ok(),
            "NAT64-encoded public IPv4 should be allowed"
        );
    }

    #[test]
    fn test_legitimate_public_ipv6_still_allowed() {
        // Google's public DNS — must NOT be blocked
        let result = validate_outbound_url_with_resolver(
            "https://[2607:f8b0:4004:800::200e]/",
            UrlValidationMode::Server,
            &|_, _| Err("resolver should not be called".to_string()),
        );
        assert!(result.is_ok(), "Public IPv6 must be allowed");
    }

    #[test]
    fn test_legitimate_resolved_public_ipv6_allowed() {
        let result = validate_outbound_url_with_resolver(
            "https://example.com/api",
            UrlValidationMode::Server,
            &resolver_with("2607:f8b0:4004:800::200e".parse().unwrap()),
        );
        assert!(result.is_ok(), "Resolved public IPv6 must be allowed");
    }

    // 6to4 (2002::/16) and Teredo (2001:0000::/32) are no longer globally
    // reachable transition ranges. The server boundary rejects the entire
    // ranges rather than treating a public embedded IPv4 as sufficient.

    #[test]
    fn test_rejects_6to4_encoded_loopback() {
        // 2002:7f00:1:: is the 6to4 wrapping of 127.0.0.1.
        let result = validate_outbound_url_with_resolver(
            "https://[2002:7f00:1::]/",
            UrlValidationMode::Server,
            &|_, _| Err("resolver should not be called".to_string()),
        );
        assert!(result.is_err(), "6to4-encoded loopback must be blocked");
        assert!(result.unwrap_err().contains("non-public"));
    }

    #[test]
    fn test_rejects_deprecated_6to4_even_with_public_ipv4() {
        // 2002:0808:0808:: wraps 8.8.8.8, but RFC 9637 makes 2002::/16
        // non-global regardless of the embedded address.
        let result = validate_outbound_url_with_resolver(
            "https://[2002:0808:0808::]/",
            UrlValidationMode::Server,
            &|_, _| Err("resolver should not be called".to_string()),
        );
        assert!(result.is_err(), "deprecated 6to4 must be refused");
    }

    #[test]
    fn test_rejects_teredo_encoded_private_ipv4() {
        // Teredo address whose embedded server IPv4 is 192.168.1.1: the last 32
        // bits are the server IPv4 XOR 0xff per octet (0x3f57:fefe).
        let result = validate_outbound_url_with_resolver(
            "https://[2001:0:0:0:0:0:3f57:fefe]/",
            UrlValidationMode::Server,
            &|_, _| Err("resolver should not be called".to_string()),
        );
        assert!(
            result.is_err(),
            "Teredo-encoded private IPv4 must be blocked"
        );
        assert!(result.unwrap_err().contains("non-public"));
    }

    #[test]
    fn test_normal_public_ipv6_still_allowed_after_carveout() {
        // A genuine public v6 (Cloudflare DNS) must not collide with the 6to4 or
        // Teredo prefixes added by the carve-out.
        let result = validate_outbound_url_with_resolver(
            "https://[2606:4700:4700::1111]/",
            UrlValidationMode::Server,
            &|_, _| Err("resolver should not be called".to_string()),
        );
        assert!(
            result.is_ok(),
            "Public IPv6 must still be allowed after the 6to4/Teredo carve-out"
        );
    }

    // F6: `validate_fetch_url` must reject IP-literal SSRF targets up front
    // (these are the fast-clear-error cases the runner pre-check relies on).

    #[test]
    fn test_fetch_rejects_loopback_literal() {
        let result = validate_fetch_url("http://127.0.0.1");
        assert!(result.is_err());
        assert!(result.unwrap_err().contains("non-public"));
    }

    #[test]
    fn test_fetch_rejects_metadata_literal() {
        let result = validate_fetch_url("http://169.254.169.254");
        assert!(result.is_err());
        // Metadata IPs are now rejected by the dedicated metadata gate (ahead of
        // the generic non-public check) so the error names the metadata endpoint.
        assert!(result.unwrap_err().contains("cloud metadata endpoint"));
    }

    #[test]
    fn test_fetch_rejects_ipv6_loopback_literal() {
        let result = validate_fetch_url("http://[::1]");
        assert!(result.is_err());
        assert!(result.unwrap_err().contains("non-public"));
    }

    #[test]
    fn test_fetch_rejects_private_10_literal() {
        let result = validate_fetch_url("http://10.0.0.1");
        assert!(result.is_err());
        assert!(result.unwrap_err().contains("non-public"));
    }

    // is_public_addr: the shared classifier reused by the DNS guard.

    fn sock(ip: &str) -> SocketAddr {
        SocketAddr::new(ip.parse().unwrap(), 443)
    }

    #[test]
    fn test_is_public_addr_rejects_private() {
        assert!(!is_public_addr(&sock("10.0.0.1")));
        assert!(!is_public_addr(&sock("172.16.0.1")));
        assert!(!is_public_addr(&sock("192.168.1.1")));
    }

    #[test]
    fn test_is_public_addr_rejects_loopback() {
        assert!(!is_public_addr(&sock("127.0.0.1")));
        assert!(!is_public_addr(&sock("::1")));
    }

    #[test]
    fn test_is_public_addr_rejects_link_local() {
        assert!(!is_public_addr(&sock("169.254.1.1")));
        assert!(!is_public_addr(&sock("fe80::1")));
    }

    #[test]
    fn test_is_public_addr_rejects_metadata() {
        assert!(!is_public_addr(&sock("169.254.169.254")));
    }

    #[test]
    fn test_is_public_addr_rejects_mapped_ipv6() {
        assert!(!is_public_addr(&sock("::ffff:127.0.0.1")));
        assert!(!is_public_addr(&sock("::ffff:169.254.169.254")));
    }

    #[test]
    fn test_is_public_addr_accepts_public() {
        assert!(is_public_addr(&sock("93.184.216.34")));
        assert!(is_public_addr(&sock("8.8.8.8")));
        assert!(is_public_addr(&sock("2607:f8b0:4004:800::200e")));
    }

    #[test]
    fn test_is_public_addr_tracks_special_purpose_registries() {
        for address in [
            "192.0.0.1",
            "192.88.99.1",
            "192.88.99.2",
            "100::1",
            "2001:2::1",
            "2001:db8::1",
            "2002:0808:0808::1",
            "3fff::1",
            "64:ff9b:1::808:808",
        ] {
            assert!(!is_public_addr(&sock(address)), "{address}");
        }
        for address in [
            "192.0.0.9",
            "192.0.0.10",
            "2001:1::1",
            "2001:1::2",
            "2001:1::3",
            "2001:3::1",
            "2001:4:112::1",
            "2001:20::1",
            "2001:30::1",
            "64:ff9b::808:808",
        ] {
            assert!(is_public_addr(&sock(address)), "{address}");
        }
    }

    // is_cloud_metadata_ip: the dedicated metadata-IP classifier the carve-out
    // is screened against.

    #[test]
    fn test_is_cloud_metadata_ip_matches_known_endpoints() {
        assert!(is_cloud_metadata_ip(&"169.254.169.254".parse().unwrap()));
        assert!(is_cloud_metadata_ip(&"100.100.100.200".parse().unwrap()));
        assert!(is_cloud_metadata_ip(&"fd00:ec2::254".parse().unwrap()));
        // Encoded forms of the IPv4 metadata address are decoded and matched.
        assert!(is_cloud_metadata_ip(
            &"::ffff:169.254.169.254".parse().unwrap()
        ));
        assert!(is_cloud_metadata_ip(
            &"64:ff9b::169.254.169.254".parse().unwrap()
        ));
    }

    #[test]
    fn test_is_cloud_metadata_ip_ignores_non_metadata() {
        // Other private/link-local addresses are NOT metadata (the carve-out may
        // permit these) — only the IMDS endpoints above are metadata.
        assert!(!is_cloud_metadata_ip(&"169.254.1.1".parse().unwrap()));
        assert!(!is_cloud_metadata_ip(&"127.0.0.1".parse().unwrap()));
        assert!(!is_cloud_metadata_ip(&"10.0.0.1".parse().unwrap()));
        assert!(!is_cloud_metadata_ip(&"100.100.100.201".parse().unwrap()));
        assert!(!is_cloud_metadata_ip(&"8.8.8.8".parse().unwrap()));
        assert!(!is_cloud_metadata_ip(&"fd00:ec2::255".parse().unwrap()));
    }

    // TIRITH_ALLOW_PRIVATE_FETCH carve-out: the opt-in relaxes private/loopback/
    // link-local fetch targets, but must NEVER reach a cloud-metadata endpoint.
    // `TEST_ENV_LOCK` serializes these env-mutating tests; `EnvVarGuard` restores
    // the prior value on drop.

    struct EnvVarGuard {
        key: &'static str,
        prev: Option<std::ffi::OsString>,
    }

    impl EnvVarGuard {
        fn set(key: &'static str, value: &str) -> Self {
            let prev = std::env::var_os(key);
            unsafe { std::env::set_var(key, value) };
            Self { key, prev }
        }
    }

    impl Drop for EnvVarGuard {
        fn drop(&mut self) {
            match &self.prev {
                Some(v) => unsafe { std::env::set_var(self.key, v) },
                None => unsafe { std::env::remove_var(self.key) },
            }
        }
    }

    #[test]
    fn test_private_fetch_carveout_still_blocks_metadata_ip_literal() {
        let _lock = crate::TEST_ENV_LOCK
            .lock()
            .unwrap_or_else(|e| e.into_inner());
        let _env = EnvVarGuard::set("TIRITH_ALLOW_PRIVATE_FETCH", "1");

        // Even with the carve-out set, the AWS/GCP/Azure IMDS IP stays blocked.
        let result = validate_fetch_url("http://169.254.169.254/latest/meta-data/");
        assert!(
            result.is_err(),
            "metadata IP must stay blocked under TIRITH_ALLOW_PRIVATE_FETCH"
        );
        assert!(result.unwrap_err().contains("cloud metadata endpoint"));

        // Alibaba Cloud metadata IP, likewise.
        let result = validate_fetch_url("http://100.100.100.200/");
        assert!(result.is_err());
        assert!(result.unwrap_err().contains("cloud metadata endpoint"));
    }

    #[test]
    fn test_private_fetch_carveout_still_blocks_metadata_hostname() {
        let _lock = crate::TEST_ENV_LOCK
            .lock()
            .unwrap_or_else(|e| e.into_inner());
        let _env = EnvVarGuard::set("TIRITH_ALLOW_PRIVATE_FETCH", "1");

        let result = validate_fetch_url("http://metadata.google.internal/");
        assert!(
            result.is_err(),
            "metadata hostname must stay blocked under TIRITH_ALLOW_PRIVATE_FETCH"
        );
        assert!(result.unwrap_err().contains("cloud metadata endpoint"));
    }

    #[test]
    fn test_private_fetch_carveout_still_blocks_ipv6_metadata_literal() {
        let _lock = crate::TEST_ENV_LOCK
            .lock()
            .unwrap_or_else(|e| e.into_inner());
        let _env = EnvVarGuard::set("TIRITH_ALLOW_PRIVATE_FETCH", "1");

        // AWS IPv6 IMDS address.
        let result = validate_fetch_url("http://[fd00:ec2::254]/latest/meta-data/");
        assert!(
            result.is_err(),
            "IPv6 metadata literal must stay blocked under TIRITH_ALLOW_PRIVATE_FETCH"
        );
        assert!(result.unwrap_err().contains("cloud metadata endpoint"));
    }

    #[test]
    fn test_private_fetch_carveout_still_blocks_domain_resolving_to_metadata() {
        let _lock = crate::TEST_ENV_LOCK
            .lock()
            .unwrap_or_else(|e| e.into_inner());
        let _env = EnvVarGuard::set("TIRITH_ALLOW_PRIVATE_FETCH", "1");

        // A hostname (DNS-rebind style) that resolves to the metadata IP must be
        // rejected even though the carve-out otherwise permits private targets.
        let result = validate_outbound_url_with_resolver(
            "http://internal.example.com/latest/meta-data/",
            UrlValidationMode::Fetch,
            &resolver_with("169.254.169.254".parse().unwrap()),
        );
        assert!(
            result.is_err(),
            "domain resolving to metadata IP must stay blocked under the carve-out"
        );
        assert!(result.unwrap_err().contains("cloud metadata endpoint"));
    }

    #[test]
    fn test_private_fetch_carveout_allows_genuine_private_hosts() {
        let _lock = crate::TEST_ENV_LOCK
            .lock()
            .unwrap_or_else(|e| e.into_inner());
        let _env = EnvVarGuard::set("TIRITH_ALLOW_PRIVATE_FETCH", "1");

        // The carve-out still does its job: loopback and RFC1918 are reachable.
        assert!(
            validate_fetch_url("http://127.0.0.1/card.json").is_ok(),
            "loopback must be allowed under TIRITH_ALLOW_PRIVATE_FETCH"
        );
        assert!(
            validate_fetch_url("http://10.0.0.1/card.json").is_ok(),
            "RFC1918 host must be allowed under TIRITH_ALLOW_PRIVATE_FETCH"
        );
    }

    #[test]
    fn test_private_fetch_carveout_does_not_apply_to_server_metadata() {
        let _lock = crate::TEST_ENV_LOCK
            .lock()
            .unwrap_or_else(|e| e.into_inner());
        let _env = EnvVarGuard::set("TIRITH_ALLOW_PRIVATE_FETCH", "1");

        // Server paths never honor the carve-out at all, metadata or otherwise.
        let result = validate_server_url("https://169.254.169.254/latest/meta-data/");
        assert!(
            result.is_err(),
            "server path must ignore the fetch carve-out"
        );
    }
}
