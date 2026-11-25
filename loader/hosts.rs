//! Host filter: the userspace half of `hash_host()` in xdp/protocol.h.
//!
//! The eBPF program never compares host names, it hashes the server address
//! of a handshake and looks the hash up in the `allowed_hosts` map. The names
//! from the config are normalized and hashed here in exactly the same way.

use anyhow::{Result, bail};

/// Longest host name the eBPF program can match (`HOST_HASH_MAX`).
pub const MAX_HOST_LEN: usize = 64;

const FNV64_OFFSET: u64 = 0xCBF2_9CE4_8422_2325;
const FNV64_PRIME: u64 = 0x0000_0100_0000_01B3;

/// Brings a configured host name into the form the eBPF program hashes:
/// ASCII lowercase, without surrounding whitespace and without one trailing
/// dot.
///
/// `*.example.com` is a wildcard: it matches any name with exactly one more
/// label in front (`mc.example.com`, not `example.com` or `a.b.example.com`).
/// The filter hashes a handshake's name in that form (`hash_host()` with
/// `wild`), so the wildcard entry is hashed like any other name.
pub fn normalize(host: &str) -> Result<String> {
    let host = host.trim().to_ascii_lowercase();
    let host = host.strip_suffix('.').unwrap_or(&host);
    if host.is_empty() {
        bail!("host name is empty");
    }
    if host.len() > MAX_HOST_LEN {
        bail!("host name is longer than {MAX_HOST_LEN} characters");
    }
    if host.bytes().any(|b| b == 0) {
        bail!("host name contains a NUL byte");
    }
    let rest = host.strip_prefix("*.").unwrap_or(host);
    if rest.contains('*') {
        bail!("'*' is only allowed as the whole first label (\"*.example.com\")");
    }
    if rest.is_empty() || rest.starts_with('.') {
        bail!("wildcard without a domain");
    }
    Ok(host.to_owned())
}

/// Whether a normalized name is a wildcard entry.
pub fn is_wildcard(normalized: &str) -> bool {
    normalized.starts_with("*.")
}

/// FNV-1a (64 bit) of a normalized host name, the key of `allowed_hosts`.
///
/// The eBPF program reports "not hashable" as 0 and therefore maps a real
/// hash of 0 to 1; so does this function.
pub fn hash(normalized: &str) -> u64 {
    let hash = normalized.bytes().fold(FNV64_OFFSET, |hash, byte| {
        (hash ^ u64::from(byte)).wrapping_mul(FNV64_PRIME)
    });
    if hash == 0 { 1 } else { hash }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn matches_published_fnv1a_vectors() {
        // the same vectors are checked against hash_host() in
        // xdp/tests/protocol_test.c, which ties both implementations together
        assert_eq!(hash(""), 0xCBF2_9CE4_8422_2325);
        assert_eq!(hash("a"), 0xAF63_DC4C_8601_EC8C);
        assert_eq!(hash("foobar"), 0x8594_4171_F739_67E8);
    }

    #[test]
    fn normalizes_like_the_filter() {
        assert_eq!(normalize("mc.example.com").unwrap(), "mc.example.com");
        assert_eq!(normalize(" MC.Example.COM. ").unwrap(), "mc.example.com");
        assert_eq!(normalize("203.0.113.7").unwrap(), "203.0.113.7");
        // only one trailing dot is dropped, like in hash_host()
        assert_eq!(normalize("mc.example.com..").unwrap(), "mc.example.com.");
    }

    #[test]
    fn rejects_unmatchable_names() {
        assert!(normalize("").is_err());
        assert!(normalize(" . ").is_err());
        assert!(normalize(&"a".repeat(MAX_HOST_LEN + 1)).is_err());
        assert!(normalize(&"a".repeat(MAX_HOST_LEN)).is_ok());
        assert!(normalize("mc.example.com\0FML").is_err());
    }

    #[test]
    fn accepts_wildcards_only_as_first_label() {
        assert_eq!(normalize("*.Example.COM.").unwrap(), "*.example.com");
        assert!(is_wildcard("*.example.com"));
        assert!(!is_wildcard("mc.example.com"));
        assert!(normalize("*").is_err());
        assert!(normalize("*.").is_err());
        assert!(normalize("*..com").is_err());
        assert!(normalize("mc.*.example.com").is_err());
        assert!(normalize("*mc.example.com").is_err());
        assert!(normalize("*.*.example.com").is_err());
    }

    #[test]
    fn wildcard_hash_continues_after_star_dot() {
        // FNV64_WILD in xdp/protocol.h is the state after "*."; the filter
        // continues from it with the labels after the first dot
        let wild = "*.".bytes().fold(FNV64_OFFSET, |h, b| {
            (h ^ u64::from(b)).wrapping_mul(FNV64_PRIME)
        });
        let rest = "example.com"
            .bytes()
            .fold(wild, |h, b| (h ^ u64::from(b)).wrapping_mul(FNV64_PRIME));
        assert_eq!(hash("*.example.com"), rest);
    }
}
