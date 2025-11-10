//! Embedded default wordlists.
//! Using include_str! to embed wordlists/subdomain.txt at compile time.

/// Embedded subdomain wordlist from wordlists/subdomain.txt
const EMBEDDED_SUBDOMAIN_TXT: &str = include_str!("../wordlists/subdomain.txt");

/// Return the embedded wordlist as owned Strings (one per line).
pub fn default_wordlist() -> Vec<String> {
    EMBEDDED_SUBDOMAIN_TXT
        .lines()
        .filter(|line| !line.trim().is_empty())
        .map(|line| line.trim().to_string())
        .collect()
}
