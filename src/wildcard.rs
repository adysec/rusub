use std::collections::{HashMap, HashSet};
use crate::dns;
use rand::seq::SliceRandom;

/// Basic wildcard detection: send a few random label queries and collect any returned IPs.
/// If we consistently get answers for random labels, treat the union of IPs as wildcard set.
pub fn detect_wildcard(domain: &str, resolvers: &Vec<String>, attempts: usize, timeout_secs: u64) -> HashSet<String> {
    let mut ips: HashSet<String> = HashSet::new();
    if resolvers.is_empty() { return ips; }
    let timeout_ms = timeout_secs * 1000;
    for i in 0..attempts {        
        let label = format!("{}_{}", rand::random::<u32>(), i);
        let host = format!("{}.{}", label, domain);
        // Use a random resolver each time
        if let Some(resolver) = resolvers.get(i % resolvers.len()) {
            if let Ok(ans) = dns::udp_query(&host, resolver, timeout_ms) {
                for a in ans { ips.insert(a); }
            }
        }
    }
    ips
}

/// Advanced wildcard detection:
/// - Perform more random probes
/// - Count frequency of each answered IP
/// - Return IPs whose frequency >= attempts * threshold (e.g., 0.6)
pub fn detect_wildcard_advanced(domain: &str, resolvers: &Vec<String>, attempts: usize, timeout_secs: u64, threshold: f64) -> HashSet<String> {
    let mut freq: HashMap<String, u32> = HashMap::new();
    if resolvers.is_empty() || attempts == 0 { return HashSet::new(); }
    let timeout_ms = timeout_secs * 1000;
    let mut rng = rand::thread_rng();
    for i in 0..attempts {
        let label = format!("adv{}_{}", rand::random::<u32>(), i);
        let host = format!("{}.{}", label, domain);
        if let Some(resolver) = resolvers.choose(&mut rng) {
            if let Ok(ans) = dns::udp_query(&host, resolver, timeout_ms) {
                for a in ans { *freq.entry(a).or_insert(0) += 1; }
            }
        }
    }
    let mut ips: HashSet<String> = HashSet::new();
    let cut = ((attempts as f64) * threshold).ceil() as u32;
    for (ip, c) in freq.into_iter() {
        if c >= cut { ips.insert(ip); }
    }
    ips
}

/// Check if answers are considered wildcard (subset of wildcard ip set)
pub fn is_wildcard(answers: &[String], wild_ips: &HashSet<String>) -> bool {
    if wild_ips.is_empty() { return false; }
    if answers.is_empty() { return false; }
    answers.iter().all(|a| wild_ips.contains(a))
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn test_is_wildcard_logic() {
        let mut set = HashSet::new();
        set.insert("1.2.3.4".into());
        assert!(is_wildcard(&["1.2.3.4".into()], &set));
        assert!(!is_wildcard(&["5.6.7.8".into()], &set));
        assert!(!is_wildcard(&[] as &[String], &set));
        let empty: HashSet<String> = HashSet::new();
        assert!(!is_wildcard(&["1.2.3.4".into()], &empty));
    }
}
