pub fn basic_seeds() -> Vec<String> {
    vec![
        "www".into(),
        "api".into(),
        "cdn".into(),
        "img".into(),
        "static".into(),
        "dev".into(),
        "test".into(),
        "stage".into(),
        "beta".into(),
        "admin".into(),
        "mail".into(),
    ]
}

/// Dynamic predictor:
/// Given discovered subdomains, extract first-label tokens and rank them by frequency.
/// Return top N (excluding ones already in base list) merged with a common service dictionary.
pub fn dynamic_extend(discovered: &[String], base: &[String], top_n: usize) -> Vec<String> {
    use std::collections::HashMap;
    let mut freq: HashMap<&str, u32> = HashMap::new();
    for d in discovered {
        if let Some(first) = d.split('.').next() {
            if first.len() >= 3 && first.len() <= 32 { *freq.entry(first).or_insert(0) += 1; }
        }
    }
    let mut items: Vec<(&str, u32)> = freq.into_iter().collect();
    items.sort_by(|a,b| b.1.cmp(&a.1));
    let mut out: Vec<String> = Vec::new();
    let base_set: std::collections::HashSet<&str> = base.iter().map(|s| s.as_str()).collect();
    for (label, _) in items.into_iter().take(top_n) {
        if !base_set.contains(label) { out.push(label.to_string()); }
    }
    // common service expansion
    let common = [
        "edge","gateway","console","dashboard","service","node","cluster","download","update","images",
        "assets","files","pkg","pkgcdn","client","backend","front","portal","account","user","auth",
        "oauth","sso","pay","payment","order","trade","shop","store","cart","data","db","cache",
        "redis","mysql","pgsql","elasticsearch","search","kibana","grafana","monitor","metrics","status",
        "health","log","logs","logging","report","analytics","stat","stats","event","events","message",
        "msg","queue","mq","rabbit","kafka","upload","dl","download","api2","api3","mobile","wap",
        "h5","web","webapp","mini","miniapp","internal","intra","secure","sec","security","scan","scanner"
    ];
    for c in common.iter() { if !base_set.contains(c) { out.push((*c).into()); } }
    out.sort(); out.dedup();
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn test_dynamic_extend() {
        let discovered = vec![
            "api.example.com".into(),
            "api.example.org".into(),
            "cdn.example.com".into(),
            "edge.example.com".into(),
            "edge.example.net".into(),
            "metrics.example.com".into(),
        ];
        let base = basic_seeds();
        let extended = dynamic_extend(&discovered, &base, 5);
        assert!(extended.contains(&"edge".into()));
        assert!(extended.contains(&"metrics".into()));
        // base seeds should not be duplicated
        assert!(!extended.contains(&"api".into()));
    }
}
use std::collections::HashSet;

/// Generate heuristic candidate labels based on an existing wordlist and some
/// common patterns. This is intentionally conservative and deterministic.
///
/// - `words`: existing base words (from wordlist/predict seeds)
/// - `max`: maximum number of heuristics to generate
pub fn generate_heuristics(words: &[String], max: usize) -> Vec<String> {
    let mut set: HashSet<String> = HashSet::new();

    // common environment/service tokens and regions
    let envs = ["prod","prod1","prod2","staging","stage","beta","dev","test","internal","qa","preprod"];
    let services = ["api","www","app","admin","portal","mail","ftp","cdn","static","img","svc","gateway"];
    let regions = ["us","eu","ap","cn","sg","jp","kr","in","br","ca"];
    let nums = ["1","2","01","02","03","2023","2024"];

    // helper to push unique; returns true if capacity reached
    fn push_unique(set: &mut HashSet<String>, s: String, max: usize) -> bool {
        if set.len() >= max { return true; }
        set.insert(s);
        set.len() >= max
    }

    // seed from supplied words: use first token chunks (split non-alnum)
    for w in words.iter().take(500) {
        if set.len() >= max { break; }
        let base = w.split(|c: char| !c.is_alphanumeric()).next().unwrap_or(w).trim();
        if base.is_empty() { continue; }
        if push_unique(&mut set, base.to_string(), max) { break; }
        for svc in services.iter() {
            if push_unique(&mut set, format!("{}{}", base, svc), max) { break; }
            if push_unique(&mut set, format!("{}-{}", base, svc), max) { break; }
        }
        if set.len() >= max { break; }
        for env in envs.iter() {
            if push_unique(&mut set, format!("{}-{}", base, env), max) { break; }
            if push_unique(&mut set, format!("{}{}", base, env), max) { break; }
        }
        if set.len() >= max { break; }
        for r in regions.iter() {
            if push_unique(&mut set, format!("{}-{}", base, r), max) { break; }
            if push_unique(&mut set, format!("{}{}", base, r), max) { break; }
        }
        if set.len() >= max { break; }
        for n in nums.iter() {
            if push_unique(&mut set, format!("{}{}", base, n), max) { break; }
        }
    }

    // cross-combine service+env and service+region
    for svc in services.iter() {
        if set.len() >= max { break; }
        for env in envs.iter() {
            if push_unique(&mut set, format!("{}-{}", svc, env), max) { break; }
            if set.len() >= max { break; }
        }
        if set.len() >= max { break; }
        for r in regions.iter() {
            if push_unique(&mut set, format!("{}-{}", svc, r), max) { break; }
            if set.len() >= max { break; }
        }
    }

    // final numeric suffixes on common services
    for svc in services.iter().take(10) {
        if set.len() >= max { break; }
        for n in nums.iter() {
            if push_unique(&mut set, format!("{}{}", svc, n), max) { break; }
            if set.len() >= max { break; }
        }
    }

    // return a stable Vec (sorted) up to max
    let mut v: Vec<String> = set.into_iter().collect();
    v.sort();
    v.truncate(max);
    v
}
