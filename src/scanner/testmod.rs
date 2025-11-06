use crate::options::Options;
use anyhow::Result;
use tokio::time::{Instant, Duration, timeout};
use crate::rawdns::udp_query_full;
use rand::{Rng, SeedableRng};
use rand_chacha::ChaCha20Rng;
use crate::resolver_pool::ResolverPool;
use crate::ratelimit::RateLimiter;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;

/// Measure approximate max UDP DNS send rate within a short time window.
/// Strategy:
/// 1. Use resolver pool to rotate resolvers.
/// 2. Fire synthetic queries for random subdomains under provided domains (or fallback to example.com if empty).
/// 3. Enforce a rate cap derived from band (if >0) via RateLimiter; if band=0 attempt best-effort uncontrolled send.
/// 4. Count sent, ok (answered with any record), nxdomain, timeouts/errors.
/// 5. Run for fixed window (default 3s) then print summary similar to ksubdomain test speed.
pub async fn run(opt: Options) -> Result<()> {
    let window_secs = 3u64; // fixed short window
    let start = Instant::now();
    let pool = ResolverPool::new(opt.resolvers.clone());
    pool.set_cooldown_secs(opt.resolver_cooldown_secs);
    let domains = if opt.domains.is_empty() { vec!["example.com".to_string()] } else { opt.domains.clone() };
    let rate_target = opt.rate.max(0); // if 0 => unlimited best effort
    let rl = if rate_target > 0 { Some(RateLimiter::new(rate_target)) } else { None };
    if let Some(r) = &rl { r.spawn_refill(); }
    let sent = Arc::new(AtomicUsize::new(0));
    let ok = Arc::new(AtomicUsize::new(0));
    let nxd = Arc::new(AtomicUsize::new(0));
    let timeouts = Arc::new(AtomicUsize::new(0));
    let errors = Arc::new(AtomicUsize::new(0));
    let mut handles = Vec::new();
    while start.elapsed() < Duration::from_secs(window_secs) {
        // optional rate limit token acquire
        if let Some(r) = &rl {
            let _permit = r.handle().acquire_owned().await.unwrap();
        }
        let pool_local = pool.clone();
        let domains_local = domains.clone();
        let sent_c = sent.clone();
        let ok_c = ok.clone();
        let nxd_c = nxd.clone();
        let to_c = timeouts.clone();
        let err_c = errors.clone();
        handles.push(tokio::spawn(async move {
            // Use a deterministic seed per task to keep Send safety (ChaCha20Rng is Send)
            let mut rng = ChaCha20Rng::from_entropy();
            let dom = domains_local[rng.gen_range(0..domains_local.len())].clone();
            let label: String = (0..8).map(|_| {
                let c = rng.gen_range(0u8..36u8);
                if c < 10 { (b'0'+c) as char } else { (b'a'+c-10) as char }
            }).collect();
            let host = format!("{}.{}", label, dom);
            if let Some(resolver) = pool_local.choose_random() {
                sent_c.fetch_add(1, Ordering::Relaxed);
                let timeout_ms = 1500; // tighter timeout for speed test
                let h = host.clone(); let r = resolver.clone();
                let fut = tokio::task::spawn_blocking(move || udp_query_full(&h, &r, timeout_ms));
                match timeout(Duration::from_millis(timeout_ms as u64 + 200), fut).await {
                    Ok(Ok(Ok(ans))) => {
                        match ans.rcode.as_str() {
                            "NXDomain" => { nxd_c.fetch_add(1, Ordering::Relaxed); },
                            "ServFail" | "Refused" | "TIMEOUT" => { err_c.fetch_add(1, Ordering::Relaxed); },
                            _ => {}
                        }
                        if !ans.records.is_empty() && ans.rcode != "NXDomain" {
                            ok_c.fetch_add(1, Ordering::Relaxed);
                        }
                    }
                    Ok(Ok(Err(_e))) => { err_c.fetch_add(1, Ordering::Relaxed); }
                    Ok(Err(_join)) => { err_c.fetch_add(1, Ordering::Relaxed); }
                    Err(_) => { to_c.fetch_add(1, Ordering::Relaxed); }
                }
            }
        }));
    }
    for h in handles { let _ = h.await; }
    let dur = start.elapsed();
    let s = dur.as_secs_f64();
    let sent_v = sent.load(Ordering::Relaxed) as f64;
    let ok_v = ok.load(Ordering::Relaxed) as f64;
    let nxd_v = nxd.load(Ordering::Relaxed) as f64;
    let to_v = timeouts.load(Ordering::Relaxed) as f64;
    let err_v = errors.load(Ordering::Relaxed) as f64;
    let pps = if s > 0.0 { sent_v / s } else { 0.0 };
    eprintln!("test-speed: window={}s sent={} (≈{:.0} pps) ok={} nxdomain={} timeouts={} errors={}", window_secs, sent_v as usize, pps, ok_v as usize, nxd_v as usize, to_v as usize, err_v as usize);
    Ok(())
}
