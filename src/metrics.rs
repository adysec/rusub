use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use tokio::time::{interval, Duration, Instant};
use std::io::{stderr, Write};
use crate::resolver_pool::ResolverPool;
use serde::Serialize;

#[derive(Default)]
pub struct Metrics {
    pub sent: AtomicU64,
    pub ok: AtomicU64,
    pub filtered: AtomicU64,
    pub failed: AtomicU64,
    pub total: AtomicU64,
    pub fallback: AtomicU64,
    pub skipped: AtomicU64,
    pub nxdomain: AtomicU64,
    pub servfail: AtomicU64,
    pub refused: AtomicU64,
    pub timeouts: AtomicU64,
}

impl Metrics {
    pub fn new() -> Arc<Self> { Arc::new(Self::default()) }
}

fn colorize(enabled: bool, code: &str, s: String) -> String {
    if enabled { format!("\x1b[{}m{}\x1b[0m", code, s) } else { s }
}

pub fn spawn_reporter(m: Arc<Metrics>, interval_secs: u64, wide: bool, color: bool, legacy: bool, pool: Option<Arc<ResolverPool>>) {
    tokio::spawn(async move {
        use std::collections::VecDeque;
        let mut last_sent = 0u64;
        let mut last_ok = 0u64;
        let mut last_err = 0u64; // recent window for (timeouts+servfail+refused)
        let mut win: VecDeque<u64> = VecDeque::new();
        let start = Instant::now();
        let mut tick = interval(Duration::from_secs(interval_secs.max(1)));
        loop {
            tick.tick().await;
            let total = m.total.load(Ordering::Relaxed);
            let sent = m.sent.load(Ordering::Relaxed);
            let ok = m.ok.load(Ordering::Relaxed);
            let filtered = m.filtered.load(Ordering::Relaxed);
            let failed = m.failed.load(Ordering::Relaxed);
            let fallback = m.fallback.load(Ordering::Relaxed);
            let skipped = m.skipped.load(Ordering::Relaxed);
            let err_sum = m.timeouts.load(Ordering::Relaxed)
                + m.servfail.load(Ordering::Relaxed)
                + m.refused.load(Ordering::Relaxed);
            let finished = ok + filtered + failed + skipped;
            let d_sent = sent.saturating_sub(last_sent);
            let d_ok = ok.saturating_sub(last_ok);
            let d_err = err_sum.saturating_sub(last_err);
            last_sent = sent; last_ok = ok;
            last_err = err_sum;

            // ETA 估算：剩余 = total - finished，速率 ~ d_sent / interval
            let rate = d_sent as f64 / (interval_secs.max(1) as f64);
            // sliding window average rate over last up to 5 ticks
            win.push_back(d_sent);
            if win.len() > 5 { win.pop_front(); }
            let sum_win: u64 = win.iter().sum();
            let rate_avg = (sum_win as f64) / (win.len().max(1) as f64) / (interval_secs.max(1) as f64);
            let remain = if total > finished { total - finished } else { 0 } as f64;
            let eta_secs = if rate > 0.0 { (remain / rate) as u64 } else { 0 };
            let percent = if total > 0 { (finished as f64 / total as f64) * 100.0 } else { 0.0 };
            let inflight = sent.saturating_sub(finished);
            let elapsed = start.elapsed().as_secs();

            let mut err = stderr();
            let res_info = if let Some(ref p) = pool { 
                let (active, total) = p.counts();
                let disabled = total.saturating_sub(active);
                let frac = if total > 0 { (disabled as f64)/(total as f64) } else { 0.0 };
                format!(" res={}/{} dis={:.0}%", active, total, frac*100.0)
            } else { String::new() };

            if legacy {
                // Legacy condensed layout (compact columns)
                let pct = colorize(color, "32", format!("{:>5.1}%", percent));
                let rat = colorize(color, "33", format!("{:.0}", rate));
                let nx = m.nxdomain.load(Ordering::Relaxed);
                let _ = write!(
                    err,
                    "\r[statL] {} | ok={} fail={} filt={} nx={} sent={} rate/s={} ETA={}s{}",
                    pct, ok, failed, filtered, nx, sent, rat, eta_secs, res_info
                );
            } else if wide {
                let pct = colorize(color, "32", format!("{:>5.1}%", percent)); // green
                let rat = colorize(color, "33", format!("{:.0}", rate)); // yellow
                let rat_avg = colorize(color, "33", format!("{:.0}", rate_avg));
                let okc = colorize(color, "32", format!("{} (+{})", ok, d_ok)); // green
                let failc = colorize(color, "31", format!("{}", failed)); // red
                let filt = colorize(color, "36", format!("{}", filtered)); // cyan
                let nx = m.nxdomain.load(Ordering::Relaxed);
                let sf = m.servfail.load(Ordering::Relaxed);
                let rf = m.refused.load(Ordering::Relaxed);
                let to = m.timeouts.load(Ordering::Relaxed);
                let err_rate = if d_sent > 0 { (d_err as f64)/(d_sent as f64) } else { 0.0 };
                let err_total = if sent > 0 { (err_sum as f64)/(sent as f64) } else { 0.0 };
                let err_rate_str = colorize(color, "35", format!("{:.2}", err_rate)); // magenta recent
                let err_total_str = colorize(color, "35", format!("{:.2}", err_total)); // magenta total
                let _ = write!(
                    err,
                    "\r[statW] {} | total={} fin={} inflight={} sent={} (+{}) ok={} filt={} fail={} skipped={} rate/s={} (avg {}) er={} tot={} fallback={} errs={}/{}/{}/{} ETA={}s elapsed={}s{}",
                    pct, total, finished, inflight, sent, d_sent, okc, filt, failc, skipped, rat, rat_avg, err_rate_str, err_total_str, fallback, nx, sf, rf, to, eta_secs, elapsed, res_info
                );
            } else {
                let pct = colorize(color, "32", format!("{:>5.1}%", percent));
                let rat = colorize(color, "33", format!("{:.0}", rate));
                let _ = write!(
                    err,
                    "\r[stat] {} | total={} fin={} sent={} (+{}) ok={} (+{}) filt={} fail={} skipped={} rate/s={} fallback={} ETA={}s{}",
                    pct, total, finished, sent, d_sent, ok, d_ok, filtered, failed, skipped, rat, fallback, eta_secs, res_info
                );
            }
            let _ = err.flush();
        }
    });
}

#[derive(Serialize)]
pub struct ProgressSnapshot {
    pub total: u64,
    pub sent: u64,
    pub ok: u64,
    pub filtered: u64,
    pub failed: u64,
    pub skipped: u64,
    pub nxdomain: u64,
    pub servfail: u64,
    pub refused: u64,
    pub timeouts: u64,
    pub rate: f64,
    pub rate_avg: f64,
    pub eta_secs: u64,
    pub percent: f64,
    pub inflight: u64,
    pub elapsed: u64,
    pub resolvers_active: Option<u64>,
    pub resolvers_total: Option<u64>,
    pub resolvers_disabled_pct: Option<f64>,
    pub error_rate_recent: f64,
    pub error_rate_total: f64,
}

pub fn spawn_json_reporter(m: Arc<Metrics>, interval_secs: u64, pool: Option<Arc<ResolverPool>>, path: std::path::PathBuf) {
    tokio::spawn(async move {
        use std::collections::VecDeque;
    let mut last_sent = 0u64;
    let mut last_err = 0u64; // recent window for (timeouts+servfail+refused)
        let start = Instant::now();
        let mut win: VecDeque<u64> = VecDeque::new();
        let mut tick = interval(Duration::from_secs(interval_secs.max(1)));
        loop {
            tick.tick().await;
            let total = m.total.load(Ordering::Relaxed);
            let sent = m.sent.load(Ordering::Relaxed);
            let ok = m.ok.load(Ordering::Relaxed);
            let filtered = m.filtered.load(Ordering::Relaxed);
            let failed = m.failed.load(Ordering::Relaxed);
            let skipped = m.skipped.load(Ordering::Relaxed);
            let nxdomain = m.nxdomain.load(Ordering::Relaxed);
            let servfail = m.servfail.load(Ordering::Relaxed);
            let refused = m.refused.load(Ordering::Relaxed);
            let timeouts = m.timeouts.load(Ordering::Relaxed);
            let finished = ok + filtered + failed + skipped;
            let err_sum = m.timeouts.load(Ordering::Relaxed)
                + m.servfail.load(Ordering::Relaxed)
                + m.refused.load(Ordering::Relaxed);
            let d_sent = sent.saturating_sub(last_sent);
            let d_err = err_sum.saturating_sub(last_err);
            last_sent = sent;
            last_err = err_sum;

            win.push_back(d_sent);
            if win.len() > 5 { win.pop_front(); }
            let sum_win: u64 = win.iter().sum();
            let rate = d_sent as f64 / (interval_secs.max(1) as f64);
            let rate_avg = (sum_win as f64) / (win.len().max(1) as f64) / (interval_secs.max(1) as f64);
            let remain = if total > finished { total - finished } else { 0 } as f64;
            let eta_secs = if rate > 0.0 { (remain / rate) as u64 } else { 0 };
            let percent = if total > 0 { (finished as f64 / total as f64) * 100.0 } else { 0.0 };
            let inflight = sent.saturating_sub(finished);
            let elapsed = start.elapsed().as_secs();

            let (resolvers_active, resolvers_total, resolvers_disabled_pct) = if let Some(ref p) = pool {
                let (a, t) = p.counts();
                let d = t.saturating_sub(a);
                let frac = if t > 0 { (d as f64)/(t as f64) } else { 0.0 };
                (Some(a as u64), Some(t as u64), Some(frac*100.0))
            } else { (None, None, None) };

            let err_total = if sent > 0 { (err_sum as f64)/(sent as f64) } else { 0.0 };
            let snap = ProgressSnapshot {
                total, sent, ok, filtered, failed, skipped, nxdomain, servfail, refused, timeouts,
                rate, rate_avg, eta_secs, percent, inflight, elapsed,
                resolvers_active, resolvers_total, resolvers_disabled_pct,
                error_rate_recent: if d_sent > 0 { (d_err as f64)/(d_sent as f64) } else { 0.0 },
                error_rate_total: err_total,
            };
            if let Ok(data) = serde_json::to_vec_pretty(&snap) {
                let _ = tokio::fs::write(&path, data).await;
            }
        }
    });
}
