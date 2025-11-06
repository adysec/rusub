use rand::seq::SliceRandom;
use std::collections::HashMap;
use std::sync::{Arc, Mutex};
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::time::{Duration, Instant};
use serde::Serialize;

struct ResolverInner {
    addr: String,
    ok: AtomicU64,
    fail: AtomicU64,
    disabled: AtomicBool,
    disabled_at: Mutex<Option<Instant>>,
}

impl ResolverInner {
    fn new(addr: String) -> Self {
        Self { addr, ok: AtomicU64::new(0), fail: AtomicU64::new(0), disabled: AtomicBool::new(false), disabled_at: Mutex::new(None) }
    }

    fn should_disable(&self) -> bool {
        let ok = self.ok.load(Ordering::Relaxed);
        let fail = self.fail.load(Ordering::Relaxed);
        // Simple heuristic:
        // - if total >= 20 and fail ratio > 0.8
        // - or fail >= 10 and ok == 0
        let total = ok + fail;
        if total >= 20 {
            let ratio = if total > 0 { (fail as f64) / (total as f64) } else { 0.0 };
            ratio > 0.8
        } else {
            fail >= 10 && ok == 0
        }
    }

    fn maybe_reenable(&self, cooldown_secs: u64) {
        if !self.disabled.load(Ordering::Relaxed) { return; }
        let mut guard = self.disabled_at.lock().unwrap();
        if let Some(ts) = *guard {
            if ts.elapsed() >= Duration::from_secs(cooldown_secs) {
                // reset counters softly and re-enable
                self.ok.store(0, Ordering::Relaxed);
                self.fail.store(0, Ordering::Relaxed);
                self.disabled.store(false, Ordering::Relaxed);
                *guard = None;
            }
        }
    }
}

pub struct ResolverPool {
    order: Mutex<Vec<Arc<ResolverInner>>>,
    map: Mutex<HashMap<String, Arc<ResolverInner>>>,
    on_disable: Mutex<Option<Arc<dyn Fn(String) + Send + Sync>>>,
    cooldown_secs: AtomicU64,
}

impl ResolverPool {
    pub fn new(list: Vec<String>) -> Arc<Self> {
        let mut order = Vec::with_capacity(list.len());
        let mut map = HashMap::with_capacity(list.len());
        for a in list.into_iter() {
            let arc = Arc::new(ResolverInner::new(a.clone()));
            order.push(arc.clone());
            map.insert(a, arc);
        }
        Arc::new(Self { order: Mutex::new(order), map: Mutex::new(map), on_disable: Mutex::new(None), cooldown_secs: AtomicU64::new(60) })
    }

    pub fn choose_random(&self) -> Option<String> {
        let order = self.order.lock().unwrap();
        // try re-enable disabled resolvers if cooldown elapsed
        let cooldown = self.cooldown_secs.load(Ordering::Relaxed);
        for r in order.iter() {
            r.maybe_reenable(cooldown);
        }
        let active: Vec<&Arc<ResolverInner>> = order.iter().filter(|r| !r.disabled.load(Ordering::Relaxed)).collect();
        let mut rng = rand::thread_rng();
        active.choose(&mut rng).map(|r| r.addr.clone())
    }

    pub fn report_ok(&self, addr: &str) {
        if let Some(item) = self.map.lock().unwrap().get(addr) {
            item.ok.fetch_add(1, Ordering::Relaxed);
        }
    }

    pub fn report_fail(&self, addr: &str) {
        if let Some(item) = self.map.lock().unwrap().get(addr) {
            item.fail.fetch_add(1, Ordering::Relaxed);
            if item.should_disable() {
                item.disabled.store(true, Ordering::Relaxed);
                *item.disabled_at.lock().unwrap() = Some(Instant::now());
                if let Some(cb) = self.on_disable.lock().unwrap().as_ref() {
                    cb(item.addr.clone());
                }
            }
        }
    }

    pub fn counts(&self) -> (usize, usize) {
        let order = self.order.lock().unwrap();
        let total = order.len();
        // Update disabled states based on cooldown before reporting counts
        let cooldown = self.cooldown_secs.load(Ordering::Relaxed);
        for r in order.iter() { r.maybe_reenable(cooldown); }
        let active = order.iter().filter(|r| !r.disabled.load(Ordering::Relaxed)).count();
        (active, total)
    }

    pub fn on_disable<F>(&self, cb: F)
    where F: Fn(String) + Send + Sync + 'static {
        *self.on_disable.lock().unwrap() = Some(Arc::new(cb));
    }

    pub fn set_cooldown_secs(&self, secs: u64) {
        self.cooldown_secs.store(secs, Ordering::Relaxed);
    }

    pub fn snapshot(&self) -> Vec<ResolverStat> {
        let order = self.order.lock().unwrap();
        order.iter().map(|r| ResolverStat {
            addr: r.addr.clone(),
            ok: r.ok.load(Ordering::Relaxed),
            fail: r.fail.load(Ordering::Relaxed),
            disabled: r.disabled.load(Ordering::Relaxed),
        }).collect()
    }
}

#[derive(Serialize)]
pub struct ResolverStat {
    pub addr: String,
    pub ok: u64,
    pub fail: u64,
    pub disabled: bool,
}

#[cfg(test)]
mod tests {
    use super::ResolverPool;
    use std::sync::Arc;
    use std::sync::atomic::{AtomicBool, Ordering};

    #[test]
    fn disable_on_many_fails_no_ok() {
        let pool = ResolverPool::new(vec!["1.1.1.1".to_string()]);
        for _ in 0..10 {
            pool.report_fail("1.1.1.1");
        }
        let (active, total) = pool.counts();
        assert_eq!(total, 1);
        assert_eq!(active, 0, "resolver should be disabled after 10 fails and 0 ok");
    }

    #[test]
    fn disable_on_high_fail_ratio() {
        let pool = ResolverPool::new(vec!["8.8.8.8".to_string()]);
        let fired = Arc::new(AtomicBool::new(false));
        {
            let fired_c = fired.clone();
            *pool.on_disable.lock().unwrap() = Some(Arc::new(move |a: String| {
                println!("resolver disabled: {}", a);
                fired_c.store(true, Ordering::Relaxed);
            }));
        }
        for _ in 0..90 { pool.report_fail("8.8.8.8"); }
        for _ in 0..10 { pool.report_ok("8.8.8.8"); }
        let (active, _total) = pool.counts();
        assert_eq!(active, 0, "resolver should be disabled when fail ratio > 0.8 with total >= 20");
        assert!(fired.load(Ordering::Relaxed));
    }

    #[test]
    fn reenable_after_cooldown() {
        let pool = ResolverPool::new(vec!["1.0.0.1".to_string()]);
        pool.set_cooldown_secs(1);
        for _ in 0..10 { pool.report_fail("1.0.0.1"); }
        let (active0, _) = pool.counts();
        assert_eq!(active0, 0, "should be disabled initially");
        std::thread::sleep(std::time::Duration::from_millis(1100));
        // trigger maybe_reenable via choose_random/counts
        let _ = pool.choose_random();
        let (active1, _) = pool.counts();
        assert_eq!(active1, 1, "should be re-enabled after cooldown");
    }
}
