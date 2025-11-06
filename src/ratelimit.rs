use std::sync::Arc;
use std::sync::atomic::{AtomicI64, Ordering};
use tokio::sync::Semaphore;
use tokio::time::{interval, Duration};

/// 简单令牌桶: 每秒补充 `rate` 令牌，容量为 `rate`，消费时 acquire 一个 permit。
#[derive(Clone)]
pub struct RateLimiter {
    sem: Arc<Semaphore>,
    rate: Arc<AtomicI64>,
}

impl RateLimiter {
    pub fn new(rate: i64) -> Self {
        let sem = Arc::new(Semaphore::new(0)); // 初始为空，避免冷启动瞬间洪水
        Self { sem, rate: Arc::new(AtomicI64::new(rate.max(0))) }
    }

    pub fn handle(&self) -> Arc<Semaphore> { self.sem.clone() }

    pub fn spawn_refill(&self) {
        let sem = self.sem.clone();
        let rate = self.rate.clone();
        tokio::spawn(async move {
            let mut tick = interval(Duration::from_secs(1));
            loop {
                tick.tick().await;
                // 补充，不超过容量 (rate)
                let rate = rate.load(Ordering::Relaxed);
                let available = sem.available_permits() as i64;
                let to_add = (rate - available).max(0);
                if to_add > 0 {
                    sem.add_permits(to_add as usize);
                }
            }
        });
    }

    pub fn set_rate(&self, new_rate: i64) {
        let r = new_rate.max(0);
        self.rate.store(r, Ordering::Relaxed);
    }

    pub fn get_rate(&self) -> i64 { self.rate.load(Ordering::Relaxed) }
}
