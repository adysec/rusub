use std::collections::HashMap;
use std::hash::Hasher;
use std::sync::{Arc};
use std::time::{Duration, SystemTime};
use tokio::sync::RwLock;
use std::sync::atomic::{AtomicI64, Ordering};
use tokio::sync::watch;
use tokio::time;
use fnv::FnvHasher;
use anyhow::Result;

#[derive(Clone, Debug)]
pub struct Item {
    pub domain: String,
    pub dns: String,
    pub time: SystemTime,
    pub retry: i32,
    pub domain_level: i32,
    pub state: EntryState,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum EntryState {
    Ok,
    WildFiltered,
    Failed,
}

struct DbShard {
    items: RwLock<HashMap<String, Item>>,
}

pub struct StatusDb {
    shards: Vec<Arc<DbShard>>,
    shard_count: usize,
    length: AtomicI64,
    expiration: Duration,
    cleanup_interval: Duration,
    stop_tx: Option<watch::Sender<bool>>,
}

impl StatusDb {
    pub fn create_memory_db() -> Arc<Self> {
        let shard_count = 64usize;
        let mut shards = Vec::with_capacity(shard_count);
        for _ in 0..shard_count {
            shards.push(Arc::new(DbShard { items: RwLock::new(HashMap::new()) }));
        }

        let (tx, mut rx) = watch::channel(false);

        let db = Arc::new(StatusDb {
            shards,
            shard_count,
            length: AtomicI64::new(0),
            expiration: Duration::from_secs(5 * 60),
            cleanup_interval: Duration::from_secs(3 * 60),
            stop_tx: Some(tx),
        });

        // spawn cleanup task
        let cloned = db.clone();
        tokio::spawn(async move {
            let mut ticker = time::interval(cloned.cleanup_interval);
            loop {
                tokio::select! {
                    _ = ticker.tick() => {
                        cloned.cleanup().await;
                    }
                    changed = rx.changed() => {
                        if changed.is_ok() {
                            if *rx.borrow() {
                                break;
                            }
                        } else {
                            break;
                        }
                    }
                }
            }
        });

        db
    }

    async fn cleanup(&self) {
        let now = SystemTime::now();
        let threshold = now.checked_sub(self.expiration).unwrap_or(SystemTime::UNIX_EPOCH);
        for shard in &self.shards {
            let mut map = shard.items.write().await;
            let keys: Vec<String> = map.iter()
                .filter_map(|(k, v)| {
                    if v.time < threshold { Some(k.clone()) } else { None }
                })
                .collect();
            for k in keys {
                if map.remove(&k).is_some() {
                    self.length.fetch_sub(1, Ordering::SeqCst);
                }
            }
        }
    }

    pub fn set_expiration(&mut self, d: Duration) {
        self.expiration = d;
    }

    fn get_shard(&self, domain: &str) -> Arc<DbShard> {
        let mut hasher = FnvHasher::default();
        hasher.write(domain.as_bytes());
        let idx = (hasher.finish() as usize) % self.shard_count;
        self.shards[idx].clone()
    }

    pub async fn add(&self, domain: String, table_data: Item) {
        let shard = self.get_shard(&domain);
        let mut map = shard.items.write().await;
        if !map.contains_key(&domain) {
            map.insert(domain.clone(), table_data);
            self.length.fetch_add(1, Ordering::SeqCst);
        } else {
            map.insert(domain.clone(), table_data);
        }
    }

    pub async fn set(&self, domain: String, table_data: Item) {
        let shard = self.get_shard(&domain);
        let mut map = shard.items.write().await;
        if !map.contains_key(&domain) {
            map.insert(domain.clone(), table_data);
            self.length.fetch_add(1, Ordering::SeqCst);
        } else {
            map.insert(domain.clone(), table_data);
        }
    }

    pub async fn get(&self, domain: &str) -> Option<Item> {
        let shard = self.get_shard(domain);
        let map = shard.items.read().await;
        map.get(domain).cloned()
    }

    pub fn length(&self) -> i64 {
        self.length.load(Ordering::SeqCst)
    }

    pub async fn del(&self, domain: &str) {
        let shard = self.get_shard(domain);
        let mut map = shard.items.write().await;
        if map.remove(domain).is_some() {
            self.length.fetch_sub(1, Ordering::SeqCst);
        }
    }

    pub async fn scan<F>(&self, mut f: F) where F: FnMut(&String, &Item) -> Result<()> {
        // collect snapshot
        let mut all: HashMap<String, Item> = HashMap::new();
        for shard in &self.shards {
            let map = shard.items.read().await;
            for (k, v) in map.iter() {
                all.insert(k.clone(), v.clone());
            }
        }
        for (k, v) in all.iter() {
            let _ = f(k, v);
        }
    }

    pub async fn snapshot(&self) -> Vec<Item> {
        let mut out: Vec<Item> = Vec::new();
        for shard in &self.shards {
            let map = shard.items.read().await;
            for (_k, v) in map.iter() {
                out.push(v.clone());
            }
        }
        out
    }

    pub fn close(&mut self) {
        if let Some(tx) = self.stop_tx.take() {
            let _ = tx.send(true);
        }
        // shards will be dropped automatically
    }
}
