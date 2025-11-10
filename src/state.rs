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

// ===== statusdb persistence (originally statusdb_persist.rs) =====
use serde::{Serialize, Deserialize};
use std::path::Path;
use std::time::UNIX_EPOCH;
use tokio::fs;

#[derive(Serialize, Deserialize, Clone, Debug)]
struct PersistItem {
    domain: String,
    dns: String,
    retry: i32,
    domain_level: i32,
    state: String,
    ts_sec: u64,
}

fn state_to_string(s: &EntryState) -> String {
    match s {
        EntryState::Ok => "Ok".into(),
        EntryState::WildFiltered => "WildFiltered".into(),
        EntryState::Failed => "Failed".into(),
    }
}

fn string_to_state(s: &str) -> EntryState {
    match s {
        "Ok" => EntryState::Ok,
        "WildFiltered" => EntryState::WildFiltered,
        _ => EntryState::Failed,
    }
}

pub async fn save_to_file(db: &StatusDb, path: &Path) -> Result<()> {
    let items = db.snapshot().await;
    let mut out: Vec<PersistItem> = Vec::with_capacity(items.len());
    for it in items.into_iter() {
        let ts = it.time.duration_since(UNIX_EPOCH).unwrap_or(Duration::from_secs(0)).as_secs();
        out.push(PersistItem {
            domain: it.domain,
            dns: it.dns,
            retry: it.retry,
            domain_level: it.domain_level,
            state: state_to_string(&it.state),
            ts_sec: ts,
        });
    }
    let data = serde_json::to_vec_pretty(&out)?;
    if let Some(parent) = path.parent() { if !parent.as_os_str().is_empty() { let _ = fs::create_dir_all(parent).await; } }
    fs::write(path, data).await?;
    Ok(())
}

pub async fn load_from_file(db: &StatusDb, path: &Path) -> Result<usize> {
    if !path.exists() { return Ok(0); }
    let data = fs::read(path).await?;
    let list: Vec<PersistItem> = match serde_json::from_slice(&data) {
        Ok(v) => v,
        Err(_) => Vec::new(),
    };
    let mut n = 0usize;
    for p in list.into_iter() {
        let t = UNIX_EPOCH + Duration::from_secs(p.ts_sec);
        let item = Item { domain: p.domain.clone(), dns: p.dns.clone(), time: t, retry: p.retry, domain_level: p.domain_level, state: string_to_state(&p.state) };
        db.add(p.domain, item).await;
        n += 1;
    }
    Ok(n)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::statusdb::{StatusDb, Item, EntryState};
    use std::time::SystemTime;

    #[tokio::test]
    async fn persist_roundtrip() {
        let db = StatusDb::create_memory_db();
        let now = SystemTime::now();
        db.add("a.example".into(), Item { domain: "a.example".into(), dns: "8.8.8.8".into(), time: now, retry: 0, domain_level: 0, state: EntryState::Ok }).await;
        db.add("b.example".into(), Item { domain: "b.example".into(), dns: "1.1.1.1".into(), time: now, retry: 1, domain_level: 0, state: EntryState::WildFiltered }).await;
        let path = std::path::PathBuf::from("/tmp/rusub_status_rt.json");
        if path.exists() { let _ = std::fs::remove_file(&path); }
        save_to_file(&db, &path).await.expect("save ok");
        let db2 = StatusDb::create_memory_db();
        let n = load_from_file(&db2, &path).await.expect("load ok");
        assert_eq!(n, 2);
        let a = db2.get("a.example").await.unwrap();
        assert!(matches!(a.state, EntryState::Ok));
        let b = db2.get("b.example").await.unwrap();
        assert!(matches!(b.state, EntryState::WildFiltered));
        let _ = std::fs::remove_file(&path);
    }
}
