use crate::statusdb::{StatusDb, Item, EntryState};
use anyhow::Result;
use serde::{Serialize, Deserialize};
use std::path::Path;
use std::time::{UNIX_EPOCH, Duration};
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
