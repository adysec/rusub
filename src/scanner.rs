use crate::options::Options;
use anyhow::Result;
use std::fs::File;
use std::io::{BufRead, BufReader};
use std::path::PathBuf;
use std::sync::Arc;
use tokio::sync::Semaphore;
use futures::stream::{FuturesUnordered, StreamExt};
use tokio::net::lookup_host;
// rand was previously used for direct resolver randomization; now handled inside ResolverPool
// (remove unused imports)
use crate::dns::udp_query_full;
use crate::output::{ScanResult, ScanRecord, build_writers};
use crate::wildcard::{detect_wildcard, is_wildcard};
use std::sync::Mutex;
use tokio::time::{timeout, Duration};
use crate::ratelimit::RateLimiter;
use crate::discovery;
use crate::metrics::{Metrics, spawn_reporter, spawn_json_reporter};
use crate::resolver_pool::ResolverPool;
use crate::state::{StatusDb, Item, EntryState};

async fn read_wordlist(path: &Option<PathBuf>) -> Result<Vec<String>> {
    if let Some(p) = path {
        let mut words = Vec::new();
        let f = File::open(p)?;
        for line in BufReader::new(f).lines() {
            if let Ok(l) = line {
                let s = l.trim();
                if s.is_empty() || s.starts_with('#') { continue; }
                words.push(s.to_string());
            }
        }
        Ok(words)
    } else {
        // 使用内置 dicts 模块减少 I/O
        Ok(crate::dicts::default_wordlist())
    }
}

pub async fn run(opt: Options) -> Result<()> {
    let mut words = read_wordlist(&opt.filename).await?;
    
    if opt.predict {
        let mut seeds = discovery::basic_seeds();
        let dyn_ext: Vec<String> = discovery::dynamic_extend(&[], &seeds, 32);
        seeds.extend(dyn_ext);
        words.append(&mut seeds);
        words.sort(); words.dedup();
    }
    //启发式扩展（基于现有词表和常见 token），可配置最大条数
    if opt.heuristic {
        let max = opt.heuristic_max.max(1);
        let mut h = discovery::generate_heuristics(&words, max);
        words.append(&mut h);
        words.sort(); words.dedup();
    }
    let discovered = Arc::new(Mutex::new(Vec::<String>::new()));
    let word_set = Arc::new(Mutex::new(words.iter().cloned().collect::<std::collections::HashSet<String>>()));
    let sem = Arc::new(Semaphore::new(opt.concurrency));
    // rate limiter based on packets-per-second (derived from band)
    let rl = RateLimiter::new(opt.rate.max(0));
    rl.spawn_refill();
    let rl_sem = rl.handle();
    // metrics & status db
    let metrics = Metrics::new();
    let scan_start = tokio::time::Instant::now();
    let status_db = StatusDb::create_memory_db();
    // load persisted status if configured
    if let Some(path) = &opt.status_file {
        match crate::state::load_from_file(&status_db, path).await {
            Ok(n) => { if !opt.silent && !opt.pure_output { eprintln!("[statusdb] loaded {} entries from {}", n, path.display()); } },
            Err(e) => { if !opt.pure_output { eprintln!("[statusdb] load error: {}", e); } }
        }
    }
    // total = words * domains (initial pass)
    let total_tasks = (words.len() as u64) * (opt.domains.len() as u64);
    metrics.total.store(total_tasks, std::sync::atomic::Ordering::Relaxed);
    // init resolver pool and base resolver list for wildcard detection
    let resolver_pool = ResolverPool::new(opt.resolvers.clone());
    resolver_pool.set_cooldown_secs(opt.resolver_cooldown_secs);
    let base_resolvers = opt.resolvers.clone();
    // log when a resolver gets disabled by health heuristics
    if !opt.pure_output {
        resolver_pool.on_disable(move |addr| {
            eprintln!("\n[resolver] disabled {}", addr);
        });
    }
    if !opt.silent && opt.progress { spawn_reporter(metrics.clone(), opt.progress_interval, opt.progress_wide, opt.progress_color, opt.progress_legacy, Some(resolver_pool.clone())); }
    // progress json reporter
    if let (Some(path), interval) = (&opt.progress_json_file, opt.progress_json_interval) {
        if interval > 0 && !opt.pure_output { spawn_json_reporter(metrics.clone(), interval, Some(resolver_pool.clone()), path.clone()); }
    }
    // adaptive rate controller
    if opt.adaptive_rate && !opt.pure_output {
        let metrics_a = metrics.clone();
        let rl_a = rl.clone();
        let min_r = opt.adaptive_min_rate;
        let max_r = opt.adaptive_max_rate.max(opt.rate);
        let err_thr = opt.adaptive_error_threshold.max(0.01);
        let dec_f = opt.adaptive_dec_factor.clamp(0.1, 0.99);
        let inc_f = opt.adaptive_inc_factor.clamp(1.0, 1.5);
        tokio::spawn(async move {
            use std::sync::atomic::Ordering;
            let mut tick = tokio::time::interval(Duration::from_secs(opt.progress_interval.max(1)*2));
            let mut last_sent = metrics_a.sent.load(Ordering::Relaxed);
            let mut last_err = metrics_a.timeouts.load(Ordering::Relaxed)
                + metrics_a.servfail.load(Ordering::Relaxed)
                + metrics_a.refused.load(Ordering::Relaxed);
            loop {
                tick.tick().await;
                let sent_now = metrics_a.sent.load(Ordering::Relaxed);
                let err_now = metrics_a.timeouts.load(Ordering::Relaxed)
                    + metrics_a.servfail.load(Ordering::Relaxed)
                    + metrics_a.refused.load(Ordering::Relaxed);
                let d_sent = sent_now.saturating_sub(last_sent) as f64;
                let d_err = err_now.saturating_sub(last_err) as f64;
                last_sent = sent_now; last_err = err_now;
                if d_sent < 100.0 { continue; } // insufficient sample
                let err_rate = d_err / d_sent;
                let current = rl_a.get_rate();
                let new_rate = if err_rate > err_thr {
                    (current as f64 * dec_f).floor() as i64
                } else {
                    (current as f64 * inc_f).ceil() as i64
                }.clamp(min_r, max_r);
                if new_rate != current { rl_a.set_rate(new_rate); }
            }
        });
    }
    // spawn periodic flush if configured
    let flush_task = if let (Some(path), interval) = (&opt.status_file, opt.status_flush_interval) {
        if interval > 0 {
            let db = status_db.clone();
            let p = path.clone();
            let silent = opt.silent;
            let pure = opt.pure_output;
            Some(tokio::spawn(async move {
                let mut tick = tokio::time::interval(Duration::from_secs(interval));
                loop {
                    tick.tick().await;
                    if let Err(e) = crate::state::save_to_file(&db, &p).await {
                        if !pure { eprintln!("[statusdb] periodic save error: {}", e); }
                    } else if !silent && !pure {
                        eprintln!("[statusdb] periodic saved to {}", p.display());
                    }
                }
            }))
        } else { None }
    } else { None };

    // periodic resolver stats if configured
    let stats_task = if let (Some(path), interval) = (&opt.resolver_stats_file, opt.resolver_stats_interval) {
        if interval > 0 {
            let pool_c = resolver_pool.clone();
            let p = path.clone();
            let pure = opt.pure_output;
            Some(tokio::spawn(async move {
                let mut tick = tokio::time::interval(Duration::from_secs(interval));
                loop {
                    tick.tick().await;
                    let snap = pool_c.snapshot();
                    if let Ok(data) = serde_json::to_vec_pretty(&snap) {
                        let _ = tokio::fs::write(&p, data).await;
                    }
                    if pure { continue; }
                }
            }))
        } else { None }
    } else { None };

    let mut tasks = FuturesUnordered::new();
    let writers = std::sync::Arc::new(build_writers(opt.output.clone(), &opt.output_type, !opt.not_print, opt.detail_records, opt.gzip, opt.append)?);

    // resolver pool created above
    for domain in opt.domains.iter() {
        let domain = domain.trim().trim_end_matches('.').to_string();
        // wildcard detection per root domain
        let wild_ips = match opt.wild_filter_mode.to_lowercase().as_str() {
            "basic" => detect_wildcard(&domain, &base_resolvers, 3, opt.timeout),
            "advanced" => crate::wildcard::detect_wildcard_advanced(&domain, &base_resolvers, 6, opt.timeout, 0.6),
            _ => std::collections::HashSet::new(),
        };
        for w in words.iter() {
            let sub = w;
            let mut host = String::with_capacity(sub.len() + 1 + domain.len());
            host.push_str(sub);
            host.push('.');
            host.push_str(&domain);
            let permit = sem.clone().acquire_owned().await.unwrap();
            // show_all: 是否输出失败/空/NXDOMAIN；only_alive=true 时仅输出有记录成功项
            let show_all = !opt.not_print && !opt.only_alive;

                let writers = writers.clone();
            let pool_local = resolver_pool.clone();
            let status_db_task = status_db.clone();
            let wild_ips_local = wild_ips.clone();
            let rl_sem_task = rl_sem.clone();
            let metrics_task = metrics.clone();
            let discovered_local = discovered.clone();
            tasks.push(tokio::spawn(async move {
                let _p = permit;
                let mut attempt = 0i32;
                let mut success = false;
                let smart_protect = opt.retry == 0; // --retry 0 时，临时错误智能补偿一次
                // cache check: skip if already known OK or wildcard
                if let Some(it) = status_db_task.get(&host).await {
                    if it.state == EntryState::Ok || it.state == EntryState::WildFiltered {
                        metrics_task.skipped.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                        return;
                    }
                }
                while opt.retry < 0 || attempt <= opt.retry || (smart_protect && attempt < 2) {
                    attempt += 1;
                    // 速率控制: 消耗一个令牌
                    // 每个查询消耗一个令牌 (Semaphore 单次 acquire)
                    let _rp = rl_sem_task.clone().acquire_owned().await.unwrap();
                    // Prefer raw UDP DNS query against a random resolver; fallback to system resolver
                    metrics_task.sent.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                    let resolver_opt = pool_local.choose_random();
                    if let Some(resolver) = resolver_opt {
                        let timeout_ms = opt.timeout * 1000;
                        let h = host.clone();
                        let r = resolver.clone();
                        let fut = tokio::task::spawn_blocking(move || udp_query_full(&h, &r, timeout_ms));
                        match timeout(Duration::from_secs(opt.timeout), fut).await {
                            Ok(Ok(Ok(ans))) => {
                                // classify by rcode for metrics and behavior
                                let mut penalized = false;
                                match ans.rcode.as_str() {
                                    "NXDomain" => { metrics_task.nxdomain.fetch_add(1, std::sync::atomic::Ordering::Relaxed); }
                                    "ServFail" => { metrics_task.servfail.fetch_add(1, std::sync::atomic::Ordering::Relaxed); penalized = true; }
                                    "Refused" => { metrics_task.refused.fetch_add(1, std::sync::atomic::Ordering::Relaxed); penalized = true; }
                                    "TIMEOUT" => { metrics_task.timeouts.fetch_add(1, std::sync::atomic::Ordering::Relaxed); penalized = true; }
                                    _ => {}
                                }
                                if penalized { pool_local.report_fail(&resolver); }
                                if ans.rcode == "NXDomain" {
                                    // definitive negative answer: don't penalize resolver; no retry
                                    success = false; break;
                                }
                                if !ans.records.is_empty() {
                                    let mut ips: Vec<String> = ans.records.iter()
                                        .filter(|r| r.rtype == "A" || r.rtype == "AAAA")
                                        .map(|r| r.data.clone()).collect();
                                    ips.sort(); ips.dedup();
                                        if !is_wildcard(&ips, &wild_ips_local) {
                                        let typed: Vec<ScanRecord> = ans.records.into_iter().map(|r| ScanRecord { rtype: r.rtype, data: r.data }).collect();
                                        let res = ScanResult { subdomain: host.clone(), answers: ips, records: Some(typed) };
                                        for ow in writers.iter() { let _ = ow.write(&res); }
                                        metrics_task.ok.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                                        let item = Item { domain: host.clone(), dns: resolver.clone(), time: std::time::SystemTime::now(), retry: attempt as i32, domain_level: 0, state: EntryState::Ok };
                                        status_db_task.add(host.clone(), item).await;
                                        pool_local.report_ok(&resolver);
                                        discovered_local.lock().unwrap().push(host.clone());
                                        success = true; break;
                                    } else {
                                        metrics_task.filtered.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                                        let item = Item { domain: host.clone(), dns: resolver.clone(), time: std::time::SystemTime::now(), retry: attempt as i32, domain_level: 0, state: EntryState::WildFiltered };
                                        status_db_task.add(host.clone(), item).await;
                                        // wildcard filtered: treat as definitive non-result; stop retrying
                                        break;
                                    }
                                } else {
                                    // empty answer considered failure -> retry (penalize only if not already)
                                    if !penalized { pool_local.report_fail(&resolver); }
                                    let item = Item { domain: host.clone(), dns: resolver.clone(), time: std::time::SystemTime::now(), retry: attempt as i32, domain_level: 0, state: EntryState::Failed };
                                    status_db_task.set(host.clone(), item).await;
                                }
                            }
                            _ => { pool_local.report_fail(&resolver); /* timeout or join error -> retry */ }
                        }
                    } else {
                        // fallback system resolver (unlikely since we supply defaults)
                        metrics_task.fallback.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                        let target = format!("{}:0", host);
                        let dur = Duration::from_secs(opt.timeout);
                        match timeout(dur, lookup_host(target)).await {
                            Ok(Ok(addrs)) => {
                                let mut ips: Vec<String> = addrs.map(|sa| sa.ip().to_string()).collect();
                                ips.sort(); ips.dedup();
                                let res = ScanResult { subdomain: host.clone(), answers: ips, records: None };
                                for ow in writers.iter() { let _ = ow.write(&res); }
                                let item = Item { domain: host.clone(), dns: "system".into(), time: std::time::SystemTime::now(), retry: attempt as i32, domain_level: 0, state: EntryState::Ok };
                                status_db_task.add(host.clone(), item).await;
                                discovered_local.lock().unwrap().push(host.clone());
                                success = true; break; // system path success not attributed to pool
                            }
                            _ => {}
                        }
                    }
                    if opt.retry >= 0 && attempt > opt.retry {
                        if smart_protect && attempt == 1 { continue; } else { break; }
                    }
                }
                if !success && show_all {
                    let res = ScanResult { subdomain: host.clone(), answers: vec![], records: None };
                    for ow in writers.iter() { let _ = ow.write(&res); }
                    metrics_task.failed.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                    let item = Item { domain: host.clone(), dns: "".into(), time: std::time::SystemTime::now(), retry: attempt as i32, domain_level: 0, state: EntryState::Failed };
                    status_db_task.set(host.clone(), item).await;
                }
            }));
        }
    }

    while let Some(res) = tasks.next().await {
        if let Err(e) = res { eprintln!("task join error: {}", e); }
    }

    // iterative dynamic predictor expansion
    if opt.predict && opt.predict_rounds > 0 {
        for _round in 0..opt.predict_rounds {
            let snapshot = discovered.lock().unwrap().clone();
            if snapshot.is_empty() { break; }
            let base = discovery::basic_seeds();
            let mut new_seeds = discovery::dynamic_extend(&snapshot, &base, opt.predict_topn.max(1));
            new_seeds.retain(|s| !word_set.lock().unwrap().contains(s));
            if new_seeds.is_empty() { break; }
            let additional = (new_seeds.len() as u64) * (opt.domains.len() as u64);
            metrics.total.fetch_add(additional, std::sync::atomic::Ordering::Relaxed);
            for domain in opt.domains.iter() {
                let domain = domain.trim().trim_end_matches('.').to_string();
                let wild_ips = match opt.wild_filter_mode.to_lowercase().as_str() {
                    "basic" => detect_wildcard(&domain, &base_resolvers, 3, opt.timeout),
                    "advanced" => crate::wildcard::detect_wildcard_advanced(&domain, &base_resolvers, 6, opt.timeout, 0.6),
                    _ => std::collections::HashSet::new(),
                };
                for s in new_seeds.iter() {
                    word_set.lock().unwrap().insert(s.clone());
                    let mut host = String::with_capacity(s.len() + 1 + domain.len());
                    host.push_str(s);
                    host.push('.');
                    host.push_str(&domain);
                    let permit = sem.clone().acquire_owned().await.unwrap();
                    let show_all = !opt.not_print && !opt.only_alive;
                    let writers = writers.clone();
                    let pool_local = resolver_pool.clone();
                    let status_db_task = status_db.clone();
                    let wild_ips_local = wild_ips.clone();
                    let rl_sem_task = rl_sem.clone();
                    let metrics_task = metrics.clone();
                    let discovered_local = discovered.clone();
                    tasks.push(tokio::spawn(async move {
                        let _p = permit;
                        let mut attempt = 0i32;
                        let mut success = false;
                        let smart_protect = opt.retry == 0; // 预测阶段同样启用智能补偿
                        if let Some(it) = status_db_task.get(&host).await {
                            if it.state == EntryState::Ok || it.state == EntryState::WildFiltered {
                                metrics_task.skipped.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                                return;
                            }
                        }
                        while opt.retry < 0 || attempt <= opt.retry || (smart_protect && attempt < 2) {
                            attempt += 1;
                            let _rp = rl_sem_task.clone().acquire_owned().await.unwrap();
                            metrics_task.sent.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                            let resolver_opt = pool_local.choose_random();
                            if let Some(resolver) = resolver_opt {
                                let timeout_ms = opt.timeout * 1000;
                                let h = host.clone();
                                let r = resolver.clone();
                                let fut = tokio::task::spawn_blocking(move || udp_query_full(&h, &r, timeout_ms));
                                match timeout(Duration::from_secs(opt.timeout), fut).await {
                                    Ok(Ok(Ok(ans))) => {
                                        let mut penalized = false;
                                        match ans.rcode.as_str() {
                                            "NXDomain" => { metrics_task.nxdomain.fetch_add(1, std::sync::atomic::Ordering::Relaxed); }
                                            "ServFail" => { metrics_task.servfail.fetch_add(1, std::sync::atomic::Ordering::Relaxed); penalized = true; }
                                            "Refused" => { metrics_task.refused.fetch_add(1, std::sync::atomic::Ordering::Relaxed); penalized = true; }
                                            "TIMEOUT" => { metrics_task.timeouts.fetch_add(1, std::sync::atomic::Ordering::Relaxed); penalized = true; }
                                            _ => {}
                                        }
                                        if penalized { pool_local.report_fail(&resolver); }
                                        if ans.rcode == "NXDomain" { success = false; break; }
                                        if !ans.records.is_empty() {
                                            let mut ips: Vec<String> = ans.records.iter().filter(|r| r.rtype == "A" || r.rtype == "AAAA").map(|r| r.data.clone()).collect();
                                            ips.sort(); ips.dedup();
                                            if !is_wildcard(&ips, &wild_ips_local) {
                                                let typed: Vec<ScanRecord> = ans.records.into_iter().map(|r| ScanRecord { rtype: r.rtype, data: r.data }).collect();
                                                let res = ScanResult { subdomain: host.clone(), answers: ips, records: Some(typed) };
                                                for ow in writers.iter() { let _ = ow.write(&res); }
                                                metrics_task.ok.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                                                let item = Item { domain: host.clone(), dns: resolver.clone(), time: std::time::SystemTime::now(), retry: attempt as i32, domain_level: 0, state: EntryState::Ok };
                                                status_db_task.add(host.clone(), item).await;
                                                pool_local.report_ok(&resolver);
                                                discovered_local.lock().unwrap().push(host.clone());
                                                success = true; break;
                                            } else {
                                                metrics_task.filtered.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                                                let item = Item { domain: host.clone(), dns: resolver.clone(), time: std::time::SystemTime::now(), retry: attempt as i32, domain_level: 0, state: EntryState::WildFiltered };
                                                status_db_task.add(host.clone(), item).await;
                                                // wildcard filtered: stop retrying further
                                                break;
                                            }
                                        } else {
                                            if !penalized { pool_local.report_fail(&resolver); }
                                        }
                                    }
                                    _ => { pool_local.report_fail(&resolver); }
                                }
                            }
                            if opt.retry >= 0 && attempt > opt.retry {
                                if smart_protect && attempt == 1 { continue; } else { break; }
                            }
                        }
                        if !success && show_all {
                            let res = ScanResult { subdomain: host.clone(), answers: vec![], records: None };
                            for ow in writers.iter() { let _ = ow.write(&res); }
                            metrics_task.failed.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                            let item = Item { domain: host.clone(), dns: "".into(), time: std::time::SystemTime::now(), retry: attempt as i32, domain_level: 0, state: EntryState::Failed };
                            status_db_task.set(host.clone(), item).await;
                        }
                    }));
                }
            }
            while let Some(res) = tasks.next().await {
                if let Err(e) = res { eprintln!("task join error: {}", e); }
            }
        }
    }

    // close writers to ensure flush (gzip trailers etc.)
    for ow in writers.iter() { let _ = ow.close(); }

    // final flush
    if let Some(path) = &opt.status_file {
        if let Err(e) = crate::state::save_to_file(&status_db, path).await {
            if !opt.pure_output { eprintln!("[statusdb] final save error: {}", e); }
        }
    }
    // final resolver stats output
    if let Some(path) = &opt.resolver_stats_file {
        if let Err(e) = tokio::fs::write(path, serde_json::to_vec_pretty(&resolver_pool.snapshot()).unwrap_or_default()).await {
            if !opt.pure_output { eprintln!("[resolver] write stats error: {}", e); }
        }
    }
    // final progress json output (single snapshot) if configured
    if let Some(path) = &opt.progress_json_file {
        use std::sync::atomic::Ordering;
        use crate::metrics::ProgressSnapshot;
        let total = metrics.total.load(Ordering::Relaxed);
        let sent = metrics.sent.load(Ordering::Relaxed);
        let ok = metrics.ok.load(Ordering::Relaxed);
        let filtered = metrics.filtered.load(Ordering::Relaxed);
        let failed = metrics.failed.load(Ordering::Relaxed);
        let skipped = metrics.skipped.load(Ordering::Relaxed);
        let nxdomain = metrics.nxdomain.load(Ordering::Relaxed);
        let servfail = metrics.servfail.load(Ordering::Relaxed);
        let refused = metrics.refused.load(Ordering::Relaxed);
        let timeouts = metrics.timeouts.load(Ordering::Relaxed);
        let finished = ok + filtered + failed + skipped;
        let percent = if total > 0 { (finished as f64 / total as f64) * 100.0 } else { 0.0 };
        let inflight = sent.saturating_sub(finished);
        let elapsed = scan_start.elapsed().as_secs();
        let (resolvers_active, resolvers_total, resolvers_disabled_pct) = {
            let (a,t) = resolver_pool.counts();
            let d = t.saturating_sub(a);
            let pct = if t>0 { (d as f64)/(t as f64)*100.0 } else { 0.0 };
            (Some(a as u64), Some(t as u64), Some(pct))
        };
        // Compute final snapshot rates from totals
        let rate_from_total = if elapsed > 0 { (sent as f64) / (elapsed as f64) } else { 0.0 };
        let remain = if total > finished { (total - finished) as f64 } else { 0.0 };
        let eta_calc = if rate_from_total > 0.0 { (remain / rate_from_total) as u64 } else { 0 };
        let err_sum = timeouts + servfail + refused;
        let err_total = if sent > 0 { (err_sum as f64)/(sent as f64) } else { 0.0 };
        let snap = ProgressSnapshot {
            total,
            sent,
            ok,
            filtered,
            failed,
            skipped,
            nxdomain,
            servfail,
            refused,
            timeouts,
            rate: rate_from_total,
            rate_avg: rate_from_total,
            eta_secs: eta_calc,
            percent,
            inflight,
            elapsed,
            resolvers_active,
            resolvers_total,
            resolvers_disabled_pct,
            error_rate_recent: 0.0,
            error_rate_total: err_total,
        };
        if let Ok(data) = serde_json::to_vec_pretty(&snap) {
            if let Err(e) = tokio::fs::write(path, data).await { if !opt.pure_output { eprintln!("[progress] write final json error: {}", e); } }
        }
    }
    // cancel periodic task (drop by abort)
    if let Some(t) = flush_task { t.abort(); }
    if let Some(t) = stats_task { t.abort(); }
    Ok(())
}
