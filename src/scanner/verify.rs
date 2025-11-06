use crate::options::Options;
use anyhow::Result;
use tokio::time::{timeout, Duration};
use crate::output::{ScanResult, ScanRecord, build_writers};
use std::sync::Arc;
use crate::resolver_pool::ResolverPool;
use crate::rawdns::udp_query_full;

pub async fn run(opt: Options) -> Result<()> {
    let writers = Arc::new(build_writers(opt.output.clone(), &opt.output_type, !opt.not_print, opt.detail_records, opt.gzip, opt.append)?);
    let pool = ResolverPool::new(opt.resolvers.clone());
    pool.set_cooldown_secs(opt.resolver_cooldown_secs);
    for d in opt.domains.iter() {
        let host = d.trim().trim_end_matches('.').to_string();
        let mut attempt: i32 = 0;
        let mut success = false;
        while opt.retry < 0 || attempt <= opt.retry {
            attempt += 1;
            if let Some(resolver) = pool.choose_random() {
                let timeout_ms = opt.timeout * 1000;
                let h = host.clone();
                let r = resolver.clone();
                let fut = tokio::task::spawn_blocking(move || udp_query_full(&h, &r, timeout_ms));
                match timeout(Duration::from_secs(opt.timeout), fut).await {
                    Ok(Ok(Ok(ans))) => {
                        let mut penalized = false;
                        match ans.rcode.as_str() {
                            "NXDomain" => {},
                            "ServFail" => { penalized = true; },
                            "Refused" => { penalized = true; },
                            "TIMEOUT" => { penalized = true; },
                            _ => {}
                        }
                        if penalized { pool.report_fail(&resolver); }
                        if ans.rcode == "NXDomain" {
                            // definitive negative: stop retrying, output empty if需要
                            let res = ScanResult { subdomain: host.clone(), answers: vec![], records: None };
                            for ow in writers.iter() { let _ = ow.write(&res); }
                            success = true; break;
                        }
                        if !ans.records.is_empty() {
                            let mut ips: Vec<String> = ans.records.iter()
                                .filter(|r| r.rtype == "A" || r.rtype == "AAAA")
                                .map(|r| r.data.clone()).collect();
                            ips.sort(); ips.dedup();
                            let typed: Vec<ScanRecord> = ans.records.into_iter().map(|r| ScanRecord { rtype: r.rtype, data: r.data }).collect();
                            let res = ScanResult { subdomain: host.clone(), answers: ips, records: Some(typed) };
                            for ow in writers.iter() { let _ = ow.write(&res); }
                            pool.report_ok(&resolver);
                            success = true; break;
                        }
                        // empty answer -> retry
                        if !penalized { pool.report_fail(&resolver); }
                    }
                    _ => { /* timeout or join error */ }
                }
            }
            if opt.retry >= 0 && attempt > opt.retry { break; }
        }
        if !success {
            let res = ScanResult { subdomain: host.clone(), answers: vec![], records: None };
            for ow in writers.iter() { let _ = ow.write(&res); }
        }
    }
    for ow in writers.iter() { let _ = ow.close(); }
    Ok(())
}
