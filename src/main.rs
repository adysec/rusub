use rusub::cli::{Cli, Commands, VerifyArgs, TestArgs};
use rusub::options::{band2rate, get_resolvers, Options, OptionMethod};
use rusub::runner::Runner;
use rusub::scanner;
use anyhow::Result;
use clap::{Parser, CommandFactory};
use std::fs::File;
use std::io::{self, BufRead};

#[tokio::main]
async fn main() -> Result<()> {
    let cli = Cli::parse();

    match cli.command {
        Commands::Enum(args) => {
            if args.common.domains.is_empty() && args.common.positional_domains.is_empty() && !args.common.stdin && args.domain_list.is_none() && args.filename.is_none() {
                let mut cmd = Cli::command();
                if let Some(sc) = cmd.find_subcommand_mut("enum") { let _ = sc.print_help(); println!(); }
                return Ok(());
            }
            let mut domains: Vec<String> = vec![];
            if !args.common.domains.is_empty() { domains.extend(args.common.domains.clone()); }
            if !args.common.positional_domains.is_empty() { domains.extend(args.common.positional_domains.clone()); }
            if args.common.stdin {
                let stdin = io::stdin();
                for line in stdin.lock().lines() {
                    if let Ok(s) = line { domains.push(s); }
                }
            }
            if let Some(list) = &args.domain_list {
                let f = File::open(list)?;
                for line in io::BufReader::new(f).lines() {
                    if let Ok(s) = line { domains.push(s); }
                }
            }

            let rate = band2rate(&args.band)?;
            println!("band '{}' => rate {} pkt/s", args.band, rate);
            let mut resolvers = get_resolvers(&args.common.resolvers);

            let mut injected = 0usize;
            if args.ns {
                for d in domains.iter() {
                    let ns_ips = rusub::rawdns::fetch_ns_ips(d, &resolvers, args.timeout).await;
                    for ip in ns_ips { if !resolvers.contains(&ip) { resolvers.push(ip); injected += 1; } }
                }
                resolvers.sort(); resolvers.dedup();
                println!("[ns] injected {} new NS resolver IP(s), total now {}", injected, resolvers.len());
            }

            let adaptive_max_rate = if args.adaptive_max_rate > 0 { args.adaptive_max_rate } else { rate };
            let adaptive_min_rate = args.adaptive_min_rate.min(adaptive_max_rate).max(100);

            let mut gzip_flag = args.gzip;
            if !gzip_flag {
                if let Some(ref p) = args.output {
                    if let Some(os) = p.as_os_str().to_str() { if os.ends_with(".gz") { gzip_flag = true; } }
                }
            }

            let mut opt = Options {
                rate,
                domains: domains.clone(),
                domain_list: args.domain_list.clone(),
                filename: args.filename.clone(),
                resolvers,
                silent: args.silent,
                timeout: args.timeout,
                retry: args.retry,
                concurrency: args.common.concurrency,
                method: OptionMethod::Enum,
                output: args.output.clone(),
                output_type: args.output_type.clone(),
                gzip: gzip_flag,
                append: args.append,
                not_print: args.not_print,
                wild_filter_mode: args.wild_filter_mode.clone(),
                predict: args.predict,
                progress: !args.no_progress,
                progress_interval: args.progress_interval,
                detail_records: args.detail_records,
                progress_wide: args.progress_wide,
                progress_color: args.progress_color,
                progress_legacy: args.progress_legacy,
                predict_rounds: args.predict_rounds,
                predict_topn: args.predict_topn,
                status_file: args.status_file.clone(),
                status_flush_interval: args.status_flush_interval,
                resolver_cooldown_secs: args.resolver_cooldown,
                adaptive_rate: args.adaptive_rate,
                adaptive_min_rate,
                adaptive_max_rate,
                adaptive_error_threshold: args.adaptive_error_threshold,
                adaptive_dec_factor: args.adaptive_dec_factor,
                adaptive_inc_factor: args.adaptive_inc_factor,
                resolver_stats_file: args.resolver_stats_file.clone(),
                resolver_stats_interval: args.resolver_stats_interval,
                progress_json_file: args.progress_json_file.clone(),
                progress_json_interval: args.progress_json_interval,
                log_level: args.common.log_level.clone(),
            };
            opt.check();

            if !opt.silent && (opt.log_level == "debug" || opt.log_level == "info") {
                println!("Parsed Options: {:#?}", opt);
            }
            let runner = Runner::new(opt).expect("create runner");
            runner.run_enumeration().await.expect("run enumeration");
    }
        Commands::Verify(args) => {
            let VerifyArgs { common, filename, output, output_type, gzip, append, not_print, silent, band, timeout, retry, wild_filter_mode, predict, eth: _ } = args;
            if common.domains.is_empty() && common.positional_domains.is_empty() && !common.stdin && filename.is_none() {
                let mut cmd = Cli::command();
                if let Some(sc) = cmd.find_subcommand_mut("verify") { let _ = sc.print_help(); println!(); }
                return Ok(());
            }
            let mut domains: Vec<String> = vec![];
            if !common.domains.is_empty() { domains.extend(common.domains.clone()); }
            if !common.positional_domains.is_empty() { domains.extend(common.positional_domains.clone()); }
            if common.stdin {
                let stdin = io::stdin();
                for line in stdin.lock().lines() { if let Ok(s) = line { domains.push(s); } }
            }
            if let Some(list) = &filename {
                let f = File::open(list)?;
                for line in io::BufReader::new(f).lines() { if let Ok(s) = line { domains.push(s); } }
            }
            let rate = band2rate(&band)?;
            println!("band '{}' => rate {} pkt/s", band, rate);
            let resolvers = get_resolvers(&common.resolvers);
            let mut gzip_flag = gzip;
            if !gzip_flag {
                if let Some(ref p) = output { if let Some(os) = p.as_os_str().to_str() { if os.ends_with(".gz") { gzip_flag = true; } } }
            }
            let opt = Options {
                rate,
                domains,
                domain_list: None,
                filename: None,
                resolvers,
                silent,
                timeout,
                retry,
                concurrency: common.concurrency,
                method: OptionMethod::Verify,
                output,
                output_type,
                gzip: gzip_flag,
                append,
                not_print,
                wild_filter_mode,
                predict,
                progress: true,
                progress_interval: 1,
                detail_records: false,
                progress_wide: false,
                progress_color: false,
                progress_legacy: false,
                predict_rounds: 0,
                predict_topn: 0,
                status_file: None,
                status_flush_interval: 0,
                resolver_cooldown_secs: 60,
                adaptive_rate: false,
                adaptive_min_rate: 0,
                adaptive_max_rate: 0,
                adaptive_error_threshold: 0.0,
                adaptive_dec_factor: 1.0,
                adaptive_inc_factor: 1.0,
                resolver_stats_file: None,
                resolver_stats_interval: 0,
                progress_json_file: None,
                progress_json_interval: 0,
                log_level: common.log_level.clone(),
            };
            scanner::run_verify(opt).await?;
    }
        Commands::Test(args) => {
            let TestArgs { common, eth: _ } = args;
            let mut domains: Vec<String> = vec![];
            if !common.domains.is_empty() { domains.extend(common.domains.clone()); }
            if !common.positional_domains.is_empty() { domains.extend(common.positional_domains.clone()); }
            if common.stdin {
                let stdin = io::stdin();
                for line in stdin.lock().lines() { if let Ok(s) = line { domains.push(s); } }
            }
            let resolvers = get_resolvers(&common.resolvers);
            let opt = Options {
                rate: 0,
                domains,
                domain_list: None,
                filename: None,
                resolvers,
                silent: false,
                timeout: 3,
                retry: 0,
                concurrency: common.concurrency,
                method: OptionMethod::Test,
                output: None,
                output_type: "txt".into(),
                gzip: false,
                append: false,
                not_print: false,
                wild_filter_mode: "none".into(),
                predict: false,
                progress: false,
                progress_interval: 1,
                detail_records: false,
                progress_wide: false,
                progress_color: false,
                progress_legacy: false,
                predict_rounds: 0,
                predict_topn: 0,
                status_file: None,
                status_flush_interval: 0,
                resolver_cooldown_secs: 60,
                adaptive_rate: false,
                adaptive_min_rate: 0,
                adaptive_max_rate: 0,
                adaptive_error_threshold: 0.0,
                adaptive_dec_factor: 1.0,
                adaptive_inc_factor: 1.0,
                resolver_stats_file: None,
                resolver_stats_interval: 0,
                progress_json_file: None,
                progress_json_interval: 0,
                log_level: common.log_level.clone(),
            };
            scanner::run_test(opt).await?;
        }
        Commands::Device(dargs) => {
            rusub::device::list_interfaces(dargs.raw, dargs.up_only)?;
        }
    }

    Ok(())
}

