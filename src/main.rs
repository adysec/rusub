use rusub::cli::{Cli, Commands};
use rusub::options::{band2rate, get_resolvers, Options, OptionMethod};
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
            // 自动纯净模式：当输出为 json/jsonl 时，默认关闭所有非结果输出
            let auto_pure = if args.pure_output { true } else { matches!(args.output_type.to_lowercase().as_str(), "json" | "jsonl") };
            if !auto_pure { println!("band '{}' => rate {} pkt/s", args.band, rate); }
            let mut resolvers = get_resolvers(&args.common.resolvers);

            let mut injected = 0usize;
            if args.ns {
                for d in domains.iter() {
                    let ns_ips = rusub::dns::fetch_ns_ips(d, &resolvers, args.timeout).await;
                    for ip in ns_ips { if !resolvers.contains(&ip) { resolvers.push(ip); injected += 1; } }
                }
                resolvers.sort(); resolvers.dedup();
                if !auto_pure {
                    println!("[ns] injected {} new NS resolver IP(s), total now {}", injected, resolvers.len());
                }
            }

            let mut gzip_flag = args.gzip;
            if !gzip_flag {
                if let Some(ref p) = args.output {
                    if let Some(os) = p.as_os_str().to_str() { if os.ends_with(".gz") { gzip_flag = true; } }
                }
            }

            // 当输出为 json/jsonl 且未显式指定 --only-alive 时，默认只输出存活结果
            let auto_only_alive = if args.only_alive { true } else { matches!(args.output_type.to_lowercase().as_str(), "json" | "jsonl") };
            
            // 启发式模式：当没有指定 -f 时，自动启用启发式
            let use_heuristic = args.filename.is_none();
            
            // 默认启用状态文件和泛解析过滤
            let status_file_path = Some(".rusub-state.json".into());
            let wild_filter = "advanced".to_string();
            
            let mut opt = Options {
                rate,
                domains: domains.clone(),
                domain_list: args.domain_list.clone(),
                filename: args.filename.clone(),
                resolvers,
                silent: false,
                timeout: args.timeout,
                retry: args.retry,
                concurrency: args.common.concurrency,
                method: OptionMethod::Enum,
                output: args.output.clone(),
                output_type: args.output_type.clone(),
                gzip: gzip_flag,
                append: false,
                not_print: args.not_print,
                wild_filter_mode: wild_filter,
                predict: false,
                progress: !auto_pure,
                progress_interval: 1,
                detail_records: false,
                progress_wide: false,
                progress_color: false,
                progress_legacy: false,
                predict_rounds: 0,
                predict_topn: 0,
                status_file: status_file_path,
                status_flush_interval: 30,
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
                log_level: args.common.log_level.clone(),
                pure_output: auto_pure,
                only_alive: auto_only_alive,
                heuristic: use_heuristic,
                heuristic_max: args.heuristic_max,
            };
            opt.check();

            if !opt.pure_output && (opt.log_level == "debug" || opt.log_level == "info") {
                println!("Parsed Options: {:#?}", opt);
            }
            scanner::run(opt).await?;
        }
    }

    Ok(())
}

