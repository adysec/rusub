use clap::{Args, Parser, Subcommand};
use std::path::PathBuf;

#[derive(Parser, Debug)]
#[command(
    author,
    version,
    about = "rusub - 高速异步子域枚举工具",
    long_about = "NAME:\n  rusub - 高速异步子域枚举工具\n\nUSAGE:\n  rusub enum [OPTIONS] [DOMAIN]...\n\n说明:\n  - 默认启发式扫描，可通过 -f 指定字典文件\n  - 自动启用断点续传、泛解析过滤\n  - json/jsonl 格式自动纯净输出、仅显示存活域名\n\n示例:\n  # 启发式扫描\n  rusub enum example.com --heuristic-max 1024 --output-type jsonl\n  \n  # 字典扫描\n  rusub enum example.com -f subdomain.txt --output-type jsonl",
    after_help = "参数说明:\n\n输入:\n  -d, --domain [DOMAIN]...       指定域名(可重复)\n      [DOMAIN]...                位置参数域名\n      --stdin                    从标准输入读取域名\n  -f, --filename <PATH>          字典文件(指定则使用字典模式，否则使用启发式)\n      --domain-list <PATH>       根域列表文件\n\n输出:\n  -o, --output <PATH>            输出文件(.gz后缀自动压缩)\n      --output-type <FMT>        输出格式: txt/json/jsonl/csv (默认 jsonl)\n      --gzip                     强制 gzip 压缩\n      --not-print                不在终端打印结果\n      --pure-output              纯净模式(仅结果行)\n      --only-alive               仅输出存活域名\n\n速率:\n  -b, --band <EXPR>              速率: 支持 K/M/G (默认 3m)\n      --timeout <SEC>            超时秒数 (默认 6)\n      --retry <N>                重试次数 (默认 3)\n\n启发式:\n      --heuristic-max <N>        启发式最大候选数 (默认 512)\n\n解析器:\n  -r, --resolvers <IP>...        指定解析器(可重复)\n  -c, --concurrency <N>          并发数 (默认 500)\n\n其他:\n      --log-level <LEVEL>        日志级别: error|warn|info|debug|silent\n"
)]
pub struct Cli {
    #[command(subcommand)]
    pub command: Commands,
}

#[derive(Subcommand, Debug)]
pub enum Commands {
    /// 枚举域名 (enum) - 主扫描流程：启发式/字典爆破、原始UDP、泛解析过滤与断点续传
    #[command(alias = "e")]
    Enum(EnumArgs),
}

/// Common args reused by multiple subcommands
#[derive(Args, Debug)]
pub struct CommonArgs {
    /// 目标域名，可重复
    #[arg(short = 'd', long = "domain")]
    pub domains: Vec<String>,

    /// 位置参数域名（可直接在命令后写 domain，不需要 -d）
    #[arg(value_name = "DOMAIN")] 
    pub positional_domains: Vec<String>,

    /// 从 stdin 读取域名列表
    #[arg(long = "stdin")]
    pub stdin: bool,

    /// 自定义解析器，可重复 (默认内置公共 DNS 列表)
    #[arg(short = 'r', long = "resolvers")]
    pub resolvers: Vec<String>,

    /// 并发数（备用）
    #[arg(short = 'c', long = "concurrency", default_value_t = 500)]
    pub concurrency: usize,

    /// 日志级别: error|warn|info|debug|silent
    #[arg(long = "log-level", default_value = "info", value_parser = ["error","warn","info","debug","silent"])]
    pub log_level: String,
}

#[derive(Args, Debug)]
pub struct EnumArgs {
    /// 基本通用参数
    #[command(flatten)]
    pub common: CommonArgs,

    /// 词表文件路径
    #[arg(short = 'f', long = "filename")]
    pub filename: Option<PathBuf>,

    /// 读取域名的列表文件
    #[arg(long = "domain-list", alias = "ds")]
    pub domain_list: Option<PathBuf>,

    /// 是否读取根域 NS 并加入其 A/AAAA 记录 IP 到解析器池 (实验特性)
    #[arg(long = "ns")]
    pub ns: bool,

    /// 输出文件路径
    #[arg(short = 'o', long = "output")]
    pub output: Option<PathBuf>,

    /// 输出类型: txt/json/jsonl/csv
    #[arg(long = "output-type", default_value = "jsonl")]
    pub output_type: String,

    /// 使用 gzip 压缩
    #[arg(long = "gzip")] 
    pub gzip: bool,

    /// 不在终端打印
    #[arg(long = "not-print")]
    pub not_print: bool,

    /// 带宽表示 (支持 K/M/G 后缀，示例: 100M, 3m)
    #[arg(short = 'b', long = "band", default_value = "3m")]
    pub band: String,

    /// 超时 (秒)
    #[arg(long = "timeout", default_value_t = 6)]
    pub timeout: u64,

    /// 重试次数 (默认 3)
    #[arg(long = "retry", default_value_t = 3)]
    pub retry: i32,

    /// 纯净输出：仅输出结果
    #[arg(long = "pure-output")]
    pub pure_output: bool,

    /// 只输出存活的域名
    #[arg(long = "only-alive")]
    pub only_alive: bool,

    /// 启发式生成的最大条目数 (默认 512)
    #[arg(long = "heuristic-max", default_value_t = 512)]
    pub heuristic_max: usize,
}


