use clap::{Args, Parser, Subcommand};
use std::path::PathBuf;

#[derive(Parser, Debug)]
#[command(
    author,
    version,
    about = "rusub - Rust 复刻 ksubdomain 的高速无状态子域枚举工具",
    long_about = "NAME:\n  rusub - Rust 复刻 ksubdomain 的高速无状态子域枚举工具\n\nUSAGE:\n  rusub <SUBCOMMAND> [OPTIONS] [DOMAIN]...\n\nCOMMANDS:\n  enum (e)    高速无状态子域枚举，词表/预测/过滤/进度/输出\n  verify (v)  验证模式：直接解析域名或文件中的域名\n  test (t)    发送能力评估(速率窗口)，随机子域 UDP 测试\n  device      列出系统网卡\n\n说明:\n  - 支持原始 UDP DNS、无限重试(--retry -1)、自适应速率、泛解析过滤、预测扩展、断点续扫、解析器健康统计与多格式(gzip)输出。\n  - 位置参数 [DOMAIN]... 与 -d/--domain 可混用；也可通过 --stdin / 文件输入。\n\n快速示例:\n  rusub enum example.com -f wordlists/small.txt --band 10M --output out.txt\n  rusub verify example.com --retry 3 --timeout 6 --output v.txt\n  rusub test example.com -r 8.8.8.8 -r 1.1.1.1",
    after_help = "完整用法速查\n\n通用输入 (enum/verify/test)：\n  -d, --domain [DOMAIN]...         指定域名(可重复)\n      [DOMAIN]...                  位置参数域名(可直接写在子命令后)\n      --stdin                      从标准输入读取域名\n  -r, --resolvers <IP>...          指定解析器(可重复)，缺省使用内置公共 DNS\n  -c, --concurrency <N>            并发数(默认 500)\n  -e, --eth <IFACE>                指定网卡(占位，与 ksubdomain 兼容)\n      --log-level <LEVEL>         日志级别: error|warn|info|debug|silent (默认 info)\n\n枚举 enum 参数：\n  -f, --filename <PATH>            词表文件\n      --domain-list <PATH>         根域列表文件 (与 -d 配合)\n      --ns                         注入根域 NS 的 A/AAAA 作为解析器(实验)\n  -o, --output <PATH>              输出文件；.gz 后缀自动启用 gzip\n      --output-type, --oy <FMT>    输出类型: txt/json/jsonl/csv/txt-domain (默认 txt)\n      --gzip                       强制使用 gzip 压缩\n      --not-print, --np            不在终端打印结果\n      --silent                     仅输出域名(静默)\n  -b, --band <EXPR>                速率: 支持 K/M/G 或 pps 数字 (默认 3m)\n      --timeout <SEC>              超时(默认 6)\n      --retry <N>                  重试(默认 3；-1=无限; 成功/NXDOMAIN/泛解析即停)\n      --wild-filter-mode <MODE>    泛解析过滤: basic/advanced/none (默认 none)\n      --predict                    启用预测\n      --predict-rounds <N>         预测迭代轮数 (默认 1)\n      --predict-topn <N>           每轮新增 TopN (默认 64)\n      --no-progress                关闭屏幕进度\n      --progress-interval <SEC>    进度刷新间隔 (默认 1)\n      --progress-wide              宽屏进度\n      --progress-color             彩色进度\n      --progress-json-file <PATH>  进度 JSON 输出\n      --progress-json-interval <S> 进度 JSON 间隔，0=仅最终\n      --detail-records             在 txt/csv 输出记录类型细节\n      --status-file <PATH>         状态持久化(断点续扫)\n      --status-flush-interval <S>  状态间隔 flush，0=关闭\n      --resolver-cooldown <SEC>    解析器冷却恢复秒数(默认 60)\n      --adaptive-rate              启用自适应速率\n      --adaptive-min-rate <pps>    自适应最小速率 (默认 1000)\n      --adaptive-max-rate <pps>    自适应最大速率 (默认=初始速率)\n      --adaptive-error-threshold <r> 错误率阈值 (默认 0.15)\n      --adaptive-dec-factor <f>    降速因子 (默认 0.7)\n      --adaptive-inc-factor <f>    升速因子 (默认 1.05)\n      --resolver-stats-file <PATH> 解析器统计 JSON 输出\n      --resolver-stats-interval <S> 统计写入间隔，0=仅最终\n\n验证 verify 参数：\n  -f, --filename <PATH>            验证域名文件\n  -o, --output <PATH>              输出文件；.gz 自动 gzip\n      --output-type, --oy <FMT>    输出类型: txt/json/jsonl/csv/txt-domain (默认 txt)\n      --gzip                       启用 gzip\n      --not-print, --np            不在终端打印\n      --silent                     静默，仅域名\n  -b, --band <EXPR>                速率表达式 (默认 3m)\n      --timeout <SEC>              超时 (默认 6)\n      --retry <N>                  重试 (默认 3；-1=无限)\n      --wild-filter-mode <MODE>    泛解析过滤模式\n      --predict                    启用预测\n\n测试 test 参数：\n  [DOMAIN]... / --stdin           用作随机标签的根域\n  -r, --resolvers <IP>...         指定解析器\n  -c, --concurrency <N>           并发 (默认 500)\n  -e, --eth <IFACE>               指定网卡(占位)\n\n设备 device 参数：\n      --raw                        显示原始接口名\n      --up-only                    仅显示 UP 接口\n\n示例：\n  rusub enum example.com -f sub.txt -b 10M -o out.json.gz --output-type json --progress-wide\n  rusub verify example.com --retry -1 --timeout 6 --wild-filter-mode basic\n  rusub test example.com -r 8.8.8.8 -r 1.1.1.1\n"
)]
pub struct Cli {
    #[command(subcommand)]
    pub command: Commands,
}

#[derive(Subcommand, Debug)]
pub enum Commands {
    /// 枚举域名 (enum) - 主扫描流程：词表扩展、原始UDP、多记录类型、过滤与进度统计
    #[command(alias = "e", after_help = "枚举参数分组:\n  输入: -d --domain-list -f --stdin\n  输出: -o --output-type --gzip --not-print --detail-records\n  速率与并发: --band -c --timeout --retry --adaptive-rate --adaptive-min-rate --adaptive-max-rate\n  泛解析: --wild-filter-mode --ns\n  预测: --predict --predict-rounds --predict-topn\n  进度: --no-progress --progress-interval --progress-wide --progress-color --progress-legacy --progress-json-file --progress-json-interval\n  状态持久化: --status-file --status-flush-interval\n  解析器健康: --resolver-cooldown --resolver-stats-file --resolver-stats-interval\n  其他: --resolvers --eth")]
    Enum(EnumArgs),
    /// 验证模式 (verify) - 直接对域名列表进行解析验证（使用解析器池 + 重试/超时）
    #[command(alias = "v", after_help = "验证参数: -d -f --stdin --band --timeout --retry --resolvers --wild-filter-mode --not-print --silent --output --output-type --gzip --predict --eth")]
    Verify(VerifyArgs),
    /// 测试 (test) - 速率窗口(默认3s)随机子域 UDP 查询评估近似发送能力
    #[command(alias = "t", after_help = "测试参数: -d --stdin --resolvers --band --concurrency --eth\n输出示例: test-speed: window=3s sent=1845 (~615 pps) ok=320 nxdomain=1420 timeouts=80 errors=25\n说明: --band 限制目标速率; 不指定则尽力发送.")]
    Test(TestArgs),
    /// 列出设备 (device) - 查看系统网卡（可结合未来 raw socket 发包路径）
    Device(DeviceArgs),
}

/// Common args reused by multiple subcommands
#[derive(Args, Debug)]
pub struct CommonArgs {
    /// 目标域名，可重复
    #[arg(short = 'd', long = "domain")]
    pub domains: Vec<String>,

    /// 位置参数域名（兼容 ksubdomain：可直接在命令后写 domain，不需要 -d）
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

    /// 输出类型: txt/json/jsonl/csv/txt-domain/txt-ks
    #[arg(long = "output-type", alias = "oy", default_value = "txt")]
    pub output_type: String,

    /// 使用 gzip 压缩 (txt/json/csv 有效；文件名以 .gz 结尾自动开启)
    #[arg(long = "gzip")] 
    pub gzip: bool,

    /// 追加写入输出文件（默认覆盖写入）
    #[arg(long = "append")]
    pub append: bool,

    /// 不在屏幕打印
    #[arg(long = "not-print", alias = "np")]
    pub not_print: bool,

    /// 静默模式
    #[arg(long = "silent")]
    pub silent: bool,

    /// 带宽表示 (支持 K/M/G 后缀、mbps/kbps/gbps、kpps/mpps/pps 或纯数字 pps；示例: 100M, 2.5M, 750K, 10mbps, 500kpps, 1200)
    #[arg(short = 'b', long = "band", default_value = "3m")]
    pub band: String,

    /// 超时 (秒)
    #[arg(long = "timeout", default_value_t = 6)]
    pub timeout: u64,

    /// 重试次数 (-1 无限: 仅对 TIMEOUT/ServFail/Refused 重试，成功/NXDOMAIN/泛解析即停止)
    #[arg(long = "retry", default_value_t = 3, allow_negative_numbers = true)]
    pub retry: i32,

    /// 泛解析过滤模式: basic/advanced/none
    #[arg(long = "wild-filter-mode", default_value = "none")]
    pub wild_filter_mode: String,

    /// 是否启用预测生成
    #[arg(long = "predict")]
    pub predict: bool,

    /// 关闭屏幕进度
    #[arg(long = "no-progress")]
    pub no_progress: bool,

    /// 进度刷新间隔(秒)
    #[arg(long = "progress-interval", default_value_t = 1)]
    pub progress_interval: u64,

    /// 在 txt/csv 中输出记录类型详细字段 (A/AAAA/CNAME/TXT)
    #[arg(long = "detail-records")]
    pub detail_records: bool,

    /// 宽屏进度模式：显示更多统计字段
    #[arg(long = "progress-wide")]
    pub progress_wide: bool,

    /// 进度彩色输出 (ANSI)，在支持的终端下增强可读性
    #[arg(long = "progress-color")]
    pub progress_color: bool,

    /// 旧版进度布局（更接近 ksubdomain 的简洁列）
    #[arg(long = "progress-legacy")]
    pub progress_legacy: bool,

    /// 预测迭代轮数（初始词表完成后再进行 N 轮动态扩展）
    #[arg(long = "predict-rounds", default_value_t = 1)]
    pub predict_rounds: u32,

    /// 每轮预测新增 TopN
    #[arg(long = "predict-topn", default_value_t = 64)]
    pub predict_topn: usize,

    /// 状态持久化文件路径（断点续扫）
    #[arg(long = "status-file")]
    pub status_file: Option<PathBuf>,

    /// 状态周期写入间隔(秒)，0 表示关闭周期 flush
    #[arg(long = "status-flush-interval", default_value_t = 30)]
    pub status_flush_interval: u64,

    /// 解析器禁用后的冷却恢复时间(秒)
    #[arg(long = "resolver-cooldown", default_value_t = 60)]
    pub resolver_cooldown: u64,

    /// 启用自适应速率控制
    #[arg(long = "adaptive-rate")]
    pub adaptive_rate: bool,

    /// 自适应最小速率 (pps)
    #[arg(long = "adaptive-min-rate", default_value_t = 1000)]
    pub adaptive_min_rate: i64,

    /// 自适应最大速率 (pps)（默认使用初始计算值，可覆盖）
    #[arg(long = "adaptive-max-rate", default_value_t = 0)]
    pub adaptive_max_rate: i64,

    /// 错误率阈值（timeouts+servfail+refused)/sent 超过则降低速率
    #[arg(long = "adaptive-error-threshold", default_value_t = 0.15)]
    pub adaptive_error_threshold: f64,

    /// 降速因子 (乘法)
    #[arg(long = "adaptive-dec-factor", default_value_t = 0.7)]
    pub adaptive_dec_factor: f64,

    /// 升速因子 (乘法)
    #[arg(long = "adaptive-inc-factor", default_value_t = 1.05)]
    pub adaptive_inc_factor: f64,

    /// 解析器统计输出文件 (JSON，包含 ok/fail/disabled 状态)
    #[arg(long = "resolver-stats-file")]
    pub resolver_stats_file: Option<PathBuf>,

    /// 解析器统计周期写入间隔(秒)，0=仅最终写入
    #[arg(long = "resolver-stats-interval", default_value_t = 0)]
    pub resolver_stats_interval: u64,

    /// 进度 JSON 输出文件
    #[arg(long = "progress-json-file")]
    pub progress_json_file: Option<PathBuf>,

    /// 进度 JSON 周期写入间隔(秒)，0=仅最终写入
    #[arg(long = "progress-json-interval", default_value_t = 0)]
    pub progress_json_interval: u64,

    /// 指定网卡（兼容 ksubdomain 的 --eth/-e；当前仅占位，无副作用）
    #[arg(short = 'e', long = "eth")]
    pub eth: Option<String>,
}

#[derive(Args, Debug)]
pub struct VerifyArgs {
    /// 基本通用参数
    #[command(flatten)]
    pub common: CommonArgs,

    /// 验证域名的文件路径
    #[arg(short = 'f', long = "filename")]
    pub filename: Option<PathBuf>,

    /// 输出文件路径
    #[arg(short = 'o', long = "output")]
    pub output: Option<PathBuf>,

    /// 输出类型: txt/json/jsonl/csv/txt-domain/txt-ks
    #[arg(long = "output-type", alias = "oy", default_value = "txt")]
    pub output_type: String,

    /// 使用 gzip 压缩
    #[arg(long = "gzip")] 
    pub gzip: bool,

    /// 追加写入输出文件（默认覆盖写入）
    #[arg(long = "append")]
    pub append: bool,

    /// 不在屏幕打印
    #[arg(long = "not-print", alias = "np")]
    pub not_print: bool,

    /// 静默模式
    #[arg(long = "silent")]
    pub silent: bool,

    /// 带宽表示 (支持 K/M/G、mbps/kbps/gbps、kpps/mpps/pps、或纯数字 pps)
    #[arg(short = 'b', long = "band", default_value = "3m")]
    pub band: String,

    /// 超时 (秒)
    #[arg(long = "timeout", default_value_t = 6)]
    pub timeout: u64,

    /// 重试次数 (-1 表示无限重试；成功/NXDOMAIN 即停止)
    #[arg(long = "retry", default_value_t = 3, allow_negative_numbers = true)]
    pub retry: i32,

    /// 泛解析过滤模式: basic/advanced/none
    #[arg(long = "wild-filter-mode", default_value = "none")]
    pub wild_filter_mode: String,

    /// 是否启用预测生成
    #[arg(long = "predict")]
    pub predict: bool,

    /// 指定网卡（兼容 --eth/-e；当前仅占位，无实际影响）
    #[arg(short = 'e', long = "eth")]
    pub eth: Option<String>,
}

#[derive(Args, Debug)]
pub struct TestArgs {
    /// 基本通用参数
    #[command(flatten)]
    pub common: CommonArgs,

    /// 指定网卡（兼容 --eth/-e；当前仅占位）
    #[arg(short = 'e', long = "eth")]
    pub eth: Option<String>,
}

#[derive(Args, Debug)]
pub struct DeviceArgs {
    /// 显示原始接口名称
    #[arg(long = "raw")]
    pub raw: bool,
    /// 仅显示可用的 (UP) 接口
    #[arg(long = "up-only")]
    pub up_only: bool,
}
