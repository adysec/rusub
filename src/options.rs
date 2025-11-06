use anyhow::Result;
use std::path::PathBuf;

#[derive(Debug, Clone)]
pub enum OptionMethod {
    Verify,
    Enum,
    Test,
}

#[derive(Debug, Clone)]
pub struct Options {
    pub rate: i64,
    pub domains: Vec<String>,
    pub domain_list: Option<PathBuf>,
    pub filename: Option<PathBuf>,
    pub resolvers: Vec<String>,
    pub silent: bool,
    pub timeout: u64,
    pub retry: i32,
    pub concurrency: usize,
    pub method: OptionMethod,
    pub output: Option<PathBuf>,
    pub output_type: String,
    pub not_print: bool,
    pub wild_filter_mode: String,
    pub predict: bool,
    pub progress: bool,
    pub progress_interval: u64,
    pub detail_records: bool,
    pub progress_wide: bool,
    pub progress_color: bool,
    pub progress_legacy: bool,
    pub predict_rounds: u32,
    pub predict_topn: usize,
    pub status_file: Option<PathBuf>,
    pub status_flush_interval: u64,
    pub resolver_cooldown_secs: u64,
    pub adaptive_rate: bool,
    pub adaptive_min_rate: i64,
    pub adaptive_max_rate: i64,
    pub adaptive_error_threshold: f64,
    pub adaptive_dec_factor: f64,
    pub adaptive_inc_factor: f64,
    pub resolver_stats_file: Option<PathBuf>,
    pub resolver_stats_interval: u64,
    pub gzip: bool,
    pub append: bool,
    pub progress_json_file: Option<PathBuf>,
    pub progress_json_interval: u64,
    pub log_level: String,
}

impl Options {
    pub fn check(&mut self) {
        if self.silent {
            // placeholder for logger level - silent implies minimal stdout
        }
    }
}

/// Convert a bandwidth expression (e.g. 1G, 500M, 2.5M, 750K) into approximate packets per second.
/// Assumptions:
/// - 1G = 1_000_000_000 bits per second, same for M/K scaling.
/// - Average DNS packet size approximation 80 bytes (~640 bits).
/// - We treat the input number as megabits/gigabits/kilobits unless no suffix is provided (raw pps).
/// - Returned value is an integer pps (floor).
pub fn band2rate(band: &str) -> Result<i64> {
    if band.is_empty() { anyhow::bail!("empty band string") }
    let s = band.trim();
    if s.is_empty() { anyhow::bail!("empty band string") }
    let lower = s.to_ascii_lowercase();

    // Helper: parse f64 numeric prefix
    let parse_num = |txt: &str| -> Result<f64> {
        let v: f64 = txt.trim().parse()?;
        if v <= 0.0 { anyhow::bail!("band value must be > 0") };
        Ok(v)
    };

    // DNS packet size (approx) in bits
    const DNS_PACKET_BITS: f64 = 80.0 * 8.0;

    // Case 1: mbps/kbps/gbps/bps (bits per second)
    if lower.ends_with("kbps") {
        let v = parse_num(&lower[..lower.len()-4])? * 1_000.0;
        return Ok(((v) / DNS_PACKET_BITS).floor() as i64);
    }
    if lower.ends_with("mbps") {
        let v = parse_num(&lower[..lower.len()-4])? * 1_000_000.0;
        return Ok(((v) / DNS_PACKET_BITS).floor() as i64);
    }
    if lower.ends_with("gbps") {
        let v = parse_num(&lower[..lower.len()-4])? * 1_000_000_000.0;
        return Ok(((v) / DNS_PACKET_BITS).floor() as i64);
    }
    if lower.ends_with("bps") {
        let v = parse_num(&lower[..lower.len()-3])?; // raw bits per second
        return Ok(((v) / DNS_PACKET_BITS).floor() as i64);
    }

    // Case 2: kpps/mpps/gpps/pps (packets per second)
    if lower.ends_with("kpps") {
        let v = parse_num(&lower[..lower.len()-4])? * 1_000.0;
        return Ok(v.floor() as i64);
    }
    if lower.ends_with("mpps") {
        let v = parse_num(&lower[..lower.len()-4])? * 1_000_000.0;
        return Ok(v.floor() as i64);
    }
    if lower.ends_with("gpps") {
        let v = parse_num(&lower[..lower.len()-4])? * 1_000_000_000.0;
        return Ok(v.floor() as i64);
    }
    if lower.ends_with("pps") {
        let v = parse_num(&lower[..lower.len()-3])?;
        return Ok(v.floor() as i64);
    }

    // Case 3: legacy K/M/G suffixes meaning Kilobits/Megabits/Gigabits per second
    if let Some(last) = lower.chars().last() {
        match last {
            'g' | 'm' | 'k' => {
                let num_part = &lower[..lower.len()-1];
                let mult = match last {
                    'g' => 1_000_000_000f64,
                    'm' => 1_000_000f64,
                    'k' => 1_000f64,
                    _ => unreachable!()
                };
                let value = parse_num(num_part)?;
                let bits_per_sec = value * mult;
                let pps = (bits_per_sec / DNS_PACKET_BITS).floor() as i64;
                if pps <= 0 { anyhow::bail!("calculated pps <= 0 for band: {}", band) }
                return Ok(pps);
            }
            _ => {}
        }
    }

    // Case 4: pure number => interpret as pps
    if lower.chars().all(|c| c.is_ascii_digit()) {
        let raw: i64 = lower.parse()?;
        return Ok(raw.max(0));
    }

    anyhow::bail!("invalid band format: {}", band)
}

pub fn get_resolvers(input: &Vec<String>) -> Vec<String> {
    if !input.is_empty() {
        return input.clone();
    }
    vec![
        "1.1.1.1".to_string(),
        "8.8.8.8".to_string(),
        "180.76.76.76".to_string(),
        "180.184.1.1".to_string(),
        "180.184.2.2".to_string(),
    ]
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn test_band2rate() {
        // For updated formula: bits / (80*8)
        assert_eq!(band2rate("1M").unwrap(), (1_000_000f64 / (80.0*8.0)).floor() as i64);
        assert_eq!(band2rate("1G").unwrap(), (1_000_000_000f64 / (80.0*8.0)).floor() as i64);
        assert_eq!(band2rate("100K").unwrap(), (100_000f64 / (80.0*8.0)).floor() as i64);
        assert_eq!(band2rate("2.5M").unwrap(), ((2.5f64*1_000_000f64) / (80.0*8.0)).floor() as i64);
        assert_eq!(band2rate("750K").unwrap(), (750_000f64 / (80.0*8.0)).floor() as i64);
        assert_eq!(band2rate("1200").unwrap(), 1200); // raw pps
        // new forms
        assert_eq!(band2rate("10mbps").unwrap(), ((10_000_000f64) / (80.0*8.0)).floor() as i64);
        assert_eq!(band2rate("2.5Mbps").unwrap(), ((2.5f64*1_000_000f64) / (80.0*8.0)).floor() as i64);
    assert_eq!(band2rate("1Gbps").unwrap(), ((1_000_000_000f64) / (80.0*8.0)).floor() as i64);
        assert_eq!(band2rate("500kpps").unwrap(), 500_000);
        assert_eq!(band2rate("1200pps").unwrap(), 1200);
    }
}
