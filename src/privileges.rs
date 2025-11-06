use std::fs;

// Linux capabilities bit index for CAP_NET_RAW is 13
const CAP_NET_RAW_BIT: u32 = 13;

fn parse_cap_eff_hex(hex: &str) -> Option<u128> {
    let s = hex.trim();
    if s.starts_with("0x") || s.starts_with("0X") {
        u128::from_str_radix(&s[2..], 16).ok()
    } else {
        u128::from_str_radix(s, 16).ok()
    }
}

pub fn has_cap_net_raw() -> bool {
    if let Ok(content) = fs::read_to_string("/proc/self/status") {
        for line in content.lines() {
            if let Some(rest) = line.strip_prefix("CapEff:") {
                if let Some(val) = parse_cap_eff_hex(rest) {
                    let bit = 1u128 << CAP_NET_RAW_BIT;
                    return (val & bit) != 0;
                }
            }
        }
    }
    false
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn test_parse_caps() {
        let v = parse_cap_eff_hex("0000000000002000").unwrap();
        assert_eq!(v & (1u128 << CAP_NET_RAW_BIT) != 0, true);
        let v2 = parse_cap_eff_hex("0x0000000000000000").unwrap();
        assert_eq!(v2 & (1u128 << CAP_NET_RAW_BIT) != 0, false);
    }
}
