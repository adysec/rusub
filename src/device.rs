use anyhow::Result;
use get_if_addrs::{get_if_addrs, IfAddr};
use crate::privileges::has_cap_net_raw;

pub fn list_interfaces(raw: bool, _up_only: bool) -> Result<()> {
    let ifs = get_if_addrs()?;
    for iface in ifs {
        let name = if raw { iface.name.clone() } else { iface.name.clone() };
        let mut addrs: Vec<String> = vec![];
        match iface.addr {
            IfAddr::V4(a) => addrs.push(a.ip.to_string()),
            IfAddr::V6(a) => addrs.push(a.ip.to_string()),
        }
        println!("{}\t{:?}", name, addrs);
    }
    println!("cap_net_raw={}", has_cap_net_raw());
    Ok(())
}
