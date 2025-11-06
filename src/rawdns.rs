use anyhow::Result;
use trust_dns_proto::op::{Message, MessageType, OpCode, Query};
use trust_dns_proto::rr::{Name, RecordType};
use trust_dns_proto::serialize::binary::{BinEncoder, BinEncodable, BinDecodable};
use std::net::UdpSocket;
use std::time::Duration;

#[derive(Debug, Clone)]
pub struct RawRecord {
    pub rtype: String,
    pub data: String,
}

#[derive(Debug, Clone)]
pub struct DnsAnswer {
    pub records: Vec<RawRecord>,
    pub rcode: String,
}

pub fn build_query(domain: &str, qtype: RecordType) -> Result<Vec<u8>> {
    let mut msg = Message::new();
    msg.set_id(rand::random::<u16>());
    msg.set_message_type(MessageType::Query);
    msg.set_op_code(OpCode::Query);
    msg.set_recursion_desired(true);
    let name = Name::from_utf8(domain)?;
    let query = Query::query(name, qtype);
    msg.add_query(query);
    let mut buf: Vec<u8> = Vec::with_capacity(512);
    let mut encoder = BinEncoder::new(&mut buf);
    msg.emit(&mut encoder)?;
    Ok(buf)
}

pub fn udp_query(domain: &str, server: &str, timeout_ms: u64) -> Result<Vec<String>> {
    let packet = build_query(domain, RecordType::A)?;
    let sock = UdpSocket::bind("0.0.0.0:0")?;
    sock.set_read_timeout(Some(Duration::from_millis(timeout_ms)))?;
    sock.send_to(&packet, format!("{}:53", server))?;
    let mut recv = [0u8; 2048];
    match sock.recv(&mut recv) {
        Ok(n) => {
            let bytes = &recv[..n];
            let msg = trust_dns_proto::op::Message::from_bytes(bytes)?;
            let mut answers = Vec::new();
            for rec in msg.answers() {
                if let Some(data) = rec.data() {
                    match data {
                        trust_dns_proto::rr::RData::A(ip) => answers.push(ip.to_string()),
                        trust_dns_proto::rr::RData::AAAA(ip) => answers.push(ip.to_string()),
                        trust_dns_proto::rr::RData::CNAME(c) => answers.push(format!("CNAME {}", c.to_utf8())),
                        trust_dns_proto::rr::RData::TXT(txt) => answers.push(format!("TXT {}", txt.to_string())),
                        _ => {}
                    }
                }
            }
            Ok(answers)
        }
        Err(_) => Ok(Vec::new())
    }
}

pub fn udp_query_typed(domain: &str, server: &str, timeout_ms: u64) -> Result<Vec<RawRecord>> {
    let packet = build_query(domain, RecordType::A)?;
    let sock = UdpSocket::bind("0.0.0.0:0")?;
    sock.set_read_timeout(Some(Duration::from_millis(timeout_ms)))?;
    sock.send_to(&packet, format!("{}:53", server))?;
    let mut recv = [0u8; 2048];
    match sock.recv(&mut recv) {
        Ok(n) => {
            let bytes = &recv[..n];
            let msg = trust_dns_proto::op::Message::from_bytes(bytes)?;
            let mut records = Vec::new();
            for rec in msg.answers() {
                if let Some(data) = rec.data() {
                    use trust_dns_proto::rr::RData;
                    match data {
                        RData::A(ip) => records.push(RawRecord{ rtype: "A".into(), data: ip.to_string()}),
                        RData::AAAA(ip) => records.push(RawRecord{ rtype: "AAAA".into(), data: ip.to_string()}),
                        RData::CNAME(c) => records.push(RawRecord{ rtype: "CNAME".into(), data: c.to_utf8()}),
                        RData::TXT(txt) => records.push(RawRecord{ rtype: "TXT".into(), data: txt.to_string()}),
                        _ => {}
                    }
                }
            }
            Ok(records)
        }
        Err(_) => Ok(Vec::new())
    }
}

pub fn udp_query_full(domain: &str, server: &str, timeout_ms: u64) -> Result<DnsAnswer> {
    let packet = build_query(domain, trust_dns_proto::rr::RecordType::A)?;
    let sock = UdpSocket::bind("0.0.0.0:0")?;
    sock.set_read_timeout(Some(Duration::from_millis(timeout_ms)))?;
    sock.send_to(&packet, format!("{}:53", server))?;
    let mut recv = [0u8; 2048];
    match sock.recv(&mut recv) {
        Ok(n) => {
            let bytes = &recv[..n];
            let msg = trust_dns_proto::op::Message::from_bytes(bytes)?;
            let rcode = format!("{:?}", msg.response_code());
            let mut records = Vec::new();
            for rec in msg.answers() {
                if let Some(data) = rec.data() {
                    use trust_dns_proto::rr::RData;
                    match data {
                        RData::A(ip) => records.push(RawRecord{ rtype: "A".into(), data: ip.to_string()}),
                        RData::AAAA(ip) => records.push(RawRecord{ rtype: "AAAA".into(), data: ip.to_string()}),
                        RData::CNAME(c) => records.push(RawRecord{ rtype: "CNAME".into(), data: c.to_utf8()}),
                        RData::TXT(txt) => records.push(RawRecord{ rtype: "TXT".into(), data: txt.to_string()}),
                        _ => {}
                    }
                }
            }
            Ok(DnsAnswer { records, rcode })
        }
        Err(_) => Ok(DnsAnswer { records: Vec::new(), rcode: "TIMEOUT".into() })
    }
}

pub fn query_ns_names(domain: &str, server: &str, timeout_ms: u64) -> Result<Vec<String>> {
    use trust_dns_proto::rr::RData;
    let packet = build_query(domain, RecordType::NS)?;
    let sock = UdpSocket::bind("0.0.0.0:0")?;
    sock.set_read_timeout(Some(Duration::from_millis(timeout_ms)))?;
    sock.send_to(&packet, format!("{}:53", server))?;
    let mut recv = [0u8; 2048];
    match sock.recv(&mut recv) {
        Ok(n) => {
            let bytes = &recv[..n];
            let msg = trust_dns_proto::op::Message::from_bytes(bytes)?;
            let mut names = Vec::new();
            for rec in msg.answers() {
                if let Some(data) = rec.data() {
                    if let RData::NS(name) = data { names.push(name.to_utf8()); }
                }
            }
            Ok(names)
        }
        Err(_) => Ok(Vec::new())
    }
}

pub async fn fetch_ns_ips(domain: &str, resolvers: &Vec<String>, timeout_secs: u64) -> Vec<String> {
    use tokio::net::lookup_host;
    let server = resolvers.get(0).cloned().unwrap_or_else(|| "8.8.8.8".to_string());
    let timeout_ms = timeout_secs * 1000;
    let names = match tokio::task::spawn_blocking({
        let d = domain.to_string();
        let s = server.clone();
        move || query_ns_names(&d, &s, timeout_ms)
    }).await {
        Ok(Ok(v)) => v,
        _ => vec![],
    };
    let mut ips = Vec::new();
    for n in names {
        let target = format!("{}:0", n);
        if let Ok(Ok(addrs)) = tokio::time::timeout(Duration::from_secs(timeout_secs), lookup_host(target)).await {
            for sa in addrs { ips.push(sa.ip().to_string()); }
        }
    }
    ips.sort(); ips.dedup();
    ips
}
