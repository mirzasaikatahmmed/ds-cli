//! DNS record lookup for `--dns-records` on taken domains.
//!
//! Uses a hand-rolled UDP DNS client to avoid pulling in a heavy resolver
//! crate. We only need A, AAAA, MX, and NS records (the four flags
//! documented in the spec), and a few short timeouts are fine for a CLI
//! tool.

use std::net::{Ipv4Addr, Ipv6Addr, SocketAddr, ToSocketAddrs, UdpSocket};
use std::time::Duration;

use anyhow::{Context, Result};

/// Default DNS server to query.
pub const DEFAULT_DNS: &str = "1.1.1.1:53";

#[derive(Debug, Clone, Default)]
#[allow(dead_code)]
pub struct DnsRecords {
    pub a: Vec<String>,
    pub aaaa: Vec<String>,
    pub mx: Vec<String>,
    pub ns: Vec<String>,
}

/// Run A, AAAA, MX, NS queries sequentially. Failures are recorded as an
/// empty vec for that record type; the lookup still returns partial data.
#[allow(dead_code)]
pub async fn resolve(domain: &str, server: Option<&str>) -> Result<DnsRecords> {
    let server = server.unwrap_or(DEFAULT_DNS);
    let domain = domain.to_string();
    let server = server.to_string();
    tokio::task::spawn_blocking(move || resolve_blocking(&domain, &server))
        .await
        .context("dns resolve task")?
}

fn resolve_blocking(domain: &str, server: &str) -> Result<DnsRecords> {
    Ok(DnsRecords {
        a: query_a(domain, server).unwrap_or_default(),
        aaaa: query_aaaa(domain, server).unwrap_or_default(),
        mx: query_mx(domain, server).unwrap_or_default(),
        ns: query_ns(domain, server).unwrap_or_default(),
    })
}

// ---------- DNS protocol ----------

fn build_query(domain: &str, qtype: u16, id: u16) -> Vec<u8> {
    let mut buf = Vec::with_capacity(64 + domain.len());
    buf.extend_from_slice(&id.to_be_bytes());
    buf.extend_from_slice(&[0x01, 0x00]);
    buf.extend_from_slice(&[0x00, 0x01]);
    buf.extend_from_slice(&[0x00, 0x00]);
    buf.extend_from_slice(&[0x00, 0x00]);
    buf.extend_from_slice(&[0x00, 0x00]);
    for label in domain.trim_end_matches('.').split('.') {
        let len = label.len().min(63) as u8;
        buf.push(len);
        buf.extend_from_slice(&label.as_bytes()[..len as usize]);
    }
    buf.push(0);
    buf.extend_from_slice(&qtype.to_be_bytes());
    buf.extend_from_slice(&[0x00, 0x01]);
    buf
}

const QTYPE_A: u16 = 1;
const QTYPE_AAAA: u16 = 28;
const QTYPE_MX: u16 = 15;
const QTYPE_NS: u16 = 2;

fn send_query(domain: &str, qtype: u16, server: &str) -> Result<Vec<u8>> {
    let server: SocketAddr = server
        .to_socket_addrs()
        .with_context(|| format!("bad DNS server: {server}"))?
        .next()
        .ok_or_else(|| anyhow::anyhow!("no DNS address for {server}"))?;
    let id: u16 = (std::process::id() as u16).wrapping_add(0x42);
    let q = build_query(domain, qtype, id);
    let sock = UdpSocket::bind(("0.0.0.0", 0)).context("binding UDP socket")?;
    sock.connect(server).context("connecting UDP to DNS")?;
    sock.set_read_timeout(Some(Duration::from_secs(3))).ok();
    sock.send(&q).context("sending DNS query")?;
    let mut buf = [0u8; 1500];
    let n = sock.recv(&mut buf).context("recv DNS response")?;
    Ok(buf[..n].to_vec())
}

struct AnswerIter<'a> {
    resp: &'a [u8],
    pos: usize,
    remaining: usize,
}

impl<'a> AnswerIter<'a> {
    fn new(resp: &'a [u8]) -> Result<Self> {
        if resp.len() < 12 {
            anyhow::bail!("short DNS response");
        }
        let qdcount = u16::from_be_bytes([resp[4], resp[5]]) as usize;
        let ancount = u16::from_be_bytes([resp[6], resp[7]]) as usize;
        let mut me = Self {
            resp,
            pos: 12,
            remaining: ancount,
        };
        // Skip questions.
        for _ in 0..qdcount {
            if me.pos >= me.resp.len() {
                return Ok(me);
            }
            me.pos = skip_name(me.resp, me.pos)?;
            me.pos += 4;
        }
        Ok(me)
    }
}

impl<'a> Iterator for AnswerIter<'a> {
    type Item = (u16, &'a [u8]);
    fn next(&mut self) -> Option<Self::Item> {
        if self.remaining == 0 || self.pos >= self.resp.len() {
            return None;
        }
        // Try to advance to the next answer.
        let name_pos = match skip_name(self.resp, self.pos) {
            Ok(p) => p,
            Err(_) => return None,
        };
        if name_pos + 10 > self.resp.len() {
            return None;
        }
        let rtype = u16::from_be_bytes([self.resp[name_pos], self.resp[name_pos + 1]]);
        let rdlen = u16::from_be_bytes([self.resp[name_pos + 8], self.resp[name_pos + 9]]) as usize;
        let rdata_start = name_pos + 10;
        if rdata_start + rdlen > self.resp.len() {
            return None;
        }
        let rdata = &self.resp[rdata_start..rdata_start + rdlen];
        self.pos = rdata_start + rdlen;
        self.remaining -= 1;
        Some((rtype, rdata))
    }
}

fn skip_name(resp: &[u8], mut pos: usize) -> Result<usize> {
    loop {
        if pos >= resp.len() {
            anyhow::bail!("truncated DNS name");
        }
        let len = resp[pos];
        if len == 0 {
            return Ok(pos + 1);
        }
        if len & 0xc0 == 0xc0 {
            return Ok(pos + 2);
        }
        pos += 1 + (len as usize);
    }
}

/// Decode a DNS name starting at `pos` within `resp`, following pointer
/// compression.
fn decode_name(resp: &[u8], pos: usize) -> Result<String> {
    let mut labels: Vec<String> = Vec::new();
    let mut p = pos;
    loop {
        if p >= resp.len() {
            anyhow::bail!("truncated name");
        }
        let len = resp[p];
        if len == 0 {
            break;
        }
        if len & 0xc0 == 0xc0 {
            if p + 1 >= resp.len() {
                anyhow::bail!("truncated pointer");
            }
            let offset = (((len & 0x3f) as usize) << 8) | (resp[p + 1] as usize);
            p = offset;
            continue;
        }
        p += 1;
        if p + (len as usize) > resp.len() {
            anyhow::bail!("truncated label");
        }
        let label = std::str::from_utf8(&resp[p..p + len as usize])
            .unwrap_or("?")
            .to_string();
        labels.push(label);
        p += len as usize;
    }
    Ok(labels.join("."))
}

fn query_a(domain: &str, server: &str) -> Result<Vec<String>> {
    let resp = send_query(domain, QTYPE_A, server)?;
    let mut out = Vec::new();
    for (rtype, rdata) in AnswerIter::new(&resp)? {
        if rtype == QTYPE_A && rdata.len() == 4 {
            out.push(Ipv4Addr::new(rdata[0], rdata[1], rdata[2], rdata[3]).to_string());
        }
    }
    Ok(out)
}

fn query_aaaa(domain: &str, server: &str) -> Result<Vec<String>> {
    let resp = send_query(domain, QTYPE_AAAA, server)?;
    let mut out = Vec::new();
    for (rtype, rdata) in AnswerIter::new(&resp)? {
        if rtype == QTYPE_AAAA && rdata.len() == 16 {
            let mut bytes = [0u8; 16];
            bytes.copy_from_slice(rdata);
            out.push(Ipv6Addr::from(bytes).to_string());
        }
    }
    Ok(out)
}

fn query_mx(domain: &str, server: &str) -> Result<Vec<String>> {
    let resp = send_query(domain, QTYPE_MX, server)?;
    let mut out = Vec::new();
    for (rtype, rdata) in AnswerIter::new(&resp)? {
        if rtype == QTYPE_MX && rdata.len() >= 3 {
            // preference(2) + name starting at offset 2 within rdata
            let name_pos_in_resp = rdata_absolute_pos(&resp, rdata, 2);
            if let Ok(name) = decode_name(&resp, name_pos_in_resp) {
                out.push(name);
            }
        }
    }
    Ok(out)
}

fn query_ns(domain: &str, server: &str) -> Result<Vec<String>> {
    let resp = send_query(domain, QTYPE_NS, server)?;
    let mut out = Vec::new();
    for (rtype, rdata) in AnswerIter::new(&resp)? {
        if rtype == QTYPE_NS {
            let name_pos_in_resp = rdata_absolute_pos(&resp, rdata, 0);
            if let Ok(name) = decode_name(&resp, name_pos_in_resp) {
                out.push(name);
            }
        }
    }
    Ok(out)
}

/// Convert an offset-within-rdata into an absolute offset within `resp`.
/// `rdata` is a sub-slice of `resp`, so this is just pointer arithmetic
/// plus an offset.
fn rdata_absolute_pos(resp: &[u8], rdata: &[u8], rdata_offset: usize) -> usize {
    let resp_start = resp.as_ptr() as usize;
    let rdata_start = rdata.as_ptr() as usize;
    if rdata_start < resp_start {
        return rdata_offset; // shouldn't happen — fall back to relative
    }
    (rdata_start - resp_start) + rdata_offset
}

#[cfg(test)]
mod tests {
    use super::*;

    fn example_response() -> Vec<u8> {
        let mut buf = Vec::new();
        buf.extend_from_slice(&[0x12, 0x34]);
        buf.extend_from_slice(&[0x81, 0x80]);
        buf.extend_from_slice(&[0x00, 0x01]); // qdcount
        buf.extend_from_slice(&[0x00, 0x01]); // ancount
        buf.extend_from_slice(&[0x00, 0x00]);
        buf.extend_from_slice(&[0x00, 0x00]);
        buf.extend_from_slice(&[7]);
        buf.extend_from_slice(b"example");
        buf.extend_from_slice(&[3]);
        buf.extend_from_slice(b"com");
        buf.push(0);
        buf.extend_from_slice(&[0x00, 0x01]);
        buf.extend_from_slice(&[0x00, 0x01]);
        buf.extend_from_slice(&[0xc0, 0x0c]);
        buf.extend_from_slice(&[0x00, 0x01]);
        buf.extend_from_slice(&[0x00, 0x01]);
        buf.extend_from_slice(&[0x00, 0x00, 0x00, 0x3c]);
        buf.extend_from_slice(&[0x00, 0x04]);
        buf.extend_from_slice(&[1, 2, 3, 4]);
        buf
    }

    #[test]
    fn parse_answers_extracts_a_record() {
        let resp = example_response();
        let iter = AnswerIter::new(&resp).unwrap();
        let a: Vec<_> = iter
            .filter(|(t, _)| *t == QTYPE_A)
            .filter_map(|(_, r)| {
                if r.len() == 4 {
                    Some(Ipv4Addr::new(r[0], r[1], r[2], r[3]).to_string())
                } else {
                    None
                }
            })
            .collect();
        assert_eq!(a, vec!["1.2.3.4"]);
    }

    #[test]
    fn iter_skips_questions() {
        let resp = example_response();
        let iter = AnswerIter::new(&resp).unwrap();
        assert_eq!(iter.count(), 1);
    }

    #[test]
    fn build_query_encodes_labels() {
        let q = build_query("foo.bar", QTYPE_A, 0x1234);
        // 12 header + 3+3+3+0 (labels) + 4 (qtype+qclass) = 25
        assert_eq!(q.len(), 12 + 9 + 4);
        assert_eq!(&q[0..2], &[0x12, 0x34]);
        assert_eq!(q[12], 3);
        assert_eq!(&q[13..16], b"foo");
        assert_eq!(q[16], 3);
        assert_eq!(&q[17..20], b"bar");
        assert_eq!(q[20], 0);
    }

    #[test]
    fn skip_name_advances_past_root_label() {
        let data = [0u8, 1, 2, 3];
        assert_eq!(skip_name(&data, 0).unwrap(), 1);
        let data = [3, b'f', b'o', b'o', 0];
        assert_eq!(skip_name(&data, 0).unwrap(), 5);
    }
}
