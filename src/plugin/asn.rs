//! Read-only access to the ASN → prefixes database shipped with the node image.
//!
//! The file is written by `lmdb-js` (LMDB 1.0 fork, data version 2): 24-byte page header,
//! keys are `ordered-binary` doubles, values are msgpackr records of two string arrays
//! (`ipv4`, `ipv6`). Stock LMDB (and therefore the `heed` crate) cannot open it, and the
//! format is small enough to read directly.

use std::{fs::File, io, os::unix::fs::FileExt, path::Path};

use anyhow::{Context, Result, bail};

const PAGE_HDR: u64 = 24;
const MDB_MAGIC: u32 = 0xBEEF_C0DE;
const DATA_VERSION: u32 = 2;
const P_BRANCH: u16 = 0x01;
const P_LEAF: u16 = 0x02;
const F_BIGDATA: u16 = 0x01;
const P_INVALID: u64 = u64::MAX;

#[derive(Debug, Default, Clone, PartialEq, Eq)]
pub struct AsnPrefixes {
    pub ipv4: Vec<String>,
    pub ipv6: Vec<String>,
}

pub struct AsnDb {
    file: File,
    page_size: u64,
    root: u64,
}

impl AsnDb {
    pub fn open(path: &Path) -> Result<Self> {
        let file = File::open(path).with_context(|| format!("cannot open {}", path.display()))?;
        // Both meta pages live at the start; the page size is stored inside them.
        let mut best: Option<(u64, u64, u64)> = None; // (txnid, root, page_size)
        let mut page_size = 4096u64;
        for pg in 0..2u64 {
            let mut buf = [0u8; 160];
            file.read_exact_at(&mut buf, pg * page_size)
                .with_context(|| "database file is too short")?;
            let magic = u32::from_le_bytes(buf[24..28].try_into().unwrap());
            let version = u32::from_le_bytes(buf[28..32].try_into().unwrap());
            if magic != MDB_MAGIC {
                bail!("not an LMDB file (bad magic)");
            }
            if version != DATA_VERSION {
                bail!("unsupported LMDB data version {version}");
            }
            // meta at +24: magic, version, address(8), mapsize(8), free db(48), main db(48), last_pg, txnid
            let free_pad = u32::from_le_bytes(buf[48..52].try_into().unwrap());
            if free_pad >= 512 {
                page_size = free_pad as u64;
            }
            let main_root = u64::from_le_bytes(buf[136..144].try_into().unwrap());
            let txnid = u64::from_le_bytes(buf[152..160].try_into().unwrap());
            if best.is_none_or(|(t, _, _)| txnid >= t) {
                best = Some((txnid, main_root, page_size));
            }
        }
        let (_, root, page_size) = best.unwrap();
        Ok(Self {
            file,
            page_size,
            root,
        })
    }

    fn read(&self, offset: u64, len: usize) -> io::Result<Vec<u8>> {
        let mut buf = vec![0u8; len];
        self.file.read_exact_at(&mut buf, offset)?;
        Ok(buf)
    }

    fn read_page(&self, pgno: u64) -> io::Result<Vec<u8>> {
        self.read(pgno * self.page_size, self.page_size as usize)
    }

    /// Raw value for a key, or `None`.
    pub fn get(&self, key: &[u8]) -> Result<Option<Vec<u8>>> {
        if self.root == P_INVALID {
            return Ok(None);
        }
        let mut pgno = self.root;
        for _ in 0..16 {
            let page = self.read_page(pgno)?;
            let flags = u16::from_le_bytes(page[18..20].try_into().unwrap());
            let lower = u16::from_le_bytes(page[20..22].try_into().unwrap()) as usize;
            let n = lower / 2;
            let node = |i: usize| -> Result<Node<'_>> {
                let ptr =
                    u16::from_le_bytes(page[24 + 2 * i..26 + 2 * i].try_into().unwrap()) as usize;
                Node::parse(&page, PAGE_HDR as usize + ptr)
            };

            if flags & P_BRANCH != 0 {
                if n == 0 {
                    return Ok(None);
                }
                // the first key of a branch page is implicit (smaller than everything)
                let (mut lo, mut hi) = (1usize, n);
                let mut pick = 0usize;
                while lo < hi {
                    let mid = (lo + hi) / 2;
                    if node(mid)?.key <= key {
                        pick = mid;
                        lo = mid + 1;
                    } else {
                        hi = mid;
                    }
                }
                pgno = node(pick)?.child();
            } else if flags & P_LEAF != 0 {
                let (mut lo, mut hi) = (0usize, n);
                while lo < hi {
                    let mid = (lo + hi) / 2;
                    let nd = node(mid)?;
                    match nd.key.cmp(key) {
                        std::cmp::Ordering::Equal => return Ok(Some(self.node_value(&nd)?)),
                        std::cmp::Ordering::Less => lo = mid + 1,
                        std::cmp::Ordering::Greater => hi = mid,
                    }
                }
                return Ok(None);
            } else {
                bail!("unexpected page type {flags:#x}");
            }
        }
        bail!("tree is too deep, database is corrupt")
    }

    fn node_value(&self, nd: &Node<'_>) -> Result<Vec<u8>> {
        let size = nd.data_size();
        if nd.flags & F_BIGDATA != 0 {
            let ovf = u64::from_le_bytes(nd.data[..8].try_into().unwrap());
            Ok(self.read(ovf * self.page_size + PAGE_HDR, size)?)
        } else {
            Ok(nd.data[..size].to_vec())
        }
    }

    pub fn prefixes(&self, asn: u32) -> Result<Option<AsnPrefixes>> {
        match self.get(&encode_number_key(asn as f64))? {
            Some(raw) => Ok(Some(decode_prefixes(&raw))),
            None => Ok(None),
        }
    }
}

struct Node<'a> {
    lo: u16,
    hi: u16,
    flags: u16,
    key: &'a [u8],
    data: &'a [u8],
}

impl<'a> Node<'a> {
    fn parse(page: &'a [u8], at: usize) -> Result<Self> {
        if at + 8 > page.len() {
            bail!("node out of page bounds");
        }
        let lo = u16::from_le_bytes(page[at..at + 2].try_into().unwrap());
        let hi = u16::from_le_bytes(page[at + 2..at + 4].try_into().unwrap());
        let flags = u16::from_le_bytes(page[at + 4..at + 6].try_into().unwrap());
        let ksize = u16::from_le_bytes(page[at + 6..at + 8].try_into().unwrap()) as usize;
        if at + 8 + ksize > page.len() {
            bail!("node key out of page bounds");
        }
        Ok(Self {
            lo,
            hi,
            flags,
            key: &page[at + 8..at + 8 + ksize],
            data: &page[at + 8 + ksize..],
        })
    }

    fn data_size(&self) -> usize {
        (self.lo as usize) | ((self.hi as usize) << 16)
    }

    fn child(&self) -> u64 {
        (self.lo as u64) | ((self.hi as u64) << 16) | ((self.flags as u64) << 32)
    }
}

/// `ordered-binary` encoding of a non-negative number: a 0x1 nibble followed by the IEEE-754
/// bits, MSB first, with trailing zero bytes trimmed (down to 4 bytes).
pub fn encode_number_key(x: f64) -> Vec<u8> {
    let bits = x.to_bits();
    let mut out = Vec::with_capacity(9);
    out.push(0x10 | (bits >> 60) as u8);
    for i in 1..8 {
        out.push((bits >> (60 - 8 * i)) as u8);
    }
    out.push(((bits & 0xf) << 4) as u8);
    // lmdb-js never goes below 4 bytes
    while out.len() > 4 && out.last() == Some(&0) {
        out.pop();
    }
    out
}

/// Pulls every string out of the msgpack payload and sorts them into IPv4 / IPv6 prefixes.
/// (The payload is a msgpackr record `{ipv4: [...], ipv6: [...]}`; the record definition
/// strings `ipv4` / `ipv6` are not prefixes and get filtered out by the CIDR check.)
pub fn decode_prefixes(raw: &[u8]) -> AsnPrefixes {
    let mut out = AsnPrefixes::default();
    let mut i = 0;
    while i < raw.len() {
        let b = raw[i];
        let (len, hdr) = match b {
            0xa0..=0xbf => ((b & 0x1f) as usize, 1),
            0xd9 if i + 1 < raw.len() => (raw[i + 1] as usize, 2),
            0xda if i + 2 < raw.len() => (u16::from_be_bytes([raw[i + 1], raw[i + 2]]) as usize, 3),
            _ => {
                i += 1;
                continue;
            }
        };
        let start = i + hdr;
        let Some(bytes) = raw.get(start..start + len) else {
            break;
        };
        if let Ok(s) = std::str::from_utf8(bytes)
            && let Ok(net) = s.parse::<ipnet::IpNet>()
        {
            match net {
                ipnet::IpNet::V4(_) => out.ipv4.push(s.to_string()),
                ipnet::IpNet::V6(_) => out.ipv6.push(s.to_string()),
            }
        }
        i = start + len;
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn number_keys_match_lmdb_js_encoding() {
        // observed in the real database: AS1, AS2, AS3, AS15169, AS32934
        assert_eq!(hex::encode(encode_number_key(1.0)), "13ff0000");
        assert_eq!(hex::encode(encode_number_key(15169.0)), "140cda08");
        assert_eq!(hex::encode(encode_number_key(32934.0)), "140e014c");
    }

    #[test]
    fn decodes_msgpackr_record() {
        // d4 72 40 | 92 a4 ipv4 a4 ipv6 | 91 ab 1.2.3.0/24 .. | 91 ab "2001:db8::/32"
        let mut raw = vec![0xd4, 0x72, 0x40, 0x92, 0xa4];
        raw.extend_from_slice(b"ipv4");
        raw.push(0xa4);
        raw.extend_from_slice(b"ipv6");
        raw.extend_from_slice(&[0x91, 0xaa]);
        raw.extend_from_slice(b"1.2.3.0/24");
        raw.extend_from_slice(&[0x91, 0xad]);
        raw.extend_from_slice(b"2001:db8::/32");
        let p = decode_prefixes(&raw);
        assert_eq!(p.ipv4, vec!["1.2.3.0/24"]);
        assert_eq!(p.ipv6, vec!["2001:db8::/32"]);
    }

    /// Runs against the real database when `ASN_LMDB_TEST_PATH` points at a decompressed copy.
    #[test]
    fn reads_real_database_if_available() {
        let Ok(path) = std::env::var("ASN_LMDB_TEST_PATH") else {
            eprintln!("skipped: ASN_LMDB_TEST_PATH not set");
            return;
        };
        let db = AsnDb::open(Path::new(&path)).unwrap();
        let google = db.prefixes(15169).unwrap().expect("AS15169 must exist");
        assert!(google.ipv4.iter().any(|p| p == "8.8.8.0/24"));
        assert!(db.prefixes(1).unwrap().is_some());
        assert!(db.prefixes(4_294_967_000).unwrap().is_none());
    }
}
