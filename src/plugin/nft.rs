//! nftables management through the `nft` CLI (script on stdin = one atomic transaction).
//!
//! The ruleset is the one `nftables-napi` builds natively: an `ip` table `<name>` and an
//! `ip6` table `<name>6`, each with named counters, address/port sets and the input /
//! forward / output chains described in that library's README.

use std::net::IpAddr;

use anyhow::{Context, Result, anyhow, bail};
use ipnet::IpNet;
use tokio::{io::AsyncWriteExt, process::Command};

pub const TABLE_NAME: &str = "remnanode";
pub const TORRENT_BLOCKER_SET: &str = "torrent-blocker";
pub const INGRESS_FILTER_IP_SET: &str = "ingress-filter-ip";
pub const EGRESS_FILTER_IP_SET: &str = "egress-filter-ip";
pub const EGRESS_FILTER_PORT_SET: &str = "egress-filter-port";

const INGRESS_ADDR_SETS: [&str; 2] = [INGRESS_FILTER_IP_SET, TORRENT_BLOCKER_SET];
const EGRESS_ADDR_SETS: [&str; 1] = [EGRESS_FILTER_IP_SET];
const EGRESS_PORT_SETS: [&str; 1] = [EGRESS_FILTER_PORT_SET];
const CHUNK: usize = 500;

#[derive(Debug, Clone)]
pub struct Nft {
    bin: String,
    table: String,
    logging: bool,
    accept_reply_traffic: bool,
}

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub(crate) enum Family {
    V4,
    V6,
}

impl Family {
    fn keyword(self) -> &'static str {
        match self {
            Family::V4 => "ip",
            Family::V6 => "ip6",
        }
    }
    fn suffix(self) -> &'static str {
        match self {
            Family::V4 => "",
            Family::V6 => "6",
        }
    }
    fn addr_type(self) -> &'static str {
        match self {
            Family::V4 => "ipv4_addr",
            Family::V6 => "ipv6_addr",
        }
    }
}

/// Canonical text for an IP or CIDR; rejects everything else so nothing user-controlled
/// can ever reach the nft script unparsed.
pub(crate) fn normalize_addr(input: &str) -> Result<(Family, String)> {
    let input = input.trim();
    if input.contains('/') {
        let net: IpNet = input
            .parse()
            .map_err(|_| anyhow!("invalid CIDR: {input}"))?;
        let net = net.trunc();
        let fam = if matches!(net, IpNet::V4(_)) {
            Family::V4
        } else {
            Family::V6
        };
        Ok((fam, net.to_string()))
    } else {
        let ip: IpAddr = input.parse().map_err(|_| anyhow!("invalid IP: {input}"))?;
        Ok((
            if ip.is_ipv4() { Family::V4 } else { Family::V6 },
            ip.to_string(),
        ))
    }
}

impl Nft {
    pub fn new(logging: bool, accept_reply_traffic: bool) -> Self {
        Self {
            bin: std::env::var("NFT_BIN")
                .ok()
                .filter(|v| !v.is_empty())
                .unwrap_or_else(|| "nft".into()),
            table: TABLE_NAME.to_string(),
            logging,
            accept_reply_traffic,
        }
    }

    #[cfg(test)]
    fn with_table(mut self, name: &str) -> Self {
        self.table = name.to_string();
        self
    }

    fn table_name(&self, fam: Family) -> String {
        format!("{}{}", self.table, fam.suffix())
    }

    fn set_name(base: &str, fam: Family) -> String {
        format!("{base}{}", fam.suffix())
    }

    // ------------------------------------------------------------ script building

    fn render_table(&self, fam: Family) -> String {
        let t = self.table_name(fam);
        let kw = fam.keyword();
        let mut s = String::new();
        s.push_str(&format!(
            "add table {kw} {t}\ndelete table {kw} {t}\ntable {kw} {t} {{\n"
        ));

        s.push_str("  counter processed {}\n");
        for base in INGRESS_ADDR_SETS
            .iter()
            .chain(&EGRESS_ADDR_SETS)
            .chain(&EGRESS_PORT_SETS)
        {
            s.push_str(&format!("  counter {} {{}}\n", Self::set_name(base, fam)));
        }
        for base in INGRESS_ADDR_SETS.iter().chain(&EGRESS_ADDR_SETS) {
            s.push_str(&format!(
                "  set {} {{ type {}; flags timeout, interval; auto-merge; counter; }}\n",
                Self::set_name(base, fam),
                fam.addr_type()
            ));
        }
        for base in EGRESS_PORT_SETS {
            s.push_str(&format!(
                "  set {} {{ type inet_proto . inet_service; flags timeout; counter; }}\n",
                Self::set_name(base, fam)
            ));
        }

        for chain in ["input", "forward"] {
            s.push_str(&format!(
                "  chain {chain} {{\n    type filter hook {chain} priority -10; policy accept;\n    counter name \"processed\"\n"
            ));
            if self.accept_reply_traffic {
                s.push_str("    ct direction reply accept\n");
            }
            for base in INGRESS_ADDR_SETS {
                let name = Self::set_name(base, fam);
                let log = if self.logging {
                    format!("log prefix \"{name}: \" ")
                } else {
                    String::new()
                };
                s.push_str(&format!(
                    "    {kw} saddr @{name} {log}counter name \"{name}\" drop\n"
                ));
            }
            s.push_str("  }\n");
        }

        s.push_str("  chain output {\n    type filter hook output priority -10; policy accept;\n");
        for base in EGRESS_ADDR_SETS {
            let name = Self::set_name(base, fam);
            s.push_str(&format!(
                "    {kw} daddr @{name} counter name \"{name}\" drop\n"
            ));
        }
        for base in EGRESS_PORT_SETS {
            let name = Self::set_name(base, fam);
            s.push_str(&format!(
                "    meta l4proto . th dport @{name} counter name \"{name}\" drop\n"
            ));
        }
        s.push_str("  }\n}\n");
        s
    }

    pub fn render_create(&self) -> String {
        format!(
            "{}{}",
            self.render_table(Family::V4),
            self.render_table(Family::V6)
        )
    }

    fn element_cmds(
        &self,
        verb: &str,
        base_set: &str,
        elements: &[(Family, String)],
        timeout: Option<u64>,
        chunk: usize,
    ) -> Vec<String> {
        let mut cmds = Vec::new();
        for fam in [Family::V4, Family::V6] {
            let items: Vec<String> = elements
                .iter()
                .filter(|(f, _)| *f == fam)
                .map(|(_, e)| match timeout {
                    Some(t) if verb == "add" => format!("{e} timeout {t}s"),
                    _ => e.clone(),
                })
                .collect();
            for part in items.chunks(chunk) {
                cmds.push(format!(
                    "{verb} element {} {} {} {{ {} }}",
                    fam.keyword(),
                    self.table_name(fam),
                    Self::set_name(base_set, fam),
                    part.join(", ")
                ));
            }
        }
        cmds
    }

    // ------------------------------------------------------------ execution

    async fn run(&self, script: &str) -> Result<()> {
        let mut child = Command::new(&self.bin)
            .args(["-f", "-"])
            .stdin(std::process::Stdio::piped())
            .stdout(std::process::Stdio::null())
            .stderr(std::process::Stdio::piped())
            .kill_on_drop(true)
            .spawn()
            .with_context(|| format!("cannot run {}", self.bin))?;
        let mut stdin = child.stdin.take().expect("stdin is piped");
        stdin.write_all(script.as_bytes()).await?;
        drop(stdin);
        let out = child.wait_with_output().await?;
        if out.status.success() {
            Ok(())
        } else {
            bail!(
                "nft failed: {}",
                String::from_utf8_lossy(&out.stderr).trim()
            )
        }
    }

    pub async fn create_tables(&self) -> Result<()> {
        self.run(&self.render_create()).await
    }

    pub async fn delete_tables(&self) -> Result<()> {
        let mut script = String::new();
        for fam in [Family::V4, Family::V6] {
            let t = self.table_name(fam);
            script.push_str(&format!(
                "add table {kw} {t}\ndelete table {kw} {t}\n",
                kw = fam.keyword()
            ));
        }
        self.run(&script).await
    }

    /// Adds IPs / CIDRs (timeout in seconds, `None` = permanent).
    pub async fn add_addresses(
        &self,
        set: &str,
        addrs: &[String],
        timeout: Option<u64>,
    ) -> Result<()> {
        if addrs.is_empty() {
            return Ok(());
        }
        let parsed = addrs
            .iter()
            .map(|a| normalize_addr(a))
            .collect::<Result<Vec<_>>>()?;
        let timeout = timeout.filter(|t| *t > 0);
        self.run(
            &self
                .element_cmds("add", set, &parsed, timeout, CHUNK)
                .join("\n"),
        )
        .await
    }

    /// Removes IPs / CIDRs; elements that are not in the set are ignored.
    pub async fn remove_addresses(&self, set: &str, addrs: &[String]) -> Result<()> {
        if addrs.is_empty() {
            return Ok(());
        }
        let parsed = addrs
            .iter()
            .map(|a| normalize_addr(a))
            .collect::<Result<Vec<_>>>()?;
        if self
            .run(
                &self
                    .element_cmds("delete", set, &parsed, None, CHUNK)
                    .join("\n"),
            )
            .await
            .is_ok()
        {
            return Ok(());
        }
        // One of them was missing and nft aborts the whole transaction: go one by one.
        for cmd in self.element_cmds("delete", set, &parsed, None, 1) {
            if let Err(e) = self.run(&cmd).await {
                let msg = e.to_string();
                if !(msg.contains("does not exist") || msg.contains("No such file")) {
                    return Err(e);
                }
            }
        }
        Ok(())
    }

    /// Adds ports (both tcp and udp) to a port set of both tables.
    pub async fn add_ports(&self, set: &str, ports: &[u16]) -> Result<()> {
        if ports.is_empty() {
            return Ok(());
        }
        let mut cmds = Vec::new();
        for fam in [Family::V4, Family::V6] {
            for part in ports.chunks(CHUNK) {
                let items: Vec<String> = part
                    .iter()
                    .flat_map(|p| [format!("tcp . {p}"), format!("udp . {p}")])
                    .collect();
                cmds.push(format!(
                    "add element {} {} {} {{ {} }}",
                    fam.keyword(),
                    self.table_name(fam),
                    Self::set_name(set, fam),
                    items.join(", ")
                ));
            }
        }
        self.run(&cmds.join("\n")).await
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn nft(logging: bool, reply: bool) -> Nft {
        Nft::new(logging, reply)
    }

    #[test]
    fn script_contains_documented_rules() {
        let s = nft(true, true).render_create();
        assert!(s.contains("add table ip remnanode\ndelete table ip remnanode"));
        assert!(s.contains("add table ip6 remnanode6"));
        assert!(s.contains("set torrent-blocker6 { type ipv6_addr;"));
        assert!(s.contains("ct direction reply accept"));
        assert!(s.contains("ip saddr @torrent-blocker log prefix \"torrent-blocker: \" counter name \"torrent-blocker\" drop"));
        assert!(s.contains("ip6 daddr @egress-filter-ip6 counter name \"egress-filter-ip6\" drop"));
        assert!(s.contains("meta l4proto . th dport @egress-filter-port counter"));
    }

    #[test]
    fn logging_and_reply_flags_are_honoured() {
        let s = nft(false, false).render_create();
        assert!(!s.contains("log prefix"));
        assert!(!s.contains("ct direction reply"));
    }

    #[test]
    fn addresses_are_normalized_and_validated() {
        assert_eq!(normalize_addr("10.1.2.3/8").unwrap().1, "10.0.0.0/8");
        assert_eq!(normalize_addr("::1").unwrap().0, Family::V6);
        assert!(normalize_addr("1.2.3.4; flush ruleset").is_err());
        assert!(normalize_addr("example.com").is_err());
    }

    #[test]
    fn element_commands_split_by_family_with_timeout() {
        let n = nft(true, true);
        let el = vec![
            normalize_addr("1.2.3.4").unwrap(),
            normalize_addr("2001:db8::1").unwrap(),
        ];
        let cmds = n.element_cmds("add", TORRENT_BLOCKER_SET, &el, Some(60), 500);
        assert_eq!(
            cmds[0],
            "add element ip remnanode torrent-blocker { 1.2.3.4 timeout 60s }"
        );
        assert_eq!(
            cmds[1],
            "add element ip6 remnanode6 torrent-blocker6 { 2001:db8::1 timeout 60s }"
        );
        let del = n.element_cmds("delete", TORRENT_BLOCKER_SET, &el, Some(60), 500);
        assert_eq!(
            del[0],
            "delete element ip remnanode torrent-blocker { 1.2.3.4 }"
        );
    }

    /// Exercises the real kernel; skipped without CAP_NET_ADMIN or the nft binary.
    #[tokio::test]
    async fn live_ruleset_roundtrip() {
        let n = nft(true, true).with_table("rwnode_test");
        if !crate::sys::has_cap_net_admin() {
            eprintln!("skipped: no CAP_NET_ADMIN");
            return;
        }
        if n.create_tables().await.is_err() {
            eprintln!("skipped: nft unusable here");
            return;
        }
        n.add_addresses(
            TORRENT_BLOCKER_SET,
            &["1.2.3.4".into(), "2001:db8::1".into()],
            Some(3600),
        )
        .await
        .unwrap();
        n.add_addresses(
            INGRESS_FILTER_IP_SET,
            &["10.0.0.0/8".into(), "10.1.0.0/16".into()],
            None,
        )
        .await
        .unwrap();
        n.add_ports(EGRESS_FILTER_PORT_SET, &[25, 465])
            .await
            .unwrap();
        n.remove_addresses(TORRENT_BLOCKER_SET, &["1.2.3.4".into(), "9.9.9.9".into()])
            .await
            .unwrap();

        let listing = Command::new("nft")
            .args(["list", "table", "ip", "rwnode_test"])
            .output()
            .await
            .unwrap();
        let text = String::from_utf8_lossy(&listing.stdout).to_string();
        assert!(text.contains("10.0.0.0/8"), "{text}");
        assert!(text.contains("tcp . 25"), "{text}");
        assert!(!text.contains("1.2.3.4"), "{text}");

        n.delete_tables().await.unwrap();
    }
}
