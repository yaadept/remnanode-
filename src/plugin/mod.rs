pub mod asn;
pub mod nft;

use std::{
    collections::{HashMap, HashSet},
    net::IpAddr,
    os::unix::fs::FileTypeExt,
    path::Path,
    sync::{
        Mutex,
        atomic::{AtomicBool, Ordering},
    },
    time::Duration,
};

use anyhow::{Result, bail};
use chrono::{DateTime, SecondsFormat, Utc};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use sha2::{Digest, Sha256};

use crate::{
    sys::has_cap_net_admin,
    xray::config_gen::{TORRENT_BLOCKER_OUTBOUND_TAG, TorrentBlockerState as TorrentBlockerCfg},
};
use asn::AsnDb;
use nft::Nft;

const DEFAULT_IGNORED_IPS: [&str; 7] = [
    "::",
    "::1",
    "0.0.0.0",
    "0.0.0.0/0",
    "127.0.0.0/8",
    "127.0.0.1",
    "255.255.255.255",
];

// ------------------------------------------------------------------ schema

#[derive(Debug, Deserialize)]
#[serde(tag = "type")]
enum SharedList {
    #[serde(rename = "ipList")]
    IpList { name: String, items: Vec<String> },
    #[serde(rename = "asList")]
    AsList { name: String, items: Vec<u32> },
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct IgnoreLists {
    ip: Option<Vec<String>>,
    user_id: Option<Vec<i64>>,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct TorrentBlockerPlugin {
    enabled: bool,
    block_duration: i64,
    ignore_lists: IgnoreLists,
    include_rule_tags: Option<Vec<String>>,
    webhook_url: Option<String>,
    rule_placement: Option<f64>,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct ConnectionDropPlugin {
    enabled: bool,
    whitelist_ips: Vec<String>,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct IngressFilterPlugin {
    enabled: bool,
    blocked_ips: Vec<String>,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct EgressFilterPlugin {
    enabled: bool,
    blocked_ips: Option<Vec<String>>,
    blocked_ports: Option<Vec<u32>>,
}

#[derive(Debug, Clone, Default, Deserialize)]
struct CleanupSockets {
    enabled: bool,
    files: Vec<String>,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct PreStartPlugin {
    #[serde(default)]
    enabled: bool,
    cleanup_sockets: Option<CleanupSockets>,
}

#[derive(Debug, Clone, Default, Deserialize)]
struct Webhook {
    enabled: bool,
    url: String,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct PostStartPlugin {
    #[serde(default)]
    enabled: bool,
    webhook: Option<Webhook>,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct NodePlugin {
    #[serde(default)]
    shared_lists: Vec<SharedList>,
    torrent_blocker: Option<TorrentBlockerPlugin>,
    ingress_filter: Option<IngressFilterPlugin>,
    egress_filter: Option<EgressFilterPlugin>,
    connection_drop: Option<ConnectionDropPlugin>,
    pre_start: Option<PreStartPlugin>,
    post_start: Option<PostStartPlugin>,
}

fn is_ip_or_cidr(s: &str) -> bool {
    s.parse::<IpAddr>().is_ok() || s.parse::<ipnet::IpNet>().is_ok()
}

fn is_http_url(s: &str) -> bool {
    (s.starts_with("http://") || s.starts_with("https://")) && s.len() > 8
}

impl NodePlugin {
    /// The checks zod does in the original schema that serde cannot express.
    fn validate(&self) -> Result<()> {
        for list in &self.shared_lists {
            match list {
                SharedList::IpList { name, items } => {
                    if !name.starts_with("ext:") {
                        bail!("shared list name must start with \"ext:\"");
                    }
                    if let Some(bad) = items.iter().find(|i| !is_ip_or_cidr(i)) {
                        bail!("invalid IP/CIDR in shared list {name}: {bad}");
                    }
                }
                SharedList::AsList { name, items } => {
                    if !name.starts_with("ext:") {
                        bail!("shared list name must start with \"ext:\"");
                    }
                    if items.contains(&0) {
                        bail!("ASN must be between 1 and 4294967295");
                    }
                }
            }
        }
        let ip_or_ext = |v: &str| v.starts_with("ext:") || is_ip_or_cidr(v);
        if let Some(tb) = &self.torrent_blocker {
            if let Some(r) = tb.rule_placement
                && !(0.0..=1000.0).contains(&r)
            {
                bail!("rulePlacement must be within 0..=1000");
            }
            if tb.include_rule_tags.as_ref().is_some_and(|t| t.is_empty()) {
                bail!("includeRuleTags must contain at least one tag");
            }
            if tb.webhook_url.as_deref().is_some_and(|u| !is_http_url(u)) {
                bail!("torrentBlocker.webhookUrl is not a valid URL");
            }
            if let Some(ips) = &tb.ignore_lists.ip
                && let Some(bad) = ips.iter().find(|i| !ip_or_ext(i))
            {
                bail!("invalid ignore IP: {bad}");
            }
        }
        if let Some(cd) = &self.connection_drop
            && let Some(bad) = cd.whitelist_ips.iter().find(|i| !ip_or_ext(i))
        {
            bail!("invalid whitelist IP: {bad}");
        }
        if let Some(f) = &self.ingress_filter
            && let Some(bad) = f.blocked_ips.iter().find(|i| !ip_or_ext(i))
        {
            bail!("invalid blocked IP: {bad}");
        }
        if let Some(f) = &self.egress_filter {
            if let Some(bad) = f.blocked_ips.iter().flatten().find(|i| !ip_or_ext(i)) {
                bail!("invalid blocked IP: {bad}");
            }
            if f.blocked_ports
                .iter()
                .flatten()
                .any(|p| !(1..=65535).contains(p))
            {
                bail!("blocked ports must be within 1..=65535");
            }
        }
        if let Some(ps) = &self.pre_start
            && let Some(cs) = &ps.cleanup_sockets
        {
            if cs.files.len() > 64 {
                bail!("No more than 64 entries allowed");
            }
            if cs
                .files
                .iter()
                .any(|f| f.trim().is_empty() || !f.trim().starts_with('/') || f.contains('\0'))
            {
                bail!("cleanup paths must be absolute");
            }
        }
        if let Some(po) = &self.post_start
            && let Some(w) = &po.webhook
            && !is_http_url(&w.url)
        {
            bail!("postStart.webhook.url must be a valid http(s) URL");
        }
        Ok(())
    }
}

// ------------------------------------------------------------------ request / report types

#[derive(Debug, Deserialize)]
pub struct SyncPlugin {
    pub config: serde_json::Map<String, Value>,
    pub uuid: String,
    pub name: String,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct XrayWebhook {
    pub email: Option<String>,
    pub level: Option<f64>,
    pub protocol: Option<String>,
    pub network: String,
    pub source: Option<String>,
    pub destination: String,
    pub route_target: Option<String>,
    pub original_target: Option<String>,
    pub inbound_tag: Option<String>,
    pub inbound_name: Option<String>,
    pub inbound_local: Option<String>,
    pub outbound_tag: Option<String>,
    pub ts: f64,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ActionReport {
    pub blocked: bool,
    pub ip: String,
    pub block_duration: i64,
    pub will_unblock_at: String,
    pub user_id: String,
    pub processed_at: String,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct TorrentBlockerReport {
    pub action_report: ActionReport,
    pub xray_report: XrayWebhook,
}

/// What the caller must do after `sync` (the plugin service does not own the Xray process).
#[derive(Debug, Default, PartialEq, Eq)]
pub struct SyncOutcome {
    pub accepted: bool,
    pub stop_xray: bool,
    pub remove_torrent_outbound: bool,
}

// ------------------------------------------------------------------ state

#[derive(Default)]
struct TorrentBlocker {
    enabled: bool,
    block_duration: Option<i64>,
    ignored_ips: HashSet<String>,
    ignored_users: HashSet<String>,
    include_rule_tags: HashSet<String>,
    webhook_url: Option<String>,
    rule_position: i64,
    reports: Vec<TorrentBlockerReport>,
}

#[derive(Clone, Copy)]
struct Available {
    connection_drop: bool,
    ingress_filter: bool,
    egress_filter: bool,
    torrent_blocker: bool,
    pre_start: bool,
    post_start: bool,
}

#[derive(Default)]
struct State {
    torrent: TorrentBlocker,
    whitelist_ips: HashSet<String>,
    pre_start_enabled: bool,
    cleanup_sockets: CleanupSockets,
    post_start_enabled: bool,
    post_start_webhook: Webhook,
    last_config_hash: Option<String>,
    active_plugin: Option<(String, String)>,
}

impl State {
    fn reset(&mut self) {
        self.torrent.enabled = false;
        self.torrent.block_duration = None;
        self.torrent.ignored_ips.clear();
        self.torrent.ignored_users.clear();
        self.torrent.include_rule_tags.clear();
        self.torrent.rule_position = 0;
        self.whitelist_ips.clear();
        self.pre_start_enabled = false;
        self.cleanup_sockets = CleanupSockets::default();
        self.post_start_enabled = false;
        self.post_start_webhook = Webhook::default();
    }

    fn clean_active(&mut self) {
        self.active_plugin = None;
        self.last_config_hash = None;
    }
}

pub struct PluginService {
    state: Mutex<State>,
    available: Mutex<Available>,
    nft: Nft,
    nft_ready: AtomicBool,
    asn: Option<AsnDb>,
    http: reqwest::Client,
}

pub fn now_iso(t: DateTime<Utc>) -> String {
    t.to_rfc3339_opts(SecondsFormat::Millis, true)
}

fn hash_value(v: &impl Serialize) -> String {
    hex::encode(Sha256::digest(serde_json::to_vec(v).unwrap_or_default()))
}

impl PluginService {
    pub fn new(nft: Nft, asn: Option<AsnDb>) -> Self {
        Self {
            state: Mutex::new(State::default()),
            available: Mutex::new(Available {
                connection_drop: false,
                ingress_filter: false,
                egress_filter: false,
                torrent_blocker: false,
                pre_start: true,
                post_start: true,
            }),
            nft,
            nft_ready: AtomicBool::new(false),
            asn,
            http: reqwest::Client::builder()
                .timeout(Duration::from_secs(5))
                .build()
                .expect("static client config"),
        }
    }

    /// Detects what this host allows (mirrors `NftService.onModuleInit`).
    pub async fn init(&self) {
        if !has_cap_net_admin() {
            tracing::warn!(
                "[PLUGIN] CAP_NET_ADMIN is not available, firewall plugins are disabled."
            );
        } else {
            self.available.lock().unwrap().connection_drop = true;
            match self.nft.create_tables().await {
                Ok(()) => {
                    self.nft_ready.store(true, Ordering::SeqCst);
                    let mut a = self.available.lock().unwrap();
                    a.ingress_filter = true;
                    a.egress_filter = true;
                    a.torrent_blocker = true;
                }
                Err(e) => {
                    tracing::error!("{e:#}");
                    tracing::warn!("[PLUGIN] nftables initialization failed.");
                }
            }
        }
        let a = *self.available.lock().unwrap();
        for (name, on) in [
            ("Ingress Filter", a.ingress_filter),
            ("Egress Filter", a.egress_filter),
            ("Torrent Blocker", a.torrent_blocker),
            ("Connection Drop", a.connection_drop),
        ] {
            if on {
                tracing::info!("[PLUGIN] {name}: available");
            } else {
                tracing::warn!("[PLUGIN] {name}: not available");
            }
        }
    }

    pub async fn shutdown(&self) {
        if self.nft_ready.load(Ordering::SeqCst)
            && let Err(e) = self.nft.delete_tables().await
        {
            tracing::error!("{e:#}");
        }
    }

    // ---------------------------------------------------------------- queries used elsewhere

    pub fn torrent_blocker_cfg(&self) -> TorrentBlockerCfg {
        let s = self.state.lock().unwrap();
        TorrentBlockerCfg {
            enabled: s.torrent.enabled,
            include_rule_tags: s.torrent.include_rule_tags.clone(),
            rule_position: s.torrent.rule_position,
        }
    }

    pub fn reports_count(&self) -> usize {
        self.state.lock().unwrap().torrent.reports.len()
    }

    pub fn collect_reports(&self) -> Vec<TorrentBlockerReport> {
        std::mem::take(&mut self.state.lock().unwrap().torrent.reports)
    }

    pub fn has_active_plugin(&self) -> bool {
        self.state.lock().unwrap().active_plugin.is_some()
    }

    // ---------------------------------------------------------------- lifecycle

    pub async fn reset(&self) {
        {
            let mut s = self.state.lock().unwrap();
            s.reset();
            s.clean_active();
        }
        self.recreate_tables().await;
    }

    async fn recreate_tables(&self) {
        if self.nft_ready.load(Ordering::SeqCst)
            && let Err(e) = self.nft.create_tables().await
        {
            tracing::error!("{e:#}");
        }
    }

    pub async fn sync(&self, plugin: Option<SyncPlugin>) -> SyncOutcome {
        match self.sync_inner(plugin).await {
            Ok(o) => o,
            Err(e) => {
                tracing::error!("{e:#}");
                SyncOutcome::default()
            }
        }
    }

    async fn sync_inner(&self, plugin: Option<SyncPlugin>) -> Result<SyncOutcome> {
        let stop = SyncOutcome {
            accepted: true,
            stop_xray: true,
            remove_torrent_outbound: false,
        };

        let Some(plugin) = plugin else {
            if !self.has_active_plugin() {
                return Ok(SyncOutcome::default());
            }
            tracing::info!(
                "[PLUGIN] Received empty plugins, but there is an active plugin. Cleaning up..."
            );
            self.reset().await;
            return Ok(stop);
        };

        let config_hash = hash_value(&plugin.config);
        if self.state.lock().unwrap().last_config_hash.as_deref() == Some(config_hash.as_str()) {
            tracing::debug!("[PLUGIN] Config unchanged. Skipping sync.");
            return Ok(SyncOutcome {
                accepted: true,
                ..Default::default()
            });
        }

        let parsed: NodePlugin = match serde_json::from_value(Value::Object(plugin.config.clone()))
            .map_err(anyhow::Error::from)
            .and_then(|p: NodePlugin| p.validate().map(|_| p))
        {
            Ok(p) => p,
            Err(e) => {
                tracing::error!("[PLUGIN] Invalid config: {e}");
                self.reset().await;
                return Ok(SyncOutcome {
                    accepted: false,
                    stop_xray: true,
                    remove_torrent_outbound: false,
                });
            }
        };

        let (cur_enabled, cur_tags, cur_pos) = {
            let s = self.state.lock().unwrap();
            (
                s.torrent.enabled,
                s.torrent.include_rule_tags.clone(),
                s.torrent.rule_position,
            )
        };

        let shared = self.resolve_shared_lists(&parsed.shared_lists).await;

        {
            let mut s = self.state.lock().unwrap();
            s.reset();
            s.clean_active();
        }
        self.recreate_tables().await;

        let avail = *self.available.lock().unwrap();
        let nft_ready = self.nft_ready.load(Ordering::SeqCst);

        // connection drop
        if let Some(cd) = parsed
            .connection_drop
            .as_ref()
            .filter(|c| c.enabled && avail.connection_drop)
        {
            let ips = self.resolve_ip_list(&cd.whitelist_ips, &shared);
            tracing::info!(
                "[PLUGIN] Connection-Drop: {} whitelisted IPs synced.",
                ips.len()
            );
            self.state.lock().unwrap().whitelist_ips = ips.into_iter().collect();
        }

        // torrent blocker
        if let Some(tb) = parsed
            .torrent_blocker
            .as_ref()
            .filter(|t| t.enabled && nft_ready)
        {
            let ips = self.resolve_ip_list(tb.ignore_lists.ip.as_deref().unwrap_or(&[]), &shared);
            let users: Vec<String> = tb
                .ignore_lists
                .user_id
                .iter()
                .flatten()
                .map(|u| u.to_string())
                .collect();
            tracing::info!(
                "[PLUGIN] Torrent-Blocker: blockDuration={}s, {} ignored IPs, {} ignored users",
                tb.block_duration,
                ips.len(),
                users.len()
            );
            let mut s = self.state.lock().unwrap();
            s.torrent.ignored_ips = ips.into_iter().collect();
            s.torrent.ignored_users = users.into_iter().collect();
            s.torrent.enabled = true;
            s.torrent.block_duration = Some(tb.block_duration);
            s.torrent.rule_position = tb.rule_placement.unwrap_or(0.0) as i64;
            s.torrent.webhook_url = tb.webhook_url.clone();
            if let Some(tags) = &tb.include_rule_tags {
                s.torrent.include_rule_tags = tags.iter().cloned().collect();
            }
        }

        // pre-start
        if let Some(ps) = parsed
            .pre_start
            .as_ref()
            .filter(|p| p.enabled && avail.pre_start)
        {
            let cs = ps.cleanup_sockets.clone().unwrap_or_default();
            tracing::info!(
                "[PLUGIN] Pre-Start: socket cleanup {}.",
                if cs.enabled {
                    format!("enabled, {} path(s)", cs.files.len())
                } else {
                    "disabled".into()
                }
            );
            let mut s = self.state.lock().unwrap();
            s.pre_start_enabled = true;
            s.cleanup_sockets = cs;
        }

        // post-start
        if let Some(po) = parsed
            .post_start
            .as_ref()
            .filter(|p| p.enabled && avail.post_start)
        {
            let wh = po.webhook.clone().unwrap_or_default();
            tracing::info!(
                "[PLUGIN] Post-Start: webhook {}.",
                if wh.enabled { "enabled" } else { "disabled" }
            );
            let mut s = self.state.lock().unwrap();
            s.post_start_enabled = true;
            s.post_start_webhook = wh;
        }

        // ingress / egress filters
        if let Some(f) = parsed
            .ingress_filter
            .as_ref()
            .filter(|f| f.enabled && nft_ready)
        {
            let ips = self.resolve_ip_list(&f.blocked_ips, &shared);
            if let Err(e) = self
                .nft
                .add_addresses(nft::INGRESS_FILTER_IP_SET, &ips, None)
                .await
            {
                tracing::error!("{e:#}");
            }
            tracing::info!("[PLUGIN] Ingress Filter: {} IPs synced.", ips.len());
        }
        if let Some(f) = parsed
            .egress_filter
            .as_ref()
            .filter(|f| f.enabled && nft_ready)
        {
            let ips = self.resolve_ip_list(f.blocked_ips.as_deref().unwrap_or(&[]), &shared);
            let ports: Vec<u16> = f
                .blocked_ports
                .iter()
                .flatten()
                .map(|p| *p as u16)
                .collect();
            if let Err(e) = self
                .nft
                .add_addresses(nft::EGRESS_FILTER_IP_SET, &ips, None)
                .await
            {
                tracing::error!("{e:#}");
            }
            if let Err(e) = self
                .nft
                .add_ports(nft::EGRESS_FILTER_PORT_SET, &ports)
                .await
            {
                tracing::error!("{e:#}");
            }
            tracing::info!(
                "[PLUGIN] Egress Filter: {} IPs, {} ports synced.",
                ips.len(),
                ports.len()
            );
        }

        {
            let mut s = self.state.lock().unwrap();
            s.last_config_hash = Some(config_hash);
            s.active_plugin = Some((plugin.uuid, plugin.name));
        }
        tracing::info!("[PLUGIN] Plugins changed...");

        let was_enabled = cur_enabled;
        let now_tb = parsed.torrent_blocker.as_ref();
        let now_enabled = now_tb.is_some_and(|t| t.enabled);
        let now_has_tags = now_tb.is_some_and(|t| t.include_rule_tags.is_some());

        let mut out = SyncOutcome {
            accepted: true,
            ..Default::default()
        };
        if was_enabled && !now_enabled && !now_has_tags {
            out.remove_torrent_outbound = true;
        } else {
            let still = was_enabled && now_enabled;
            let new_tags: HashSet<&String> = now_tb
                .and_then(|t| t.include_rule_tags.as_ref())
                .into_iter()
                .flatten()
                .collect();
            let old_tags: HashSet<&String> = cur_tags.iter().collect();
            let new_pos = now_tb.and_then(|t| t.rule_placement).unwrap_or(0.0) as i64;
            out.stop_xray = (was_enabled && !now_enabled)
                || (!was_enabled && now_enabled)
                || (still && old_tags != new_tags)
                || (still && cur_pos != new_pos);
        }
        Ok(out)
    }

    fn resolve_ip_list(
        &self,
        ips: &[String],
        shared: &HashMap<String, Vec<String>>,
    ) -> Vec<String> {
        ips.iter()
            .flat_map(|ip| {
                if ip.starts_with("ext:") {
                    match shared.get(ip) {
                        Some(list) => list.clone(),
                        None => {
                            tracing::warn!("[PLUGIN] Shared IP list \"{ip}\" not found");
                            Vec::new()
                        }
                    }
                } else {
                    vec![ip.clone()]
                }
            })
            .collect()
    }

    async fn resolve_shared_lists(&self, lists: &[SharedList]) -> HashMap<String, Vec<String>> {
        let mut map = HashMap::new();
        for list in lists {
            match list {
                SharedList::IpList { name, items } => {
                    map.insert(name.clone(), items.clone());
                }
                SharedList::AsList { name, items } => {
                    let mut prefixes = Vec::new();
                    for asn in items {
                        let found = match &self.asn {
                            Some(db) => db.prefixes(*asn).unwrap_or_else(|e| {
                                tracing::error!("[PLUGIN] ASN lookup failed: {e:#}");
                                None
                            }),
                            None => None,
                        };
                        match found {
                            Some(p) => {
                                tracing::info!(
                                    "[PLUGIN] ASN {asn} resolved: {} IPv4, {} IPv6",
                                    p.ipv4.len(),
                                    p.ipv6.len()
                                );
                                prefixes.extend(p.ipv4);
                                prefixes.extend(p.ipv6);
                            }
                            None => tracing::warn!("[PLUGIN] ASN {asn} not found"),
                        }
                    }
                    map.insert(name.clone(), prefixes);
                }
            }
        }
        map
    }

    // ---------------------------------------------------------------- nft endpoints

    pub async fn block_ips(&self, ips: &[(String, u64)]) -> bool {
        if !self.nft_ready.load(Ordering::SeqCst) {
            return false;
        }
        for (ip, timeout) in ips {
            if let Err(e) = self.block_ip(ip, *timeout).await {
                tracing::error!("{e:#}");
                return false;
            }
        }
        true
    }

    pub async fn block_ip(&self, ip: &str, timeout_secs: u64) -> Result<()> {
        if !self.nft_ready.load(Ordering::SeqCst) {
            return Ok(());
        }
        self.nft
            .add_addresses(
                nft::TORRENT_BLOCKER_SET,
                &[ip.to_string()],
                Some(timeout_secs).filter(|t| *t > 0),
            )
            .await?;
        self.drop_connections(vec![ip.to_string()]).await;
        Ok(())
    }

    pub async fn unblock_ips(&self, ips: &[String]) -> bool {
        if !self.nft_ready.load(Ordering::SeqCst) {
            return false;
        }
        let r1 = self
            .nft
            .remove_addresses(nft::TORRENT_BLOCKER_SET, ips)
            .await;
        let r2 = self
            .nft
            .remove_addresses(nft::INGRESS_FILTER_IP_SET, ips)
            .await;
        match (r1, r2) {
            (Ok(()), Ok(())) => true,
            (a, b) => {
                for e in [a.err(), b.err()].into_iter().flatten() {
                    tracing::error!("{e:#}");
                }
                false
            }
        }
    }

    pub async fn recreate_tables_endpoint(&self) -> bool {
        if !self.nft_ready.load(Ordering::SeqCst) {
            return false;
        }
        match self.nft.create_tables().await {
            Ok(()) => true,
            Err(e) => {
                tracing::error!("{e:#}");
                false
            }
        }
    }

    // ---------------------------------------------------------------- connection drop

    pub async fn drop_connections(&self, ips: Vec<String>) {
        if ips.is_empty() || !self.available.lock().unwrap().connection_drop {
            return;
        }
        let targets: Vec<IpAddr> = {
            let s = self.state.lock().unwrap();
            ips.iter()
                .filter(|ip| {
                    !s.whitelist_ips.contains(*ip) && !DEFAULT_IGNORED_IPS.contains(&ip.as_str())
                })
                .filter_map(|ip| ip.parse().ok())
                .collect()
        };
        if targets.is_empty() {
            return;
        }
        let started = std::time::Instant::now();
        match tokio::task::spawn_blocking(move || crate::sockdestroy::kill_sockets(&targets)).await
        {
            Ok(Ok(r)) => tracing::debug!(
                "Destroyed connections: matched={} destroyed={} failed={} in {:?}",
                r.matched,
                r.destroyed,
                r.failed,
                started.elapsed()
            ),
            Ok(Err(e)) => tracing::error!("Error in DropConnections: {e}"),
            Err(e) => tracing::error!("Error in DropConnections: {e}"),
        }
    }

    // ---------------------------------------------------------------- torrent webhook

    pub async fn handle_xray_webhook(&self, body: Value) {
        let (enabled, duration) = {
            let s = self.state.lock().unwrap();
            (s.torrent.enabled, s.torrent.block_duration)
        };
        if !enabled {
            return;
        }
        let hook: XrayWebhook = match serde_json::from_value(body) {
            Ok(h) => h,
            Err(e) => {
                tracing::error!("Invalid webhook: {e}");
                return;
            }
        };
        tracing::debug!("{}", serde_json::to_string(&hook).unwrap_or_default());

        let Some(ip) = extract_ip(hook.source.as_deref()) else {
            return;
        };
        let Some(email) = hook.email.clone() else {
            return;
        };

        let whitelisted = {
            let s = self.state.lock().unwrap();
            s.torrent.ignored_ips.contains(&ip)
                || DEFAULT_IGNORED_IPS.contains(&ip.as_str())
                || s.torrent.ignored_users.contains(&email)
        };
        if whitelisted {
            return;
        }

        let block_duration = duration.unwrap_or(0);
        let mut blocked = false;
        match self.block_ip(&ip, block_duration.max(0) as u64).await {
            Ok(()) => {
                blocked = true;
                tracing::info!(
                    "[TORRENT-BLOCKER] IP: {ip}, user: {email}, blocked: {blocked}, duration: {block_duration}s"
                );
            }
            Err(e) => tracing::error!("Failed to block IP {ip}: {e:#}"),
        }

        let now = Utc::now();
        let will_unblock_at = chrono::Duration::try_seconds(block_duration)
            .and_then(|d| now.checked_add_signed(d))
            .unwrap_or(DateTime::<Utc>::MAX_UTC);
        let report = TorrentBlockerReport {
            action_report: ActionReport {
                blocked,
                ip,
                block_duration,
                will_unblock_at: now_iso(will_unblock_at),
                user_id: email,
                processed_at: now_iso(now),
            },
            xray_report: hook,
        };

        let webhook_url = {
            let mut s = self.state.lock().unwrap();
            s.torrent.reports.push(report.clone());
            s.torrent.webhook_url.clone()
        };
        if let Some(url) = webhook_url {
            self.send_webhook(url, serde_json::to_value(&report).unwrap_or_default(), None);
        }
    }

    pub fn send_webhook(&self, url: String, body: Value, on_error: Option<&'static str>) {
        let client = self.http.clone();
        tokio::spawn(async move {
            match client.post(&url).json(&body).send().await {
                Ok(r) if r.status().is_success() => {}
                Ok(r) => {
                    if let Some(ctx) = on_error {
                        tracing::warn!("{ctx} Webhook failed: HTTP {}", r.status());
                    }
                }
                Err(e) => {
                    if let Some(ctx) = on_error {
                        tracing::warn!("{ctx} Webhook failed: {e}");
                    }
                }
            }
        });
    }

    // ---------------------------------------------------------------- pre / post start

    pub async fn run_pre_start(&self) {
        let (enabled, cs) = {
            let s = self.state.lock().unwrap();
            (
                s.pre_start_enabled && self.available.lock().unwrap().pre_start,
                s.cleanup_sockets.clone(),
            )
        };
        if !enabled || !cs.enabled || cs.files.is_empty() {
            return;
        }
        let started = std::time::Instant::now();
        let removed = tokio::task::spawn_blocking(move || cleanup_sockets(&cs.files))
            .await
            .unwrap_or(0);
        tracing::info!("[PRE-START] Cleanup Sockets: {removed} stale socket(s) removed.");
        tracing::info!("[PRE-START] Stage completed in {:?}", started.elapsed());
    }

    pub fn run_post_start(&self, metadata: Option<&Value>) {
        let (enabled, wh) = {
            let s = self.state.lock().unwrap();
            (
                s.post_start_enabled && self.available.lock().unwrap().post_start,
                s.post_start_webhook.clone(),
            )
        };
        if !enabled || !wh.enabled {
            return;
        }
        self.send_webhook(
            wh.url,
            serde_json::json!({
                "scope": "service",
                "event": "service.core_started",
                "timestamp": now_iso(Utc::now()),
                "metadata": metadata.cloned().unwrap_or_else(|| serde_json::json!({})),
            }),
            Some("[POST-START]"),
        );
    }
}

const MAX_MATCHES_PER_PATTERN: usize = 256;

fn cleanup_sockets(patterns: &[String]) -> usize {
    let mut removed = 0;
    for pattern in patterns {
        let magic = pattern.contains(['*', '?', '[']);
        let paths: Vec<std::path::PathBuf> = if magic {
            match glob::glob(pattern) {
                Ok(it) => {
                    let mut v: Vec<_> = it.flatten().take(MAX_MATCHES_PER_PATTERN + 1).collect();
                    if v.len() > MAX_MATCHES_PER_PATTERN {
                        tracing::warn!(
                            "[PRE-START] Cleanup Sockets: pattern \"{pattern}\" matched more than {MAX_MATCHES_PER_PATTERN} entries, the rest is skipped."
                        );
                        v.truncate(MAX_MATCHES_PER_PATTERN);
                    }
                    v
                }
                Err(e) => {
                    tracing::warn!(
                        "[PRE-START] Cleanup Sockets: failed to expand pattern \"{pattern}\": {e}"
                    );
                    continue;
                }
            }
        } else {
            vec![Path::new(pattern).to_path_buf()]
        };
        for path in paths {
            match std::fs::symlink_metadata(&path) {
                Ok(m) if m.file_type().is_socket() => match std::fs::remove_file(&path) {
                    Ok(()) => {
                        tracing::info!(
                            "[PRE-START] Cleanup Sockets: removed stale socket \"{}\".",
                            path.display()
                        );
                        removed += 1;
                    }
                    Err(e) => tracing::warn!(
                        "[PRE-START] Cleanup Sockets: failed to remove \"{}\": {e}",
                        path.display()
                    ),
                },
                Ok(_) => tracing::debug!(
                    "[PRE-START] Cleanup Sockets: \"{}\" is not a socket, skipped.",
                    path.display()
                ),
                Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
                Err(e) => tracing::warn!(
                    "[PRE-START] Cleanup Sockets: failed to stat \"{}\": {e}",
                    path.display()
                ),
            }
        }
    }
    removed
}

/// `[::1]:443`, `tcp:1.2.3.4:5678`, `udp:[2001:db8::1]:53` -> the bare IP.
pub fn extract_ip(source: Option<&str>) -> Option<String> {
    let mut s = source?;
    for prefix in ["tcp:", "udp:"] {
        if let Some(rest) = s.strip_prefix(prefix) {
            s = rest;
            break;
        }
    }
    let candidate = if let Some(rest) = s.strip_prefix('[') {
        rest.split_once(']')?.0
    } else if s.parse::<IpAddr>().is_ok() {
        s
    } else {
        match s.rsplit_once(':') {
            Some((host, port)) if !port.is_empty() && port.bytes().all(|b| b.is_ascii_digit()) => {
                host
            }
            _ => s,
        }
    };
    candidate.parse::<IpAddr>().ok().map(|ip| ip.to_string())
}

pub fn torrent_outbound_tag() -> &'static str {
    TORRENT_BLOCKER_OUTBOUND_TAG
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn plugin(cfg: Value) -> Option<SyncPlugin> {
        Some(SyncPlugin {
            config: cfg.as_object().unwrap().clone(),
            uuid: "00000000-0000-0000-0000-000000000000".into(),
            name: "t".into(),
        })
    }

    fn svc() -> PluginService {
        PluginService::new(Nft::new(false, false), None)
    }

    #[tokio::test]
    async fn absurd_block_duration_does_not_panic() {
        let s = svc();
        {
            let mut st = s.state.lock().unwrap();
            st.torrent.enabled = true;
            st.torrent.block_duration = Some(i64::MAX);
        }
        let hook = json!({
            "email": "u", "level": 0, "protocol": "bittorrent", "network": "tcp",
            "source": "tcp:203.0.113.9:1", "destination": "tcp:1.2.3.4:6881",
            "routeTarget": null, "originalTarget": null, "inboundTag": null, "inboundName": null,
            "inboundLocal": null, "outboundTag": null, "ts": 1
        });
        s.handle_xray_webhook(hook).await;
        let reports = s.collect_reports();
        assert_eq!(reports.len(), 1);
        assert!(!reports[0].action_report.will_unblock_at.is_empty());
    }

    #[test]
    fn source_parsing() {
        assert_eq!(extract_ip(Some("1.2.3.4:5678")).as_deref(), Some("1.2.3.4"));
        assert_eq!(
            extract_ip(Some("tcp:1.2.3.4:5678")).as_deref(),
            Some("1.2.3.4")
        );
        assert_eq!(
            extract_ip(Some("udp:[2001:db8::1]:53")).as_deref(),
            Some("2001:db8::1")
        );
        assert_eq!(extract_ip(Some("[::1]:1")).as_deref(), Some("::1"));
        assert_eq!(extract_ip(Some("1.2.3.4")).as_deref(), Some("1.2.3.4"));
        assert_eq!(extract_ip(Some("not-an-ip:80")), None);
        assert_eq!(extract_ip(None), None);
    }

    #[tokio::test]
    async fn pre_and_post_start_sync_without_firewall() {
        let s = svc();
        let out = s
            .sync(plugin(json!({
                "preStart": {"enabled": true, "cleanupSockets": {"enabled": true, "files": ["/tmp/x.sock"]}},
                "postStart": {"enabled": true, "webhook": {"enabled": true, "url": "https://example.com/h"}}
            })))
            .await;
        assert!(out.accepted && !out.stop_xray);
        assert!(s.has_active_plugin());
        // identical config is a no-op
        let again = s
            .sync(plugin(json!({
                "preStart": {"enabled": true, "cleanupSockets": {"enabled": true, "files": ["/tmp/x.sock"]}},
                "postStart": {"enabled": true, "webhook": {"enabled": true, "url": "https://example.com/h"}}
            })))
            .await;
        assert_eq!(
            again,
            SyncOutcome {
                accepted: true,
                ..Default::default()
            }
        );
    }

    #[tokio::test]
    async fn invalid_config_is_rejected_and_stops_xray() {
        let s = svc();
        let out = s
            .sync(plugin(json!({"preStart": {"enabled": true, "cleanupSockets": {"enabled": true, "files": ["relative"]}}})))
            .await;
        assert_eq!(
            out,
            SyncOutcome {
                accepted: false,
                stop_xray: true,
                remove_torrent_outbound: false
            }
        );
        assert!(!s.has_active_plugin());
    }

    #[tokio::test]
    async fn empty_plugin_without_active_one_is_not_accepted() {
        assert_eq!(svc().sync(None).await, SyncOutcome::default());
    }

    #[tokio::test]
    async fn removing_active_plugin_stops_xray() {
        let s = svc();
        s.sync(plugin(json!({"postStart": {"enabled": true}})))
            .await;
        let out = s.sync(None).await;
        assert!(out.accepted && out.stop_xray);
        assert!(!s.has_active_plugin());
    }

    #[test]
    fn cleanup_only_removes_sockets() {
        let dir = tempfile::tempdir().unwrap();
        let sock = dir.path().join("a.sock");
        let _l = std::os::unix::net::UnixListener::bind(&sock).unwrap();
        let file = dir.path().join("b.sock");
        std::fs::write(&file, b"x").unwrap();
        let removed = cleanup_sockets(&[format!("{}/*.sock", dir.path().display())]);
        assert_eq!(removed, 1);
        assert!(!sock.exists());
        assert!(file.exists());
    }

    #[test]
    fn validation_catches_bad_values() {
        let bad: NodePlugin = serde_json::from_value(json!({
            "torrentBlocker": {"enabled": true, "blockDuration": 10, "ignoreLists": {"ip": ["nope"]}}
        }))
        .unwrap();
        assert!(bad.validate().is_err());
        let ok: NodePlugin = serde_json::from_value(json!({
            "sharedLists": [{"type": "ipList", "name": "ext:a", "items": ["1.1.1.1", "10.0.0.0/8"]}],
            "ingressFilter": {"enabled": true, "blockedIps": ["ext:a"]}
        }))
        .unwrap();
        assert!(ok.validate().is_ok());
    }
}
