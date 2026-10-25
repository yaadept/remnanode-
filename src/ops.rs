//! Business logic behind the REST endpoints: user management and statistics.

use std::{collections::HashMap, sync::Arc};

use base64::Engine;
use chrono::{DateTime, Utc};
use futures_util::StreamExt;
use serde::Serialize;
use serde_json::{Value, json};
use tonic::Code;

use crate::{
    app::App,
    dto::*,
    error::*,
    plugin::now_iso,
    sys,
    xray::grpc::{Account, Stat, XrayApi},
};

type R<T> = Result<T, ApiError>;

#[derive(Serialize)]
pub struct SuccessError {
    pub success: bool,
    pub error: Option<String>,
}

fn ok_err(success: bool, error: Option<String>) -> SuccessError {
    SuccessError { success, error }
}

/// Outcome of one gRPC call the way the TS SDK wraps it: `Ok(())` = isOk.
type SdkResult = Result<(), String>;

fn sdk(r: Result<bool, tonic::Status>, what: &str) -> SdkResult {
    r.map(|_| ())
        .map_err(|s| format!("Error {what}: {}", s.message()))
}

fn all_failed(results: &[SdkResult]) -> Option<String> {
    if results.iter().all(|r| r.is_err()) {
        Some(
            results
                .iter()
                .find_map(|r| r.as_ref().err().cloned())
                .unwrap_or_default(),
        )
    } else {
        None
    }
}

// ------------------------------------------------------------------ handler

impl App {
    async fn user_ips(&self, user_id: &str) -> Option<Vec<String>> {
        if !self.cap_net_admin {
            return None;
        }
        match self.xray.api.online_ip_list(user_id, true).await {
            Ok(ips) => Some(ips.into_keys().collect()),
            Err(s) if s.code() == Code::NotFound => None,
            Err(s) => {
                tracing::error!("Failed to get user IPs for user {user_id}: {}", s.message());
                None
            }
        }
    }

    fn drop_in_background(&self, ips: Option<Vec<String>>) {
        if let Some(ips) = ips {
            let plugins = self.plugins.clone();
            tokio::spawn(async move { plugins.drop_connections(ips).await });
        }
    }

    pub async fn add_user(&self, req: AddUserRequest) -> R<SuccessError> {
        let api = &self.xray.api;
        let Some(first) = req.data.first() else {
            return Err(ApiError::internal(
                "Cannot read properties of undefined (reading 'username')",
            ));
        };
        let user_id = first.username().to_string();
        let hash = &req.hash_data;

        for item in &req.data {
            self.internal.add_xtls_config_inbound(item.tag());
        }

        let user_ips = if hash.prev_vless_uuid.is_some() {
            self.user_ips(&user_id).await
        } else {
            None
        };

        for tag in self.internal.xtls_config_inbounds() {
            tracing::debug!("Removing user: {user_id} from tag: {tag}");
            let _ = api.remove_user(&tag, &user_id).await;
            let hashed = hash.prev_vless_uuid.as_deref().unwrap_or(&hash.vless_uuid);
            self.internal.remove_user_from_inbound(&tag, hashed);
        }

        if hash.prev_vless_uuid.is_some() {
            self.drop_in_background(user_ips);
        }

        let mut results: Vec<SdkResult> = Vec::new();
        for item in &req.data {
            tracing::debug!(
                "Adding user: {} with type: {}",
                item.username(),
                item_type(item)
            );
            let (tag, username, account) = match item {
                AddUserItem::Trojan {
                    tag,
                    username,
                    password,
                } => (
                    tag,
                    username,
                    Account::Trojan {
                        password: password.clone(),
                    },
                ),
                AddUserItem::Vless {
                    tag,
                    username,
                    uuid,
                    flow,
                } => (
                    tag,
                    username,
                    Account::Vless {
                        id: uuid.clone(),
                        flow: flow.clone(),
                    },
                ),
                AddUserItem::Shadowsocks {
                    tag,
                    username,
                    password,
                    cipher_type,
                    ..
                } => (
                    tag,
                    username,
                    Account::Shadowsocks {
                        password: password.clone(),
                        cipher_type: *cipher_type,
                        iv_check: false,
                    },
                ),
                AddUserItem::Shadowsocks22 {
                    tag,
                    username,
                    password,
                } => (
                    tag,
                    username,
                    Account::Shadowsocks2022 {
                        key: password.clone(),
                    },
                ),
                AddUserItem::Hysteria {
                    tag,
                    username,
                    password,
                } => (
                    tag,
                    username,
                    Account::Hysteria {
                        auth: password.clone(),
                    },
                ),
            };
            let r = api.add_user(tag, username, 0, account).await;
            if r.is_ok() {
                self.internal.add_user_to_inbound(tag, &hash.vless_uuid);
            }
            results.push(sdk(r, "adding user"));
        }

        if let Some(msg) = all_failed(&results) {
            tracing::error!("Error adding users: {msg}");
            return Ok(ok_err(false, Some(msg).filter(|m| !m.is_empty())));
        }
        Ok(ok_err(true, None))
    }

    pub async fn remove_user(&self, req: RemoveUserRequest) -> R<SuccessError> {
        let tags = self.internal.xtls_config_inbounds();
        if tags.is_empty() {
            return Ok(ok_err(true, None));
        }
        let user_ips = self.user_ips(&req.username).await;

        let mut results = Vec::new();
        for tag in &tags {
            tracing::debug!("Removing user: {} from tag: {tag}", req.username);
            results.push(sdk(
                self.xray.api.remove_user(tag, &req.username).await,
                "removing user",
            ));
            self.internal
                .remove_user_from_inbound(tag, &req.hash_data.vless_uuid);
        }
        self.drop_in_background(user_ips);

        if let Some(msg) = all_failed(&results) {
            tracing::error!("{msg}");
            return Ok(ok_err(false, Some(msg).filter(|m| !m.is_empty())));
        }
        Ok(ok_err(true, None))
    }

    pub async fn add_users(&self, req: AddUsersRequest) -> R<SuccessError> {
        let started = std::time::Instant::now();
        let api = &self.xray.api;

        for tag in &req.affected_inbound_tags {
            self.internal.add_xtls_config_inbound(tag);
        }
        tracing::info!(
            "Adding {} users to inbounds: {}",
            req.users.len(),
            req.affected_inbound_tags.join(", ")
        );

        for user in &req.users {
            let ud = &user.user_data;
            for tag in self.internal.xtls_config_inbounds() {
                let _ = api.remove_user(&tag, &ud.user_id).await;
                self.internal.remove_user_from_inbound(&tag, &ud.hash_uuid);
            }
            for item in &user.inbound_data {
                let (tag, account) = match item {
                    InboundData::Trojan { tag } => (
                        tag,
                        Account::Trojan {
                            password: ud.trojan_password.clone(),
                        },
                    ),
                    InboundData::Vless { tag, flow } => (
                        tag,
                        Account::Vless {
                            id: ud.vless_uuid.clone(),
                            flow: flow.clone(),
                        },
                    ),
                    InboundData::Shadowsocks { tag } => (
                        tag,
                        Account::Shadowsocks {
                            password: ud.ss_password.clone(),
                            cipher_type: 0,
                            iv_check: false,
                        },
                    ),
                    InboundData::Shadowsocks22 { tag } => (
                        tag,
                        Account::Shadowsocks2022 {
                            key: base64::engine::general_purpose::STANDARD
                                .encode(ud.ss_password.as_bytes()),
                        },
                    ),
                    InboundData::Hysteria { tag } => (
                        tag,
                        Account::Hysteria {
                            auth: ud.vless_uuid.clone(),
                        },
                    ),
                };
                if api.add_user(tag, &ud.user_id, 0, account).await.is_ok() {
                    self.internal.add_user_to_inbound(tag, &ud.vless_uuid);
                }
            }
        }
        tracing::info!("Users addition took: {:?}", started.elapsed());
        Ok(ok_err(true, None))
    }

    pub async fn remove_users(&self, req: RemoveUsersRequest) -> R<SuccessError> {
        let started = std::time::Instant::now();
        let tags = self.internal.xtls_config_inbounds();
        if tags.is_empty() {
            return Ok(ok_err(true, None));
        }
        tracing::info!(
            "Removing {} users from inbounds: {}",
            req.users.len(),
            tags.join(", ")
        );

        let mut results = Vec::new();
        for u in &req.users {
            let ips = self.user_ips(&u.user_id).await;
            for tag in &tags {
                tracing::debug!("Removing user: {} from tag: {tag}", u.user_id);
                results.push(sdk(
                    self.xray.api.remove_user(tag, &u.user_id).await,
                    "removing user",
                ));
                self.internal.remove_user_from_inbound(tag, &u.hash_uuid);
            }
            self.drop_in_background(ips);
        }
        tracing::info!("Users removal took: {:?}", started.elapsed());

        if let Some(msg) = all_failed(&results) {
            tracing::error!("{msg}");
            return Ok(ok_err(false, Some(msg).filter(|m| !m.is_empty())));
        }
        Ok(ok_err(true, None))
    }

    pub async fn drop_users_connections(&self, req: DropUsersConnectionsRequest) -> bool {
        for id in &req.user_ids {
            let ips = self.user_ips(id).await;
            self.drop_in_background(ips);
        }
        true
    }

    pub fn drop_ips(&self, req: DropIpsRequest) -> bool {
        self.drop_in_background(Some(req.ips));
        true
    }

    pub async fn remove_torrent_outbound(&self) {
        if let Err(s) = self
            .xray
            .api
            .remove_outbound(crate::plugin::torrent_outbound_tag())
            .await
        {
            tracing::error!("{}", s.message());
        }
    }
}

fn item_type(i: &AddUserItem) -> &'static str {
    match i {
        AddUserItem::Trojan { .. } => "trojan",
        AddUserItem::Vless { .. } => "vless",
        AddUserItem::Shadowsocks { .. } => "shadowsocks",
        AddUserItem::Shadowsocks22 { .. } => "shadowsocks22",
        AddUserItem::Hysteria { .. } => "hysteria",
    }
}

// ------------------------------------------------------------------ stats

#[derive(Serialize, Clone, Debug, PartialEq)]
pub struct Traffic {
    pub downlink: i64,
    pub uplink: i64,
}

#[derive(Serialize)]
pub struct UserTraffic {
    pub username: String,
    pub downlink: i64,
    pub uplink: i64,
}

#[derive(Serialize)]
pub struct InboundTraffic {
    pub inbound: String,
    pub downlink: i64,
    pub uplink: i64,
}

#[derive(Serialize)]
pub struct OutboundTraffic {
    pub outbound: String,
    pub downlink: i64,
    pub uplink: i64,
}

/// Groups `kind>>>name>>>traffic>>>(uplink|downlink)` counters by name, in first-seen order.
pub fn aggregate(stats: &[Stat]) -> Vec<(String, Traffic)> {
    let mut order: Vec<String> = Vec::new();
    let mut map: HashMap<String, Traffic> = HashMap::new();
    for s in stats {
        let parts: Vec<&str> = s.name.split(">>>").collect();
        let Some(name) = parts.get(1) else { continue };
        let entry = map.entry((*name).to_string()).or_insert_with(|| {
            order.push((*name).to_string());
            Traffic {
                downlink: 0,
                uplink: 0,
            }
        });
        match parts.get(3) {
            Some(&"uplink") => entry.uplink += s.value,
            Some(&"downlink") => entry.downlink += s.value,
            _ => {}
        }
    }
    order
        .into_iter()
        .map(|n| {
            let t = map.remove(&n).unwrap();
            (n, t)
        })
        .collect()
}

fn sdk_err(s: tonic::Status) -> String {
    s.message().to_string()
}

fn ts(secs: i64) -> String {
    now_iso(DateTime::<Utc>::from_timestamp(secs, 0).unwrap_or_default())
}

#[derive(Serialize)]
pub struct IpSeen {
    pub ip: String,
    #[serde(rename = "lastSeen")]
    pub last_seen: String,
}

#[derive(Serialize)]
pub struct UserIps {
    #[serde(rename = "userId")]
    pub user_id: String,
    pub ips: Vec<IpSeen>,
}

impl App {
    pub async fn user_online(&self, username: &str) -> bool {
        match self.xray.api.user_online(username).await {
            Ok(v) => v,
            Err(s) => {
                tracing::error!("{}", s.message());
                false
            }
        }
    }

    pub async fn system_stats(&self) -> R<Value> {
        let x = self.xray.api.sys_stats().await.map_err(|s| {
            tracing::warn!("{}", s.message());
            ApiError::known(FAILED_TO_GET_SYSTEM_STATS)
        })?;
        Ok(json!({
            "xrayInfo": {
                "numGoroutine": x.num_goroutine, "numGC": x.num_gc, "alloc": x.alloc,
                "totalAlloc": x.total_alloc, "sys": x.sys, "mallocs": x.mallocs, "frees": x.frees,
                "liveObjects": x.live_objects, "pauseTotalNs": x.pause_total_ns, "uptime": x.uptime,
            },
            "plugins": { "torrentBlocker": { "reportsCount": self.plugins.reports_count() } },
            "system": { "stats": sys::system_stats(self.net.default_rate()) },
        }))
    }

    pub async fn users_stats(&self, reset: bool) -> R<Vec<UserTraffic>> {
        let stats = self
            .xray
            .api
            .query_stats("user>>>", reset)
            .await
            .map_err(|s| {
                tracing::warn!("{}", s.message());
                ApiError::known(FAILED_TO_GET_USERS_STATS)
            })?;
        Ok(aggregate(&stats)
            .into_iter()
            .filter(|(_, t)| t.uplink != 0 || t.downlink != 0)
            .map(|(username, t)| UserTraffic {
                username,
                downlink: t.downlink,
                uplink: t.uplink,
            })
            .collect())
    }

    pub async fn inbound_stats(&self, tag: &str, reset: bool) -> R<InboundTraffic> {
        let stats = self
            .xray
            .api
            .query_stats(&format!("inbound>>>{tag}>>>"), reset)
            .await
            .map_err(|_| ApiError::known(FAILED_TO_GET_INBOUND_STATS))?;
        aggregate(&stats)
            .into_iter()
            .next()
            .map(|(inbound, t)| InboundTraffic {
                inbound,
                downlink: t.downlink,
                uplink: t.uplink,
            })
            .ok_or_else(|| ApiError::known(FAILED_TO_GET_INBOUND_STATS))
    }

    pub async fn outbound_stats(&self, tag: &str, reset: bool) -> R<OutboundTraffic> {
        let stats = self
            .xray
            .api
            .query_stats(&format!("outbound>>>{tag}>>>"), reset)
            .await
            .map_err(|_| ApiError::known(FAILED_TO_GET_OUTBOUND_STATS))?;
        aggregate(&stats)
            .into_iter()
            .next()
            .map(|(outbound, t)| OutboundTraffic {
                outbound,
                downlink: t.downlink,
                uplink: t.uplink,
            })
            .ok_or_else(|| ApiError::known(FAILED_TO_GET_OUTBOUND_STATS))
    }

    pub async fn all_inbounds(&self, reset: bool, err: KnownError) -> R<Vec<InboundTraffic>> {
        let stats = self
            .xray
            .api
            .query_stats("inbound>>>", reset)
            .await
            .map_err(|_| ApiError::known(err))?;
        Ok(aggregate(&stats)
            .into_iter()
            .map(|(inbound, t)| InboundTraffic {
                inbound,
                downlink: t.downlink,
                uplink: t.uplink,
            })
            .collect())
    }

    pub async fn all_outbounds(&self, reset: bool) -> R<Vec<OutboundTraffic>> {
        let stats = self
            .xray
            .api
            .query_stats("outbound>>>", reset)
            .await
            .map_err(|s| {
                tracing::error!("{}", sdk_err(s));
                ApiError::known(FAILED_TO_GET_OUTBOUNDS_STATS)
            })?;
        Ok(aggregate(&stats)
            .into_iter()
            .map(|(outbound, t)| OutboundTraffic {
                outbound,
                downlink: t.downlink,
                uplink: t.uplink,
            })
            .collect())
    }

    pub async fn user_ip_list(&self, user_id: &str) -> Vec<IpSeen> {
        match self.xray.api.online_ip_list(user_id, true).await {
            Ok(ips) => ips
                .into_iter()
                .map(|(ip, t)| IpSeen {
                    ip,
                    last_seen: ts(t),
                })
                .collect(),
            Err(s) => {
                if s.code() != Code::NotFound {
                    tracing::error!("{}", s.message());
                } else {
                    tracing::debug!("no online IPs for {user_id}: {}", s.message());
                }
                Vec::new()
            }
        }
    }

    pub async fn users_ip_list(&self) -> Vec<UserIps> {
        match self.xray.api.users_stats(false, false).await {
            Ok(users) => {
                tracing::debug!("GetUsersStats returned {} user(s)", users.len());
                users
                    .into_iter()
                    .map(|u| UserIps {
                        user_id: u.email,
                        ips: u
                            .ips
                            .into_iter()
                            .map(|i| IpSeen {
                                ip: i.ip,
                                last_seen: ts(i.last_seen),
                            })
                            .collect(),
                    })
                    .collect()
            }
            Err(s) if s.code() == Code::Unimplemented => {
                users_ip_list_legacy(self.xray.api.clone()).await
            }
            Err(s) => {
                tracing::error!("{}", s.message());
                Vec::new()
            }
        }
    }
}

/// Older Xray builds lack `GetUsersStats`: ask for online users and then each one's IPs.
async fn users_ip_list_legacy(api: XrayApi) -> Vec<UserIps> {
    let Ok(online) = api.all_online_users().await else {
        return Vec::new();
    };
    let mut names: Vec<String> = online
        .iter()
        .filter_map(|m| {
            m.strip_prefix("user>>>")?
                .strip_suffix(">>>online")
                .map(str::to_string)
        })
        .collect();
    names.sort();
    names.dedup();

    let api = Arc::new(api);
    let results: Vec<UserIps> = futures_util::stream::iter(names)
        .map(|name| {
            let api = api.clone();
            async move {
                let ips = api.online_ip_list(&name, false).await.unwrap_or_default();
                UserIps {
                    ips: ips
                        .into_iter()
                        .map(|(ip, t)| IpSeen {
                            ip,
                            last_seen: ts(t),
                        })
                        .collect(),
                    user_id: name,
                }
            }
        })
        .buffer_unordered(50)
        .collect()
        .await;
    results.into_iter().filter(|u| !u.ips.is_empty()).collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn stat(name: &str, value: i64) -> Stat {
        Stat {
            name: name.into(),
            value,
        }
    }

    #[test]
    fn aggregates_counters_per_name() {
        let out = aggregate(&[
            stat("user>>>alice>>>traffic>>>uplink", 10),
            stat("user>>>alice>>>traffic>>>downlink", 20),
            stat("user>>>bob>>>traffic>>>uplink", 5),
            stat("user>>>alice>>>online", 1),
        ]);
        assert_eq!(out.len(), 2);
        assert_eq!(out[0].0, "alice");
        assert_eq!(
            out[0].1,
            Traffic {
                downlink: 20,
                uplink: 10
            }
        );
        assert_eq!(
            out[1].1,
            Traffic {
                downlink: 0,
                uplink: 5
            }
        );
    }

    #[test]
    fn all_failed_semantics() {
        assert_eq!(
            all_failed(&[]),
            Some(String::new()),
            "empty list counts as all-failed, like JS every()"
        );
        assert_eq!(all_failed(&[Ok(()), Err("x".into())]), None);
        assert_eq!(
            all_failed(&[Err("a".into()), Err("b".into())]),
            Some("a".into())
        );
    }
}
