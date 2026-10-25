//! Request bodies of the node REST API (the zod schemas of `libs/contract`).

use serde::Deserialize;

use crate::{plugin::SyncPlugin, xray::service::StartRequest};

pub trait Validate {
    /// Extra checks zod performs that serde cannot express; returns the failing messages.
    fn validate(&self) -> Vec<String> {
        Vec::new()
    }
}

fn check_uuid(errors: &mut Vec<String>, path: &str, v: &str) {
    if uuid::Uuid::parse_str(v).is_err() {
        errors.push(format!("{path}: Invalid UUID"));
    }
}

fn check_flow(errors: &mut Vec<String>, flow: &str) {
    if flow != "xtls-rprx-vision" && !flow.is_empty() {
        errors.push("flow: Invalid option: expected one of \"xtls-rprx-vision\"|\"\"".into());
    }
}

// ------------------------------------------------------------------ handler

#[derive(Debug, Deserialize)]
#[serde(tag = "type", rename_all = "lowercase")]
pub enum AddUserItem {
    Trojan {
        tag: String,
        username: String,
        password: String,
    },
    Vless {
        tag: String,
        username: String,
        uuid: String,
        flow: String,
    },
    #[serde(rename_all = "camelCase")]
    Shadowsocks {
        tag: String,
        username: String,
        password: String,
        cipher_type: i32,
        #[allow(dead_code)]
        iv_check: bool,
    },
    Shadowsocks22 {
        tag: String,
        username: String,
        password: String,
    },
    Hysteria {
        tag: String,
        username: String,
        password: String,
    },
}

impl AddUserItem {
    pub fn tag(&self) -> &str {
        match self {
            Self::Trojan { tag, .. }
            | Self::Vless { tag, .. }
            | Self::Shadowsocks { tag, .. }
            | Self::Shadowsocks22 { tag, .. }
            | Self::Hysteria { tag, .. } => tag,
        }
    }

    pub fn username(&self) -> &str {
        match self {
            Self::Trojan { username, .. }
            | Self::Vless { username, .. }
            | Self::Shadowsocks { username, .. }
            | Self::Shadowsocks22 { username, .. }
            | Self::Hysteria { username, .. } => username,
        }
    }
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct AddUserHashData {
    pub vless_uuid: String,
    pub prev_vless_uuid: Option<String>,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct AddUserRequest {
    pub data: Vec<AddUserItem>,
    pub hash_data: AddUserHashData,
}

impl Validate for AddUserRequest {
    fn validate(&self) -> Vec<String> {
        let mut e = Vec::new();
        for (i, item) in self.data.iter().enumerate() {
            match item {
                AddUserItem::Vless { flow, uuid, .. } => {
                    check_flow(&mut e, flow);
                    let _ = (i, uuid);
                }
                AddUserItem::Shadowsocks { cipher_type, .. }
                    if ![-1, 0, 5, 6, 7, 8].contains(cipher_type) =>
                {
                    e.push(format!("data.{i}.cipherType: Invalid enum value"));
                }
                _ => {}
            }
        }
        check_uuid(&mut e, "hashData.vlessUuid", &self.hash_data.vless_uuid);
        if let Some(p) = &self.hash_data.prev_vless_uuid {
            check_uuid(&mut e, "hashData.prevVlessUuid", p);
        }
        e
    }
}

#[derive(Debug, Deserialize)]
#[serde(tag = "type", rename_all = "lowercase")]
pub enum InboundData {
    Trojan { tag: String },
    Vless { tag: String, flow: String },
    Shadowsocks { tag: String },
    Shadowsocks22 { tag: String },
    Hysteria { tag: String },
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct UserData {
    pub user_id: String,
    pub hash_uuid: String,
    pub vless_uuid: String,
    pub trojan_password: String,
    pub ss_password: String,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct AddUsersUser {
    pub inbound_data: Vec<InboundData>,
    pub user_data: UserData,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct AddUsersRequest {
    pub affected_inbound_tags: Vec<String>,
    pub users: Vec<AddUsersUser>,
}

impl Validate for AddUsersRequest {
    fn validate(&self) -> Vec<String> {
        let mut e = Vec::new();
        for (i, u) in self.users.iter().enumerate() {
            check_uuid(
                &mut e,
                &format!("users.{i}.userData.hashUuid"),
                &u.user_data.hash_uuid,
            );
            check_uuid(
                &mut e,
                &format!("users.{i}.userData.vlessUuid"),
                &u.user_data.vless_uuid,
            );
            for d in &u.inbound_data {
                if let InboundData::Vless { flow, .. } = d {
                    check_flow(&mut e, flow);
                }
            }
        }
        e
    }
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct RemoveUserHashData {
    pub vless_uuid: String,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct RemoveUserRequest {
    pub username: String,
    pub hash_data: RemoveUserHashData,
}

impl Validate for RemoveUserRequest {
    fn validate(&self) -> Vec<String> {
        let mut e = Vec::new();
        check_uuid(&mut e, "hashData.vlessUuid", &self.hash_data.vless_uuid);
        e
    }
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct RemoveUsersItem {
    pub user_id: String,
    pub hash_uuid: String,
}

#[derive(Debug, Deserialize)]
pub struct RemoveUsersRequest {
    pub users: Vec<RemoveUsersItem>,
}

impl Validate for RemoveUsersRequest {
    fn validate(&self) -> Vec<String> {
        let mut e = Vec::new();
        for (i, u) in self.users.iter().enumerate() {
            check_uuid(&mut e, &format!("users.{i}.hashUuid"), &u.hash_uuid);
        }
        e
    }
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct DropUsersConnectionsRequest {
    pub user_ids: Vec<String>,
}

impl Validate for DropUsersConnectionsRequest {
    fn validate(&self) -> Vec<String> {
        if self.user_ids.is_empty() {
            vec!["userIds: Too small: expected array to have >=1 items".into()]
        } else {
            vec![]
        }
    }
}

#[derive(Debug, Deserialize)]
pub struct DropIpsRequest {
    pub ips: Vec<String>,
}

impl Validate for DropIpsRequest {
    fn validate(&self) -> Vec<String> {
        if self.ips.is_empty() {
            vec!["ips: Too small: expected array to have >=1 items".into()]
        } else {
            vec![]
        }
    }
}

// ------------------------------------------------------------------ stats

#[derive(Debug, Deserialize)]
pub struct ResetRequest {
    pub reset: bool,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct TagResetRequest {
    pub tag: String,
    pub reset: bool,
}

#[derive(Debug, Deserialize)]
pub struct UsernameRequest {
    pub username: String,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct UserIdRequest {
    pub user_id: String,
}

#[derive(Debug, Default, Deserialize)]
pub struct GeocheckRequest {
    pub ip: Option<String>,
    pub interface: Option<String>,
}

// ------------------------------------------------------------------ plugin

#[derive(Debug, Deserialize)]
pub struct SyncRequest {
    pub plugin: Option<SyncPlugin>,
}

#[derive(Debug, Deserialize)]
pub struct BlockIp {
    pub ip: String,
    pub timeout: f64,
}

#[derive(Debug, Deserialize)]
pub struct BlockIpsRequest {
    pub ips: Vec<BlockIp>,
}

impl Validate for BlockIpsRequest {
    fn validate(&self) -> Vec<String> {
        self.ips
            .iter()
            .enumerate()
            .filter(|(_, i)| i.ip.parse::<std::net::IpAddr>().is_err())
            .map(|(n, _)| format!("ips.{n}.ip: Invalid IP address"))
            .collect()
    }
}

#[derive(Debug, Deserialize)]
pub struct UnblockIpsRequest {
    pub ips: Vec<String>,
}

impl Validate for UnblockIpsRequest {
    fn validate(&self) -> Vec<String> {
        self.ips
            .iter()
            .enumerate()
            .filter(|(_, i)| i.parse::<std::net::IpAddr>().is_err())
            .map(|(n, _)| format!("ips.{n}: Invalid IP address"))
            .collect()
    }
}

impl Validate for StartRequest {}
impl Validate for ResetRequest {}
impl Validate for TagResetRequest {}
impl Validate for UsernameRequest {}
impl Validate for UserIdRequest {}
impl Validate for GeocheckRequest {}
impl Validate for SyncRequest {
    fn validate(&self) -> Vec<String> {
        match &self.plugin {
            Some(p) if uuid::Uuid::parse_str(&p.uuid).is_err() => {
                vec!["plugin.uuid: Invalid UUID".into()]
            }
            _ => vec![],
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn add_user_accepts_every_protocol() {
        let req: AddUserRequest = serde_json::from_value(json!({
            "data": [
                {"type": "trojan", "tag": "t", "username": "u", "password": "p"},
                {"type": "vless", "tag": "v", "username": "u", "uuid": "11111111-1111-1111-1111-111111111111", "flow": "xtls-rprx-vision"},
                {"type": "shadowsocks", "tag": "s", "username": "u", "password": "p", "cipherType": 6, "ivCheck": false},
                {"type": "shadowsocks22", "tag": "s2", "username": "u", "password": "p"},
                {"type": "hysteria", "tag": "h", "username": "u", "password": "p"}
            ],
            "hashData": {"vlessUuid": "11111111-1111-1111-1111-111111111111"}
        }))
        .unwrap();
        assert_eq!(req.data.len(), 5);
        assert!(req.validate().is_empty());
    }

    #[test]
    fn validation_flags_bad_uuid_and_flow() {
        let req: AddUserRequest = serde_json::from_value(json!({
            "data": [{"type": "vless", "tag": "v", "username": "u", "uuid": "x", "flow": "weird"}],
            "hashData": {"vlessUuid": "nope"}
        }))
        .unwrap();
        assert_eq!(req.validate().len(), 2);
    }

    #[test]
    fn unknown_protocol_is_rejected() {
        let r: Result<AddUserRequest, _> = serde_json::from_value(json!({
            "data": [{"type": "socks", "tag": "v", "username": "u"}],
            "hashData": {"vlessUuid": "11111111-1111-1111-1111-111111111111"}
        }));
        assert!(r.is_err());
    }
}
