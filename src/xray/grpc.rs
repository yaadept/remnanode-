//! Minimal hand-written Xray gRPC client. The messages mirror the `.proto` files of
//! Xray-core (app/proxyman/command, app/stats/command, common/protocol, proxy/*);
//! only the calls the node actually makes are defined.

use std::{
    collections::HashMap,
    os::linux::net::SocketAddrExt,
    os::unix::net::{SocketAddr, UnixStream as StdUnixStream},
};

use hyper_util::rt::TokioIo;
use prost::Message;
use tonic::{
    Code, Request, Status,
    client::Grpc,
    transport::{Channel, Endpoint},
};
use tonic_prost::ProstCodec;
use tower::service_fn;

// ---------------------------------------------------------------- messages

#[derive(Clone, PartialEq, Message)]
pub struct TypedMessage {
    #[prost(string, tag = "1")]
    pub r#type: String,
    #[prost(bytes = "vec", tag = "2")]
    pub value: Vec<u8>,
}

#[derive(Clone, PartialEq, Message)]
pub struct User {
    #[prost(uint32, tag = "1")]
    pub level: u32,
    #[prost(string, tag = "2")]
    pub email: String,
    #[prost(message, optional, tag = "3")]
    pub account: Option<TypedMessage>,
}

#[derive(Clone, PartialEq, Message)]
pub struct AddUserOperation {
    #[prost(message, optional, tag = "1")]
    pub user: Option<User>,
}

#[derive(Clone, PartialEq, Message)]
pub struct RemoveUserOperation {
    #[prost(string, tag = "1")]
    pub email: String,
}

#[derive(Clone, PartialEq, Message)]
pub struct AlterInboundRequest {
    #[prost(string, tag = "1")]
    pub tag: String,
    #[prost(message, optional, tag = "2")]
    pub operation: Option<TypedMessage>,
}

#[derive(Clone, PartialEq, Message)]
pub struct AlterInboundResponse {}

#[derive(Clone, PartialEq, Message)]
pub struct RemoveOutboundRequest {
    #[prost(string, tag = "1")]
    pub tag: String,
}

#[derive(Clone, PartialEq, Message)]
pub struct RemoveOutboundResponse {}

// accounts ------------------------------------------------------------------

#[derive(Clone, PartialEq, Message)]
pub struct VlessAccount {
    #[prost(string, tag = "1")]
    pub id: String,
    #[prost(string, tag = "2")]
    pub flow: String,
    #[prost(string, tag = "3")]
    pub encryption: String,
}

#[derive(Clone, PartialEq, Message)]
pub struct TrojanAccount {
    #[prost(string, tag = "1")]
    pub password: String,
}

#[derive(Clone, PartialEq, Message)]
pub struct ShadowsocksAccount {
    #[prost(string, tag = "1")]
    pub password: String,
    #[prost(int32, tag = "2")]
    pub cipher_type: i32,
    #[prost(bool, tag = "3")]
    pub iv_check: bool,
}

#[derive(Clone, PartialEq, Message)]
pub struct Shadowsocks2022Account {
    #[prost(string, tag = "1")]
    pub key: String,
}

#[derive(Clone, PartialEq, Message)]
pub struct HysteriaAccount {
    #[prost(string, tag = "1")]
    pub auth: String,
}

// stats ----------------------------------------------------------------------

#[derive(Clone, PartialEq, Message)]
pub struct GetStatsRequest {
    #[prost(string, tag = "1")]
    pub name: String,
    #[prost(bool, tag = "2")]
    pub reset: bool,
}

#[derive(Clone, PartialEq, Message)]
pub struct Stat {
    #[prost(string, tag = "1")]
    pub name: String,
    #[prost(int64, tag = "2")]
    pub value: i64,
}

#[derive(Clone, PartialEq, Message)]
pub struct GetStatsResponse {
    #[prost(message, optional, tag = "1")]
    pub stat: Option<Stat>,
}

#[derive(Clone, PartialEq, Message)]
pub struct QueryStatsRequest {
    #[prost(string, tag = "1")]
    pub pattern: String,
    #[prost(bool, tag = "2")]
    pub reset: bool,
}

#[derive(Clone, PartialEq, Message)]
pub struct QueryStatsResponse {
    #[prost(message, repeated, tag = "1")]
    pub stat: Vec<Stat>,
}

#[derive(Clone, PartialEq, Message)]
pub struct SysStatsRequest {}

#[derive(Clone, PartialEq, Message)]
pub struct SysStatsResponse {
    #[prost(uint32, tag = "1")]
    pub num_goroutine: u32,
    #[prost(uint32, tag = "2")]
    pub num_gc: u32,
    #[prost(uint64, tag = "3")]
    pub alloc: u64,
    #[prost(uint64, tag = "4")]
    pub total_alloc: u64,
    #[prost(uint64, tag = "5")]
    pub sys: u64,
    #[prost(uint64, tag = "6")]
    pub mallocs: u64,
    #[prost(uint64, tag = "7")]
    pub frees: u64,
    #[prost(uint64, tag = "8")]
    pub live_objects: u64,
    #[prost(uint64, tag = "9")]
    pub pause_total_ns: u64,
    #[prost(uint32, tag = "10")]
    pub uptime: u32,
}

#[derive(Clone, PartialEq, Message)]
pub struct GetStatsOnlineIpListResponse {
    #[prost(string, tag = "1")]
    pub name: String,
    #[prost(map = "string, int64", tag = "2")]
    pub ips: HashMap<String, i64>,
}

#[derive(Clone, PartialEq, Message)]
pub struct OnlineIpEntry {
    #[prost(string, tag = "1")]
    pub ip: String,
    #[prost(int64, tag = "2")]
    pub last_seen: i64,
}

#[derive(Clone, PartialEq, Message)]
pub struct TrafficUserStat {
    #[prost(int64, tag = "1")]
    pub uplink: i64,
    #[prost(int64, tag = "2")]
    pub downlink: i64,
}

#[derive(Clone, PartialEq, Message)]
pub struct UserStat {
    #[prost(string, tag = "1")]
    pub email: String,
    #[prost(message, repeated, tag = "2")]
    pub ips: Vec<OnlineIpEntry>,
    #[prost(message, optional, tag = "3")]
    pub traffic: Option<TrafficUserStat>,
}

#[derive(Clone, PartialEq, Message)]
pub struct GetUsersStatsRequest {
    #[prost(bool, tag = "1")]
    pub include_traffic: bool,
    #[prost(bool, tag = "2")]
    pub reset: bool,
}

#[derive(Clone, PartialEq, Message)]
pub struct GetUsersStatsResponse {
    #[prost(message, repeated, tag = "1")]
    pub users: Vec<UserStat>,
}

#[derive(Clone, PartialEq, Message)]
pub struct GetAllOnlineUsersRequest {}

#[derive(Clone, PartialEq, Message)]
pub struct GetAllOnlineUsersResponse {
    #[prost(string, repeated, tag = "1")]
    pub users: Vec<String>,
}

// ---------------------------------------------------------------- user accounts

/// Shadowsocks `CipherType` values from Xray (`UNKNOWN=0, AES_128_GCM=5, ...`).
pub fn typed<M: Message>(type_name: &str, msg: &M) -> TypedMessage {
    TypedMessage {
        r#type: type_name.to_string(),
        value: msg.encode_to_vec(),
    }
}

pub enum Account {
    Vless {
        id: String,
        flow: String,
    },
    Trojan {
        password: String,
    },
    Shadowsocks {
        password: String,
        cipher_type: i32,
        iv_check: bool,
    },
    Shadowsocks2022 {
        key: String,
    },
    Hysteria {
        auth: String,
    },
}

impl Account {
    fn into_typed(self) -> TypedMessage {
        match self {
            Account::Vless { id, flow } => typed(
                "xray.proxy.vless.Account",
                &VlessAccount {
                    id,
                    flow,
                    encryption: "none".into(),
                },
            ),
            Account::Trojan { password } => {
                typed("xray.proxy.trojan.Account", &TrojanAccount { password })
            }
            Account::Shadowsocks {
                password,
                cipher_type,
                iv_check,
            } => typed(
                "xray.proxy.shadowsocks.Account",
                &ShadowsocksAccount {
                    password,
                    cipher_type,
                    iv_check,
                },
            ),
            Account::Shadowsocks2022 { key } => typed(
                "xray.proxy.shadowsocks_2022.Account",
                &Shadowsocks2022Account { key },
            ),
            Account::Hysteria { auth } => typed(
                "xray.proxy.hysteria.account.Account",
                &HysteriaAccount { auth },
            ),
        }
    }
}

// ---------------------------------------------------------------- client

#[derive(Clone)]
pub struct XrayApi {
    channel: Channel,
}

impl XrayApi {
    /// Connects lazily to Xray's API listening on an *abstract* unix socket.
    pub fn connect_abstract(name: String) -> Self {
        let endpoint = Endpoint::from_static("http://xray.invalid")
            .timeout(std::time::Duration::from_secs(60));
        let channel =
            endpoint.connect_with_connector_lazy(service_fn(move |_: tonic::transport::Uri| {
                let name = name.clone();
                async move {
                    let addr = SocketAddr::from_abstract_name(name.as_bytes())?;
                    let std_stream = StdUnixStream::connect_addr(&addr)?;
                    std_stream.set_nonblocking(true)?;
                    let stream = tokio::net::UnixStream::from_std(std_stream)?;
                    Ok::<_, std::io::Error>(TokioIo::new(stream))
                }
            }));
        Self { channel }
    }

    async fn unary<Req, Resp>(&self, path: &'static str, req: Req) -> Result<Resp, Status>
    where
        Req: Message + Send + Sync + 'static,
        Resp: Message + Default + Send + Sync + 'static,
    {
        let mut grpc = Grpc::new(self.channel.clone()).max_decoding_message_size(100_000_000);
        grpc.ready()
            .await
            .map_err(|e| Status::new(Code::Unavailable, e.to_string()))?;
        let codec: ProstCodec<Req, Resp> = ProstCodec::default();
        let res = grpc
            .unary(
                Request::new(req),
                tonic::codegen::http::uri::PathAndQuery::from_static(path),
                codec,
            )
            .await?;
        Ok(res.into_inner())
    }

    // ---- handler service

    async fn alter_inbound(&self, tag: &str, op: TypedMessage) -> Result<(), Status> {
        self.unary::<_, AlterInboundResponse>(
            "/xray.app.proxyman.command.HandlerService/AlterInbound",
            AlterInboundRequest {
                tag: tag.to_string(),
                operation: Some(op),
            },
        )
        .await
        .map(|_| ())
    }

    /// `Ok(true)` = added, `Ok(false)` = user already existed.
    pub async fn add_user(
        &self,
        tag: &str,
        email: &str,
        level: u32,
        account: Account,
    ) -> Result<bool, Status> {
        let op = AddUserOperation {
            user: Some(User {
                level,
                email: email.to_string(),
                account: Some(account.into_typed()),
            }),
        };
        match self
            .alter_inbound(
                tag,
                typed("xray.app.proxyman.command.AddUserOperation", &op),
            )
            .await
        {
            Ok(()) => Ok(true),
            Err(e) if e.message().contains("already exists") => Ok(false),
            Err(e) => Err(e),
        }
    }

    /// `Ok(true)` = removed, `Ok(false)` = user was not there.
    pub async fn remove_user(&self, tag: &str, email: &str) -> Result<bool, Status> {
        let op = RemoveUserOperation {
            email: email.to_string(),
        };
        match self
            .alter_inbound(
                tag,
                typed("xray.app.proxyman.command.RemoveUserOperation", &op),
            )
            .await
        {
            Ok(()) => Ok(true),
            Err(e) if e.message().contains("not found") => Ok(false),
            Err(e) => Err(e),
        }
    }

    pub async fn remove_outbound(&self, tag: &str) -> Result<(), Status> {
        self.unary::<_, RemoveOutboundResponse>(
            "/xray.app.proxyman.command.HandlerService/RemoveOutbound",
            RemoveOutboundRequest {
                tag: tag.to_string(),
            },
        )
        .await
        .map(|_| ())
    }

    // ---- stats service

    pub async fn sys_stats(&self) -> Result<SysStatsResponse, Status> {
        self.unary(
            "/xray.app.stats.command.StatsService/GetSysStats",
            SysStatsRequest {},
        )
        .await
    }

    pub async fn query_stats(&self, pattern: &str, reset: bool) -> Result<Vec<Stat>, Status> {
        let r: QueryStatsResponse = self
            .unary(
                "/xray.app.stats.command.StatsService/QueryStats",
                QueryStatsRequest {
                    pattern: pattern.to_string(),
                    reset,
                },
            )
            .await?;
        Ok(r.stat)
    }

    /// `Ok(true)` when the `online` counter exists.
    pub async fn user_online(&self, username: &str) -> Result<bool, Status> {
        match self
            .unary::<_, GetStatsResponse>(
                "/xray.app.stats.command.StatsService/GetStatsOnline",
                GetStatsRequest {
                    name: format!("user>>>{username}>>>online"),
                    reset: false,
                },
            )
            .await
        {
            Ok(_) => Ok(true),
            Err(e) if e.message().contains("online not found.") => Ok(false),
            Err(e) => Err(e),
        }
    }

    pub async fn online_ip_list(
        &self,
        username: &str,
        reset: bool,
    ) -> Result<HashMap<String, i64>, Status> {
        let r: GetStatsOnlineIpListResponse = self
            .unary(
                "/xray.app.stats.command.StatsService/GetStatsOnlineIpList",
                GetStatsRequest {
                    name: format!("user>>>{username}>>>online"),
                    reset,
                },
            )
            .await?;
        Ok(r.ips)
    }

    pub async fn all_online_users(&self) -> Result<Vec<String>, Status> {
        let r: GetAllOnlineUsersResponse = self
            .unary(
                "/xray.app.stats.command.StatsService/GetAllOnlineUsers",
                GetAllOnlineUsersRequest {},
            )
            .await?;
        Ok(r.users)
    }

    pub async fn users_stats(
        &self,
        include_traffic: bool,
        reset: bool,
    ) -> Result<Vec<UserStat>, Status> {
        let r: GetUsersStatsResponse = self
            .unary(
                "/xray.app.stats.command.StatsService/GetUsersStats",
                GetUsersStatsRequest {
                    include_traffic,
                    reset,
                },
            )
            .await?;
        Ok(r.users)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn vless_account_encodes_with_expected_type_url() {
        let t = Account::Vless {
            id: "u".into(),
            flow: "".into(),
        }
        .into_typed();
        assert_eq!(t.r#type, "xray.proxy.vless.Account");
        // field 1 = "u", field 3 = "none"
        assert_eq!(
            t.value,
            [&[0x0a, 1, b'u'][..], &[0x1a, 4], b"none"].concat()
        );
    }
}
