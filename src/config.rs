use std::path::PathBuf;

use anyhow::{Context, Result, anyhow, bail};
use rand::distr::{Alphanumeric, SampleString};

pub const NODE_VERSION: &str = env!("CARGO_PKG_VERSION");

#[derive(Debug, Clone)]
pub struct Config {
    pub node_port: u16,
    pub secret_key: String,
    pub disable_hashed_set_check: bool,
    pub internal_rest_token: String,
    pub internal_socket_path: String,
    pub xtls_api_socket_path: String,
    pub nftables_logging: bool,
    pub nftables_accept_reply_traffic: bool,
    pub sni_verification: bool,
    pub xray_bin: PathBuf,
    pub assets_dir: PathBuf,
    pub asn_lmdb_path: PathBuf,
    pub geocheck_bin: PathBuf,
    pub forward_xray_logs: bool,
}

fn bool_env(name: &str, default: bool) -> Result<bool> {
    match std::env::var(name) {
        Err(_) => Ok(default),
        Ok(v) if v.is_empty() => Ok(default),
        Ok(v) if v == "true" => Ok(true),
        Ok(v) if v == "false" => Ok(false),
        Ok(_) => bail!("{name}: Must be \"true\" or \"false\"."),
    }
}

fn random_alnum(len: usize) -> String {
    Alphanumeric.sample_string(&mut rand::rng(), len)
}

fn path_env(name: &str, default: &str) -> PathBuf {
    std::env::var(name)
        .ok()
        .filter(|v| !v.is_empty())
        .unwrap_or_else(|| default.to_string())
        .into()
}

impl Config {
    pub fn from_env() -> Result<Self> {
        let node_port = std::env::var("NODE_PORT")
            .map_err(|_| anyhow!("NODE_PORT is required"))?
            .parse::<u16>()
            .context("NODE_PORT must be a valid port number")?;

        let secret_key = std::env::var("SECRET_KEY")
            .ok()
            .filter(|v| !v.is_empty())
            .ok_or_else(|| anyhow!("SECRET_KEY missing in environment variables."))?;

        // Without s6-overlay nothing generates these for us, so create per-run values
        // unless the operator pinned them.
        let rnd = random_alnum(10);
        let pick = |name: &str, default: String| {
            std::env::var(name)
                .ok()
                .filter(|v| !v.is_empty())
                .unwrap_or(default)
        };

        Ok(Self {
            node_port,
            secret_key,
            disable_hashed_set_check: bool_env("DISABLE_HASHED_SET_CHECK", false)?,
            internal_rest_token: pick("INTERNAL_REST_TOKEN", random_alnum(64)),
            internal_socket_path: pick("INTERNAL_SOCKET_PATH", format!("rwint-{rnd}")),
            xtls_api_socket_path: pick("XTLS_API_SOCKET_PATH", format!("xtls-api-{rnd}")),
            nftables_logging: bool_env("NFTABLES_LOGGING", true)?,
            nftables_accept_reply_traffic: bool_env("NFTABLES_ACCEPT_REPLY_TRAFFIC", false)?,
            sni_verification: bool_env("SNI_VERIFICATION", false)?,
            xray_bin: path_env("XRAY_BIN", "/usr/local/bin/xray"),
            assets_dir: path_env("XRAY_LOCATION_ASSET", "/usr/local/share/xray"),
            asn_lmdb_path: path_env("ASN_LMDB_PATH", "/usr/local/share/asn/asn-prefixes.lmdb"),
            geocheck_bin: path_env("GEOCHECK_BIN", "/usr/local/bin/geocheck"),
            forward_xray_logs: bool_env("XRAY_FORWARD_LOGS", true)?,
        })
    }
}
