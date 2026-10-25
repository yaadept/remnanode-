mod api;
mod app;
mod config;
mod dto;
mod error;
mod geocheck;
mod hashed_set;
mod http;
mod internal;
mod ops;
mod payload;
mod plugin;
mod sockdestroy;
mod sys;
mod tls;
mod xray;

use std::{
    net::{Ipv6Addr, SocketAddr},
    os::{
        linux::net::SocketAddrExt,
        unix::net::{SocketAddr as UnixAddr, UnixListener as StdUnixListener},
    },
    path::Path,
    sync::Arc,
};

use anyhow::{Context, Result};
use tokio::net::{TcpListener, TcpSocket, UnixListener};
use tokio_util::sync::CancellationToken;
use tracing_subscriber::EnvFilter;

use crate::{
    app::App,
    config::{Config, NODE_VERSION},
    internal::InternalState,
    plugin::{PluginService, asn::AsnDb, nft::Nft},
    xray::{grpc::XrayApi, service::XrayService},
};

const INSTANCE_LOCK: &str = "rwnode-lock";

fn init_logging() {
    let default = if std::env::var("NODE_ENV").is_ok_and(|v| v == "development") {
        "debug"
    } else {
        "info"
    };
    tracing_subscriber::fmt()
        .with_env_filter(
            EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new(default)),
        )
        .with_target(true)
        .init();
}

/// `listen(port)` in Node binds the IPv6 wildcard with dual-stack; mirror that and fall back to IPv4.
async fn bind_tcp(port: u16) -> Result<TcpListener> {
    let v6 = (|| {
        let socket = TcpSocket::new_v6()?;
        socket.set_reuseaddr(true)?;
        socket.bind(SocketAddr::from((Ipv6Addr::UNSPECIFIED, port)))?;
        socket.listen(1024)
    })();
    match v6 {
        Ok(l) => Ok(l),
        Err(_) => TcpListener::bind(("0.0.0.0", port))
            .await
            .with_context(|| format!("cannot bind port {port}")),
    }
}

fn bind_abstract(name: &str) -> Result<StdUnixListener> {
    let addr = UnixAddr::from_abstract_name(name.as_bytes())?;
    let l = StdUnixListener::bind_addr(&addr)
        .with_context(|| format!("cannot bind abstract socket @{name}"))?;
    l.set_nonblocking(true)?;
    Ok(l)
}

async fn shutdown_signal() {
    use tokio::signal::unix::{SignalKind, signal};
    let mut term = signal(SignalKind::terminate()).expect("SIGTERM handler");
    let mut int = signal(SignalKind::interrupt()).expect("SIGINT handler");
    tokio::select! {
        _ = term.recv() => {}
        _ = int.recv() => {}
    }
}

async fn run() -> Result<()> {
    let cfg = Arc::new(Config::from_env()?);

    let node_payload = payload::parse_node_payload(&cfg.secret_key)?;
    payload::assert_payload_integrity(&node_payload)?;
    let tls_config = tls::build_server_config(&node_payload, cfg.sni_verification)?;
    let jwt_key = payload::jwt_decoding_key(&node_payload.jwt_public_key)?;

    let net = sys::NetworkStats::start();

    let asn = if cfg.asn_lmdb_path.exists() {
        match AsnDb::open(&cfg.asn_lmdb_path) {
            Ok(db) => {
                tracing::info!("ASN database opened successfully");
                Some(db)
            }
            Err(e) => {
                tracing::error!("Failed to open ASN database: {e:#}");
                None
            }
        }
    } else {
        tracing::warn!(
            "{} not found - ASN lookup disabled",
            cfg.asn_lmdb_path.display()
        );
        None
    };

    let plugins = Arc::new(PluginService::new(
        Nft::new(cfg.nftables_logging, cfg.nftables_accept_reply_traffic),
        asn,
    ));
    plugins.init().await;

    let internal = Arc::new(InternalState::default());
    let api = XrayApi::connect_abstract(cfg.xtls_api_socket_path.clone());
    let xray = XrayService::new(
        cfg.clone(),
        api,
        internal.clone(),
        plugins.clone(),
        net.clone(),
    )
    .await?;
    let app = App::new(
        cfg.clone(),
        xray.clone(),
        internal,
        plugins.clone(),
        net,
        jwt_key,
    );

    let shutdown = CancellationToken::new();

    let tcp = bind_tcp(cfg.node_port).await?;
    tokio::spawn(http::serve_tls(
        tcp,
        tls_config,
        api::node_router(app.clone()),
        shutdown.clone(),
    ));

    let internal_listener = UnixListener::from_std(bind_abstract(&cfg.internal_socket_path)?)?;
    tokio::spawn(http::serve_unix(
        internal_listener,
        api::internal_router(app.clone()),
        shutdown.clone(),
    ));

    let _lock = match bind_abstract(INSTANCE_LOCK) {
        Ok(l) => Some(l),
        Err(_) => {
            tracing::error!(
                "Another Remnawave Node instance appears to be running on this host. Running two nodes side by side is not supported."
            );
            None
        }
    };

    tracing::info!(
        "Remnawave Node (Rust) v{NODE_VERSION} listening on port {} (mTLS, TLS 1.3){}",
        cfg.node_port,
        if Path::new(&cfg.xray_bin).exists() {
            ""
        } else {
            " - WARNING: Xray binary not found"
        }
    );

    shutdown_signal().await;
    tracing::info!("Shutting down...");
    shutdown.cancel();
    xray.shutdown().await;
    plugins.shutdown().await;
    Ok(())
}

#[tokio::main]
async fn main() {
    init_logging();
    if let Err(e) = run().await {
        tracing::error!("{e:#}");
        std::process::exit(1);
    }
}
