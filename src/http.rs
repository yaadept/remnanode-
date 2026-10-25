//! Connection plumbing: a hyper accept loop that can *destroy* a connection without
//! answering (what the original does for bad JWTs, unknown routes and bad internal tokens).

use std::{
    net::SocketAddr,
    sync::{
        Arc,
        atomic::{AtomicU64, Ordering},
    },
    time::Duration,
};

use axum::{Router, body::Body};
use hyper::{Request, body::Incoming};
use hyper_util::{
    rt::{TokioIo, TokioTimer},
    service::TowerToHyperService,
};
use tokio::{
    io::{AsyncRead, AsyncWrite},
    net::{TcpListener, UnixListener},
    sync::Semaphore,
};
use tokio_rustls::TlsAcceptor;
use tokio_util::sync::CancellationToken;
use tower::ServiceExt;

const HANDSHAKE_TIMEOUT: Duration = Duration::from_secs(10);
const HEADERS_TIMEOUT: Duration = Duration::from_secs(61);
/// Upper bound on simultaneously open connections; the panel needs a handful. Excess
/// connections are closed right away so idle sockets cannot exhaust file descriptors.
const MAX_CONNECTIONS: usize = 2048;

/// Cancel it from a handler to drop the connection on the floor.
#[derive(Clone)]
pub struct Kill(pub CancellationToken);

#[derive(Clone, Copy)]
pub struct ConnInfo(pub Option<SocketAddr>);

async fn serve_conn<I>(io: I, router: Router, peer: Option<SocketAddr>)
where
    I: AsyncRead + AsyncWrite + Unpin + Send + 'static,
{
    let kill = CancellationToken::new();
    let k = kill.clone();
    let svc = tower::service_fn(move |mut req: Request<Incoming>| {
        req.extensions_mut().insert(Kill(k.clone()));
        req.extensions_mut().insert(ConnInfo(peer));
        router.clone().oneshot(req.map(Body::new))
    });

    let conn = hyper::server::conn::http1::Builder::new()
        .timer(TokioTimer::new())
        .header_read_timeout(HEADERS_TIMEOUT)
        .keep_alive(true)
        .serve_connection(TokioIo::new(io), TowerToHyperService::new(svc));

    tokio::select! {
        r = conn => {
            if let Err(e) = r {
                tracing::debug!("connection closed with error: {e}");
            }
        }
        _ = kill.cancelled() => {}
    }
}

pub async fn serve_tls(
    listener: TcpListener,
    config: Arc<rustls::ServerConfig>,
    router: Router,
    shutdown: CancellationToken,
) {
    let acceptor = TlsAcceptor::from(config);
    let permits = Arc::new(Semaphore::new(MAX_CONNECTIONS));
    let dropped = AtomicU64::new(0);
    loop {
        let (tcp, peer) = tokio::select! {
            _ = shutdown.cancelled() => return,
            r = listener.accept() => match r {
                Ok(v) => v,
                Err(e) => {
                    tracing::warn!("accept failed: {e}");
                    tokio::time::sleep(Duration::from_millis(50)).await;
                    continue;
                }
            }
        };
        let Ok(permit) = permits.clone().try_acquire_owned() else {
            // unauthenticated peers can trigger this: log the first drop of a burst only
            if dropped.fetch_add(1, Ordering::Relaxed).is_multiple_of(1000) {
                tracing::warn!("connection limit ({MAX_CONNECTIONS}) reached, dropping {peer}");
            }
            continue;
        };
        let _ = tcp.set_nodelay(true);
        let acceptor = acceptor.clone();
        let router = router.clone();
        tokio::spawn(async move {
            let _permit = permit;
            match tokio::time::timeout(HANDSHAKE_TIMEOUT, acceptor.accept(tcp)).await {
                Ok(Ok(tls)) => serve_conn(tls, router, Some(peer)).await,
                Ok(Err(e)) => tracing::debug!("TLS handshake with {peer} failed: {e}"),
                Err(_) => tracing::debug!("TLS handshake with {peer} timed out"),
            }
        });
    }
}

pub async fn serve_unix(listener: UnixListener, router: Router, shutdown: CancellationToken) {
    loop {
        let (stream, _) = tokio::select! {
            _ = shutdown.cancelled() => return,
            r = listener.accept() => match r {
                Ok(v) => v,
                Err(e) => {
                    tracing::warn!("internal accept failed: {e}");
                    tokio::time::sleep(Duration::from_millis(50)).await;
                    continue;
                }
            }
        };
        let router = router.clone();
        tokio::spawn(serve_conn(stream, router, None));
    }
}
