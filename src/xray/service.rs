use std::{
    sync::{
        Arc, RwLock,
        atomic::{AtomicBool, Ordering},
    },
    time::{Duration, Instant},
};

use serde::{Deserialize, Serialize};
use serde_json::{Map, Value};

use super::{
    config_gen::{InternalParams, generate_api_config},
    grpc::XrayApi,
    loader::{CoreLoader, prepare_geodata},
    process::XrayProcess,
};
use crate::{
    config::{Config, NODE_VERSION},
    internal::{Hashes, InternalState},
    plugin::PluginService,
    sys::{self, NetworkStats, NodeSystemInfo, NodeSystemStats},
};

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Internals {
    pub metadata: Option<Value>,
    #[allow(dead_code)]
    pub integrations: Option<Value>,
    #[serde(default)]
    pub force_restart: bool,
    pub hashes: Hashes,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct StartRequest {
    pub internals: Internals,
    pub xray_config: Map<String, Value>,
}

#[derive(Debug, Serialize)]
pub struct NodeInformation {
    pub version: Option<String>,
}

#[derive(Debug, Serialize)]
pub struct NodeSystem {
    pub info: NodeSystemInfo,
    pub stats: NodeSystemStats,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct StartResponse {
    pub is_started: bool,
    pub version: Option<String>,
    pub error: Option<String>,
    pub node_information: NodeInformation,
    pub system: NodeSystem,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct HealthResponse {
    pub is_alive: bool,
    pub xray_internal_status_cached: bool,
    pub xray_version: Option<String>,
    pub node_version: String,
}

pub struct XrayService {
    cfg: Arc<Config>,
    pub api: XrayApi,
    process: XrayProcess,
    internal: Arc<InternalState>,
    plugins: Arc<PluginService>,
    net: NetworkStats,
    loader: CoreLoader,
    http: reqwest::Client,
    version: RwLock<Option<String>>,
    online: AtomicBool,
    processing: AtomicBool,
}

/// Clears the "start in progress" flag on every exit path.
struct ProcessingGuard<'a>(&'a AtomicBool);
impl Drop for ProcessingGuard<'_> {
    fn drop(&mut self) {
        self.0.store(false, Ordering::SeqCst);
    }
}

impl XrayService {
    pub async fn new(
        cfg: Arc<Config>,
        api: XrayApi,
        internal: Arc<InternalState>,
        plugins: Arc<PluginService>,
        net: NetworkStats,
    ) -> anyhow::Result<Arc<Self>> {
        let http = reqwest::Client::builder()
            .redirect(reqwest::redirect::Policy::custom(|attempt| {
                // downloads are https-only, including every redirect hop
                if attempt.url().scheme() != "https" {
                    attempt.error("redirect to a non-https url")
                } else if attempt.previous().len() >= 5 {
                    attempt.error("too many redirects")
                } else {
                    attempt.follow()
                }
            }))
            .build()?;
        let mut loader = CoreLoader::new(http.clone(), cfg.xray_bin.clone());
        loader.ensure_link().await;

        let config_arg = format!(
            "@{}:/internal/get-config?token={}",
            cfg.internal_socket_path, cfg.internal_rest_token
        );
        let process = XrayProcess::spawn(
            loader.link_path().to_path_buf(),
            config_arg,
            cfg.forward_xray_logs,
        );

        let svc = Arc::new(Self {
            cfg,
            api,
            process,
            internal,
            plugins,
            net,
            loader,
            http,
            version: RwLock::new(None),
            online: AtomicBool::new(false),
            processing: AtomicBool::new(false),
        });
        svc.refresh_version().await;
        Ok(svc)
    }

    fn version(&self) -> Option<String> {
        self.version.read().unwrap().clone()
    }

    async fn refresh_version(&self) {
        if let Some(v) = self.process.core_version().await {
            *self.version.write().unwrap() = Some(v);
        }
    }

    pub fn is_online(&self) -> bool {
        self.online.load(Ordering::SeqCst)
    }

    fn system(&self) -> NodeSystem {
        NodeSystem {
            info: sys::system_info(),
            stats: sys::system_stats(self.net.default_rate()),
        }
    }

    fn response(
        &self,
        started: bool,
        version: Option<String>,
        error: Option<String>,
        system: NodeSystem,
    ) -> StartResponse {
        StartResponse {
            is_started: started,
            version,
            error,
            node_information: NodeInformation {
                version: Some(NODE_VERSION.to_string()),
            },
            system,
        }
    }

    pub async fn start(&self, body: StartRequest, ip: &str) -> StartResponse {
        let system = self.system();
        let started_at = Instant::now();

        if self.processing.swap(true, Ordering::SeqCst) {
            tracing::warn!("Request already in progress");
            return self.response(
                false,
                self.version(),
                Some("Request already in progress".into()),
                system,
            );
        }
        let _guard = ProcessingGuard(&self.processing);

        let resp = self.start_inner(body, system).await;
        tracing::info!(
            "Attempt to start XTLS took: {:?} (IP: {ip})",
            started_at.elapsed()
        );
        resp
    }

    async fn start_inner(&self, body: StartRequest, system: NodeSystem) -> StartResponse {
        let StartRequest {
            internals,
            xray_config,
        } = body;
        let internals = &internals;

        if self.is_online() && !self.cfg.disable_hashed_set_check && !internals.force_restart {
            let should_restart = if self.api.sys_stats().await.is_ok() {
                let t = Instant::now();
                let r = self.internal.is_need_restart_core(&internals.hashes);
                tracing::info!("Configuration hash check completed in {:?}", t.elapsed());
                r
            } else {
                self.online.store(false, Ordering::SeqCst);
                tracing::warn!("Xray Core health check failed, restarting...");
                true
            };
            if !should_restart {
                return self.response(true, self.version(), None, system);
            }
        }

        if internals.force_restart {
            tracing::warn!("Force restart requested");
        }

        let full_config = generate_api_config(
            xray_config,
            &self.plugins.torrent_blocker_cfg(),
            &InternalParams {
                socket_path: &self.cfg.internal_socket_path,
                token: &self.cfg.internal_rest_token,
                xtls_api_socket_path: &self.cfg.xtls_api_socket_path,
            },
            sys::has_cap_net_admin(),
        );

        let geodata = full_config.get("geodata").cloned();
        self.internal
            .extract_users_from_config(&internals.hashes, full_config);

        self.loader.prepare(geodata.as_ref()).await;
        prepare_geodata(&self.http, &self.cfg.assets_dir, geodata.as_ref()).await;

        if let Err(e) = self.restart_process().await {
            tracing::error!("Failed to (re)start Xray process: {e}");
            return self.response(false, None, Some(e), system);
        }

        let (started, start_error) = self.wait_until_ready().await;
        if !started {
            self.online.store(false, Ordering::SeqCst);
            tracing::error!(
                "Xray Core v{} failed to start. [RN-001] Xray core failed to start",
                self.version().unwrap_or_default()
            );
            let tail = self.process.tail(5);
            if !tail.is_empty() {
                tracing::error!(
                    "Xray Core Log Tail\n{}",
                    tail.iter()
                        .map(|l| format!("│ {l}"))
                        .collect::<Vec<_>>()
                        .join("\n")
                );
            }
            let reason = tail
                .last()
                .map(|l| l.trim().chars().take(500).collect::<String>())
                .filter(|l| !l.is_empty());
            let error = match (start_error, reason) {
                (Some(e), Some(r)) => Some(format!("{e} · {r}")),
                (e, _) => e,
            };
            return self.response(false, self.version(), error, system);
        }

        self.online.store(true, Ordering::SeqCst);
        self.refresh_version().await;
        tracing::info!(
            "✔ XRay Core v{} is up and running.",
            self.version().unwrap_or_default()
        );

        self.plugins.run_post_start(internals.metadata.as_ref());
        self.response(true, self.version(), None, system)
    }

    async fn restart_process(&self) -> Result<(), String> {
        self.process.stop().await.map_err(|e| e.to_string())?;
        self.plugins.run_pre_start().await;
        self.process.start().await.map_err(|e| e.to_string())
    }

    /// Polls Xray's API until it answers (30 retries, 100ms growing x1.5 up to 2s).
    async fn wait_until_ready(&self) -> (bool, Option<String>) {
        let started_pid = self.process.status().pid;
        let t0 = Instant::now();
        let mut delay = Duration::from_millis(100);

        for attempt in 1..=31u32 {
            match self.api.sys_stats().await {
                Ok(_) => return (true, None),
                Err(status) => {
                    let st = self.process.status();
                    if !st.up || (started_pid.is_some() && st.pid != started_pid) {
                        tracing::error!("Failed to get Xray internal status: process is down");
                        return (
                            false,
                            Some(format!(
                                "Xray Core process is not running anymore (process: {})",
                                self.process.status_line()
                            )),
                        );
                    }
                    if attempt == 31 {
                        tracing::error!("Failed to get Xray internal status: {}", status.message());
                        return (false, Some("Xray Core did not become ready in time".into()));
                    }
                    tracing::warn!(
                        "▸ XRay Core status check, {attempt}/31 · elapsed {:?} · retrying in {}ms",
                        t0.elapsed(),
                        delay.as_millis()
                    );
                    tokio::time::sleep(delay).await;
                    delay = delay.mul_f64(1.5).min(Duration::from_secs(2));
                }
            }
        }
        (false, Some("Xray Core did not become ready in time".into()))
    }

    pub async fn stop(&self, with_plugin_cleanup: bool, with_online_check: bool) -> bool {
        if with_plugin_cleanup {
            self.plugins.reset().await;
        }
        if with_online_check && !self.is_online() {
            return true;
        }
        match self.process.stop().await {
            Ok(()) => tracing::info!("Xray process stopped."),
            Err(e) => tracing::info!("Failed to stop Xray process. Error: {e}"),
        }
        self.online.store(false, Ordering::SeqCst);
        self.internal.cleanup();
        true
    }

    pub fn health(&self) -> HealthResponse {
        // An Xray that died on its own must not keep reporting "online".
        let alive = self.process.status().up;
        if self.is_online() && !alive {
            self.online.store(false, Ordering::SeqCst);
        }
        HealthResponse {
            is_alive: true,
            xray_internal_status_cached: self.is_online(),
            xray_version: self.version(),
            node_version: NODE_VERSION.to_string(),
        }
    }

    pub async fn shutdown(&self) {
        let _ = self.process.stop().await;
    }
}
