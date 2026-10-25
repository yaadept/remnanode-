use std::{net::IpAddr, process::Stdio, sync::atomic::Ordering, time::Duration};

use serde_json::Value;
use tokio::process::Command;

use crate::{app::App, dto::GeocheckRequest, error::*};

const TIMEOUT: Duration = Duration::from_secs(45);

struct RunGuard<'a>(&'a std::sync::atomic::AtomicBool);
impl Drop for RunGuard<'_> {
    fn drop(&mut self) {
        self.0.store(false, Ordering::SeqCst);
    }
}

fn fail(message: String) -> ApiError {
    ApiError::with(FAILED_TO_GET_GEOCHECK, message)
}

impl App {
    pub async fn geocheck(&self, body: GeocheckRequest) -> Result<Value, ApiError> {
        let ip = body.ip.as_deref().map(str::trim).filter(|s| !s.is_empty());
        let iface = body
            .interface
            .as_deref()
            .map(str::trim)
            .filter(|s| !s.is_empty());

        let bind_to = if let Some(ip) = ip {
            if ip.parse::<IpAddr>().is_err() {
                return Err(fail(format!(
                    "Geocheck: \"{ip}\" is not a valid IP address."
                )));
            }
            Some(ip)
        } else {
            iface
        };

        if self.geocheck_running.swap(true, Ordering::SeqCst) {
            return Err(fail("Geocheck: a run is already in progress.".into()));
        }
        let _guard = RunGuard(&self.geocheck_running);

        let target = bind_to.unwrap_or("default route");
        let started = std::time::Instant::now();

        let mut cmd = Command::new(&self.cfg.geocheck_bin);
        if let Some(b) = bind_to {
            cmd.args(["--interface", b]);
        }
        cmd.args(["--json", "--svg-base64", "--quiet"])
            .stdin(Stdio::null())
            .kill_on_drop(true);

        let out = match tokio::time::timeout(TIMEOUT, cmd.output()).await {
            Err(_) => {
                let m = format!(
                    "Geocheck via {target} exceeded {}ms and was killed.",
                    TIMEOUT.as_millis()
                );
                tracing::error!("{m}");
                return Err(fail(m));
            }
            Ok(Err(e)) => {
                let m = format!("Geocheck via {target} failed: {e}");
                tracing::error!("{m}");
                return Err(fail(m));
            }
            Ok(Ok(o)) => o,
        };

        let report: Result<Value, String> = if out.status.success() {
            serde_json::from_slice::<Value>(&out.stdout)
                .map_err(|e| e.to_string())
                .and_then(|v| {
                    if v.pointer("/image/data")
                        .and_then(Value::as_str)
                        .is_some_and(|s| !s.is_empty())
                    {
                        Ok(v)
                    } else {
                        Err("geocheck report carries no image".into())
                    }
                })
        } else {
            Err(format!(
                "Command failed: {}",
                String::from_utf8_lossy(&out.stderr).trim()
            ))
        };

        match report {
            Ok(v) => {
                tracing::info!("Geocheck via {target} took {:?}", started.elapsed());
                Ok(v)
            }
            Err(e) => {
                let m = format!("Geocheck via {target} failed: {e}");
                tracing::error!("{m}");
                Err(fail(m))
            }
        }
    }
}
