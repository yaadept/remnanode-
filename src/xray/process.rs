//! Runs the Xray binary as a child process (the Docker image uses s6-overlay for this).
//! Mirrors `s6-svc -o`: started once, not restarted when it dies on its own.

use std::{
    collections::VecDeque,
    path::{Path, PathBuf},
    process::Stdio,
    sync::{Arc, Mutex},
    time::Duration,
};

use anyhow::{Context, Result, anyhow};
use tokio::{
    io::{AsyncBufReadExt, AsyncRead, BufReader},
    process::{Child, Command},
    sync::{mpsc, oneshot, watch},
};

const LOG_RING: usize = 500;
/// SIGTERM, then SIGKILL after this long (`timeout-kill` of the s6 service).
const KILL_AFTER: Duration = Duration::from_millis(3000);

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct ProcStatus {
    pub up: bool,
    pub pid: Option<u32>,
}

enum Cmd {
    Start(oneshot::Sender<Result<()>>),
    Stop(oneshot::Sender<()>),
}

#[derive(Clone)]
pub struct XrayProcess {
    tx: mpsc::Sender<Cmd>,
    status: watch::Receiver<ProcStatus>,
    logs: Arc<Mutex<VecDeque<String>>>,
    bin: PathBuf,
}

impl XrayProcess {
    pub fn spawn(bin: PathBuf, config_arg: String, forward_logs: bool) -> Self {
        let (tx, rx) = mpsc::channel(8);
        let (status_tx, status) = watch::channel(ProcStatus::default());
        let logs = Arc::new(Mutex::new(VecDeque::with_capacity(LOG_RING)));
        tokio::spawn(supervise(
            bin.clone(),
            config_arg,
            forward_logs,
            rx,
            status_tx,
            logs.clone(),
        ));
        Self {
            tx,
            status,
            logs,
            bin,
        }
    }

    pub fn status(&self) -> ProcStatus {
        *self.status.borrow()
    }

    pub async fn start(&self) -> Result<()> {
        let (ack, rx) = oneshot::channel();
        self.tx
            .send(Cmd::Start(ack))
            .await
            .map_err(|_| anyhow!("process supervisor is gone"))?;
        rx.await
            .map_err(|_| anyhow!("process supervisor is gone"))?
    }

    pub async fn stop(&self) -> Result<()> {
        let (ack, rx) = oneshot::channel();
        self.tx
            .send(Cmd::Stop(ack))
            .await
            .map_err(|_| anyhow!("process supervisor is gone"))?;
        rx.await
            .map_err(|_| anyhow!("process supervisor is gone"))?;
        Ok(())
    }

    pub fn tail(&self, n: usize) -> Vec<String> {
        let logs = self.logs.lock().unwrap();
        logs.iter().rev().take(n).rev().cloned().collect()
    }

    pub fn status_line(&self) -> String {
        let s = self.status();
        match (s.up, s.pid) {
            (true, Some(pid)) => format!("up (pid {pid})"),
            _ => "down".to_string(),
        }
    }

    pub async fn core_version(&self) -> Option<String> {
        match read_core_version(&self.bin).await {
            Ok(v) => v.semver,
            Err(e) => {
                tracing::warn!("Failed to read xray core version: {e}");
                None
            }
        }
    }
}

async fn supervise(
    bin: PathBuf,
    config_arg: String,
    forward_logs: bool,
    mut rx: mpsc::Receiver<Cmd>,
    status: watch::Sender<ProcStatus>,
    logs: Arc<Mutex<VecDeque<String>>>,
) {
    let mut child: Option<Child> = None;

    loop {
        tokio::select! {
            cmd = rx.recv() => {
                let Some(cmd) = cmd else { break };
                match cmd {
                    Cmd::Start(ack) => {
                        if child.is_some() {
                            let _ = ack.send(Ok(()));
                            continue;
                        }
                        match spawn_child(&bin, &config_arg, forward_logs, &logs) {
                            Ok(c) => {
                                let _ = status.send(ProcStatus { up: true, pid: c.id() });
                                child = Some(c);
                                let _ = ack.send(Ok(()));
                            }
                            Err(e) => {
                                let _ = ack.send(Err(e));
                            }
                        }
                    }
                    Cmd::Stop(ack) => {
                        if let Some(c) = child.take() {
                            terminate(c).await;
                        }
                        let _ = status.send(ProcStatus::default());
                        let _ = ack.send(());
                    }
                }
            }
            exit = wait_child(&mut child), if child.is_some() => {
                child = None;
                let _ = status.send(ProcStatus::default());
                match exit {
                    Ok(code) => tracing::warn!("Xray process exited: {code}"),
                    Err(e) => tracing::warn!("Failed to wait for Xray process: {e}"),
                }
            }
        }
    }

    if let Some(c) = child.take() {
        terminate(c).await;
    }
}

async fn wait_child(child: &mut Option<Child>) -> std::io::Result<std::process::ExitStatus> {
    match child {
        Some(c) => c.wait().await,
        None => std::future::pending().await,
    }
}

async fn terminate(mut child: Child) {
    if let Some(pid) = child.id() {
        // SAFETY: plain signal delivery to a child we own.
        unsafe { libc::kill(pid as i32, libc::SIGTERM) };
    }
    if tokio::time::timeout(KILL_AFTER, child.wait())
        .await
        .is_err()
    {
        tracing::warn!("Xray did not stop in {KILL_AFTER:?}, killing");
        let _ = child.kill().await;
    }
}

fn spawn_child(
    bin: &Path,
    config_arg: &str,
    forward_logs: bool,
    logs: &Arc<Mutex<VecDeque<String>>>,
) -> Result<Child> {
    let mut child = Command::new(bin)
        .args(["-config", config_arg, "-format", "json"])
        .env("XRAY_JSON_STRICT", "true")
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .kill_on_drop(true)
        .spawn()
        .with_context(|| format!("cannot start {}", bin.display()))?;

    if let Some(out) = child.stdout.take() {
        tokio::spawn(pump(out, forward_logs, logs.clone()));
    }
    if let Some(err) = child.stderr.take() {
        tokio::spawn(pump(err, forward_logs, logs.clone()));
    }
    Ok(child)
}

async fn pump<R: AsyncRead + Unpin>(reader: R, forward: bool, logs: Arc<Mutex<VecDeque<String>>>) {
    let mut lines = BufReader::new(reader).lines();
    while let Ok(Some(line)) = lines.next_line().await {
        if forward {
            tracing::info!(target: "xray", "{line}");
        }
        let mut ring = logs.lock().unwrap();
        if ring.len() == LOG_RING {
            ring.pop_front();
        }
        ring.push_back(line);
    }
}

#[derive(Debug)]
pub struct CoreVersion {
    pub raw: String,
    pub semver: Option<String>,
}

pub async fn read_core_version(path: &Path) -> Result<CoreVersion> {
    let out = tokio::time::timeout(
        Duration::from_secs(3),
        Command::new(path)
            .arg("version")
            .stdin(Stdio::null())
            .output(),
    )
    .await
    .map_err(|_| anyhow!("version check timed out"))??;
    let stdout = String::from_utf8_lossy(&out.stdout);
    let raw = stdout
        .lines()
        .next()
        .map(str::trim)
        .unwrap_or_default()
        .to_string();
    if raw.is_empty() {
        return Err(anyhow!("binary produced no version output"));
    }
    let semver = coerce_semver(&raw);
    Ok(CoreVersion { raw, semver })
}

/// First `major.minor.patch` found in the text ("Xray 26.7.28 (...)" -> "26.7.28").
pub fn coerce_semver(s: &str) -> Option<String> {
    let bytes = s.as_bytes();
    let mut i = 0;
    while i < bytes.len() {
        if bytes[i].is_ascii_digit() {
            let start = i;
            let mut parts = 0;
            let mut j = i;
            loop {
                let ds = j;
                while j < bytes.len() && bytes[j].is_ascii_digit() {
                    j += 1;
                }
                if j == ds {
                    break;
                }
                parts += 1;
                if parts == 3 {
                    return Some(s[start..j].to_string());
                }
                if j < bytes.len() && bytes[j] == b'.' {
                    j += 1;
                } else {
                    break;
                }
            }
            i = start + 1;
        } else {
            i += 1;
        }
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn semver_coercion() {
        assert_eq!(
            coerce_semver("Xray 26.7.28 (Xray, Penetrates Everything.) abc"),
            Some("26.7.28".into())
        );
        assert_eq!(coerce_semver("v1.8.24"), Some("1.8.24".into()));
        assert_eq!(coerce_semver("no version"), None);
        assert_eq!(coerce_semver("1.2"), None);
    }
}
