//! Host information, network rate sampling and capability checks (all via /proc).

use std::{
    collections::HashMap,
    fs,
    sync::{Arc, RwLock},
    time::{Duration, Instant},
};

use serde::Serialize;

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct NetworkInterface {
    pub interface: String,
    pub rx_bytes_per_sec: f64,
    pub tx_bytes_per_sec: f64,
    pub rx_total: u64,
    pub tx_total: u64,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct NodeSystemInfo {
    pub arch: String,
    pub cpus: usize,
    pub cpu_model: String,
    pub memory_total: u64,
    pub hostname: String,
    pub platform: String,
    pub release: String,
    #[serde(rename = "type")]
    pub os_type: String,
    pub version: String,
    pub network_interfaces: Vec<String>,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct NodeSystemStats {
    pub memory_free: u64,
    pub memory_used: u64,
    pub uptime: f64,
    pub load_avg: [f64; 3],
    pub interface: Option<NetworkInterface>,
}

fn read_trim(path: &str) -> String {
    fs::read_to_string(path)
        .map(|s| s.trim().to_string())
        .unwrap_or_default()
}

fn meminfo_kb(key: &str) -> Option<u64> {
    let text = fs::read_to_string("/proc/meminfo").ok()?;
    text.lines().find_map(|l| {
        let rest = l.strip_prefix(key)?.strip_prefix(':')?;
        rest.split_whitespace().next()?.parse().ok()
    })
}

pub fn system_info() -> NodeSystemInfo {
    let cpuinfo = fs::read_to_string("/proc/cpuinfo").unwrap_or_default();
    let cpus = cpuinfo
        .lines()
        .filter(|l| l.starts_with("processor"))
        .count();
    let cpus = if cpus > 0 {
        cpus
    } else {
        std::thread::available_parallelism()
            .map(|n| n.get())
            .unwrap_or(1)
    };
    let cpu_model = cpuinfo
        .lines()
        .find(|l| l.starts_with("model name"))
        .and_then(|l| l.split_once(':'))
        .map(|(_, v)| v.trim().to_string())
        .unwrap_or_else(|| "unknown".into());

    let arch = match std::env::consts::ARCH {
        "x86_64" => "x64",
        "aarch64" => "arm64",
        "x86" => "ia32",
        other => other,
    };

    let mut interfaces: Vec<String> = fs::read_dir("/sys/class/net")
        .map(|d| {
            d.flatten()
                .map(|e| e.file_name().to_string_lossy().into_owned())
                .collect()
        })
        .unwrap_or_default();
    interfaces.sort();

    NodeSystemInfo {
        arch: arch.into(),
        cpus,
        cpu_model,
        memory_total: meminfo_kb("MemTotal").unwrap_or(0) * 1024,
        hostname: read_trim("/proc/sys/kernel/hostname"),
        platform: "linux".into(),
        release: read_trim("/proc/sys/kernel/osrelease"),
        os_type: "Linux".into(),
        version: read_trim("/proc/sys/kernel/version"),
        network_interfaces: interfaces,
    }
}

pub fn system_stats(interface: Option<NetworkInterface>) -> NodeSystemStats {
    let total = meminfo_kb("MemTotal").unwrap_or(0) * 1024;
    // libuv's os.freemem() on Linux reports MemAvailable.
    let free = meminfo_kb("MemAvailable")
        .or_else(|| meminfo_kb("MemFree"))
        .unwrap_or(0)
        * 1024;
    let uptime = read_trim("/proc/uptime")
        .split_whitespace()
        .next()
        .and_then(|v| v.parse().ok())
        .unwrap_or(0.0);
    let load: Vec<f64> = read_trim("/proc/loadavg")
        .split_whitespace()
        .take(3)
        .filter_map(|v| v.parse().ok())
        .collect();
    NodeSystemStats {
        memory_free: free,
        memory_used: total.saturating_sub(free),
        uptime,
        load_avg: [
            load.first().copied().unwrap_or(0.0),
            load.get(1).copied().unwrap_or(0.0),
            load.get(2).copied().unwrap_or(0.0),
        ],
        interface,
    }
}

/// True when the process holds CAP_NET_ADMIN (bit 12 of the effective set).
pub fn has_cap_net_admin() -> bool {
    fs::read_to_string("/proc/self/status")
        .ok()
        .and_then(|s| {
            s.lines()
                .find_map(|l| l.strip_prefix("CapEff:").map(|v| v.trim().to_string()))
        })
        .and_then(|hex| u64::from_str_radix(&hex, 16).ok())
        .is_some_and(|caps| caps & (1 << 12) != 0)
}

// ------------------------------------------------------------------ network rates

#[derive(Clone, Copy)]
struct Counters {
    rx: u64,
    tx: u64,
    at: Instant,
}

#[derive(Clone, Default)]
pub struct NetworkStats {
    rates: Arc<RwLock<HashMap<String, NetworkInterface>>>,
    default_iface: Arc<RwLock<Option<String>>>,
}

fn read_proc_net_dev() -> HashMap<String, Counters> {
    let now = Instant::now();
    let mut out = HashMap::new();
    let Ok(text) = fs::read_to_string("/proc/net/dev") else {
        return out;
    };
    for line in text.lines().skip(2) {
        let Some((name, rest)) = line.split_once(':') else {
            continue;
        };
        let f: Vec<&str> = rest.split_whitespace().collect();
        if f.len() < 16 {
            continue;
        }
        let (Ok(rx), Ok(tx)) = (f[0].parse(), f[8].parse()) else {
            continue;
        };
        out.insert(name.trim().to_string(), Counters { rx, tx, at: now });
    }
    out
}

fn default_interface() -> Option<String> {
    let text = fs::read_to_string("/proc/net/route").ok()?;
    let mut best: Option<(String, u32)> = None;
    for line in text.lines().skip(1) {
        let f: Vec<&str> = line.split_whitespace().collect();
        if f.len() < 11 || f[1] != "00000000" {
            continue;
        }
        let metric = f[6].parse::<u32>().unwrap_or(0);
        if best.as_ref().is_none_or(|(_, m)| metric < *m) {
            best = Some((f[0].to_string(), metric));
        }
    }
    best.map(|(i, _)| i)
}

impl NetworkStats {
    /// Starts the 1s sampler. Without /proc/net/dev it stays idle.
    pub fn start() -> Self {
        let this = Self::default();
        if !std::path::Path::new("/proc/net/dev").exists() {
            tracing::warn!("/proc/net/dev not found - network stats polling disabled");
            return this;
        }
        *this.default_iface.write().unwrap() = default_interface();
        tracing::info!(
            "Network stats polling started (default: {})",
            this.default_iface
                .read()
                .unwrap()
                .as_deref()
                .unwrap_or("unknown")
        );

        let rates = this.rates.clone();
        tokio::spawn(async move {
            let mut prev = read_proc_net_dev();
            let mut tick = tokio::time::interval(Duration::from_secs(1));
            tick.tick().await;
            loop {
                tick.tick().await;
                let now = read_proc_net_dev();
                let mut map = rates.write().unwrap();
                for (name, cur) in &now {
                    let Some(p) = prev.get(name) else { continue };
                    let elapsed = cur.at.duration_since(p.at).as_secs_f64();
                    if elapsed <= 0.0 {
                        continue;
                    }
                    map.insert(
                        name.clone(),
                        NetworkInterface {
                            interface: name.clone(),
                            rx_bytes_per_sec: (cur.rx.saturating_sub(p.rx)) as f64 / elapsed,
                            tx_bytes_per_sec: (cur.tx.saturating_sub(p.tx)) as f64 / elapsed,
                            rx_total: cur.rx,
                            tx_total: cur.tx,
                        },
                    );
                }
                drop(map);
                prev = now;
            }
        });
        this
    }

    pub fn default_rate(&self) -> Option<NetworkInterface> {
        let name = self.default_iface.read().unwrap().clone()?;
        self.rates.read().unwrap().get(&name).cloned()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn info_and_stats_are_populated() {
        let info = system_info();
        assert!(info.cpus >= 1);
        assert!(info.memory_total > 0);
        let stats = system_stats(None);
        assert!(stats.memory_free <= info.memory_total);
        assert!(stats.uptime > 0.0);
    }
}
