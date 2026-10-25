//! Custom Xray core and geodata asset provisioning (ports of `CoreLoaderService`,
//! `GeodataService` and `downloadFile`).

use std::{
    os::unix::fs::PermissionsExt,
    path::{Path, PathBuf},
    time::Duration,
};

use anyhow::{Context, Result, anyhow, bail};
use futures_util::StreamExt;
use serde::Deserialize;
use sha2::{Digest, Sha256};
use tokio::io::AsyncWriteExt;

use super::process::read_core_version;

const IDLE_TIMEOUT: Duration = Duration::from_secs(5);
const TOTAL_TIMEOUT: Duration = Duration::from_secs(15);
const MAX_SIZE: u64 = 128 * 1024 * 1024;
const ASSET_CONCURRENCY: usize = 5;

pub struct Downloaded {
    pub sha256: String,
    pub size: u64,
}

pub async fn download_file(
    client: &reqwest::Client,
    url: &str,
    path: &Path,
    expected_sha256: Option<&str>,
) -> Result<Downloaded> {
    let tmp = PathBuf::from(format!("{}.download", path.display()));
    let result = tokio::time::timeout(
        TOTAL_TIMEOUT,
        download_inner(client, url, &tmp, path, expected_sha256),
    )
    .await
    .map_err(|_| anyhow!("download exceeded {TOTAL_TIMEOUT:?}"))
    .and_then(|r| r);
    if result.is_err() {
        let _ = tokio::fs::remove_file(&tmp).await;
    }
    result
}

async fn download_inner(
    client: &reqwest::Client,
    url: &str,
    tmp: &Path,
    dest: &Path,
    expected_sha256: Option<&str>,
) -> Result<Downloaded> {
    let resp = client.get(url).send().await?;
    if !resp.status().is_success() {
        bail!("unexpected response {}", resp.status());
    }
    if resp.url().scheme() != "https" {
        bail!("redirected to a non-https url \"{}\"", resp.url());
    }
    if resp.content_length().is_some_and(|l| l > MAX_SIZE) {
        bail!("content-length exceeds {MAX_SIZE} bytes");
    }

    let mut file = tokio::fs::File::create(tmp).await?;
    let mut digest = Sha256::new();
    let mut size = 0u64;
    let mut stream = resp.bytes_stream();
    loop {
        let chunk = match tokio::time::timeout(IDLE_TIMEOUT, stream.next()).await {
            Err(_) => bail!("no data received for {IDLE_TIMEOUT:?}"),
            Ok(None) => break,
            Ok(Some(c)) => c?,
        };
        size += chunk.len() as u64;
        if size > MAX_SIZE {
            bail!("body exceeds {MAX_SIZE} bytes");
        }
        digest.update(&chunk);
        file.write_all(&chunk).await?;
    }
    file.flush().await?;
    drop(file);

    if size == 0 {
        bail!("empty response body");
    }
    let sha256 = hex::encode(digest.finalize());
    if let Some(expected) = expected_sha256
        && sha256 != expected.to_lowercase()
    {
        bail!("sha256 mismatch, got {sha256}, expected {expected}");
    }
    tokio::fs::rename(tmp, dest).await?;
    Ok(Downloaded { sha256, size })
}

fn pretty_bytes(n: u64) -> String {
    let mut v = n as f64;
    for unit in ["B", "kB", "MB", "GB"] {
        if v < 1000.0 {
            return format!("{v:.1} {unit}");
        }
        v /= 1000.0;
    }
    format!("{v:.1} TB")
}

// ------------------------------------------------------------------ core loader

#[derive(Deserialize)]
struct CoreSection {
    url: String,
    sha256: String,
}

#[derive(Deserialize)]
struct CoreWrapper {
    core: Option<CoreSection>,
}

#[derive(serde::Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
struct Marker {
    url: String,
    sha256: String,
    size: u64,
    mtime_ms: f64,
    version: String,
    installed_at: String,
}

pub struct CoreLoader {
    client: reqwest::Client,
    /// False when `rw-core` cannot be created (read-only dir): the stock binary runs directly
    /// and custom cores are unavailable.
    link_usable: bool,
    link: PathBuf,
    stock: PathBuf,
    custom: PathBuf,
    staged: PathBuf,
    marker: PathBuf,
}

fn mtime_ms(meta: &std::fs::Metadata) -> f64 {
    meta.modified()
        .ok()
        .and_then(|t| t.duration_since(std::time::UNIX_EPOCH).ok())
        .map(|d| d.as_secs_f64() * 1000.0)
        .unwrap_or(0.0)
}

fn is_sha256_hex(s: &str) -> bool {
    s.len() == 64 && s.bytes().all(|b| b.is_ascii_hexdigit())
}

impl CoreLoader {
    pub fn new(client: reqwest::Client, stock: PathBuf) -> Self {
        let dir = stock
            .parent()
            .map(Path::to_path_buf)
            .unwrap_or_else(|| PathBuf::from("."));
        let custom = dir.join("xray-custom");
        Self {
            client,
            link_usable: false,
            link: dir.join("rw-core"),
            staged: PathBuf::from(format!("{}.staged", custom.display())),
            marker: dir.join(".rw-core.json"),
            custom,
            stock,
        }
    }

    /// The path the process supervisor should execute (a symlink swapped atomically).
    pub fn link_path(&self) -> &Path {
        if self.link_usable {
            &self.link
        } else {
            &self.stock
        }
    }

    /// Makes sure `rw-core` exists when the stock binary does (a plain install has no link yet).
    pub async fn ensure_link(&mut self) {
        if tokio::fs::symlink_metadata(&self.link).await.is_ok() {
            self.link_usable = true;
        } else if tokio::fs::metadata(&self.stock).await.is_ok() {
            match self.point_link_at(&self.stock).await {
                Ok(()) => self.link_usable = true,
                Err(e) => tracing::warn!(
                    "Cannot create {}: {e:#}; custom cores are disabled",
                    self.link.display()
                ),
            }
        }
    }

    pub async fn prepare(&self, geodata: Option<&serde_json::Value>) {
        if !self.link_usable {
            return;
        }
        let parsed: Result<CoreWrapper, _> =
            serde_json::from_value(geodata.cloned().unwrap_or_else(|| serde_json::json!({})));
        let core = match parsed {
            Ok(w) => w.core,
            Err(e) => {
                tracing::warn!("Invalid \"core\" section, skipped: {e}");
                return;
            }
        };
        let Some(core) = core else {
            if let Err(e) = self.restore_stock().await {
                tracing::error!("Failed to restore the bundled core: {e:#}");
            }
            return;
        };
        if !core.url.starts_with("https://") || !is_sha256_hex(&core.sha256) {
            tracing::warn!(
                "Invalid \"core\" section, skipped: url must be https and sha256 a 64-char hex"
            );
            return;
        }
        let core = CoreSection {
            url: core.url,
            sha256: core.sha256.to_lowercase(),
        };
        if self.is_installed(&core).await {
            return;
        }
        self.install(&core).await;
    }

    async fn is_installed(&self, core: &CoreSection) -> bool {
        let Ok(raw) = tokio::fs::read(&self.marker).await else {
            return false;
        };
        let Ok(marker) = serde_json::from_slice::<Marker>(&raw) else {
            return false;
        };
        if marker.url != core.url {
            tracing::info!("Configured url changed, re-downloading.");
            return false;
        }
        if marker.sha256 != core.sha256 {
            tracing::info!("Configured sha256 changed, re-downloading.");
            return false;
        }
        let Ok(meta) = tokio::fs::metadata(&self.custom).await else {
            return false;
        };
        if meta.len() != marker.size || (mtime_ms(&meta) - marker.mtime_ms).abs() > 1.0 {
            tracing::warn!("Installed binary no longer matches the marker.");
            return false;
        }
        tokio::fs::read_link(&self.link).await.ok().as_deref() == Some(self.custom.as_path())
    }

    async fn install(&self, core: &CoreSection) {
        let started = std::time::Instant::now();
        let res: Result<()> = async {
            let dl =
                download_file(&self.client, &core.url, &self.staged, Some(&core.sha256)).await?;
            tokio::fs::set_permissions(&self.staged, std::fs::Permissions::from_mode(0o755))
                .await?;
            let version = read_core_version(&self.staged).await?.raw;
            tokio::fs::rename(&self.staged, &self.custom).await?;
            self.point_link_at(&self.custom).await?;
            let meta = tokio::fs::metadata(&self.custom).await?;
            let marker = Marker {
                url: core.url.clone(),
                sha256: dl.sha256,
                size: meta.len(),
                mtime_ms: mtime_ms(&meta),
                version: version.clone(),
                installed_at: crate::plugin::now_iso(chrono::Utc::now()),
            };
            tokio::fs::write(&self.marker, serde_json::to_vec_pretty(&marker)?).await?;
            tracing::info!(
                "Installed \"{version}\" ({}) in {:?}",
                pretty_bytes(dl.size),
                started.elapsed()
            );
            Ok(())
        }
        .await;
        if let Err(e) = res {
            tracing::error!("Failed to install custom core: {e:#}");
            let _ = tokio::fs::remove_file(&self.staged).await;
        }
    }

    async fn restore_stock(&self) -> Result<()> {
        let current = tokio::fs::read_link(&self.link).await.ok();
        if current.is_none() || current.as_deref() == Some(self.stock.as_path()) {
            return Ok(());
        }
        self.point_link_at(&self.stock).await?;
        let _ = tokio::fs::remove_file(&self.marker).await;
        let _ = tokio::fs::remove_file(&self.custom).await;
        tracing::warn!("No core configured, rolled back to the bundled one.");
        Ok(())
    }

    async fn point_link_at(&self, target: &Path) -> Result<()> {
        let tmp = PathBuf::from(format!("{}.tmp", self.link.display()));
        let _ = tokio::fs::remove_file(&tmp).await;
        tokio::fs::symlink(target, &tmp)
            .await
            .with_context(|| format!("symlink {}", tmp.display()))?;
        tokio::fs::rename(&tmp, &self.link).await?;
        Ok(())
    }
}

// ------------------------------------------------------------------ geodata assets

#[derive(Deserialize)]
struct Asset {
    url: String,
    file: String,
}

#[derive(Deserialize)]
struct Assets {
    #[serde(default)]
    assets: Vec<Asset>,
}

/// File names only: no separators, no `.`/`..`.
pub(crate) fn valid_asset_name(s: &str) -> bool {
    !s.is_empty()
        && s != "."
        && s != ".."
        && s.bytes()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'_' | b'.' | b'-'))
}

pub async fn prepare_geodata(
    client: &reqwest::Client,
    assets_dir: &Path,
    geodata: Option<&serde_json::Value>,
) {
    let Some(geodata) = geodata else { return };
    let assets = match serde_json::from_value::<Assets>(geodata.clone()) {
        Ok(a) => a.assets,
        Err(e) => {
            tracing::warn!("Invalid \"assets\" section, skipped: {e}");
            return;
        }
    };
    if let Some(bad) = assets
        .iter()
        .find(|a| !valid_asset_name(&a.file) || !a.url.starts_with("https://"))
    {
        tracing::warn!(
            "Invalid \"assets\" section, skipped: \"{}\" must be a file name without a path and an https url",
            bad.file
        );
        return;
    }
    if assets.is_empty() {
        return;
    }
    let started = std::time::Instant::now();
    let total = assets.len();
    futures_util::stream::iter(assets)
        .for_each_concurrent(ASSET_CONCURRENCY, |a| async move {
            prepare_asset(client, assets_dir, a).await
        })
        .await;
    tracing::info!("{total} asset(s) processed in {:?}", started.elapsed());
}

async fn prepare_asset(client: &reqwest::Client, dir: &Path, asset: Asset) {
    let path = dir.join(&asset.file);
    if tokio::fs::metadata(&path)
        .await
        .is_ok_and(|m| m.is_file() && m.len() > 0)
    {
        return;
    }
    let started = std::time::Instant::now();
    match download_file(client, &asset.url, &path, None).await {
        Ok(d) => {
            tracing::info!(
                "Downloaded \"{}\" ({}) in {:?}",
                asset.file,
                pretty_bytes(d.size),
                started.elapsed()
            );
            return;
        }
        Err(e) => tracing::error!("Failed to download \"{}\": {e:#}", asset.url),
    }
    match tokio::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(&path)
        .await
    {
        Ok(_) => tracing::warn!("Created empty stub asset \"{}\".", path.display()),
        Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => {}
        Err(e) => tracing::error!("Failed to create stub asset \"{}\": {e}", path.display()),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn asset_names() {
        assert!(valid_asset_name("geoip-custom.dat"));
        assert!(!valid_asset_name("../etc/passwd"));
        assert!(!valid_asset_name(".."));
        assert!(!valid_asset_name("a/b"));
        assert!(!valid_asset_name(""));
    }

    #[test]
    fn sha_validation() {
        assert!(is_sha256_hex(&"a".repeat(64)));
        assert!(!is_sha256_hex("xyz"));
    }

    #[tokio::test]
    async fn restore_is_noop_without_link() {
        let dir = tempfile::tempdir().unwrap();
        let mut loader = CoreLoader::new(reqwest::Client::new(), dir.path().join("xray"));
        // no stock binary: nothing to link, the stock path is used as is
        loader.ensure_link().await;
        assert_eq!(loader.link_path(), dir.path().join("xray"));
        assert!(
            tokio::fs::symlink_metadata(dir.path().join("rw-core"))
                .await
                .is_err()
        );

        std::fs::write(dir.path().join("xray"), b"bin").unwrap();
        loader.ensure_link().await;
        assert_eq!(loader.link_path(), dir.path().join("rw-core"));
        assert_eq!(
            tokio::fs::read_link(loader.link_path()).await.unwrap(),
            dir.path().join("xray")
        );
        loader.prepare(None).await;
    }
}
