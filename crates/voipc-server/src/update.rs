//! The relay updating itself (`[update]`, 1.6): it checks the same release
//! feed as the desktop apps, takes a newer release of the same major version
//! once it has seen it for `delay_minutes`, and replaces its own binary with
//! it, the way Syncthing does. The binary must be writable by the user the
//! relay runs as (OPERATING.md §14); a container takes a new image instead.
//!
//! What it trusts: only a binary signed with the updater key the apps trust,
//! for the version and the file the feed names (the same check as Tauri's
//! `requireSignedVersion`). What can go wrong is kept recoverable:
//! - nothing replaces the running binary until the new one has run here
//!   (`--version`) and the accounts database is copied; the rename is the
//!   commit point;
//! - the old binary stays as `<exe>.previous`; a new one that never gets as
//!   far as serving is replaced by it again at its next start, and its
//!   version is not taken again (`<exe>.failed`).

use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::Duration;

use anyhow::{anyhow, bail, Context, Result};
use semver::Version;
use serde::Deserialize;
use tokio::sync::mpsc;
use tracing::{error, info, warn};

use crate::config::UpdateConfig;
use crate::state::ServerState;

/// Whether there is an official build of this one to update to.
pub const SUPPORTED: bool = cfg!(all(target_os = "linux", target_arch = "x86_64"));

/// The key every release is signed with: the apps' own
/// (client/src-tauri/tauri.conf.json `plugins.updater.pubkey`, which a test
/// holds this to).
const PUBKEY: &str = "dW50cnVzdGVkIGNvbW1lbnQ6IG1pbmlzaWduIHB1YmxpYyBrZXk6IDVGMkEyQzdDNjYwMTIyOTgKUldTWUlnRm1mQ3dxWDV6NWlYQjJSNTZrcXJaVVNETU9MOWY1ZVUvakhON28vTnBCZSsreTh6b24K";

/// The release file, its key in the feed, and the feeds (the apps' too:
/// client/src-tauri/src/updater.rs).
const ASSET: &str = "voipc-server-linux-x86_64";
const PLATFORM: &str = "linux-x86_64-server";
const STABLE_FEED: &str = "https://github.com/luki4fun/voipc/releases/latest/download/latest.json";
const RC_FEED: &str = "https://github.com/luki4fun/voipc/releases/download/updater-rc/latest.json";

const CHECK_EVERY: Duration = Duration::from_secs(5 * 60);
const MAX_FEED: usize = 1 << 20;
const MAX_BINARY: usize = 200 << 20;
/// Copies of the accounts database kept from before an update.
const KEEP_BACKUPS: usize = 2;
/// Past this a copy goes at the next update, as OPERATING says of every copy: it still holds
/// what people have since deleted, and it is stale for a rollback. Not the newest: until that
/// update has finished, its copy is the only way back.
const BACKUP_MAX_AGE: Duration = Duration::from_secs(30 * 86_400);

/// The running binary and the files beside it.
#[derive(Debug, Clone)]
pub struct Paths {
    exe: PathBuf,
    download: PathBuf,
    previous: PathBuf,
    updating: PathBuf,
    failed: PathBuf,
}

impl Paths {
    fn of(exe: PathBuf) -> Self {
        let with = |ext: &str| {
            let mut s = exe.clone().into_os_string();
            s.push(ext);
            PathBuf::from(s)
        };
        Paths {
            download: with(".download"),
            previous: with(".previous"),
            updating: with(".updating"),
            failed: with(".failed"),
            exe,
        }
    }

    /// The binary this process runs, taken before anything replaces it.
    pub fn current() -> Result<Self> {
        Ok(Self::of(
            std::env::current_exe().context("finding this binary")?,
        ))
    }

    /// For a relay with `[update] enabled`: refused at the start when it
    /// could not replace its binary.
    pub fn writable() -> Result<Self> {
        let paths = Self::current()?;
        let probe = paths.exe.with_file_name(".voipc-update-probe");
        std::fs::write(&probe, b"")
            .and_then(|()| std::fs::remove_file(&probe))
            .map_err(|e| {
                anyhow!(
                    "[update] enabled replaces {}, but this user cannot write there ({e}): see OPERATING.md §14, or switch it off",
                    paths.exe.display()
                )
            })?;
        Ok(paths)
    }

    fn backup(&self, version: &str) -> PathBuf {
        let mut s = self.exe.clone().into_os_string();
        s.push(format!(".accounts-before-{version}.db"));
        PathBuf::from(s)
    }

    fn failed_versions(&self) -> Vec<String> {
        std::fs::read_to_string(&self.failed)
            .unwrap_or_default()
            .lines()
            .map(|l| l.trim().to_string())
            .filter(|l| !l.is_empty())
            .collect()
    }

    fn mark_failed(&self, version: &str) {
        let mut all = self.failed_versions();
        all.push(version.to_string());
        if let Err(e) = std::fs::write(&self.failed, all.join("\n") + "\n") {
            warn!("update: could not note {version} as failed: {e}");
        }
    }
}

// ── At start ──────────────────────────────────────────────────────────────

/// What a start finds in `<exe>.updating`, on the serving path only (a
/// `health` or `ban` run never touches it).
#[derive(Debug, PartialEq)]
enum Marker {
    None,
    /// The first start after the update to this version.
    First(String),
    /// A second start that finds the first one never got ready.
    Failed(String),
}

fn read_marker(paths: &Paths) -> Marker {
    let Ok(text) = std::fs::read_to_string(&paths.updating) else {
        return Marker::None;
    };
    let text = text.trim();
    match text.strip_suffix(" started") {
        Some(v) => Marker::Failed(v.to_string()),
        None if !text.is_empty() => Marker::First(text.to_string()),
        None => Marker::None,
    }
}

/// Before the config is read: the first start after an update says so, and
/// a start after one that never got ready goes back to the previous binary.
pub fn after_restart() {
    let Ok(paths) = Paths::current() else { return };
    match read_marker(&paths) {
        Marker::None => {}
        Marker::First(v) => {
            if let Err(e) = std::fs::write(&paths.updating, format!("{v} started")) {
                warn!("update: could not mark the first start of {v}: {e}");
            }
        }
        Marker::Failed(v) => match roll_back(&paths, &v) {
            Ok(()) => {
                error!(
                    "update: {v} did not start; back to the previous binary. If it had migrated the accounts database already, \
                     the previous one refuses it: restore {} (OPERATING.md §14)",
                    paths.backup(&v).display()
                );
                exec(&paths.exe);
            }
            Err(e) => error!(
                "update: {v} did not start last time, and going back failed ({e:#}); running {v}"
            ),
        },
    }
}

fn roll_back(paths: &Paths, version: &str) -> Result<()> {
    std::fs::remove_file(&paths.updating).context("removing the marker")?;
    paths.mark_failed(version);
    std::fs::rename(&paths.previous, &paths.exe).context("putting the previous binary back")
}

/// Once the relay serves: the update it started as worked.
pub fn ready() {
    let Ok(paths) = Paths::current() else { return };
    if let Marker::First(v) | Marker::Failed(v) = read_marker(&paths) {
        if std::fs::remove_file(&paths.updating).is_ok() {
            info!("update: now running {v}");
        }
    }
}

/// Replace this process with `exe`, with the same arguments. Returns only by
/// exiting: the clients were told the relay is going, so it must not stay
/// down on a clean exit (`Restart=on-failure` restarts a failed one).
pub fn exec(exe: &Path) -> ! {
    #[cfg(unix)]
    {
        use std::os::unix::process::CommandExt;
        let err = std::process::Command::new(exe)
            .args(std::env::args_os().skip(1))
            .exec();
        error!("update: could not start {}: {err}", exe.display());
    }
    #[cfg(not(unix))]
    error!("update: cannot restart {} on this platform", exe.display());
    std::process::exit(1)
}

/// The update this relay restarts into: its marker first, then the new
/// binary. Called after the clients were told and the state was saved.
pub fn restart(paths: &Paths, version: &str) -> ! {
    if let Err(e) = std::fs::write(&paths.updating, version) {
        // Without it a broken update would not be rolled back; still better
        // than not starting the binary that is already in place
        warn!("update: could not write {}: {e}", paths.updating.display());
    }
    exec(&paths.exe)
}

// ── The check ─────────────────────────────────────────────────────────────

#[derive(Debug, Deserialize)]
struct Feed {
    version: String,
    #[serde(default)]
    platforms: std::collections::HashMap<String, Asset>,
}

#[derive(Debug, Clone, Deserialize)]
struct Asset {
    url: String,
    signature: String,
}

/// The release in `feed` to take, if any: newer than `ours`, of the same
/// major version, not failed here before, and with a relay build.
fn pick(feed: &Feed, ours: &Version, failed: &[String]) -> Option<(Version, Asset)> {
    let v = Version::parse(&feed.version).ok()?;
    if v <= *ours || v.major != ours.major || failed.contains(&v.to_string()) {
        return None;
    }
    Some((v, feed.platforms.get(PLATFORM)?.clone()))
}

/// `data` against a Tauri `.sig` (base64 of a minisign signature) by the key
/// `pubkey` (base64 of a minisign public key), for `version` of `file`.
fn verify(data: &[u8], sig: &str, pubkey: &str, file: &str, version: &str) -> Result<()> {
    use base64::Engine;
    let text = |b64: &str| -> Result<String> {
        let bytes = base64::engine::general_purpose::STANDARD.decode(b64.trim())?;
        Ok(String::from_utf8(bytes)?)
    };
    let key =
        minisign_verify::PublicKey::decode(&text(pubkey)?).map_err(|e| anyhow!("the key: {e}"))?;
    let sig = minisign_verify::Signature::decode(&text(sig)?)
        .map_err(|e| anyhow!("the signature: {e}"))?;
    key.verify(data, &sig, true)
        .map_err(|e| anyhow!("not signed with the release key: {e}"))?;
    // Only now is the trusted comment trusted: the signature covers it
    let fields: Vec<&str> = sig.trusted_comment().split('\t').collect();
    if !fields.contains(&format!("file:{file}").as_str()) {
        bail!("signed for another file ({})", sig.trusted_comment());
    }
    if !fields
        .iter()
        .any(|f| f.strip_prefix("version:") == Some(version))
    {
        bail!(
            "signed for another version than {version} ({})",
            sig.trusted_comment()
        );
    }
    Ok(())
}

fn http_client() -> Result<reqwest::Client> {
    // The bundled roots: a static binary on a host without a CA store still
    // reaches GitHub
    let roots = rustls::RootCertStore::from_iter(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());
    let tls = rustls::ClientConfig::builder_with_provider(Arc::new(
        rustls::crypto::ring::default_provider(),
    ))
    .with_safe_default_protocol_versions()?
    .with_root_certificates(roots)
    .with_no_client_auth();
    Ok(reqwest::Client::builder()
        .tls_backend_preconfigured(tls)
        .https_only(!cfg!(debug_assertions))
        .user_agent(concat!("voipc-server/", env!("CARGO_PKG_VERSION")))
        .connect_timeout(Duration::from_secs(20))
        .timeout(Duration::from_secs(300))
        .build()?)
}

async fn get(client: &reqwest::Client, url: &str, cap: usize) -> Result<Vec<u8>> {
    let mut resp = client.get(url).send().await?.error_for_status()?;
    let mut out = Vec::new();
    while let Some(chunk) = resp.chunk().await? {
        if out.len() + chunk.len() > cap {
            bail!("{url} is larger than {cap} bytes");
        }
        out.extend_from_slice(&chunk);
    }
    Ok(out)
}

/// Where to look, and with which key. A debug build may be pointed at a
/// local feed and key for a dry run; a release build never.
fn feed_and_key(cfg: &UpdateConfig) -> (String, String) {
    let feed = if cfg.release_candidates {
        RC_FEED
    } else {
        STABLE_FEED
    };
    #[cfg(debug_assertions)]
    if let (Ok(feed), Ok(key)) = (
        std::env::var("VOIPC_UPDATE_FEED"),
        std::env::var("VOIPC_UPDATE_PUBKEY"),
    ) {
        return (feed, key);
    }
    (feed.into(), PUBKEY.into())
}

/// Checks the feed every few minutes; once an update has waited its delay,
/// stages it and sends its version to the main loop, which restarts into it.
pub fn spawn(
    cfg: UpdateConfig,
    paths: Paths,
    state: Arc<ServerState>,
    ready: mpsc::Sender<String>,
) {
    tokio::spawn(async move {
        let ours = Version::parse(env!("CARGO_PKG_VERSION")).expect("our own version is semver");
        let (feed_url, key) = feed_and_key(&cfg);
        let client = match http_client() {
            Ok(c) => c,
            Err(e) => return error!("update: no HTTP client ({e:#}); not checking for updates"),
        };
        let delay = Duration::from_secs(60 * u64::from(cfg.delay_minutes));
        info!(feed = %feed_url, delay_minutes = cfg.delay_minutes, "update: checking for newer releases");
        let mut seen: Option<(Version, tokio::time::Instant)> = None;
        let mut every = tokio::time::interval(CHECK_EVERY);
        loop {
            // The tick's own time, so a delay of one period is taken at the next
            let now = every.tick().await;
            let feed = match get(&client, &feed_url, MAX_FEED)
                .await
                .and_then(|b| Ok(serde_json::from_slice::<Feed>(&b)?))
            {
                Ok(feed) => feed,
                Err(e) => {
                    warn!("update: the feed: {e:#}");
                    continue;
                }
            };
            let Some((version, asset)) = pick(&feed, &ours, &paths.failed_versions()) else {
                continue;
            };
            let since = match &seen {
                Some((v, at)) if *v == version => *at,
                _ => {
                    info!(%version, "update: found; taking it {} minutes after first seeing it", cfg.delay_minutes);
                    seen = Some((version.clone(), now));
                    now
                }
            };
            if now - since < delay {
                continue;
            }
            let v = version.to_string();
            match stage(&client, &paths, &v, &asset, &key, &state).await {
                Ok(()) => {
                    info!(version = %v, "update: in place; restarting into it");
                    let _ = ready.send(v).await;
                    return;
                }
                Err(e) => {
                    error!("update: {v} not taken, staying on {ours}: {e:#}");
                    paths.mark_failed(&v);
                }
            }
        }
    });
}

/// Everything before the restart, the rename last: until then the running
/// binary is the one in place.
async fn stage(
    client: &reqwest::Client,
    paths: &Paths,
    version: &str,
    asset: &Asset,
    key: &str,
    state: &ServerState,
) -> Result<()> {
    let bytes = get(client, &asset.url, MAX_BINARY)
        .await
        .context("downloading")?;
    verify(&bytes, &asset.signature, key, ASSET, version).context("checking it")?;
    write_executable(&paths.download, &bytes).context("writing it")?;
    preflight(&paths.download, version).await?;
    if let Some(relay) = &state.accounts {
        backup(relay.store(), paths, version).await?;
    }
    std::fs::copy(&paths.exe, &paths.previous).context("keeping the running binary")?;
    std::fs::rename(&paths.download, &paths.exe).context("putting the new binary in place")
}

fn write_executable(path: &Path, bytes: &[u8]) -> std::io::Result<()> {
    use std::io::Write;
    let _ = std::fs::remove_file(path);
    let mut o = std::fs::OpenOptions::new();
    o.write(true).create_new(true);
    #[cfg(unix)]
    std::os::unix::fs::OpenOptionsExt::mode(&mut o, 0o755);
    let mut f = o.open(path)?;
    f.write_all(bytes)?;
    f.sync_all()
}

/// The new binary runs on this host and is the version it says.
async fn preflight(binary: &Path, version: &str) -> Result<()> {
    let out = tokio::time::timeout(
        Duration::from_secs(30),
        tokio::process::Command::new(binary)
            .arg("--version")
            .output(),
    )
    .await
    .map_err(|_| anyhow!("the new binary did not answer --version"))?
    .context("running the new binary")?;
    let said = String::from_utf8_lossy(&out.stdout);
    if !out.status.success() || said.trim() != format!("voipc-server {version}") {
        bail!(
            "the new binary said {:?}, not voipc-server {version}",
            said.trim()
        );
    }
    Ok(())
}

/// The accounts database as it was before `version` migrates it, beside the
/// binary; the last `KEEP_BACKUPS` stay. Postgres has pg_dump.
async fn backup(store: &l4f_accounts::store::Store, paths: &Paths, version: &str) -> Result<()> {
    if !matches!(store, l4f_accounts::store::Store::Lite(_)) {
        info!("update: the accounts database is Postgres, whose backups are the operator's");
        return Ok(());
    }
    let to = paths.backup(version);
    let mut part = to.clone().into_os_string();
    part.push(".part");
    let part = PathBuf::from(part);
    let _ = std::fs::remove_file(&part);
    crate::accounts::sqlite_backup(store, &part)
        .await
        .context("copying the accounts database")?;
    std::fs::rename(&part, &to).context("naming the copy")?;
    info!("update: the accounts database copied to {}", to.display());
    prune_backups(paths);
    Ok(())
}

fn prune_backups(paths: &Paths) {
    let (Some(dir), Some(name)) = (paths.exe.parent(), paths.exe.file_name()) else {
        return;
    };
    let prefix = format!("{}.accounts-before-", name.to_string_lossy());
    let Ok(entries) = std::fs::read_dir(dir) else {
        return;
    };
    let mut found: Vec<_> = entries
        .flatten()
        .filter(|e| {
            let n = e.file_name().to_string_lossy().into_owned();
            n.starts_with(&prefix) && n.ends_with(".db")
        })
        .filter_map(|e| Some((e.metadata().ok()?.modified().ok()?, e.path())))
        .collect();
    found.sort();
    let now = std::time::SystemTime::now();
    for (i, (at, path)) in found.iter().rev().enumerate() {
        let aged = now
            .duration_since(*at)
            .is_ok_and(|age| age > BACKUP_MAX_AGE);
        if i >= KEEP_BACKUPS || (i > 0 && aged) {
            let _ = std::fs::remove_file(path);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use base64::Engine;

    /// tauri-plugin-updater 2.14's test vector: a throwaway key, and its
    /// signature of the payload `test` made with
    /// `tauri signer sign --app-version 2.0.0` of a file named `payload`.
    const KEY: &str = "untrusted comment: minisign public key: A49EF4746FA6E6D7\nRWTX5qZvdPSepDGWg2bz8n6ArQnBMwgQK1geVosorcbLzcunD+KJ+cYe";
    const SIG: &str = "untrusted comment: signature from tauri secret key\nRUTX5qZvdPSepPF2zsjvP/L/TQtBLRnWRvaq+4omK1UEugtQp/USrGiI1v762sDy3id3aor7bRC9ETyeot6lMHHrWoZ5hjUM1Qc=\ntrusted comment: timestamp:1791649051\tfile:payload\tversion:2.0.0\nDDq2CLOEl5cQmC2eJRHlnZPVViOZsu1CjpPKQoei4A/XBfkDqGO0B+QMrcrHgEQ5qV3mne75tdFWhJpqUXh9AA==";

    fn b64(s: &str) -> String {
        base64::engine::general_purpose::STANDARD.encode(s)
    }

    #[test]
    fn only_a_release_signed_for_its_file_and_version_passes() {
        let (key, sig) = (b64(KEY), b64(SIG));
        verify(b"test", &sig, &key, "payload", "2.0.0").unwrap();
        let err = |data: &[u8], file: &str, version: &str| {
            verify(data, &sig, &key, file, version)
                .unwrap_err()
                .to_string()
        };
        assert!(err(b"tesT", "payload", "2.0.0").contains("not signed"));
        assert!(err(b"test", ASSET, "2.0.0").contains("another file"));
        assert!(err(b"test", "payload", "2.0.1").contains("another version"));
        // The release key did not sign it
        assert!(verify(b"test", &sig, PUBKEY, "payload", "2.0.0").is_err());
    }

    /// The relay trusts the key the apps trust.
    #[test]
    fn the_key_is_the_apps_key() {
        let conf: serde_json::Value =
            serde_json::from_str(include_str!("../../../client/src-tauri/tauri.conf.json"))
                .unwrap();
        assert_eq!(conf["plugins"]["updater"]["pubkey"].as_str(), Some(PUBKEY));
    }

    fn feed(version: &str, with_server: bool) -> Feed {
        let mut platforms = std::collections::HashMap::new();
        if with_server {
            platforms.insert(
                PLATFORM.to_string(),
                Asset {
                    url: "u".into(),
                    signature: "s".into(),
                },
            );
        }
        Feed {
            version: version.into(),
            platforms,
        }
    }

    #[test]
    fn what_a_relay_takes() {
        let ours = Version::parse("1.6.0").unwrap();
        let take = |v: &str| pick(&feed(v, true), &ours, &[]).map(|(v, _)| v.to_string());
        assert_eq!(take("1.6.1").as_deref(), Some("1.6.1"));
        assert_eq!(
            take("1.7.0-rc.1").as_deref(),
            Some("1.7.0-rc.1"),
            "the rc feed's"
        );
        assert_eq!(take("1.6.0"), None, "not the same");
        assert_eq!(take("1.5.9"), None, "never back");
        assert_eq!(take("2.0.0"), None, "never a new major on its own");
        assert_eq!(take("nonsense"), None);
        assert!(
            pick(&feed("1.6.1", false), &ours, &[]).is_none(),
            "no relay build in it"
        );
        assert!(
            pick(&feed("1.6.1", true), &ours, &["1.6.1".into()]).is_none(),
            "failed here before"
        );
        // An rc relay moves on to its final
        let rc = Version::parse("1.7.0-rc.2").unwrap();
        assert!(pick(&feed("1.7.0", true), &rc, &[]).is_some());
        assert!(pick(&feed("1.7.0-rc.1", true), &rc, &[]).is_none());
    }

    fn temp_paths(name: &str) -> (Paths, PathBuf) {
        let dir = std::env::temp_dir().join(format!("voipc-update-{name}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        (Paths::of(dir.join("voipc-server")), dir)
    }

    #[test]
    fn the_marker_tells_a_first_start_from_a_failed_one() {
        let (paths, dir) = temp_paths("marker");
        assert_eq!(read_marker(&paths), Marker::None);
        std::fs::write(&paths.updating, "1.6.1").unwrap();
        assert_eq!(read_marker(&paths), Marker::First("1.6.1".into()));
        std::fs::write(&paths.updating, "1.6.1 started").unwrap();
        assert_eq!(read_marker(&paths), Marker::Failed("1.6.1".into()));
        std::fs::remove_dir_all(dir).unwrap();
    }

    #[test]
    fn a_roll_back_restores_the_previous_binary_and_skips_the_version() {
        let (paths, dir) = temp_paths("rollback");
        std::fs::write(&paths.exe, "new").unwrap();
        std::fs::write(&paths.previous, "old").unwrap();
        std::fs::write(&paths.updating, "1.6.1 started").unwrap();
        roll_back(&paths, "1.6.1").unwrap();
        assert_eq!(std::fs::read_to_string(&paths.exe).unwrap(), "old");
        assert!(!paths.previous.exists() && !paths.updating.exists());
        assert_eq!(paths.failed_versions(), ["1.6.1"]);
        paths.mark_failed("1.6.2");
        assert_eq!(paths.failed_versions(), ["1.6.1", "1.6.2"]);
        std::fs::remove_dir_all(dir).unwrap();
    }

    /// A copy of `version`, this many days old.
    fn copy_aged(paths: &Paths, version: &str, days: u64) {
        let p = paths.backup(version);
        std::fs::write(&p, "db").unwrap();
        let at = std::time::SystemTime::now() - Duration::from_secs(days * 86_400);
        std::fs::File::options()
            .write(true)
            .open(&p)
            .unwrap()
            .set_modified(at)
            .unwrap();
    }

    #[test]
    fn two_backups_stay() {
        let (paths, dir) = temp_paths("prune");
        for (i, v) in ["1.6.1", "1.6.2", "1.6.3"].iter().enumerate() {
            copy_aged(&paths, v, 3 - i as u64);
        }
        std::fs::write(&paths.exe, "bin").unwrap();
        prune_backups(&paths);
        assert!(!paths.backup("1.6.1").exists());
        assert!(paths.backup("1.6.2").exists() && paths.backup("1.6.3").exists());
        assert!(paths.exe.exists(), "nothing else goes");
        std::fs::remove_dir_all(dir).unwrap();
    }

    #[test]
    fn a_copy_past_thirty_days_goes_and_the_newest_stays_whatever_its_age() {
        let (paths, dir) = temp_paths("prune-aged");
        copy_aged(&paths, "1.6.1", 90);
        copy_aged(&paths, "1.6.2", 31);
        prune_backups(&paths);
        assert!(!paths.backup("1.6.1").exists());
        assert!(paths.backup("1.6.2").exists(), "the only way back");
        // Under the age, the second stays with the newest
        copy_aged(&paths, "1.6.3", 29);
        copy_aged(&paths, "1.6.4", 1);
        prune_backups(&paths);
        assert!(!paths.backup("1.6.2").exists());
        assert!(paths.backup("1.6.3").exists() && paths.backup("1.6.4").exists());
        std::fs::remove_dir_all(dir).unwrap();
    }

    #[tokio::test]
    async fn the_preflight_runs_the_new_binary() {
        let (paths, dir) = temp_paths("preflight");
        let fake = |said: &str| {
            write_executable(
                &paths.download,
                format!("#!/bin/sh\necho '{said}'\n").as_bytes(),
            )
            .unwrap();
        };
        fake("voipc-server 1.6.1");
        preflight(&paths.download, "1.6.1").await.unwrap();
        fake("voipc-server 1.6.0");
        assert!(preflight(&paths.download, "1.6.1").await.is_err());
        std::fs::remove_dir_all(dir).unwrap();
    }
}
