//! What this device keeps of the group key (plan 3d): `gk_local.bin` in the data directory,
//! per relay and account. Each group's floor (and the keyholder header it names), the
//! keyholder's own pair and the seats it sealed that no header named yet, and a guest's
//! highest counters seen. A floor that is lost lets a relay that kept an old backup take this
//! device back to it; one that survives a restart does not.
//!
//! Not encrypted at rest (owner, open choice 10): readable by this user only (`write_atomic`
//! makes it 0600, the directory is 0700), as `settings.json` is.

use std::collections::BTreeMap;
use std::path::PathBuf;
use std::sync::{Mutex, PoisonError};

use serde::{Deserialize, Serialize};
use voipc_crypto::group_state::LocalGk;

/// Whose it is: the relay (its id in hex for an account signed in there, else the
/// `host:port` connected to) and the account, `None` for a guest. One keyholder pair per
/// relay and account.
pub type Scope = (String, Option<[u8; 16]>);

const FILE: &str = "gk_local.bin";
const VERSION: u32 = 1;

#[derive(Default, Serialize, Deserialize)]
struct GkFile {
    version: u32,
    relays: BTreeMap<Scope, LocalGk>,
}

/// The file as this run has it.
struct Loaded {
    file: GkFile,
    /// A file a newer VoIPC wrote is read as empty and never written over.
    writable: bool,
}

/// `gk_local.bin`, read at its first use, written whole at every save (every connection of
/// the app shares it, each under its own scope).
pub struct Store {
    /// `None`: the data directory's, resolved at first use (Android sets it in `setup`).
    path: Option<PathBuf>,
    loaded: Mutex<Option<Loaded>>,
}

impl Store {
    pub fn new(path: Option<PathBuf>) -> Store {
        Store {
            path,
            loaded: Mutex::new(None),
        }
    }

    fn path(&self) -> PathBuf {
        self.path
            .clone()
            .unwrap_or_else(|| crate::config::data_dir().join(FILE))
    }

    fn with<T>(&self, f: impl FnOnce(&mut Loaded, &std::path::Path) -> T) -> T {
        let path = self.path();
        let mut loaded = self.loaded.lock().unwrap_or_else(PoisonError::into_inner);
        let loaded = loaded.get_or_insert_with(|| read(&path));
        f(loaded, &path)
    }

    /// What this device kept for `scope`.
    pub fn load(&self, scope: &Scope) -> Option<LocalGk> {
        self.with(|l, _| l.file.relays.get(scope).cloned())
    }

    /// Keeps what `snapshot` takes, if it takes anything. It is taken under the file's lock
    /// and written before that is let go: a save asked while another is being written waits
    /// for it, so one that finds nothing left to take knows the last snapshot is on disk
    /// (3c: nothing goes out under a head before its floor is), and snapshots are written in
    /// the order they were taken, across every connection.
    pub fn save(&self, snapshot: impl FnOnce() -> Option<(Scope, LocalGk)>) -> Result<(), String> {
        self.with(|l, path| {
            let Some((scope, local)) = snapshot() else {
                return Ok(());
            };
            if !l.writable {
                return Ok(());
            }
            l.file.relays.insert(scope, local);
            let bytes = postcard::to_allocvec(&l.file).map_err(|e| e.to_string())?;
            crate::config::write_atomic(path, &bytes)
                .map_err(|e| format!("could not write {}: {e}", path.display()))
        })
    }
}

/// The file, or none: one that does not read is kept aside and started anew.
fn read(path: &std::path::Path) -> Loaded {
    let mut loaded = Loaded {
        file: GkFile {
            version: VERSION,
            relays: BTreeMap::new(),
        },
        writable: true,
    };
    let Ok(bytes) = std::fs::read(path) else {
        return loaded;
    };
    match postcard::from_bytes::<GkFile>(&bytes) {
        Ok(file) if file.version > VERSION => {
            tracing::warn!("{} was written by a newer VoIPC: not used", path.display());
            loaded.writable = false;
        }
        Ok(file) => loaded.file = file,
        Err(e) => {
            let secs = voipc_crypto::time::now_millis() / 1000;
            let aside = path.with_file_name(format!("{FILE}.unreadable-{secs}"));
            let kept = std::fs::rename(path, &aside);
            tracing::warn!(
                "{} does not read ({e}): started anew, the file is kept as {} ({kept:?})",
                path.display(),
                aside.display()
            );
        }
    }
    loaded
}

#[cfg(test)]
mod tests {
    use super::*;
    use voipc_crypto::group_key::{Floor, NamesFloor, Seen};
    use voipc_crypto::group_state::LocalFloor;

    fn dir(name: &str) -> PathBuf {
        let dir =
            std::env::temp_dir().join(format!("voipc-gk-local-{name}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        dir
    }

    fn floor(epoch: u32) -> LocalFloor {
        LocalFloor {
            floor: Floor {
                gen: [3; 16],
                gen_time: 1_700_000_000,
                epoch,
                join: 2,
                d: [4; 32],
                d_e: [5; 32],
                kh: [6; 32],
                time: 1_700_000_100,
                gated: false,
                gens: vec![([3; 16], 1_700_000_000)],
            },
            kh: Some((vec![1, 2, 3], vec![4; 64])),
            head: None,
            names: Some(NamesFloor {
                gen: [3; 16],
                epoch,
                join: 2,
                names_hash: [7; 32],
                time: 1_700_000_100,
            }),
            taken: 1_700_000_200,
        }
    }

    fn local(epoch: u32) -> LocalGk {
        let mut l = LocalGk::default();
        l.floors.insert("c:42".into(), floor(epoch));
        l.counters.raise(
            [9; 16],
            Seen {
                n: 4,
                made: 1_700_000_000,
            },
            true,
        );
        l
    }

    #[test]
    fn floors_survive_a_reload_of_the_app() {
        let path = dir("reload").join(FILE);
        let scope: Scope = ("aa".repeat(16), Some([1; 16]));
        Store::new(Some(path.clone()))
            .save(|| Some((scope.clone(), local(7))))
            .unwrap();
        let again = Store::new(Some(path.clone())).load(&scope).expect("kept");
        assert_eq!(again.floors.get("c:42"), Some(&floor(7)));
        assert_eq!(again.counters, local(7).counters);
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let mode = std::fs::metadata(&path).unwrap().permissions().mode();
            assert_eq!(mode & 0o777, 0o600, "readable by this user only");
        }
    }

    #[test]
    fn each_relay_and_account_keeps_its_own() {
        let path = dir("scopes").join(FILE);
        let store = Store::new(Some(path.clone()));
        let a: Scope = ("aa".repeat(16), Some([1; 16]));
        let other_relay: Scope = ("bb".repeat(16), Some([1; 16]));
        let guest: Scope = ("example.org:9987".into(), None);
        store.save(|| Some((a.clone(), local(9)))).unwrap();
        store.save(|| Some((guest.clone(), local(5)))).unwrap();
        store.save(|| None).unwrap();
        let again = Store::new(Some(path));
        assert_eq!(again.load(&a).unwrap().floors["c:42"], floor(9));
        assert_eq!(again.load(&guest).unwrap().floors["c:42"], floor(5));
        assert!(again.load(&other_relay).is_none());
    }

    #[test]
    fn a_save_asked_while_another_is_written_waits_until_that_one_is_on_disk() {
        use std::sync::{mpsc, Arc};
        use std::time::Duration;
        let path = dir("waits").join(FILE);
        let store = Arc::new(Store::new(Some(path.clone())));
        let scope: Scope = ("aa".repeat(16), None);
        let (taking, taken) = mpsc::channel();
        let (go, wait) = mpsc::channel::<()>();
        // One task's save is taking its snapshot (the floor it marked unsaved)
        let first = {
            let (store, scope) = (store.clone(), scope.clone());
            std::thread::spawn(move || {
                store.save(|| {
                    taking.send(()).unwrap();
                    wait.recv().unwrap();
                    Some((scope, local(7)))
                })
            })
        };
        taken.recv().unwrap();
        // Another task is about to send under that head: it finds nothing left to save, and
        // must not go on before the first save is on disk
        let (seen, saw) = mpsc::channel();
        let second = {
            let (store, path, scope) = (store.clone(), path.clone(), scope.clone());
            std::thread::spawn(move || {
                store.save(|| {
                    seen.send(Store::new(Some(path)).load(&scope)).unwrap();
                    None
                })
            })
        };
        assert!(
            saw.recv_timeout(Duration::from_millis(200)).is_err(),
            "the second save waits for the first"
        );
        go.send(()).unwrap();
        first.join().unwrap().unwrap();
        second.join().unwrap().unwrap();
        let on_disk = saw.recv().unwrap().expect("the first save was written");
        assert_eq!(on_disk.floors["c:42"], floor(7));
    }

    #[test]
    fn a_file_a_newer_voipc_wrote_is_neither_read_nor_written_over() {
        let path = dir("newer").join(FILE);
        let scope: Scope = ("aa".repeat(16), None);
        let mut newer = GkFile {
            version: VERSION + 1,
            relays: BTreeMap::new(),
        };
        newer.relays.insert(scope.clone(), local(1));
        let bytes = postcard::to_allocvec(&newer).unwrap();
        std::fs::write(&path, &bytes).unwrap();
        let store = Store::new(Some(path.clone()));
        assert!(store.load(&scope).is_none());
        store.save(|| Some((scope.clone(), local(2)))).unwrap();
        assert_eq!(std::fs::read(&path).unwrap(), bytes);
    }

    #[test]
    fn a_file_that_does_not_read_is_kept_aside_and_started_anew() {
        let dir = dir("unreadable");
        let path = dir.join(FILE);
        std::fs::write(&path, b"\xff\xff\xff\xff\xff\xff not postcard").unwrap();
        let store = Store::new(Some(path.clone()));
        let scope: Scope = ("aa".repeat(16), None);
        assert!(store.load(&scope).is_none());
        store.save(|| Some((scope.clone(), local(2)))).unwrap();
        assert!(Store::new(Some(path)).load(&scope).is_some());
        let aside = std::fs::read_dir(&dir)
            .unwrap()
            .filter_map(|e| e.ok())
            .any(|e| e.file_name().to_string_lossy().contains("unreadable-"));
        assert!(aside, "the old file is kept beside it");
    }
}
