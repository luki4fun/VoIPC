//! Files the server writes for itself: whole or not at all, and those with
//! secrets in them (password hashes, a game token, a database copy)
//! readable by this user only.

use std::io::Write;
use std::path::{Path, PathBuf};

/// `bytes` to `path` through a new temporary file next to it — never one
/// that is there already, so a link planted under that name is not followed —
/// synced, then renamed over `path`. `secret`: mode 0600.
pub fn atomic_write(path: &Path, bytes: &[u8], secret: bool) -> std::io::Result<()> {
    let tmp = PathBuf::from(format!("{}.{:08x}.tmp", path.display(), rand::random::<u32>()));
    let mut o = std::fs::OpenOptions::new();
    o.write(true).create_new(true);
    #[cfg(unix)]
    if secret {
        std::os::unix::fs::OpenOptionsExt::mode(&mut o, 0o600);
    }
    #[cfg(not(unix))]
    let _ = secret;
    let r = o.open(&tmp).and_then(|mut f| {
        f.write_all(bytes)?;
        f.sync_all()?;
        std::fs::rename(&tmp, path)
    });
    if r.is_err() {
        let _ = std::fs::remove_file(&tmp);
    }
    r
}

/// Readable and writable by this user only (a no-op off Unix).
pub fn owner_only(path: &Path) -> std::io::Result<()> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600))
    }
    #[cfg(not(unix))]
    {
        let _ = path;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_secret_file_is_written_whole_for_its_owner_only() {
        let dir = std::env::temp_dir().join(format!("voipc-fsutil-{:08x}", rand::random::<u32>()));
        std::fs::create_dir(&dir).unwrap();
        let path = dir.join("s.json");
        std::fs::write(&path, b"old").unwrap();
        atomic_write(&path, b"new", true).unwrap();
        assert_eq!(std::fs::read(&path).unwrap(), b"new");
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            assert_eq!(std::fs::metadata(&path).unwrap().permissions().mode() & 0o777, 0o600);
        }
        assert_eq!(std::fs::read_dir(&dir).unwrap().count(), 1, "no temporary file left behind");
        std::fs::remove_dir_all(&dir).unwrap();
    }
}
