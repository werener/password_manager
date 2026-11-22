use std::fs;
use std::io::Write;
use std::path::{Path, PathBuf};

#[cfg(unix)]
use std::os::unix::fs::PermissionsExt;

use crate::error::{ClientError, ClientResult};

pub struct FileLock {
    _lock: Box<fd_lock::RwLock<fs::File>>,
    _guard: fd_lock::RwLockWriteGuard<'static, fs::File>,
}

pub fn lock_path_for(path: &Path) -> PathBuf {
    path.with_extension(match path.extension().and_then(|e| e.to_str()) {
        Some(ext) => format!("{ext}.lock"),
        None => "lock".to_string(),
    })
}

pub fn lock_exclusive(path: &Path) -> ClientResult<FileLock> {
    let lock_path = lock_path_for(path);
    if let Some(parent) = lock_path.parent() {
        ensure_dir(parent)?;
    }
    let file = fs::OpenOptions::new()
        .create(true)
        .read(true)
        .write(true)
        .open(&lock_path)
        .map_err(|source| ClientError::Io {
            path: lock_path.clone(),
            source,
        })?;
    let mut lock = Box::new(fd_lock::RwLock::new(file));
    let guard = lock.write().map_err(|e| ClientError::Io {
        path: lock_path,
        source: std::io::Error::other(e.to_string()),
    })?;
    // SAFETY: guard borrows data owned by `lock`; `lock` is kept boxed in FileLock
    // and dropped after `_guard` due to field order.
    let guard: fd_lock::RwLockWriteGuard<'static, fs::File> = unsafe { std::mem::transmute(guard) };
    Ok(FileLock {
        _lock: lock,
        _guard: guard,
    })
}

pub fn ensure_dir(path: &Path) -> ClientResult<()> {
    fs::create_dir_all(path).map_err(|source| ClientError::Io {
        path: path.to_path_buf(),
        source,
    })?;
    #[cfg(unix)]
    fs::set_permissions(path, fs::Permissions::from_mode(0o700)).map_err(|source| {
        ClientError::Io {
            path: path.to_path_buf(),
            source,
        }
    })?;
    Ok(())
}

pub fn write_atomic(
    path: &Path,
    contents: &[u8],
    #[allow(unused_variables)] mode: u32,
) -> ClientResult<()> {
    let parent = path
        .parent()
        .ok_or_else(|| ClientError::Config("invalid path: no parent".into()))?;
    ensure_dir(parent)?;

    let name = path.file_name().and_then(|n| n.to_str()).unwrap_or("file");
    let tmp = parent.join(format!(
        ".{name}.tmp-{}-{}",
        std::process::id(),
        uuid::Uuid::new_v4()
    ));
    {
        let mut file = fs::File::create(&tmp).map_err(|source| ClientError::Io {
            path: tmp.clone(),
            source,
        })?;
        file.write_all(contents).map_err(|source| ClientError::Io {
            path: tmp.clone(),
            source,
        })?;
        file.sync_all().map_err(|source| ClientError::Io {
            path: tmp.clone(),
            source,
        })?;
    }
    #[cfg(unix)]
    fs::set_permissions(&tmp, fs::Permissions::from_mode(mode)).map_err(|source| {
        ClientError::Io {
            path: tmp.clone(),
            source,
        }
    })?;
    fs::rename(&tmp, path).map_err(|source| ClientError::Io {
        path: path.to_path_buf(),
        source,
    })?;
    Ok(())
}

pub fn read_to_string(path: &Path) -> ClientResult<Option<String>> {
    if !path.exists() {
        return Ok(None);
    }
    fs::read_to_string(path)
        .map(Some)
        .map_err(|source| ClientError::Io {
            path: path.to_path_buf(),
            source,
        })
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::Duration;

    #[test]
    fn lock_exclusive_blocks_until_released() {
        let dir = std::env::temp_dir().join(format!("pm-lock-{}", uuid::Uuid::new_v4()));
        fs::create_dir_all(&dir).unwrap();
        let path = dir.join("session.json");
        fs::write(&path, "{}").unwrap();

        let lock = lock_exclusive(&path).unwrap();
        let path2 = path.clone();
        let handle = std::thread::spawn(move || lock_exclusive(&path2).is_ok());
        std::thread::sleep(Duration::from_millis(100));
        assert!(
            !handle.is_finished(),
            "second lock should block while first is held"
        );
        drop(lock);
        assert!(
            handle.join().unwrap(),
            "second lock should succeed after release"
        );
    }
}
