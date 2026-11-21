use std::fs;
use std::io::Write;
use std::path::Path;

#[cfg(unix)]
use std::os::unix::fs::PermissionsExt;

use crate::error::{ClientError, ClientResult};

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

    let tmp = parent.join(format!(
        ".{}.tmp-{}",
        path.file_name().and_then(|n| n.to_str()).unwrap_or("file"),
        std::process::id()
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
