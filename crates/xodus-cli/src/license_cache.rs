//! Device-bound offline license cache for installed games.
//!
//! Microsoft grants offline play only to the account's designated offline
//! device: the content license then arrives with a device-bound *lease* whose
//! policy says `isOffline` and carries an expiry (30 days, renewed on every
//! online launch). This cache stores the encrypted SPLicense block for exactly
//! that case and for no longer than the lease allows. The block's content keys
//! stay wrapped by the device key in the system keyring, so the file alone
//! decrypts nothing; entries are bound to one account and are purged whenever
//! Microsoft refuses the content while online.
use std::fs;
use std::path::{Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};

use serde_json::{Value, json};
use xodus::models::devicecredential::License;

const SCHEMA: u64 = 2;
const MAX_FILE_BYTES: u64 = 64 * 1024;
const MAX_BLOCK_CHARS: usize = 48 * 1024;
/// Upper bound on offline use after the last successful online license check,
/// independent of the lease's own expiry.
pub const MAX_OFFLINE_SECONDS: u64 = 30 * 24 * 60 * 60;

pub fn diagnostic(stage: &'static str) {
    eprintln!("NEXUS_CONTENT_LICENSE_DIAGNOSTIC_V1 {stage} 0");
}

pub fn unix_now() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|elapsed| elapsed.as_secs())
        .unwrap_or(0)
}

/// Offline validity: the lease expiry, never more than the fixed offline
/// window after `now`.
pub fn offline_expiry(lease_expires_at: u64, now: u64) -> u64 {
    now.saturating_add(MAX_OFFLINE_SECONDS).min(lease_expires_at)
}

#[derive(Debug, PartialEq, Eq)]
pub enum Stored {
    Saved,
    /// Microsoft attached no offline lease (this is not the account's
    /// designated offline device); nothing is kept.
    OnlineOnly,
}

pub struct CachedLicense {
    pub splicense_block: String,
    pub expires_at: u64,
}

pub struct LicenseCache {
    root: PathBuf,
}

impl LicenseCache {
    pub fn new(root: &Path) -> Self {
        Self {
            root: root.to_path_buf(),
        }
    }

    fn entry_path(&self, content_id: &str) -> Result<PathBuf, String> {
        let valid = !content_id.is_empty()
            && content_id.len() <= 64
            && content_id
                .bytes()
                .all(|byte| byte.is_ascii_alphanumeric() || byte == b'-');
        if !valid {
            return Err(
                "The content identifier is not valid for the offline license cache.".to_string(),
            );
        }
        Ok(self
            .root
            .join(format!("{}.json", content_id.to_ascii_lowercase())))
    }

    fn ensure_root(&self) -> std::io::Result<()> {
        let mut builder = fs::DirBuilder::new();
        builder.recursive(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::DirBuilderExt;
            builder.mode(0o700);
        }
        builder.create(&self.root)
    }

    /// Records a license Microsoft just issued. `offline_lease_expires_at` is
    /// the expiry of the offline lease that came with it; without one nothing
    /// is kept and any earlier entry for the same content is removed.
    pub fn store(
        &self,
        content_id: &str,
        puid: &str,
        market: &str,
        license: &License,
        offline_lease_expires_at: Option<u64>,
        now: u64,
    ) -> Result<Stored, String> {
        let path = self.entry_path(content_id)?;
        let Some(lease_expires_at) = offline_lease_expires_at else {
            remove_quietly(&path);
            return Ok(Stored::OnlineOnly);
        };
        if license.splicense_block.is_empty() || license.splicense_block.len() > MAX_BLOCK_CHARS {
            return Err("The content license block is not cacheable.".to_string());
        }
        let expires_at = offline_expiry(lease_expires_at, now);
        let entry = json!({
            "schema": SCHEMA,
            "contentId": content_id.to_ascii_lowercase(),
            "puid": puid,
            "market": market,
            "storedAt": now,
            "expiresAt": expires_at,
            "leaseExpiresAt": lease_expires_at,
            "bindingType": license.binding.binding_type,
            "splicenseBlock": license.splicense_block,
        });
        self.ensure_root().map_err(|_| cache_io_error())?;
        let temporary = path.with_extension("json.tmp");
        write_private(&temporary, entry.to_string().as_bytes()).map_err(|_| cache_io_error())?;
        if fs::rename(&temporary, &path).is_err() {
            remove_quietly(&temporary);
            return Err(cache_io_error());
        }
        Ok(Stored::Saved)
    }

    /// Returns a stored license for this account and content while it is still
    /// valid. Expired or unreadable entries are removed.
    pub fn load(
        &self,
        content_id: &str,
        puid: &str,
        now: u64,
    ) -> Result<Option<CachedLicense>, String> {
        let path = self.entry_path(content_id)?;
        let metadata = match fs::metadata(&path) {
            Ok(metadata) => metadata,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
                diagnostic("content-cache-missing");
                return Ok(None);
            }
            Err(_) => return Err(cache_io_error()),
        };
        if !metadata.is_file() || metadata.len() > MAX_FILE_BYTES {
            return Self::invalid(&path);
        }
        let bytes = fs::read(&path).map_err(|_| cache_io_error())?;
        let Ok(value) = serde_json::from_slice::<Value>(&bytes) else {
            return Self::invalid(&path);
        };
        let expected_content = content_id.to_ascii_lowercase();
        let same_content =
            value.get("contentId").and_then(Value::as_str) == Some(expected_content.as_str());
        let block = value.get("splicenseBlock").and_then(Value::as_str);
        let expires_at = value.get("expiresAt").and_then(Value::as_u64);
        let (Some(block), Some(expires_at)) = (block, expires_at) else {
            return Self::invalid(&path);
        };
        if value.get("schema").and_then(Value::as_u64) != Some(SCHEMA)
            || !same_content
            || block.is_empty()
            || block.len() > MAX_BLOCK_CHARS
        {
            return Self::invalid(&path);
        }
        if value.get("puid").and_then(Value::as_str) != Some(puid) {
            // Another account's entry on this device is neither usable nor ours to remove.
            diagnostic("content-cache-missing");
            return Ok(None);
        }
        if expires_at <= now {
            remove_quietly(&path);
            diagnostic("content-cache-expired");
            return Ok(None);
        }
        Ok(Some(CachedLicense {
            splicense_block: block.to_string(),
            expires_at,
        }))
    }

    /// Removes the entry after Microsoft refused the content while online.
    pub fn purge(&self, content_id: &str) -> Result<bool, String> {
        let path = self.entry_path(content_id)?;
        match fs::remove_file(&path) {
            Ok(()) => Ok(true),
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(false),
            Err(_) => Err(cache_io_error()),
        }
    }

    fn invalid(path: &Path) -> Result<Option<CachedLicense>, String> {
        remove_quietly(path);
        diagnostic("content-cache-invalid");
        Ok(None)
    }
}

fn cache_io_error() -> String {
    "The offline license cache could not be accessed.".to_string()
}

fn remove_quietly(path: &Path) {
    let _ = fs::remove_file(path);
}

fn write_private(path: &Path, bytes: &[u8]) -> std::io::Result<()> {
    use std::io::Write;
    let mut options = fs::OpenOptions::new();
    options.write(true).create(true).truncate(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600);
    }
    let mut file = options.open(path)?;
    file.write_all(bytes)?;
    file.sync_all()
}

#[cfg(test)]
#[path = "license_cache_tests.rs"]
mod tests;
