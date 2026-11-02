//! Synthetic license metadata only. No account, keyring, network or game files.
use super::*;
use xodus::models::devicecredential::{Binding, LicenseInfo, LicenseType, LicenseUsage};

const DAY: u64 = 24 * 60 * 60;
const NOW: u64 = 1_800_000_000;

fn license(block: &str) -> License {
    License {
        splicense_block: block.to_string(),
        license_info: LicenseInfo {
            license_type: LicenseType::Full,
            license_usage: Some(LicenseUsage::Online),
            license_category: Some("Retail".to_string()),
            issued_date: None,
            last_updated_date: None,
            begin_date: None,
            expiration_date: None,
        },
        custom_policies: None,
        binding: Binding {
            binding_type: "Machine".to_string(),
            device_id: Some("synthetic-device".to_string()),
            product_id: None,
            pfm: None,
            user_id: None,
            usid: None,
            lease_required: Some("True".to_string()),
            lease_renewal_period: None,
            associated_pfns: None,
        },
    }
}

#[test]
fn offline_license_expiry_is_the_lease_expiry_capped_by_the_offline_window() {
    assert_eq!(offline_expiry(NOW + 3 * DAY, NOW), NOW + 3 * DAY);
    assert_eq!(offline_expiry(NOW + 400 * DAY, NOW), NOW + 30 * DAY);
    // A lease that already expired yields an entry that never validates.
    assert!(offline_expiry(NOW - 1, NOW) <= NOW);
}

#[test]
fn offline_license_roundtrip_is_bound_to_content_and_account() {
    let root = tempfile::tempdir().unwrap();
    let cache = LicenseCache::new(root.path());
    let block = "c3ludGhldGljLWJsb2Nr";
    let stored = cache
        .store("ABCDEF01-2345", "puid-a", "US", &license(block), Some(NOW + 30 * DAY), NOW)
        .unwrap();
    assert_eq!(stored, Stored::Saved);
    let entry = cache.load("abcdef01-2345", "puid-a", NOW + DAY).unwrap().unwrap();
    assert_eq!(entry.splicense_block, block);
    assert_eq!(entry.expires_at, NOW + 30 * DAY);
    assert!(cache.load("abcdef01-2345", "puid-b", NOW + DAY).unwrap().is_none());
    assert!(cache.load("other-content", "puid-a", NOW + DAY).unwrap().is_none());
    // Another account's lookup must not destroy the owner's entry.
    assert!(cache.load("abcdef01-2345", "puid-a", NOW + DAY).unwrap().is_some());
    assert!(!root.path().join("abcdef01-2345.json.tmp").exists());
}

#[test]
fn offline_license_expires_and_is_removed_without_extending_the_lease() {
    let root = tempfile::tempdir().unwrap();
    let cache = LicenseCache::new(root.path());
    cache
        .store("content-1", "puid", "US", &license("YmxvY2s="), Some(NOW + 2 * DAY), NOW)
        .unwrap();
    assert!(cache.load("content-1", "puid", NOW + 2 * DAY - 1).unwrap().is_some());
    assert!(cache.load("content-1", "puid", NOW + 2 * DAY).unwrap().is_none());
    assert!(!root.path().join("content-1.json").exists());
    assert!(cache.load("content-1", "puid", NOW).unwrap().is_none());
}

#[test]
fn offline_license_without_an_offline_lease_is_never_stored_and_purges_a_stale_entry() {
    let root = tempfile::tempdir().unwrap();
    let cache = LicenseCache::new(root.path());
    cache
        .store("content-2", "puid", "US", &license("YmxvY2s="), Some(NOW + 30 * DAY), NOW)
        .unwrap();
    assert!(root.path().join("content-2.json").exists());
    let stored = cache
        .store("content-2", "puid", "US", &license("YmxvY2s="), None, NOW)
        .unwrap();
    assert_eq!(stored, Stored::OnlineOnly);
    assert!(!root.path().join("content-2.json").exists());
    assert!(cache.load("content-2", "puid", NOW).unwrap().is_none());
    assert!(cache
        .store("content-3", "puid", "US", &license(""), Some(NOW + DAY), NOW)
        .is_err());
    assert!(!root.path().join("content-3.json").exists());
}

#[test]
fn offline_license_purge_reports_whether_an_entry_existed() {
    let root = tempfile::tempdir().unwrap();
    let cache = LicenseCache::new(root.path());
    assert!(!cache.purge("content-4").unwrap());
    cache
        .store("content-4", "puid", "US", &license("YmxvY2s="), Some(NOW + DAY), NOW)
        .unwrap();
    assert!(cache.purge("content-4").unwrap());
    assert!(!cache.purge("content-4").unwrap());
    assert!(cache.load("content-4", "puid", NOW).unwrap().is_none());
}

#[test]
fn offline_license_rejects_unsafe_identifiers_and_malformed_entries() {
    let root = tempfile::tempdir().unwrap();
    let cache = LicenseCache::new(root.path());
    let too_long = "x".repeat(65);
    for bad in ["", "../escape", "a/b", "a\\b", "with space", too_long.as_str()] {
        assert!(cache.store(bad, "puid", "US", &license("YmxvY2s="), Some(NOW + DAY), NOW).is_err());
        assert!(cache.load(bad, "puid", NOW).is_err());
        assert!(cache.purge(bad).is_err());
    }
    assert!(!root.path().join("escape.json").exists());
    std::fs::create_dir_all(root.path()).unwrap();
    let corrupt = root.path().join("content-5.json");
    std::fs::write(&corrupt, b"{ not json").unwrap();
    assert!(cache.load("content-5", "puid", NOW).unwrap().is_none());
    assert!(!corrupt.exists());
    let old_schema = json!({
        "schema": 1, "contentId": "content-6", "puid": "puid", "expiresAt": NOW + DAY, "splicenseBlock": "YmxvY2s=",
    });
    std::fs::write(root.path().join("content-6.json"), old_schema.to_string()).unwrap();
    assert!(cache.load("content-6", "puid", NOW).unwrap().is_none());
    assert!(!root.path().join("content-6.json").exists());
    let mismatched = json!({
        "schema": 2, "contentId": "other", "puid": "puid", "expiresAt": NOW + DAY, "splicenseBlock": "YmxvY2s=",
    });
    std::fs::write(root.path().join("content-7.json"), mismatched.to_string()).unwrap();
    assert!(cache.load("content-7", "puid", NOW).unwrap().is_none());
    std::fs::write(root.path().join("content-8.json"), vec![b'0'; (MAX_FILE_BYTES + 1) as usize]).unwrap();
    assert!(cache.load("content-8", "puid", NOW).unwrap().is_none());
    assert!(!root.path().join("content-8.json").exists());
}

#[cfg(unix)]
#[test]
fn offline_license_files_are_private_to_the_user() {
    use std::os::unix::fs::PermissionsExt;
    let root = tempfile::tempdir().unwrap();
    let nested = root.path().join("license-cache");
    let cache = LicenseCache::new(&nested);
    cache
        .store("content-9", "puid", "US", &license("YmxvY2s="), Some(NOW + DAY), NOW)
        .unwrap();
    assert_eq!(std::fs::metadata(&nested).unwrap().permissions().mode() & 0o777, 0o700);
    assert_eq!(
        std::fs::metadata(nested.join("content-9.json")).unwrap().permissions().mode() & 0o777,
        0o600
    );
}
