//! Synthetic license metadata only. No account, keyring, network or game files.
use super::*;
use base64::{Engine, prelude::BASE64_STANDARD};
use xodus::models::devicecredential::{Binding, LicenseInfo, LicenseUsage};

pub(crate) const DAY: u64 = 24 * 60 * 60;
pub(crate) const NOW: u64 = 1_800_000_000;
pub(crate) const BLOCK: &str = "c3ludGhldGljLWJsb2Nr";

pub(crate) fn rfc3339(seconds: u64) -> String {
    chrono::DateTime::from_timestamp(seconds as i64, 0).unwrap().to_rfc3339()
}

/// A key license as Microsoft issues it: Machine-bound with a required lease
/// on the designated offline device, User-bound elsewhere.
pub(crate) fn key(binding: &str, block: &str) -> License {
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
            binding_type: binding.to_string(),
            device_id: (binding == "Machine").then(|| "synthetic-device".to_string()),
            product_id: None,
            pfm: None,
            user_id: None,
            usid: None,
            lease_required: (binding == "Machine").then(|| "True".to_string()),
            lease_renewal_period: None,
            associated_pfns: None,
        },
    }
}

/// A lease document (base64 XML) shaped like Microsoft's, with the given
/// `CustomPolicies` JSON.
pub(crate) fn lease_with(policy: &str, device: &str, expiration: Option<u64>) -> String {
    let expiration = expiration
        .map(|at| format!("<ExpirationDate>{}</ExpirationDate>", rfc3339(at)))
        .unwrap_or_default();
    BASE64_STANDARD.encode(format!(
        "<License><SPLicenseBlock>synthetic-lease</SPLicenseBlock><LicenseInfo Type=\"Lease\" LicenseUsage=\"Online\">{expiration}</LicenseInfo><CustomPolicies>{}</CustomPolicies><Binding Binding_Type=\"Machine\"><DeviceId>{device}</DeviceId><LeaseRequired>True</LeaseRequired><LeaseRenewalPeriod>2880</LeaseRenewalPeriod></Binding></License>",
        BASE64_STANDARD.encode(policy)
    ))
}

/// The designated device's offline lease, expiring at `expires`.
pub(crate) fn offline_lease(expires: u64) -> String {
    lease_with(
        &format!(
            "{{\"isOffline\":true,\"expiresAt\":\"{}\",\"pollAt\":\"{}\",\"leaseEnforcement\":\"EnforceConcurrency\"}}",
            rfc3339(expires),
            rfc3339(expires.saturating_sub(28 * DAY))
        ),
        "synthetic-device",
        Some(expires),
    )
}

pub(crate) fn holder(puid: &str, device: &str) -> Holder {
    Holder { puid: puid.to_string(), device_id: device.to_string() }
}

fn usable(cache: &LicenseCache, content: &str, who: &Holder, now: u64) -> Result<CachedLicense, Unusable> {
    cache.load(content, who, now).unwrap()
}

#[test]
fn lease_restrictions_come_from_the_lease_microsoft_issued() {
    let machine = key("Machine", BLOCK);
    assert_eq!(check_lease(&offline_lease(NOW + 30 * DAY), &machine, NOW, NOW), LeaseCheck::Valid(NOW + 30 * DAY));
    // Never beyond the offline window after issue, whatever the lease says.
    assert_eq!(check_lease(&offline_lease(NOW + 400 * DAY), &machine, NOW, NOW), LeaseCheck::Valid(NOW + 30 * DAY));
    // The lease's own expiration date bounds it as well.
    let short = lease_with(&format!("{{\"isOffline\":true,\"expiresAt\":\"{}\"}}", rfc3339(NOW + 20 * DAY)), "synthetic-device", Some(NOW + 5 * DAY));
    assert_eq!(check_lease(&short, &machine, NOW, NOW), LeaseCheck::Valid(NOW + 5 * DAY));
    assert_eq!(check_lease(&offline_lease(NOW + DAY), &machine, NOW, NOW + DAY), LeaseCheck::Expired);
    // Only an offline lease for a device-bound, lease-required key qualifies.
    let online = lease_with(&format!("{{\"isOffline\":false,\"expiresAt\":\"{}\"}}", rfc3339(NOW + DAY)), "synthetic-device", None);
    let no_expiry = lease_with("{\"isOffline\":true}", "synthetic-device", None);
    let other_device = lease_with(&format!("{{\"isOffline\":true,\"expiresAt\":\"{}\"}}", rfc3339(NOW + DAY)), "another-device", None);
    for document in [online, no_expiry, other_device, "not base64".to_string(), String::new(), "A".repeat(MAX_LEASE_CHARS + 1)] {
        assert!(matches!(check_lease(&document, &machine, NOW, NOW), LeaseCheck::Invalid(_)));
    }
    assert!(matches!(check_lease(&offline_lease(NOW + DAY), &key("User", BLOCK), NOW, NOW), LeaseCheck::Invalid(_)));
    let mut not_required = machine.clone();
    not_required.binding.lease_required = Some("False".to_string());
    assert!(matches!(check_lease(&offline_lease(NOW + DAY), &not_required, NOW, NOW), LeaseCheck::Invalid(_)));
    // A key license document is not a lease.
    let key_document = BASE64_STANDARD.encode("<License><SPLicenseBlock>x</SPLicenseBlock><LicenseInfo Type=\"Full\"/><Binding Binding_Type=\"Machine\"/></License>");
    assert!(matches!(check_lease(&key_document, &machine, NOW, NOW), LeaseCheck::Invalid(_)));
}

#[test]
fn lease_dates_are_read_in_the_formats_microsoft_uses() {
    let at = |text: &str| lease_time(text);
    assert_eq!(at("2026-11-25T21:40:54.4072339+00:00"), Some(1_795_642_854));
    assert_eq!(at("2026-11-25T21:40:54Z"), Some(1_795_642_854));
    // LicenseInfo's ExpirationDate on a real lease: UTC without an offset.
    assert_eq!(at("2026-11-25T21:40:54.4072339"), Some(1_795_642_854));
    assert_eq!(at(" 2026-11-25 21:40:54 "), Some(1_795_642_854));
    assert_eq!(at("11/25/2026 21:40:54"), Some(1_795_642_854));
    for bad in ["", "soon", "2026-13-40T99:00:00", "1795642854"] {
        assert_eq!(at(bad), None, "{bad}");
    }
    assert_eq!(date_shape("2026-11-25T21:40:54.4072339"), "9999-99-99T99:99:99.9999999");
    // A lease whose ExpirationDate has no offset is accepted and still bounds offline use.
    let naive = lease_with(&format!("{{\"isOffline\":true,\"expiresAt\":\"{}\"}}", rfc3339(NOW + 20 * DAY)), "synthetic-device", None);
    let document = BASE64_STANDARD.encode(
        String::from_utf8(BASE64_STANDARD.decode(&naive).unwrap()).unwrap().replace(
            "<LicenseInfo Type=\"Lease\" LicenseUsage=\"Online\">",
            &format!("<LicenseInfo Type=\"Lease\" LicenseUsage=\"Online\"><ExpirationDate>{}.0000000</ExpirationDate>",
                chrono::DateTime::from_timestamp((NOW + 5 * DAY) as i64, 0).unwrap().format("%Y-%m-%dT%H:%M:%S")),
        ),
    );
    assert_eq!(check_lease(&document, &key("Machine", BLOCK), NOW, NOW), LeaseCheck::Valid(NOW + 5 * DAY));
}

#[test]
fn offline_license_roundtrip_is_bound_to_content_account_and_device() {
    let root = tempfile::tempdir().unwrap();
    let cache = LicenseCache::new(root.path());
    let owner = holder("puid-a", "device-a");
    let stored = cache
        .store("ABCDEF01-2345", &owner, "US", &key("Machine", BLOCK), &[offline_lease(NOW + 30 * DAY)], NOW)
        .unwrap();
    assert_eq!(stored, Stored::Saved);
    let entry = usable(&cache, "abcdef01-2345", &owner, NOW + DAY).unwrap();
    assert_eq!(entry.splicense_block, BLOCK);
    assert_eq!(entry.expires_at, NOW + 30 * DAY);
    assert_eq!(usable(&cache, "other-content", &owner, NOW + DAY).err(), Some(Unusable::Missing));
    assert!(!root.path().join("abcdef01-2345.json.tmp").exists());
}

#[test]
fn expired_leases_are_refused_and_removed_whatever_the_local_file_claims() {
    let root = tempfile::tempdir().unwrap();
    let cache = LicenseCache::new(root.path());
    let owner = holder("puid", "device");
    cache.store("content-1", &owner, "US", &key("Machine", BLOCK), &[offline_lease(NOW + 2 * DAY)], NOW).unwrap();
    assert!(usable(&cache, "content-1", &owner, NOW + 2 * DAY - 1).is_ok());
    // Editing the fields Nexus wrote cannot extend the lease: expiry is read
    // from the lease document, and the issue time cannot move forward past
    // the recorded use.
    let path = root.path().join("content-1.json");
    let mut entry: Value = serde_json::from_slice(&std::fs::read(&path).unwrap()).unwrap();
    entry["expiresAt"] = json!(NOW + 365 * DAY);
    entry["issuedAt"] = json!(NOW + 300 * DAY);
    std::fs::write(&path, entry.to_string()).unwrap();
    assert_eq!(usable(&cache, "content-1", &owner, NOW + 2 * DAY).err(), Some(Unusable::Clock));
    entry["issuedAt"] = json!(NOW);
    std::fs::write(&path, entry.to_string()).unwrap();
    assert_eq!(usable(&cache, "content-1", &owner, NOW + 2 * DAY).err(), Some(Unusable::Expired));
    assert!(!path.exists());
    assert_eq!(usable(&cache, "content-1", &owner, NOW).err(), Some(Unusable::Missing));
}

#[test]
fn a_swapped_lease_document_is_validated_again() {
    let root = tempfile::tempdir().unwrap();
    let cache = LicenseCache::new(root.path());
    let owner = holder("puid", "device");
    cache.store("content-2", &owner, "US", &key("Machine", BLOCK), &[offline_lease(NOW + 30 * DAY)], NOW).unwrap();
    let path = root.path().join("content-2.json");
    let mut entry: Value = serde_json::from_slice(&std::fs::read(&path).unwrap()).unwrap();
    entry["lease"] = json!(lease_with(&format!("{{\"isOffline\":false,\"expiresAt\":\"{}\"}}", rfc3339(NOW + 30 * DAY)), "synthetic-device", None));
    std::fs::write(&path, entry.to_string()).unwrap();
    assert_eq!(usable(&cache, "content-2", &owner, NOW + DAY).err(), Some(Unusable::Invalid));
    assert!(!path.exists());
}

#[test]
fn a_clock_set_back_cannot_stretch_offline_use() {
    let root = tempfile::tempdir().unwrap();
    let cache = LicenseCache::new(root.path());
    let owner = holder("puid", "device");
    cache.store("content-3", &owner, "US", &key("Machine", BLOCK), &[offline_lease(NOW + 30 * DAY)], NOW).unwrap();
    assert!(usable(&cache, "content-3", &owner, NOW + 10 * DAY).is_ok());
    assert_eq!(usable(&cache, "content-3", &owner, NOW + 5 * DAY).err(), Some(Unusable::Clock));
    // Small corrections are tolerated; the entry stays for when the clock is right.
    assert!(usable(&cache, "content-3", &owner, NOW + 10 * DAY - CLOCK_SKEW_SECONDS).is_ok());
    assert!(usable(&cache, "content-3", &owner, NOW + 11 * DAY).is_ok());
}

#[test]
fn another_account_or_device_registration_removes_every_stored_license() {
    let root = tempfile::tempdir().unwrap();
    let cache = LicenseCache::new(root.path());
    let first = holder("puid-a", "device-a");
    for content in ["content-4", "content-5"] {
        cache.store(content, &first, "US", &key("Machine", BLOCK), &[offline_lease(NOW + 30 * DAY)], NOW).unwrap();
    }
    assert_eq!(usable(&cache, "content-4", &holder("puid-b", "device-a"), NOW + DAY).err(), Some(Unusable::Account));
    for content in ["content-4", "content-5"] {
        assert!(!root.path().join(format!("{content}.json")).exists());
    }
    // The first account's licenses do not come back for it either.
    assert_eq!(usable(&cache, "content-5", &first, NOW + DAY).err(), Some(Unusable::Missing));

    // A new device registration (sign-out with device reset, then sign-in) is a different holder.
    cache.store("content-6", &first, "US", &key("Machine", BLOCK), &[offline_lease(NOW + 30 * DAY)], NOW).unwrap();
    assert_eq!(usable(&cache, "content-6", &holder("puid-a", "device-b"), NOW + DAY).err(), Some(Unusable::Account));
    assert!(!root.path().join("content-6.json").exists());

    // Storing for a new account first removes what the previous one left.
    cache.store("content-7", &first, "US", &key("Machine", BLOCK), &[offline_lease(NOW + 30 * DAY)], NOW).unwrap();
    cache.store("content-8", &holder("puid-b", "device-a"), "US", &key("Machine", BLOCK), &[offline_lease(NOW + 30 * DAY)], NOW).unwrap();
    assert!(!root.path().join("content-7.json").exists());
    assert!(root.path().join("content-8.json").exists());
}

#[test]
fn a_license_without_a_valid_offline_lease_is_never_stored_and_purges_a_stale_entry() {
    let root = tempfile::tempdir().unwrap();
    let cache = LicenseCache::new(root.path());
    let owner = holder("puid", "device");
    cache.store("content-9", &owner, "US", &key("Machine", BLOCK), &[offline_lease(NOW + 30 * DAY)], NOW).unwrap();
    assert!(root.path().join("content-9.json").exists());
    let online = lease_with(&format!("{{\"isOffline\":false,\"expiresAt\":\"{}\"}}", rfc3339(NOW + DAY)), "synthetic-device", None);
    assert_eq!(cache.store("content-9", &owner, "US", &key("Machine", BLOCK), &[online], NOW).unwrap(), Stored::OnlineOnly);
    assert!(!root.path().join("content-9.json").exists());
    assert_eq!(cache.store("content-9", &owner, "US", &key("Machine", BLOCK), &[], NOW).unwrap(), Stored::OnlineOnly);
    assert!(cache.store("content-10", &owner, "US", &key("Machine", ""), &[offline_lease(NOW + DAY)], NOW).is_err());
    assert!(!root.path().join("content-10.json").exists());
    // With several leases the earliest-expiring valid one bounds offline use.
    cache.store("content-11", &owner, "US", &key("Machine", BLOCK), &[offline_lease(NOW + 20 * DAY), offline_lease(NOW + 3 * DAY)], NOW).unwrap();
    assert_eq!(usable(&cache, "content-11", &owner, NOW).unwrap().expires_at, NOW + 3 * DAY);
}

#[test]
fn revoke_all_removes_every_license_and_the_owner_record_only() {
    let root = tempfile::tempdir().unwrap();
    let cache = LicenseCache::new(root.path());
    assert_eq!(cache.revoke_all().unwrap(), 0);
    let owner = holder("puid", "device");
    for content in ["content-12", "content-13"] {
        cache.store(content, &owner, "US", &key("Machine", BLOCK), &[offline_lease(NOW + DAY)], NOW).unwrap();
    }
    std::fs::write(root.path().join("unrelated.txt"), b"kept").unwrap();
    assert_eq!(cache.revoke_all().unwrap(), 2);
    assert!(!root.path().join(OWNER_FILE).exists());
    assert!(root.path().join("unrelated.txt").exists());
    assert!(cache.purge("content-12").is_ok_and(|existed| !existed));
}

#[test]
fn offline_license_rejects_unsafe_identifiers_and_malformed_entries() {
    let root = tempfile::tempdir().unwrap();
    let cache = LicenseCache::new(root.path());
    let owner = holder("puid", "device");
    let too_long = "x".repeat(65);
    for bad in ["", "../escape", "a/b", "a\\b", "with space", too_long.as_str()] {
        assert!(cache.store(bad, &owner, "US", &key("Machine", BLOCK), &[offline_lease(NOW + DAY)], NOW).is_err());
        assert!(cache.load(bad, &owner, NOW).is_err());
        assert!(cache.purge(bad).is_err());
    }
    assert!(!root.path().join("escape.json").exists());
    cache.store("content-14", &owner, "US", &key("Machine", BLOCK), &[offline_lease(NOW + DAY)], NOW).unwrap();
    let corrupt = root.path().join("content-15.json");
    std::fs::write(&corrupt, b"{ not json").unwrap();
    assert_eq!(usable(&cache, "content-15", &owner, NOW).err(), Some(Unusable::Invalid));
    assert!(!corrupt.exists());
    // Entries written before lease validation (schema 2) are never used.
    let old_schema = json!({
        "schema": 2, "contentId": "content-16", "puid": "puid", "expiresAt": NOW + DAY, "splicenseBlock": BLOCK,
    });
    std::fs::write(root.path().join("content-16.json"), old_schema.to_string()).unwrap();
    assert_eq!(usable(&cache, "content-16", &owner, NOW).err(), Some(Unusable::Invalid));
    assert!(!root.path().join("content-16.json").exists());
    std::fs::write(root.path().join("content-17.json"), vec![b'0'; (MAX_FILE_BYTES + 1) as usize]).unwrap();
    assert_eq!(usable(&cache, "content-17", &owner, NOW).err(), Some(Unusable::Invalid));
    assert!(!root.path().join("content-17.json").exists());
}

#[cfg(unix)]
#[test]
fn offline_license_files_are_private_to_the_user() {
    use std::os::unix::fs::PermissionsExt;
    let root = tempfile::tempdir().unwrap();
    let nested = root.path().join("license-cache");
    let cache = LicenseCache::new(&nested);
    cache
        .store("content-18", &holder("puid", "device"), "US", &key("Machine", BLOCK), &[offline_lease(NOW + DAY)], NOW)
        .unwrap();
    assert_eq!(std::fs::metadata(&nested).unwrap().permissions().mode() & 0o777, 0o700);
    for file in ["content-18.json", OWNER_FILE] {
        assert_eq!(std::fs::metadata(nested.join(file)).unwrap().permissions().mode() & 0o777, 0o600);
    }
}
