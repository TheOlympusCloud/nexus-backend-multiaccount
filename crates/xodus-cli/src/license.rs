use std::path::Path;

use xodus::licensing::content::{LicenseContentError, lease_policy, parse_lease};
use xodus::licensing::splicense::{DeviceKey, SPLicense};
use xodus::models::devicecredential::License;
use xodus::models::live::ExchangeUserTokenOutcome;
use xodus::models::secrets::{Token, User};
use xodus::models::soap;
use xodus::tokens::TokenManager;

use crate::license_cache::{LicenseCache, Stored, diagnostic, unix_now};

/// Why the online content-license request did not produce a license.
#[derive(Debug)]
pub enum OnlineFailure {
    /// Microsoft could not be reached or answered with a transient service
    /// error. A stored offline license may be used.
    Unreachable(String),
    /// Microsoft answered and refused this account or content. Any stored
    /// offline license is removed.
    Refused(String),
    /// Credential, sign-in or response problems that offline play must not hide.
    Other(String),
}

impl OnlineFailure {
    pub fn message(&self) -> &str {
        match self {
            Self::Unreachable(message) | Self::Refused(message) | Self::Other(message) => message,
        }
    }
}

/// A content license as Microsoft issued it: the key license plus the leases
/// that came with it.
pub struct OnlineLicense {
    pub key: License,
    pub leases: Vec<License>,
}

/// Fetches the content license online. `cache` enables device-bound offline
/// use: a license that arrives with an offline lease is recorded there and
/// consulted only when Microsoft is unreachable. `offline` states that the
/// caller already found Microsoft unreachable: no request is made and only
/// the stored license can satisfy the launch.
pub async fn get_license(
    client: &reqwest::Client,
    tokens: &TokenManager,
    content_id: String,
    market: String,
    cache: Option<&Path>,
    offline: bool,
) -> std::result::Result<(DeviceKey, SPLicense), String> {
    let user = tokens.get_user().map_err(|error| error.to_string())?;
    if offline {
        // Skip the ticket and license requests and their connect timeouts;
        // the stored license is held to the same rules as after a failed
        // request, so nothing is granted that an unreachable Microsoft would
        // not have allowed.
        return recover_offline(
            tokens,
            cache,
            &content_id,
            &user.puid,
            OnlineFailure::Unreachable("Microsoft is unreachable (offline launch requested).".to_string()),
            unix_now(),
        );
    }
    match fetch_online(client, tokens, &user, content_id.clone(), market.clone()).await {
        Ok(license) => {
            let material = license_material(tokens, &license.key.splicense_block)?;
            if let Some(root) = cache {
                record_license(root, &content_id, &user.puid, &market, &license);
            }
            Ok(material)
        }
        Err(failure) => recover_offline(tokens, cache, &content_id, &user.puid, failure, unix_now()),
    }
}

/// The offline lease Microsoft attached, if any: the earliest expiry among
/// leases whose policy allows offline use, as Unix seconds.
pub fn offline_lease_expiry(leases: &[License]) -> Option<u64> {
    leases
        .iter()
        .filter_map(lease_policy)
        .filter(|policy| policy.is_offline)
        .filter_map(|policy| policy.expires_at.map(|expires| expires.timestamp()))
        .filter(|seconds| *seconds > 0)
        .map(|seconds| seconds as u64)
        .min()
}

fn record_license(root: &Path, content_id: &str, puid: &str, market: &str, license: &OnlineLicense) {
    // Policy metadata only: no identifiers, keys or license blocks.
    let leases: Vec<String> = license
        .leases
        .iter()
        .map(|lease| match lease_policy(lease) {
            Some(policy) => format!(
                "lease offline={} expires={} poll={} enforcement={:?}",
                policy.is_offline,
                policy.expires_at.map(|t| t.to_rfc3339()).unwrap_or_else(|| "none".into()),
                policy.poll_at.map(|t| t.to_rfc3339()).unwrap_or_else(|| "none".into()),
                policy.lease_enforcement
            ),
            None => "lease without readable policy".to_string(),
        })
        .collect();
    eprintln!(
        "Content license policy: type {:?}, usage {:?}, category {:?}, binding {}, lease required {:?}; {} lease(s): {}.",
        license.key.license_info.license_type,
        license.key.license_info.license_usage,
        license.key.license_info.license_category,
        license.key.binding.binding_type,
        license.key.binding.lease_required,
        license.leases.len(),
        if leases.is_empty() { "none".to_string() } else { leases.join("; ") },
    );
    let offline_until = offline_lease_expiry(&license.leases);
    match LicenseCache::new(root).store(content_id, puid, market, &license.key, offline_until, unix_now()) {
        Ok(Stored::Saved) => diagnostic("content-cache-stored"),
        Ok(Stored::OnlineOnly) => {
            eprintln!(
                "No offline lease was issued for this device; offline play requires it to be the account's designated offline device."
            );
            diagnostic("content-cache-skipped")
        }
        Err(_) => diagnostic("content-cache-write-failed"),
    }
}

/// Decides whether a stored offline license may stand in for the failed
/// online request. Only an unreachable service qualifies; refusals purge.
/// Set once a launch continues on the stored offline license, so later
/// online-only steps of the same launch (PlayFab authorisation) are skipped
/// instead of waiting for their own timeouts.
pub static OFFLINE_LICENSE_USED: std::sync::atomic::AtomicBool = std::sync::atomic::AtomicBool::new(false);

pub fn recover_offline(
    tokens: &TokenManager,
    cache: Option<&Path>,
    content_id: &str,
    puid: &str,
    failure: OnlineFailure,
    now: u64,
) -> Result<(DeviceKey, SPLicense), String> {
    let message = failure.message().to_string();
    match failure {
        OnlineFailure::Refused(_) => {
            if let Some(root) = cache
                && LicenseCache::new(root).purge(content_id) == Ok(true)
            {
                diagnostic("content-cache-purged");
            }
            Err(message)
        }
        OnlineFailure::Other(_) => Err(message),
        OnlineFailure::Unreachable(_) => {
            let Some(root) = cache else {
                return Err(message);
            };
            match LicenseCache::new(root).load(content_id, puid, now) {
                Ok(Some(entry)) => {
                    OFFLINE_LICENSE_USED.store(true, std::sync::atomic::Ordering::Relaxed);
                    diagnostic("content-cache-used");
                    eprintln!(
                        "Microsoft content licensing is unreachable; using the offline license stored on this device (valid for {} more day(s)).",
                        entry.expires_at.saturating_sub(now).div_ceil(24 * 60 * 60)
                    );
                    license_material(tokens, &entry.splicense_block)
                }
                Ok(None) => Err(format!(
                    "{message} No valid offline license is stored for this game. Play it once while online on the account's designated offline device to enable offline play."
                )),
                Err(error) => Err(format!("{message} {error}")),
            }
        }
    }
}

fn transport_failure(error: &(dyn std::error::Error + 'static)) -> bool {
    let mut current = Some(error);
    while let Some(error) = current {
        if let Some(request) = error.downcast_ref::<reqwest::Error>() {
            return request.is_connect() || request.is_timeout() || request.is_request();
        }
        current = error.source();
    }
    false
}

fn ticket_failure(error: &(dyn std::error::Error + 'static), message: &str) -> OnlineFailure {
    if transport_failure(error) {
        OnlineFailure::Unreachable(message.to_string())
    } else {
        OnlineFailure::Other(message.to_string())
    }
}

fn content_failure(error: LicenseContentError) -> OnlineFailure {
    let message = error.to_string();
    match error {
        LicenseContentError::Timeout
        | LicenseContentError::Request
        | LicenseContentError::Read
        | LicenseContentError::RateLimited
        | LicenseContentError::Server(_) => OnlineFailure::Unreachable(message),
        LicenseContentError::Forbidden | LicenseContentError::NotEntitled => {
            OnlineFailure::Refused(message)
        }
        _ => OnlineFailure::Other(message),
    }
}

async fn fetch_online(
    client: &reqwest::Client,
    tokens: &TokenManager,
    user: &User,
    content_id: String,
    market: String,
) -> Result<OnlineLicense, OnlineFailure> {
    let other = |message: String| OnlineFailure::Other(message);
    let dev_token = tokens
        .get_device_sts_token()
        .map_err(|error| other(error.to_string()))?;
    let Token::Legacy(dev_token) = dev_token else {
        return Err(other("Invalid STS token".to_string()));
    };
    let user_token = tokens
        .get_user_sts_token()
        .map_err(|error| other(error.to_string()))?;
    let Token::Legacy(legacy) = user_token else {
        return Err(other("Unspported user token".to_string()));
    };

    let ms_device_token = xodus::api::live::exchange_device_token(
        client,
        dev_token.clone(),
        "{d6d5a677-0872-4ab0-9442-bb792fce85c5}".to_string(),
        "www.microsoft.com".to_owned(),
        Some(soap::PolicyReference::mbi_ssl()),
    )
    .await
    .map_err(|error| {
        ticket_failure(
            &error,
            "Microsoft device-ticket request failed. Check your connection and sign-in.",
        )
    })?;

    let user_token = xodus::api::live::exchange_user_token(
        client,
        legacy,
        user.username.clone(),
        dev_token,
        None,
        Some("Silent".to_string()),
        "{d6d5a677-0872-4ab0-9442-bb792fce85c5}".to_string(),
        &[(
            "www.microsoft.com".to_owned(),
            Some(soap::PolicyReference::mbi_ssl()),
        )],
    )
    .await
    .map_err(|error| {
        ticket_failure(
            &error,
            "Microsoft user-ticket request failed. Check your connection and sign-in.",
        )
    })?;

    let ms_device_token =
        Token::try_from(ms_device_token).map_err(|error| other(error.to_string()))?;
    let Token::Compact(ms_device_token) = ms_device_token else {
        return Err(other("Unsupported token".to_string()));
    };

    let user_token: Token = match user_token {
        ExchangeUserTokenOutcome::Fault(_) => {
            return Err(other("Failed to get exchange MS token".to_string()));
        }
        ExchangeUserTokenOutcome::Issued(
            soap::BodyContent::RequestSecurityTokenResponseCollection(collection),
        ) => {
            let token = collection
                .security_tokens
                .into_iter()
                .next()
                .ok_or_else(|| other("Microsoft returned no content-licensing user ticket.".into()))?;
            Token::try_from(token).map_err(|error| other(error.to_string()))?
        }
        ExchangeUserTokenOutcome::Issued(soap::BodyContent::RequestSecurityTokenResponse(
            token,
        )) => Token::try_from(*token).map_err(|error| other(error.to_string()))?,
        _ => {
            return Err(other(
                "Microsoft returned an unsupported content-licensing user ticket.".into(),
            ));
        }
    };
    let Token::Compact(user_token) = user_token else {
        return Err(other("Unsupported token".to_string()));
    };
    let user_token = xodus::models::secrets::licensing_ticket(user_token);

    let (content, key) = xodus::licensing::content::get_license_content(
        client,
        ms_device_token,
        user_token,
        user.puid.clone(),
        content_id,
        market,
    )
    .await
    .map_err(content_failure)?;

    // Leases are optional policy metadata; an unreadable lease never blocks
    // the launch, it only means no offline permission is recorded.
    let leases = content
        .leases
        .iter()
        .filter_map(|lease| parse_lease(&lease.value).ok())
        .collect();
    Ok(OnlineLicense { key, leases })
}

fn license_material(tokens: &TokenManager, block: &str) -> Result<(DeviceKey, SPLicense), String> {
    let game_splicense = SPLicense::parse_base64(block).map_err(|_| {
        eprintln!("NEXUS_CONTENT_LICENSE_DIAGNOSTIC_V1 content-license-blob 0");
        "Microsoft returned an invalid content-license block. Share the backend diagnostic log."
            .to_string()
    })?;

    let dev_license = tokens
        .get_device_license()
        .map_err(|error| error.to_string())?;
    let device_license = SPLicense::parse_base64(&dev_license.splicense).map_err(|_| {
        "Stored device-license data is invalid. Sign in again in Settings.".to_string()
    })?;
    let key = device_license
        .encrypted_device_key
        .ok_or("Stored device license has no decryption key. Sign in again in Settings.")?
        .derive_device_key();
    Ok((key, game_splicense))
}

#[cfg(test)]
mod tests {
    use super::*;
    use base64::{Engine, prelude::BASE64_STANDARD};
    use xodus::models::devicecredential::{Binding, LicenseInfo, LicenseType, LicenseUsage};
    use xodus::models::secrets::Device;
    #[test]
    fn content_license_bad_blocks_return_fixed_errors_without_touching_credentials() {
        let tokens = TokenManager::with_memory();
        let error = license_material(&tokens, "private-secret-bad-base64")
            .err()
            .unwrap();
        assert!(error.contains("invalid content-license block"));
        assert!(!error.contains("private-secret"));
        assert!(tokens.get_device_license().is_err());
        let empty = BASE64_STANDARD.encode([0u8; 8]);
        assert!(license_material(&tokens, &empty).is_err());
        tokens
            .save_device_license(&Device {
                username: "synthetic".into(),
                password: "unused".into(),
                puid: "unused".into(),
                hwid: "unchanged".into(),
                device_id: "unchanged".into(),
                splicense: empty.clone(),
            })
            .unwrap();
        assert!(
            license_material(&tokens, &empty)
                .err()
                .unwrap()
                .contains("no decryption key")
        );
        assert_eq!(tokens.get_device_license().unwrap().hwid, "unchanged");
    }

    fn synthetic(block: &str, policies: Option<&str>) -> License {
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
            custom_policies: policies.map(|json| BASE64_STANDARD.encode(json)),
            binding: Binding {
                binding_type: "Machine".to_string(),
                device_id: None,
                product_id: None,
                pfm: None,
                user_id: None,
                usid: None,
                lease_required: Some("True".to_string()),
                lease_renewal_period: Some("2880".to_string()),
                associated_pfns: None,
            },
        }
    }

    #[test]
    fn offline_lease_expiry_requires_an_offline_lease_and_takes_the_earliest() {
        let offline = |expires: &str| synthetic("", Some(&format!(
            "{{\"isOffline\":true,\"expiresAt\":\"{expires}\",\"pollAt\":\"2026-10-26T00:00:00+00:00\",\"leaseEnforcement\":\"EnforceConcurrency\"}}")));
        let online = synthetic("", Some("{\"isOffline\":false,\"expiresAt\":\"2099-01-01T00:00:00+00:00\"}"));
        let unreadable = synthetic("", Some("not json"));
        assert_eq!(offline_lease_expiry(&[]), None);
        assert_eq!(offline_lease_expiry(&[online.clone(), unreadable.clone(), synthetic("", None)]), None);
        let early = offline("2026-11-01T00:00:00+00:00");
        let late = offline("2026-11-23T22:11:38.7544426+00:00");
        assert_eq!(offline_lease_expiry(&[late.clone(), online, early]), Some(1_793_491_200));
        assert_eq!(offline_lease_expiry(&[late, unreadable]), Some(1_795_471_898));
        // An offline lease without a usable expiry grants nothing.
        assert_eq!(offline_lease_expiry(&[synthetic("", Some("{\"isOffline\":true}"))]), None);
    }

    #[test]
    fn offline_recovery_uses_the_stored_license_only_when_microsoft_is_unreachable() {
        let tokens = TokenManager::with_memory();
        let root = tempfile::tempdir().unwrap();
        let cache = LicenseCache::new(root.path());
        // A structurally valid, empty SPLicense: header and offset only.
        let block = BASE64_STANDARD.encode([0u8; 8]);
        let now = 1_800_000_000;
        cache
            .store("content-a", "puid", "US", &synthetic(&block, None), Some(now + 20 * 24 * 60 * 60), now)
            .unwrap();
        let unreachable = || OnlineFailure::Unreachable("Could not connect.".into());

        // The cached block is accepted and the flow proceeds to the keyring device key.
        let error = recover_offline(&tokens, Some(root.path()), "content-a", "puid", unreachable(), now)
            .err()
            .unwrap();
        assert!(!error.contains("Could not connect"), "{error}");
        assert!(!error.contains("offline license is stored"), "{error}");
        assert!(root.path().join("content-a.json").exists());
        // The launch now runs on the stored license; later online-only steps skip their timeouts.
        assert!(OFFLINE_LICENSE_USED.load(std::sync::atomic::Ordering::Relaxed));

        // No cache directory, another account or no entry keep the original failure.
        for (cache_root, puid, content) in [
            (None, "puid", "content-a"),
            (Some(root.path()), "someone-else", "content-a"),
            (Some(root.path()), "puid", "content-b"),
        ] {
            let error = recover_offline(&tokens, cache_root, content, puid, unreachable(), now)
                .err()
                .unwrap();
            assert!(error.starts_with("Could not connect."), "{error}");
            assert_eq!(error.contains("offline license is stored"), cache_root.is_some(), "{error}");
        }

        // Sign-in and response problems never consult the cache.
        let error = recover_offline(&tokens, Some(root.path()), "content-a", "puid",
            OnlineFailure::Other("Sign in again.".into()), now).err().unwrap();
        assert_eq!(error, "Sign in again.");
        assert!(root.path().join("content-a.json").exists());

        // Expired entries fail closed and disappear.
        let error = recover_offline(&tokens, Some(root.path()), "content-a", "puid", unreachable(),
            now + crate::license_cache::MAX_OFFLINE_SECONDS).err().unwrap();
        assert!(error.contains("offline license is stored"), "{error}");
        assert!(!root.path().join("content-a.json").exists());
    }

    #[tokio::test]
    async fn offline_launch_never_contacts_microsoft_and_uses_only_the_stored_license() {
        let tokens = TokenManager::with_memory();
        tokens
            .save_user(&xodus::models::secrets::User { puid: "puid".into(), username: "user@example.com".into() })
            .unwrap();
        let root = tempfile::tempdir().unwrap();
        let block = BASE64_STANDARD.encode([0u8; 8]);
        let now = unix_now();
        LicenseCache::new(root.path())
            .store("content-a", "puid", "US", &synthetic(&block, None), Some(now + 20 * 24 * 60 * 60), now)
            .unwrap();
        // Any request would have to connect within a millisecond and fail: the
        // offline path must never issue one.
        let client = reqwest::ClientBuilder::new()
            .connect_timeout(std::time::Duration::from_millis(1))
            .build()
            .unwrap();

        // The stored block is accepted and the flow proceeds to the device key,
        // exactly as after a failed request.
        let error = get_license(&client, &tokens, "content-a".into(), "US".into(), Some(root.path()), true)
            .await
            .err()
            .unwrap();
        assert!(!error.contains("offline launch requested"), "{error}");
        assert!(root.path().join("content-a.json").exists());
        assert!(OFFLINE_LICENSE_USED.load(std::sync::atomic::Ordering::Relaxed));

        // Without a stored license the launch fails closed and says why.
        let error = get_license(&client, &tokens, "content-b".into(), "US".into(), Some(root.path()), true)
            .await
            .err()
            .unwrap();
        assert!(error.starts_with("Microsoft is unreachable (offline launch requested)."), "{error}");
        assert!(error.contains("No valid offline license is stored"), "{error}");
        let error = get_license(&client, &tokens, "content-a".into(), "US".into(), None, true)
            .await
            .err()
            .unwrap();
        assert!(error.starts_with("Microsoft is unreachable (offline launch requested)."), "{error}");
    }

    #[test]
    fn offline_recovery_purges_the_stored_license_when_microsoft_refuses() {
        let tokens = TokenManager::with_memory();
        let root = tempfile::tempdir().unwrap();
        let cache = LicenseCache::new(root.path());
        let block = BASE64_STANDARD.encode([0u8; 8]);
        cache
            .store("content-c", "puid", "US", &synthetic(&block, None), Some(10), 1)
            .unwrap();
        let error = recover_offline(&tokens, Some(root.path()), "content-c", "puid",
            OnlineFailure::Refused("Not entitled.".into()), 2).err().unwrap();
        assert_eq!(error, "Not entitled.");
        assert!(!root.path().join("content-c.json").exists());
        assert!(recover_offline(&tokens, None, "content-c", "puid",
            OnlineFailure::Refused("Not entitled.".into()), 2).is_err());
    }

    #[test]
    fn online_failures_are_classified_without_inferring_entitlement() {
        for error in [LicenseContentError::Timeout, LicenseContentError::Request,
            LicenseContentError::Read, LicenseContentError::RateLimited, LicenseContentError::Server(503)] {
            assert!(matches!(content_failure(error), OnlineFailure::Unreachable(_)));
        }
        for error in [LicenseContentError::Forbidden, LicenseContentError::NotEntitled] {
            assert!(matches!(content_failure(error), OnlineFailure::Refused(_)));
        }
        for error in [LicenseContentError::Unauthorized, LicenseContentError::Http(418),
            LicenseContentError::Json, LicenseContentError::Schema, LicenseContentError::EmptyKeys,
            LicenseContentError::Size, LicenseContentError::Xml] {
            assert!(matches!(content_failure(error), OnlineFailure::Other(_)));
        }
        let local = std::io::Error::other("not a transport failure");
        assert!(!transport_failure(&local));
        assert!(matches!(ticket_failure(&local, "ticket"), OnlineFailure::Other(message) if message == "ticket"));
    }
}
