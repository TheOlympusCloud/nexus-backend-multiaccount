//! Compatibility metadata from authenticated MSA sessions, not an entitlement.
use xodus::models::secrets::User;

fn account_id(puid: &str) -> Option<String> {
    if puid.len() != 16 || !puid.bytes().all(|c| c.is_ascii_hexdigit()) || puid.bytes().all(|c| c == b'0') {
        return None;
    }
    Some(puid.to_ascii_lowercase())
}

/// The Xbox ticket's account paired with the current Store account. The ticket must still
/// match the current session it came from (the separate player, or the Store account itself).
pub fn bound_ids(ticket: Option<&User>, current: Option<&User>, store: Option<&User>) -> (Option<String>, Option<String>) {
    let (Some(ticket), Some(current), Some(store)) = (ticket, current, store) else { return (None, None) };
    let (Some(xbox), Some(current_id), Some(store_id)) = (account_id(&ticket.puid), account_id(&current.puid), account_id(&store.puid)) else {
        return (None, None);
    };
    // A change/logout while exchanging tickets must not publish a stale pair.
    if xbox != current_id || ticket.username.is_empty() || !ticket.username.eq_ignore_ascii_case(&current.username) {
        return (None, None);
    }
    (Some(xbox), Some(store_id))
}

#[cfg(test)]
mod tests {
    use super::*;
    fn user(puid: &str) -> User { User { puid: puid.into(), username: "synthetic@example.invalid".into() } }
    #[test]
    fn account_metadata_uses_real_session_ids_and_rejects_mixed_accounts() {
        let a = user("0123456789ABCDEF");
        let b = user("fedcba9876543210");
        assert_eq!(bound_ids(Some(&a), Some(&a), Some(&a)), (Some("0123456789abcdef".into()), Some("0123456789abcdef".into())));
        // A ticket issued to one account is never published for the session that replaced it.
        assert_eq!(bound_ids(Some(&a), Some(&b), Some(&b)), (None, None));
        assert_eq!(bound_ids(Some(&a), None, Some(&a)), (None, None));
        assert_eq!(bound_ids(None, Some(&a), Some(&a)), (None, None));
        assert_eq!(bound_ids(Some(&a), Some(&a), None), (None, None));
        let renamed = User { puid: a.puid.clone(), username: "other@example.invalid".into() };
        assert_eq!(bound_ids(Some(&a), Some(&renamed), Some(&a)), (None, None));
    }
    #[test]
    fn account_metadata_publishes_distinct_player_and_store_ids() {
        let player = User { puid: "0123456789ABCDEF".into(), username: "player@example.invalid".into() };
        let store = User { puid: "fedcba9876543210".into(), username: "store@example.invalid".into() };
        assert_eq!(bound_ids(Some(&player), Some(&player), Some(&store)), (Some("0123456789abcdef".into()), Some("fedcba9876543210".into())));
        let bad_store = User { puid: "0000000000000000".into(), ..store };
        assert_eq!(bound_ids(Some(&player), Some(&player), Some(&bad_store)), (None, None));
    }
    #[test]
    fn account_metadata_rejects_a_replaced_player_ticket() {
        let player = User { puid: "0123456789ABCDEF".into(), username: "player@example.invalid".into() };
        let other = User { puid: "1111111111111111".into(), username: "other@example.invalid".into() };
        let store = User { puid: "fedcba9876543210".into(), username: "store@example.invalid".into() };
        assert_eq!(bound_ids(Some(&player), Some(&other), Some(&store)), (None, None));
        assert_eq!(bound_ids(Some(&player), None, Some(&store)), (None, None));
    }
    #[test]
    fn account_metadata_rejects_placeholder_malformed_and_empty_ids() {
        for value in ["", "0", "0000000000000000", "281474000000000000000", "synthetic", "0123456789abcdeg", "0123456789abcdef\n"] {
            let bad = user(value);
            assert_eq!(bound_ids(Some(&bad), Some(&bad), Some(&bad)), (None, None));
        }
    }
    #[test]
    fn account_metadata_xml_is_additive_and_omitted_for_unbound_sessions() {
        use xodus::models::xgameruntime::xuser::MSATokenResponse;
        let mut value = MSATokenResponse { token: "synthetic-ticket".into(), expiry: 1, device_rps: "synthetic-device".into(), device_expiry: 2, xbox_msa_account_id: None, store_msa_account_id: None };
        let xml = quick_xml::se::to_string(&value).unwrap();
        assert!(!xml.contains("MsaAccountId"));
        value.xbox_msa_account_id = Some("0123456789abcdef".into());
        value.store_msa_account_id = Some("0123456789abcdef".into());
        let xml = quick_xml::se::to_string(&value).unwrap();
        assert!(xml.contains("<XboxMsaAccountId>0123456789abcdef</XboxMsaAccountId>"));
        assert!(xml.contains("<StoreMsaAccountId>0123456789abcdef</StoreMsaAccountId>"));
    }
}
