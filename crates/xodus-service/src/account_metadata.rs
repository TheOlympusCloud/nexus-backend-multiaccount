//! Compatibility metadata from authenticated MSA sessions, not an entitlement.
use xodus::models::secrets::User;
use xodus::tokens::{TokenManager, manager::UserTokenSnapshot};

fn account_id(puid: &str) -> Option<String> {
    if puid.len() != 16 || !puid.bytes().all(|c| c.is_ascii_hexdigit()) || puid.bytes().all(|c| c == b'0') {
        return None;
    }
    Some(puid.to_ascii_lowercase())
}

/// The Xbox ticket's account paired with the Store account, both from snapshots taken before the
/// ticket exchange. A change to either session during the exchange publishes no pair.
pub fn bound_ids(
    player: &TokenManager,
    ticket: &UserTokenSnapshot,
    tokens: &TokenManager,
    store: Option<&UserTokenSnapshot>,
) -> (Option<String>, Option<String>) {
    let Some(store) = store else { return (None, None) };
    if player.validate_user_token_snapshot(ticket).is_err() || tokens.validate_user_token_snapshot(store).is_err() {
        return (None, None);
    }
    ids(ticket.user(), store.user())
}

fn ids(ticket: Option<&User>, store: Option<&User>) -> (Option<String>, Option<String>) {
    let (Some(ticket), Some(store)) = (ticket, store) else { return (None, None) };
    match (account_id(&ticket.puid), account_id(&store.puid)) {
        (Some(xbox), Some(store_id)) if !ticket.username.is_empty() && !store.username.is_empty() => (Some(xbox), Some(store_id)),
        _ => (None, None),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashMap;
    use xodus::models::secrets::Token;
    use xodus::tokens::PASSPORT_STS;
    fn user(puid: &str) -> User { User { puid: puid.into(), username: "synthetic@example.invalid".into() } }
    const STORE: &str = "fedcba9876543210";
    const PLAYER: &str = "0123456789ABCDEF";
    fn sign_in(tokens: &TokenManager, puid: &str) {
        tokens.save_user_session(User { puid: puid.into(), username: format!("{puid}@example.invalid") },
            HashMap::from([(PASSPORT_STS.into(), Token::Compact(puid.into()))])).unwrap();
    }
    /// The player and Store snapshots a ticket exchange starts from.
    fn exchange(tokens: &TokenManager) -> (TokenManager, UserTokenSnapshot, UserTokenSnapshot) {
        let player = tokens.player_account().unwrap();
        let ticket = player.user_token_snapshot().unwrap();
        (player, ticket, tokens.user_token_snapshot().unwrap())
    }
    #[test]
    fn account_metadata_uses_real_session_ids_and_rejects_mixed_accounts() {
        let tokens = TokenManager::with_memory();
        sign_in(&tokens, STORE);
        let (player, ticket, store) = exchange(&tokens);
        assert_eq!(bound_ids(&player, &ticket, &tokens, Some(&store)), (Some(STORE.into()), Some(STORE.into())));
        sign_in(&tokens.player_session(), PLAYER);
        let (player, ticket, store) = exchange(&tokens);
        assert_eq!(bound_ids(&player, &ticket, &tokens, Some(&store)), (Some("0123456789abcdef".into()), Some(STORE.into())));
        assert_eq!(bound_ids(&player, &ticket, &tokens, None), (None, None));
        // Snapshots that no longer match the stored sessions would pair two configurations.
        sign_in(&tokens.player_session(), "2222222222222222");
        assert_eq!(bound_ids(&player, &ticket, &tokens, Some(&store)), (None, None));
    }
    #[test]
    fn account_metadata_rejects_a_store_change_during_the_exchange() {
        let tokens = TokenManager::with_memory();
        sign_in(&tokens, STORE);
        sign_in(&tokens.player_session(), PLAYER);
        let (player, ticket, store) = exchange(&tokens);
        sign_in(&tokens, "1111111111111111");
        assert_eq!(bound_ids(&player, &ticket, &tokens, Some(&store)), (None, None));
    }
    #[test]
    fn account_metadata_rejects_a_player_change_during_the_exchange() {
        let tokens = TokenManager::with_memory();
        sign_in(&tokens, STORE);
        sign_in(&tokens.player_session(), PLAYER);
        let (player, ticket, store) = exchange(&tokens);
        sign_in(&tokens.player_session(), "2222222222222222");
        assert_eq!(bound_ids(&player, &ticket, &tokens, Some(&store)), (None, None));
        tokens.player_session().remove_persistent().unwrap();
        assert_eq!(bound_ids(&player, &ticket, &tokens, Some(&store)), (None, None));
    }
    #[test]
    fn account_metadata_keeps_the_pair_across_a_token_refresh() {
        // With one account the exchange itself refreshes the session the Store snapshot names.
        let tokens = TokenManager::with_memory();
        sign_in(&tokens, STORE);
        let (player, mut ticket, store) = exchange(&tokens);
        player.accept_user_token_refresh(&mut ticket, Some((PASSPORT_STS.into(), Token::Compact("renewed".into())))).unwrap();
        assert_eq!(bound_ids(&player, &ticket, &tokens, Some(&store)), (Some(STORE.into()), Some(STORE.into())));
    }
    #[test]
    fn account_metadata_rejects_placeholder_malformed_and_empty_ids() {
        for value in ["", "0", "0000000000000000", "281474000000000000000", "synthetic", "0123456789abcdeg", "0123456789abcdef\n"] {
            let bad = user(value);
            assert_eq!(ids(Some(&bad), Some(&bad)), (None, None));
        }
        let unnamed = User { puid: STORE.into(), username: String::new() };
        assert_eq!(ids(Some(&unnamed), Some(&unnamed)), (None, None));
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
