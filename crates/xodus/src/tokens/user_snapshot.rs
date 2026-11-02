use super::*;

// Intentionally no Debug implementation: snapshots contain credentials.
pub struct UserTokenSnapshot {
    source: Source,
    token: Token,
}
enum Source {
    Session(UserSession),
    Legacy {
        tokens: Vec<u8>,
        user: Option<Vec<u8>>,
        generation: Option<Vec<u8>>,
    },
}
impl UserTokenSnapshot {
    pub fn token(&self) -> Token {
        self.token.clone()
    }
    pub fn user(&self) -> Option<&User> {
        match &self.source {
            Source::Session(session) => Some(&session.user),
            _ => None,
        }
    }
}

impl TokenManager {
    pub(super) fn invalidate_legacy_requests(&self) -> Result<(), TokenStoreError> {
        // A non-secret tombstone survives logout so identical legacy credentials
        // from a later login cannot make an old request current again.
        Self::write_verified(
            &*self.persistent,
            keys::USER_GENERATION,
            uuid::Uuid::new_v4().as_bytes(),
        )
    }

    pub fn user_token_snapshot(&self) -> Result<UserTokenSnapshot, TokenStoreError> {
        let _guard = self.persistent_update()?;
        self.user_snapshot_unlocked()
    }

    fn user_snapshot_unlocked(&self) -> Result<UserTokenSnapshot, TokenStoreError> {
        if let Some(mut session) = self.user_session()? {
            let token = session
                .tokens
                .get(PASSPORT_STS)
                .cloned()
                .ok_or(TokenStoreError::NotFound)?;
            if session.generation.is_none() {
                session.generation = Some(uuid::Uuid::new_v4().to_string());
                Self::write_verified(
                    &*self.persistent,
                    keys::USER_SESSION,
                    &serde_json::to_vec(&session)?,
                )?;
            }
            return Ok(UserTokenSnapshot {
                source: Source::Session(session),
                token,
            });
        }
        let tokens = self
            .persistent
            .get(keys::USER_TOKENS)?
            .ok_or(TokenStoreError::NotFound)?;
        let parsed: TokenStore = serde_json::from_slice(&tokens)?;
        let token = parsed
            .tokens
            .get(PASSPORT_STS)
            .cloned()
            .ok_or(TokenStoreError::NotFound)?;
        Ok(UserTokenSnapshot {
            token,
            source: Source::Legacy {
                tokens,
                user: self.persistent.get(keys::USER_INFO)?,
                generation: self.persistent.get(keys::USER_GENERATION)?,
            },
        })
    }

    fn current_snapshot_session(
        &self,
        snapshot: &UserTokenSnapshot,
    ) -> Result<Option<UserSession>, TokenStoreError> {
        let current = self.user_session()?;
        match (&snapshot.source, &current) {
            (Source::Session(before), Some(after))
                if before.generation == after.generation
                    && before.user.puid == after.user.puid
                    && before.user.username == after.user.username =>
            {
                Ok(current)
            }
            (
                Source::Legacy {
                    tokens,
                    user,
                    generation,
                },
                None,
            ) if self.persistent.get(keys::USER_TOKENS)?.as_ref() == Some(tokens)
                && self.persistent.get(keys::USER_INFO)? == *user
                && self.persistent.get(keys::USER_GENERATION)? == *generation =>
            {
                Ok(None)
            }
            _ => Err(TokenStoreError::SessionChanged),
        }
    }

    pub fn validate_user_token_snapshot(
        &self,
        snapshot: &UserTokenSnapshot,
    ) -> Result<(), TokenStoreError> {
        let _guard = self.persistent_update()?;
        self.current_snapshot_session(snapshot)?;
        Ok(())
    }

    /// Reject another login/logout; do not replace a newer refresh credential
    /// from a concurrent request within the same session. No network under lock.
    pub fn accept_user_token_refresh(
        &self,
        snapshot: &mut UserTokenSnapshot,
        refreshed: Option<(String, Token)>,
    ) -> Result<(), TokenStoreError> {
        let _guard = self.persistent_update()?;
        let current = self.current_snapshot_session(snapshot)?;
        if let Some((address, token)) = refreshed {
            if let Some(mut session) = current {
                let Source::Session(before) = &snapshot.source else {
                    unreachable!()
                };
                if serde_json::to_vec(&session.tokens.get(PASSPORT_STS))?
                    == serde_json::to_vec(&before.tokens.get(PASSPORT_STS))?
                    && serde_json::to_vec(&session.tokens.get(&address))?
                        == serde_json::to_vec(&before.tokens.get(&address))?
                {
                    session.tokens.insert(address, token);
                    Self::write_verified(
                        &*self.persistent,
                        keys::USER_SESSION,
                        &serde_json::to_vec(&session)?,
                    )?;
                }
            } else {
                self.invalidate_legacy_requests()?;
                Self::write_token_store(&*self.persistent, keys::USER_TOKENS, address, token)?;
            }
        }
        *snapshot = self.user_snapshot_unlocked()?;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    fn session(manager: &TokenManager, name: &str) {
        manager
            .save_user_session(
                User {
                    puid: name.into(),
                    username: name.into(),
                },
                HashMap::from([(PASSPORT_STS.into(), Token::Compact(name.into()))]),
            )
            .unwrap();
    }
    #[test]
    fn credential_snapshot_rejects_logout_account_switch_and_identical_relogin() {
        for mode in [0, 1, 2] {
            let manager = TokenManager::with_memory();
            session(&manager, "a");
            let mut snapshot = manager.user_token_snapshot().unwrap();
            match mode {
                0 => manager.remove_persistent().unwrap(),
                1 => session(&manager, "b"),
                _ => {
                    manager.remove_persistent().unwrap();
                    session(&manager, "a");
                }
            }
            assert!(matches!(
                manager.accept_user_token_refresh(
                    &mut snapshot,
                    Some((PASSPORT_STS.into(), Token::Compact("stale".into())))
                ),
                Err(TokenStoreError::SessionChanged)
            ));
            assert!(matches!(
                manager.validate_user_token_snapshot(&snapshot),
                Err(TokenStoreError::SessionChanged)
            ));
            assert!(
                !matches!(manager.get_user_token_for(PASSPORT_STS).unwrap(), Some(Token::Compact(value)) if value == "stale")
            );
        }
    }
    #[test]
    fn credential_snapshot_does_not_overwrite_newer_refresh_in_same_session() {
        let manager = TokenManager::with_memory();
        session(&manager, "a");
        let mut early = manager.user_token_snapshot().unwrap();
        let mut late = manager.user_token_snapshot().unwrap();
        manager
            .accept_user_token_refresh(
                &mut early,
                Some((PASSPORT_STS.into(), Token::Compact("newer".into()))),
            )
            .unwrap();
        manager
            .accept_user_token_refresh(
                &mut late,
                Some((PASSPORT_STS.into(), Token::Compact("older".into()))),
            )
            .unwrap();
        assert!(
            matches!(manager.get_user_sts_token().unwrap(), Token::Compact(value) if value == "newer")
        );
        manager.validate_user_token_snapshot(&late).unwrap();
    }
    #[test]
    fn credential_snapshot_preserves_parallel_distinct_addresses_and_checks_ticket_only_replies() {
        let manager = TokenManager::with_memory();
        session(&manager, "a");
        let mut a = manager.user_token_snapshot().unwrap();
        let mut b = manager.user_token_snapshot().unwrap();
        manager
            .accept_user_token_refresh(&mut a, Some(("first".into(), Token::Compact("a".into()))))
            .unwrap();
        manager
            .accept_user_token_refresh(&mut b, Some(("second".into(), Token::Compact("b".into()))))
            .unwrap();
        assert!(manager.get_user_token_for("first").unwrap().is_some());
        assert!(manager.get_user_token_for("second").unwrap().is_some());
        session(&manager, "b");
        assert!(matches!(
            manager.accept_user_token_refresh(&mut a, None),
            Err(TokenStoreError::SessionChanged)
        ));
    }
    #[test]
    fn credential_snapshot_legacy_tombstone_prevents_identical_relogin_aba() {
        let manager = TokenManager::with_memory();
        manager
            .save_user_token(PASSPORT_STS.into(), Token::Compact("same".into()))
            .unwrap();
        let mut snapshot = manager.user_token_snapshot().unwrap();
        manager.remove_persistent().unwrap();
        manager
            .save_user_token(PASSPORT_STS.into(), Token::Compact("same".into()))
            .unwrap();
        assert!(matches!(
            manager.accept_user_token_refresh(&mut snapshot, None),
            Err(TokenStoreError::SessionChanged)
        ));
    }
    #[test]
    fn credential_snapshot_migrates_old_session_once_without_changing_tokens() {
        let backend = Arc::new(MemoryBackend::default());
        backend.set(keys::USER_SESSION, br#"{"user":{"puid":"a","username":"a"},"tokens":{"http://Passport.NET/STS":"original"}}"#).unwrap();
        let manager = TokenManager::new(backend.clone(), Arc::new(MemoryBackend::default()));
        let first = manager.user_token_snapshot().unwrap();
        let bytes = backend.get(keys::USER_SESSION).unwrap();
        let second = manager.user_token_snapshot().unwrap();
        assert_eq!(bytes, backend.get(keys::USER_SESSION).unwrap());
        assert!(matches!(second.token(), Token::Compact(value) if value == "original"));
        manager.validate_user_token_snapshot(&first).unwrap();
    }
    #[test]
    fn credential_snapshot_storage_failures_do_not_publish_or_advance_credentials() {
        use std::sync::atomic::{AtomicBool, Ordering};
        struct Backend {
            data: MemoryBackend,
            fail: AtomicBool,
        }
        impl TokenBackend for Backend {
            fn get(&self, key: &str) -> Result<Option<Vec<u8>>, TokenStoreError> {
                self.data.get(key)
            }
            fn remove(&self, key: &str) -> Result<(), TokenStoreError> {
                self.data.remove(key)
            }
            fn set(&self, key: &str, value: &[u8]) -> Result<(), TokenStoreError> {
                if self.fail.load(Ordering::SeqCst) {
                    return Err(std::io::Error::other("fixture storage unavailable").into());
                }
                self.data.set(key, value)
            }
        }
        let backend = Arc::new(Backend {
            data: MemoryBackend::default(),
            fail: AtomicBool::new(false),
        });
        let original = br#"{"user":{"puid":"a","username":"a"},"tokens":{"http://Passport.NET/STS":"original"}}"#;
        backend.set(keys::USER_SESSION, original).unwrap();
        let manager = TokenManager::new(backend.clone(), Arc::new(MemoryBackend::default()));
        backend.fail.store(true, Ordering::SeqCst);
        assert!(manager.user_token_snapshot().is_err());
        assert_eq!(backend.get(keys::USER_SESSION).unwrap().unwrap(), original);
        backend.fail.store(false, Ordering::SeqCst);
        let mut snapshot = manager.user_token_snapshot().unwrap();
        backend.fail.store(true, Ordering::SeqCst);
        assert!(
            manager
                .accept_user_token_refresh(
                    &mut snapshot,
                    Some((PASSPORT_STS.into(), Token::Compact("new".into())))
                )
                .is_err()
        );
        assert!(
            matches!(manager.get_user_sts_token().unwrap(), Token::Compact(value) if value == "original")
        );
        backend.fail.store(false, Ordering::SeqCst);
        manager
            .accept_user_token_refresh(
                &mut snapshot,
                Some((PASSPORT_STS.into(), Token::Compact("new".into()))),
            )
            .unwrap();
        assert!(
            matches!(manager.get_user_sts_token().unwrap(), Token::Compact(value) if value == "new")
        );
    }
}
