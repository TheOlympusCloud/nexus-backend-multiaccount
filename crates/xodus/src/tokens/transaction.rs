use std::{fs::File, io, os::{fd::{AsRawFd, FromRawFd}, unix::fs::{DirBuilderExt, MetadataExt, OpenOptionsExt}}, path::Path, time::{Duration, Instant}};

/// Cooperative credential transaction lock. Leave the inode in place on drop:
/// unlinking it would let a later process lock a different file concurrently.
pub(crate) fn lock_at(root: &Path, wait: Duration) -> io::Result<File> {
    match std::fs::DirBuilder::new().mode(0o700).create(root) {
        Ok(()) => {},
        Err(error) if error.kind() == io::ErrorKind::AlreadyExists => {},
        Err(error) => return Err(error),
    }
    let uid = unsafe { libc::geteuid() };
    let directory = std::fs::OpenOptions::new().read(true)
        .custom_flags(libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_CLOEXEC).open(root)?;
    let meta = directory.metadata()?;
    if !meta.is_dir() || meta.uid() != uid || meta.mode() & 0o077 != 0 {
        return Err(io::Error::other("Unsafe credential lock directory"));
    }
    let fd = unsafe { libc::openat(directory.as_raw_fd(), c"store.lock".as_ptr(),
        libc::O_RDWR | libc::O_CREAT | libc::O_NOFOLLOW | libc::O_CLOEXEC | libc::O_NONBLOCK, 0o600) };
    if fd < 0 { return Err(io::Error::last_os_error()); }
    let file = unsafe { File::from_raw_fd(fd) };
    let meta = file.metadata()?;
    if !meta.is_file() || meta.uid() != uid || meta.nlink() != 1 || meta.mode() & 0o077 != 0 {
        return Err(io::Error::other("Unsafe credential lock file"));
    }
    let deadline = Instant::now() + wait;
    loop {
        match fs2::FileExt::try_lock_exclusive(&file) {
            Ok(()) => return Ok(file),
            Err(error) if error.kind() == io::ErrorKind::WouldBlock && Instant::now() < deadline =>
                std::thread::sleep(Duration::from_millis(10)),
            Err(error) => return Err(error),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::tokens::{backend::MemoryBackend, manager::TokenManager, store::{TokenBackend, TokenMutationGuard, TokenStoreError}};
    use crate::models::secrets::Token;
    use std::{path::PathBuf, sync::Arc, process::{Command, Stdio}, io::BufRead};

    struct Directory(PathBuf);
    impl Directory {
        fn new() -> Self {
            let path = std::env::temp_dir().join(format!("nexus-credential-{}", uuid::Uuid::new_v4()));
            std::fs::create_dir(&path).unwrap(); Self(path)
        }
    }
    impl Drop for Directory { fn drop(&mut self) { let _ = std::fs::remove_dir_all(&self.0); } }
    struct Child(std::process::Child);
    impl Drop for Child { fn drop(&mut self) { let _ = self.0.kill(); let _ = self.0.wait(); } }
    struct FileBackend(PathBuf);
    impl TokenBackend for FileBackend {
        fn mutation_lock(&self) -> Result<Box<dyn TokenMutationGuard + '_>, TokenStoreError> {
            Ok(Box::new(lock_at(&self.0.join("lock"), Duration::from_secs(5))?))
        }
        fn get(&self, key: &str) -> Result<Option<Vec<u8>>, TokenStoreError> {
            let result = match std::fs::read(self.0.join(key)) {
                Ok(value) => Some(value),
                Err(error) if error.kind() == io::ErrorKind::NotFound => None,
                Err(error) => return Err(error.into()),
            };
            std::thread::sleep(Duration::from_millis(2));
            Ok(result)
        }
        fn set(&self, key: &str, value: &[u8]) -> Result<(), TokenStoreError> {
            let temp = self.0.join(format!("write-{}", std::process::id()));
            std::fs::write(&temp, value)?;
            std::fs::rename(temp, self.0.join(key))?; Ok(())
        }
        fn remove(&self, key: &str) -> Result<(), TokenStoreError> {
            match std::fs::remove_file(self.0.join(key)) {
                Ok(()) => Ok(()), Err(e) if e.kind() == io::ErrorKind::NotFound => Ok(()), Err(e) => Err(e.into()),
            }
        }
    }
    fn manager(root: &Path) -> TokenManager {
        TokenManager::new(Arc::new(FileBackend(root.to_owned())), Arc::new(MemoryBackend::default()))
    }
    fn child(root: &Path, mode: &str) -> Child {
        Child(Command::new(std::env::current_exe().unwrap())
            .args(["--ignored", "--exact", "tokens::transaction::tests::credential_process_fixture", "--nocapture"])
            .env("NEXUS_CREDENTIAL_FIXTURE_ROOT", root).env("NEXUS_CREDENTIAL_FIXTURE_MODE", mode)
            .stdout(Stdio::piped()).stderr(Stdio::piped()).spawn().unwrap())
    }
    #[test]
    #[ignore = "synthetic subprocess used by credential transaction regressions"]
    fn credential_process_fixture() {
        let root = PathBuf::from(std::env::var_os("NEXUS_CREDENTIAL_FIXTURE_ROOT").unwrap());
        let mode = std::env::var("NEXUS_CREDENTIAL_FIXTURE_MODE").unwrap();
        if mode == "hold" {
            let _guard = lock_at(&root.join("lock"), Duration::from_secs(5)).unwrap();
            println!("LOCK_READY");
            std::thread::sleep(Duration::from_secs(20));
        } else if mode == "logout" || mode == "relogin" || mode == "switch" {
            let manager = manager(&root);
            manager.remove_persistent().unwrap();
            if mode != "logout" {
                let name = if mode == "relogin" { "a" } else { "b" };
                manager.save_user_session(crate::models::secrets::User { puid: name.into(), username: name.into() },
                    std::collections::HashMap::from([(crate::tokens::PASSPORT_STS.into(), Token::Compact(name.into()))])).unwrap();
            }
        } else {
            let manager = manager(&root);
            for i in 0..20 { manager.save_device_token(format!("{mode}-{i}"), Token::Compact("synthetic".into())).unwrap(); }
        }
    }
    #[test]
    fn credential_separate_processes_preserve_all_token_merges() {
        let root = Directory::new();
        let mut a = child(&root.0, "a"); let mut b = child(&root.0, "b");
        assert!(a.0.wait().unwrap().success()); assert!(b.0.wait().unwrap().success());
        let manager = manager(&root.0);
        for name in ["a", "b"] { for i in 0..20 {
            assert!(matches!(manager.get_device_token_for(&format!("{name}-{i}")).unwrap(), Some(Token::Compact(value)) if value == "synthetic"));
        }}
    }
    #[test]
    fn credential_process_lock_is_bounded_and_released_after_kill() {
        let root = Directory::new(); let mut process = child(&root.0, "hold");
        let output = process.0.stdout.take().unwrap();
        let (send, receive) = std::sync::mpsc::channel();
        let reader = std::thread::spawn(move || {
            for line in io::BufReader::new(output).lines() { if line.unwrap() == "LOCK_READY" { send.send(()).unwrap(); break; } }
        });
        receive.recv_timeout(Duration::from_secs(5)).unwrap();
        assert!(lock_at(&root.0.join("lock"), Duration::from_millis(30)).is_err());
        process.0.kill().unwrap(); process.0.wait().unwrap(); reader.join().unwrap();
        drop(lock_at(&root.0.join("lock"), Duration::from_millis(30)).unwrap());
    }
    #[test]
    fn credential_process_lock_rejects_unsafe_paths_without_touching_targets() {
        use std::os::unix::fs::{PermissionsExt, symlink};
        let root = Directory::new(); let directory = root.0.join("lock");
        let guard = lock_at(&directory, Duration::ZERO).unwrap();
        assert!(lock_at(&directory, Duration::ZERO).is_err()); drop(guard);
        let file = directory.join("store.lock");
        std::fs::remove_file(&file).unwrap();
        let sentinel = root.0.join("sentinel"); std::fs::write(&sentinel, b"unchanged").unwrap();
        symlink(&sentinel, &file).unwrap(); assert!(lock_at(&directory, Duration::ZERO).is_err());
        std::fs::remove_file(&file).unwrap();
        std::fs::hard_link(&sentinel, &file).unwrap(); assert!(lock_at(&directory, Duration::ZERO).is_err());
        std::fs::remove_file(&file).unwrap();
        let name = std::ffi::CString::new(file.as_os_str().as_encoded_bytes()).unwrap();
        assert_eq!(unsafe { libc::mkfifo(name.as_ptr(), 0o600) }, 0);
        assert!(lock_at(&directory, Duration::ZERO).is_err()); std::fs::remove_file(&file).unwrap();
        let link = root.0.join("link"); symlink(&directory, &link).unwrap();
        assert!(lock_at(&link, Duration::ZERO).is_err());
        std::fs::set_permissions(&directory, std::fs::Permissions::from_mode(0o755)).unwrap();
        assert!(lock_at(&directory, Duration::ZERO).is_err());
        assert_eq!(std::fs::read(sentinel).unwrap(), b"unchanged");
    }
    #[test]
    fn credential_stale_response_is_rejected_after_another_process_changes_session() {
        for mode in ["logout", "switch", "relogin"] {
            let root = Directory::new(); let manager = manager(&root.0);
            manager.save_user_session(crate::models::secrets::User { puid: "a".into(), username: "a".into() },
                std::collections::HashMap::from([(crate::tokens::PASSPORT_STS.into(), Token::Compact("a".into()))])).unwrap();
            let mut snapshot = manager.user_token_snapshot().unwrap();
            let mut other = child(&root.0, mode); assert!(other.0.wait().unwrap().success());
            assert!(matches!(manager.accept_user_token_refresh(&mut snapshot,
                Some((crate::tokens::PASSPORT_STS.into(), Token::Compact("stale".into())))), Err(TokenStoreError::SessionChanged)));
        }
    }

}
