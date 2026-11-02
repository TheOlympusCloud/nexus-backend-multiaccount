//! Isolated update throughput contracts. Only synthetic files and loopback HTTP.
use super::*;
use std::sync::{
    Arc,
    atomic::{AtomicUsize, Ordering},
};
use tokio::io::AsyncReadExt;

fn segment(length: usize, encrypted: bool) -> SegmentFile {
    SegmentFile {
        offset: 0,
        length: length as u64,
        keep_encrypted: encrypted,
        data_hashs: vec![],
    }
}
async fn xvd() -> XvdFile {
    let mut header = vec![0u8; 0x3000];
    header[512..520].copy_from_slice(b"msft-xvd");
    header[528..536].copy_from_slice(&116444736000000000u64.to_le_bytes());
    header[652..656].copy_from_slice(&4u32.to_le_bytes());
    XvdFile::parse(&mut std::io::Cursor::new(header))
        .await
        .unwrap()
}

#[test]
fn streaming_update_throughput_prefers_same_position_and_reads_contiguous_pages_once() {
    struct Count {
        data: std::io::Cursor<Vec<u8>>,
        bytes: usize,
        reads: usize,
    }
    impl Read for Count {
        fn read(&mut self, data: &mut [u8]) -> io::Result<usize> {
            self.reads += 1;
            let n = std::io::Read::read(&mut self.data, data)?;
            self.bytes += n;
            Ok(n)
        }
    }
    impl Seek for Count {
        fn seek(&mut self, position: SeekFrom) -> io::Result<u64> {
            self.data.seek(position)
        }
    }
    // Every page shares a hash, the old first-match index would select page0
    // repeatedly and invalidate its1MiB read-ahead buffer for each4KiB page.
    let mut old = segment(8 * 1024 * 1024, true);
    old.data_hashs = vec![[7; 20]; 2048];
    let index = HashMap::from([([7; 20], 0)]);
    let candidates = local_candidates(&old, &old, &index, 0, 2048);
    assert_eq!(candidates, (0..2048).map(Some).collect::<Vec<_>>());
    let data = vec![9; 8 * 1024 * 1024];
    let mut reader = Count {
        data: std::io::Cursor::new(data.clone()),
        bytes: 0,
        reads: 0,
    };
    let mut output = vec![0; data.len()];
    assert!(
        read_local_pages(&mut reader, &mut output, &candidates)
            .into_iter()
            .all(|read| read)
    );
    assert_eq!(output, data);
    assert_eq!((reader.bytes, reader.reads), (data.len(), 1));
    let partial = read_local_pages(
        &mut reader,
        &mut [0; PAGE_SIZE * 4],
        &[Some(2), None, Some(0), Some(1)],
    );
    assert_eq!(partial, [true, false, true, true]);
    assert!(!read_local_pages(&mut reader, &mut [0; PAGE_SIZE], &[Some(9999)])[0]);
}

#[test]
fn streaming_update_throughput_ranges_cover_all_gaps_once_with_bounded_memory() {
    for mask in 0u32..1024 {
        let reused: Vec<_> = (0..10).map(|i| mask & (1 << i) != 0).collect();
        let ranges = missing_ranges(&reused);
        let mut fetched = vec![0; reused.len()];
        for range in ranges {
            assert!(range.len() <= 256);
            assert!(!range.is_empty());
            for n in range {
                fetched[n] += 1;
            }
        }
        for (n, local) in reused.into_iter().enumerate() {
            assert!(fetched[n] <= 1);
            if !local {
                assert_eq!(fetched[n], 1);
            }
        }
    }
    assert_eq!(missing_ranges(&[false; 2048]).len(), 8);
    let mut islands = vec![true; 2048];
    islands[0] = false;
    islands[100] = false;
    assert_eq!(missing_ranges(&islands), vec![0..1, 100..101]);
}

async fn server(
    body: Arc<Vec<u8>>,
    count: usize,
    concurrency: usize,
    fail_after: Option<usize>,
) -> (String, tokio::task::JoinHandle<usize>) {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = listener.local_addr().unwrap();
    let task = tokio::spawn(async move {
        let barrier = Arc::new(tokio::sync::Barrier::new(concurrency.min(count)));
        let active = Arc::new(AtomicUsize::new(0));
        let peak = Arc::new(AtomicUsize::new(0));
        let mut tasks = tokio::task::JoinSet::new();
        for index in 0..count {
            let (mut socket, _) = listener.accept().await.unwrap();
            let (body, barrier, active, peak) =
                (body.clone(), barrier.clone(), active.clone(), peak.clone());
            tasks.spawn(async move {
                let mut request = Vec::new();
                while !request.ends_with(b"\r\n\r\n") { request.push(socket.read_u8().await.unwrap()); assert!(request.len() < 8192); }
                let request = String::from_utf8(request).unwrap().to_ascii_lowercase();
                let range = request.lines().find_map(|line| line.strip_prefix("range: bytes=")).unwrap();
                let (start, end) = range.split_once('-').unwrap();
                let (start,end) = (start.parse::<usize>().unwrap(),end.parse::<usize>().unwrap());
                assert_eq!(start % PAGE_SIZE, 0);
                assert!(end - start < 1024 * 1024);
                assert!(end < body.len());
                let now = active.fetch_add(1, Ordering::SeqCst) + 1;
                peak.fetch_max(now, Ordering::SeqCst);
                // The first group cannot finish unless requests really overlap.
                if index < concurrency.min(count) { barrier.wait().await; }
                active.fetch_sub(1, Ordering::SeqCst);
                if fail_after.is_some_and(|limit| start >= limit) {
                    socket.write_all(b"HTTP/1.1 403 Test\r\nContent-Length: 0\r\nConnection: close\r\n\r\n").await.unwrap();
                } else {
                    socket.write_all(format!("HTTP/1.1 206 Test\r\nContent-Length: {}\r\nContent-Range: bytes {start}-{end}/{}\r\nConnection: close\r\n\r\n",end-start+1,body.len()).as_bytes()).await.unwrap();
                    socket.write_all(&body[start..=end]).await.unwrap();
                }
            });
        }
        while let Some(result) = tasks.join_next().await {
            result.unwrap();
        }
        peak.load(Ordering::SeqCst)
    });
    (format!("http://{address}/fixture"), task)
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn streaming_update_throughput_parallel_ranges_preserve_plain_and_ciphertext_tails() {
    for encrypted in [false, true] {
        for parallel in [1usize, 2, 8] {
            let root = tempfile::tempdir().unwrap();
            let length: usize = 4 * 1024 * 1024 + 123;
            let body = Arc::new(
                (0..length.div_ceil(PAGE_SIZE) * PAGE_SIZE)
                    .map(|i| (i % 251) as u8)
                    .collect::<Vec<_>>(),
            );
            let (url, task) = server(body.clone(), 5, parallel, None).await;
            let file = segment(length, encrypted);
            let target = root.path().join("staged");
            let mut out = tokio::fs::File::create(&target).await.unwrap();
            let (_control, pause) = watch::channel(false);
            let (tx, mut rx) = tokio::sync::mpsc::channel(16);
            let mut checkpoints = Vec::new();
            tokio::time::timeout(
                std::time::Duration::from_secs(10),
                transfer(
                    &xvd().await,
                    &reqwest::Client::new(),
                    &url,
                    &root.path().join("missing"),
                    None,
                    &file,
                    &mut out,
                    [0; 32],
                    0,
                    pause,
                    parallel,
                    &tx,
                    0,
                    |p| {
                        checkpoints.push(p);
                        Ok(())
                    },
                ),
            )
            .await
            .unwrap()
            .unwrap();
            out.flush().await.unwrap();
            assert_eq!(task.await.unwrap(), parallel.min(5));
            let physical = if encrypted { body.len() } else { length };
            assert_eq!(fs::read(target).unwrap(), body[..physical]);
            assert!(
                checkpoints.is_empty(),
                "memory fetches must not commit filesystem checkpoints"
            );
            drop(tx);
            let mut network = 0;
            while let Some(event) = rx.recv().await {
                if let ProgressEvent::Traffic { network: n, reused } = event {
                    network += n;
                    assert_eq!(reused, 0);
                }
            }
            assert_eq!(network, length as u64);
        }
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn streaming_update_throughput_failed_window_resumes_only_durable_contiguous_output() {
    use tokio::io::AsyncSeekExt;
    let root = tempfile::tempdir().unwrap();
    let body = Arc::new(
        (0..9 * 1024 * 1024)
            .map(|i| (i % 251) as u8)
            .collect::<Vec<_>>(),
    );
    let file = segment(body.len(), false);
    let files = HashMap::from([("staged".to_owned(), segment(body.len(), false))]);
    let mut journal = resume::Journal::open(root.path(), "fixture", &files).unwrap();
    let target = root.path().join("staged");
    let mut out = tokio::fs::File::create(&target).await.unwrap();
    let (_control, pause) = watch::channel(false);
    let (tx, _rx) = tokio::sync::mpsc::channel(32);
    let client = reqwest::Client::new();
    let xvd = xvd().await;
    let (url, task) = server(body.clone(), 9, 4, Some(8 * 1024 * 1024)).await;
    let failed = tokio::time::timeout(
        std::time::Duration::from_secs(10),
        transfer(
            &xvd,
            &client,
            &url,
            &root.path().join("missing"),
            None,
            &file,
            &mut out,
            [0; 32],
            0,
            pause.clone(),
            4,
            &tx,
            0,
            |p| journal.checkpoint("staged", p),
        ),
    )
    .await
    .unwrap();
    assert!(failed.is_err());
    task.await.unwrap();
    assert_eq!(fs::read(&target).unwrap(), body[..8 * 1024 * 1024]);
    drop(journal);
    let mut journal = resume::Journal::open(root.path(), "fixture", &files).unwrap();
    let offset = journal.offset("staged", file.length);
    assert_eq!(offset, 8 * 1024 * 1024);
    out.seek(SeekFrom::Start(offset)).await.unwrap();
    let (url, task) = server(body.clone(), 1, 1, None).await;
    tokio::time::timeout(
        std::time::Duration::from_secs(10),
        transfer(
            &xvd,
            &client,
            &url,
            &root.path().join("missing"),
            None,
            &file,
            &mut out,
            [0; 32],
            offset,
            pause,
            4,
            &tx,
            0,
            |p| journal.checkpoint("staged", p),
        ),
    )
    .await
    .unwrap()
    .unwrap();
    out.flush().await.unwrap();
    journal.checkpoint("staged", file.length).unwrap();
    task.await.unwrap();
    assert_eq!(fs::read(target).unwrap(), *body);
    assert_eq!(journal.offset("staged", file.length), file.length);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn streaming_update_throughput_pause_and_cancellation_never_claim_prefetched_bytes() {
    let root = tempfile::tempdir().unwrap();
    let target = root.path().join("staged");
    let mut out = tokio::fs::File::create(&target).await.unwrap();
    let file = segment(1024 * 1024, false);
    let xvd = xvd().await;
    let client = reqwest::Client::new();
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = listener.local_addr().unwrap();
    let (control, pause) = watch::channel(true);
    let (stop, stopped) = watch::channel(false);
    let (tx, _rx) = tokio::sync::mpsc::channel(16);
    let mut checkpoints = Vec::new();
    let driver = async {
        assert!(
            tokio::time::timeout(std::time::Duration::from_millis(50), listener.accept())
                .await
                .is_err(),
            "paused update must not open a range request"
        );
        control.send(false).unwrap();
        let (mut socket, _) = listener.accept().await.unwrap();
        let mut request = Vec::new();
        while !request.ends_with(b"\r\n\r\n") {
            request.push(socket.read_u8().await.unwrap());
        }
        socket.write_all(b"HTTP/1.1 206 Test\r\nContent-Length: 1048576\r\nContent-Range: bytes 0-1048575/1048576\r\nConnection: close\r\n\r\n").await.unwrap();
        socket.write_all(&vec![7; 8192]).await.unwrap();
        stop.send(true).unwrap();
        let mut ignored = Vec::new();
        let closed = socket.read_to_end(&mut ignored).await;
        assert!(
            closed.is_ok() || closed.is_err_and(|e| e.kind() == io::ErrorKind::ConnectionReset)
        );
    };
    let url = format!("http://{address}/fixture");
    let missing = root.path().join("missing");
    let operation = failure::run_or_cancel(
        stopped,
        transfer(
            &xvd,
            &client,
            &url,
            &missing,
            None,
            &file,
            &mut out,
            [0; 32],
            0,
            pause,
            4,
            &tx,
            0,
            |p| {
                checkpoints.push(p);
                Ok(())
            },
        ),
    );
    let (result, ()) = tokio::time::timeout(std::time::Duration::from_secs(5), async {
        tokio::join!(operation, driver)
    })
    .await
    .unwrap();
    assert!(result.is_err());
    let mut complete = false;
    assert!(
        failure::settle(&mut out, result, || {
            complete = true;
            Ok(())
        })
        .await
        .is_err()
    );
    assert!(!complete);
    assert!(checkpoints.iter().all(|p| *p == 0));
    assert!(fs::read(target).unwrap().is_empty());
}
