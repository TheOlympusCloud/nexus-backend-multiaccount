// Temporary context, full service design will be much more extensive

use std::{sync::Arc, time::Duration};

use xodus::models::secrets::LegacyToken;
use xodus::tokens::TokenManager;

pub struct SimpleContext {
    pub client: reqwest::Client,
    pub device_token: Option<LegacyToken>,
    tokens: Arc<TokenManager>,
}

impl SimpleContext {
    pub fn new(device_token: LegacyToken, tokens: Arc<TokenManager>) -> Self {
        let client = service_client(Duration::from_secs(60));

        Self {
            client,
            device_token: Some(device_token),
            tokens,
        }
    }

    pub fn tokens(&self) -> &Arc<TokenManager> {
        &self.tokens
    }
}

fn service_client(timeout: Duration) -> reqwest::Client {
    reqwest::ClientBuilder::new()
        .user_agent(format!("xodus-service/{}", env!("CARGO_PKG_VERSION")))
        .connection_verbose(true)
        .connect_timeout(std::time::Duration::from_secs(10))
        .timeout(timeout)
        .build()
        .unwrap()
}

#[cfg(test)]
mod deadline_tests {
    use super::*;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    async fn stalled_http(mode: u8) {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        let server = tokio::spawn(async move {
            let (mut socket, _) = tokio::time::timeout(Duration::from_secs(1), listener.accept())
                .await
                .unwrap()
                .unwrap();
            let mut request = [0; 1024];
            socket.read(&mut request).await.unwrap();
            if mode == 0 {
                tokio::time::sleep(Duration::from_millis(250)).await;
                return;
            }
            socket
                .write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 10\r\nConnection: close\r\n\r\n")
                .await
                .unwrap();
            if mode == 1 {
                tokio::time::sleep(Duration::from_millis(250)).await;
                return;
            }
            for _ in 0..10 {
                tokio::time::sleep(Duration::from_millis(30)).await;
                if socket.write_all(b"x").await.is_err() {
                    break;
                }
            }
        });
        let client = service_client(Duration::from_millis(80));
        let response = client.get(format!("http://{address}/fixture")).send().await;
        let result = match response {
            Ok(response) => response.text().await,
            Err(error) => Err(error),
        };
        let error = result.expect_err("stalled response unexpectedly completed");
        assert!(error.is_timeout(), "expected total deadline, got {error}");
        server.await.unwrap();
    }
    #[tokio::test]
    async fn http_deadline_covers_headers() {
        stalled_http(0).await;
    }
    #[tokio::test]
    async fn http_deadline_covers_body() {
        stalled_http(1).await;
    }
    #[tokio::test]
    async fn http_deadline_does_not_restart_for_each_chunk() {
        stalled_http(2).await;
    }
}
