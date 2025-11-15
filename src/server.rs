use anyhow::Result;
use tokio::net::TcpListener;

pub async fn tls_server() -> Result<()> {
    let tcp_server = TcpListener::bind("127.0.0.1:8080").await?;
    tcp_server.accept().await?;
    Ok(())
}
