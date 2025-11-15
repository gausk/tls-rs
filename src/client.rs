use anyhow::Result;
use tokio::net::TcpStream;

pub async fn tls_client() -> Result<()> {
    let _tcp_client = TcpStream::connect("127.0.0.1:8080").await?;
    println!("Connected to the server");
    Ok(())
}
