use std::io;
use std::sync::Arc;

use tokio::net::TcpStream;
use tokio_rustls::client::TlsStream;
use tokio_rustls::rustls::pki_types::ServerName;
use tokio_rustls::rustls::{ClientConfig, RootCertStore};
use tokio_rustls::TlsConnector;

pub fn webpki_client_config() -> Arc<ClientConfig> {
    let mut roots = RootCertStore::empty();
    roots.extend(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());
    Arc::new(
        ClientConfig::builder()
            .with_root_certificates(roots)
            .with_no_client_auth(),
    )
}

pub async fn connect_tls(
    host: &str,
    port: u16,
    server_name: &str,
    config: Arc<ClientConfig>,
) -> io::Result<TlsStream<TcpStream>> {
    let tcp = TcpStream::connect((host, port)).await?;
    tcp.set_nodelay(true).ok();
    let name = ServerName::try_from(server_name.to_owned())
        .map_err(|_| io::Error::new(io::ErrorKind::InvalidInput, "invalid server name"))?;
    TlsConnector::from(config).connect(name, tcp).await
}
