//! TCP listener that drops connections from outside the allow-list before
//! any HTTP is spoken, with optional TLS.

use std::io;
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::{Duration, Instant};

use axum::extract::connect_info::Connected;
use axum::serve::IncomingStream;
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::mpsc;
use tokio_rustls::server::TlsStream;
use tokio_rustls::TlsAcceptor;
use tokio_util::either::Either;

use crate::netutil::{allowed, Prefix};

/// Remote address of a connection (axum ConnectInfo).
#[derive(Debug, Clone, Copy)]
pub struct PeerAddr(pub SocketAddr);

pub type Conn = Either<TcpStream, TlsStream<TcpStream>>;

pub struct FilteredListener {
    rx: mpsc::Receiver<(Conn, SocketAddr)>,
    local: SocketAddr,
}

impl FilteredListener {
    pub async fn bind(
        addr: SocketAddr,
        allow: Vec<Prefix>,
        tls: Option<TlsAcceptor>,
    ) -> Result<Self, String> {
        let l = TcpListener::bind(addr)
            .await
            .map_err(|e| format!("listen {addr}: {e}"))?;
        let local = l.local_addr().map_err(|e| e.to_string())?;
        let (tx, rx) = mpsc::channel(64);
        tokio::spawn(async move {
            let mut last_log = Instant::now() - Duration::from_secs(60);
            loop {
                let (s, peer) = match l.accept().await {
                    Ok(x) => x,
                    Err(e) => {
                        eprintln!("fsview: accept: {e}");
                        tokio::time::sleep(Duration::from_millis(100)).await;
                        continue;
                    }
                };
                if !allowed(peer.ip(), &allow) {
                    if last_log.elapsed() > Duration::from_secs(10) {
                        eprintln!("fsview: rejected connection from {peer} (not in allow-list)");
                        last_log = Instant::now();
                    }
                    continue; // dropping the stream closes it
                }
                let tx = tx.clone();
                match &tls {
                    None => {
                        if tx.send((Either::Left(s), peer)).await.is_err() {
                            return;
                        }
                    }
                    Some(acc) => {
                        let acc = acc.clone();
                        tokio::spawn(async move {
                            if let Ok(Ok(t)) =
                                tokio::time::timeout(Duration::from_secs(10), acc.accept(s)).await
                            {
                                let _ = tx.send((Either::Right(t), peer)).await;
                            }
                        });
                    }
                }
            }
        });
        Ok(FilteredListener { rx, local })
    }
}

impl axum::serve::Listener for FilteredListener {
    type Io = Conn;
    type Addr = SocketAddr;

    async fn accept(&mut self) -> (Self::Io, Self::Addr) {
        match self.rx.recv().await {
            Some(x) => x,
            None => std::future::pending().await,
        }
    }

    fn local_addr(&self) -> io::Result<Self::Addr> {
        Ok(self.local)
    }
}

impl Connected<IncomingStream<'_, FilteredListener>> for PeerAddr {
    fn connect_info(s: IncomingStream<'_, FilteredListener>) -> Self {
        PeerAddr(*s.remote_addr())
    }
}

/// Loads a PEM certificate chain and key.
pub fn tls_acceptor(cert: &str, key: &str) -> Result<TlsAcceptor, String> {
    let certs = rustls_pemfile::certs(&mut io::BufReader::new(
        std::fs::File::open(cert).map_err(|e| format!("{cert}: {e}"))?,
    ))
    .collect::<Result<Vec<_>, _>>()
    .map_err(|e| format!("{cert}: {e}"))?;
    let key = rustls_pemfile::private_key(&mut io::BufReader::new(
        std::fs::File::open(key).map_err(|e| format!("{key}: {e}"))?,
    ))
    .map_err(|e| format!("{key}: {e}"))?
    .ok_or_else(|| format!("{key}: no private key found"))?;
    let provider = Arc::new(rustls::crypto::ring::default_provider());
    let cfg = rustls::ServerConfig::builder_with_provider(provider)
        .with_safe_default_protocol_versions()
        .map_err(|e| e.to_string())?
        .with_no_client_auth()
        .with_single_cert(certs, key)
        .map_err(|e| format!("TLS: {e}"))?;
    Ok(TlsAcceptor::from(Arc::new(cfg)))
}
