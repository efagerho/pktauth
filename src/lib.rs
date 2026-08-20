//! Shared QUIC plumbing for the `server` (echo responder) and `client` (pinger)
//! binaries.
//!
//! Ping protocol: the client opens one bidirectional stream per ping, writes the
//! ping payload, and finishes the stream. The server reads the stream to its end
//! and writes the same bytes back on the stream's response half. The round-trip
//! time is measured by the client from stream open to the last echoed byte.
//!
//! Both binaries bind their own UDP socket and perform every send and receive
//! themselves; Quinn runs on top of it as the QUIC protocol implementation. See
//! [`socket::PacketSocket`] for the I/O layer and [`server_endpoint`] /
//! [`client_endpoint`] for how it is mounted into Quinn.

pub mod auth;
pub mod socket;

use std::{
    io,
    net::Ipv4Addr,
    sync::{Arc, Once},
    time::{Duration, Instant},
};

use quinn::{
    ClientConfig, Connection, ConnectionError, Endpoint, EndpointConfig, IdleTimeout, RecvStream,
    SendStream, ServerConfig, TokioRuntime, TransportConfig,
    crypto::rustls::{NoInitialCipherSuite, QuicClientConfig, QuicServerConfig},
};
use rustls::pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer};

use crate::{
    auth::{AuthCidGenerator, Direction, Peers},
    socket::PacketSocket,
};

/// ALPN identifier negotiated by both ends of the ping protocol.
pub const ALPN: &[u8] = b"pktauth-ping/1";

/// Upper bound on a single ping payload, applied when reading either direction
/// so a peer cannot force unbounded buffering.
pub const MAX_PING_BYTES: usize = 64 * 1024;

const IDLE_TIMEOUT: Duration = Duration::from_secs(30);
const KEEP_ALIVE_INTERVAL: Duration = Duration::from_secs(5);

#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error("failed to generate a self-signed certificate: {0}")]
    Rcgen(#[from] rcgen::Error),
    #[error("TLS configuration error: {0}")]
    Tls(#[from] rustls::Error),
    #[error("TLS configuration has no cipher suite usable for QUIC: {0}")]
    NoInitialCipherSuite(#[from] NoInitialCipherSuite),
    #[error("failed to start connecting: {0}")]
    Connect(#[from] quinn::ConnectError),
    #[error("connection lost: {0}")]
    Connection(#[from] ConnectionError),
    #[error("failed to write to stream: {0}")]
    Write(#[from] quinn::WriteError),
    #[error("failed to read stream: {0}")]
    Read(#[from] quinn::ReadToEndError),
    #[error("stream was already closed: {0}")]
    ClosedStream(#[from] quinn::ClosedStream),
    #[error("echo mismatch: sent {} bytes, got {} bytes back", .sent.len(), .echoed.len())]
    EchoMismatch { sent: Vec<u8>, echoed: Vec<u8> },
    #[error("socket error: {0}")]
    Io(#[from] io::Error),
}

pub type Result<T> = std::result::Result<T, Error>;

/// A server configuration together with the certificate clients must trust to
/// reach it.
pub struct ServerCredentials {
    pub config: ServerConfig,
    pub cert_der: CertificateDer<'static>,
}

/// rustls needs a process-wide crypto provider; both binaries and the tests may
/// reach this concurrently, so installing is done exactly once and a provider
/// installed by someone else is left alone.
fn install_crypto_provider() {
    static INSTALL: Once = Once::new();
    INSTALL.call_once(|| {
        let _ = rustls::crypto::ring::default_provider().install_default();
    });
}

fn transport_config() -> TransportConfig {
    let mut transport = TransportConfig::default();
    transport.max_idle_timeout(Some(
        IdleTimeout::try_from(IDLE_TIMEOUT).expect("IDLE_TIMEOUT fits in a QUIC varint"),
    ));
    transport.keep_alive_interval(Some(KEEP_ALIVE_INTERVAL));
    transport
}

/// Builds a server config backed by a freshly generated self-signed certificate
/// valid for `subject_alt_names`.
pub fn self_signed_server_config(subject_alt_names: Vec<String>) -> Result<ServerCredentials> {
    install_crypto_provider();

    let certified = rcgen::generate_simple_self_signed(subject_alt_names)?;
    let key = PrivatePkcs8KeyDer::from(certified.signing_key.serialize_der());
    let cert_der = CertificateDer::from(certified.cert);

    let mut crypto = rustls::ServerConfig::builder()
        .with_no_client_auth()
        .with_single_cert(vec![cert_der.clone()], PrivateKeyDer::from(key))?;
    crypto.alpn_protocols = vec![ALPN.to_vec()];

    let mut config = ServerConfig::with_crypto(Arc::new(QuicServerConfig::try_from(crypto)?));
    config.transport_config(Arc::new(transport_config()));

    Ok(ServerCredentials { config, cert_der })
}

/// Builds a client config that trusts exactly `trusted_certs` — the server's
/// self-signed certificate is pinned rather than verified against a CA.
pub fn client_config(
    trusted_certs: impl IntoIterator<Item = CertificateDer<'static>>,
) -> Result<ClientConfig> {
    install_crypto_provider();

    let mut roots = rustls::RootCertStore::empty();
    for cert in trusted_certs {
        roots.add(cert)?;
    }

    let mut crypto = rustls::ClientConfig::builder()
        .with_root_certificates(roots)
        .with_no_client_auth();
    crypto.alpn_protocols = vec![ALPN.to_vec()];

    let mut config = ClientConfig::new(Arc::new(QuicClientConfig::try_from(crypto)?));
    config.transport_config(Arc::new(transport_config()));

    Ok(config)
}

/// Mounts `socket` into Quinn as a listening endpoint.
///
/// Quinn does not own or create the socket: it calls back into
/// [`PacketSocket`] for every datagram it sends, and parses the datagrams that
/// socket reads off the wire.
///
/// The connection IDs this endpoint advertises are authentication tokens for
/// the client-to-server direction, so every packet the client sends carries one
/// in its destination connection ID field. Each is minted against the address
/// its own connection is at, so one server serves any number of clients without
/// being told their addresses in advance.
pub fn server_endpoint(
    socket: PacketSocket,
    config: ServerConfig,
    local_ip: Ipv4Addr,
) -> Result<Endpoint> {
    let mut endpoint_config = EndpointConfig::default();
    endpoint_config.cid_generator(Arc::new(move || {
        Box::new(AuthCidGenerator::new(Direction::ClientToServer, local_ip))
    }));

    Ok(Endpoint::new_with_abstract_socket(
        endpoint_config,
        Some(config),
        Box::new(socket),
        Arc::new(TokioRuntime),
    )?)
}

/// Mounts `socket` into Quinn as a client-side endpoint.
///
/// The client picks the connection IDs for both directions: the tokens it
/// advertises authenticate the server-to-client direction, while the
/// destination connection ID of its Initial packet authenticates the
/// client-to-server direction.
pub fn client_endpoint(
    socket: PacketSocket,
    mut config: ClientConfig,
    peers: Peers,
) -> Result<Endpoint> {
    let mut endpoint_config = EndpointConfig::default();
    endpoint_config.cid_generator(Arc::new(move || {
        Box::new(AuthCidGenerator::new(
            Direction::ServerToClient,
            peers.client,
        ))
    }));
    config.initial_dst_cid_provider(auth::initial_dst_cid_provider(peers));

    let endpoint = Endpoint::new_with_abstract_socket(
        endpoint_config,
        None,
        Box::new(socket),
        Arc::new(TokioRuntime),
    )?;
    endpoint.set_default_client_config(config);
    Ok(endpoint)
}

/// Builds a ping payload of `size` bytes whose first 8 bytes carry `seq`.
///
/// Payloads shorter than 8 bytes carry a truncated sequence number; the echo
/// check compares full payloads, so this only affects readability of a capture.
pub fn ping_payload(seq: u64, size: usize) -> Vec<u8> {
    let mut payload = vec![0u8; size];
    let seq_bytes = seq.to_be_bytes();
    let header = seq_bytes.len().min(size);
    payload[..header].copy_from_slice(&seq_bytes[..header]);
    for (i, byte) in payload[header..].iter_mut().enumerate() {
        *byte = (i % 251) as u8;
    }
    payload
}

/// Accepts connections until `endpoint` is closed, echoing every stream of each.
///
/// Per-connection outcomes are deliberately silent. Anything a remote peer can
/// provoke once per packet must not write once per packet: with packet
/// authentication disabled, every unauthenticated Initial reaches Quinn and
/// fails its handshake, so logging each failure turns a packet flood into a
/// write-amplified one. Worse, `eprintln!` takes a process-wide lock, so every
/// handshake task queues behind it and the delay lands on legitimate traffic.
/// Measured at 250k unauthenticated packets/s, that logging cost 0.15 of a core
/// and pushed the echo round-trip from 0.55 ms to 16 ms.
///
/// Failures are dropped rather than reported: one misbehaving or disappearing
/// client must not take the server down. Callers wanting visibility should count
/// outcomes, not print them.
pub async fn run_echo_server(endpoint: Endpoint) {
    while let Some(incoming) = endpoint.accept().await {
        tokio::spawn(async move {
            if let Ok(connection) = incoming.await {
                let _ = serve_connection(connection).await;
            }
        });
    }
}

/// Echoes every bidirectional stream opened by the peer until it goes away.
pub async fn serve_connection(connection: Connection) -> Result<()> {
    loop {
        let (send, recv) = match connection.accept_bi().await {
            Ok(streams) => streams,
            // A peer that closed cleanly, or an endpoint shutting down, is a
            // normal end of service rather than a failure.
            Err(
                ConnectionError::ApplicationClosed(_)
                | ConnectionError::ConnectionClosed(_)
                | ConnectionError::LocallyClosed,
            ) => return Ok(()),
            Err(e) => return Err(e.into()),
        };

        let remote = connection.remote_address();
        tokio::spawn(async move {
            if let Err(e) = echo_stream(send, recv).await {
                eprintln!("stream from {remote} failed: {e}");
            }
        });
    }
}

async fn echo_stream(mut send: SendStream, mut recv: RecvStream) -> Result<()> {
    let payload = recv.read_to_end(MAX_PING_BYTES).await?;
    send.write_all(&payload).await?;
    send.finish()?;
    Ok(())
}

/// Sends one ping and waits for the echo, returning the round-trip time.
pub async fn ping(connection: &Connection, payload: &[u8]) -> Result<Duration> {
    let start = Instant::now();

    let (mut send, mut recv) = connection.open_bi().await?;
    send.write_all(payload).await?;
    send.finish()?;
    let echoed = recv.read_to_end(MAX_PING_BYTES).await?;

    let rtt = start.elapsed();
    if echoed != payload {
        return Err(Error::EchoMismatch {
            sent: payload.to_vec(),
            echoed,
        });
    }
    Ok(rtt)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ping_payload_carries_sequence_number() {
        let payload = ping_payload(0x0102_0304_0506_0708, 16);
        assert_eq!(payload.len(), 16, "payload must be exactly the requested size");
        assert_eq!(
            &payload[..8],
            &[1, 2, 3, 4, 5, 6, 7, 8],
            "first 8 bytes must be the big-endian sequence number"
        );
    }

    #[test]
    fn ping_payload_handles_sizes_below_the_header() {
        assert!(
            ping_payload(u64::MAX, 0).is_empty(),
            "a zero-size payload must not panic on the truncated header"
        );
        assert_eq!(
            ping_payload(u64::MAX, 3),
            vec![0xff, 0xff, 0xff],
            "a short payload must carry a truncated sequence number"
        );
    }
}
