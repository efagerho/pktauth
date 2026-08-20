//! End-to-end tests: a real QUIC server and client over the loopback interface,
//! both running on sockets this crate owns, reads, writes, and authenticates
//! itself.

use std::net::{Ipv4Addr, SocketAddr, UdpSocket};

use quinn::{Connection, Endpoint};
use rustls::pki_types::CertificateDer;

use pktauth::{
    auth::{Authenticator, Direction, Peers, TOKEN_LEN},
    socket::PacketSocket,
};

const LOCALHOST: Ipv4Addr = Ipv4Addr::LOCALHOST;

const PEERS: Peers = Peers {
    client: LOCALHOST,
    server: LOCALHOST,
};

fn ephemeral() -> SocketAddr {
    SocketAddr::from((LOCALHOST, 0))
}

struct Server {
    addr: SocketAddr,
    socket: PacketSocket,
    cert: CertificateDer<'static>,
}

/// Starts an echo server on an ephemeral loopback port.
fn start_server() -> Server {
    start_server_with(Some(Authenticator::new(
        Direction::ClientToServer,
        LOCALHOST,
    )))
}

fn start_server_with(authenticator: Option<Authenticator>) -> Server {
    let credentials = pktauth::self_signed_server_config(vec!["localhost".to_string()])
        .expect("server config must build from a fresh self-signed certificate");
    let socket = PacketSocket::bind(ephemeral(), authenticator).expect("server socket must bind");
    let addr = socket.local_addr().expect("bound socket has a local address");
    let endpoint = pktauth::server_endpoint(socket.clone(), credentials.config, LOCALHOST)
        .expect("server endpoint must build");

    tokio::spawn(pktauth::run_echo_server(endpoint));

    Server {
        addr,
        socket,
        cert: credentials.cert_der,
    }
}

async fn connect(server: &Server) -> (PacketSocket, Endpoint, Connection) {
    let socket = PacketSocket::bind(
        ephemeral(),
        Some(Authenticator::new(Direction::ServerToClient, LOCALHOST)),
    )
    .expect("client socket must bind");
    let endpoint = pktauth::client_endpoint(
        socket.clone(),
        pktauth::client_config([server.cert.clone()]).expect("client config must build"),
        PEERS,
    )
    .expect("client endpoint must build");
    let connection = endpoint
        .connect(server.addr, "localhost")
        .expect("connect must start")
        .await
        .expect("handshake must succeed");

    (socket, endpoint, connection)
}

#[tokio::test]
async fn server_reflects_payloads_of_varying_size() {
    let server = start_server();
    let (_socket, _endpoint, connection) = connect(&server).await;

    for (seq, size) in [0usize, 1, 64, 1500, pktauth::MAX_PING_BYTES]
        .into_iter()
        .enumerate()
    {
        let payload = pktauth::ping_payload(seq as u64, size);
        pktauth::ping(&connection, &payload)
            .await
            .unwrap_or_else(|e| panic!("ping of {size} bytes must be echoed verbatim: {e}"));
    }
}

#[tokio::test]
async fn server_handles_concurrent_pings_on_one_connection() {
    let server = start_server();
    let (_socket, _endpoint, connection) = connect(&server).await;

    let pings = (0..32u64).map(|seq| {
        let connection = connection.clone();
        tokio::spawn(async move {
            let payload = pktauth::ping_payload(seq, 256);
            pktauth::ping(&connection, &payload).await
        })
    });

    for (seq, ping) in pings.enumerate() {
        ping.await
            .expect("ping task must not panic")
            .unwrap_or_else(|e| panic!("concurrent ping seq={seq} must be echoed: {e}"));
    }
}

#[tokio::test]
async fn server_keeps_serving_after_a_client_disconnects() {
    let server = start_server();

    for round in 0..3u64 {
        let (_socket, endpoint, connection) = connect(&server).await;

        let payload = pktauth::ping_payload(round, 128);
        pktauth::ping(&connection, &payload)
            .await
            .unwrap_or_else(|e| panic!("ping in round {round} must be echoed: {e}"));

        // Drop the connection abruptly, without a graceful close, to check the
        // accept loop survives a client vanishing mid-connection.
        drop(connection);
        endpoint.close(0u32.into(), b"round over");
    }
}

/// Guards the point of this design: Quinn must be doing its I/O through our
/// socket, not one of its own.
#[tokio::test]
async fn every_datagram_passes_through_our_socket() {
    let server = start_server();
    let (socket, _endpoint, connection) = connect(&server).await;

    let before = socket.counts();
    let payload = pktauth::ping_payload(0, 4096);
    pktauth::ping(&connection, &payload)
        .await
        .expect("ping must be echoed");
    let after = socket.counts();

    assert!(
        after.sent > before.sent && after.received > before.received,
        "the ping must have moved packets through our own socket, but counts went from {before:?} to {after:?}"
    );
    assert!(
        after.sent_bytes >= payload.len() as u64,
        "our socket must have written at least the payload itself: {after:?}"
    );
    // The handshake alone already crosses the socket several times.
    assert!(
        before.sent > 0 && before.received > 0,
        "the handshake must have gone through our own socket: {before:?}"
    );
}

/// The whole connection, handshake included, only works if every connection ID
/// Quinn puts on the wire carries a tag the far end accepts. A single
/// successful ping is therefore an end-to-end proof of the token scheme.
#[tokio::test]
async fn an_authenticated_connection_is_never_rejected() {
    let server = start_server();
    let (client_socket, _endpoint, connection) = connect(&server).await;

    for seq in 0..8u64 {
        pktauth::ping(&connection, &pktauth::ping_payload(seq, 512))
            .await
            .unwrap_or_else(|e| panic!("authenticated ping seq={seq} must be echoed: {e}"));
    }

    assert_eq!(
        server.socket.counts().rejected,
        0,
        "the server must not have rejected any of its peer's authenticated packets"
    );
    assert_eq!(
        client_socket.counts().rejected,
        0,
        "the client must not have rejected any of the server's authenticated packets"
    );
}

/// Datagrams without a valid tag must be dropped before Quinn parses them, and
/// must not disturb a healthy connection.
#[tokio::test]
async fn forged_packets_are_dropped_before_quinn_sees_them() {
    let server = start_server();
    let (_socket, _endpoint, connection) = connect(&server).await;

    // Establish a working baseline first, so a later failure is attributable to
    // the forged traffic rather than to setup.
    pktauth::ping(&connection, &pktauth::ping_payload(0, 128))
        .await
        .expect("the connection must work before any forgery");
    let before = server.socket.counts();

    let attacker = UdpSocket::bind(ephemeral()).expect("attacker socket must bind");
    let forgeries: Vec<Vec<u8>> = vec![
        // Long header, plausible token length, garbage tag.
        {
            let mut packet = vec![0xc0, 0x00, 0x00, 0x00, 0x01, TOKEN_LEN as u8];
            packet.extend_from_slice(&[0x00; TOKEN_LEN]);
            packet.extend_from_slice(&[0xaa; 1180]);
            packet
        },
        // Short header with a garbage connection ID.
        {
            let mut packet = vec![0x40];
            packet.extend_from_slice(&[0x5a; TOKEN_LEN]);
            packet.extend_from_slice(&[0xaa; 64]);
            packet
        },
        // A token minted for the wrong direction: the server key is only valid
        // on packets heading back to the client.
        {
            let mut packet = vec![0xc0, 0x00, 0x00, 0x00, 0x01, TOKEN_LEN as u8];
            packet.extend_from_slice(&pktauth::auth::mint(Direction::ServerToClient, PEERS));
            packet.extend_from_slice(&[0xaa; 1180]);
            packet
        },
        // Not QUIC at all.
        b"definitely not a quic packet".to_vec(),
    ];

    for forgery in &forgeries {
        attacker
            .send_to(forgery, server.addr)
            .expect("attacker must be able to send");
    }

    // Drive the connection until the server has read the forgeries; the pings
    // double as the proof that the connection survived them.
    for seq in 1..16u64 {
        pktauth::ping(&connection, &pktauth::ping_payload(seq, 128))
            .await
            .unwrap_or_else(|e| panic!("ping seq={seq} must still be echoed after forgery: {e}"));
        if server.socket.counts().rejected >= before.rejected + forgeries.len() as u64 {
            break;
        }
    }

    let after = server.socket.counts();
    assert_eq!(
        after.rejected - before.rejected,
        forgeries.len() as u64,
        "every forged datagram must have been rejected, counts went from {before:?} to {after:?}"
    );
}

/// Waits for `socket` to have read at least `at_least` datagrams, so a test can
/// assert on what happened to a packet it sent rather than racing the receive
/// loop.
async fn wait_for_received(socket: &PacketSocket, at_least: u64) {
    let poll = async {
        while socket.counts().received < at_least {
            tokio::time::sleep(std::time::Duration::from_millis(10)).await;
        }
    };
    tokio::time::timeout(std::time::Duration::from_secs(2), poll)
        .await
        .unwrap_or_else(|_| {
            panic!(
                "socket should have read {at_least} datagrams by now, counts are {:?}",
                socket.counts()
            )
        });
}

/// The server's `--no-dcid-validation` mode. The very packet that
/// `forged_packets_are_dropped_before_quinn_sees_them` has rejected is passed
/// straight through to Quinn instead.
#[tokio::test]
async fn dcid_validation_can_be_turned_off() {
    let server = start_server_with(None);

    let mut forgery = vec![0xc0, 0x00, 0x00, 0x00, 0x01, TOKEN_LEN as u8];
    forgery.extend_from_slice(&[0x00; TOKEN_LEN]);
    forgery.extend_from_slice(&[0xaa; 1180]);

    let attacker = UdpSocket::bind(ephemeral()).expect("attacker socket must bind");
    attacker
        .send_to(&forgery, server.addr)
        .expect("attacker must be able to send");

    wait_for_received(&server.socket, 1).await;
    assert_eq!(
        server.socket.counts().rejected,
        0,
        "with validation off, an unauthenticated datagram must reach Quinn rather than be dropped"
    );

    // Quinn discarding the garbage on its own must leave the server serving.
    let (_socket, _endpoint, connection) = connect(&server).await;
    pktauth::ping(&connection, &pktauth::ping_payload(0, 128))
        .await
        .expect("the server must still serve clients with validation off");
    assert_eq!(
        server.socket.counts().rejected,
        0,
        "nothing at all should be rejected while validation is off"
    );
}

/// Negative control for the whole scheme: a client whose tokens are minted for
/// a different address pair cannot complete a handshake at all, because the
/// server drops its Initial before Quinn ever parses it.
#[tokio::test]
async fn a_client_with_mismatched_bindings_cannot_connect() {
    let server = start_server();

    let wrong = Peers {
        client: Ipv4Addr::new(192, 0, 2, 9),
        server: LOCALHOST,
    };
    let socket = PacketSocket::bind(
        ephemeral(),
        Some(Authenticator::new(Direction::ServerToClient, LOCALHOST)),
    )
    .expect("client socket must bind");
    let endpoint = pktauth::client_endpoint(
        socket,
        pktauth::client_config([server.cert.clone()]).expect("client config must build"),
        wrong,
    )
    .expect("client endpoint must build");

    let connecting = endpoint
        .connect(server.addr, "localhost")
        .expect("connect must start");
    let outcome = tokio::time::timeout(std::time::Duration::from_secs(2), connecting).await;

    assert!(
        outcome.is_err(),
        "the handshake must stall rather than succeed, got {outcome:?}"
    );
    assert!(
        server.socket.counts().rejected > 0,
        "the server must have dropped the mismatched client's packets"
    );
}

/// A token is only valid on the path it was minted for, so the same client key
/// used from a different source address must not get through.
#[tokio::test]
async fn tokens_minted_for_another_address_are_rejected() {
    let server = start_server();

    let elsewhere = Peers {
        client: Ipv4Addr::new(192, 0, 2, 9),
        server: LOCALHOST,
    };
    let mut packet = vec![0xc0, 0x00, 0x00, 0x00, 0x01, TOKEN_LEN as u8];
    packet.extend_from_slice(&pktauth::auth::mint(Direction::ClientToServer, elsewhere));
    packet.extend_from_slice(&[0xaa; 1180]);

    let attacker = UdpSocket::bind(ephemeral()).expect("attacker socket must bind");
    attacker
        .send_to(&packet, server.addr)
        .expect("attacker must be able to send");

    // A connection afterwards both drives the server's receive loop and shows
    // the endpoint was unharmed.
    let (_socket, _endpoint, connection) = connect(&server).await;
    pktauth::ping(&connection, &pktauth::ping_payload(0, 128))
        .await
        .expect("the server must still serve authenticated clients");

    assert_eq!(
        server.socket.counts().rejected,
        1,
        "a token minted for a different source address must not authenticate"
    );
}
