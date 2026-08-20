//! Packet authentication carried in the QUIC connection ID.
//!
//! # Token format
//!
//! Every connection ID this crate mints is a 20-byte authentication token,
//! which is exactly the QUIC maximum connection ID length:
//!
//! ```text
//! | key selector (2) | nonce (8) | tag (10) |
//! ```
//!
//! The tag authenticates the nonce and the IPv4 addresses of both ends:
//!
//! ```text
//! M   = nonce64 || src_ipv4 || dst_ipv4     (16 bytes, exactly one AES block)
//! tag = Trunc80(AES(F, M))
//! ```
//!
//! # Why this works with QUIC
//!
//! A QUIC connection uses a different connection ID in each direction, and the
//! client picks both of them when it opens the connection: the DCID of its
//! Initial packet is what the server sees on inbound packets, and the SCID of
//! that same Initial becomes the DCID the server puts on packets heading back.
//! So the client mints `DCID_AB` under `F_AB` (client to server) and `DCID_BA`
//! under `F_BA` (server to client). Because both keys are shared, each side can
//! independently mint and verify tokens for the direction it owns, and Quinn's
//! own connection ID rotation keeps working: the CIDs a peer issues mid-
//! connection are minted the same way.
//!
//! Binding both addresses into the tag is what makes a captured token useless
//! from anywhere else: the tag only verifies on the path it was minted for, and
//! the two directions cannot be confused because each uses a different key.
//!
//! # Why this needs a patched Quinn
//!
//! Stock Quinn builds one [`ConnectionIdGenerator`] per endpoint, shared by
//! every connection, and hands `generate_cid` no peer address — so a server
//! could only ever be configured for one client address, and any client sending
//! from elsewhere would have its packets dropped the moment it started using a
//! server-issued connection ID.
//!
//! This crate therefore builds against a Quinn carrying a
//! `ConnectionIdGenerator::generate_cid_for(remote, local_ip)` patch, which
//! tells the generator which peer a connection ID is being minted for. With it,
//! a server serves any number of clients without being told their addresses in
//! advance: it mints each token against the address the connection is actually
//! at, exactly as [`Authenticator`] recomputes it on receipt.
//!
//! Migration is still not supported. A peer that moves must probe from its new
//! address using a connection ID issued for the old one, and no token for the
//! new path can exist until the peer has been seen there. The same applies to
//! NAT rebinding, which is the form this takes in practice.
//!
//! # This is a proof of concept
//!
//! The keys below are compiled into the binaries in the clear, the nonce is
//! never checked for reuse, and tokens never expire, so a captured token is
//! replayable on its own path forever. Real deployments need provisioned keys,
//! replay windows, and key rotation.

use std::{
    net::{IpAddr, Ipv4Addr, SocketAddr},
    sync::Arc,
    time::Duration,
};

use aes::{
    Aes128,
    cipher::{Array, BlockCipherEncrypt, KeyInit},
};
use quinn::{ConnectionId, ConnectionIdGenerator};
use rand::Rng;

/// Full token length, which is also the QUIC maximum connection ID length.
pub const TOKEN_LEN: usize = 20;

const SELECTOR_LEN: usize = 2;
const NONCE_LEN: usize = 8;
/// `Trunc80` of the AES output.
const TAG_LEN: usize = 10;
const AES_BLOCK_LEN: usize = 16;

const SELECTOR_RANGE: std::ops::Range<usize> = 0..SELECTOR_LEN;
const NONCE_RANGE: std::ops::Range<usize> = SELECTOR_LEN..SELECTOR_LEN + NONCE_LEN;
const TAG_RANGE: std::ops::Range<usize> = SELECTOR_LEN + NONCE_LEN..TOKEN_LEN;

const _: () = assert!(
    SELECTOR_LEN + NONCE_LEN + TAG_LEN == TOKEN_LEN,
    "token fields must exactly fill the 20 bytes QUIC allows in a connection ID"
);
const _: () = assert!(
    NONCE_LEN + 2 * 4 == AES_BLOCK_LEN,
    "the authenticated message must be exactly one AES block"
);

/// `F_AB`: authenticates client-to-server packets. Proof-of-concept key, not a
/// secret.
const F_AB: [u8; 16] = [
    0xa0, 0xb1, 0xc2, 0xd3, 0xe4, 0xf5, 0x06, 0x17, 0x28, 0x39, 0x4a, 0x5b, 0x6c, 0x7d, 0x8e, 0x9f,
];

/// `F_BA`: authenticates server-to-client packets. Proof-of-concept key, not a
/// secret.
const F_BA: [u8; 16] = [
    0x5f, 0x4e, 0x3d, 0x2c, 0x1b, 0x0a, 0xf9, 0xe8, 0xd7, 0xc6, 0xb5, 0xa4, 0x93, 0x82, 0x71, 0x60,
];

/// The IPv4 addresses of the two ends. Both sides must agree on these, since
/// they are authenticated by every tag.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Peers {
    pub client: Ipv4Addr,
    pub server: Ipv4Addr,
}

/// Which direction of the connection a token authenticates, and therefore which
/// key it uses.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Direction {
    ClientToServer,
    ServerToClient,
}

impl Direction {
    const fn selector(self) -> u16 {
        match self {
            Self::ClientToServer => 0x0001,
            Self::ServerToClient => 0x0002,
        }
    }

    const fn key(self) -> &'static [u8; 16] {
        match self {
            Self::ClientToServer => &F_AB,
            Self::ServerToClient => &F_BA,
        }
    }

    fn from_selector(selector: u16) -> Option<Self> {
        match selector {
            0x0001 => Some(Self::ClientToServer),
            0x0002 => Some(Self::ServerToClient),
            _ => None,
        }
    }

    /// The `(source, destination)` addresses a packet travelling this direction
    /// carries, which is the order they are fed to the PRF in.
    pub const fn path(self, peers: Peers) -> (Ipv4Addr, Ipv4Addr) {
        match self {
            Self::ClientToServer => (peers.client, peers.server),
            Self::ServerToClient => (peers.server, peers.client),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum AuthError {
    #[error("expected a {TOKEN_LEN}-byte token, got {0} bytes")]
    BadLength(usize),
    #[error("unknown key selector {0:#06x}")]
    UnknownSelector(u16),
    #[error("token authenticates the wrong direction")]
    WrongDirection,
    #[error("tag does not authenticate this nonce and address pair")]
    BadTag,
    #[error("datagram is not recognizable as QUIC")]
    NotQuic,
    #[error("only IPv4 peers can be authenticated, got {0}")]
    NotIpv4(std::net::IpAddr),
}

/// `Trunc80(AES(key, nonce || src || dst))`.
fn tag(key: &[u8; 16], nonce: &[u8], src: Ipv4Addr, dst: Ipv4Addr) -> [u8; TAG_LEN] {
    debug_assert_eq!(nonce.len(), NONCE_LEN, "nonce must be exactly 64 bits");

    let mut message = [0u8; AES_BLOCK_LEN];
    message[..NONCE_LEN].copy_from_slice(nonce);
    message[NONCE_LEN..NONCE_LEN + 4].copy_from_slice(&src.octets());
    message[NONCE_LEN + 4..].copy_from_slice(&dst.octets());

    let mut block = Array::from(message);
    Aes128::new(&Array::from(*key)).encrypt_block(&mut block);

    let mut tag = [0u8; TAG_LEN];
    tag.copy_from_slice(&block[..TAG_LEN]);
    tag
}

fn assemble(direction: Direction, nonce: &[u8], src: Ipv4Addr, dst: Ipv4Addr) -> [u8; TOKEN_LEN] {
    let mut token = [0u8; TOKEN_LEN];
    token[SELECTOR_RANGE].copy_from_slice(&direction.selector().to_be_bytes());
    token[NONCE_RANGE].copy_from_slice(nonce);
    token[TAG_RANGE].copy_from_slice(&tag(direction.key(), nonce, src, dst));
    token
}

/// Mints a fresh token for `direction` between `peers`.
pub fn mint(direction: Direction, peers: Peers) -> [u8; TOKEN_LEN] {
    let (src, dst) = direction.path(peers);
    mint_between(direction, src, dst)
}

/// Mints a fresh token for `direction` on the path `src` to `dst`.
pub fn mint_between(direction: Direction, src: Ipv4Addr, dst: Ipv4Addr) -> [u8; TOKEN_LEN] {
    let mut nonce = [0u8; NONCE_LEN];
    rand::rng().fill_bytes(&mut nonce);
    assemble(direction, &nonce, src, dst)
}

/// Checks that `token` was minted for `direction` on the path `src` to `dst`.
pub fn verify(
    token: &[u8],
    direction: Direction,
    src: Ipv4Addr,
    dst: Ipv4Addr,
) -> Result<(), AuthError> {
    if token.len() != TOKEN_LEN {
        return Err(AuthError::BadLength(token.len()));
    }

    let (Some(selector), Some(nonce), Some(claimed)) = (
        token.get(SELECTOR_RANGE),
        token.get(NONCE_RANGE),
        token.get(TAG_RANGE),
    ) else {
        return Err(AuthError::BadLength(token.len()));
    };

    let selector = u16::from_be_bytes([
        *selector.first().expect("selector field is 2 bytes"),
        *selector.get(1).expect("selector field is 2 bytes"),
    ]);
    match Direction::from_selector(selector) {
        None => return Err(AuthError::UnknownSelector(selector)),
        // Refusing the other direction's key is what stops a token captured on
        // the return path from being replayed back at its own sender.
        Some(found) if found != direction => return Err(AuthError::WrongDirection),
        Some(_) => {}
    }

    let expected = tag(direction.key(), nonce, src, dst);
    match constant_time_eq(claimed, &expected) {
        true => Ok(()),
        false => Err(AuthError::BadTag),
    }
}

fn constant_time_eq(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() {
        return false;
    }
    a.iter()
        .zip(b.iter())
        .fold(0u8, |acc, (x, y)| acc | (x ^ y))
        == 0
}

/// Locates the destination connection ID in a QUIC datagram without decrypting
/// anything.
///
/// This is all the parsing a packet-level filter needs: enough to tell that the
/// datagram is QUIC and to find the token.
pub fn destination_cid(datagram: &[u8]) -> Option<&[u8]> {
    let first = *datagram.first()?;
    match first & 0x80 != 0 {
        // Long header: flags(1) version(4) dcid_len(1) dcid.
        true => {
            let len = usize::from(*datagram.get(5)?);
            if len > TOKEN_LEN {
                return None;
            }
            datagram.get(6..6 + len)
        }
        // Short header: flags(1) then a connection ID whose length is not on the
        // wire. Every ID we issue is a full-length token, so that is what we
        // expect to find here.
        false => datagram.get(1..1 + TOKEN_LEN),
    }
}

/// Authenticates inbound datagrams before Quinn parses them.
#[derive(Debug, Clone, Copy)]
pub struct Authenticator {
    inbound: Direction,
    local_ip: Ipv4Addr,
}

impl Authenticator {
    /// Builds an authenticator for an endpoint at `local_ip` that should only
    /// accept packets travelling `inbound`.
    pub fn new(inbound: Direction, local_ip: Ipv4Addr) -> Self {
        Self { inbound, local_ip }
    }

    /// Returns `Ok` only if `datagram`, received from `src`, carries a token
    /// minted for this path and direction.
    pub fn check(&self, datagram: &[u8], src: std::net::IpAddr) -> Result<(), AuthError> {
        let std::net::IpAddr::V4(src) = src else {
            return Err(AuthError::NotIpv4(src));
        };
        let cid = destination_cid(datagram).ok_or(AuthError::NotQuic)?;
        verify(cid, self.inbound, src, self.local_ip)
    }
}

/// Issues authenticated connection IDs for one direction of a connection.
///
/// Quinn asks this for the connection IDs it advertises to the peer, which the
/// peer then puts in the destination field of every packet it sends us. Every
/// such packet travels from the peer to us, so the tag binds the peer's address
/// as the source and our own as the destination — the same pair
/// [`Authenticator`] recomputes on receipt.
#[derive(Debug)]
pub struct AuthCidGenerator {
    direction: Direction,
    local_ip: Ipv4Addr,
}

impl AuthCidGenerator {
    pub fn new(direction: Direction, local_ip: Ipv4Addr) -> Self {
        Self {
            direction,
            local_ip,
        }
    }
}

impl ConnectionIdGenerator for AuthCidGenerator {
    /// Only reachable on a Quinn without the `generate_cid_for` patch, which
    /// cannot say who the connection ID is for. Rather than guess an address or
    /// panic, mint a token that is guaranteed not to authenticate, so the
    /// failure is a dropped packet rather than a silently unauthenticated one.
    fn generate_cid(&mut self) -> ConnectionId {
        ConnectionId::new(&mint_between(
            self.direction,
            Ipv4Addr::UNSPECIFIED,
            self.local_ip,
        ))
    }

    fn generate_cid_for(&mut self, remote: SocketAddr, _local_ip: Option<IpAddr>) -> ConnectionId {
        let IpAddr::V4(peer) = remote.ip() else {
            // Same reasoning as above: an IPv6 peer cannot be represented in a
            // tag, so issue one that will never verify instead of pretending.
            return ConnectionId::new(&mint_between(
                self.direction,
                Ipv4Addr::UNSPECIFIED,
                self.local_ip,
            ));
        };
        ConnectionId::new(&mint_between(self.direction, peer, self.local_ip))
    }

    fn cid_len(&self) -> usize {
        TOKEN_LEN
    }

    fn cid_lifetime(&self) -> Option<Duration> {
        None
    }

    // `validate` is deliberately left at its permissive default: Quinn only
    // consults it for short-header packets on unknown connections, and by then
    // `Authenticator::check` has already rejected anything unauthenticated.
    // (Its `InvalidCid` error type is not re-exported by `quinn`, so it cannot
    // be implemented here anyway.)
}

/// Builds the provider Quinn uses to pick the destination connection ID of the
/// client's Initial packet, which is the first token the server ever sees.
pub fn initial_dst_cid_provider(peers: Peers) -> Arc<dyn Fn() -> ConnectionId + Send + Sync> {
    Arc::new(move || ConnectionId::new(&mint(Direction::ClientToServer, peers)))
}

#[cfg(test)]
mod tests {
    use super::*;

    const PEERS: Peers = Peers {
        client: Ipv4Addr::new(10, 0, 0, 1),
        server: Ipv4Addr::new(10, 0, 0, 2),
    };

    fn check(token: &[u8], direction: Direction) -> Result<(), AuthError> {
        let (src, dst) = direction.path(PEERS);
        verify(token, direction, src, dst)
    }

    #[test]
    fn minted_tokens_verify_on_their_own_path() {
        for direction in [Direction::ClientToServer, Direction::ServerToClient] {
            let token = mint(direction, PEERS);
            assert_eq!(token.len(), TOKEN_LEN, "token must fill a maximal QUIC CID");
            assert_eq!(
                check(&token, direction),
                Ok(()),
                "a freshly minted token must verify for {direction:?}"
            );
        }
    }

    #[test]
    fn tokens_do_not_verify_for_the_reverse_direction() {
        let token = mint(Direction::ClientToServer, PEERS);
        assert_eq!(
            check(&token, Direction::ServerToClient),
            Err(AuthError::WrongDirection),
            "a client-to-server token must not be replayable at the client"
        );
    }

    #[test]
    fn tokens_are_bound_to_the_address_pair() {
        let token = mint(Direction::ClientToServer, PEERS);
        let elsewhere = Ipv4Addr::new(192, 0, 2, 9);

        assert_eq!(
            verify(&token, Direction::ClientToServer, elsewhere, PEERS.server),
            Err(AuthError::BadTag),
            "a token replayed from another source address must fail"
        );
        assert_eq!(
            verify(&token, Direction::ClientToServer, PEERS.client, elsewhere),
            Err(AuthError::BadTag),
            "a token replayed towards another destination must fail"
        );
        assert_eq!(
            verify(&token, Direction::ClientToServer, PEERS.server, PEERS.client),
            Err(AuthError::BadTag),
            "swapping source and destination must fail"
        );
    }

    #[test]
    fn every_corrupted_byte_is_detected() {
        let token = mint(Direction::ClientToServer, PEERS);
        for byte in 0..TOKEN_LEN {
            let mut corrupted = token;
            corrupted[byte] ^= 0x01;
            assert!(
                check(&corrupted, Direction::ClientToServer).is_err(),
                "flipping a bit in byte {byte} must invalidate the token"
            );
        }
    }

    #[test]
    fn tags_are_deterministic_and_nonce_dependent() {
        let (src, dst) = Direction::ClientToServer.path(PEERS);
        let nonce = [7u8; NONCE_LEN];
        let key = Direction::ClientToServer.key();

        assert_eq!(
            tag(key, &nonce, src, dst),
            tag(key, &nonce, src, dst),
            "the PRF must be deterministic"
        );
        assert_ne!(
            tag(key, &nonce, src, dst),
            tag(key, &[8u8; NONCE_LEN], src, dst),
            "a different nonce must produce a different tag"
        );
        assert_ne!(
            tag(&F_AB, &nonce, src, dst),
            tag(&F_BA, &nonce, src, dst),
            "the two directions must not share a tag space"
        );
    }

    #[test]
    fn malformed_tokens_are_rejected_rather_than_panicking() {
        for len in [0usize, 1, TOKEN_LEN - 1, TOKEN_LEN + 1] {
            assert_eq!(
                check(&vec![0u8; len], Direction::ClientToServer),
                Err(AuthError::BadLength(len)),
                "a {len}-byte token must be rejected on length alone"
            );
        }

        let mut token = mint(Direction::ClientToServer, PEERS);
        token[SELECTOR_RANGE].copy_from_slice(&0xbeefu16.to_be_bytes());
        assert_eq!(
            check(&token, Direction::ClientToServer),
            Err(AuthError::UnknownSelector(0xbeef)),
            "an unknown key selector must be named in the error"
        );
    }

    /// The payoff of the `generate_cid_for` patch: one endpoint issues connection
    /// IDs bound to whichever peer each connection is with, so a server needs no
    /// advance knowledge of its clients' addresses.
    #[test]
    fn generated_cids_bind_the_peer_they_are_issued_for() {
        let server = Ipv4Addr::new(10, 0, 0, 2);
        let alice = Ipv4Addr::new(10, 0, 0, 1);
        let bob = Ipv4Addr::new(198, 51, 100, 7);
        let mut generator = AuthCidGenerator::new(Direction::ClientToServer, server);

        let for_alice = generator.generate_cid_for(SocketAddr::from((alice, 4433)), None);
        let for_bob = generator.generate_cid_for(SocketAddr::from((bob, 4433)), None);

        assert_eq!(
            verify(&for_alice, Direction::ClientToServer, alice, server),
            Ok(()),
            "a CID issued for Alice must authenticate packets from Alice"
        );
        assert_eq!(
            verify(&for_bob, Direction::ClientToServer, bob, server),
            Ok(()),
            "the same generator must also serve Bob, at a different address"
        );
        assert_eq!(
            verify(&for_alice, Direction::ClientToServer, bob, server),
            Err(AuthError::BadTag),
            "Bob must not be able to authenticate with a CID issued for Alice"
        );
    }

    #[test]
    fn cids_generated_without_a_peer_address_never_authenticate() {
        let server = Ipv4Addr::new(10, 0, 0, 2);
        let client = Ipv4Addr::new(10, 0, 0, 1);
        let mut generator = AuthCidGenerator::new(Direction::ClientToServer, server);

        // Reached only on an unpatched Quinn, which cannot say who the CID is
        // for. Failing closed is the point: the packet is dropped rather than
        // admitted on an address the tag never covered.
        let blind = generator.generate_cid();
        assert_eq!(
            verify(&blind, Direction::ClientToServer, client, server),
            Err(AuthError::BadTag),
            "a CID minted without knowing the peer must never authenticate one"
        );
    }

    #[test]
    fn destination_cid_is_located_in_both_header_forms() {
        let token = mint(Direction::ClientToServer, PEERS);

        let mut long = vec![0xc0, 0x00, 0x00, 0x00, 0x01, TOKEN_LEN as u8];
        long.extend_from_slice(&token);
        long.extend_from_slice(&[0xaa; 32]);
        assert_eq!(
            destination_cid(&long),
            Some(&token[..]),
            "a long header carries an explicit connection ID length"
        );

        let mut short = vec![0x40];
        short.extend_from_slice(&token);
        short.extend_from_slice(&[0xaa; 32]);
        assert_eq!(
            destination_cid(&short),
            Some(&token[..]),
            "a short header connection ID is implicitly our own token length"
        );
    }

    #[test]
    fn truncated_datagrams_do_not_panic() {
        assert_eq!(destination_cid(&[]), None, "an empty datagram has no CID");
        assert_eq!(
            destination_cid(&[0xc0, 0x00, 0x00, 0x00, 0x01, TOKEN_LEN as u8, 0x00]),
            None,
            "a long header truncated mid-CID must be rejected"
        );
        assert_eq!(
            destination_cid(&[0x40, 0x00]),
            None,
            "a short header truncated mid-CID must be rejected"
        );
        assert_eq!(
            destination_cid(&[0xc0, 0x00, 0x00, 0x00, 0x01, 21]),
            None,
            "a CID length above the QUIC maximum must be rejected"
        );
    }
}
