//! A hand-rolled UDP socket that Quinn drives its I/O through.
//!
//! Quinn abstracts packet I/O behind [`AsyncUdpSocket`], so instead of letting
//! it create and own a socket we bind our own and implement the trait over it.
//! Every datagram Quinn sends goes out through [`PacketSocket::send_datagram`],
//! and every datagram Quinn parses is one we read off the wire in
//! [`PacketSocket::poll_recv`] and hand to it.
//!
//! This is deliberately plain `recv_from`/`send_to` I/O: no GSO, no GRO, and no
//! control messages. It gives up some throughput compared to `quinn-udp` in
//! exchange for every packet crossing a single, inspectable choke point.
//!
//! That choke point is where packet authentication happens: every datagram is
//! checked by [`Authenticator`] and dropped on failure, so Quinn only ever
//! parses packets carrying a valid token. See [`crate::auth`]. A socket bound
//! without an authenticator skips the check and hands Quinn everything it
//! reads.

use std::{
    fmt, future,
    io::{self, IoSliceMut},
    net::{SocketAddr, UdpSocket as StdUdpSocket},
    pin::Pin,
    sync::{
        Arc,
        atomic::{AtomicU64, Ordering},
    },
    task::{Context, Poll, ready},
};

use quinn::{
    AsyncUdpSocket, UdpSender,
    udp::{RecvMeta, Transmit},
};

use crate::auth::Authenticator;

/// Cumulative packet counters, as observed at the syscall boundary.
///
/// `received` counts every datagram read off the wire, including the
/// `rejected` ones that failed authentication and never reached Quinn.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PacketCounts {
    pub sent: u64,
    pub sent_bytes: u64,
    pub received: u64,
    pub received_bytes: u64,
    pub rejected: u64,
}

#[derive(Debug, Default)]
struct Counters {
    sent: AtomicU64,
    sent_bytes: AtomicU64,
    received: AtomicU64,
    received_bytes: AtomicU64,
    rejected: AtomicU64,
}

/// A UDP socket owned by this crate, exposed to Quinn as its I/O backend.
///
/// Cloning shares one underlying socket, which is how the application keeps a
/// handle for statistics while Quinn owns the copy it does I/O through.
#[derive(Debug, Clone)]
pub struct PacketSocket {
    inner: Arc<Inner>,
}

#[derive(Debug)]
struct Inner {
    io: tokio::net::UdpSocket,
    authenticator: Option<Authenticator>,
    counters: Counters,
}

impl PacketSocket {
    /// Binds a socket for Quinn to use, authenticating every inbound datagram
    /// with `authenticator`. Must be called from within a Tokio runtime, since
    /// the socket registers with the current reactor.
    ///
    /// Passing `None` disables the check, which hands Quinn every datagram the
    /// socket reads regardless of what it carries. Outbound connection IDs are
    /// unaffected: this only controls whether inbound tokens are verified.
    pub fn bind(addr: SocketAddr, authenticator: Option<Authenticator>) -> io::Result<Self> {
        let socket = StdUdpSocket::bind(addr)?;
        socket.set_nonblocking(true)?;
        Ok(Self {
            inner: Arc::new(Inner {
                io: tokio::net::UdpSocket::from_std(socket)?,
                authenticator,
                counters: Counters::default(),
            }),
        })
    }

    pub fn local_addr(&self) -> io::Result<SocketAddr> {
        self.inner.io.local_addr()
    }

    pub fn counts(&self) -> PacketCounts {
        let counters = &self.inner.counters;
        PacketCounts {
            sent: counters.sent.load(Ordering::Relaxed),
            sent_bytes: counters.sent_bytes.load(Ordering::Relaxed),
            received: counters.received.load(Ordering::Relaxed),
            received_bytes: counters.received_bytes.load(Ordering::Relaxed),
            rejected: counters.rejected.load(Ordering::Relaxed),
        }
    }

    /// Writes exactly one datagram. This is the only place packets leave the
    /// process, so it is where per-packet processing would hook in.
    fn send_datagram(&self, destination: SocketAddr, contents: &[u8]) -> io::Result<()> {
        let sent = self.inner.io.try_send_to(contents, destination)?;
        self.inner.counters.sent.fetch_add(1, Ordering::Relaxed);
        self.inner
            .counters
            .sent_bytes
            .fetch_add(sent as u64, Ordering::Relaxed);
        Ok(())
    }

    fn try_send(&self, transmit: &Transmit<'_>) -> io::Result<()> {
        // `max_transmit_segments` reports 1, so Quinn should never hand us a
        // GSO batch; split one anyway rather than putting an oversized payload
        // on the wire as a single datagram.
        match transmit.segment_size {
            None => self.send_datagram(transmit.destination, transmit.contents),
            Some(segment_size) => {
                for datagram in transmit.contents.chunks(segment_size) {
                    self.send_datagram(transmit.destination, datagram)?;
                }
                Ok(())
            }
        }
    }
}

impl AsyncUdpSocket for PacketSocket {
    fn create_sender(&self) -> Pin<Box<dyn UdpSender>> {
        Box::pin(PacketSender {
            socket: self.clone(),
            writable: None,
        })
    }

    fn poll_recv(
        &mut self,
        cx: &mut Context<'_>,
        bufs: &mut [IoSliceMut<'_>],
        meta: &mut [RecvMeta],
    ) -> Poll<io::Result<usize>> {
        let inner = &*self.inner;
        loop {
            ready!(inner.io.poll_recv_ready(cx))?;

            // `filled` indexes the next slot to hand to Quinn. A rejected
            // datagram leaves it alone, so the slot is reused by whatever comes
            // next and Quinn never learns the packet existed.
            let mut filled = 0;
            while let Some(buf) = bufs.get_mut(filled) {
                match inner.io.try_recv_from(buf) {
                    Ok((len, addr)) => {
                        inner.counters.received.fetch_add(1, Ordering::Relaxed);
                        inner
                            .counters
                            .received_bytes
                            .fetch_add(len as u64, Ordering::Relaxed);

                        // Authentication happens here, on the raw datagram,
                        // before Quinn is given a chance to parse it.
                        if let Some(authenticator) = &inner.authenticator {
                            let datagram = buf.get(..len).expect(
                                "try_recv_from cannot report more bytes than the buffer holds",
                            );
                            if authenticator.check(datagram, addr.ip()).is_err() {
                                inner.counters.rejected.fetch_add(1, Ordering::Relaxed);
                                continue;
                            }
                        }

                        let Some(meta) = meta.get_mut(filled) else {
                            break;
                        };
                        // `RecvMeta` is non-exhaustive, so start from the
                        // default and fill in what plain `recv_from` can tell
                        // us. Everything left at its default — the ECN
                        // codepoint, destination address, interface index and
                        // kernel timestamp — needs control messages we do not
                        // ask for.
                        *meta = RecvMeta::default();
                        meta.addr = addr;
                        meta.len = len;
                        // One datagram per buffer: there is no GRO here, so the
                        // stride is the whole datagram.
                        meta.stride = len;
                        filled += 1;
                    }
                    // The socket drained: `try_recv_from` has already cleared
                    // readiness, so looping re-registers the waker.
                    Err(e) if e.kind() == io::ErrorKind::WouldBlock => break,
                    // A queued ICMP error from a previous send says nothing
                    // about this socket's ability to receive: drop it and keep
                    // going, or an unreachable peer would kill the endpoint.
                    Err(e) if is_transient(&e) => break,
                    Err(e) => {
                        if filled > 0 {
                            break;
                        }
                        return Poll::Ready(Err(e));
                    }
                }
            }

            if filled > 0 {
                return Poll::Ready(Ok(filled));
            }
        }
    }

    fn local_addr(&self) -> io::Result<SocketAddr> {
        self.inner.io.local_addr()
    }

    fn max_receive_segments(&self) -> usize {
        1
    }

    fn may_fragment(&self) -> bool {
        // We never set IP_DONTFRAG / IPV6_DONTFRAG, so report the conservative
        // answer; Quinn responds by disabling MTU discovery.
        true
    }
}

fn is_transient(e: &io::Error) -> bool {
    matches!(
        e.kind(),
        io::ErrorKind::ConnectionRefused
            | io::ErrorKind::ConnectionReset
            | io::ErrorKind::HostUnreachable
            | io::ErrorKind::NetworkUnreachable
    )
}

/// Sends datagrams for one Quinn task.
///
/// Quinn builds one of these per task and warns that they must not clobber each
/// other's wakers, so each owns its own `writable()` future over a shared clone
/// of the socket rather than sharing a single readiness slot.
struct PacketSender {
    socket: PacketSocket,
    writable: Option<Pin<Box<dyn future::Future<Output = io::Result<()>> + Send + Sync>>>,
}

impl fmt::Debug for PacketSender {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("PacketSender")
            .field("socket", &self.socket)
            .finish_non_exhaustive()
    }
}

impl UdpSender for PacketSender {
    fn poll_send(
        self: Pin<&mut Self>,
        transmit: &Transmit<'_>,
        cx: &mut Context<'_>,
    ) -> Poll<io::Result<()>> {
        let this = self.get_mut();
        loop {
            if this.writable.is_none() {
                let socket = this.socket.clone();
                this.writable = Some(Box::pin(async move { socket.inner.io.writable().await }));
            }
            let writable = this
                .writable
                .as_mut()
                .expect("the writable future was just installed");
            let ready = ready!(writable.as_mut().poll(cx));
            // Polling a future after it completes is a logic error, so drop it
            // and build a fresh one if we go round again.
            this.writable = None;
            ready?;

            match this.socket.try_send(transmit) {
                Ok(()) => return Poll::Ready(Ok(())),
                // The socket claimed to be writable but wasn't; go back and
                // wait for a fresh readiness signal.
                Err(e) if e.kind() == io::ErrorKind::WouldBlock => continue,
                // Anything else is about this one datagram, not the endpoint:
                // drop it, exactly as Quinn's own sender does. Tearing down
                // every connection because one packet met an ICMP error or an
                // MTU probe was refused would be far worse than losing it.
                Err(_) => return Poll::Ready(Ok(())),
            }
        }
    }

    fn max_transmit_segments(&self) -> usize {
        1
    }
}
