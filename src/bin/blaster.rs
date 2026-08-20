//! Floods a QUIC endpoint with Initial packets carrying random destination
//! connection IDs, none of which will carry a valid authentication tag.
//!
//! This exists to measure the packet authentication filter under load: how many
//! unauthenticated packets a second a server can reject, and what that costs it.
//! Point it at your own endpoints.
//!
//! Everything but the connection ID is fixed, so each packet costs one
//! `send` syscall plus 20 bytes of PRNG output written into a buffer that is
//! otherwise built once at startup. There is no QUIC stack involved: the
//! template is assembled by hand and written straight to a connected
//! `UdpSocket`.

use std::{
    error::Error,
    net::{SocketAddr, UdpSocket},
    sync::{
        Arc,
        atomic::{AtomicBool, AtomicU64, Ordering},
    },
    thread,
    time::{Duration, Instant},
};

use clap::Parser;
use pktauth::auth::TOKEN_LEN;

/// Smallest datagram a QUIC Initial may be sent in, per RFC 9000.
const MIN_INITIAL_DATAGRAM: usize = 1200;

/// Datagrams sent between checks of the stop flag and the rate limiter.
const BATCH: u64 = 64;

#[derive(Parser)]
#[command(
    about = "Floods a QUIC endpoint with Initial packets bearing random connection IDs",
    long_about = "Floods a QUIC endpoint with Initial packets bearing random connection IDs.\n\n\
                  Intended for load-testing the packet authentication filter on endpoints you \
                  operate: the connection IDs are random, so none of them carry a valid tag and \
                  every packet should be rejected before the QUIC layer parses it."
)]
struct Args {
    /// Endpoint to flood.
    #[arg(long, default_value = "127.0.0.1:4433")]
    target: SocketAddr,

    /// Sender threads; each gets its own socket. Defaults to the machine's
    /// parallelism.
    #[arg(long)]
    threads: Option<usize>,

    /// How long to run, in seconds; 0 runs until interrupted.
    #[arg(long, default_value_t = 10)]
    duration: u64,

    /// Datagram size in bytes.
    #[arg(long, default_value_t = MIN_INITIAL_DATAGRAM)]
    size: usize,

    /// Packets per second across all threads; 0 sends as fast as the machine
    /// allows.
    #[arg(long, default_value_t = 0)]
    pps: u64,
}

#[derive(Debug, Default)]
struct Stats {
    sent: AtomicU64,
    bytes: AtomicU64,
    errors: AtomicU64,
}

/// A QUIC Initial packet with one mutable field.
///
/// The bytes are laid out once; blasting only rewrites the destination
/// connection ID in place, which is the only part a packet authenticator looks
/// at before deciding whether to drop the datagram.
struct InitialTemplate {
    bytes: Vec<u8>,
    dcid_offset: usize,
}

impl InitialTemplate {
    fn new(size: usize) -> Result<Self, String> {
        if size < MIN_INITIAL_DATAGRAM {
            return Err(format!(
                "--size must be at least {MIN_INITIAL_DATAGRAM} bytes, the minimum RFC 9000 \
                 allows for a datagram carrying an Initial packet, got {size}"
            ));
        }
        if size > u16::MAX as usize {
            return Err(format!("--size must fit in a UDP datagram, got {size}"));
        }

        let mut bytes = Vec::with_capacity(size);

        // Long header, fixed bit set, type Initial, 4-byte packet number.
        bytes.push(0xc3);
        // Version 1.
        bytes.extend_from_slice(&1u32.to_be_bytes());
        // Destination connection ID, full length so it looks exactly like a
        // token; contents are overwritten per packet.
        bytes.push(TOKEN_LEN as u8);
        let dcid_offset = bytes.len();
        bytes.extend_from_slice(&[0u8; TOKEN_LEN]);
        // Source connection ID, fixed for the run.
        bytes.push(TOKEN_LEN as u8);
        bytes.extend_from_slice(&[0x5a; TOKEN_LEN]);
        // Token length: a varint zero, since this is not a response to a Retry.
        bytes.push(0x00);

        // Length covers the packet number and payload, as a 2-byte varint.
        const PACKET_NUMBER_LEN: usize = 4;
        let remaining = size
            .checked_sub(bytes.len() + 2)
            .ok_or_else(|| format!("--size {size} is too small to hold an Initial header"))?;
        let length = u16::try_from(remaining)
            .map_err(|_| format!("--size {size} needs a longer varint than this tool emits"))?;
        assert!(
            length < 0x4000,
            "the length field must fit a 2-byte varint, which {size}-byte datagrams satisfy"
        );
        bytes.extend_from_slice(&(0x4000 | length).to_be_bytes());

        // Packet number, then payload. A real Initial would be AEAD-protected;
        // these bytes only have to survive header parsing, since the packet is
        // meant to be dropped before anyone tries to decrypt it.
        bytes.extend_from_slice(&[0u8; PACKET_NUMBER_LEN]);
        bytes.resize(size, 0x42);

        assert_eq!(
            bytes.len(),
            size,
            "the assembled template must be exactly the requested datagram size"
        );
        Ok(Self { bytes, dcid_offset })
    }

    /// Overwrites the destination connection ID with fresh pseudorandom bytes.
    #[inline]
    fn randomize_dcid(&mut self, rng: &mut SplitMix64) {
        let dcid = self
            .bytes
            .get_mut(self.dcid_offset..self.dcid_offset + TOKEN_LEN)
            .expect("the template always reserves a full-length connection ID");
        for chunk in dcid.chunks_mut(8) {
            let word = rng.next().to_ne_bytes();
            let len = chunk.len();
            chunk.copy_from_slice(
                word.get(..len)
                    .expect("chunks_mut never yields more than 8 bytes"),
            );
        }
    }
}

/// A very fast non-cryptographic PRNG.
///
/// The connection IDs only have to miss a 80-bit tag, which anything
/// unpredictable to the target does; spending ChaCha on 20 bytes per packet
/// would cost more than the syscall being measured.
struct SplitMix64(u64);

impl SplitMix64 {
    #[inline]
    fn next(&mut self) -> u64 {
        self.0 = self.0.wrapping_add(0x9e37_79b9_7f4a_7c15);
        let mut z = self.0;
        z = (z ^ (z >> 30)).wrapping_mul(0xbf58_476d_1ce4_e5b9);
        z = (z ^ (z >> 27)).wrapping_mul(0x94d0_49bb_1331_11eb);
        z ^ (z >> 31)
    }
}

fn blast(
    target: SocketAddr,
    size: usize,
    pps: u64,
    seed: u64,
    running: Arc<AtomicBool>,
    stats: Arc<Stats>,
) -> Result<(), Box<dyn Error + Send + Sync>> {
    let socket = UdpSocket::bind(match target.is_ipv4() {
        true => "0.0.0.0:0",
        false => "[::]:0",
    })?;
    // Connecting lets each datagram go out with `send` rather than `send_to`,
    // which skips re-resolving the destination on every syscall.
    socket.connect(target)?;

    let mut template = InitialTemplate::new(size)?;
    let mut rng = SplitMix64(seed);
    let start = Instant::now();
    let mut sent = 0u64;

    while running.load(Ordering::Relaxed) {
        for _ in 0..BATCH {
            template.randomize_dcid(&mut rng);
            match socket.send(&template.bytes) {
                Ok(n) => {
                    stats.sent.fetch_add(1, Ordering::Relaxed);
                    stats.bytes.fetch_add(n as u64, Ordering::Relaxed);
                }
                // A local error says nothing about the target and must not stop
                // the run: an ICMP port-unreachable from a previous packet
                // surfaces here, and the whole point is to keep sending.
                Err(_) => {
                    stats.errors.fetch_add(1, Ordering::Relaxed);
                }
            }
        }
        sent += BATCH;

        if pps > 0 {
            // Pace against an absolute schedule so the rate does not drift.
            let target_elapsed = Duration::from_secs_f64(sent as f64 / pps as f64);
            if let Some(sleep) = target_elapsed.checked_sub(start.elapsed()) {
                thread::sleep(sleep);
            }
        }
    }

    Ok(())
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn Error>> {
    let args = Args::parse();

    // Fail before spawning anything if the template cannot be built.
    InitialTemplate::new(args.size)?;

    let threads = match args.threads {
        Some(0) | None => thread::available_parallelism().map_or(1, |n| n.get()),
        Some(n) => n,
    };
    let per_thread_pps = match args.pps {
        0 => 0,
        pps => (pps / threads as u64).max(1),
    };

    println!(
        "blasting {} with {}-byte Initials from {threads} thread(s){}",
        args.target,
        args.size,
        match args.pps {
            0 => String::from(", unpaced"),
            pps => format!(", target {pps} packets/s"),
        }
    );

    let stats = Arc::new(Stats::default());
    let running = Arc::new(AtomicBool::new(true));
    let mut seed = SplitMix64(0x243f_6a88_85a3_08d3);

    let workers: Vec<_> = (0..threads)
        .map(|i| {
            let (target, size) = (args.target, args.size);
            let (running, stats) = (running.clone(), stats.clone());
            let seed = seed.next();
            thread::Builder::new()
                .name(format!("blaster-{i}"))
                .spawn(move || blast(target, size, per_thread_pps, seed, running, stats))
        })
        .collect::<Result<_, _>>()?;

    let reporter = tokio::spawn(report(stats.clone()));

    let started = Instant::now();
    let deadline = async {
        match args.duration {
            0 => std::future::pending::<()>().await,
            secs => tokio::time::sleep(Duration::from_secs(secs)).await,
        }
    };
    tokio::select! {
        () = deadline => {}
        result = tokio::signal::ctrl_c() => result?,
    }

    running.store(false, Ordering::Relaxed);
    reporter.abort();
    for worker in workers {
        match worker.join() {
            Ok(Ok(())) => {}
            Ok(Err(e)) => eprintln!("sender failed: {e}"),
            Err(_) => eprintln!("a sender thread panicked"),
        }
    }

    let elapsed = started.elapsed().as_secs_f64();
    let sent = stats.sent.load(Ordering::Relaxed);
    let bytes = stats.bytes.load(Ordering::Relaxed);
    let errors = stats.errors.load(Ordering::Relaxed);
    println!("--- blaster summary ---");
    println!(
        "{sent} packets ({:.1} MiB) in {elapsed:.2}s, {errors} send errors",
        bytes as f64 / (1024.0 * 1024.0)
    );
    println!(
        "{:.0} packets/s, {:.1} MiB/s",
        sent as f64 / elapsed,
        bytes as f64 / elapsed / (1024.0 * 1024.0)
    );
    Ok(())
}

/// Prints a throughput line every second.
async fn report(stats: Arc<Stats>) {
    let mut last_sent = 0u64;
    let mut last_bytes = 0u64;
    loop {
        tokio::time::sleep(Duration::from_secs(1)).await;
        let sent = stats.sent.load(Ordering::Relaxed);
        let bytes = stats.bytes.load(Ordering::Relaxed);
        println!(
            "{:>9} packets/s  {:>7.1} MiB/s  ({sent} total)",
            sent - last_sent,
            (bytes - last_bytes) as f64 / (1024.0 * 1024.0)
        );
        last_sent = sent;
        last_bytes = bytes;
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_template_is_a_parseable_quic_initial() {
        let template = InitialTemplate::new(MIN_INITIAL_DATAGRAM)
            .expect("a minimum-size datagram must be buildable");
        assert_eq!(
            template.bytes.len(),
            MIN_INITIAL_DATAGRAM,
            "the datagram must be exactly the requested size"
        );

        // The point of the exercise: the connection ID must land where a packet
        // authenticator looks for it.
        let dcid = pktauth::auth::destination_cid(&template.bytes)
            .expect("the target's own parser must find a connection ID");
        assert_eq!(
            dcid.len(),
            TOKEN_LEN,
            "the connection ID must be token-sized so it reaches the tag check"
        );
        assert_eq!(
            dcid.as_ptr(),
            template.bytes[template.dcid_offset..].as_ptr(),
            "the parser must find the connection ID exactly where we write it"
        );
    }

    #[test]
    fn randomizing_rewrites_only_the_connection_id() {
        let mut template =
            InitialTemplate::new(MIN_INITIAL_DATAGRAM).expect("template must build");
        let original = template.bytes.clone();
        let mut rng = SplitMix64(1);
        template.randomize_dcid(&mut rng);

        let (offset, end) = (template.dcid_offset, template.dcid_offset + TOKEN_LEN);
        assert_ne!(
            &template.bytes[offset..end],
            &original[offset..end],
            "the connection ID must change"
        );
        assert_eq!(
            &template.bytes[..offset],
            &original[..offset],
            "the header before the connection ID must be untouched"
        );
        assert_eq!(
            &template.bytes[end..],
            &original[end..],
            "everything after the connection ID must be untouched"
        );
    }

    #[test]
    fn generated_connection_ids_do_not_repeat() {
        let mut template =
            InitialTemplate::new(MIN_INITIAL_DATAGRAM).expect("template must build");
        let mut rng = SplitMix64(42);
        let mut seen = std::collections::HashSet::new();
        for _ in 0..10_000 {
            template.randomize_dcid(&mut rng);
            let dcid = template.bytes[template.dcid_offset..][..TOKEN_LEN].to_vec();
            assert!(seen.insert(dcid), "connection IDs must not repeat");
        }
    }

    #[test]
    fn undersized_datagrams_are_refused() {
        assert!(
            InitialTemplate::new(MIN_INITIAL_DATAGRAM - 1).is_err(),
            "a datagram below the RFC 9000 minimum for an Initial must be refused"
        );
    }
}
