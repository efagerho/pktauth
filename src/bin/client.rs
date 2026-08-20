//! QUIC ping client: sends payloads to the echo server and reports round-trip
//! times.

use std::{
    error::Error,
    fs,
    net::{IpAddr, Ipv4Addr, SocketAddr},
    path::PathBuf,
    time::Duration,
};

use clap::Parser;
use pktauth::{
    auth::{Authenticator, Direction, Peers},
    socket::{PacketCounts, PacketSocket},
};
use rustls::pki_types::CertificateDer;

#[derive(Parser)]
#[command(about = "QUIC ping client for the pktauth echo server")]
struct Args {
    /// Address of the echo server.
    #[arg(long, default_value = "127.0.0.1:4433")]
    server: SocketAddr,

    /// Server certificate (DER) to trust, as written by the server.
    #[arg(long, default_value = "server_cert.der")]
    cert: PathBuf,

    /// Server name to validate the certificate against.
    #[arg(long, default_value = "localhost")]
    server_name: String,

    /// Number of pings to send; 0 means keep pinging until interrupted.
    #[arg(long, default_value_t = 5)]
    count: u64,

    /// Delay between pings, in milliseconds.
    #[arg(long, default_value_t = 500)]
    interval_ms: u64,

    /// Ping payload size in bytes.
    #[arg(long, default_value_t = 64)]
    size: usize,

    /// IPv4 address to send from. Packet authentication binds both addresses
    /// into every tag, so the socket is bound to exactly this address.
    #[arg(long, default_value = "127.0.0.1")]
    local_ip: Ipv4Addr,
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn Error>> {
    let args = Args::parse();

    if args.size > pktauth::MAX_PING_BYTES {
        return Err(format!(
            "payload size {} exceeds the protocol maximum of {} bytes",
            args.size,
            pktauth::MAX_PING_BYTES
        )
        .into());
    }

    // The tag covers both addresses, so the server must be reached over IPv4.
    let IpAddr::V4(server_ip) = args.server.ip() else {
        return Err(format!("--server must be an IPv4 address, got {}", args.server.ip()).into());
    };
    let peers = Peers {
        client: args.local_ip,
        server: server_ip,
    };

    let cert = CertificateDer::from(fs::read(&args.cert)?);
    let authenticator = Authenticator::new(Direction::ServerToClient, args.local_ip);
    let socket = PacketSocket::bind(SocketAddr::new(args.local_ip.into(), 0), Some(authenticator))?;
    let endpoint =
        pktauth::client_endpoint(socket.clone(), pktauth::client_config([cert])?, peers)?;

    let connection = endpoint.connect(args.server, &args.server_name)?.await?;
    println!(
        "connected to {} ({} bytes per ping)",
        connection.remote_address(),
        args.size
    );

    let interval = Duration::from_millis(args.interval_ms);
    let mut rtts = Vec::new();
    let mut lost = 0u64;
    let mut seq = 0u64;

    while args.count == 0 || seq < args.count {
        if seq > 0 && !interval.is_zero() {
            tokio::time::sleep(interval).await;
        }

        let payload = pktauth::ping_payload(seq, args.size);
        match pktauth::ping(&connection, &payload).await {
            Ok(rtt) => {
                println!(
                    "echo from {}: seq={seq} bytes={} rtt={:.3}ms",
                    connection.remote_address(),
                    payload.len(),
                    rtt.as_secs_f64() * 1e3
                );
                rtts.push(rtt);
            }
            Err(e) => {
                // A lost or corrupted ping is reported and counted, never fatal:
                // the next one may well succeed.
                eprintln!("ping seq={seq} failed: {e}");
                lost += 1;
            }
        }
        seq += 1;
    }

    connection.close(0u32.into(), b"done");
    endpoint.wait_idle().await;

    print_summary(seq, &rtts, lost, socket.counts());
    Ok(())
}

fn print_summary(sent: u64, rtts: &[Duration], lost: u64, counts: PacketCounts) {
    let loss_pct = if sent == 0 {
        0.0
    } else {
        lost as f64 * 100.0 / sent as f64
    };
    println!("--- ping statistics ---");
    println!("{sent} sent, {} echoed, {loss_pct:.1}% loss", rtts.len());
    println!(
        "udp packets: {} sent ({} bytes), {} received ({} bytes), {} rejected as unauthenticated",
        counts.sent, counts.sent_bytes, counts.received, counts.received_bytes, counts.rejected
    );

    if rtts.is_empty() {
        return;
    }
    let min = rtts.iter().min().expect("rtts is non-empty");
    let max = rtts.iter().max().expect("rtts is non-empty");
    let avg = rtts.iter().sum::<Duration>() / rtts.len() as u32;
    println!(
        "rtt min/avg/max = {:.3}/{:.3}/{:.3} ms",
        min.as_secs_f64() * 1e3,
        avg.as_secs_f64() * 1e3,
        max.as_secs_f64() * 1e3
    );
}
