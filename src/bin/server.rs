//! QUIC echo server: reflects back the payload of every ping stream.

use std::{
    error::Error,
    fs,
    net::{IpAddr, SocketAddr},
    path::PathBuf,
};

use clap::Parser;
use pktauth::{
    auth::{Authenticator, Direction},
    socket::PacketSocket,
};

#[derive(Parser)]
#[command(about = "QUIC ping responder that echoes back every payload it receives")]
struct Args {
    /// Address to listen on.
    #[arg(long, default_value = "127.0.0.1:4433")]
    listen: SocketAddr,

    /// Where to write the generated self-signed certificate (DER) for clients
    /// to pin.
    #[arg(long, default_value = "server_cert.der")]
    cert_out: PathBuf,

    /// Subject alternative name to issue the certificate for; the client must
    /// use this as its server name.
    #[arg(long, default_value = "localhost")]
    server_name: String,

    /// Accept inbound packets without validating the authentication token in
    /// their destination connection ID.
    ///
    /// The server still issues authenticated connection IDs; only the check on
    /// arriving packets is skipped. Intended for debugging and for measuring
    /// what the check costs, not for deployment.
    #[arg(long)]
    no_dcid_validation: bool,
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn Error>> {
    let args = Args::parse();

    // The tag covers both addresses, so the server must listen on a concrete
    // IPv4 address rather than a wildcard.
    let IpAddr::V4(server_ip) = args.listen.ip() else {
        return Err(format!("--listen must be an IPv4 address, got {}", args.listen.ip()).into());
    };
    if server_ip.is_unspecified() {
        return Err("--listen must name a concrete IPv4 address, not a wildcard, because packet authentication binds the server address into every tag".into());
    }

    let credentials = pktauth::self_signed_server_config(vec![args.server_name.clone()])?;
    fs::write(&args.cert_out, &credentials.cert_der)?;
    println!(
        "wrote self-signed certificate for {} to {}",
        args.server_name,
        args.cert_out.display()
    );

    let authenticator = match args.no_dcid_validation {
        false => Some(Authenticator::new(Direction::ClientToServer, server_ip)),
        true => None,
    };
    let socket = PacketSocket::bind(args.listen, authenticator)?;
    println!("listening on {}", socket.local_addr()?);
    match args.no_dcid_validation {
        false => println!("authenticating inbound packets with the client key"),
        true => eprintln!(
            "WARNING: --no-dcid-validation is set. Inbound packets are passed to QUIC without \
             checking their authentication token, so any sender that can reach this port is \
             accepted. Use this for debugging only."
        ),
    }
    let endpoint = pktauth::server_endpoint(socket.clone(), credentials.config, server_ip)?;

    tokio::select! {
        () = pktauth::run_echo_server(endpoint.clone()) => {}
        result = tokio::signal::ctrl_c() => {
            result?;
            println!("shutting down");
        }
    }

    endpoint.close(0u32.into(), b"server shutting down");
    endpoint.wait_idle().await;

    let counts = socket.counts();
    println!(
        "udp packets: {} received ({} bytes), {} sent ({} bytes), {} rejected as unauthenticated",
        counts.received, counts.received_bytes, counts.sent, counts.sent_bytes, counts.rejected
    );
    Ok(())
}
