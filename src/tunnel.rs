use anyhow::{bail, Result};
use portable_atomic::{AtomicU64, Ordering};
use quiche::h3::NameValue;
use ring::rand::SecureRandom;
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::{Duration, Instant};

use crate::config::Config;
use crate::icmp;
use crate::packet;
use crate::tls;
use crate::udp_socket::bind_udp_socket;

const MAX_DATAGRAM_SIZE: usize = 1350;
const RECONNECT_DELAY: Duration = Duration::from_secs(1);

/// Configuration for a MASQUE tunnel session.
pub struct TunnelConfig {
    pub endpoint: SocketAddr,
    pub sni: String,
    pub keepalive_period: Duration,
    pub mtu: u32,
}

struct Stats {
    tx_packets: AtomicU64,
    rx_packets: AtomicU64,
    tx_bytes: AtomicU64,
    rx_bytes: AtomicU64,
    dropped: AtomicU64,
    quic_lost: AtomicU64,
    quic_retrans: AtomicU64,
}

impl Stats {
    fn new() -> Arc<Self> {
        Arc::new(Self {
            tx_packets: AtomicU64::new(0),
            rx_packets: AtomicU64::new(0),
            tx_bytes: AtomicU64::new(0),
            rx_bytes: AtomicU64::new(0),
            dropped: AtomicU64::new(0),
            quic_lost: AtomicU64::new(0),
            quic_retrans: AtomicU64::new(0),
        })
    }
}

fn format_bytes(bytes: u64) -> String {
    const KIB: u64 = 1024;
    const MIB: u64 = 1024 * KIB;
    const GIB: u64 = 1024 * MIB;
    if bytes >= GIB {
        format!("{:.1} GiB", bytes as f64 / GIB as f64)
    } else if bytes >= MIB {
        format!("{:.1} MiB", bytes as f64 / MIB as f64)
    } else if bytes >= KIB {
        format!("{:.1} KiB", bytes as f64 / KIB as f64)
    } else {
        format!("{bytes} B")
    }
}

fn format_duration(d: Duration) -> String {
    let secs = d.as_secs();
    if secs < 60 {
        format!("{secs}s")
    } else if secs < 3600 {
        format!("{}m {:02}s", secs / 60, secs % 60)
    } else {
        format!(
            "{}h {:02}m {:02}s",
            secs / 3600,
            (secs % 3600) / 60,
            secs % 60
        )
    }
}

/// Run the MASQUE tunnel, reconnecting on-demand when traffic arrives.
pub async fn maintain_tunnel(
    config: &Config,
    tunnel_cfg: &TunnelConfig,
    tun_dev: tun::Device,
) -> Result<()> {
    if tunnel_cfg.keepalive_period.is_zero() {
        bail!("keepalive period must be greater than zero");
    }

    let async_dev = tun::AsyncDevice::new(tun_dev)
        .map_err(|e| anyhow::anyhow!("failed to create async TUN device: {e}"))?;
    let (mut tun_reader, mut tun_writer) = tokio::io::split(async_dev);

    // Buffer for the first packet on reconnection
    let mtu = tunnel_cfg.mtu as usize;
    let mut pending_pkt: Option<Vec<u8>> = None;

    loop {
        // If we have no pending packet, wait for TUN traffic before connecting
        if pending_pkt.is_none() {
            eprint!("\r\x1b[2K[idle] Waiting for traffic...");
            let mut wait_buf = vec![0u8; mtu + 128];
            let n = tokio::io::AsyncReadExt::read(&mut tun_reader, &mut wait_buf).await?;
            if n == 0 {
                bail!("TUN device closed");
            }
            wait_buf.truncate(n);
            pending_pkt = Some(wait_buf);
        }

        eprintln!("\r\x1b[2K[connecting] {} ...", tunnel_cfg.endpoint);

        match run_tunnel_session(
            config,
            tunnel_cfg,
            &mut tun_reader,
            &mut tun_writer,
            &mut pending_pkt,
        )
        .await
        {
            Ok(()) => {
                eprintln!("\r\x1b[2K[disconnected] Session ended");
            }
            Err(e) => {
                eprintln!("\r\x1b[2K[error] {e:#}");
                tokio::time::sleep(RECONNECT_DELAY).await;
            }
        }
        // Loop back to idle
    }
}

async fn run_tunnel_session<R, W>(
    config: &Config,
    tunnel_cfg: &TunnelConfig,
    tun_reader: &mut R,
    tun_writer: &mut W,
    pending_pkt: &mut Option<Vec<u8>>,
) -> Result<()>
where
    R: tokio::io::AsyncRead + Unpin,
    W: tokio::io::AsyncWrite + Unpin,
{
    let tls_material = tls::prepare_tls_material(config)?;

    let mut quic_config = tls::build_quic_config(&tls_material, MAX_DATAGRAM_SIZE)?;

    let bind_addr: SocketAddr = match tunnel_cfg.endpoint {
        SocketAddr::V4(_) => "0.0.0.0:0".parse().unwrap(),
        SocketAddr::V6(_) => "[::]:0".parse().unwrap(),
    };

    let socket = bind_udp_socket(bind_addr, "masque-native-tunnel")?;
    socket.connect(tunnel_cfg.endpoint).await?;
    let local_addr = socket.local_addr()?;

    let mut scid = [0u8; quiche::MAX_CONN_ID_LEN];
    ring::rand::SystemRandom::new()
        .fill(&mut scid)
        .map_err(|_| anyhow::anyhow!("RNG failure"))?;
    let scid = quiche::ConnectionId::from_ref(&scid);

    let mut conn = quiche::connect(
        Some(&tunnel_cfg.sni),
        &scid,
        local_addr,
        tunnel_cfg.endpoint,
        &mut quic_config,
    )
    .map_err(|e| anyhow::anyhow!("quiche connect: {e}"))?;

    let mut out = vec![0u8; MAX_DATAGRAM_SIZE];
    let mut buf = vec![0u8; 65535];

    let (write, send_info) = conn
        .send(&mut out)
        .map_err(|e| anyhow::anyhow!("initial send: {e}"))?;
    socket.send_to(&out[..write], send_info.to).await?;

    // Complete handshake
    loop {
        let timeout = conn.timeout().unwrap_or(Duration::from_millis(100));

        tokio::select! {
            result = socket.recv(&mut buf) => {
                let len = result?;
                let recv_info = quiche::RecvInfo {
                    to: local_addr,
                    from: tunnel_cfg.endpoint,
                };
                if let Err(error) = conn.recv(&mut buf[..len], recv_info) {
                log::debug!("dropping UDP packet rejected by QUIC: {error}");
            }
            }
            () = tokio::time::sleep(timeout) => {
                conn.on_timeout();
            }
        }

        loop {
            match conn.send(&mut out) {
                Ok((write, send_info)) => {
                    socket.send_to(&out[..write], send_info.to).await?;
                }
                Err(quiche::Error::Done) => break,
                Err(e) => bail!("send during handshake: {e}"),
            }
        }

        if conn.is_established() {
            break;
        }
        if conn.is_closed() {
            bail!("connection closed during handshake");
        }
    }

    // Verify endpoint key pinning.
    let peer_cert = conn
        .peer_cert()
        .ok_or_else(|| anyhow::anyhow!("peer did not provide a certificate"))?;
    if !tls::verify_endpoint_key(peer_cert, &tls_material.endpoint_pub_key_spki_der) {
        bail!("peer certificate public key does not match pinned endpoint key");
    }
    log::debug!("Endpoint key pinning verified");

    // Set up HTTP/3
    let mut h3_config = quiche::h3::Config::new().map_err(|e| anyhow::anyhow!("h3 config: {e}"))?;
    h3_config.enable_extended_connect(true);

    let mut h3_conn = quiche::h3::Connection::with_transport(&mut conn, &h3_config)
        .map_err(|e| anyhow::anyhow!("h3 connection: {e}"))?;

    // Send CONNECT request for cf-connect-ip
    let req = vec![
        quiche::h3::Header::new(b":method", b"CONNECT"),
        quiche::h3::Header::new(b":protocol", b"cf-connect-ip"),
        quiche::h3::Header::new(b":scheme", b"https"),
        quiche::h3::Header::new(b":authority", b"cloudflareaccess.com"),
        quiche::h3::Header::new(b":path", b"/"),
        quiche::h3::Header::new(b"capsule-protocol", b"?1"),
        quiche::h3::Header::new(b"user-agent", b""),
    ];

    let stream_id = h3_conn
        .send_request(&mut conn, &req, false)
        .map_err(|e| anyhow::anyhow!("send CONNECT request: {e}"))?;

    let flow_id = stream_id / 4;
    log::debug!("CONNECT request sent on stream {stream_id}, flow_id={flow_id}");

    loop {
        match conn.send(&mut out) {
            Ok((write, send_info)) => {
                socket.send_to(&out[..write], send_info.to).await?;
            }
            Err(quiche::Error::Done) => break,
            Err(e) => bail!("send after CONNECT: {e}"),
        }
    }

    // Wait for 2xx
    let mut connect_established = false;
    for _ in 0..100 {
        let timeout = conn.timeout().unwrap_or(Duration::from_millis(100));

        tokio::select! {
            result = socket.recv(&mut buf) => {
                let len = result?;
                let recv_info = quiche::RecvInfo {
                    to: local_addr,
                    from: tunnel_cfg.endpoint,
                };
                if let Err(error) = conn.recv(&mut buf[..len], recv_info) {
                log::debug!("dropping UDP packet rejected by QUIC: {error}");
            }
            }
            () = tokio::time::sleep(timeout) => {
                conn.on_timeout();
            }
        }

        loop {
            match h3_conn.poll(&mut conn) {
                Ok((sid, quiche::h3::Event::Headers { list, .. })) if sid == stream_id => {
                    for h in &list {
                        if h.name() == b":status" {
                            let status = std::str::from_utf8(h.value()).unwrap_or("?");
                            log::debug!("CONNECT response status: {status}");
                            if status.starts_with('2') {
                                connect_established = true;
                            } else {
                                bail!("CONNECT rejected with status {status}");
                            }
                        }
                    }
                }
                Ok(_) => {}
                Err(quiche::h3::Error::Done) => break,
                Err(e) => bail!("h3 poll error: {e}"),
            }
        }

        // Flush
        loop {
            match conn.send(&mut out) {
                Ok((write, send_info)) => {
                    socket.send_to(&out[..write], send_info.to).await?;
                }
                Err(quiche::Error::Done) => break,
                Err(e) => bail!("send during CONNECT wait: {e}"),
            }
        }

        if connect_established {
            break;
        }
        if conn.is_closed() {
            bail!("connection closed before CONNECT response");
        }
    }

    if !connect_established {
        bail!("timed out waiting for CONNECT response");
    }

    eprintln!("\r\x1b[2K[connected] MASQUE tunnel established");

    let stats = Stats::new();
    let session_start = Instant::now();

    // Spawn stats display task
    let stats_display = stats.clone();
    let stats_handle =
        tokio::spawn(async move {
            let mut interval = tokio::time::interval(Duration::from_secs(1));
            loop {
                interval.tick().await;
                let tx_p = stats_display.tx_packets.load(Ordering::Relaxed);
                let rx_p = stats_display.rx_packets.load(Ordering::Relaxed);
                let tx_b = stats_display.tx_bytes.load(Ordering::Relaxed);
                let rx_b = stats_display.rx_bytes.load(Ordering::Relaxed);
                let dropped = stats_display.dropped.load(Ordering::Relaxed);
                let lost = stats_display.quic_lost.load(Ordering::Relaxed);
                let retrans = stats_display.quic_retrans.load(Ordering::Relaxed);
                let uptime = session_start.elapsed();
                eprint!(
                "\r\x1b[2K[connected {}] tx: {} ({})  rx: {} ({})  drop: {}  lost: {}  retrans: {}",
                format_duration(uptime),
                tx_p, format_bytes(tx_b),
                rx_p, format_bytes(rx_b),
                dropped, lost, retrans,
            );
            }
        });

    // Build the flow_id varint prefix + context_id zero
    let mut flow_prefix = Vec::with_capacity(16);
    {
        let mut tmp = [0u8; 8];
        let mut b = octets::OctetsMut::with_slice(&mut tmp);
        b.put_varint(flow_id).unwrap();
        let len = b.off();
        flow_prefix.extend_from_slice(&tmp[..len]);
    }
    flow_prefix.push(0x00);

    if let Some(mut pkt) = pending_pkt.take() {
        if packet::prepare_outgoing(&mut pkt).is_ok() {
            let mut dgram = Vec::with_capacity(flow_prefix.len() + pkt.len());
            dgram.extend_from_slice(&flow_prefix);
            dgram.extend_from_slice(&pkt);
            let pkt_len = pkt.len() as u64;
            if conn.dgram_send_buf(dgram).is_ok() {
                stats.tx_packets.fetch_add(1, Ordering::Relaxed);
                stats.tx_bytes.fetch_add(pkt_len, Ordering::Relaxed);
            }
        }
    }

    // Main data forwarding loop
    let mtu = tunnel_cfg.mtu as usize;
    let mut tun_buf = vec![0u8; mtu + 128];
    let keepalive_interval = tunnel_cfg.keepalive_period;

    let result: Result<()> = async {
        loop {
            let quic_timeout = conn.timeout();
            let timeout = quic_timeout
                .unwrap_or(keepalive_interval)
                .min(keepalive_interval);

            tokio::select! {
            // Read from TUN -> send to QUIC
            result = tokio::io::AsyncReadExt::read(tun_reader, &mut tun_buf) => {
                let n = result?;
                if n == 0 {
                    bail!("TUN device closed");
                }

                let pkt = &mut tun_buf[..n];
                match packet::prepare_outgoing(pkt) {
                    Ok(_) => {
                        let pkt_len = n as u64;
                        let mut dgram = Vec::with_capacity(flow_prefix.len() + n);
                        dgram.extend_from_slice(&flow_prefix);
                        dgram.extend_from_slice(pkt);

                        match conn.dgram_send_buf(dgram) {
                            Ok(()) => {
                                stats.tx_packets.fetch_add(1, Ordering::Relaxed);
                                stats.tx_bytes.fetch_add(pkt_len, Ordering::Relaxed);
                            }
                            Err(quiche::Error::InvalidState) => {
                                log::warn!("datagram send: peer doesn't support datagrams");
                            }
                            Err(quiche::Error::Done) => {
                                stats.dropped.fetch_add(1, Ordering::Relaxed);
                                log::trace!("datagram send queue full, dropping packet");
                            }
                            Err(e) => {
                                stats.dropped.fetch_add(1, Ordering::Relaxed);
                                log::debug!("datagram send error: {e}, generating ICMP");
                                if let Some(icmp_pkt) = icmp::compose_icmp_too_large(&tun_buf[..n], 1280) {
                                    tokio::io::AsyncWriteExt::write_all(tun_writer, &icmp_pkt)
                                        .await
                                        .map_err(|error| anyhow::anyhow!("failed to write ICMP response to TUN: {error}"))?;
                                }
                            }
                        }
                    }
                    Err(e) => {
                        stats.dropped.fetch_add(1, Ordering::Relaxed);
                        log::trace!("dropping outgoing packet: {e}");
                    }
                }
            }

            // Read from QUIC socket
            result = socket.recv(&mut buf) => {
                let len = result?;
                let recv_info = quiche::RecvInfo {
                    to: local_addr,
                    from: tunnel_cfg.endpoint,
                };
                if let Err(e) = conn.recv(&mut buf[..len], recv_info) {
                    log::debug!("quic recv error: {e}");
                }
            }

            // QUIC loss-recovery timeout and idle keepalive share the wakeup.
            () = tokio::time::sleep(timeout) => {
                if quic_timeout.is_some_and(|duration| duration <= keepalive_interval) {
                    conn.on_timeout();
                }
                if quic_timeout.is_none_or(|duration| keepalive_interval <= duration) {
                    conn.send_ack_eliciting()
                        .map_err(|error| anyhow::anyhow!("failed to schedule QUIC keepalive: {error}"))?;
                }
            }
        }

        // After any event, drain all pending UDP packets from the socket.
        // This prevents stale ACKs and reduces unnecessary retransmissions
        // when the TUN or timeout branch wins the select.
        while let Ok(len) = socket.try_recv(&mut buf) {
            let recv_info = quiche::RecvInfo {
                to: local_addr,
                from: tunnel_cfg.endpoint,
            };
            if let Err(error) = conn.recv(&mut buf[..len], recv_info) {
                log::debug!("dropping UDP packet rejected by QUIC: {error}");
            }
        }

        // Process H3 events (capsules, etc.)
        loop {
            match h3_conn.poll(&mut conn) {
                Ok(_) => {}
                Err(quiche::h3::Error::Done) => break,
                Err(e) => {
                    log::warn!("h3 poll error: {e}");
                    break;
                }
            }
        }

        // Drain received datagrams -> TUN
        loop {
            match conn.dgram_recv_buf() {
                Ok(dgram) => {
                    if let Some(ip_payload) = parse_datagram(&dgram, flow_id) {
                        if packet::validate_incoming(ip_payload).is_ok() {
                            stats.rx_packets.fetch_add(1, Ordering::Relaxed);
                            stats
                                .rx_bytes
                                .fetch_add(ip_payload.len() as u64, Ordering::Relaxed);
                            tokio::io::AsyncWriteExt::write_all(tun_writer, ip_payload)
                                .await
                                .map_err(|error| anyhow::anyhow!("failed to write inbound packet to TUN: {error}"))?;
                        }
                    }
                }
                Err(quiche::Error::Done) => break,
                Err(e) => {
                    log::debug!("dgram recv error: {e}");
                    break;
                }
            }
        }

        // Always flush outgoing QUIC packets
        loop {
            match conn.send(&mut out) {
                Ok((write, send_info)) => {
                    if let Err(e) = socket.send_to(&out[..write], send_info.to).await {
                        log::warn!("UDP send error: {e}");
                        break;
                    }
                }
                Err(quiche::Error::Done) => break,
                Err(e) => {
                    log::error!("quic send error: {e}");
                    bail!("quic send error: {e}");
                }
            }
        }

        // Update QUIC-level stats
        let qs = conn.stats();
        stats.quic_lost.store(qs.lost as u64, Ordering::Relaxed);
        stats
            .quic_retrans
            .store(qs.retrans as u64, Ordering::Relaxed);

            if conn.is_closed() {
                break Ok(());
            }
        }
    }
    .await;

    stats_handle.abort();
    let _ = stats_handle.await;
    result
}

/// Parse an H3 datagram: `varint(flow_id)` + `varint(context_id)` + IP packet
/// Returns the IP payload slice if `flow_id` matches and `context_id` == 0.
fn parse_datagram(dgram: &[u8], expected_flow_id: u64) -> Option<&[u8]> {
    let mut b = octets::Octets::with_slice(dgram);

    let fid = b.get_varint().ok()?;
    if fid != expected_flow_id {
        return None;
    }

    let ctx_id = b.get_varint().ok()?;
    if ctx_id != 0 {
        return None;
    }

    let off = b.off();
    if off >= dgram.len() {
        return None;
    }

    Some(&dgram[off..])
}

#[cfg(test)]
mod tests {
    use super::*;

    // ---- parse_datagram tests ----

    fn encode_varint(val: u64) -> Vec<u8> {
        let mut tmp = [0u8; 8];
        let mut b = octets::OctetsMut::with_slice(&mut tmp);
        b.put_varint(val).unwrap();
        let len = b.off();
        tmp[..len].to_vec()
    }

    fn make_datagram(flow_id: u64, context_id: u64, payload: &[u8]) -> Vec<u8> {
        let mut dgram = Vec::new();
        dgram.extend_from_slice(&encode_varint(flow_id));
        dgram.extend_from_slice(&encode_varint(context_id));
        dgram.extend_from_slice(payload);
        dgram
    }

    #[test]
    fn parse_datagram_valid() {
        let payload = b"hello world";
        let dgram = make_datagram(0, 0, payload);
        let result = parse_datagram(&dgram, 0);
        assert_eq!(result, Some(payload.as_ref()));
    }

    #[test]
    fn parse_datagram_flow_id_mismatch() {
        let dgram = make_datagram(1, 0, b"data");
        assert_eq!(parse_datagram(&dgram, 0), None);
    }

    #[test]
    fn parse_datagram_nonzero_context() {
        let dgram = make_datagram(0, 1, b"data");
        assert_eq!(parse_datagram(&dgram, 0), None);
    }

    #[test]
    fn parse_datagram_empty_payload() {
        let dgram = make_datagram(0, 0, b"");
        // Empty payload means off == dgram.len(), should return None
        assert_eq!(parse_datagram(&dgram, 0), None);
    }

    #[test]
    fn parse_datagram_large_flow_id() {
        // flow_id that requires 4-byte varint encoding
        let flow_id = 16384;
        let payload = vec![0xABu8; 1300];
        let dgram = make_datagram(flow_id, 0, &payload);
        let result = parse_datagram(&dgram, flow_id);
        assert_eq!(result, Some(payload.as_ref()));
    }

    #[test]
    fn parse_datagram_truncated() {
        // Just a single byte - can't even decode flow_id
        let dgram = vec![0xFF];
        assert_eq!(parse_datagram(&dgram, 0), None);
    }

    // ---- format_bytes tests ----

    #[test]
    fn format_bytes_values() {
        assert_eq!(format_bytes(0), "0 B");
        assert_eq!(format_bytes(512), "512 B");
        assert_eq!(format_bytes(1023), "1023 B");
        assert_eq!(format_bytes(1024), "1.0 KiB");
        assert_eq!(format_bytes(1536), "1.5 KiB");
        assert_eq!(format_bytes(1_048_576), "1.0 MiB");
        assert_eq!(format_bytes(1_073_741_824), "1.0 GiB");
    }

    // ---- format_duration tests ----

    #[test]
    fn format_duration_values() {
        assert_eq!(format_duration(Duration::from_secs(0)), "0s");
        assert_eq!(format_duration(Duration::from_secs(59)), "59s");
        assert_eq!(format_duration(Duration::from_secs(60)), "1m 00s");
        assert_eq!(format_duration(Duration::from_secs(90)), "1m 30s");
        assert_eq!(format_duration(Duration::from_secs(3600)), "1h 00m 00s");
        assert_eq!(format_duration(Duration::from_secs(3661)), "1h 01m 01s");
    }
}
