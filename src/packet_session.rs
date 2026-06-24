use anyhow::{bail, Result};
use bytes::Bytes;
use octets::Octets;
use quiche::h3::NameValue;
use ring::rand::SecureRandom;
use std::collections::VecDeque;
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;
use tokio::sync::{mpsc, watch};
use tokio::sync::mpsc::error::TrySendError;

use crate::config::Config;
use crate::packet;
use crate::tls;

const MAX_DATAGRAM_SIZE: usize = 1350;
const DEFAULT_QUEUE_CAPACITY: usize = 32768;

#[derive(Debug, Clone)]
pub struct PacketSessionConfig {
    pub endpoint: SocketAddr,
    pub bind: Option<SocketAddr>,
    pub sni: String,
    pub keepalive_period: Duration,
    pub mtu: u32,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PacketSessionState {
    Idle,
    Connecting,
    Handshaking,
    Ready,
    Reconnecting,
    Closed,
}

#[derive(Debug, Clone)]
pub enum PacketSessionCloseReason {
    Requested,
    InputClosed,
    OutputClosed,
    InternalError(String),
}

#[derive(Debug)]
pub enum PacketSessionEvent {
    Packet(Bytes),
    Closed(PacketSessionCloseReason),
}

#[derive(Debug, Clone)]
pub enum PacketSessionControl {
    Close,
}

pub struct PacketSessionHandle {
    pub packet_tx: mpsc::Sender<Bytes>,
    pub event_rx: mpsc::Receiver<PacketSessionEvent>,
    pub state_rx: watch::Receiver<PacketSessionState>,
    pub control_tx: mpsc::Sender<PacketSessionControl>,
}

enum SessionLoopOutcome {
    Reconnect(String),
    Close(PacketSessionCloseReason),
}

pub fn start_packet_session(
    config: Arc<Config>,
    session_cfg: PacketSessionConfig,
) -> PacketSessionHandle {
    let (packet_tx, packet_rx) = mpsc::channel(DEFAULT_QUEUE_CAPACITY);
    let (event_tx, event_rx) = mpsc::channel(DEFAULT_QUEUE_CAPACITY);
    let (control_tx, control_rx) = mpsc::channel(8);
    let (state_tx, state_rx) = watch::channel(PacketSessionState::Idle);

    tokio::spawn(run_packet_session_manager(
        config,
        session_cfg,
        packet_rx,
        event_tx,
        control_rx,
        state_tx,
    ));

    PacketSessionHandle {
        packet_tx,
        event_rx,
        state_rx,
        control_tx,
    }
}

async fn run_packet_session_manager(
    config: Arc<Config>,
    session_cfg: PacketSessionConfig,
    mut packet_rx: mpsc::Receiver<Bytes>,
    event_tx: mpsc::Sender<PacketSessionEvent>,
    mut control_rx: mpsc::Receiver<PacketSessionControl>,
    state_tx: watch::Sender<PacketSessionState>,
) {
    let mut pending_packet: Option<Bytes> = None;

    loop {
        if pending_packet.is_none() {
            let _ = state_tx.send(PacketSessionState::Idle);
            tokio::select! {
                maybe_packet = packet_rx.recv() => {
                    match maybe_packet {
                        Some(packet) => pending_packet = Some(packet),
                        None => {
                            emit_closed(&event_tx, &state_tx, PacketSessionCloseReason::InputClosed).await;
                            return;
                        }
                    }
                }
                maybe_control = control_rx.recv() => {
                    if matches!(maybe_control, Some(PacketSessionControl::Close)) {
                        emit_closed(&event_tx, &state_tx, PacketSessionCloseReason::Requested).await;
                        return;
                    }
                }
            }
        }

        match run_packet_session_once(
            config.as_ref(),
            &session_cfg,
            &mut pending_packet,
            &mut packet_rx,
            &event_tx,
            &mut control_rx,
            &state_tx,
        )
        .await
        {
            SessionLoopOutcome::Reconnect(reason) => {
                log::warn!("packet session reconnecting: {reason}");
                let _ = state_tx.send(PacketSessionState::Reconnecting);
                tokio::time::sleep(Duration::from_secs(1)).await;
            }
            SessionLoopOutcome::Close(reason) => {
                emit_closed(&event_tx, &state_tx, reason).await;
                return;
            }
        }
    }
}

async fn emit_closed(
    event_tx: &mpsc::Sender<PacketSessionEvent>,
    state_tx: &watch::Sender<PacketSessionState>,
    reason: PacketSessionCloseReason,
) {
    let _ = state_tx.send(PacketSessionState::Closed);
    let _ = event_tx.send(PacketSessionEvent::Closed(reason)).await;
}

async fn run_packet_session_once(
    config: &Config,
    session_cfg: &PacketSessionConfig,
    pending_packet: &mut Option<Bytes>,
    packet_rx: &mut mpsc::Receiver<Bytes>,
    event_tx: &mpsc::Sender<PacketSessionEvent>,
    control_rx: &mut mpsc::Receiver<PacketSessionControl>,
    state_tx: &watch::Sender<PacketSessionState>,
) -> SessionLoopOutcome {
    let tls_material = match tls::prepare_tls_material(config) {
        Ok(material) => material,
        Err(error) => {
            return SessionLoopOutcome::Close(PacketSessionCloseReason::InternalError(format!(
                "failed to prepare TLS material: {error:#}"
            )));
        }
    };

    let mut quic_config = match build_quic_config(&tls_material) {
        Ok(config) => config,
        Err(error) => {
            return SessionLoopOutcome::Close(PacketSessionCloseReason::InternalError(format!(
                "failed to build quic config: {error:#}"
            )));
        }
    };

    let bind_addr: SocketAddr = session_cfg
        .bind
        .unwrap_or_else(|| match session_cfg.endpoint {
            SocketAddr::V4(_) => "0.0.0.0:0".parse().unwrap(),
            SocketAddr::V6(_) => "[::]:0".parse().unwrap(),
        });

    let socket = match tokio::net::UdpSocket::bind(bind_addr).await {
        Ok(socket) => socket,
        Err(error) => {
            return SessionLoopOutcome::Reconnect(format!("bind failed: {error}"));
        }
    };
    if let Err(error) = socket.connect(session_cfg.endpoint).await {
        return SessionLoopOutcome::Reconnect(format!("connect failed: {error}"));
    }
    let local_addr = match socket.local_addr() {
        Ok(addr) => addr,
        Err(error) => {
            return SessionLoopOutcome::Reconnect(format!("local_addr failed: {error}"));
        }
    };

    let mut scid = [0u8; quiche::MAX_CONN_ID_LEN];
    if ring::rand::SystemRandom::new().fill(&mut scid).is_err() {
        return SessionLoopOutcome::Close(PacketSessionCloseReason::InternalError(
            "RNG failure".to_string(),
        ));
    }
    let scid = quiche::ConnectionId::from_ref(&scid);

    let mut conn = match quiche::connect(
        Some(&session_cfg.sni),
        &scid,
        local_addr,
        session_cfg.endpoint,
        &mut quic_config,
    ) {
        Ok(conn) => conn,
        Err(error) => {
            return SessionLoopOutcome::Reconnect(format!("quiche connect failed: {error}"));
        }
    };

    let mut out = vec![0u8; MAX_DATAGRAM_SIZE];
    let mut buf = vec![0u8; 65535];

    if let Err(error) = flush_conn_send(&socket, &mut conn, &mut out).await {
        return SessionLoopOutcome::Reconnect(format!("initial send failed: {error}"));
    }

    let _ = state_tx.send(PacketSessionState::Connecting);
    let handshake_outcome = complete_handshake(
        &socket,
        &mut conn,
        &mut out,
        &mut buf,
        local_addr,
        session_cfg.endpoint,
        control_rx,
        state_tx,
    )
    .await;
    if let Some(outcome) = handshake_outcome {
        return outcome;
    }

    if let Some(peer_cert) = conn.peer_cert() {
        if !tls::verify_endpoint_key(peer_cert, &tls_material.endpoint_pub_key_spki_der) {
            return SessionLoopOutcome::Reconnect(
                "peer certificate public key does not match pinned endpoint key".to_string(),
            );
        }
    }

    let mut h3_config = match quiche::h3::Config::new() {
        Ok(config) => config,
        Err(error) => {
            return SessionLoopOutcome::Reconnect(format!("h3 config failed: {error}"));
        }
    };
    h3_config.enable_extended_connect(true);

    let mut h3_conn = match quiche::h3::Connection::with_transport(&mut conn, &h3_config) {
        Ok(conn) => conn,
        Err(error) => {
            return SessionLoopOutcome::Reconnect(format!("h3 connection failed: {error}"));
        }
    };

    let req = vec![
        quiche::h3::Header::new(b":method", b"CONNECT"),
        quiche::h3::Header::new(b":protocol", b"cf-connect-ip"),
        quiche::h3::Header::new(b":scheme", b"https"),
        quiche::h3::Header::new(b":authority", b"cloudflareaccess.com"),
        quiche::h3::Header::new(b":path", b"/"),
        quiche::h3::Header::new(b"capsule-protocol", b"?1"),
        quiche::h3::Header::new(b"user-agent", b""),
    ];

    let stream_id = match h3_conn.send_request(&mut conn, &req, false) {
        Ok(id) => id,
        Err(error) => {
            return SessionLoopOutcome::Reconnect(format!("send CONNECT request failed: {error}"));
        }
    };
    let flow_id = stream_id / 4;

    if let Err(error) = flush_conn_send(&socket, &mut conn, &mut out).await {
        return SessionLoopOutcome::Reconnect(format!("post CONNECT send failed: {error}"));
    }

    let connect_outcome = wait_for_connect_response(
        &socket,
        &mut conn,
        &mut h3_conn,
        &mut out,
        &mut buf,
        local_addr,
        session_cfg.endpoint,
        stream_id,
        control_rx,
        state_tx,
    )
    .await;
    if let Some(outcome) = connect_outcome {
        return outcome;
    }

    let _ = state_tx.send(PacketSessionState::Ready);

    let flow_prefix = build_flow_prefix(flow_id);
    let mut queue = VecDeque::new();
    if let Some(packet) = pending_packet.take() {
        queue.push_back(packet);
    }

    run_connected_loop(
        &socket,
        &mut conn,
        &mut h3_conn,
        &flow_prefix,
        &mut queue,
        packet_rx,
        event_tx,
        control_rx,
        &mut out,
        &mut buf,
        local_addr,
        session_cfg,
    )
    .await
}

fn build_quic_config(tls_material: &tls::TlsMaterial) -> Result<quiche::Config> {
    let mut quic_config = quiche::Config::new(quiche::PROTOCOL_VERSION)
        .map_err(|e| anyhow::anyhow!("quiche config: {e}"))?;

    quic_config.verify_peer(false);
    quic_config
        .set_application_protos(quiche::h3::APPLICATION_PROTOCOL)
        .map_err(|e| anyhow::anyhow!("set ALPN: {e}"))?;
    quic_config
        .load_cert_chain_from_pem_file(tls_material.cert_pem_file.path().to_str().unwrap())
        .map_err(|e| anyhow::anyhow!("load cert: {e}"))?;
    quic_config
        .load_priv_key_from_pem_file(tls_material.key_pem_file.path().to_str().unwrap())
        .map_err(|e| anyhow::anyhow!("load key: {e}"))?;

    quic_config.set_max_idle_timeout(0);
    quic_config.set_max_recv_udp_payload_size(MAX_DATAGRAM_SIZE);
    quic_config.set_max_send_udp_payload_size(MAX_DATAGRAM_SIZE);
    quic_config.set_initial_max_data(10_000_000);
    quic_config.set_initial_max_stream_data_bidi_local(1_000_000);
    quic_config.set_initial_max_stream_data_bidi_remote(1_000_000);
    quic_config.set_initial_max_stream_data_uni(1_000_000);
    quic_config.set_initial_max_streams_bidi(100);
    quic_config.set_initial_max_streams_uni(100);
    quic_config.set_disable_active_migration(true);
    quic_config.enable_dgram(true, 1000, 1000);

    Ok(quic_config)
}

async fn complete_handshake(
    socket: &tokio::net::UdpSocket,
    conn: &mut quiche::Connection,
    out: &mut [u8],
    buf: &mut [u8],
    local_addr: SocketAddr,
    endpoint: SocketAddr,
    control_rx: &mut mpsc::Receiver<PacketSessionControl>,
    state_tx: &watch::Sender<PacketSessionState>,
) -> Option<SessionLoopOutcome> {
    let _ = state_tx.send(PacketSessionState::Handshaking);

    loop {
        let timeout = conn.timeout().unwrap_or(Duration::from_millis(100));

        tokio::select! {
            result = socket.recv(buf) => {
                match result {
                    Ok(len) => {
                        let recv_info = quiche::RecvInfo { to: local_addr, from: endpoint };
                        conn.recv(&mut buf[..len], recv_info).ok();
                    }
                    Err(error) => return Some(SessionLoopOutcome::Reconnect(format!("UDP recv during handshake failed: {error}"))),
                }
            }
            maybe_control = control_rx.recv() => {
                if matches!(maybe_control, Some(PacketSessionControl::Close)) {
                    return Some(SessionLoopOutcome::Close(PacketSessionCloseReason::Requested));
                }
            }
            () = tokio::time::sleep(timeout) => {
                conn.on_timeout();
            }
        }

        if let Err(error) = flush_conn_send(socket, conn, out).await {
            return Some(SessionLoopOutcome::Reconnect(format!(
                "send during handshake failed: {error}"
            )));
        }

        if conn.is_established() {
            return None;
        }
        if conn.is_closed() {
            return Some(SessionLoopOutcome::Reconnect(
                "connection closed during handshake".to_string(),
            ));
        }
    }
}

async fn wait_for_connect_response(
    socket: &tokio::net::UdpSocket,
    conn: &mut quiche::Connection,
    h3_conn: &mut quiche::h3::Connection,
    out: &mut [u8],
    buf: &mut [u8],
    local_addr: SocketAddr,
    endpoint: SocketAddr,
    stream_id: u64,
    control_rx: &mut mpsc::Receiver<PacketSessionControl>,
    state_tx: &watch::Sender<PacketSessionState>,
) -> Option<SessionLoopOutcome> {
    let _ = state_tx.send(PacketSessionState::Handshaking);
    let mut connect_established = false;

    for _ in 0..100 {
        let timeout = conn.timeout().unwrap_or(Duration::from_millis(100));

        tokio::select! {
            result = socket.recv(buf) => {
                match result {
                    Ok(len) => {
                        let recv_info = quiche::RecvInfo { to: local_addr, from: endpoint };
                        conn.recv(&mut buf[..len], recv_info).ok();
                    }
                    Err(error) => return Some(SessionLoopOutcome::Reconnect(format!("UDP recv before CONNECT response failed: {error}"))),
                }
            }
            maybe_control = control_rx.recv() => {
                if matches!(maybe_control, Some(PacketSessionControl::Close)) {
                    return Some(SessionLoopOutcome::Close(PacketSessionCloseReason::Requested));
                }
            }
            () = tokio::time::sleep(timeout) => {
                conn.on_timeout();
            }
        }

        loop {
            match h3_conn.poll(conn) {
                Ok((sid, quiche::h3::Event::Headers { list, has_body: _ })) if sid == stream_id => {
                    for header in &list {
                        if header.name() == b":status" {
                            let status = std::str::from_utf8(header.value()).unwrap_or("?");
                            if status.starts_with('2') {
                                connect_established = true;
                            } else {
                                return Some(SessionLoopOutcome::Reconnect(format!(
                                    "CONNECT rejected with status {status}"
                                )));
                            }
                        }
                    }
                }
                Ok(_) => {}
                Err(quiche::h3::Error::Done) => break,
                Err(error) => {
                    return Some(SessionLoopOutcome::Reconnect(format!(
                        "h3 poll error: {error}"
                    )));
                }
            }
        }

        if let Err(error) = flush_conn_send(socket, conn, out).await {
            return Some(SessionLoopOutcome::Reconnect(format!(
                "send during CONNECT wait failed: {error}"
            )));
        }

        if connect_established {
            return None;
        }
        if conn.is_closed() {
            return Some(SessionLoopOutcome::Reconnect(
                "connection closed before CONNECT response".to_string(),
            ));
        }
    }

    Some(SessionLoopOutcome::Reconnect(
        "timed out waiting for CONNECT response".to_string(),
    ))
}

#[allow(clippy::too_many_arguments)]
async fn run_connected_loop(
    socket: &tokio::net::UdpSocket,
    conn: &mut quiche::Connection,
    h3_conn: &mut quiche::h3::Connection,
    flow_prefix: &[u8],
    queue: &mut VecDeque<Bytes>,
    packet_rx: &mut mpsc::Receiver<Bytes>,
    event_tx: &mpsc::Sender<PacketSessionEvent>,
    control_rx: &mut mpsc::Receiver<PacketSessionControl>,
    out: &mut [u8],
    buf: &mut [u8],
    local_addr: SocketAddr,
    session_cfg: &PacketSessionConfig,
) -> SessionLoopOutcome {
    loop {
        flush_pending_queue(conn, flow_prefix, queue);

        let timeout = conn
            .timeout()
            .unwrap_or(session_cfg.keepalive_period)
            .min(session_cfg.keepalive_period);

        tokio::select! {
            maybe_packet = packet_rx.recv() => {
                match maybe_packet {
                    Some(packet) => queue.push_back(packet),
                    None => return SessionLoopOutcome::Close(PacketSessionCloseReason::InputClosed),
                }
            }
            result = socket.recv(buf) => {
                match result {
                    Ok(len) => {
                        let recv_info = quiche::RecvInfo { to: local_addr, from: session_cfg.endpoint };
                        conn.recv(&mut buf[..len], recv_info).ok();
                    }
                    Err(error) => return SessionLoopOutcome::Reconnect(format!("UDP recv failed: {error}")),
                }
            }
            maybe_control = control_rx.recv() => {
                if matches!(maybe_control, Some(PacketSessionControl::Close)) {
                    return SessionLoopOutcome::Close(PacketSessionCloseReason::Requested);
                }
            }
            () = tokio::time::sleep(timeout) => {
                conn.on_timeout();
            }
        }

        flush_pending_queue(conn, flow_prefix, queue);

        while let Ok(len) = socket.try_recv(buf) {
            let recv_info = quiche::RecvInfo {
                to: local_addr,
                from: session_cfg.endpoint,
            };
            conn.recv(&mut buf[..len], recv_info).ok();
        }

        loop {
            match h3_conn.poll(conn) {
                Ok(_) => {}
                Err(quiche::h3::Error::Done) => break,
                Err(error) => {
                    return SessionLoopOutcome::Reconnect(format!("h3 poll error: {error}"));
                }
            }
        }

        loop {
            match conn.dgram_recv_vec() {
                Ok(dgram) => {
                    if let Some(offset) = parse_datagram_offset(&dgram, 0) {
                        let dgram = Bytes::from(dgram);
                        let packet = dgram.slice(offset..);
                        if packet::validate_incoming(packet.as_ref()).is_ok() {
                            match event_tx.try_send(PacketSessionEvent::Packet(packet)) {
                                Ok(()) => {}
                                Err(TrySendError::Full(PacketSessionEvent::Packet(packet))) => {
                                    log::warn!(
                                        "dropping incoming MASQUE packet because bridge event queue is full: {} bytes",
                                        packet.len()
                                    );
                                }
                                Err(TrySendError::Closed(PacketSessionEvent::Packet(_))) => {
                                    return SessionLoopOutcome::Close(
                                        PacketSessionCloseReason::OutputClosed,
                                    );
                                }
                                Err(TrySendError::Full(_)) => {}
                                Err(TrySendError::Closed(_)) => {
                                    return SessionLoopOutcome::Close(
                                        PacketSessionCloseReason::OutputClosed,
                                    );
                                }
                            }
                        }
                    }
                }
                Err(quiche::Error::Done) => break,
                Err(error) => {
                    log::debug!("dgram recv error: {error}");
                    break;
                }
            }
        }

        if let Err(error) = flush_conn_send(socket, conn, out).await {
            return SessionLoopOutcome::Reconnect(format!("quic send error: {error}"));
        }

        if conn.is_closed() {
            return SessionLoopOutcome::Reconnect("MASQUE connection closed".to_string());
        }
    }
}

async fn flush_conn_send(
    socket: &tokio::net::UdpSocket,
    conn: &mut quiche::Connection,
    out: &mut [u8],
) -> Result<()> {
    loop {
        match conn.send(out) {
            Ok((write, send_info)) => {
                socket.send_to(&out[..write], send_info.to).await?;
            }
            Err(quiche::Error::Done) => break,
            Err(error) => bail!("{error}"),
        }
    }
    Ok(())
}

fn flush_pending_queue(
    conn: &mut quiche::Connection,
    flow_prefix: &[u8],
    queue: &mut VecDeque<Bytes>,
) {
    while let Some(packet) = queue.pop_front() {
        match build_flow_datagram(flow_prefix, packet) {
            Some(dgram) => match conn.dgram_send_vec(dgram) {
                Ok(()) | Err(quiche::Error::InvalidState) => {}
                Err(quiche::Error::Done) => {
                    break;
                }
                Err(error) => {
                    log::debug!("datagram send error: {error}");
                }
            },
            None => {
                log::trace!("dropping outgoing packet before MASQUE send");
            }
        }
    }
}

fn build_flow_datagram(flow_prefix: &[u8], packet: Bytes) -> Option<Vec<u8>> {
    let mut dgram = Vec::with_capacity(flow_prefix.len() + packet.len());
    dgram.extend_from_slice(flow_prefix);
    dgram.extend_from_slice(&packet);
    if packet::prepare_outgoing(&mut dgram[flow_prefix.len()..]).is_ok() {
        Some(dgram)
    } else {
        None
    }
}

fn build_flow_prefix(flow_id: u64) -> Vec<u8> {
    let mut prefix = Vec::with_capacity(16);
    let mut tmp = [0u8; 8];
    let mut builder = octets::OctetsMut::with_slice(&mut tmp);
    builder.put_varint(flow_id).unwrap();
    let len = builder.off();
    drop(builder);
    prefix.extend_from_slice(&tmp[..len]);
    prefix.push(0x00);
    prefix
}

fn parse_datagram_offset(dgram: &[u8], expected_flow_id: u64) -> Option<usize> {
    let mut bytes = Octets::with_slice(dgram);
    let flow_id = bytes.get_varint().ok()?;
    if flow_id != expected_flow_id {
        return None;
    }
    let context_id = bytes.get_varint().ok()?;
    if context_id != 0 {
        return None;
    }
    let offset = bytes.off();
    if offset >= dgram.len() {
        return None;
    }
    Some(offset)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn encode_varint(value: u64) -> Vec<u8> {
        let mut tmp = [0u8; 8];
        let mut builder = octets::OctetsMut::with_slice(&mut tmp);
        builder.put_varint(value).unwrap();
        let len = builder.off();
        drop(builder);
        tmp[..len].to_vec()
    }

    #[test]
    fn parse_datagram_offset_valid() {
        let payload = b"hello";
        let mut datagram = Vec::new();
        datagram.extend_from_slice(&encode_varint(0));
        datagram.extend_from_slice(&encode_varint(0));
        datagram.extend_from_slice(payload);

        let offset = parse_datagram_offset(&datagram, 0).unwrap();
        assert_eq!(&datagram[offset..], payload);
    }

    #[test]
    fn build_flow_datagram_prepares_ttl() {
        let flow_prefix = build_flow_prefix(0);
        let packet = Bytes::from_static(&[
            0x45, 0x00, 0x00, 0x14, 0x00, 0x00, 0x00, 0x00, 64, 0x11, 0x00, 0x00, 10, 0, 0, 1, 10,
            0, 0, 2,
        ]);
        let datagram = build_flow_datagram(&flow_prefix, packet).unwrap();
        assert_eq!(datagram[flow_prefix.len() + 8], 63);
    }
}
