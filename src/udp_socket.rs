use std::io;
use std::net::{SocketAddr, UdpSocket as StdUdpSocket};

use socket2::SockRef;
use tokio::net::UdpSocket;

const UDP_SOCKET_BUFFER_BYTES: usize = 4 * 1024 * 1024;

pub fn bind_udp_socket(bind_addr: SocketAddr, label: &'static str) -> io::Result<UdpSocket> {
    let socket = StdUdpSocket::bind(bind_addr)?;
    let sock_ref = SockRef::from(&socket);
    sock_ref.set_recv_buffer_size(UDP_SOCKET_BUFFER_BYTES)?;
    sock_ref.set_send_buffer_size(UDP_SOCKET_BUFFER_BYTES)?;

    let recv_buffer_bytes = sock_ref.recv_buffer_size()?;
    let send_buffer_bytes = sock_ref.send_buffer_size()?;
    socket.set_nonblocking(true)?;

    log::info!(
        "configured UDP socket buffers for {} on {}: recv={} send={}",
        label,
        bind_addr,
        recv_buffer_bytes,
        send_buffer_bytes
    );

    if recv_buffer_bytes < UDP_SOCKET_BUFFER_BYTES {
        log::warn!(
            "actual UDP receive buffer for {} on {} is below requested size: actual={} requested={}",
            label,
            bind_addr,
            recv_buffer_bytes,
            UDP_SOCKET_BUFFER_BYTES
        );
    }

    if send_buffer_bytes < UDP_SOCKET_BUFFER_BYTES {
        log::warn!(
            "actual UDP send buffer for {} on {} is below requested size: actual={} requested={}",
            label,
            bind_addr,
            send_buffer_bytes,
            UDP_SOCKET_BUFFER_BYTES
        );
    }

    UdpSocket::from_std(socket)
}
