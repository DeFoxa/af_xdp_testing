use eyre::Result;
use std::net::UdpSocket;

pub fn setup_udp_server() -> Result<()> {
    let socket = UdpSocket::bind("0.0.0.0:7777")?;

    println!("listening on 7777");

    let mut buf = [0; 1024];

    loop {
        let (amt, src) = socket.recv_from(&mut buf)?;
        println!("received {} bytes, from {}", amt, src);
        println!("data: {}", String::from_utf8_lossy(&buf[..amt]));
    }
}
