use std::net::Ipv4Addr;
use tokio::net::TcpStream;
use uuid::Uuid;

#[derive(Debug)]
pub struct Peer<'a> {
    pub ip: Ipv4Addr,
    pub tcp_port: u16,
    pub id: Uuid,
    pub stream: &'a mut TcpStream,
}

impl Peer<'_> {
    pub fn new(ip: [u8; 4], tcp_port: u16, id: Uuid, stream: &mut TcpStream) -> Peer {
        Peer {
            ip: Ipv4Addr::from(ip),
            tcp_port: tcp_port,
            id: id,
            stream: stream,
        }
    }
}
