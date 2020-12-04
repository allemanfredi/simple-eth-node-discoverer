use tokio::net::TcpStream;
use tokio::prelude::*;
use utils::app_error::AppError;

pub const PING: u8 = 0x01;
pub const PONG: u8 = 0x02;
pub const FIND_NODE: u8 = 0x03;
pub const NEIGHBORS: u8 = 0x04;

#[derive(Clone, Debug)]
pub enum Data {
    // version, sender_ip, sender_tcp_port, recipient_ip, expiration, node id
    Ping(u8, [u8; 4], u16, [u8; 4], u64, u128),
    // recipient_ip, recipient_tcp_port, ping hash, expiration, node id
    Pong([u8; 4], u16, [u8; 32], u64, u128),
    // public key (65 bytes), expiration
    FindNode(Vec<u8>, u64),
    // number of nodes, nodes and expiration (node = ip, tcp port, node id  ->  4 + 2 + 16 = 22 bytes)
    Neighbors(u16, Vec<u8>, u64),
}

impl Data {
    pub fn serialize(&self) -> Vec<u8> {
        match self {
            Data::Ping(version, sender_ip, sender_tcp_port, recipient_ip, expiration, peer_id) => {
                let mut serialized = vec![];
                serialized.push(*version);
                serialized.extend(sender_ip);
                serialized.extend(&sender_tcp_port.to_be_bytes());
                serialized.extend(recipient_ip);
                serialized.extend(&expiration.to_be_bytes());
                serialized.extend(&peer_id.to_be_bytes());

                serialized
            }
            Data::Pong(recipient_ip, recipient_tcp_port, ping_hash, expiration, peer_id) => {
                let mut serialized = vec![];
                serialized.extend(recipient_ip);
                serialized.extend(&recipient_tcp_port.to_be_bytes());
                serialized.extend(ping_hash);
                serialized.extend(&expiration.to_be_bytes());
                serialized.extend(&peer_id.to_be_bytes());

                serialized
            }
            Data::FindNode(public_key, expiration) => {
                let mut serialized = vec![];
                serialized.extend(public_key);
                serialized.extend(&expiration.to_be_bytes());

                serialized
            }
            Data::Neighbors(number_of_nodes, nodes, expiration) => {
                let mut serialized = vec![];
                serialized.extend(&number_of_nodes.to_be_bytes());
                serialized.extend(nodes);
                serialized.extend(&expiration.to_be_bytes());

                serialized
            }
        }
    }
}

#[derive(Clone, Debug)]
pub struct Header {
    pub packet_type: u8,
    // signature = sign(packet-type || packet-data) -> 64 bytes
    pub signature: Vec<u8>,
    // hash = keccak256(signature || packet-type || packet-data)
    pub hash: [u8; 32],
}

impl Header {
    pub fn serialize(&self) -> Vec<u8> {
        let mut serialized: Vec<u8> = Vec::new();
        serialized.push(self.packet_type);
        serialized.extend(&self.signature);
        serialized.extend(&self.hash);

        serialized
    }
}

#[derive(Clone, Debug)]
pub struct Packet {
    pub header: Header,
    pub data: Data,
}

impl Packet {
    pub fn serialize(&self) -> Vec<u8> {
        let mut serialized: Vec<u8> = Vec::new();
        serialized.extend(&self.header.serialize());
        serialized.extend(&self.data.serialize());

        serialized
    }

    pub async fn write_to_tcp_stream(&self, stream: &mut TcpStream) -> Result<(), AppError> {
        Packet::write_all_to_stream(stream, &self.serialize()).await?;
        Ok(())
    }

    pub async fn from_tcp_stream(stream: &mut TcpStream) -> Result<Packet, AppError> {
        // packet type
        let mut packet_type_buf = [0u8; 1];
        //stream.read(&mut packet_type_buf).await?;
        Packet::read_exact_from_stream(stream, &mut packet_type_buf).await?;
        let packet_type = packet_type_buf[0];

        // signature
        let mut signature = [0u8; 64];
        Packet::read_exact_from_stream(stream, &mut signature).await?;

        // hash
        let mut hash = [0u8; 32];
        Packet::read_exact_from_stream(stream, &mut hash).await?;

        let header = Header {
            packet_type: packet_type,
            signature: signature.to_vec(),
            hash: hash,
        };

        let packet_data = match packet_type {
            PING => {
                // version
                let mut version_buf = [0u8; 1];
                Packet::read_exact_from_stream(stream, &mut version_buf).await?;
                let version = version_buf[0];

                // sender ip
                let mut sender_ip = [0u8; 4];
                Packet::read_exact_from_stream(stream, &mut sender_ip).await?;

                // sender tcp port
                let mut sender_tcp_port_buf = [0u8; 2];
                Packet::read_exact_from_stream(stream, &mut sender_tcp_port_buf).await?;
                let sender_tcp_port = u16::from_be_bytes(sender_tcp_port_buf);

                // recipient ip
                let mut recipient_ip = [0u8; 4];
                Packet::read_exact_from_stream(stream, &mut recipient_ip).await?;

                // expiration
                let mut expiration_buf = [0u8; 8];
                Packet::read_exact_from_stream(stream, &mut expiration_buf).await?;
                let expiration = u64::from_be_bytes(expiration_buf);

                // peer id
                let mut peer_id_buf = [0u8; 16];
                Packet::read_exact_from_stream(stream, &mut peer_id_buf).await?;
                let peer_id = u128::from_be_bytes(peer_id_buf);

                Data::Ping(
                    version,
                    sender_ip,
                    sender_tcp_port,
                    recipient_ip,
                    expiration,
                    peer_id,
                )
            }
            PONG => {
                // recipient ip
                let mut recipient_ip = [0u8; 4];
                Packet::read_exact_from_stream(stream, &mut recipient_ip).await?;

                // recipient tcp port
                let mut peer_tcp_port_buf = [0u8; 2];
                Packet::read_exact_from_stream(stream, &mut peer_tcp_port_buf).await?;
                let peer_tcp_port = u16::from_be_bytes(peer_tcp_port_buf);

                // ping hash
                let mut ping_hash = [0u8; 32];
                Packet::read_exact_from_stream(stream, &mut ping_hash).await?;

                // expiration
                let mut expiration_buf = [0u8; 8];
                Packet::read_exact_from_stream(stream, &mut expiration_buf).await?;
                let expiration = u64::from_be_bytes(expiration_buf);

                // peer id
                let mut peer_id_buf = [0u8; 16];
                Packet::read_exact_from_stream(stream, &mut peer_id_buf).await?;
                let peer_id = u128::from_be_bytes(peer_id_buf);

                Data::Pong(recipient_ip, peer_tcp_port, ping_hash, expiration, peer_id)
            }
            FIND_NODE => {
                // public key
                let mut public_key = [0u8; 65];
                Packet::read_exact_from_stream(stream, &mut public_key).await?;

                // expiration
                let mut expiration_buf = [0u8; 8];
                Packet::read_exact_from_stream(stream, &mut expiration_buf).await?;
                let expiration = u64::from_be_bytes(expiration_buf);

                Data::FindNode(public_key.to_vec(), expiration)
            }
            NEIGHBORS => {
                // number of nodes
                let mut number_of_nodes_buf = [0u8; 2];
                Packet::read_exact_from_stream(stream, &mut number_of_nodes_buf).await?;
                let number_of_nodes = u16::from_be_bytes(number_of_nodes_buf);

                // nodes (1 node = 22 bytes)
                let mut nodes = Vec::with_capacity((number_of_nodes * 22) as usize);
                Packet::read_exact_from_stream(stream, &mut nodes).await?;

                // expiration
                let mut expiration_buf = [0u8; 8];
                Packet::read_exact_from_stream(stream, &mut expiration_buf).await?;
                let expiration = u64::from_be_bytes(expiration_buf);

                Data::Neighbors(number_of_nodes, nodes, expiration)
            }
            _ => return Err(AppError::new("Invalid packet type")),
        };

        Ok(Packet {
            header: header,
            data: packet_data,
        })
    }

    pub async fn read_exact_from_stream(
        stream: &mut TcpStream,
        buf: &mut [u8],
    ) -> Result<(), AppError> {
        match stream.read(buf).await {
            Ok(_) => Ok(()),
            Err(_) => Err(AppError::new("Error reading from tcp stream")),
        }
    }

    pub async fn write_all_to_stream(stream: &mut TcpStream, buf: &[u8]) -> Result<(), AppError> {
        match stream.write_all(buf).await {
            Ok(_) => Ok(()),
            Err(_) => Err(AppError::new("Error writing to tcp stream")),
        }
    }
}
