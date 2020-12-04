use rand::thread_rng;
use secp256k1::{sign, verify, Message, PublicKey, SecretKey, Signature};
use sha3::{Digest, Keccak256};
use std::net::{IpAddr, Ipv4Addr};
use std::str::FromStr;
use std::time::{SystemTime, UNIX_EPOCH};
use tokio::net::TcpStream;
use uuid::Uuid;

use crate::discover::packets::{Data, Header, Packet, FIND_NODE, NEIGHBORS, PING, PONG};
use crate::peer::Peer;

use utils::app_error::AppError;

pub struct Protocol {
    private_key: SecretKey,
    pub public_key: PublicKey,
}

impl Protocol {
    pub fn new() -> Protocol {
        let private_key = SecretKey::random(&mut thread_rng());
        let public_key = PublicKey::from_secret_key(&private_key);

        Protocol {
            private_key: private_key,
            public_key: public_key,
        }
    }

    pub async fn ping(
        &self,
        stream: &mut TcpStream,
        peer_ip: &str,
        local_peer_id: &Uuid,
    ) -> Result<Packet, AppError> {
        let local_ip = match stream.local_addr().unwrap().ip() {
            IpAddr::V4(ipv4) => ipv4,
            _ => return Err(AppError::new("IPv6 not supported")),
        };

        let local_port = stream.local_addr().unwrap().port();

        let packet_data = Data::Ping(
            0x00,
            local_ip.octets(),
            local_port,
            Ipv4Addr::from_str(&peer_ip).unwrap().octets(),
            SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap()
                .as_secs(),
            local_peer_id.as_u128(),
        );
        let header = self._build_header(&packet_data.serialize(), PING);

        let ping: Packet = Packet {
            header: header.clone(),
            data: packet_data.clone(),
        };

        ping.write_to_tcp_stream(stream).await?;

        Ok(ping)
    }

    pub async fn wait_for_ping(&self, stream: &mut TcpStream) -> Result<Packet, AppError> {
        let packet = Packet::from_tcp_stream(stream).await?;
        match packet.header.packet_type {
            PING => Ok(packet),
            _ => Err(AppError::new("Expected Ping message")),
        }
    }

    pub async fn pong(
        &self,
        stream: &mut TcpStream,
        local_peer_id: &Uuid,
        ping: &Packet,
    ) -> Result<bool, AppError> {
        let recipient_ip = match stream.local_addr().unwrap().ip() {
            IpAddr::V4(ipv4) => ipv4,
            _ => return Err(AppError::new("IPv6 not supported")),
        };

        let recipient_port = stream.local_addr().unwrap().port();

        // recipient_ip, ping hash, expiration
        let packet_data = Data::Pong(
            recipient_ip.octets(),
            recipient_port,
            ping.header.hash,
            SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap()
                .as_secs(),
            local_peer_id.as_u128(),
        );
        let header = self._build_header(&packet_data.serialize(), PONG);

        let pong = Packet {
            header: header,
            data: packet_data,
        };

        pong.write_to_tcp_stream(stream).await?;

        Ok(true)
    }

    pub async fn wait_for_pong(&self, stream: &mut TcpStream) -> Result<Packet, AppError> {
        let packet = Packet::from_tcp_stream(stream).await?;
        match packet.header.packet_type {
            PONG => Ok(packet),
            _ => Err(AppError::new("Expected Pong message")),
        }
    }

    pub async fn check_pong_message(
        &self,
        stream: &mut TcpStream,
        packet: Packet,
    ) -> Result<(), AppError> {
        // read pong message
        let pong = self.wait_for_pong(stream).await?;

        // if valid return packet
        match pong.data {
            Data::Pong(recipient_ip, recipient_tcp_port, ping_hash, _, node_id) => {
                if ping_hash != packet.header.hash {
                    return Err(AppError::new("Hashed do not match"));
                }

                Ok(())
            }
            _ => return Err(AppError::new("Expected pong message")),
        }
    }

    fn _build_header(&self, packet_data: &[u8], packet_type: u8) -> Header {
        let mut content = vec![];
        content.push(packet_type);
        content.extend(packet_data);
        let message_content = self._compute_keccak256(&content);
        let message = Message::parse_slice(&message_content).unwrap();
        let (signature, _) = sign(&message, &self.private_key);
        let serialized_signature = signature.serialize();

        // hash = keccak256(signature || packet-type || packet-data)
        content = vec![];
        content.extend(&serialized_signature.to_vec());
        content.push(packet_type);
        content.extend(packet_data);
        Header {
            packet_type: packet_type,
            signature: serialized_signature.to_vec(),
            hash: self._compute_keccak256(&content),
        }
    }

    fn _compute_keccak256(&self, chunk: &[u8]) -> [u8; 32] {
        let mut hasher = Keccak256::new();
        hasher.update(&chunk);
        let hash = hasher.finalize().to_vec();
        let mut fixed_hash = [0; 32];
        for i in 0..hash.len() {
            fixed_hash[i] = hash[i];
        }
        fixed_hash
    }
}
