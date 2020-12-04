use std::sync::{Arc, Mutex};
use std::thread;
use std::time;
use tokio::net::{TcpListener, TcpStream};
use uuid::Uuid;

use settings::DefaultPeer;
use utils::app_error::AppError;

use crate::discover::protocol::Protocol;
use crate::peer::Peer;

pub struct PeersHandler<'a> {
    id: Uuid,
    peers: Arc<Mutex<Vec<Peer<'a>>>>,
    ip: String,
    tcp_port: u16,
}

impl PeersHandler<'_> {
    pub fn new<'a>(tcp_port: u16) -> PeersHandler<'a> {
        PeersHandler {
            id: Uuid::new_v4(),
            peers: Arc::new(Mutex::new(vec![])),
            ip: String::from("127.0.0.1"), //TODO: make it dynamic
            tcp_port: tcp_port,
        }
    }

    pub async fn listen_for_peers(&self) -> Result<(), AppError> {
        let mut listener =
            match TcpListener::bind(&format!("{}:{}", &self.ip, &self.tcp_port)).await {
                Ok(listener) => listener,
                Err(_) => return Err(AppError::new("Failed to bind")),
            };

        println!("{:?}", listener.local_addr().unwrap());

        loop {
            match listener.accept().await {
                Ok(res) => {
                    let (mut stream, _) = res;
                    self._handle_peer(&mut stream).await?;
                }
                Err(_) => println!("Failed to accept peer"),
            };
        }
    }

    async fn _handle_peer(&self, stream: &mut TcpStream) -> Result<(), AppError> {
        let discoverer = Protocol::new();
        let ping = discoverer.wait_for_ping(stream).await?;
        discoverer.pong(stream, &self.id, &ping).await?;
        println!("Accepted connection from {}", stream.peer_addr().unwrap());
        Ok(())
    }

    pub async fn spawn_discover(
        &mut self,
        default_peers: Vec<DefaultPeer>,
    ) -> Result<(), AppError> {
        // try to connect with default peers
        self.spawn_connect_with_default_peers(default_peers);
        self.spawn_discover_new_peers();
        Ok(())
    }

    fn spawn_connect_with_default_peers(
        &mut self,
        default_peers: Vec<DefaultPeer>,
    ) -> Result<(), AppError> {
        let self_ip = self.ip.clone();
        let self_tcp_port = self.tcp_port.clone();
        let self_id = self.id.clone();
        let self_peers = self.peers.clone();

        tokio::spawn(async move {
            let mut connected: Vec<String> = vec![];

            let discoverer = Protocol::new();

            loop {
                for default_peer in &default_peers {
                    let formatted_self_address = format!("{}:{}", self_ip, self_tcp_port);
                    let formatted_peer_address =
                        format!("{}:{}", default_peer.ip, default_peer.tcp_port);

                    if !connected.contains(&formatted_peer_address)
                        && formatted_peer_address != formatted_self_address
                    {
                        println!("Trying to connect with {}...", formatted_peer_address);

                        match TcpStream::connect(&format!(
                            "{}:{}",
                            default_peer.ip, default_peer.tcp_port
                        ))
                        .await
                        {
                            Ok(mut stream) => {
                                match discoverer
                                    .ping(&mut stream, &default_peer.ip, &self_id)
                                    .await
                                {
                                    Ok(ping_packet) => {
                                        match discoverer
                                            .check_pong_message(&mut stream, ping_packet)
                                            .await
                                        {
                                            Ok(_) => {
                                                connected.push(formatted_peer_address);

                                                //self_peers.lock().unwrap().push(peer);

                                                println!(
                                                    "Connected with {}:{}",
                                                    default_peer.ip, default_peer.tcp_port
                                                );
                                            }
                                            Err(err) => println!(
                                                "Failed retrieve pong message with {}:{}",
                                                default_peer.ip, err.msg
                                            ),
                                        }
                                    }

                                    Err(err) => {
                                        println!(
                                            "Failed handshake with {}. {}",
                                            formatted_peer_address, err.msg
                                        );
                                    }
                                }
                            }
                            Err(_) => println!("Peer {} Not Found", formatted_peer_address),
                        };
                    }
                }

                if connected.len() == default_peers.len() {
                    return;
                }
                thread::sleep(time::Duration::from_millis(10000));
            }
        });

        Ok(())
    }

    fn spawn_discover_new_peers(&mut self) -> Result<(), AppError> {
        Ok(())
    }
}
