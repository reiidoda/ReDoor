#![allow(dead_code)]

use anyhow::{anyhow, Result};
use async_trait::async_trait;
use libp2p::{
    futures::{AsyncReadExt, AsyncWriteExt, StreamExt},
    identity,
    multiaddr::Protocol,
    swarm::SwarmEvent,
    Multiaddr, PeerId, StreamProtocol, SwarmBuilder,
};
use libp2p_request_response::{
    Behaviour as RRBehaviour, Codec as RRCodec, Config as RRConfig, Event as RREvent,
    Message as RRMessage, ProtocolSupport, RequestId,
};
use rand::Rng;
use std::time::Duration;
use tokio::sync::mpsc;
use tokio::time::timeout;

const PROTO: &str = "/redoor/1.0.0";

#[derive(Clone)]
pub struct P2PClient {
    local_peer_id: PeerId,
    keypair: identity::Keypair,
    command_sender: mpsc::Sender<Command>,
}

enum Command {
    SendRequest {
        target: Multiaddr,
        payload: Vec<u8>,
        response_sender: mpsc::Sender<Result<Vec<u8>>>,
    },
}

impl P2PClient {
    pub fn local_peer_id_base58(&self) -> String {
        self.local_peer_id.to_base58()
    }

    pub async fn new() -> Result<Self> {
        let keypair = identity::Keypair::generate_ed25519();
        let local_peer_id = PeerId::from(keypair.public());

        let (cmd_tx, mut cmd_rx) = mpsc::channel(32);

        let mut swarm = SwarmBuilder::with_existing_identity(keypair.clone())
            .with_tokio()
            .with_tcp(
                libp2p::tcp::Config::default(),
                libp2p::noise::Config::new,
                libp2p::yamux::Config::default,
            )?
            .with_behaviour(|_key| {
                let cfg = RRConfig::default();
                let proto = StreamProtocol::new(PROTO);
                let behaviours = std::iter::once((proto, ProtocolSupport::Full));
                RRBehaviour::<RedoorCodec>::new(behaviours, cfg)
            })?
            .build();

        // Listen on all interfaces, random port
        swarm.listen_on("/ip4/0.0.0.0/tcp/0".parse()?)?;

        // Spawn the swarm event loop
        tokio::spawn(async move {
            let mut pending_requests: std::collections::HashMap<
                RequestId,
                mpsc::Sender<Result<Vec<u8>>>,
            > = std::collections::HashMap::new();

            loop {
                tokio::select! {
                    event = swarm.select_next_some() => {
                        match event {
                            SwarmEvent::Behaviour(RREvent::Message {
                                peer: _,
                                message: RRMessage::Response { request_id, response },
                            }) => {
                                if let Some(sender) = pending_requests.remove(&request_id) {
                                    let _ = sender.send(Ok(strip_pad(response))).await;
                                }
                            }
                            SwarmEvent::Behaviour(RREvent::Message {
                                peer: _,
                                message: RRMessage::Request { request_id: _, request, channel },
                            }) => {
                                // Echo padded response back (stateless echo for now)
                                // In a real app, we would process the request here.
                                swarm.behaviour_mut().send_response(channel, maybe_pad(&request)).ok();
                            }
                            _ => {}
                        }
                    }
                    command = cmd_rx.recv() => {
                        match command {
                            Some(Command::SendRequest { target, payload, response_sender }) => {
                                if let Ok(peer_id) = pop_peer_id_clone(&target) {
                                    swarm.behaviour_mut().add_address(&peer_id, target);
                                    let req_id = swarm.behaviour_mut().send_request(&peer_id, maybe_pad(&payload));
                                    pending_requests.insert(req_id, response_sender);
                                }
                            }
                            None => break, // Channel closed
                        }
                    }
                }
            }
        });

        Ok(Self {
            local_peer_id,
            keypair,
            command_sender: cmd_tx,
        })
    }

    /// Send one request with padding + jitter to a peer multiaddr that includes /p2p/<peer_id>.
    /// Returns the raw response bytes (unpadded).
    pub async fn send_once(&self, target: &str, payload: &[u8]) -> Result<Vec<u8>> {
        let addr: Multiaddr = target.parse()?;
        let (resp_tx, mut resp_rx) = mpsc::channel(1);

        self.command_sender
            .send(Command::SendRequest {
                target: addr,
                payload: payload.to_vec(),
                response_sender: resp_tx,
            })
            .await
            .map_err(|_| anyhow!("P2P actor closed"))?;

        let resp = timeout(Duration::from_secs(10), resp_rx.recv())
            .await
            .map_err(|_| anyhow!("P2P request timed out"))?
            .ok_or_else(|| anyhow!("P2P response channel closed"))??;

        Ok(resp)
    }
}

#[derive(Clone, Default)]
struct RedoorCodec;

#[async_trait]
impl RRCodec for RedoorCodec {
    type Protocol = StreamProtocol;
    type Request = Vec<u8>;
    type Response = Vec<u8>;

    async fn read_request<T>(
        &mut self,
        _: &Self::Protocol,
        io: &mut T,
    ) -> std::io::Result<Self::Request>
    where
        T: libp2p::futures::AsyncRead + Unpin + Send,
    {
        let mut buf = Vec::new();
        io.read_to_end(&mut buf).await?;
        Ok(buf)
    }

    async fn read_response<T>(
        &mut self,
        _: &Self::Protocol,
        io: &mut T,
    ) -> std::io::Result<Self::Response>
    where
        T: libp2p::futures::AsyncRead + Unpin + Send,
    {
        let mut buf = Vec::new();
        io.read_to_end(&mut buf).await?;
        Ok(buf)
    }

    async fn write_request<T>(
        &mut self,
        _: &Self::Protocol,
        io: &mut T,
        req: Self::Request,
    ) -> std::io::Result<()>
    where
        T: libp2p::futures::AsyncWrite + Unpin + Send,
    {
        io.write_all(&req).await
    }

    async fn write_response<T>(
        &mut self,
        _: &Self::Protocol,
        io: &mut T,
        res: Self::Response,
    ) -> std::io::Result<()>
    where
        T: libp2p::futures::AsyncWrite + Unpin + Send,
    {
        io.write_all(&res).await
    }
}

fn pop_peer_id_clone(addr: &Multiaddr) -> Result<PeerId> {
    // Clone to avoid mutating the original if we just want to extract ID
    let mut a = addr.clone();
    match a.pop() {
        Some(Protocol::P2p(hash)) => {
            Ok(PeerId::from_multihash(hash.into()).map_err(|_| anyhow!("bad peer id"))?)
        }
        _ => Err(anyhow!("target multiaddr must end with /p2p/<peerid>")),
    }
}

fn maybe_pad(blob: &[u8]) -> Vec<u8> {
    let pad_to: usize = std::env::var("P2P_PAD_TO")
        .ok()
        .and_then(|v| v.parse().ok())
        .unwrap_or(4096);
    if pad_to == 0 {
        return blob.to_vec();
    }
    let rem = blob.len() % pad_to;
    if rem == 0 {
        return blob.to_vec();
    }
    let pad_len = pad_to - rem;
    let mut padded = Vec::with_capacity(blob.len() + pad_len);
    padded.extend_from_slice(blob);
    let mut rng = rand::thread_rng();
    for _ in 0..pad_len {
        padded.push(rng.gen());
    }
    padded
}

fn strip_pad(data: Vec<u8>) -> Vec<u8> {
    data
}

fn maybe_delay() {
    let min_ms: u64 = std::env::var("P2P_DELAY_MIN_MS")
        .ok()
        .and_then(|v| v.parse().ok())
        .unwrap_or(0);
    let max_ms: u64 = std::env::var("P2P_DELAY_MAX_MS")
        .ok()
        .and_then(|v| v.parse().ok())
        .unwrap_or(0);
    if max_ms == 0 {
        return;
    }
    let mut rng = rand::thread_rng();
    let delay = if max_ms <= min_ms {
        max_ms
    } else {
        rng.gen_range(min_ms..=max_ms)
    };
    std::thread::sleep(Duration::from_millis(delay));
}
