use crate::blockchain_client::verify_blockchain::BlockchainClient;
use crate::engine::ClientEngine;
use crate::network::relay::RelayClient;

pub struct ClientEngineBuilder {
    relay_url: Option<String>,
    blockchain_addr: Option<String>,
}

impl ClientEngineBuilder {
    pub fn new() -> Self {
        Self {
            relay_url: None,
            blockchain_addr: None,
        }
    }

    pub fn with_relay(mut self, url: &str) -> Self {
        self.relay_url = Some(url.to_string());
        self
    }

    pub fn with_blockchain(mut self, addr: &str) -> Self {
        self.blockchain_addr = Some(addr.to_string());
        self
    }

    pub fn build(self) -> ClientEngine {
        let engine = ClientEngine::new();

        if let Some(url) = self.relay_url {
            let mut guard = engine.state.lock().unwrap();
            guard.relay_client = Some(RelayClient::new(&url));
        }

        if let Some(addr) = self.blockchain_addr {
            let mut guard = engine.state.lock().unwrap();
            guard.blockchain_client = Some(BlockchainClient::new(addr));
        }

        engine
    }
}

impl Default for ClientEngineBuilder {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_builder_configuration() {
        let relay = "http://test-relay.com";
        let chain = "127.0.0.1:9999";

        let engine = ClientEngineBuilder::new()
            .with_relay(relay)
            .with_blockchain(chain)
            .build();

        let guard = engine.state.lock().unwrap();

        if let Some(rc) = &guard.relay_client {
            assert_eq!(rc.base_url, relay);
        } else {
            panic!("Relay client not configured");
        }

        if let Some(bc) = &guard.blockchain_client {
            assert_eq!(bc.base_url, chain);
        } else {
            panic!("Blockchain client not configured");
        }
    }
}
