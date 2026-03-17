mod api;
mod config;
mod consensus;
mod crypto;
mod dto;
mod ledger;
mod metrics;
mod tcp_server;

use hex;
use log::info;
use std::env;
use std::io;
use std::sync::Arc;
use tokio::net::TcpListener;
use tokio::signal;
use tokio::sync::Mutex;
use tokio::task;

// Initialize logging early
fn init_logging() {
    let _ = env_logger::try_init();
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    init_logging();
    info!("Starting Redoor Blockchain Node...");

    // Initialize validators (optional, from file or env)
    // Try loading persisted validators first
    if let Ok(true) = consensus::authority::load_validators_from_file() {
        println!("Loaded validators from file.");
    } else if let Ok(val_str) = env::var("VALIDATORS") {
        let validators: Vec<Vec<u8>> = val_str
            .split(',')
            .filter_map(|s| hex::decode(s).ok())
            .collect();
        consensus::authority::init_validators(validators);
        println!("Initialized with trusted validators from VALIDATORS env.");
    }

    // Initialize the blockchain
    // Use Arc<Mutex<Blockchain>> to share state across threads safely
    let blockchain = Arc::new(Mutex::new(ledger::chain::Blockchain::new()));

    let node_config = config::NodeConfig::from_env()
        .map_err(|e| io::Error::new(io::ErrorKind::InvalidInput, e))?;

    let tls_acceptor = if let (Some(cert), Some(key)) = (
        node_config.cert_file.as_deref(),
        node_config.key_file.as_deref(),
    ) {
        Some(tcp_server::make_tls_acceptor(cert, key)?)
    } else {
        None
    };

    // Spawn an HTTP API (warp) to allow POSTing transactions and signed blocks
    {
        let blockchain_tx = blockchain.clone();
        let admin_token = node_config.admin_token.clone();

        crate::metrics::init_metrics();

        let routes = api::routes(blockchain_tx, admin_token);

        let socket_addr = node_config.http_addr;

        task::spawn(async move {
            warp::serve(routes).run(socket_addr).await;
        });
    }

    let listener = TcpListener::bind(node_config.tcp_addr).await?;
    println!(
        "Blockchain Node listening on {} ({})",
        node_config.tcp_addr,
        if tls_acceptor.is_some() {
            "TLS"
        } else {
            "plaintext"
        }
    );

    // Main loop with graceful shutdown
    loop {
        tokio::select! {
            accept_result = listener.accept() => {
                match accept_result {
                    Ok((socket, _)) => {
                        let blockchain = blockchain.clone();
                        let tls_acceptor = tls_acceptor.clone();
                        tokio::spawn(async move {
                            tcp_server::handle_connection(socket, blockchain, tls_acceptor).await;
                        });
                    }
                    Err(e) => eprintln!("Accept error: {}", e),
                }
            }
            _ = signal::ctrl_c() => {
                println!("Shutdown signal received. Exiting...");
                break;
            }
        }
    }

    Ok(())
}
