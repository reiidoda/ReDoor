pub mod api;
pub mod blockchain_client;
pub mod builder;
pub mod config;
pub mod crypto;
pub mod diagnostics;
pub mod engine;
pub mod ffi;
pub mod network;
pub mod orchestrator;
pub mod ratchet;
pub mod service;
pub mod simulation;
pub mod storage;
pub mod ui;

// Re-export the non-interactive helper for embedding (e.g., iOS staticlib).
pub use api::scripted_loopback;
