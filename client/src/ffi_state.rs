//! C-friendly FFI surface for iOS (or other native hosts).
//! Provides stateful interaction for a real chat app.

use crate::engine::ClientEngine;
use std::ffi::{CStr};
use std::os::raw::c_char;
use std::sync::OnceLock;

static ENGINE: OnceLock<ClientEngine> = OnceLock::new();

pub fn get_engine() -> &'static ClientEngine {
    ENGINE.get_or_init(|| ClientEngine::new())
}