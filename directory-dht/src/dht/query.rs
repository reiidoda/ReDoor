use std::collections::HashMap;
use std::sync::{Arc, Mutex};

// Query prekeys
#[allow(dead_code)]
pub async fn query_key(
    store: &Arc<Mutex<HashMap<String, Vec<u8>>>>,
    key_id: &str,
) -> Option<Vec<u8>> {
    let map = store.lock().unwrap();
    map.get(key_id).cloned()
}
