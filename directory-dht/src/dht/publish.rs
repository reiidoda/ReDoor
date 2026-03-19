use std::collections::HashMap;
use std::sync::{Arc, Mutex};

// Publish identity keys and prekeys
#[allow(dead_code)]
pub async fn publish_key(
    store: &Arc<Mutex<HashMap<String, Vec<u8>>>>,
    key_id: &str,
    key_data: &[u8],
) {
    let mut map = store.lock().unwrap();
    map.insert(key_id.to_string(), key_data.to_vec());
    println!("Published key for ID: {}", key_id);
}
