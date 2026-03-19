use std::collections::HashMap;
use std::sync::{Arc, Mutex};

// In-memory message storage
pub struct EphemeralStorage {
    messages: Arc<Mutex<HashMap<String, Vec<u8>>>>,
}

impl EphemeralStorage {
    pub fn new() -> Self {
        Self {
            messages: Arc::new(Mutex::new(HashMap::new())),
        }
    }

    pub fn store(&self, id: &str, msg: &[u8]) {
        let mut map = self.messages.lock().unwrap();
        map.insert(id.to_string(), msg.to_vec());
    }

    pub fn wipe(&self) {
        let mut map = self.messages.lock().unwrap();
        map.clear();
    }
}
