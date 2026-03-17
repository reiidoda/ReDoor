use std::collections::HashMap;
use std::sync::{Arc, Mutex};

// Key management and deletion
pub struct KeyManager {
    keys: Arc<Mutex<HashMap<String, [u8; 32]>>>,
}

impl KeyManager {
    pub fn new() -> Self {
        Self {
            keys: Arc::new(Mutex::new(HashMap::new())),
        }
    }

    pub fn store_key(&self, id: &str, key: [u8; 32]) {
        let mut map = self.keys.lock().unwrap();
        map.insert(id.to_string(), key);
    }

    pub fn wipe_all(&self) {
        let mut map = self.keys.lock().unwrap();
        map.clear();
    }
}
