use std::collections::HashSet;
use std::fs;
use std::path::Path;
use std::sync::RwLock;

// Global set of trusted public keys (raw bytes).
// If None, we are in "dev mode" and accept all signatures.
static VALIDATORS: RwLock<Option<HashSet<Vec<u8>>>> = RwLock::new(None);
const VALIDATORS_FILE: &str = "validators.json";

/// Initialize the validator set. This overwrites any existing set.
pub fn init_validators(validators: Vec<Vec<u8>>) {
    let mut set = HashSet::new();
    for v in validators {
        set.insert(v);
    }
    let mut lock = VALIDATORS.write().unwrap();
    *lock = Some(set);
}

/// Check if a public key is in the validator set.
/// Returns true if the set is uninitialized (dev mode).
pub fn validate_authority(public_key: &[u8]) -> bool {
    let lock = VALIDATORS.read().unwrap();
    match &*lock {
        Some(validators) => validators.contains(public_key),
        None => true,
    }
}

/// List currently trusted validators as hex strings.
pub fn list_validators() -> Vec<String> {
    let lock = VALIDATORS.read().unwrap();
    match &*lock {
        Some(validators) => validators.iter().map(hex::encode).collect(),
        None => vec![],
    }
}

/// Save the current validator set to disk.
pub fn save_validators_to_file() -> std::io::Result<()> {
    let lock = VALIDATORS.read().unwrap();
    if let Some(validators) = &*lock {
        let hex_validators: Vec<String> = validators.iter().map(hex::encode).collect();
        let json = serde_json::to_string(&hex_validators)?;
        // Atomic write pattern
        let tmp_file = format!("{}.tmp", VALIDATORS_FILE);
        fs::write(&tmp_file, json)?;
        fs::rename(tmp_file, VALIDATORS_FILE)?;
    }
    Ok(())
}

/// Load validators from disk if the file exists.
/// Returns Ok(true) if loaded, Ok(false) if file doesn't exist.
pub fn load_validators_from_file() -> std::io::Result<bool> {
    if Path::new(VALIDATORS_FILE).exists() {
        let content = fs::read_to_string(VALIDATORS_FILE)?;
        let hex_validators: Vec<String> = serde_json::from_str(&content)?;
        let mut validators = Vec::new();
        for h in hex_validators {
            if let Ok(b) = hex::decode(h) {
                validators.push(b);
            }
        }
        init_validators(validators);
        Ok(true)
    } else {
        Ok(false)
    }
}

#[cfg(test)]
pub fn clear_validators_for_tests() {
    let mut lock = VALIDATORS.write().unwrap();
    *lock = None;
}
