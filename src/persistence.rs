use std::collections::{HashMap, HashSet};
use std::fs;
use std::path::PathBuf;
use serde::{Deserialize, Serialize};
use ed25519_dalek::SigningKey;
use rand::rngs::OsRng;
use aes_gcm::{
    aead::{Aead, KeyInit},
    Aes256Gcm, Nonce,
};
use sha2::{Sha256, Digest};
use crate::debug_println;

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct EncryptedPassword {
    pub nonce: Vec<u8>,      // 12-byte nonce for AES-GCM
    pub ciphertext: Vec<u8>, // Encrypted password
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct AppState {
    // Match iOS UserDefaults keys exactly
    pub nickname: Option<String>,                              // bitchat.nickname
    pub blocked_peers: HashSet<String>,                       // bitchat.blockedUsers (SHA256 fingerprints)
    pub channel_creators: HashMap<String, String>,            // bitchat.channelCreators
    pub joined_channels: Vec<String>,                         // bitchat.joinedChannels
    pub password_protected_channels: HashSet<String>,         // bitchat.passwordProtectedChannels
    pub channel_key_commitments: HashMap<String, String>,     // bitchat.channelKeyCommitments
    pub favorites: HashSet<String>,                           // bitchat.favorites (SHA256 fingerprints)
    pub identity_key: Option<Vec<u8>>,                        // bitchat.identityKey (Ed25519 private key)
    pub noise_static_key: Option<Vec<u8>>,                   // bitchat.noiseStaticKey (X25519 private key)
    pub encrypted_channel_passwords: HashMap<String, EncryptedPassword>, // Encrypted channel passwords
}

impl AppState {
    pub fn new() -> Self {
        Self {
            nickname: None,
            blocked_peers: HashSet::new(),
            channel_creators: HashMap::new(),
            joined_channels: Vec::new(),
            password_protected_channels: HashSet::new(),
            channel_key_commitments: HashMap::new(),
            favorites: HashSet::new(),
            identity_key: None,
            noise_static_key: None,
            encrypted_channel_passwords: HashMap::new(),
        }
    }
}

pub fn get_state_file_path() -> PathBuf {
    let mut path = dirs::home_dir().unwrap_or_else(|| PathBuf::from("."));
    path.push(".bitchat");
    
    // Create directory if it doesn't exist
    if !path.exists() {
        let _ = fs::create_dir_all(&path);
    }
    
    path.push("state.json");
    path
}

pub fn load_state() -> AppState {
    let path = get_state_file_path();
    
    let mut state = if path.exists() {
        match fs::read_to_string(&path) {
            Ok(contents) => {
                match serde_json::from_str(&contents) {
                    Ok(state) => state,
                    Err(_) => {
                        debug_println!("Warning: Could not parse state file, using defaults");
                        AppState::new()
                    }
                }
            }
            Err(_) => {
                debug_println!("Warning: Could not read state file, using defaults");
                AppState::new()
            }
        }
    } else {
        AppState::new()
    };
    
    // Generate persistent identity key if not present (matching iOS behavior)
    if state.identity_key.is_none() {
        let signing_key = SigningKey::generate(&mut OsRng);
        state.identity_key = Some(signing_key.to_bytes().to_vec());
        // Save immediately to persist the identity key
        let _ = save_state(&state);
    }
    
    // Generate persistent Noise static key if not present (matching iOS behavior)
    if state.noise_static_key.is_none() {
        let noise_key = x25519_dalek::StaticSecret::random_from_rng(&mut OsRng);
        state.noise_static_key = Some(noise_key.to_bytes().to_vec());
        // Save immediately to persist the Noise static key
        let _ = save_state(&state);
    }
    
    state
}

pub fn save_state(state: &AppState) -> Result<(), Box<dyn std::error::Error>> {
    let path = get_state_file_path();
    let json = serde_json::to_string_pretty(state)?;
    fs::write(&path, json)?;
    Ok(())
}

// Derive AES key from identity key using HKDF-like approach
fn derive_encryption_key(identity_key: &[u8]) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(b"bitchat-password-encryption");
    hasher.update(identity_key);
    let result = hasher.finalize();
    let mut key = [0u8; 32];
    key.copy_from_slice(&result);
    key
}

// Encrypt a password using the identity key
pub fn encrypt_password(password: &str, identity_key: &[u8]) -> Result<EncryptedPassword, Box<dyn std::error::Error>> {
    let key = derive_encryption_key(identity_key);
    let cipher = Aes256Gcm::new_from_slice(&key)?;
    
    // Generate random nonce
    let mut nonce_bytes = [0u8; 12];
    rand::Rng::fill(&mut OsRng, &mut nonce_bytes);
    let nonce = Nonce::from_slice(&nonce_bytes);
    
    // Encrypt the password
    let ciphertext = cipher.encrypt(nonce, password.as_bytes())
        .map_err(|e| format!("Encryption failed: {}", e))?;
    
    Ok(EncryptedPassword {
        nonce: nonce_bytes.to_vec(),
        ciphertext,
    })
}

// Decrypt a password using the identity key
#[allow(dead_code)]
pub fn decrypt_password(encrypted: &EncryptedPassword, identity_key: &[u8]) -> Result<String, Box<dyn std::error::Error>> {
    let key = derive_encryption_key(identity_key);
    let cipher = Aes256Gcm::new_from_slice(&key)?;
    
    if encrypted.nonce.len() != 12 {
        return Err("Invalid nonce length".into());
    }
    
    let nonce = Nonce::from_slice(&encrypted.nonce);
    
    // Decrypt the password
    let plaintext = cipher.decrypt(nonce, encrypted.ciphertext.as_ref())
        .map_err(|e| format!("Decryption failed: {}", e))?;
    
    String::from_utf8(plaintext)
        .map_err(|e| format!("Invalid UTF-8: {}", e).into())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_persistent_noise_static_key() {
        // Test that the same noise static key is generated and persisted
        let state1 = load_state();
        let state2 = load_state();
        
        // Both states should have the same noise static key
        assert!(state1.noise_static_key.is_some());
        assert!(state2.noise_static_key.is_some());
        assert_eq!(state1.noise_static_key, state2.noise_static_key);
        
        // The key should be 32 bytes (X25519 private key size)
        assert_eq!(state1.noise_static_key.unwrap().len(), 32);
    }
}