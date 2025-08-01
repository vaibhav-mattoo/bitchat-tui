use aes_gcm::{
    aead::{Aead, AeadCore, KeyInit, OsRng},
    Aes256Gcm, Nonce,
};
use ed25519_dalek::{Signature, Signer, SigningKey, VerifyingKey};
use hkdf::Hkdf;
use pbkdf2::pbkdf2_hmac;
use sha2::Sha256;
use std::collections::HashMap;
use std::sync::{Arc, RwLock};
use x25519_dalek::{PublicKey, StaticSecret};
use crate::debug_println;
use crate::noise_session::NoiseSessionManager;

#[derive(Debug)]
pub enum EncryptionError {
    NoSharedSecret,
    InvalidPublicKey,
    EncryptionFailed,
    DecryptionFailed,
    #[allow(dead_code)]
    SignatureVerificationFailed,
}

pub struct EncryptionService {
    // Key agreement keys for encryption
    private_key: StaticSecret,
    public_key: PublicKey,
    
    // Signing keys for authentication
    signing_key: SigningKey,
    verifying_key: VerifyingKey,
    
    // Persistent identity for favorites (separate from ephemeral keys)
    _identity_key: SigningKey,  // Reserved for future features
    identity_public: VerifyingKey,
    
    // Storage for peer keys - wrapped in Arc<RwLock> for thread safety
    peer_public_keys: Arc<RwLock<HashMap<String, PublicKey>>>,
    peer_signing_keys: Arc<RwLock<HashMap<String, VerifyingKey>>>,
    peer_identity_keys: Arc<RwLock<HashMap<String, VerifyingKey>>>,
    shared_secrets: Arc<RwLock<HashMap<String, [u8; 32]>>>,
    
    // Noise session manager for transport cipher encryption
    noise_manager: Option<Arc<RwLock<NoiseSessionManager>>>,
}

impl EncryptionService {
    pub fn new() -> Self {
        // Generate ephemeral key pairs for this session
        let private_key = StaticSecret::random_from_rng(OsRng);
        let public_key = PublicKey::from(&private_key);
        
        let signing_key = SigningKey::generate(&mut OsRng);
        let verifying_key = signing_key.verifying_key();
        
        // Generate persistent identity key for this session
        let identity_key = SigningKey::generate(&mut OsRng);
        let identity_public = identity_key.verifying_key();
        
        Self {
            private_key,
            public_key,
            signing_key,
            verifying_key,
            _identity_key: identity_key,
            identity_public,
            peer_public_keys: Arc::new(RwLock::new(HashMap::new())),
            peer_signing_keys: Arc::new(RwLock::new(HashMap::new())),
            peer_identity_keys: Arc::new(RwLock::new(HashMap::new())),
            shared_secrets: Arc::new(RwLock::new(HashMap::new())),
            noise_manager: None,
        }
    }
    
    /// Create combined public key data for exchange (96 bytes total)
    pub fn get_combined_public_key_data(&self) -> Vec<u8> {
        let mut data = Vec::with_capacity(96);
        data.extend_from_slice(self.public_key.as_bytes());         // 32 bytes - ephemeral encryption key
        data.extend_from_slice(&self.verifying_key.to_bytes());     // 32 bytes - ephemeral signing key
        data.extend_from_slice(&self.identity_public.to_bytes());   // 32 bytes - persistent identity key
        data  // Total: 96 bytes
    }
    
    /// Add peer's combined public keys
    pub fn add_peer_public_key(&self, peer_id: &str, public_key_data: &[u8]) -> Result<(), EncryptionError> {
        if public_key_data.len() != 96 {
            debug_println!("[CRYPTO] Invalid public key data size: {}, expected 96", public_key_data.len());
            return Err(EncryptionError::InvalidPublicKey);
        }
        
        // Extract all three keys: 32 for key agreement + 32 for signing + 32 for identity
        let key_agreement_bytes: [u8; 32] = public_key_data[0..32]
            .try_into()
            .map_err(|_| EncryptionError::InvalidPublicKey)?;
        let signing_key_bytes: [u8; 32] = public_key_data[32..64]
            .try_into()
            .map_err(|_| EncryptionError::InvalidPublicKey)?;
        let identity_key_bytes: [u8; 32] = public_key_data[64..96]
            .try_into()
            .map_err(|_| EncryptionError::InvalidPublicKey)?;
        
        let public_key = PublicKey::from(key_agreement_bytes);
        // Parse signing key - iOS keys will parse correctly
        let signing_key = VerifyingKey::from_bytes(&signing_key_bytes)
            .map_err(|_| EncryptionError::InvalidPublicKey)?;
        
        // Parse identity key with Android compatibility fallback
        // Android has a bug where it sends invalid identity keys
        let identity_key = match VerifyingKey::from_bytes(&identity_key_bytes) {
            Ok(key) => key,
            Err(_) => {
                // This is likely Android with the identity key bug
                // For now, just use the signing key as identity key to maintain compatibility
                debug_println!("[CRYPTO] Note: Peer {} appears to be Android (invalid identity key format)", peer_id);
                signing_key.clone()
            }
        };
        
        // Store all keys
        {
            let mut peer_keys = self.peer_public_keys.write().unwrap();
            peer_keys.insert(peer_id.to_string(), public_key);
        }
        {
            let mut signing_keys = self.peer_signing_keys.write().unwrap();
            signing_keys.insert(peer_id.to_string(), signing_key);
        }
        {
            let mut identity_keys = self.peer_identity_keys.write().unwrap();
            identity_keys.insert(peer_id.to_string(), identity_key);
        }
        
        // [CRYPTO] Keys stored successfully - debug output suppressed for clean mode
        
        // Generate shared secret for encryption
        let shared_secret = self.private_key.diffie_hellman(&public_key);
        
        // Derive symmetric key using HKDF (matching Swift's implementation)
        let hkdf = Hkdf::<Sha256>::new(Some(b"bitchat-v1"), shared_secret.as_bytes());
        let mut symmetric_key = [0u8; 32];
        hkdf.expand(&[], &mut symmetric_key)
            .map_err(|_| EncryptionError::EncryptionFailed)?;
        
        // Store shared secret
        {
            let mut secrets = self.shared_secrets.write().unwrap();
            secrets.insert(peer_id.to_string(), symmetric_key);
        }
        
        Ok(())
    }
    
    /// Get peer's persistent identity key for favorites
    pub fn get_peer_identity_key(&self, peer_id: &str) -> Option<Vec<u8>> {
        let identity_keys = self.peer_identity_keys.read().unwrap();
        identity_keys.get(peer_id).map(|key| key.to_bytes().to_vec())
    }
    
    /// Calculate SHA256 fingerprint of a peer's identity key (first 16 bytes as hex)
    pub fn get_peer_fingerprint(&self, peer_id: &str) -> Option<String> {
        self.get_peer_identity_key(peer_id).map(|key_bytes| {
            use sha2::Digest;
            let hash = Sha256::digest(&key_bytes);
            // Take first 16 bytes and convert to lowercase hex
            hash.iter()
                .take(16)
                .map(|byte| format!("{:02x}", byte))
                .collect::<String>()
        })
    }

    /// Get our own identity fingerprint (SHA256 hash of our static public key)
    pub fn get_identity_fingerprint(&self) -> String {
        use sha2::Digest;
        let hash = Sha256::digest(self.public_key.to_bytes());
        hash.iter()
            .map(|byte| format!("{:02x}", byte))
            .collect::<String>()
    }
    
    /// Encrypt data for a specific peer
    /// Set the Noise session manager for transport cipher encryption
    pub fn set_noise_manager(&mut self, noise_manager: Arc<RwLock<NoiseSessionManager>>) {
        self.noise_manager = Some(noise_manager);
    }
    
    /// Encrypt data for a peer using Noise transport ciphers if available, fallback to legacy
    pub fn encrypt(&self, data: &[u8], peer_id: &str) -> Result<Vec<u8>, EncryptionError> {
        // Try Noise encryption first (for established sessions)
        if let Some(noise_manager) = &self.noise_manager {
            if let Ok(noise_manager) = noise_manager.read() {
                if noise_manager.has_established_session(peer_id) {
                    // We can't call mutable methods on a read guard, so we'll fall back to legacy
                    debug_println!("[CRYPTO] Noise session exists but can't encrypt from read guard, falling back to legacy");
                }
            }
        }
        
        // Fallback to legacy encryption method
        self.encrypt_legacy(data, peer_id)
    }
    
    /// Legacy encryption method (original implementation)
    fn encrypt_legacy(&self, data: &[u8], peer_id: &str) -> Result<Vec<u8>, EncryptionError> {
        let secrets = self.shared_secrets.read().unwrap();
        let symmetric_key = secrets.get(peer_id)
            .ok_or(EncryptionError::NoSharedSecret)?;
        
        let cipher = Aes256Gcm::new_from_slice(symmetric_key)
            .map_err(|_| EncryptionError::EncryptionFailed)?;
        let nonce = Aes256Gcm::generate_nonce(&mut OsRng);
        
        let ciphertext = cipher.encrypt(&nonce, data)
            .map_err(|_| EncryptionError::EncryptionFailed)?;
        
        // Return combined format matching Swift (nonce + ciphertext + tag)
        let mut result = Vec::with_capacity(nonce.len() + ciphertext.len());
        result.extend_from_slice(&nonce);
        result.extend_from_slice(&ciphertext);
        
        Ok(result)
    }
    
    /// Decrypt data from a specific peer using Noise transport ciphers if available, fallback to legacy
    pub fn decrypt(&self, data: &[u8], peer_id: &str) -> Result<Vec<u8>, EncryptionError> {
        // Try Noise decryption first (for established sessions)
        if let Some(noise_manager) = &self.noise_manager {
            if let Ok(noise_manager) = noise_manager.read() {
                if noise_manager.has_established_session(peer_id) {
                    // We can't call mutable methods on a read guard, so we'll fall back to legacy
                    debug_println!("[CRYPTO] Noise session exists but can't decrypt from read guard, falling back to legacy");
                }
            }
        }
        
        // Fallback to legacy decryption method
        self.decrypt_legacy(data, peer_id)
    }
    
    /// Legacy decryption method (original implementation)
    fn decrypt_legacy(&self, data: &[u8], peer_id: &str) -> Result<Vec<u8>, EncryptionError> {
        if data.len() < 12 {  // Minimum size for nonce
            return Err(EncryptionError::DecryptionFailed);
        }
        
        let secrets = self.shared_secrets.read().unwrap();
        let symmetric_key = secrets.get(peer_id)
            .ok_or(EncryptionError::NoSharedSecret)?;
        
        let cipher = Aes256Gcm::new_from_slice(symmetric_key)
            .map_err(|_| EncryptionError::DecryptionFailed)?;
        
        // Extract nonce and ciphertext
        let nonce = Nonce::from_slice(&data[..12]);
        let ciphertext = &data[12..];
        
        let plaintext = cipher.decrypt(nonce, ciphertext)
            .map_err(|_| EncryptionError::DecryptionFailed)?;
        
        Ok(plaintext)
    }
    
    /// Sign data using our signing key
    pub fn sign(&self, data: &[u8]) -> Vec<u8> {
        let signature = self.signing_key.sign(data);
        signature.to_bytes().to_vec()
    }
    
    /// Verify signature from a peer
    #[allow(dead_code)]
    pub fn verify(&self, signature: &[u8], data: &[u8], peer_id: &str) -> Result<bool, EncryptionError> {
        let signing_keys = self.peer_signing_keys.read().unwrap();
        let verifying_key = signing_keys.get(peer_id)
            .ok_or(EncryptionError::NoSharedSecret)?;
        
        let signature_bytes: [u8; 64] = signature.try_into()
            .map_err(|_| EncryptionError::SignatureVerificationFailed)?;
        let signature = Signature::from_bytes(&signature_bytes);
        
        Ok(verifying_key.verify_strict(data, &signature).is_ok())
    }
    
    /// Derive channel key from password (matching Swift's PBKDF2 implementation)
    pub fn derive_channel_key(password: &str, channel_name: &str) -> [u8; 32] {
        let mut key = [0u8; 32];
        pbkdf2_hmac::<Sha256>(
            password.as_bytes(),
            channel_name.as_bytes(),  // Use channel name as salt
            100_000,                  // iterations matching Swift
            &mut key,
        );
        key
    }
    
    /// Encrypt data with a channel key (for password-protected channels)
    pub fn encrypt_with_key(&self, data: &[u8], key: &[u8; 32]) -> Result<Vec<u8>, EncryptionError> {
        let cipher = Aes256Gcm::new_from_slice(key)
            .map_err(|_| EncryptionError::EncryptionFailed)?;
        let nonce = Aes256Gcm::generate_nonce(&mut OsRng);
        
        let ciphertext = cipher.encrypt(&nonce, data)
            .map_err(|_| EncryptionError::EncryptionFailed)?;
        
        // Return combined format (nonce + ciphertext + tag)
        let mut result = Vec::with_capacity(nonce.len() + ciphertext.len());
        result.extend_from_slice(&nonce);
        result.extend_from_slice(&ciphertext);
        
        Ok(result)
    }
    
    /// Decrypt data with a channel key
    pub fn decrypt_with_key(&self, data: &[u8], key: &[u8; 32]) -> Result<Vec<u8>, EncryptionError> {
        if data.len() < 12 {
            return Err(EncryptionError::DecryptionFailed);
        }
        
        let cipher = Aes256Gcm::new_from_slice(key)
            .map_err(|_| EncryptionError::DecryptionFailed)?;
        
        let nonce = Nonce::from_slice(&data[..12]);
        let ciphertext = &data[12..];
        
        let plaintext = cipher.decrypt(nonce, ciphertext)
            .map_err(|_| EncryptionError::DecryptionFailed)?;
        
        Ok(plaintext)
    }
    
    /// Check if we have a peer's encryption key
    pub fn has_peer_key(&self, peer_id: &str) -> bool {
        let shared_secrets = self.shared_secrets.read().unwrap();
        shared_secrets.contains_key(peer_id)
    }
    
    /// Encrypt data specifically for a peer (used for ACKs)
    pub fn encrypt_for_peer(&self, peer_id: &str, data: &[u8]) -> Result<Vec<u8>, EncryptionError> {
        // This is the same as encrypt() but makes the intent clearer
        self.encrypt(data, peer_id)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_key_exchange() {
        let alice = EncryptionService::new();
        let bob = EncryptionService::new();
        
        // Exchange public keys
        let alice_keys = alice.get_combined_public_key_data();
        let bob_keys = bob.get_combined_public_key_data();
        
        assert_eq!(alice_keys.len(), 96);
        assert_eq!(bob_keys.len(), 96);
        
        // Add each other's keys
        alice.add_peer_public_key("bob", &bob_keys).unwrap();
        bob.add_peer_public_key("alice", &alice_keys).unwrap();
        
        // Test encryption/decryption
        let message = b"Hello, Bob!";
        let encrypted = alice.encrypt(message, "bob").unwrap();
        let decrypted = bob.decrypt(&encrypted, "alice").unwrap();
        
        assert_eq!(message, &decrypted[..]);
    }
    
    #[test]
    fn test_channel_key_derivation() {
        let key1 = EncryptionService::derive_channel_key("password123", "#general");
        let key2 = EncryptionService::derive_channel_key("password123", "#general");
        let key3 = EncryptionService::derive_channel_key("different", "#general");
        
        assert_eq!(key1, key2);  // Same password + channel = same key
        assert_ne!(key1, key3);  // Different password = different key
    }
}