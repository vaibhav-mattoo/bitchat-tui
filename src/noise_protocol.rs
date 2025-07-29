use chacha20poly1305::{ChaCha20Poly1305, Key as ChaChaKey, Nonce as ChaChaNonce};
use chacha20poly1305::aead::{Aead as ChaChaAead, KeyInit};
use hmac::{Hmac, Mac as HmacMac};
use sha2::{Sha256, Digest};
use x25519_dalek::{StaticSecret, PublicKey};
use crate::debug_full_println;

// MARK: - Constants and Types

#[derive(Debug, Clone, Copy, PartialEq)]
pub enum NoisePattern {
    XX,  // Most versatile, mutual authentication
    IK,  // Initiator knows responder's static key
    NK,  // Anonymous initiator
}

#[derive(Debug, Clone, Copy, PartialEq)]
pub enum NoiseRole {
    Initiator,
    Responder,
}

#[derive(Debug, Clone, Copy, PartialEq)]
pub enum NoiseMessagePattern {
    E,   // Ephemeral key
    S,   // Static key
    EE,  // DH(ephemeral, ephemeral)
    ES,  // DH(ephemeral, static)
    SE,  // DH(static, ephemeral)
    SS,  // DH(static, static)
}

// MARK: - Noise Protocol Configuration

pub struct NoiseProtocolName {
    pub pattern: String,
    pub dh: String,
    pub cipher: String,
    pub hash: String,
}

impl NoiseProtocolName {
    pub fn new(pattern: &str) -> Self {
        Self {
            pattern: pattern.to_string(),
            dh: "25519".to_string(),
            cipher: "ChaChaPoly".to_string(),
            hash: "SHA256".to_string(),
        }
    }
    
    pub fn full_name(&self) -> String {
        format!("Noise_{}_{}_{}_{}", self.pattern, self.dh, self.cipher, self.hash)
    }
}

// MARK: - Errors

#[derive(Debug, thiserror::Error)]
pub enum NoiseError {
    #[error("Uninitialized cipher")]
    UninitializedCipher,
    #[error("Invalid ciphertext")]
    InvalidCiphertext,
    #[error("Handshake complete")]
    HandshakeComplete,
    #[error("Handshake not complete")]
    HandshakeNotComplete,
    #[error("Missing local static key")]
    MissingLocalStaticKey,
    #[error("Missing keys")]
    MissingKeys,
    #[error("Invalid message")]
    InvalidMessage,
    #[error("Authentication failure")]
    AuthenticationFailure,
    #[error("Invalid public key")]
    InvalidPublicKey,
    #[error("Replay detected")]
    ReplayDetected,
    #[error("Nonce exceeded")]
    NonceExceeded,
    #[error("Encryption failed")]
    EncryptionFailed,
    #[error("Decryption failed")]
    DecryptionFailed,
} 

// MARK: - Cipher State

// Constants for replay protection
const NONCE_SIZE_BYTES: usize = 4;
const REPLAY_WINDOW_SIZE: usize = 1024;
const REPLAY_WINDOW_BYTES: usize = REPLAY_WINDOW_SIZE / 8; // 128 bytes
const HIGH_NONCE_WARNING_THRESHOLD: u64 = 1_000_000_000;

/// Manages symmetric encryption state for Noise protocol sessions.
/// Handles ChaCha20-Poly1305 AEAD encryption with automatic nonce management
/// and replay protection using a sliding window algorithm.
pub struct NoiseCipherState {
    pub key: Option<ChaChaKey>,
    pub nonce: u64,
    pub use_extracted_nonce: bool,
    
    // Sliding window replay protection (only used when use_extracted_nonce = true)
    pub highest_received_nonce: u64,
    pub replay_window: [u8; REPLAY_WINDOW_BYTES],
}

impl NoiseCipherState {
    pub fn new() -> Self {
        Self {
            key: None,
            nonce: 0,
            use_extracted_nonce: false,
            highest_received_nonce: 0,
            replay_window: [0u8; REPLAY_WINDOW_BYTES],
        }
    }
    
    pub fn new_with_key(key: ChaChaKey, use_extracted_nonce: bool) -> Self {
        Self {
            key: Some(key),
            nonce: 0,
            use_extracted_nonce,
            highest_received_nonce: 0,
            replay_window: [0u8; REPLAY_WINDOW_BYTES],
        }
    }
    
    pub fn initialize_key(&mut self, key: ChaChaKey) {
        self.key = Some(key);
        self.nonce = 0;
    }
    
    pub fn has_key(&self) -> bool {
        self.key.is_some()
    }
    
    // MARK: - Sliding Window Replay Protection
    
    /// Check if nonce is valid for replay protection
    fn is_valid_nonce(&self, received_nonce: u64) -> bool {
        if received_nonce + REPLAY_WINDOW_SIZE as u64 <= self.highest_received_nonce {
            return false;  // Too old, outside window
        }
        
        if received_nonce > self.highest_received_nonce {
            return true;  // Always accept newer nonces
        }
        
        let offset = (self.highest_received_nonce - received_nonce) as usize;
        let byte_index = offset / 8;
        let bit_index = offset % 8;
        
        (self.replay_window[byte_index] & (1 << bit_index)) == 0  // Not yet seen
    }
    
    /// Mark nonce as seen in replay window
    fn mark_nonce_as_seen(&mut self, received_nonce: u64) {
        if received_nonce > self.highest_received_nonce {
            let shift = (received_nonce - self.highest_received_nonce) as usize;
            
            if shift >= REPLAY_WINDOW_SIZE {
                // Clear entire window - shift is too large
                self.replay_window = [0u8; REPLAY_WINDOW_BYTES];
            } else {
                // Shift window right by `shift` bits
                for i in (0..REPLAY_WINDOW_BYTES).rev() {
                    let source_byte_index = if i >= shift / 8 { i - shift / 8 } else { 0 };
                    let mut new_byte: u8 = 0;
                    
                    if source_byte_index < REPLAY_WINDOW_BYTES {
                        new_byte = self.replay_window[source_byte_index] >> (shift % 8);
                        if source_byte_index > 0 && shift % 8 != 0 {
                            new_byte |= self.replay_window[source_byte_index - 1] << (8 - shift % 8);
                        }
                    }
                    
                    self.replay_window[i] = new_byte;
                }
            }
            
            self.highest_received_nonce = received_nonce;
            self.replay_window[0] |= 1;  // Mark most recent bit as seen
        } else {
            let offset = (self.highest_received_nonce - received_nonce) as usize;
            let byte_index = offset / 8;
            let bit_index = offset % 8;
            self.replay_window[byte_index] |= 1 << bit_index;
        }
    }
    
    /// Extract nonce from combined payload <nonce><ciphertext>
    /// Returns tuple of (nonce, ciphertext) or None if invalid
    fn extract_nonce_from_ciphertext_payload(&self, combined_payload: &[u8]) -> Option<(u64, Vec<u8>)> {
        if combined_payload.len() < NONCE_SIZE_BYTES {
            return None;
        }

        // Extract 4-byte nonce (big-endian)
        let nonce_data = &combined_payload[..NONCE_SIZE_BYTES];
        let mut extracted_nonce: u64 = 0;
        for &byte in nonce_data {
            extracted_nonce = (extracted_nonce << 8) | byte as u64;
        }

        // Extract ciphertext (remaining bytes)
        let ciphertext = combined_payload[NONCE_SIZE_BYTES..].to_vec();

        Some((extracted_nonce, ciphertext))
    }

    /// Convert nonce to 4-byte array (big-endian)
    fn nonce_to_bytes(&self, nonce: u64) -> Vec<u8> {
        let mut bytes = vec![0u8; NONCE_SIZE_BYTES];
        let nonce_be = nonce.to_be_bytes();
        // Copy only the last 4 bytes from the 8-byte u64
        bytes.copy_from_slice(&nonce_be[4..]);
        bytes
    }
    
    pub fn encrypt(&mut self, plaintext: &[u8], _associated_data: &[u8]) -> Result<Vec<u8>, NoiseError> {
        let key = self.key.as_ref().ok_or(NoiseError::UninitializedCipher)?;
        
        // Debug logging for nonce tracking
        let current_nonce = self.nonce;
        
        // Check if nonce exceeds 4-byte limit (u32 max value)
        if self.nonce > u32::MAX as u64 - 1 {
            return Err(NoiseError::NonceExceeded);
        }
        
        // Create nonce from counter (12 bytes, with nonce in bytes 4-12)
        let mut nonce_data = [0u8; 12];
        let nonce_bytes = current_nonce.to_le_bytes();
        nonce_data[4..12].copy_from_slice(&nonce_bytes);
        
        let cipher = ChaCha20Poly1305::new(key);
        let nonce = ChaChaNonce::from_slice(&nonce_data);
        
        let ciphertext = cipher.encrypt(nonce, plaintext)
            .map_err(|_| NoiseError::EncryptionFailed)?;
        
        // Increment local nonce
        self.nonce += 1;
               
        // Create combined payload: <nonce><ciphertext>
        let combined_payload: Vec<u8>;
        if self.use_extracted_nonce {
            let nonce_bytes = self.nonce_to_bytes(current_nonce);
            combined_payload = [nonce_bytes, ciphertext].concat();
        } else {
            combined_payload = ciphertext;
        }
        
        // Log high nonce values that might indicate issues
        if current_nonce > HIGH_NONCE_WARNING_THRESHOLD {
            debug_full_println!("[NOISE] High nonce value detected: {} - consider rekeying", current_nonce);
        }
                
        Ok(combined_payload)
    }
    
    pub fn decrypt(&mut self, ciphertext: &[u8], _associated_data: &[u8]) -> Result<Vec<u8>, NoiseError> {
        let key = self.key.as_ref().ok_or(NoiseError::UninitializedCipher)?;
        
        if ciphertext.len() < 16 {
            return Err(NoiseError::InvalidCiphertext);
        }
        
        let encrypted_data: Vec<u8>;
        let tag: Vec<u8>;
        let decryption_nonce: u64;
        
        if self.use_extracted_nonce {
            // Extract nonce and ciphertext from combined payload
            let (extracted_nonce, actual_ciphertext) = self.extract_nonce_from_ciphertext_payload(ciphertext)
                .ok_or(NoiseError::InvalidCiphertext)?;
            
            // Validate nonce with sliding window replay protection
            if !self.is_valid_nonce(extracted_nonce) {
                debug_full_println!("[NOISE] Replay attack detected: nonce {} rejected", extracted_nonce);
                return Err(NoiseError::ReplayDetected);
            }

            // Split ciphertext and tag
            if actual_ciphertext.len() < 16 {
                return Err(NoiseError::InvalidCiphertext);
            }
            encrypted_data = actual_ciphertext[..actual_ciphertext.len() - 16].to_vec();
            tag = actual_ciphertext[actual_ciphertext.len() - 16..].to_vec();
            decryption_nonce = extracted_nonce;
        } else {
            // Split ciphertext and tag
            encrypted_data = ciphertext[..ciphertext.len() - 16].to_vec();
            tag = ciphertext[ciphertext.len() - 16..].to_vec();
            decryption_nonce = self.nonce;
        }
        
        // Create nonce from counter (12 bytes, with nonce in bytes 4-12)
        let mut nonce_data = [0u8; 12];
        let nonce_bytes = decryption_nonce.to_le_bytes();
        nonce_data[4..12].copy_from_slice(&nonce_bytes);
        
        let cipher = ChaCha20Poly1305::new(key);
        let nonce = ChaChaNonce::from_slice(&nonce_data);
        
        // Log high nonce values that might indicate issues
        if decryption_nonce > HIGH_NONCE_WARNING_THRESHOLD {
            debug_full_println!("[NOISE] High nonce value detected: {} - consider rekeying", decryption_nonce);
        }
        
        // Combine encrypted data and tag
        let mut combined_ciphertext = encrypted_data;
        combined_ciphertext.extend_from_slice(&tag);
        
        let plaintext = cipher.decrypt(nonce, &*combined_ciphertext)
            .map_err(|_| NoiseError::DecryptionFailed)?;
        
        if self.use_extracted_nonce {
            // Mark nonce as seen after successful decryption
            self.mark_nonce_as_seen(decryption_nonce);
        }
        self.nonce += 1;
        
        Ok(plaintext)
    }
}

// MARK: - Symmetric State

/// Manages the symmetric cryptographic state during Noise handshakes.
/// Responsible for key derivation, protocol name hashing, and maintaining
/// the chaining key that provides key separation between handshake messages.
pub struct NoiseSymmetricState {
    pub cipher_state: NoiseCipherState,
    pub chaining_key: Vec<u8>,
    pub hash: Vec<u8>,
}

impl NoiseSymmetricState {
    pub fn new(protocol_name: &str) -> Self {
        let mut hash = vec![0u8; 32];
        let name_data = protocol_name.as_bytes();
        
        if name_data.len() <= 32 {
            hash[..name_data.len()].copy_from_slice(name_data);
        } else {
            let mut hasher = Sha256::new();
            hasher.update(name_data);
            hash.copy_from_slice(&hasher.finalize());
        }
        
        Self {
            cipher_state: NoiseCipherState::new(),
            chaining_key: hash.clone(),
            hash,
        }
    }
    
    pub fn mix_key(&mut self, input_key_material: &[u8]) {
        let output = self.hkdf(&self.chaining_key, input_key_material, 2);
        self.chaining_key = output[0].clone();
        let temp_key = ChaChaKey::clone_from_slice(&output[1]);
        self.cipher_state.initialize_key(temp_key);
    }
    
    pub fn mix_hash(&mut self, data: &[u8]) {
        let mut hasher = Sha256::new();
        hasher.update(&self.hash);
        hasher.update(data);
        self.hash = hasher.finalize().to_vec();
    }
    
    pub fn mix_key_and_hash(&mut self, input_key_material: &[u8]) {
        let output = self.hkdf(&self.chaining_key, input_key_material, 3);
        self.chaining_key = output[0].clone();
        self.mix_hash(&output[1]);
        let temp_key = ChaChaKey::clone_from_slice(&output[2]);
        self.cipher_state.initialize_key(temp_key);
    }
    
    pub fn get_handshake_hash(&self) -> Vec<u8> {
        self.hash.clone()
    }
    
    pub fn has_cipher_key(&self) -> bool {
        self.cipher_state.has_key()
    }
    
    pub fn encrypt_and_hash(&mut self, plaintext: &[u8]) -> Result<Vec<u8>, NoiseError> {
        if self.cipher_state.has_key() {
            let ciphertext = self.cipher_state.encrypt(plaintext, &self.hash)?;
            self.mix_hash(&ciphertext);
            Ok(ciphertext)
        } else {
            self.mix_hash(plaintext);
            Ok(plaintext.to_vec())
        }
    }
    
    pub fn decrypt_and_hash(&mut self, ciphertext: &[u8]) -> Result<Vec<u8>, NoiseError> {
        if self.cipher_state.has_key() {
            let plaintext = self.cipher_state.decrypt(ciphertext, &self.hash)?;
            self.mix_hash(ciphertext);
            Ok(plaintext)
        } else {
            self.mix_hash(ciphertext);
            Ok(ciphertext.to_vec())
        }
    }
    
    pub fn split(&self) -> (NoiseCipherState, NoiseCipherState) {
        let output = self.hkdf(&self.chaining_key, &[], 2);
        let temp_key1 = ChaChaKey::clone_from_slice(&output[0]);
        let temp_key2 = ChaChaKey::clone_from_slice(&output[1]);
        
        let c1 = NoiseCipherState::new_with_key(temp_key1, true);
        let c2 = NoiseCipherState::new_with_key(temp_key2, true);
        
        (c1, c2)
    }
    
    // HKDF implementation matching Swift version
    fn hkdf(&self, chaining_key: &[u8], input_key_material: &[u8], num_outputs: usize) -> Vec<Vec<u8>> {
        let mut mac = <Hmac<Sha256> as hmac::Mac>::new_from_slice(chaining_key).unwrap();
        HmacMac::update(&mut mac, input_key_material);
        let temp_key = mac.finalize().into_bytes();
        
        let mut outputs = Vec::new();
        let mut current_output = Vec::new();
        
        for i in 1..=num_outputs {
            let mut mac = <Hmac<Sha256> as hmac::Mac>::new_from_slice(&temp_key).unwrap();
            HmacMac::update(&mut mac, &current_output);
            HmacMac::update(&mut mac, &[i as u8]);
            current_output = mac.finalize().into_bytes().to_vec();
            outputs.push(current_output.clone());
        }
        
        outputs
    }
} 

// MARK: - Handshake State

/// Orchestrates the complete Noise handshake process.
/// This is the main interface for establishing encrypted sessions between peers.
/// Manages the handshake state machine, message patterns, and key derivation.
pub struct NoiseHandshakeState {
    pub role: NoiseRole,
    pub pattern: NoisePattern,
    pub symmetric_state: NoiseSymmetricState,
    
    // Keys
    pub local_static_private: Option<StaticSecret>,
    pub local_static_public: Option<PublicKey>,
    pub local_ephemeral_private: Option<StaticSecret>,
    pub local_ephemeral_public: Option<PublicKey>,
    
    pub remote_static_public: Option<PublicKey>,
    pub remote_ephemeral_public: Option<PublicKey>,
    
    // Message patterns
    pub message_patterns: Vec<Vec<NoiseMessagePattern>>,
    pub current_pattern: usize,
}

impl NoiseHandshakeState {
    pub fn new(role: NoiseRole, pattern: NoisePattern, local_static_key: Option<StaticSecret>, remote_static_key: Option<PublicKey>) -> Self {
        // Initialize protocol name
        let protocol_name = NoiseProtocolName::new(&pattern.pattern_name());
        let symmetric_state = NoiseSymmetricState::new(&protocol_name.full_name());
        
        // Initialize message patterns
        let message_patterns = pattern.message_patterns();
        
        let mut handshake = Self {
            role,
            pattern,
            symmetric_state,
            local_static_private: local_static_key.clone(),
            local_static_public: local_static_key.as_ref().map(|k| PublicKey::from(k)),
            local_ephemeral_private: None,
            local_ephemeral_public: None,
            remote_static_public: remote_static_key,
            remote_ephemeral_public: None,
            message_patterns,
            current_pattern: 0,
        };
        
        // Mix pre-message keys according to pattern
        handshake.mix_pre_message_keys();
        handshake
    }
    
    fn mix_pre_message_keys(&mut self) {
        // Mix prologue (empty for XX pattern normally)
        self.symmetric_state.mix_hash(&[]); // Empty prologue for XX pattern
        // For XX pattern, no pre-message keys
        // For IK/NK patterns, we'd mix the responder's static key here
        match self.pattern {
            NoisePattern::XX => {
                // No pre-message keys
            }
            NoisePattern::IK | NoisePattern::NK => {
                if matches!(self.role, NoiseRole::Initiator) {
                    if let Some(remote_static) = self.remote_static_public {
                        self.symmetric_state.mix_hash(&remote_static.to_bytes());
                    }
                }
            }
        }
    }
    
    pub fn write_message(&mut self, payload: &[u8]) -> Result<Vec<u8>, NoiseError> {
        if self.current_pattern >= self.message_patterns.len() {
            return Err(NoiseError::HandshakeComplete);
        }
                
        let mut message_buffer = Vec::new();
        let patterns = &self.message_patterns[self.current_pattern];
        
        for pattern in patterns {
            match pattern {
                NoiseMessagePattern::E => {
                    // Generate ephemeral key
                    self.local_ephemeral_private = Some(StaticSecret::random_from_rng(&mut rand::thread_rng()));
                    self.local_ephemeral_public = Some(PublicKey::from(self.local_ephemeral_private.as_ref().unwrap()));
                    message_buffer.extend_from_slice(&self.local_ephemeral_public.as_ref().unwrap().to_bytes());
                    self.symmetric_state.mix_hash(&self.local_ephemeral_public.as_ref().unwrap().to_bytes());
                }
                
                NoiseMessagePattern::S => {
                    // Send static key (encrypted if cipher is initialized)
                    let static_public = self.local_static_public.as_ref()
                        .ok_or(NoiseError::MissingLocalStaticKey)?;
                    let encrypted = self.symmetric_state.encrypt_and_hash(&static_public.to_bytes())?;
                    message_buffer.extend_from_slice(&encrypted);
                }
                
                NoiseMessagePattern::EE => {
                    // DH(local ephemeral, remote ephemeral)
                    let local_ephemeral = self.local_ephemeral_private.as_ref()
                        .ok_or(NoiseError::MissingKeys)?;
                    let remote_ephemeral = self.remote_ephemeral_public.as_ref()
                        .ok_or(NoiseError::MissingKeys)?;
                    let shared = local_ephemeral.diffie_hellman(remote_ephemeral);
                    self.symmetric_state.mix_key(&shared.to_bytes());
                }
                
                NoiseMessagePattern::ES => {
                    // DH(ephemeral, static) - direction depends on role
                    match self.role {
                        NoiseRole::Initiator => {
                            let local_ephemeral = self.local_ephemeral_private.as_ref()
                                .ok_or(NoiseError::MissingKeys)?;
                            let remote_static = self.remote_static_public.as_ref()
                                .ok_or(NoiseError::MissingKeys)?;
                            let shared = local_ephemeral.diffie_hellman(remote_static);
                            self.symmetric_state.mix_key(&shared.to_bytes());
                        }
                        NoiseRole::Responder => {
                            let local_static = self.local_static_private.as_ref()
                                .ok_or(NoiseError::MissingKeys)?;
                            let remote_ephemeral = self.remote_ephemeral_public.as_ref()
                                .ok_or(NoiseError::MissingKeys)?;
                            let shared = local_static.diffie_hellman(remote_ephemeral);
                            self.symmetric_state.mix_key(&shared.to_bytes());
                        }
                    }
                }
                
                NoiseMessagePattern::SE => {
                    // DH(static, ephemeral) - direction depends on role
                    match self.role {
                        NoiseRole::Initiator => {
                            let local_static = self.local_static_private.as_ref()
                                .ok_or(NoiseError::MissingKeys)?;
                            let remote_ephemeral = self.remote_ephemeral_public.as_ref()
                                .ok_or(NoiseError::MissingKeys)?;
                            let shared = local_static.diffie_hellman(remote_ephemeral);
                            self.symmetric_state.mix_key(&shared.to_bytes());
                        }
                        NoiseRole::Responder => {
                            let local_ephemeral = self.local_ephemeral_private.as_ref()
                                .ok_or(NoiseError::MissingKeys)?;
                            let remote_static = self.remote_static_public.as_ref()
                                .ok_or(NoiseError::MissingKeys)?;
                            let shared = local_ephemeral.diffie_hellman(remote_static);
                            self.symmetric_state.mix_key(&shared.to_bytes());
                        }
                    }
                }
                
                NoiseMessagePattern::SS => {
                    // DH(static, static)
                    let local_static = self.local_static_private.as_ref()
                        .ok_or(NoiseError::MissingKeys)?;
                    let remote_static = self.remote_static_public.as_ref()
                        .ok_or(NoiseError::MissingKeys)?;
                    let shared = local_static.diffie_hellman(remote_static);
                    self.symmetric_state.mix_key(&shared.to_bytes());
                }
            }
        }
        
        // Encrypt payload
        let encrypted_payload = self.symmetric_state.encrypt_and_hash(payload)?;
        message_buffer.extend_from_slice(&encrypted_payload);
        
        self.current_pattern += 1;
        Ok(message_buffer)
    }
    
    pub fn read_message(&mut self, message: &[u8]) -> Result<Vec<u8>, NoiseError> {
        if self.current_pattern >= self.message_patterns.len() {
            return Err(NoiseError::HandshakeComplete);
        }
                
        let mut buffer = message.to_vec();
        let patterns = &self.message_patterns[self.current_pattern];
        
        for pattern in patterns {
            match pattern {
                NoiseMessagePattern::E => {
                    // Read ephemeral key
                    if buffer.len() < 32 {
                        return Err(NoiseError::InvalidMessage);
                    }
                    let ephemeral_bytes = buffer[..32].to_vec();
                    buffer = buffer[32..].to_vec();
                    
                    self.remote_ephemeral_public = Some(PublicKey::from(TryInto::<[u8; 32]>::try_into(ephemeral_bytes.clone()).unwrap()));
                    self.symmetric_state.mix_hash(&ephemeral_bytes);
                }
                
                NoiseMessagePattern::S => {
                    // Read static key (encrypted if cipher is initialized)
                    let static_key = self.symmetric_state.decrypt_and_hash(&buffer)?;
                    buffer = buffer[static_key.len()..].to_vec();
                    
                    self.remote_static_public = Some(PublicKey::from(TryInto::<[u8; 32]>::try_into(static_key).unwrap()));
                }
                
                NoiseMessagePattern::EE => {
                    // DH(local ephemeral, remote ephemeral)
                    let local_ephemeral = self.local_ephemeral_private.as_ref()
                        .ok_or(NoiseError::MissingKeys)?;
                    let remote_ephemeral = self.remote_ephemeral_public.as_ref()
                        .ok_or(NoiseError::MissingKeys)?;
                    let shared = local_ephemeral.diffie_hellman(remote_ephemeral);
                    self.symmetric_state.mix_key(&shared.to_bytes());
                }
                
                NoiseMessagePattern::ES => {
                    // DH(ephemeral, static) - direction depends on role
                    match self.role {
                        NoiseRole::Initiator => {
                            let local_ephemeral = self.local_ephemeral_private.as_ref()
                                .ok_or(NoiseError::MissingKeys)?;
                            let remote_static = self.remote_static_public.as_ref()
                                .ok_or(NoiseError::MissingKeys)?;
                            let shared = local_ephemeral.diffie_hellman(remote_static);
                            self.symmetric_state.mix_key(&shared.to_bytes());
                        }
                        NoiseRole::Responder => {
                            let local_static = self.local_static_private.as_ref()
                                .ok_or(NoiseError::MissingKeys)?;
                            let remote_ephemeral = self.remote_ephemeral_public.as_ref()
                                .ok_or(NoiseError::MissingKeys)?;
                            let shared = local_static.diffie_hellman(remote_ephemeral);
                            self.symmetric_state.mix_key(&shared.to_bytes());
                        }
                    }
                }
                
                NoiseMessagePattern::SE => {
                    // DH(static, ephemeral) - direction depends on role
                    match self.role {
                        NoiseRole::Initiator => {
                            let local_static = self.local_static_private.as_ref()
                                .ok_or(NoiseError::MissingKeys)?;
                            let remote_ephemeral = self.remote_ephemeral_public.as_ref()
                                .ok_or(NoiseError::MissingKeys)?;
                            let shared = local_static.diffie_hellman(remote_ephemeral);
                            self.symmetric_state.mix_key(&shared.to_bytes());
                        }
                        NoiseRole::Responder => {
                            let local_ephemeral = self.local_ephemeral_private.as_ref()
                                .ok_or(NoiseError::MissingKeys)?;
                            let remote_static = self.remote_static_public.as_ref()
                                .ok_or(NoiseError::MissingKeys)?;
                            let shared = local_ephemeral.diffie_hellman(remote_static);
                            self.symmetric_state.mix_key(&shared.to_bytes());
                        }
                    }
                }
                
                NoiseMessagePattern::SS => {
                    // DH(static, static)
                    let local_static = self.local_static_private.as_ref()
                        .ok_or(NoiseError::MissingKeys)?;
                    let remote_static = self.remote_static_public.as_ref()
                        .ok_or(NoiseError::MissingKeys)?;
                    let shared = local_static.diffie_hellman(remote_static);
                    self.symmetric_state.mix_key(&shared.to_bytes());
                }
            }
        }
        
        // Decrypt payload
        let decrypted_payload = self.symmetric_state.decrypt_and_hash(&buffer)?;
        
        self.current_pattern += 1;
        Ok(decrypted_payload)
    }
    
    pub fn is_handshake_complete(&self) -> bool {
        self.current_pattern >= self.message_patterns.len()
    }
    
    pub fn get_transport_ciphers(&self) -> Result<(NoiseCipherState, NoiseCipherState), NoiseError> {
        if !self.is_handshake_complete() {
            return Err(NoiseError::HandshakeNotComplete);
        }
        
        let (c1, c2) = self.symmetric_state.split();
        
        // Initiator uses c1 for sending, c2 for receiving
        // Responder uses c2 for sending, c1 for receiving
        Ok(match self.role {
            NoiseRole::Initiator => (c1, c2),
            NoiseRole::Responder => (c2, c1),
        })
    }
    
    pub fn get_remote_static_public_key(&self) -> Option<PublicKey> {
        self.remote_static_public
    }
    
    pub fn get_handshake_hash(&self) -> Vec<u8> {
        self.symmetric_state.get_handshake_hash()
    }
}

// MARK: - Pattern Extensions

impl NoisePattern {
    pub fn pattern_name(&self) -> &'static str {
        match self {
            NoisePattern::XX => "XX",
            NoisePattern::IK => "IK",
            NoisePattern::NK => "NK",
        }
    }
    
    pub fn message_patterns(&self) -> Vec<Vec<NoiseMessagePattern>> {
        match self {
            NoisePattern::XX => {
                vec![
                    vec![NoiseMessagePattern::E],           // -> e
                    vec![NoiseMessagePattern::E, NoiseMessagePattern::EE, NoiseMessagePattern::S, NoiseMessagePattern::ES], // <- e, ee, s, es
                    vec![NoiseMessagePattern::S, NoiseMessagePattern::SE]       // -> s, se
                ]
            }
            NoisePattern::IK => {
                vec![
                    vec![NoiseMessagePattern::E, NoiseMessagePattern::ES, NoiseMessagePattern::S, NoiseMessagePattern::SS], // -> e, es, s, ss
                    vec![NoiseMessagePattern::E, NoiseMessagePattern::EE, NoiseMessagePattern::SE]      // <- e, ee, se
                ]
            }
            NoisePattern::NK => {
                vec![
                    vec![NoiseMessagePattern::E, NoiseMessagePattern::ES],      // -> e, es
                    vec![NoiseMessagePattern::E, NoiseMessagePattern::EE]       // <- e, ee
                ]
            }
        }
    }
}

// MARK: - Key Validation

impl NoiseHandshakeState {
    /// Validate a Curve25519 public key
    /// Checks for weak/invalid keys that could compromise security
    pub fn validate_public_key(key_data: &[u8]) -> Result<PublicKey, NoiseError> {
        // Check key length
        if key_data.len() != 32 {
            return Err(NoiseError::InvalidPublicKey);
        }
        
        // Check for all-zero key (point at infinity)
        if key_data.iter().all(|&b| b == 0) {
            return Err(NoiseError::InvalidPublicKey);
        }
        
        // Check for low-order points that could enable small subgroup attacks
        // These are the known bad points for Curve25519
        let low_order_points: [&[u8]; 8] = [
            &[0x00; 32], // Already checked above
            &[0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01], // Point of order 1
            &[0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01], // Another low-order point
            &[0xe0, 0xeb, 0x7a, 0x7c, 0x3b, 0x41, 0xb8, 0xae, 0x16, 0x56, 0xe3, 0xfa, 0xf1, 0x9f, 0xc4, 0x6a, 0xda, 0x09, 0x8d, 0xeb, 0x9c, 0x32, 0xb1, 0xfd, 0x86, 0x62, 0x05, 0x16, 0x5f, 0x49, 0xb8, 0x00], // Low order point
            &[0x5f, 0x9c, 0x95, 0xbc, 0xa3, 0x50, 0x8c, 0x24, 0xb1, 0xd0, 0xb1, 0x55, 0x9c, 0x83, 0xef, 0x5b, 0x04, 0x44, 0x5c, 0xc4, 0x58, 0x1c, 0x8e, 0x86, 0xd8, 0x22, 0x4e, 0xdd, 0xd0, 0x9f, 0x11, 0x57], // Low order point
            &[0xff; 32], // All ones
            &[0xda, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff], // Another bad point
            &[0xdb, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff], // Another bad point
        ];
        
        // Check against known bad points
        if low_order_points.contains(&key_data) {
            debug_full_println!("[NOISE] Low-order point detected");
            return Err(NoiseError::InvalidPublicKey);
        }
        
        // Try to create the key - x25519-dalek will validate curve points internally
        let key_array: [u8; 32] = key_data.try_into().map_err(|_| NoiseError::InvalidPublicKey)?;
        match PublicKey::from(key_array) {
            public_key => Ok(public_key),
        }
    }
} 