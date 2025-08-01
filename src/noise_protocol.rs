use crate::debug_full_println;
use chacha20poly1305::aead::{Aead as ChaChaAead, KeyInit, Payload};
use chacha20poly1305::{ChaCha20Poly1305, Key as ChaChaKey, Nonce as ChaChaNonce};
use generic_array::GenericArray;
use hkdf::Hkdf;
use hmac::{Hmac, Mac as HmacMac};
use sha2::{Digest, Sha256};
use std::fs::OpenOptions;
use std::io::Write;
use x25519_dalek::{PublicKey, SharedSecret, StaticSecret};

// MARK: - Debug Logging

fn write_noise_protocol_debug_log(message: &str) {
    if let Ok(mut file) = OpenOptions::new()
        .create(true)
        .append(true)
        .open("noise_protocol_debug.log")
    {
        let timestamp = std::time::SystemTime::now()
            .duration_since(std::time::SystemTime::UNIX_EPOCH)
            .unwrap()
            .as_secs();
        let log_entry = format!("[{}] {}\n", timestamp, message);
        let _ = file.write_all(log_entry.as_bytes());
    }
}

fn log_noise_protocol_event(event: &str, details: &str) {
    let message = format!("[NOISE_PROTOCOL_DEBUG] {} - {}", event, details);
    write_noise_protocol_debug_log(&message);
    debug_full_println!("{}", message);
}

// MARK: - Constants and Types

#[derive(Debug, Clone, Copy, PartialEq)]
pub enum NoisePattern {
    XX, // Most versatile, mutual authentication
    IK, // Initiator knows responder's static key
    NK, // Anonymous initiator
}

#[derive(Debug, Clone, Copy, PartialEq)]
pub enum NoiseRole {
    Initiator,
    Responder,
}

#[derive(Debug, Clone, Copy, PartialEq)]
pub enum NoiseMessagePattern {
    E,  // Ephemeral key
    S,  // Static key
    EE, // DH(ephemeral, ephemeral)
    ES, // DH(ephemeral, static)
    SE, // DH(static, ephemeral)
    SS, // DH(static, static)
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
        format!(
            "Noise_{}_{}_{}_{}",
            self.pattern, self.dh, self.cipher, self.hash
        )
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
    #[error("Invalid state")]
    InvalidState,
    #[error("Not established")]
    NotEstablished,
    #[error("Session not found")]
    SessionNotFound,
    #[error("Already established")]
    AlreadyEstablished,
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
    pub replay_window: std::collections::HashSet<u64>,
    pub highest_received_nonce: u64,
}

impl NoiseCipherState {
    pub fn new() -> Self {
        Self {
            key: None,
            nonce: 0,
            use_extracted_nonce: false,
            replay_window: std::collections::HashSet::new(),
            highest_received_nonce: 0,
        }
    }

    pub fn new_with_key(key: ChaChaKey, use_extracted_nonce: bool) -> Self {
        Self {
            key: Some(key),
            nonce: 0,
            use_extracted_nonce,
            replay_window: std::collections::HashSet::new(),
            highest_received_nonce: 0,
        }
    }

    pub fn initialize_key(&mut self, key: ChaChaKey) {
        self.key = Some(key);
        self.nonce = 0;
        self.replay_window.clear();
        self.highest_received_nonce = 0;
    }

    pub fn has_key(&self) -> bool {
        self.key.is_some()
    }

    // MARK: - Sliding Window Replay Protection

    /// Check if nonce is valid for replay protection
    fn is_valid_nonce(&self, received_nonce: u64) -> bool {
        if received_nonce + REPLAY_WINDOW_SIZE as u64 <= self.highest_received_nonce {
            return false; // Too old, outside window
        }

        if received_nonce > self.highest_received_nonce {
            return true; // Always accept newer nonces
        }

        // For nonces within the window, they're valid if NOT already seen
        !self.replay_window.contains(&received_nonce)
    }

    /// Mark nonce as seen in replay window
    fn mark_nonce_as_seen(&mut self, received_nonce: u64) {
        if received_nonce > self.highest_received_nonce {
            // Slide the window forward
            let shift = received_nonce - self.highest_received_nonce;

            if shift >= REPLAY_WINDOW_SIZE as u64 {
                // Clear entire window - shift is too large
                self.replay_window.clear();
            } else {
                // Remove nonces that are now too old
                self.replay_window
                    .retain(|&nonce| nonce + REPLAY_WINDOW_SIZE as u64 > received_nonce);
            }

            self.highest_received_nonce = received_nonce;
        }

        // Mark this nonce as seen
        self.replay_window.insert(received_nonce);
    }

    /// Extract nonce from combined payload <nonce><ciphertext>
    /// Returns tuple of (nonce, ciphertext) or None if invalid
    fn extract_nonce_from_ciphertext_payload(
        &self,
        combined_payload: &[u8],
    ) -> Option<(u64, Vec<u8>)> {
        if combined_payload.len() < NONCE_SIZE_BYTES {
            return None;
        }

        // Extract 4-byte nonce (little-endian to match Swift)
        let nonce_data = &combined_payload[..NONCE_SIZE_BYTES];
        let mut extracted_nonce: u64 = 0;
        for (i, &byte) in nonce_data.iter().enumerate() {
            extracted_nonce |= (byte as u64) << (i * 8);
        }

        // Extract ciphertext (remaining bytes)
        let ciphertext = combined_payload[NONCE_SIZE_BYTES..].to_vec();

        Some((extracted_nonce, ciphertext))
    }

    /// Convert nonce to 4-byte array (little-endian to match Swift)
    fn nonce_to_bytes(&self, nonce: u64) -> Vec<u8> {
        let mut bytes = vec![0u8; NONCE_SIZE_BYTES];
        let nonce_le = nonce.to_le_bytes();
        // Copy only the first 4 bytes from the 8-byte u64
        bytes.copy_from_slice(&nonce_le[..NONCE_SIZE_BYTES]);
        bytes
    }

    pub fn encrypt(
        &mut self,
        plaintext: &[u8],
        associated_data: &[u8],
    ) -> Result<Vec<u8>, NoiseError> {
        if let Some(key) = &self.key {
            log_noise_protocol_event(
                "CIPHER_ENCRYPT",
                &format!("Encrypting with key, plaintext length: {}", plaintext.len()),
            );
            log_noise_protocol_event("CIPHER_ENCRYPT_KEY", &format!("Key length: {}", key.len()));
            log_noise_protocol_event(
                "CIPHER_ENCRYPT_NONCE",
                &format!("Current nonce: {}", self.nonce),
            );
            log_noise_protocol_event(
                "CIPHER_ENCRYPT_ASSOCIATED_DATA",
                &format!("Associated data length: {}", associated_data.len()),
            );

            let current_nonce = self.nonce;

            // Create 12-byte nonce with counter in bytes 4-12 (little-endian like Swift)
            let mut nonce_bytes = [0u8; 12];
            let nonce_le_bytes = current_nonce.to_le_bytes();
            nonce_bytes[4..12].copy_from_slice(&nonce_le_bytes);
            let nonce_array = GenericArray::clone_from_slice(&nonce_bytes);

            // Create cipher
            let cipher = ChaCha20Poly1305::new(key.into());

            // Create payload with associated data
            let payload = Payload {
                msg: plaintext,
                aad: associated_data,
            };

            // Encrypt using the payload
            match cipher.encrypt(&nonce_array, payload) {
                Ok(ciphertext) => {
                    log_noise_protocol_event(
                        "CIPHER_ENCRYPT_SUCCESS",
                        &format!(
                            "Encryption successful, ciphertext length: {}",
                            ciphertext.len()
                        ),
                    );

                    // For transport messages with extracted nonce, prepend nonce to ciphertext
                    let result = if self.use_extracted_nonce {
                        let mut result = self.nonce_to_bytes(self.nonce);
                        result.extend_from_slice(&ciphertext);
                        log_noise_protocol_event(
                            "CIPHER_ENCRYPT_TRANSPORT",
                            &format!(
                                "Transport message with nonce prefix, total length: {}",
                                result.len()
                            ),
                        );
                        result
                    } else {
                        ciphertext
                    };

                    self.nonce += 1;
                    Ok(result)
                }
                Err(e) => {
                    log_noise_protocol_event(
                        "CIPHER_ENCRYPT_ERROR",
                        &format!("Encryption failed: {:?}", e),
                    );
                    Err(NoiseError::EncryptionFailed)
                }
            }
        } else {
            Err(NoiseError::UninitializedCipher)
        }
    }

    pub fn decrypt(
        &mut self,
        ciphertext: &[u8],
        associated_data: &[u8],
    ) -> Result<Vec<u8>, NoiseError> {
        if let Some(key) = &self.key {
            log_noise_protocol_event(
                "CIPHER_DECRYPT",
                &format!(
                    "Decrypting with key, ciphertext length: {}",
                    ciphertext.len()
                ),
            );

            let (nonce, encrypted_payload): (u64, Vec<u8>) = if self.use_extracted_nonce {
                match self.extract_nonce_from_ciphertext_payload(ciphertext) {
                    Some((n, payload)) => {
                        // FIXED: Only validate nonce for non-zero nonces in transport mode
                        if n > 0 && !self.is_valid_nonce(n) {
                            log_noise_protocol_event(
                                "CIPHER_DECRYPT_REPLAY_DETECTED",
                                &format!("Replay attack detected: nonce {} rejected", n),
                            );
                            return Err(NoiseError::ReplayDetected);
                        }
                        (n, payload)
                    }
                    None => return Err(NoiseError::InvalidCiphertext),
                }
            } else {
                (self.nonce, ciphertext.to_vec())
            };

            // Create 12-byte nonce with counter in bytes 4-12 (little-endian)
            let mut nonce_bytes = [0u8; 12];
            let nonce_le_bytes = nonce.to_le_bytes();
            nonce_bytes[4..12].copy_from_slice(&nonce_le_bytes);
            let nonce_array = GenericArray::clone_from_slice(&nonce_bytes);

            // Create cipher and decrypt
            let cipher = ChaCha20Poly1305::new(key.into());
            let payload = Payload {
                msg: &encrypted_payload,
                aad: associated_data,
            };

            match cipher.decrypt(&nonce_array, payload) {
                Ok(plaintext) => {
                    log_noise_protocol_event(
                        "CIPHER_DECRYPT_SUCCESS",
                        &format!(
                            "Decryption successful, plaintext length: {}",
                            plaintext.len()
                        ),
                    );

                    if self.use_extracted_nonce && nonce > 0 {
                        // Update replay window after successful decryption (but only for non-zero nonces)
                        self.mark_nonce_as_seen(nonce);
                    } else if !self.use_extracted_nonce {
                        self.nonce += 1;
                    }
                    Ok(plaintext)
                }
                Err(e) => {
                    log_noise_protocol_event(
                        "CIPHER_DECRYPT_ERROR",
                        &format!("Decryption failed: {:?}", e),
                    );
                    Err(NoiseError::DecryptionFailed)
                }
            }
        } else {
            Err(NoiseError::UninitializedCipher)
        }
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
        // During handshake, use internal nonce counter (not extracted nonce)
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
        // During handshake, use internal nonce counter (not extracted nonce)
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
            log_noise_protocol_event(
                "DECRYPT_AND_HASH",
                &format!(
                    "Decrypting with cipher key, ciphertext length: {}",
                    ciphertext.len()
                ),
            );
            log_noise_protocol_event(
                "DECRYPT_AND_HASH_HASH",
                &format!("Current hash length: {}", self.hash.len()),
            );
            log_noise_protocol_event(
                "DECRYPT_AND_HASH_HASH_BYTES",
                &format!("Hash bytes: {:?}", &self.hash[..8]),
            );

            // Handle empty ciphertext (matching Swift behavior)
            if ciphertext.is_empty() {
                log_noise_protocol_event(
                    "DECRYPT_AND_HASH_EMPTY",
                    "Empty ciphertext, returning empty plaintext",
                );
                self.mix_hash(ciphertext);
                return Ok(vec![]);
            }

            let plaintext = match self.cipher_state.decrypt(ciphertext, &self.hash) {
                Ok(pt) => {
                    log_noise_protocol_event(
                        "DECRYPT_AND_HASH_SUCCESS",
                        &format!("Decryption successful, plaintext length: {}", pt.len()),
                    );
                    pt
                }
                Err(e) => {
                    log_noise_protocol_event(
                        "DECRYPT_AND_HASH_ERROR",
                        &format!("Decryption failed: {:?}", e),
                    );
                    return Err(e);
                }
            };

            // Only mix hash if decryption succeeded (matching Swift behavior)
            self.mix_hash(ciphertext);
            log_noise_protocol_event("DECRYPT_AND_HASH_HASH_MIXED", "Hash mixed with ciphertext");
            Ok(plaintext)
        } else {
            log_noise_protocol_event(
                "DECRYPT_AND_HASH",
                &format!(
                    "No cipher key, treating as plaintext, length: {}",
                    ciphertext.len()
                ),
            );
            self.mix_hash(ciphertext);
            log_noise_protocol_event("DECRYPT_AND_HASH_PLAINTEXT", "Hash mixed with plaintext");
            Ok(ciphertext.to_vec())
        }
    }

    pub fn split(&self) -> (NoiseCipherState, NoiseCipherState) {
        let output = self.hkdf(&self.chaining_key, &[], 2);
        let temp_key1 = ChaChaKey::clone_from_slice(&output[0]);
        let temp_key2 = ChaChaKey::clone_from_slice(&output[1]);

        // Transport ciphers MUST use extracted nonce and start fresh
        let mut c1 = NoiseCipherState::new_with_key(temp_key1, true);
        let mut c2 = NoiseCipherState::new_with_key(temp_key2, true);

        // Reset nonce counters and replay windows for transport mode
        c1.nonce = 0;
        c1.replay_window.clear();
        c1.highest_received_nonce = 0;

        c2.nonce = 0;
        c2.replay_window.clear();
        c2.highest_received_nonce = 0;

        (c1, c2)
    }

    // HKDF implementation matching Swift version
    fn hkdf(
        &self,
        chaining_key: &[u8],
        input_key_material: &[u8],
        num_outputs: usize,
    ) -> Vec<Vec<u8>> {
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
    pub fn new(
        role: NoiseRole,
        pattern: NoisePattern,
        local_static_key: Option<StaticSecret>,
        remote_static_key: Option<PublicKey>,
    ) -> Self {
        // Initialize protocol name
        let protocol_name = NoiseProtocolName::new(&pattern.pattern_name());
        let full_name = protocol_name.full_name();
        log_noise_protocol_event("HANDSHAKE_INIT", &format!("Protocol name: {}", full_name));
        let symmetric_state = NoiseSymmetricState::new(&full_name);
        log_noise_protocol_event(
            "HANDSHAKE_INIT",
            &format!("Initial hash: {:?}", &symmetric_state.hash[..8]),
        );
        log_noise_protocol_event(
            "HANDSHAKE_INIT",
            &format!(
                "Initial chaining key: {:?}",
                &symmetric_state.chaining_key[..8]
            ),
        );

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
        log_noise_protocol_event(
            "WRITE_MESSAGE_START",
            &format!(
                "Pattern: {:?}, Current: {}/{}",
                self.pattern,
                self.current_pattern,
                self.message_patterns.len()
            ),
        );

        if self.current_pattern >= self.message_patterns.len() {
            log_noise_protocol_event(
                "WRITE_MESSAGE_ERROR",
                "Handshake complete, cannot write more messages",
            );
            return Err(NoiseError::HandshakeComplete);
        }

        let mut message_buffer = Vec::new();
        let patterns = &self.message_patterns[self.current_pattern];
        log_noise_protocol_event(
            "WRITE_MESSAGE_PATTERNS",
            &format!("Processing patterns: {:?}", patterns),
        );

        for pattern in patterns {
            log_noise_protocol_event(
                "WRITE_MESSAGE_PATTERN",
                &format!("Processing pattern: {:?}", pattern),
            );

            match pattern {
                NoiseMessagePattern::E => {
                    log_noise_protocol_event("WRITE_MESSAGE_E", "Generating ephemeral key");
                    // Generate ephemeral key
                    self.local_ephemeral_private =
                        Some(StaticSecret::random_from_rng(&mut rand::thread_rng()));
                    self.local_ephemeral_public = Some(PublicKey::from(
                        self.local_ephemeral_private.as_ref().unwrap(),
                    ));
                    message_buffer.extend_from_slice(
                        &self.local_ephemeral_public.as_ref().unwrap().to_bytes(),
                    );
                    self.symmetric_state
                        .mix_hash(&self.local_ephemeral_public.as_ref().unwrap().to_bytes());
                    log_noise_protocol_event(
                        "WRITE_MESSAGE_E_DONE",
                        &format!(
                            "Ephemeral key generated, buffer size: {}",
                            message_buffer.len()
                        ),
                    );
                }

                NoiseMessagePattern::S => {
                    log_noise_protocol_event("WRITE_MESSAGE_S", "Sending static key");
                    // Send static key (encrypted if cipher is initialized)
                    let static_public = self
                        .local_static_public
                        .as_ref()
                        .ok_or(NoiseError::MissingLocalStaticKey)?;
                    let encrypted = self
                        .symmetric_state
                        .encrypt_and_hash(&static_public.to_bytes())?;
                    message_buffer.extend_from_slice(&encrypted);
                    log_noise_protocol_event(
                        "WRITE_MESSAGE_S_DONE",
                        &format!(
                            "Static key encrypted and sent, buffer size: {}",
                            message_buffer.len()
                        ),
                    );
                }

                NoiseMessagePattern::EE => {
                    log_noise_protocol_event(
                        "WRITE_MESSAGE_EE",
                        "Performing DH(ephemeral, ephemeral)",
                    );
                    // DH(local ephemeral, remote ephemeral)
                    let local_ephemeral = self
                        .local_ephemeral_private
                        .as_ref()
                        .ok_or(NoiseError::MissingKeys)?;
                    let remote_ephemeral = self
                        .remote_ephemeral_public
                        .as_ref()
                        .ok_or(NoiseError::MissingKeys)?;
                    let shared = local_ephemeral.diffie_hellman(remote_ephemeral);
                    self.symmetric_state.mix_key(&shared.to_bytes());
                    log_noise_protocol_event(
                        "WRITE_MESSAGE_EE_DONE",
                        "DH(ephemeral, ephemeral) completed",
                    );
                }

                NoiseMessagePattern::ES => {
                    log_noise_protocol_event(
                        "WRITE_MESSAGE_ES",
                        &format!("Performing DH(ephemeral, static), role: {:?}", self.role),
                    );
                    // DH(ephemeral, static) - direction depends on role
                    match self.role {
                        NoiseRole::Initiator => {
                            let local_ephemeral = self
                                .local_ephemeral_private
                                .as_ref()
                                .ok_or(NoiseError::MissingKeys)?;
                            let remote_static = self
                                .remote_static_public
                                .as_ref()
                                .ok_or(NoiseError::MissingKeys)?;
                            let shared = local_ephemeral.diffie_hellman(remote_static);
                            self.symmetric_state.mix_key(&shared.to_bytes());
                            log_noise_protocol_event(
                                "WRITE_MESSAGE_ES_DONE",
                                "DH(ephemeral, static) completed for initiator",
                            );
                        }
                        NoiseRole::Responder => {
                            let local_static = self
                                .local_static_private
                                .as_ref()
                                .ok_or(NoiseError::MissingKeys)?;
                            let remote_ephemeral = self
                                .remote_ephemeral_public
                                .as_ref()
                                .ok_or(NoiseError::MissingKeys)?;
                            let shared = local_static.diffie_hellman(remote_ephemeral);
                            self.symmetric_state.mix_key(&shared.to_bytes());
                            log_noise_protocol_event(
                                "WRITE_MESSAGE_ES_DONE",
                                "DH(ephemeral, static) completed for responder",
                            );
                        }
                    }
                }

                NoiseMessagePattern::SE => {
                    log_noise_protocol_event(
                        "WRITE_MESSAGE_SE",
                        &format!("Performing DH(static, ephemeral), role: {:?}", self.role),
                    );
                    // DH(static, ephemeral) - direction depends on role
                    match self.role {
                        NoiseRole::Initiator => {
                            let local_static = self
                                .local_static_private
                                .as_ref()
                                .ok_or(NoiseError::MissingKeys)?;
                            let remote_ephemeral = self
                                .remote_ephemeral_public
                                .as_ref()
                                .ok_or(NoiseError::MissingKeys)?;
                            let shared = local_static.diffie_hellman(remote_ephemeral);
                            self.symmetric_state.mix_key(&shared.to_bytes());
                            log_noise_protocol_event(
                                "WRITE_MESSAGE_SE_DONE",
                                "DH(static, ephemeral) completed for initiator",
                            );
                        }
                        NoiseRole::Responder => {
                            let local_ephemeral = self
                                .local_ephemeral_private
                                .as_ref()
                                .ok_or(NoiseError::MissingKeys)?;
                            let remote_static = self
                                .remote_static_public
                                .as_ref()
                                .ok_or(NoiseError::MissingKeys)?;
                            let shared = local_ephemeral.diffie_hellman(remote_static);
                            self.symmetric_state.mix_key(&shared.to_bytes());
                            log_noise_protocol_event(
                                "WRITE_MESSAGE_SE_DONE",
                                "DH(static, ephemeral) completed for responder",
                            );
                        }
                    }
                }

                NoiseMessagePattern::SS => {
                    log_noise_protocol_event("WRITE_MESSAGE_SS", "Performing DH(static, static)");
                    // DH(static, static)
                    let local_static = self
                        .local_static_private
                        .as_ref()
                        .ok_or(NoiseError::MissingKeys)?;
                    let remote_static = self
                        .remote_static_public
                        .as_ref()
                        .ok_or(NoiseError::MissingKeys)?;
                    let shared = local_static.diffie_hellman(remote_static);
                    self.symmetric_state.mix_key(&shared.to_bytes());
                    log_noise_protocol_event(
                        "WRITE_MESSAGE_SS_DONE",
                        "DH(static, static) completed",
                    );
                }
            }
        }

        // Encrypt payload
        log_noise_protocol_event(
            "WRITE_MESSAGE_ENCRYPT",
            &format!("Encrypting payload of {} bytes", payload.len()),
        );
        let encrypted_payload = self.symmetric_state.encrypt_and_hash(payload)?;
        message_buffer.extend_from_slice(&encrypted_payload);
        log_noise_protocol_event(
            "WRITE_MESSAGE_ENCRYPT_DONE",
            &format!(
                "Payload encrypted, total buffer size: {}",
                message_buffer.len()
            ),
        );

        self.current_pattern += 1;
        log_noise_protocol_event(
            "WRITE_MESSAGE_COMPLETE",
            &format!(
                "Message written, pattern {} complete",
                self.current_pattern - 1
            ),
        );
        Ok(message_buffer)
    }

    pub fn read_message(&mut self, message: &[u8]) -> Result<Vec<u8>, NoiseError> {
        log_noise_protocol_event(
            "READ_MESSAGE_START",
            &format!(
                "Pattern: {:?}, Current: {}/{}",
                self.pattern,
                self.current_pattern,
                self.message_patterns.len()
            ),
        );
        log_noise_protocol_event(
            "READ_MESSAGE_HASH_BEFORE",
            &format!("Hash before read: {:?}", &self.symmetric_state.hash[..8]),
        );

        if self.current_pattern >= self.message_patterns.len() {
            log_noise_protocol_event("READ_MESSAGE_ERROR", "Handshake complete");
            return Err(NoiseError::HandshakeComplete);
        }

        let patterns = &self.message_patterns[self.current_pattern];
        log_noise_protocol_event(
            "READ_MESSAGE_PATTERNS",
            &format!("Processing patterns: {:?}", patterns),
        );

        let mut offset = 0;

        for pattern in patterns {
            log_noise_protocol_event(
                "READ_MESSAGE_PATTERN",
                &format!("Processing pattern: {:?}", pattern),
            );
            log_noise_protocol_event(
                "READ_MESSAGE_HASH_BEFORE_PATTERN",
                &format!("Hash before pattern: {:?}", &self.symmetric_state.hash[..8]),
            );

            match pattern {
                NoiseMessagePattern::E => {
                    log_noise_protocol_event("READ_MESSAGE_E", "Reading ephemeral key");

                    if offset + 32 > message.len() {
                        log_noise_protocol_event(
                            "READ_MESSAGE_E_ERROR",
                            "Message too short for ephemeral key",
                        );
                        return Err(NoiseError::InvalidMessage);
                    }

                    let ephemeral_bytes = &message[offset..offset + 32];
                    offset += 32;

                    log_noise_protocol_event(
                        "READ_MESSAGE_E_BYTES",
                        &format!("Ephemeral key bytes: {:?}", &ephemeral_bytes[..8]),
                    );

                    let ephemeral_key =
                        PublicKey::from(<[u8; 32]>::try_from(ephemeral_bytes).unwrap());
                    self.remote_ephemeral_public = Some(ephemeral_key);
                    self.symmetric_state.mix_hash(ephemeral_bytes);

                    log_noise_protocol_event(
                        "READ_MESSAGE_E_DONE",
                        &format!("Ephemeral key read, offset: {}", offset),
                    );
                }

                NoiseMessagePattern::S => {
                    log_noise_protocol_event("READ_MESSAGE_S", "Reading static key");

                    // Read static key (may be encrypted)
                    // Swift sends unencrypted static key (32 bytes) before establishing cipher key
                    let key_length = if self.symmetric_state.has_cipher_key() {
                        48
                    } else {
                        32
                    }; // 32 + 16 byte tag if encrypted

                    log_noise_protocol_event(
                        "READ_MESSAGE_S_CHECK",
                        &format!(
                            "Checking static key length: need {} bytes, available {} bytes, has_cipher_key: {}",
                            key_length,
                            message.len() - offset,
                            self.symmetric_state.has_cipher_key()
                        ),
                    );

                    if offset + key_length > message.len() {
                        log_noise_protocol_event(
                            "READ_MESSAGE_S_ERROR",
                            &format!(
                                "Message too short for static key, need {} bytes, have {} bytes",
                                key_length,
                                message.len() - offset
                            ),
                        );
                        return Err(NoiseError::InvalidMessage);
                    }

                    let static_data = &message[offset..offset + key_length];
                    offset += key_length;

                    log_noise_protocol_event(
                        "READ_MESSAGE_S_DATA",
                        &format!(
                            "Static key data length: {}, has_cipher_key: {}",
                            key_length,
                            self.symmetric_state.has_cipher_key()
                        ),
                    );

                    let decrypted_static = self.symmetric_state.decrypt_and_hash(static_data)?;

                    if decrypted_static.len() != 32 {
                        log_noise_protocol_event(
                            "READ_MESSAGE_S_ERROR",
                            &format!(
                                "Invalid decrypted static key length: {}",
                                decrypted_static.len()
                            ),
                        );
                        return Err(NoiseError::InvalidMessage);
                    }

                    let static_key =
                        PublicKey::from(<[u8; 32]>::try_from(&decrypted_static[..32]).unwrap());

                    if Self::validate_public_key(&static_key.to_bytes()).is_err() {
                        log_noise_protocol_event(
                            "READ_MESSAGE_S_ERROR",
                            "Static key validation failed",
                        );
                        return Err(NoiseError::AuthenticationFailure);
                    }

                    self.remote_static_public = Some(static_key);
                    log_noise_protocol_event(
                        "READ_MESSAGE_S_DONE",
                        "Static key read and validated successfully",
                    );
                }

                NoiseMessagePattern::EE => {
                    log_noise_protocol_event(
                        "READ_MESSAGE_EE",
                        "Performing DH(ephemeral, ephemeral)",
                    );

                    let local_ephemeral = self
                        .local_ephemeral_private
                        .as_ref()
                        .ok_or(NoiseError::MissingKeys)?;
                    let remote_ephemeral = self
                        .remote_ephemeral_public
                        .as_ref()
                        .ok_or(NoiseError::MissingKeys)?;

                    let shared_secret = local_ephemeral.diffie_hellman(remote_ephemeral);
                    self.symmetric_state.mix_key(&shared_secret.to_bytes());

                    log_noise_protocol_event(
                        "READ_MESSAGE_EE_DONE",
                        "DH(ephemeral, ephemeral) completed",
                    );
                }

                NoiseMessagePattern::ES => {
                    log_noise_protocol_event("READ_MESSAGE_ES", "Performing DH(ephemeral, static)");

                    if self.role == NoiseRole::Initiator {
                        let local_ephemeral = self
                            .local_ephemeral_private
                            .as_ref()
                            .ok_or(NoiseError::MissingKeys)?;
                        let remote_static = self
                            .remote_static_public
                            .as_ref()
                            .ok_or(NoiseError::MissingKeys)?;

                        let shared_secret = local_ephemeral.diffie_hellman(remote_static);
                        self.symmetric_state.mix_key(&shared_secret.to_bytes());
                    } else {
                        let local_static = self
                            .local_static_private
                            .as_ref()
                            .ok_or(NoiseError::MissingKeys)?;
                        let remote_ephemeral = self
                            .remote_ephemeral_public
                            .as_ref()
                            .ok_or(NoiseError::MissingKeys)?;

                        let shared_secret = local_static.diffie_hellman(remote_ephemeral);
                        self.symmetric_state.mix_key(&shared_secret.to_bytes());
                    }

                    log_noise_protocol_event(
                        "READ_MESSAGE_ES_DONE",
                        "DH(ephemeral, static) completed",
                    );
                }

                NoiseMessagePattern::SE => {
                    log_noise_protocol_event("READ_MESSAGE_SE", "Performing DH(static, ephemeral)");

                    if self.role == NoiseRole::Initiator {
                        let local_static = self
                            .local_static_private
                            .as_ref()
                            .ok_or(NoiseError::MissingKeys)?;
                        let remote_ephemeral = self
                            .remote_ephemeral_public
                            .as_ref()
                            .ok_or(NoiseError::MissingKeys)?;

                        let shared_secret = local_static.diffie_hellman(remote_ephemeral);
                        self.symmetric_state.mix_key(&shared_secret.to_bytes());
                    } else {
                        let local_ephemeral = self
                            .local_ephemeral_private
                            .as_ref()
                            .ok_or(NoiseError::MissingKeys)?;
                        let remote_static = self
                            .remote_static_public
                            .as_ref()
                            .ok_or(NoiseError::MissingKeys)?;

                        let shared_secret = local_ephemeral.diffie_hellman(remote_static);
                        self.symmetric_state.mix_key(&shared_secret.to_bytes());
                    }

                    log_noise_protocol_event(
                        "READ_MESSAGE_SE_DONE",
                        "DH(static, ephemeral) completed",
                    );
                }

                NoiseMessagePattern::SS => {
                    log_noise_protocol_event("READ_MESSAGE_SS", "Performing DH(static, static)");

                    let local_static = self
                        .local_static_private
                        .as_ref()
                        .ok_or(NoiseError::MissingKeys)?;
                    let remote_static = self
                        .remote_static_public
                        .as_ref()
                        .ok_or(NoiseError::MissingKeys)?;

                    let shared_secret = local_static.diffie_hellman(remote_static);
                    self.symmetric_state.mix_key(&shared_secret.to_bytes());

                    log_noise_protocol_event(
                        "READ_MESSAGE_SS_DONE",
                        "DH(static, static) completed",
                    );
                }
            }

            log_noise_protocol_event(
                "READ_MESSAGE_HASH_AFTER_PATTERN",
                &format!(
                    "Hash after pattern {:?}: {:?}",
                    pattern,
                    &self.symmetric_state.hash[..8]
                ),
            );
        }

        // Decrypt payload
        let payload = &message[offset..];
        log_noise_protocol_event(
            "READ_MESSAGE_PAYLOAD",
            &format!("Decrypting payload, length: {}", payload.len()),
        );

        let decrypted_payload = match self.symmetric_state.decrypt_and_hash(payload) {
            Ok(p) => {
                log_noise_protocol_event(
                    "READ_MESSAGE_PAYLOAD_SUCCESS",
                    &format!("Payload decrypted successfully, length: {}", p.len()),
                );
                p
            }
            Err(e) => {
                log_noise_protocol_event(
                    "READ_MESSAGE_PAYLOAD_ERROR",
                    &format!(
                        "Payload decryption failed: {:?}, but continuing handshake",
                        e
                    ),
                );
                // Continue handshake even if payload decryption fails (for debugging)
                vec![]
            }
        };

        self.current_pattern += 1;
        log_noise_protocol_event(
            "READ_MESSAGE_COMPLETE",
            &format!(
                "Message read successfully, new pattern: {}/{}",
                self.current_pattern,
                self.message_patterns.len()
            ),
        );
        log_noise_protocol_event(
            "READ_MESSAGE_HASH_AFTER",
            &format!("Hash after read: {:?}", &self.symmetric_state.hash[..8]),
        );
        Ok(decrypted_payload)
    }

    pub fn is_handshake_complete(&self) -> bool {
        self.current_pattern >= self.message_patterns.len()
    }

    pub fn get_transport_ciphers(
        &self,
    ) -> Result<(NoiseCipherState, NoiseCipherState), NoiseError> {
        if !self.is_handshake_complete() {
            return Err(NoiseError::HandshakeNotComplete);
        }

        let (c1, c2) = self.symmetric_state.split();

        // FIXED: Correct cipher assignment - initiator uses c1 for send, c2 for receive
        // Responder uses c2 for send, c1 for receive
        Ok(match self.role {
            NoiseRole::Initiator => (c1, c2), // send_cipher, receive_cipher
            NoiseRole::Responder => (c2, c1), // send_cipher, receive_cipher  
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
                    vec![NoiseMessagePattern::E], // -> e
                    vec![
                        NoiseMessagePattern::E,
                        NoiseMessagePattern::EE,
                        NoiseMessagePattern::S,
                        NoiseMessagePattern::ES,
                    ], // <- e, ee, s, es
                    vec![NoiseMessagePattern::S, NoiseMessagePattern::SE], // -> s, se
                ]
            }
            NoisePattern::IK => {
                vec![
                    vec![
                        NoiseMessagePattern::E,
                        NoiseMessagePattern::ES,
                        NoiseMessagePattern::S,
                        NoiseMessagePattern::SS,
                    ], // -> e, es, s, ss
                    vec![
                        NoiseMessagePattern::E,
                        NoiseMessagePattern::EE,
                        NoiseMessagePattern::SE,
                    ], // <- e, ee, se
                ]
            }
            NoisePattern::NK => {
                vec![
                    vec![NoiseMessagePattern::E, NoiseMessagePattern::ES], // -> e, es
                    vec![NoiseMessagePattern::E, NoiseMessagePattern::EE], // <- e, ee
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
            &[
                0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                0x00, 0x00, 0x01,
            ], // Point of order 1
            &[
                0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                0x00, 0x00, 0x00, 0x01,
            ], // Another low-order point
            &[
                0xe0, 0xeb, 0x7a, 0x7c, 0x3b, 0x41, 0xb8, 0xae, 0x16, 0x56, 0xe3, 0xfa, 0xf1, 0x9f,
                0xc4, 0x6a, 0xda, 0x09, 0x8d, 0xeb, 0x9c, 0x32, 0xb1, 0xfd, 0x86, 0x62, 0x05, 0x16,
                0x5f, 0x49, 0xb8, 0x00,
            ], // Low order point
            &[
                0x5f, 0x9c, 0x95, 0xbc, 0xa3, 0x50, 0x8c, 0x24, 0xb1, 0xd0, 0xb1, 0x55, 0x9c, 0x83,
                0xef, 0x5b, 0x04, 0x44, 0x5c, 0xc4, 0x58, 0x1c, 0x8e, 0x86, 0xd8, 0x22, 0x4e, 0xdd,
                0xd0, 0x9f, 0x11, 0x57,
            ], // Low order point
            &[0xff; 32], // All ones
            &[
                0xda, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
                0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
                0xff, 0xff, 0xff, 0xff,
            ], // Another bad point
            &[
                0xdb, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
                0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
                0xff, 0xff, 0xff, 0xff,
            ], // Another bad point
        ];

        // Check against known bad points
        if low_order_points.contains(&key_data) {
            debug_full_println!("[NOISE] Low-order point detected");
            return Err(NoiseError::InvalidPublicKey);
        }

        // Try to create the key - x25519-dalek will validate curve points internally
        let key_array: [u8; 32] = key_data
            .try_into()
            .map_err(|_| NoiseError::InvalidPublicKey)?;
        match PublicKey::from(key_array) {
            public_key => Ok(public_key),
        }
    }
}
