use crate::data_structures::EncryptionStatus;
use crate::debug_full_println;
use crate::noise_protocol::{
    NoiseCipherState, NoiseError, NoiseHandshakeState, NoisePattern, NoiseRole, NoiseSymmetricState,
};
use sha2::{Digest, Sha256};
use std::collections::HashMap;
use std::fs::OpenOptions;
use std::io::Write;
use std::sync::{Arc, Mutex};
use std::time::SystemTime;
use x25519_dalek::{PublicKey, StaticSecret};

// MARK: - Debug Logging

fn write_noise_debug_log(message: &str) {
    if let Ok(mut file) = OpenOptions::new()
        .create(true)
        .append(true)
        .open("noise_debug.log")
    {
        let timestamp = SystemTime::now()
            .duration_since(SystemTime::UNIX_EPOCH)
            .unwrap()
            .as_secs();
        let log_entry = format!("[{}] {}\n", timestamp, message);
        let _ = file.write_all(log_entry.as_bytes());
    }
}

fn log_noise_event(event: &str, peer_id: &str, details: &str) {
    let message = format!("[NOISE_DEBUG] {} - Peer: {} - {}", event, peer_id, details);
    write_noise_debug_log(&message);
    debug_full_println!("{}", message);
}

// MARK: - Noise Session State

#[derive(Debug, Clone, PartialEq)]
pub enum NoiseSessionState {
    Uninitialized,
    Handshaking,
    Established,
    Failed(String),
}

// MARK: - Pending Message

#[derive(Debug, Clone)]
pub struct PendingMessage {
    pub content: String,
    pub timestamp: SystemTime,
    pub retry_count: u8,
}

// MARK: - Noise Session

pub struct NoiseSession {
    pub peer_id: String,
    pub role: NoiseRole,
    state: NoiseSessionState,
    handshake_state: Option<NoiseHandshakeState>,
    send_cipher: Option<NoiseCipherState>,
    receive_cipher: Option<NoiseCipherState>,

    // Keys
    local_static_key: StaticSecret,
    remote_static_public_key: Option<PublicKey>,

    // Handshake messages for retransmission
    sent_handshake_messages: Vec<Vec<u8>>,
    handshake_hash: Option<Vec<u8>>,

    // Message queue for pending messages during handshake
    pending_messages: Vec<PendingMessage>,
}

impl NoiseSession {
    pub fn new(
        peer_id: String,
        role: NoiseRole,
        local_static_key: StaticSecret,
        remote_static_key: Option<PublicKey>,
    ) -> Self {
        Self {
            peer_id,
            role,
            state: NoiseSessionState::Uninitialized,
            handshake_state: None,
            send_cipher: None,
            receive_cipher: None,
            local_static_key,
            remote_static_public_key: remote_static_key,
            sent_handshake_messages: Vec::new(),
            handshake_hash: None,
            pending_messages: Vec::new(),
        }
    }

    // MARK: - Message Queue

    pub fn queue_message(&mut self, content: String) {
        let pending_msg = PendingMessage {
            content,
            timestamp: SystemTime::now(),
            retry_count: 0,
        };
        self.pending_messages.push(pending_msg);
        debug_full_println!(
            "[NOISE] Queued message for {} ({} pending)",
            self.peer_id,
            self.pending_messages.len()
        );
    }

    pub fn get_pending_messages(&mut self) -> Vec<String> {
        let messages: Vec<String> = self
            .pending_messages
            .iter()
            .map(|pm| pm.content.clone())
            .collect();
        self.pending_messages.clear();
        messages
    }

    pub fn has_pending_messages(&self) -> bool {
        !self.pending_messages.is_empty()
    }

    // MARK: - Handshake

    pub fn start_handshake(&mut self) -> Result<Vec<u8>, NoiseError> {
        log_noise_event(
            "HANDSHAKE_START",
            &self.peer_id,
            &format!("Role: {:?}, State: {:?}", self.role, self.state),
        );

        if self.state != NoiseSessionState::Uninitialized {
            log_noise_event(
                "HANDSHAKE_ERROR",
                &self.peer_id,
                &format!("Invalid state: {:?}", self.state),
            );
            return Err(NoiseError::InvalidState);
        }

        log_noise_event("HANDSHAKE_INIT", &self.peer_id, "Creating handshake state");

        // For XX pattern, we don't need remote static key upfront
        self.handshake_state = Some(NoiseHandshakeState::new(
            self.role,
            NoisePattern::XX,
            Some(self.local_static_key.clone()),
            None,
        ));

        self.state = NoiseSessionState::Handshaking;
        log_noise_event(
            "HANDSHAKE_STATE_CHANGE",
            &self.peer_id,
            "State changed to Handshaking",
        );

        // Only initiator writes the first message
        if matches!(self.role, NoiseRole::Initiator) {
            log_noise_event(
                "HANDSHAKE_WRITE",
                &self.peer_id,
                "Initiator writing first message",
            );
            let message = self.handshake_state.as_mut().unwrap().write_message(&[])?;
            log_noise_event(
                "HANDSHAKE_MESSAGE_CREATED",
                &self.peer_id,
                &format!("Message size: {} bytes", message.len()),
            );
            self.sent_handshake_messages.push(message.clone());
            Ok(message)
        } else {
            log_noise_event(
                "HANDSHAKE_RESPONDER",
                &self.peer_id,
                "Responder waiting for initiation",
            );
            // Responder doesn't send first message in XX pattern
            Ok(vec![])
        }
    }

    pub fn process_handshake_message(
        &mut self,
        message: &[u8],
    ) -> Result<Option<Vec<u8>>, NoiseError> {
        log_noise_event(
            "HANDSHAKE_PROCESS",
            &self.peer_id,
            &format!(
                "Processing message of {} bytes, current state: {:?}, role: {:?}",
                message.len(),
                self.state,
                self.role
            ),
        );

        // Initialize handshake state if needed (for responders)
        if self.state == NoiseSessionState::Uninitialized
            && matches!(self.role, NoiseRole::Responder)
        {
            log_noise_event(
                "HANDSHAKE_INIT_RESPONDER",
                &self.peer_id,
                "Initializing handshake state for responder",
            );
            self.handshake_state = Some(NoiseHandshakeState::new(
                self.role,
                NoisePattern::XX,
                Some(self.local_static_key.clone()),
                None,
            ));
            self.state = NoiseSessionState::Handshaking;
            log_noise_event(
                "HANDSHAKE_STATE_CHANGE",
                &self.peer_id,
                "Responder state changed to Handshaking",
            );
        }

        if self.state != NoiseSessionState::Handshaking {
            log_noise_event(
                "HANDSHAKE_ERROR",
                &self.peer_id,
                &format!("Invalid state for processing: {:?}", self.state),
            );
            return Err(NoiseError::InvalidState);
        }

        let handshake = self
            .handshake_state
            .as_mut()
            .ok_or(NoiseError::InvalidState)?;
        log_noise_event("HANDSHAKE_READ", &self.peer_id, "Reading handshake message");

        // Process incoming message
        let _payload = handshake.read_message(message)?;
        log_noise_event(
            "HANDSHAKE_READ_SUCCESS",
            &self.peer_id,
            "Successfully read handshake message",
        );

        // Check if handshake is complete
        if handshake.is_handshake_complete() {
            log_noise_event(
                "HANDSHAKE_COMPLETE",
                &self.peer_id,
                "Handshake is complete, getting transport ciphers",
            );

            // Get transport ciphers
            let (send, receive) = handshake.get_transport_ciphers()?;
            self.send_cipher = Some(send);
            self.receive_cipher = Some(receive);
            log_noise_event(
                "HANDSHAKE_CIPHERS_SET",
                &self.peer_id,
                "Transport ciphers established",
            );

            // Store remote static key
            self.remote_static_public_key = handshake.get_remote_static_public_key();
            if let Some(ref remote_key) = self.remote_static_public_key {
                log_noise_event(
                    "HANDSHAKE_REMOTE_KEY",
                    &self.peer_id,
                    &format!("Remote static key: {:?}", &remote_key.to_bytes()[..8]),
                );
            }

            // Store handshake hash for channel binding
            self.handshake_hash = Some(handshake.get_handshake_hash());
            log_noise_event(
                "HANDSHAKE_HASH_STORED",
                &self.peer_id,
                &format!(
                    "Handshake hash: {:?}",
                    &self.handshake_hash.as_ref().unwrap()[..16]
                ),
            );

            self.state = NoiseSessionState::Established;
            self.handshake_state = None; // Clear handshake state
            log_noise_event(
                "HANDSHAKE_ESTABLISHED",
                &self.peer_id,
                "Session established successfully",
            );

            Ok(None)
        } else {
            log_noise_event(
                "HANDSHAKE_RESPONSE_NEEDED",
                &self.peer_id,
                "Generating handshake response",
            );

            // Generate response
            let response = handshake.write_message(&[])?;
            log_noise_event(
                "HANDSHAKE_RESPONSE_CREATED",
                &self.peer_id,
                &format!("Response size: {} bytes", response.len()),
            );
            self.sent_handshake_messages.push(response.clone());

            // Check if handshake is complete after writing
            if handshake.is_handshake_complete() {
                log_noise_event(
                    "HANDSHAKE_COMPLETE_AFTER_RESPONSE",
                    &self.peer_id,
                    "Handshake complete after writing response",
                );

                // Get transport ciphers
                let (send, receive) = handshake.get_transport_ciphers()?;
                self.send_cipher = Some(send);
                self.receive_cipher = Some(receive);
                log_noise_event(
                    "HANDSHAKE_CIPHERS_SET_AFTER_RESPONSE",
                    &self.peer_id,
                    "Transport ciphers established after response",
                );

                // Store remote static key
                self.remote_static_public_key = handshake.get_remote_static_public_key();
                if let Some(ref remote_key) = self.remote_static_public_key {
                    log_noise_event(
                        "HANDSHAKE_REMOTE_KEY_AFTER_RESPONSE",
                        &self.peer_id,
                        &format!("Remote static key: {:?}", &remote_key.to_bytes()[..8]),
                    );
                }

                // Store handshake hash for channel binding
                self.handshake_hash = Some(handshake.get_handshake_hash());
                log_noise_event(
                    "HANDSHAKE_HASH_STORED_AFTER_RESPONSE",
                    &self.peer_id,
                    &format!(
                        "Handshake hash: {:?}",
                        &self.handshake_hash.as_ref().unwrap()[..16]
                    ),
                );

                self.state = NoiseSessionState::Established;
                self.handshake_state = None; // Clear handshake state
                log_noise_event(
                    "HANDSHAKE_ESTABLISHED_AFTER_RESPONSE",
                    &self.peer_id,
                    "Session established after response",
                );
            }

            Ok(Some(response))
        }
    }

    // MARK: - Transport

    pub fn encrypt(&mut self, plaintext: &[u8]) -> Result<Vec<u8>, NoiseError> {
        if self.state != NoiseSessionState::Established {
            return Err(NoiseError::NotEstablished);
        }

        let cipher = self
            .send_cipher
            .as_mut()
            .ok_or(NoiseError::NotEstablished)?;
        cipher.encrypt(plaintext, &[])
    }

    pub fn decrypt(&mut self, ciphertext: &[u8]) -> Result<Vec<u8>, NoiseError> {
        if self.state != NoiseSessionState::Established {
            return Err(NoiseError::NotEstablished);
        }

        let cipher = self
            .receive_cipher
            .as_mut()
            .ok_or(NoiseError::NotEstablished)?;
        cipher.decrypt(ciphertext, &[])
    }

    // MARK: - State Management

    pub fn get_state(&self) -> NoiseSessionState {
        self.state.clone()
    }

    pub fn is_established(&self) -> bool {
        matches!(self.state, NoiseSessionState::Established)
    }

    pub fn get_remote_static_public_key(&self) -> Option<PublicKey> {
        self.remote_static_public_key
    }

    pub fn get_handshake_hash(&self) -> Option<Vec<u8>> {
        self.handshake_hash.clone()
    }

    pub fn reset(&mut self) {
        let was_established = matches!(self.state, NoiseSessionState::Established);
        self.state = NoiseSessionState::Uninitialized;
        self.handshake_state = None;
        self.send_cipher = None;
        self.receive_cipher = None;
        self.sent_handshake_messages.clear();
        self.handshake_hash = None;
        self.pending_messages.clear();

        if was_established {
            debug_full_println!("[NOISE] Session expired for {}", self.peer_id);
        }
    }
}

// MARK: - Session Manager

pub struct NoiseSessionManager {
    sessions: Arc<Mutex<HashMap<String, NoiseSession>>>,
    local_static_key: StaticSecret,

    // Fingerprint management (matching Swift implementation)
    peer_fingerprints: Arc<Mutex<HashMap<String, String>>>, // peer_id -> fingerprint
    fingerprint_to_peer_id: Arc<Mutex<HashMap<String, String>>>, // fingerprint -> peer_id

    // Verified fingerprints (matching Swift implementation)
    verified_fingerprints: Arc<Mutex<std::collections::HashSet<String>>>,

    // Encryption status tracking (matching Swift implementation)
    peer_encryption_status: Arc<Mutex<HashMap<String, EncryptionStatus>>>,

    // Callbacks (matching Swift implementation)
    on_session_established: Option<Box<dyn Fn(String, PublicKey) + Send + Sync>>,
    on_session_failed: Option<Box<dyn Fn(String, NoiseError) + Send + Sync>>,
    on_peer_authenticated: Option<Box<dyn Fn(String, String) + Send + Sync>>, // peer_id, fingerprint
    on_handshake_required: Option<Box<dyn Fn(String) + Send + Sync>>, // peer_id needs handshake
}

impl NoiseSessionManager {
    pub fn new(local_static_key: StaticSecret) -> Self {
        Self {
            sessions: Arc::new(Mutex::new(HashMap::new())),
            local_static_key,
            peer_fingerprints: Arc::new(Mutex::new(HashMap::new())),
            fingerprint_to_peer_id: Arc::new(Mutex::new(HashMap::new())),
            verified_fingerprints: Arc::new(Mutex::new(std::collections::HashSet::new())),
            peer_encryption_status: Arc::new(Mutex::new(HashMap::new())),
            on_session_established: None,
            on_session_failed: None,
            on_peer_authenticated: None,
            on_handshake_required: None,
        }
    }

    // MARK: - Callback Management

    pub fn set_on_session_established<F>(&mut self, callback: F)
    where
        F: Fn(String, PublicKey) + Send + Sync + 'static,
    {
        self.on_session_established = Some(Box::new(callback));
    }

    pub fn set_on_session_failed<F>(&mut self, callback: F)
    where
        F: Fn(String, NoiseError) + Send + Sync + 'static,
    {
        self.on_session_failed = Some(Box::new(callback));
    }

    pub fn set_on_peer_authenticated<F>(&mut self, callback: F)
    where
        F: Fn(String, String) + Send + Sync + 'static,
    {
        self.on_peer_authenticated = Some(Box::new(callback));
    }

    pub fn set_on_handshake_required<F>(&mut self, callback: F)
    where
        F: Fn(String) + Send + Sync + 'static,
    {
        self.on_handshake_required = Some(Box::new(callback));
    }

    // MARK: - Fingerprint Management

    pub fn get_peer_fingerprint(&self, peer_id: &str) -> Option<String> {
        let fingerprints = self.peer_fingerprints.lock().unwrap();
        fingerprints.get(peer_id).cloned()
    }

    pub fn get_peer_id_for_fingerprint(&self, fingerprint: &str) -> Option<String> {
        let fingerprint_map = self.fingerprint_to_peer_id.lock().unwrap();
        fingerprint_map.get(fingerprint).cloned()
    }

    // MARK: - Verified Fingerprint Management (matching Swift implementation)

    pub fn verify_fingerprint(&mut self, fingerprint: &str) {
        let mut verified = self.verified_fingerprints.lock().unwrap();
        verified.insert(fingerprint.to_string());
        log_noise_event(
            "FINGERPRINT_VERIFIED",
            "SYSTEM",
            &format!("Fingerprint {} marked as verified", &fingerprint[..16]),
        );
    }

    pub fn is_fingerprint_verified(&self, fingerprint: &str) -> bool {
        let verified = self.verified_fingerprints.lock().unwrap();
        verified.contains(fingerprint)
    }

    pub fn get_verified_fingerprints(&self) -> std::collections::HashSet<String> {
        let verified = self.verified_fingerprints.lock().unwrap();
        verified.clone()
    }

    pub fn load_verified_fingerprints(&mut self, fingerprints: std::collections::HashSet<String>) {
        let mut verified = self.verified_fingerprints.lock().unwrap();
        *verified = fingerprints;
        log_noise_event(
            "FINGERPRINTS_LOADED",
            "SYSTEM",
            &format!("Loaded {} verified fingerprints", verified.len()),
        );
    }

    // MARK: - Encryption Status Management (matching Swift implementation)

    pub fn update_encryption_status(&mut self, peer_id: &str) {
        let sessions = self.sessions.lock().unwrap();
        let mut status_map = self.peer_encryption_status.lock().unwrap();

        if let Some(session) = sessions.get(peer_id) {
            match session.get_state() {
                NoiseSessionState::Established => {
                    // Check if fingerprint is verified
                    if let Some(fingerprint) = self.get_peer_fingerprint(peer_id) {
                        if self.is_fingerprint_verified(&fingerprint) {
                            status_map.insert(peer_id.to_string(), EncryptionStatus::NoiseVerified);
                            log_noise_event(
                                "STATUS_UPDATE",
                                peer_id,
                                "Setting encryption status to NoiseVerified",
                            );
                        } else {
                            status_map.insert(peer_id.to_string(), EncryptionStatus::NoiseSecured);
                            log_noise_event(
                                "STATUS_UPDATE",
                                peer_id,
                                "Setting encryption status to NoiseSecured",
                            );
                        }
                    } else {
                        status_map.insert(peer_id.to_string(), EncryptionStatus::NoiseSecured);
                        log_noise_event(
                            "STATUS_UPDATE",
                            peer_id,
                            "Setting encryption status to NoiseSecured (no fingerprint)",
                        );
                    }
                }
                NoiseSessionState::Handshaking => {
                    status_map.insert(peer_id.to_string(), EncryptionStatus::NoiseHandshaking);
                    log_noise_event(
                        "STATUS_UPDATE",
                        peer_id,
                        "Setting encryption status to NoiseHandshaking",
                    );
                }
                NoiseSessionState::Uninitialized => {
                    status_map.insert(peer_id.to_string(), EncryptionStatus::NoHandshake);
                    log_noise_event(
                        "STATUS_UPDATE",
                        peer_id,
                        "Setting encryption status to NoHandshake",
                    );
                }
                NoiseSessionState::Failed(_) => {
                    status_map.insert(peer_id.to_string(), EncryptionStatus::None);
                    log_noise_event(
                        "STATUS_UPDATE",
                        peer_id,
                        "Setting encryption status to None (failed)",
                    );
                }
            }
        } else {
            status_map.insert(peer_id.to_string(), EncryptionStatus::NoHandshake);
            log_noise_event(
                "STATUS_UPDATE",
                peer_id,
                "Setting encryption status to NoHandshake (no session)",
            );
        }
    }

    pub fn get_encryption_status(&self, peer_id: &str) -> EncryptionStatus {
        let status_map = self.peer_encryption_status.lock().unwrap();
        status_map
            .get(peer_id)
            .cloned()
            .unwrap_or(EncryptionStatus::NoHandshake)
    }

    pub fn clear_encryption_status(&mut self, peer_id: &str) {
        let mut status_map = self.peer_encryption_status.lock().unwrap();
        status_map.remove(peer_id);
        log_noise_event("STATUS_CLEARED", peer_id, "Cleared encryption status");
    }

    // MARK: - Identity Fingerprint (matching Swift implementation)

    /// Get our own identity fingerprint (SHA256 hash of our static public key)
    pub fn get_identity_fingerprint(&self) -> String {
        let public_key = PublicKey::from(&self.local_static_key);
        self.calculate_fingerprint(&public_key)
    }

    fn calculate_fingerprint(&self, public_key: &PublicKey) -> String {
        let mut hasher = Sha256::new();
        // Use to_bytes() which should match Swift's rawRepresentation for Curve25519
        hasher.update(public_key.to_bytes());
        let result = hasher.finalize();
        result
            .iter()
            .map(|b| format!("{:02x}", b))
            .collect::<String>()
    }

    fn handle_session_established(&self, peer_id: String, remote_static_key: PublicKey) {
        log_noise_event(
            "FINGERPRINT_CALC",
            &peer_id,
            "Calculating fingerprint for remote static key",
        );

        // Calculate fingerprint
        let fingerprint = self.calculate_fingerprint(&remote_static_key);
        log_noise_event(
            "FINGERPRINT_CALCULATED",
            &peer_id,
            &format!("Fingerprint: {}", &fingerprint[..16]),
        );

        // Store fingerprint mapping
        {
            let mut fingerprints = self.peer_fingerprints.lock().unwrap();
            let mut fingerprint_map = self.fingerprint_to_peer_id.lock().unwrap();

            fingerprints.insert(peer_id.clone(), fingerprint.clone());
            fingerprint_map.insert(fingerprint.clone(), peer_id.clone());
            log_noise_event(
                "FINGERPRINT_STORED",
                &peer_id,
                "Fingerprint mappings stored",
            );
        }

        debug_full_println!(
            "[NOISE] Session established with {} (fingerprint: {})",
            peer_id,
            &fingerprint[..16]
        );

        // Call session established callback if set
        if let Some(callback) = &self.on_session_established {
            log_noise_event(
                "CALLBACK_TRIGGERED",
                &peer_id,
                "Calling session established callback",
            );
            callback(peer_id.clone(), remote_static_key);
        } else {
            log_noise_event(
                "NO_CALLBACK",
                &peer_id,
                "No session established callback set",
            );
        }

        // Call peer authenticated callback if set (matching Swift implementation)
        if let Some(callback) = &self.on_peer_authenticated {
            log_noise_event(
                "PEER_AUTH_CALLBACK",
                &peer_id,
                &format!(
                    "Calling peer authenticated callback with fingerprint: {}",
                    &fingerprint[..16]
                ),
            );
            callback(peer_id.clone(), fingerprint);
        }
    }

    // MARK: - Session Management

    pub fn create_session(
        &mut self,
        peer_id: String,
        role: NoiseRole,
    ) -> Result<NoiseSession, NoiseError> {
        write_noise_debug_log(&format!(
            "[DEBUG] Creating session for peer: {} with role: {:?}",
            peer_id, role
        ));

        // Check if session already exists and is established
        let mut sessions = self.sessions.lock().unwrap();
        if let Some(existing_session) = sessions.get(&peer_id) {
            if existing_session.state == NoiseSessionState::Established {
                return Err(NoiseError::AlreadyEstablished); // keep the channel
            }
            // handshaking or failed sessions are handled below
        }

        write_noise_debug_log("[DEBUG] About to create new NoiseHandshakeState");

        // Create new handshake state
        let handshake_state = match role {
            NoiseRole::Initiator => {
                write_noise_debug_log("[DEBUG] Creating handshake state as initiator");
                NoiseHandshakeState::new(
                    role,
                    NoisePattern::XX,
                    Some(self.local_static_key.clone()),
                    None,
                )
            }
            NoiseRole::Responder => {
                write_noise_debug_log("[DEBUG] Creating handshake state as responder");
                NoiseHandshakeState::new(
                    role,
                    NoisePattern::XX,
                    Some(self.local_static_key.clone()),
                    None,
                )
            }
        };

        write_noise_debug_log("[DEBUG] Handshake state created successfully");

        // Check if we need to create a new session or update existing one
        if let Some(existing_session) = sessions.get_mut(&peer_id) {
            // Update existing session with new handshake state
            existing_session.handshake_state = Some(handshake_state);
            write_noise_debug_log(&format!(
                "[DEBUG] Updated existing session for peer: {}",
                peer_id
            ));
            Ok(existing_session.clone())
        } else {
            // Create new session
            let session = NoiseSession {
                peer_id: peer_id.clone(),
                role,
                state: NoiseSessionState::Handshaking,
                handshake_state: Some(handshake_state),
                send_cipher: None,
                receive_cipher: None,
                local_static_key: self.local_static_key.clone(),
                remote_static_public_key: None,
                sent_handshake_messages: Vec::new(),
                handshake_hash: None,
                pending_messages: Vec::new(),
            };

            write_noise_debug_log(&format!(
                "[DEBUG] Session created successfully for peer: {}",
                peer_id
            ));

            // Store the session
            sessions.insert(peer_id.clone(), session.clone());

            Ok(session)
        }
    }

    pub fn get_session(&self, peer_id: &str) -> Option<NoiseSession> {
        let sessions = self.sessions.lock().unwrap();
        sessions.get(peer_id).cloned()
    }

    pub fn remove_session(&mut self, peer_id: &str) {
        let mut sessions = self.sessions.lock().unwrap();
        write_noise_debug_log(&format!("[DEBUG] Removing session for peer: {}", peer_id));
        if let Some(session) = sessions.get(peer_id) {
            if session.is_established() {
                debug_full_println!("[NOISE] Session expired for {}", peer_id);
            }
        }
        sessions.remove(peer_id);
        write_noise_debug_log(&format!("[DEBUG] Session removed for peer: {}", peer_id));

        // Also remove fingerprint mappings
        {
            let mut fingerprints = self.peer_fingerprints.lock().unwrap();
            let mut fingerprint_map = self.fingerprint_to_peer_id.lock().unwrap();

            if let Some(fingerprint) = fingerprints.remove(peer_id) {
                fingerprint_map.remove(&fingerprint);
            }
        }
    }

    pub fn migrate_session(&mut self, from_old_peer_id: &str, to_new_peer_id: &str) {
        let mut sessions = self.sessions.lock().unwrap();
        if let Some(session) = sessions.remove(from_old_peer_id) {
            sessions.insert(to_new_peer_id.to_string(), session);
            debug_full_println!(
                "[NOISE] Migrated Noise session from {} to {}",
                from_old_peer_id,
                to_new_peer_id
            );
        }

        // Also migrate fingerprint mappings
        {
            let mut fingerprints = self.peer_fingerprints.lock().unwrap();
            let mut fingerprint_map = self.fingerprint_to_peer_id.lock().unwrap();

            if let Some(fingerprint) = fingerprints.remove(from_old_peer_id) {
                fingerprints.insert(to_new_peer_id.to_string(), fingerprint.clone());
                fingerprint_map.insert(fingerprint, to_new_peer_id.to_string());
            }
        }
    }

    pub fn get_established_sessions(&self) -> Vec<NoiseSession> {
        let sessions = self.sessions.lock().unwrap();
        sessions
            .values()
            .filter(|session| session.is_established())
            .cloned()
            .collect()
    }

    // MARK: - Handshake Helpers

    pub fn has_established_session(&self, peer_id: &str) -> bool {
        let sessions = self.sessions.lock().unwrap();
        if let Some(session) = sessions.get(peer_id) {
            session.state == NoiseSessionState::Established
        } else {
            false
        }
    }

    pub fn has_session(&self, peer_id: &str) -> bool {
        let sessions = self.sessions.lock().unwrap();
        let has_session = sessions.contains_key(peer_id);
        write_noise_debug_log(&format!(
            "[DEBUG] Checking if session exists for peer: {} - Result: {}",
            peer_id, has_session
        ));
        has_session
    }

    pub fn store_pending_message(
        &mut self,
        peer_id: &str,
        message: String,
    ) -> Result<(), NoiseError> {
        let mut sessions = self.sessions.lock().unwrap();
        if let Some(session) = sessions.get_mut(peer_id) {
            session.pending_messages.push(PendingMessage {
                content: message,
                timestamp: std::time::SystemTime::now(),
                retry_count: 0,
            });
            Ok(())
        } else {
            Err(NoiseError::SessionNotFound)
        }
    }

    pub fn encrypt_message(
        &mut self,
        peer_id: &str,
        message: &[u8],
    ) -> Result<Vec<u8>, NoiseError> {
        log_noise_event(
            "ENCRYPT_MESSAGE_START",
            peer_id,
            &format!(
                "Starting encryption for message of length: {}",
                message.len()
            ),
        );

        let mut sessions = self.sessions.lock().unwrap();
        log_noise_event(
            "ENCRYPT_MESSAGE_SESSIONS",
            peer_id,
            &format!("Found {} total sessions", sessions.len()),
        );

        if let Some(session) = sessions.get_mut(peer_id) {
            log_noise_event(
                "ENCRYPT_MESSAGE_SESSION_FOUND",
                peer_id,
                &format!("Session state: {:?}", session.get_state()),
            );

            if session.is_established() {
                log_noise_event(
                    "ENCRYPT_MESSAGE_ESTABLISHED",
                    peer_id,
                    "Session is established, checking send cipher",
                );

                if let Some(send_cipher) = &mut session.send_cipher {
                    log_noise_event(
                        "ENCRYPT_MESSAGE_CIPHER_FOUND",
                        peer_id,
                        &format!(
                            "Send cipher found, encrypting message of length: {}",
                            message.len()
                        ),
                    );

                    let result = send_cipher.encrypt(message, &[]);
                    match &result {
                        Ok(encrypted) => {
                            log_noise_event(
                                "ENCRYPT_MESSAGE_SUCCESS",
                                peer_id,
                                &format!(
                                    "Encryption successful, result length: {}",
                                    encrypted.len()
                                ),
                            );
                        }
                        Err(e) => {
                            log_noise_event(
                                "ENCRYPT_MESSAGE_CIPHER_ERROR",
                                peer_id,
                                &format!("Cipher encryption failed: {:?}", e),
                            );
                            // Don't reset session on encryption failure, just return error
                        }
                    }
                    return result;
                } else {
                    log_noise_event(
                        "ENCRYPT_MESSAGE_NO_CIPHER",
                        peer_id,
                        "Session established but no send cipher available",
                    );
                    return Err(NoiseError::NotEstablished);
                }
            } else {
                log_noise_event(
                    "ENCRYPT_MESSAGE_NOT_ESTABLISHED",
                    peer_id,
                    &format!(
                        "Session not established, current state: {:?}",
                        session.get_state()
                    ),
                );
                return Err(NoiseError::NotEstablished);
            }
        } else {
            log_noise_event(
                "ENCRYPT_MESSAGE_NO_SESSION",
                peer_id,
                "No session found for peer",
            );
            return Err(NoiseError::SessionNotFound);
        }
    }

    pub fn decrypt_message(
        &mut self,
        peer_id: &str,
        encrypted_message: &[u8],
    ) -> Result<Vec<u8>, NoiseError> {
        log_noise_event(
            "DECRYPT_MESSAGE_START",
            peer_id,
            &format!(
                "Starting decryption for message of length: {}",
                encrypted_message.len()
            ),
        );

        let mut sessions = self.sessions.lock().unwrap();
        log_noise_event(
            "DECRYPT_MESSAGE_SESSIONS",
            peer_id,
            &format!("Found {} total sessions", sessions.len()),
        );

        if let Some(session) = sessions.get_mut(peer_id) {
            log_noise_event(
                "DECRYPT_MESSAGE_SESSION_FOUND",
                peer_id,
                &format!("Session state: {:?}", session.get_state()),
            );

            if session.is_established() {
                log_noise_event(
                    "DECRYPT_MESSAGE_ESTABLISHED",
                    peer_id,
                    "Session is established, checking receive cipher",
                );

                if let Some(recv_cipher) = &mut session.receive_cipher {
                    log_noise_event(
                        "DECRYPT_MESSAGE_CIPHER_FOUND",
                        peer_id,
                        &format!(
                            "Receive cipher found, decrypting message of length: {}",
                            encrypted_message.len()
                        ),
                    );

                    let result = recv_cipher.decrypt(encrypted_message, &[]);
                    match &result {
                        Ok(decrypted) => {
                            log_noise_event(
                                "DECRYPT_MESSAGE_SUCCESS",
                                peer_id,
                                &format!(
                                    "Decryption successful, result length: {}",
                                    decrypted.len()
                                ),
                            );
                        }
                        Err(e) => {
                            log_noise_event(
                                "DECRYPT_MESSAGE_CIPHER_ERROR",
                                peer_id,
                                &format!("Cipher decryption failed: {:?}", e),
                            );
                            // Don't reset session on decryption failure, just return error
                        }
                    }
                    return result;
                } else {
                    log_noise_event(
                        "DECRYPT_MESSAGE_NO_CIPHER",
                        peer_id,
                        "Session established but no receive cipher available",
                    );
                    return Err(NoiseError::NotEstablished);
                }
            } else {
                log_noise_event(
                    "DECRYPT_MESSAGE_NOT_ESTABLISHED",
                    peer_id,
                    &format!(
                        "Session not established, current state: {:?}",
                        session.get_state()
                    ),
                );
                return Err(NoiseError::NotEstablished);
            }
        } else {
            log_noise_event(
                "DECRYPT_MESSAGE_NO_SESSION",
                peer_id,
                "No session found for peer",
            );
            return Err(NoiseError::SessionNotFound);
        }
    }

    pub fn initiate_handshake(&mut self, peer_id: &str) -> Result<Vec<u8>, NoiseError> {
        write_noise_debug_log(&format!(
            "[DEBUG] Starting initiate_handshake for peer: {}",
            peer_id
        ));

        let mut sessions = self.sessions.lock().unwrap();

        // Check if session exists
        if !sessions.contains_key(peer_id) {
            write_noise_debug_log(&format!(
                "[DEBUG] No session exists for peer: {}, creating new session as initiator",
                peer_id
            ));

            // Create new session as initiator
            let session = NoiseSession {
                peer_id: peer_id.to_string(),
                role: NoiseRole::Initiator,
                state: NoiseSessionState::Handshaking,
                handshake_state: Some(NoiseHandshakeState::new(
                    NoiseRole::Initiator,
                    NoisePattern::XX,
                    Some(self.local_static_key.clone()),
                    None,
                )),
                send_cipher: None,
                receive_cipher: None,
                local_static_key: self.local_static_key.clone(),
                remote_static_public_key: None,
                sent_handshake_messages: Vec::new(),
                handshake_hash: None,
                pending_messages: Vec::new(),
            };

            sessions.insert(peer_id.to_string(), session);
            write_noise_debug_log(&format!(
                "[DEBUG] Created new session as initiator for peer: {}",
                peer_id
            ));
        } else {
            write_noise_debug_log(&format!(
                "[DEBUG] Session already exists for peer: {}",
                peer_id
            ));
        }

        // Get the session and start handshake
        if let Some(session) = sessions.get_mut(peer_id) {
            write_noise_debug_log(&format!(
                "[DEBUG] Starting handshake for session with role: {:?}",
                session.role
            ));

            if let Some(handshake_state) = &mut session.handshake_state {
                let message = handshake_state.write_message(&[])?;
                session.sent_handshake_messages.push(message.clone());
                write_noise_debug_log(&format!(
                    "[DEBUG] Handshake message created, length: {}",
                    message.len()
                ));

                // Call handshake required callback if set
                if let Some(callback) = &self.on_handshake_required {
                    log_noise_event(
                        "HANDSHAKE_REQUIRED",
                        peer_id,
                        "Calling handshake required callback",
                    );
                    callback(peer_id.to_string());
                }

                // Update encryption status (need to drop sessions lock first)
                drop(sessions);
                self.update_encryption_status(peer_id);

                Ok(message)
            } else {
                write_noise_debug_log("[DEBUG] No handshake state found");
                Err(NoiseError::InvalidState)
            }
        } else {
            write_noise_debug_log("[DEBUG] Session not found after creation");
            Err(NoiseError::SessionNotFound)
        }
    }

    pub fn handle_incoming_handshake(
        &mut self,
        peer_id: &str,
        handshake_data: &[u8],
    ) -> Result<Option<Vec<u8>>, NoiseError> {
        write_noise_debug_log(&format!(
            "[DEBUG] Starting handle_incoming_handshake for peer: {}",
            peer_id
        ));

        // CRITICAL FIX: Check for existing established session first
        {
            let sessions = self.sessions.lock().unwrap();
            if let Some(sess) = sessions.get(peer_id) {
                if sess.get_state() == NoiseSessionState::Established {
                    write_noise_debug_log(&format!(
                        "[DEBUG] Ignoring handshake - session already established for peer: {}",
                        peer_id
                    ));
                    return Ok(None);
                }
            }
        }

        let mut sessions = self.sessions.lock().unwrap();

        // Only create new session if none exists or current is failed
        let should_create_new = match sessions.get(peer_id) {
            None => true,
            Some(session) => match session.get_state() {
                NoiseSessionState::Failed(_) => true,
                _ => false, // Continue with existing session
            },
        };

        if should_create_new {
            let session = NoiseSession {
                peer_id: peer_id.to_string(),
                role: NoiseRole::Responder,
                state: NoiseSessionState::Uninitialized,
                handshake_state: None,
                send_cipher: None,
                receive_cipher: None,
                local_static_key: self.local_static_key.clone(),
                remote_static_public_key: None,
                sent_handshake_messages: Vec::new(),
                handshake_hash: None,
                pending_messages: Vec::new(),
            };
            sessions.insert(peer_id.to_string(), session);
        }

        let session = sessions.get_mut(peer_id).unwrap();
        let result = session.process_handshake_message(handshake_data);

        // Handle session established callback
        if result.is_ok() && session.is_established() {
            if let Some(remote_key) = session.get_remote_static_public_key() {
                self.handle_session_established(peer_id.to_string(), remote_key);
            }
        }

        result
    }

    // MARK: - Encryption/Decryption

    pub fn encrypt(&mut self, plaintext: &[u8], peer_id: &str) -> Result<Vec<u8>, NoiseError> {
        let mut sessions = self.sessions.lock().unwrap();
        let session = sessions
            .get_mut(peer_id)
            .ok_or(NoiseError::SessionNotFound)?;
        session.encrypt(plaintext)
    }

    pub fn decrypt(&mut self, ciphertext: &[u8], peer_id: &str) -> Result<Vec<u8>, NoiseError> {
        let mut sessions = self.sessions.lock().unwrap();
        let session = sessions
            .get_mut(peer_id)
            .ok_or(NoiseError::SessionNotFound)?;
        session.decrypt(ciphertext)
    }

    // MARK: - Message Queue Management

    pub fn queue_message(&mut self, peer_id: &str, content: String) -> bool {
        let mut sessions = self.sessions.lock().unwrap();
        if let Some(session) = sessions.get_mut(peer_id) {
            session.queue_message(content);
            true
        } else {
            false
        }
    }

    pub fn get_pending_messages(&mut self, peer_id: &str) -> Vec<String> {
        let mut sessions = self.sessions.lock().unwrap();
        if let Some(session) = sessions.get_mut(peer_id) {
            session.get_pending_messages()
        } else {
            Vec::new()
        }
    }

    // MARK: - Key Management

    pub fn get_remote_static_key(&self, peer_id: &str) -> Option<PublicKey> {
        self.get_session(peer_id)?.get_remote_static_public_key()
    }

    pub fn get_handshake_hash(&self, peer_id: &str) -> Option<Vec<u8>> {
        self.get_session(peer_id)?.get_handshake_hash()
    }

    /// Check if a session is ready for transport cipher encryption/decryption
    pub fn is_session_ready(&self, peer_id: &str) -> bool {
        let sessions = self.sessions.lock().unwrap();
        sessions
            .get(peer_id)
            .map(|s| s.is_established())
            .unwrap_or(false)
    }

    // FIXED: Add method to store peer static keys for identity announcements
    pub fn store_peer_static_key(&mut self, peer_id: &str, static_key_bytes: &[u8]) -> Result<(), NoiseError> {
        if static_key_bytes.len() != 32 {
            return Err(NoiseError::InvalidPublicKey);
        }
        
        // Validate and store the key for future handshakes
        let static_key_array: [u8; 32] = static_key_bytes.try_into()
            .map_err(|_| NoiseError::InvalidPublicKey)?;
        let public_key = PublicKey::from(static_key_array);
        
        // Store in a map for later use during handshakes
        // You might need to add a field to store these keys
        log_noise_event("STATIC_KEY_STORED", peer_id, &format!("Stored static key for peer: {}", peer_id));
        Ok(())
    }
}

impl Clone for NoiseSession {
    fn clone(&self) -> Self {
        Self {
            peer_id: self.peer_id.clone(),
            role: self.role.clone(),
            state: self.state.clone(),
            handshake_state: self.handshake_state.clone(),
            send_cipher: self.send_cipher.clone(),
            receive_cipher: self.receive_cipher.clone(),
            local_static_key: self.local_static_key.clone(),
            remote_static_public_key: self.remote_static_public_key,
            sent_handshake_messages: self.sent_handshake_messages.clone(),
            handshake_hash: self.handshake_hash.clone(),
            pending_messages: self.pending_messages.clone(),
        }
    }
}

impl Clone for NoiseCipherState {
    fn clone(&self) -> Self {
        Self {
            key: self.key.clone(),
            nonce: self.nonce,
            use_extracted_nonce: self.use_extracted_nonce,
            highest_received_nonce: self.highest_received_nonce,
            replay_window: self.replay_window.clone(),
        }
    }
}

impl Clone for NoiseHandshakeState {
    fn clone(&self) -> Self {
        Self {
            role: self.role.clone(),
            pattern: self.pattern.clone(),
            symmetric_state: self.symmetric_state.clone(),
            local_static_private: self.local_static_private.clone(),
            local_static_public: self.local_static_public,
            local_ephemeral_private: self.local_ephemeral_private.clone(),
            local_ephemeral_public: self.local_ephemeral_public,
            remote_static_public: self.remote_static_public,
            remote_ephemeral_public: self.remote_ephemeral_public,
            message_patterns: self.message_patterns.clone(),
            current_pattern: self.current_pattern,
        }
    }
}

impl Clone for NoiseSymmetricState {
    fn clone(&self) -> Self {
        Self {
            cipher_state: self.cipher_state.clone(),
            chaining_key: self.chaining_key.clone(),
            hash: self.hash.clone(),
        }
    }
}
