use std::collections::HashMap;
use std::sync::{Arc, Mutex};
use std::time::SystemTime;
use x25519_dalek::{StaticSecret, PublicKey};
use crate::noise_protocol::{NoiseHandshakeState, NoiseCipherState, NoiseSymmetricState, NoiseRole, NoisePattern, NoiseError};
use crate::debug_full_println;

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
    pub fn new(peer_id: String, role: NoiseRole, local_static_key: StaticSecret, remote_static_key: Option<PublicKey>) -> Self {
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
        debug_full_println!("[NOISE] Queued message for {} ({} pending)", self.peer_id, self.pending_messages.len());
    }
    
    pub fn get_pending_messages(&mut self) -> Vec<String> {
        let messages: Vec<String> = self.pending_messages.iter().map(|pm| pm.content.clone()).collect();
        self.pending_messages.clear();
        messages
    }
    
    pub fn has_pending_messages(&self) -> bool {
        !self.pending_messages.is_empty()
    }
    
    // MARK: - Handshake
    
    pub fn start_handshake(&mut self) -> Result<Vec<u8>, NoiseError> {
        if self.state != NoiseSessionState::Uninitialized {
            return Err(NoiseError::HandshakeComplete);
        }
        
        // For XX pattern, we don't need remote static key upfront
        self.handshake_state = Some(NoiseHandshakeState::new(
            self.role,
            NoisePattern::XX,
            Some(self.local_static_key.clone()),
            None
        ));
        
        self.state = NoiseSessionState::Handshaking;
        
        // Only initiator writes the first message
        if matches!(self.role, NoiseRole::Initiator) {
            let message = self.handshake_state.as_mut().unwrap().write_message(&[])?;
            self.sent_handshake_messages.push(message.clone());
            Ok(message)
        } else {
            // Responder doesn't send first message in XX pattern
            Ok(vec![])
        }
    }
    
    pub fn process_handshake_message(&mut self, message: &[u8]) -> Result<Option<Vec<u8>>, NoiseError> {
        debug_full_println!("[NOISE] Processing handshake message for {}, current state: {:?}, role: {:?}", 
                           self.peer_id, self.state, self.role);
        
        // Initialize handshake state if needed (for responders)
        if self.state == NoiseSessionState::Uninitialized && matches!(self.role, NoiseRole::Responder) {
            self.handshake_state = Some(NoiseHandshakeState::new(
                self.role,
                NoisePattern::XX,
                Some(self.local_static_key.clone()),
                None
            ));
            self.state = NoiseSessionState::Handshaking;
            debug_full_println!("[NOISE] Initialized handshake state for responder");
        }
        
        if self.state != NoiseSessionState::Handshaking {
            return Err(NoiseError::HandshakeComplete);
        }
        
        let handshake = self.handshake_state.as_mut().ok_or(NoiseError::HandshakeComplete)?;
        
        // Process incoming message
        let _payload = handshake.read_message(message)?;
        debug_full_println!("[NOISE] Read handshake message, checking if complete");
        
        // Check if handshake is complete
        if handshake.is_handshake_complete() {
            // Get transport ciphers
            let (send, receive) = handshake.get_transport_ciphers()?;
            self.send_cipher = Some(send);
            self.receive_cipher = Some(receive);
            
            // Store remote static key
            self.remote_static_public_key = handshake.get_remote_static_public_key();
            
            // Store handshake hash for channel binding
            self.handshake_hash = Some(handshake.get_handshake_hash());
            
            self.state = NoiseSessionState::Established;
            self.handshake_state = None; // Clear handshake state
            
            debug_full_println!("[NOISE] Handshake complete (no response needed), transitioning to established");
            
            Ok(None)
        } else {
            // Generate response
            let response = handshake.write_message(&[])?;
            self.sent_handshake_messages.push(response.clone());
            debug_full_println!("[NOISE] Generated handshake response of size {}", response.len());
            
            // Check if handshake is complete after writing
            if handshake.is_handshake_complete() {
                // Get transport ciphers
                let (send, receive) = handshake.get_transport_ciphers()?;
                self.send_cipher = Some(send);
                self.receive_cipher = Some(receive);
                
                // Store remote static key
                self.remote_static_public_key = handshake.get_remote_static_public_key();
                
                // Store handshake hash for channel binding
                self.handshake_hash = Some(handshake.get_handshake_hash());
                
                self.state = NoiseSessionState::Established;
                self.handshake_state = None; // Clear handshake state
                
                debug_full_println!("[NOISE] Handshake complete after writing response, transitioning to established");
            }
            
            Ok(Some(response))
        }
    }
    
    // MARK: - Transport
    
    pub fn encrypt(&mut self, plaintext: &[u8]) -> Result<Vec<u8>, NoiseError> {
        if self.state != NoiseSessionState::Established {
            return Err(NoiseError::HandshakeNotComplete);
        }
        
        let cipher = self.send_cipher.as_mut().ok_or(NoiseError::HandshakeNotComplete)?;
        cipher.encrypt(plaintext, &[])
    }
    
    pub fn decrypt(&mut self, ciphertext: &[u8]) -> Result<Vec<u8>, NoiseError> {
        if self.state != NoiseSessionState::Established {
            return Err(NoiseError::HandshakeNotComplete);
        }
        
        let cipher = self.receive_cipher.as_mut().ok_or(NoiseError::HandshakeNotComplete)?;
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
}

impl NoiseSessionManager {
    pub fn new(local_static_key: StaticSecret) -> Self {
        Self {
            sessions: Arc::new(Mutex::new(HashMap::new())),
            local_static_key,
        }
    }
    
    // MARK: - Session Management
    
    pub fn create_session(&mut self, peer_id: String, role: NoiseRole) -> NoiseSession {
        let session = NoiseSession::new(
            peer_id.clone(),
            role,
            self.local_static_key.clone(),
            None
        );
        
        {
            let mut sessions = self.sessions.lock().unwrap();
            sessions.insert(peer_id, session.clone());
        }
        
        session
    }
    
    pub fn get_session(&self, peer_id: &str) -> Option<NoiseSession> {
        let sessions = self.sessions.lock().unwrap();
        sessions.get(peer_id).cloned()
    }
    
    pub fn remove_session(&mut self, peer_id: &str) {
        let mut sessions = self.sessions.lock().unwrap();
        if let Some(session) = sessions.get(peer_id) {
            if session.is_established() {
                debug_full_println!("[NOISE] Session expired for {}", peer_id);
            }
        }
        sessions.remove(peer_id);
    }
    
    pub fn migrate_session(&mut self, from_old_peer_id: &str, to_new_peer_id: &str) {
        let mut sessions = self.sessions.lock().unwrap();
        if let Some(session) = sessions.remove(from_old_peer_id) {
            sessions.insert(to_new_peer_id.to_string(), session);
            debug_full_println!("[NOISE] Migrated Noise session from {} to {}", from_old_peer_id, to_new_peer_id);
        }
    }
    
    pub fn get_established_sessions(&self) -> Vec<NoiseSession> {
        let sessions = self.sessions.lock().unwrap();
        sessions.values()
            .filter(|session| session.is_established())
            .cloned()
            .collect()
    }
    
    // MARK: - Handshake Helpers
    
    pub fn initiate_handshake(&mut self, peer_id: &str) -> Result<Vec<u8>, NoiseError> {
        // Check if we already have an established session
        if let Some(existing_session) = self.get_session(peer_id) {
            if existing_session.is_established() {
                // Session already established, don't recreate
                return Err(NoiseError::HandshakeComplete);
            }
        }
        
        // Remove any existing non-established session
        self.remove_session(peer_id);
        
        // Create new initiator session
        let mut session = NoiseSession::new(
            peer_id.to_string(),
            NoiseRole::Initiator,
            self.local_static_key.clone(),
            None
        );
        
        let handshake_data = session.start_handshake()?;
        
        // Store the session
        {
            let mut sessions = self.sessions.lock().unwrap();
            sessions.insert(peer_id.to_string(), session);
        }
        
        Ok(handshake_data)
    }
    
    pub fn handle_incoming_handshake(&mut self, peer_id: &str, message: &[u8]) -> Result<Option<Vec<u8>>, NoiseError> {
        let mut should_create_new = false;
        let mut existing_session: Option<NoiseSession> = None;
        
        {
            let mut sessions = self.sessions.lock().unwrap();
            
            if let Some(existing) = sessions.get(peer_id) {
                // If we have an established session, the peer must have cleared their session
                // for a good reason (e.g., decryption failure, restart, etc.)
                // We should accept the new handshake to re-establish encryption
                if existing.is_established() {
                    debug_full_println!("[NOISE] Accepting handshake from {} despite existing session - peer likely cleared their session", peer_id);
                    sessions.remove(peer_id);
                    should_create_new = true;
                } else {
                    // If we're in the middle of a handshake and receive a new initiation,
                    // reset and start fresh (the other side may have restarted)
                    if existing.get_state() == NoiseSessionState::Handshaking && message.len() == 32 {
                        sessions.remove(peer_id);
                        should_create_new = true;
                    } else {
                        existing_session = Some(existing.clone());
                    }
                }
            } else {
                should_create_new = true;
            }
            
            // Get or create session
            let mut session: NoiseSession;
            if should_create_new {
                let new_session = NoiseSession::new(
                    peer_id.to_string(),
                    NoiseRole::Responder,
                    self.local_static_key.clone(),
                    None
                );
                sessions.insert(peer_id.to_string(), new_session.clone());
                session = new_session;
            } else {
                session = existing_session.unwrap();
            }
            
            // Process the handshake message
            let response = session.process_handshake_message(message)?;
            
            // Update the session in the map
            sessions.insert(peer_id.to_string(), session);
            
            Ok(response)
        }
    }
    
    // MARK: - Encryption/Decryption
    
    pub fn encrypt(&mut self, plaintext: &[u8], peer_id: &str) -> Result<Vec<u8>, NoiseError> {
        let mut sessions = self.sessions.lock().unwrap();
        let session = sessions.get_mut(peer_id).ok_or(NoiseError::HandshakeNotComplete)?;
        session.encrypt(plaintext)
    }
    
    pub fn decrypt(&mut self, ciphertext: &[u8], peer_id: &str) -> Result<Vec<u8>, NoiseError> {
        let mut sessions = self.sessions.lock().unwrap();
        let session = sessions.get_mut(peer_id).ok_or(NoiseError::HandshakeNotComplete)?;
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
            replay_window: self.replay_window,
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