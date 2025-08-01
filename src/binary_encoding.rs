use crate::data_structures::{
    DeliveryAck, ReadReceipt, HandshakeRequest, ProtocolAck, ProtocolNack,
    VersionHello, VersionAck, NoiseIdentityAnnouncement
};
use crate::binary_protocol_utils::{BinaryDataExt, hex_encode, hex_decode};

// MARK: - DeliveryAck Binary Encoding

impl DeliveryAck {
    pub fn to_binary_data(&self) -> Vec<u8> {
        let mut data = Vec::new();
        
        data.append_uuid(&self.original_message_id);
        data.append_uuid(&self.ack_id);
        
        // RecipientID as 8-byte hex string
        let recipient_data = hex_decode(&self.recipient_id).unwrap_or_else(|| vec![0u8; 8]);
        let mut recipient_bytes = recipient_data;
        while recipient_bytes.len() < 8 {
            recipient_bytes.push(0);
        }
        data.extend_from_slice(&recipient_bytes[..8]);
        
        data.append_u8(self.hop_count);
        data.append_date(self.timestamp);
        data.append_string(&self.recipient_nickname, None);
        
        data
    }
    
    pub fn from_binary_data(data: &[u8]) -> Option<Self> {
        let data_copy = data.to_vec();
        
        // Minimum size: 2 UUIDs (32) + recipientID (8) + hopCount (1) + timestamp (8) + min nickname
        if data_copy.len() < 50 {
            return None;
        }
        
        let mut offset = 0;
        
        let original_message_id = data_copy.read_uuid(&mut offset)?;
        let ack_id = data_copy.read_uuid(&mut offset)?;
        
        let recipient_id_data = data_copy.read_fixed_bytes(&mut offset, 8)?;
        let recipient_id = hex_encode(&recipient_id_data);
        
        let hop_count = data_copy.read_u8(&mut offset)?;
        let timestamp = data_copy.read_date(&mut offset)?;
        let recipient_nickname = data_copy.read_string(&mut offset, None)?;
        
        Some(DeliveryAck {
            original_message_id,
            ack_id,
            recipient_id,
            recipient_nickname,
            timestamp,
            hop_count,
        })
    }
}

// MARK: - ReadReceipt Binary Encoding

impl ReadReceipt {
    pub fn to_binary_data(&self) -> Vec<u8> {
        let mut data = Vec::new();
        
        data.append_uuid(&self.original_message_id);
        data.append_uuid(&self.receipt_id);
        
        // ReaderID as 8-byte hex string
        let reader_data = hex_decode(&self.reader_id).unwrap_or_else(|| vec![0u8; 8]);
        let mut reader_bytes = reader_data;
        while reader_bytes.len() < 8 {
            reader_bytes.push(0);
        }
        data.extend_from_slice(&reader_bytes[..8]);
        
        data.append_date(self.timestamp);
        data.append_string(&self.reader_nickname, None);
        
        data
    }
    
    pub fn from_binary_data(data: &[u8]) -> Option<Self> {
        let data_copy = data.to_vec();
        
        // Minimum size: 2 UUIDs (32) + readerID (8) + timestamp (8) + min nickname
        if data_copy.len() < 49 {
            return None;
        }
        
        let mut offset = 0;
        
        let original_message_id = data_copy.read_uuid(&mut offset)?;
        let receipt_id = data_copy.read_uuid(&mut offset)?;
        
        let reader_id_data = data_copy.read_fixed_bytes(&mut offset, 8)?;
        let reader_id = hex_encode(&reader_id_data);
        
        let timestamp = data_copy.read_date(&mut offset)?;
        let reader_nickname = data_copy.read_string(&mut offset, None)?;
        
        Some(ReadReceipt {
            original_message_id,
            receipt_id,
            reader_id,
            reader_nickname,
            timestamp,
        })
    }
}

// MARK: - HandshakeRequest Binary Encoding

impl HandshakeRequest {
    pub fn to_binary_data(&self) -> Vec<u8> {
        let mut data = Vec::new();
        
        // UUID (16 bytes)
        data.append_uuid(&self.request_id);
        
        // RequesterID as 8-byte hex string (matches Swift implementation)
        let mut requester_data = Vec::new();
        let mut temp_id = self.requester_id.clone();
        while temp_id.len() >= 2 && requester_data.len() < 8 {
            if let Ok(byte) = u8::from_str_radix(&temp_id[..2], 16) {
                requester_data.push(byte);
            }
            temp_id = temp_id[2..].to_string();
        }
        while requester_data.len() < 8 {
            requester_data.push(0);
        }
        data.extend_from_slice(&requester_data);
        
        // TargetID as 8-byte hex string (matches Swift implementation)
        let mut target_data = Vec::new();
        let mut temp_id = self.target_id.clone();
        while temp_id.len() >= 2 && target_data.len() < 8 {
            if let Ok(byte) = u8::from_str_radix(&temp_id[..2], 16) {
                target_data.push(byte);
            }
            temp_id = temp_id[2..].to_string();
        }
        while target_data.len() < 8 {
            target_data.push(0);
        }
        data.extend_from_slice(&target_data);
        
        // Pending message count (1 byte)
        data.append_u8(self.pending_message_count);
        
        // Timestamp (8 bytes)
        data.append_date(self.timestamp);
        
        // Requester nickname (variable length)
        data.append_string(&self.requester_nickname, None);
        
        data
    }
    
    pub fn from_binary_data(data: &[u8]) -> Option<Self> {
        // Create defensive copy (matches Swift implementation)
        let data_copy = data.to_vec();
        
        // Minimum size: UUID (16) + requesterID (8) + targetID (8) + count (1) + timestamp (8) + min nickname
        if data_copy.len() < 42 {
            return None;
        }
        
        let mut offset = 0;
        
        // UUID (16 bytes)
        let request_id = data_copy.read_uuid(&mut offset)?;
        
        // RequesterID (8 bytes)
        let requester_id_data = data_copy.read_fixed_bytes(&mut offset, 8)?;
        let requester_id = hex_encode(&requester_id_data);
        
        // TargetID (8 bytes)
        let target_id_data = data_copy.read_fixed_bytes(&mut offset, 8)?;
        let target_id = hex_encode(&target_id_data);
        
        // Pending message count (1 byte)
        let pending_message_count = data_copy.read_u8(&mut offset)?;
        
        // Timestamp (8 bytes)
        let timestamp = data_copy.read_date(&mut offset)?;
        
        // Requester nickname (variable length)
        let requester_nickname = data_copy.read_string(&mut offset, None)?;
        
        // Use the private constructor (matches Swift implementation)
        Some(HandshakeRequest::from_parts(
            request_id,
            requester_id,
            requester_nickname,
            target_id,
            pending_message_count,
            timestamp,
        ))
    }
}

// MARK: - ProtocolAck Binary Encoding

impl ProtocolAck {
    pub fn to_binary_data(&self) -> Vec<u8> {
        let mut data = Vec::new();
        
        data.append_uuid(&self.original_packet_id);
        data.append_uuid(&self.ack_id);
        
        // Sender and receiver IDs as 8-byte hex strings
        let sender_data = hex_decode(&self.sender_id).unwrap_or_else(|| vec![0u8; 8]);
        let receiver_data = hex_decode(&self.receiver_id).unwrap_or_else(|| vec![0u8; 8]);
        
        data.extend_from_slice(&sender_data[..8]);
        data.extend_from_slice(&receiver_data[..8]);
        
        data.append_u8(self.packet_type);
        data.append_u8(self.hop_count);
        data.append_date(self.timestamp);
        
        data
    }
    
    pub fn from_binary_data(data: &[u8]) -> Option<Self> {
        let data_copy = data.to_vec();
        
        // Minimum size: 2 UUIDs + 2 IDs + type + hop + timestamp
        if data_copy.len() < 50 {
            return None;
        }
        
        let mut offset = 0;
        
        let original_packet_id = data_copy.read_uuid(&mut offset)?;
        let ack_id = data_copy.read_uuid(&mut offset)?;
        
        let sender_id_data = data_copy.read_fixed_bytes(&mut offset, 8)?;
        let receiver_id_data = data_copy.read_fixed_bytes(&mut offset, 8)?;
        
        let packet_type = data_copy.read_u8(&mut offset)?;
        let hop_count = data_copy.read_u8(&mut offset)?;
        let timestamp = data_copy.read_date(&mut offset)?;
        
        let sender_id = hex_encode(&sender_id_data);
        let receiver_id = hex_encode(&receiver_id_data);
        
        Some(ProtocolAck {
            original_packet_id,
            ack_id,
            sender_id,
            receiver_id,
            packet_type,
            timestamp,
            hop_count,
        })
    }
}

// MARK: - ProtocolNack Binary Encoding

impl ProtocolNack {
    pub fn to_binary_data(&self) -> Vec<u8> {
        let mut data = Vec::new();
        
        data.append_uuid(&self.original_packet_id);
        data.append_uuid(&self.nack_id);
        
        // Sender and receiver IDs as 8-byte hex strings
        let sender_data = hex_decode(&self.sender_id).unwrap_or_else(|| vec![0u8; 8]);
        let receiver_data = hex_decode(&self.receiver_id).unwrap_or_else(|| vec![0u8; 8]);
        
        data.extend_from_slice(&sender_data[..8]);
        data.extend_from_slice(&receiver_data[..8]);
        
        data.append_u8(self.packet_type);
        data.append_u8(self.error_code);
        data.append_date(self.timestamp);
        data.append_string(&self.reason, None);
        
        data
    }
    
    pub fn from_binary_data(data: &[u8]) -> Option<Self> {
        let data_copy = data.to_vec();
        
        // Minimum size
        if data_copy.len() < 52 {
            return None;
        }
        
        let mut offset = 0;
        
        let original_packet_id = data_copy.read_uuid(&mut offset)?;
        let nack_id = data_copy.read_uuid(&mut offset)?;
        
        let sender_id_data = data_copy.read_fixed_bytes(&mut offset, 8)?;
        let receiver_id_data = data_copy.read_fixed_bytes(&mut offset, 8)?;
        
        let packet_type = data_copy.read_u8(&mut offset)?;
        let error_code = data_copy.read_u8(&mut offset)?;
        let timestamp = data_copy.read_date(&mut offset)?;
        let reason = data_copy.read_string(&mut offset, None)?;
        
        let sender_id = hex_encode(&sender_id_data);
        let receiver_id = hex_encode(&receiver_id_data);
        
        Some(ProtocolNack {
            original_packet_id,
            nack_id,
            sender_id,
            receiver_id,
            packet_type,
            timestamp,
            reason,
            error_code,
        })
    }
}

// MARK: - VersionHello Binary Encoding

impl VersionHello {
    pub fn to_binary_data(&self) -> Vec<u8> {
        let mut data = Vec::new();
        
        // Flags byte: bit 0 = hasCapabilities
        let mut flags: u8 = 0;
        if self.capabilities.is_some() {
            flags |= 0x01;
        }
        data.append_u8(flags);
        
        // Supported versions array
        data.append_u8(self.supported_versions.len() as u8);
        for version in &self.supported_versions {
            data.append_u8(*version);
        }
        
        data.append_u8(self.preferred_version);
        data.append_string(&self.client_version, None);
        data.append_string(&self.platform, None);
        
        if let Some(ref capabilities) = self.capabilities {
            data.append_u8(capabilities.len() as u8);
            for capability in capabilities {
                data.append_string(capability, None);
            }
        }
        
        data
    }
    
    pub fn from_binary_data(data: &[u8]) -> Option<Self> {
        let data_copy = data.to_vec();
        
        // Minimum size check
        if data_copy.len() < 4 {
            return None;
        }
        
        let mut offset = 0;
        
        let flags = data_copy.read_u8(&mut offset)?;
        let has_capabilities = (flags & 0x01) != 0;
        
        let version_count = data_copy.read_u8(&mut offset)?;
        let mut supported_versions = Vec::new();
        for _ in 0..version_count {
            let version = data_copy.read_u8(&mut offset)?;
            supported_versions.push(version);
        }
        
        let preferred_version = data_copy.read_u8(&mut offset)?;
        let client_version = data_copy.read_string(&mut offset, None)?;
        let platform = data_copy.read_string(&mut offset, None)?;
        
        let mut capabilities: Option<Vec<String>> = None;
        if has_capabilities {
            let cap_count = data_copy.read_u8(&mut offset)?;
            let mut caps = Vec::new();
            for _ in 0..cap_count {
                let capability = data_copy.read_string(&mut offset, None)?;
                caps.push(capability);
            }
            capabilities = Some(caps);
        }
        
        Some(VersionHello {
            supported_versions,
            preferred_version,
            client_version,
            platform,
            capabilities,
        })
    }
}

// MARK: - VersionAck Binary Encoding

impl VersionAck {
    pub fn to_binary_data(&self) -> Vec<u8> {
        let mut data = Vec::new();
        
        // Flags byte: bit 0 = hasCapabilities, bit 1 = hasReason
        let mut flags: u8 = 0;
        if self.capabilities.is_some() {
            flags |= 0x01;
        }
        if self.reason.is_some() {
            flags |= 0x02;
        }
        data.append_u8(flags);
        
        data.append_u8(self.agreed_version);
        data.append_string(&self.server_version, None);
        data.append_string(&self.platform, None);
        data.append_u8(if self.rejected { 1 } else { 0 });
        
        if let Some(ref capabilities) = self.capabilities {
            data.append_u8(capabilities.len() as u8);
            for capability in capabilities {
                data.append_string(capability, None);
            }
        }
        
        if let Some(ref reason) = self.reason {
            data.append_string(reason, None);
        }
        
        data
    }
    
    pub fn from_binary_data(data: &[u8]) -> Option<Self> {
        let data_copy = data.to_vec();
        
        // Minimum size: flags(1) + version(1) + rejected(1) + min strings
        if data_copy.len() < 5 {
            return None;
        }
        
        let mut offset = 0;
        
        let flags = data_copy.read_u8(&mut offset)?;
        let has_capabilities = (flags & 0x01) != 0;
        let has_reason = (flags & 0x02) != 0;
        
        let agreed_version = data_copy.read_u8(&mut offset)?;
        let server_version = data_copy.read_string(&mut offset, None)?;
        let platform = data_copy.read_string(&mut offset, None)?;
        let rejected_byte = data_copy.read_u8(&mut offset)?;
        
        let rejected = rejected_byte != 0;
        
        let mut capabilities: Option<Vec<String>> = None;
        if has_capabilities {
            let cap_count = data_copy.read_u8(&mut offset)?;
            let mut caps = Vec::new();
            for _ in 0..cap_count {
                let capability = data_copy.read_string(&mut offset, None)?;
                caps.push(capability);
            }
            capabilities = Some(caps);
        }
        
        let mut reason: Option<String> = None;
        if has_reason {
            reason = data_copy.read_string(&mut offset, None);
        }
        
        Some(VersionAck {
            agreed_version,
            server_version,
            platform,
            capabilities,
            rejected,
            reason,
        })
    }
}

// MARK: - NoiseIdentityAnnouncement Binary Encoding

impl NoiseIdentityAnnouncement {
    pub fn to_binary_data(&self) -> Vec<u8> {
        let mut data = Vec::new();
        
        // Flags byte: bit 0 = hasPreviousPeerID
        let mut flags: u8 = 0;
        if self.previous_peer_id.is_some() {
            flags |= 0x01;
        }
        data.append_u8(flags);
        
        // PeerID as 8-byte hex string
        let peer_data = hex_decode(&self.peer_id).unwrap_or_else(|| vec![0u8; 8]);
        let mut peer_bytes = peer_data;
        while peer_bytes.len() < 8 {
            peer_bytes.push(0);
        }
        data.extend_from_slice(&peer_bytes[..8]);
        
        data.append_data(&self.public_key, None);
        data.append_data(&self.signing_public_key, None);
        data.append_string(&self.nickname, None);
        data.append_date(self.timestamp);
        
        if let Some(ref previous_peer_id) = self.previous_peer_id {
            // Previous PeerID as 8-byte hex string
            let prev_data = hex_decode(previous_peer_id).unwrap_or_else(|| vec![0u8; 8]);
            let mut prev_bytes = prev_data;
            while prev_bytes.len() < 8 {
                prev_bytes.push(0);
            }
            data.extend_from_slice(&prev_bytes[..8]);
        }
        
        data.append_data(&self.signature, None);
        
        data
    }
    
    pub fn from_binary_data(data: &[u8]) -> Option<Self> {
        let data_copy = data.to_vec();
        
        // Minimum size check: flags(1) + peerID(8) + min data lengths
        if data_copy.len() < 20 {
            return None;
        }
        
        let mut offset = 0;
        
        let flags = data_copy.read_u8(&mut offset)?;
        let has_previous_peer_id = (flags & 0x01) != 0;
        
        // Read peerID using safe method
        let peer_id_bytes = data_copy.read_fixed_bytes(&mut offset, 8)?;
        let peer_id = hex_encode(&peer_id_bytes);
        
        let public_key = data_copy.read_data(&mut offset, None)?;
        let signing_public_key = data_copy.read_data(&mut offset, None)?;
        let raw_nickname = data_copy.read_string(&mut offset, None)?;
        let timestamp = data_copy.read_date(&mut offset)?;
        
        // Trim whitespace from nickname
        let nickname = raw_nickname.trim().to_string();
        
        let mut previous_peer_id: Option<String> = None;
        if has_previous_peer_id {
            // Read previousPeerID using safe method
            let prev_id_bytes = data_copy.read_fixed_bytes(&mut offset, 8)?;
            previous_peer_id = Some(hex_encode(&prev_id_bytes));
        }
        
        let signature = data_copy.read_data(&mut offset, None)?;
        
        Some(NoiseIdentityAnnouncement {
            peer_id,
            public_key,
            signing_public_key,
            nickname,
            timestamp,
            previous_peer_id,
            signature,
        })
    }
} 