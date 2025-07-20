use rand::Rng;
use std::time::Duration;
use tokio::time;
use btleplug::api::{Peripheral, WriteType};
use crate::{MessageType, create_bitchat_packet, parse_bitchat_packet, debug_full_println};

// Match Swift's fragment size limit: 500 bytes per fragment
// This aligns with Swift's maxFragmentSize configuration
// BLE 5.0 supports up to 512 bytes MTU on iOS
#[allow(dead_code)]
const MAX_FRAGMENT_SIZE: usize = 500;  // Match Swift implementation

#[repr(u8)]
#[derive(Debug, Clone, Copy)]
#[allow(dead_code)]
pub enum FragmentType {
    Start = 0x05,
    Continue = 0x06,
    End = 0x07,
}

#[derive(Clone)]
#[allow(dead_code)]
pub struct Fragment {
    pub fragment_id: [u8; 8],
    pub fragment_type: FragmentType,
    pub index: u16,
    pub total: u16,
    pub original_type: u8,
    pub data: Vec<u8>,
}

// Helper function to convert fragment ID to hex string (matching Swift's hexEncodedString)
#[allow(dead_code)]
fn fragment_id_to_hex(fragment_id: &[u8; 8]) -> String {
    fragment_id.iter().map(|b| format!("{:02x}", b)).collect()
}

// Helper function to convert hex string back to fragment ID
#[allow(dead_code)]
fn hex_to_fragment_id(hex: &str) -> Result<[u8; 8], String> {
    if hex.len() != 16 {
        return Err("Invalid hex string length".to_string());
    }
    
    let mut fragment_id = [0u8; 8];
    for (i, chunk) in hex.as_bytes().chunks(2).enumerate() {
        let hex_str = std::str::from_utf8(chunk).map_err(|_| "Invalid UTF-8")?;
        fragment_id[i] = u8::from_str_radix(hex_str, 16).map_err(|_| "Invalid hex")?;
    }
    
    Ok(fragment_id)
}

#[allow(dead_code)]
pub fn fragment_payload(payload: &[u8], original_msg_type: u8) -> Vec<Fragment> {
    if payload.len() <= MAX_FRAGMENT_SIZE {
        return vec![];
    }
    
    // Generate random 8 bytes for fragment ID (matching Swift's arc4random_buf)
    let mut fragment_id = [0u8; 8];
    rand::thread_rng().fill(&mut fragment_id);
    
    let chunks: Vec<&[u8]> = payload.chunks(MAX_FRAGMENT_SIZE).collect();
    let total = chunks.len() as u16;
    
    chunks.iter().enumerate().map(|(i, chunk)| {
        let fragment_type = match i {
            0 => FragmentType::Start,
            n if n == chunks.len() - 1 => FragmentType::End,
            _ => FragmentType::Continue,
        };
        
        Fragment {
            fragment_id,
            fragment_type,
            index: i as u16,
            total,
            original_type: original_msg_type,
            data: chunk.to_vec(),
        }
    }).collect()
} 


// Helper function to create fragment packets
#[allow(dead_code)]
pub fn create_fragment_packet(sender_id: &str, fragment: Fragment) -> Vec<u8> {
    let mut payload = Vec::new();
    
    // Fragment header: fragmentID (8) + index (2) + total (2) + originalType (1) + data
    payload.extend_from_slice(&fragment.fragment_id);
    
    // Index as 2 bytes (big-endian)
    payload.push((fragment.index >> 8) as u8);
    payload.push((fragment.index & 0xFF) as u8);
    
    // Total as 2 bytes (big-endian)  
    payload.push((fragment.total >> 8) as u8);
    payload.push((fragment.total & 0xFF) as u8);
    
    // Original message type
    payload.push(fragment.original_type);
    
    if fragment.index == 0 || fragment.index == fragment.total - 1 {
        debug_full_println!("[DEBUG] Fragment {}/{} metadata: ID={} index_bytes={:02X}{:02X} total_bytes={:02X}{:02X} type={:02X}",
                fragment.index + 1, fragment.total,
                hex::encode(&fragment.fragment_id[..4]), // Show first 4 bytes of ID
                (fragment.index >> 8) as u8, (fragment.index & 0xFF) as u8,
                (fragment.total >> 8) as u8, (fragment.total & 0xFF) as u8,
                fragment.original_type);
    }
    
    // Fragment data
    payload.extend_from_slice(&fragment.data);
    
    let msg_type = match fragment.fragment_type {
        FragmentType::Start => MessageType::FragmentStart,
        FragmentType::Continue => MessageType::FragmentContinue,
        FragmentType::End => MessageType::FragmentEnd,
    };
    
    create_bitchat_packet(sender_id, msg_type, payload)
}

// Enable fragmentation to match Swift's 500-byte threshold
// This fixes the issue where messages disappear after a certain length
pub fn should_fragment(packet_data: &[u8]) -> bool {
    packet_data.len() > 500  // Fragment complete packets larger than 500 bytes
} 

// Swift-compatible packet sending with automatic fragmentation
pub async fn send_packet_with_fragmentation(
    peripheral: &btleplug::platform::Peripheral,
    cmd_char: &btleplug::api::Characteristic,
    packet: Vec<u8>,
    my_peer_id: &str
) -> Result<(), Box<dyn std::error::Error>> {
    // Swift's logic: if packet > 500 bytes, fragment it
    if packet.len() > 500 {
        debug_full_println!("[DEBUG] ==================== FRAGMENTATION START ====================");
        debug_full_println!("[DEBUG] Original packet size: {} bytes", packet.len());
        debug_full_println!("[DEBUG] Original packet hex (first 64 bytes): {}", hex::encode(&packet[..std::cmp::min(64, packet.len())]));
        
        // Fragment the complete packet data into chunks
        // iOS BLE MTU is typically 185 bytes by default (can negotiate higher)
        // Fragment overhead: 13 (fragment metadata) + 21 (packet header) = 34 bytes
        // Safe chunk size: 150 bytes to ensure compatibility with default iOS MTU
        // This results in ~184 byte packets which work reliably on iOS
        let fragment_size = 150; // Conservative size for iOS BLE compatibility
        let chunks: Vec<&[u8]> = packet.chunks(fragment_size).collect();
        let total_fragments = chunks.len() as u16;
        
        // Generate random 8-byte fragment ID (matching working example)
        let mut fragment_id = [0u8; 8];
        rand::thread_rng().fill(&mut fragment_id);
        
        debug_full_println!("[DEBUG] Fragment ID: {}", hex::encode(&fragment_id));
        debug_full_println!("[DEBUG] Fragment size: {} bytes", fragment_size);
        debug_full_println!("[DEBUG] Total fragments: {}", total_fragments);
        
        // Send fragments with Swift's timing (20ms delay)
        for (index, chunk) in chunks.iter().enumerate() {
            let fragment_type = match index {
                0 => MessageType::FragmentStart,
                n if n == chunks.len() - 1 => MessageType::FragmentEnd,
                _ => MessageType::FragmentContinue,
            };
            
            debug_full_println!("[DEBUG] --- Fragment {}/{} ---", index + 1, total_fragments);
            debug_full_println!("[DEBUG] Type: {:?}", fragment_type);
            debug_full_println!("[DEBUG] Chunk size: {} bytes", chunk.len());
            debug_full_println!("[DEBUG] Chunk hex (first 32 bytes): {}", hex::encode(&chunk[..std::cmp::min(32, chunk.len())]));
            
            // Create fragment payload matching Swift format exactly:
            // fragmentID (8) + index (2) + total (2) + originalType (1) + data
            let mut fragment_payload = Vec::new();
            fragment_payload.extend_from_slice(&fragment_id);
            
            // Swift uses big-endian for index and total
            let index_bytes = [(index as u16 >> 8) as u8, (index as u16 & 0xFF) as u8];
            let total_bytes = [(total_fragments >> 8) as u8, (total_fragments & 0xFF) as u8];
            
            fragment_payload.push(index_bytes[0]);
            fragment_payload.push(index_bytes[1]);
            fragment_payload.push(total_bytes[0]);
            fragment_payload.push(total_bytes[1]);
            fragment_payload.push(MessageType::Message as u8); // Original packet type
            fragment_payload.extend_from_slice(chunk);
            
            debug_full_println!("[DEBUG] Fragment header: ID={} index={:02X}{:02X} total={:02X}{:02X} type={:02X}", 
                    hex::encode(&fragment_id[..4]),
                    index_bytes[0], index_bytes[1],
                    total_bytes[0], total_bytes[1],
                    MessageType::Message as u8);
            debug_full_println!("[DEBUG] Fragment payload size: {} bytes", fragment_payload.len());
            
            // DETAILED PAYLOAD ANALYSIS
            debug_full_println!("[DEBUG] === DETAILED PAYLOAD ANALYSIS ===");
            debug_full_println!("[DEBUG] Fragment payload hex: {}", hex::encode(&fragment_payload));
            debug_full_println!("[DEBUG] Fragment payload breakdown:");
            debug_full_println!("[DEBUG]   Fragment ID (8 bytes): {}", hex::encode(&fragment_payload[0..8]));
            debug_full_println!("[DEBUG]   Index (2 bytes): {} = {:02X}{:02X}", index, fragment_payload[8], fragment_payload[9]);
            debug_full_println!("[DEBUG]   Total (2 bytes): {} = {:02X}{:02X}", total_fragments, fragment_payload[10], fragment_payload[11]);
            debug_full_println!("[DEBUG]   Original type (1 byte): {} = {:02X}", MessageType::Message as u8, fragment_payload[12]);
            debug_full_println!("[DEBUG]   Data ({} bytes): {}", chunk.len(), hex::encode(&fragment_payload[13..std::cmp::min(13 + 32, fragment_payload.len())]));
            
            // Create fragment packet
            let fragment_packet = create_bitchat_packet(
                my_peer_id,
                fragment_type,
                fragment_payload
            );
            
            debug_full_println!("[DEBUG] Final fragment packet size: {} bytes", fragment_packet.len());
            debug_full_println!("[DEBUG] Final packet hex (first 64 bytes): {}", hex::encode(&fragment_packet[..std::cmp::min(64, fragment_packet.len())]));
            
            // DECODE THE FINAL PACKET TO VERIFY
            debug_full_println!("[DEBUG] === FINAL PACKET VERIFICATION ===");
            if let Ok(parsed_packet) = parse_bitchat_packet(&fragment_packet) {
                debug_full_println!("[DEBUG] ✅ Fragment packet parsed successfully");
                debug_full_println!("[DEBUG] Packet type: {:?}", parsed_packet.msg_type);
                debug_full_println!("[DEBUG] Packet TTL: {}", parsed_packet.ttl);
                debug_full_println!("[DEBUG] Packet sender: {}", parsed_packet.sender_id_str);
                debug_full_println!("[DEBUG] Packet payload size: {} bytes", parsed_packet.payload.len());
                debug_full_println!("[DEBUG] Packet payload hex: {}", hex::encode(&parsed_packet.payload));
                
                // Verify the fragment payload structure
                if parsed_packet.payload.len() >= 13 {
                    let frag_id = &parsed_packet.payload[0..8];
                    let frag_index = ((parsed_packet.payload[8] as u16) << 8) | (parsed_packet.payload[9] as u16);
                    let frag_total = ((parsed_packet.payload[10] as u16) << 8) | (parsed_packet.payload[11] as u16);
                    let frag_orig_type = parsed_packet.payload[12];
                    
                    debug_full_println!("[DEBUG] Verified fragment ID: {}", hex::encode(frag_id));
                    debug_full_println!("[DEBUG] Verified fragment index: {}", frag_index);
                    debug_full_println!("[DEBUG] Verified fragment total: {}", frag_total);
                    debug_full_println!("[DEBUG] Verified original type: 0x{:02X}", frag_orig_type);
                    
                    if frag_index == index as u16 && frag_total == total_fragments && frag_orig_type == MessageType::Message as u8 {
                        debug_full_println!("[DEBUG] ✅ Fragment payload verification passed");
                    } else {
                        debug_full_println!("[DEBUG] ❌ Fragment payload verification failed");
                    }
                } else {
                    debug_full_println!("[DEBUG] ❌ Fragment payload too small for verification");
                }
            } else {
                debug_full_println!("[DEBUG] ❌ Failed to parse fragment packet");
            }
            
            // Send fragment
            if peripheral.write(cmd_char, &fragment_packet, WriteType::WithoutResponse).await.is_err() {
                return Err(format!("Failed to send fragment {}/{} (size: {} bytes)", index + 1, total_fragments, fragment_packet.len()).into());
            }
            
            debug_full_println!("[DEBUG] ✓ Fragment {}/{} sent successfully", index + 1, total_fragments);
            
            // Swift's 20ms delay between fragments
            if index < chunks.len() - 1 {
                time::sleep(Duration::from_millis(20)).await;
            }
        }
        
        debug_full_println!("[DEBUG] ✓ Successfully sent {} fragments", total_fragments);
        debug_full_println!("[DEBUG] ==================== FRAGMENTATION END ====================");
        Ok(())
    } else {
        // Packet is small enough, send directly
        let write_type = if packet.len() > 512 {
            WriteType::WithResponse
        } else {
            WriteType::WithoutResponse
        };
        
        if peripheral.write(cmd_char, &packet, write_type).await.is_err() {
            return Err(format!("Failed to send {} byte packet", packet.len()).into());
        }
        
        Ok(())
    }
}

