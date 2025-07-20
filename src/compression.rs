use lz4_flex::{compress_prepend_size, decompress_size_prepended};
use crate::debug_full_println;

#[allow(dead_code)]
const COMPRESSION_THRESHOLD: usize = 100;

#[allow(dead_code)]
pub fn compress_if_beneficial(data: &[u8]) -> (Vec<u8>, bool) {
    if data.len() < COMPRESSION_THRESHOLD {
        return (data.to_vec(), false);
    }
    
    let compressed = compress_prepend_size(data);
    if compressed.len() < data.len() {
        (compressed, true)
    } else {
        (data.to_vec(), false)
    }
}

pub fn decompress(data: &[u8]) -> Result<Vec<u8>, String> {
    decompress_size_prepended(data)
        .map_err(|e| format!("Decompression failed: {}", e))
}

// Decompress raw LZ4 data with known output size (for Swift compatibility)
#[allow(dead_code)]
pub fn decompress_raw(data: &[u8], output_size: usize) -> Result<Vec<u8>, String> {
    // Check for Apple's compression format markers
    if data.len() > 4 && &data[0..4] == b"bv41" {
        debug_full_println!("[DECOMPRESS] Detected Apple bv41 compression format");
        
        // Apple's bv41 format structure:
        // Bytes 0-3: "bv41" magic marker
        // Bytes 4-7: Original size (little-endian)
        // Bytes 8-11: Compressed size (little-endian)
        // Bytes 12+: Actual compressed data (but may have additional header)
        
        if data.len() > 16 {
            // Parse the header
            let original_size_le = ((data[4] as u32) | 
                                    ((data[5] as u32) << 8) | 
                                    ((data[6] as u32) << 16) | 
                                    ((data[7] as u32) << 24)) as usize;
            
            let compressed_size_le = ((data[8] as u32) | 
                                      ((data[9] as u32) << 8) | 
                                      ((data[10] as u32) << 16) | 
                                      ((data[11] as u32) << 24)) as usize;
            
            debug_full_println!("[DECOMPRESS] bv41 header: original_size={}, compressed_size={}", original_size_le, compressed_size_le);
            debug_full_println!("[DECOMPRESS] Expected output_size={}", output_size);
            
            // The compressed_size in the header tells us exactly how much data to use
            // The LZ4 data starts at offset 12 and continues for compressed_size bytes
            if data.len() >= 12 + compressed_size_le {
                let lz4_data = &data[12..12 + compressed_size_le];
                debug_full_println!("[DECOMPRESS] Attempting to decompress {} bytes of LZ4 data", compressed_size_le);
                debug_full_println!("[DECOMPRESS] First 32 bytes of LZ4 data: {:02x?}", 
                         &lz4_data[..std::cmp::min(32, lz4_data.len())]);
                
                // Try standard LZ4 decompression
                if let Ok(result) = lz4_flex::decompress(lz4_data, output_size) {
                    debug_full_println!("[DECOMPRESS] Successfully decompressed bv41 format using exact compressed size");
                    return Ok(result);
                }
                
                // If that fails, the compressed data might have its own header
                // Check for common patterns
                if lz4_data.len() > 4 {
                    // Sometimes there's an additional 4-byte header
                    if let Ok(result) = lz4_flex::decompress(&lz4_data[4..], output_size) {
                        debug_full_println!("[DECOMPRESS] Successfully decompressed after skipping 4-byte header");
                        return Ok(result);
                    }
                    
                    // Or 2-byte header
                    if let Ok(result) = lz4_flex::decompress(&lz4_data[2..], output_size) {
                        debug_full_println!("[DECOMPRESS] Successfully decompressed after skipping 2-byte header");
                        return Ok(result);
                    }
                }
            } else {
                debug_full_println!("[DECOMPRESS] ERROR: Not enough data! Expected {} bytes after header, but only have {}", 
                         compressed_size_le, data.len().saturating_sub(12));
            }
            
            // Original scanning code as fallback
        }
        
        return Err("Failed to decompress Apple bv41 format - could not find LZ4 data start".to_string());
    }
    
    // Check for "bv4-" marker (another Apple compression variant)  
    if data.len() > 4 && &data[0..4] == b"bv4-" {
        debug_full_println!("[DECOMPRESS] Detected Apple bv4- compression format");
        if data.len() > 12 {
            if let Ok(result) = lz4_flex::decompress(&data[12..], output_size) {
                debug_full_println!("[DECOMPRESS] Successfully decompressed bv4- format");
                return Ok(result);
            }
        }
    }
    
    // Try standard LZ4 decompression first
    if let Ok(result) = lz4_flex::decompress(data, output_size) {
        debug_full_println!("[DECOMPRESS] Successfully decompressed standard LZ4 format");
        return Ok(result);
    }
    
    // If that fails, try skipping potential Apple Compression framework header
    // Apple's framework may add additional metadata
    if data.len() > 12 {
        // Try skipping first 12 bytes (possible Apple header)
        if let Ok(result) = lz4_flex::decompress(&data[12..], output_size) {
            debug_full_println!("[DECOMPRESS] Successfully decompressed with 12-byte header skip");
            return Ok(result);
        }
    }
    
    // Try other common header sizes
    for skip in [4, 8, 16].iter() {
        if data.len() > *skip {
            if let Ok(result) = lz4_flex::decompress(&data[*skip..], output_size) {
                debug_full_println!("[DECOMPRESS] Successfully decompressed with {}-byte header skip", skip);
                return Ok(result);
            }
        }
    }
    
    Err(format!("Raw decompression failed after trying multiple formats. Data len: {}, expected output: {}", data.len(), output_size))
} 