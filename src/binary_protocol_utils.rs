

// MARK: - Hex Encoding/Decoding

pub fn hex_encode(data: &[u8]) -> String {
    if data.is_empty() {
        return String::new();
    }
    data.iter().map(|b| format!("{:02x}", b)).collect()
}

pub fn hex_decode(hex_string: &str) -> Option<Vec<u8>> {
    if hex_string.len() % 2 != 0 {
        return None;
    }
    
    let len = hex_string.len() / 2;
    let mut data = Vec::with_capacity(len);
    
    for i in 0..len {
        let start = i * 2;
        let end = start + 2;
        if let Ok(byte) = u8::from_str_radix(&hex_string[start..end], 16) {
            data.push(byte);
        } else {
            return None;
        }
    }
    
    Some(data)
}

// MARK: - Binary Encoding Utilities

pub trait BinaryEncodable {
    fn to_binary_data(&self) -> Vec<u8>;
    fn from_binary_data(data: &[u8]) -> Option<Self> where Self: Sized;
}

// Extension trait for Vec<u8> to add binary encoding methods
pub trait BinaryDataExt {
    fn append_u8(&mut self, value: u8);
    fn append_u16(&mut self, value: u16);
    fn append_u32(&mut self, value: u32);
    fn append_u64(&mut self, value: u64);
    fn append_string(&mut self, string: &str, max_length: Option<usize>);
    fn append_data(&mut self, data: &[u8], max_length: Option<usize>);
    fn append_date(&mut self, timestamp: u64);
    fn append_uuid(&mut self, uuid: &str);
    
    fn read_u8(&self, offset: &mut usize) -> Option<u8>;
    fn read_u16(&self, offset: &mut usize) -> Option<u16>;
    fn read_u32(&self, offset: &mut usize) -> Option<u32>;
    fn read_u64(&self, offset: &mut usize) -> Option<u64>;
    fn read_string(&self, offset: &mut usize, max_length: Option<usize>) -> Option<String>;
    fn read_data(&self, offset: &mut usize, max_length: Option<usize>) -> Option<Vec<u8>>;
    fn read_date(&self, offset: &mut usize) -> Option<u64>;
    fn read_uuid(&self, offset: &mut usize) -> Option<String>;
    fn read_fixed_bytes(&self, offset: &mut usize, count: usize) -> Option<Vec<u8>>;
}

impl BinaryDataExt for Vec<u8> {
    fn append_u8(&mut self, value: u8) {
        self.push(value);
    }
    
    fn append_u16(&mut self, value: u16) {
        self.extend_from_slice(&value.to_be_bytes());
    }
    
    fn append_u32(&mut self, value: u32) {
        self.extend_from_slice(&value.to_be_bytes());
    }
    
    fn append_u64(&mut self, value: u64) {
        self.extend_from_slice(&value.to_be_bytes());
    }
    
    fn append_string(&mut self, string: &str, max_length: Option<usize>) {
        let max_len = max_length.unwrap_or(255);
        let data = string.as_bytes();
        let length = std::cmp::min(data.len(), max_len);
        
        if max_len <= 255 {
            self.push(length as u8);
        } else {
            self.append_u16(length as u16);
        }
        
        self.extend_from_slice(&data[..length]);
    }
    
    fn append_data(&mut self, data: &[u8], max_length: Option<usize>) {
        let max_len = max_length.unwrap_or(65535);
        let length = std::cmp::min(data.len(), max_len);
        
        if max_len <= 255 {
            self.push(length as u8);
        } else {
            self.append_u16(length as u16);
        }
        
        self.extend_from_slice(&data[..length]);
    }
    
    fn append_date(&mut self, timestamp: u64) {
        // Convert to milliseconds like Swift
        let timestamp_ms = timestamp * 1000;
        self.append_u64(timestamp_ms);
    }
    
    fn append_uuid(&mut self, uuid: &str) {
        // Convert UUID string to 16 bytes
        let clean_uuid = uuid.replace("-", "");
        if clean_uuid.len() != 32 {
            // Pad with zeros if invalid
            let uuid_data = vec![0u8; 16];
            self.extend_from_slice(&uuid_data);
            return;
        }
        
        let mut uuid_data = Vec::with_capacity(16);
        for i in 0..16 {
            let start = i * 2;
            let end = start + 2;
            if let Ok(byte) = u8::from_str_radix(&clean_uuid[start..end], 16) {
                uuid_data.push(byte);
            } else {
                uuid_data.push(0);
            }
        }
        
        self.extend_from_slice(&uuid_data);
    }
    
    fn read_u8(&self, offset: &mut usize) -> Option<u8> {
        if *offset >= self.len() {
            return None;
        }
        let value = self[*offset];
        *offset += 1;
        Some(value)
    }
    
    fn read_u16(&self, offset: &mut usize) -> Option<u16> {
        if *offset + 2 > self.len() {
            return None;
        }
        let bytes: [u8; 2] = [self[*offset], self[*offset + 1]];
        let value = u16::from_be_bytes(bytes);
        *offset += 2;
        Some(value)
    }
    
    fn read_u32(&self, offset: &mut usize) -> Option<u32> {
        if *offset + 4 > self.len() {
            return None;
        }
        let bytes: [u8; 4] = [
            self[*offset], self[*offset + 1], 
            self[*offset + 2], self[*offset + 3]
        ];
        let value = u32::from_be_bytes(bytes);
        *offset += 4;
        Some(value)
    }
    
    fn read_u64(&self, offset: &mut usize) -> Option<u64> {
        if *offset + 8 > self.len() {
            return None;
        }
        let bytes: [u8; 8] = [
            self[*offset], self[*offset + 1], self[*offset + 2], self[*offset + 3],
            self[*offset + 4], self[*offset + 5], self[*offset + 6], self[*offset + 7]
        ];
        let value = u64::from_be_bytes(bytes);
        *offset += 8;
        Some(value)
    }
    
    fn read_string(&self, offset: &mut usize, max_length: Option<usize>) -> Option<String> {
        let length: usize = if max_length.unwrap_or(255) <= 255 {
            self.read_u8(offset)?.into()
        } else {
            self.read_u16(offset)?.into()
        };
        
        if *offset + length > self.len() {
            return None;
        }
        
        let string_data = &self[*offset..*offset + length];
        *offset += length;
        
        String::from_utf8(string_data.to_vec()).ok()
    }
    
    fn read_data(&self, offset: &mut usize, max_length: Option<usize>) -> Option<Vec<u8>> {
        let length: usize = if max_length.unwrap_or(65535) <= 255 {
            self.read_u8(offset)?.into()
        } else {
            self.read_u16(offset)?.into()
        };
        
        if *offset + length > self.len() {
            return None;
        }
        
        let data = self[*offset..*offset + length].to_vec();
        *offset += length;
        
        Some(data)
    }
    
    fn read_date(&self, offset: &mut usize) -> Option<u64> {
        // Convert from milliseconds like Swift
        let timestamp_ms = self.read_u64(offset)?;
        Some(timestamp_ms / 1000)
    }
    
    fn read_uuid(&self, offset: &mut usize) -> Option<String> {
        let uuid_data = self.read_fixed_bytes(offset, 16)?;
        
        // Convert 16 bytes to UUID string format
        let hex_string = hex_encode(&uuid_data);
        
        // Insert hyphens at proper positions: 8-4-4-4-12
        let mut result = String::new();
        for (index, chunk) in hex_string.as_bytes().chunks(2).enumerate() {
            if index == 4 || index == 6 || index == 8 || index == 10 {
                result.push('-');
            }
            result.push_str(&String::from_utf8_lossy(chunk));
        }
        
        Some(result.to_uppercase())
    }
    
    fn read_fixed_bytes(&self, offset: &mut usize, count: usize) -> Option<Vec<u8>> {
        if *offset + count > self.len() {
            return None;
        }
        
        let data = self[*offset..*offset + count].to_vec();
        *offset += count;
        
        Some(data)
    }
}

// MARK: - Message Type Registry

#[repr(u8)]
#[derive(Debug, Clone, Copy, PartialEq)]
pub enum BinaryMessageType {
    DeliveryAck = 0x01,
    ReadReceipt = 0x02,
    VersionHello = 0x07,
    VersionAck = 0x08,
    NoiseIdentityAnnouncement = 0x09,
    NoiseMessage = 0x0A,
} 