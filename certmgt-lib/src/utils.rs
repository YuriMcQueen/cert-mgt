use std::collections::HashSet;
use std::sync::Mutex;
use rcgen::SerialNumber;
use x509_parser::prelude::ASN1Time;
use rand::RngCore;
use rand::rng;
use crate::CertMgtError;

pub fn asn1_time_to_timestamp(asn1_time: &ASN1Time) -> i64 {
    asn1_time.timestamp()
}

pub fn generate_secure_serial_number() -> Result<SerialNumber, CertMgtError> {
    // Generate exactly 159 bits like your OpenSSL version
    // 159 bits = 19 bytes + 7 bits, but we'll use 20 bytes and mask appropriately
    let mut serial_bytes = [0u8; 20];

    // Generate cryptographically secure random bytes
    rng().fill_bytes(&mut serial_bytes);

    // Mask to exactly 159 bits (159 = 8*19 + 7)
    // Keep 7 bits in the first byte: 0x7F = 0111 1111
    serial_bytes[0] &= 0x7F;

    // Ensure it's not zero (extremely unlikely but good practice)
    if serial_bytes.iter().all(|&b| b == 0) {
        serial_bytes[19] = 1;
    }

    // Remove leading zeros to minimize size (optional, but cleaner)
    let start_idx = serial_bytes.iter().position(|&b| b != 0).unwrap_or(19);
    let trimmed = &serial_bytes[start_idx..];

    // Convert to rcgen SerialNumber
    Ok(SerialNumber::from_slice(trimmed))
}