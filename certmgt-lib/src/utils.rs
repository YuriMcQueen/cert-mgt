use x509_parser::prelude::ASN1Time;
use rand::{RngCore, thread_rng};
use time::{OffsetDateTime};
use x509_cert::serial_number::SerialNumber;
use x509_cert::time::Time;
use crate::CertMgtError;

pub fn asn1_time_to_timestamp(asn1_time: &ASN1Time) -> i64 {
    asn1_time.timestamp()
}
pub fn create_time_from_offset_datetime(dt: OffsetDateTime) -> Result<Time, CertMgtError> {
    use der::asn1::{UtcTime, GeneralizedTime};

    // X.509 uses UTCTime for dates before 2050 and GeneralizedTime for dates 2050 and later
    if dt.year() < 2050 {
        let utc_time = UtcTime::from_unix_duration(
            std::time::Duration::from_secs(dt.unix_timestamp() as u64)
        ).map_err(|e| CertMgtError::CaGenerationError(format!("UTC time creation failed: {}", e)))?;
        Ok(Time::UtcTime(utc_time))
    } else {
        let gen_time = GeneralizedTime::from_unix_duration(
            std::time::Duration::from_secs(dt.unix_timestamp() as u64)
        ).map_err(|e| CertMgtError::CaGenerationError(format!("Generalized time creation failed: {}", e)))?;
        Ok(Time::GeneralTime(gen_time))
    }
}

pub fn generate_secure_serial_number() -> Result<SerialNumber, CertMgtError> {
    let mut serial_bytes = [0u8; 20];

    // Generate cryptographically secure random bytes
    thread_rng().fill_bytes(&mut serial_bytes);

    // Mask to exactly 159 bits (159 = 8*19 + 7)
    // Keep 7 bits in the first byte: 0x7F = 0111 1111
    serial_bytes[0] &= 0x7F;

    // Ensure it's not zero (extremely unlikely but good practice)
    if serial_bytes.iter().all(|&b| b == 0) {
        serial_bytes[19] = 1;
    }

    // Remove leading zeros to minimize size
    let start_idx = serial_bytes.iter().position(|&b| b != 0).unwrap_or(19);
    let trimmed = &serial_bytes[start_idx..];

    // Convert SerialNumber
    let serial_number = SerialNumber::new(trimmed)?;
    Ok(serial_number)
}