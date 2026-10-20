use crate::CertMgtError;
use chrono::{DateTime, Utc};
use rand::{RngCore, thread_rng};
use time::OffsetDateTime;
use x509_cert::serial_number::SerialNumber;
use x509_cert::time::Time;
use x509_parser::prelude::ASN1Time;

pub fn asn1_time_to_timestamp(asn1_time: &ASN1Time) -> i64 {
    asn1_time.timestamp()
}

/// Convert a unix-seconds timestamp to a typed `DateTime<Utc>`.
pub fn timestamp_to_datetime(ts: i64) -> Result<DateTime<Utc>, CertMgtError> {
    DateTime::from_timestamp(ts, 0)
        .ok_or_else(|| CertMgtError::InvalidConfiguration(format!("invalid unix timestamp: {ts}")))
}

/// Canonical DN string from subject components, in a fixed order so that
/// equal DNs always produce equal strings (used for CA matching on import)
pub fn canonical_dn(
    country: &str,
    state: &str,
    locality: &str,
    organization: &str,
    organizational_unit: &str,
    common_name: &str,
) -> String {
    let mut parts = Vec::new();
    if !country.is_empty() {
        parts.push(format!("C={country}"));
    }
    if !state.is_empty() {
        parts.push(format!("ST={state}"));
    }
    if !locality.is_empty() {
        parts.push(format!("L={locality}"));
    }
    if !organization.is_empty() {
        parts.push(format!("O={organization}"));
    }
    if !organizational_unit.is_empty() {
        parts.push(format!("OU={organizational_unit}"));
    }
    parts.push(format!("CN={common_name}"));
    parts.join(", ")
}
pub fn create_time_from_offset_datetime(dt: OffsetDateTime) -> Result<Time, CertMgtError> {
    use der::asn1::{GeneralizedTime, UtcTime};

    // X.509 uses UTCTime for dates before 2050 and GeneralizedTime for dates 2050 and later
    if dt.year() < 2050 {
        let utc_time =
            UtcTime::from_unix_duration(std::time::Duration::from_secs(dt.unix_timestamp() as u64))
                .map_err(|e| {
                    CertMgtError::CaGenerationError(format!("UTC time creation failed: {}", e))
                })?;
        Ok(Time::UtcTime(utc_time))
    } else {
        let gen_time = GeneralizedTime::from_unix_duration(std::time::Duration::from_secs(
            dt.unix_timestamp() as u64,
        ))
        .map_err(|e| {
            CertMgtError::CaGenerationError(format!("Generalized time creation failed: {}", e))
        })?;
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
