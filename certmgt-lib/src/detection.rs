use crate::types::CertDataType;
use base64::Engine as _;
use base64::prelude::BASE64_STANDARD;
use std::error::Error;

pub fn detect_cert_type(bytes: &[u8]) -> Result<CertDataType, Box<dyn Error>> {
    if bytes.starts_with(&[0x30, 0x82]) {
        return Ok(CertDataType::P12 { as_base64: false });
    }

    if let Ok(content) = str::from_utf8(bytes) {
        let has_cert = content.contains("-----BEGIN CERTIFICATE-----");
        let has_key = content.contains("-----BEGIN PRIVATE KEY-----")
            || content.contains("-----BEGIN ENCRYPTED PRIVATE KEY-----")
            || content.contains("-----BEGIN RSA PRIVATE KEY-----");

        if has_cert && has_key {
            return Ok(CertDataType::PemCertAndKey);
        } else if has_cert {
            return Ok(CertDataType::PemOnlyCert);
        } else if has_key {
            return Ok(CertDataType::PemOnlyKey);
        }

        let filtered: String = content.chars().filter(|c| !c.is_whitespace()).collect();
        if filtered.chars().all(|c| c.is_ascii_alphanumeric() || "+/=".contains(c)) {
            if let Ok(decoded) = BASE64_STANDARD.decode(&filtered) {
                if decoded.starts_with(&[0x30]) {
                    return Ok(CertDataType::P12 { as_base64: true });
                }
            }
        }
    }

    Err("Could not detect certificate format".into())
}
