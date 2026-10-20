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
        if filtered
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || "+/=".contains(c))
            && let Ok(decoded) = BASE64_STANDARD.decode(&filtered)
            && decoded.starts_with(&[0x30])
        {
            return Ok(CertDataType::P12 { as_base64: true });
        }
    }

    Err("Could not detect certificate format".into())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_detect_pem_cert_and_key() {
        let pem = b"-----BEGIN CERTIFICATE-----
MIID...
-----END CERTIFICATE-----
-----BEGIN PRIVATE KEY-----
MIIE...
-----END PRIVATE KEY-----";

        let result = detect_cert_type(pem).unwrap();
        assert!(matches!(result, CertDataType::PemCertAndKey));
    }

    #[test]
    fn test_detect_pem_only_cert() {
        let pem = b"-----BEGIN CERTIFICATE-----
MIID...
-----END CERTIFICATE-----";

        let result = detect_cert_type(pem).unwrap();
        assert!(matches!(result, CertDataType::PemOnlyCert));
    }

    #[test]
    fn test_detect_pem_only_key() {
        let pem = b"-----BEGIN PRIVATE KEY-----
MIIE...
-----END PRIVATE KEY-----";

        let result = detect_cert_type(pem).unwrap();
        assert!(matches!(result, CertDataType::PemOnlyKey));
    }

    #[test]
    fn test_detect_p12_raw_binary() {
        let p12 = &[0x30, 0x82, 0x04, 0xB0]; // Mock raw DER
        let result = detect_cert_type(p12).unwrap();
        assert!(matches!(result, CertDataType::P12 { as_base64: false }));
    }

    #[test]
    fn test_detect_p12_base64() {
        // Base64 of &[0x30, 0x82, 0x04, 0xB0]
        let base64_p12 = BASE64_STANDARD.encode([0x30, 0x82, 0x04, 0xB0]);
        let result = detect_cert_type(base64_p12.as_bytes()).unwrap();
        assert!(matches!(result, CertDataType::P12 { as_base64: true }));
    }

    #[test]
    fn test_invalid_format() {
        let garbage = b"This is not a certificate";
        let result = detect_cert_type(garbage);
        assert!(result.is_err());
    }
}
