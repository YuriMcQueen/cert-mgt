use base64::prelude::BASE64_STANDARD;
use base64::Engine as _;
use std::error::Error;
use crate::types::CertDataType;

pub fn detect_cert_type(bytes: &[u8]) -> Result<CertDataType, Box<dyn Error>> {
    // Try interpreting as UTF-8 text (PEM is always text)
    let content = str::from_utf8(bytes).ok();

    if let Some(content) = content {
        let has_cert = content.contains("-----BEGIN CERTIFICATE-----");
        let has_key = content.contains("-----BEGIN PRIVATE KEY-----")
            || content.contains("-----BEGIN ENCRYPTED PRIVATE KEY-----")
            || content.contains("-----BEGIN RSA PRIVATE KEY-----");

        return match (has_cert, has_key) {
            (true, true) => Ok(CertDataType::PemCertAndKey),
            (true, false) => Ok(CertDataType::PemOnlyCert),
            (false, true) => Ok(CertDataType::PemOnlyKey),
            _ => {
                // Remove ALL whitespace characters (including newlines, spaces, tabs, etc.)
                let filtered: String = content.chars().filter(|c| !c.is_whitespace()).collect();

                // Decode the cleaned base64 string directly (not as bytes)
                match BASE64_STANDARD.decode(&filtered) {
                    Ok(decoded) => {
                        println!("Successfully decoded {} bytes", decoded.len());
                        println!(
                            "First 8 bytes: {:02x?}",
                            &decoded[..std::cmp::min(8, decoded.len())]
                        );

                        // P12 files start with ASN.1 SEQUENCE tag (0x30)
                        if decoded.len() >= 2 && decoded[0] == 0x30 {
                            return Ok(CertDataType::P12 { as_base64: true });
                        }

                        Err("Decoded data doesn't appear to be a valid P12 file (missing ASN.1 SEQUENCE header).".into())
                    }
                    Err(e) => {
                        println!("Base64 decode error: {}", e);
                        Err(format!("Failed to decode as base64: {}", e).into())
                    }
                }
            }
        };
    }

    // Try detecting raw binary PKCS#12 (.p12/.pfx)
    if bytes.starts_with(&[0x30, 0x82]) {
        return Ok(CertDataType::P12 { as_base64: false });
    }

    Err("Could not detect certificate format".into())
}
