use base64::prelude::BASE64_STANDARD;
use base64::Engine as _;
use openssl::nid::Nid;
use openssl::pkcs12::Pkcs12;
use openssl::pkey::{PKey, Private};
use openssl::x509::X509;
use std::error::Error;

use crate::detection::detect_cert_type;
use crate::types::{CertificateConfig, CertData, CertDataType};
use crate::utils::{parse_cert_field, asn1_time_to_timestamp};

impl CertificateConfig {
    pub fn read_from_path(path: &str, password: Option<&str>) -> Result<Self, Box<dyn Error>> {
        let bytes = std::fs::read(path)?;
        let cert_type = detect_cert_type(&bytes)?;

        match cert_type {
            CertDataType::PemCertAndKey => {
                let content = std::str::from_utf8(&bytes)?;
                let cert = X509::from_pem(content.as_bytes())?;
                let key = PKey::private_key_from_pem(content.as_bytes())?;

                // Extract certificate and key as PEM strings
                let cert_pem = String::from_utf8(cert.to_pem()?)?;
                let key_pem = String::from_utf8(key.private_key_to_pem_pkcs8()?)?;

                let cert_data = CertData::Pem {
                    cert: cert_pem,
                    key: Some(key_pem),
                };

                Ok(Self::from_x509_and_key(cert, Some(key), cert_data))
            }

            CertDataType::PemOnlyCert => {
                let cert = X509::from_pem(&bytes)?;
                let cert_pem = String::from_utf8(cert.to_pem()?)?;

                let cert_data = CertData::Pem {
                    cert: cert_pem,
                    key: None, // No key available
                };

                Ok(Self::from_x509_and_key(cert, None, cert_data))
            }

            CertDataType::PemOnlyKey => {
                Err("PEM file contains only private key, certificate missing".into())
            }

            CertDataType::P12 { as_base64 } => {
                let raw = if as_base64 {
                    // Need to filter whitespace from the original content before decoding
                    let content = std::str::from_utf8(&bytes)?;
                    let filtered: String = content.chars().filter(|c| !c.is_whitespace()).collect();
                    BASE64_STANDARD.decode(&filtered)?
                } else {
                    bytes.clone()
                };

                let parsed = Pkcs12::from_der(&raw)?.parse2(password.unwrap_or(""))?;
                let cert = parsed.cert.ok_or("Missing cert in P12")?;
                let key = parsed.pkey.ok_or("Missing key in P12")?;

                // Store the P12 data (either base64 or raw bytes as base64)
                let p12_data = if as_base64 {
                    std::str::from_utf8(&bytes)?.to_string()
                } else {
                    BASE64_STANDARD.encode(&raw)
                };

                let cert_data = CertData::P12 {
                    data: p12_data,
                    password: password.unwrap_or("").to_string(),
                    as_base64,
                };

                Ok(Self::from_x509_and_key(cert, Some(key), cert_data))
            }
        }
    }

    fn from_x509_and_key(
        cert: X509,
        key: Option<PKey<Private>>,
        cert_data: CertData,
    ) -> Self {
        // Extract certificate information
        let subject_name = cert.subject_name();
        let country = parse_cert_field(subject_name, Nid::COUNTRYNAME).unwrap_or_default();
        let state = parse_cert_field(subject_name, Nid::STATEORPROVINCENAME).unwrap_or_default();
        let locality = parse_cert_field(subject_name, Nid::LOCALITYNAME).unwrap_or_default();
        let organization = parse_cert_field(subject_name, Nid::ORGANIZATIONNAME).unwrap_or_default();
        let organizational_unit = parse_cert_field(subject_name, Nid::ORGANIZATIONALUNITNAME).unwrap_or_default();

        // Check if this is a CA certificate
        let is_ca = subject_name
            .entries_by_nid(openssl::nid::Nid::BASIC_CONSTRAINTS)
            .into_iter()
            .map(|entry| entry.data().as_slice())
            .any(|data| data.windows(5).any(|w| w == b"CA:TRUE"));

        let common_name = parse_cert_field(subject_name, Nid::COMMONNAME).unwrap_or_default();
        let not_after = asn1_time_to_timestamp(cert.not_after());
        let not_before = asn1_time_to_timestamp(cert.not_before());
        let key_size = key.as_ref().map(|k| k.bits());

        CertificateConfig {
            country,
            state,
            locality,
            organization,
            organizational_unit,
            common_name,
            is_ca,
            not_after,
            not_before,
            key_size,
            cert_data,
        }
    }
}

// Helper methods for accessing certificate data
impl CertificateConfig {
    /// Get the certificate as PEM string
    pub fn get_cert_pem(&self) -> Option<&str> {
        match &self.cert_data {
            CertData::Pem { cert, .. } => Some(cert),
            CertData::P12 { .. } => None, // Would need to extract from P12
        }
    }

    /// Get the private key as PEM string
    pub fn get_key_pem(&self) -> Option<&str> {
        match &self.cert_data {
            CertData::Pem { key, .. } => key.as_deref(),
            CertData::P12 { .. } => None, // Would need to extract from P12
        }
    }

    /// Check if this certificate has a private key
    pub fn has_private_key(&self) -> bool {
        match &self.cert_data {
            CertData::Pem { key, .. } => key.is_some(),
            CertData::P12 { .. } => true, // P12 always contains both cert and key
        }
    }
}