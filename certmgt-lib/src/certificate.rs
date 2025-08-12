use std::collections::HashMap;
use crate::detection::detect_cert_type;
use crate::types::{CaConfig, CertData, CertDataType, CertificateAuthority, CertificateConfig, ServerCertConfig};
use crate::utils::{asn1_time_to_timestamp, parse_cert_field};
use crate::CertMgtError;
use base64::prelude::BASE64_STANDARD;
use base64::Engine as _;

use std::error::Error;
use std::time::{SystemTime, UNIX_EPOCH};
use p12::PFX;
use pem::{parse, parse_many};
use time::OffsetDateTime;
use x509_parser::asn1_rs::{FromDer, Oid};
use x509_parser::certificate::X509Certificate;
use x509_parser::oid_registry;
use x509_parser::public_key::PublicKey;
use rcgen::{Certificate, CertificateParams, DistinguishedName, DnType, ExtendedKeyUsagePurpose, KeyPair, KeyUsagePurpose, BasicConstraints, IsCa, SanType, Issuer};

impl CertificateConfig {
    pub fn read_from_path(path: &str, password: Option<&str>) -> Result<Self, Box<dyn Error>> {
        let bytes = std::fs::read(path)?;
        let cert_type = detect_cert_type(&bytes)?;

        match cert_type {
            CertDataType::PemCertAndKey => {
                let content = std::str::from_utf8(&bytes)?;
                Self::parse_pem_cert_and_key(content)
            }
            CertDataType::PemOnlyCert => {
                let content = std::str::from_utf8(&bytes)?;
                Self::parse_pem_cert_only(content)
            }
            CertDataType::PemOnlyKey => {
                Err("PEM file contains only private key, certificate missing".into())
            }
            CertDataType::P12 { as_base64 } => {
                Self::parse_p12(&bytes, password, as_base64)
            }
        }
    }
    fn parse_pem_cert_and_key(content: &str) -> Result<Self, Box<dyn Error>> {
        let pems = parse_many(content)?;

        let mut cert_pem: Option<String> = None;
        let mut key_pem: Option<String> = None;
        let mut cert_der_bytes: Option<Vec<u8>> = None;

        for pem in pems {
            match pem.tag() {
                "CERTIFICATE" => {
                    // Store the DER bytes
                    cert_der_bytes = Some(pem.contents().to_vec());
                    // Reconstruct PEM format
                    cert_pem = Some(pem::encode(&pem));
                }
                "PRIVATE KEY" | "RSA PRIVATE KEY" | "EC PRIVATE KEY" => {
                    key_pem = Some(pem::encode(&pem));
                }
                _ => {
                    // Unknown PEM type, skip
                }
            }
        }

        let cert_pem = cert_pem.ok_or("No certificate found in PEM")?;
        let der_bytes = cert_der_bytes.ok_or("No certificate DER data found")?;

        // Parse the certificate here where der_bytes is still in scope
        let (_, parsed_cert) = X509Certificate::from_der(&der_bytes)?;

        let cert_data = CertData::Pem {
            cert: cert_pem,
            key: key_pem,
        };

        // Extract certificate info immediately while parsed_cert is valid
        let cert = get_cert_info(parsed_cert, cert_data)?;

        Ok(cert)
    }
    fn parse_pem_cert_only(content: &str) -> Result<Self, Box<dyn Error>> {
        let pem = parse(content)?;

        if pem.tag() != "CERTIFICATE" {
            return Err("PEM does not contain a certificate".into());
        }

        // Parse the certificate with x509_parser
        let (_, cert) = X509Certificate::from_der(pem.contents())?;
        let owned_cert = cert.to_owned();
        let cert_pem = pem::encode(&pem);
        let cert_data = CertData::Pem {
            cert: cert_pem,
            key: None,
        };

        let cert = get_cert_info(cert, cert_data)?;

        Ok(cert)
    }
    pub fn parse_p12(
        bytes: &[u8],
        password: Option<&str>,
        as_base64: bool,
    ) -> Result<Self, Box<dyn Error>> {
        // Decode base64 if necessary
        let raw = if as_base64 {
            let s = std::str::from_utf8(bytes)?;
            let filtered: String = s.chars().filter(|c| !c.is_whitespace()).collect();
            BASE64_STANDARD.decode(&filtered)?
        } else {
            bytes.to_vec()
        };

        let pfx = PFX::parse(&raw)?;
        let pwd = password.unwrap_or("");

        if !pfx.verify_mac(pwd) {
            return Err("PFX MAC verification failed".into());
        }
        // Build cert_data to store entire original P12 content
        let cert_data = CertData::P12 {
            data: if as_base64 {
                String::from_utf8(bytes.to_vec())?
            } else {
                base64::encode(&raw)
            },
            password: pwd.to_string(),
            as_base64,
        };
        let certs = pfx.cert_bags(pwd)?;
        let mut leaf_cert: Option<X509Certificate> = None;

        // Iterate through all certificates
        for der in &certs {
            let (_, cert) = X509Certificate::from_der(der)?;
            // Check if it's a leaf cert (subject != issuer typically)
            if cert.subject() != cert.issuer() {
                leaf_cert = Some(cert.to_owned());
                break;
            }
        }

        let cert = leaf_cert.ok_or("No leaf certificate found in PFX")?;
        let cert = get_cert_info(cert, cert_data)?;

        Ok(cert)
    }

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

    /// Create a new CA certificate
    pub fn new_ca(config: CaConfig) -> Result<Self, CertMgtError> {
        // Create CA certificate parameters
        let mut ca_params = CertificateParams::new(vec![config.common_name.clone()])
            .map_err(|e| CertMgtError::CaGenerationError(e.to_string()))?;

        // Set up distinguished name
        let mut distinguished_name = rcgen::DistinguishedName::new();
        distinguished_name.push(DnType::CommonName, &config.common_name);
        distinguished_name.push(DnType::OrganizationName, &config.organization);
        distinguished_name.push(DnType::StateOrProvinceName, &config.state);
        distinguished_name.push(DnType::CountryName, &config.country);
        ca_params.distinguished_name = distinguished_name;

        // Configure as CA certificate
        ca_params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);

        // Set validity period
        let now = OffsetDateTime::now_utc();
        ca_params.not_before = now;
        ca_params.not_after = now + time::Duration::days(config.validity_days as i64);

        // Set key usage for CA
        ca_params.key_usages = vec![
            rcgen::KeyUsagePurpose::KeyCertSign,
            rcgen::KeyUsagePurpose::CrlSign,
            rcgen::KeyUsagePurpose::DigitalSignature,
        ];

        // Generate key pair
        let key_pair = if config.key_size == 4096 {
            KeyPair::generate_for(&rcgen::PKCS_RSA_SHA256)
        } else {
            KeyPair::generate()
        }.map_err(|e| CertMgtError::KeyGenerationError(e.to_string()))?;

        // Generate self-signed CA certificate
        let ca_cert = ca_params.self_signed(&key_pair)
            .map_err(|e| CertMgtError::CaGenerationError(e.to_string()))?;

        // Create certificate data
        let cert_pem = ca_cert.pem();
        let key_pem = key_pair.serialize_pem();

        Ok(CertificateConfig {
            country: config.country,
            state: config.state,
            locality: "".to_string(),
            organization: config.organization,
            organizational_unit: "".to_string(),
            common_name: config.common_name,
            is_ca: true,
            not_before: now.unix_timestamp(),
            not_after: (now + time::Duration::days(config.validity_days as i64)).unix_timestamp(),
            key_size: Some(config.key_size as usize),
            cert_data: CertData::Pem {
                cert: cert_pem,
                key: Some(key_pem)
            },
            serial_number: "1".to_string(),
        })
    }

    /// Sign a server certificate using this CA
    pub fn sign_certificate(
        &self,
        config: &ServerCertConfig,
        next_serial: u64
    ) -> Result<CertificateConfig, CertMgtError> {
        // Verify this is a CA certificate
        if !self.is_ca {
            return Err(CertMgtError::InvalidConfiguration("Not a CA certificate".to_string()));
        }

        // Create issuer from this CA
        let issuer = self.create_issuer()?;

        // Create certificate parameters
        let mut cert_params = CertificateParams::new(vec![config.common_name.clone()])
            .map_err(|e| CertMgtError::CertificateGenerationError(e.to_string()))?;

        // Set up distinguished name
        let mut distinguished_name = rcgen::DistinguishedName::new();
        distinguished_name.push(DnType::CommonName, &config.common_name);
        distinguished_name.push(DnType::OrganizationName, &config.organization);
        distinguished_name.push(DnType::StateOrProvinceName, &config.state);
        distinguished_name.push(DnType::CountryName, &config.country);
        cert_params.distinguished_name = distinguished_name;

        // Set as end-entity certificate
        cert_params.is_ca = IsCa::NoCa;

        // Set validity period
        let now = OffsetDateTime::now_utc();
        cert_params.not_before = now;
        cert_params.not_after = now + time::Duration::days(config.validity_days as i64);

        // Set key usage for server certificate
        cert_params.key_usages = vec![
            rcgen::KeyUsagePurpose::DigitalSignature,
            rcgen::KeyUsagePurpose::KeyEncipherment,
        ];
        cert_params.extended_key_usages = vec![rcgen::ExtendedKeyUsagePurpose::ServerAuth];

        // Enable authority key identifier extension
        cert_params.use_authority_key_identifier_extension = true;

        // Add subject alternative names
        for san in &config.alt_names {
            if san.parse::<std::net::IpAddr>().is_ok() {
                cert_params.subject_alt_names.push(rcgen::SanType::IpAddress(san.parse().unwrap()));
            } else {
                cert_params.subject_alt_names.push(rcgen::SanType::DnsName(san.parse().unwrap()));
            }
        }

        // Generate key pair for the new certificate
        let key_pair = if config.key_size == 4096 {
            KeyPair::generate_for(&rcgen::PKCS_RSA_SHA256)
        } else {
            KeyPair::generate()
        }.map_err(|e| CertMgtError::KeyGenerationError(e.to_string()))?;

        // Set serial number
        cert_params.serial_number = Some(next_serial.into());

        // Sign the certificate
        let certificate = cert_params.signed_by(&key_pair, &issuer)
            .map_err(|e| CertMgtError::CertificateSigningError(e.to_string()))?;

        // Create certificate data
        let cert_pem = certificate.pem();
        let key_pem = key_pair.serialize_pem();

        Ok(CertificateConfig {
            country: config.country.clone(),
            state: config.state.clone(),
            locality: "".to_string(),
            organization: config.organization.clone(),
            organizational_unit: "".to_string(),
            common_name: config.common_name.clone(),
            is_ca: false,
            not_before: now.unix_timestamp(),
            not_after: (now + time::Duration::days(config.validity_days as i64)).unix_timestamp(),
            key_size: Some(config.key_size),
            cert_data: CertData::Pem {
                cert: cert_pem,
                key: Some(key_pem)
            },
            serial_number: next_serial.to_string(),
        })
    }

    /// Renew this certificate with the same key pair
    pub fn renew_with_ca(
        &self,
        ca_cert: &CertificateConfig,
        new_validity_days: u32,
        next_serial: u64
    ) -> Result<CertificateConfig, CertMgtError> {
        if self.is_ca {
            return Err(CertMgtError::InvalidConfiguration("Cannot renew CA certificates".to_string()));
        }

        // Extract existing private key
        let existing_key_pair = self.extract_private_key()?;

        // Create renewed config with same parameters but new validity
        let renewed_config = ServerCertConfig {
            common_name: self.common_name.clone(),
            organization: self.organization.clone(),
            state: self.state.clone(),
            country: self.country.clone(),
            validity_days: new_validity_days,
            key_size: self.key_size.unwrap_or(2048),
            alt_names: vec![], // You'd need to store/extract SANs if needed
        };

        // Create issuer from CA
        let issuer = ca_cert.create_issuer()?;

        // Create new certificate with same key
        let mut cert_params = CertificateParams::new(vec![renewed_config.common_name.clone()])
            .map_err(|e| CertMgtError::CertificateGenerationError(e.to_string()))?;

        // Set up parameters (similar to sign_certificate)
        // ... (parameter setup code)

        let now = OffsetDateTime::now_utc();
        cert_params.not_before = now;
        cert_params.not_after = now + time::Duration::days(new_validity_days as i64);
        cert_params.serial_number = Some(next_serial.into());

        // Sign with existing key pair
        let certificate = cert_params.signed_by(&existing_key_pair, &issuer)
            .map_err(|e| CertMgtError::CertificateSigningError(e.to_string()))?;

        let cert_pem = certificate.pem();
        let key_pem = existing_key_pair.serialize_pem();

        Ok(CertificateConfig {
            country: self.country.clone(),
            state: self.state.clone(),
            locality: self.locality.clone(),
            organization: self.organization.clone(),
            organizational_unit: self.organizational_unit.clone(),
            common_name: self.common_name.clone(),
            is_ca: false,
            not_before: now.unix_timestamp(),
            not_after: (now + time::Duration::days(new_validity_days as i64)).unix_timestamp(),
            key_size: self.key_size,
            cert_data: CertData::Pem {
                cert: cert_pem,
                key: Some(key_pem)
            },
            serial_number: next_serial.to_string(),
        })
    }

    /// Check if certificate needs renewal
    pub fn needs_renewal(&self, threshold_days: u32) -> bool {
        let now = OffsetDateTime::now_utc().unix_timestamp();
        let expiry_threshold = self.not_after - (threshold_days as i64 * 24 * 60 * 60);
        now >= expiry_threshold
    }

    /// Get days until expiration
    pub fn days_until_expiry(&self) -> i64 {
        let now = OffsetDateTime::now_utc().unix_timestamp();
        (self.not_after - now) / (24 * 60 * 60)
    }

    /// Check if certificate is expired
    pub fn is_expired(&self) -> bool {
        let now = OffsetDateTime::now_utc().unix_timestamp();
        now > self.not_after
    }

    /// Validate certificate data integrity
    pub fn validate(&self) -> Result<(), CertMgtError> {
        match &self.cert_data {
            CertData::Pem { cert, .. } => {
                // Parse the PEM first
                let pem = pem::parse(cert)
                    .map_err(|e| CertMgtError::InvalidConfiguration(format!("Invalid PEM format: {}", e)))?;

                // Then parse the certificate
                let (_remainder, _cert) = X509Certificate::from_der(&pem.contents())
                    .map_err(|e| CertMgtError::InvalidConfiguration(format!("Invalid certificate: {}", e)))?;

                Ok(())
            }
            CertData::P12 { .. } => {
                Ok(())
            }
        }
    }

    /// Export certificate in PEM format
    pub fn export_pem(&self) -> Result<String, CertMgtError> {
        match &self.cert_data {
            CertData::Pem { cert, key } => {
                let mut pem_content = cert.clone();
                if let Some(key_data) = key {
                    if !key_data.is_empty() {
                        pem_content.push('\n');
                        pem_content.push_str(key_data);
                    }
                }
                Ok(pem_content)
            }
            _ => Err(CertMgtError::UnsupportedCertFormat("Certificate is not in PEM format".to_string())),
        }
    }

    /// Check if certificate has a private key
    pub fn has_private_key(&self) -> bool {
        match &self.cert_data {
            CertData::Pem { key: Some(key_data), .. } => !key_data.is_empty(),
            CertData::P12 { .. } => true, // P12 always contains private key
            _ => false,
        }
    }

    // Private helper methods
    fn create_issuer(&self) -> Result<Issuer<'_, KeyPair>, CertMgtError> {
        if !self.is_ca {
            return Err(CertMgtError::InvalidConfiguration("Not a CA certificate".to_string()));
        }

        let (cert_pem, key_pem) = match &self.cert_data {
            CertData::Pem { cert, key: Some(key) } => (cert, key),
            CertData::Pem { key: None, .. } => {
                return Err(CertMgtError::KeyLoadError("CA certificate has no private key".to_string()));
            }
            _ => return Err(CertMgtError::UnsupportedCertFormat("Expected PEM format".to_string())),
        };

        let signing_key = KeyPair::from_pem(key_pem)
            .map_err(|e| CertMgtError::KeyLoadError(e.to_string()))?;

        Issuer::from_ca_cert_pem(cert_pem, signing_key)
            .map_err(|e| CertMgtError::IssuerCreationError(e.to_string()))
    }

    fn extract_private_key(&self) -> Result<KeyPair, CertMgtError> {
        match &self.cert_data {
            CertData::Pem { key: Some(key_pem), .. } => {
                KeyPair::from_pem(key_pem)
                    .map_err(|e| CertMgtError::KeyExtractionError(e.to_string()))
            }
            CertData::Pem { key: None, .. } => {
                Err(CertMgtError::KeyExtractionError("Certificate has no private key".to_string()))
            }
            _ => Err(CertMgtError::UnsupportedCertFormat("Expected PEM format".to_string())),
        }
    }
}

// Utility functions that work with collections of CertificateConfig
impl CertificateConfig {
    /// Find CA certificate from a collection
    pub fn find_ca(certificates: &[CertificateConfig]) -> Option<&CertificateConfig> {
        certificates.iter().find(|cert| cert.is_ca)
    }

    /// Find certificates expiring within threshold days
    pub fn find_expiring(certificates: &[CertificateConfig], threshold_days: u32) -> Vec<&CertificateConfig> {
        certificates.iter()
            .filter(|cert| cert.needs_renewal(threshold_days))
            .collect()
    }

    /// Find certificate by common name
    pub fn find_by_common_name<'a>(certificates: &'a [CertificateConfig], common_name: &str) -> Option<&'a CertificateConfig> {
        certificates.iter().find(|cert| cert.common_name == common_name)
    }

    /// Get next serial number from existing certificates
    pub fn get_next_serial(certificates: &[CertificateConfig]) -> u64 {
        certificates.iter()
            .filter_map(|cert| cert.serial_number.parse::<u64>().ok())
            .max()
            .unwrap_or(0) + 1
    }
}



fn get_subject_attr(parsed: &X509Certificate, oid: Oid) -> String {
    parsed.subject().iter_by_oid(&oid)
        .next()
        .and_then(|attr| attr.as_str().ok())
        .map(|s| s.to_owned())
        .unwrap_or_default()

}

fn get_key_size(cert: &X509Certificate) -> Option<usize> {
    cert.subject_pki
        .parsed()
        .map(|pk| match pk {
            PublicKey::RSA(rsa) => rsa.key_size(),       // RSA: bits in modulus
            PublicKey::EC(ec)   => ec.key_size(),        // EC: curve size
            PublicKey::DSA(buf) => 8 * buf.len(),        // DSA: parameter length
            _ => 0,
        })
        .ok()
        .filter(|&bits| bits > 0)
}
fn get_cert_info(cert: X509Certificate, cert_data: CertData) -> Result<CertificateConfig, Box<dyn std::error::Error>> {
    let serial_number = cert.serial.to_string();
    let is_ca = cert.is_ca();
    let not_after = asn1_time_to_timestamp(&cert.validity.not_after);
    let not_before = asn1_time_to_timestamp(&cert.validity.not_before);
    let country = get_subject_attr(&cert, oid_registry::OID_X509_COUNTRY_NAME);
    let state = get_subject_attr(&cert, oid_registry::OID_X509_STATE_OR_PROVINCE_NAME);
    let locality = get_subject_attr(&cert, oid_registry::OID_X509_LOCALITY_NAME);
    let organization = get_subject_attr(&cert, oid_registry::OID_X509_ORGANIZATION_NAME);
    let organizational_unit = get_subject_attr(&cert, oid_registry::OID_X509_ORGANIZATIONAL_UNIT);
    let common_name = get_subject_attr(&cert, oid_registry::OID_X509_COMMON_NAME);
    let key_size = get_key_size(&cert);
    let cert = CertificateConfig {
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
        serial_number,
    };

    Ok(cert)
}
