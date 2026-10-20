use crate::CertMgtError;
use crate::detection::detect_cert_type;
use crate::types::{CaConfig, CertData, CertDataType, CertificateConfig, ServerCertConfig};
use crate::utils::{
    asn1_time_to_timestamp, canonical_dn, create_time_from_offset_datetime,
    generate_secure_serial_number, timestamp_to_datetime,
};
use base64::Engine as _;
use base64::prelude::BASE64_STANDARD;

use const_oid::db::rfc5912::SHA_256_WITH_RSA_ENCRYPTION;
use der::asn1::{Null, Utf8StringRef};
use der::{Any, Decode, Encode};
use p12_keystore::{KeyStore, KeyStoreEntry};
use pem::{parse, parse_many};
use rand::thread_rng;
use rsa::pkcs1::{DecodeRsaPrivateKey, EncodeRsaPublicKey};
use rsa::pkcs8::{DecodePrivateKey, EncodePrivateKey, EncodePublicKey};
use rsa::sha2::Sha256;
use rsa::signature::{SignatureEncoding, Signer};
use rsa::{RsaPrivateKey, RsaPublicKey, pkcs1v15::SigningKey};
use spki::{AlgorithmIdentifier, SubjectPublicKeyInfo};
use std::error::Error;
use std::net::IpAddr;
use std::path::Path;
use time::{Duration, OffsetDateTime};
use uuid::Uuid;
use x509_cert::attr::AttributeTypeAndValue;
use x509_cert::ext::pkix::KeyUsages;
use x509_cert::{
    Certificate, TbsCertificate, Version,
    ext::{
        Extension, Extensions,
        pkix::{AuthorityKeyIdentifier, BasicConstraints, ExtendedKeyUsage, SubjectAltName},
    },
    name::{Name, RelativeDistinguishedName},
    serial_number::SerialNumber,
    time::Validity,
};
use x509_parser::asn1_rs::{FromDer, Oid};
use x509_parser::certificate::X509Certificate;
use x509_parser::oid_registry;
use x509_parser::pem::parse_x509_pem;
use x509_parser::public_key::PublicKey;

impl CertificateConfig {
    pub fn read_from_path(path: &str, password: Option<&str>) -> Result<Self, CertMgtError> {
        let bytes = std::fs::read(path).map_err(CertMgtError::IoError)?;
        let cert_type = detect_cert_type(&bytes)
            .map_err(|e| CertMgtError::UnsupportedCertFormat(format!("{}: {}", path, e)))?;

        match cert_type {
            CertDataType::PemCertAndKey => {
                let content = std::str::from_utf8(&bytes)?;
                Self::parse_pem_cert_and_key(content)
                    .map_err(|e| CertMgtError::InvalidConfiguration(format!("{}: {}", path, e)))
            }
            CertDataType::PemOnlyCert => {
                let content = std::str::from_utf8(&bytes)?;
                Self::parse_pem_cert_only(content)
                    .map_err(|e| CertMgtError::InvalidConfiguration(format!("{}: {}", path, e)))
            }
            CertDataType::PemOnlyKey => Err(CertMgtError::PemKeyOnly),
            CertDataType::P12 { as_base64 } => Self::parse_p12(&bytes, password, as_base64),
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
    ) -> Result<CertificateConfig, CertMgtError> {
        // Decode base64 if necessary
        let raw = if as_base64 {
            let s = std::str::from_utf8(bytes)?;
            let filtered: String = s.chars().filter(|c| !c.is_whitespace()).collect();
            BASE64_STANDARD.decode(&filtered)?
        } else {
            bytes.to_vec()
        };

        // If no password provided, signal that CLI should prompt
        let pwd = if let Some(p) = password {
            p
        } else {
            return Err(CertMgtError::P12PasswordRequired);
        };

        // Try to load the PKCS#12 keystore
        let keystore = KeyStore::from_pkcs12(&raw, pwd).map_err(|e| {
            let msg = e.to_string();
            if msg.contains("mac verify failure") {
                CertMgtError::P12WrongPassword
            } else {
                CertMgtError::P12LoadFailed(msg)
            }
        })?;

        // Build CertData to store the entire original P12 content
        let cert_data = CertData::P12 {
            data: if as_base64 {
                String::from_utf8(bytes.to_vec())?
            } else {
                BASE64_STANDARD.encode(&raw)
            },
            password: pwd.to_string(),
            as_base64,
        };

        // Collect all certificates and find the leaf certificate
        let mut leaf_cert: Option<X509Certificate> = None;
        let mut all_certs: Vec<X509Certificate> = Vec::new();

        eprintln!("Found {} aliases in keystore", keystore.entries().count());

        for alias in keystore.entries() {
            if let Some(entry) = keystore.entry(alias.0) {
                match entry {
                    KeyStoreEntry::PrivateKeyChain(private_key_chain) => {
                        // First certificate is usually the leaf
                        if let Some(cert) = private_key_chain.chain().first() {
                            let cert_der = cert.as_der();
                            let (_, parsed_cert) = X509Certificate::from_der(cert_der)
                                .map_err(|e| CertMgtError::InvalidConfiguration(e.to_string()))?;
                            if leaf_cert.is_none() {
                                leaf_cert = Some(parsed_cert.clone());
                            }
                            all_certs.push(parsed_cert);
                        }

                        // Collect remaining chain certificates
                        for cert in private_key_chain.chain().iter().skip(1) {
                            let cert_der = cert.as_der();
                            let (_, parsed_cert) = X509Certificate::from_der(cert_der)
                                .map_err(|e| CertMgtError::InvalidConfiguration(e.to_string()))?;
                            all_certs.push(parsed_cert);
                        }
                    }
                    KeyStoreEntry::Certificate(cert) => {
                        let cert_der = cert.as_der();
                        let (_, parsed_cert) = X509Certificate::from_der(cert_der)
                            .map_err(|e| CertMgtError::InvalidConfiguration(e.to_string()))?;
                        all_certs.push(parsed_cert.clone());

                        if leaf_cert.is_none() && parsed_cert.subject() != parsed_cert.issuer() {
                            leaf_cert = Some(parsed_cert);
                        }
                    }
                    _ => {}
                }
            }
        }

        // Fallback if no clear leaf certificate
        if leaf_cert.is_none() && !all_certs.is_empty() {
            let longest_subject_cert = all_certs
                .iter()
                .max_by_key(|cert| cert.subject().to_string().len());
            leaf_cert = longest_subject_cert
                .cloned()
                .or_else(|| all_certs.first().cloned());
        }

        let cert = leaf_cert.ok_or(CertMgtError::InvalidConfiguration(
            "No leaf certificate found in PKCS#12".into(),
        ))?;
        get_cert_info(cert, cert_data)
            .map_err(|e| CertMgtError::InvalidConfiguration(e.to_string()))
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
        // Generate RSA key pair
        let private_key =
            RsaPrivateKey::new(&mut thread_rng(), config.key_size as usize).map_err(|e| {
                CertMgtError::CaGenerationError(format!("Key generation failed: {}", e))
            })?;
        let public_key = RsaPublicKey::from(&private_key);

        // Create subject name
        let subject = create_distinguished_name(
            &config.common_name,
            &config.organization,
            &config.state,
            &config.country,
        )?;

        // Set validity period
        let now = OffsetDateTime::now_utc();
        let not_before = create_time_from_offset_datetime(now)
            .map_err(|e| CertMgtError::CaGenerationError(format!("Invalid start time: {}", e)))?;
        let not_after =
            create_time_from_offset_datetime(now + Duration::days(config.validity_days as i64))?;
        let validity = Validity {
            not_before,
            not_after,
        };

        // Generate serial number
        let serial_number = SerialNumber::from(1u32);

        // Create subject public key info
        let subject_public_key_info = public_key.to_public_key_der().map_err(|e| {
            CertMgtError::CaGenerationError(format!("Public key encoding failed: {}", e))
        })?;
        let spki = SubjectPublicKeyInfo::from_der(subject_public_key_info.as_ref())
            .map_err(|e| CertMgtError::CaGenerationError(format!("SPKI parsing failed: {}", e)))?;

        // Create extensions for CA certificate
        let extensions = create_ca_extensions()?;

        // Create TBS (To Be Signed) certificate
        let tbs_cert = TbsCertificate {
            version: Version::V3,
            serial_number,
            signature: rsa_with_sha256_algorithm_identifier(),
            issuer: subject.clone(), // Self-signed, so issuer = subject
            validity,
            subject,
            subject_public_key_info: spki,
            issuer_unique_id: None,
            subject_unique_id: None,
            extensions: Some(extensions),
        };

        // Sign the certificate
        let tbs_der = tbs_cert
            .to_der()
            .map_err(|e| CertMgtError::CaGenerationError(format!("TBS encoding failed: {}", e)))?;
        let signature = sign_with_rsa_sha256(&private_key, &tbs_der)?;

        // Create final certificate
        let certificate = Certificate {
            tbs_certificate: tbs_cert,
            signature_algorithm: rsa_with_sha256_algorithm_identifier(),
            signature: der::asn1::BitString::from_bytes(&signature).map_err(|e| {
                CertMgtError::CaGenerationError(format!(
                    "Signature BitString creation failed: {}",
                    e
                ))
            })?,
        };

        // Encode to PEM
        let cert_der = certificate.to_der().map_err(|e| {
            CertMgtError::CaGenerationError(format!("Certificate encoding failed: {}", e))
        })?;
        let cert_pem = pem_encode("CERTIFICATE", &cert_der);

        let key_der = private_key.to_pkcs8_der().map_err(|e| {
            CertMgtError::CaGenerationError(format!("Private key encoding failed: {}", e))
        })?;
        let key_pem = pem_encode("PRIVATE KEY", key_der.as_bytes());

        let mut cert = CertificateConfig {
            country: config.country,
            state: config.state,
            locality: "".to_string(),
            organization: config.organization,
            organizational_unit: "".to_string(),
            common_name: config.common_name,
            is_ca: true,
            not_before: timestamp_to_datetime(now.unix_timestamp())?,
            not_after: timestamp_to_datetime(
                (now + Duration::days(config.validity_days as i64)).unix_timestamp(),
            )?,
            key_size: Some(config.key_size as usize),
            cert_data: CertData::Pem {
                cert: cert_pem,
                key: Some(key_pem),
            },
            serial_number: "1".to_string(),
            id: Uuid::new_v4().to_string(),
            ca_id: None,
            issuer_dn: String::new(),
        };
        // A CA is self-signed: its issuer is itself
        cert.issuer_dn = cert.subject_dn();
        Ok(cert)
    }

    /// Sign a server certificate using this CA
    pub fn sign_certificate(
        &self,
        config: &ServerCertConfig,
    ) -> Result<CertificateConfig, CertMgtError> {
        if !self.is_ca {
            return Err(CertMgtError::InvalidConfiguration(
                "Not a CA certificate".to_string(),
            ));
        }

        let mut rng = thread_rng();

        // Generate new key pair for the server certificate
        let private_key = RsaPrivateKey::new(&mut rng, config.key_size).map_err(|e| {
            CertMgtError::CertificateGenerationError(format!("Key generation failed: {}", e))
        })?;
        let public_key = RsaPublicKey::from(&private_key);

        // Extract CA private key for signing
        let ca_private_key = self.extract_ca_private_key()?;

        // Create subject name
        let subject = create_distinguished_name(
            &config.common_name,
            &config.organization,
            &config.state,
            &config.country,
        )?;

        // Create issuer name (from CA)
        let issuer = create_distinguished_name(
            &self.common_name,
            &self.organization,
            &self.state,
            &self.country,
        )?;

        // Set validity period
        let now = OffsetDateTime::now_utc();
        let not_before = create_time_from_offset_datetime(now)
            .map_err(|e| CertMgtError::CaGenerationError(format!("Invalid start time: {}", e)))?;
        let not_after =
            create_time_from_offset_datetime(now + Duration::days(config.validity_days as i64))?;
        let validity = Validity {
            not_before,
            not_after,
        };

        // Generate serial number
        let serial_num = generate_secure_serial_number()?;
        let serial_number = SerialNumber::new(serial_num.as_bytes()).map_err(|e| {
            CertMgtError::CertificateGenerationError(format!(
                "Serial number creation failed: {}",
                e
            ))
        })?;

        // Create subject public key info
        let subject_public_key_info = public_key.to_public_key_der().map_err(|e| {
            CertMgtError::CertificateGenerationError(format!("Public key encoding failed: {}", e))
        })?;
        let spki =
            SubjectPublicKeyInfo::from_der(subject_public_key_info.as_ref()).map_err(|e| {
                CertMgtError::CertificateGenerationError(format!("SPKI parsing failed: {}", e))
            })?;

        // Create extensions for server certificate
        let extensions = create_server_extensions(&config.alt_names, &self.get_ca_public_key()?)?;

        // Create TBS certificate
        let tbs_cert = TbsCertificate {
            version: Version::V3,
            serial_number,
            signature: rsa_with_sha256_algorithm_identifier(),
            issuer,
            validity,
            subject,
            subject_public_key_info: spki,
            issuer_unique_id: None,
            subject_unique_id: None,
            extensions: Some(extensions),
        };

        // Sign the certificate with CA private key
        let tbs_der = tbs_cert.to_der().map_err(|e| {
            CertMgtError::CertificateGenerationError(format!("TBS encoding failed: {}", e))
        })?;

        let signature = sign_with_rsa_sha256(&ca_private_key, &tbs_der)?;

        // Create final certificate
        let certificate = Certificate {
            tbs_certificate: tbs_cert,
            signature_algorithm: rsa_with_sha256_algorithm_identifier(),
            signature: der::asn1::BitString::from_bytes(&signature).map_err(|e| {
                CertMgtError::CertificateGenerationError(format!(
                    "Signature BitString creation failed: {}",
                    e
                ))
            })?,
        };

        // Encode to PEM
        let cert_der = certificate.to_der().map_err(|e| {
            CertMgtError::CertificateGenerationError(format!("Certificate encoding failed: {}", e))
        })?;
        let cert_pem = pem_encode("CERTIFICATE", &cert_der);

        let key_der = private_key.to_pkcs8_der().map_err(|e| {
            CertMgtError::CertificateGenerationError(format!("Private key encoding failed: {}", e))
        })?;
        let key_pem = pem_encode("PRIVATE KEY", key_der.as_bytes());

        Ok(CertificateConfig {
            country: config.country.clone(),
            state: config.state.clone(),
            locality: "".to_string(),
            organization: config.organization.clone(),
            organizational_unit: "".to_string(),
            common_name: config.common_name.clone(),
            is_ca: false,
            not_before: timestamp_to_datetime(now.unix_timestamp())?,
            not_after: timestamp_to_datetime(
                (now + Duration::days(config.validity_days as i64)).unix_timestamp(),
            )?,
            key_size: Some(config.key_size),
            cert_data: CertData::Pem {
                cert: cert_pem,
                key: Some(key_pem),
            },
            serial_number: serial_num.to_string(),
            id: Uuid::new_v4().to_string(),
            ca_id: Some(self.id.clone()),
            issuer_dn: self.subject_dn(),
        })
    }

    /// Renew this certificate with the same key pair
    pub fn renew_with_ca(
        &self,
        ca_cert: &CertificateConfig,
        new_validity_days: u32,
        next_serial: u64,
    ) -> Result<CertificateConfig, CertMgtError> {
        if self.is_ca {
            return Err(CertMgtError::InvalidConfiguration(
                "Cannot renew CA certificates".to_string(),
            ));
        }

        // Extract existing private key
        let existing_private_key = self.extract_private_key_rsa()?;
        let public_key = RsaPublicKey::from(&existing_private_key);

        // Extract CA private key for signing
        let ca_private_key = ca_cert.extract_ca_private_key()?;

        // Create subject and issuer names
        let subject = create_distinguished_name(
            &self.common_name,
            &self.organization,
            &self.state,
            &self.country,
        )?;

        let issuer = create_distinguished_name(
            &ca_cert.common_name,
            &ca_cert.organization,
            &ca_cert.state,
            &ca_cert.country,
        )?;

        // Set new validity period
        let now = OffsetDateTime::now_utc();
        let not_before = create_time_from_offset_datetime(now)
            .map_err(|e| CertMgtError::CaGenerationError(format!("Invalid start time: {}", e)))?;
        let not_after =
            create_time_from_offset_datetime(now + Duration::days(new_validity_days as i64))?;
        let validity = Validity {
            not_before,
            not_after,
        };

        // Set serial number
        let serial_number = SerialNumber::new(&next_serial.to_be_bytes()).map_err(|e| {
            CertMgtError::CertificateGenerationError(format!(
                "Serial number creation failed: {}",
                e
            ))
        })?;

        // Create subject public key info
        let subject_public_key_info = public_key.to_public_key_der().map_err(|e| {
            CertMgtError::CertificateGenerationError(format!("Public key encoding failed: {}", e))
        })?;
        let spki =
            SubjectPublicKeyInfo::from_der(subject_public_key_info.as_ref()).map_err(|e| {
                CertMgtError::CertificateGenerationError(format!("SPKI parsing failed: {}", e))
            })?;

        // Create extensions (using empty alt_names - you might want to extract from original cert)
        let extensions = create_server_extensions(&[], &ca_cert.get_ca_public_key()?)?;

        // Create TBS certificate
        let tbs_cert = TbsCertificate {
            version: Version::V3,
            serial_number,
            signature: rsa_with_sha256_algorithm_identifier(),
            issuer,
            validity,
            subject,
            subject_public_key_info: spki,
            issuer_unique_id: None,
            subject_unique_id: None,
            extensions: Some(extensions),
        };

        // Sign with CA private key
        let tbs_der = tbs_cert.to_der().map_err(|e| {
            CertMgtError::CertificateGenerationError(format!("TBS encoding failed: {}", e))
        })?;

        let signature = sign_with_rsa_sha256(&ca_private_key, &tbs_der)?;

        // Create final certificate
        let certificate = Certificate {
            tbs_certificate: tbs_cert,
            signature_algorithm: rsa_with_sha256_algorithm_identifier(),
            signature: der::asn1::BitString::from_bytes(&signature).map_err(|e| {
                CertMgtError::CertificateGenerationError(format!(
                    "Signature BitString creation failed: {}",
                    e
                ))
            })?,
        };

        // Encode to PEM
        let cert_der = certificate.to_der().map_err(|e| {
            CertMgtError::CertificateGenerationError(format!("Certificate encoding failed: {}", e))
        })?;
        let cert_pem = pem_encode("CERTIFICATE", &cert_der);

        let key_der = existing_private_key.to_pkcs8_der().map_err(|e| {
            CertMgtError::CertificateGenerationError(format!("Private key encoding failed: {}", e))
        })?;
        let key_pem = pem_encode("PRIVATE KEY", key_der.as_bytes());

        Ok(CertificateConfig {
            country: self.country.clone(),
            state: self.state.clone(),
            locality: self.locality.clone(),
            organization: self.organization.clone(),
            organizational_unit: self.organizational_unit.clone(),
            common_name: self.common_name.clone(),
            is_ca: false,
            not_before: timestamp_to_datetime(now.unix_timestamp())?,
            not_after: timestamp_to_datetime(
                (now + Duration::days(new_validity_days as i64)).unix_timestamp(),
            )?,
            key_size: self.key_size,
            cert_data: CertData::Pem {
                cert: cert_pem,
                key: Some(key_pem),
            },
            serial_number: next_serial.to_string(),
            id: Uuid::new_v4().to_string(),
            ca_id: Some(ca_cert.id.clone()),
            issuer_dn: ca_cert.subject_dn(),
        })
    }

    // Helper methods
    fn extract_private_key_rsa(&self) -> Result<RsaPrivateKey, CertMgtError> {
        match &self.cert_data {
            CertData::Pem {
                key: Some(key_pem), ..
            } => {
                let key_der = pem_decode(key_pem).map_err(|e| {
                    CertMgtError::InvalidConfiguration(format!("PEM decode failed: {}", e))
                })?;
                RsaPrivateKey::from_pkcs8_der(&key_der).map_err(|e| {
                    CertMgtError::InvalidConfiguration(format!("Private key parsing failed: {}", e))
                })
            }
            CertData::P12 { data, password, .. } => {
                let filtered: String = data.chars().filter(|c| !c.is_whitespace()).collect();
                let raw = BASE64_STANDARD.decode(&filtered).map_err(|e| {
                    CertMgtError::InvalidConfiguration(format!("P12 base64 decode failed: {e}"))
                })?;
                let keystore = KeyStore::from_pkcs12(&raw, password).map_err(|e| {
                    let msg = e.to_string();
                    if msg.contains("mac verify failure") {
                        CertMgtError::P12WrongPassword
                    } else {
                        CertMgtError::P12LoadFailed(msg)
                    }
                })?;
                let chain = keystore
                    .private_key_chain()
                    .map(|(_, chain)| chain)
                    .ok_or_else(|| {
                        CertMgtError::InvalidConfiguration("No private key available".to_string())
                    })?;
                RsaPrivateKey::from_pkcs8_der(chain.key()).map_err(|e| {
                    CertMgtError::InvalidConfiguration(format!("Private key parsing failed: {e}"))
                })
            }
            _ => Err(CertMgtError::InvalidConfiguration(
                "No private key available".to_string(),
            )),
        }
    }
    pub fn matches_key_file(&self, key_path: &Path) -> bool {
        // Extract cert public key
        let cert_pubkey = match &self.cert_data {
            CertData::Pem { cert, .. } => {
                let (_, pem) = parse_x509_pem(cert.as_bytes()).unwrap();
                let cert = pem.parse_x509().unwrap();
                Some(cert.subject_pki.subject_public_key.data.to_vec())
            }
            _ => return false,
        };

        // Extract key public key
        let key_bytes = match std::fs::read(key_path) {
            Ok(b) => b,
            Err(_) => return false,
        };
        let key_str = match std::str::from_utf8(&key_bytes) {
            Ok(s) => s,
            Err(_) => return false,
        };

        let key_pubkey = match pem::parse(key_str.as_bytes()) {
            Ok(pem) => {
                // Use `pem.contents()` instead of `.contents`
                match RsaPrivateKey::from_pkcs1_der(pem.contents()) {
                    Ok(rsa) => match rsa.to_public_key().to_pkcs1_der() {
                        Ok(der) => Some(der.as_bytes().to_vec()),
                        Err(_) => None,
                    },
                    Err(_) => None,
                }
            }
            Err(_) => None,
        };

        cert_pubkey.is_some() && cert_pubkey == key_pubkey
    }
    /// Returns `true` if the given PEM key file matches the certificate.
    pub fn attach_key_from_file(
        &mut self,
        key_path: &Path,
        _password: Option<&str>,
    ) -> Result<(), CertMgtError> {
        let bytes = std::fs::read(key_path)?;
        let key_str = std::str::from_utf8(&bytes)?;

        match &mut self.cert_data {
            CertData::Pem {
                cert: _,
                key: existing_key,
            } => {
                if existing_key.is_some() {
                    eprintln!("Certificate already has a key attached. Overwriting.");
                }
                *existing_key = Some(key_str.to_string());
            }
            CertData::P12 { .. } => {
                return Err(CertMgtError::InvalidPrivateKey(
                    "Cannot attach PEM key to P12 certificate".into(),
                ));
            }
        }

        Ok(())
    }

    fn extract_ca_private_key(&self) -> Result<RsaPrivateKey, CertMgtError> {
        self.extract_private_key_rsa()
    }

    fn get_ca_public_key(&self) -> Result<RsaPublicKey, CertMgtError> {
        let private_key = self.extract_private_key_rsa()?;
        Ok(RsaPublicKey::from(&private_key))
    }

    /// Check if certificate needs renewal
    pub fn needs_renewal(&self, threshold_days: u32) -> bool {
        let now = OffsetDateTime::now_utc().unix_timestamp();
        let expiry_threshold = self.not_after.timestamp() - (threshold_days as i64 * 24 * 60 * 60);
        now >= expiry_threshold
    }

    /// Get days until expiration
    pub fn days_until_expiry(&self) -> i64 {
        let now = OffsetDateTime::now_utc().unix_timestamp();
        (self.not_after.timestamp() - now) / (24 * 60 * 60)
    }

    /// Check if certificate is expired
    pub fn is_expired(&self) -> bool {
        let now = OffsetDateTime::now_utc().unix_timestamp();
        now > self.not_after.timestamp()
    }

    /// Validate certificate data integrity
    pub fn validate(&self) -> Result<(), CertMgtError> {
        match &self.cert_data {
            CertData::Pem { cert, .. } => {
                // Parse the PEM first
                let pem = parse(cert).map_err(|e| {
                    CertMgtError::InvalidConfiguration(format!("Invalid PEM format: {}", e))
                })?;

                // Then parse the certificate
                let (_remainder, _cert) =
                    X509Certificate::from_der(pem.contents()).map_err(|e| {
                        CertMgtError::InvalidConfiguration(format!("Invalid certificate: {}", e))
                    })?;

                Ok(())
            }
            CertData::P12 { .. } => Ok(()),
        }
    }

    /// Export certificate in PEM format
    pub fn export_pem(&self) -> Result<String, CertMgtError> {
        match &self.cert_data {
            CertData::Pem { cert, key } => {
                let mut pem_content = cert.clone();
                if let Some(key_data) = key
                    && !key_data.is_empty()
                {
                    pem_content.push('\n');
                    pem_content.push_str(key_data);
                }
                Ok(pem_content)
            }
            _ => Err(CertMgtError::UnsupportedCertFormat(
                "Certificate is not in PEM format".to_string(),
            )),
        }
    }

    /// Check if certificate has a private key
    pub fn has_private_key(&self) -> bool {
        match &self.cert_data {
            CertData::Pem {
                key: Some(key_data),
                ..
            } => !key_data.is_empty(),
            CertData::P12 { .. } => true, // P12 always contains private key
            _ => false,
        }
    }

    // Utility functions that work with collections of CertificateConfig
    /// Find CA certificate from a collection
    pub fn find_ca(certificates: &[CertificateConfig]) -> Option<&CertificateConfig> {
        certificates.iter().find(|cert| cert.is_ca)
    }

    /// Find certificates expiring within threshold days
    pub fn find_expiring(
        certificates: &[CertificateConfig],
        threshold_days: u32,
    ) -> Vec<&CertificateConfig> {
        certificates
            .iter()
            .filter(|cert| cert.needs_renewal(threshold_days))
            .collect()
    }

    /// Find certificate by common name
    pub fn find_by_common_name<'a>(
        certificates: &'a [CertificateConfig],
        common_name: &str,
    ) -> Option<&'a CertificateConfig> {
        certificates
            .iter()
            .find(|cert| cert.common_name == common_name)
    }

    /// Get next serial number from existing certificates
    pub fn get_next_serial(certificates: &[CertificateConfig]) -> u64 {
        certificates
            .iter()
            .filter_map(|cert| cert.serial_number.parse::<u64>().ok())
            .max()
            .unwrap_or(0)
            + 1
    }
}

fn create_distinguished_name(
    common_name: &str,
    organization: &str,
    state: &str,
    country: &str,
) -> Result<Name, CertMgtError> {
    use der::{Encode, asn1::PrintableString, asn1::SetOfVec};

    let mut rdn_sequence = Vec::new();

    // Country
    if !country.is_empty() {
        let country_value = PrintableString::new(country)
            .map_err(|e| CertMgtError::CaGenerationError(format!("Invalid country name: {}", e)))?;
        let country_bytes = country_value.to_der().map_err(|e| {
            CertMgtError::CaGenerationError(format!("Country encoding failed: {}", e))
        })?;
        let country_attr = AttributeTypeAndValue {
            oid: const_oid::db::rfc4519::C,
            value: der::Any::from_der(&country_bytes).map_err(|e| {
                CertMgtError::CaGenerationError(format!("Country value creation failed: {}", e))
            })?,
        };
        let country_set = SetOfVec::try_from(vec![country_attr]).map_err(|e| {
            CertMgtError::CaGenerationError(format!("Country RDN creation failed: {}", e))
        })?;
        rdn_sequence.push(RelativeDistinguishedName::from(country_set));
    }

    // State
    if !state.is_empty() {
        let state_value = PrintableString::new(state)
            .map_err(|e| CertMgtError::CaGenerationError(format!("Invalid state name: {}", e)))?;
        let state_bytes = state_value.to_der().map_err(|e| {
            CertMgtError::CaGenerationError(format!("State encoding failed: {}", e))
        })?;
        let state_attr = AttributeTypeAndValue {
            oid: const_oid::db::rfc4519::ST,
            value: der::Any::from_der(&state_bytes).map_err(|e| {
                CertMgtError::CaGenerationError(format!("State value creation failed: {}", e))
            })?,
        };
        let state_set = SetOfVec::try_from(vec![state_attr]).map_err(|e| {
            CertMgtError::CaGenerationError(format!("State RDN creation failed: {}", e))
        })?;
        rdn_sequence.push(RelativeDistinguishedName::from(state_set));
    }

    // Organization
    if !organization.is_empty() {
        let org_value = PrintableString::new(organization).map_err(|e| {
            CertMgtError::CaGenerationError(format!("Invalid organization name: {}", e))
        })?;
        let org_bytes = org_value.to_der().map_err(|e| {
            CertMgtError::CaGenerationError(format!("Organization encoding failed: {}", e))
        })?;
        let org_attr = AttributeTypeAndValue {
            oid: const_oid::db::rfc4519::O,
            value: der::Any::from_der(&org_bytes).map_err(|e| {
                CertMgtError::CaGenerationError(format!(
                    "Organization value creation failed: {}",
                    e
                ))
            })?,
        };
        let org_set = SetOfVec::try_from(vec![org_attr]).map_err(|e| {
            CertMgtError::CaGenerationError(format!("Organization RDN creation failed: {}", e))
        })?;
        rdn_sequence.push(RelativeDistinguishedName::from(org_set));
    }

    // // Common Name
    // let cn_value = ::new(common_name)
    //     .map_err(|e| CertMgtError::CaGenerationError(format!("Invalid common name {}: {}", common_name, e)))?;

    let cn_value = Utf8StringRef::new(common_name)?;
    let cn_bytes = cn_value.to_der().map_err(|e| {
        CertMgtError::CaGenerationError(format!("Common name encoding failed: {}", e))
    })?;
    let cn_attr = AttributeTypeAndValue {
        oid: const_oid::db::rfc4519::CN,
        value: der::Any::from_der(&cn_bytes).map_err(|e| {
            CertMgtError::CaGenerationError(format!("Common name value creation failed: {}", e))
        })?,
    };
    let cn_set = SetOfVec::try_from(vec![cn_attr]).map_err(|e| {
        CertMgtError::CaGenerationError(format!("Common name RDN creation failed: {}", e))
    })?;
    rdn_sequence.push(RelativeDistinguishedName::from(cn_set));

    Ok(Name::from(rdn_sequence))
}

fn create_ca_extensions() -> Result<Extensions, CertMgtError> {
    let mut extensions = Vec::new();

    // Basic Constraints - CA:TRUE
    let basic_constraints = BasicConstraints {
        ca: true,
        path_len_constraint: None,
    };
    extensions.push(Extension {
        extn_id: const_oid::db::rfc5280::ID_CE_BASIC_CONSTRAINTS,
        critical: true,
        extn_value: der::asn1::OctetString::new(&*basic_constraints.to_der().map_err(|e| {
            CertMgtError::CaGenerationError(format!("Basic constraints encoding failed: {}", e))
        })?)
        .map_err(|e| {
            CertMgtError::CaGenerationError(format!(
                "Basic constraints OctetString creation failed: {}",
                e
            ))
        })?,
    });

    // Key Usage
    let key_usage = KeyUsages::KeyCertSign | KeyUsages::CRLSign | KeyUsages::DigitalSignature;
    extensions.push(Extension {
        extn_id: const_oid::db::rfc5280::ID_CE_KEY_USAGE,
        critical: true,
        extn_value: der::asn1::OctetString::new(&*key_usage.to_der().map_err(|e| {
            CertMgtError::CaGenerationError(format!("Key usage encoding failed: {}", e))
        })?)
        .map_err(|e| {
            CertMgtError::CaGenerationError(format!("Key usage OctetString creation failed: {}", e))
        })?,
    });

    Ok(Extensions::from(extensions))
}

fn create_server_extensions(
    alt_names: &[String],
    ca_public_key: &RsaPublicKey,
) -> Result<Extensions, CertMgtError> {
    let mut extensions = Vec::new();

    // Basic Constraints - CA:FALSE
    let basic_constraints = BasicConstraints {
        ca: false,
        path_len_constraint: None,
    };
    extensions.push(Extension {
        extn_id: const_oid::db::rfc5280::ID_CE_BASIC_CONSTRAINTS,
        critical: true,
        extn_value: der::asn1::OctetString::new(&*basic_constraints.to_der().map_err(|e| {
            CertMgtError::CertificateGenerationError(format!(
                "Basic constraints encoding failed: {}",
                e
            ))
        })?)
        .map_err(|e| {
            CertMgtError::CertificateGenerationError(format!(
                "Basic constraints OctetString creation failed: {}",
                e
            ))
        })?,
    });

    // Key Usage
    let key_usage = KeyUsages::DigitalSignature | KeyUsages::KeyEncipherment;
    extensions.push(Extension {
        extn_id: const_oid::db::rfc5280::ID_CE_KEY_USAGE,
        critical: true,
        extn_value: der::asn1::OctetString::new(&*key_usage.to_der().map_err(|e| {
            CertMgtError::CertificateGenerationError(format!("Key usage encoding failed: {}", e))
        })?)
        .map_err(|e| {
            CertMgtError::CertificateGenerationError(format!(
                "Key usage OctetString creation failed: {}",
                e
            ))
        })?,
    });

    // Extended Key Usage
    let ext_key_usage = ExtendedKeyUsage::from(vec![
        const_oid::db::rfc5280::ID_KP_SERVER_AUTH,
        const_oid::db::rfc5280::ID_KP_CLIENT_AUTH,
    ]);
    extensions.push(Extension {
        extn_id: const_oid::db::rfc5280::ID_CE_EXT_KEY_USAGE,
        critical: false,
        extn_value: der::asn1::OctetString::new(&*ext_key_usage.to_der().map_err(|e| {
            CertMgtError::CertificateGenerationError(format!(
                "Extended key usage encoding failed: {}",
                e
            ))
        })?)
        .map_err(|e| {
            CertMgtError::CertificateGenerationError(format!(
                "Extended key usage OctetString creation failed: {}",
                e
            ))
        })?,
    });

    // Subject Alternative Name
    if !alt_names.is_empty() {
        let mut san_names = Vec::new();
        for name in alt_names {
            if let Ok(ip) = name.parse::<IpAddr>() {
                let ip_bytes = match ip {
                    IpAddr::V4(ipv4) => ipv4.octets().to_vec(),
                    IpAddr::V6(ipv6) => ipv6.octets().to_vec(),
                };
                san_names.push(x509_cert::ext::pkix::name::GeneralName::IpAddress(
                    der::asn1::OctetString::new(&*ip_bytes).map_err(|e| {
                        CertMgtError::CertificateGenerationError(format!(
                            "IP address OctetString creation failed: {}",
                            e
                        ))
                    })?,
                ));
            } else {
                let ia5_string = der::asn1::Ia5String::new(name).map_err(|e| {
                    CertMgtError::CertificateGenerationError(format!("Invalid DNS name: {}", e))
                })?;
                san_names.push(x509_cert::ext::pkix::name::GeneralName::DnsName(ia5_string));
            }
        }

        let subject_alt_name = SubjectAltName(san_names);
        extensions.push(Extension {
            extn_id: const_oid::db::rfc5280::ID_CE_SUBJECT_ALT_NAME,
            critical: false,
            extn_value: der::asn1::OctetString::new(&*subject_alt_name.to_der().map_err(|e| {
                CertMgtError::CertificateGenerationError(format!("SAN encoding failed: {}", e))
            })?)
            .map_err(|e| {
                CertMgtError::CertificateGenerationError(format!(
                    "SAN OctetString creation failed: {}",
                    e
                ))
            })?,
        });
    }

    // Authority Key Identifier
    let ca_public_key_der = ca_public_key.to_public_key_der().map_err(|e| {
        CertMgtError::CertificateGenerationError(format!("CA public key encoding failed: {}", e))
    })?;
    let key_id = sha1_hash(ca_public_key_der.as_ref());

    let authority_key_id = AuthorityKeyIdentifier {
        key_identifier: Some(der::asn1::OctetString::new(key_id).map_err(|e| {
            CertMgtError::CertificateGenerationError(format!(
                "Key ID OctetString creation failed: {}",
                e
            ))
        })?),
        authority_cert_issuer: None,
        authority_cert_serial_number: None,
    };

    extensions.push(Extension {
        extn_id: const_oid::db::rfc5280::ID_CE_AUTHORITY_KEY_IDENTIFIER,
        critical: false,
        extn_value: der::asn1::OctetString::new(&*authority_key_id.to_der().map_err(|e| {
            CertMgtError::CertificateGenerationError(format!(
                "Authority key ID encoding failed: {}",
                e
            ))
        })?)
        .map_err(|e| {
            CertMgtError::CertificateGenerationError(format!(
                "Authority key ID OctetString creation failed: {}",
                e
            ))
        })?,
    });

    Ok(Extensions::from(extensions))
}

fn rsa_with_sha256_algorithm_identifier() -> AlgorithmIdentifier<Any> {
    AlgorithmIdentifier {
        oid: SHA_256_WITH_RSA_ENCRYPTION,
        parameters: Some(Null.into()),
    }
}
fn pem_encode(label: &str, data: &[u8]) -> String {
    use base64::{Engine as _, engine::general_purpose::STANDARD};
    let encoded = STANDARD.encode(data);
    format!(
        "-----BEGIN {}-----\n{}\n-----END {}-----\n",
        label,
        encoded
            .chars()
            .collect::<Vec<_>>()
            .chunks(64)
            .map(|chunk| chunk.iter().collect::<String>())
            .collect::<Vec<_>>()
            .join("\n"),
        label
    )
}

fn pem_decode(pem: &str) -> Result<Vec<u8>, Box<dyn Error>> {
    use base64::{Engine as _, engine::general_purpose::STANDARD};

    let lines: Vec<&str> = pem.lines().collect();
    let start_idx = lines
        .iter()
        .position(|&line| line.starts_with("-----BEGIN"))
        .ok_or("No PEM begin marker found")?;
    let end_idx = lines
        .iter()
        .position(|&line| line.starts_with("-----END"))
        .ok_or("No PEM end marker found")?;

    let base64_data = lines[start_idx + 1..end_idx].join("");
    Ok(STANDARD.decode(base64_data)?)
}

fn sha1_hash(data: &[u8]) -> [u8; 20] {
    use sha1::{Digest, Sha1};
    let mut hasher = Sha1::new();
    hasher.update(data);
    hasher.finalize().into()
}

fn get_subject_attr(parsed: &X509Certificate, oid: Oid) -> String {
    parsed
        .subject()
        .iter_by_oid(&oid)
        .next()
        .and_then(|attr| attr.as_str().ok())
        .map(|s| s.to_owned())
        .unwrap_or_default()
}

fn get_issuer_attr(parsed: &X509Certificate, oid: Oid) -> String {
    parsed
        .issuer()
        .iter_by_oid(&oid)
        .next()
        .and_then(|attr| attr.as_str().ok())
        .map(|s| s.to_owned())
        .unwrap_or_default()
}

fn get_key_size(cert: &X509Certificate) -> Option<usize> {
    cert.subject_pki
        .parsed()
        .map(|pk| match pk {
            PublicKey::RSA(rsa) => rsa.key_size(), // RSA: bits in modulus
            PublicKey::EC(ec) => ec.key_size(),    // EC: curve size
            PublicKey::DSA(buf) => 8 * buf.len(),  // DSA: parameter length
            _ => 0,
        })
        .ok()
        .filter(|&bits| bits > 0)
}
fn get_cert_info(
    cert: X509Certificate,
    cert_data: CertData,
) -> Result<CertificateConfig, Box<dyn Error>> {
    let serial_number = cert.serial.to_string();
    let is_ca = cert.is_ca();
    let not_after = timestamp_to_datetime(asn1_time_to_timestamp(&cert.validity.not_after))
        .map_err(|e| e.to_string())?;
    let not_before = timestamp_to_datetime(asn1_time_to_timestamp(&cert.validity.not_before))
        .map_err(|e| e.to_string())?;
    let country = get_subject_attr(&cert, oid_registry::OID_X509_COUNTRY_NAME);
    let state = get_subject_attr(&cert, oid_registry::OID_X509_STATE_OR_PROVINCE_NAME);
    let locality = get_subject_attr(&cert, oid_registry::OID_X509_LOCALITY_NAME);
    let organization = get_subject_attr(&cert, oid_registry::OID_X509_ORGANIZATION_NAME);
    let organizational_unit = get_subject_attr(&cert, oid_registry::OID_X509_ORGANIZATIONAL_UNIT);
    let common_name = get_subject_attr(&cert, oid_registry::OID_X509_COMMON_NAME);
    let issuer_dn = canonical_dn(
        &get_issuer_attr(&cert, oid_registry::OID_X509_COUNTRY_NAME),
        &get_issuer_attr(&cert, oid_registry::OID_X509_STATE_OR_PROVINCE_NAME),
        &get_issuer_attr(&cert, oid_registry::OID_X509_LOCALITY_NAME),
        &get_issuer_attr(&cert, oid_registry::OID_X509_ORGANIZATION_NAME),
        &get_issuer_attr(&cert, oid_registry::OID_X509_ORGANIZATIONAL_UNIT),
        &get_issuer_attr(&cert, oid_registry::OID_X509_COMMON_NAME),
    );
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
        id: Uuid::new_v4().to_string(),
        ca_id: None,
        issuer_dn,
    };

    Ok(cert)
}

/// Re-link non-CA certificates to their issuing CA by DN.
/// Runs after import/merge: links freshly imported entries and repairs
/// links that dangled (e.g. after a CA was force-reimported).
pub fn relink_ca_references(certificates: &mut [CertificateConfig]) {
    // Collect CA identity up-front (owned) so we can iterate mutably below
    let cas: Vec<(String, String)> = certificates
        .iter()
        .filter(|c| c.is_ca)
        .map(|c| (c.id.clone(), c.subject_dn()))
        .collect();
    for cert in certificates.iter_mut().filter(|c| !c.is_ca) {
        if cert
            .ca_id
            .as_deref()
            .is_some_and(|id| cas.iter().any(|(cid, _)| cid == id))
        {
            continue;
        }
        cert.ca_id = cas
            .iter()
            .find(|(_, dn)| *dn == cert.issuer_dn)
            .map(|(id, _)| id.clone());
    }
}

fn sign_with_rsa_sha256(private_key: &RsaPrivateKey, data: &[u8]) -> Result<Vec<u8>, CertMgtError> {
    let signing_key = SigningKey::<Sha256>::new(private_key.clone());
    let signature = signing_key.sign(data); // Automatically hashes & signs
    Ok(signature.to_bytes().to_vec())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn p12_ca_can_sign_certificates() {
        let ca = CertificateConfig::new_ca(CaConfig {
            country: "US".into(),
            state: "CA".into(),
            organization: "Test Org".into(),
            common_name: "Test P12 CA".into(),
            key_size: 2048,
            validity_days: 365,
        })
        .expect("CA generation failed");

        let (cert_pem, key_pem) = match &ca.cert_data {
            CertData::Pem {
                cert,
                key: Some(key),
                ..
            } => (cert.clone(), key.clone()),
            _ => panic!("expected PEM CA with private key"),
        };

        let cert_der = pem::parse(&cert_pem).expect("cert PEM").contents().to_vec();
        let key_der = pem::parse(&key_pem).expect("key PEM").contents().to_vec();
        let p12_cert = p12_keystore::Certificate::from_der(&cert_der).expect("p12 cert");
        let chain = p12_keystore::PrivateKeyChain::new(key_der, b"ca", [p12_cert]);
        let mut keystore = KeyStore::new();
        keystore.add_entry("ca", KeyStoreEntry::PrivateKeyChain(chain));
        let p12_bytes = keystore.writer("s3cret").write().expect("p12 write");

        let ca_from_p12 =
            CertificateConfig::parse_p12(&p12_bytes, Some("s3cret"), false).expect("parse_p12");
        assert!(ca_from_p12.is_ca);
        assert!(ca_from_p12.has_private_key());

        let server = CertificateConfig::sign_certificate(
            &ca_from_p12,
            &ServerCertConfig {
                country: "US".into(),
                state: "CA".into(),
                organization: "Test Org".into(),
                common_name: "p12.test.example".into(),
                alt_names: vec![],
                key_size: 2048,
                validity_days: 30,
            },
        )
        .expect("signing with P12 CA must work");
        assert_eq!(server.common_name, "p12.test.example");
    }

    #[test]
    fn generated_cert_links_to_its_ca() {
        let ca = CertificateConfig::new_ca(CaConfig {
            country: "US".into(),
            state: "CA".into(),
            organization: "Link Org".into(),
            common_name: "Link CA".into(),
            key_size: 2048,
            validity_days: 365,
        })
        .expect("CA generation failed");

        // A CA is self-linked: issuer DN is its own subject DN, no ca_id
        assert_eq!(ca.id.len(), 36, "id must be a UUID v4 string");
        assert_eq!(ca.ca_id, None);
        assert_eq!(ca.issuer_dn, ca.subject_dn());
        assert!(ca.subject_dn().contains("CN=Link CA"));

        let server = CertificateConfig::sign_certificate(
            &ca,
            &ServerCertConfig {
                country: "US".into(),
                state: "CA".into(),
                organization: "Link Org".into(),
                common_name: "linked.test.example".into(),
                alt_names: vec![],
                key_size: 2048,
                validity_days: 30,
            },
        )
        .expect("signing failed");

        // The child cert carries the CA's ID and subject DN as issuer
        assert_ne!(server.id, ca.id);
        assert_eq!(server.ca_id, Some(ca.id.clone()));
        assert_eq!(server.issuer_dn, ca.subject_dn());
    }

    #[test]
    fn relink_repairs_dangling_links() {
        let ca = CertificateConfig::new_ca(CaConfig {
            country: "US".into(),
            state: "CA".into(),
            organization: "Link Org".into(),
            common_name: "Relink CA".into(),
            key_size: 2048,
            validity_days: 365,
        })
        .expect("CA generation failed");

        let server = CertificateConfig::sign_certificate(
            &ca,
            &ServerCertConfig {
                country: "US".into(),
                state: "CA".into(),
                organization: "Link Org".into(),
                common_name: "relinked.test.example".into(),
                alt_names: vec![],
                key_size: 2048,
                validity_days: 30,
            },
        )
        .expect("signing failed");

        let mut certs = vec![ca, server];
        // Simulate a CA force-reimport: the child still points at the dead ID
        certs[1].ca_id = Some("dead-id".into());
        relink_ca_references(&mut certs);
        // The DN still matches the live CA → link is repaired
        assert_eq!(certs[1].ca_id, Some(certs[0].id.clone()));

        // An external issuer (DN matches no CA) must remain unlinked
        let mut orphan = certs[1].clone();
        orphan.issuer_dn = "CN=Unknown External CA".to_string();
        orphan.ca_id = None;
        let mut all = vec![certs[0].clone(), orphan];
        relink_ca_references(&mut all);
        assert_eq!(all[1].ca_id, None);
    }
}
