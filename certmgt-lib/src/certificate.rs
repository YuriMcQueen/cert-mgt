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
use rcgen::{Certificate, CertificateParams, DistinguishedName, DnType, ExtendedKeyUsagePurpose, KeyPair, KeyUsagePurpose, BasicConstraints, IsCa, SanType};

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

    /// Check if this certificate has a private key
    pub fn has_private_key(&self) -> bool {
        match &self.cert_data {
            CertData::Pem { key, .. } => key.is_some(),
            CertData::P12 { .. } => true, // P12 always contains both cert and key
        }
    }
}



impl CertificateAuthority {
    /// Creates a new Certificate Authority from CaConfig
    pub fn new(config: CaConfig) -> Result<Self, CertMgtError> {
        // Create CA certificate parameters
        let mut ca_params = CertificateParams::new(vec![config.common_name.clone()])
            .map_err(|e| CertMgtError::CaGenerationError(e.to_string()))?;

        // Set up distinguished name
        let mut distinguished_name = DistinguishedName::new();
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
            KeyUsagePurpose::KeyCertSign,
            KeyUsagePurpose::CrlSign,
            KeyUsagePurpose::DigitalSignature,
        ];

        // Generate key pair with specified size
        let key_pair: KeyPair = if config.key_size == 4096 {
            KeyPair::generate_for(&rcgen::PKCS_RSA_SHA256)
        } else {
            KeyPair::generate()
        }.map_err(|e| CertMgtError::KeyGenerationError(e.to_string()))?;


        // Generate self-signed CA certificate
        let ca_cert = ca_params.self_signed(&key_pair)
            .map_err(|e| CertMgtError::CaGenerationError(e.to_string()))?;

        Ok(CertificateAuthority {
            ca_cert,
            ca_config: config,
            serial_counter: 1,
            issued_certificates: HashMap::new(),
        })
    }


    /// Signs a server certificate based on ServerCertConfig
    pub fn sign_server_certificate(&mut self, config: &ServerCertConfig, cert_data_type: CertDataType) -> Result<CertificateConfig, CertMgtError> {
        // Create certificate parameters
        let mut cert_params = CertificateParams::new(vec![config.common_name.clone()])
            .map_err(|e| CertMgtError::CertificateGenerationError(e.to_string()))?;

        // Set up distinguished name
        let mut distinguished_name = DistinguishedName::new();
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
            KeyUsagePurpose::DigitalSignature,
            KeyUsagePurpose::KeyEncipherment,
        ];
        cert_params.extended_key_usages = vec![ExtendedKeyUsagePurpose::ServerAuth];

        // Add subject alternative names
        for san in &config.alt_names {
            if san.parse::<std::net::IpAddr>().is_ok() {
                cert_params.subject_alt_names.push(SanType::IpAddress(san.parse().unwrap()));
            } else {
                cert_params.subject_alt_names.push(SanType::DnsName(san.clone()));
            }
        }

        // Generate key pair with specified size
        let key_pair = if config.key_size == 4096 {
            KeyPair::generate_for(&rcgen::PKCS_RSA_SHA256)
        } else {
            KeyPair::generate()
        }.map_err(|e| CertMgtError::KeyGenerationError(e.to_string()))?;

        cert_params.key_pair = Some(key_pair);

        // Increment serial number
        self.serial_counter += 1;
        cert_params.serial_number = Some(self.serial_counter.into());

        // Sign the certificate with CA
        let certificate = cert_params.signed_by(&self.ca_cert, &self.ca_cert.key_pair().unwrap())
            .map_err(|e| CertMgtError::CertificateSigningError(e.to_string()))?;

        // Create CertificateConfig based on requested format
        let cert_data = self.create_cert_data(&certificate, cert_data_type, "changeme")?;

        let cert_config = CertificateConfig {
            country: config.country.clone(),
            state: config.state.clone(),
            locality: "".to_string(), // Not specified in ServerCertConfig
            organization: config.organization.clone(),
            organizational_unit: "".to_string(), // Not specified in ServerCertConfig
            common_name: config.common_name.clone(),
            is_ca: false,
            not_before: now.unix_timestamp(),
            not_after: (now + time::Duration::days(config.validity_days as i64)).unix_timestamp(),
            key_size: Some(config.key_size),
            cert_data,
            serial_number: ,
        };

        // Store the issued certificate
        self.issued_certificates.insert(config.common_name.clone(), cert_config.clone());

        Ok(cert_config)
    }

    /// Creates a custom certificate from a full CertificateConfig (for renewal scenarios)
    pub fn sign_certificate_from_config(&mut self, config: &CertificateConfig, cert_data_type: CertDataType) -> Result<CertificateConfig, CertMgtError> {
        // Create certificate parameters
        let mut cert_params = CertificateParams::new(vec![config.common_name.clone()])
            .map_err(|e| CertMgtError::CertificateGenerationError(e.to_string()))?;

        // Set up distinguished name
        let mut distinguished_name = DistinguishedName::new();
        distinguished_name.push(DnType::CommonName, &config.common_name);
        distinguished_name.push(DnType::OrganizationName, &config.organization);
        distinguished_name.push(DnType::OrganizationalUnitName, &config.organizational_unit);
        distinguished_name.push(DnType::StateOrProvinceName, &config.state);
        distinguished_name.push(DnType::LocalityName, &config.locality);
        distinguished_name.push(DnType::CountryName, &config.country);
        cert_params.distinguished_name = distinguished_name;

        // Set CA flag
        cert_params.is_ca = if config.is_ca {
            IsCa::Ca(BasicConstraints::Constrained(0))
        } else {
            IsCa::NoCa
        };

        // Set validity period from config timestamps
        let not_before = OffsetDateTime::from_unix_timestamp(config.not_before)
            .map_err(|e| CertMgtError::CertificateGenerationError(e.to_string()))?;
        let not_after = OffsetDateTime::from_unix_timestamp(config.not_after)
            .map_err(|e| CertMgtError::CertificateGenerationError(e.to_string()))?;

        cert_params.not_before = not_before;
        cert_params.not_after = not_after;

        // Set key usage based on certificate type
        if config.is_ca {
            cert_params.key_usages = vec![
                KeyUsagePurpose::KeyCertSign,
                KeyUsagePurpose::CrlSign,
                KeyUsagePurpose::DigitalSignature,
            ];
        } else {
            cert_params.key_usages = vec![
                KeyUsagePurpose::DigitalSignature,
                KeyUsagePurpose::KeyEncipherment,
            ];
            cert_params.extended_key_usages = vec![ExtendedKeyUsagePurpose::ServerAuth];
        }

        // Generate key pair
        let key_size = config.key_size.unwrap_or(2048);
        let key_pair = if key_size == 4096 {
            KeyPair::generate_for(&rcgen::PKCS_RSA_SHA256)
        } else {
            KeyPair::generate()
        }.map_err(|e| CertMgtError::KeyGenerationError(e.to_string()))?;

        cert_params.key_pair = Some(key_pair);

        // Increment serial number
        self.serial_counter += 1;
        cert_params.serial_number = Some(self.serial_counter.into());

        // Sign the certificate
        let certificate = cert_params.signed_by(&self.ca_cert, &self.ca_cert.key_pair().unwrap())
            .map_err(|e| CertMgtError::CertificateSigningError(e.to_string()))?;

        // Create CertData based on requested format
        let cert_data = self.create_cert_data(&certificate, cert_data_type, "changeme")?;

        let mut new_config = config.clone();
        new_config.cert_data = cert_data;
        new_config.key_size = Some(key_size);

        // Store the issued certificate
        self.issued_certificates.insert(config.common_name.clone(), new_config.clone());

        Ok(new_config)
    }

    /// Renews an existing certificate with extended validity
    pub fn renew_certificate(&mut self, common_name: &str, new_validity_days: u32, cert_data_type: CertDataType) -> Result<CertificateConfig, CertMgtError> {
        // Get the original certificate config
        let mut original_config = self.issued_certificates.get(common_name)
            .ok_or_else(|| CertMgtError::CertificateNotFound(common_name.to_string()))?
            .clone();

        // Update validity period
        let now = OffsetDateTime::now_utc();
        original_config.not_before = now.unix_timestamp();
        original_config.not_after = (now + time::Duration::days(new_validity_days as i64)).unix_timestamp();

        // Sign the renewed certificate
        self.sign_certificate_from_config(&original_config, cert_data_type)
    }

    /// Creates CertData in the requested format
    fn create_cert_data(&self, certificate: &Certificate, cert_data_type: CertDataType, p12_password: &str) -> Result<CertData, CertMgtError> {
        match cert_data_type {
            CertDataType::PemOnlyCert => {
                Ok(CertData::Pem {
                    cert: certificate.pem(),
                    key: None,
                })
            }
            CertDataType::PemOnlyKey => {
                let key_pem = certificate.key_pair()
                    .ok_or_else(|| CertMgtError::InvalidPrivateKey("Certificate has no private key".to_string()))?
                    .serialize_pem();
                Ok(CertData::Pem {
                    cert: "".to_string(),
                    key: Some(key_pem),
                })
            }
            CertDataType::PemCertAndKey => {
                let key_pem = certificate.key_pair()
                    .ok_or_else(|| CertMgtError::InvalidPrivateKey("Certificate has no private key".to_string()))?
                    .serialize_pem();
                Ok(CertData::Pem {
                    cert: certificate.pem(),
                    key: Some(key_pem),
                })
            }
            CertDataType::P12 { as_base64 } => {
                self.create_p12_data(certificate, p12_password, as_base64)
            }
        }


    }
    fn create_p12_data(&self, certificate: &Certificate, password: &str, as_base64: bool) -> Result<CertData, CaError> {
        // For P12 creation, we need to use external crate like `p12`
        // This is a simplified implementation - you'd need proper P12 creation
        let cert_der = certificate.der();
        let key_der = certificate.key_pair()
            .ok_or_else(|| CaError::Serialization("Certificate has no private key".to_string()))?
            .serialize_der();

        // Create a simple P12 structure (this is simplified - use proper p12 crate)
        let p12_data = format!("P12-DATA-{}-{}",
                               base64::engine::general_purpose::STANDARD.encode(&cert_der),
                               base64::engine::general_purpose::STANDARD.encode(&key_der)
        );

        let data = if as_base64 {
            base64::engine::general_purpose::STANDARD.encode(p12_data.as_bytes())
        } else {
            p12_data
        };

        Ok(CertData::P12 {
            data,
            password: password.to_string(),
            as_base64,
        })
    }

    /// Exports all issued certificates as JSON
    pub fn export_certificates_json(&self) -> Result<String, CertMgtError> {
        let certificates: Vec<&CertificateConfig> = self.issued_certificates.values().collect();
        serde_json::to_string_pretty(&certificates)
            .map_err(|e| CertMgtError::JsonError(e))
    }

    /// Imports certificates from JSON
    pub fn import_certificates_json(&mut self, json_data: &str) -> Result<usize, CertMgtError> {
        let certificates: Vec<CertificateConfig> = serde_json::from_str(json_data)
            .map_err(|e| CertMgtError::JsonError(e))?;

        let count = certificates.len();
        for cert_config in certificates {
            self.issued_certificates.insert(cert_config.common_name.clone(), cert_config);
        }

        Ok(count)
    }

    /// Gets the CA certificate as CertificateConfig
    pub fn get_ca_certificate_config(&self) -> Result<CertificateConfig, CertMgtError> {
        let now = OffsetDateTime::now_utc();
        let validity_end = now + time::Duration::days(self.ca_config.validity_days as i64);

        let cert_data = CertData::Pem {
            cert: self.ca_cert.pem(),
            key: Some(self.ca_cert.key_pair()
                .ok_or_else(|| CertMgtError::Serialization("CA has no private key".to_string()))?
                .serialize_pem()),
        };

        Ok(CertificateConfig {
            country: self.ca_config.country.clone(),
            state: self.ca_config.state.clone(),
            locality: "".to_string(),
            organization: self.ca_config.organization.clone(),
            organizational_unit: "".to_string(),
            common_name: self.ca_config.common_name.clone(),
            is_ca: true,
            not_before: now.unix_timestamp(),
            not_after: validity_end.unix_timestamp(),
            key_size: Some(self.ca_config.key_size.try_into().unwrap()),
            cert_data,
            serial_number: "".to_string(),
        })
    }

    /// Lists all issued certificates
    pub fn list_issued_certificates(&self) -> Vec<&CertificateConfig> {
        self.issued_certificates.values().collect()
    }

    /// Gets a specific certificate config
    pub fn get_certificate_config(&self, common_name: &str) -> Option<&CertificateConfig> {
        self.issued_certificates.get(common_name)
    }

    /// Validates if a certificate is still valid based on timestamps
    pub fn is_certificate_valid(&self, common_name: &str) -> bool {
        if let Some(cert_config) = self.issued_certificates.get(common_name) {
            let now = SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_secs() as i64;
            now >= cert_config.not_before && now <= cert_config.not_after
        } else {
            false
        }
    }

    /// Removes a certificate from the issued certificates list
    pub fn revoke_certificate(&mut self, common_name: &str) -> Result<CertificateConfig, CertMgtError> {
        self.issued_certificates.remove(common_name)
            .ok_or_else(|| CertMgtError::InvalidInput(format!("Certificate for '{}' not found", common_name)))

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
