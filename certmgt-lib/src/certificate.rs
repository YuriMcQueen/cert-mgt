use crate::detection::detect_cert_type;
use crate::types::{CaConfig, CertData, CertDataType, CertificateConfig, ServerCertConfig};
use crate::utils::{asn1_time_to_timestamp, parse_cert_field};
use crate::CertMgtError;
use base64::prelude::BASE64_STANDARD;
use base64::Engine as _;
use openssl::asn1::Asn1Time;
use openssl::bn::{BigNum, MsbOption};
use openssl::error::ErrorStack;
use openssl::hash::MessageDigest;
use openssl::nid::Nid;
use openssl::pkcs12::Pkcs12;
use openssl::pkey::{PKey, Private};
use openssl::rsa::Rsa;
use openssl::x509::extension::{AuthorityKeyIdentifier, BasicConstraints, KeyUsage, SubjectAlternativeName, SubjectKeyIdentifier};
use openssl::x509::{X509NameBuilder, X509Ref, X509Req, X509ReqBuilder, X509VerifyResult, X509};
use std::error::Error;
use x509_parser::asn1_rs::{FromDer, Oid};
use x509_parser::certificate::X509Certificate;
use x509_parser::extensions::ParsedExtension;
use x509_parser::oid_registry;
use x509_parser::public_key::PublicKey;

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

    fn from_x509_and_key(cert: X509, key: Option<PKey<Private>>, cert_data: CertData) -> Self {
        // Extract certificate information
        let subject_name = cert.subject_name();
        let country = parse_cert_field(subject_name, Nid::COUNTRYNAME).unwrap_or_default();
        let state = parse_cert_field(subject_name, Nid::STATEORPROVINCENAME).unwrap_or_default();
        let locality = parse_cert_field(subject_name, Nid::LOCALITYNAME).unwrap_or_default();
        let organization =
            parse_cert_field(subject_name, Nid::ORGANIZATIONNAME).unwrap_or_default();
        let organizational_unit =
            parse_cert_field(subject_name, Nid::ORGANIZATIONALUNITNAME).unwrap_or_default();

        // Check if this is a CA certificate
        // let is_ca = is_ca(&cert).unwrap_or_else(|_| false);
        // let common_name = parse_cert_field(subject_name, Nid::COMMONNAME).unwrap_or_default();
        // let not_after = asn1_time_to_timestamp(cert.not_after());
        // let not_before = asn1_time_to_timestamp(cert.not_before());
        // let key_size = key.as_ref().map(|k| k.bits());
        let cert = get_cert_info(&cert, cert_data).unwrap();
        println!("{:?}", cert);
        cert
        // CertificateConfig {
        //     country,
        //     state,
        //     locality,
        //     organization,
        //     organizational_unit,
        //     common_name,
        //     is_ca,
        //     not_after,
        //     not_before,
        //     key_size,
        //     cert_data,
        //     serial_number,
        // }
    }
    pub fn generate_ca(config: CaConfig) -> Result<Self, CertMgtError> {
        let (cert, key_pair) = Self::mk_ca_cert(&config)?;

        // Convert to PEM format
        let cert_pem = String::from_utf8(cert.to_pem()?)?;
        let key_pem = String::from_utf8(key_pair.private_key_to_pem_pkcs8()?)?;

        let cert_data = CertData::Pem {
            cert: cert_pem,
            key: Some(key_pem),
        };

        Ok(Self::from_x509_and_key(cert, Some(key_pair), cert_data))
    }

    /// Generate a server certificate signed by the provided CA
    pub fn generate_server_cert(
        config: ServerCertConfig,
        ca_cert: &CertificateConfig,
    ) -> Result<Self, CertMgtError> {
        // Extract CA certificate and key
        let ca_x509 = match &ca_cert.cert_data {
            CertData::Pem { cert, .. } => X509::from_pem(cert.as_bytes())?,
            CertData::P12 { .. } => {
                return Err(CertMgtError::InvalidConfiguration(
                    "P12 CA certificates not supported for signing".to_string()
                ))
            }
        };

        let ca_key = match &ca_cert.cert_data {
            CertData::Pem { key: Some(key), .. } => PKey::private_key_from_pem(key.as_bytes())?,
            _ => {
                return Err(CertMgtError::InvalidConfiguration(
                    "CA certificate must have a private key".to_string()
                ))
            }
        };

        let (cert, key_pair) = Self::mk_ca_signed_cert(&config, &ca_x509, &ca_key)?;

        // Convert to PEM format
        let cert_pem = String::from_utf8(cert.to_pem()?)?;
        let key_pem = String::from_utf8(key_pair.private_key_to_pem_pkcs8()?)?;

        let cert_data = CertData::Pem {
            cert: cert_pem,
            key: Some(key_pem),
        };

        Ok(Self::from_x509_and_key(cert, Some(key_pair), cert_data))
    }

    /// Renew an existing certificate with the same configuration but new validity period
    pub fn renew_with_ca(
        &self,
        ca_cert: &CertificateConfig,
        new_validity_days: u32,
    ) -> Result<Self, CertMgtError> {
        let config = ServerCertConfig {
            country: self.country.clone(),
            state: self.state.clone(),
            organization: self.organization.clone(),
            common_name: self.common_name.clone(),
            alt_names: vec![], // You might want to extract this from the original cert
            key_size: self.key_size.unwrap_or(2048),
            validity_days: new_validity_days,
        };

        Self::generate_server_cert(config, ca_cert)
    }

    /// Verify that this certificate was issued by the given CA
    pub fn verify_with_ca(&self, ca_cert: &CertificateConfig) -> Result<bool, Box<dyn Error>> {
        let cert_x509 = match &self.cert_data {
            CertData::Pem { cert, .. } => X509::from_pem(cert.as_bytes())?,
            CertData::P12 { .. } => return Err("P12 certificate verification not implemented".into()),
        };

        let ca_x509 = match &ca_cert.cert_data {
            CertData::Pem { cert, .. } => X509::from_pem(cert.as_bytes())?,
            CertData::P12 { .. } => return Err("P12 CA certificates not supported for verification".into()),
        };

        match ca_x509.issued(&cert_x509) {
            X509VerifyResult::OK => Ok(true),
            _ => Ok(false),
        }
    }

    /// Save certificate and key to files
    pub fn save_to_files(&self, cert_path: &str, key_path: Option<&str>) -> Result<(), Box<dyn Error>> {
        match &self.cert_data {
            CertData::Pem { cert, key } => {
                std::fs::write(cert_path, cert)?;

                if let (Some(key_content), Some(key_file_path)) = (key, key_path) {
                    std::fs::write(key_file_path, key_content)?;
                }
            }
            CertData::P12 { data, .. } => {
                // For P12, save the base64 data
                std::fs::write(cert_path, data)?;
            }
        }
        Ok(())
    }

    // Internal helper methods (adapted from your CLI code)
    fn mk_ca_cert(config: &CaConfig) -> Result<(X509, PKey<Private>), ErrorStack> {
        let rsa = Rsa::generate(config.key_size)?;
        let key_pair = PKey::from_rsa(rsa)?;

        let mut x509_name = X509NameBuilder::new()?;
        x509_name.append_entry_by_text("C", &config.country)?;
        x509_name.append_entry_by_text("ST", &config.state)?;
        x509_name.append_entry_by_text("O", &config.organization)?;
        x509_name.append_entry_by_text("CN", &config.common_name)?;
        let x509_name = x509_name.build();

        let mut cert_builder = X509::builder()?;
        cert_builder.set_version(2)?;
        let serial_number = {
            let mut serial = BigNum::new()?;
            serial.rand(159, MsbOption::MAYBE_ZERO, false)?;
            serial.to_asn1_integer()?
        };
        cert_builder.set_serial_number(&serial_number)?;
        cert_builder.set_subject_name(&x509_name)?;
        cert_builder.set_issuer_name(&x509_name)?;
        cert_builder.set_pubkey(&key_pair)?;
        let not_before = Asn1Time::days_from_now(0)?;
        cert_builder.set_not_before(&not_before)?;
        let not_after = Asn1Time::days_from_now(config.validity_days)?;
        cert_builder.set_not_after(&not_after)?;

        cert_builder.append_extension(BasicConstraints::new().critical().ca().build()?)?;
        cert_builder.append_extension(
            KeyUsage::new()
                .critical()
                .key_cert_sign()
                .crl_sign()
                .build()?,
        )?;

        let subject_key_identifier =
            SubjectKeyIdentifier::new().build(&cert_builder.x509v3_context(None, None))?;
        cert_builder.append_extension(subject_key_identifier)?;

        cert_builder.sign(&key_pair, MessageDigest::sha256())?;
        let cert = cert_builder.build();

        Ok((cert, key_pair))
    }

    fn mk_ca_signed_cert(
        config: &ServerCertConfig,
        ca_cert: &X509Ref,
        ca_key_pair: &PKey<Private>,
    ) -> Result<(X509, PKey<Private>), ErrorStack> {
        let rsa = Rsa::generate(config.key_size as u32)?;
        let key_pair = PKey::from_rsa(rsa)?;
        let req = Self::mk_request(config, &key_pair)?;

        let mut cert_builder = X509::builder()?;
        cert_builder.set_version(2)?;
        let serial_number = {
            let mut serial = BigNum::new()?;
            serial.rand(159, MsbOption::MAYBE_ZERO, false)?;
            serial.to_asn1_integer()?
        };
        cert_builder.set_serial_number(&serial_number)?;
        cert_builder.set_subject_name(req.subject_name())?;
        cert_builder.set_issuer_name(ca_cert.subject_name())?;
        cert_builder.set_pubkey(&key_pair)?;
        let not_before = Asn1Time::days_from_now(0)?;
        cert_builder.set_not_before(&not_before)?;
        let not_after = Asn1Time::days_from_now(config.validity_days)?;
        cert_builder.set_not_after(&not_after)?;

        cert_builder.append_extension(BasicConstraints::new().build()?)?;

        cert_builder.append_extension(
            KeyUsage::new()
                .critical()
                .non_repudiation()
                .digital_signature()
                .key_encipherment()
                .build()?,
        )?;

        let subject_key_identifier =
            SubjectKeyIdentifier::new().build(&cert_builder.x509v3_context(Some(ca_cert), None))?;
        cert_builder.append_extension(subject_key_identifier)?;

        let auth_key_identifier = AuthorityKeyIdentifier::new()
            .keyid(false)
            .issuer(false)
            .build(&cert_builder.x509v3_context(Some(ca_cert), None))?;
        cert_builder.append_extension(auth_key_identifier)?;

        let mut subject_alt_name = SubjectAlternativeName::new();
        for dns in &config.alt_names {
            subject_alt_name.dns(dns);
        }
        let alt_names = subject_alt_name.build(&cert_builder.x509v3_context(Some(ca_cert), None))?;
        cert_builder.append_extension(alt_names)?;

        cert_builder.sign(ca_key_pair, MessageDigest::sha256())?;
        let cert = cert_builder.build();

        Ok((cert, key_pair))
    }

    fn mk_request(config: &ServerCertConfig, key_pair: &PKey<Private>) -> Result<X509Req, ErrorStack> {
        let mut req_builder = X509ReqBuilder::new()?;
        req_builder.set_pubkey(key_pair)?;

        let mut x509_name = X509NameBuilder::new()?;
        x509_name.append_entry_by_text("C", &config.country)?;
        x509_name.append_entry_by_text("ST", &config.state)?;
        x509_name.append_entry_by_text("O", &config.organization)?;
        x509_name.append_entry_by_text("CN", &config.common_name)?;
        let x509_name = x509_name.build();
        req_builder.set_subject_name(&x509_name)?;

        req_builder.sign(key_pair, MessageDigest::sha256())?;
        let req = req_builder.build();
        Ok(req)
    }
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
fn get_cert_info(cert: &X509, cert_data: CertData) -> Result<CertificateConfig, Box<dyn std::error::Error>> {
    let der = cert.to_der()?;
    let (_, parsed) = X509Certificate::from_der(&der)?;
    let serial_number = parsed.serial.to_string();
    let is_ca = parsed.is_ca();
    let not_after = asn1_time_to_timestamp(&parsed.validity.not_after);
    let not_before = asn1_time_to_timestamp(&parsed.validity.not_before);
    let country = get_subject_attr(&parsed, oid_registry::OID_X509_COUNTRY_NAME);
    let state = get_subject_attr(&parsed, oid_registry::OID_X509_STATE_OR_PROVINCE_NAME);
    let locality = get_subject_attr(&parsed, oid_registry::OID_X509_LOCALITY_NAME);
    let organization = get_subject_attr(&parsed, oid_registry::OID_X509_ORGANIZATION_NAME);
    let organizational_unit = get_subject_attr(&parsed, oid_registry::OID_X509_ORGANIZATIONAL_UNIT);
    let common_name = get_subject_attr(&parsed, oid_registry::OID_X509_COMMON_NAME);
    let key_size = get_key_size(&parsed);
    // let is_ca = parsed
    //     .extensions()
    //     .iter()
    //     .map(|ext| ext.parsed_extension())
    //     .find_map(|pe| match pe {
    //         ParsedExtension::BasicConstraints(bc) => Some(bc.ca),
    //         _ => None,
    //     })
    //     .unwrap_or(false);
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
