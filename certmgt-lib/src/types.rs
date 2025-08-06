use std::collections::HashMap;
use std::fmt;
use rcgen::Certificate;
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CertificateConfig {
    pub country: String,
    pub state: String,
    pub locality: String,
    pub organization: String,
    pub organizational_unit: String,
    pub common_name: String,
    pub is_ca: bool,
    pub not_after: i64,
    pub not_before: i64,
    pub key_size: Option<usize>,
    pub cert_data: CertData,
    pub serial_number: String,
}

pub struct CertificateAuthority {
    pub(crate) ca_cert: Certificate,
    pub(crate) ca_config: CaConfig,
    pub(crate) serial_counter: u64,
    pub(crate) issued_certificates: HashMap<String, CertificateConfig>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum CertData {
    Pem {
        cert: String,
        key: Option<String>,
    },
    P12 {
        data: String,
        password: String,
        as_base64: bool,
    },
}

impl fmt::Display for CertData {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            CertData::Pem { cert, key } => {
                writeln!(f, "PEM Certificate:")?;
                writeln!(f, "{}", cert.replace("\\n", "\n"))?;
                if let Some(k) = key {
                    writeln!(f, "\nPEM Private Key:")?;
                    writeln!(f, "{}", k.replace("\\n", "\n"))?;
                }
                Ok(())
            }
            CertData::P12 { data, password, as_base64 } => {
                writeln!(f, "PKCS#12 certificate (as_base64={}):", as_base64)?;
                writeln!(f, "{}", data.replace("\\n", "\n"))?;
                writeln!(f, "Password: {}", password)?;
                Ok(())
            }
        }
    }
}

#[derive(Debug)]
pub enum CertDataType {
    PemOnlyCert,
    PemOnlyKey,
    PemCertAndKey,
    P12 { as_base64: bool },
}

#[derive(Debug, Clone)]
pub struct CaConfig {
    pub country: String,
    pub state: String,
    pub organization: String,
    pub common_name: String,
    pub key_size: u32,
    pub validity_days: u32,
}

impl Default for CaConfig {
    fn default() -> Self {
        Self {
            country: "US".to_string(),
            state: "CA".to_string(),
            organization: "My Organization".to_string(),
            common_name: "My CA".to_string(),
            key_size: 2048,
            validity_days: 3650, // 10 years
        }
    }
}

/// Configuration for generating a server certificate
#[derive(Debug, Clone)]
pub struct ServerCertConfig {
    pub country: String,
    pub state: String,
    pub organization: String,
    pub common_name: String,
    pub alt_names: Vec<String>,
    pub key_size: usize,
    pub validity_days: u32,
}

impl Default for ServerCertConfig {
    fn default() -> Self {
        Self {
            country: "US".to_string(),
            state: "CA".to_string(),
            organization: "My Organization".to_string(),
            common_name: "localhost".to_string(),
            alt_names: vec!["localhost".to_string()],
            key_size: 2048,
            validity_days: 365,
        }
    }
}
