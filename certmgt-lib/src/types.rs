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
    pub key_size: Option<u32>,
    pub cert_data: CertData,
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
    pub key_size: u32,
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
