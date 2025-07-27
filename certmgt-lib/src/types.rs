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
    Pem { cert: String, key: Option<String> },
    P12 { data: String, password: String, as_base64: bool },
}

#[derive(Debug)]
pub enum CertDataType {
    PemOnlyCert,
    PemOnlyKey,
    PemCertAndKey,
    P12 { as_base64: bool },
}
