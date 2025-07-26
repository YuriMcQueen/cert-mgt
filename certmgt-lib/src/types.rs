use serde::Serialize;

#[derive(Debug, Clone, Serialize)]
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
    pub cert_type: CertType,
    pub cert_pem: Option<String>,
    pub key_pem: Option<String>,
}

#[derive(Debug, Clone, Serialize)]
pub enum CertType {
    Pem,
    P12 { password: String, as_base64: bool },
}

#[derive(Debug)]
pub enum CertDataType {
    PemOnlyCert,
    PemOnlyKey,
    PemCertAndKey,
    P12 { as_base64: bool },
}
