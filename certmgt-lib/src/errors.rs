use thiserror::Error;

#[derive(Debug, Error)]
pub enum CertMgtError {
    #[error("Certificate with common name '{0}' not found")]
    CertificateNotFound(String),

    #[error("Cannot attach key to P12 certificate")]
    NotPemCertificate,

    #[error("Invalid private key: {0}")]
    InvalidPrivateKey(String),

    #[error("Invalid filters: {0}")]
    FilterError(String),

    #[error("IO error")]
    IoError(#[from] std::io::Error),

    #[error("JSON error")]
    JsonError(#[from] serde_json::Error),

    #[error("OpenSSL error")]
    OpensslError(#[from] openssl::error::ErrorStack),
}
