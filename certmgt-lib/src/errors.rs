use thiserror::Error;

// Your existing error type
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

    #[error("Certificate generation failed: {0}")]
    CertificateGenerationError(String),

    #[error("Invalid certificate format: {0}")]
    UnsupportedCertFormat(String),

    #[error("CA generation failed: {0}")]
    CaGenerationError(String),

    #[error("Key generation failed: {0}")]
    KeyGenerationError(String),

    #[error("Error extracting key: {0}")]
    KeyExtractionError(String),

    #[error("Error creating issuer: {0}")]
    IssuerCreationError(String),

    #[error("Error loading key: {0}")]
    KeyLoadError(String),

    #[error("Certificate signing failed: {0}")]
    CertificateSigningError(String),

    #[error("Invalid certificate configuration: {0}")]
    InvalidConfiguration(String),

    #[error("UTF-8 conversion error")]
    Utf8Error(#[from] std::string::FromUtf8Error),

    #[error("String UTF-8 error")]
    StrUtf8Error(#[from] std::str::Utf8Error),

    #[error("Base64 decode error")]
    Base64Error(#[from] base64::DecodeError),

    #[error("Parse int error")]
    ParseIntError(#[from] std::num::ParseIntError),

    #[error("Time format error")]
    TimeError(#[from] chrono::ParseError),

    #[error("IO error")]
    IoError(#[from] std::io::Error),

    #[error("JSON error")]
    JsonError(#[from] serde_json::Error),

    #[error("Rcgen error")]
    RcGenError(#[from] rcgen::Error),

    #[error("AddrParse error")]
    AddrParseError(#[from] std::net::AddrParseError),

    // Add this if you need to wrap other error types
    #[error("Other error: {0}")]
    Other(#[from] Box<dyn std::error::Error + Send + Sync>),
}
