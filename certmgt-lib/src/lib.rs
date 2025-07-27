pub mod certificate;
pub mod detection;
pub mod types;
pub mod utils;
pub mod json;

// Re-export main types for convenience
pub use types::CertificateConfig;
pub use types::{CertData, CertDataType};
pub use json::{load_certificates_from_json, save_certificates_to_json_compressed, save_certificates_to_json, load_certificates_from_json_compressed, attach_private_key_to_certificate, list_all_certificate_names, AttachKeyError};
pub use detection::detect_cert_type;