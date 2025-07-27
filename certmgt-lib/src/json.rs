use crate::errors::CertMgtError;
use crate::types::{CertData, CertificateConfig};
use serde::{Deserialize, Serialize};
use std::path::Path;

#[derive(Debug, Serialize, Deserialize)]
pub struct CertificateDatabase {
    pub version: String,
    pub created_at: i64,
    pub certificates: Vec<CertificateConfig>,
}

impl CertificateDatabase {
    pub fn new() -> Self {
        Self {
            version: "1.0".to_string(),
            created_at: chrono::Utc::now().timestamp(),
            certificates: Vec::new(),
        }
    }

    pub fn with_certificates(certificates: Vec<CertificateConfig>) -> Self {
        Self {
            version: "1.0".to_string(),
            created_at: chrono::Utc::now().timestamp(),
            certificates,
        }
    }
}

// JSON storage functions (replacing your parquet functions)
pub fn save_certificates_to_json(
    configs: Vec<CertificateConfig>,
    path: &Path,
) -> Result<(), CertMgtError> {
    let db = CertificateDatabase::with_certificates(configs);
    let json = serde_json::to_string_pretty(&db)?;
    std::fs::write(path, json)?;
    Ok(())
}

pub fn load_certificates_from_json(path: &Path) -> Result<Vec<CertificateConfig>, CertMgtError> {
    let content = std::fs::read_to_string(path)?;
    let db: CertificateDatabase = serde_json::from_str(&content)?;
    Ok(db.certificates)
}

// Compressed JSON variant (if you need smaller files)
pub fn save_certificates_to_json_compressed(
    configs: Vec<CertificateConfig>,
    path: &Path,
) -> Result<(), CertMgtError> {
    use flate2::{Compression, write::GzEncoder};
    use std::io::Write;

    let db = CertificateDatabase::with_certificates(configs);
    let json = serde_json::to_string(&db)?; // No pretty printing for compression

    let file = std::fs::File::create(path)?;
    let mut encoder = GzEncoder::new(file, Compression::default());
    encoder.write_all(json.as_bytes())?;
    encoder.finish()?;
    Ok(())
}

pub fn load_certificates_from_json_compressed(
    path: &Path,
) -> Result<Vec<CertificateConfig>, CertMgtError> {
    use flate2::read::GzDecoder;
    use std::io::Read;

    let file = std::fs::File::open(path)?;
    let mut decoder = GzDecoder::new(file);
    let mut content = String::new();
    decoder.read_to_string(&mut content)?;

    let db: CertificateDatabase = serde_json::from_str(&content)?;
    Ok(db.certificates)
}

// JSONL (JSON Lines) variant for streaming/appending
pub fn save_certificates_to_jsonl(
    configs: Vec<CertificateConfig>,
    path: &Path,
) -> Result<(), Box<dyn std::error::Error>> {
    use std::io::Write;

    let mut file = std::fs::File::create(path)?;
    for config in configs {
        let line = serde_json::to_string(&config)?;
        writeln!(file, "{}", line)?;
    }
    Ok(())
}

pub fn load_certificates_from_jsonl(
    path: &Path,
) -> Result<Vec<CertificateConfig>, Box<dyn std::error::Error>> {
    let content = std::fs::read_to_string(path)?;
    let mut configs = Vec::new();

    for line in content.lines() {
        if line.trim().is_empty() {
            continue;
        }
        let config: CertificateConfig = serde_json::from_str(line)?;
        configs.push(config);
    }

    Ok(configs)
}

// Append a single certificate to JSONL file
pub fn append_certificate_to_jsonl(
    config: CertificateConfig,
    path: &Path,
) -> Result<(), Box<dyn std::error::Error>> {
    use std::fs::OpenOptions;
    use std::io::Write;

    let mut file = OpenOptions::new().create(true).append(true).open(path)?;

    let line = serde_json::to_string(&config)?;
    writeln!(file, "{}", line)?;
    Ok(())
}

/// Export certificate in its original format with optional filtering
pub fn export_certificate(
    config: &CertificateConfig,
    output_path: &Path,
) -> Result<(), Box<dyn std::error::Error>> {
    use base64::Engine as _;
    use base64::prelude::BASE64_STANDARD;

    match &config.cert_data {
        CertData::Pem { cert, key } => {
            // Export as PEM file - combine cert and key if both exist
            let mut pem_content = cert.clone();
            if let Some(key_data) = key {
                if !key_data.is_empty() {
                    pem_content.push('\n');
                    pem_content.push_str(key_data);
                }
            }
            std::fs::write(output_path, pem_content)?;
        }

        CertData::P12 {
            data,
            password: _,
            as_base64,
        } => {
            // Export as P12 file in original format
            if *as_base64 {
                // Data was originally base64, decode it to binary for P12 file
                let filtered: String = data.chars().filter(|c| !c.is_whitespace()).collect();
                let p12_bytes = BASE64_STANDARD.decode(&filtered)?;
                std::fs::write(output_path, p12_bytes)?;
            } else {
                // Data is stored as base64 but was originally binary
                let p12_bytes = BASE64_STANDARD.decode(data)?;
                std::fs::write(output_path, p12_bytes)?;
            }
        }
    }

    Ok(())
}

/// Export certificates with optional filtering
pub fn export_certificates_with_filter<F>(
    configs: &[CertificateConfig],
    output_dir: &Path,
    filter: Option<F>,
) -> Result<Vec<String>, Box<dyn std::error::Error>>
where
    F: Fn(&CertificateConfig) -> bool,
{
    use std::fs;

    // Create output directory if it doesn't exist
    fs::create_dir_all(output_dir)?;

    let mut exported_files = Vec::new();

    for (index, config) in configs.iter().enumerate() {
        // Apply filter if provided
        if let Some(ref filter_fn) = filter {
            if !filter_fn(config) {
                continue;
            }
        }

        // Generate filename based on common name and certificate type
        let extension = match &config.cert_data {
            CertData::Pem { .. } => "pem",
            CertData::P12 { .. } => "p12",
        };

        let filename = if config.common_name.is_empty() {
            format!("cert_{}.{}", index, extension)
        } else {
            // Sanitize common name for filename
            let sanitized_name = config
                .common_name
                .chars()
                .map(|c| {
                    if c.is_alphanumeric() || c == '-' || c == '_' {
                        c
                    } else {
                        '_'
                    }
                })
                .collect::<String>();
            format!("{}_{}.{}", sanitized_name, index, extension)
        };

        let output_path = output_dir.join(&filename);
        export_certificate(config, &output_path)?;
        exported_files.push(filename);
    }

    Ok(exported_files)
}

/// Export all certificates without filtering
pub fn export_all_certificates(
    configs: &[CertificateConfig],
    output_dir: &Path,
) -> Result<Vec<String>, Box<dyn std::error::Error>> {
    export_certificates_with_filter(configs, output_dir, None::<fn(&CertificateConfig) -> bool>)
}

pub struct AttachKeyResult {
    pub certificate_common_name: String,
    pub had_existing_key: bool,
    pub key_was_encrypted: bool,
}

/// Attach a private key to an existing PEM certificate in a JSON database
pub fn attach_private_key_to_certificate(
    json_path: &Path,
    common_name: &str,
    key_path: &Path,
    key_password: Option<&str>,
    force_replace: bool,
) -> Result<AttachKeyResult, CertMgtError> {
    use openssl::pkey::PKey;

    // Load existing certificates
    let mut configs = match json_path.extension().and_then(|ext| ext.to_str()) {
        Some("gz") => load_certificates_from_json_compressed(json_path)?,
        _ => load_certificates_from_json(json_path)?,
    };
    // Find the certificate to update
    let cert_index = configs
        .iter()
        .position(|config| config.common_name == common_name)
        .ok_or_else(|| CertMgtError::CertificateNotFound(common_name.to_string()))?;

    // Check if it's a PEM certificate and if it already has a key
    let config = &mut configs[cert_index];
    let had_existing_key = match &config.cert_data {
        CertData::P12 { .. } => {
            return Err(CertMgtError::NotPemCertificate);
        }
        CertData::Pem { key: Some(_), .. } => {
            if !force_replace {
                return Err(CertMgtError::InvalidPrivateKey(
                    "Certificate already has a private key. Use force_replace=true to override."
                        .to_string(),
                ));
            }
            true
        }
        CertData::Pem { key: None, .. } => false,
    };

    // Read the private key file
    let key_content = std::fs::read_to_string(key_path)?;

    // Validate that it's a valid private key
    let key_was_encrypted = key_password.is_some();
    let _key_validation = if let Some(password) = key_password {
        PKey::private_key_from_pem_passphrase(key_content.as_bytes(), password.as_bytes())?
    } else {
        PKey::private_key_from_pem(key_content.as_bytes())
            .map_err(|e| CertMgtError::InvalidPrivateKey(e.to_string()))?
    };

    // Update the certificate with the new key
    if let CertData::Pem { key, .. } = &mut configs[cert_index].cert_data {
        *key = Some(key_content);
    }

    // Save back to JSON
    match json_path.extension().and_then(|ext| ext.to_str()) {
        Some("gz") => save_certificates_to_json_compressed(configs, json_path)?,
        _ => save_certificates_to_json(configs, json_path)?,
    };

    Ok(AttachKeyResult {
        certificate_common_name: common_name.to_string(),
        had_existing_key,
        key_was_encrypted,
    })
}

/// List all certificates in a JSON database that don't have private keys
pub fn list_certificates_without_keys(json_path: &Path) -> Result<Vec<String>, CertMgtError> {
    let configs = load_certificates_from_json(json_path)?;

    let certs_without_keys: Vec<String> = configs
        .iter()
        .filter_map(|config| match &config.cert_data {
            CertData::Pem { key: None, .. } => Some(config.common_name.clone()),
            _ => None,
        })
        .collect();

    Ok(certs_without_keys)
}

/// Get all certificate common names from a JSON database

pub fn list_all_certificate_names(json_path: &Path) -> Result<Vec<String>, CertMgtError> {
    // Match on the Option<Option<&str>> returned by extension()
    let configs = match json_path.extension().and_then(|ext| ext.to_str()) {
        Some("gz") => load_certificates_from_json_compressed(json_path)?,
        _ => load_certificates_from_json(json_path)?,
    };

    // Return the common_name values
    Ok(configs
        .into_iter()
        .map(|config| config.common_name)
        .collect())
}

// Helper functions for querying certificates (basic filtering without SQL-like operations)
pub fn find_certificates_by_common_name(
    json_path: &Path,
    common_name: &str,
) -> Result<Vec<CertificateConfig>, CertMgtError> {
    let configs = load_certificates_from_json(json_path)?;
    Ok(configs
        .into_iter()
        .filter(|config| config.common_name.contains(common_name))
        .collect())
}

pub fn find_certificates_by_organization(
    json_path: &Path,
    organization: &str,
) -> Result<Vec<CertificateConfig>, CertMgtError> {
    let configs = load_certificates_from_json(json_path)?;
    Ok(configs
        .into_iter()
        .filter(|config| config.organization.contains(organization))
        .collect())
}

pub fn find_expiring_certificates(
    json_path: &Path,
    days_ahead: i64,
) -> Result<Vec<CertificateConfig>, CertMgtError> {
    let configs = load_certificates_from_json(json_path)?;
    let threshold = chrono::Utc::now().timestamp() + (days_ahead * 24 * 60 * 60);

    Ok(configs
        .into_iter()
        .filter(|config| config.not_after <= threshold && config.not_after > 0)
        .collect())
}

pub fn find_ca_certificates(json_path: &Path) -> Result<Vec<CertificateConfig>, CertMgtError> {
    let configs = load_certificates_from_json(json_path)?;
    Ok(configs.into_iter().filter(|config| config.is_ca).collect())
}
