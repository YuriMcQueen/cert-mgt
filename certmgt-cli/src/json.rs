use crate::{
    cert_fingerprint, discover_cert_files, is_compressed_file, load_certificates_from_database,
};
use base64::Engine as _;
use base64::prelude::BASE64_STANDARD;
use certmgt_lib::{CertData, CertMgtError, CertificateConfig};
use flate2::{Compression, write::GzEncoder};
use serde::{Deserialize, Serialize};
use std::collections::HashSet;
use std::io;
use std::io::Write;
use std::path::{Path, PathBuf};
use crate::config::TuiConfig;
use anyhow::{Result, Context};

trait IntoCertConfigs {
    fn into_configs(self, tui_config: TuiConfig) -> Result<Vec<CertificateConfig>>;
}

impl IntoCertConfigs for Vec<PathBuf> {
    fn into_configs(self, tui_config: TuiConfig)-> Result<Vec<CertificateConfig>> {
        discover_and_parse(self, &tui_config, None) // or pass password_file externally
    }
}

impl IntoCertConfigs for Vec<CertificateConfig> {
    fn into_configs(self, _tui_config: TuiConfig) -> Result<Vec<CertificateConfig>> {
        Ok(self)
    }
}

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
pub fn import<T: IntoCertConfigs>(
    tui_config: &TuiConfig,
    inputs: T,
    database: PathBuf,
    compressed: bool,
    force: bool,
    password_file: Option<PathBuf>,
) -> Result<()> {
    let mut final_configs = load_existing_database(&database)?;
    let mut seen: HashSet<String> =
        final_configs.iter().map(|c| cert_fingerprint(&c.cert_data)).collect();

    let new_configs = inputs.into_configs(tui_config.clone())
        .map_err(anyhow::Error::from)?;

    let (imported, skipped, overridden) =
        merge_configs(new_configs, &mut final_configs, &mut seen, force);

    save_database(&database, compressed, final_configs)?;
    println!(
        "✅ Import complete: {} new, {} skipped, {} overridden",
        imported, skipped, overridden
    );
    Ok(())
}


fn load_existing_database(database: &PathBuf) -> Result<Vec<CertificateConfig>> {
    if database.exists() {
        match load_certificates_from_database(database) {
            Ok(existing) => {
                println!("Found {} existing certificates in database", existing.len());
                Ok(existing)
            }
            Err(e) => {
                eprintln!("Error reading existing database: {}", e);
                Err(e.into())
            }
        }
    } else {
        Ok(Vec::new())
    }
}

fn discover_and_parse(
    inputs: Vec<PathBuf>,
    tui_config: &TuiConfig,
    password_file: Option<PathBuf>,
) -> Result<Vec<CertificateConfig>> {
    let mut configs = Vec::new();
    for p in inputs {
        let discovered_files = discover_cert_files(&p);
        if discovered_files.is_empty() {
            eprintln!("No certificates found in {}", p.display());
            continue;
        }
        println!("Found {} certificates in {}", discovered_files.len(), p.display());

        for file_path in discovered_files {
            if let Some(config) = parse_certificate_file(&file_path, tui_config, password_file.as_ref().map(|p| p.as_path())) {
                configs.push(config);
            }
        }
    }
    Ok(configs)
}

fn parse_certificate_file(
    file_path: &Path,
    tui_config: &TuiConfig,
    password_file: Option<&Path>,
) -> Option<CertificateConfig> {
    loop {
        match CertificateConfig::read_from_path(file_path.to_str().unwrap_or_default(), None) {
            Ok(config) => return Some(config),

            // Handle password-protected P12
            Err(e) if e.to_string().contains("requires a password") => {
                if let Some(config) = try_with_passwords(tui_config, file_path, password_file) {
                    return Some(config);
                }

                // Interactive fallback
                eprintln!("P12 file {} requires a password.", file_path.display());
                eprint!("Enter password: ");
                io::stdout().flush().ok()?;
                let password = rpassword::read_password().ok()?;
                if let Ok(config) =
                    CertificateConfig::read_from_path(file_path.to_str().unwrap(), Some(&password))
                {
                    return Some(config);
                } else {
                    eprintln!("Password did not work for {}", file_path.display());
                    return None;
                }
            }

            // Handle PEM key-only file
            Err(e) if e.to_string().contains("PEM file contains only private key") => {
                return match find_and_attach_matching_cert(file_path) {
                    Ok(config) => Some(config),
                    Err(e) => {
                        eprintln!("Error resolving PEM key {}: {}", file_path.display(), e);
                        None
                    }
                };
            }

            Err(e) => {
                eprintln!("Error reading {}: {}", file_path.display(), e);
                return None;
            }
        }
    }
}


fn try_with_passwords(
    tui_config: &TuiConfig,
    file_path: &Path,
    password_file: Option<&Path>,
) -> Option<CertificateConfig> {
    // 1. Config-driven passwords from TuiConfig
    if let Some(configured) = tui_config.try_passwords_for_file(file_path) {
        return Some(configured);
    }

    // 2. Password file fallback
    if let Some(pf) = password_file {
        if let Ok(password) = std::fs::read_to_string(pf) {
            if let Ok(config) = CertificateConfig::read_from_path(
                file_path.to_str().unwrap(),
                Some(password.trim()),
            ) {
                return Some(config);
            }
        }
    }

    None
}


fn find_and_attach_matching_cert(
    file_path: &Path,
) -> Result<CertificateConfig, Box<dyn std::error::Error>> {
    let dir = file_path.parent().unwrap_or_else(|| Path::new("."));
    let candidates = discover_cert_files(dir);

    let matching_cert_path = candidates
        .into_iter()
        .filter(|p| *p != file_path)
        .find(|p| {
            CertificateConfig::read_from_path(p.to_str().unwrap(), None)
                .map(|c| c.matches_key_file(file_path))
                .unwrap_or(false)
        });

    if let Some(cert_path) = matching_cert_path {
        let mut cert_config = CertificateConfig::read_from_path(cert_path.to_str().unwrap(), None)?;
        cert_config.attach_key_from_file(file_path, None)?;
        Ok(cert_config)
    } else {
        Err(format!("No matching certificate found for key {}", file_path.display()).into())
    }
}

fn merge_configs(
    new_configs: Vec<CertificateConfig>,
    final_configs: &mut Vec<CertificateConfig>,
    seen: &mut HashSet<String>,
    force: bool,
) -> (usize, usize, usize) {
    let mut imported = 0;
    let mut skipped = 0;
    let mut overridden = 0;

    for config in new_configs {
        let fp = cert_fingerprint(&config.cert_data);
        if seen.contains(&fp) {
            if force {
                println!("Overriding duplicate: {}", config.common_name);
                overridden += 1;
                final_configs.retain(|c| cert_fingerprint(&c.cert_data) != fp);
            } else {
                println!("Skipping duplicate: {}", config.common_name);
                skipped += 1;
                continue;
            }
        } else {
            imported += 1;
        }
        seen.insert(fp);
        final_configs.push(config);
    }

    (imported, skipped, overridden)
}

fn save_database(
    database: &PathBuf,
    compressed: bool,
    configs: Vec<CertificateConfig>,
) -> Result<()> {
    let use_compression = compressed || is_compressed_file(database);
    if use_compression {
        save_certificates_to_json_compressed(configs, database)?;
    } else {
        save_certificates_to_json(configs, database)?;
    }
    Ok(())
}

// Compressed JSON variant (if you need smaller files)
pub fn save_certificates_to_json_compressed(
    configs: Vec<CertificateConfig>,
    path: &Path,
) -> Result<(), CertMgtError> {
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

/// Export certificate in its original format with optional filtering
pub fn export_certificate(
    config: &CertificateConfig,
    output_path: &Path,
) -> Result<(), Box<dyn std::error::Error>> {
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
    validate_private_key(&key_content, key_password)?;

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

fn validate_private_key(key_content: &str, password: Option<&str>) -> Result<(), CertMgtError> {
    let pem_blocks = pem::parse_many(key_content)
        .map_err(|e| CertMgtError::InvalidPrivateKey(format!("Invalid PEM format: {}", e)))?;

    let private_key_tags = [
        "PRIVATE KEY",
        "ENCRYPTED PRIVATE KEY",
        "RSA PRIVATE KEY",
        "EC PRIVATE KEY",
        "DSA PRIVATE KEY",
    ];

    let has_private_key = pem_blocks
        .iter()
        .any(|block| private_key_tags.contains(&block.tag()));

    if !has_private_key {
        return Err(CertMgtError::InvalidPrivateKey(
            "No private key found in PEM data".to_string(),
        ));
    }

    // Check for encrypted keys when no password provided
    let has_encrypted_key = pem_blocks
        .iter()
        .any(|block| block.tag() == "ENCRYPTED PRIVATE KEY");

    if has_encrypted_key && password.is_none() {
        return Err(CertMgtError::InvalidPrivateKey(
            "Encrypted private key requires password".to_string(),
        ));
    }

    Ok(())
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
