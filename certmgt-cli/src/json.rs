use crate::config::{PasswordSourceConfig, TuiConfig, load_passwords};
use crate::db::{
    cert_fingerprint, discover_cert_files, is_compressed_file, load_certificates_from_database,
};
use anyhow::Result;
use base64::Engine as _;
use base64::prelude::BASE64_STANDARD;
use certmgt_lib::{CertData, CertMgtError, CertificateConfig, relink_ca_references};
use flate2::{Compression, write::GzEncoder};
use serde::{Deserialize, Serialize};
use std::collections::HashSet;
use std::io;
use std::io::Write;
use std::path::{Path, PathBuf};

pub trait IntoCertConfigs {
    fn into_configs(self, tui_config: TuiConfig, prints: bool) -> Result<Vec<CertificateConfig>>;
}

impl IntoCertConfigs for Vec<PathBuf> {
    fn into_configs(self, tui_config: TuiConfig, prints: bool) -> Result<Vec<CertificateConfig>> {
        discover_and_parse(self, &tui_config, None, prints) // or pass password_file externally
    }
}

impl IntoCertConfigs for Vec<CertificateConfig> {
    fn into_configs(self, _tui_config: TuiConfig, _prints: bool) -> Result<Vec<CertificateConfig>> {
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
    _password_file: Option<PathBuf>,
    prints: bool,
) -> Result<()> {
    let mut final_configs = load_existing_database(&database, prints)?;
    let mut seen: HashSet<String> = final_configs
        .iter()
        .map(|c| cert_fingerprint(&c.cert_data))
        .collect();

    let new_configs = inputs.into_configs(tui_config.clone(), prints)?;

    let (imported, skipped, overridden) =
        merge_configs(new_configs, &mut final_configs, &mut seen, force, prints);

    // Link certs to their issuing CAs (batch + existing DB)
    relink_ca_references(&mut final_configs);

    save_database(&database, compressed, final_configs)?;
    if prints {
        println!(
            "✅ Import complete: {} new, {} skipped, {} overridden",
            imported, skipped, overridden
        );
    }

    Ok(())
}

fn load_existing_database(database: &Path, prints: bool) -> Result<Vec<CertificateConfig>> {
    if database.exists() {
        match load_certificates_from_database(database) {
            Ok(existing) => {
                if prints {
                    println!("Found {} existing certificates in database", existing.len());
                }
                Ok(existing)
            }
            Err(e) => {
                if prints {
                    eprintln!("Error reading existing database: {}", e);
                }
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
    prints: bool,
) -> Result<Vec<CertificateConfig>> {
    let mut configs = Vec::new();
    for p in inputs {
        let discovered_files = discover_cert_files(&p);
        if discovered_files.is_empty() {
            if prints {
                eprintln!("No certificates found in {}", p.display());
            }
            continue;
        }
        if prints {
            println!(
                "Found {} certificates in {}",
                discovered_files.len(),
                p.display()
            );
        }

        for file_path in discovered_files {
            if let Some(config) =
                parse_certificate_file(&file_path, tui_config, password_file.as_deref(), prints)
            {
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
    prints: bool,
) -> Option<CertificateConfig> {
    match CertificateConfig::read_from_path(file_path.to_str().unwrap_or_default(), None) {
        Ok(config) => Some(config),

        // Handle password-protected P12
        Err(CertMgtError::P12PasswordRequired) => {
            if let Some(config) = try_with_passwords(tui_config, file_path, password_file) {
                return Some(config);
            }

            // Interactive fallback
            if prints {
                eprintln!("P12 file {} requires a password.", file_path.display());
                eprint!("Enter password: ");
            }
            io::stdout().flush().ok()?;
            let password = rpassword::read_password().ok()?;
            if let Ok(config) =
                CertificateConfig::read_from_path(file_path.to_str().unwrap(), Some(&password))
            {
                Some(config)
            } else {
                if prints {
                    eprintln!("Password did not work for {}", file_path.display());
                }
                None
            }
        }

        // Handle PEM key-only file
        Err(CertMgtError::PemKeyOnly) => match find_and_attach_matching_cert(file_path) {
            Ok(config) => Some(config),
            Err(e) => {
                if prints {
                    eprintln!("Error resolving PEM key {}: {}", file_path.display(), e);
                }
                None
            }
        },

        Err(e) => {
            if prints {
                eprintln!("Error reading {}: {}", file_path.display(), e);
            }
            None
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

    // 2. Password file fallback (lines of `file=pw`, or one password per line)
    if let Some(pf) = password_file
        && let Ok(sources) = load_passwords(pf)
    {
        let file_name = file_path
            .file_name()
            .and_then(|n| n.to_str())
            .unwrap_or_default();
        let mut candidates: Vec<String> = Vec::new();
        match sources {
            PasswordSourceConfig::Map(map) => {
                if let Some(pw) = map.get(file_name) {
                    candidates.push(pw.clone());
                }
                candidates.extend(map.values().cloned());
            }
            PasswordSourceConfig::List(list) => candidates.extend(list),
        }
        if let Some(path_str) = file_path.to_str() {
            for pw in &candidates {
                if let Ok(config) = CertificateConfig::read_from_path(path_str, Some(pw)) {
                    return Some(config);
                }
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
        Err(format!(
            "No matching certificate found for key {}",
            file_path.display()
        )
        .into())
    }
}

fn merge_configs(
    new_configs: Vec<CertificateConfig>,
    final_configs: &mut Vec<CertificateConfig>,
    seen: &mut HashSet<String>,
    force: bool,
    prints: bool,
) -> (usize, usize, usize) {
    let mut imported = 0;
    let mut skipped = 0;
    let mut overridden = 0;

    for mut config in new_configs {
        let fp = cert_fingerprint(&config.cert_data);
        if seen.contains(&fp) {
            if force {
                if prints {
                    println!("Overriding duplicate: {}", config.common_name);
                }
                overridden += 1;
                // Preserve the stable ID so CA links from other certs survive
                let old_id = final_configs
                    .iter()
                    .find(|c| cert_fingerprint(&c.cert_data) == fp)
                    .map(|c| c.id.clone());
                final_configs.retain(|c| cert_fingerprint(&c.cert_data) != fp);
                if let Some(id) = old_id {
                    config.id = id;
                }
            } else {
                if prints {
                    println!("Skipping duplicate: {}", config.common_name);
                }
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

pub fn save_database(
    database: &Path,
    compressed: bool,
    configs: Vec<CertificateConfig>,
) -> Result<()> {
    // The loader picks its codec by extension, so the extension is the
    // single source of truth. Honor an explicit --compressed request by
    // switching to a .json.gz path instead of writing gz bytes into a
    // .json file.
    let gz_path = database.with_extension("json.gz");
    let path: &Path = if compressed && !is_compressed_file(database) {
        &gz_path
    } else {
        database
    };
    if is_compressed_file(path) {
        save_certificates_to_json_compressed(configs, path)?;
    } else {
        save_certificates_to_json(configs, path)?;
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
            if let Some(key_data) = key
                && !key_data.is_empty()
            {
                pem_content.push('\n');
                pem_content.push_str(key_data);
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
        if let Some(ref filter_fn) = filter
            && !filter_fn(config)
        {
            continue;
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
