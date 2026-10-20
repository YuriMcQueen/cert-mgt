use crate::json::{load_certificates_from_json, load_certificates_from_json_compressed};
use certmgt_lib::{CertData, CertMgtError, CertificateConfig};
use serde::de::Error;
use sha2::{Digest, Sha256};
use std::path::{Path, PathBuf};
use walkdir::WalkDir;

pub fn is_database_file(path: &Path) -> bool {
    match path.extension().and_then(|ext| ext.to_str()) {
        Some("json") => true,
        Some("gz") => {
            // Check if it's .json.gz
            path.file_stem()
                .and_then(|stem| Path::new(stem).extension())
                .and_then(|ext| ext.to_str())
                == Some("json")
        }
        Some("parquet") => true, // Legacy support
        _ => false,
    }
}

pub fn is_compressed_file(path: &Path) -> bool {
    path.extension().and_then(|ext| ext.to_str()) == Some("gz")
}

pub fn load_certificates_from_database(
    path: &Path,
) -> Result<Vec<CertificateConfig>, CertMgtError> {
    match path.extension().and_then(|ext| ext.to_str()) {
        Some("json") => load_certificates_from_json(path),
        Some("gz") => {
            // Assume .json.gz
            load_certificates_from_json_compressed(path)
                .map_err(|e| CertMgtError::JsonError(serde_json::Error::custom(e.to_string())))
        }
        Some("parquet") => {
            // Legacy support - you'd need to keep one parquet function or convert
            eprintln!("Legacy parquet format detected. Please convert to JSON first:");
            eprintln!(
                "  certmgt-cli convert --input {} --output {}",
                path.display(),
                path.with_extension("json").display()
            );
            std::process::exit(1);
        }
        _ => {
            eprintln!("Unsupported database format. Use .json or .json.gz files.");
            std::process::exit(1);
        }
    }
}

pub fn discover_cert_files(path: &Path) -> Vec<PathBuf> {
    if path.is_file() {
        vec![path.to_path_buf()]
    } else if path.is_dir() {
        WalkDir::new(path)
            .into_iter()
            .filter_map(|e| e.ok())
            .filter(|e| e.file_type().is_file())
            .filter(|e| {
                e.path()
                    .extension()
                    .and_then(|ext| ext.to_str())
                    .map(|ext| {
                        matches!(
                            ext.to_lowercase().as_str(),
                            "crt" | "pem" | "cer" | "der" | "p12" | "txt" | "b64"
                        )
                    })
                    .unwrap_or(false)
            })
            .map(|e| e.path().to_path_buf())
            .collect()
    } else {
        vec![]
    }
}

pub fn cert_fingerprint_bytes(cert_data: &CertData) -> Vec<u8> {
    let mut hasher = Sha256::new();
    match cert_data {
        CertData::Pem { cert, key } => {
            hasher.update(cert.as_bytes());
            if let Some(k) = key {
                hasher.update(k.as_bytes());
            }
        }
        CertData::P12 { data, .. } => {
            hasher.update(data.as_bytes());
        }
    }
    hasher.finalize().to_vec()
}

pub fn cert_fingerprint(cert_data: &CertData) -> String {
    hex::encode(cert_fingerprint_bytes(cert_data))
}
