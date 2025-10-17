mod cli;
mod config;
mod json;
mod tui;

use crate::cli::{Commands, ListType};
use crate::config::{TuiConfig};
use crate::json::*;
use crate::tui::launch_tui;
use certmgt_lib::filters::filter_certificates;
use certmgt_lib::types::{CaConfig, ServerCertConfig};
use certmgt_lib::{CertData, CertMgtError, CertificateConfig};
use clap::Parser;
use serde::de::Error;
use sha2::{Digest, Sha256};
use std::io::Write;
use std::path::{Path, PathBuf};
use walkdir::WalkDir;

fn main() -> anyhow::Result<()> {
    let cli = cli::Cli::parse();
    let config = TuiConfig::load();

    match cli.cmd {
        Commands::Tui => {
            launch_tui()?;
        }
        Commands::Read {
            path,
            password,
            filters,
            or_logic,
            format,
            show_content,
        } => {
            let configs: Vec<CertificateConfig> = if is_database_file(&path) {
                // Read from database file
                let certificates = load_certificates_from_database(&path)?;
                let filtered_configs =
                    filter_certificates(certificates, filters.clone(), or_logic)?;

                let logic_type = if or_logic { "OR" } else { "AND" };
                println!(
                    "Filter results ({} logic): {} certificates found",
                    logic_type,
                    filtered_configs.len()
                );
                println!(
                    "Applied filters: {}",
                    filters.join(&format!(" {} ", logic_type))
                );
                filtered_configs
            } else {
                // Read single certificate file - wrap in Vec for consistency
                match CertificateConfig::read_from_path(path.to_str().unwrap(), password.as_deref())
                {
                    Ok(cfg) => vec![cfg],
                    Err(e) => {
                        // If it's a P12 file and no password was provided, prompt for one
                        if e.to_string().contains("mac verify failure") && password.is_none() {
                            eprintln!(
                                "P12 file requires a password. Please provide it with --password"
                            );
                            std::process::exit(1);
                        }
                        eprintln!("Error reading certificate: {}", e);
                        std::process::exit(1);
                    }
                }
            };

            // Display certificates based on format
            match format.as_str() {
                "summary" => display_summary(&configs, show_content),
                "detailed" => display_detailed(&configs, show_content),
                "json" => display_json(&configs, show_content)?,
                "table" => display_table(&configs),
                "content" => display_content_only(&configs),
                _ => {
                    eprintln!(
                        "Unsupported format: {}. Use: summary, detailed, json, table, content",
                        format
                    );
                    std::process::exit(1);
                }
            }
        }

        Commands::Import {
            inputs,
            database,
            compressed,
            force,
            password_file,
        } => {
            import(&config, inputs, database, compressed, force, password_file, true)?;
        }

        Commands::Export {
            database,
            output_dir,
            filters,
            or_logic,
            filter,
            org_filter,
            ca_only,
        } => {
            // Handle deprecated options by converting them to new filter format
            let mut all_filters = filters;

            // Convert deprecated options to new filter format
            if let Some(pattern) = filter {
                eprintln!(
                    "⚠️  WARNING: --filter is deprecated. Use --filters 'common_name~{}' instead",
                    pattern
                );
                all_filters.push(format!("common_name~{}", pattern));
            }

            if let Some(org_pattern) = org_filter {
                eprintln!(
                    "⚠️  WARNING: --org-filter is deprecated. Use --filters 'organization~{}' instead",
                    org_pattern
                );
                all_filters.push(format!("organization~{}", org_pattern));
            }

            if ca_only {
                eprintln!(
                    "⚠️  WARNING: --ca-only is deprecated. Use --filters 'is_ca==true' instead"
                );
                all_filters.push("is_ca==true".to_string());
            }
            let certificates = load_certificates_from_database(&database)?;

            let filtered_configs = if all_filters.is_empty() {
                certificates
            } else {
                // Apply advanced filtering
                match filter_certificates(certificates, all_filters, or_logic) {
                    Ok(configs) => configs,
                    Err(e) => {
                        eprintln!("Error filtering certificates: {}", e);
                        std::process::exit(1);
                    }
                }
            };

            println!(
                "Found {} certificates matching filters",
                filtered_configs.len()
            );

            // Export the filtered certificates
            let exported_files = match export_all_certificates(&filtered_configs, &output_dir) {
                Ok(files) => files,
                Err(e) => {
                    eprintln!("Error exporting certificates: {}", e);
                    std::process::exit(1);
                }
            };

            println!(
                "Successfully exported {} certificates to {}:",
                exported_files.len(),
                output_dir.display()
            );
            for file in &exported_files {
                println!("  - {}", file);
            }
        }
        Commands::List {
            database,
            list_type,
        } => match list_type {
            ListType::WithoutKeys => {
                let certificates = load_certificates_from_database(&database)?;
                let configs = filter_certificates(
                    certificates,
                    vec!["has_private_key==false".to_string()],
                    false,
                )?;
                println!(
                    "Certificates without private keys ({} found):",
                    configs.len()
                );
                for config in configs {
                    println!("  - {}", config.common_name);
                }
            }

            ListType::CAs => {
                let certificates = load_certificates_from_database(&database)?;
                let configs =
                    filter_certificates(certificates, vec!["is_ca==true".to_string()], false)?;
                println!("CA certificates ({} found):", configs.len());
                for config in configs {
                    println!("  - {} ({})", config.common_name, config.organization);
                }
            }

            ListType::Expiring { days } => {
                let certificates = load_certificates_from_database(&database)?;
                let threshold = chrono::Utc::now().timestamp() + (days * 24 * 60 * 60);
                let filters = vec![
                    format!("not_after<={}", threshold),
                    format!("not_after>{}", chrono::Utc::now().timestamp()),
                ];
                let configs = filter_certificates(certificates, filters, false)?;
                println!(
                    "Certificates expiring within {} days ({} found):",
                    days,
                    configs.len()
                );
                for config in configs {
                    let days_left = (config.not_after - chrono::Utc::now().timestamp()) / 86400;
                    println!("  - {} (expires in {} days)", config.common_name, days_left);
                }
            }

            ListType::Expired => {
                let certificates = load_certificates_from_database(&database)?;
                let filter = format!("not_after<{}", chrono::Utc::now().timestamp());
                let configs = filter_certificates(certificates, vec![filter], false)?;
                println!("Expired certificates ({} found):", configs.len());
                for config in configs {
                    let days_ago = (chrono::Utc::now().timestamp() - config.not_after) / 86400;
                    println!("  - {} (expired {} days ago)", config.common_name, days_ago);
                }
            }

            ListType::ByOrg { pattern } => {
                let certificates = load_certificates_from_database(&database)?;
                let filter = format!("organization~{}", pattern);
                let configs = filter_certificates(certificates, vec![filter], false)?;
                println!(
                    "Certificates with organization matching '{}' ({} found):",
                    pattern,
                    configs.len()
                );
                for config in configs {
                    println!("  - {} ({})", config.common_name, config.organization);
                }
            }

            ListType::ByCN { pattern } => {
                let certificates = load_certificates_from_database(&database)?;
                let filter = format!("common_name~{}", pattern);
                let configs = filter_certificates(certificates, vec![filter], false)?;
                println!(
                    "Certificates with common name matching '{}' ({} found):",
                    pattern,
                    configs.len()
                );
                for config in configs {
                    println!("  - {}", config.common_name);
                }
            }
        },

        Commands::AttachKey {
            database,
            common_name,
            key_path,
            key_password,
        } => {
            // Check if certificate exists and get available certificates for better error messages
            let available_certs = match list_all_certificate_names(&database) {
                Ok(certs) => certs,
                Err(e) => {
                    eprintln!("Error loading certificate database: {}", e);
                    std::process::exit(1);
                }
            };

            // Check if the target certificate exists
            if !available_certs.contains(&common_name) {
                eprintln!("Certificate with common name '{}' not found", common_name);
                eprintln!("Available certificates:");
                for cert_name in available_certs {
                    eprintln!("  - {}", cert_name);
                }
                std::process::exit(1);
            }

            // Handle password for encrypted keys
            let key_password = if key_password.is_some() {
                key_password
            } else {
                // Check if key might be encrypted by trying to read it
                let key_content = std::fs::read_to_string(&key_path)?;
                if key_content.contains("ENCRYPTED") {
                    eprint!("Private key appears to be encrypted. Enter password: ");
                    use std::io::{self, Write};
                    io::stdout().flush()?;
                    Some(rpassword::read_password()?)
                } else {
                    None
                }
            };

            // For existing keys, ask for confirmation unless force is specified
            let force_replace = match attach_private_key_to_certificate(
                &database,
                &common_name,
                &key_path,
                key_password.as_deref(),
                false, // Don't force initially
            ) {
                Ok(result) => {
                    // Success on first try
                    println!(
                        "✅ Private key attached to certificate '{}'",
                        result.certificate_common_name
                    );
                    if result.key_was_encrypted {
                        println!("   (Key was encrypted and successfully decrypted)");
                    }
                    if result.had_existing_key {
                        println!("   (Replaced existing private key)");
                    }
                    return Ok(());
                }
                Err(CertMgtError::InvalidPrivateKey(msg))
                    if msg.contains("already has a private key") =>
                {
                    // Key already exists, ask for confirmation
                    eprintln!(
                        "Certificate '{}' already has a private key attached.",
                        common_name
                    );
                    eprint!("Do you want to replace it? (y/N): ");
                    use std::io::{self, Write};
                    io::stdout().flush()?;

                    let mut response = String::new();
                    io::stdin().read_line(&mut response)?;
                    response.trim().to_lowercase().starts_with('y')
                }
                Err(e) => {
                    eprintln!("❌ Error attaching private key: {}", e);
                    if let CertMgtError::InvalidPrivateKey(_) = e {
                        eprintln!(
                            "💡 Make sure the key file is in PEM format and the password is correct."
                        );
                    }
                    std::process::exit(1);
                }
            };

            if force_replace {
                // Try again with force=true
                match attach_private_key_to_certificate(
                    &database,
                    &common_name,
                    &key_path,
                    key_password.as_deref(),
                    true,
                ) {
                    Ok(result) => {
                        println!(
                            "✅ Private key attached to certificate '{}'",
                            result.certificate_common_name
                        );
                        if result.key_was_encrypted {
                            println!("   (Key was encrypted and successfully decrypted)");
                        }
                        println!("   (Replaced existing private key)");
                    }
                    Err(e) => {
                        eprintln!("❌ Error attaching private key: {}", e);
                        std::process::exit(1);
                    }
                }
            } else {
                println!("Operation cancelled.");
            }
        }

        Commands::Convert { input, output } => {
            println!("Converting {} to {}...", input.display(), output.display());

            // Load from input (supports various formats)
            let configs = load_certificates_from_database(&input)?;
            println!("Loaded {} certificates", configs.len());

            // Save to output format
            let use_compression = is_compressed_file(&output);
            let result = if use_compression {
                save_certificates_to_json_compressed(configs, &output)
            } else {
                save_certificates_to_json(configs, &output)
            };

            match result {
                Ok(_) => {
                    let format = if use_compression {
                        "compressed JSON"
                    } else {
                        "JSON"
                    };
                    println!(
                        "✅ Successfully converted to {} ({})",
                        output.display(),
                        format
                    );
                }
                Err(e) => {
                    eprintln!("❌ Error converting: {}", e);
                    std::process::exit(1);
                }
            }
        }
        Commands::Generate {
            validity_days,
            country,
            state,
            organization,
            common_name,
            key_size,
            alt_names,
            ca_validity_days,
            ca_key_size,
            database,
        } => {
            let new_ca_config = CaConfig {
                country: country.clone(),
                state: state.clone(),
                organization: organization.clone(),
                common_name: common_name.clone(),
                key_size: ca_key_size,
                validity_days: ca_validity_days,
            };

            let new_cert_config = ServerCertConfig {
                country,
                state,
                organization,
                common_name,
                alt_names,
                key_size: key_size as usize,
                validity_days,
            };
            let ca = CertificateConfig::new_ca(new_ca_config)?;
            println!("{:?}", ca.cert_data);
            let cert = CertificateConfig::sign_certificate(&ca, &new_cert_config)?;
            save_certificates_to_json(vec![ca, cert], &database)?;
        }
    }
    Ok(())
}

// Helper functions

fn is_database_file(path: &PathBuf) -> bool {
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

fn is_compressed_file(path: &PathBuf) -> bool {
    path.extension().and_then(|ext| ext.to_str()) == Some("gz")
}

fn load_certificates_from_database(path: &PathBuf) -> Result<Vec<CertificateConfig>, CertMgtError> {
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

// Display functions remain the same...
fn display_summary(configs: &[CertificateConfig], show_content: bool) {
    println!("Found {} certificate(s):", configs.len());
    for (idx, config) in configs.iter().enumerate() {
        let cert_type = match &config.cert_data {
            certmgt_lib::CertData::Pem { key, .. } => {
                if key.is_some() {
                    "PEM+Key"
                } else {
                    "PEM"
                }
            }
            certmgt_lib::CertData::P12 { as_base64, .. } => {
                if *as_base64 {
                    "P12(B64)"
                } else {
                    "P12"
                }
            }
        };

        let expires_in_days = (config.not_after - chrono::Utc::now().timestamp()) / 86400;
        let status = if expires_in_days < 0 {
            "EXPIRED"
        } else if expires_in_days < 30 {
            "EXPIRING"
        } else {
            "VALID"
        };

        println!(
            "{:3}: {} | {} | {} | {} days | {}",
            idx + 1,
            config.common_name.chars().take(30).collect::<String>(),
            cert_type,
            status,
            expires_in_days,
            if config.is_ca { "CA" } else { "CERT" }
        );

        if show_content {
            display_certificate_content(config, idx + 1);
        }
    }
}

fn display_detailed(configs: &[CertificateConfig], show_content: bool) {
    println!("Found {} certificate(s):", configs.len());
    for (idx, config) in configs.iter().enumerate() {
        println!("\n{}", "=".repeat(60));
        println!("Certificate {}: {}", idx + 1, config.common_name);
        println!("{}", "=".repeat(60));

        println!("Subject Information:");
        println!("  Serial Number: {}", config.serial_number);
        println!("  Common Name: {}", config.common_name);
        println!("  Organization: {}", config.organization);
        println!("  Organizational Unit: {}", config.organizational_unit);
        println!("  Country: {}", config.country);
        println!("  State: {}", config.state);
        println!("  Locality: {}", config.locality);

        println!("\nCertificate Details:");
        println!("  Is CA: {}", config.is_ca);
        println!("  Key Size: {:?}", config.key_size);
        println!("  Has Private Key: {}", config.has_private_key());

        // Format timestamps
        let not_before = chrono::DateTime::from_timestamp(config.not_before, 0)
            .map(|dt| dt.format("%Y-%m-%d %H:%M:%S UTC").to_string())
            .unwrap_or_else(|| "Invalid date".to_string());
        let not_after = chrono::DateTime::from_timestamp(config.not_after, 0)
            .map(|dt| dt.format("%Y-%m-%d %H:%M:%S UTC").to_string())
            .unwrap_or_else(|| "Invalid date".to_string());

        println!("  Valid From: {}", not_before);
        println!("  Valid Until: {}", not_after);

        let expires_in_days = (config.not_after - chrono::Utc::now().timestamp()) / 86400;
        if expires_in_days < 0 {
            println!("  Status: ⚠️  EXPIRED ({} days ago)", -expires_in_days);
        } else if expires_in_days < 30 {
            println!(
                "  Status: ⚠️  EXPIRING SOON ({} days remaining)",
                expires_in_days
            );
        } else {
            println!("  Status: ✅ VALID ({} days remaining)", expires_in_days);
        }

        println!("\nCertificate Type:");
        match &config.cert_data {
            certmgt_lib::CertData::Pem { cert, key } => {
                println!("  Format: PEM");
                println!("  Certificate Length: {} bytes", cert.len());
                if let Some(key_data) = key {
                    println!("  Private Key Length: {} bytes", key_data.len());
                } else {
                    println!("  Private Key: Not included");
                }
            }
            certmgt_lib::CertData::P12 {
                data, as_base64, ..
            } => {
                println!("  Format: PKCS#12");
                println!(
                    "  Encoding: {}",
                    if *as_base64 { "Base64" } else { "Binary" }
                );
                println!("  Data Length: {} bytes", data.len());
                println!("  Contains: Certificate + Private Key");
            }
        }

        if show_content {
            display_certificate_content(config, idx + 1);
        }
    }
}

fn display_json(configs: &[CertificateConfig], show_content: bool) -> anyhow::Result<()> {
    use serde_json;

    // Create a simplified structure for JSON output
    let json_configs: Vec<serde_json::Value> = configs
        .iter()
        .map(|config| {
            let cert_type_info = match &config.cert_data {
                certmgt_lib::CertData::Pem { key, cert } => {
                    let mut info = serde_json::json!({
                    "format": "PEM",
                    "has_private_key": key.is_some()
                    });

                    if show_content {
                        info["certificate_pem"] = serde_json::Value::String(cert.clone());
                        if let Some(key_data) = key {
                            info["private_key_pem"] = serde_json::Value::String(key_data.clone());
                        }
                    }
                    info
                }
                certmgt_lib::CertData::P12 {
                    as_base64, data, ..
                } => {
                    let mut info = serde_json::json!({
                    "format": "PKCS12",
                    "encoding": if *as_base64 { "base64" } else { "binary" },
                    "has_private_key": true
                    });

                    if show_content {
                        info["p12_data"] = serde_json::Value::String(data.clone());
                    }
                    info
                }
            };

            serde_json::json!({
            "common_name": config.common_name,
            "organization": config.organization,
            "organizational_unit": config.organizational_unit,
            "country": config.country,
            "state": config.state,
            "locality": config.locality,
            "is_ca": config.is_ca,
            "key_size": config.key_size,
            "not_before": config.not_before,
            "not_after": config.not_after,
            "has_private_key": config.has_private_key(),
            "certificate_type": cert_type_info,
            "serial_number": config.serial_number,
            })
        })
        .collect();

    println!("{}", serde_json::to_string_pretty(&json_configs)?);
    Ok(())
}

fn display_table(configs: &[CertificateConfig]) {
    use std::cmp;

    // Calculate column widths
    let mut max_cn = 15;
    let mut max_org = 12;

    for config in configs {
        max_cn = cmp::max(max_cn, config.common_name.len());
        max_org = cmp::max(max_org, config.organization.len());
    }

    // Limit column widths for readability
    max_cn = cmp::min(max_cn, 40);
    max_org = cmp::min(max_org, 25);

    // Print header
    println!(
        "{:<3} | {:<width_cn$} | {:<width_org$} | {:<8} | {:<10} | {:<6} | {:<4}",
        "#",
        "Common Name",
        "Organization",
        "Type",
        "Expires",
        "Status",
        "CA",
        width_cn = max_cn,
        width_org = max_org
    );

    println!(
        "{}",
        "-".repeat(3 + 3 + max_cn + 3 + max_org + 3 + 8 + 3 + 10 + 3 + 6 + 3 + 4)
    );

    // Print rows
    for (idx, config) in configs.iter().enumerate() {
        let cn = if config.common_name.len() > max_cn {
            format!("{}...", &config.common_name[..max_cn - 3])
        } else {
            config.common_name.clone()
        };

        let org = if config.organization.len() > max_org {
            format!("{}...", &config.organization[..max_org - 3])
        } else {
            config.organization.clone()
        };

        let cert_type = match &config.cert_data {
            certmgt_lib::CertData::Pem { key, .. } => {
                if key.is_some() {
                    "PEM+Key"
                } else {
                    "PEM"
                }
            }
            certmgt_lib::CertData::P12 { .. } => "P12",
        };

        let expires_in_days = (config.not_after - chrono::Utc::now().timestamp()) / 86400;
        let expires_str = if expires_in_days < 0 {
            format!("{}d ago", -expires_in_days)
        } else {
            format!("{}d", expires_in_days)
        };

        let status = if expires_in_days < 0 {
            "EXPIRED"
        } else if expires_in_days < 30 {
            "EXPIRING"
        } else {
            "VALID"
        };

        println!(
            "{:<3} | {:<width_cn$} | {:<width_org$} | {:<8} | {:<10} | {:<6} | {:<4}",
            idx + 1,
            cn,
            org,
            cert_type,
            expires_str,
            status,
            if config.is_ca { "YES" } else { "NO" },
            width_cn = max_cn,
            width_org = max_org
        );
    }
}

fn display_certificate_content(config: &CertificateConfig, index: usize) {
    println!("\n{}", "-".repeat(50));
    println!("Certificate {} Content:", index);
    println!("{}", "-".repeat(50));

    match &config.cert_data {
        certmgt_lib::CertData::Pem { cert, key } => {
            println!("📄 Certificate (PEM):");
            println!("{}", cert);

            if let Some(key_data) = key {
                println!("\n🔑 Private Key (PEM):");
                println!("{}", key_data);
            } else {
                println!("\n🔑 Private Key: Not included");
            }
        }
        certmgt_lib::CertData::P12 {
            data, as_base64, ..
        } => {
            println!(
                "📦 PKCS#12 Data ({}):",
                if *as_base64 {
                    "Base64"
                } else {
                    "Binary as Base64"
                }
            );

            // Display P12 data with line breaks for readability
            let chunks: Vec<&str> = data
                .as_bytes()
                .chunks(64)
                .map(|chunk| std::str::from_utf8(chunk).unwrap_or(""))
                .collect();

            for chunk in chunks {
                if !chunk.is_empty() {
                    println!("{}", chunk);
                }
            }

            println!(
                "\n💡 Note: This is the complete PKCS#12 bundle containing both certificate and private key."
            );
        }
    }
    println!();
}

fn display_content_only(configs: &[CertificateConfig]) {
    for (idx, config) in configs.iter().enumerate() {
        if idx > 0 {
            println!("\n{}", "=".repeat(80));
        }

        println!("Certificate {}: {}", idx + 1, config.common_name);
        display_certificate_content(config, idx + 1);
    }
}

fn discover_cert_files(path: &Path) -> Vec<PathBuf> {
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
//
// fn cert_fingerprint(cert_data: &CertData) -> String {
//     match cert_data {
//         CertData::Pem { cert, key } => {
//             // You can decide whether to include `key` in the fingerprint.
//             // If you include it, same cert with different private key is treated as different.
//             let mut hasher = Sha256::new();
//             hasher.update(cert.as_bytes());
//             if let Some(k) = key {
//                 hasher.update(k.as_bytes());
//             }
//             format!("{:x}", hasher.finalize())
//         }
//         CertData::P12 {
//             data, as_base64, ..
//         } => {
//             let mut hasher = Sha256::new();
//             if *as_base64 {
//                 // Already base64 string, hash as-is
//                 hasher.update(data.as_bytes());
//             } else {
//                 // If not base64, treat as raw binary
//                 hasher.update(data.as_bytes());
//             }
//             format!("{:x}", hasher.finalize())
//         }
//     }
// }

fn cert_fingerprint_bytes(cert_data: &CertData) -> Vec<u8> {
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

fn cert_fingerprint(cert_data: &CertData) -> String {
    hex::encode(cert_fingerprint_bytes(cert_data))
}