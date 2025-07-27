// src/main.rs
use certmgt_lib::{
    CertificateConfig, save_certificates_to_json, load_certificates_from_json,
    attach_private_key_to_certificate, list_all_certificate_names, AttachKeyError,
    // Optional: compressed JSON functions
    save_certificates_to_json_compressed, load_certificates_from_json_compressed
};
use certmgt_lib::json::{export_certificate, export_certificates_with_filter, export_all_certificates};
use clap::{Parser, Subcommand};
use std::path::PathBuf;
use serde::de::Error;

#[derive(Parser)]
#[command(version, about)]
struct Cli {
    #[command(subcommand)]
    cmd: Commands,
}

#[derive(Subcommand)]
enum Commands {
    /// Read certificates from a file (JSON, parquet, PEM, or P12) and display them
    Read {
        #[arg(long)]
        path: PathBuf,
        #[arg(long)]
        password: Option<String>,
        #[arg(long, help = "Output format: summary, detailed, json, table", default_value = "summary")]
        format: String,
        #[arg(long, help = "Show certificate content (PEM data)")]
        show_content: bool,
    },
    /// Import certificate files (PEM/P12) into a JSON database
    Import {
        #[arg(long, value_name = "CERTS...")]
        inputs: Vec<PathBuf>,
        #[arg(long, help = "Output database file (.json or .json.gz)")]
        database: PathBuf,
        #[arg(long, help = "Append to existing database instead of overwriting")]
        append: bool,
        #[arg(long, help = "Use compressed JSON format")]
        compressed: bool,
    },
    /// Export certificates from JSON database to individual files in their original format
    Export {
        #[arg(long, help = "Input database file (.json or .json.gz)")]
        database: PathBuf,
        #[arg(long)]
        output_dir: PathBuf,
        #[arg(long, help = "Filter by common name pattern")]
        filter: Option<String>,
        #[arg(long, help = "Filter by organization")]
        org_filter: Option<String>,
        #[arg(long, help = "Export only CA certificates")]
        ca_only: bool,
    },
    /// Attach a private key to an existing PEM certificate in the JSON database
    AttachKey {
        #[arg(long, help = "Database file (.json or .json.gz)")]
        database: PathBuf,
        #[arg(long, help = "Common name of the certificate to update")]
        common_name: String,
        #[arg(long, help = "Path to the private key file")]
        key_path: PathBuf,
        #[arg(long, help = "Password for encrypted private key")]
        key_password: Option<String>,
    },
    /// Convert between different database formats
    Convert {
        #[arg(long, help = "Input file (supports .json, .json.gz, .parquet for legacy)")]
        input: PathBuf,
        #[arg(long, help = "Output file (.json or .json.gz)")]
        output: PathBuf,
    },
}

fn main() -> anyhow::Result<()> {
    let cli = Cli::parse();

    match cli.cmd {
        Commands::Read { path, password, format, show_content } => {
            let configs: Vec<CertificateConfig> = if is_database_file(&path) {
                // Read from database file
                load_certificates_from_database(&path)?
            } else {
                // Read single certificate file - wrap in Vec for consistency
                match CertificateConfig::read_from_path(path.to_str().unwrap(), password.as_deref()) {
                    Ok(cfg) => vec![cfg],
                    Err(e) => {
                        // If it's a P12 file and no password was provided, prompt for one
                        if e.to_string().contains("mac verify failure") && password.is_none() {
                            eprintln!("P12 file requires a password. Please provide it with --password");
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
                    eprintln!("Unsupported format: {}. Use: summary, detailed, json, table, content", format);
                    std::process::exit(1);
                }
            }
        }

        Commands::Import { inputs, database, append, compressed } => {
            // Load new certificates from input files
            let mut new_configs = Vec::new();
            for p in &inputs {
                // Try reading without password first, then prompt if needed
                let config = match CertificateConfig::read_from_path(p.to_str().unwrap(), None) {
                    Ok(config) => config,
                    Err(e) if e.to_string().contains("mac verify failure") => {
                        // P12 file needs password - prompt user
                        eprintln!("P12 file {} requires a password.", p.display());
                        eprint!("Enter password: ");
                        use std::io::{self, Write};
                        io::stdout().flush().unwrap();

                        let password = rpassword::read_password()?;
                        match CertificateConfig::read_from_path(p.to_str().unwrap(), Some(&password)) {
                            Ok(config) => config,
                            Err(e) => {
                                eprintln!("Error reading {} with password: {}", p.display(), e);
                                std::process::exit(1);
                            }
                        }
                    }
                    Err(e) => {
                        eprintln!("Error reading {}: {}", p.display(), e);
                        std::process::exit(1);
                    }
                };

                println!("Loaded certificate: {}", config.common_name);
                new_configs.push(config);
            }

            let final_configs = if append && database.exists() {
                // Load existing certificates and append new ones
                match load_certificates_from_database(&database) {
                    Ok(mut existing) => {
                        println!("Found {} existing certificates in database", existing.len());
                        existing.extend(new_configs);
                        existing
                    }
                    Err(e) => {
                        eprintln!("Error reading existing database: {}", e);
                        std::process::exit(1);
                    }
                }
            } else {
                // Just use the new certificates (overwrite mode)
                new_configs
            };

            // Save based on compression flag or file extension
            let use_compression = compressed || is_compressed_file(&database);

            let result = if use_compression {
                save_certificates_to_json_compressed(final_configs.clone(), &database)
            } else {
                save_certificates_to_json(final_configs.clone(), &database)
            };

            match result {
                Ok(_) => {
                    let format = if use_compression { "compressed JSON" } else { "JSON" };
                    println!("Successfully saved {} certificates to {} ({})",
                             final_configs.len(), database.display(), format);
                }
                Err(e) => {
                    eprintln!("Error saving to database: {}", e);
                    std::process::exit(1);
                }
            }
        }

        Commands::Export { database, output_dir, filter, org_filter, ca_only } => {
            // Load certificates from database file
            let configs = match load_certificates_from_database(&database) {
                Ok(configs) => configs,
                Err(e) => {
                    eprintln!("Error loading database: {}", e);
                    std::process::exit(1);
                }
            };

            println!("Loaded {} certificates from database", configs.len());

            // Build filter function based on command line arguments
            let filter_fn = |config: &CertificateConfig| -> bool {
                // Apply CA filter
                if ca_only && !config.is_ca {
                    return false;
                }

                // Apply common name filter
                if let Some(ref pattern) = filter {
                    if !config.common_name.contains(pattern) {
                        return false;
                    }
                }

                // Apply organization filter
                if let Some(ref org_pattern) = org_filter {
                    if !config.organization.contains(org_pattern) {
                        return false;
                    }
                }

                true
            };

            // Export certificates with filtering
            let exported_files = if filter.is_some() || org_filter.is_some() || ca_only {
                match export_certificates_with_filter(&configs, &output_dir, Some(filter_fn)) {
                    Ok(files) => files,
                    Err(e) => {
                        eprintln!("Error exporting certificates: {}", e);
                        std::process::exit(1);
                    }
                }
            } else {
                // Export all certificates
                match export_all_certificates(&configs, &output_dir) {
                    Ok(files) => files,
                    Err(e) => {
                        eprintln!("Error exporting certificates: {}", e);
                        std::process::exit(1);
                    }
                }
            };

            println!("Successfully exported {} certificates to {}:", exported_files.len(), output_dir.display());
            for file in &exported_files {
                println!("  - {}", file);
            }
        }

        Commands::AttachKey { database, common_name, key_path, key_password } => {
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
                    io::stdout().flush().unwrap();
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
                    println!("✅ Private key attached to certificate '{}'", result.certificate_common_name);
                    if result.key_was_encrypted {
                        println!("   (Key was encrypted and successfully decrypted)");
                    }
                    if result.had_existing_key {
                        println!("   (Replaced existing private key)");
                    }
                    return Ok(());
                }
                Err(AttachKeyError::InvalidPrivateKey(msg)) if msg.contains("already has a private key") => {
                    // Key already exists, ask for confirmation
                    eprintln!("Certificate '{}' already has a private key attached.", common_name);
                    eprint!("Do you want to replace it? (y/N): ");
                    use std::io::{self, Write};
                    io::stdout().flush().unwrap();

                    let mut response = String::new();
                    io::stdin().read_line(&mut response).unwrap();
                    response.trim().to_lowercase().starts_with('y')
                }
                Err(e) => {
                    eprintln!("❌ Error attaching private key: {}", e);
                    if let AttachKeyError::InvalidPrivateKey(_) = e {
                        eprintln!("💡 Make sure the key file is in PEM format and the password is correct.");
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
                        println!("✅ Private key attached to certificate '{}'", result.certificate_common_name);
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
                    let format = if use_compression { "compressed JSON" } else { "JSON" };
                    println!("✅ Successfully converted to {} ({})", output.display(), format);
                }
                Err(e) => {
                    eprintln!("❌ Error converting: {}", e);
                    std::process::exit(1);
                }
            }
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
                .and_then(|stem| std::path::Path::new(stem).extension())
                .and_then(|ext| ext.to_str()) == Some("json")
        }
        Some("parquet") => true, // Legacy support
        _ => false,
    }
}

fn is_compressed_file(path: &PathBuf) -> bool {
    path.extension().and_then(|ext| ext.to_str()) == Some("gz")
}

fn load_certificates_from_database(path: &PathBuf) -> Result<Vec<CertificateConfig>, AttachKeyError> {
    match path.extension().and_then(|ext| ext.to_str()) {
        Some("json") => load_certificates_from_json(path),
        Some("gz") => {
            // Assume .json.gz
            load_certificates_from_json_compressed(path).map_err(|e| {
                AttachKeyError::JsonError(serde_json::Error::custom(e.to_string()))
            })
        }
        Some("parquet") => {
            // Legacy support - you'd need to keep one parquet function or convert
            eprintln!("Legacy parquet format detected. Please convert to JSON first:");
            eprintln!("  certmgt-cli convert --input {} --output {}",
                      path.display(),
                      path.with_extension("json").display());
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
                if key.is_some() { "PEM+Key" } else { "PEM" }
            }
            certmgt_lib::CertData::P12 { as_base64, .. } => {
                if *as_base64 { "P12(B64)" } else { "P12" }
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

        println!("{:3}: {} | {} | {} | {} days | {}",
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
            println!("  Status: ⚠️  EXPIRING SOON ({} days remaining)", expires_in_days);
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
            certmgt_lib::CertData::P12 { data, as_base64, .. } => {
                println!("  Format: PKCS#12");
                println!("  Encoding: {}", if *as_base64 { "Base64" } else { "Binary" });
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
    let json_configs: Vec<serde_json::Value> = configs.iter().map(|config| {
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
            certmgt_lib::CertData::P12 { as_base64, data, .. } => {
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
            "certificate_type": cert_type_info
        })
    }).collect();

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
    println!("{:<3} | {:<width_cn$} | {:<width_org$} | {:<8} | {:<10} | {:<6} | {:<4}",
             "#", "Common Name", "Organization", "Type", "Expires", "Status", "CA",
             width_cn = max_cn, width_org = max_org);

    println!("{}", "-".repeat(3 + 3 + max_cn + 3 + max_org + 3 + 8 + 3 + 10 + 3 + 6 + 3 + 4));

    // Print rows
    for (idx, config) in configs.iter().enumerate() {
        let cn = if config.common_name.len() > max_cn {
            format!("{}...", &config.common_name[..max_cn-3])
        } else {
            config.common_name.clone()
        };

        let org = if config.organization.len() > max_org {
            format!("{}...", &config.organization[..max_org-3])
        } else {
            config.organization.clone()
        };

        let cert_type = match &config.cert_data {
            certmgt_lib::CertData::Pem { key, .. } => {
                if key.is_some() { "PEM+Key" } else { "PEM" }
            }
            certmgt_lib::CertData::P12 { .. } => "P12"
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

        println!("{:<3} | {:<width_cn$} | {:<width_org$} | {:<8} | {:<10} | {:<6} | {:<4}",
                 idx + 1, cn, org, cert_type, expires_str, status,
                 if config.is_ca { "YES" } else { "NO" },
                 width_cn = max_cn, width_org = max_org);
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
        certmgt_lib::CertData::P12 { data, as_base64, .. } => {
            println!("📦 PKCS#12 Data ({}):", if *as_base64 { "Base64" } else { "Binary as Base64" });

            // Display P12 data with line breaks for readability
            let chunks: Vec<&str> = data.as_bytes()
                .chunks(64)
                .map(|chunk| std::str::from_utf8(chunk).unwrap_or(""))
                .collect();

            for chunk in chunks {
                if !chunk.is_empty() {
                    println!("{}", chunk);
                }
            }

            println!("\n💡 Note: This is the complete PKCS#12 bundle containing both certificate and private key.");
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