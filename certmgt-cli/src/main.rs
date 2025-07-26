// src/main.rs
use certmgt_lib::{CertificateConfig, ParquetExportOptions, save_certificates_to_parquet, load_certificates_from_parquet};
use certmgt_lib::parquet::export_certificate_as_p12;
use clap::{Parser, Subcommand};
use std::path::PathBuf;

#[derive(Parser)]
#[command(version, about)]
struct Cli {
    #[command(subcommand)]
    cmd: Commands,
}

#[derive(Subcommand)]
enum Commands {
    /// Read certificates from a file (parquet, PEM, or P12) and display them
    Read {
        #[arg(long)]
        path: PathBuf,
        #[arg(long)]
        password: Option<String>,
    },
    /// Import certificate files (PEM/P12) into a Parquet database
    Import {
        #[arg(long, value_name = "CERTS...")]
        inputs: Vec<PathBuf>,
        #[arg(long)]
        parquet: PathBuf,
        #[arg(long, help = "Append to existing parquet file instead of overwriting")]
        append: bool,
    },
    /// Export certificates from Parquet database to individual PEM/P12 files
    Export {
        #[arg(long)]
        parquet: PathBuf,
        #[arg(long)]
        output_dir: PathBuf,
        #[arg(long, help = "Export format: pem, p12")]
        format: Option<String>,
        #[arg(long, help = "Filter by common name pattern")]
        filter: Option<String>,
        #[arg(long, help = "Password for P12 export (default: empty)")]
        password: Option<String>,
    },
}

fn main() -> anyhow::Result<()> {
    let cli = Cli::parse();

    match cli.cmd {
        Commands::Read { path, password } => {
            let configs: Vec<CertificateConfig> = if path.extension().and_then(|ext| ext.to_str()) == Some("parquet") {
                // Read from Parquet file - returns Vec<CertificateConfig>
                match load_certificates_from_parquet(&path) {
                    Ok(configs) => configs,
                    Err(e) => {
                        eprintln!("Error reading Parquet file: {}", e);
                        std::process::exit(1);
                    }
                }
            } else {
                // Read single certificate file - wrap in Vec for consistency
                match CertificateConfig::read_from_path(path.to_str().unwrap(), password.as_deref()) {
                    Ok(cfg) => vec![cfg],
                    Err(e) => {
                        eprintln!("Error reading certificate: {}", e);
                        std::process::exit(1);
                    }
                }
            };

            // Display all certificates (for now, until TUI is implemented)
            println!("Found {} certificate(s):", configs.len());
            for (idx, config) in configs.iter().enumerate() {
                println!("\n--- Certificate {} ---", idx + 1);
                println!("Common Name: {}", config.common_name);
                println!("Organization: {}", config.organization);
                println!("Country: {}", config.country);
                println!("Is CA: {}", config.is_ca);
                println!("Key Size: {:?}", config.key_size);
                println!("Type: {:?}", config.cert_type);
                println!("Not Before: {}", config.not_before);
                println!("Not After: {}", config.not_after);
            }

            // TODO: When TUI is ready, replace the above with:
            // display_certificates_in_table(configs);
        }
        Commands::Import { inputs, parquet, append } => {
            // Load new certificates from input files
            let mut new_configs = Vec::new();
            for p in &inputs {
                match CertificateConfig::read_from_path(p.to_str().unwrap(), None) {
                    Ok(config) => new_configs.push(config),
                    Err(e) => {
                        eprintln!("Error reading {}: {}", p.display(), e);
                        std::process::exit(1);
                    }
                }
            }

            let final_configs = if append && parquet.exists() {
                // Load existing certificates and append new ones
                match load_certificates_from_parquet(&parquet) {
                    Ok(mut existing) => {
                        existing.extend(new_configs);
                        existing
                    }
                    Err(e) => {
                        eprintln!("Error reading existing Parquet file: {}", e);
                        std::process::exit(1);
                    }
                }
            } else {
                // Just use the new certificates (overwrite mode)
                new_configs
            };

            match save_certificates_to_parquet(final_configs.clone(), &parquet) {
                Ok(_) => println!("Imported {} certificates to {:?}", inputs.len(), parquet),
                Err(e) => {
                    eprintln!("Error saving to Parquet: {}", e);
                    std::process::exit(1);
                }
            }
        }
        Commands::Export { parquet, output_dir, format, filter, password } => {
            // Load certificates from parquet file
            let configs = match load_certificates_from_parquet(&parquet) {
                Ok(configs) => configs,
                Err(e) => {
                    eprintln!("Error loading Parquet file: {}", e);
                    std::process::exit(1);
                }
            };

            // Apply filter if specified
            let filtered_configs: Vec<_> = if let Some(pattern) = filter {
                configs.into_iter()
                    .filter(|config| config.common_name.contains(&pattern))
                    .collect()
            } else {
                configs
            };

            // Create output directory if it doesn't exist
            if let Err(e) = std::fs::create_dir_all(&output_dir) {
                eprintln!("Error creating output directory: {}", e);
                std::process::exit(1);
            }

            let export_format = format.as_deref().unwrap_or("pem");
            let mut exported_count = 0;

            for config in &filtered_configs {
                let filename = format!("{}.{}",
                                       config.common_name.replace("*", "wildcard").replace("/", "_"),
                                       export_format
                );
                let file_path = output_dir.join(filename);

                match export_format {
                    "pem" => {
                        if let Some(cert_pem) = &config.cert_pem {
                            if let Err(e) = std::fs::write(&file_path, cert_pem) {
                                eprintln!("Error writing PEM file {}: {}", file_path.display(), e);
                                continue;
                            }
                            exported_count += 1;
                        } else {
                            eprintln!("No PEM data available for {}", config.common_name);
                        }
                    }
                    "p12" => {
                        let p12_password = password.as_deref().unwrap_or("");
                        if let Err(e) = export_certificate_as_p12(config, &file_path, p12_password) {
                            eprintln!("Error writing P12 file {}: {}", file_path.display(), e);
                            continue;
                        }
                        exported_count += 1;
                    }
                    _ => {
                        eprintln!("Unsupported format: {}", export_format);
                        std::process::exit(1);
                    }
                }
            }

            println!("Exported {} certificates from {:?} to {:?}",
                     exported_count, parquet, output_dir);
        }
    }
    Ok(())
}