use crate::db::{is_database_file, load_certificates_from_database};
use crate::display;
use certmgt_lib::filters::filter_certificates;
use certmgt_lib::{CertMgtError, CertificateConfig};
use std::path::PathBuf;

fn die(msg: &str) -> ! {
    eprintln!("{msg}");
    std::process::exit(1);
}

pub fn run(
    path: PathBuf,
    password: Option<String>,
    filters: Vec<String>,
    or_logic: bool,
    format: String,
    show_content: bool,
) {
    let configs: Vec<CertificateConfig> = if is_database_file(&path) {
        // Read from database file
        let certificates = load_certificates_from_database(&path)
            .unwrap_or_else(|e| die(&format!("Error loading database: {e}")));
        let filtered_configs = filter_certificates(certificates, filters.clone(), or_logic)
            .unwrap_or_else(|e| die(&format!("Error filtering certificates: {e}")));

        let logic_type = if or_logic { "OR" } else { "AND" };
        println!(
            "Filter results ({} logic): {} certificates found",
            logic_type,
            filtered_configs.len()
        );
        println!(
            "Applied filters: {}",
            filters.join(&format!(" {logic_type} "))
        );
        filtered_configs
    } else {
        // Read single certificate file - wrap in Vec for consistency
        match CertificateConfig::read_from_path(path.to_str().unwrap(), password.as_deref()) {
            Ok(cfg) => vec![cfg],
            Err(e) => {
                // If it's a P12 file and no password was provided, prompt for one
                if matches!(e, CertMgtError::P12WrongPassword) && password.is_none() {
                    die("P12 file requires a password. Please provide it with --password");
                }
                die(&format!("Error reading certificate: {e}"));
            }
        }
    };

    // Display certificates based on format
    match format.as_str() {
        "summary" => display::display_summary(&configs, show_content),
        "detailed" => display::display_detailed(&configs, show_content),
        "json" => display::display_json(&configs, show_content)
            .unwrap_or_else(|e| die(&format!("Error rendering JSON: {e}"))),
        "table" => display::display_table(&configs),
        "content" => display::display_content_only(&configs),
        _ => die(&format!(
            "Unsupported format: {format}. Use: summary, detailed, json, table, content"
        )),
    }
}
