use crate::db::load_certificates_from_database;
use crate::json::export_all_certificates;
use certmgt_lib::filters::filter_certificates;
use std::path::PathBuf;

fn die(msg: &str) -> ! {
    eprintln!("{msg}");
    std::process::exit(1);
}

pub fn run(
    database: PathBuf,
    output_dir: PathBuf,
    filters: Vec<String>,
    or_logic: bool,
    filter: Option<String>,
    org_filter: Option<String>,
    ca_only: bool,
) -> anyhow::Result<()> {
    // Handle deprecated options by converting them to new filter format
    let mut all_filters = filters;

    // Convert deprecated options to new filter format
    if let Some(pattern) = filter {
        eprintln!(
            "⚠️  WARNING: --filter is deprecated. Use --filters 'common_name~{}' instead",
            pattern
        );
        all_filters.push(format!("common_name~{pattern}"));
    }

    if let Some(org_pattern) = org_filter {
        eprintln!(
            "⚠️  WARNING: --org-filter is deprecated. Use --filters 'organization~{}' instead",
            org_pattern
        );
        all_filters.push(format!("organization~{org_pattern}"));
    }

    if ca_only {
        eprintln!("⚠️  WARNING: --ca-only is deprecated. Use --filters 'is_ca==true' instead");
        all_filters.push("is_ca==true".to_string());
    }
    let certificates = load_certificates_from_database(&database)?;

    let filtered_configs = if all_filters.is_empty() {
        certificates
    } else {
        // Apply advanced filtering
        match filter_certificates(certificates, all_filters, or_logic) {
            Ok(configs) => configs,
            Err(e) => die(&format!("Error filtering certificates: {e}")),
        }
    };

    println!(
        "Found {} certificates matching filters",
        filtered_configs.len()
    );

    // Export the filtered certificates
    let exported_files = match export_all_certificates(&filtered_configs, &output_dir) {
        Ok(files) => files,
        Err(e) => die(&format!("Error exporting certificates: {e}")),
    };

    println!(
        "Successfully exported {} certificates to {}:",
        exported_files.len(),
        output_dir.display()
    );
    for file in &exported_files {
        println!("  - {file}");
    }
    Ok(())
}
