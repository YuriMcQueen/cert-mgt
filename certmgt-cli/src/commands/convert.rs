use crate::db::{is_compressed_file, load_certificates_from_database};
use crate::json::{save_certificates_to_json, save_certificates_to_json_compressed};
use std::path::PathBuf;

pub fn run(input: PathBuf, output: PathBuf) -> anyhow::Result<()> {
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
                "✅ Successfully converted to {} ({format})",
                output.display()
            );
        }
        Err(e) => {
            eprintln!("❌ Error converting: {e}");
            std::process::exit(1);
        }
    }
    Ok(())
}
