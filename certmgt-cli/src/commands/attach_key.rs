use crate::json::{attach_private_key_to_certificate, list_all_certificate_names};
use certmgt_lib::CertMgtError;
use std::io::{self, Write};
use std::path::PathBuf;

fn die(msg: &str) -> ! {
    eprintln!("{msg}");
    std::process::exit(1);
}

fn print_attach_result(result: &crate::json::AttachKeyResult, replaced: bool) {
    println!(
        "✅ Private key attached to certificate '{}'",
        result.certificate_common_name
    );
    if result.key_was_encrypted {
        println!("   (Key was encrypted and successfully decrypted)");
    }
    if replaced || result.had_existing_key {
        println!("   (Replaced existing private key)");
    }
}

pub fn run(
    database: PathBuf,
    common_name: String,
    key_path: PathBuf,
    key_password: Option<String>,
) -> anyhow::Result<()> {
    // Check if certificate exists and get available certificates for better error messages
    let available_certs = match list_all_certificate_names(&database) {
        Ok(certs) => certs,
        Err(e) => die(&format!("Error loading certificate database: {e}")),
    };

    // Check if the target certificate exists
    if !available_certs.contains(&common_name) {
        eprintln!("Certificate with common name '{common_name}' not found");
        eprintln!("Available certificates:");
        for cert_name in available_certs {
            eprintln!("  - {cert_name}");
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
            print_attach_result(&result, false);
            return Ok(());
        }
        Err(CertMgtError::InvalidPrivateKey(msg)) if msg.contains("already has a private key") => {
            // Key already exists, ask for confirmation
            eprintln!("Certificate '{common_name}' already has a private key attached.");
            eprint!("Do you want to replace it? (y/N): ");
            io::stdout().flush()?;

            let mut response = String::new();
            io::stdin().read_line(&mut response)?;
            response.trim().to_lowercase().starts_with('y')
        }
        Err(e) => {
            eprintln!("❌ Error attaching private key: {e}");
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
            Ok(result) => print_attach_result(&result, true),
            Err(e) => die(&format!("❌ Error attaching private key: {e}")),
        }
    } else {
        println!("Operation cancelled.");
    }
    Ok(())
}
