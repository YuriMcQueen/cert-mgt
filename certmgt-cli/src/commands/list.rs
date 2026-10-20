use crate::cli::ListType;
use crate::db::load_certificates_from_database;
use certmgt_lib::filters::filter_certificates;
use std::path::PathBuf;

fn print_matches(count: usize, configs: impl IntoIterator<Item = (String, String)>, title: &str) {
    println!("{title} ({count} found):");
    for (cn, org) in configs {
        println!("  - {cn} ({org})");
    }
}

pub fn run(database: PathBuf, list_type: ListType) -> anyhow::Result<()> {
    let load = |f: &str| -> anyhow::Result<Vec<_>> {
        let certificates = load_certificates_from_database(&database)?;
        let configs = filter_certificates(certificates, vec![f.to_string()], false)?;
        Ok(configs)
    };

    match list_type {
        ListType::WithoutKeys => {
            let configs = load("has_private_key==false")?;
            println!(
                "Certificates without private keys ({} found):",
                configs.len()
            );
            for config in configs {
                println!("  - {}", config.common_name);
            }
        }

        ListType::CAs => {
            let configs = load("is_ca==true")?;
            print_matches(
                configs.len(),
                configs.into_iter().map(|c| (c.common_name, c.organization)),
                "CA certificates",
            );
        }

        ListType::Expiring { days } => {
            let now = chrono::Utc::now().timestamp();
            let threshold = now + (days * 24 * 60 * 60);
            let certificates = load_certificates_from_database(&database)?;
            let filters = vec![
                format!("not_after<={threshold}"),
                format!("not_after>{now}"),
            ];
            let configs = filter_certificates(certificates, filters, false)?;
            println!(
                "Certificates expiring within {days} days ({} found):",
                configs.len()
            );
            for config in configs {
                let days_left =
                    (config.not_after.timestamp() - chrono::Utc::now().timestamp()) / 86400;
                println!("  - {} (expires in {days_left} days)", config.common_name);
            }
        }

        ListType::Expired => {
            let now = chrono::Utc::now().timestamp();
            let configs = load(&format!("not_after<{now}"))?;
            println!("Expired certificates ({} found):", configs.len());
            for config in configs {
                let days_ago = (now - config.not_after.timestamp()) / 86400;
                println!("  - {} (expired {days_ago} days ago)", config.common_name);
            }
        }

        ListType::ByOrg { pattern } => {
            let configs = load(&format!("organization~{pattern}"))?;
            print_matches(
                configs.len(),
                configs.into_iter().map(|c| (c.common_name, c.organization)),
                &format!("Certificates with organization matching '{pattern}'"),
            );
        }

        ListType::ByCN { pattern } => {
            let configs = load(&format!("common_name~{pattern}"))?;
            println!(
                "Certificates with common name matching '{pattern}' ({} found):",
                configs.len()
            );
            for config in configs {
                println!("  - {}", config.common_name);
            }
        }
    }
    Ok(())
}
