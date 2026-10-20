use certmgt_lib::CertData;
use certmgt_lib::CertificateConfig;

fn cert_type_label(config: &CertificateConfig) -> &'static str {
    match &config.cert_data {
        CertData::Pem { key, .. } => {
            if key.is_some() {
                "PEM+Key"
            } else {
                "PEM"
            }
        }
        CertData::P12 { as_base64, .. } => {
            if *as_base64 {
                "P12(B64)"
            } else {
                "P12"
            }
        }
    }
}

fn expires_in_days(config: &CertificateConfig) -> i64 {
    (config.not_after.timestamp() - chrono::Utc::now().timestamp()) / 86400
}

fn expiry_status(expires_in_days: i64) -> &'static str {
    if expires_in_days < 0 {
        "EXPIRED"
    } else if expires_in_days < 30 {
        "EXPIRING"
    } else {
        "VALID"
    }
}

pub fn display_summary(configs: &[CertificateConfig], show_content: bool) {
    println!("Found {} certificate(s):", configs.len());
    for (idx, config) in configs.iter().enumerate() {
        let expires_in_days = expires_in_days(config);
        println!(
            "{:3}: {} | {} | {} | {} days | {}",
            idx + 1,
            config.common_name.chars().take(30).collect::<String>(),
            cert_type_label(config),
            expiry_status(expires_in_days),
            expires_in_days,
            if config.is_ca { "CA" } else { "CERT" }
        );

        if show_content {
            display_certificate_content(config, idx + 1);
        }
    }
}

pub fn display_detailed(configs: &[CertificateConfig], show_content: bool) {
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
        println!("  ID: {}", config.id);
        println!("  Is CA: {}", config.is_ca);
        println!(
            "  Issuer: {}",
            config
                .ca_id
                .as_deref()
                .and_then(|id| configs.iter().find(|c| c.id == id))
                .map(|c| c.common_name.clone())
                .unwrap_or_else(|| {
                    if config.is_ca {
                        "(self-signed)".to_string()
                    } else {
                        config.issuer_dn.clone()
                    }
                })
        );
        println!("  Key Size: {:?}", config.key_size);
        println!("  Has Private Key: {}", config.has_private_key());

        // Format timestamps
        let not_before = config
            .not_before
            .format("%Y-%m-%d %H:%M:%S UTC")
            .to_string();
        let not_after = config.not_after.format("%Y-%m-%d %H:%M:%S UTC").to_string();

        println!("  Valid From: {}", not_before);
        println!("  Valid Until: {}", not_after);

        let expires_in_days = expires_in_days(config);
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
            CertData::Pem { cert, key } => {
                println!("  Format: PEM");
                println!("  Certificate Length: {} bytes", cert.len());
                if let Some(key_data) = key {
                    println!("  Private Key Length: {} bytes", key_data.len());
                } else {
                    println!("  Private Key: Not included");
                }
            }
            CertData::P12 {
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

pub fn display_json(configs: &[CertificateConfig], show_content: bool) -> anyhow::Result<()> {
    // Create a simplified structure for JSON output
    let json_configs: Vec<serde_json::Value> = configs
        .iter()
        .map(|config| {
            let cert_type_info = match &config.cert_data {
                CertData::Pem { key, cert } => {
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
                CertData::P12 {
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
            "id": config.id,
            "common_name": config.common_name,
            "organization": config.organization,
            "organizational_unit": config.organizational_unit,
            "country": config.country,
            "state": config.state,
            "locality": config.locality,
            "is_ca": config.is_ca,
            "issuer": config
                .ca_id
                .as_deref()
                .and_then(|id| configs.iter().find(|c| c.id == id))
                .map(|c| c.common_name.clone())
                .unwrap_or_else(|| {
                    if config.is_ca {
                        "self".to_string()
                    } else {
                        config.issuer_dn.clone()
                    }
                }),
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

pub fn display_table(configs: &[CertificateConfig]) {
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
        "{:<3} | {:<width_cn$} | {:<width_org$} | {:<8} | {:<10} | {:<6} | {:<4} | {:<25}",
        "#",
        "Common Name",
        "Organization",
        "Type",
        "Expires",
        "Status",
        "CA",
        "Issuer",
        width_cn = max_cn,
        width_org = max_org
    );

    println!(
        "{}",
        "-".repeat(3 + 3 + max_cn + 3 + max_org + 3 + 8 + 3 + 10 + 3 + 6 + 3 + 4 + 3 + 25)
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

        let issuer = config
            .ca_id
            .as_deref()
            .and_then(|id| configs.iter().find(|c| c.id == id))
            .map(|c| c.common_name.clone())
            .unwrap_or_else(|| {
                if config.is_ca {
                    "self".to_string()
                } else if config.issuer_dn.len() > 25 {
                    format!(
                        "{}...",
                        config.issuer_dn.chars().take(22).collect::<String>()
                    )
                } else {
                    config.issuer_dn.clone()
                }
            });

        let cert_type = match &config.cert_data {
            CertData::Pem { key, .. } => {
                if key.is_some() {
                    "PEM+Key"
                } else {
                    "PEM"
                }
            }
            CertData::P12 { .. } => "P12",
        };

        let expires_in_days = expires_in_days(config);
        let expires_str = if expires_in_days < 0 {
            format!("{}d ago", -expires_in_days)
        } else {
            format!("{}d", expires_in_days)
        };

        println!(
            "{:<3} | {:<width_cn$} | {:<width_org$} | {:<8} | {:<10} | {:<6} | {:<4} | {:<25}",
            idx + 1,
            cn,
            org,
            cert_type,
            expires_str,
            expiry_status(expires_in_days),
            if config.is_ca { "YES" } else { "NO" },
            issuer,
            width_cn = max_cn,
            width_org = max_org
        );
    }
}

pub fn display_certificate_content(config: &CertificateConfig, index: usize) {
    println!("\n{}", "-".repeat(50));
    println!("Certificate {} Content:", index);
    println!("{}", "-".repeat(50));

    match &config.cert_data {
        CertData::Pem { cert, key } => {
            println!("📄 Certificate (PEM):");
            println!("{}", cert);

            if let Some(key_data) = key {
                println!("\n🔑 Private Key (PEM):");
                println!("{}", key_data);
            } else {
                println!("\n🔑 Private Key: Not included");
            }
        }
        CertData::P12 {
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

pub fn display_content_only(configs: &[CertificateConfig]) {
    for (idx, config) in configs.iter().enumerate() {
        if idx > 0 {
            println!("\n{}", "=".repeat(80));
        }

        println!("Certificate {}: {}", idx + 1, config.common_name);
        display_certificate_content(config, idx + 1);
    }
}
