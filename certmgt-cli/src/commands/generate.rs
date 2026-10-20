use crate::json::save_database;
use certmgt_lib::CertificateConfig;
use certmgt_lib::types::{CaConfig, ServerCertConfig};
use std::path::PathBuf;

pub struct Params {
    pub validity_days: u32,
    pub country: String,
    pub state: String,
    pub organization: String,
    pub common_name: String,
    pub key_size: u32,
    pub alt_names: Vec<String>,
    pub ca_common_name: String,
    pub ca_validity_days: u32,
    pub ca_key_size: u32,
    pub database: PathBuf,
}

pub fn run(p: Params) -> anyhow::Result<()> {
    let new_ca_config = CaConfig {
        country: p.country.clone(),
        state: p.state.clone(),
        organization: p.organization.clone(),
        common_name: p.ca_common_name,
        key_size: p.ca_key_size,
        validity_days: p.ca_validity_days,
    };

    let new_cert_config = ServerCertConfig {
        country: p.country,
        state: p.state,
        organization: p.organization,
        common_name: p.common_name,
        alt_names: p.alt_names,
        key_size: p.key_size as usize,
        validity_days: p.validity_days,
    };
    let ca = CertificateConfig::new_ca(new_ca_config)?;
    let cert = CertificateConfig::sign_certificate(&ca, &new_cert_config)?;
    save_database(&p.database, false, vec![ca, cert])?;
    println!(
        "✅ Generated CA + certificate for {} -> {}",
        new_cert_config.common_name,
        p.database.display()
    );
    Ok(())
}
