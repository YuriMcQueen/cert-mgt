use polars::prelude::*;
use std::path::Path;
use crate::types::{CertificateConfig, CertType};

#[derive(Default)]
pub struct ParquetExportOptions {
    pub compression: ParquetCompression,
    pub statistics: bool,
    pub row_group_size: Option<usize>,
}

impl ParquetExportOptions {
    pub fn new() -> Self {
        Self {
            compression: ParquetCompression::Snappy,
            statistics: true,
            row_group_size: None,
        }
    }

    pub fn with_compression(mut self, compression: ParquetCompression) -> Self {
        self.compression = compression;
        self
    }
}

#[derive(Default)]
pub enum ParquetCompressionConfig {
    #[default]
    Snappy,
    Gzip,
    Lz4,
    Brotli,
    Zstd,
}

// Free functions for better separation of concerns
pub fn save_certificates_to_parquet(configs: Vec<CertificateConfig>, path: &Path) -> PolarsResult<()> {
    let mut df = certificates_to_dataframe(configs)?;

    let file = std::fs::File::create(path).map_err(PolarsError::from)?;

    ParquetWriter::new(file)
        .with_compression(ParquetCompression::Snappy)
        .finish(&mut df)?;

    Ok(())
}

pub fn save_certificates_to_parquet_with_options(
    configs: Vec<CertificateConfig>,
    path: impl AsRef<Path>,
    compression: ParquetCompression,
    statistics: bool,
) -> PolarsResult<()> {
    let mut df = certificates_to_dataframe(configs)?;

    let file = std::fs::File::create(path).map_err(PolarsError::from)?;
    let mut writer = ParquetWriter::new(file).with_compression(compression);

    if statistics {
        writer = writer.with_statistics(StatisticsOptions::default());
    }

    writer.finish(&mut df)?;
    Ok(())
}

pub fn load_certificates_from_parquet(path: &Path) -> PolarsResult<Vec<CertificateConfig>> {
    // Step 1: scan the Parquet file lazily
    let lf = LazyFrame::scan_parquet(path, ScanArgsParquet::default())?;

    // Step 2: collect into an eager DataFrame
    let df = lf
        .select([
            col("common_name"),
            col("country"),
            col("state"),
            col("locality"),
            col("organization"),
            col("organizational_unit"),
            col("is_ca"),
            col("not_before"),
            col("not_after"),
            col("key_size"),
            col("cert_type"),
            col("cert_pem"),      // Load actual PEM data
            col("key_pem"),       // Load actual key data
            col("p12_password"),  // Load P12 password
        ])
        .collect()?;

    // Step 3: extract columns
    let cn = df.column("common_name")?.str()?;
    let co = df.column("country")?.str()?;
    let st = df.column("state")?.str()?;
    let lo = df.column("locality")?.str()?;
    let or = df.column("organization")?.str()?;
    let ou = df.column("organizational_unit")?.str()?;
    let ca = df.column("is_ca")?.bool()?;
    let nb = df.column("not_before")?.i64()?;
    let na = df.column("not_after")?.i64()?;
    let ks = df.column("key_size")?.u32()?;
    let ct = df.column("cert_type")?.str()?;
    let cp = df.column("cert_pem")?.str()?;
    let kp = df.column("key_pem")?.str()?;
    let pp = df.column("p12_password")?.str()?;

    let mut configs = Vec::with_capacity(df.height());

    for idx in 0..df.height() {
        let cert_type = match ct.get(idx).unwrap_or("PEM") {
            "PEM" => CertType::Pem,
            "P12_BASE64" => CertType::P12 {
                password: pp.get(idx).unwrap_or("").to_string(),
                as_base64: true
            },
            "P12_BINARY" => CertType::P12 {
                password: pp.get(idx).unwrap_or("").to_string(),
                as_base64: false
            },
            _ => CertType::Pem,
        };

        configs.push(CertificateConfig {
            country: co.get(idx).unwrap_or("").to_string(),
            state: st.get(idx).unwrap_or("").to_string(),
            locality: lo.get(idx).unwrap_or("").to_string(),
            organization: or.get(idx).unwrap_or("").to_string(),
            organizational_unit: ou.get(idx).unwrap_or("").to_string(),
            common_name: cn.get(idx).unwrap_or("").to_string(),
            is_ca: ca.get(idx).unwrap_or(false),
            not_before: nb.get(idx).unwrap_or(0),
            not_after: na.get(idx).unwrap_or(0),
            key_size: ks.get(idx),
            cert_type,
            // Load actual certificate data instead of placeholders
            cert_pem: cp.get(idx).filter(|s| !s.is_empty()).map(|s| s.to_string()),
            key_pem: kp.get(idx).filter(|s| !s.is_empty()).map(|s| s.to_string()),
        });
    }

    Ok(configs)
}

/// Load certificates from Parquet file (basic DataFrame only)
pub fn load_dataframe_from_parquet(path: &Path) -> PolarsResult<DataFrame> {
    LazyFrame::scan_parquet(path, ScanArgsParquet::default())?.collect()
}

/// Export a certificate to P12 format
pub fn export_certificate_as_p12(config: &CertificateConfig, output_path: &Path, password: &str) -> Result<(), Box<dyn std::error::Error>> {
    use openssl::pkcs12::Pkcs12;
    use openssl::pkey::PKey;
    use openssl::x509::X509;
    use base64::prelude::BASE64_STANDARD;
    use base64::Engine as _;

    // Get the certificate and key PEM data
    let cert_pem = config.cert_pem.as_ref()
        .ok_or("No certificate PEM data available")?;
    let key_pem = config.key_pem.as_ref()
        .ok_or("No private key PEM data available")?;

    // Parse the PEM data
    let cert = X509::from_pem(cert_pem.as_bytes())?;
    let key = PKey::private_key_from_pem(key_pem.as_bytes())?;

    // Create P12 bundle
    let p12_builder = Pkcs12::builder();
    let p12 = p12_builder.build2(password, &key, &cert)?;

    // Convert to DER format
    let p12_der = p12.to_der()?;

    // Check if we need to base64 encode based on original cert type
    match &config.cert_type {
        CertType::P12 { as_base64: true, .. } => {
            // Export as base64 encoded
            let encoded = BASE64_STANDARD.encode(&p12_der);
            std::fs::write(output_path, encoded)?;
        }
        _ => {
            // Export as binary
            std::fs::write(output_path, p12_der)?;
        }
    }

    Ok(())
}

fn certificates_to_dataframe(configs: Vec<CertificateConfig>) -> PolarsResult<DataFrame> {
    let mut common_names = Vec::new();
    let mut countries = Vec::new();
    let mut states = Vec::new();
    let mut localities = Vec::new();
    let mut organizations = Vec::new();
    let mut organizational_units = Vec::new();
    let mut is_cas = Vec::new();
    let mut not_afters = Vec::new();
    let mut not_befores = Vec::new();
    let mut key_sizes = Vec::new();
    let mut cert_types = Vec::new();
    let mut cert_pems = Vec::new();    // Store actual PEM data
    let mut key_pems = Vec::new();     // Store actual key data
    let mut p12_passwords = Vec::new(); // Store P12 passwords

    for config in configs {
        common_names.push(config.common_name);
        countries.push(config.country);
        states.push(config.state);
        localities.push(config.locality);
        organizations.push(config.organization);
        organizational_units.push(config.organizational_unit);
        is_cas.push(config.is_ca);
        not_afters.push(config.not_after as i64);
        not_befores.push(config.not_before as i64);
        key_sizes.push(config.key_size);

        // Store actual certificate and key data
        cert_pems.push(config.cert_pem.unwrap_or_default());
        key_pems.push(config.key_pem.unwrap_or_default());

        // Convert cert type to string for storage and extract password
        let (cert_type_str, password) = match config.cert_type {
            CertType::Pem => ("PEM".to_string(), String::new()),
            CertType::P12 { password, as_base64 } => {
                let type_str = if as_base64 {
                    "P12_BASE64".to_string()
                } else {
                    "P12_BINARY".to_string()
                };
                (type_str, password)
            }
        };
        cert_types.push(cert_type_str);
        p12_passwords.push(password);
    }

    DataFrame::new(vec![
        Series::new(PlSmallStr::from("common_name"), common_names).into_column(),
        Series::new(PlSmallStr::from("country"), countries).into_column(),
        Series::new(PlSmallStr::from("state"), states).into_column(),
        Series::new(PlSmallStr::from("locality"), localities).into_column(),
        Series::new(PlSmallStr::from("organization"), organizations).into_column(),
        Series::new(
            PlSmallStr::from("organizational_unit"),
            organizational_units,
        ).into_column(),
        Series::new(PlSmallStr::from("is_ca"), is_cas).into_column(),
        Series::new(PlSmallStr::from("not_after"), not_afters).into_column(),
        Series::new(PlSmallStr::from("not_before"), not_befores).into_column(),
        Series::new(PlSmallStr::from("key_size"), key_sizes).into_column(),
        Series::new(PlSmallStr::from("cert_type"), cert_types).into_column(),
        Series::new(PlSmallStr::from("cert_pem"), cert_pems).into_column(),      // Store actual PEM
        Series::new(PlSmallStr::from("key_pem"), key_pems).into_column(),        // Store actual key
        Series::new(PlSmallStr::from("p12_password"), p12_passwords).into_column(), // Store P12 passwords
    ])
}