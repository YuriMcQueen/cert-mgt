use base64::prelude::BASE64_STANDARD;
use base64::{
    Engine as _, alphabet,
    engine::{self, general_purpose},
};
use chrono::NaiveDateTime;
use openssl::asn1::{Asn1Time, Asn1TimeRef};
use openssl::nid::Nid;
use openssl::pkcs12::Pkcs12;
use openssl::pkey::{PKey, Private};
use openssl::x509::{X509, X509NameRef};
use polars::prelude::*;
use std::error::Error;
use std::path::Path;

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
#[derive(Debug, Clone)]
pub struct CertificateConfig {
    pub country: String,
    pub state: String,
    pub locality: String,
    pub organization: String,
    pub organizational_unit: String,
    pub common_name: String,
    pub is_ca: bool,
    pub not_after: i64,
    pub not_before: i64,
    pub key_size: Option<u32>,
    pub cert_type: CertType,
    pub cert_pem: Option<String>,
    pub key_pem: Option<String>,
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
#[derive(Debug, Clone)]
pub enum CertType {
    Pem,
    P12 { password: String, as_base64: bool },
}
#[derive(Debug)]
pub enum CertDataType {
    PemOnlyCert,
    PemOnlyKey,
    PemCertAndKey,
    P12 { as_base64: bool },
}
impl CertificateConfig {
    pub fn read_from_path(path: &str, password: Option<&str>) -> Result<Self, Box<dyn Error>> {
        let bytes = std::fs::read(path)?;
        let cert_type = detect_cert_type(&bytes)?;
        match cert_type {
            CertDataType::PemCertAndKey => {
                let content = std::str::from_utf8(&bytes)?;
                let cert = X509::from_pem(content.as_bytes())?;
                let key = PKey::private_key_from_pem(content.as_bytes())?;

                // Extract just the certificate part
                let cert_pem = String::from_utf8(cert.to_pem()?)?;
                // Extract just the private key part
                let key_pem = String::from_utf8(key.private_key_to_pem_pkcs8()?)?;

                Ok(Self::from_x509_and_key(
                    cert,
                    Some(key),
                    CertType::Pem,
                    Some(cert_pem),
                    Some(key_pem),
                ))
            }

            CertDataType::PemOnlyCert => {
                let cert = X509::from_pem(&bytes)?;

                let cert_pem = String::from_utf8(cert.to_pem()?)?;

                Ok(Self::from_x509_and_key(
                    cert,
                    None,
                    CertType::Pem,
                    Some(cert_pem),
                    None,
                ))
            }

            CertDataType::PemOnlyKey => {
                Err("PEM file contains only private key, certificate missing".into())
            }

            CertDataType::P12 { as_base64 } => {
                let raw = if as_base64 {
                    // Need to filter whitespace from the original content before decoding
                    let content = std::str::from_utf8(&bytes)?;
                    let filtered: String = content.chars().filter(|c| !c.is_whitespace()).collect();
                    BASE64_STANDARD.decode(&filtered)?
                } else {
                    bytes
                };
                let parsed = Pkcs12::from_der(&raw)?.parse2(password.unwrap_or(""))?;

                let cert = parsed.cert.ok_or("Missing cert in P12")?;
                let key = parsed.pkey.ok_or("Missing key in P12")?;

                let cert_pem = String::from_utf8(cert.to_pem()?)?;
                let key_pem = String::from_utf8(key.private_key_to_pem_pkcs8()?)?;

                Ok(Self::from_x509_and_key(
                    cert,
                    Some(key),
                    CertType::P12 {
                        password: password.unwrap_or("").to_string(),
                        as_base64,
                    },
                    Some(cert_pem),
                    Some(key_pem),
                ))
            }
        }
    }

    fn from_x509_and_key(
        cert: X509,
        key: Option<PKey<Private>>,
        cert_type: CertType,
        cert_pem: Option<String>,
        key_pem: Option<String>,
    ) -> Self {
        // Example: extract common name, is_ca, and other fields here
        let subject_name = cert.subject_name();
        let country = parse_cert_field(subject_name, Nid::COUNTRYNAME).unwrap_or_default();
        let state = parse_cert_field(subject_name, Nid::STATEORPROVINCENAME).unwrap_or_default();
        let locality = parse_cert_field(subject_name, Nid::LOCALITYNAME).unwrap_or_default();
        let organization =
            parse_cert_field(subject_name, Nid::ORGANIZATIONNAME).unwrap_or_default();
        let organizational_unit =
            parse_cert_field(subject_name, Nid::ORGANIZATIONALUNITNAME).unwrap_or_default();
        let is_ca = subject_name
            .entries_by_nid(openssl::nid::Nid::BASIC_CONSTRAINTS)
            .into_iter()
            .map(|entry| entry.data().as_slice())
            .any(|data| data.windows(5).any(|w| w == b"CA:TRUE"));
        let common_name = parse_cert_field(subject_name, Nid::COMMONNAME).unwrap_or_default();
        let not_after = asn1_time_to_timestamp(cert.not_after());
        let not_before = asn1_time_to_timestamp(cert.not_before());
        let key_size = match &key {
            Some(key) => Some(key.bits()),
            None => None,
        };
        CertificateConfig {
            country,
            state,
            locality,
            organization,
            organizational_unit,
            common_name,
            is_ca,
            not_after,
            not_before,
            key_size,
            cert_type,
            cert_pem,
            key_pem,
        }
    }
    pub fn to_dataframe(configs: Vec<CertificateConfig>) -> PolarsResult<DataFrame> {
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
        let mut has_cert_pems = Vec::new();
        let mut has_key_pems = Vec::new();

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

            // Convert cert type to string for storage
            let cert_type_str = match config.cert_type {
                CertType::Pem => "PEM".to_string(),
                CertType::P12 {
                    password: _,
                    as_base64,
                } => {
                    if as_base64 {
                        "P12_BASE64".to_string()
                    } else {
                        "P12_BINARY".to_string()
                    }
                }
            };
            cert_types.push(cert_type_str);

            // Store boolean flags instead of full PEM content to save space
            has_cert_pems.push(config.cert_pem.is_some());
            has_key_pems.push(config.key_pem.is_some());
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
            )
            .into_column(),
            Series::new(PlSmallStr::from("is_ca"), is_cas).into_column(),
            Series::new(PlSmallStr::from("not_after"), not_afters).into_column(),
            Series::new(PlSmallStr::from("not_before"), not_befores).into_column(),
            Series::new(PlSmallStr::from("key_size"), key_sizes).into_column(),
            Series::new(PlSmallStr::from("cert_type"), cert_types).into_column(),
            Series::new(PlSmallStr::from("has_cert_pem"), has_cert_pems).into_column(),
            Series::new(PlSmallStr::from("has_key_pem"), has_key_pems).into_column(),
        ])
    }

    pub fn save_to_parquet(configs: Vec<CertificateConfig>, path: &Path) -> PolarsResult<()> {
        let mut df = Self::to_dataframe(configs)?;

        let file = std::fs::File::create(path).map_err(PolarsError::from)?;

        ParquetWriter::new(file)
            .with_compression(ParquetCompression::Snappy)
            .finish(&mut df)?;

        Ok(())
    }
    pub fn save_to_parquet_with_options(
        configs: Vec<CertificateConfig>,
        path: impl AsRef<Path>,
        compression: ParquetCompression,
        statistics: bool,
    ) -> PolarsResult<()> {
        let mut df = Self::to_dataframe(configs)?;

        let file = std::fs::File::create(path).map_err(PolarsError::from)?;
        let mut writer = ParquetWriter::new(file).with_compression(compression);

        if statistics {
            writer = writer.with_statistics(StatisticsOptions::default());
        }

        writer.finish(&mut df)?;
        Ok(())
    }
}
/// Load certificates from Parquet file (basic info only)
pub fn load_from_parquet(path: &Path) -> PolarsResult<DataFrame> {
    LazyFrame::scan_parquet(path, Default::default())?.collect()
}

fn parse_cert_field(cert: &X509NameRef, nid: Nid) -> Option<String> {
    cert.entries_by_nid(nid)
        .next()
        .and_then(|entry| entry.data().as_utf8().ok())
        .map(|data| data.to_string())
}
fn asn1_time_to_timestamp(asn1_time: &Asn1TimeRef) -> i64 {
    let time_str = asn1_time.to_string();
    let ts = time_str.replace(" GMT", "").replace(" UTC", "");

    if let Ok(dt) = NaiveDateTime::parse_from_str(&ts, "%b %e %H:%M:%S %Y") {
        return dt.timestamp();
    }

    // fallback diff code swapped...
    let epoch = Asn1Time::from_unix(0).unwrap();
    match epoch.diff(asn1_time) {
        Ok(diff) => diff.days as i64 * 86400 + diff.secs as i64,
        Err(_) => 0,
    }
}
pub fn detect_cert_type(bytes: &[u8]) -> Result<CertDataType, Box<dyn Error>> {
    // Try interpreting as UTF-8 text (PEM is always text)
    let content = str::from_utf8(bytes).ok();

    if let Some(content) = content {
        let has_cert = content.contains("-----BEGIN CERTIFICATE-----");
        let has_key = content.contains("-----BEGIN PRIVATE KEY-----")
            || content.contains("-----BEGIN ENCRYPTED PRIVATE KEY-----")
            || content.contains("-----BEGIN RSA PRIVATE KEY-----");

        return match (has_cert, has_key) {
            (true, true) => Ok(CertDataType::PemCertAndKey),
            (true, false) => Ok(CertDataType::PemOnlyCert),
            (false, true) => Ok(CertDataType::PemOnlyKey),
            _ => {
                // Remove ALL whitespace characters (including newlines, spaces, tabs, etc.)
                let filtered: String = content.chars().filter(|c| !c.is_whitespace()).collect();

                // Decode the cleaned base64 string directly (not as bytes)
                match BASE64_STANDARD.decode(&filtered) {
                    Ok(decoded) => {
                        println!("Successfully decoded {} bytes", decoded.len());
                        println!(
                            "First 8 bytes: {:02x?}",
                            &decoded[..std::cmp::min(8, decoded.len())]
                        );

                        // P12 files start with ASN.1 SEQUENCE tag (0x30)
                        if decoded.len() >= 2 && decoded[0] == 0x30 {
                            return Ok(CertDataType::P12 { as_base64: true });
                        }

                        Err("Decoded data doesn't appear to be a valid P12 file (missing ASN.1 SEQUENCE header).".into())
                    }
                    Err(e) => {
                        println!("Base64 decode error: {}", e);
                        Err(format!("Failed to decode as base64: {}", e).into())
                    }
                }
            }
        };
    }

    // Try detecting raw binary PKCS#12 (.p12/.pfx)
    if bytes.starts_with(&[0x30, 0x82]) {
        return Ok(CertDataType::P12 { as_base64: false });
    }

    Err("Could not detect certificate format".into())
}

