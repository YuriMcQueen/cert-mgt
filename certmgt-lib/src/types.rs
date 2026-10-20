use chrono::{DateTime, TimeZone, Utc};
use serde::{Deserialize, Deserializer, Serialize, Serializer};
use std::fmt;

/// Keeps the on-disk JSON format as unix-seconds i64 (backward compatible)
/// while the in-memory representation is a typed `DateTime<Utc>`.
mod unix_ts {
    use super::*;

    pub fn serialize<S: Serializer>(dt: &DateTime<Utc>, s: S) -> Result<S::Ok, S::Error> {
        s.serialize_i64(dt.timestamp())
    }

    pub fn deserialize<'de, D: Deserializer<'de>>(d: D) -> Result<DateTime<Utc>, D::Error> {
        let ts = i64::deserialize(d)?;
        Utc.timestamp_opt(ts, 0)
            .single()
            .ok_or_else(|| serde::de::Error::custom("invalid unix timestamp"))
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CertificateConfig {
    pub country: String,
    pub state: String,
    pub locality: String,
    pub organization: String,
    pub organizational_unit: String,
    pub common_name: String,
    pub is_ca: bool,
    #[serde(with = "unix_ts")]
    pub not_after: DateTime<Utc>,
    #[serde(with = "unix_ts")]
    pub not_before: DateTime<Utc>,
    pub key_size: Option<usize>,
    pub cert_data: CertData,
    pub serial_number: String,
    /// Stable unique ID for this entry (UUID v4); preserved across re-imports
    pub id: String,
    /// ID of the CA that issued this certificate (`None` for CAs and unknown issuers)
    pub ca_id: Option<String>,
    /// Canonical issuer DN string (display fallback + re-linking)
    pub issuer_dn: String,
}

impl CertificateConfig {
    /// Canonical DN string for this certificate's subject
    pub fn subject_dn(&self) -> String {
        crate::utils::canonical_dn(
            &self.country,
            &self.state,
            &self.locality,
            &self.organization,
            &self.organizational_unit,
            &self.common_name,
        )
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum CertData {
    Pem {
        cert: String,
        key: Option<String>,
    },
    P12 {
        data: String,
        password: String,
        as_base64: bool,
    },
}

impl fmt::Display for CertData {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            CertData::Pem { cert, key } => {
                writeln!(f, "PEM Certificate:")?;
                writeln!(f, "{}", cert.replace("\\n", "\n"))?;
                if let Some(k) = key {
                    writeln!(f, "\nPEM Private Key:")?;
                    writeln!(f, "{}", k.replace("\\n", "\n"))?;
                }
                Ok(())
            }
            CertData::P12 {
                data,
                password,
                as_base64,
            } => {
                writeln!(f, "PKCS#12 certificate (as_base64={}):", as_base64)?;
                writeln!(f, "{}", data.replace("\\n", "\n"))?;
                writeln!(f, "Password: {}", "*".repeat(password.len()))?;
                Ok(())
            }
        }
    }
}

#[derive(Debug)]
pub enum CertDataType {
    PemOnlyCert,
    PemOnlyKey,
    PemCertAndKey,
    P12 { as_base64: bool },
}

#[derive(Debug, Clone)]
pub struct CaConfig {
    pub country: String,
    pub state: String,
    pub organization: String,
    pub common_name: String,
    pub key_size: u32,
    pub validity_days: u32,
}

impl Default for CaConfig {
    fn default() -> Self {
        Self {
            country: "US".to_string(),
            state: "CA".to_string(),
            organization: "My Organization".to_string(),
            common_name: "My CA".to_string(),
            key_size: 2048,
            validity_days: 3650, // 10 years
        }
    }
}

/// Configuration for generating a server certificate
#[derive(Debug, Clone)]
pub struct ServerCertConfig {
    pub country: String,
    pub state: String,
    pub organization: String,
    pub common_name: String,
    pub alt_names: Vec<String>,
    pub key_size: usize,
    pub validity_days: u32,
}

impl Default for ServerCertConfig {
    fn default() -> Self {
        Self {
            country: "US".to_string(),
            state: "CA".to_string(),
            organization: "My Organization".to_string(),
            common_name: "localhost".to_string(),
            alt_names: vec!["localhost".to_string()],
            key_size: 2048,
            validity_days: 365,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample_config() -> CertificateConfig {
        CertificateConfig {
            country: "US".to_string(),
            state: "IL".to_string(),
            locality: "Chicago".to_string(),
            organization: "Test".to_string(),
            organizational_unit: "Unit".to_string(),
            common_name: "example.test".to_string(),
            is_ca: false,
            not_before: Utc.timestamp_opt(1_700_000_000, 0).unwrap(),
            not_after: Utc.timestamp_opt(1_800_000_000, 0).unwrap(),
            key_size: None,
            cert_data: CertData::Pem {
                cert: "MIIB".to_string(),
                key: None,
            },
            serial_number: "1".to_string(),
            id: uuid::Uuid::new_v4().to_string(),
            ca_id: None,
            issuer_dn: "CN=Test CA".to_string(),
        }
    }

    #[test]
    fn timestamps_roundtrip_as_unix_seconds() {
        let config = sample_config();
        // On-disk format must stay integer unix seconds (backward compatible)
        let value = serde_json::to_value(&config).unwrap();
        assert_eq!(value["not_before"], 1_700_000_000i64);
        assert_eq!(value["not_after"], 1_800_000_000i64);

        let restored: CertificateConfig = serde_json::from_value(value).unwrap();
        assert_eq!(restored.not_before, config.not_before);
        assert_eq!(restored.not_after, config.not_after);
    }

    #[test]
    fn legacy_integer_timestamps_deserialize() {
        // Existing databases store bare integers; they must still load.
        let json = r#"{
            "country": "US", "state": "IL", "locality": "",
            "organization": "Test", "organizational_unit": "",
            "common_name": "legacy.test", "is_ca": true,
            "not_before": 1672531200, "not_after": 1988083200,
            "key_size": 2048,
            "cert_data": { "Pem": { "cert": "MIIB", "key": "LS0t" } },
            "serial_number": "1",
            "id": "00000000-0000-4000-8000-000000000000",
            "ca_id": null,
            "issuer_dn": "CN=legacy.test"
        }"#;
        let config: CertificateConfig = serde_json::from_str(json).unwrap();
        assert_eq!(
            config.not_before,
            Utc.timestamp_opt(1_672_531_200, 0).unwrap()
        );
        assert_eq!(
            config.not_after,
            Utc.timestamp_opt(1_988_083_200, 0).unwrap()
        );
    }
}
