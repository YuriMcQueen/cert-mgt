use super::*;
#[cfg(test)]
mod tests {


    #[test]
    fn test_detect_pem_cert_and_key() {
        let pem = b"-----BEGIN CERTIFICATE-----
MIID...
-----END CERTIFICATE-----
-----BEGIN PRIVATE KEY-----
MIIE...
-----END PRIVATE KEY-----";

        let result = detect_cert_type(pem).unwrap();
        assert_eq!(matches!(result, CertDataType::PemCertAndKey), true);
    }

    #[test]
    fn test_detect_pem_only_cert() {
        let pem = b"-----BEGIN CERTIFICATE-----
MIID...
-----END CERTIFICATE-----";

        let result = detect_cert_type(pem).unwrap();
        assert_eq!(matches!(result, CertDataType::PemOnlyCert), true);
    }

    #[test]
    fn test_detect_pem_only_key() {
        let pem = b"-----BEGIN PRIVATE KEY-----
MIIE...
-----END PRIVATE KEY-----";

        let result = detect_cert_type(pem).unwrap();
        assert_eq!(matches!(result, CertDataType::PemOnlyKey), true);
    }

    #[test]
    fn test_detect_p12_raw_binary() {
        let p12 = &[0x30, 0x82, 0x04, 0xB0]; // Mock raw DER
        let result = detect_cert_type(p12).unwrap();
        assert!(matches!(result, CertDataType::P12 { as_base64: false }));
    }

    #[test]
    fn test_detect_p12_base64() {
        // Base64 of &[0x30, 0x82, 0x04, 0xB0]
        let base64_p12 = base64::encode(&[0x30, 0x82, 0x04, 0xB0]);
        let result = detect_cert_type(base64_p12.as_bytes()).unwrap();
        assert!(matches!(result, CertDataType::P12 { as_base64: true }));
    }

    #[test]
    fn test_invalid_format() {
        let garbage = b"This is not a certificate";
        let result = detect_cert_type(garbage);
        assert!(result.is_err());
    }
}