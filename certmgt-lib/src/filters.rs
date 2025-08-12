use crate::{
    CertData, CertMgtError, CertificateConfig,
};
use std::path::Path;
use std::str::FromStr;

// Filter operations
#[derive(Debug, Clone, PartialEq)]
pub enum FilterOp {
    Equal,
    NotEqual,
    Contains,
    NotContains,
    GreaterThan,
    LessThan,
    GreaterThanOrEqual,
    LessThanOrEqual,
}

impl FromStr for FilterOp {
    type Err = CertMgtError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s {
            "==" | "eq" => Ok(FilterOp::Equal),
            "!=" | "ne" => Ok(FilterOp::NotEqual),
            "~" | "contains" => Ok(FilterOp::Contains),
            "!~" | "not_contains" => Ok(FilterOp::NotContains),
            ">" | "gt" => Ok(FilterOp::GreaterThan),
            "<" | "lt" => Ok(FilterOp::LessThan),
            ">=" | "gte" => Ok(FilterOp::GreaterThanOrEqual),
            "<=" | "lte" => Ok(FilterOp::LessThanOrEqual),
            _ => Err(CertMgtError::FilterError(format!(
                "Unknown filter operation: {}",
                s
            ))),
        }
    }
}

// Filter fields
#[derive(Debug, Clone, PartialEq)]
pub enum FilterField {
    CommonName,
    Organization,
    NotAfter,
    NotBefore,
    IsCA,
    HasPrivateKey,
}

impl FromStr for FilterField {
    type Err = CertMgtError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s.to_lowercase().as_str() {
            "common_name" | "cn" => Ok(FilterField::CommonName),
            "organization" | "org" | "o" => Ok(FilterField::Organization),
            "not_after" | "expires" | "expiry" => Ok(FilterField::NotAfter),
            "not_before" | "valid_from" => Ok(FilterField::NotBefore),
            "is_ca" | "ca" => Ok(FilterField::IsCA),
            "has_private_key" | "has_key" | "key" => Ok(FilterField::HasPrivateKey),
            _ => Err(CertMgtError::FilterError(format!(
                "Unknown filter field: {}",
                s
            ))),
        }
    }
}

// Filter value types
#[derive(Debug, Clone, PartialEq)]
pub enum FilterValue {
    String(String),
    Number(i64),
    Boolean(bool),
}

impl FromStr for FilterValue {
    type Err = CertMgtError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        // Try boolean first
        if let Ok(b) = s.parse::<bool>() {
            return Ok(FilterValue::Boolean(b));
        }

        // Try number
        if let Ok(n) = s.parse::<i64>() {
            return Ok(FilterValue::Number(n));
        }

        // Default to string
        Ok(FilterValue::String(s.to_string()))
    }
}

// Complete filter expression
#[derive(Debug, Clone)]
pub struct FilterExpression {
    pub field: FilterField,
    pub operation: FilterOp,
    pub value: FilterValue,
}

impl FromStr for FilterExpression {
    type Err = CertMgtError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        // Find the operation in the string
        let operators = [">=", "<=", "==", "!=", "!~", ">", "<", "~"];

        for op_str in &operators {
            if let Some(pos) = s.find(op_str) {
                let field_str = s[..pos].trim();
                let value_str = s[pos + op_str.len()..].trim();

                let field = FilterField::from_str(field_str)?;
                let operation = FilterOp::from_str(op_str)?;
                let value = FilterValue::from_str(value_str)?;

                return Ok(FilterExpression {
                    field,
                    operation,
                    value,
                });
            }
        }

        Err(CertMgtError::FilterError(format!(
            "Invalid filter expression: {}",
            s
        )))
    }
}

// Multiple filters with AND/OR logic
#[derive(Debug, Clone)]
pub enum FilterLogic {
    And(Vec<FilterExpression>),
    Or(Vec<FilterExpression>),
    Single(FilterExpression),
}

impl FilterLogic {
    pub fn from_strings(filters: Vec<String>, use_or: bool) -> Result<Self, CertMgtError> {
        if filters.is_empty() {
            return Err(CertMgtError::FilterError("No filters provided".to_string()));
        }

        if filters.len() == 1 {
            let expr = FilterExpression::from_str(&filters[0])?;
            return Ok(FilterLogic::Single(expr));
        }

        let expressions: Result<Vec<_>, _> = filters
            .into_iter()
            .map(|f| FilterExpression::from_str(&f))
            .collect();

        let expressions = expressions?;

        if use_or {
            Ok(FilterLogic::Or(expressions))
        } else {
            Ok(FilterLogic::And(expressions))
        }
    }
    pub fn matches(&self, config: &CertificateConfig) -> bool {
        match self {
            FilterLogic::Single(expr) => expr.matches(config),
            FilterLogic::And(expressions) => expressions.iter().all(|expr| expr.matches(config)),
            FilterLogic::Or(expressions) => expressions.iter().any(|expr| expr.matches(config)),
        }
    }
}

// Filter application logic
impl FilterExpression {
    pub fn matches(&self, config: &CertificateConfig) -> bool {
        let field_value = self.extract_field_value(config);
        self.compare_values(&field_value, &self.value)
    }

    fn extract_field_value(&self, config: &CertificateConfig) -> FilterValue {
        match self.field {
            FilterField::CommonName => FilterValue::String(config.common_name.clone()),
            FilterField::Organization => FilterValue::String(config.organization.clone()),
            FilterField::NotAfter => FilterValue::Number(config.not_after),
            FilterField::NotBefore => FilterValue::Number(config.not_before),
            FilterField::IsCA => FilterValue::Boolean(config.is_ca),
            FilterField::HasPrivateKey => {
                let has_key = match &config.cert_data {
                    CertData::Pem { key: Some(_), .. } => true,
                    _ => false,
                };
                FilterValue::Boolean(has_key)
            }
        }
    }

    fn compare_values(&self, field_value: &FilterValue, filter_value: &FilterValue) -> bool {
        match (&self.operation, field_value, filter_value) {
            // String operations
            (FilterOp::Equal, FilterValue::String(a), FilterValue::String(b)) => a == b,
            (FilterOp::NotEqual, FilterValue::String(a), FilterValue::String(b)) => a != b,
            (FilterOp::Contains, FilterValue::String(a), FilterValue::String(b)) => a.contains(b),
            (FilterOp::NotContains, FilterValue::String(a), FilterValue::String(b)) => {
                !a.contains(b)
            }

            // Number operations
            (FilterOp::Equal, FilterValue::Number(a), FilterValue::Number(b)) => a == b,
            (FilterOp::NotEqual, FilterValue::Number(a), FilterValue::Number(b)) => a != b,
            (FilterOp::GreaterThan, FilterValue::Number(a), FilterValue::Number(b)) => a > b,
            (FilterOp::LessThan, FilterValue::Number(a), FilterValue::Number(b)) => a < b,
            (FilterOp::GreaterThanOrEqual, FilterValue::Number(a), FilterValue::Number(b)) => {
                a >= b
            }
            (FilterOp::LessThanOrEqual, FilterValue::Number(a), FilterValue::Number(b)) => a <= b,

            // Boolean operations
            (FilterOp::Equal, FilterValue::Boolean(a), FilterValue::Boolean(b)) => a == b,
            (FilterOp::NotEqual, FilterValue::Boolean(a), FilterValue::Boolean(b)) => a != b,

            // Cross-type comparisons (convert numbers to strings for string operations)
            (FilterOp::Contains, FilterValue::String(a), FilterValue::Number(b)) => {
                a.contains(&b.to_string())
            }
            (FilterOp::NotContains, FilterValue::String(a), FilterValue::Number(b)) => {
                !a.contains(&b.to_string())
            }

            // Default: false for incompatible operations
            _ => false,
        }
    }
}
// Main generic filter function
pub fn filter_certificates(
    certificates: Vec<CertificateConfig>,
    filters: Vec<String>,
    use_or_logic: bool,
) -> Result<Vec<CertificateConfig>, CertMgtError> {

    if filters.is_empty() {
        return Ok(certificates);
    }

    let filter_logic = FilterLogic::from_strings(filters, use_or_logic)?;

    Ok(certificates
        .into_iter()
        .filter(|config| filter_logic.matches(config))
        .collect())
}

// Convenience functions for common operations
pub fn filter_certificates_simple(
    certificates: Vec<CertificateConfig>,
    filter_str: &str,
) -> Result<Vec<CertificateConfig>, CertMgtError> {
    filter_certificates(certificates, vec![filter_str.to_string()], false)
}

// Updated versions of your existing functions using the new filter system
pub fn list_certificates_without_keys(certificates: Vec<CertificateConfig>) -> Result<Vec<String>, CertMgtError> {
    let filtered = filter_certificates_simple(certificates, "has_private_key==false")?;
    Ok(filtered
        .into_iter()
        .map(|config| config.common_name)
        .collect())
}

pub fn find_certificates_by_common_name(
    certificates: Vec<CertificateConfig>,
    common_name: &str,
) -> Result<Vec<CertificateConfig>, CertMgtError> {
    filter_certificates_simple(certificates, &format!("common_name~{}", common_name))
}

pub fn find_certificates_by_organization(
    certificates: Vec<CertificateConfig>,
    organization: &str,
) -> Result<Vec<CertificateConfig>, CertMgtError> {
    filter_certificates_simple(certificates, &format!("organization~{}", organization))
}

pub fn find_expiring_certificates(
    certificates: Vec<CertificateConfig>,
    days_ahead: i64,
) -> Result<Vec<CertificateConfig>, CertMgtError> {
    let threshold = chrono::Utc::now().timestamp() + (days_ahead * 24 * 60 * 60);


    Ok(certificates
        .into_iter()
        .filter(|config| config.not_after <= threshold && config.not_after > 0)
        .collect())
}

pub fn find_ca_certificates(certificates: Vec<CertificateConfig>) -> Result<Vec<CertificateConfig>, CertMgtError> {
    filter_certificates_simple(certificates, "is_ca==true")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_filter_expression_parsing() {
        let expr = FilterExpression::from_str("organization==example").unwrap();
        assert_eq!(expr.field, FilterField::Organization);
        assert_eq!(expr.operation, FilterOp::Equal);
        assert_eq!(expr.value, FilterValue::String("example".to_string()));
    }

    #[test]
    fn test_complex_filters() {
        let filters = vec![
            "organization~example".to_string(),
            "is_ca==true".to_string(),
        ];
        let logic = FilterLogic::from_strings(filters, false).unwrap();
        // This would match certificates where organization contains "example" AND is_ca is true
    }

    #[test]
    fn test_date_filters() {
        let expr = FilterExpression::from_str("not_after<=1234567890").unwrap();
        assert_eq!(expr.field, FilterField::NotAfter);
        assert_eq!(expr.operation, FilterOp::LessThanOrEqual);
        assert_eq!(expr.value, FilterValue::Number(1234567890));
    }
}
