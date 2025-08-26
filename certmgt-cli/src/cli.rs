use std::path::PathBuf;
use clap::{Parser, Subcommand};

#[derive(Parser)]
#[command(version, about)]
pub(crate) struct Cli {
    #[command(subcommand)]
    pub(crate) cmd: Commands,
}

#[derive(Subcommand)]
pub enum Commands {
    Tui,
    Generate {
        #[arg(long, short = 'n', help = "Expiration in days", default_value = "365")]
        validity_days: u32,
        #[arg(long, short = 'c', help = "Country", default_value = "US")]
        country: String,
        #[arg(long, short = 's', help = "State", default_value = "IL")]
        state: String,
        #[arg(long, short = 'o', help = "Organization", default_value = "Example Inc")]
        organization: String,
        #[arg(long, help = "Common name", default_value = "example.com")]
        common_name: String,
        #[arg(long, help = "Certificate key size", default_value = "2048")]
        key_size: u32,
        #[arg(long, help = "Common name", default_value = "example.com")]
        alt_names: Vec<String>,
        #[arg(long, help = "CA key size", default_value = "2048")]
        ca_key_size: u32,
        #[arg(long, help = "CA expiration in days", default_value = "365")]
        ca_validity_days: u32,
        #[arg(long, help = "Output database file (.json or .json.gz)")]
        database: PathBuf,

    },
    /// Read certificates from a file (JSON, parquet, PEM, or P12) and display them
    Read {
        #[arg(long)]
        path: PathBuf,
        #[arg(long)]
        password: Option<String>,
        #[arg(
            long,
            help = "Output format: summary, detailed, json, table",
            default_value = "summary"
        )]
        format: String,
        #[arg(long, help = "Show certificate content (PEM data)")]
        show_content: bool,
        #[arg(
            long,
            help = "Filter expressions (e.g., 'common_name~example', 'is_ca==true', 'not_after<=1672531200')"
        )]
        filters: Vec<String>,
        #[arg(long, help = "Use OR logic between filters (default: AND)")]
        or_logic: bool,
    },
    /// Import certificate files (PEM/P12) into a JSON database
    Import {
        #[arg(long, value_name = "CERTS...")]
        inputs: Vec<PathBuf>,
        #[arg(long, help = "Output database file (.json or .json.gz)")]
        database: PathBuf,
        #[arg(long, help = "Use compressed JSON format")]
        compressed: bool,
        #[arg(long, help = "Overwrite duplicates")]
        force: bool,
        #[arg(long, help = "path to p12 passwords file")]
        password_file: Option<PathBuf>,
    },
    /// Export certificates from JSON database to individual files in their original format
    Export {
        #[arg(long, help = "Input database file (.json or .json.gz)")]
        database: PathBuf,
        #[arg(long)]
        output_dir: PathBuf,
        #[arg(
            long,
            help = "Advanced filter expressions (e.g., 'common_name~example')"
        )]
        filters: Vec<String>,
        #[arg(long, help = "Use OR logic between filters (default: AND)")]
        or_logic: bool,
        #[arg(
            long,
            help = "[DEPRECATED] Filter by common name pattern - use --filters 'common_name~PATTERN' instead"
        )]
        filter: Option<String>,
        #[arg(
            long,
            help = "[DEPRECATED] Filter by organization - use --filters 'organization~PATTERN' instead"
        )]
        org_filter: Option<String>,
        #[arg(
            long,
            help = "[DEPRECATED] Export only CA certificates - use --filters 'is_ca==true' instead"
        )]
        ca_only: bool,
    },

    /// List certificates that match specific criteria (convenience commands)
    List {
        #[arg(long, help = "Input database file (.json or .json.gz)")]
        database: PathBuf,
        #[command(subcommand)]
        list_type: ListType,
    },
    /// Attach a private key to an existing PEM certificate in the JSON database
    AttachKey {
        #[arg(long, help = "Database file (.json or .json.gz)")]
        database: PathBuf,
        #[arg(long, help = "Common name of the certificate to update")]
        common_name: String,
        #[arg(long, help = "Path to the private key file")]
        key_path: PathBuf,
        #[arg(long, help = "Password for encrypted private key")]
        key_password: Option<String>,
    },
    /// Convert between different database formats
    Convert {
        #[arg(
            long,
            help = "Input file (supports .json, .json.gz, .parquet for legacy)"
        )]
        input: PathBuf,
        #[arg(long, help = "Output file (.json or .json.gz)")]
        output: PathBuf,
    },
}

#[derive(Subcommand)]
pub enum ListType {
    /// List certificates without private keys
    WithoutKeys,
    /// List CA certificates
    CAs,
    /// List certificates expiring within N days
    Expiring {
        #[arg(help = "Number of days ahead to check")]
        days: i64,
    },
    /// List expired certificates
    Expired,
    /// List certificates by organization pattern
    ByOrg {
        #[arg(help = "Organization pattern to match")]
        pattern: String,
    },
    /// List certificates by common name pattern
    ByCN {
        #[arg(help = "Common name pattern to match")]
        pattern: String,
    },
}