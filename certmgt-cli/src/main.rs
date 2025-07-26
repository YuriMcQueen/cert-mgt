// src/main.rs
use certmgt_lib::{CertificateConfig, ParquetExportOptions};
use clap::{Parser, Subcommand};
use std::path::PathBuf;

#[derive(Parser)]
#[command(version, about)]
struct Cli {
    #[command(subcommand)]
    cmd: Commands,
}

#[derive(Subcommand)]
enum Commands {
    /// Read a certificate and output metadata
    Read {
        #[arg(long)]
        path: PathBuf,
        #[arg(long)]
        password: Option<String>,
    },
    /// Export to Parquet
    Export {
        #[arg(long, value_name = "CERTS...")]
        inputs: Vec<PathBuf>,
        #[arg(long)]
        output: PathBuf,
    },
}

fn main() -> anyhow::Result<()> {
    let cli = Cli::parse();

    match cli.cmd {
        Commands::Read { path, password } => {
            let cfg =
                CertificateConfig::read_from_path(path.to_str().unwrap(), password.as_deref())
                    .unwrap();
            println!("{:#?}", cfg);
        }
        Commands::Export { inputs, output } => {
            let mut configs = Vec::new();
            for p in inputs {
                configs.push(CertificateConfig::read_from_path(p.to_str().unwrap(), None).unwrap());
            }
            let opts = ParquetExportOptions::new();
            certmgt_lib::CertificateConfig::save_to_parquet(configs.clone(), &output)?;
            println!("Exported {} certs to {:?}", configs.len(), output);
        }
    }
    Ok(())
}
