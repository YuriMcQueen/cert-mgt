mod cli;
mod commands;
mod config;
mod db;
mod display;
mod json;
mod tui;

use crate::cli::{Cli, Commands};
use crate::config::TuiConfig;
use clap::Parser;

fn main() -> anyhow::Result<()> {
    let cli = Cli::parse();
    let config = TuiConfig::load();

    match cli.cmd {
        Commands::Tui => tui::launch_tui()?,
        Commands::Read {
            path,
            password,
            filters,
            or_logic,
            format,
            show_content,
        } => {
            commands::read::run(path, password, filters, or_logic, format, show_content);
        }
        Commands::Import {
            inputs,
            database,
            compressed,
            force,
            password_file,
        } => {
            commands::import::run(&config, inputs, database, compressed, force, password_file)?;
        }
        Commands::Export {
            database,
            output_dir,
            filters,
            or_logic,
            filter,
            org_filter,
            ca_only,
        } => {
            commands::export::run(
                database, output_dir, filters, or_logic, filter, org_filter, ca_only,
            )?;
        }
        Commands::List {
            database,
            list_type,
        } => {
            commands::list::run(database, list_type)?;
        }
        Commands::AttachKey {
            database,
            common_name,
            key_path,
            key_password,
        } => {
            commands::attach_key::run(database, common_name, key_path, key_password)?;
        }
        Commands::Convert { input, output } => {
            commands::convert::run(input, output)?;
        }
        Commands::Generate {
            validity_days,
            country,
            state,
            organization,
            common_name,
            key_size,
            alt_names,
            ca_common_name,
            ca_validity_days,
            ca_key_size,
            database,
        } => {
            commands::generate::run(commands::generate::Params {
                validity_days,
                country,
                state,
                organization,
                common_name,
                key_size,
                alt_names,
                ca_common_name,
                ca_validity_days,
                ca_key_size,
                database,
            })?;
        }
    }
    Ok(())
}
