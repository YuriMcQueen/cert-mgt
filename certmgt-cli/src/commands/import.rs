use crate::config::TuiConfig;
use crate::json::import;
use std::path::PathBuf;

pub fn run(
    config: &TuiConfig,
    inputs: Vec<PathBuf>,
    database: PathBuf,
    compressed: bool,
    force: bool,
    password_file: Option<PathBuf>,
) -> anyhow::Result<()> {
    import(
        config,
        inputs,
        database,
        compressed,
        force,
        password_file,
        true,
    )?;
    Ok(())
}
