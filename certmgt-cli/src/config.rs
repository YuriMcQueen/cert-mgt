use certmgt_lib::CertificateConfig;
use dirs::home_dir;
use rpassword::read_password;
use serde::{Deserialize, Serialize};
use std::path::Path;
use std::{collections::HashMap, fs, io, path::PathBuf};
use toml::value::Time;

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(untagged)]
pub enum PasswordSourceConfig {
    /// A flat list of passwords to try for every p12
    List(Vec<String>),

    /// Explicit mapping from filename to password
    Map(HashMap<String, String>),
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TuiConfig {
    pub default_database_path: Option<String>,
    pub auto_load_default: bool,
    pub color_theme: String,
    pub show_expired_warning: bool,
    pub expiry_warning_days: u32,
    pub recent_databases: Vec<String>,
    pub max_recent_databases: usize,

    #[serde(default)]
    pub p12_passwords: Option<PasswordSourceConfig>,
}

impl TuiConfig {
    pub fn p12_passwords_print(&self) -> String {
        match self.p12_passwords {
            Some(PasswordSourceConfig::Map(ref map)) => map
                .iter()
                .map(|(x, y)| format!("{}:{}", x, y))
                .collect::<Vec<_>>()
                .join(","),
            Some(PasswordSourceConfig::List(ref list)) => list.join(","),
            None => String::from(""),
        }
    }
}
impl Default for TuiConfig {
    fn default() -> Self {
        Self {
            default_database_path: None,
            auto_load_default: true,
            color_theme: "default".to_string(),
            show_expired_warning: true,
            expiry_warning_days: 30,
            recent_databases: Vec::new(),
            max_recent_databases: 5,
            p12_passwords: None,
        }
    }
}

impl TuiConfig {
    pub fn load() -> Self {
        if let Some(config_path) = Self::config_file_path() {
            if config_path.exists() {
                match fs::read_to_string(&config_path) {
                    Ok(content) => match toml::from_str(&content) {
                        Ok(config) => return config,
                        Err(e) => eprintln!("Warning: Failed to parse config file: {}", e),
                    },
                    Err(e) => eprintln!("Warning: Failed to read config file: {}", e),
                }
            }
        }
        Self::default()
    }

    pub fn save(&self) -> Result<(), Box<dyn std::error::Error>> {
        if let Some(config_path) = Self::config_file_path() {
            if let Some(parent) = config_path.parent() {
                fs::create_dir_all(parent)?;
            }
            let content = toml::to_string_pretty(self)?;
            fs::write(config_path, content)?;
        }
        Ok(())
    }

    pub fn config_file_path() -> Option<PathBuf> {
        home_dir().map(|mut path| {
            path.push(".config");
            path.push("certmgt");
            path.push("tui-config.toml");
            path
        })
    }

    pub fn add_recent_database(&mut self, path: &str) {
        self.recent_databases.retain(|p| p != path);
        self.recent_databases.insert(0, path.to_string());
        self.recent_databases.truncate(self.max_recent_databases);
    }

    /// Try to unlock a p12 using map first, then list, then prompt.
    pub fn try_passwords_for_file(&self, file_path: &std::path::Path) -> Option<CertificateConfig> {
        let file_name = file_path.file_name()?.to_string_lossy().to_string();
        eprintln!("DEBUG: Loaded p12_passwords = {:?}", self.p12_passwords);
        // 1. Try explicit map
        if let Some(PasswordSourceConfig::Map(map)) = &self.p12_passwords {
            if let Some(pw) = map.get(&file_name) {
                if let Ok(config) =
                    CertificateConfig::read_from_path(file_path.to_str().unwrap(), Some(pw))
                {
                    return Some(config);
                } else {
                    eprintln!("Warning: Failed to read config file: {}", file_name);
                }
            }
        }

        // 2. Try list
        if let Some(PasswordSourceConfig::List(list)) = &self.p12_passwords {
            for pw in list {
                if let Ok(config) =
                    CertificateConfig::read_from_path(file_path.to_str().unwrap(), Some(pw))
                {
                    return Some(config);
                } else {
                    eprintln!("Warning: Failed to read config file: {}", file_name);
                }
            }
        }

        // 3. Fallback to interactive input
        // (optional: only if in TUI/CLI context)
        println!("Enter password for {}: ", file_name);
        if let Ok(password) = read_password() {
            if !password.is_empty() {
                if let Ok(config) =
                    CertificateConfig::read_from_path(file_path.to_str().unwrap(), Some(&password))
                {
                    return Some(config);
                }
            }
        }

        None
    }
}

pub fn load_passwords(path: &Path) -> io::Result<PasswordSourceConfig> {
    use std::io::BufRead;
    let file = std::fs::File::open(path)?;
    let reader = io::BufReader::new(file);

    let mut map = HashMap::new();
    let mut list = Vec::new();

    for line in reader.lines() {
        if let Ok(l) = line {
            let line = l.trim();
            if line.is_empty() || line.starts_with('#') {
                continue;
            }
            if let Some((fname, pw)) = line.split_once('=') {
                map.insert(fname.trim().to_string(), pw.trim().to_string());
            } else {
                list.push(line.to_string());
            }
        }
    }

    if !map.is_empty() {
        Ok(PasswordSourceConfig::Map(map))
    } else {
        Ok(PasswordSourceConfig::List(list))
    }
}
