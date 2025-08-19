// Add this to your main.rs file

use crossterm::{
    event::{self, DisableMouseCapture, EnableMouseCapture, Event, KeyCode},
    execute,
    terminal::{disable_raw_mode, enable_raw_mode, EnterAlternateScreen, LeaveAlternateScreen},
};
use ratatui::{
    backend::{Backend, CrosstermBackend},
    layout::{Constraint, Direction, Layout, Rect, Alignment},
    style::{Color, Modifier, Style},
    text::{Line, Span},
    widgets::{Block, Borders, Clear, List, ListItem, ListState, Paragraph, Wrap},
    Frame, Terminal,
};
use serde::{Deserialize, Serialize};
use std::{fs, io, path::Path};
use std::path::PathBuf;
use crossterm::event::KeyModifiers;
use dirs::home_dir;
use ratatui::layout::Margin;
use certmgt_lib::{CertMgtError, CertificateConfig};
use certmgt_lib::types::{CaConfig, ServerCertConfig};
use crate::json::save_certificates_to_json;
use crate::load_certificates_from_database;

// Configuration management
#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct TuiConfig {
    pub default_database_path: Option<String>,
    pub auto_load_default: bool,
    pub color_theme: String,
    pub show_expired_warning: bool,
    pub expiry_warning_days: i64,
    pub recent_databases: Vec<String>,
    pub max_recent_databases: usize,
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
        }
    }
}

impl TuiConfig {
    pub fn load() -> Self {
        if let Some(config_path) = Self::config_file_path() {
            if config_path.exists() {
                match fs::read_to_string(&config_path) {
                    Ok(content) => {
                        match toml::from_str(&content) {
                            Ok(config) => return config,
                            Err(e) => eprintln!("Warning: Failed to parse config file: {}", e),
                        }
                    }
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
        // Remove if already exists
        self.recent_databases.retain(|p| p != path);
        // Add to front
        self.recent_databases.insert(0, path.to_string());
        // Keep only max_recent_databases
        self.recent_databases.truncate(self.max_recent_databases);
    }
}

// Enhanced App struct with configuration and setup screen
pub struct App {
    pub certificates: Vec<CertificateConfig>,
    pub list_state: ListState,
    pub current_view: ViewMode,
    pub show_help: bool,
    pub status_message: String,
    pub database_path: Option<PathBuf>,
    pub config: TuiConfig,
    pub input_buffer: String,
    pub input_mode: bool,
    pub setup_state: SetupState,
    pub show_generate_popup: bool,
    pub cert_form: Option<CertForm>,
}

#[derive(Clone)]
pub enum ViewMode {
    Setup,
    CertificateList,
    CertificateDetail(usize),
    Help,
    Config,
}
#[derive(Debug, Clone, PartialEq)]
pub struct CertForm {
    pub field_index: usize,
    pub country: String,
    pub state: String,
    pub organization: String,
    pub common_name: String,
    pub alt_names: Vec<String>,
    pub temp_alt_name: String,
    pub key_size: u32,
    pub validity_days: u32,
    pub ca_key_size: u32,
    pub ca_validity_days: u32,
    pub database: String,
    pub fields: Vec<FormField>,
}

#[derive(Debug, Clone, PartialEq)]
pub struct FormField {
    pub name: String,
    pub value: String,
    pub field_type: FieldType,
    pub required: bool,
    pub validation_error: Option<String>,
}

#[derive(Debug, Clone, PartialEq)]
pub enum FieldType {
    Text,
    Number,
    List, // For alt names
}

impl Default for CertForm {
    fn default() -> Self {
        let mut form = Self {
            field_index: 0,
            country: "US".to_string(),  // Default values
            state: "CA".to_string(),
            organization: "My Organization".to_string(),
            common_name: "example.com".to_string(),
            alt_names: Vec::new(),
            temp_alt_name: String::new(),
            key_size: 2048,
            validity_days: 365,
            ca_key_size: 4096,
            ca_validity_days: 3650,
            database: String::new(),
            fields: Vec::new(),
        };
        form.init_fields();
        form
    }
}

impl CertForm {
    fn init_fields(&mut self) {
        self.fields = vec![
            FormField {
                name: "Country".to_string(),
                value: self.country.clone(),
                field_type: FieldType::Text,
                required: true,
                validation_error: None,
            },
            FormField {
                name: "State".to_string(),
                value: self.state.clone(),
                field_type: FieldType::Text,
                required: true,
                validation_error: None,
            },
            FormField {
                name: "Organization".to_string(),
                value: self.organization.clone(),
                field_type: FieldType::Text,
                required: true,
                validation_error: None,
            },
            FormField {
                name: "Common Name".to_string(),
                value: self.common_name.clone(),
                field_type: FieldType::Text,
                required: true,
                validation_error: None,
            },
            FormField {
                name: "Key Size".to_string(),
                value: self.key_size.to_string(),
                field_type: FieldType::Number,
                required: true,
                validation_error: None,
            },
            FormField {
                name: "Validity Days".to_string(),
                value: self.validity_days.to_string(),
                field_type: FieldType::Number,
                required: true,
                validation_error: None,
            },
            FormField {
                name: "CA Key Size".to_string(),
                value: self.ca_key_size.to_string(),
                field_type: FieldType::Number,
                required: true,
                validation_error: None,
            },
            FormField {
                name: "CA Validity Days".to_string(),
                value: self.ca_validity_days.to_string(),
                field_type: FieldType::Number,
                required: true,
                validation_error: None,
            },
            FormField {
                name: "Alt Names".to_string(),
                value: self.temp_alt_name.clone(),
                field_type: FieldType::List,
                required: false,
                validation_error: None,
            },
        ];
    }

    pub fn next_field(&mut self) {
        self.field_index = (self.field_index + 1) % self.fields.len();
    }

    pub fn prev_field(&mut self) {
        if self.field_index == 0 {
            self.field_index = self.fields.len() - 1;
        } else {
            self.field_index -= 1;
        }
    }

    pub fn add_char(&mut self, c: char) {
        if self.field_index < self.fields.len() {
            self.fields[self.field_index].value.push(c);
            self.fields[self.field_index].validation_error = None;
            self.sync_field_values();
        }
    }

    pub fn delete_char(&mut self) {
        if self.field_index < self.fields.len() {
            self.fields[self.field_index].value.pop();
            self.fields[self.field_index].validation_error = None;
            self.sync_field_values();
        }
    }

    fn sync_field_values(&mut self) {
        // Sync form fields back to the main struct
        for (i, field) in self.fields.iter().enumerate() {
            match i {
                0 => self.country = field.value.clone(),
                1 => self.state = field.value.clone(),
                2 => self.organization = field.value.clone(),
                3 => self.common_name = field.value.clone(),
                4 => self.key_size = field.value.parse().unwrap_or(2048),
                5 => self.validity_days = field.value.parse().unwrap_or(365),
                6 => self.ca_key_size = field.value.parse().unwrap_or(4096),
                7 => self.ca_validity_days = field.value.parse().unwrap_or(3650),
                8 => self.temp_alt_name = field.value.clone(),
                _ => {}
            }
        }
    }

    pub fn add_alt_name(&mut self) {
        if !self.temp_alt_name.is_empty() {
            self.alt_names.push(self.temp_alt_name.clone());
            self.temp_alt_name.clear();
            // Update the corresponding field
            if let Some(field) = self.fields.get_mut(8) {
                field.value.clear();
            }
        }
    }

    pub fn remove_alt_name(&mut self, index: usize) {
        if index < self.alt_names.len() {
            self.alt_names.remove(index);
        }
    }

    pub fn validate(&mut self) -> bool {
        let mut is_valid = true;

        for field in &mut self.fields {
            if field.required && field.value.trim().is_empty() {
                field.validation_error = Some("This field is required".to_string());
                is_valid = false;
            } else if field.field_type == FieldType::Number {
                if field.value.parse::<u32>().is_err() {
                    field.validation_error = Some("Must be a valid number".to_string());
                    is_valid = false;
                }
            }
        }

        is_valid
    }
}
#[derive(Clone, PartialEq)]
pub enum SetupState {
    Welcome,
    DatabasePath,
    RecentDatabases,
    ConfigSettings,
}

impl App {
    pub fn new() -> App {
        let config = TuiConfig::load();
        let mut list_state = ListState::default();
        list_state.select(Some(0));

        App {
            certificates: Vec::new(),
            list_state,
            current_view: ViewMode::Setup,
            show_help: false,
            status_message: "Welcome to Certificate Manager TUI".to_string(),
            database_path: None,
            config,
            input_buffer: String::new(),
            input_mode: false,
            setup_state: SetupState::Welcome,
            show_generate_popup: false,
            cert_form: None,
        }
    }

    pub fn load_certificates(&mut self, path: &PathBuf) -> Result<(), CertMgtError> {
        self.certificates = load_certificates_from_database(path)?;
        self.database_path = Some(path.clone());

        // Add to recent databases
        if let Some(path_str) = path.to_str() {
            self.config.add_recent_database(path_str);
            let _ = self.config.save(); // Save config with new recent database
        }

        self.status_message = format!("Loaded {} certificates from {}",
                                      self.certificates.len(), path.display());
        self.current_view = ViewMode::CertificateList;
        Ok(())
    }

    pub fn try_auto_load(&mut self) {
        if self.config.auto_load_default {
            if let Some(default_path) = self.config.default_database_path.clone() {
                let path = PathBuf::from(default_path.clone());
                if path.exists() {
                    if let Err(e) = &self.load_certificates(&path) {
                        self.status_message = format!("Failed to auto-load {}: {}", default_path, e);
                    }
                    return;
                }
            }
        }

        // Try common default locations
        let default_paths = vec![
            PathBuf::from("certificates.json"),
            PathBuf::from("certs.json"),
            PathBuf::from("cert-database.json"),
        ];

        for path in default_paths {
            if path.exists() {
                if let Ok(()) = self.load_certificates(&path) {
                    return;
                }
            }
        }
    }

    pub fn set_database_path(&mut self, path: String) {
        let path_buf = PathBuf::from(&path);
        if path_buf.exists() {
            if let Err(e) = self.load_certificates(&path_buf) {
                self.status_message = format!("Error loading database: {}", e);
            }
        } else {
            self.status_message = format!("File does not exist: {}", path);
        }
    }

    pub fn save_config(&mut self) {
        if let Err(e) = self.config.save() {
            self.status_message = format!("Failed to save config: {}", e);
        } else {
            self.status_message = "Configuration saved successfully".to_string();
        }
    }

    // Navigation methods remain the same...
    pub fn next(&mut self) {
        if self.certificates.is_empty() {
            return;
        }

        let i = match self.list_state.selected() {
            Some(i) => {
                if i >= self.certificates.len() - 1 {
                    0
                } else {
                    i + 1
                }
            }
            None => 0,
        };
        self.list_state.select(Some(i));
    }

    pub fn previous(&mut self) {
        if self.certificates.is_empty() {
            return;
        }

        let i = match self.list_state.selected() {
            Some(i) => {
                if i == 0 {
                    self.certificates.len() - 1
                } else {
                    i - 1
                }
            }
            None => 0,
        };
        self.list_state.select(Some(i));
    }

    pub fn enter_detail_view(&mut self) {
        if let Some(selected) = self.list_state.selected() {
            if selected < self.certificates.len() {
                self.current_view = ViewMode::CertificateDetail(selected);
            }
        }
    }

    pub fn back_to_list(&mut self) {
        match self.current_view {
            ViewMode::Setup => {
                // Can't go back from setup until database is loaded
                self.status_message = "Please select a database first".to_string();
            }
            _ => {
                self.current_view = ViewMode::CertificateList;
                self.show_help = false;
                self.input_mode = false;
            }
        }
    }

    pub fn toggle_help(&mut self) {
        self.show_help = !self.show_help;
        if self.show_help {
            self.current_view = ViewMode::Help;
        } else {
            match self.database_path {
                Some(_) => self.current_view = ViewMode::CertificateList,
                None => self.current_view = ViewMode::Setup,
            }
        }
    }

    pub fn show_config(&mut self) {
        self.current_view = ViewMode::Config;
    }

    pub fn back_to_setup(&mut self) {
        self.current_view = ViewMode::Setup;
        self.input_mode = false;
    }
}

// Replace the launch_tui function in main.rs
pub fn launch_tui() -> anyhow::Result<()> {
    // Setup terminal
    enable_raw_mode()?;
    let mut stdout = io::stdout();
    execute!(stdout, EnterAlternateScreen, EnableMouseCapture)?;
    let backend = CrosstermBackend::new(stdout);
    let mut terminal = Terminal::new(backend)?;

    // Create app state
    let mut app = App::new();

    // Try to auto-load a database
    app.try_auto_load();

    let res = run_app(&mut terminal, &mut app);

    // Save config before exiting
    let _ = app.config.save();

    // Restore terminal
    disable_raw_mode()?;
    execute!(
        terminal.backend_mut(),
        LeaveAlternateScreen,
        DisableMouseCapture
    )?;
    terminal.show_cursor()?;

    if let Err(err) = res {
        println!("{:?}", err);
    }

    Ok(())
}

fn run_app<B: Backend>(terminal: &mut Terminal<B>, app: &mut App) -> io::Result<()> {
    loop {
        terminal.draw(|f| ui::<B>(f, app))?;

        if let Event::Key(key) = event::read()? {
            // Handle popup events first (highest priority)
            if app.show_generate_popup {
                if let Some(ref mut form) = app.cert_form {
                    match key.code {
                        KeyCode::Esc => {
                            app.show_generate_popup = false;
                            app.cert_form = None;
                            app.status_message = "Certificate generation cancelled".to_string();
                        }
                        KeyCode::Tab => {
                            form.next_field();
                        }
                        KeyCode::BackTab => {
                            form.prev_field();
                        }
                        KeyCode::Enter => {
                            // If we're on the alt names field (index 8), add the alt name
                            if form.field_index == 8 {
                                if !form.temp_alt_name.is_empty() {
                                    form.alt_names.push(form.temp_alt_name.clone());
                                    form.temp_alt_name.clear();
                                    if let Some(field) = form.fields.get_mut(8) {
                                        field.value.clear();
                                    }
                                    app.status_message = "Alternative name added".to_string();
                                }
                            }
                        }
                        KeyCode::F(5) | KeyCode::Char(' ') => {
                            // Take the form temporarily to avoid borrow issues
                            if let Some(form) = app.cert_form.take() {
                                handle_certificate_generation(app, form);
                            }
                        }
                        KeyCode::F(2) => {
                            // Reset form with F2
                            *form = CertForm::default();
                            if let Some(ref db_path) = app.database_path {
                                form.database = db_path.to_string_lossy().to_string();
                            }
                            app.status_message = "Form reset".to_string();
                        }
                        KeyCode::Delete => {
                            // Delete last alt name with Delete key
                            if !form.alt_names.is_empty() {
                                form.alt_names.pop();
                                app.status_message = "Removed last alternative name".to_string();
                            }
                        }
                        KeyCode::Char(c) => {
                            form.add_char(c);
                        }
                        KeyCode::Backspace => {
                            form.delete_char();
                        }
                        _ => {}
                    }
                }
                continue; // Skip other event handling when popup is open
            }

            if app.input_mode {
                match key.code {
                    KeyCode::Enter => {
                        if !app.input_buffer.is_empty() {
                            app.set_database_path(app.input_buffer.clone());
                            app.input_buffer.clear();
                        }
                        app.input_mode = false;
                    }
                    KeyCode::Char(c) => {
                        app.input_buffer.push(c);
                    }
                    KeyCode::Backspace => {
                        app.input_buffer.pop();
                    }
                    KeyCode::Esc => {
                        app.input_mode = false;
                        app.input_buffer.clear();
                    }
                    _ => {}
                }
                continue;
            }

            match app.current_view {
                ViewMode::Setup => {
                    match key.code {
                        KeyCode::Char('q') => return Ok(()),
                        KeyCode::Char('h') => app.toggle_help(),
                        KeyCode::Char('n') => {
                            app.input_mode = true;
                            app.status_message = "Enter path to certificate database:".to_string();
                        }
                        KeyCode::Char('c') => app.show_config(),
                        KeyCode::Down | KeyCode::Char('j') => {
                            app.next();
                        }
                        KeyCode::Up | KeyCode::Char('k') => {
                            app.previous();
                        }
                        KeyCode::Enter => {
                            if let Some(selected) = app.list_state.selected() {
                                if selected < app.config.recent_databases.len() {
                                    let path = app.config.recent_databases[selected].clone();
                                    app.set_database_path(path);
                                }
                            }
                        }
                        _ => {}
                    }
                },
                ViewMode::CertificateList => {
                    match key.code {
                        KeyCode::Char('q') => return Ok(()),
                        KeyCode::Char('h') => app.toggle_help(),
                        KeyCode::Down | KeyCode::Char('j') => app.next(),
                        KeyCode::Up | KeyCode::Char('k') => app.previous(),
                        KeyCode::Enter => app.enter_detail_view(),
                        KeyCode::Char('l') => {
                            app.input_mode = true;
                            app.status_message = "Enter path to certificate database:".to_string();
                        },
                        KeyCode::Char('r') => {
                            if let Some(ref path) = app.database_path.clone() {
                                if let Err(e) = app.load_certificates(path) {
                                    app.status_message = format!("Error reloading: {}", e);
                                }
                            }
                        },
                        KeyCode::Char('c') => app.show_config(),
                        KeyCode::Char('g') => {
                            // Show certificate generation popup
                            let mut form = CertForm::default();

                            // Pre-populate database path if available
                            if let Some(ref db_path) = app.database_path {
                                form.database = db_path.to_string_lossy().to_string();
                            }

                            app.cert_form = Some(form);
                            app.show_generate_popup = true;
                            app.status_message = "Fill in certificate details. Use Tab to navigate, Ctrl+G to generate".to_string();
                        }
                        KeyCode::Char('s') => app.back_to_setup(),
                        _ => {}
                    }
                },
                ViewMode::CertificateDetail(_) => {
                    match key.code {
                        KeyCode::Char('q') => return Ok(()),
                        KeyCode::Esc | KeyCode::Backspace => app.back_to_list(),
                        KeyCode::Char('h') => app.toggle_help(),
                        _ => {}
                    }
                },
                ViewMode::Config => {
                    match key.code {
                        KeyCode::Char('q') => return Ok(()),
                        KeyCode::Esc => app.back_to_list(),
                        KeyCode::Char('s') => app.save_config(),
                        _ => {}
                    }
                }
                ViewMode::Help => {
                    match key.code {
                        KeyCode::Esc | KeyCode::Char('h') => {
                            // Go back to previous view
                            app.current_view = ViewMode::CertificateList;
                        }
                        _ => {}
                    }
                }
            }
        }
    }
}




fn ui<B: Backend>(f: &mut Frame, app: &mut App) {
    match app.current_view {
        ViewMode::Setup => draw_setup_screen::<B>(f, app),
        ViewMode::CertificateList => {
            draw_certificate_list::<B>(f, app);

            // Draw popup on top if needed
            if app.show_generate_popup {
                if let Some(ref form) = app.cert_form {
                    draw_cert_popup::<B>(f, form);
                }
            }
        }
        ViewMode::CertificateDetail(index) => draw_certificate_detail::<B>(f, app, index),
        ViewMode::Help => draw_help::<B>(f, app),
        ViewMode::Config => draw_config_screen::<B>(f, app),
    }
}

fn draw_setup_screen<B: Backend>(f: &mut Frame, app: &mut App) {
    let chunks = Layout::default()
        .direction(Direction::Vertical)
        .margin(2)
        .constraints([
            Constraint::Length(7),  // Welcome banner
            Constraint::Min(8),     // Main content
            Constraint::Length(4),  // Input area
            Constraint::Length(3),  // Status/help
        ])
        .split(f.size());

    // Welcome banner
    let banner = vec![
        Line::from(vec![
            Span::styled("🔐 Certificate Management TUI 🔐", Style::default().fg(Color::Cyan).add_modifier(Modifier::BOLD))
        ]),
        Line::from(""),
        Line::from("Welcome! Please select or enter a certificate database to get started."),
    ];
    let welcome = Paragraph::new(banner)
        .block(Block::default().borders(Borders::ALL).title("Welcome"))
        .alignment(Alignment::Center);
    f.render_widget(welcome, chunks[0]);

    // Recent databases or setup options
    if !app.config.recent_databases.is_empty() {
        let items: Vec<ListItem> = app.config.recent_databases
            .iter()
            .enumerate()
            .map(|(i, path)| {
                let exists = Path::new(path).exists();
                let status_icon = if exists { "✅" } else { "❌" };
                let style = if exists {
                    Style::default().fg(Color::White)
                } else {
                    Style::default().fg(Color::DarkGray)
                };

                ListItem::new(Line::from(vec![
                    Span::styled(format!("{} ", status_icon), style),
                    Span::styled(path.clone(), style),
                ]))
            })
            .collect();

        let recent_list = List::new(items)
            .block(Block::default().borders(Borders::ALL).title("Recent Databases (↑↓ to navigate, Enter to select)"))
            .highlight_style(Style::default().bg(Color::DarkGray).add_modifier(Modifier::BOLD))
            .highlight_symbol(">> ");

        f.render_stateful_widget(recent_list, chunks[1], &mut app.list_state);
    } else {
        let no_recent = Paragraph::new("No recent databases found.\n\nPress 'n' to enter a new database path\nPress 'c' to configure settings\nPress 'h' for help")
            .block(Block::default().borders(Borders::ALL).title("Getting Started"))
            .alignment(Alignment::Center);
        f.render_widget(no_recent, chunks[1]);
    }

    // Input area
    let input_text = if app.input_mode {
        format!("Database path: {}_", app.input_buffer)
    } else {
        "Press 'n' for new database, 'c' for config, 'h' for help, 'q' to quit".to_string()
    };

    let input_style = if app.input_mode {
        Style::default().fg(Color::Yellow)
    } else {
        Style::default().fg(Color::Gray)
    };

    let input = Paragraph::new(input_text)
        .style(input_style)
        .block(Block::default().borders(Borders::ALL).title(
            if app.input_mode { "Enter Database Path" } else { "Actions" }
        ));
    f.render_widget(input, chunks[2]);

    // Status bar
    let status = Paragraph::new(app.status_message.as_str())
        .style(Style::default().fg(Color::Yellow))
        .block(Block::default().borders(Borders::ALL).title("Status"));
    f.render_widget(status, chunks[3]);
}

fn draw_config_screen<B: Backend>(f: &mut Frame, app: &App) {
    let chunks = Layout::default()
        .direction(Direction::Vertical)
        .margin(1)
        .constraints([
            Constraint::Length(3),
            Constraint::Min(0),
            Constraint::Length(3),
        ])
        .split(f.size());

    // Title
    let title = Paragraph::new("Configuration Settings")
        .style(Style::default().fg(Color::Cyan))
        .block(Block::default().borders(Borders::ALL).title("Configuration"));
    f.render_widget(title, chunks[0]);

    // Config details
    let config_path = TuiConfig::config_file_path()
        .map(|p| p.display().to_string())
        .unwrap_or_else(|| "Unable to determine config path".to_string());

    let config_text = format!(
        "Configuration File: {}\n\
         \n\
         Current Settings:\n\
         • Default Database: {}\n\
         • Auto-load Default: {}\n\
         • Color Theme: {}\n\
         • Show Expired Warning: {}\n\
         • Expiry Warning Days: {}\n\
         • Max Recent Databases: {}\n\
         \n\
         Recent Databases ({}):\n{}",
        config_path,
        app.config.default_database_path.as_deref().unwrap_or("None"),
        app.config.auto_load_default,
        app.config.color_theme,
        app.config.show_expired_warning,
        app.config.expiry_warning_days,
        app.config.max_recent_databases,
        app.config.recent_databases.len(),
        app.config.recent_databases.iter()
            .take(5)
            .enumerate()
            .map(|(i, path)| format!("  {}. {}", i + 1, path))
            .collect::<Vec<_>>()
            .join("\n")
    );

    let config_paragraph = Paragraph::new(config_text)
        .style(Style::default().fg(Color::White))
        .block(Block::default().borders(Borders::ALL))
        .wrap(Wrap { trim: true });
    f.render_widget(config_paragraph, chunks[1]);

    // Actions
    let actions = Paragraph::new("Press 's' to save configuration, ESC to go back, 'q' to quit")
        .style(Style::default().fg(Color::Yellow))
        .block(Block::default().borders(Borders::ALL).title("Actions"));
    f.render_widget(actions, chunks[2]);
}

// Keep existing certificate list, detail, and help functions...
fn draw_certificate_list<B: Backend>(f: &mut Frame, app: &mut App) {
    let chunks = Layout::default()
        .direction(Direction::Vertical)
        .margin(1)
        .constraints([
            Constraint::Length(3),
            Constraint::Min(0),
            Constraint::Length(3),
        ])
        .split(f.size());

    // Title with database info
    let title_text = if let Some(ref path) = app.database_path {
        format!("Certificate Management - {}", path.display())
    } else {
        "Certificate Management - No Database Loaded".to_string()
    };

    let title = Paragraph::new(title_text)
        .style(Style::default().fg(Color::Cyan))
        .block(Block::default().borders(Borders::ALL).title("Certificate Manager"));
    f.render_widget(title, chunks[0]);

    // Certificate list
    let items: Vec<ListItem> = app
        .certificates
        .iter()
        .enumerate()
        .map(|(i, cert)| {
            let expires_in_days = (cert.not_after - chrono::Utc::now().timestamp()) / 86400;
            let status_color = if expires_in_days < 0 {
                Color::Red
            } else if expires_in_days < app.config.expiry_warning_days {
                Color::Yellow
            } else {
                Color::Green
            };

            let cert_type = match &cert.cert_data {
                certmgt_lib::CertData::Pem { key, .. } => {
                    if key.is_some() { "PEM+Key" } else { "PEM" }
                },
                certmgt_lib::CertData::P12 { .. } => "P12",
            };

            let line = Line::from(vec![
                Span::styled(
                    format!("{:3} ", i + 1),
                    Style::default().fg(Color::Gray)
                ),
                Span::styled(
                    format!("{:<30} ", cert.common_name.chars().take(30).collect::<String>()),
                    Style::default().fg(Color::White)
                ),
                Span::styled(
                    format!("{:<30} ", cert.serial_number.chars().take(30).collect::<String>()),
                    Style::default().fg(Color::White)
                ),
                Span::styled(
                    format!("{:<8} ", cert_type),
                    Style::default().fg(Color::Blue)
                ),
                Span::styled(
                    format!("{:>8}d ", expires_in_days),
                    Style::default().fg(status_color)
                ),
                Span::styled(
                    if cert.is_ca { "CA" } else { "CERT" },
                    Style::default().fg(if cert.is_ca { Color::Magenta } else { Color::Cyan })
                ),
            ]);
            ListItem::new(line)
        })
        .collect();

    let list = List::new(items)
        .block(
            Block::default()
                .borders(Borders::ALL)
                .title(format!("Certificates ({})", app.certificates.len()))
        )
        .highlight_style(
            Style::default()
                .bg(Color::DarkGray)
                .add_modifier(Modifier::BOLD)
        )
        .highlight_symbol(">> ");

    f.render_stateful_widget(list, chunks[1], &mut app.list_state);

    // Status bar with additional shortcuts
    let status_text = format!("{} | 'l' load, 'r' reload, 's' setup, 'c' config", app.status_message);
    let status = Paragraph::new(status_text)
        .style(Style::default().fg(Color::Yellow))
        .block(Block::default().borders(Borders::ALL).title("Status"));
    f.render_widget(status, chunks[2]);
}

fn draw_certificate_detail<B: Backend>(f: &mut Frame, app: &App, index: usize) {
    if index >= app.certificates.len() {
        return;
    }

    let cert = &app.certificates[index];
    let chunks = Layout::default()
        .direction(Direction::Vertical)
        .margin(1)
        .constraints([
            Constraint::Length(3),
            Constraint::Min(0),
            Constraint::Length(3),
        ])
        .split(f.size());

    // Title
    let title = Paragraph::new(format!("Certificate Details - {}", cert.common_name))
        .style(Style::default().fg(Color::Cyan))
        .block(Block::default().borders(Borders::ALL).title("Certificate Detail"));
    f.render_widget(title, chunks[0]);

    // Certificate details
    let expires_in_days = (cert.not_after - chrono::Utc::now().timestamp()) / 86400;
    let not_before = chrono::DateTime::from_timestamp(cert.not_before, 0)
        .map(|dt| dt.format("%Y-%m-%d %H:%M:%S UTC").to_string())
        .unwrap_or_else(|| "Invalid date".to_string());
    let not_after = chrono::DateTime::from_timestamp(cert.not_after, 0)
        .map(|dt| dt.format("%Y-%m-%d %H:%M:%S UTC").to_string())
        .unwrap_or_else(|| "Invalid date".to_string());

    let status = if expires_in_days < 0 {
        format!("❌ EXPIRED ({} days ago)", -expires_in_days)
    } else if expires_in_days < app.config.expiry_warning_days {
        format!("⚠️  EXPIRING SOON ({} days)", expires_in_days)
    } else {
        format!("✅ VALID ({} days)", expires_in_days)
    };
    let cert_info: (&str, &str, Option<&str>)= match &cert.cert_data {
        certmgt_lib::CertData::Pem { key, cert } => {

            if key.is_some() { ("PEM with Private Key", cert, key.as_deref()) } else { ("PEM Certificate Only",cert, None) }
        },
        certmgt_lib::CertData::P12 { as_base64,data , .. } => {
            if *as_base64 { ("PKCS#12 (Base64)", data, None) } else { ("PKCS#12 (Binary)", data, None) }
        }
    };
    let detail_text = format!(
        "Common Name: {}\n\
         Organization: {}\n\
         Organizational Unit: {}\n\
         Country: {}\n\
         State: {}\n\
         Locality: {}\n\
         \n\
         Certificate Type: {}\n\
         Is CA: {}\n\
         Key Size: {:?}\n\
         Has Private Key: {}\n\
         \n\
         Valid From: {}\n\
         Valid Until: {}\n\
         Status: {}\n\
         Cert Data: {}\n",
        cert.common_name,
        cert.organization,
        cert.organizational_unit,
        cert.country,
        cert.state,
        cert.locality,
        cert_info.0,
        cert.is_ca,
        cert.key_size,
        cert.has_private_key(),
        not_before,
        not_after,
        status,
        cert_info.1
    );

    let detail_paragraph = Paragraph::new(detail_text)
        .style(Style::default().fg(Color::White))
        .block(Block::default().borders(Borders::ALL))
        .wrap(Wrap { trim: true });
    f.render_widget(detail_paragraph, chunks[1]);

    // Navigation help
    let help = Paragraph::new("Press ESC or Backspace to go back, 'h' for help, 'q' to quit")
        .style(Style::default().fg(Color::Yellow))
        .block(Block::default().borders(Borders::ALL).title("Navigation"));
    f.render_widget(help, chunks[2]);
}

fn draw_help<B: Backend>(f: &mut Frame, app: &App) {
    let help_text = "Certificate Management TUI - Help\n\n\
        SETUP SCREEN:\n\
        n           Enter new database path\n\
        ↑/k         Navigate recent databases\n\
        ↓/j         Navigate recent databases\n\
        Enter       Load selected database\n\
        c           Show configuration\n\
        \n\
        NAVIGATION:\n\
        ↑/k         Move up in list\n\
        ↓/j         Move down in list\n\
        Enter       View certificate details\n\
        ESC/Back    Return to previous view\n\
        \n\
        ACTIONS:\n\
        l           Load new certificate database\n\
        r           Reload current database\n\
        s           Return to setup screen\n\
        c           Show configuration\n\
        h           Toggle this help screen\n\
        q           Quit application\n\
        \n\
        CERTIFICATE STATUS:\n\
        Green       Valid (beyond warning threshold)\n\
        Yellow      Expiring soon (within warning days)\n\
        Red         Expired\n\
        \n\
        CERTIFICATE TYPES:\n\
        PEM         Certificate in PEM format\n\
        PEM+Key     Certificate with private key\n\
        P12         PKCS#12 bundle\n\
        \n\
        CONFIGURATION:\n\
        Config file: ~/.config/certmgt/tui-config.toml\n\
        Settings include default database path, theme,\n\
        warning thresholds, and recent databases.\n\
        \n\
        Press 'h' or ESC to close this help screen.";

    let help_paragraph = Paragraph::new(help_text)
        .style(Style::default().fg(Color::White))
        .block(
            Block::default()
                .borders(Borders::ALL)
                .title("Help")
                .title_style(Style::default().fg(Color::Cyan))
        )
        .wrap(Wrap { trim: true });

    let area = centered_rect(80, 80, f.size());
    f.render_widget(Clear, area);
    f.render_widget(help_paragraph, area);
}

fn centered_rect(percent_x: u16, percent_y: u16, r: Rect) -> Rect {
    let popup_layout = Layout::default()
        .direction(Direction::Vertical)
        .constraints([
            Constraint::Percentage((100 - percent_y) / 2),
            Constraint::Percentage(percent_y),
            Constraint::Percentage((100 - percent_y) / 2),
        ])
        .split(r);

    Layout::default()
        .direction(Direction::Horizontal)
        .constraints([
            Constraint::Percentage((100 - percent_x) / 2),
            Constraint::Percentage(percent_x),
            Constraint::Percentage((100 - percent_x) / 2),
        ])
        .split(popup_layout[1])[1]
}

fn handle_certificate_generation(app: &mut App, mut form: CertForm) {
    // Validate form first
    if !form.validate() {
        app.status_message = "Please fix validation errors before generating certificate".to_string();
        // Put the form back since validation failed
        app.cert_form = Some(form);
        return;
    }

    // Ensure we have a database path
    let database_path = if !form.database.is_empty() {
        form.database.clone()
    } else if let Some(ref db_path) = app.database_path {
        db_path.to_string_lossy().to_string()
    } else {
        app.status_message = "No database path specified".to_string();
        // Put the form back since we can't proceed
        app.cert_form = Some(form);
        return;
    };

    // Show progress message
    app.status_message = "Generating certificate...".to_string();

    // Create certificate configs
    let ca_config = CaConfig {
        country: form.country.clone(),
        state: form.state.clone(),
        organization: form.organization.clone(),
        common_name: format!("{} CA", form.common_name),
        key_size: form.ca_key_size,
        validity_days: form.ca_validity_days,
    };

    let server_config = ServerCertConfig {
        country: form.country.clone(),
        state: form.state.clone(),
        organization: form.organization.clone(),
        common_name: form.common_name.clone(),
        alt_names: form.alt_names.clone(),
        key_size: form.key_size as usize,
        validity_days: form.validity_days,
    };

    // Generate certificates
    match CertificateConfig::new_ca(ca_config) {
        Ok(ca) => {
            match CertificateConfig::sign_certificate(&ca, &server_config) {
                Ok(cert) => {
                    match save_certificates_to_json(vec![ca, cert], database_path.as_ref()) {
                        Ok(_) => {
                            app.status_message = "Certificate generated and saved successfully!".to_string();
                            app.show_generate_popup = false;
                            // Don't put form back - generation was successful, close popup

                            // Reload certificates to show the new ones
                            if let Some(ref path) = app.database_path.clone() {
                                if let Err(e) = app.load_certificates(path) {
                                    app.status_message = format!("Certificate saved but failed to reload: {}", e);
                                }
                            }
                        }
                        Err(e) => {
                            app.status_message = format!("Error saving certificates: {}", e);
                            // Put the form back since there was an error
                            app.cert_form = Some(form);
                        }
                    }
                }
                Err(e) => {
                    app.status_message = format!("Error signing certificate: {}", e);
                    // Put the form back since there was an error
                    app.cert_form = Some(form);
                }
            }
        }
        Err(e) => {
            app.status_message = format!("Error creating CA certificate: {}", e);
            // Put the form back since there was an error
            app.cert_form = Some(form);
        }
    }
}

fn draw_cert_popup<B: Backend>(f: &mut Frame, form: &CertForm) {
    let area = f.size();

    // Calculate popup size (80% of screen, but with min/max constraints)
    let popup_width = std::cmp::min(80, std::cmp::max(60, area.width * 4 / 5));
    let popup_height = std::cmp::min(25, std::cmp::max(20, area.height * 4 / 5));

    let popup_area = Rect {
        x: (area.width - popup_width) / 2,
        y: (area.height - popup_height) / 2,
        width: popup_width,
        height: popup_height,
    };

    // Draw background overlay
    let overlay = Block::default()
        .style(Style::default().bg(Color::Black).add_modifier(Modifier::DIM));
    f.render_widget(Clear, area);
    f.render_widget(overlay, area);

    // Draw main popup
    let popup_block = Block::default()
        .title("🔐 Generate Certificate")
        .borders(Borders::ALL)
        .border_style(Style::default().fg(Color::Cyan))
        .style(Style::default().bg(Color::Black));

    f.render_widget(popup_block, popup_area);

    let inner = popup_area.inner(Margin { vertical: 1, horizontal: 2 });

    // Split popup into sections
    let chunks = Layout::default()
        .direction(Direction::Vertical)
        .constraints([
            Constraint::Min(15),     // Form fields
            Constraint::Length(5),   // Alt names section
            Constraint::Length(3),   // Action buttons
        ])
        .split(inner);

    // Draw form fields
    draw_form_fields::<B>(f, chunks[0], form);

    // Draw alt names section
    draw_alt_names_section::<B>(f, chunks[1], form);

    // Draw action buttons
    draw_action_buttons::<B>(f, chunks[2], form);
}

fn draw_form_fields<B: Backend>(f: &mut Frame, area: Rect, form: &CertForm) {
    let field_height = 2;
    let fields_per_column = (area.height as usize) / field_height;
    let num_columns = (form.fields.len() + fields_per_column - 1) / fields_per_column;

    if num_columns <= 1 {
        // Single column layout
        for (i, field) in form.fields.iter().enumerate() {
            if i >= fields_per_column { break; }

            let field_area = Rect {
                x: area.x,
                y: area.y + (i * field_height) as u16,
                width: area.width,
                height: field_height as u16,
            };

            draw_single_field::<B>(f, field_area, field, i == form.field_index);
        }
    } else {
        // Multi-column layout
        let column_width = area.width / num_columns as u16;

        for (i, field) in form.fields.iter().enumerate() {
            let column = i / fields_per_column;
            let row = i % fields_per_column;

            if row >= area.height as usize / field_height { continue; }

            let field_area = Rect {
                x: area.x + (column as u16 * column_width),
                y: area.y + (row * field_height) as u16,
                width: column_width - 1,
                height: field_height as u16,
            };

            draw_single_field::<B>(f, field_area, field, i == form.field_index);
        }
    }
}

fn draw_single_field<B: Backend>(f: &mut Frame, area: Rect, field: &FormField, is_active: bool) {
    let field_chunks = Layout::default()
        .direction(Direction::Horizontal)
        .constraints([
            Constraint::Length(15), // Label
            Constraint::Min(0),     // Input
        ])
        .split(area);

    // Label
    let label_style = if field.required {
        Style::default().fg(Color::White).add_modifier(Modifier::BOLD)
    } else {
        Style::default().fg(Color::Gray)
    };

    let label_text = if field.required {
        format!("{}*:", field.name)
    } else {
        format!("{}:", field.name)
    };

    let label = Paragraph::new(label_text)
        .style(label_style)
        .alignment(Alignment::Right);
    f.render_widget(label, field_chunks[0]);

    // Input field
    let input_style = if is_active {
        Style::default().fg(Color::Yellow).bg(Color::DarkGray)
    } else if field.validation_error.is_some() {
        Style::default().fg(Color::Red)
    } else {
        Style::default().fg(Color::White)
    };

    let input_text = if is_active {
        format!("{}_", field.value)
    } else {
        field.value.clone()
    };

    let input_block = Block::default()
        .borders(Borders::ALL)
        .border_style(if is_active {
            Style::default().fg(Color::Yellow)
        } else if field.validation_error.is_some() {
            Style::default().fg(Color::Red)
        } else {
            Style::default().fg(Color::Gray)
        });

    let input = Paragraph::new(input_text)
        .style(input_style)
        .block(input_block);

    f.render_widget(input, field_chunks[1]);
}

fn draw_alt_names_section<B: Backend>(f: &mut Frame, area: Rect, form: &CertForm) {
    let block = Block::default()
        .title("Alternative Names")
        .borders(Borders::ALL)
        .border_style(Style::default().fg(Color::Blue));

    let inner = block.inner(area);
    f.render_widget(block, area);

    if form.alt_names.is_empty() {
        let empty_text = Paragraph::new("No alternative names added")
            .style(Style::default().fg(Color::Gray))
            .alignment(Alignment::Center);
        f.render_widget(empty_text, inner);
    } else {
        let alt_names_text = form.alt_names
            .iter()
            .enumerate()
            .map(|(i, name)| format!("{}. {}", i + 1, name))
            .collect::<Vec<_>>()
            .join("\n");

        let alt_names_para = Paragraph::new(alt_names_text)
            .style(Style::default().fg(Color::White))
            .wrap(Wrap { trim: true });
        f.render_widget(alt_names_para, inner);
    }
}

fn draw_action_buttons<B: Backend>(f: &mut Frame, area: Rect, _form: &CertForm) {
    let help_text = vec![
        Line::from(vec![
            Span::styled("Tab/Shift+Tab", Style::default().fg(Color::Yellow)),
            Span::raw(": Navigate • "),
            Span::styled("Enter", Style::default().fg(Color::Green)),
            Span::raw(": Add Alt Name / Generate • "),
            Span::styled("Ctrl+G", Style::default().fg(Color::Green)),
            Span::raw(": Generate Certificate"),
        ]),
        Line::from(vec![
            Span::styled("Ctrl+D", Style::default().fg(Color::Red)),
            Span::raw(": Delete Alt Name • "),
            Span::styled("Esc", Style::default().fg(Color::Red)),
            Span::raw(": Cancel • "),
            Span::styled("Ctrl+R", Style::default().fg(Color::Blue)),
            Span::raw(": Reset Form"),
        ]),
    ];

    let help_para = Paragraph::new(help_text)
        .block(Block::default().borders(Borders::ALL).title("Controls"))
        .alignment(Alignment::Center);

    f.render_widget(help_para, area);
}