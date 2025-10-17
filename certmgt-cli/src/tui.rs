// Add this to your main.rs file

use crossterm::{
    event::{self, DisableMouseCapture, EnableMouseCapture, Event, KeyCode, KeyModifiers},
    execute,
    terminal::{EnterAlternateScreen, LeaveAlternateScreen, disable_raw_mode, enable_raw_mode},
};
use ratatui::{
    Frame, Terminal,
    backend::{Backend, CrosstermBackend},
    layout::{Alignment, Constraint, Direction, Layout, Rect},
    style::{Color, Modifier, Style},
    text::{Line, Span},
    widgets::{Block, Borders, Clear, List, ListItem, ListState, Paragraph, Wrap},
};
use std::path::PathBuf;
use std::{fs, io, path::Path};

use crate::config::TuiConfig;
use crate::json::{import, save_certificates_to_json};
use crate::load_certificates_from_database;
use certmgt_lib::types::{CaConfig, ServerCertConfig};
use certmgt_lib::{CertMgtError, CertificateConfig};
use ratatui::layout::Margin;
use ratatui::style::palette::material::GREEN;
use ratatui::style::palette::tailwind::SLATE;
use ratatui::widgets::ScrollbarState;
use certmgt_lib::filters::FilterOp::Contains;

const NORMAL_ROW_BG: Color = SLATE.c950;
const ALT_ROW_BG_COLOR: Color = SLATE.c900;
const SELECTED_STYLE: Style = Style::new().bg(SLATE.c800).add_modifier(Modifier::BOLD);
const TEXT_FG_COLOR: Color = SLATE.c200;
const COMPLETED_TEXT_FG_COLOR: Color = GREEN.c500;

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
    pub vertical_scroll: u16,
    pub show_generate_popup: bool,
    pub cert_form: Option<CertForm>,
    pub show_ca_selector: bool,
    pub ca_list: Vec<CertificateConfig>,
    pub ca_selected: usize, 
    pub selected_ca: Option<CertificateConfig>,
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
    pub generate_new_ca: bool,
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
            country: "US".to_string(), // Default values
            state: "CA".to_string(),
            organization: "My Organization".to_string(),
            common_name: "example.com".to_string(),
            alt_names: Vec::new(),
            temp_alt_name: String::new(),
            key_size: 2048,
            validity_days: 365,
            ca_key_size: 2048,
            ca_validity_days: 3650,
            database: String::new(),
            fields: Vec::new(),
            generate_new_ca: false,
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
                value: String::new(), // This should start empty for input
                field_type: FieldType::List,
                required: false,
                validation_error: None,
            },
        ];
    }

    pub fn add_char(&mut self, c: char) -> String {
        if self.field_index < self.fields.len() {
            let field = &mut self.fields[self.field_index];
            let old_value = field.value.clone();

            match field.field_type {
                FieldType::Number => {
                    if c.is_ascii_digit() {
                        field.value.push(c);
                        field.validation_error = None;
                        return format!(
                            "Added '{}' to field {} ({}): '{}' -> '{}'",
                            c, self.field_index, field.name, old_value, field.value
                        );
                    } else {
                        return format!(
                            "Rejected non-digit '{}' for number field {}",
                            c, field.name
                        );
                    }
                }
                FieldType::Text | FieldType::List => {
                    if c.is_ascii_graphic() || c == ' ' {
                        field.value.push(c);
                        field.validation_error = None;
                        return format!(
                            "Added '{}' to field {} ({}): '{}' -> '{}'",
                            c, self.field_index, field.name, old_value, field.value
                        );
                    } else {
                        return format!("Rejected char '{}' for text field {}", c, field.name);
                    }
                }
            }
        }
        "add_char: invalid field_index".to_string()
    }

    pub fn delete_char(&mut self) -> String {
        if self.field_index < self.fields.len() {
            let field = &mut self.fields[self.field_index];
            let old_value = field.value.clone();

            if !field.value.is_empty() {
                field.value.pop();
                field.validation_error = None;
                return format!(
                    "Deleted from field {} ({}): '{}' -> '{}'",
                    self.field_index, field.name, old_value, field.value
                );
            } else {
                return format!(
                    "Field {} ({}) is already empty",
                    self.field_index, field.name
                );
            }
        }
        "delete_char: invalid field_index".to_string()
    }

    fn update_struct_field(&mut self, field_index: usize) {
        if field_index >= self.fields.len() {
            return;
        }

        let field_value = &self.fields[field_index].value;

        match field_index {
            0 => self.country = field_value.clone(),
            1 => self.state = field_value.clone(),
            2 => self.organization = field_value.clone(),
            3 => self.common_name = field_value.clone(),
            4 => {
                if let Ok(size) = field_value.parse::<u32>() {
                    if size >= 1024 && size <= 8192 {
                        self.key_size = size;
                    }
                }
            }
            5 => {
                if let Ok(days) = field_value.parse::<u32>() {
                    if days >= 1 && days <= 36500 {
                        self.validity_days = days;
                    }
                }
            }
            6 => {
                if let Ok(size) = field_value.parse::<u32>() {
                    if size >= 2048 && size <= 8192 {
                        self.ca_key_size = size;
                    }
                }
            }
            7 => {
                if let Ok(days) = field_value.parse::<u32>() {
                    if days >= 1 && days <= 36500 {
                        self.ca_validity_days = days;
                    }
                }
            }
            8 => self.temp_alt_name = field_value.clone(),
            _ => {}
        }
    }

    // Make sure validation works properly
    pub fn validate(&mut self) -> bool {
        let mut is_valid = true;

        // Check required fields
        for (index, field) in self.fields.iter_mut().enumerate() {
            field.validation_error = None;

            if field.required && field.value.trim().is_empty() {
                field.validation_error = Some("Required field".to_string());
                is_valid = false;
            }

            // Validate number fields
            if field.field_type == FieldType::Number && !field.value.trim().is_empty() {
                match field.value.parse::<u32>() {
                    Ok(value) => {
                        let (min_val, max_val) = match index {
                            4 => (1024, 8192), // Key size
                            5 => (1, 36500),   // Validity days
                            6 => (2048, 8192), // CA key size
                            7 => (1, 36500),   // CA validity days
                            _ => continue,
                        };

                        if value < min_val || value > max_val {
                            field.validation_error =
                                Some(format!("Must be {}-{}", min_val, max_val));
                            is_valid = false;
                        }
                    }
                    Err(_) => {
                        field.validation_error = Some("Invalid number".to_string());
                        is_valid = false;
                    }
                }
            }
        }

        is_valid
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

    fn sync_single_field(&mut self, field_index: usize) {
        if field_index >= self.fields.len() {
            return;
        }

        let field_value = &self.fields[field_index].value;

        match field_index {
            0 => self.country = field_value.clone(),
            1 => self.state = field_value.clone(),
            2 => self.organization = field_value.clone(),
            3 => self.common_name = field_value.clone(),
            4 => {
                if let Ok(size) = field_value.parse::<u32>() {
                    if size >= 1024 && size <= 8192 {
                        self.key_size = size;
                    }
                }
            }
            5 => {
                if let Ok(days) = field_value.parse::<u32>() {
                    if days >= 1 && days <= 36500 {
                        self.validity_days = days;
                    }
                }
            }
            6 => {
                if let Ok(size) = field_value.parse::<u32>() {
                    if size >= 2048 && size <= 8192 {
                        self.ca_key_size = size;
                    }
                }
            }
            7 => {
                if let Ok(days) = field_value.parse::<u32>() {
                    if days >= 1 && days <= 36500 {
                        self.ca_validity_days = days;
                    }
                }
            }
            8 => self.temp_alt_name = field_value.clone(),
            _ => {}
        }
    }

    // Keep the original sync_field_values for when you need to sync all fields
    // But call it less frequently to avoid loops
    fn sync_all_fields(&mut self) {
        for i in 0..self.fields.len() {
            self.sync_single_field(i);
        }
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
            vertical_scroll: 0,
            show_generate_popup: false,
            cert_form: None,
            show_ca_selector: false,
            ca_list: vec![],
            ca_selected: 0,
            selected_ca: None,
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

        self.status_message = format!(
            "Loaded {} certificates from {}",
            self.certificates.len(),
            path.display()
        );
        self.current_view = ViewMode::CertificateList;
        Ok(())
    }

    pub fn try_auto_load(&mut self) {
        if self.config.auto_load_default {
            if let Some(default_path) = self.config.default_database_path.clone() {
                let path = PathBuf::from(default_path.clone());
                if path.exists() {
                    if let Err(e) = &self.load_certificates(&path) {
                        self.status_message =
                            format!("Failed to auto-load {}: {}", default_path, e);
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
    fn next_ca(&mut self) {
        if self.ca_list.is_empty() { return; }
        if self.ca_selected + 1 >= self.ca_list.len() {
            self.ca_selected = 0;
        } else {
            self.ca_selected += 1;
        }
    }

    fn previous_ca(&mut self) {
        if self.ca_list.is_empty() { return; }
        if self.ca_selected == 0 {
            self.ca_selected = self.ca_list.len() - 1;
        } else {
            self.ca_selected -= 1;
        }
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
    fn scroll_down(&mut self) {
        self.vertical_scroll = (self.vertical_scroll + 1) % 80;
    }
    fn scroll_up(&mut self) {
        while self.vertical_scroll > 0 {
            self.vertical_scroll = (self.vertical_scroll - 1) % 80;
        }
    }
}

// Replace the launch_tui function in main.rs
pub fn launch_tui() -> anyhow::Result<()> {
    // Setup terminal
    enable_raw_mode()?;
    let mut stdout = io::stdout();
    execute!(stdout, EnterAlternateScreen)?;
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
            if app.show_ca_selector {
                // Only handle CA selection keys
                match key.code {
                    KeyCode::Up => app.previous_ca(),
                    KeyCode::Down => app.next_ca(),
                    KeyCode::Enter => {
                        app.selected_ca = Some(app.ca_list[app.ca_selected].clone());
                        app.show_ca_selector = false;

                        if let Some(form) = app.cert_form.take() {
                            handle_certificate_generation(app, form);
                        }
                    }
                    KeyCode::Esc => app.show_ca_selector = false,
                    _ => {}
                }
                continue
            // Handle popup events first (highest priority)
            } else if app.show_generate_popup {
                match key.code {
                    KeyCode::Esc => {
                        app.show_generate_popup = false;
                        app.cert_form = None;
                        app.status_message = "Certificate generation cancelled".to_string();
                    }
                    KeyCode::Char('g') if key.modifiers.contains(KeyModifiers::CONTROL) => {
                        if let Some(form) = app.cert_form.take() {
                            // Debug version - add step-by-step status messages
                            app.status_message = "Starting certificate generation...".to_string();

                            handle_certificate_generation(app, form);
                        }
                    }
                    KeyCode::Char('c') => {
                        if let Some(form) = app.cert_form.take() {
                            if !form.generate_new_ca && app.selected_ca.is_none() {
                                // Open CA selector instead of generating certificate yet
                                let database = app.database_path.clone().unwrap();
                                let all_certs = load_certificates_from_database(&database).unwrap_or_default();
                                let available_cas: Vec<_> = all_certs.into_iter().filter(|c| c.is_ca).collect();

                                if available_cas.is_empty() {
                                    app.status_message = "No existing CA certificates found.".to_string();
                                    app.cert_form = Some(form); // keep popup open
                                } else if available_cas.len() == 1 {
                                    app.selected_ca = Some(available_cas[0].clone());
                                    handle_certificate_generation(app, form); // single CA, continue
                                } else {
                                    app.ca_list = available_cas;
                                    app.ca_selected = 0;
                                    app.show_ca_selector = true;
                                    app.cert_form = Some(form); // keep form open but wait for CA
                                }
                            } else {
                                // Either generating new CA or CA already selected
                                handle_certificate_generation(app, form);
                            }
                        }
                    }
                    KeyCode::Tab => {
                        if let Some(ref mut form) = app.cert_form {
                            form.next_field();
                        }
                    }
                    KeyCode::BackTab => {
                        if let Some(ref mut form) = app.cert_form {
                            form.prev_field();
                        }
                    }
                    KeyCode::Enter => {
                        // Handle alt names on field 8
                        if let Some(ref mut form) = app.cert_form {
                            if form.field_index == 8 {
                                let alt_name = form.temp_alt_name.trim().to_string();
                                if !alt_name.is_empty() {
                                    form.alt_names.push(alt_name);
                                    form.temp_alt_name.clear();
                                    if let Some(field) = form.fields.get_mut(8) {
                                        field.value.clear();
                                    }
                                    app.status_message = "Alternative name added".to_string();
                                }
                            }
                        }
                    }
                    KeyCode::Char(c) => {
                        if let Some(ref mut form) = app.cert_form {
                            if form.field_index < form.fields.len() {
                                form.fields[form.field_index].value.push(c);
                                // Update the corresponding struct field
                                form.update_struct_field(form.field_index);
                            }
                        }
                    }
                    KeyCode::Backspace => {
                        if let Some(ref mut form) = app.cert_form {
                            if form.field_index < form.fields.len() {
                                form.fields[form.field_index].value.pop();
                                form.update_struct_field(form.field_index);
                            }
                        }
                    }
                    _ => {}
                }
                continue;
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
                ViewMode::Setup => match key.code {
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
                        }
                        KeyCode::Char('r') => {
                            if let Some(ref path) = app.database_path.clone() {
                                if let Err(e) = app.load_certificates(path) {
                                    app.status_message = format!("Error reloading: {}", e);
                                }
                            }
                        }
                        KeyCode::Char('c') => app.show_config(),
                        KeyCode::Char('g') => {
                            let mut form = CertForm::default();

                            // Pre-populate database path if available
                            if let Some(ref db_path) = app.database_path {
                                form.database = db_path.to_string_lossy().to_string();
                            }

                            app.cert_form = Some(form);
                            app.show_generate_popup = true;
                            app.status_message = "Use Tab/Shift+Tab to navigate fields, type to edit, Ctrl+G to generate".to_string();
                        }
                        KeyCode::Char('s') => app.back_to_setup(),
                        _ => {}
                    }
                }
                ViewMode::CertificateDetail(_) => match key.code {
                    KeyCode::Char('q') => return Ok(()),
                    KeyCode::Esc | KeyCode::Backspace => app.back_to_list(),
                    KeyCode::Char('h') => app.toggle_help(),
                    KeyCode::Down => app.scroll_down(),
                    KeyCode::Up => app.scroll_up(),
                    _ => {}
                },
                ViewMode::Config => match key.code {
                    KeyCode::Char('q') => return Ok(()),
                    KeyCode::Esc => app.back_to_list(),
                    KeyCode::Char('s') => app.save_config(),
                    _ => {}
                },
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
            // Draw popup for ca cert list
            if app.show_ca_selector {
                draw_ca_selection_popup::<B>(f, f.size(), &app.ca_list, &mut {
                    let mut state = ListState::default();
                    state.select(Some(app.ca_selected));
                    state
                });
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
            Constraint::Length(7), // Welcome banner
            Constraint::Min(8),    // Main content
            Constraint::Length(4), // Input area
            Constraint::Length(3), // Status/help
        ])
        .split(f.size());

    // Welcome banner
    let banner = vec![
        Line::from(vec![Span::styled(
            "🔐 Certificate Management TUI 🔐",
            Style::default()
                .fg(Color::LightGreen)
                .add_modifier(Modifier::BOLD),
        )]),
        Line::from(""),
        Line::from("Welcome! Please select or enter a certificate database to get started."),
    ];
    let welcome = Paragraph::new(banner)
        .block(Block::default().borders(Borders::ALL).title("Welcome"))
        .alignment(Alignment::Center);
    f.render_widget(welcome, chunks[0]);

    // Recent databases or setup options
    if !app.config.recent_databases.is_empty() {
        let items: Vec<ListItem> = app
            .config
            .recent_databases
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
            .block(
                Block::default()
                    .borders(Borders::ALL)
                    .title("Recent Databases (↑↓ to navigate, Enter to select)"),
            )
            .highlight_style(
                Style::default()
                    .bg(Color::DarkGray)
                    .add_modifier(Modifier::BOLD),
            )
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

    let input = Paragraph::new(input_text).style(input_style).block(
        Block::default()
            .borders(Borders::ALL)
            .title(if app.input_mode {
                "Enter Database Path"
            } else {
                "Actions"
            }),
    );
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
        .block(
            Block::default()
                .borders(Borders::ALL)
                .title("Configuration"),
        );
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
         • Max Recent Databases: {:?}\n\
         • p12 Passwords: {:#?}\n\
         \n\
         Recent Databases ({}):\n{}",
        config_path,
        app.config
            .default_database_path
            .as_deref()
            .unwrap_or("None"),
        app.config.auto_load_default,
        app.config.color_theme,
        app.config.show_expired_warning,
        app.config.expiry_warning_days,
        app.config.max_recent_databases,
        app.config.p12_passwords_print(),
        app.config.recent_databases.len(),
        app.config
            .recent_databases
            .iter()
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
        .block(
            Block::default()
                .borders(Borders::ALL)
                .title("Certificate Manager"),
        );
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
            } else if expires_in_days < app.config.expiry_warning_days as i64 {
                Color::Yellow
            } else {
                Color::Green
            };

            let cert_type = match &cert.cert_data {
                certmgt_lib::CertData::Pem { key, .. } => {
                    if key.is_some() {
                        "PEM+Key"
                    } else {
                        "PEM"
                    }
                }
                certmgt_lib::CertData::P12 { .. } => "P12",
            };

            let line = Line::from(vec![
                Span::styled(format!("{:3} ", i + 1), Style::default().fg(Color::Gray)),
                Span::styled(
                    format!(
                        "{:<30} ",
                        cert.common_name.chars().take(30).collect::<String>()
                    ),
                    Style::default().fg(Color::White),
                ),
                Span::styled(
                    format!(
                        "{:<40} ",
                        cert.serial_number.chars().take(30).collect::<String>()
                    ),
                    Style::default().fg(Color::White),
                ),
                Span::styled(
                    format!("{:<8} ", cert_type),
                    Style::default().fg(Color::Blue),
                ),
                Span::styled(
                    format!("{:>8}d ", expires_in_days),
                    Style::default().fg(status_color),
                ),
                Span::styled(
                    if cert.is_ca { "CA" } else { "CERT" },
                    Style::default().fg(if cert.is_ca {
                        Color::Magenta
                    } else {
                        Color::Cyan
                    }),
                ),
            ]);
            ListItem::new(line)
        })
        .collect();

    let list = List::new(items)
        .block(
            Block::default()
                .borders(Borders::ALL)
                .title(format!("Certificates ({})", app.certificates.len())),
        )
        .highlight_style(
            Style::default()
                .bg(Color::DarkGray)
                .add_modifier(Modifier::BOLD),
        )
        .highlight_symbol(">> ");

    f.render_stateful_widget(list, chunks[1], &mut app.list_state);

    // Status bar with additional shortcuts
    let status_text = format!(
        "{} | 'l' load, 'r' reload, 's' setup, 'c' config, 'g' generate",
        app.status_message
    );
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
        .block(
            Block::default()
                .borders(Borders::ALL)
                .title("Certificate Detail"),
        );
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
    } else if expires_in_days < app.config.expiry_warning_days as i64 {
        format!("⚠️  EXPIRING SOON ({} days)", expires_in_days)
    } else {
        format!("✅ VALID ({} days)", expires_in_days)
    };
    let cert_info: (&str, &str, Option<&str>) = match &cert.cert_data {
        certmgt_lib::CertData::Pem { key, cert } => {
            if key.is_some() {
                ("PEM with Private Key", cert, key.as_deref())
            } else {
                ("PEM Certificate Only", cert, None)
            }
        }
        certmgt_lib::CertData::P12 {
            as_base64, data, ..
        } => {
            if *as_base64 {
                ("PKCS#12 (Base64)", data, None)
            } else {
                ("PKCS#12 (Binary)", data, None)
            }
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
        .scroll((app.vertical_scroll, 0))
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
                .title_style(Style::default().fg(Color::Cyan)),
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
    // Step 1: Validation
    app.status_message = "Validating form...".to_string();
    if !form.validate() {
        app.status_message = "Validation failed - check required fields".to_string();
        app.cert_form = Some(form);
        return;
    }

    // Step 2: Database path
    app.status_message = "Checking database path...".to_string();
    let database_path = if !form.database.is_empty() {
        form.database.clone()
    } else if let Some(ref db_path) = app.database_path {
        db_path.to_string_lossy().to_string()
    } else {
        app.status_message = "No database path available".to_string();
        app.cert_form = Some(form);
        return;
    };
    let database = PathBuf::from(database_path);



    // Step 3: Create CA config
    app.status_message = "Creating CA configuration...".to_string();
    let ca_config = CaConfig {
        country: form.country.clone(),
        state: form.state.clone(),
        organization: form.organization.clone(),
        common_name: format!("{} CA", form.common_name),
        key_size: form.ca_key_size,
        validity_days: form.ca_validity_days,
    };

    let ca_cert = match form.generate_new_ca {
        true => {
            match CertificateConfig::new_ca(ca_config) {
                Ok(cert) => {
                    app.status_message = "CA certificate created successfully".to_string();
                    cert
                }
                Err(e) => {
                    app.status_message = format!("CA generation failed: {}", e);
                    app.cert_form = Some(form);
                    return;
                }
            }
        }
        false => {
            app.selected_ca.clone().unwrap()
        }
    };

    // Step 4: Generate CA (this might be where it freezes)
    app.status_message = "Generating CA certificate...".to_string();

    // Step 5: Create server config
    app.status_message = "Creating server certificate configuration...".to_string();
    let server_config = ServerCertConfig {
        country: form.country.clone(),
        state: form.state.clone(),
        organization: form.organization.clone(),
        common_name: form.common_name.clone(),
        alt_names: form.alt_names.clone(),
        key_size: form.key_size as usize,
        validity_days: form.validity_days,
    };

    // Step 6: Generate server cert (another potential freeze point)
    app.status_message = "Generating server certificate...".to_string();
    let server_cert = match CertificateConfig::sign_certificate(&ca_cert, &server_config) {
        Ok(cert) => {
            app.status_message = "Server certificate created successfully".to_string();
            cert
        }
        Err(e) => {
            app.status_message = format!("Server cert generation failed: {}", e);
            app.cert_form = Some(form);
            return;
        }
    };

    // Step 7: Save generated certificates using import()
    let new_certs = vec![ca_cert, server_cert];

    if let Err(e) = import(
        &app.config,
        new_certs,
        database,
        false,
        true,
        None,
        false,
    ) {
        app.status_message = format!("Save failed: {}", e);
        app.cert_form = Some(form);  // preserve form
        return;
    }

    app.status_message = "💾 Certificates saved successfully!".to_string();
    app.show_generate_popup = false;
    app.cert_form = None;

    // Reload certificates in TUI
    if let Some(ref path) = app.database_path.clone() {
        if let Err(e) = app.load_certificates(path) {
            app.status_message = format!("Saved but reload failed: {}", e);
        }
    }

}

// This is your selectable CA popup
pub fn tui_select_ca<B: Backend>(
    ca_list: &[CertificateConfig],
    f: &mut Frame,
    app: &mut App,
) -> Option<CertificateConfig> {
    if ca_list.is_empty() {
        return None;
    }

    let mut state = ListState::default();
    state.select(Some(0)); // default selection at the top

    loop {
        let area = f.size();
        draw_ca_selection_popup::<B>(f, area, ca_list, &mut state);

        // Wait for key event
        if let Event::Key(key) = event::read().unwrap() {
            match key.code {
                KeyCode::Up => {
                    let i = state.selected().unwrap_or(0);
                    if i > 0 {
                        state.select(Some(i - 1));
                    }
                }
                KeyCode::Down => {
                    let i = state.selected().unwrap_or(0);
                    if i < ca_list.len() - 1 {
                        state.select(Some(i + 1));
                    }
                }
                KeyCode::Enter => {
                    if let Some(i) = state.selected() {
                        return Some(ca_list[i].clone());
                    }
                }
                KeyCode::Esc => return None,
                _ => {}
            }
        }
    }
}

fn draw_cert_popup<B: Backend>(f: &mut Frame, form: &CertForm) {
    let area = f.size();

    // Create a reasonably sized popup (don't make it too big)
    let popup_width = std::cmp::min(80, area.width.saturating_sub(4));
    let popup_height = std::cmp::min(38, area.height.saturating_sub(2));

    let popup_area = Rect {
        x: (area.width.saturating_sub(popup_width)) / 2,
        y: (area.height.saturating_sub(popup_height)) / 2,
        width: popup_width,
        height: popup_height,
    };

    // Clear only the popup area (not the whole screen)
    f.render_widget(Clear, popup_area);

    // Draw main popup border
    let popup_block = Block::default()
        .title(" Generate Certificate ")
        .borders(Borders::ALL)
        .border_style(Style::default().fg(Color::Cyan))
        .style(Style::default().bg(Color::DarkGray));

    f.render_widget(popup_block, popup_area);

    // Get inner area for content
    let inner = popup_area.inner(Margin {
        vertical: 1,
        horizontal: 1,
    });

    // Split into sections
    let chunks = Layout::default()
        .direction(Direction::Vertical)
        .constraints([
            Constraint::Percentage(60),
            Constraint::Percentage(30),
            Constraint::Percentage(10),
            Constraint::Percentage(10),
        ])
        .split(inner);

        let checkbox_text = if form.generate_new_ca {
            "[ ] Generate new CA"
        } else {
            "[X] Generate new CA"
        };

        let checkbox = Paragraph::new(checkbox_text)
            .style(Style::default().fg(Color::Yellow))
            .alignment(Alignment::Left);

        f.render_widget(checkbox, chunks[2]);

    // Controls go one row lower now
    draw_action_buttons::<B>(f, chunks[3], form);
    // Draw each section
    draw_form_fields_simple::<B>(f, chunks[0], form);
    // draw_action_buttons::<B>(f, chunks[2], form);
}


fn draw_ca_selection_popup<B: Backend>(
    f: &mut Frame,
    area: Rect,
    ca_list: &[CertificateConfig],
    state: &mut ListState
) {
    let popup_width = std::cmp::min(60, area.width.saturating_sub(4));
    let popup_height = std::cmp::min(20, area.height.saturating_sub(2));

    let popup_area = Rect {
        x: (area.width.saturating_sub(popup_width)) / 2,
        y: (area.height.saturating_sub(popup_height)) / 2,
        width: popup_width,
        height: popup_height,
    };

    f.render_widget(Clear, popup_area);

    let popup_block = Block::default()
        .title(" Select a CA ")
        .borders(Borders::ALL)
        .border_style(Style::default().fg(Color::Magenta))
        .style(Style::default().bg(Color::DarkGray));

    f.render_widget(popup_block.clone(), popup_area);

    let inner = popup_area.inner(Margin { vertical: 1, horizontal: 1 });

    // Turn CAs into list items
    let items: Vec<ListItem> = ca_list.iter()
        .map(|ca| {
            let expiration = (ca.not_after - chrono::Utc::now().timestamp()) / 86400;
            let label = format!(
                "{} ({} days, key {:?})",
                ca.common_name, expiration, ca.key_size
            );
            ListItem::new(label)
        })
        .collect();

    let list = List::new(items)
        .block(Block::default().title("Available CA Certificates").borders(Borders::ALL))
        .highlight_style(Style::default().fg(Color::Yellow).bg(Color::Blue))
        .highlight_symbol(">> ");

    f.render_stateful_widget(list, inner, state);
}

fn draw_form_fields_simple<B: Backend>(f: &mut Frame, area: Rect, form: &CertForm) {
    let mut lines = Vec::new();

    // Show ALL fields including alt names (index 8)
    for (i, field) in form.fields.iter().enumerate() {
        let prefix = if i == form.field_index { "► " } else { "  " };
        let suffix = if i == form.field_index { "_" } else { "" };

        let line_text = if i == 8 {
            // Special handling for alt names field
            format!("{}Alt Names (current): {}{}", prefix, field.value, suffix)
        } else {
            format!("{}{}: {}{}", prefix, field.name, field.value, suffix)
        };

        let style = if i == form.field_index {
            Style::default().fg(Color::Yellow).bg(Color::DarkGray)
        } else {
            Style::default().fg(Color::White)
        };

        lines.push(Line::from(Span::styled(line_text, style)));
    }

    // Add a separator and show current alt names list
    if !form.alt_names.is_empty() {
        lines.push(Line::from(""));
        lines.push(Line::from(Span::styled(
            "Added Alt Names:",
            Style::default().fg(Color::Cyan),
        )));
        for (i, alt_name) in form.alt_names.iter().enumerate() {
            lines.push(Line::from(Span::styled(
                format!("  {}. {}", i + 1, alt_name),
                Style::default().fg(Color::Green),
            )));
        }
    }

    let paragraph = Paragraph::new(lines)
        .block(
            Block::default()
                .borders(Borders::ALL)
                .title("Certificate Fields"),
        )
        .wrap(ratatui::widgets::Wrap { trim: true });

    f.render_widget(paragraph, area);
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
        let alt_names_text = form
            .alt_names
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
            Span::raw(": Add Alt Name • "),
            Span::styled("Ctrl+G", Style::default().fg(Color::Green)),
            Span::raw(": Generate Certificate"),
        ]),
        Line::from(vec![
            Span::styled("Delete", Style::default().fg(Color::Red)),
            Span::raw(": Remove Alt Name • "),
            Span::styled("F2", Style::default().fg(Color::Blue)),
            Span::raw(": Reset Form • "),
            Span::styled("Esc", Style::default().fg(Color::Red)),
            Span::raw(": Cancel"),
        ]),
    ];

    let help_para = Paragraph::new(help_text)
        .block(Block::default().borders(Borders::ALL).title("Controls"))
        .alignment(Alignment::Center);

    f.render_widget(help_para, area);
}
