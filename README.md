# cert-mgt

Certificate management toolkit: import, store, inspect, filter, renew and export
X.509 certificates (PEM and PKCS#12) in a local JSON database, with a ratatui TUI.

## Workspace

| Crate         | Description                                    |
|---------------|------------------------------------------------|
| `certmgt-lib` | Parsing, generation, CA signing, renewal, filtering |
| `certmgt-cli` | `certmgt-cli` binary (CLI + TUI)               |

## Build

```sh
cargo build --release
cargo test
cargo clippy --all-targets
```

Requires Rust ≥ 1.85 (edition 2024).

## Usage

```sh
# Launch the TUI
certmgt-cli tui

# Generate a CA + server certificate pair into a database
certmgt-cli generate --database certs.json.gz

# Import PEM/P12 files (recursively) into a database
certmgt-cli import --inputs certs/ --database certs.json.gz --password-file p12-passwords

# Read / inspect (summary | detailed | json | table)
certmgt-cli read --path certs.json.gz --format table
certmgt-cli read --path example.com.pem --show-content

# Filter with expressions (AND by default, --or-logic for OR)
certmgt-cli read --path certs.json.gz --filters 'common_name~example' 'is_ca==true'

# List convenience subcommands
certmgt-cli list --database certs.json.gz expiring 30
certmgt-cli list --database certs.json.gz without-keys

# Export back to PEM/P12 files
certmgt-cli export --database certs.json.gz --output-dir out/ --filters 'common_name~example'

# Attach a private key to a stored PEM certificate
certmgt-cli attach-key --database certs.json.gz --common-name example.com --key-file example.com.key

# Convert between .json / .json.gz
certmgt-cli convert --input certs.json --output certs.json.gz
```

Databases are `.json` or `.json.gz` files (versioned `CertificateDatabase` schema).

## Configuration

`~/.config/certmgt/tui-config.toml`:

```toml
default_database_path = "certs.json.gz"
auto_load_default = true
color_theme = "default"
show_expired_warning = true
expiry_warning_days = 30
max_recent_databases = 5

# P12 passwords: per-file map, or a flat list tried for every P12
p12_passwords = { "bundle.p12" = "s3cret" }
# p12_passwords = ["fallback1", "fallback2"]
```

`import --password-file` reads the same format line-based (`file=pw` or bare `pw`, `#` comments).

## Security notes

- Private keys are stored **unencrypted** inside the JSON database — treat database
  files as secret material, restrict file permissions, never commit them.
- Never commit `*.pem`, `*.p12` or generated databases (see `.gitignore`).
- If a key ever leaked into git history, rotate it; removing the file from HEAD
  does not remove it from history.
