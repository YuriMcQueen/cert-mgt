use assert_cmd::Command;
use predicates::prelude::*;
use std::path::{Path, PathBuf};

fn bin() -> Command {
    Command::cargo_bin("certmgt-cli").unwrap()
}

fn generate_in(dir: &Path, db_name: &str) -> PathBuf {
    let db = dir.join(db_name);
    bin()
        .args([
            "generate",
            "--database",
            db.to_str().unwrap(),
            "--common-name",
            "leaf.example.com",
            "--ca-common-name",
            "test-ca.example.com",
        ])
        .assert()
        .success();
    db
}

fn is_gzip(path: &Path) -> bool {
    let bytes = std::fs::read(path).unwrap();
    bytes.len() >= 2 && bytes[0] == 0x1f && bytes[1] == 0x8b
}

#[test]
fn generate_writes_gzip_for_json_gz_path() {
    let dir = tempfile::tempdir().unwrap();
    let db = generate_in(dir.path(), "db.json.gz");
    assert!(db.exists());
    // Regression: generate used to write plain JSON into .json.gz paths
    assert!(is_gzip(&db));
}

#[test]
fn generate_writes_plain_json_for_json_path() {
    let dir = tempfile::tempdir().unwrap();
    let db = generate_in(dir.path(), "db.json");
    let first = std::fs::read(&db).unwrap()[0];
    assert_eq!(first, b'{');
}

#[test]
fn read_generated_db_summary() {
    let dir = tempfile::tempdir().unwrap();
    let db = generate_in(dir.path(), "db.json.gz");
    bin()
        .args([
            "read",
            "--path",
            db.to_str().unwrap(),
            "--format",
            "summary",
        ])
        .assert()
        .success()
        .stdout(predicate::str::contains("leaf.example.com"))
        .stdout(predicate::str::contains("test-ca.example.com"))
        .stdout(predicate::str::contains("PEM+Key"));
}

#[test]
fn read_with_ca_filter() {
    let dir = tempfile::tempdir().unwrap();
    let db = generate_in(dir.path(), "db.json.gz");
    bin()
        .args([
            "read",
            "--path",
            db.to_str().unwrap(),
            "--filters",
            "is_ca==true",
        ])
        .assert()
        .success()
        .stdout(predicate::str::contains("1 certificates found"))
        .stdout(predicate::str::contains("test-ca.example.com"))
        .stdout(predicate::str::contains("CA"));
}

#[test]
fn import_export_roundtrip() {
    let dir = tempfile::tempdir().unwrap();
    let db = generate_in(dir.path(), "db.json.gz");

    // Export to PEM files
    let out = dir.path().join("exported");
    bin()
        .args([
            "export",
            "--database",
            db.to_str().unwrap(),
            "--output-dir",
            out.to_str().unwrap(),
        ])
        .assert()
        .success()
        .stdout(predicate::str::contains("Successfully exported 2"));

    let pems: Vec<_> = std::fs::read_dir(&out)
        .unwrap()
        .filter_map(|e| e.ok())
        .filter(|e| e.path().extension().and_then(|x| x.to_str()) == Some("pem"))
        .collect();
    assert_eq!(pems.len(), 2);

    // Re-import into a fresh uncompressed DB
    let db2 = dir.path().join("imported.json");
    bin()
        .args([
            "import",
            "--inputs",
            out.to_str().unwrap(),
            "--database",
            db2.to_str().unwrap(),
        ])
        .assert()
        .success()
        .stdout(predicate::str::contains("2 new"));

    bin()
        .args([
            "read",
            "--path",
            db2.to_str().unwrap(),
            "--format",
            "summary",
        ])
        .assert()
        .success()
        .stdout(predicate::str::contains("leaf.example.com"))
        .stdout(predicate::str::contains("test-ca.example.com"));
}

#[test]
fn convert_json_to_gz_and_back() {
    let dir = tempfile::tempdir().unwrap();
    let plain = generate_in(dir.path(), "plain.json");
    let gz = dir.path().join("plain.json.gz");

    bin()
        .args([
            "convert",
            "--input",
            plain.to_str().unwrap(),
            "--output",
            gz.to_str().unwrap(),
        ])
        .assert()
        .success();
    assert!(is_gzip(&gz));

    let plain2 = dir.path().join("again.json");
    bin()
        .args([
            "convert",
            "--input",
            gz.to_str().unwrap(),
            "--output",
            plain2.to_str().unwrap(),
        ])
        .assert()
        .success();
    assert_eq!(std::fs::read(&plain2).unwrap()[0], b'{');

    bin()
        .args([
            "read",
            "--path",
            plain2.to_str().unwrap(),
            "--format",
            "summary",
        ])
        .assert()
        .success()
        .stdout(predicate::str::contains("leaf.example.com"));
}

#[test]
fn list_cas_and_expiring() {
    let dir = tempfile::tempdir().unwrap();
    let db = generate_in(dir.path(), "db.json.gz");

    bin()
        .args(["list", "--database", db.to_str().unwrap(), "c-as"])
        .assert()
        .success()
        .stdout(predicate::str::contains("test-ca.example.com"));

    bin()
        .args(["list", "--database", db.to_str().unwrap(), "expiring", "30"])
        .assert()
        .success()
        .stdout(predicate::str::contains("0 found"));
}

#[test]
fn import_compressed_flag_appends_gz() {
    let dir = tempfile::tempdir().unwrap();
    let db = generate_in(dir.path(), "db.json.gz");
    let out = dir.path().join("exported");
    bin()
        .args([
            "export",
            "--database",
            db.to_str().unwrap(),
            "--output-dir",
            out.to_str().unwrap(),
        ])
        .assert()
        .success();

    // Regression: --compressed with a .json path used to write gz bytes into .json
    let target = dir.path().join("imported.json");
    bin()
        .args([
            "import",
            "--inputs",
            out.to_str().unwrap(),
            "--database",
            target.to_str().unwrap(),
            "--compressed",
        ])
        .assert()
        .success();

    let gz = dir.path().join("imported.json.gz");
    assert!(
        gz.exists(),
        "--compressed should switch the path to .json.gz"
    );
    assert!(is_gzip(&gz));
    assert!(!target.exists());
}

#[test]
fn generated_db_links_leaf_to_ca() {
    let dir = tempfile::tempdir().unwrap();
    let db = generate_in(dir.path(), "db.json");

    bin()
        .args(["read", "--path", db.to_str().unwrap(), "--format", "json"])
        .assert()
        .success()
        // leaf cert is linked to its CA
        .stdout(predicate::str::contains(
            r#""issuer": "test-ca.example.com""#,
        ))
        // CA is self-issued
        .stdout(predicate::str::contains(r#""issuer": "self""#))
        // every entry carries a UUID
        .stdout(predicate::str::contains(r#""id": ""#));
}
