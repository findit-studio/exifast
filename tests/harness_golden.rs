//! Verifies the golden-generation harness wiring (bundled Perl ExifTool).
//!
//! Unix-only: the generator is a `bash` + `perl` pipeline, and the CI
//! matrix includes `windows-latest` where it cannot run. It is also
//! skipped *gracefully* when `perl` or the bundled ExifTool is absent
//! (e.g. a clean checkout without the sibling `exiftool/` tree), so the
//! suite never fails merely because this optional toolchain is missing.
//! The check writes only into a throwaway temp dir — it never mutates the
//! tracked `tests/golden/` files.
#![cfg(unix)]

use std::path::{Path, PathBuf};
use std::process::Command;

/// The bundled ExifTool script (`$EXIFTOOL` override, else the sibling
/// checkout), or `None` when it is not present → skip, not fail.
fn exiftool_script(root: &str) -> Option<PathBuf> {
  if let Ok(p) = std::env::var("EXIFTOOL") {
    let p = PathBuf::from(p);
    return p.is_file().then_some(p);
  }
  let p = Path::new(root).join("../exiftool/exiftool");
  p.is_file().then_some(p)
}

/// Whether a usable `perl` is on `PATH` (ExifTool is a Perl script).
fn have_perl() -> bool {
  Command::new("perl")
    .args(["-e", "1"])
    .status()
    .map(|s| s.success())
    .unwrap_or(false)
}

#[test]
#[cfg_attr(
  miri,
  ignore = "spawns bash/perl/exiftool; Miri cannot spawn processes"
)]
fn gen_golden_produces_valid_stable_json() {
  let root = env!("CARGO_MANIFEST_DIR");

  let Some(exiftool) = exiftool_script(root) else {
    eprintln!("SKIP: bundled ExifTool not found (set $EXIFTOOL); harness check skipped");
    return;
  };
  if !have_perl() {
    eprintln!("SKIP: perl not available; harness check skipped");
    return;
  }

  // Write goldens into a throwaway dir (via $GOLDEN_DIR) so this test is
  // side-effect-free and never touches the tracked tests/golden/ files.
  let tmp = tempfile::tempdir().expect("create tempdir");
  let out = tmp.path().join("AAC.aac.json");

  let run = || {
    let status = Command::new("bash")
      .arg(Path::new(root).join("tools/gen_golden.sh"))
      .arg("AAC.aac")
      .current_dir(root)
      .env("EXIFTOOL", &exiftool)
      .env("GOLDEN_DIR", tmp.path())
      .status()
      .expect("failed to launch gen_golden.sh");
    assert!(status.success(), "gen_golden.sh exited non-zero");
    std::fs::read(&out).expect("golden file not written")
  };

  // Deterministic: two runs must be byte-identical.
  let first = run();
  let second = run();
  assert_eq!(first, second, "golden output is not deterministic");

  // Valid `[ {…} ]`, and `SourceFile` must be the STABLE RELATIVE path
  // (the generator runs ExifTool from the fixtures dir with the bare
  // basename) — never a machine-specific absolute path that would make
  // committed goldens non-portable.
  let v: serde_json::Value = serde_json::from_slice(&first).expect("golden is not valid JSON");
  let obj = v
    .get(0)
    .and_then(|o| o.as_object())
    .expect("expected [ {…} ]");
  assert_eq!(
    obj.get("SourceFile").and_then(|s| s.as_str()),
    Some("AAC.aac"),
    "SourceFile must be the stable relative fixture name, not an absolute path"
  );
}
