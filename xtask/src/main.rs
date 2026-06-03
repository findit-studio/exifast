use anyhow::{bail, ensure, Context, Result};

mod conv_registry;
mod emit;
mod listx;

fn main() -> Result<()> {
  let args: Vec<String> = std::env::args().skip(1).collect();
  match args.first().map(String::as_str) {
    Some("gen-tables") => gen_tables(&args[1..]),
    _ => {
      eprintln!("usage: cargo xtask gen-tables --module <M> --out <path> [--check]");
      bail!("unknown command");
    }
  }
}

/// `cargo xtask gen-tables --module <M> --out <path> [--check]`.
///
/// Runs `exiftool -listx` (which dumps EVERY table — `-listx` ignores any
/// tag/group filter, so we filter to the wanted `<table>` in
/// [`listx::parse_listx`]), renders it via [`emit::emit_table`], then either
/// writes `--out` or, with `--check`, fails if the committed file has drifted.
///
/// `--module` is the ExifTool group-1 name (e.g. `XMP-tiff`); it is translated
/// to the `<table name=…>` form (`XMP::tiff`) by [`table_name_for_module`].
fn gen_tables(rest: &[String]) -> Result<()> {
  let module = flag(rest, "--module").context("--module required")?;
  let out = flag(rest, "--out").context("--out required")?;
  let check = rest.iter().any(|a| a == "--check");

  let exiftool = std::env::var("EXIFTOOL").unwrap_or_else(|_| "exiftool".into());
  let dump = std::process::Command::new(&exiftool)
    .arg("-listx")
    .output()
    .with_context(|| format!("run `{exiftool} -listx`"))?;
  ensure!(
    dump.status.success(),
    "`{exiftool} -listx` failed: {}",
    String::from_utf8_lossy(&dump.stderr)
  );
  let xml = String::from_utf8(dump.stdout).context("exiftool -listx emitted non-UTF8")?;

  let table_name = table_name_for_module(module);
  let model = listx::parse_listx(&xml, &table_name)?;
  let src = emit::emit_table(&model);

  if check {
    let existing = std::fs::read_to_string(out).unwrap_or_default();
    ensure!(
      existing == src,
      "generated table drifted from {out}; rerun `cargo xtask gen-tables --module {module} --out {out}`"
    );
  } else {
    std::fs::write(out, &src).with_context(|| format!("write {out}"))?;
  }
  Ok(())
}

/// Translate an ExifTool group-1 module name to its `<table name=…>` form:
/// `XMP-tiff` → `XMP::tiff`, `XMP-exif` → `XMP::exif`. A name that is already
/// in `Mod::table` form, or has no `-`, is returned unchanged.
fn table_name_for_module(module: &str) -> String {
  if module.contains("::") {
    return module.to_string();
  }
  match module.split_once('-') {
    Some((g0, sub)) => format!("{g0}::{sub}"),
    None => module.to_string(),
  }
}

/// The value following `name` in `rest` (e.g. `--out <value>`).
fn flag<'a>(rest: &'a [String], name: &str) -> Option<&'a str> {
  rest
    .iter()
    .position(|a| a == name)
    .and_then(|i| rest.get(i + 1))
    .map(String::as_str)
}

#[cfg(test)]
mod tests {
  use super::*;

  #[test]
  fn module_to_table_name() {
    assert_eq!(table_name_for_module("XMP-tiff"), "XMP::tiff");
    assert_eq!(table_name_for_module("XMP-exif"), "XMP::exif");
    assert_eq!(table_name_for_module("XMP::tiff"), "XMP::tiff");
    assert_eq!(table_name_for_module("XMP"), "XMP");
  }

  #[test]
  fn flag_reads_following_value() {
    let args = vec![
      "--module".to_string(),
      "XMP-tiff".to_string(),
      "--out".to_string(),
      "/tmp/x.rs".to_string(),
    ];
    assert_eq!(flag(&args, "--module"), Some("XMP-tiff"));
    assert_eq!(flag(&args, "--out"), Some("/tmp/x.rs"));
    assert_eq!(flag(&args, "--missing"), None);
  }
}
