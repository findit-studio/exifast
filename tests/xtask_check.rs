// SPDX-License-Identifier: GPL-3.0-or-later
// exifast — a 1:1 Rust port of ExifTool (Phil Harvey). See THIRD_PARTY.md.

//! Drift guard (table-codegen Phase-1 Task 8): the committed XMP table
//! (`src/formats/xmp/tables_generated.rs`) must still equal what
//! `cargo xtask gen-tables --module XMP … --check` produces from the pinned
//! `exiftool -listx` 13.59. This catches (a) a hand edit to the generated file,
//! (b) an emitter change that was not re-run, and (c) an exiftool version bump
//! that shifts a tag/value-map — keeping the checked-in table honest against
//! the generator + the pinned ExifTool.
//!
//! Skipped *gracefully* (never failed) when the toolchain the generator needs
//! is absent, so the suite does not break on a clean checkout / CI runner
//! without it:
//!   * the bundled ExifTool (`$EXIFTOOL`, else the sibling `../exiftool/`
//!     checkout) — the generator's source of truth;
//!   * `perl` — ExifTool is a Perl script;
//!   * Miri — cannot spawn processes;
//!   * a `cargo` on `PATH` to build + run the `xtask` crate.
//!
//! The `--check` run is side-effect-free: it regenerates IN MEMORY and only
//! COMPARES against the committed file (it never writes it). The nested cargo
//! build uses a SEPARATE target dir so it cannot deadlock on the outer test's
//! build lock.

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

/// Whether `cargo` is invokable (needed to build + run the `xtask` crate).
fn have_cargo() -> bool {
  Command::new(env!("CARGO"))
    .arg("--version")
    .status()
    .map(|s| s.success())
    .unwrap_or(false)
}

/// Shared body for every `--check` drift assertion: regenerate `module` (in the
/// `kind` vocabulary) IN MEMORY and fail if it differs from the committed `out`.
/// Skips *gracefully* (returns) when the generator's toolchain (bundled
/// ExifTool / perl / cargo) is absent, so a clean checkout / a CI runner without
/// it never breaks. The nested `cargo run -p xtask` uses a SEPARATE, stable
/// target dir so it cannot deadlock on the outer test's build lock, and
/// `RUSTFLAGS` is cleared so the lib's #55/FU-15 dead-code baseline does not
/// turn a `-Dwarnings` build into a false drift report.
fn assert_no_drift(module: &str, kind: &str, out: &str) {
  let root = env!("CARGO_MANIFEST_DIR");

  let Some(exiftool) = exiftool_script(root) else {
    eprintln!("SKIP: bundled ExifTool not found (set $EXIFTOOL); --check drift guard skipped");
    return;
  };
  if !have_perl() {
    eprintln!("SKIP: perl not available; --check drift guard skipped");
    return;
  }
  if !have_cargo() {
    eprintln!("SKIP: cargo not available; --check drift guard skipped");
    return;
  }

  // A SEPARATE target dir for the nested `cargo run -p xtask` so it does not
  // contend with the outer test invocation's build lock. Stable (reused across
  // runs) so repeat runs are fast.
  let nested_target = std::env::temp_dir().join("exifast-xtask-check-target");

  let status = Command::new(env!("CARGO"))
    .args([
      "run",
      "--quiet",
      "--release",
      "--package",
      "xtask",
      "--",
      "gen-tables",
      "--module",
      module,
      "--kind",
      kind,
      "--out",
      out,
      "--check",
    ])
    .current_dir(root)
    .env("EXIFTOOL", &exiftool)
    .env("CARGO_TARGET_DIR", &nested_target)
    // Do NOT inherit a `-Dwarnings` RUSTFLAGS into the nested build: the xtask
    // crate compiles the lib with its `std,all-formats` feature set, which has
    // a few `pub(crate)`-never-used items that warn (the gate's #55/FU-15
    // baseline), and `-Dwarnings` would fail that build — a false drift report.
    // The committed table is what matters here, not the lib's lint state.
    .env_remove("RUSTFLAGS")
    .status()
    .expect("failed to launch `cargo run -p xtask … --check`");

  assert!(
    status.success(),
    "committed {out} has DRIFTED from the generator (exiftool -listx 13.59). \
     Regenerate with `EXIFTOOL=… cargo xtask gen-tables --module {module} \
     --kind {kind} --out {out}` and commit the result."
  );
}

#[test]
#[cfg_attr(
  miri,
  ignore = "spawns cargo/perl/exiftool; Miri cannot spawn processes"
)]
fn committed_xmp_table_matches_generator() {
  // The XMP table is the `field` vocabulary (the `--module XMP` whole-group
  // path); kind defaults to `field`, passed explicitly here for symmetry.
  assert_no_drift("XMP", "field", "src/formats/xmp/tables_generated.rs");
}

#[test]
#[cfg_attr(
  miri,
  ignore = "spawns cargo/perl/exiftool; Miri cannot spawn processes"
)]
fn committed_dsf_table_matches_generator() {
  // `%DSF::Main` in the generic `tagdef` vocabulary (the audio/container tag
  // tables). Drift here means a 13.x ExifTool bump changed `DSF::Main`'s tags /
  // value-maps; the hand table in `src/formats/dsf.rs` must then be re-reviewed.
  assert_no_drift("DSF::Main", "tagdef", "src/formats/dsf_generated.rs");
}

#[test]
#[cfg_attr(
  miri,
  ignore = "spawns cargo/perl/exiftool; Miri cannot spawn processes"
)]
fn committed_aac_table_matches_generator() {
  // `%AAC::Main` in the generic `tagdef` vocabulary.
  assert_no_drift("AAC::Main", "tagdef", "src/formats/aac_generated.rs");
}

#[test]
#[cfg_attr(
  miri,
  ignore = "spawns cargo/perl/exiftool; Miri cannot spawn processes"
)]
fn committed_mpc_table_matches_generator() {
  // `%MPC::Main` in the generic `tagdef` vocabulary.
  assert_no_drift("MPC::Main", "tagdef", "src/formats/mpc_generated.rs");
}
