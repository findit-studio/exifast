//! Golden-v2 C4 — extraction throughput bench over the representative fixtures.
//!
//! Mirrors `tests/alloc_budget.rs`'s fixture set. The alloc-count harness is the
//! load-bearing perf guard (allocation pressure is the indexer KPI); this bench
//! tracks wall-clock so a CPU regression (an extra parse pass, an O(n²) scan)
//! shows up in `cargo bench` too. Not wired into CI — a developer aid.

use criterion::{criterion_group, Criterion};
use std::hint::black_box;

/// Read a fixture's bytes.
fn fixture_bytes(name: &str) -> Vec<u8> {
  let path = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
    .join("tests")
    .join("fixtures")
    .join(name);
  std::fs::read(&path).unwrap_or_else(|e| panic!("read fixture {name}: {e}"))
}

const FIXTURES: &[&str] = &[
  "MakerNotes_Apple.jpg",
  "MakerNotes_Canon.jpg",
  "ID3v2_4_big.mp3",
  "QuickTime_frea_rexing17b.mov",
  "Real.ra",
];

fn bench_extract(c: &mut Criterion) {
  // `media_metadata` — detect + parse + project (mode-independent typed path).
  let mut mm = c.benchmark_group("media_metadata");
  for &name in FIXTURES {
    let bytes = fixture_bytes(name);
    mm.bench_function(name, |b| {
      b.iter(|| black_box(exifast::media_metadata(black_box(&bytes))));
    });
  }
  mm.finish();

  // `extract_info` — the JSON render path, both modes (a MakerNote fixture
  // decodes only the requested mode's vendor body after P0).
  let mut ei = c.benchmark_group("extract_info");
  for &name in FIXTURES {
    let bytes = fixture_bytes(name);
    ei.bench_function(format!("{name}/-j"), |b| {
      b.iter(|| black_box(exifast::parser::extract_info(black_box(name), black_box(&bytes), true)));
    });
    ei.bench_function(format!("{name}/-n"), |b| {
      b.iter(|| {
        black_box(exifast::parser::extract_info(black_box(name), black_box(&bytes), false))
      });
    });
  }
  ei.finish();
}

criterion_group!(benches, bench_extract);

// A hand-written `main` (instead of `criterion_main!`) so the harness is inert
// under `cargo test --all-targets -- <args>`: that runs every target, including
// this bench, passing libtest flags (`--skip gen_golden`) that criterion's
// (default-features-trimmed) CLI parser rejects. `cargo bench` passes `--bench`;
// `cargo test` does NOT — so when `--bench` is absent we exit 0 without touching
// criterion's arg parser, keeping the conformance gate command working while
// still running the real timing loop under `cargo bench`.
fn main() {
  if !std::env::args().any(|a| a == "--bench") {
    // Invoked by `cargo test` (or `--list` etc.) — nothing to do; exit clean.
    return;
  }
  // `criterion_group!`'s generated `benches()` builds a `Criterion` from the
  // CLI args (here only `--bench`), runs every registered bench, and prints the
  // final summary.
  benches();
}
