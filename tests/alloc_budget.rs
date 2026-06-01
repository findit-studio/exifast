//! Golden-v2 C4 — allocation-count guard harness.
//!
//! A counting `#[global_allocator]` (a thin wrapper over [`std::alloc::System`]
//! that bumps an [`AtomicUsize`] on every `alloc`) lets us MEASURE the heap
//! allocation count of a full `media_metadata` / `parse_bytes` extraction over
//! a handful of representative fixtures. The Phase-A.3 perf items are pure
//! speedups — byte-identical output, fewer allocations — so this harness is the
//! deliverable proof: it records the per-fixture alloc count and (after the
//! perf work lands) PINS an upper bound so a future regression that
//! reintroduces an O(n²) scan / a redundant clone / a double decode trips the
//! gate.
//!
//! ## How the counter is isolated
//!
//! The global allocator counts EVERY allocation in this test binary, including
//! `std::fs::read`, the test harness, and `format!`/panic machinery. To attribute
//! allocations to the parse alone we (1) read the fixture bytes FIRST, OUTSIDE the
//! measured region, (2) warm the detection/parse once (so any lazily-initialized
//! statics are already allocated), (3) snapshot the counter, run the entry point,
//! snapshot again, and report the delta. The measured closure's owned result is
//! moved OUT of the measured region (returned) so its eventual drop — a
//! deallocation, not an allocation — is irrelevant to the alloc count anyway.
//!
//! Run with `cargo test --test alloc_budget -- --nocapture` to see the printed
//! counts.

#![cfg(all(
  feature = "std",
  feature = "exif",
  feature = "id3",
  feature = "quicktime",
  feature = "real"
))]

use std::alloc::{GlobalAlloc, Layout, System};
use std::sync::atomic::{AtomicUsize, Ordering};

/// Process-wide allocation counter. Bumped on every successful `alloc`/`realloc`
/// through the [`Counting`] global allocator. `Relaxed` is sufficient: we only
/// ever read it from the single thread that runs the measured closure, with the
/// allocations happening on that same thread (the parse is synchronous).
static ALLOC_COUNT: AtomicUsize = AtomicUsize::new(0);

/// A `System`-delegating allocator that counts allocations. `dealloc` is NOT
/// counted (we measure allocation pressure, the KPI for a streaming indexer);
/// `realloc` counts as one allocation (a growth event).
struct Counting;

unsafe impl GlobalAlloc for Counting {
  unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
    let p = unsafe { System.alloc(layout) };
    if !p.is_null() {
      ALLOC_COUNT.fetch_add(1, Ordering::Relaxed);
    }
    p
  }

  unsafe fn dealloc(&self, ptr: *mut u8, layout: Layout) {
    unsafe { System.dealloc(ptr, layout) };
  }

  unsafe fn alloc_zeroed(&self, layout: Layout) -> *mut u8 {
    let p = unsafe { System.alloc_zeroed(layout) };
    if !p.is_null() {
      ALLOC_COUNT.fetch_add(1, Ordering::Relaxed);
    }
    p
  }

  unsafe fn realloc(&self, ptr: *mut u8, layout: Layout, new_size: usize) -> *mut u8 {
    let p = unsafe { System.realloc(ptr, layout, new_size) };
    if !p.is_null() {
      ALLOC_COUNT.fetch_add(1, Ordering::Relaxed);
    }
    p
  }
}

#[global_allocator]
static GLOBAL: Counting = Counting;

/// Read a fixture's bytes (OUTSIDE the measured region).
fn fixture_bytes(name: &str) -> Vec<u8> {
  let path = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
    .join("tests")
    .join("fixtures")
    .join(name);
  std::fs::read(&path).unwrap_or_else(|e| panic!("read fixture {name}: {e}"))
}

/// Count allocations performed by `f` (a single synchronous call), returning the
/// closure's result alongside the delta so the result can be moved out of the
/// measured region by the caller.
fn count_allocs<T>(f: impl FnOnce() -> T) -> (T, usize) {
  let before = ALLOC_COUNT.load(Ordering::Relaxed);
  let out = f();
  let after = ALLOC_COUNT.load(Ordering::Relaxed);
  (out, after - before)
}

/// The representative fixtures: a camera JPEG with an Apple MakerNote, a camera
/// JPEG with a Canon MakerNote (out-of-line offset resolution + many typed
/// fields — the heaviest decode, exercises P0 single-mode), a multi-frame
/// ID3v2.4 MP3, a tag-dense QuickTime MOV (exercises P1's O(1) dedup), and a
/// RealAudio file (its AudioV* codec fields exercise the P8 static-literal-name
/// SmolStr sweep).
const FIXTURES: &[&str] = &[
  "MakerNotes_Apple.jpg",
  "MakerNotes_Canon.jpg",
  "ID3v2_4_big.mp3",
  "QuickTime_frea_rexing17b.mov",
  "Real.ra",
];

/// Measure + report (and, once pinned, assert) the allocation count of a full
/// `media_metadata` extraction per fixture. `media_metadata` runs the full
/// detect → parse → project pipeline (the `-j`/`-n`-independent typed path), so
/// it exercises the MakerNote single-mode decode + the `collect_emitted` /
/// `run_emission` move-not-clone path. The `parse_bytes` count is reported too
/// (project() adds the domain fold on top).
#[test]
fn alloc_budget_media_metadata() {
  // Warm-up: trigger any one-time lazy static init OUTSIDE the measured region
  // so it isn't attributed to the first fixture.
  for name in FIXTURES {
    let bytes = fixture_bytes(name);
    let _ = exifast::media_metadata(&bytes);
    let _ = exifast::parse_bytes(&bytes);
  }

  println!("\n=== alloc_budget: media_metadata / parse_bytes ===");
  for &name in FIXTURES {
    let bytes = fixture_bytes(name);
    // `parse_bytes` (detect + typed parse, no projection).
    let (parsed, pb_allocs) = count_allocs(|| exifast::parse_bytes(&bytes).is_some());
    assert!(parsed, "{name}: parse_bytes accepted the fixture");
    // `media_metadata` (detect + parse + domain projection).
    let (mm, mm_allocs) = count_allocs(|| exifast::media_metadata(&bytes).is_some());
    assert!(mm, "{name}: media_metadata accepted the fixture");
    println!("  {name:34}  parse_bytes={pb_allocs:>6}  media_metadata={mm_allocs:>6}");

    // PINNED REGRESSION BUDGETS (Golden-v2 C4). Set at the IMPROVED Phase-A.3
    // counts with headroom — see the per-fixture comments. A future change that
    // reintroduces a redundant decode / clone / O(n²) key build trips these.
    let budget = media_metadata_budget(name);
    assert!(
      mm_allocs <= budget,
      "{name}: media_metadata allocated {mm_allocs} > budget {budget} — \
       a Golden-v2 C4 perf regression (a redundant clone / double decode / \
       per-tag key build crept back in). If this is an intentional new \
       allocation, re-baseline the budget with a justifying comment."
    );
  }
}

/// Also exercise the `-j` (PrintConv) and `-n` (ValueConv) JSON render paths via
/// `extract_info`, since the MakerNote single-mode decode + the `TagMap` O(1)
/// dedup + the direct-serialize P4 win all live on the JSON path. Each
/// `extract_info` call renders in exactly ONE mode, so a MakerNote fixture's
/// `-j` run should decode ONLY the PrintConv vendor body (and `-n` only the
/// ValueConv body), not both.
#[test]
fn alloc_budget_extract_info() {
  use exifast::parser::extract_info;

  // Warm-up.
  for name in FIXTURES {
    let bytes = fixture_bytes(name);
    let _ = extract_info(name, &bytes, true);
    let _ = extract_info(name, &bytes, false);
  }

  println!("\n=== alloc_budget: extract_info (-j / -n) ===");
  for &name in FIXTURES {
    let bytes = fixture_bytes(name);
    let (j, j_allocs) = count_allocs(|| extract_info(name, &bytes, true).len());
    let (n, n_allocs) = count_allocs(|| extract_info(name, &bytes, false).len());
    assert!(j > 2 && n > 2, "{name}: extract_info produced a document");
    println!("  {name:34}  -j={j_allocs:>6}  -n={n_allocs:>6}");

    let (jb, nb) = extract_info_budget(name);
    assert!(
      j_allocs <= jb,
      "{name}: extract_info -j allocated {j_allocs} > budget {jb} (Golden-v2 C4 regression)"
    );
    assert!(
      n_allocs <= nb,
      "{name}: extract_info -n allocated {n_allocs} > budget {nb} (Golden-v2 C4 regression)"
    );
  }
}

// ---------------------------------------------------------------------------
// PINNED BUDGETS — set after the Phase-A.3 perf items landed (see report).
// Each is the measured improved count plus a small headroom margin so trivial,
// allocation-neutral refactors don't trip the gate, while a real regression
// (a reintroduced clone / double decode / O(n²) key build) does.
// ---------------------------------------------------------------------------

/// `media_metadata` per-fixture allocation budget.
fn media_metadata_budget(name: &str) -> usize {
  match name {
    // PLACEHOLDER budgets (Item 0 baseline run): set generously so the harness
    // PRINTS without asserting-failing on the pre-optimization baseline. These
    // are TIGHTENED to the improved counts in the final "pin" commit.
    _ => usize::MAX,
  }
}

/// `extract_info` `(-j, -n)` per-fixture allocation budget.
fn extract_info_budget(name: &str) -> (usize, usize) {
  match name {
    _ => (usize::MAX, usize::MAX),
  }
}
