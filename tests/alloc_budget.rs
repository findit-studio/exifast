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

/// Measure + report + assert the per-fixture allocation counts for both the
/// `media_metadata`/`parse_bytes` typed path AND the `extract_info` `-j`/`-n`
/// JSON render path.
///
/// **One** `#[test]` (not two) ON PURPOSE: the allocation counter is a
/// PROCESS-GLOBAL `AtomicUsize`, and libtest runs a binary's tests on multiple
/// threads, so a SECOND measuring test would increment the shared counter
/// DURING this one's measurement window (cross-contamination — observed as
/// inflated, non-deterministic counts when both ran in parallel). With a single
/// test the measured regions are strictly sequential on one thread, so the
/// counts are deterministic regardless of `--test-threads`. (This binary has no
/// other test, and the criterion bench is a separate binary with its own
/// allocator/counter.)
///
/// `media_metadata` runs detect → parse → project (the mode-independent typed
/// path: P0 single-mode MakerNote decode + P2/P3 move-not-clone). `extract_info`
/// runs the JSON render path (P1 O(1) dedup + P4 direct-serialize + P0). Each
/// `extract_info` call renders in exactly ONE mode, so a MakerNote fixture's
/// `-j` run decodes ONLY the PrintConv vendor body (and `-n` only ValueConv).
#[test]
fn alloc_budget() {
  use exifast::parser::extract_info;

  // Warm-up: trigger any one-time lazy static init OUTSIDE the measured regions
  // so it isn't attributed to the first fixture.
  for name in FIXTURES {
    let bytes = fixture_bytes(name);
    let _ = exifast::media_metadata(&bytes);
    let _ = exifast::parse_bytes(&bytes);
    let _ = extract_info(name, &bytes, true);
    let _ = extract_info(name, &bytes, false);
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

    // PINNED REGRESSION BUDGET (Golden-v2 C4) — the IMPROVED Phase-A.3 count
    // plus headroom. A regression past it means a redundant decode / clone /
    // per-tag key build crept back in.
    let budget = media_metadata_budget(name);
    assert!(
      mm_allocs <= budget,
      "{name}: media_metadata allocated {mm_allocs} > budget {budget} — \
       a Golden-v2 C4 perf regression (a redundant clone / double decode / \
       per-tag key build crept back in). If this is an intentional new \
       allocation, re-baseline the budget with a justifying comment."
    );
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

/// `media_metadata` per-fixture allocation budget. PINNED at the improved
/// Phase-A.3 count + ~6-10% headroom (the comment shows the measured count). A
/// regression past these means a redundant decode / clone / per-tag key build
/// crept back in; an intentional new allocation should re-baseline WITH a
/// justifying comment, not just bump the number.
///
/// RE-BASELINED for Contract A (golden-value pipeline, #198): `RawValue::Text`
/// now carries the pre-FixUTF8 `raw` bytes alongside the display `text`, so each
/// decoded EXIF `string` leaf allocates ONE extra `Box<[u8]>`. This is an
/// intentional, faithful cost (a byte-walking RawConv must see `$val`'s original
/// bytes); the string-heavy fixtures rise by their string-leaf count (Apple
/// +15, Canon +9, ID3 +15 — ID3 strings flow through the same EXIF `Text`).
fn media_metadata_budget(name: &str) -> usize {
  match name {
    // Canon dominates (the MakerNote vendor decode). P0 (single-mode decode)
    // took its `media_metadata` from 1391 → 756; Contract A adds the per-string
    // `raw` box (756 → 765).
    "MakerNotes_Canon.jpg" => 820, // measured 765 (Contract A: 756 → 765)
    "MakerNotes_Apple.jpg" => 160, // measured 148 (Contract A: 133 → 148)
    "ID3v2_4_big.mp3" => 225,      // measured 209 (Contract A: 194 → 209)
    "QuickTime_frea_rexing17b.mov" => 40, // measured 31 (no EXIF string leaf)
    "Real.ra" => 30,               // measured 21 (P8: 31 → 21)
    // An unlisted fixture: no pinned budget (the harness still prints + checks
    // parse acceptance, just no ceiling).
    _ => usize::MAX,
  }
}

/// `extract_info` `(-j, -n)` per-fixture allocation budget — the JSON render
/// path that carries the P1 O(1) dedup + P4 direct-serialize + P0 single-mode
/// MakerNote wins. PINNED at the improved Phase-A.3 counts + headroom.
///
/// RE-BASELINED for Contract A (#198): the per-string `raw` box (see
/// `media_metadata_budget`) also surfaces on the render path (Apple +18/+18,
/// Canon +9/+12, ID3 +8/+8) — an intentional, faithful cost.
fn extract_info_budget(name: &str) -> (usize, usize) {
  match name {
    // P1+P4 took -j 2085 → 1547; P0 then took it 1547 → 907. -n stays ~1632
    // (one value-conv decode, now on demand). Contract A: (907,1632) → (916,1644).
    "MakerNotes_Canon.jpg" => (985, 1750), // measured (916, 1644)
    // RE-BASELINED for #243 phase 3 (Apple → shared Walker). Routing Apple
    // through the shared `Walker` (instead of the bespoke `walk_apple_body`
    // oracle) adds the Walker's own structural allocations on the `-n` recompute
    // walk (its `entries` / `active_ifd_offsets` Vecs + chain-guard `HashSet`),
    // which the leaner hand-written oracle did not allocate: `-n` rises 474 → 511.
    // This is the migration's INTENDED structural cost, NOT a redundant clone —
    // BOTH per-tag `RawValue` clones (`emit_apple_value` + the typed-populate
    // capture) were removed (matching Canon, which passes `&RawValue` straight
    // to its PrintConv), which is what keeps `media_metadata` BELOW its 160
    // budget (149) and `-j` within its 385 budget (377). The `-j` ceiling is
    // unchanged (377 < 385).
    //
    // RE-BASELINED AGAIN for #243 phase 3 Apple R4 (format-16 `Make eq 'Apple'`
    // gate): the isolated Apple walk now threads the parent IFD0 `Make` into its
    // fresh `Walker` (`captured_make: make.map(String::from)`) so the BigTIFF
    // `int64u` (code 16) carve-out gates on `$$et{Make} eq 'Apple'`
    // (`Exif.pm:6464`), faithful to ExifTool. The real Apple fixture's Make is
    // "Apple", so each isolated walk allocates ONE short `String`; the `-n` path
    // runs TWO isolated walks (the dispatch's eager `-j` decode for the typed slot
    // + the on-demand recompute), so `-n` rises 511 → 513 (+2). This is the
    // correctness fix's INTENDED, minimal cost (a non-Apple container must NOT
    // admit code 16), NOT a redundant clone. `-n` ceiling raised to 514. `-j`
    // runs ONE isolated walk (+1: 377 → 378), still within its 385 budget.
    "MakerNotes_Apple.jpg" => (385, 514), // measured (378, 513) — R4 Make-gate threads IFD0 Make into the isolated walk(s)
    "ID3v2_4_big.mp3" => (130, 130),      // measured (118, 117)
    "QuickTime_frea_rexing17b.mov" => (150, 150), // measured (135, 137); P1: 266/259 → 135/137
    "Real.ra" => (100, 100),              // measured (88, 87)
    _ => (usize::MAX, usize::MAX),
  }
}
