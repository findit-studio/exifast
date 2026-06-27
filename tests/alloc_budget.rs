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

/// Process-wide allocation BYTE counter (the requested `layout.size()` summed
/// over every `alloc`/`alloc_zeroed`, plus the `new_size` of every `realloc`).
/// Complements [`ALLOC_COUNT`]: an alloc-COUNT delta is size-blind (one big copy
/// and two big copies differ by only ONE count), so proving "a block is copied
/// once, not twice" needs the BYTE volume. Read on the same single thread as the
/// measured closure, so `Relaxed` is sufficient.
static ALLOC_BYTES: AtomicUsize = AtomicUsize::new(0);

/// A `System`-delegating allocator that counts allocations. `dealloc` is NOT
/// counted (we measure allocation pressure, the KPI for a streaming indexer);
/// `realloc` counts as one allocation (a growth event).
struct Counting;

unsafe impl GlobalAlloc for Counting {
  unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
    let p = unsafe { System.alloc(layout) };
    if !p.is_null() {
      ALLOC_COUNT.fetch_add(1, Ordering::Relaxed);
      ALLOC_BYTES.fetch_add(layout.size(), Ordering::Relaxed);
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
      ALLOC_BYTES.fetch_add(layout.size(), Ordering::Relaxed);
    }
    p
  }

  unsafe fn realloc(&self, ptr: *mut u8, layout: Layout, new_size: usize) -> *mut u8 {
    let p = unsafe { System.realloc(ptr, layout, new_size) };
    if !p.is_null() {
      ALLOC_COUNT.fetch_add(1, Ordering::Relaxed);
      ALLOC_BYTES.fetch_add(new_size, Ordering::Relaxed);
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

/// Count the BYTE VOLUME (`layout.size()` summed) allocated by `f`, returning the
/// closure's result alongside the delta. Used to prove a copy happens once, not
/// twice — a property the size-blind [`count_allocs`] cannot see (it differs by
/// only ONE count between a single and a double materialization of the same block).
fn count_alloc_bytes<T>(f: impl FnOnce() -> T) -> (T, usize) {
  let before = ALLOC_BYTES.load(Ordering::Relaxed);
  let out = f();
  let after = ALLOC_BYTES.load(Ordering::Relaxed);
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

  read_value_byte_len_float_rational_is_zero_heap();
  geotiff_block_capture_is_single_copy();
}

/// The placeholder-length path ([`exifast::exif::ifd::read_value_byte_len`]) for
/// a LARGE in-bounds `Double`/`Rational` block must allocate O(1) heap, NOT
/// O(count): each element's `%.15g` / rational `$val` byte length is measured by
/// writing into a `LenSink` (a byte-counting `fmt::Write` sink) and a stack
/// buffer, never by building + dropping a per-element `String`. Before the fix
/// the `Double` arm called `format_g(..).len()` and the `Rational` arm
/// `.exiftool_val_str().len()`, each forcing ONE heap `String` per element — so
/// a count-N block (near the `0x7fffffff` BigTIFF gate) drove N short heap
/// allocations (an allocator/CPU-churn DoS). This measures the alloc delta and
/// asserts it is a tiny CONSTANT, independent of `count`.
///
/// Called INLINE from the single `alloc_budget` test (not a second `#[test]`):
/// the allocation counter is a process-global `AtomicUsize`, so a parallel
/// second measuring test would cross-contaminate this window (see the module
/// doc). Running it as a sequential section keeps the counts deterministic.
fn read_value_byte_len_float_rational_is_zero_heap() {
  use exifast::exif::ifd::{ByteOrder, Format, read_value_byte_len};

  // A 16 KiB buffer of varied (non-zero, multi-token) bytes so each element's
  // `%.15g` / rational token is a realistic multi-byte string — the case the OLD
  // per-element `String` allocated. Built OUTSIDE the measured region.
  let mut data = vec![0u8; 16 * 1024];
  for (i, b) in data.iter_mut().enumerate() {
    *b = (i as u8).wrapping_mul(31).wrapping_add(7);
  }
  let order = ByteOrder::Little;

  // SMALL and LARGE element counts for the same format. If the path allocated
  // per element, the LARGE count's delta would dwarf the SMALL's; the fix makes
  // BOTH a tiny constant.
  let small = 4usize;
  let large = 2048usize; // Double: 2048 * 8 = 16384 = the whole buffer.

  // Warm-up: any first-call lazy init happens OUTSIDE the measured deltas.
  let _ = read_value_byte_len(&data, 0, Format::Double, small, data.len(), order);
  let _ = read_value_byte_len(&data, 0, Format::Rational64s, small, data.len(), order);

  // `Double` — the headline DoS shape (`GeoTiffDoubleParams`, code 12).
  let (len_small_d, allocs_small_d) =
    count_allocs(|| read_value_byte_len(&data, 0, Format::Double, small, data.len(), order));
  let (len_large_d, allocs_large_d) =
    count_allocs(|| read_value_byte_len(&data, 0, Format::Double, large, data.len(), order));

  // `Rational64s` — the other heap-`String`-per-element arm (`exiftool_val_str`).
  let large_r = 2048usize; // 2048 * 8 = 16384 = the whole buffer.
  let (len_small_r, allocs_small_r) =
    count_allocs(|| read_value_byte_len(&data, 0, Format::Rational64s, small, data.len(), order));
  let (len_large_r, allocs_large_r) =
    count_allocs(|| read_value_byte_len(&data, 0, Format::Rational64s, large_r, data.len(), order));

  println!("\n=== alloc_budget: read_value_byte_len zero-heap (float/rational) ===");
  println!(
    "  Double      small({small})={allocs_small_d} large({large})={allocs_large_d}  (len {len_small_d}/{len_large_d})"
  );
  println!(
    "  Rational64s small({small})={allocs_small_r} large({large_r})={allocs_large_r}  (len {len_small_r}/{len_large_r})"
  );

  // The lengths are non-trivial (a multi-token join), proving the measured call
  // actually formatted every element — not a short-circuit to 0.
  assert!(
    len_large_d > len_small_d && len_large_d > 1000,
    "Double large-count length must reflect every formatted element (got {len_large_d})"
  );
  assert!(
    len_large_r > len_small_r && len_large_r > 1000,
    "Rational large-count length must reflect every formatted element (got {len_large_r})"
  );

  // THE REGRESSION: the LARGE-count probe (2048 elements) must allocate a tiny
  // CONSTANT, NOT ~2048 (one heap `String` per element, the pre-fix behavior).
  // The fix's per-element path (`LenSink` + a stack `StackBuf`) touches the heap
  // ZERO times; the small ceiling absorbs any incidental harness allocation
  // while remaining FAR below O(count). If `format_g_into`/`exiftool_val_str_into`
  // regressed to building a per-element `String`, `allocs_large_*` would be
  // ~2048 and this trips.
  const ZERO_HEAP_CEILING: usize = 8;
  assert!(
    allocs_large_d <= ZERO_HEAP_CEILING,
    "Double placeholder-length path allocated {allocs_large_d} heap blocks for {large} elements \
     — expected O(1) (≤ {ZERO_HEAP_CEILING}); a per-element `String` regressed back in \
     (the #150 allocation-DoS class)."
  );
  assert!(
    allocs_large_r <= ZERO_HEAP_CEILING,
    "Rational placeholder-length path allocated {allocs_large_r} heap blocks for {large_r} elements \
     — expected O(1) (≤ {ZERO_HEAP_CEILING}); a per-element `String` regressed back in."
  );

  // And the delta does NOT grow with count: large-count allocs must not exceed
  // the small-count allocs by more than the constant ceiling (i.e. it is NOT
  // proportional to the 512× larger element count).
  assert!(
    allocs_large_d <= allocs_small_d + ZERO_HEAP_CEILING,
    "Double allocs scaled with count ({allocs_small_d} → {allocs_large_d} for {small} → {large}) \
     — the placeholder-length path must be O(1) in `count`."
  );
  assert!(
    allocs_large_r <= allocs_small_r + ZERO_HEAP_CEILING,
    "Rational allocs scaled with count ({allocs_small_r} → {allocs_large_r}) — must be O(1)."
  );
}

/// #429 — the classic-TIFF GeoTiff block-capture fast-path copies an over-large
/// `GeoTiffDoubleParams` (0x87b0) block AT MOST ONCE.
///
/// The three `Binary => 1` GeoTiff block tags (`GeoTiffDirectory` 0x87af /
/// `GeoTiffDoubleParams` 0x87b0 / `GeoTiffAsciiParams` 0x87b1) are never emitted
/// as leaves — they are captured raw for the post-IFD0 `ProcessGeoTiff` pass and
/// then dropped. The pre-fix classic walker still fell through to the generic
/// `read_value`, materializing the full `undef` payload into a THROWAWAY
/// `RawValue::Bytes`, and THEN `emit` copied the same slice AGAIN into the
/// capture slot — TWO heap copies of an attacker-controlled, in-bounds-but-huge
/// block, both BEFORE `geotiff::process` (and so before its `MAX_GEOKEY_ELEMENTS`
/// `DirectoryTooLarge` budget) could run. The fix special-cases the three tags in
/// `walk_entry` BEFORE `read_value`: it captures the block ONCE and returns,
/// never building the throwaway `RawValue`/`ExifEntry`.
///
/// This crafts a TIFF whose sole IFD0 entry is a `GeoTiffDoubleParams` block with
/// NO `GeoTiffDirectory` — so `geotiff::process` returns early (`$et->GetValue
/// ('GeoTiffDirectory') or return`, `GeoTiff.pm:2136`) and its budget NEVER runs
/// on the params, leaving the `walk_entry` capture as the ONLY bound. It measures
/// the BYTE volume of a SMALL-block vs a LARGE-block parse: the block-proportional
/// GROWTH must be ~ONE copy of the size increase (the single capture), not TWO.
/// The constant structural overhead cancels in the delta, so a `1.5×` ceiling
/// cleanly separates the single-copy fast-path (~1.0×) from the pre-fix
/// double-copy (~2.0×).
///
/// Called INLINE from the single `alloc_budget` test (the allocation counters are
/// process-global, so a parallel second `#[test]` would cross-contaminate this
/// window — see the module doc).
fn geotiff_block_capture_is_single_copy() {
  use exifast::parse_exif;

  // A classic little-endian TIFF whose sole IFD0 entry is a `GeoTiffDoubleParams`
  // (0x87b0) `undef[block]` value out-of-line at offset 26, with NO 0x87af
  // directory. On-disk `undef` (1-byte element) so `count == block == read_len`.
  fn tiff_with_double_params(block: usize) -> Vec<u8> {
    let mut t: Vec<u8> = vec![b'I', b'I', 0x2a, 0x00, 0x08, 0x00, 0x00, 0x00];
    t.extend_from_slice(&1u16.to_le_bytes()); // IFD0 numEntries = 1
    t.extend_from_slice(&0x87b0u16.to_le_bytes()); // tag = GeoTiffDoubleParams
    t.extend_from_slice(&7u16.to_le_bytes()); // format = UNDEF (1-byte element)
    t.extend_from_slice(&u32::try_from(block).expect("fits u32").to_le_bytes()); // count
    t.extend_from_slice(&26u32.to_le_bytes()); // out-of-line value offset
    t.extend_from_slice(&0u32.to_le_bytes()); // next-IFD = 0
    assert_eq!(t.len(), 26, "the value must start exactly at offset 26");
    t.resize(26 + block, 0x5a); // the in-bounds params block
    t
  }

  const SMALL: usize = 64 * 1024; // 64 KiB
  const LARGE: usize = 4 * 1024 * 1024; // 4 MiB
  let small_tiff = tiff_with_double_params(SMALL);
  let large_tiff = tiff_with_double_params(LARGE);

  // Warm-up OUTSIDE the measured region (lazy statics, first-call init).
  assert!(parse_exif(&small_tiff).is_some());
  assert!(parse_exif(&large_tiff).is_some());

  let (small_ok, small_bytes) = count_alloc_bytes(|| parse_exif(&small_tiff).is_some());
  let (large_ok, large_bytes) = count_alloc_bytes(|| parse_exif(&large_tiff).is_some());
  assert!(small_ok && large_ok, "both crafted TIFFs parse");

  println!("\n=== alloc_budget: geotiff block-capture single-copy ===");
  println!("  0x87b0 small({SMALL})={small_bytes}B  large({LARGE})={large_bytes}B");

  // The large parse must allocate AT LEAST one full block (proves the capture
  // actually ran — not a short-circuit that never touched the params).
  assert!(
    large_bytes >= LARGE,
    "the large block must be captured at least once: {large_bytes} < {LARGE}"
  );

  // THE REGRESSION GUARD: the block-proportional GROWTH between the two parses
  // must be ~ONE copy of the block-size increase (the single capture). A growth
  // approaching 2× means the block was materialized TWICE — the `read_value`
  // throwaway plus the `emit` slot copy that the #429 fast-path removed.
  let block_delta = LARGE - SMALL;
  let measured_delta = large_bytes.saturating_sub(small_bytes);
  let ceiling = block_delta + block_delta / 2; // 1.5× — between 1 copy and 2.
  assert!(
    measured_delta < ceiling,
    "GeoTiff 0x87b0 capture grew {measured_delta} bytes for a {block_delta}-byte \
     block-size increase (ceiling {ceiling} = 1.5×) — a growth near 2× means the \
     block is copied TWICE (the read_value throwaway + the emit copy the #429 \
     fast-path eliminated)."
  );
  // And it IS at least one copy of the delta (the capture scales with the block),
  // bracketing the growth to ~[1×, 1.5×) — i.e. exactly one copy.
  assert!(
    measured_delta >= block_delta,
    "the capture must scale one-for-one with the block: {measured_delta} < {block_delta}"
  );
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
    "MakerNotes_Apple.jpg" => 165, // measured 151 (#261 SOF File dims: 148 → 151)
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
    // RE-BASELINED for #261 (JPEG SOF `File:*` dimension tags): emitting the six
    // SOF tags (`ImageWidth`/`ImageHeight`/`EncodingProcess`/`BitsPerSample`/
    // `ColorComponents`/`YCbCrSubSampling`) grows the per-render `tags` Vec by 6
    // EmittedTags, so `-j` rises 378 → 384 and `-n` 513 → 520. An intentional,
    // faithful cost (these tags are byte-identical to bundled ExifTool), NOT a
    // redundant clone — the names are `SmolStr::new_static` and the dimension
    // values are integer `TagValue`s (no heap), the only heap touch being the Vec
    // growth.
    //
    // RE-BASELINED for #133 PR 3 (Tier-A EXIF Composites): the JSON render path's
    // Composite post-pass now BUILDS Apple's full ported Composite set — the PR-2
    // GPS quintet (GPSLatitude/Longitude/Altitude/DateTime/Position) PLUS the new
    // Tier-A `Aperture`/`ImageSize`/`Megapixels`/`ShutterSpeed`/`SubSecCreateDate`/
    // `SubSecDateTimeOriginal` (Apple carries FNumber/dimensions/DateTimeOriginal/
    // SubSecTime). Each built composite renders a value + appends to BOTH the
    // ValueConv and PrintConv views, and the `BuildCompositeTags` fixpoint
    // allocates a per-def `$val[]`/`$prt[]` pair on each pass over the now-15-entry
    // registry (Megapixels defers on `Composite:ImageSize`, forcing a 2nd pass), so
    // `-j` rises 384 → 699 and `-n` 520 → 790. This is the INTENDED cost of
    // building the newly-ported composites (the output is conformance- + typed-
    // serde-pinned byte-exact), NOT a redundant clone or double decode — the
    // `media_metadata` typed path is UNCHANGED (152 < 165) since it never runs the
    // Composite post-pass. (A future engine-perf PR could reuse the per-pass
    // `$val[]`/`$prt[]` scratch Vecs to shave the fixpoint overhead.) Ceilings
    // raised to (770, 860).
    // RE-BASELINED for #133 PR 5 (full video Composite activation): the TagMap
    // now carries each entry's family-0 group (an extra inline `SmolStr` per
    // insert) so the Composite engine can resolve a family-0-qualified
    // ingredient (`Sony:GPSLatitude`). The Composite re-emission inserts every
    // tag into BOTH the ValueConv and PrintConv views, so the per-entry family-0
    // clone is paid twice over the now-large Apple tag+composite set: `-j` 699 →
    // 835, `-n` 790 → 956. A faithful, necessary metadata carry (PART A — it is
    // what enables the Sony SubDoc GPS Composites), NOT a redundant clone; the
    // `media_metadata` typed path is UNCHANGED (152) since it never runs the
    // Composite post-pass. Ceilings raised to (870, 990).
    // RE-BASELINED for #381 (the `Composite:Flash`/`LensID`/`DateTimeCreated`
    // ports): the `BuildCompositeTags` fixpoint now evaluates THREE more defs
    // per pass over BOTH views — none builds for Apple (no XMP flash field, no
    // `LensType`, no IPTC date), but each attempt allocates its per-def
    // `$val[]`/`$prt[]` scratch pair, so `-j` rises +6 and `-n` +6 (the
    // engine-overhead cost the existing #133-PR-3 comment already flagged a
    // future perf PR could shave by reusing the scratch Vecs). The prior `(870,
    // 990)` ceiling was also already exceeded on the base (the measured drifted
    // to (884, 1002) before #381 without a re-baseline); the new ceilings cover
    // BOTH the drift and the #381 +6. `media_metadata` is UNCHANGED by the new
    // Composites (163, never runs the post-pass).
    "MakerNotes_Apple.jpg" => (910, 1030), // measured (890, 1008) — #381 +3 Composite defs
    "ID3v2_4_big.mp3" => (130, 130),       // measured (118, 117)
    // RE-BASELINED for #133 PR 5: a `video/*` QuickTime now RUNS the Composite
    // post-pass (the full-video flip), building `Composite:AvgBitrate`/`ImageSize`/
    // `Megapixels`/`Rotation` + re-emitting the opposite view — `-j` 135 → 195,
    // `-n` 137 → 213. The intended cost of the newly-built video composites (the
    // `Composite:GPSPosition` is the unported timed-GPS deferral), NOT a redundant
    // clone. Ceilings raised to (210, 230).
    //
    // RE-BASELINED (composite-def scratch drift): the `BuildCompositeTags`
    // fixpoint evaluates more `Composite` defs per pass than at the (195, 213)
    // baseline (the post-`#133` def additions — e.g. the `Flash`/`LensID`/
    // `DateTimeCreated` set that also re-baselined `MakerNotes_Apple` above),
    // over BOTH views. None of the added defs builds for this dashcam — the
    // golden still emits only `Composite:AvgBitrate`, and `FocalLength35efl`/
    // `FocusDistance` never fire (no `FocalLength`, no Sony `FocusInfo`), so the
    // now-zero-heap `whole_f64_to_tag_value` is not on this path — but each
    // evaluated def still allocates its per-def `$val[]`/`$prt[]` scratch pair,
    // so `-j` 195 → 217 and `-n` 213 → 234. Documented engine-overhead scratch
    // (a future perf PR could reuse the scratch Vecs), NOT a redundant clone /
    // double decode.
    //
    // RE-BASELINED for the %Canon::Composite port: the registry grew by 10 Canon
    // composite defs (DriveMode/Lens/Lens35efl/ShootingMode/FlashType/
    // RedEyeReduction/ConditionalFEC/ShutterCurtainHack/WB_RGGBLevels/ISO). They
    // do NOT build for this non-Canon MOV (every `Require` is missing), but the
    // `BuildCompositeTags` fixpoint still allocates a per-def `$val[]`/`$prt[]`
    // scratch pair while resolving each before it aborts — so `-j` 217 → 237 and
    // `-n` 234 → 254. The SAME documented fixpoint-scratch cost #133 PR 3 took
    // (a future perf PR could reuse the scratch Vecs); NOT a redundant clone.
    // Ceilings raised to (252, 270).
    "QuickTime_frea_rexing17b.mov" => (252, 270), // measured (237, 254) — +Canon composite-def scratch
    "Real.ra" => (100, 100),                      // measured (88, 87)
    _ => (usize::MAX, usize::MAX),
  }
}
