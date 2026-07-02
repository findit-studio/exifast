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
  // Real Sony ARWs — the `%Sony::Main` walk (#443 confines its suppressed-Unknown
  // `0x94xx` cipher-leaf values to a BORROWED span, so their per-leaf value clone
  // is gone). Pinned so a regression that re-materializes them trips the gate.
  "Sony_ILME-FX3_real.ARW",
  "Sony_SLT-A33_real.ARW",
  "Sony_DSLR-A200_real.ARW",
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
  sony_cipher_data_is_borrowed_not_amplified();
  sony_conditional_subdir_fallback_is_borrowed_not_amplified();
  sony_raw_selector_subdir_fallback_is_borrowed_not_amplified();
  sony_plain_binary_subdir_is_borrowed_not_amplified();
  sony_nonundef_subdir_is_borrowed_not_amplified();
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

/// The seven `%Sony::Main` `%unknownCipherData` SUPPRESSED-`Unknown` LEAF tag
/// IDs (`Sony_0x9407`/`8`/`9`/`b`/`d`/`f` + `0x9411`, `Sony.pm:2055-2114`).
const SONY_CIPHER_IDS: [u16; 7] = [0x9407, 0x9408, 0x9409, 0x940b, 0x940d, 0x940f, 0x9411];

/// The value offset (TIFF-absolute) where [`sony_cipher_tiff`] places the shared
/// region — after the 8-byte header, IFD0, ExifIFD, the 12-byte `SONY DSC`
/// prefix, and the `n` cipher-leaf entries of the Sony Main IFD.
fn sony_region_off(n: usize) -> usize {
  // 8 (header) + 18 (IFD0: 1 entry) + 18 (ExifIFD: 1 entry) + 12 ("SONY DSC ..")
  // = MN body IFD at 56, then 2 (count) + n*12 (entries) + 4 (next-IFD).
  56 + 2 + n * 12 + 4
}

/// Craft a MINIMAL little-endian TIFF whose Sony MakerNote is a `%Sony::Main`
/// IFD of `%unknownCipherData` SUPPRESSED-`Unknown` cipher rows (`ids` — either
/// the suppressed LEAVES or the conditional-`SubDirectory` dispatchers, and
/// `ids` MAY repeat a single id), each an out-of-line `undef[span]` value
/// pointing at a 1-byte-SHIFTED, OVERLAPPING, DISTINCT window of ONE shared
/// `region`-byte block:
///
/// `IFD0(ExifOffset)` → `ExifIFD(MakerNote 0x927c)` → `"SONY DSC \0\0\0"` +
/// `Sony Main IFD(ids…)` + the shared region.
///
/// The Sony Main IFD is `Base => Inherit` (offsets are TIFF-absolute), so every
/// leaf's value pointer resolves into the shared region. `span` is FIXED
/// (`region - 16`, independent of `ids.len()`) so scaling the leaf count keeps
/// the per-leaf window identical; the 16-byte margin keeps up to 16 shifted
/// windows in-bounds. `span` stays below the 100 000-element excessive-count
/// gate so the walk raises no warnings.
fn sony_cipher_tiff(ids: &[u16], region: usize) -> Vec<u8> {
  // The #443 leaves are `undef` (format 7, 1-byte element); `count == span`.
  sony_subdir_tiff_fmt(ids, region, 7, 1)
}

/// Craft the SAME MakerNote as [`sony_cipher_tiff`] but with a caller-chosen on-disk
/// `format_code` (+ its `elem_size`) for every `%Sony::Main` row — used by the #486
/// R2 probe to encode duplicate `SubDirectory` rows as a NON-`undef` format (`int8u`
/// / `int16u` / `ascii`). Each row's on-disk value byte extent (`value_size ==
/// count * elem_size`) stays `span == region - 16`, so the shared-region overlap +
/// the per-row window are byte-identical to the `undef` builder; only the declared
/// `$format` (and thus the decoded `RawValue`'s SHAPE) changes. The dead-value walk
/// guard's SubDirectory class is format-INDEPENDENT, so it must zero the walk clone
/// for these too — the DoS the R1 `undef`-gated guard still admitted.
fn sony_subdir_tiff_fmt(ids: &[u16], region: usize, format_code: u16, elem_size: usize) -> Vec<u8> {
  assert!(
    ids.len() <= 16 && region >= 32,
    "up to 16 shifted windows fit"
  );
  let span_bytes = region - 16;
  assert!(
    span_bytes % elem_size == 0,
    "value byte extent must be a whole number of elements"
  );
  // The on-disk value byte size (`$size == $count * $formatSize`) is what the
  // dispatchers re-slice + the guard would clone; keep it FIXED at `span_bytes`
  // across formats so the probe isolates the format gate, not the region size.
  let count = u32::try_from(span_bytes / elem_size).expect("count fits u32");
  assert!(count < 100_000, "keep count below the excessive-count gate");
  let region_off = sony_region_off(ids.len());
  let total = region_off + region;
  const EXIF_OFF: u32 = 26;
  const MN_OFF: usize = 44;

  let mut t: Vec<u8> = Vec::with_capacity(total);
  // [0..8] TIFF header — little-endian, IFD0 at offset 8.
  t.extend_from_slice(&[b'I', b'I', 0x2a, 0x00]);
  t.extend_from_slice(&8u32.to_le_bytes());
  // [8] IFD0 — a single ExifOffset (0x8769) pointer.
  t.extend_from_slice(&1u16.to_le_bytes());
  t.extend_from_slice(&0x8769u16.to_le_bytes());
  t.extend_from_slice(&4u16.to_le_bytes()); // LONG
  t.extend_from_slice(&1u32.to_le_bytes());
  t.extend_from_slice(&EXIF_OFF.to_le_bytes());
  t.extend_from_slice(&0u32.to_le_bytes());
  assert_eq!(t.len(), EXIF_OFF as usize);
  // [26] ExifIFD — a single MakerNote (0x927c) whose value is the Sony blob.
  let mn_len = u32::try_from(total - MN_OFF).expect("mn_len fits u32");
  t.extend_from_slice(&1u16.to_le_bytes());
  t.extend_from_slice(&0x927cu16.to_le_bytes());
  t.extend_from_slice(&7u16.to_le_bytes()); // UNDEF (the MakerNote wrapper itself)
  t.extend_from_slice(&mn_len.to_le_bytes());
  t.extend_from_slice(&u32::try_from(MN_OFF).unwrap().to_le_bytes());
  t.extend_from_slice(&0u32.to_le_bytes());
  assert_eq!(t.len(), MN_OFF);
  // [44] `MakerNoteSony` primary signature (Start = $valuePtr + 12).
  t.extend_from_slice(b"SONY DSC \x00\x00\x00");
  // [56] Sony Main IFD — the rows, ASCENDING (a valid sorted IFD).
  t.extend_from_slice(&u16::try_from(ids.len()).unwrap().to_le_bytes());
  for (i, &id) in ids.iter().enumerate() {
    t.extend_from_slice(&id.to_le_bytes());
    t.extend_from_slice(&format_code.to_le_bytes()); // caller-chosen on-disk format
    t.extend_from_slice(&count.to_le_bytes()); // count (value_size == count*elem_size)
    // 1-byte-shifted, overlapping, DISTINCT windows of the shared region.
    t.extend_from_slice(&u32::try_from(region_off + i).unwrap().to_le_bytes());
  }
  t.extend_from_slice(&0u32.to_le_bytes());
  assert_eq!(t.len(), region_off);
  // [region_off] the shared region every row's window overlaps.
  t.resize(total, 0x5a);
  t
}

/// #443 — the Sony `0x94xx` `%unknownCipherData` suppressed-`Unknown` leaves are
/// emitted as BORROWED value spans (zero-copy from the input buffer), so a
/// crafted MakerNote cannot amplify memory: N such leaves over one M-byte region
/// retain O(N) span descriptors, not the pre-fix O(N·M) (each leaf materialized a
/// throwaway `RawValue::Bytes` PLUS a cached `TagValue::Bytes`).
///
/// Two byte-volume probes prove invariants (iv) [O(N+M), not N·M] and (v)
/// [overlapping 1-byte-shifted DISTINCT spans share the buffer]:
///   1. N→2N leaves over the SAME (large) region — the delta must be O(N·span-
///      descriptor), far below even ONE span copy.
///   2. small-M vs large-M region (fixed 7 leaves) — the growth must be O(1) in
///      the region size, not the pre-fix ~2·N·ΔM.
/// A third probe (invariant ii/vii) reads a suppressed leaf's value through the
/// PUBLIC accessor and asserts it materializes the EXACT on-disk span bytes.
///
/// Called INLINE from the single `alloc_budget` test (the counters are
/// process-global; see the module doc).
fn sony_cipher_data_is_borrowed_not_amplified() {
  use exifast::parse_exif;

  // Overlapping-span windows, all deep enough that the pre-fix copy would be a
  // clear multiple of the region growth. `span = region - 16` in every build.
  const SMALL: usize = 8_016; // span 8000
  const LARGE: usize = 90_016; // span 90000 (< the 100k excessive-count gate)

  // --- (a) N→2N leaves over the SAME large region. ---
  let tiff_n = sony_cipher_tiff(&SONY_CIPHER_IDS[0..3], LARGE);
  let tiff_2n = sony_cipher_tiff(&SONY_CIPHER_IDS[0..6], LARGE);
  // Warm-up OUTSIDE the measured region (lazy statics / first-call init).
  assert!(parse_exif(&tiff_n).is_some(), "3-leaf Sony TIFF parses");
  assert!(parse_exif(&tiff_2n).is_some(), "6-leaf Sony TIFF parses");
  let (_n_ok, bytes_n) = count_alloc_bytes(|| parse_exif(&tiff_n).is_some());
  let (_2n_ok, bytes_2n) = count_alloc_bytes(|| parse_exif(&tiff_2n).is_some());

  // --- (b) small-M vs large-M region, fixed 7 leaves. ---
  let tiff_small = sony_cipher_tiff(&SONY_CIPHER_IDS, SMALL);
  let tiff_large = sony_cipher_tiff(&SONY_CIPHER_IDS, LARGE);
  assert!(
    parse_exif(&tiff_small).is_some(),
    "small-region Sony TIFF parses"
  );
  assert!(
    parse_exif(&tiff_large).is_some(),
    "large-region Sony TIFF parses"
  );
  let (_s_ok, small_bytes) = count_alloc_bytes(|| parse_exif(&tiff_small).is_some());
  let (_l_ok, large_bytes) = count_alloc_bytes(|| parse_exif(&tiff_large).is_some());

  println!("\n=== alloc_budget: sony 0x94xx cipher-leaf borrow (single-copy) ===");
  println!("  N=3 leaves={bytes_n}B  N=6 leaves={bytes_2n}B  (same {LARGE}B region)");
  println!("  M=small({SMALL})={small_bytes}B  M=large({LARGE})={large_bytes}B");

  let span = LARGE - 16; // 90000 — the per-leaf window / pre-fix per-copy volume

  // (a) Doubling the leaf count over the SAME region adds only O(N descriptors)
  // — FAR below one span copy. The pre-fix path would add 3 leaves × (throwaway
  // RawValue + cached copy) ≈ 6·span here.
  let n_delta = bytes_2n.saturating_sub(bytes_n);
  assert!(
    n_delta < span,
    "N→2N cipher leaves grew {n_delta} bytes for the SAME region — a borrowed \
     span must add O(N descriptors), NOT O(N·M); a growth ≥ one span ({span}) \
     means a per-leaf value copy regressed back in (#443)."
  );

  // (b) Growing the region (fixed 7 leaves) must be O(1) — the spans are
  // borrowed from the input buffer, never copied. The pre-fix path copied each
  // of the 7 overlapping windows TWICE, so it would grow ~14·ΔM.
  let region_delta = LARGE - SMALL; // 82000
  let m_growth = large_bytes.saturating_sub(small_bytes);
  assert!(
    m_growth < region_delta,
    "the 7 cipher leaves grew {m_growth} bytes for a {region_delta}-byte region \
     increase — a borrowed span must be O(1) in the region size; a growth near \
     14·ΔM means the overlapping windows are being COPIED (#443)."
  );

  // --- (c) invariant (ii)/(vii): the PUBLIC accessor materializes the EXACT
  // on-disk span for a SUPPRESSED leaf (non-empty, correct window). ---
  let meta = parse_exif(&tiff_small).expect("small Sony TIFF parses");
  let mn = meta.maker_note().expect("Sony MakerNote captured");
  let leaf = mn
    .emissions_print_conv()
    .iter()
    .find(|e| e.name() == "Sony_0x9407")
    .expect("the 0x9407 %unknownCipherData leaf is cached");
  assert!(
    leaf.unknown(),
    "0x9407 is Unknown => 1 (suppressed by default)"
  );
  // `Sony_0x9407` is leaf index 0 ⇒ its window starts at the region base.
  let base = sony_region_off(SONY_CIPHER_IDS.len());
  let want = &tiff_small[base..base + (SMALL - 16)];
  assert!(!want.is_empty(), "the on-disk span is non-empty");
  assert_eq!(
    leaf.value().as_ref(),
    &exifast::value::TagValue::Bytes(want.to_vec()),
    "the suppressed cipher leaf materializes the EXACT on-disk span bytes"
  );
}

/// #443 R2 — the Sony CONDITIONAL-`SubDirectory` cipher dispatchers
/// (`0x2010`/`0x940a`/`0x940c`/`0x940e`) also confine their walk-clone. Each is
/// a `sub_table: Some(...)` row that decodes a real enciphered sub-table when the
/// `Model` matches a branch and falls through to `%unknownCipherData` (emitting
/// NOTHING) when none does. Pre-fix the walk still `read_value`-cloned the
/// (crafted-huge) `undef[N]` value span onto EACH entry, so N duplicate
/// dispatcher rows over one shared M-byte region retained O(N·M); the #443 R2
/// walk-guard extension stores a zero-copy empty `RawValue` for these rows too
/// (their decode re-slices the span from the input buffer for BOTH the matched
/// and the fallback path), bounding the retained heap to O(N + M).
///
/// This TIFF carries NO `Model`, so every dispatcher's model gate fails and all
/// N `0x940e` rows fall back (`sony_emit_enciphered_subblock`'s `_ => {}` — no
/// `process_enciphered`, zero decode allocation), isolating the walk clone the
/// fix removes. It repeats a SINGLE id (the walker processes every entry with no
/// ascending/dedup gate) over 1-byte-shifted overlapping windows so N scales
/// while the shared region stays fixed. Proves invariant (vi) for the fallback
/// shape (the leaf-ID probe above covers the leaf shape).
///
/// Called INLINE from the single `alloc_budget` test (the counters are
/// process-global; see the module doc).
fn sony_conditional_subdir_fallback_is_borrowed_not_amplified() {
  use exifast::parse_exif;

  // The per-row window; `span = region - 16` in the crafted TIFF (< the 100k
  // excessive-count gate, so the walk raises no warnings + processes every row).
  const LARGE: usize = 90_016; // span 90000

  // N→2N duplicate `0x940e` dispatcher rows over the SAME large region. With no
  // Model they all fall back to `%unknownCipherData` (emit nothing); pre-fix each
  // still retained a `read_value` clone of the 90000-byte window.
  let ids_n = [0x940e_u16; 4];
  let ids_2n = [0x940e_u16; 8];
  let tiff_n = sony_cipher_tiff(&ids_n, LARGE);
  let tiff_2n = sony_cipher_tiff(&ids_2n, LARGE);
  // Warm-up OUTSIDE the measured region (lazy statics / first-call init).
  assert!(
    parse_exif(&tiff_n).is_some(),
    "4-dispatcher Sony TIFF parses"
  );
  assert!(
    parse_exif(&tiff_2n).is_some(),
    "8-dispatcher Sony TIFF parses"
  );
  let (_n_ok, bytes_n) = count_alloc_bytes(|| parse_exif(&tiff_n).is_some());
  let (_2n_ok, bytes_2n) = count_alloc_bytes(|| parse_exif(&tiff_2n).is_some());

  println!("\n=== alloc_budget: sony conditional-subdir fallback borrow (single-copy) ===");
  println!("  N=4 dispatchers={bytes_n}B  N=8 dispatchers={bytes_2n}B  (same {LARGE}B region)");

  // Doubling the fallback-dispatcher count over the SAME region adds only O(N
  // descriptors) — FAR below one span copy. The pre-fix path added 4 rows ×
  // one `read_value` clone ≈ 4·span here (each retained on its walked entry).
  let span = LARGE - 16; // 90000 — the per-row window / pre-fix per-clone volume
  let n_delta = bytes_2n.saturating_sub(bytes_n);
  assert!(
    n_delta < span,
    "N→2N conditional-subdir fallback rows grew {n_delta} bytes for the SAME \
     region — the walk must store a zero-copy empty RawValue (O(N descriptors)), \
     NOT O(N·M); a growth ≥ one span ({span}) means the fallback rows' \
     read_value clone regressed back in (#443 R2)."
  );

  // Confirm we exercised the FALLBACK path (not a matched decode): with no Model
  // the `0x940e` dispatcher falls to `%unknownCipherData` and emits NO leaf, so
  // the Sony MakerNote carries zero emissions. A non-zero count would mean a
  // matched sub-table decode ran (the probe would no longer test the fallback).
  let meta = parse_exif(&tiff_n).expect("dispatcher Sony TIFF parses");
  let dispatcher_leaves = meta
    .maker_note()
    .map_or(0, |mn| mn.emissions_print_conv().len());
  assert_eq!(
    dispatcher_leaves, 0,
    "0x940e with no Model must fall back to %unknownCipherData (emit no leaf); \
     a non-zero count means a matched decode ran (test no longer exercises the \
     fallback path)."
  );
}

/// #443 R3 — the CLASS-KILLER regression probe. The R1 (suppressed-leaf) and R2
/// (`0x2010`/`0x940a`/`0x940c`/`0x940e`) predicates were HAND-LISTED tag IDs, so
/// they kept missing members of the same enciphered-`SubDirectory` class — e.g.
/// `0x9405` (a `sub_table: Some(Tag9xxx)` row selected by the RAW value's FIRST
/// BYTE, not by `Model`): pre-R3 its walk clone was NOT confined, re-amplifying
/// O(N·M). R3 (now #486) derives the class from `sub_table: Some(_)` (the routing),
/// so `0x9405` — and every other `Tag9xxx` ID — is covered WITHOUT a
/// hand-maintained list.
///
/// This probes the RAW-SELECTOR fallback shape the reviewer named (distinct from
/// the R2 MODEL-selector probe above): the crafted region is all `0x5a`, which is
/// NEITHER a `Tag9405a` selector (`/^[\x1b\x40\x7d]/`) NOR a `Tag9405b` selector
/// (`/^[\x3a\xb3\x7e\x9a\x25\xe1\x76\x8b]/`), so `sony_emit_enciphered_subblock`
/// falls to its `_ => {}` `%unknownCipherData` arm (no `process_enciphered`, zero
/// decode allocation) — isolating the walk clone the fix removes. N duplicate
/// `0x9405` rows over 1-byte-shifted overlapping windows of ONE fixed region make
/// N scale while M stays fixed. Pre-R3 this FAILS (the `0x9405` clone regresses);
/// post-R3 the delta is O(N descriptors).
///
/// Called INLINE from the single `alloc_budget` test (the counters are
/// process-global; see the module doc).
fn sony_raw_selector_subdir_fallback_is_borrowed_not_amplified() {
  use exifast::parse_exif;

  // The per-row window; `span = region - 16` (< the 100k excessive-count gate, so
  // the walk raises no warnings + processes every row).
  const LARGE: usize = 90_016; // span 90000

  // N→2N duplicate `0x9405` RAW-SELECTOR dispatcher rows over the SAME large
  // region. Every window's first byte is `0x5a` (a non-matching selector), so all
  // fall back to `%unknownCipherData` (emit nothing); pre-R3 each still retained a
  // `read_value` clone of the 90000-byte window (0x9405 ∉ the R2 hand list).
  let ids_n = [0x9405_u16; 4];
  let ids_2n = [0x9405_u16; 8];
  let tiff_n = sony_cipher_tiff(&ids_n, LARGE);
  let tiff_2n = sony_cipher_tiff(&ids_2n, LARGE);
  // Warm-up OUTSIDE the measured region (lazy statics / first-call init).
  assert!(parse_exif(&tiff_n).is_some(), "4-selector Sony TIFF parses");
  assert!(
    parse_exif(&tiff_2n).is_some(),
    "8-selector Sony TIFF parses"
  );
  let (_n_ok, bytes_n) = count_alloc_bytes(|| parse_exif(&tiff_n).is_some());
  let (_2n_ok, bytes_2n) = count_alloc_bytes(|| parse_exif(&tiff_2n).is_some());

  println!("\n=== alloc_budget: sony raw-selector-subdir fallback borrow (single-copy) ===");
  println!("  N=4 selectors={bytes_n}B  N=8 selectors={bytes_2n}B  (same {LARGE}B region)");

  // Doubling the fallback-row count over the SAME region adds only O(N
  // descriptors) — FAR below one span copy. The pre-R3 path added 4 rows × one
  // `read_value` clone ≈ 4·span here (each retained on its walked entry).
  let span = LARGE - 16; // 90000 — the per-row window / pre-fix per-clone volume
  let n_delta = bytes_2n.saturating_sub(bytes_n);
  assert!(
    n_delta < span,
    "N→2N raw-selector fallback rows grew {n_delta} bytes for the SAME region — \
     the routing-derived guard must store a zero-copy empty RawValue for a \
     `Tag9xxx` `0x9405` row (O(N descriptors)), NOT O(N·M); a growth ≥ one span \
     ({span}) means an enciphered-subdir ID slipped the class-killer predicate \
     (the #443 R1/R2 whack-a-mole)."
  );

  // Confirm we exercised the RAW-SELECTOR FALLBACK (not a matched decode): the
  // all-`0x5a` region matches neither `Tag9405a` nor `Tag9405b`, so `0x9405`
  // falls to `%unknownCipherData` and emits NO leaf. A non-zero count would mean a
  // matched sub-table decode ran (the probe would no longer test the fallback).
  let meta = parse_exif(&tiff_n).expect("selector Sony TIFF parses");
  let selector_leaves = meta
    .maker_note()
    .map_or(0, |mn| mn.emissions_print_conv().len());
  assert_eq!(
    selector_leaves, 0,
    "0x9405 with a non-matching first byte must fall back to %unknownCipherData \
     (emit no leaf); a non-zero count means a matched decode ran (test no longer \
     exercises the raw-selector fallback path)."
  );
}

/// #486 — the residual eager-clone the #443 enciphered-only guard left. The
/// older PLAIN (un-enciphered) `ProcessBinaryData` sub-tables (`CameraInfo`
/// `0x0010`/`FocusInfo` `0x0020`/`CameraSettings` `0x0114`/`ExtraInfo` `0x0116`/
/// `ShotInfo` `0x3000`) ALSO decode by re-slicing the verbatim span from `data`
/// (`sony_emit_binary_subdir`, `exif/mod.rs`), NEVER reading the walk's decoded
/// `RawValue` — yet #443's enciphered-only guard covered ONLY the
/// enciphered-subblock class, so each such row still `read_value`-cloned its
/// (possibly-huge, in-bounds) `undef[N]` block. #486 R1 widens the guard to EVERY
/// `sub_table: Some(_)` row (`sony_tag_has_sub_table`), so the plain-binary rows now
/// store a zero-copy empty `RawValue` too. (#486 R2 then drops the residual `undef`
/// format-gate for this class — see `sony_nonundef_subdir_is_borrowed_not_amplified`.)
///
/// The probe uses `0x0010` `CameraInfo` with a `$count` (`span == 90000`) that
/// matches NONE of the ported tables (368/5478/5506/6118/15360), so
/// `sony_emit_binary_subdir` hits its `_ => return` arm (re-slices `data`, emits
/// NOTHING) — isolating the walk clone the fix removes. N→2N duplicate rows over
/// ONE fixed region make N scale while M stays fixed; pre-#486 each row retained a
/// 90000-byte clone (a plain-binary sub_table ∉ the enciphered class), so the
/// N→2N delta was ≈ N·span; post-#486 it is O(N descriptors).
///
/// Called INLINE from the single `alloc_budget` test (the counters are
/// process-global; see the module doc).
fn sony_plain_binary_subdir_is_borrowed_not_amplified() {
  use exifast::parse_exif;

  // The per-row window; `span = region - 16` (< the 100k excessive-count gate, so
  // the walk raises no warnings + processes every row). 90000 matches no ported
  // CameraInfo `$count` → the plain-binary dispatcher's no-op `_ => return`.
  const LARGE: usize = 90_016; // span 90000

  // N→2N duplicate `0x0010` PLAIN-BINARY sub-table rows over the SAME large
  // region. The non-matching count falls to `sony_emit_binary_subdir`'s no-op arm
  // (emits nothing); pre-#486 each still retained a `read_value` clone of the
  // 90000-byte window (a plain-binary sub_table was OUTSIDE the enciphered class).
  let ids_n = [0x0010_u16; 4];
  let ids_2n = [0x0010_u16; 8];
  let tiff_n = sony_cipher_tiff(&ids_n, LARGE);
  let tiff_2n = sony_cipher_tiff(&ids_2n, LARGE);
  // Warm-up OUTSIDE the measured region (lazy statics / first-call init).
  assert!(
    parse_exif(&tiff_n).is_some(),
    "4-row plain-binary Sony TIFF parses"
  );
  assert!(
    parse_exif(&tiff_2n).is_some(),
    "8-row plain-binary Sony TIFF parses"
  );
  let (_n_ok, bytes_n) = count_alloc_bytes(|| parse_exif(&tiff_n).is_some());
  let (_2n_ok, bytes_2n) = count_alloc_bytes(|| parse_exif(&tiff_2n).is_some());

  println!("\n=== alloc_budget: sony plain-binary-subdir borrow (single-copy) ===");
  println!("  N=4 rows={bytes_n}B  N=8 rows={bytes_2n}B  (same {LARGE}B region)");

  // Doubling the plain-binary row count over the SAME region adds only O(N
  // descriptors) — FAR below one span copy. The pre-#486 path added 4 rows × one
  // `read_value` clone ≈ 4·span here (each retained on its walked entry).
  let span = LARGE - 16; // 90000 — the per-row window / pre-fix per-clone volume
  let n_delta = bytes_2n.saturating_sub(bytes_n);
  assert!(
    n_delta < span,
    "N→2N plain-binary sub-table rows grew {n_delta} bytes for the SAME region — \
     the widened guard must store a zero-copy empty RawValue for a `0x0010` \
     `CameraInfo` row (O(N descriptors)), NOT O(N·M); a growth ≥ one span \
     ({span}) means the plain-binary rows' read_value clone is still eager (the \
     #486 gap the #443 enciphered-only predicate left)."
  );

  // Confirm we exercised the PLAIN-BINARY no-op path (not a matched decode): the
  // 90000-byte count matches no ported `CameraInfo` table, so `0x0010` re-slices
  // `data` and emits NO leaf. A non-zero count would mean a matched sub-table
  // decode ran (the probe would no longer isolate the eager-clone the fix removes).
  let meta = parse_exif(&tiff_n).expect("plain-binary Sony TIFF parses");
  let plain_leaves = meta
    .maker_note()
    .map_or(0, |mn| mn.emissions_print_conv().len());
  assert_eq!(
    plain_leaves, 0,
    "0x0010 with a non-matching count must fall to sony_emit_binary_subdir's no-op \
     arm (emit no leaf); a non-zero count means a matched decode ran (test no \
     longer isolates the plain-binary eager-clone)."
  );
}

/// #486 R2 — the residual eager-clone the R1 (`undef`-gated) guard STILL left for a
/// NON-`undef` SubDirectory encoding. The R1 guard zeroed the walk clone only for
/// `matches!(format, Format::Undef)`, but a `%Sony::Main` `SubDirectory` row's
/// decoded value is dead REGARDLESS of the on-disk `$format`: `emit_sony_value`
/// returns at its Step-2 `sub_table.is_some()` guard (a STATIC table fact, not a
/// format check) and `sony_emit_binary_subdir` re-slices `data` keyed on
/// `tag_id`/`value_size`, so it reads the decoded `RawValue` for NO format. A
/// crafted IFD can therefore encode duplicate `0x0010` `CameraInfo` rows as `int8u`
/// (format 1) / `int16u` (format 3) / `ascii` (format 2) over one shared span — all
/// NON-`undef` — and (pre-R2) each retained a large dead `read_value` clone, the
/// SAME N×M DoS #486 R1 closed for `undef`, re-opened for every other format.
///
/// This probe mirrors `sony_plain_binary_subdir_is_borrowed_not_amplified` but sweeps
/// the three attacker-reachable non-`undef` shapes (each with a `count > 1` under the
/// 100 000 excessive-count gate, so no warning fires and the guard's `count != 1`
/// carve-out does not apply). For each, doubling the row count over the SAME region
/// must add only O(N descriptors) — proving the guard's SubDirectory class is now
/// FORMAT-INDEPENDENT (the R2 fix). `int8u`/`ascii` (1-byte element) worst-case:
/// their `read_value` clone is a `Vec<u64>`/`Box<[u8]>` of `span` elements — for
/// `int8u` that is 8·span bytes, LARGER than the `undef` case, so the R1 gap this
/// closes was strictly worse for the integer encoding.
///
/// Called INLINE from the single `alloc_budget` test (the counters are
/// process-global; see the module doc).
fn sony_nonundef_subdir_is_borrowed_not_amplified() {
  use exifast::parse_exif;

  // span 90000 (< the 100k excessive-count gate). 90000 matches no ported
  // CameraInfo `$count`/`value_size` → the plain-binary dispatcher's `_ => return`.
  const LARGE: usize = 90_016;
  let span = LARGE - 16; // 90000 — the per-row window / pre-fix per-clone volume

  println!("\n=== alloc_budget: sony NON-undef subdir borrow (#486 R2, single-copy) ===");

  // (format_code, elem_size, label) — the three attacker-reachable non-`undef`
  // encodings of a `0x0010` SubDirectory row. `value_size == count * elem_size ==
  // span` in every build, so the shared-region window is byte-identical to the
  // `undef` probe; only the declared `$format` (⇒ decoded `RawValue` shape) differs.
  for &(fmt, elem, label) in &[(1u16, 1usize, "int8u"), (3, 2, "int16u"), (2, 1, "ascii")] {
    let ids_n = [0x0010_u16; 4];
    let ids_2n = [0x0010_u16; 8];
    let tiff_n = sony_subdir_tiff_fmt(&ids_n, LARGE, fmt, elem);
    let tiff_2n = sony_subdir_tiff_fmt(&ids_2n, LARGE, fmt, elem);
    // Warm-up OUTSIDE the measured region (lazy statics / first-call init).
    assert!(
      parse_exif(&tiff_n).is_some(),
      "4-row {label} Sony TIFF parses"
    );
    assert!(
      parse_exif(&tiff_2n).is_some(),
      "8-row {label} Sony TIFF parses"
    );
    let (_n_ok, bytes_n) = count_alloc_bytes(|| parse_exif(&tiff_n).is_some());
    let (_2n_ok, bytes_2n) = count_alloc_bytes(|| parse_exif(&tiff_2n).is_some());
    let n_delta = bytes_2n.saturating_sub(bytes_n);
    println!(
      "  {label:<6}  N=4 rows={bytes_n}B  N=8 rows={bytes_2n}B  Δ(N→2N)={n_delta}B  (same {span}B span)"
    );

    // Doubling the NON-`undef` SubDirectory row count over the SAME region adds only
    // O(N descriptors) — FAR below one span copy. The pre-R2 (`undef`-gated) guard
    // MISSED these rows, so each of the 4 extra rows retained one `read_value` clone
    // (≥ span bytes; for `int8u`/`ascii` a `Vec<u64>`/`Box<[u8]>` of `span` elements),
    // so the delta was ≈ 4·span. A growth ≥ one span means the guard is STILL
    // format-gated (the #486 R2 gap).
    assert!(
      n_delta < span,
      "N→2N {label} SubDirectory rows grew {n_delta} bytes for the SAME region — the \
       widened guard must store a zero-copy empty RawValue for a `0x0010` `CameraInfo` \
       row REGARDLESS of its on-disk format (O(N descriptors)), NOT O(N·M); a growth ≥ \
       one span ({span}) means the SubDirectory guard is still `undef`-gated (the #486 \
       R2 non-`undef` DoS bypass)."
    );

    // Confirm the NON-`undef` no-op path (not a matched decode): the 90000-byte
    // value_size matches no ported `CameraInfo` table, so `0x0010` re-slices `data`
    // and emits NO leaf — the same isolation the R1 `undef` probe asserts. (A
    // matched decode would mean the probe no longer isolates the eager-clone.)
    let meta = parse_exif(&tiff_n).unwrap_or_else(|| panic!("{label} Sony TIFF parses"));
    let leaves = meta
      .maker_note()
      .map_or(0, |mn| mn.emissions_print_conv().len());
    assert_eq!(
      leaves, 0,
      "0x0010 ({label}) with a non-matching value_size must fall to \
       sony_emit_binary_subdir's no-op arm (emit no leaf); a non-zero count means a \
       matched decode ran (test no longer isolates the eager-clone)."
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
    "MakerNotes_Apple.jpg" => 165, // measured 151 (#261 SOF File dims: 148 → 151)
    "ID3v2_4_big.mp3" => 225,      // measured 209 (Contract A: 194 → 209)
    "QuickTime_frea_rexing17b.mov" => 40, // measured 31 (no EXIF string leaf)
    "Real.ra" => 30,               // measured 21 (P8: 31 → 21)
    // Real Sony ARWs (#443) — POST-fix, the `%Sony::Main` suppressed-Unknown
    // `0x94xx` cipher leaves no longer clone their value into the cached
    // emission (they carry a BORROWED span), so these are a lower/equal
    // baseline: measured FX3 485 / A33 329 / A200 258, each + ~7% headroom.
    "Sony_ILME-FX3_real.ARW" => 520,  // measured 485
    "Sony_SLT-A33_real.ARW" => 355,   // measured 329
    "Sony_DSLR-A200_real.ARW" => 280, // measured 258
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
    // Real Sony ARWs (#443) — POST-fix `-j`/`-n` render budgets. The
    // suppressed-Unknown `0x94xx` cipher leaves are dropped BEFORE materializing
    // (the `push_maker_note_tags` reorder), so their transient value clone is
    // gone from BOTH render modes: measured + ~7% headroom.
    "Sony_ILME-FX3_real.ARW" => (3300, 3440), // measured (3083, 3213)
    "Sony_SLT-A33_real.ARW" => (2230, 2380),  // measured (2083, 2225)
    "Sony_DSLR-A200_real.ARW" => (2120, 2250), // measured (1979, 2098)
    _ => (usize::MAX, usize::MAX),
  }
}
