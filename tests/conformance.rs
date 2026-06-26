//! §4 conformance: `exifast::extract_info` output must match the
//! bundled-ExifTool golden for every ported fixture, for both the default
//! (`-j -G1 -struct`) and `-n` snapshots. The gate is the TOKEN-EXACT
//! [`json_equivalent_strict`] (`src/jsondiff.rs`, Contract B / #197): object
//! key ORDER is insensitive, the key MULTISET must match, array order IS
//! significant, and every scalar must match by JSON TYPE as well as value — a
//! quoted `"123"` is NOT the bare number `123` (within-type value-style
//! insensitivity is still kept: `1 == 1.0`, `3.4e+38 == 3.4e38`). The
//! serializer reproduces ExifTool's exact `EscapeJSON` bare-number-vs-quoted-
//! string typing, so the goldens pin that typing. One case per ported format —
//! add a `#[test]` per format as it lands (FORMATS.md order).
//!
//! Gated on `feature = "json"`: the suite imports the `json`-gated `jsondiff`,
//! and `std` does NOT imply `json`, so a `--features std,id3` test build must
//! skip this whole file (the lib still builds; this is a json-output
//! conformance check).
#![cfg(feature = "json")]
use exifast::{jsondiff::json_equivalent_strict as json_equivalent, parser::extract_info};

/// Assert exifast's output for `fixture` matches the committed bundled-ExifTool
/// golden `golden` TOKEN-EXACTLY via [`json_equivalent_strict`]. `print_on` =
/// ExifTool PrintConv (`false` ⇒ `-n`).
///
/// Token-exact (Contract B / #197): the serializer reproduces ExifTool's
/// `EscapeJSON` bare-number-vs-quoted-string typing, so a numeric scalar must
/// match the golden's JSON TYPE as well as its value (within-type spelling —
/// `1`==`1.0`, trailing zeros — stays insensitive; object key order stays
/// insensitive). A genuine value/structure difference — a wrong number, a
/// quote-vs-bare type mismatch, a missing/extra key, a different array order —
/// fails (do NOT weaken the goldens to mask one).
fn check(fixture: &str, golden: &str, print_on: bool) {
  let root = env!("CARGO_MANIFEST_DIR");
  let data = std::fs::read(format!("{root}/tests/fixtures/{fixture}"))
    .unwrap_or_else(|e| panic!("read fixture {fixture}: {e}"));
  let want = std::fs::read_to_string(format!("{root}/tests/golden/{golden}"))
    .unwrap_or_else(|e| panic!("read golden {golden}: {e}"));
  let got = extract_info(fixture, &data, print_on);
  if let Err(e) = json_equivalent(&got, &want) {
    panic!(
      "{fixture} vs {golden}: value mismatch: {}\n--- got ---\n{got}\n\
       --- want ---\n{want}",
      e.message()
    );
  }
}

/// Strip a set of FULLY-QUALIFIED `-j -G1` keys (exact `Family1:Name`, e.g.
/// `"Composite:GPSAltitude"`) from every object in the document. Used where
/// exifast emits a tag whose VALUE diverges from bundled because a dependent
/// subsystem is deferred — a golden-only `-x` would leave exifast's extra, so
/// that EXACT tag is dropped from BOTH sides.
///
/// Matching is EXACT (not an `:tail` suffix): excluding `Composite:GPSAltitude`
/// must NOT also strip the distinct `XMP-exif:GPSAltitude` (a same-named tag in
/// a different family-1 group). Over-broad suffix matching previously masked
/// the embedded-XMP GPS values from the comparison — the `XMP-exif:GPS*` tags
/// are part of the #361 byte-exact fix and MUST stay in the comparison so their
/// byte-exactness is actually verified.
fn drop_keys(doc: &str, exact_keys: &[&str]) -> String {
  let mut v: serde_json::Value = serde_json::from_str(doc).expect("valid JSON document");
  if let Some(arr) = v.as_array_mut() {
    for el in arr {
      if let Some(obj) = el.as_object_mut() {
        obj.retain(|k, _| !exact_keys.iter().any(|t| k == t));
      }
    }
  }
  serde_json::to_string(&v).expect("re-serialize document")
}

/// Like [`check`] but compares with `excluded` FULLY-QUALIFIED keys removed from
/// BOTH the exifast output and the golden — for a tag exifast emits whose value
/// diverges from bundled under a deferred subsystem (the golden keeps the
/// matching `-x`). Keys are matched EXACTLY by their `Family1:Name` (see
/// [`drop_keys`]).
fn check_excluding(fixture: &str, golden: &str, print_on: bool, excluded: &[&str]) {
  let root = env!("CARGO_MANIFEST_DIR");
  let data = std::fs::read(format!("{root}/tests/fixtures/{fixture}"))
    .unwrap_or_else(|e| panic!("read fixture {fixture}: {e}"));
  let want = std::fs::read_to_string(format!("{root}/tests/golden/{golden}"))
    .unwrap_or_else(|e| panic!("read golden {golden}: {e}"));
  let got = drop_keys(&extract_info(fixture, &data, print_on), excluded);
  let want = drop_keys(&want, excluded);
  if let Err(e) = json_equivalent(&got, &want) {
    panic!(
      "{fixture} vs {golden} [excluding {excluded:?}]: value mismatch: {}\n--- got ---\n{got}\n\
       --- want ---\n{want}",
      e.message()
    );
  }
}

/// Pin `TZ=UTC` before the first `jiff::tz::TimeZone::system()` call
/// (Codex R2 F1). The binary-plist `<date>` path ports the faithful
/// `ConvertUnixTime(_, 1)` localtime branch — its offset is OS-TZ dependent.
/// The committed goldens are captured `TZ=UTC` (`tools/gen_golden.sh`), so
/// every plist conformance case that has a `<date>` pins the same UTC zone
/// here for a host-independent comparison. `jiff` caches the system zone on
/// first use; `Once` makes this idempotent and ordered.
fn pin_utc() {
  use std::sync::Once;
  static ONCE: Once = Once::new();
  ONCE.call_once(|| {
    // SAFETY: runs before the first `TimeZone::system()` call (every
    // date-bearing plist case calls this first) and the test does not
    // spawn threads that read the environment concurrently.
    unsafe { std::env::set_var("TZ", "UTC") };
  });
}

#[test]
fn aac_conformance() {
  check("AAC.aac", "AAC.aac.json", true);
  check("AAC.aac", "AAC.aac.n.json", false);
}

#[test]
fn crw_conformance() {
  // Canon CRW (CIFF) container — Phase 1. `tests/fixtures/CanonRaw_min.crw` is
  // a HAND-CRAFTED minimal CIFF heap (the REAL bundled `t/images/CanonRaw.crw`
  // emits ~25 camera `Composite:*` tags + embedded XMP that this port cannot
  // emit, so it cannot be a byte-exact fixture). The crafted heap exercises:
  //   - the `ProcessCRW` header validate + the recursive `ProcessCanonRaw`
  //     HEAP walker (incl. a nested auto-subdirectory `0x2807 CameraObject`,
  //     tagType 0x28, whose `CanonImageType`/`ROMOperationMode` records prove
  //     recursion reaches nested leaves);
  //   - the value-in-directory path (`BaseISO` via tag|0x4000);
  //   - several `CanonRaw::Main` scalar records — `Make`/`Model` (the
  //     `MakeModel` binary sub-table), `FileFormat`+`TargetCompressionRatio`
  //     (the `ImageFormat` sub-table, PrintHex), `CanonFirmwareVersion`,
  //     `OwnerName`, `OriginalFileName`, `ThumbnailFileName`,
  //     `CanonModelID` (PrintHex + `%canonModelID` ⇒ "EOS D30"),
  //     `CanonImageType`, `ROMOperationMode`.
  // It DELIBERATELY excludes every Composite-trigger combo (no
  // CameraSettings/ShotInfo/FocalLength → no `Composite:Lens`/`DriveMode`/
  // `ShutterSpeed`/…), so the bundled `-G1 -j` output carries ONLY File:/
  // CanonRaw: keys (oracle-confirmed: NO Composite/XMP). The reused
  // `Canon::*` MakerNote sub-table dispatch (incl. the #183 ShotInfo
  // `FILE_TYPE eq "CRW"` raw-0 ExposureTime branch) is covered by the
  // `crw.rs` unit tests + the `vendors/canon` suite, since exercising it in
  // the conformance fixture would emit a `Composite:ShutterSpeed`.
  check("CanonRaw_min.crw", "CanonRaw_min.crw.json", true);
  check("CanonRaw_min.crw", "CanonRaw_min.crw.n.json", false);

  // EXTENDED coverage — the rest of the `CanonRaw::Main` scalar table plus a
  // Canon sub-table, in two CRAFTED Composite-free CIFF heaps (each verified
  // with `perl exiftool -G1 -j` to carry ONLY File:/CanonRaw:/Canon: keys):
  //
  // `CanonRaw_records.crw` exercises the NEWLY-PORTED scalar + structural
  // records — `TargetImageType`/`RecordID`/`FileNumber` (the `116-1602` dash
  // PrintConv)/`UserComment` (the `0x0805` non-`ImageDescription` arm)/
  // `CanonFileDescription` (the `0x0805` `ImageDescription` arm)/`MeasuredEV`
  // (`$val+5`)/`SerialNumber` (`%.10d` EOS PrintConv)/`ColorTemperature`/
  // `ColorSpace` (PrintConv) — plus the structural sub-tables `TimeStamp`
  // (DateTimeOriginal via `ConvertUnixTime`)/`DecoderTable`/`RawJpgInfo`
  // (PrintConv), and a `Canon::SensorInfo` sub-table (the sensor + black-mask
  // border coordinates). It DELIBERATELY omits `ImageInfo` (whose
  // ImageWidth/Height would synthesize `Composite:ImageSize`/`Megapixels`) and
  // `CameraSettings` (lens/shoot Composites).
  check("CanonRaw_records.crw", "CanonRaw_records.crw.json", true);
  check("CanonRaw_records.crw", "CanonRaw_records.crw.n.json", false);

  // `CanonRaw_colorbalance.crw` exercises the `Canon::ColorBalance` sub-table
  // (the `WB_RGGBLevels{Auto,Daylight,Shade,Cloudy,Tungsten,Fluorescent,Flash,
  // Custom,Kelvin}` + `WB_RGGBBlackLevels` int16s[4] quads, rendered
  // space-joined). ColorBalance alone does NOT trigger the WB Composites
  // (those need `WB_RGGBLevelsAsShot`/`Measured` from the deferred ColorData),
  // so the bundled `-G1 -j`/`-n` goldens carry only File:/CanonRaw:/Canon:.
  check(
    "CanonRaw_colorbalance.crw",
    "CanonRaw_colorbalance.crw.json",
    true,
  );
  check(
    "CanonRaw_colorbalance.crw",
    "CanonRaw_colorbalance.crw.n.json",
    false,
  );
}

#[test]
fn crw_scalars_conformance() {
  // The LAST coverage gap in `%CanonRaw::Main` — the remaining scalar tags plus
  // the previously-omitted NAMED no-conv records. `tests/fixtures/
  // CanonRaw_scalars.crw` is a CRAFTED Composite-free CIFF heap (verified via
  // `perl exiftool 13.59 -G1 -j`/`-n` to carry ONLY File:/CanonRaw: keys — no
  // Composite/XMP) exercising:
  //   - `ShutterReleaseMethod` (0x1010, int16u PrintConv ⇒ `"Single Shot"`/0),
  //   - `ShutterReleaseTiming` (0x1011, int16u PrintConv ⇒ `"Priority on
  //     focus"`/1),
  //   - `ReleaseSetting` (0x1016, int16u, no conv ⇒ `3`),
  //   - `SelfTimerTime` (0x1806, int32u, ValueConv `$val/1000` ⇒ `10` value,
  //     PrintConv `"$val s"` ⇒ `"10 s"`),
  //   - `TargetDistanceSetting` (0x1807, `Format => 'float'`, PrintConv
  //     `"$val mm"` ⇒ `"1234 mm"`/1234),
  //   - `NullRecord` (0x0000, int8u[4] ⇒ `"1 2 3 4"`),
  //   - `FreeBytes` (0x0001, `Format => 'undef', Binary => 1` ⇒ the `(Binary
  //     data 10 bytes …)` placeholder),
  //   - `CanonColorInfo1` (0x0032, int8u[6] ⇒ `"10 20 30 40 50 60"`) and
  //     `CanonColorInfo2` (0x102c, int16u[8] ⇒ `"1 2 3 4 5 6 7 8"`) — NAMED
  //     records with no sub-tags/PrintConv, whose whole value ExifTool reads as
  //     a `%crwTagFormat{tagType}` array (`CanonRaw.pm:798-800`).
  // These records carry no Composite linkage, so the goldens are File:/
  // CanonRaw: only. This completes the `%CanonRaw::Main` record coverage: every
  // table entry is now handled (the only un-emitted entries are `CanonFlashInfo`
  // 0x1028 `Unknown => 1`, suppressed by default, and `CustomFunctions` 0x1033,
  // the #87 CanonCustom deferral).
  check("CanonRaw_scalars.crw", "CanonRaw_scalars.crw.json", true);
  check("CanonRaw_scalars.crw", "CanonRaw_scalars.crw.n.json", false);
}

#[test]
fn crw_omitted_records_conformance() {
  // The three previously-omitted `CanonRaw::Main` binary sub-tables (the Codex
  // CRW finding) — `ExposureInfo` (0x1818), `FlashInfo` (0x1813), `WhiteSample`
  // (0x1030) — plus a `TimeStamp` (0x180e) carrying a FRACTIONAL `TimeZoneCode`.
  // `tests/fixtures/CanonRaw_omitted_records.crw` is a CRAFTED Composite-free
  // CIFF heap (verified via `perl exiftool -G1 -j`/`-n` to carry ONLY File:/
  // CanonRaw: keys) exercising:
  //   - `ExposureInfo` pos0 `ExposureCompensation` (float). pos1
  //     `ShutterSpeedValue` / pos2 `ApertureValue` are DELIBERATELY omitted
  //     from the fixture: ANY emitted ApertureValue/ShutterSpeedValue
  //     synthesizes a `Composite:Aperture`/`Composite:ShutterSpeed` (Exif.pm
  //     %Composite), which the port has no Composite subsystem to produce —
  //     so their ValueConv (`1/(2**$val)` / `2**($val/2)`) + PrintConv
  //     (`PrintExposureTime` / `sprintf("%.1f")`) are covered by the `crw.rs`
  //     unit tests instead.
  //   - `FlashInfo` pos0 `FlashGuideNumber` + pos1 `FlashThreshold` (float, no
  //     conv, no Composite).
  //   - `WhiteSample` pos1..5 (`WhiteSampleWidth`/`Height`/`LeftBorder`/
  //     `TopBorder`/`Bits`, int16u) + the pos-0x37 `BlackLevels` int16u[4]
  //     (rendered space-joined; a 3-word remnant `"129 130 131"` here). The
  //     fixture's first int16u equals the block byte length so the
  //     `Canon::Validate` gate passes (an invalid block emits NOTHING + a
  //     `Invalid WhiteSample data` warning, exercised by the `crw.rs` unit
  //     test `white_sample_invalid_length_suppressed`).
  //   - `TimeStamp` `TimeZoneCode` 19800 ⇒ `5.5` (the FLOAT `$val/3600`
  //     ValueConv — a +5:30 zone must NOT truncate to `5`).
  check(
    "CanonRaw_omitted_records.crw",
    "CanonRaw_omitted_records.crw.json",
    true,
  );
  check(
    "CanonRaw_omitted_records.crw",
    "CanonRaw_omitted_records.crw.n.json",
    false,
  );
}

#[test]
fn crw_whitesample_big_conformance() {
  // The SubDirectory read-gate fix (`CanonRaw.pm:707-709`: a record whose tag
  // has a `SubDirectory` is read REGARDLESS of size). `WhiteSample` (0x1030) is
  // the concrete real case — its named fields (`WhiteSampleWidth`/`Height`/
  // `LeftBorder`/`TopBorder`/`Bits` + `BlackLevels`) are "followed by the
  // encrypted white sample values" (`CanonRaw.pm:598`), so a real block can
  // exceed 512 bytes while every named tag lives in the first ~118 bytes.
  //
  // `tests/fixtures/CanonRaw_whitesample_big.crw` is a CRAFTED Composite-free
  // CIFF heap (verified via `perl exiftool 13.59 -G1 -j`/`-n` to carry ONLY
  // File:/CanonRaw: keys — no Composite/XMP) whose WhiteSample block is 600
  // bytes (offset-0 length word = 600 so the `Canon::Validate` gate passes),
  // with the named fields up front and a 482-byte arbitrary "encrypted" tail.
  // Before the fix the 600-byte block tripped `size > 512` and was dropped to a
  // `(Binary data 600 bytes)` placeholder, losing the named tags; the oracle
  // (and now the port) read the full block and extract them. The goldens
  // CONTAIN the WhiteSample named tags, proving the >512 block was read.
  check(
    "CanonRaw_whitesample_big.crw",
    "CanonRaw_whitesample_big.crw.json",
    true,
  );
  check(
    "CanonRaw_whitesample_big.crw",
    "CanonRaw_whitesample_big.crw.n.json",
    false,
  );
}

#[test]
fn crw_value_in_directory_conformance() {
  // The `valueInDir` branch (`CanonRaw.pm:692-699`): a record's value lives in
  // the entry's 8-byte size+ptr fields (`$size = 8`, `$value = substr($buff,
  // $pt+2, 8)`), and for a non-string/non-subdir value bundled FORCES
  // `$count = 1` (`CanonRaw.pm:698-699`). `tests/fixtures/CanonRaw_valueindir.crw`
  // is a CRAFTED Composite-free CIFF heap (verified via `perl exiftool 13.59
  // -G1 -j`/`-n` to carry ONLY File:/CanonRaw: keys) whose 5 R3 scalars
  // (`ShutterReleaseMethod`/`Timing`, `ReleaseSetting`, `SelfTimerTime`,
  // `TargetDistanceSetting`) PLUS `BaseISO` are all stored inline via
  // `valueInDir`, and an inline `CanonColorInfo2` (0x102c) array record —
  // whose `valueInDir` `$count = 1` makes it emit the BARE FIRST word (`11`),
  // NOT the 4-word `int(8/2)` array. Confirms every new scalar decodes from the
  // inline field identically to the out-of-line path, and the array record
  // honours the forced count.
  check(
    "CanonRaw_valueindir.crw",
    "CanonRaw_valueindir.crw.json",
    true,
  );
  check(
    "CanonRaw_valueindir.crw",
    "CanonRaw_valueindir.crw.n.json",
    false,
  );
}

#[test]
fn crw_zero_length_records_conformance() {
  // The ZERO-LENGTH (`size == 0`) record edge (`ReadValue` `$count == 0` ⇒ the
  // EMPTY STRING `''`, `ExifTool.pm:6296-6298`). `tests/fixtures/
  // CanonRaw_zerolen.crw` is a CRAFTED Composite-free CIFF heap (verified via
  // `perl exiftool 13.59 -G1 -j`/`-n` to carry ONLY File:/CanonRaw: keys) whose
  // NAMED no-conv ARRAY records (`NullRecord` 0x0000, `CanonColorInfo1` 0x0032,
  // `CanonColorInfo2` 0x102c) are each zero-length ⇒ emitted as `""`, and whose
  // binary LEAVES (`RawData` 0x2005, `FreeBytes` 0x0001) are zero-length ⇒
  // `(Binary data 0 bytes, use -b option to extract)`. (Zero-length numeric
  // SCALAR records — whose per-type ValueConv-of-empty rendering, e.g.
  // `"Unknown ()"`/`"0 s"`/`" mm"`, only arises on this MALFORMED input that no
  // camera-written CRW produces — stay a documented crafted-input residual; see
  // the `emit_scalar` note in `src/formats/crw.rs`.)
  check("CanonRaw_zerolen.crw", "CanonRaw_zerolen.crw.json", true);
  check("CanonRaw_zerolen.crw", "CanonRaw_zerolen.crw.n.json", false);
}

#[test]
fn riff_avi_conformance() {
  // FORMATS.md row 26 — bundled `lib/Image/ExifTool/t/images/RIFF.avi`
  // (1262 bytes, Canon MotionJPEG Camera AVI from 2003). Exercises the
  // RIFF/AVI walker end-to-end:
  //  - outer RIFF/AVI magic + 4-byte body TYPE (RIFF.pm:2040-2053)
  //  - `LIST_hdrl` → `avih` (`%AVIHeader` int32u table, RIFF.pm:1076-1108)
  //  - `LIST_strl` x2 (vids + auds), each with `strh` (`%StreamHeader`
  //    PRIORITY=0 first-wins, RIFF.pm:1160-1248) + `strf` (`%AudioFormat`
  //    for auds RIFF.pm:687-709; inline BMP-V3 for vids BMP.pm:36-150)
  //  - `LIST_INFO` → `ISFT` Software (RIFF.pm:869-874)
  //  - `IDIT` DateTimeOriginal via `ConvertRIFFDate` (RIFF.pm:1601-1619)
  // Goldens are the bundled `perl exiftool -j -G1 -struct` output with
  // `System:*` + `Composite:*` + `XMP-*:*` stripped (the standard uniform
  // exclusion; Composite synthesis + XMP infra are Phase-3+ forward items).
  check("RIFF.avi", "RIFF.avi.json", true);
  check("RIFF.avi", "RIFF.avi.n.json", false);
}

#[test]
fn riff_junk_conformance() {
  // The ported `%Main` `JUNK` Condition subset (RIFF.pm:442-492, #154), each on
  // a HAND-CRAFTED minimal AVI (a `RIFF`/`AVI ` + `LIST_hdrl`/`avih` + a single
  // `JUNK` chunk) — every fixture's bundled `-G1 -j` output is oracle-confirmed
  // to carry ONLY File:/RIFF:/Pentax: + the ported Composites
  // (ImageSize/Megapixels/Duration, which exifast emits byte-exact).
  //
  // `AVI_textjunk.avi` — `TextJunk` (RIFF.pm:488-491). The JUNK payload
  // "Hello RIFF Junk Text\0\0\0\0" matches the ASCII-only RawConv
  // `/^([^\0-\x1f\x7f-\xff]+)\0*$/`, so `$1` ("Hello RIFF Junk Text") emits as
  // `RIFF:TextJunk`.
  check("AVI_textjunk.avi", "AVI_textjunk.avi.json", true);
  check("AVI_textjunk.avi", "AVI_textjunk.avi.n.json", false);

  // `AVI_pentaxjunk.avi` — `PentaxJunk` (Optio RS1000, RIFF.pm:469-473 →
  // `%Pentax::Junk`, `Pentax.pm:6409-6418`). The `^IIII\x01\0`-tagged JUNK emits
  // its single `Model` `string[32]` @ 0x0c ("Optio RS1000") under
  // `MakerNotes:Pentax:Model`.
  check("AVI_pentaxjunk.avi", "AVI_pentaxjunk.avi.json", true);
  check("AVI_pentaxjunk.avi", "AVI_pentaxjunk.avi.n.json", false);

  // `AVI_pentaxjunk2.avi` — `PentaxJunk2` (Optio RZ18, RIFF.pm:474-478 →
  // `%Pentax::Junk2`, `Pentax.pm:6610-6658`). The `^PENTDigital Camera`-tagged
  // JUNK emits `Pentax:Make`/`Model`/`FNumber` (rational64u 28/10 → 2.8, the
  // `%.1f` PrintConv)/`DateTime1`/`DateTime2` (the 0x12b+ thumbnail leaves are
  // out of range for this minimal chunk). The engine's EXIF Composite post-pass
  // resolves `FNumber` from the `MakerNotes:Pentax:FNumber` ingredient and
  // builds `Composite:Aperture` = 2.8 byte-exact vs bundled — so it is KEPT
  // (plain `check`, no exclusion), alongside the ported
  // ImageSize/Megapixels/Duration.
  check("AVI_pentaxjunk2.avi", "AVI_pentaxjunk2.avi.json", true);
  check("AVI_pentaxjunk2.avi", "AVI_pentaxjunk2.avi.n.json", false);

  // `AVI_pentaxjunk2_dup.avi` (#422) — the `AVI_pentaxjunk2.avi` base with a
  // SECOND, FULL-LENGTH `PentaxJunk2` `JUNK` chunk (a different `Model`
  // "Optio RZ99" + `DateTime` 2099) appended at the top level. ExifTool re-runs
  // the matched `%Pentax::Junk2` SubDirectory on EVERY `JUNK` chunk it walks, so
  // the later chunk's `Pentax:*` leaves last-wins over the earlier one's via the
  // normal `Priority => 1` tag-overwrite — bundled 13.59 keeps
  // `Model = Optio RZ99` / `DateTime1 = 2099:12:31 23:59:58` (the SECOND chunk),
  // NOT the first "Optio RZ18"/2014. The pre-#422 first-match-wins capture (the
  // `pentax_junk.is_none()` guard) wrongly froze the FIRST chunk; the now
  // ordered-Vec + replay-all dispatch emits both chunks' leaves and the central
  // `TagMap` resolves each tag to the last-walked.
  check(
    "AVI_pentaxjunk2_dup.avi",
    "AVI_pentaxjunk2_dup.avi.json",
    true,
  );
  check(
    "AVI_pentaxjunk2_dup.avi",
    "AVI_pentaxjunk2_dup.avi.n.json",
    false,
  );

  // `AVI_pentaxjunk2_partial.avi` (#422 Codex [high]) — a FULL `PentaxJunk2`
  // chunk (Make=PENTAX, Model="Optio RZ18", FNumber 28/10, DateTime 2014)
  // followed by a SHORTER same-signature `PentaxJunk2` chunk (44 bytes: only the
  // `Make`="RICOH " leaf @ 0x12 is in range; `Model`/`FNumber`/`DateTime` @
  // 0x2c/0x5e/0x83/0x9d are PAST the chunk end). ExifTool replays the
  // SubDirectory per chunk and the `TagMap` dedups PER LEAF, so bundled 13.59
  // keeps the first chunk's `Model`/`FNumber`/`DateTime1`/`DateTime2` (the short
  // chunk emits none of them) while the later `Make = "RICOH "` wins. The
  // pre-fix whole-payload OVERWRITE would have dropped Model/FNumber/DateTime
  // (keeping only the short chunk's Make subset); the ordered-Vec + replay-all
  // fix preserves the union, matching bundled byte-exact.
  check(
    "AVI_pentaxjunk2_partial.avi",
    "AVI_pentaxjunk2_partial.avi.json",
    true,
  );
  check(
    "AVI_pentaxjunk2_partial.avi",
    "AVI_pentaxjunk2_partial.avi.n.json",
    false,
  );

  // `AVI_pentaxjunk2_before_hydt.avi` (#434) — a CRAFTED AVI placing a FULL
  // `PentaxJunk2` `JUNK` chunk (the real `AVI_pentaxjunk2.avi` body: `FNumber`
  // 28/10 → 2.8) at the top level BEFORE the real `Pentax.avi` `LIST_hydt`
  // MakerNote (whose `%Pentax::Main` hymn IFD also carries an `FNumber`, here
  // 0.0). This is the cross-source ordering deferred at #422 R5: the pre-#434
  // `tags()` replayed the MakerNote unconditionally BEFORE the `JUNK`, so a
  // crafted JUNK-before-hydt file would have resolved the lone overlapping leaf
  // (`Pentax:FNumber`) wrong. The fix replays a SINGLE walk-ordered
  // `pentax_events` list so the central `TagMap` resolves in true RIFF walk
  // order. Bundled 13.59 keeps `Pentax:FNumber = 2.8` here REGARDLESS of order:
  // the `%Pentax::Main` hymn `FNumber` is `Priority => 0` (`Pentax.pm:1484`)
  // while the `%Pentax::Junk2` `FNumber` is the default `Priority => 1`, so the
  // `JUNK` value wins and the later hymn `FNumber` never overrides it
  // (`ExifTool.pm:9544-9589`). exifast threads the emission's `Priority => N`
  // into the MakerNote replay, so it matches byte-exact (the hymn `Pentax:*`
  // leaves + the `JUNK` `Make`/`Model`/`DateTime`, `Composite:Aperture` = 2.8).
  // The golden is generated with the SAME `EXCLUDE` as `Pentax.avi` (the shared
  // hymn IFD): the three still-deferred size-24 AEInfo leaves
  // `AEWhiteBalance`/`AEMeteringMode2`/`LevelIndicator` are dropped — a
  // pre-existing `%Pentax::Main` port gap, NOT a #434 regression (the diff
  // carries no tag exifast emits that bundled does not).
  check(
    "AVI_pentaxjunk2_before_hydt.avi",
    "AVI_pentaxjunk2_before_hydt.avi.json",
    true,
  );
  check(
    "AVI_pentaxjunk2_before_hydt.avi",
    "AVI_pentaxjunk2_before_hydt.avi.n.json",
    false,
  );
}

#[test]
fn riff_strd_conformance() {
  // The ported `%RIFF::StreamData` subset (RIFF.pm:1250-1276, `ProcessStreamData`
  // at RIFF.pm:1699-1748, #158), each on a HAND-CRAFTED minimal AVI: a `RIFF`/
  // `AVI ` + `LIST_hdrl` (`avih` + `LIST_strl` carrying a single `strd` chunk).
  // `ProcessStreamData` keys the table by the `strd` chunk's leading 4-byte tag
  // ID. Every fixture's bundled `-G1 -j` output is oracle-confirmed to carry
  // ONLY File:/RIFF:/Casio: + the ported Composites (ImageSize/Megapixels/
  // Duration, emitted byte-exact). The three rows render mode-independently
  // (`-j` ≡ `-n`: the tags carry no PrintConv/ValueConv).
  //
  // `AVI_strd_zora.avi` — `Zora` (Samsung PL90, RIFF.pm:1270 `Zora =>
  // 'VendorName'`). A plain tag (no Format) ⇒ ExifTool's default string render
  // (`tr/\0//d`): the WHOLE payload "Zora"+"SAMSUNG"+"\0" → `RIFF:VendorName` =
  // "ZoraSAMSUNG" (the tag ID is included; the trailing NUL is deleted).
  check("AVI_strd_zora.avi", "AVI_strd_zora.avi.json", true);
  check("AVI_strd_zora.avi", "AVI_strd_zora.avi.n.json", false);

  // `AVI_strd_casi.avi` — `CASI` (Casio GV-10, RIFF.pm:1266-1269 → `%Casio::AVI`,
  // `Casio.pm:2006-2015`). `ProcessBinaryData` offset-0 `Software` `Format =>
  // 'string'` reads from the `CASI` tag ID itself (no `Start` override) as a
  // C-string ⇒ `Casio:Software` = "CASICasio GV-10 Software" (family-0
  // `MakerNotes`, family-1 `Casio`).
  check("AVI_strd_casi.avi", "AVI_strd_casi.avi.json", true);
  check("AVI_strd_casi.avi", "AVI_strd_casi.avi.n.json", false);

  // `AVI_strd_unknown.avi` — the `unknown` fallback (RIFF.pm:1271-1275). The
  // `XVND`-tagged strd matches no named row; its all-printable payload passes the
  // `UnknownData` RawConv `/^[^\0-\x1f\x7f-\xff]+$/` ⇒ `RIFF:UnknownData` =
  // "XVNDGenericVendorData" (the whole payload, tag ID included).
  check("AVI_strd_unknown.avi", "AVI_strd_unknown.avi.json", true);
  check("AVI_strd_unknown.avi", "AVI_strd_unknown.avi.n.json", false);

  // `AVI_strd_multi.avi` — a TWO-STREAM AVI: `LIST_hdrl` carries `avih` + two
  // `LIST_strl`, each with its own `strd` of a DIFFERENT `%RIFF::StreamData`
  // variant — stream 0 `XVND…` (the `unknown` fallback ⇒ `RIFF:UnknownData`),
  // stream 1 `Zora…` (⇒ `RIFF:VendorName`). ExifTool runs `ProcessStreamData`
  // on EVERY `strd` it walks (one per stream), so BOTH leaves emit; the #158
  // first-match-wins capture dropped the second `strd` entirely. Oracle-pinned
  // vs bundled 13.59 (`-G1 -j`/`-n` carry BOTH `RIFF:UnknownData` AND
  // `RIFF:VendorName` + the ported Composites) — this case FAILS on the old
  // single-slot capture and PASSES once each matched `strd` is recorded in walk
  // order and emitted.
  check("AVI_strd_multi.avi", "AVI_strd_multi.avi.json", true);
  check("AVI_strd_multi.avi", "AVI_strd_multi.avi.n.json", false);

  // `AVI_strd_dup.avi` — a TWO-STREAM AVI whose two `strd` chunks are the SAME
  // variant (both `Zora…`, payloads "ZoraFIRST" then "ZoraSECOND"), so each
  // renders to the SAME tag `RIFF:VendorName`. Both records emit in walk order
  // and the `TagMap` priority-1 duplicate rule keeps the LAST-walked one —
  // exactly bundled 13.59's default-duplicate last-wins (`RIFF:VendorName` =
  // "ZoraSECOND", NOT the first "ZoraFIRST"). Confirms the ordered-Vec fix
  // defers same-key resolution to the normal dedup path rather than blocking at
  // capture (which would have wrongly frozen the FIRST value).
  check("AVI_strd_dup.avi", "AVI_strd_dup.avi.json", true);
  check("AVI_strd_dup.avi", "AVI_strd_dup.avi.n.json", false);
}

#[test]
fn riff_wav_extensible_encoding_conformance() {
  // Finding 1 (full `%audioEncoding`, RIFF.pm:90-335). A crafted WAV whose
  // `fmt ` Encoding is `0xfffe` = `WAVE_FORMAT_EXTENSIBLE` (RIFF.pm:333) —
  // a code OUTSIDE the previous partial table. PrintConv ⇒ "Extensible";
  // `-n` ⇒ the raw `1`-style int (here `65534`). Oracle-verified.
  check(
    "RIFF_wav_extensible.wav",
    "RIFF_wav_extensible.wav.json",
    true,
  );
  check(
    "RIFF_wav_extensible.wav",
    "RIFF_wav_extensible.wav.n.json",
    false,
  );
}

#[test]
fn riff_info_latin1_charset_conformance() {
  // Finding 2 (CSET/charset). A WAV with `LIST_INFO` `IART` carrying cp1252
  // high bytes (`0xe9`→é, `0x80`→€). The DEFAULT RIFF charset is `'Latin'`
  // (cp1252), NOT UTF-8 (RIFF.pm:1782-1790, 1829), so bundled decodes the
  // Artist to "Café €" — the previous UTF-8-lossy path would have produced
  // U+FFFD. Oracle-verified.
  check("RIFF_info_latin1.wav", "RIFF_info_latin1.wav.json", true);
  check("RIFF_info_latin1.wav", "RIFF_info_latin1.wav.n.json", false);
}

#[test]
fn riff_info_casio_valueconv_conformance() {
  // Finding 2 (INFO ValueConvs). `ISFT` "EXILIM\0CASIO" → "EXILIM, CASIO"
  // (the Casio embedded-NUL ValueConv, RIFF.pm:873); `ICRD` "2003-03-10" →
  // "2003:03:10" (the hyphen→colon date ValueConv, RIFF.pm:853).
  // Oracle-verified.
  check("RIFF_info_casio.wav", "RIFF_info_casio.wav.json", true);
  check("RIFF_info_casio.wav", "RIFF_info_casio.wav.n.json", false);
}

#[test]
fn riff_truncated_fmt_conformance() {
  // Finding 4 (truncated-chunk guard). A WAV whose `fmt ` chunk declares 16
  // payload bytes but only 12 are present (runs past EOF). Bundled does NOT
  // dispatch the partial chunk (no `RIFF:Encoding`/etc.) and warns once
  // "Error reading RIFF file (corrupted?)" (RIFF.pm:2150/2216). Oracle-verified.
  check(
    "RIFF_truncated_fmt.wav",
    "RIFF_truncated_fmt.wav.json",
    true,
  );
  check(
    "RIFF_truncated_fmt.wav",
    "RIFF_truncated_fmt.wav.n.json",
    false,
  );
}

#[test]
fn riff_webp_conformance() {
  // FORMATS.md row 26 (WEBP via the RIFF walker) — bundled
  // `lib/Image/ExifTool/t/images/RIFF.webp` (586 bytes, a 1x1 Extended WEBP).
  // Exercises the WEBP chunk tables + the embedded EXIF/XMP seam (#153, #160):
  //  - `VP8X` (`%RIFF::VP8X`, RIFF.pm:1351-1379): WebP_Flags BITMASK
  //    ("XMP, EXIF, Alpha"), the 24-bit canvas ImageWidth/Height (1x1), AND the
  //    `OverrideFileType('Extended WEBP', undef, 'webp')` promotion
  //    (RIFF.pm:2106 -> `File:FileType` = "Extended WEBP", extension "webp").
  //  - `ALPH` (`%RIFF::ALPH`, RIFF.pm:1467-1497): AlphaPreprocessing/Filtering/
  //    Compression (all three read byte 0 `& 0x03`, verbatim per the table).
  //  - `VP8 ` (`%RIFF::VP8`, RIFF.pm:1279-1319): VP8Version (Mask 0x0e) +
  //    Horizontal/VerticalScale (Mask 0xc000); its ImageWidth/Height are the
  //    `Priority => 0` duplicates the `VP8X` canvas suppresses (the `-a`-only
  //    `RIFF:Copy1`, absent from this default `-j`/`-n` output).
  //  - `EXIF` chunk (RIFF.pm:557-576): the embedded `MM\0*` TIFF block re-walked
  //    through the shared `ProcessTIFF` parser -> `File:ExifByteOrder` + IFD0
  //    (XResolution/YResolution/ResolutionUnit/Artist/YCbCrPositioning).
  //  - `XMP ` chunk (RIFF.pm:577-580): the standard packet -> XMP-x:XMPToolkit +
  //    XMP-dc:Subject (a Bag -> ["test"]).
  // Goldens drop `Composite:*` (ImageSize/Megapixels synthesized from the VP8X
  // dimensions; this port has no Composite subsystem) and `System:*` — the
  // standard `EXCLUDE="-x Composite:all"` regen (see `tools/gen_golden.sh`).
  check("RIFF.webp", "RIFF.webp.json", true);
  check("RIFF.webp", "RIFF.webp.n.json", false);
}

#[test]
fn riff_webp_malformed_metadata_conformance() {
  // Malformed embedded-metadata WEBP variants (#153 Codex R1) — CRAFTED 1x1
  // Extended-WEBP fixtures pinning the byte-exact `ExifTool:Warning` and the
  // repeated-chunk tag retention against bundled 13.59.
  //
  //  - `RIFF_webp_improper_exif.webp`: a single `EXIF` chunk with the
  //    non-standard `Exif\0\0` header (RIFF.pm:567 `Warn(..., 1)`) ⇒ the
  //    MINOR `"[minor] Improper EXIF header"` warning (NOT a plain
  //    `ExifTool:Warning`) plus the chunk's `IFD0:Artist` (the 6-byte header
  //    stripped, the TIFF re-walked through `ProcessTIFF`).
  //  - `RIFF_webp_incorrect_xmp.webp`: a single `XMP\0` chunk (the incorrect
  //    tag ID, RIFF.pm:582-587 `Warn(..., 1)`) ⇒ `"[minor] Incorrect XMP tag
  //    ID"` plus the packet's `XMP-x:XMPToolkit`.
  //  - `RIFF_webp_multi_meta.webp`: TWO `EXIF` chunks (IFD0:Artist then
  //    IFD0:Make) and TWO `XMP ` chunks (x:xmptk then dc:creator). RIFF
  //    dispatches EVERY metadata chunk it walks (RIFF.pm:557-587), so the
  //    output retains the DISTINCT tags from all four — `IFD0:Artist`,
  //    `IFD0:Make`, `XMP-x:XMPToolkit`, `XMP-dc:Creator` — proving the ordered
  //    replay (a single Option would drop the earlier EXIF/XMP chunk).
  // Composite:* (ImageSize/Megapixels synthesized from the VP8X canvas) is
  // dropped via `EXCLUDE="-x Composite:all"` at regen, like `RIFF.webp`.
  check(
    "RIFF_webp_improper_exif.webp",
    "RIFF_webp_improper_exif.webp.json",
    true,
  );
  check(
    "RIFF_webp_improper_exif.webp",
    "RIFF_webp_improper_exif.webp.n.json",
    false,
  );
  check(
    "RIFF_webp_incorrect_xmp.webp",
    "RIFF_webp_incorrect_xmp.webp.json",
    true,
  );
  check(
    "RIFF_webp_incorrect_xmp.webp",
    "RIFF_webp_incorrect_xmp.webp.n.json",
    false,
  );
  check(
    "RIFF_webp_multi_meta.webp",
    "RIFF_webp_multi_meta.webp.json",
    true,
  );
  check(
    "RIFF_webp_multi_meta.webp",
    "RIFF_webp_multi_meta.webp.n.json",
    false,
  );
}

#[test]
fn quicktime_sp1_conformance() {
  // QuickTime port Sub-Port 1 (the box/atom walker + core structural
  // atoms). `tests/fixtures/QuickTime_sp1.mov` is a SYNTHETIC minimal
  // `.mov` exercising exactly the atoms SP1 implements: `ftyp` +
  // `moov`(`mvhd` + 2 `trak`s, each `tkhd`/`mdia`(`mdhd`/`hdlr`)) +
  // `mdat`. The real bundled `QuickTime.mov`/`QuickTime.m4a` fixtures
  // land in a later sub-port (SP1 cannot reach byte-exact parity on
  // them — most of their tags belong to SP2-SP4).
  //
  // PR #38 Codex R1/F1: the goldens are now the FULL UNSTRIPPED bundled
  // `perl exiftool -j -G1 -struct -api QuickTimeUTC=1` output — every tag
  // ExifTool emits for the ftyp/mvhd/tkhd/mdhd/mdat atoms SP1 implements
  // (MajorBrand/MinorVersion/CompatibleBrands, PreferredRate/Volume,
  // MatrixStructure, the Preview/Poster/Selection/Current time tags,
  // NextTrackID, MediaDataSize/Offset, TrackCreate/ModifyDate, TrackLayer/
  // Volume, MediaCreate/ModifyDate, …). Only the STANDARD `System:*` /
  // `Composite:*` exclusions remain (composite synthesis is deferred per
  // `[[exifast-phase2-forward-items]]`, the same uniform exclusion every
  // other format golden applies). No per-tag stripping.
  check("QuickTime_sp1.mov", "QuickTime_sp1.mov.json", true);
  check("QuickTime_sp1.mov", "QuickTime_sp1.mov.n.json", false);
}

#[test]
fn quicktime_v1_tkhd_conformance() {
  // PR #38 Codex R1/F2: a SYNTHETIC `.mov` with a VERSION-1 tkhd. The v1
  // Hook widens only the three time/duration fields (create/modify/duration,
  // +12 bytes), so ImageWidth/ImageHeight (int32u table indices 19/20) sit
  // at byte offsets 88/92 — NOT 96/100. Verified vs bundled ExifTool:
  // ImageWidth=1280, ImageHeight=720. Without the F2 fix the decoder read
  // garbage from 96/100.
  check("QuickTime_v1tkhd.mov", "QuickTime_v1tkhd.mov.json", true);
  check("QuickTime_v1tkhd.mov", "QuickTime_v1tkhd.mov.n.json", false);
}

#[test]
fn quicktime_stsd_fixed_field_bleed_conformance() {
  // #302: the faithful whole-box fixed-field BLEED for a NON-LAST `stsd`
  // sample-description entry. ExifTool reads each %VisualSampleDesc fixed field
  // at `substr($$dataPt, off + dirStart, ...)` within
  // `$size = min(DirLen, dataLen - dirStart)` where `DirLen` is the ProcessHybrid
  // child boundary (an ABSOLUTE box offset, QuickTime.pm:9680). The synthetic
  // `QuickTime_stsd_fixed_field_bleed.mov` has a 3-entry `vide` `stsd` whose
  // middle entry (a short `hvc1` with an early child boundary, `dirStart` 94 ⇒
  // `$size` 100) reads its `BitDepth` (entry-relative 82) PAST its 36-byte extent
  // into the third entry's bytes — `0xBEEF` is planted there ⇒
  // `Track1:BitDepth 48879`. Its `VendorID` (rel 20) likewise reads the entry's
  // own child `glbl` 4cc. Goldens are bundled `perl exiftool -j -G1 -struct -api
  // QuickTimeUTC=1` (`System:*`/`Composite:*` excluded per the Phase-2 forward
  // item, MOV precedent). See
  // `tools/gen_quicktime_stsd_bleed_fixture.py` and the unit test
  // `walk_trak_vide_nonlast_entry_fixed_field_bleeds_into_next`.
  check(
    "QuickTime_stsd_fixed_field_bleed.mov",
    "QuickTime_stsd_fixed_field_bleed.mov.json",
    true,
  );
  check(
    "QuickTime_stsd_fixed_field_bleed.mov",
    "QuickTime_stsd_fixed_field_bleed.mov.n.json",
    false,
  );
}

#[test]
fn quicktime_moov_order_conformance() {
  // PR #38 Codex R1/F4 (REFUTED): a SYNTHETIC `.mov` whose `trak` precedes
  // `mvhd` inside `moov`. The `TrackDuration` durationInfo is a ValueConv
  // applied at OUTPUT time using the FINAL movie TimeScale — so the trak's
  // TrackDuration is `18000/600 = 30 s` even though the trak is parsed
  // before mvhd (verified vs bundled). Pins the final-TimeScale semantics
  // against the Codex-suggested (incorrect) parse-order threading.
  check(
    "QuickTime_moov_order.mov",
    "QuickTime_moov_order.mov.json",
    true,
  );
  check(
    "QuickTime_moov_order.mov",
    "QuickTime_moov_order.mov.n.json",
    false,
  );
}

#[test]
fn quicktime_sp2_conformance() {
  // QuickTime port Sub-Port 2 — the `udta` camera atoms + `moov/meta`
  // Keys/ItemList metadata (make + model + software + capture-date + GPS).
  // `tests/fixtures/QuickTime_sp2.mov` is a SYNTHETIC minimal `.mov` carrying
  // a `moov/udta` with the `©mak`/`©mod`/`©swr`/`©nam`/`©day`/`©xyz`/`©cmt`
  // atoms AND a `moov/meta` (`hdlr`=mdta + `keys`/`ilst`) with the
  // `com.apple.quicktime.make`/`model`/`software`/`creationdate`/`location.ISO6709`
  // keys. Exercises: the international-text decoder, the `%iso8601Date`
  // ValueConv (©day / creationdate), the `ConvertISO6709` ValueConv + the
  // `PrintGPSCoordinates` PrintConv (©xyz / location), the Keys index table +
  // ilst-data decode, and the `QuickTime:HandlerType=mdta` (moov/meta hdlr).
  // Group split (`-G1`): `QuickTime:UserData` vs `QuickTime:Keys`. Goldens are
  // the full bundled `perl exiftool -j -G1 -struct -api QuickTimeUTC=1` output
  // (`System:*` / `Composite:*` excluded per the uniform Phase-2 forward-item
  // exclusion).
  check("QuickTime_sp2.mov", "QuickTime_sp2.mov.json", true);
  check("QuickTime_sp2.mov", "QuickTime_sp2.mov.n.json", false);
}

#[test]
fn quicktime_sp2_badgps_conformance() {
  // QuickTime SP2 — the `ConvertISO6709` raw-string PASS-THROUGH (the high
  // Codex finding). `tests/fixtures/QuickTime_sp2_badgps.mov` is the SP2 fixture
  // with its `©xyz` payload binary-patched from the decodable
  // `+37.3318-122.0312+010.500/` to the NON-coordinate string `hello` (atom +
  // `udta` + `moov` sizes fixed; no `stco`/sample tables ⇒ no offset shifts).
  // ExifTool's `ConvertISO6709` (QuickTime.pm:8884-8909) has NO `else` branch —
  // a string matching none of the three ISO 6709 forms is `return $val`
  // UNCHANGED — so `UserData:GPSCoordinates` is STILL emitted: under `-n` the
  // raw `hello`; under `-j` `PrintGPSCoordinates("hello")` = `0 deg 0' 0.00" N,
  // ` (the non-numeric latitude numifies to 0; the missing longitude is `undef`
  // and renders as the empty string after the `, `). The Keys
  // `location.ISO6709` is left a valid coordinate, so the decoded happy path is
  // still exercised in the SAME file. Regression for the port previously
  // DROPPING the tag on an undecodable-but-present `©xyz`. Goldens via the same
  // bundled `perl exiftool -j -G1 -struct -api QuickTimeUTC=1` (System/Composite
  // excluded per the Phase-2 forward-item exclusion).
  check(
    "QuickTime_sp2_badgps.mov",
    "QuickTime_sp2_badgps.mov.json",
    true,
  );
  check(
    "QuickTime_sp2_badgps.mov",
    "QuickTime_sp2_badgps.mov.n.json",
    false,
  );
}

#[test]
fn quicktime_sp2_iso6709long_conformance() {
  // QuickTime SP2 — `ConvertISO6709` DECIMAL-form numification fidelity (a
  // verified Codex [medium]). `tests/fixtures/QuickTime_sp2_iso6709long.mov` is
  // the SP2 fixture with its `©xyz` payload binary-patched from the decodable
  // `+37.3318-122.0312+010.500/` to the LONG-fractional decimal coordinate
  // `+12.123456789012345678901-034.9876543210987654321+010.123456789012345/`
  // (atom + `udta` + `moov` sizes fixed). ExifTool's `ConvertISO6709`
  // (QuickTime.pm:8887) builds the decimal ValueConv from `($1+0)`/`($2+0)`/
  // `($3+0)` — Perl NUMIFIES each matched substring to a double then
  // stringifies it (~15 significant digits), so `-n`
  // `UserData:GPSCoordinates` = `12.1234567890123 -34.9876543210988
  // 10.1234567890123` (f64-rounded), NOT the verbatim 21-digit string. The port
  // builds the decimal form from the parsed f64 via `perl_num`
  // (`format_g(_, 15)`), matching exactly. The Keys `location.ISO6709` keeps a
  // normal coordinate so the byte-identical happy path coexists in the file.
  // Goldens via the same bundled `perl exiftool -j -G1 -struct -api
  // QuickTimeUTC=1` (System/Composite excluded per the Phase-2 forward item).
  check(
    "QuickTime_sp2_iso6709long.mov",
    "QuickTime_sp2_iso6709long.mov.json",
    true,
  );
  check(
    "QuickTime_sp2_iso6709long.mov",
    "QuickTime_sp2_iso6709long.mov.n.json",
    false,
  );
}

#[test]
fn quicktime_sp2_infgps_conformance() {
  // QuickTime SP2 — `PrintGPSCoordinates`/`GPS::ToDMS` non-finite fidelity (a
  // verified Codex [medium]). `tests/fixtures/QuickTime_sp2_infgps.mov` is the
  // SP2 fixture with its `©xyz` payload binary-patched to the NON-finite raw
  // string `inf inf -inf` (atom + `udta` + `moov` sizes fixed). No ISO 6709 form
  // matches, so `ConvertISO6709` returns the string UNCHANGED: under `-n`
  // `UserData:GPSCoordinates` = the verbatim `inf inf -inf` (lowercase — never
  // numified), while under `-j` `PrintGPSCoordinates` runs each token through
  // `GPS::ToDMS` + Perl numeric stringification, which use Perl's titlecase
  // `Inf`/`-Inf`/`NaN`: `Inf deg NaN' NaN" N, Inf deg NaN' NaN" E, Inf m Below
  // Sea Level` (the `-inf` altitude is `-(-Inf)` = `Inf` in the Below-Sea-Level
  // branch). Regression for `to_dms`/`perl_num` previously emitting Rust's
  // lowercase `inf`. Goldens via the same bundled `perl exiftool -j -G1 -struct
  // -api QuickTimeUTC=1` (System/Composite excluded per the Phase-2 forward
  // item).
  check(
    "QuickTime_sp2_infgps.mov",
    "QuickTime_sp2_infgps.mov.json",
    true,
  );
  check(
    "QuickTime_sp2_infgps.mov",
    "QuickTime_sp2_infgps.mov.n.json",
    false,
  );
}

#[test]
fn quicktime_sp2_ilst_before_keys_conformance() {
  // QuickTime SP2 — `ProcessKeys` SINGLE-PASS, file-order key resolution (a
  // verified Codex [high]). `tests/fixtures/QuickTime_sp2_ilst_before_keys.mov`
  // is the SP2 fixture with the `moov/meta` children REORDERED so the `ilst`
  // box precedes the `keys` box (hdlr, ilst, keys). ExifTool's `ProcessMOV`
  // walks `meta` children in order with no look-ahead: `ProcessKeys` registers
  // the ItemList key tags (id `"$KeysCount.$index"`) only when the `keys` atom
  // is reached (QuickTime.pm:9857), and an `ilst` item resolves its id
  // `"$KeysCount.unpack('N')"` against the table built SO FAR
  // (QuickTime.pm:10132). An `ilst` ahead of its `keys` therefore finds NO
  // registered id ⇒ EVERY item is dropped, so the bundled output has ZERO
  // `Keys:*` tags (the udta `UserData:*`, both tracks, and the `mdta`
  // HandlerType are byte-identical to the base `QuickTime_sp2.mov` golden).
  // Regression for the prior two-pass design, which wrongly resolved the `ilst`
  // against a FUTURE `keys` table and populated the Keys tags anyway. Goldens
  // via the same bundled `perl exiftool -j -G1 -struct -api QuickTimeUTC=1`
  // (System/Composite excluded per the Phase-2 forward item).
  check(
    "QuickTime_sp2_ilst_before_keys.mov",
    "QuickTime_sp2_ilst_before_keys.mov.json",
    true,
  );
  check(
    "QuickTime_sp2_ilst_before_keys.mov",
    "QuickTime_sp2_ilst_before_keys.mov.n.json",
    false,
  );
}

#[test]
fn quicktime_sp2_macroman_conformance() {
  // QuickTime SP2 — default-language (`lang 0`) `udta` text is MacRoman by
  // default (a verified Codex [medium]). `tests/fixtures/QuickTime_sp2_macroman
  // .mov` is the SP2 fixture with the `©nam` (Title) text bytes changed to the
  // MacRoman sequence `Caf\x8e Clip` (lang 0; `0x8e` = MacRoman é = U+00E9),
  // size-preserving (same 9-byte length as the original `Test Clip`). ExifTool
  // treats QuickTime language 0 as a Macintosh language code whose charset
  // defaults to `CharsetQuickTime` = MacRoman, using UTF-8 ONLY when the bytes
  // are "obviously UTF8" (`IsUTF8 > 0`, QuickTime.pm:10499-10506). `Caf\x8e
  // Clip` is NOT valid UTF-8 (`0x8e` is an invalid lead byte), so it decodes as
  // MacRoman ⇒ `UserData:Title` = `Café Clip` in BOTH `-j` and `-n` (a charset
  // decode, not a PrintConv). Regression for the prior code, which treated
  // `lang 0` as UTF-8 unconditionally and corrupted the byte to U+FFFD. Every
  // other tag is byte-identical to the base `QuickTime_sp2.mov` golden. Goldens
  // via the same bundled `perl exiftool -j -G1 -struct -api QuickTimeUTC=1`
  // (System/Composite excluded per the Phase-2 forward item).
  check(
    "QuickTime_sp2_macroman.mov",
    "QuickTime_sp2_macroman.mov.json",
    true,
  );
  check(
    "QuickTime_sp2_macroman.mov",
    "QuickTime_sp2_macroman.mov.n.json",
    false,
  );
}

#[test]
fn quicktime_sp2_meta_handlerclass_conformance() {
  // QuickTime SP2 — `moov/meta/hdlr` HandlerClass / ComponentType emission (a
  // verified Codex [medium]). `tests/fixtures/QuickTime_sp2_meta_handlerclass
  // .mov` is the SP2 fixture with the `moov/meta/hdlr` body offset-4
  // ComponentType changed from all-zero to `mhlr` (size-preserving). The SAME
  // `%QuickTime::Handler` table drives the `moov/meta/hdlr` and the per-`trak`
  // hdlr (QuickTime.pm:2824 + 7229/7321 → 8391-8402), so a non-zero meta
  // ComponentType emits `QuickTime:HandlerClass` (`mhlr` → "Media Handler" under
  // `-j`, raw `mhlr` under `-n`) — the RawConv drops only an all-zero value.
  // Regression for the prior code, which decoded only the meta HandlerType
  // (offset 8) and never the meta HandlerClass. Every other tag is
  // byte-identical to the base `QuickTime_sp2.mov` golden (whose meta
  // ComponentType IS all-zero ⇒ no meta HandlerClass). Goldens via the same
  // bundled `perl exiftool -j -G1 -struct -api QuickTimeUTC=1` (System/Composite
  // excluded per the Phase-2 forward item).
  check(
    "QuickTime_sp2_meta_handlerclass.mov",
    "QuickTime_sp2_meta_handlerclass.mov.json",
    true,
  );
  check(
    "QuickTime_sp2_meta_handlerclass.mov",
    "QuickTime_sp2_meta_handlerclass.mov.n.json",
    false,
  );
}

#[test]
fn quicktime_sp2_udta_camid_conformance() {
  // QuickTime SP2 camera-identity sweep — the NON-copyright-symbol `udta`
  // camera atoms plus the new copyright-symbol identity atoms.
  // `tests/fixtures/QuickTime_sp2_udta_camid.mov` is a SYNTHETIC `.mov` whose
  // `moov/udta` carries `manu`/`modl` (Canon SX280-style, each prefixed with the
  // 6 unknown bytes `00 00 00 00 15 c7` consumed by the RawConv
  // `s/^\0{4}..//s; s/\0.*//`), three competing Avoid Model atoms
  // (`modl`/`cmnm`/`CNMN`) plus a non-Avoid copyright-symbol `mod`, `slno` vs the
  // Avoid `SNum` (SerialNumber), `CNFV` vs the Avoid `FIRM` (FirmwareVersion),
  // `CNCV` (CompressorVersion), `cmid` (CameraID), the copyright-symbol `cpy`
  // (Copyright) and `date` (DateTimeOriginal, %iso8601Date). Exercises:
  //
  //   - the `manu`/`modl` Canon-prefix RawConv (Make=`Canon`, the bare value
  //     after the 6-byte strip + NUL truncation);
  //   - ExifTool's duplicate-tag PRIORITY rule (ExifTool.pm:9468-9566): the
  //     non-Avoid copyright-symbol `mod` (`Canon EOS R5`) WINS over the three
  //     Avoid Model atoms; `slno` beats `SNum`; `CNFV` beats `FIRM` — i.e. a
  //     priority-1 source always overrides an `Avoid` (priority-0) one
  //     regardless of file order (verified vs bundled);
  //   - the `Format => 'string'` NUL truncation (`cmnm`/`CNMN`/`slno`/`CNCV`/
  //     `CNFV`/`cmid`);
  //   - the new copyright-symbol `cpy` Copyright + `date` DateTimeOriginal.
  //
  // Goldens via the same bundled `perl exiftool -j -G1 -struct -api
  // QuickTimeUTC=1` (System/Composite excluded per the Phase-2 forward item).
  check(
    "QuickTime_sp2_udta_camid.mov",
    "QuickTime_sp2_udta_camid.mov.json",
    true,
  );
  check(
    "QuickTime_sp2_udta_camid.mov",
    "QuickTime_sp2_udta_camid.mov.n.json",
    false,
  );
}

#[test]
fn quicktime_sp2_android_conformance() {
  // QuickTime SP2 camera-identity sweep — the `com.android.*` Keys full-key
  // FALLBACK (a verified Codex [medium]). `tests/fixtures/QuickTime_sp2_android
  // .mov` is a SYNTHETIC `.mov` whose `moov/meta` keys box holds
  // `com.android.version` / `com.android.manufacturer` / `com.android.model`
  // (plus a `moov/udta` copyright-symbol `mak`). These keys are NOT in the
  // `com.apple.quicktime` namespace, so `ProcessKeys` (QuickTime.pm:9803) strips
  // only the bare `com.` prefix to `android.manufacturer` (which is not a table
  // id), then the `for(;;)` loop (9807-9824) FALLS BACK to the FULL key
  // `com.android.manufacturer` — which resolves to `Keys:AndroidMake`. So the
  // bundled output is `Keys:AndroidVersion=13` / `Keys:AndroidMake=Google` /
  // `Keys:AndroidModel=Pixel 8 Pro` (plus `UserData:Make=motorola`). Regression
  // for the prior code, which kept only the stripped key and DROPPED every
  // `com.android.*` tag. Goldens via the same bundled `perl exiftool -j -G1
  // -struct -api QuickTimeUTC=1` (System/Composite excluded per the Phase-2
  // forward item).
  check(
    "QuickTime_sp2_android.mov",
    "QuickTime_sp2_android.mov.json",
    true,
  );
  check(
    "QuickTime_sp2_android.mov",
    "QuickTime_sp2_android.mov.n.json",
    false,
  );
}

#[test]
fn quicktime_sp2_gopro_conformance() {
  // QuickTime SP2 Part-2 — the conv-less `%QuickTime::UserData` camera atoms
  // (the xtask `--kind quicktime` generated `4cc → Name` map) PLUS the two
  // code-valued atoms hand-ported in the walker. `tests/fixtures/
  // QuickTime_sp2_gopro.mov` is a SYNTHETIC `.mov` whose `moov/udta` carries:
  //   - international-text (©-prefixed) atoms `©mal` MakerURL / `©gpt`
  //     CameraPitch / `©gyw` CameraYaw / `©grl` CameraRoll (QuickTime.pm:1639,
  //     2148-2150 — bare `'Name'`, conv-less);
  //   - plain-string atoms `GoPr` GoProType / `LENS` LensSerialNumber / `FOV\0`
  //     FieldOfView (QuickTime.pm:2117/2119/2131 — bare `'Name'`, conv-less);
  //   - code-valued `CAME` SerialNumberHash / `MUID` MediaUID
  //     (QuickTime.pm:2120-2127 — `ValueConv => 'unpack("H*",$val)'`), whose
  //     raw bytes `00 11 de ad be ef` / `ca fe f0 0d 12 34` HASH to the
  //     lower-case hex `0011deadbeef` / `cafef00d1234`.
  // The conv-less atoms emit verbatim under `QuickTime:UserData`; the numeric-
  // looking `©gpt`/`©gyw`/`©grl` strings (`12.5` / `-3.0` / `0.0`) render as
  // JSON NUMBERS via the token-exact JSON typing (Contract B), exactly as
  // ExifTool's `-j` numifies them. Goldens via the bundled `perl exiftool -j
  // -G1 -struct -api QuickTimeUTC=1` (System/Composite excluded per the
  // Phase-2 forward item).
  check(
    "QuickTime_sp2_gopro.mov",
    "QuickTime_sp2_gopro.mov.json",
    true,
  );
  check(
    "QuickTime_sp2_gopro.mov",
    "QuickTime_sp2_gopro.mov.n.json",
    false,
  );
}

#[test]
fn quicktime_sp2_keys_direction_conformance() {
  // QuickTime SP2 Part-2 — the conv-less `%QuickTime::Keys` atoms (generated
  // `key → Name` map) PLUS the two code-valued Keys atoms hand-ported in the
  // walker. `tests/fixtures/QuickTime_sp2_keys_direction.mov` is a SYNTHETIC
  // `.mov` whose `moov/meta` keys box holds:
  //   - `com.apple.quicktime.direction.facing` CameraDirection /
  //     `…direction.motion` CameraMotion (QuickTime.pm:6735-6736 — bare `Name`
  //     + a family-2-only `Groups => { 2 => 'Location' }`, conv-less), each a
  //     plain UTF-8 `data` value (`front` / `walking`);
  //   - `com.android.capture.fps` AndroidCaptureFPS (QuickTime.pm:6763,
  //     `Writable => 'float'`), a `data` atom with the float flag `0x17` and
  //     the IEEE big-endian `f32` `29.97` — decoded numerically (the f32→f64
  //     widening renders `%.15g` as `29.9699993133545` in BOTH modes);
  //   - `samsung.android.utc_offset` AndroidTimeZone (QuickTime.pm:6769), a
  //     full-key-fallback plain string (`+09:00`).
  // Exercises the float `data`-atom decode (`QuickTimeFormat` flag path) and
  // the generated conv-less Keys map. Goldens via the bundled `perl exiftool -j
  // -G1 -struct -api QuickTimeUTC=1` (System/Composite excluded).
  check(
    "QuickTime_sp2_keys_direction.mov",
    "QuickTime_sp2_keys_direction.mov.json",
    true,
  );
  check(
    "QuickTime_sp2_keys_direction.mov",
    "QuickTime_sp2_keys_direction.mov.n.json",
    false,
  );
}

#[test]
fn quicktime_sp2_ilst_binary_conformance() {
  // QuickTime SP2 — the conv-less Keys `data`-atom BINARY branch
  // (QuickTime.pm:10411-10414 `elsif (not $$tagInfo{ValueConv}) { $value =
  // \$buf }`). `tests/fixtures/QuickTime_sp2_ilst_binary.mov` (crafted by
  // `tools/gen_quicktime_sp2_decode_fixtures.py`) holds a `moov/meta` keys box
  // with `com.apple.quicktime.direction.facing` (CameraDirection — conv-less +
  // Format-less in `%QuickTime::Keys`) whose `data` atom carries the BINARY flag
  // `0x00` with a 3-byte value. `QuickTimeFormat(0x00, 3)` returns undef (only
  // len 1/2 map to int8u/int16u), so with no ValueConv the value becomes a
  // binary scalar ref ⇒ `Keys:CameraDirection` renders the universal
  // `(Binary data 3 bytes, use -b option to extract)` placeholder in BOTH modes.
  // Verified vs bundled 13.59. Goldens via the bundled `perl exiftool -j -G1
  // -struct -api QuickTimeUTC=1` (System/Composite excluded).
  check(
    "QuickTime_sp2_ilst_binary.mov",
    "QuickTime_sp2_ilst_binary.mov.json",
    true,
  );
  check(
    "QuickTime_sp2_ilst_binary.mov",
    "QuickTime_sp2_ilst_binary.mov.n.json",
    false,
  );
}

#[test]
fn quicktime_sp2_ilst_numeric_conformance() {
  // QuickTime SP2 — the conv-less Keys `data`-atom NUMERIC branch
  // (QuickTime.pm:10402-10409 `$format = QuickTimeFormat($flags,$len); ... $value
  // = ReadValue(...)`). `tests/fixtures/QuickTime_sp2_ilst_numeric.mov` holds
  // `com.apple.quicktime.direction.facing` (CameraDirection) whose `data` atom
  // carries the unsigned-int flag `0x16` with a 2-byte value `0x012c`.
  // `QuickTimeFormat(0x16, 2)` ⇒ `int16u` ⇒ `ReadValue` ⇒ the NUMBER 300, with
  // no PrintConv/ValueConv ⇒ `Keys:CameraDirection` = the bare JSON number `300`
  // in BOTH modes. Verified vs bundled 13.59. Goldens via the bundled `perl
  // exiftool -j -G1 -struct -api QuickTimeUTC=1` (System/Composite excluded).
  check(
    "QuickTime_sp2_ilst_numeric.mov",
    "QuickTime_sp2_ilst_numeric.mov.json",
    true,
  );
  check(
    "QuickTime_sp2_ilst_numeric.mov",
    "QuickTime_sp2_ilst_numeric.mov.n.json",
    false,
  );
}

#[test]
fn quicktime_sp2_itext_empty_first_conformance() {
  // QuickTime SP2 — the international-text empty-entry CONTINUATION
  // (QuickTime.pm:10483 `next if not $len and $pos`). `tests/fixtures/
  // QuickTime_sp2_itext_empty_first.mov` holds a `moov/udta` `©nam` (Title)
  // whose FIRST international-text entry is empty (len 0) FOLLOWED BY a valid
  // entry (len 2, lang 0, `Hi`). ExifTool's entry loop advances past the empty
  // header then `next`s (it does NOT bail), so the later entry is decoded ⇒
  // `UserData:Title` = `Hi` in BOTH modes. Regression for the prior code that
  // bailed on an empty first entry. Verified vs bundled 13.59. Goldens via the
  // bundled `perl exiftool -j -G1 -struct -api QuickTimeUTC=1` (System/Composite
  // excluded).
  check(
    "QuickTime_sp2_itext_empty_first.mov",
    "QuickTime_sp2_itext_empty_first.mov.json",
    true,
  );
  check(
    "QuickTime_sp2_itext_empty_first.mov",
    "QuickTime_sp2_itext_empty_first.mov.n.json",
    false,
  );
}

#[test]
fn quicktime_sp2_itext_empty_only_conformance() {
  // QuickTime SP2 — an international-text atom whose ONLY entry is empty emits
  // NO tag. `tests/fixtures/QuickTime_sp2_itext_empty_only.mov` holds a `©nam`
  // (Title) with a single empty (len 0) entry; the loop skips it
  // (QuickTime.pm:10483) and the next 4-byte-header read overruns, so the loop
  // ends with NO `FoundTag` ⇒ the golden has no `UserData:Title` (and no `udta`
  // tag at all). Verified vs bundled 13.59. Goldens via the bundled `perl
  // exiftool -j -G1 -struct -api QuickTimeUTC=1` (System/Composite excluded).
  check(
    "QuickTime_sp2_itext_empty_only.mov",
    "QuickTime_sp2_itext_empty_only.mov.json",
    true,
  );
  check(
    "QuickTime_sp2_itext_empty_only.mov",
    "QuickTime_sp2_itext_empty_only.mov.n.json",
    false,
  );
}

#[test]
fn mxf_conformance() {
  // FORMATS.md row 24 (Engine-only). `tests/fixtures/MXF.mxf` is the
  // bundled `lib/Image/ExifTool/t/images/MXF.mxf` (7510 bytes — header
  // partition pack + Primer + Preface/Identification/Material+Source
  // Package/Track/SequenceSet/TimecodeComponent/WaveAudioDescriptor local
  // sets + footer). Exercises the KLV walker, BER length decoder, Primer
  // local-id→UL map, local-set walker, the MXF-specific value decoders
  // (UTF-16BE, Timestamp, VersionType, ProductVersion, GUID, PackageID,
  // rational64s, Boolean, Length+%duration), `Track<N>` family-1 group
  // attribution via the object-tree walk, EditRate-based duration
  // conversion, the synthesized best `MXF:Duration`, and the reverse-order
  // duplicate removal. Goldens are bundled `perl exiftool -j -G1:1
  // -api struct=1` output with `System:*` stripped (the engine emits no
  // `System:*`); the bundled MXF output has NO `Composite:*` rows, so the
  // goldens are otherwise UNTRIMMED.
  check("MXF.mxf", "MXF.mxf.json", true);
  check("MXF.mxf", "MXF.mxf.n.json", false);
}

#[test]
fn mxf_bad_array_conformance() {
  // Golden-v2 Phase B.1.5 — the `Bad array or batch size` warning
  // (MXF.pm:2525-2528). An `(Array|Batch)` value with `len > 16` whose
  // header `(count, size)` fails `$len == 8 + $count * $size` raises
  // `$et->Warn("Bad array or batch size")` while `$$et{SET_GROUP1} = 'MXF'`
  // (MXF.pm:2838) ⇒ the group-scoped `MXF:Warning` TAG. The entry read loop
  // is independent of the size check, so the warning is the ONLY output delta.
  //
  // Crafted fixture: the bundled `MXF.mxf` with the Preface `Identifications`
  // StrongReferenceBatch (local tag 0x3b06) `count` bumped 1→2 (so `8 + 2*16
  // = 40 != 24`); the loop still reads the 1 present GUID then `last`s
  // (MXF.pm:2532), so the tree walk / every other tag is byte-identical.
  // Goldens are `tools/gen_golden.sh` 13.59 output (version stamp normalized
  // to 13.58) — `diff` vs `MXF.mxf.json` is exactly the one added
  // `MXF:Warning` line.
  check("MXF_bad_array.mxf", "MXF_bad_array.mxf.json", true);
  check("MXF_bad_array.mxf", "MXF_bad_array.mxf.n.json", false);
}

#[test]
fn mxf_multidescriptor_conformance() {
  // Codex R1/F1 regression: a multi-essence MXF whose audio descriptors are
  // reachable from the `Preface` root ONLY through the HIDDEN structural
  // edges `SourcePackage.EssenceDescription (StrongReference) ->
  // MultipleDescriptor.FileDescriptors (StrongReferenceArray) ->
  // [WaveAudioDescriptor, WaveAudioDescriptor]`, and whose SourcePackage
  // tracks hang off `PackageTracks` (StrongReferenceArray) rather than
  // `Tracks`. Neither `FileDescriptors`, `MultipleDescriptor.SampleRate`'s
  // owning set, nor `PackageTracks` are ever EMITTED (all `Unknown => 1`),
  // but ExifTool decodes them into `@strongRef` (MXF.pm:2638) so `SetGroups`
  // (MXF.pm:2770) walks the descriptor subtree and re-stamps the descriptor
  // tags with the linked `Track<N>` group (`Track3`/`Track4` here, via each
  // descriptor's `LinkedTrackID`). Before the fix the descriptor ULs were
  // dropped at the tag-table lookup, so `set_groups` never visited the
  // descriptors and their tags stayed under `MXF` with un-converted
  // durations. Goldens are the bundled oracle (`tools/gen_golden.sh`).
  check(
    "MXF_MultiDescriptor.mxf",
    "MXF_MultiDescriptor.mxf.json",
    true,
  );
  check(
    "MXF_MultiDescriptor.mxf",
    "MXF_MultiDescriptor.mxf.n.json",
    false,
  );
}

#[test]
fn m2ts_conformance() {
  // FORMATS.md row 25 (M2TS / AVCHD camcorder container).
  // `tests/fixtures/M2TS.mts` is the bundled `lib/Image/ExifTool/t/images/
  // M2TS.mts` (1344 bytes — a Canon AVCHD camcorder file: PAT @ PID 0x0
  // → PMT @ PID 0x0100 → H.264 video @ PID 0x1011 + AC-3 audio @ PID
  // 0x1100 with 192-byte BDAV-prefixed packets). Exercises:
  //
  // - 192-byte (BDAV) vs 188-byte (raw) packet stride detection
  //   (M2TS.pm:594-615);
  // - PAT (table id 0) → PMT (table id 2) walker (M2TS.pm:817-894);
  // - AC-3 stream-descriptor decode in the PMT ES-loop (M2TS.pm:887-890
  //   `ParseAC3Descriptor`) ⇒ `AC3:AudioBitrate` / `SurroundMode` /
  //   `AudioChannels`;
  // - AC-3 PES payload sample-rate scan (M2TS.pm:253-261 `ParseAC3Audio`)
  //   ⇒ `AC3:AudioSampleRate`;
  // - H.264 PES payload forward to the existing `H264::ParseH264Video`
  //   port (M2TS.pm:343-345);
  // - Final flush of partial PID streams at EOF (M2TS.pm:1009-1013);
  // - The bundled minor warning when an H.264 stream was seen and
  //   `ExtractEmbedded` is off (M2TS.pm:349-351);
  // - `SetFileType(M2TS)` for a 4-byte timecode prefix (M2TS.pm:617),
  //   driven via `FileTypeFinalize::Explicit`.
  //
  // Goldens are bundled `perl exiftool -j -G1 -struct` output with
  // `System:*` stripped (the engine emits no `System:*`) AND
  // `Composite:*` stripped (the Composite engine isn't yet ported; the
  // bundled M2TS output has `Composite:ImageSize` / `Composite:Megapixels`
  // / `Composite:ShutterSpeed` synthesized from `H264:*` — a follow-up
  // deferral).
  check("M2TS.mts", "M2TS.mts.json", true);
  check("M2TS.mts", "M2TS.mts.n.json", false);
}

#[test]
fn m2ts_h264_mdpm_multiframe_noee_conformance() {
  // #304 — a CRAFTED 192-byte (BDAV) M2TS carrying an H.264 (0x1b) PES with TWO
  // access units, each an SEI/MDPM block with DIFFERENT timed values:
  //   frame 1 — SPS (1920x1088) + MDPM DateTimeOriginal 2020 + GPS 48N/11E;
  //   frame 2 — MDPM DateTimeOriginal 2021 + GPS 49N/12E.
  //
  // This NO-`ee` golden pins the bundled `ParseH264Video` first-frame behavior
  // (H264.pm:1079-1082): without `-ee` the `GotNAL06` latch suppresses every
  // SEI after the first, so ONLY frame 1's MDPM (DateTimeOriginal + GPS) is
  // extracted, plus the `[minor] ExtractEmbedded` hint (M2TS.pm:349-351). The
  // per-frame `-ee` `Doc<N>` extraction is pinned in
  // `tests/timed_metadata_conformance.rs::m2ts_h264_mdpm_ee_byte_exact`.
  //
  // Goldens are bundled `perl exiftool -j -G1 -struct` with `System:*` +
  // `Composite:*` stripped. Bundled synthesizes `Composite:GPSLatitude`/
  // `Longitude`/`Position` from the H.264/GPS values, but the M2TS GPS is TIMED
  // (per-PES sub-document) — its faithful Composites are the SubDoc / `Doc<N>`
  // axis #133 PR 5 adds, so exifast DEFERS them here (`AnyMeta::M2ts` ⇒
  // `defers_composites`); the GPS stills got their Composites in #133 PR 2.
  check("M2TS_h264_mdpm.mts", "M2TS_h264_mdpm.mts.json", true);
  check("M2TS_h264_mdpm.mts", "M2TS_h264_mdpm.mts.n.json", false);
}

#[test]
fn quicktime_nested_size0_conformance() {
  // PR #38 Codex R1/F5: a SYNTHETIC `.mov` whose `moov` contains a size-0
  // `free` atom (a CONTAINED zero-size = terminator, QuickTime.pm:10036-
  // 10043) BEFORE a `trak`. Bundled ExifTool stops the contained walk at the
  // terminator, so the trailing `trak` is DROPPED (no `Track1:*` tags). A
  // top-level size-0 still extends to EOF (the `mdat`-size path). Pins the
  // top-level-vs-contained size-0 distinction.
  check(
    "QuickTime_nested_size0.mov",
    "QuickTime_nested_size0.mov.json",
    true,
  );
  check(
    "QuickTime_nested_size0.mov",
    "QuickTime_nested_size0.mov.n.json",
    false,
  );
}

#[test]
fn quicktime_zerodate_conformance() {
  // PR #38 Codex R2/F1: a SYNTHETIC `.mov` whose mvhd/tkhd/mdhd carry RAW-ZERO
  // CreateDate/ModifyDate/Track*Date/Media*Date. The timeInfo RawConv only
  // `undef`s a zero date under `StrictDate` (QuickTime.pm:265, unimplemented +
  // off in the gen-golden config); otherwise the ValueConv
  // `ConvertUnixTime(0, …)` emits the zero sentinel "0000:00:00 00:00:00"
  // (ExifTool.pm:6776). Verified vs bundled — the zero dates are EMITTED, not
  // dropped. Without the fix the typed layer silently omitted them.
  check(
    "QuickTime_zerodate.mov",
    "QuickTime_zerodate.mov.json",
    true,
  );
  check(
    "QuickTime_zerodate.mov",
    "QuickTime_zerodate.mov.n.json",
    false,
  );
}

#[test]
fn quicktime_m4a_conformance() {
  // PR #38 Codex R2/F2: a SYNTHETIC `.mov` with an `M4A ` major brand. The
  // QuickTime parser derives `File:FileType=M4A` AND `File:MIMEType=audio/mp4`
  // from `ftyp` (QuickTime.pm:10008 `SetFileType($ft, $mimeLookup{$ft})`).
  // M4A is ABSENT from the generic `%mimeType` table, so the engine must carry
  // the parser-supplied MIME through finalization. Verified vs bundled —
  // MIMEType=audio/mp4 (not the base MOV `video/quicktime`).
  check("QuickTime_m4a.mov", "QuickTime_m4a.mov.json", true);
  check("QuickTime_m4a.mov", "QuickTime_m4a.mov.n.json", false);
}

#[test]
fn quicktime_m4a_isom_override_conformance() {
  // PR #38 Codex R10/F1: a SYNTHETIC `.mov` with an `isom` MAJOR brand whose
  // brands resolve to MP4, plus a single `soun`-handler track and NO `vide`
  // handler. ExifTool runs a post-walk override (QuickTime.pm:10619-10624):
  // when the resolved type is MP4 AND `save_ftyp` (the major brand) matches
  // `^(iso|dash|mp42)` AND a `soun` handler exists AND no `vide` handler
  // exists, `OverrideFileType('M4A','audio/mp4')` flips the type. So this
  // audio-only `.m4a` is `File:FileType=M4A` / `File:FileTypeExtension=m4a` /
  // `File:MIMEType=audio/mp4`, while `QuickTime:MajorBrand` keeps the `isom`
  // PrintConv ("MP4 Base Media v1 …"). Verified vs bundled ExifTool 13.58 —
  // this is the ubiquitous real-world M4A audio-file fidelity case.
  check(
    "QuickTime_m4a_isom_override.mov",
    "QuickTime_m4a_isom_override.mov.json",
    true,
  );
  check(
    "QuickTime_m4a_isom_override.mov",
    "QuickTime_m4a_isom_override.mov.n.json",
    false,
  );
}

#[test]
fn quicktime_useext_glv_conformance() {
  // PR #38 Codex R11/F1: the `%useExt` rule (QuickTime.pm:240
  // `%useExt = ( GLV => 'MP4' )`, applied at QuickTime.pm:10006-10007). This
  // fixture is the BYTE-IDENTICAL twin of `QuickTime_m4a_isom_override.mov`
  // (same `isom` major brand, audio-only `soun` track, MP4-resolving brands)
  // but named with a `.glv` extension. ExifTool's `%useExt` rule promotes the
  // ftyp-derived `MP4` to `GLV` BEFORE `SetFileType` — and because that runs
  // before the post-walk MP4→M4A override (gated on `$$et{FileType} eq 'MP4'`,
  // QuickTime.pm:10619), the audio-only override no longer fires. So the same
  // bytes that yield `File:FileType=M4A` as `.mov` yield `File:FileType=GLV` /
  // `File:FileTypeExtension=glv` (raw `GLV`) / `File:MIMEType=video/mp4` as
  // `.glv` (`%mimeLookup` has no `GLV` entry ⇒ the `'video/mp4'` fallback).
  // Verified vs bundled ExifTool 13.58 — the canonical Garmin Low-resolution
  // Video real-world fidelity case. Exercises the engine's `ext` channel
  // (`extract_info` derives `$$et{FILE_EXT}` from the `.glv` fixture name).
  check(
    "QuickTime_useext_glv.glv",
    "QuickTime_useext_glv.glv.json",
    true,
  );
  check(
    "QuickTime_useext_glv.glv",
    "QuickTime_useext_glv.glv.n.json",
    false,
  );
}

#[test]
fn quicktime_m4v_conformance() {
  // PR #38 Codex R2/F2: a SYNTHETIC `.mov` with an `M4V ` major brand ⇒
  // `File:FileType=M4V`, `File:MIMEType=video/x-m4v` (QuickTime.pm:10008 +
  // %mimeLookup). M4V is absent from the generic `%mimeType` table; the
  // ftyp-derived MIME is carried through finalization (verified vs bundled).
  check("QuickTime_m4v.mov", "QuickTime_m4v.mov.json", true);
  check("QuickTime_m4v.mov", "QuickTime_m4v.mov.n.json", false);
}

#[test]
fn quicktime_zerotimescale_conformance() {
  // PR #38 Codex R2/F3: a SYNTHETIC `.mov` with movie TimeScale=0 and
  // Duration=1200. The durationInfo PrintConv gates on TimeScale TRUTHINESS
  // (`$$self{TimeScale} ? ConvertDuration($val) : $val`, QuickTime.pm:315) —
  // a zero TimeScale is falsy, so Duration emits the BARE raw value 1200 (not
  // a ConvertDuration string). Likewise the Preview/Poster/etc. movie-scale
  // durations emit their raw 0. Verified vs bundled.
  check(
    "QuickTime_zerotimescale.mov",
    "QuickTime_zerotimescale.mov.json",
    true,
  );
  check(
    "QuickTime_zerotimescale.mov",
    "QuickTime_zerotimescale.mov.n.json",
    false,
  );
}

#[test]
fn quicktime_maclang_conformance() {
  // PR #38 Codex R2/F4: a SYNTHETIC `.mov` whose mdhd MediaLanguageCode is a
  // MACINTOSH numeric code (12, < 0x400). The ValueConv keeps the bare number
  // (QuickTime.pm:7280); the PrintConv maps numeric values through
  // `$ttLang{Macintosh}` (Font.pm:92-117) ⇒ 12 → "ar", with an
  // `Unknown ($val)` fallback (QuickTime.pm:7281-7285). Verified vs bundled —
  // `-j` "ar", `-n` raw 12. Without the fix `-j` leaked the raw number.
  check("QuickTime_maclang.mov", "QuickTime_maclang.mov.json", true);
  check(
    "QuickTime_maclang.mov",
    "QuickTime_maclang.mov.n.json",
    false,
  );
}

#[test]
fn quicktime_matrixfrac_conformance() {
  // PR #38 Codex R3/F1: a SYNTHETIC `.mov` whose mvhd MatrixStructure carries
  // raw 1 in the a/d/w slots. The `Format => 'fixed32s[9]'` reads each entry
  // through GetFixed32s (ExifTool.pm:6121-6127) which divides by 0x10000 then
  // ROUNDS to 5 decimal places: 1/65536 = 1.52587890625e-05 → 2e-05. The
  // ValueConv then applies `$_ /= 0x4000` to the right column (entry 8: that
  // rounded 2e-05 / 0x4000 = 1.220703125e-09). Perl interpolates each into
  // `"@a"` via `%.15g`. Verified vs bundled —
  // `MatrixStructure: "2e-05 0 0 0 2e-05 0 0 0 1.220703125e-09"`. Without the
  // GetFixed32s rounding + `%.15g` formatting, the port emitted the full Rust
  // float `0.0000152587890625 …`.
  check(
    "QuickTime_matrixfrac.mov",
    "QuickTime_matrixfrac.mov.json",
    true,
  );
  check(
    "QuickTime_matrixfrac.mov",
    "QuickTime_matrixfrac.mov.n.json",
    false,
  );
}

#[test]
fn quicktime_multimoov_conformance() {
  // PR #38 Codex R3/F2: a SYNTHETIC `.mov` with TWO top-level `moov` atoms.
  // The first carries the track (tkhd Duration=1200) under mvhd TimeScale=600;
  // a SECOND top-level moov overwrites the GLOBAL movie TimeScale to 300. The
  // `mvhd` TimeScale RawConv (`$$self{TimeScale} = $val`, QuickTime.pm:1384)
  // is a single global slot, last-wins; the TrackDuration durationInfo
  // ValueConv runs at OUTPUT against that FINAL value ⇒ 1200/300 = 4. Verified
  // vs bundled — `Track1:TrackDuration = 4`. Without learning every mvhd's
  // TimeScale BEFORE converting any TrackDuration the port emitted 1200/600 =
  // 2.
  check(
    "QuickTime_multimoov.mov",
    "QuickTime_multimoov.mov.json",
    true,
  );
  check(
    "QuickTime_multimoov.mov",
    "QuickTime_multimoov.mov.n.json",
    false,
  );
}

#[test]
fn quicktime_size0_moov_conformance() {
  // PR #38 Codex R4/F1: a SYNTHETIC `.mov` = ftyp + a TOP-LEVEL size-0 `moov`
  // containing a real `mvhd`. For a top-level size-0 atom ExifTool prints
  // "extends to end of file", records the synthetic `$tag-size`/`$tag-offset`
  // tags ONLY if they exist (just `mdat`), then `last` — STOPS the walk WITHOUT
  // processing the payload (QuickTime.pm:10044-10056). So the size-0 `moov`'s
  // `mvhd` is NEVER decoded; verified vs bundled — ONLY the ftyp tags survive
  // (no CreateDate/TimeScale/Duration/tracks). Previously the size-0 atom was
  // treated as a normal extends-to-EOF Atom and the `mvhd` payload was decoded.
  check(
    "QuickTime_size0_moov.mov",
    "QuickTime_size0_moov.mov.json",
    true,
  );
  check(
    "QuickTime_size0_moov.mov",
    "QuickTime_size0_moov.mov.n.json",
    false,
  );
}

#[test]
fn quicktime_multimoov_tracks_conformance() {
  // PR #38 Codex R4/F2: a SYNTHETIC `.mov` with TWO top-level `moov` atoms,
  // each holding ONE (byte-identical) `trak`. ExifTool's `$track` counter is a
  // `my` local of EACH moov's `ProcessMOV` invocation (QuickTime.pm:9944),
  // `++`-incremented per `trak` (QuickTime.pm:10354) — so it RESETS to 1 per
  // moov and BOTH traks become `Track1` (NOT `Track1` + `Track2`). In default
  // JSON the second `Track1` collapses on the family-1 collision; verified vs
  // bundled — a single `Track1` group, NO `Track2`. Previously the tracks were
  // flattened into one Vec and numbered with a GLOBAL `enumerate()+1`, wrongly
  // yielding `Track1` + `Track2`.
  check(
    "QuickTime_multimoov_tracks.mov",
    "QuickTime_multimoov_tracks.mov.json",
    true,
  );
  check(
    "QuickTime_multimoov_tracks.mov",
    "QuickTime_multimoov_tracks.mov.n.json",
    false,
  );
}

#[test]
fn quicktime_multimoov_tracksdistinct_conformance() {
  // PR #38 Codex R5/F1: a SYNTHETIC `.mov` with TWO top-level `moov` atoms,
  // BOTH numbering their lone `trak` as `Track1`, but carrying DISTINCT tags:
  // moov1's `Track1` comes from a bare `tkhd` (TrackID=7, TrackDuration,
  // TrackLayer/Volume, MatrixStructure, ImageWidth/Height, …) while moov2's
  // `Track1` comes from a bare `mdia`(`mdhd`/`hdlr`) (MediaTimeScale=90000,
  // MediaDuration, MediaLanguageCode, HandlerType, …). ExifTool's `%noDups`
  // first-wins collision is per rendered tag KEY (`(family-1 group, tag name)`),
  // NOT per group: verified vs bundled — the single `Track1` group carries BOTH
  // moov1's TrackID and moov2's MediaTimeScale/MediaDuration/HandlerType. The
  // R4/F2 serializer wrongly `continue`d the ENTIRE later same-group track,
  // dropping every Media* tag. (TrackDuration = 1200/300 = 4 — the FINAL global
  // TimeScale=300 from moov2's mvhd, last-wins, R3/F2.)
  check(
    "QuickTime_multimoov_tracksdistinct.mov",
    "QuickTime_multimoov_tracksdistinct.mov.json",
    true,
  );
  check(
    "QuickTime_multimoov_tracksdistinct.mov",
    "QuickTime_multimoov_tracksdistinct.mov.n.json",
    false,
  );
}

#[test]
fn quicktime_size0_mdat_first_conformance() {
  // PR #38 Codex R5/F2: a SYNTHETIC `.mov` whose VERY FIRST top-level atom is
  // `size == 0, type = mdat` (extends to EOF). ExifTool's first-atom recognition
  // gate (QuickTime.pm:9984 `$$tagTablePtr{$tag} or return 0`) keys on the
  // 4-byte `$tag` REGARDLESS of size, so `mdat` is recognized → FileType MOV;
  // the per-atom loop then treats the size-0 `mdat` as extends-to-EOF, records
  // the synthetic `mdat-size`/`mdat-offset` (QuickTime.pm:10044-10056), and
  // `last`. Verified vs bundled — FileType MOV + MediaDataSize=32 (40-byte file,
  // 8-byte header) + MediaDataOffset=8, nothing else. The port previously
  // rejected the file at the first-atom gate (which accepted only
  // `HeaderOutcome::Atom`, not a top-level size-0 `ExtendsToEof`) and returned
  // `Ok(None)`, losing the QuickTime result entirely.
  check(
    "QuickTime_size0_mdat_first.mov",
    "QuickTime_size0_mdat_first.mov.json",
    true,
  );
  check(
    "QuickTime_size0_mdat_first.mov",
    "QuickTime_size0_mdat_first.mov.n.json",
    false,
  );
}

#[test]
fn quicktime_multimoov_movdur_conformance() {
  // PR #38 Codex R6/F1: a SYNTHETIC `.mov` with TWO top-level `moov` atoms.
  // moov1's `mvhd` has TimeScale=600 + Duration=3000; moov2's `mvhd` is a
  // SHORT 16-byte header carrying only version/create/modify/TimeScale=300 —
  // NO Duration field. The movie `Duration` is a `%durationInfo` tag whose
  // ValueConv `$val / $$self{TimeScale}` runs at OUTPUT against the FINAL
  // global movie TimeScale (last-wins, 300) — and an absent Duration in the
  // later short `mvhd` must NOT erase moov1's found count. Verified vs
  // bundled: `QuickTime:Duration = "10.00 s"` (3000 / 300), with
  // MovieHeaderVersion/CreateDate/ModifyDate/TimeScale from moov2 (last-wins
  // for the fields it DOES carry). The port previously converted Duration at
  // `mvhd` decode against the SAME mvhd's TimeScale and let the short moov2
  // overwrite the field with `None`.
  check(
    "QuickTime_multimoov_movdur.mov",
    "QuickTime_multimoov_movdur.mov.json",
    true,
  );
  check(
    "QuickTime_multimoov_movdur.mov",
    "QuickTime_multimoov_movdur.mov.n.json",
    false,
  );
}

#[test]
fn quicktime_multimoov_gpmf_conformance() {
  // GoPro Codex R7/F1: a SYNTHETIC `.mov` with TWO top-level `moov` atoms where
  // ONLY the LATER `moov` carries `udta/GPMF` (a GoPro DEVC container holding
  // DVNM/FMWR/CASN). ExifTool's `for(;;)` atom-list walk (QuickTime.pm:10032)
  // descends EVERY top-level `moov` (Movie SubDirectory, QuickTime.pm:678-681)
  // and EVERY `udta` (QuickTime.pm:1214-1217), dispatching EVERY `GPMF` to
  // `GoPro::ProcessGoPro` (QuickTime.pm:2132-2135) and accumulating tags — so
  // the GPMF in the second `moov` IS extracted. Verified vs bundled ExifTool
  // 13.59: `GoPro:DeviceName = "Hero8 Black"`,
  // `GoPro:FirmwareVersion = "HD8.01.02.51.00"`,
  // `GoPro:CameraSerialNumber = "C3221324545448"` (plus the moov1 track/movie
  // tags). The port's static GPMF discovery previously inspected ONLY the FIRST
  // top-level `moov` (`find_top_level_box(data, "moov")` → first match), so a
  // first-`moov`-without-GPMF / later-`moov`-with-GPMF file dropped EVERY GoPro
  // tag; `for_each_moov_gpmf` now visits every `moov`/`udta`/`GPMF` in order.
  check(
    "QuickTime_multimoov_gpmf.mov",
    "QuickTime_multimoov_gpmf.mov.json",
    true,
  );
  check(
    "QuickTime_multimoov_gpmf.mov",
    "QuickTime_multimoov_gpmf.mov.n.json",
    false,
  );
}

#[test]
fn quicktime_gopro_gpmf_conformance() {
  // GoPro Codex R12-A: the FULL default-visible `%GoPro::GPMF` tag set. A
  // SYNTHETIC `.mov` whose `moov/udta/GPMF` (QuickTime.pm:2132-2135 →
  // `GoPro::ProcessGoPro`, processed WITHOUT `-ee` since it is a moov atom)
  // carries a DEVC exercising a broad slice of the ~95 newly-emitted tags
  // across every conv family:
  //   - identity (typed): DVNM/FMWR/CASN;
  //   - hash PrintConv: Protune (Y→On), AutoRotation (U→Up), DigitalZoomOn
  //     (N→No, %noYes), FieldOfView (W→Wide);
  //   - regex/suffix PrintConv: MetadataVersion (7.1.2), CameraTemperature
  //     ("42.5 C"), TimeZone (+01:00), VideoFrameRate (30000/1001),
  //     VideoFrameSize (1920x1080);
  //   - plain string/numeric: WhiteBalance/ExposureType/ExposureCompensation,
  //     ChapterNumber, AccelerometerMatrix, ISOSpeeds, Magnetometer (scaled);
  //   - ValueConv-folded: CreationDate (ConvertUnixTime);
  //   - `Binary => 1`: Accelerometer/Gyroscope/CameraOrientation +
  //     ExposureTimes (`PrintExposureTime` per element) — the placeholder N =
  //     byte length of the post-`ScaleValues` value string (exiftool:3987).
  // Goldens are the bundled `perl exiftool 13.59 -j -G1 -struct
  // -api QuickTimeUTC=1` output (`tools/gen_golden.sh`, `-x System/Composite`),
  // so the `-j` (PrintConv) and `-n` (ValueConv) renderings are oracle-pinned.
  check(
    "QuickTime_gopro_gpmf.mov",
    "QuickTime_gopro_gpmf.mov.json",
    true,
  );
  check(
    "QuickTime_gopro_gpmf.mov",
    "QuickTime_gopro_gpmf.mov.n.json",
    false,
  );
}

#[test]
fn quicktime_gopro_gpmf_mp4_conformance() {
  // GoPro Hero8 `.mp4` variant of `QuickTime_gopro_gpmf` (#127). UNLIKE the
  // synthetic `.mov` sibling (whose `moov/udta/GPMF` blob carries the typed
  // `%GoPro::GPMF` device tags), this is a real transcoded `.mp4` (98 kB,
  // muxed by `Lavf62.12.101`): THREE tracks (`vide`/`soun`/`tmcd`, all with a
  // `GoPro AVC/AAC` `HandlerDescription`) and a `moov/udta/LocationInformation`
  // atom (`Lat=33.12650 Lon=-117.32719`) — but NO `gpmd` GPMF timed track and
  // NO `GoPro:*` device record at all. Because there is no embedded/timed
  // metadata, the bundled oracle's default (`-j`) and `-ee` outputs are
  // byte-identical (124 tags each): the Composite `GPSLatitude`/`Longitude`
  // come from the always-extracted `LocationInformation` udta atom, NOT from a
  // `-ee`-gated gpmd stream — so there is no `-ee`-gating divergence to pin
  // (cf. #211), and only the two standard goldens are needed.
  //
  // exifast emits a clean SUBSET of the bundled tags (zero extra). The QuickTime
  // container phase-1 port (#100) decodes the `hdlr` HandlerDescription and the
  // `vide`/`soun`/other `stsd` sample-description fixed fields; phase-2 adds the
  // `stsd`-entry `colr`/`pasp`/`btrt` CHILD atoms (the `ProcessHybrid`
  // child-atom walk); phase-4 adds the `vmhd` `GraphicsMode`/`OpColor` and the
  // `tref` `TimecodeTrack`. So the retained set includes per-track
  // `HandlerDescription`, the `vide` `CompressorID`/`SourceImageWidth`/
  // `SourceImageHeight`/`XResolution`/`YResolution`/`CompressorName`/`BitDepth`,
  // the `vmhd` `GraphicsMode`/`OpColor`, the `tref` `TimecodeTrack`, the `colr`
  // `ColorProfiles`/`ColorPrimaries`/`TransferCharacteristics`/`MatrixCoefficients`/
  // `VideoFullRangeFlag` (the CICP enums), the `pasp` `PixelAspectRatio`, the
  // `btrt` `BufferSize`/`MaxBitrate`/`AverageBitrate` (`PRIORITY => 0`), the `soun`
  // `Balance`/`AudioFormat`/`AudioChannels`/`AudioBitsPerSample`/`AudioSampleRate`
  // (plus the `soun` `btrt`), and the `tmcd` `OtherFormat`. The still-deferred
  // tags, excluded via `tools/gen_golden.sh EXCLUDE` (`-x` is ExifTool TRUTH; we
  // defer the unported, never edit a value):
  //   - `System:all`/`Composite:all` — filesystem + the deferred QuickTime
  //     Composite subsystem (incl. the `LocationInformation`-derived
  //     `GPSLatitude`/`Longitude`/`Position`), matching the `.mov` goldens;
  //   - `ItemList:all` (`©too` Encoder) + `UserData:all`
  //     (`LocationInformation`) — udta atoms this port does not decode;
  //   - the movie-level `1QuickTime:HandlerType`/`HandlerVendorID` (the
  //     `udta/hdlr` `mdir`/`appl`), family-1-scoped so the per-track
  //     `Track<N>:HandlerType`/`HandlerDescription` the port DOES emit is
  //     retained;
  //   - the deferred `stts`-derived frame rates the port does NOT yet walk:
  //     the `stts` `VideoFrameRate` (Track1) and the `tmcd` `PlaybackFrameRate`
  //     (Track3) — a later QuickTime-container phase.
  // The retained set is byte-exact vs the bundled `perl exiftool 13.59 -j -G1
  // -struct -api QuickTimeUTC=1`, so the `-j`/`-n` renderings are oracle-pinned.
  check(
    "QuickTime_gopro_gpmf.mp4",
    "QuickTime_gopro_gpmf.mp4.json",
    true,
  );
  check(
    "QuickTime_gopro_gpmf.mp4",
    "QuickTime_gopro_gpmf.mp4.n.json",
    false,
  );
}

#[test]
fn quicktime_gopro_scen_conformance() {
  // GoPro Codex R13: a complex `?` record (`SCEN` SceneClassification,
  // GoPro.pm:482) whose preceding `TYPE` is `Ff` — a 4-char FourCC scene code
  // (`F`, `undef`) followed by a float probability (`f`). ExifTool's
  // ProcessGoPro (GoPro.pm:848-863) reads EACH column via `ReadValue`: the
  // `undef` `F` column returns the raw 4 bytes (a printable FourCC like `SNOW`)
  // and the float renders via `%.15g`, joined per row with a space
  // (`join ' ', @s`). The synthetic `moov/udta/GPMF` carries six rows
  // (SNOW/URBA/INDO/WATR/VEGE/BEAC, GoPro.pm:482) with exactly-representable f32
  // probabilities. The pre-R13 numeric-only decoder DROPPED these rows (the
  // leading column is non-numeric); the fix keeps the FourCC column. SCEN has
  // no PrintConv, so the `-j` and `-n` renderings are identical: a JSON ARRAY
  // (`$val = \@rows`, GoPro.pm:863) of per-row strings. Goldens are the bundled
  // `perl exiftool 13.59 -j -G1 -api QuickTimeUTC=1` output
  // (`tools/gen_golden.sh`, `-x System/Composite`).
  check(
    "QuickTime_gopro_scen.mov",
    "QuickTime_gopro_scen.mov.json",
    true,
  );
  check(
    "QuickTime_gopro_scen.mov",
    "QuickTime_gopro_scen.mov.n.json",
    false,
  );
}

#[test]
fn quicktime_gopro_hero8_gpmf_conformance() {
  // Real GoPro HERO8 Black MP4 (from GoPro's official gpmf-parser repo,
  // `samples/hero8.mp4`, 4.2 MB, 12.6 s, 848×480, firmware HD8.01.01.20.00).
  // This is the default (non-`-ee`) conformance: container-level metadata only
  // (Track1–Track5, GoPro:*, Composite:*). The gpmd track (Track4, GoPro MET)
  // carries GPMF GPS/accel data but that requires `-ee` to decode — tracked
  // separately via timed_metadata_conformance.
  //
  // ACTIVE (QuickTime container phase 7): the two `stts`-derived frame rates
  // (`Track1:VideoFrameRate` = the `CalcSampleRate` average; `Track3:
  // PlaybackFrameRate` = the `tmcd` `OtherSampleDesc` `rational64u`) were the
  // last no-`ee` residual; with those emitted the no-`ee` `.json`/`.n.json` are
  // byte-exact and this conformance is no longer `#[ignore]`d.
  // Goldens: bundled ExifTool 13.59 (`tools/gen_golden.sh`), TZ=UTC.
  check(
    "QuickTime_gopro_hero8_gpmf.mp4",
    "QuickTime_gopro_hero8_gpmf.mp4.json",
    true,
  );
  check(
    "QuickTime_gopro_hero8_gpmf.mp4",
    "QuickTime_gopro_hero8_gpmf.mp4.n.json",
    false,
  );
}

#[test]
fn quicktime_trunc_ftyp_conformance() {
  // PR #38 Codex R6/F2: a 12-byte file whose first atom is `ftyp` with a
  // DECLARED size of 100 — the header is intact but the brand payload
  // overruns EOF. ExifTool gates the format on the 4-byte `$tag` ALONE
  // (QuickTime.pm:9984), so the file IS QuickTime: `$tag eq 'ftyp' and $size
  // >= 12` runs, the short brand read fails, `$fileType` stays undef and
  // defaults to MP4 (QuickTime.pm:10004), then the `Truncated 'ftyp' data`
  // warning stops the walk. Verified vs bundled: FileType=MP4 +
  // `ExifTool:Warning = "Truncated 'ftyp' data (missing 92 bytes)"`, no
  // `QuickTime:*` tags. The port previously rejected the file outright (the
  // payload-bounds check returned `None` at the first-atom gate).
  check(
    "QuickTime_trunc_ftyp.mov",
    "QuickTime_trunc_ftyp.mov.json",
    true,
  );
  check(
    "QuickTime_trunc_ftyp.mov",
    "QuickTime_trunc_ftyp.mov.n.json",
    false,
  );
}

#[test]
fn quicktime_overrun_mdat_conformance() {
  // PR #38 Codex R6/F2: a 12-byte file whose first atom is `mdat` with a
  // DECLARED size of 100. ExifTool records the synthetic `mdat-size` /
  // `mdat-offset` from the DECLARED size BEFORE the short payload read
  // (QuickTime.pm:10156-10158); `mdat` is `Unknown` so `GetTagInfo` returns
  // undef and the seek-past `else` branch fires `Truncated 'mdat' data at
  // offset 0x0` (QuickTime.pm:10590). Verified vs bundled: FileType=MOV +
  // MediaDataSize=92 + MediaDataOffset=8 + the truncation warning. The port
  // previously rejected the file at the first-atom gate.
  check(
    "QuickTime_overrun_mdat.mov",
    "QuickTime_overrun_mdat.mov.json",
    true,
  );
  check(
    "QuickTime_overrun_mdat.mov",
    "QuickTime_overrun_mdat.mov.n.json",
    false,
  );
}

#[test]
fn quicktime_mdat64_moov_conformance() {
  // PR #38 Codex R12/F1 [REAL-INPUT]: `ftyp` + a `size == 1` 64-bit `mdat`
  // (declared total 48, FITS) + a trailing `moov`. With the DEFAULT
  // `LargeFileSupport => 1` (ExifTool.pm:1167) the walker decodes the 64-bit
  // size (`$size = $hi*4294967296 + $lo - 16`, QuickTime.pm:10074) and SKIPS
  // the `mdat` to REACH the trailing `moov` — the exact path a real >2GB video
  // takes (a 64-bit `mdat` before a trailing `moov`). Verified vs bundled
  // ExifTool 13.58: the full `mvhd` tags appear (Duration=5.00 s, TimeScale,
  // CreateDate/ModifyDate, MatrixStructure, NextTrackID), plus MediaDataSize=32
  // / MediaDataOffset=36. Before the fix the walker stopped at the `mdat` with
  // the bogus `LargeFileSupport not enabled` Malformed and lost everything in
  // the `moov`.
  check(
    "QuickTime_mdat64_moov.mov",
    "QuickTime_mdat64_moov.mov.json",
    true,
  );
  check(
    "QuickTime_mdat64_moov.mov",
    "QuickTime_mdat64_moov.mov.n.json",
    false,
  );
}

#[test]
fn quicktime_mdat64_large_conformance() {
  // PR #38 Codex R12/F1 [REAL-INPUT]: a `size == 1` 64-bit `mdat` declaring a
  // total of 0x80000010 — i.e. `lo > 0x7fffffff` (hi == 0), the real >2GB
  // shape. ExifTool's `not LargeFileSupport ⇒ 'End of processing at large
  // atom'` branch (QuickTime.pm:10067) is DEAD under the default
  // `LargeFileSupport => 1`, so the 64-bit size is PARSED: the synthetic
  // `mdat-size` is the full DECLARED payload (0x80000010 - 16 = 2147483648,
  // QuickTime.pm:10074/10156-10158), recorded BEFORE the short read; the read
  // then comes up short and the `Unknown` `mdat` fires `Truncated 'mdat' data
  // at offset 0x14` (QuickTime.pm:10590). Verified vs bundled ExifTool 13.58:
  // FileType=MOV + MediaDataSize=2147483648 + MediaDataOffset=36 + that
  // warning — NOT the `LargeFileSupport not enabled` rejection the port emitted
  // before the fix.
  check(
    "QuickTime_mdat64_large.mov",
    "QuickTime_mdat64_large.mov.json",
    true,
  );
  check(
    "QuickTime_mdat64_large.mov",
    "QuickTime_mdat64_large.mov.n.json",
    false,
  );
}

#[test]
fn quicktime_dupmdhd_conformance() {
  // PR #38 Codex R7/F1: a SYNTHETIC `.mov` whose `moov/trak/mdia` holds TWO
  // `mdhd` atoms — a FULL mdhd (TimeScale=600, Duration=1200) followed by a
  // SHORT 16-byte mdhd carrying only version/create/modify/TimeScale=300, NO
  // Duration field. `MediaDuration`/`MediaTimeScale` are per-track binary-data
  // fields; bundled ExifTool never erases an earlier FoundTag when a later
  // field is absent. Verified vs bundled: `Track1:MediaDuration = "2.00 s"`
  // (the FULL mdhd's 1200/600, NOT erased) + `Track1:MediaTimeScale = 300`
  // (the short mdhd's, last-wins for the field it DOES carry). The port
  // previously passed the short mdhd's absent Duration `None` into
  // `set_media_duration_seconds`, clearing the earlier 2.00 s.
  check("QuickTime_dupmdhd.mov", "QuickTime_dupmdhd.mov.json", true);
  check(
    "QuickTime_dupmdhd.mov",
    "QuickTime_dupmdhd.mov.n.json",
    false,
  );
}

#[test]
fn quicktime_nested_trunc_mvhd_conformance() {
  // PR #38 Codex R7/F2: a SYNTHETIC `.mov` with a truncated `mvhd` CONTAINED
  // inside `moov` — the mvhd header is intact but its declared 92-byte payload
  // overruns EOF (only 4 bytes present). `walk_atoms` must surface the same
  // `Truncated '...' data` warning the top-level loop emits. Verified vs
  // bundled: `ExifTool:Warning = "Truncated 'mvhd' data (missing 88 bytes)"`.
  // The port's `walk_atoms` previously broke silently on a contained
  // `TruncatedAtom` outcome.
  check(
    "QuickTime_nested_trunc_mvhd.mov",
    "QuickTime_nested_trunc_mvhd.mov.json",
    true,
  );
  check(
    "QuickTime_nested_trunc_mvhd.mov",
    "QuickTime_nested_trunc_mvhd.mov.n.json",
    false,
  );
}

#[test]
fn quicktime_nested_trunc_tkhd_conformance() {
  // PR #38 Codex R7/F2: a truncated `tkhd` inside `moov/trak` (declared
  // 90-byte payload, 4 bytes present). ExifTool attaches the truncation
  // warning to the CURRENT family-1 group, so it surfaces as `Track1:Warning`
  // (NOT the document-level `ExifTool:Warning`). Verified vs bundled:
  // `Track1:Warning = "Truncated 'tkhd' data (missing 86 bytes)"`.
  check(
    "QuickTime_nested_trunc_tkhd.mov",
    "QuickTime_nested_trunc_tkhd.mov.json",
    true,
  );
  check(
    "QuickTime_nested_trunc_tkhd.mov",
    "QuickTime_nested_trunc_tkhd.mov.n.json",
    false,
  );
}

#[test]
fn quicktime_nested_trunc_mdhd_conformance() {
  // PR #38 Codex R7/F2: a truncated `mdhd` nested THREE levels deep inside
  // `moov/trak/mdia` (declared 40-byte payload, 4 bytes present). The
  // recursive `walk_atoms` surfaces the warning into the enclosing track's
  // family-1 group. Verified vs bundled:
  // `Track1:Warning = "Truncated 'mdhd' data (missing 36 bytes)"`.
  check(
    "QuickTime_nested_trunc_mdhd.mov",
    "QuickTime_nested_trunc_mdhd.mov.json",
    true,
  );
  check(
    "QuickTime_nested_trunc_mdhd.mov",
    "QuickTime_nested_trunc_mdhd.mov.n.json",
    false,
  );
}

#[test]
fn quicktime_invalid_size_conformance() {
  // PR #38 Codex R8/F1: an 8-byte file `00000004 66747970` — the first atom's
  // 4-byte type `ftyp` is a recognized magic atom but its declared `size == 4`
  // is structurally invalid (`< 8`). ExifTool gates the format on the 4-byte
  // `$tag` ALONE (QuickTime.pm:9984) and `SetFileType`s ⇒ MOV BEFORE the
  // per-atom loop's `$size < 8` check sets `$warnStr = 'Invalid atom size'`
  // and `last`s (QuickTime.pm:10058). Verified vs bundled: FileType MOV +
  // `ExifTool:Warning = "Invalid atom size"`. The port previously rejected
  // the file outright — `read_atom_header` returned `None` for `size < 8` and
  // `parse_inner` turned that into `Ok(None)`, losing the QuickTime result.
  check(
    "QuickTime_invalid_size.mov",
    "QuickTime_invalid_size.mov.json",
    true,
  );
  check(
    "QuickTime_invalid_size.mov",
    "QuickTime_invalid_size.mov.n.json",
    false,
  );
}

#[test]
fn quicktime_trunc_ext_hdr_conformance() {
  // PR #38 Codex R8/F1: a 12-byte file whose first atom is `size == 1 ftyp`
  // but whose 8-byte extended-size header is truncated (only 4 of 8 bytes).
  // QuickTime.pm:10059 `$raf->Read($buff,8) == 8 or $warnStr = 'Truncated
  // atom header', last` — but the 8-byte tag/size header was already read and
  // `SetFileType` already ran. Verified vs bundled: FileType MOV +
  // `ExifTool:Warning = "Truncated atom header"`. The port previously
  // returned `Ok(None)` (the truncated-extended-header path returned `None`).
  check(
    "QuickTime_trunc_ext_hdr.mov",
    "QuickTime_trunc_ext_hdr.mov.json",
    true,
  );
  check(
    "QuickTime_trunc_ext_hdr.mov",
    "QuickTime_trunc_ext_hdr.mov.n.json",
    false,
  );
}

#[test]
fn quicktime_short_ftyp_conformance() {
  // PR #38 Codex R8/F1: an 8-byte file `00000008 66747970` — a `ftyp` first
  // atom whose RAW 32-bit `size` is `8`, i.e. `< 12`. ExifTool's file-type
  // branch `if ($tag eq 'ftyp' and $size >= 12)` FAILS (the brand path needs
  // `$size >= 12`) so it takes `else { SetFileType() }` ⇒ MOV
  // (QuickTime.pm:9986/10012). Verified vs bundled: FileType MOV. The port
  // previously defaulted a short `ftyp` to MP4 (it keyed the brand path on a
  // readable >=4-byte payload rather than the RAW 32-bit size >= 12).
  check(
    "QuickTime_short_ftyp.mov",
    "QuickTime_short_ftyp.mov.json",
    true,
  );
  check(
    "QuickTime_short_ftyp.mov",
    "QuickTime_short_ftyp.mov.n.json",
    false,
  );
}

#[test]
fn quicktime_ext_ftyp_conformance() {
  // PR #38 Codex R8/F1: a 24-byte file whose first atom is an EXTENDED-size
  // `ftyp` (`size32 == 1`, 64-bit size 24) with the `isom` major brand.
  // ExifTool's `$size >= 12` ftyp gate sees the RAW 32-bit `$size == 1` (the
  // 64-bit decode happens later, INSIDE the per-atom loop), so it FAILS ⇒
  // `else { SetFileType() }` ⇒ MOV — even though the `isom` brand would
  // otherwise resolve to MP4. The brand is still decoded from the (valid)
  // extended-size atom walk. Verified vs bundled: FileType MOV +
  // `QuickTime:MajorBrand = "MP4 Base Media v1 [IS0 14496-12:2003]"` +
  // `QuickTime:MinorVersion = "0.0.0"`. The port previously resolved the
  // file type from the normalized payload brand and wrongly yielded MP4.
  check(
    "QuickTime_ext_ftyp.mov",
    "QuickTime_ext_ftyp.mov.json",
    true,
  );
  check(
    "QuickTime_ext_ftyp.mov",
    "QuickTime_ext_ftyp.mov.n.json",
    false,
  );
}

#[test]
fn quicktime_ftyp_first_qt_conformance() {
  // PR #38 Codex R9/F1: a `ftyp` whose major brand is `isom`, minor version 0,
  // and FIRST compatible brand is `qt  `. ExifTool's compatible-brand regex
  // `/^.{8}(.{4})+(qt  )/s` (QuickTime.pm:10000) skips the major brand + minor
  // version via `^.{8}`, then `(.{4})+` requires ONE OR MORE 4-byte slots
  // BEFORE the matched brand — so a `qt  ` in the FIRST compatible-brand slot
  // (buffer offset 8) can NOT trigger the match. `$fileType` stays undef ⇒
  // `$fileType or $fileType = 'MP4'` (QuickTime.pm:10004). Verified vs bundled:
  // FileType MP4 (not MOV). The port previously scanned every slot from offset
  // 8 and returned MOV on the first `qt  ` it saw.
  check(
    "QuickTime_ftyp_first_qt.mov",
    "QuickTime_ftyp_first_qt.mov.json",
    true,
  );
  check(
    "QuickTime_ftyp_first_qt.mov",
    "QuickTime_ftyp_first_qt.mov.n.json",
    false,
  );
}

#[test]
fn quicktime_nested_invalid_mvhd_conformance() {
  // PR #38 Codex R9/F2: a `moov` containing an `mvhd` whose declared
  // `size == 4` is structurally invalid (`< 8`). ExifTool runs the same
  // `ProcessMOV` per-atom `for(;;)` loop on the contained `moov` directory
  // (QuickTime.pm:10035-10075), so the `size < 8` check sets `$warnStr =
  // 'Invalid atom size'` and `last`s; the warning is emitted at the
  // directory's exit. Verified vs bundled: `ExifTool:Warning = "Invalid atom
  // size"`. The port's `walk_atoms` previously treated a contained
  // `HeaderOutcome::Malformed` like a size-0 terminator — a SILENT break.
  check(
    "QuickTime_nested_invalid_mvhd.mov",
    "QuickTime_nested_invalid_mvhd.mov.json",
    true,
  );
  check(
    "QuickTime_nested_invalid_mvhd.mov",
    "QuickTime_nested_invalid_mvhd.mov.n.json",
    false,
  );
}

#[test]
fn quicktime_nested_invalid_tkhd_conformance() {
  // PR #38 Codex R9/F2: a `tkhd` with an invalid declared `size == 4` inside
  // `moov/trak`. ExifTool attaches the `Invalid atom size` warning to the
  // CURRENT family-1 group — the `trak`'s `Track#` — so it surfaces as
  // `Track1:Warning`, NOT the document-level `ExifTool:Warning`. Verified vs
  // bundled: `Track1:Warning = "Invalid atom size"`.
  check(
    "QuickTime_nested_invalid_tkhd.mov",
    "QuickTime_nested_invalid_tkhd.mov.json",
    true,
  );
  check(
    "QuickTime_nested_invalid_tkhd.mov",
    "QuickTime_nested_invalid_tkhd.mov.n.json",
    false,
  );
}

// ============================================================================
// QuickTime SP4 brand-variant real-fixture conformance (#151)
// ============================================================================
//
// Three REAL bundled brand-variant containers prove the already-merged SP4
// `ftyp`-driven brand-detection dispatch (HEIC/AVIF/iso5/msf1) end-to-end: the
// brand routes to the correct `File:FileType`/`File:MIMEType` and the
// `ProcessMOV` walk emits the `ftyp` brand tags (`QuickTime:MajorBrand`/
// `MinorVersion`/`CompatibleBrands`) plus whatever structural atoms the port
// supports, BYTE-EXACT against the bundled ExifTool oracle.
//
// The goldens (`tools/gen_golden.sh` with the per-fixture `EXCLUDE` below) drop
// `System:all` + `Composite:all` (the QuickTime Composite subsystem is the
// Phase-2 forward item) AND the container/codec-config atoms this port does not
// decode — the HEVC/AV1 `*Configuration*` sample-description fields, the HEIF
// `ispe` `ImageSpatialExtent`, the `vmhd` `GraphicsMode`/`OpColor`, the
// `mvex/mehd` `MovieFragmentSequence`, and the file-`meta` `hdlr`
// `HandlerType`/`HandlerDescription`. Since the QuickTime container phase-1 port
// (#100) the per-track `stsd` `OtherFormat` (the `pict`/`text` 4cc) and the
// `trak` `hdlr` `HandlerDescription` ARE now decoded and retained byte-exact.
// exifast emits a strict SUBSET of the oracle (verified: it produces NO tag the
// oracle lacks); every excluded key is an unsupported container-structure tag,
// deferred via `-x`, never a value the port gets wrong.

#[test]
fn avif_brand_conformance() {
  // `tests/fixtures/AVIF_sample.avif` — a real AV1 Image File. Oracle (bundled
  // `exiftool -G1 -j`): File:FileType AVIF, File:MIMEType image/avif,
  // QuickTime:MajorBrand "AV1 Image File Format (.AVIF)" (brand `avif`),
  // CompatibleBrands [avif, mif1, miaf, MA1B], File:ImageWidth 1204,
  // File:ImageHeight 800, Meta:PrimaryItemReference 1.
  //
  // EXCLUDE (now baked into the `gen_golden.sh AVIF_sample.avif` arm): `-x
  // System:all -x HandlerType -x HandlerDescription -x PixelAspectRatio
  // -x ImageSpatialExtent -x ImagePixelDepth`. The AVIF has only a file-`meta`
  // `pict` handler (no `trak`), so the bare `-x HandlerType`/`HandlerDescription`
  // are collision-free; the `pasp`/`ispe`/`pixi` property atoms are the
  // unsupported spatial-extent / aspect fields (the ipco QuickTime-group
  // property-tag emission, sibling-issue #146/#147 territory). The `av1C` AV1
  // Codec Configuration IS now ported (#149) — the three non-`Unknown`
  // `AV1Config` tags (`AV1ConfigurationVersion` 1, `ChromaFormat` "YUV
  // 4:2:0"/3, `ChromaSamplePosition` "Unknown"/0) emit byte-exact and are KEPT
  // in the golden. The brand routing + `pitm` + the primary-`ispe`
  // `File:ImageWidth`/`Height` (#146) are byte-exact.
  // `Composite:all` is NO LONGER excluded: an `image/*` QuickTime is allow-listed
  // (#133 PR 3), so exifast now builds the ported `Composite:ImageSize`
  // ("1204x800") + `Composite:Megapixels` (0.963) from the primary dimensions,
  // and they are KEPT in the golden (AVIF emits no unported Composite).
  check("AVIF_sample.avif", "AVIF_sample.avif.json", true);
  check("AVIF_sample.avif", "AVIF_sample.avif.n.json", false);
}

#[test]
fn heic_msf1_brand_conformance() {
  // `tests/fixtures/HEIF_C001_msf1.heic` — a real HEVC still image whose `msf1`
  // compatible brand sits ahead of `heic`. Oracle: File:FileType HEIC,
  // File:MIMEType image/heic, QuickTime:MajorBrand "High Efficiency Image Format
  // HEVC still image (.HEIC)" (brand `heic`), CompatibleBrands
  // [msf1, mif1, heic, hevc, iso8], Meta:PrimaryItemReference 20001. The file
  // ALSO carries a `moov`/`trak` (the HEVC image track) whose `mvhd`/`tkhd`/
  // `mdhd`/`hdlr` core atoms the port decodes byte-exact (CreateDate,
  // TrackID 1003, Track1:ImageWidth 1280, Track1:HandlerType "Picture", …).
  //
  // EXCLUDE (now baked into the `gen_golden.sh HEIF_C001_msf1.heic` arm): `-x
  // System:all -x Copy1:HandlerType -x ImageSpatialExtent` + the `hvcC` HEVC
  // sample-description config block (`HEVCConfigurationVersion`,
  // `GeneralProfileSpace`/`GeneralTierFlag`/`GeneralProfileIDC`,
  // `GenProfileCompatibilityFlags`, `ConstraintIndicatorFlags`,
  // `GeneralLevelIDC`, `MinSpatialSegmentationIDC`, `ParallelismType`,
  // `ChromaFormat`, `BitDepthLuma`/`BitDepthChroma`, `AverageFrameRate`/
  // `ConstantFrameRate`, `NumTemporalLayers`, `TemporalIDNested`). `Composite:
  // AvgBitrate` is NO LONGER excluded (#133 PR 5: it is now the ported `mdat`-
  // bitrate composite — the SUM of all three `mdat` sizes / Duration, "50.2
  // Mbps"), and neither is `Composite:all`: an `image/*` QuickTime is
  // allow-listed (#133 PR 3), so exifast now builds + KEEPS the ported
  // `Composite:ImageSize` ("1280x720") + `Composite:Megapixels` (0.922) +
  // `Composite:AvgBitrate` ("50.2 Mbps"). The `pict`
  // track is a non-`vide`/`soun`/`meta` handler, so the phase-1 port (#100)
  // emits its `stsd` 4cc as `Track1:OtherFormat` "hvc1"; the phase-4 port adds
  // the `vmhd` `GraphicsMode`/`OpColor` — all three now RETAINED byte-exact.
  //
  // `-x Copy1:HandlerType` is the ONE non-obvious exclusion: the file carries
  // TWO `hdlr` boxes with the SAME tag NAME — the file-`meta` `hdlr` (which the
  // port's `walk_heif_meta` reads only for `pitm`, NOT `hdlr` — a deliberate
  // unsupported container tag) and the `trak` `hdlr` (which the port DOES emit
  // as `Track1:HandlerType`). They are distinguished only by ExifTool's
  // family-4 copy-number group (`Copy1` = the file-`meta` duplicate, `Main` =
  // the track), so excluding `Copy1:HandlerType` drops EXACTLY the unsupported
  // file-`meta` `QuickTime:HandlerType` while keeping the port-emitted
  // `Track1:HandlerType` — no value is altered.
  check("HEIF_C001_msf1.heic", "HEIF_C001_msf1.heic.json", true);
  check("HEIF_C001_msf1.heic", "HEIF_C001_msf1.heic.n.json", false);
}

#[test]
fn iso5_brand_conformance() {
  // `tests/fixtures/ISOBMFF_iso5_brand.mp4` — a real fragmented MP4 whose major
  // brand `iso5` ("MP4 Base Media v5") has no `(.EXT)` substring, so the brand
  // dispatch falls through to MP4 (no `mp41`/`mp42`/`f4v`/`qt` compatible
  // brand). Oracle: File:FileType MP4, File:MIMEType video/mp4,
  // QuickTime:MajorBrand "MP4 Base Media v5", MinorVersion "0.0.1",
  // CompatibleBrands [iso5, dsms, msix, dash]. The `moov`/`trak` (a GPAC text
  // track) decodes byte-exact incl. Track1:MediaLanguageCode "und",
  // Track1:HandlerType "Text", and the no-`-ee` Track1:Warning.
  //
  // EXCLUDE: `-x System:all -x Composite:all -x MovieFragmentSequence` — only
  // the `mvex/mehd` `MovieFragmentSequence` is an unsupported container tag now.
  // The phase-1 port (#100) decodes the `trak` `hdlr` `HandlerDescription`
  // ("nhml@GPAC0.5.1-DEV-rev5339") and the `text`-handler `stsd` `OtherFormat`
  // ("depi"), both RETAINED byte-exact.
  check(
    "ISOBMFF_iso5_brand.mp4",
    "ISOBMFF_iso5_brand.mp4.json",
    true,
  );
  check(
    "ISOBMFF_iso5_brand.mp4",
    "ISOBMFF_iso5_brand.mp4.n.json",
    false,
  );
}

#[test]
fn mxf_utf16_bom_conformance() {
  // Codex R2/F1 regression: `MXF.mxf` with every UTF-16 `ApplicationName` /
  // `TrackName` value rewritten to carry a byte-order mark (byte-length
  // preserved by dropping one trailing char). MXF.pm:2484 decodes UTF-16 via
  // `$et->Decode($val, 'UTF16')` with no byte-order arg, so Charset::Decompose
  // (Charset.pm:188-206) defaults to GetByteOrder() = 'MM' (big-endian, set at
  // MXF.pm:2821) and then strips a leading BOM: `$val =~ s/^(\xfe\xff|\xff\xfe)//`
  // sets `$fmt = $1 eq "\xfe\xff" ? 'n*' : 'v*'`. So a `FE FF` (BE) BOM is
  // stripped and the remainder decoded big-endian (NOT preserved as a leading
  // U+FEFF), and a `FF FE` (LE) BOM is stripped AND the remainder decoded
  // little-endian (NOT garbled by a big-endian read). Both goldens come from
  // the bundled oracle (`tools/gen_golden.sh`) and decode to the identical
  // BOM-stripped text ("ExifToo", "Timecode Trac", "Sound Trac").
  check("MXF_BomBE.mxf", "MXF_BomBE.mxf.json", true);
  check("MXF_BomBE.mxf", "MXF_BomBE.mxf.n.json", false);
  check("MXF_BomLE.mxf", "MXF_BomLE.mxf.json", true);
  check("MXF_BomLE.mxf", "MXF_BomLE.mxf.n.json", false);
}

#[test]
fn mxf_dup_duration_all_ff_conformance() {
  // Codex R3/F1 regression: two same-InstanceUID `TimecodeComponent` sets, the
  // EARLIER carrying a VALID `Duration` (100) and the LATER (footer-style)
  // carrying an all-`0xff` `Duration`. MXF.pm:98's `%duration` RawConv
  // (`$val > 1e18 ? undef : $val`) returns `undef` for the all-`0xff` value, so
  // `FoundTag` stores NO key (ExifTool.pm:9493) and MXF.pm:2666's
  // `next unless $key` skips its `push @groups`. The dropped value is therefore
  // ABSENT from the reverse-file-order duplicate pass (MXF.pm:2946-2962): it
  // never claims the `"Duration <UID>"` key, so the earlier VALID `Duration`
  // is the one kept. Before the fix the port queued a `Duration(i64::MIN)`
  // sentinel `WalkEntry` for the drop; being LATER in file order it won the
  // dedup and DELETED the valid earlier `Duration`, then emitted nothing —
  // erasing `MXF:Duration` entirely. The oracle keeps the valid `0:01:40`
  // (`-n`: `100`). Goldens are the bundled oracle (`tools/gen_golden.sh`).
  check("MXF_DupDurationFF.mxf", "MXF_DupDurationFF.mxf.json", true);
  check(
    "MXF_DupDurationFF.mxf",
    "MXF_DupDurationFF.mxf.n.json",
    false,
  );
}

#[test]
fn mxf_utf16_embedded_nul_conformance() {
  // Codex R4/F1 regression: `MXF.mxf` with the UTF-16 `ApplicationName` value
  // changed from `ExifTool` to `E\0ifTool` — the second code unit `00 78`
  // (`x`, U+0078) flipped to `00 00` (U+0000) in all 3 metadata sets carrying
  // it (3 bytes total: 0x78 -> 0x00). The NUL is followed by NON-zero stale
  // text `ifTool`. MXF.pm:2484 decodes UTF-16 via `$et->Decode($val,'UTF16')`,
  // which routes through Charset::Decompose then Charset::Recompose. Recompose's
  // UTF-8 branch (Charset.pm:318-327, `$csType == 0x100`) packs the code-point
  // array and runs `$outVal =~ s/\0.*//s` — TRUNCATING the UTF-8 output at the
  // first NUL (sub header, Charset.pm:308: "truncated at null character if it
  // exists"). So the oracle emits `MXF:ApplicationName` as `"E"`, dropping the
  // post-NUL `ifTool`. Before the fix `decode_utf16` SKIPPED NUL code units
  // (`tr/\0//d`-style), wrongly concatenating the stale text into `"EifTool"`.
  // Golden is the bundled oracle (`tools/gen_golden.sh`).
  check(
    "MXF_Utf16EmbeddedNul.mxf",
    "MXF_Utf16EmbeddedNul.mxf.json",
    true,
  );
  check(
    "MXF_Utf16EmbeddedNul.mxf",
    "MXF_Utf16EmbeddedNul.mxf.n.json",
    false,
  );
}

#[test]
fn matroska_conformance() {
  // FORMATS.md row 23. `tests/fixtures/Matroska.mkv` is the bundled
  // `lib/Image/ExifTool/t/images/Matroska.mkv` (507 bytes, video+audio
  // tracks with `DocType="matroska"`). Goldens are bundled
  // `perl exiftool -j -G1:1 -api struct=1` output with `System:*` and
  // `Composite:*` stripped uniformly (matching every other format
  // conformance — composite-tag system is deferred per
  // `[[exifast-phase2-forward-items]]`).
  check("Matroska.mkv", "Matroska.mkv.json", true);
  check("Matroska.mkv", "Matroska.mkv.n.json", false);
}

#[test]
fn matroska_simpletag_conformance() {
  // PR #31 R1 finding F1 — Tags → SimpleTag → TagName/TagString
  // mapping via `Image::ExifTool::Matroska::StdTag` (Matroska.pm:750-
  // 891). Synthetic fixture: EBMLHeader + Segment[Info + Tracks +
  // Tags[Tag[SimpleTag(TITLE, "Hello World"), SimpleTag(ARTIST, "Test
  // Artist"), SimpleTag(DATE_RELEASED, "2010-01-15")]]]. Exercises the
  // StdTag canonical-name lookup (TITLE→Title, ARTIST→Artist,
  // DATE_RELEASED→DateReleased + dateInfo separator conversion).
  // Goldens captured with `perl exiftool -j -G1:1 -api struct=1
  // -x System:all -x Composite:all`.
  check(
    "Matroska_simpletag.mkv",
    "Matroska_simpletag.mkv.json",
    true,
  );
  check(
    "Matroska_simpletag.mkv",
    "Matroska_simpletag.mkv.n.json",
    false,
  );
}

#[test]
fn matroska_unknown_segment_conformance() {
  // PR #31 R1 finding F2 — unknown-size master element handling
  // (Matroska.pm:1073-1085, 1114). Synthetic fixture: EBMLHeader +
  // Segment(size = unknown-8-byte-VINT)[Info + Tracks]. Without F2
  // the walker breaks on the unknown-size VINT after EBMLHeader and
  // emits ONLY File:* + EBMLHeader children (losing Info + Tracks).
  // With F2 the walker descends the unknown-size Segment using the
  // parent's end (here EOF) as the effective bound, faithful to
  // Matroska.pm:1073 `$size = 1e20` for unknown-size masters.
  check(
    "Matroska_unknown_segment.mkv",
    "Matroska_unknown_segment.mkv.json",
    true,
  );
  check(
    "Matroska_unknown_segment.mkv",
    "Matroska_unknown_segment.mkv.n.json",
    false,
  );
}

#[test]
fn matroska_cluster_skip_conformance() {
  // PR #31 R1 finding F3 — Cluster default-skip (Matroska.pm:1096-
  // 1105). Synthetic fixture: EBMLHeader + Segment[Info + Cluster
  // (with Timecode + SimpleBlock body) + Tags]. Bundled DEFAULT
  // behavior is to `last` the walker at the first Cluster (no
  // `-v`/`-U > 1`/`-ee`), so Tags AFTER Cluster MUST NOT be emitted —
  // matches our `Kind::SkipBody` → `break` semantics. Verifies we
  // emit Info:* but neither walk into Cluster's body (SimpleBlock
  // would emit nothing anyway since it's NoSave) nor pick up the
  // Tags AFTER Cluster.
  check(
    "Matroska_cluster_skip.mkv",
    "Matroska_cluster_skip.mkv.json",
    true,
  );
  check(
    "Matroska_cluster_skip.mkv",
    "Matroska_cluster_skip.mkv.n.json",
    false,
  );
}

#[test]
fn matroska_negative_subsecond_date_conformance() {
  // PR #31 R2 finding companion fixture — pre-2001 DateUTC (signed
  // nanoseconds < 0) exercises BOTH (a) the EBML 8-byte signed-decode
  // f64-promotion loss (`Matroska.pm:1184-1191` — Perl's `$val * 256 +
  // $byte` accumulator promotes IV→NV at ~2^64 magnitude, so the
  // post-subtract `$val` is OFF FROM THE EXACT INTEGER by ~256), and
  // (b) the fractional-second `$frac < 0 → frac += 1, $itime -= 1`
  // correction branch in `ExifTool.pm:6782`.
  //
  // Synthetic fixture: raw_ns = -1_500_000_000 (1.5 s before Matroska
  // epoch). Bundled-Perl emits "2000:12:31 23:59:58.499999762Z" — the
  // `.499999762` (not `.5`) is Perl's deliberate decode loss; our
  // `convert_matroska_date` replays it via `(raw_ns as u64) as f64 -
  // 2^64` for byte-exact match.
  check(
    "Matroska_negative_subsecond_date.mkv",
    "Matroska_negative_subsecond_date.mkv.json",
    true,
  );
  check(
    "Matroska_negative_subsecond_date.mkv",
    "Matroska_negative_subsecond_date.mkv.n.json",
    false,
  );
}

#[test]
fn matroska_subsecond_date_conformance() {
  // PR #31 R2 finding — `Value::Date` rendering used `as i64` casting on
  // `secs_unix` (f64), silently dropping the subsecond component that
  // Perl's `ConvertUnixTime($t, undef, -9) . 'Z'` preserves
  // (ExifTool.pm:6773-6800 fractional branch + `dec=-9` trim). The
  // bundled Matroska.mkv fixture's DateTimeOriginal carries integer
  // nanoseconds (`2010:02:03 21:17:48Z` — no fractional), so the
  // original conformance didn't catch the loss.
  //
  // Synthetic fixture: minimal EBMLHeader + Segment[Info[TimecodeScale,
  // MuxingApp, WritingApp, DateUTC = 286_658_268_123_456_789]] →
  // post-Matroska-offset `$t = 1264965468.123456789` → bundled-Perl
  // emits `"2010:01:31 19:17:48.123456717Z"` (the `.717` instead of
  // `.789` is the inherent f64 precision loss of Perl's `$val / 1e9`,
  // which our `convert_matroska_date` faithfully transliterates).
  //
  // Goldens captured with `EXIFTOOL=...exiftool tools/gen_golden.sh
  // Matroska_subsecond_date.mkv` — UNTRIMMED; the synthetic body is so
  // minimal there are no System:* / Composite:* tags emitted by Perl
  // for this fixture (gen_golden.sh strips fs-dependent System fields).
  check(
    "Matroska_subsecond_date.mkv",
    "Matroska_subsecond_date.mkv.json",
    true,
  );
  check(
    "Matroska_subsecond_date.mkv",
    "Matroska_subsecond_date.mkv.n.json",
    false,
  );
}

#[test]
fn matroska_attachment_conformance() {
  // PR #31 R1 finding F5 — Binary elements (Matroska.pm:552
  // `AttachedFileData`, 695 `TagBinary`). Synthetic fixture:
  // EBMLHeader + Segment[Info + Tracks + Attachments[AttachedFile
  // (Name=cover.jpg, MIME=image/jpeg, UID=deadbeef, Data=32B)]].
  // Bundled emits AttachedFileData as
  // `"(Binary data 32 bytes, use -b option to extract)"` (identical
  // string for both `-j` and `-n` — TagValue::Bytes serialization in
  // `src/value.rs:711-716`). With pre-F5 `Kind::Skip` the binary
  // payload was silently dropped.
  check(
    "Matroska_attachment.mkv",
    "Matroska_attachment.mkv.json",
    true,
  );
  check(
    "Matroska_attachment.mkv",
    "Matroska_attachment.mkv.n.json",
    false,
  );
}

#[test]
fn matroska_duration_before_scale_conformance() {
  // PR #31 R3 finding — Duration ValueConv (Matroska.pm:170-171)
  // `'$$self{TimecodeScale} ? $val * $$self{TimecodeScale} / 1e9 :
  // $val / 1000'`. ValueConv/PrintConv are deferred to output time
  // and read `$$self{TimecodeScale}` LAZILY (verified empirically
  // against bundled-Perl 13.58 — for files where Duration precedes
  // TimecodeScale, bundled still applies the FINAL TimecodeScale).
  //
  // Synthetic fixture: minimal EBMLHeader + Segment[Info[MuxingApp,
  // WritingApp, Duration=60000.0 raw_float, TimecodeScale=1_000_000
  // (1 ms)]] — Duration appears BEFORE TimecodeScale in the EBML
  // walk. Bundled emits `"Info:Duration": "0:01:00"` because the
  // LAST `$$self{TimecodeScale}` (1 ms) is used at output-time
  // ValueConv ⇒ `60000 * 1e6 / 1e9 = 60.0 s = "0:01:00"`. This
  // pins the order-independence semantic so a future walk-time
  // ValueConv refactor that misread Perl's deferred-eval semantics
  // would regress.
  check(
    "Matroska_duration_before_scale.mkv",
    "Matroska_duration_before_scale.mkv.json",
    true,
  );
  check(
    "Matroska_duration_before_scale.mkv",
    "Matroska_duration_before_scale.mkv.n.json",
    false,
  );
}

#[test]
fn matroska_duration_no_scale_conformance() {
  // PR #31 R3 — Duration FALSY branch (NO TimecodeScale in the file).
  // ValueConv: `$$self{TimecodeScale} ? ... : $val / 1000` — when
  // TimecodeScale is absent, `$$self{TimecodeScale}` is `undef` ⇒
  // FALSY ⇒ fallback fires ⇒ `60000 / 1000 = 60`. PrintConv ALSO
  // gates on the same ternary ⇒ bare numeric (NOT
  // `ConvertDuration($val)`), so `-j` and `-n` BOTH emit `60`.
  //
  // Synthetic fixture: minimal EBMLHeader + Segment[Info[MuxingApp,
  // WritingApp, Duration=60000.0]] (no TimecodeScale element at all).
  check(
    "Matroska_duration_no_scale.mkv",
    "Matroska_duration_no_scale.mkv.json",
    true,
  );
  check(
    "Matroska_duration_no_scale.mkv",
    "Matroska_duration_no_scale.mkv.n.json",
    false,
  );
}

#[test]
fn matroska_track_targeted_tag_conformance() {
  // PR #31 R4 finding F2 — Track-targeted SimpleTag misattribution
  // (Matroska.pm:1207-1216). Bundled records every `TrackUID` inside a
  // TrackEntry into `%trackNum{$val} = $$et{SET_GROUP1}` (raw bytes →
  // Track<N>); when `TagTrackUID` is later read inside `Tags/Tag/
  // Targets`, the matching raw bytes look up the mapped `Track<N>` and
  // OVERRIDE SET_GROUP1 for the duration of the enclosing `Tag` master.
  // SimpleTag children then emit under `Track<N>` instead of the
  // default file-level group.
  //
  // Synthetic fixture: TrackEntry[TrackNumber=1, TrackUID=01020304,
  // TrackType=Video] + Tags[Tag[Targets[TagTrackUID=01020304],
  // SimpleTag[TagName="TITLE", TagString="Track Title"]]]. Bundled
  // emits `Track1:TagTrackUID: "01020304"` AND `Track1:Title: "Track
  // Title"` (NOT `Matroska:TagTrackUID` / `Matroska:Title`, which is
  // what the pre-fix walker emitted).
  //
  // Lock-depth semantics: the `Tag` master's index in `Walker.ends` is
  // used as the reset trigger, faithful to Perl's
  // `$trackIndent = substr($$et{INDENT}, 0, -2)` one-level-up reset
  // (Matroska.pm:1215). Multiple sibling Tags in the same Tags section
  // can each re-set/reset independently.
  check(
    "Matroska_track_targeted_tag.mkv",
    "Matroska_track_targeted_tag.mkv.json",
    true,
  );
  check(
    "Matroska_track_targeted_tag.mkv",
    "Matroska_track_targeted_tag.mkv.n.json",
    false,
  );
}

#[test]
fn matroska_simpletag_duplicates_conformance() {
  // PR #31 R5 finding — SimpleTag accumulator semantics. Matroska.pm:1224-
  // 1226 is `if ($$tagInfo{NoSave} or $struct) { ... $$struct{$tagName} =
  // $val if $struct; }` — i.e. plain Perl hash assignment, which is
  // OVERWRITE semantics. Two divergences from the pre-R5 Rust port:
  //   (1) The accumulator was first-wins on TagName/TagString/TagBinary —
  //       Perl is last-wins (a second-occurrence `$$struct{TagString}` would
  //       silently overwrite the first).
  //   (2) Only TagBinary/TagName/TagString routed into the struct; other
  //       leaves inside SimpleTag (e.g. `TagDefault` 0x484, `Format =>
  //       'unsigned'`, Matroska.pm:690) fell through `Kind::Unsigned` →
  //       `push_entry` → emitted as a TOP-LEVEL `Tags:TagDefault` tag.
  //       Bundled NEVER emits such children (HandleStruct, Matroska.pm:
  //       897-948, only reads TagName/TagString/TagBinary/TagLanguage — the
  //       absorbed TagDefault is silently dropped at flush time per the
  //       explicit "not currently handling TagDefault attribute" comment
  //       at Matroska.pm:929).
  //
  // Synthetic fixture: a single Tag block with TWO SimpleTags:
  //   #1: TagName="TITLE", TagString="First", TagString="Last",
  //       TagDefault=1 → bundled emits `Matroska:Title: "Last"`.
  //   #2: TagName="ARTIST", TagString="Original Artist",
  //       TagName="REPLACED_ARTIST", TagDefault=0 → bundled emits
  //       `Matroska:ReplacedArtist: "Original Artist"` (the LAST TagName
  //       binds the canonical lookup key; `REPLACED_ARTIST` is NOT in
  //       StdTag so `synthesize_tag_name` kicks in: lowercase →
  //       `replaced_artist`, ucfirst → `Replaced_artist`, then `_a` → `A`
  //       per `s/_([a-z])/\U$1/g` ⇒ `ReplacedArtist`).
  //
  // Neither golden contains `Matroska:TagDefault` (or any TagDefault
  // emission anywhere) — the pre-R5 Rust would have emitted both as
  // top-level tags.
  check(
    "Matroska_simpletag_duplicates.mkv",
    "Matroska_simpletag_duplicates.mkv.json",
    true,
  );
  check(
    "Matroska_simpletag_duplicates.mkv",
    "Matroska_simpletag_duplicates.mkv.n.json",
    false,
  );
}

#[test]
fn matroska_chapters_conformance() {
  // PR #31 R4 finding F1 — ChapterTimeStart (0x11) + ChapterTimeEnd (0x12)
  // were `Kind::Skip` (silent drop). Bundled extracts both as
  // `Format => 'unsigned'`, `ValueConv => '$val / 1e9'`,
  // `PrintConv => 'ConvertDuration($val)'` (Matroska.pm:580-592). Group
  // attribution: each ChapterAtom (Matroska.pm:1117-1118) bumps a 1-based
  // counter and SET_GROUP1 → `Chapter<n>`, so a fixture with one
  // ChapterAtom emits `Chapter1:ChapterTimeStart`, etc.
  //
  // Two ancillary fixes wrapped into this finding:
  //   (a) The walker's ID-validity guard previously rejected ID 0
  //       (`id_v.value() <= 0` ⇒ `< 0`, faithful to Matroska.pm:1068
  //       `$tag >= 0`). ChapterDisplay's ID IS 0 (Matroska.pm:615), so
  //       any chapter content (including ChapterString) was being
  //       dropped.
  //   (b) The new `Kind::ChapterTimeNs` carries raw u64 ns through to
  //       output-time `ValueConv` + `ConvertDuration` (faithful to the
  //       deferred-eval semantics the rest of the Matroska module uses).
  //
  // Synthetic fixture: EBMLHeader + Segment[Info(TimecodeScale=1ms,
  // MuxingApp, WritingApp) + Chapters[EditionEntry[ChapterAtom[
  // ChapterTimeStart=60s in ns, ChapterTimeEnd=120s in ns, ChapterDisplay
  // [ChapterString="Intro"]]]]]. Bundled `-j` emits
  // `Chapter1:ChapterTimeStart: "0:01:00"`, ChapterTimeEnd: "0:02:00",
  // ChapterString: "Intro". Bundled `-n` emits the bare numeric seconds.
  check("Matroska_chapters.mkv", "Matroska_chapters.mkv.json", true);
  check(
    "Matroska_chapters.mkv",
    "Matroska_chapters.mkv.n.json",
    false,
  );
}

#[test]
fn matroska_duration_zero_scale_conformance() {
  // PR #31 R3 finding — the ACTUAL pre-fix bug. ValueConv:
  // `$$self{TimecodeScale} ? $val * $$self{TimecodeScale} / 1e9 :
  // $val / 1000` — PERL TRUTHINESS, so `$$self{TimecodeScale} = 0`
  // is FALSY (NOT just `undef`). Pre-R3-fix Rust code matched
  // `Some(ts) => raw * ts / 1e9` unconditionally, so `Some(0)`
  // took the WRONG branch ⇒ `60000 * 0 / 1e9 = 0`. Post-fix
  // adds an explicit `ts != 0` guard ⇒ both `None` AND `Some(0)`
  // fall through to `$val / 1000` ⇒ `60.0`. PrintConv mirrors
  // the same truthiness ⇒ bare numeric.
  //
  // Synthetic fixture: minimal EBMLHeader + Segment[Info[MuxingApp,
  // WritingApp, TimecodeScale=0, Duration=60000.0]] — TimecodeScale
  // explicitly stored as 0 (1-byte unsigned).
  check(
    "Matroska_duration_zero_scale.mkv",
    "Matroska_duration_zero_scale.mkv.json",
    true,
  );
  check(
    "Matroska_duration_zero_scale.mkv",
    "Matroska_duration_zero_scale.mkv.n.json",
    false,
  );
}

#[test]
fn matroska_illegal_float_size_conformance() {
  // Golden-v2 Phase B.1.5 — the `Illegal float size` warning + the
  // undef→ValueConv leaf VALUE fix (Matroska.pm:1178-1180). A `Format =>
  // 'float'` element (here `Duration`, 0x4489) with a non-4/8-byte size
  // (3) is the `else { $et->Warn("Illegal float size ($size)") }` branch:
  // `$val` is left UNDEF, the warning is raised under the active
  // `SET_GROUP1 = 'Info'` (Matroska.pm:1121) ⇒ the group-scoped
  // `Info:Warning` TAG, and the Duration leaf is its undef→ValueConv result
  // = `0` (`undef / 1000`, no TimecodeScale present). NOT `NaN`.
  //
  // Crafted fixture: minimal EBMLHeader + Segment[Info[MuxingApp, WritingApp,
  // Duration(size 3)]]; the Info/Segment container sizes are widened so the
  // bad-size Duration fits its container (otherwise the :1074 corruption check
  // fires first). Goldens are `tools/gen_golden.sh` 13.59 output (version
  // stamp normalized to 13.58); the ONLY delta vs a valid Duration is the
  // added `Info:Warning` + `Info:Duration: 0`.
  check(
    "Matroska_illegal_float_size.mkv",
    "Matroska_illegal_float_size.mkv.json",
    true,
  );
  check(
    "Matroska_illegal_float_size.mkv",
    "Matroska_illegal_float_size.mkv.n.json",
    false,
  );
}

#[test]
fn matroska_warning_collision_conformance() {
  // Golden-v2 Phase B R1 — a group-scoped `$et->Warn` `Warning` TAG colliding
  // with a REAL same-group SimpleTag `Warning` on the `-G1` output key
  // `Info:Warning`. Both are the pseudo-tag `Warning`: the diagnostic is the
  // `Extra` table `Warning` (`Priority => 0`, ExifTool.pm:1299), the SimpleTag
  // is the `StdTag` table `Warning` (table `PRIORITY => 0`, Matroska.pm:752).
  // ExifTool NEVER lets a priority-0 duplicate override (the new value is
  // shunted to `Warning (1)`, ExifTool.pm:9544-9560) and the default `%noDups`
  // output keeps the FIRST-extracted by file order (ExifTool.pm:5404-5417) —
  // i.e. whichever the walk reached FIRST wins.
  //
  // FORWARD fixture: Info[MuxingApp, WritingApp, Duration(size 3 — illegal
  // float, raises `Info:Warning` AT the Duration walk position),
  // SimpleTag[TagName=Warning, TagString="from-simpletag"]]. The illegal-float
  // diagnostic is walk-FIRST, so the oracle survivor is `Info:Warning =
  // "Illegal float size (3)"` (NOT the later SimpleTag). This pins that the
  // diagnostic — now emitted IN-STREAM at its walk position (not drained last)
  // — correctly wins when it is the first FoundTag. (The old run_diagnostics-
  // last path also produced this value, by accident of last-wins; the reverse
  // fixture is the one that exercised the bug.) Goldens are `gen_golden.sh`
  // 13.59 output, version stamp normalized to 13.58.
  check(
    "Matroska_warning_collision.mkv",
    "Matroska_warning_collision.mkv.json",
    true,
  );
  check(
    "Matroska_warning_collision.mkv",
    "Matroska_warning_collision.mkv.n.json",
    false,
  );
}

#[test]
fn matroska_warning_collision_rev_conformance() {
  // Golden-v2 Phase B R1 (the bug-exercising direction) — same `Info:Warning`
  // collision as `matroska_warning_collision`, but the REAL SimpleTag
  // `Warning` is walk-FIRST and the illegal-float diagnostic is walk-LATER:
  // Info[MuxingApp, WritingApp, SimpleTag[TagName=Warning,
  // TagString="from-simpletag"], Duration(size 3)]. The SimpleTag is the first
  // FoundTag, so the oracle survivor is `Info:Warning = "from-simpletag"` (the
  // priority-0 diagnostic raised later does NOT override it).
  //
  // This is the case the pre-fix port got WRONG: it drained the group-scoped
  // diagnostic through `run_diagnostics` AFTER `run_emission` (which had
  // already written the SimpleTag `Info:Warning`), and TagMap's last-wins
  // clobbered the SimpleTag with the diagnostic → `"Illegal float size (3)"`,
  // diverging from the oracle. The fix emits the group-scoped warning
  // IN-STREAM at its walk position (mirroring QuickTime's `Track<N>:Warning`)
  // and makes `Warning`/`Error` FIRST-wins in TagMap (the faithful priority-0
  // dedup), so the first-walked SimpleTag survives. Goldens normalized to
  // 13.58.
  check(
    "Matroska_warning_collision_rev.mkv",
    "Matroska_warning_collision_rev.mkv.json",
    true,
  );
  check(
    "Matroska_warning_collision_rev.mkv",
    "Matroska_warning_collision_rev.mkv.n.json",
    false,
  );
}

#[test]
fn matroska_truncated_header_conformance() {
  // Golden-v2 Phase B.1.5 — the `Truncated Matroska header` warning + NO
  // `File:*` (Matroska.pm:1003-1006). When the EBML header's declared body
  // overruns the file (`$pos + $hlen > $dataLen`), bundled `$et->Warn(
  // 'Truncated Matroska header'), return 1` — BEFORE `SetFileType()` at
  // :1007 — so the document carries ONLY `ExifTool:Warning` (document-level,
  // no `SET_GROUP1` active) and NO `File:FileType`/`FileTypeExtension`/
  // `MIMEType` triplet and NO `Matroska:*` tags.
  //
  // Crafted fixture: the 4-byte EBML magic + a header declaring a 35-byte
  // body, truncated to 20 bytes total (16 < 36 ⇒ truncated). Goldens are
  // `tools/gen_golden.sh` 13.59 output (version stamp normalized to 13.58).
  check(
    "Matroska_truncated_header.mkv",
    "Matroska_truncated_header.mkv.json",
    true,
  );
  check(
    "Matroska_truncated_header.mkv",
    "Matroska_truncated_header.mkv.n.json",
    false,
  );
}

#[test]
fn plist_bin_conformance() {
  // FORMATS.md row 12b. `tests/fixtures/PLIST-bin.plist` is the bundled
  // `lib/Image/ExifTool/t/images/PLIST-bin.plist` (351 bytes — a binary
  // `bplist00` with a `<dict>` of one each of every plist scalar shape
  // plus an `<array>` and `<data>`). Goldens are bundled
  // `tools/gen_golden.sh` output (`perl exiftool -j -G1 -struct`, the
  // canonical generator — `System:*` fs-dependent fields stripped). The
  // binary `<array>` is a real Perl arrayref ⇒ emitted as a list
  // (`["one","two","three"]`); the binary `<date>` uses the local-time
  // `ConvertUnixTime(_, 1)` branch — the port now ports that faithful
  // localtime path (Codex R2 F1), so the test pins `TZ=UTC` (the golden's
  // capture zone) for a host-independent `+00:00` suffix.
  pin_utc();
  check("PLIST-bin.plist", "PLIST-bin.plist.json", true);
  check("PLIST-bin.plist", "PLIST-bin.plist.n.json", false);
}

/// Codex R14 F1 — a truncated `bplist00` (the 8-byte magic only, no trailer):
/// a plausible short/partially-copied binary plist in a real media library.
/// Bundled recognizes the `bplist0` magic (PLIST.pm:480), calls
/// `SetFileType('PLIST', 'application/x-plist')` (PLIST.pm:483), and — because
/// `ProcessBinaryPLIST` fails on the missing trailer — adds `$et->Error('Error
/// reading binary PLIST file')` (PLIST.pm:485-486) while still finalizing as
/// PLIST (`$result = 1`, PLIST.pm:489). The error lands in the family-1 `PLIST`
/// group (`SET_GROUP1 = 'PLIST'`, PLIST.pm:484), so the `-G1` golden keys it
/// `PLIST:Error`. Before the fix the port returned `None` (dropping the file:
/// no FileType/MIME/error). Goldens are bundled `tools/gen_golden.sh` output
/// (`perl exiftool -j -G1 -struct`; the perl exit code is 1 because of the
/// error, so the `.n.json` was captured with the same flags + `-n`).
///
/// This exercises the engine surface (`extract_info` via `check`). The typed
/// `parse_bytes` surface is asserted in `plist_trunc_bin_parse_bytes_recognized`.
#[test]
fn plist_trunc_bin_conformance() {
  check("plist_trunc_bin.plist", "plist_trunc_bin.plist.json", true);
  check(
    "plist_trunc_bin.plist",
    "plist_trunc_bin.plist.n.json",
    false,
  );
}

/// Codex R14 F1 (the typed `parse_bytes` surface) — the SAME truncated
/// `bplist00` must NOT be dropped by the public typed dispatch either: it is a
/// RECOGNIZED PLIST carrying the error, not `Ok(None)`. Asserts the typed
/// `AnyMeta::Plist` arm is returned with `format() == Binary` and
/// `error() == Some("Error reading binary PLIST file")` (PLIST.pm:486), and
/// that the rendered engine output carries `PLIST:Error` + `File:FileType =
/// PLIST` + `File:MIMEType = application/x-plist` (PLIST.pm:483) — the
/// observability bundled emits and the pre-fix `Ok(None)` lost.
#[test]
fn plist_trunc_bin_parse_bytes_recognized() {
  let trunc: &[u8] = b"bplist00";
  // Typed public dispatch must recognize it (not `Ok(None)`).
  let meta =
    exifast::parse_bytes(trunc).expect("truncated bplist00 is a RECOGNIZED PLIST, not Ok(None)");
  match meta {
    exifast::format_parser::AnyMeta::Plist(p) => {
      assert!(p.format().is_binary(), "binary plist");
      assert_eq!(
        p.error(),
        Some("Error reading binary PLIST file"),
        "carries the bundled PLIST.pm:486 error"
      );
      assert!(
        p.tags_slice().is_empty(),
        "an error meta has no extracted tags"
      );
    }
    other => panic!("expected AnyMeta::Plist, got {other:?}"),
  }
  // And the engine render carries the recognized-PLIST classification + error.
  let json = extract_info("plist_trunc_bin.plist", trunc, true);
  let v: serde_json::Value = serde_json::from_str(&json).expect("valid JSON");
  let obj = v.as_array().unwrap()[0].as_object().unwrap();
  assert_eq!(
    obj.get("File:FileType").and_then(|x| x.as_str()),
    Some("PLIST")
  );
  assert_eq!(
    obj.get("File:MIMEType").and_then(|x| x.as_str()),
    Some("application/x-plist")
  );
  assert_eq!(
    obj.get("PLIST:Error").and_then(|x| x.as_str()),
    Some("Error reading binary PLIST file")
  );
  // The error is family-1 `PLIST:Error` (PLIST.pm:484 SET_GROUP1), NOT the
  // family-0 `ExifTool:Error` the engine uses for finalization-stage errors.
  assert!(
    !obj.contains_key("ExifTool:Error"),
    "the error is the PLIST-grouped tag, not ExifTool:Error"
  );
}

#[test]
fn plist_xml_conformance() {
  // FORMATS.md row 12b. `tests/fixtures/PLIST-xml.plist` is the bundled
  // `lib/Image/ExifTool/t/images/PLIST-xml.plist` (795 bytes — the same
  // value set as the binary fixture, XML-encoded). Family-1 group is
  // `"XML"` (the XMP-machinery path, PLIST.pm:48/466-469). Under
  // `exiftool -struct` (the golden generator) the XML `<array>` collapses
  // to the last-value-wins scalar (`"three"`) — each `<string>` is a
  // separate `FoundTag` call and `-struct` suppresses list accumulation.
  check("PLIST-xml.plist", "PLIST-xml.plist.json", true);
  check("PLIST-xml.plist", "PLIST-xml.plist.n.json", false);
}

/// Codex R1 F1 — an XML `<array>` of `<dict>` elements. The XMP event parser
/// inserts an EMPTY key-stack component for the `<array>` level
/// (PLIST.pm:191-194 `push '' while @keys < @props-3`), so a `cast`→array→
/// `{name}` reaches the `cast//name` tag ID and emits `XML:Cast`. Under
/// `-struct` the repeated `name` keys collapse last-value-wins (`"Bob"`). The
/// `plainstr` string array confirms the verified string-array last-wins
/// behavior is unchanged. Bundled `exiftool -j -G1 -struct` is the golden.
#[test]
fn plist_xml_array_of_dict_conformance() {
  check(
    "plist_synth_xml_array_of_dict.plist",
    "plist_synth_xml_array_of_dict.plist.json",
    true,
  );
  check(
    "plist_synth_xml_array_of_dict.plist",
    "plist_synth_xml_array_of_dict.plist.n.json",
    false,
  );
}

/// Codex R5 F1 — the `XMLFileType=ModdXML` content override (PLIST.pm:133-141
/// RawConv → `OverrideFileType('MODD')`). The fixture has a `.xml` extension
/// (NO `.modd`/`.plist`), so ExifTool types it `XMP` first
/// (`$$self{FILE_TYPE} eq 'XMP'`) and the override fires: `File:FileType=MODD`,
/// `File:FileTypeExtension=modd`/`MODD` (PrintConv/-n), MIME stays
/// `application/xml` (MODD has no `%mimeType` entry). Bundled
/// `exiftool -j -G1 -struct` is the golden.
#[test]
fn plist_xml_modd_content_conformance() {
  check(
    "plist_synth_xml_modd_content.xml",
    "plist_synth_xml_modd_content.xml.json",
    true,
  );
  check(
    "plist_synth_xml_modd_content.xml",
    "plist_synth_xml_modd_content.xml.n.json",
    false,
  );
}

/// Codex R11 F1 — the `XMLFileType` MODD override is keyed on the EXACT RAW tag
/// ID (PLIST.pm:203 table lookup), NOT the generated tag NAME. The fixture's
/// raw key `xMLFileType` generates the SAME emitted name `XMLFileType` (ucfirst,
/// PLIST.pm:210-212), but its raw ID differs from `XMLFileType`, so the RawConv
/// is absent and NO override fires. Bundled (`.xml` ⇒ `FILE_TYPE eq 'XMP'`)
/// reports `File:FileType=PLIST` with `XML:XMLFileType=ModdXML` — i.e. the name
/// collides while the override does not. The old port checked the generated
/// name and would have wrongly typed this `MODD`.
#[test]
fn plist_xml_xmlfiletype_collide_conformance() {
  check(
    "plist_synth_xml_xmlfiletype_collide.xml",
    "plist_synth_xml_xmlfiletype_collide.xml.json",
    true,
  );
  check(
    "plist_synth_xml_xmlfiletype_collide.xml",
    "plist_synth_xml_xmlfiletype_collide.xml.n.json",
    false,
  );
}

/// Codex R11 F2 — the `%plistType` AAE override (PLIST.pm:42, applied at :225:
/// `OverrideFileType($plistType{$tag})`) keyed on the EXACT RAW tag ID
/// `adjustmentBaseVersion`. The fixture has a `.xml` extension (NO `.aae`), so
/// ExifTool types it `XMP` first (`$$self{FILE_TYPE} eq 'XMP'`) and the override
/// fires: `File:FileType=AAE`, `File:FileTypeExtension=aae`/`AAE` (PrintConv/-n),
/// MIME `application/vnd.apple.photos` (`%mimeType{AAE}`, ExifTool.pm:621). This
/// is an ACTIVE, NON-compressed AAE fixture — distinct from the existing
/// `plist_aae_compressed.aae` (which is typed AAE by its `.aae` extension, not
/// by content). Bundled `exiftool -j -G1 -struct` is the golden.
#[test]
fn plist_xml_aae_override_conformance() {
  check(
    "plist_synth_xml_aae_override.xml",
    "plist_synth_xml_aae_override.xml.json",
    true,
  );
  check(
    "plist_synth_xml_aae_override.xml",
    "plist_synth_xml_aae_override.xml.n.json",
    false,
  );
}

/// Codex R12 F1 — a valid XML plist carrying a leading UTF-8 BOM (`EF BB BF`).
/// Bundled accepts it ONLY through its XMP path: the XMP `%magicNumber`
/// (ExifTool.pm:1045 `…(\xef\xbb\xbf)?…\s*<`) matches the BOM that the PLIST
/// `%magicNumber` (ExifTool.pm:1015 `(bplist0|\s*<|…)`) does NOT, so XMP is the
/// first/only detection candidate; `ProcessXMP` then content-sniffs `<plist>`
/// (XMP.pm:4349 BOM-tolerant `<?xml` + :4385 `<plist[\s>]`), `SetFileType(
/// 'PLIST','application/xml')`, and routes the body to `PLIST::FoundTag`. The
/// oracle yields `File:FileType=PLIST`, `File:MIMEType=application/xml`, and the
/// plist key values for this in-memory BOM plist. Before the fix the port
/// dropped it entirely (Unknown file type / File format error): `parse_inner`
/// only treated ASCII-whitespace-then-`<` as XML, and the engine had no XMP
/// fallback to hand a BOM XML plist to `ProcessPlist`. The fix skips the BOM at
/// the XML gate and routes the BOM-prefixed XML `<plist>` candidate (detected as
/// XMP) to `ProcessPlist`; nested-dict key flattening (`TestDictAuthor`) still
/// works. Bundled `exiftool -j -G1 -struct` is the golden.
#[test]
fn plist_xml_utf8bom_conformance() {
  check(
    "plist_synth_xml_utf8bom.plist",
    "plist_synth_xml_utf8bom.plist.json",
    true,
  );
  check(
    "plist_synth_xml_utf8bom.plist",
    "plist_synth_xml_utf8bom.plist.n.json",
    false,
  );
}

/// Codex R5 F2 — a nested XML `<array>` of SCALARS. `<key>outer</key>` then
/// `<array><array><string>Deep</string></array></array>`: a value event leaves
/// the `@keys` stack untouched (PLIST.pm:200-202), so the deeply nested scalar
/// is stored under the bare `outer` key ID ⇒ `XML:Outer="Deep"`. The prior
/// pass dropped nested arrays (the wildcard arm + `scalar_to_leaf`→None).
#[test]
fn plist_xml_nested_scalar_array_conformance() {
  check(
    "plist_synth_xml_nested_scalar_array.plist",
    "plist_synth_xml_nested_scalar_array.plist.json",
    true,
  );
  check(
    "plist_synth_xml_nested_scalar_array.plist",
    "plist_synth_xml_nested_scalar_array.plist.n.json",
    false,
  );
}

/// Codex R5 F2 — a nested XML `<array>` containing a `<dict>`. Two `<array>`
/// levels each insert an empty key-stack slot (PLIST.pm:191-194), so
/// `<key>top</key>`→array→array→`{inner}` reaches tag ID `top///inner` ⇒
/// `XML:TopInner="Val"`. Confirms the empty-slot accounting recurses through
/// nested arrays, not just the single-array-of-dict case.
#[test]
fn plist_xml_nested_array_of_dict_conformance() {
  check(
    "plist_synth_xml_nested_array_of_dict.plist",
    "plist_synth_xml_nested_array_of_dict.plist.json",
    true,
  );
  check(
    "plist_synth_xml_nested_array_of_dict.plist",
    "plist_synth_xml_nested_array_of_dict.plist.n.json",
    false,
  );
}

/// Codex R6 F2 — a HETEROGENEOUS XML `<array>` (mixed `<dict>` + scalar
/// members). Bundled processes XML as ONE event stream with a single sticky
/// `@keys` stack (PLIST.pm:160-202): a scalar value event NEVER extends
/// `@keys`, so a scalar following a `<dict>` in the same `<array>` inherits the
/// dict's last `<key>` (`<key>top</key>`→array→`{foo→A}`,`B` ⇒ both A and B
/// land at `top//foo`, last-wins `B` under `-struct`), while a scalar BEFORE a
/// dict keeps the array's bare key (`<key>rev</key>`→array→`S`,`{bar→D}` ⇒
/// `Rev="S"` + `RevBar="D"`). The prior tree walker popped the dict key path
/// before the sibling scalar (`Top="B"` / `TopFoo="A"`); the event-stream
/// rework reproduces the sticky state. Bundled `exiftool -j -G1 -struct` golden.
#[test]
fn plist_xml_mixed_array_conformance() {
  check(
    "plist_synth_xml_mixed_array.plist",
    "plist_synth_xml_mixed_array.plist.json",
    true,
  );
  check(
    "plist_synth_xml_mixed_array.plist",
    "plist_synth_xml_mixed_array.plist.n.json",
    false,
  );
}

/// Codex R6 F3 — EMPTY XML containers surface as `XML:<Tag> = ""`. An empty
/// `<dict/>`, `<array/>`, or empty container body fires a value event with the
/// (un-trimmed) raw body string under the current `<key>` (PLIST.pm:200-202 via
/// the XMP parser's no-child-elements value path), rather than being treated as
/// pure structure and dropped. Bundled `exiftool -j -G1 -struct` golden.
#[test]
fn plist_xml_empty_containers_conformance() {
  check(
    "plist_synth_xml_empty_containers.plist",
    "plist_synth_xml_empty_containers.plist.json",
    true,
  );
  check(
    "plist_synth_xml_empty_containers.plist",
    "plist_synth_xml_empty_containers.plist.n.json",
    false,
  );
}

/// Codex R6 F1 — an ARRAY-emitted top-level `XMLFileType` still drives the MODD
/// override. `<key>XMLFileType</key><array><string>ModdXML</string></array>`:
/// the scalar value event does not extend `@keys`, so the EMITTED tag ID is
/// still `XMLFileType` (PLIST.pm:200-202) and its `ModdXML` value fires the
/// `RawConv`→`OverrideFileType('MODD')` (PLIST.pm:133-141). The fixture has a
/// `.xml` extension (FILE_TYPE=XMP) so the override's `eq 'XMP'` guard holds ⇒
/// `File:FileType=MODD`. The prior `is_modd_xml_root` only matched a direct
/// root string; the override is now derived from the event-stream emission.
/// Bundled `exiftool -j -G1 -struct` golden.
#[test]
fn plist_xml_modd_array_conformance() {
  check(
    "plist_synth_xml_modd_array.xml",
    "plist_synth_xml_modd_array.xml.json",
    true,
  );
  check(
    "plist_synth_xml_modd_array.xml",
    "plist_synth_xml_modd_array.xml.n.json",
    false,
  );
}

/// Codex R1 F2 — a binary `<array>` with one member of every scalar shape
/// (`int` / `real` / `string` / `bool` / `data`). PLIST.pm:381-386 keeps
/// every non-`HASH` referenced object, so the list preserves each member's
/// TYPE (`[42,3.5,"hi",false,"(Binary data …)"]`) — not the prior
/// `Vec<String>` flattening that dropped `real` / `data`.
#[test]
fn plist_bin_mixed_array_conformance() {
  check(
    "plist_synth_bin_mixed_array.plist",
    "plist_synth_bin_mixed_array.plist.json",
    true,
  );
  check(
    "plist_synth_bin_mixed_array.plist",
    "plist_synth_bin_mixed_array.plist.n.json",
    false,
  );
}

/// Codex R1 F3 — binary dict keys exercising the binary-only `Tag`-prefix
/// guard (PLIST.pm:364): a key shorter than 2 chars, one starting with a
/// digit, and one starting with `-` are all prefixed `Tag` (`TagX`,
/// `Tag9Abc`, `Tag-Foo`), while a normal key (`Good`) is not. The XML-only
/// `MetaDataList//` / `//name` strips do NOT apply on the binary path.
#[test]
fn plist_bin_tag_prefix_conformance() {
  check(
    "plist_synth_bin_tag_prefix.plist",
    "plist_synth_bin_tag_prefix.plist.json",
    true,
  );
  check(
    "plist_synth_bin_tag_prefix.plist",
    "plist_synth_bin_tag_prefix.plist.n.json",
    false,
  );
}

/// Codex R2 F1 — a binary `<date>` exercises the faithful
/// `ConvertUnixTime(_, 1)` localtime branch (PLIST.pm:277, ExifTool.pm:6794).
/// The port now ports that localtime path (jiff `TimeZone::system()` under
/// `std`); the golden is captured `TZ=UTC` (`tools/gen_golden.sh`), so the
/// test pins the same UTC zone — the `<date>` renders `2021:07:04
/// 03:30:00+00:00` (UTC clock + `TimeZoneString` `+00:00`). The prior port
/// hard-coded `+00:00` regardless of OS TZ; this fixture pins the localtime
/// code path's UTC-host output.
#[test]
fn plist_bin_date_conformance() {
  pin_utc();
  check(
    "plist_synth_bin_date.plist",
    "plist_synth_bin_date.plist.json",
    true,
  );
  check(
    "plist_synth_bin_date.plist",
    "plist_synth_bin_date.plist.n.json",
    false,
  );
}

/// Codex R2 F3 — an XML plist whose dict keys exercise the generic
/// `AddTagToTable` name cleanup (ExifTool.pm:9254): a key shorter than 2
/// chars (`x`), a digit-leading key (`9abc`) and a dash-leading key (`-foo`)
/// are all `Tag`-prefixed on the XML path too (`XML:TagX`, `XML:Tag9Abc`,
/// `XML:Tag-Foo`), while a normal letter-leading key (`good`) is left bare
/// (`XML:Good`). R1 F3 had added the guard to the binary path only; bundled
/// `exiftool -j -G1 -struct` is the golden.
#[test]
fn plist_xml_short_keys_conformance() {
  check(
    "plist_synth_xml_short_keys.plist",
    "plist_synth_xml_short_keys.plist.json",
    true,
  );
  check(
    "plist_synth_xml_short_keys.plist",
    "plist_synth_xml_short_keys.plist.n.json",
    false,
  );
}

/// Codex R2 F4 — a binary `<array>` of `<dict>` elements (the `cast`→array→
/// `{name}` shape). PLIST.pm:347-377 routes each dict member's `key`/`value`
/// pairs through `HandleTag` as a separate `parent/key` tag (`cast/name` ⇒
/// `CastName`, accumulated across the consecutive members into a list), then
/// PLIST.pm:384 `ref ne 'HASH'` drops the dict from the arrayref so the
/// array's own tag is the empty list (`Cast => []`). The prior port dropped
/// the dict children entirely (`value_to_list_leaf` returned `None`);
/// bundled `exiftool -j -G1 -struct` is the golden — emits BOTH
/// `PLIST:CastName` and `PLIST:Cast`.
#[test]
fn plist_bin_array_of_dict_conformance() {
  check(
    "plist_synth_bin_array_of_dict.plist",
    "plist_synth_bin_array_of_dict.plist.json",
    true,
  );
  check(
    "plist_synth_bin_array_of_dict.plist",
    "plist_synth_bin_array_of_dict.plist.n.json",
    false,
  );
}

/// Codex R3 F1 — the `%PLIST::Main` static tag table is consulted by raw tag
/// ID BEFORE dynamic name generation (PLIST.pm:203 / :358). The XML
/// `FoundTag` path inserts an empty key-stack slot per nesting level
/// (PLIST.pm:191-194), so `MetaDataList`→array→`{DateTimeOriginal,Duration,
/// Geolocation/{Latitude,MapDatum}}` reaches the double-slash `MetaDataList//
/// …` static IDs — applying the fixed `Name`, the `DateTimeOriginal`
/// `ValueConv` (days-since-1899 ⇒ `ConvertUnixTime`, mode-independent), the
/// `Duration` `ConvertDuration` `PrintConv` (print-mode only ⇒ `1:02:05` vs
/// raw `3725.0`), and the `GPSLatitude` `ToDMS` `PrintConv` (`-j` DMS string
/// vs `-n` raw float). The prior port generated dynamic `MetaDataList…` names
/// and missed every conversion; bundled `exiftool -j/-n -G1 -struct` is the
/// golden.
#[test]
fn plist_xml_static_table_conformance() {
  check(
    "plist_synth_xml_static_table.plist",
    "plist_synth_xml_static_table.plist.json",
    true,
  );
  check(
    "plist_synth_xml_static_table.plist",
    "plist_synth_xml_static_table.plist.n.json",
    false,
  );
}

/// Codex R3 F1 — the `GPSLongitude` static-table tag, exercising the `ToDMS`
/// hemisphere flip (`E`→`W`) on a negative value (PLIST.pm:89 `ToDMS($self,
/// $val, 1, "E")`). Kept in a fixture WITHOUT a Latitude so the GPS
/// `Composite:GPSPosition` (a global Composite tag, outside the PLIST
/// module's no-`%Composite` scope) does not fire. `-j` ⇒ `122 deg 25' 9.84"
/// W`, `-n` ⇒ raw `-122.4194`.
#[test]
fn plist_xml_gps_longitude_conformance() {
  check(
    "plist_synth_xml_gps_longitude.plist",
    "plist_synth_xml_gps_longitude.plist.json",
    true,
  );
  check(
    "plist_synth_xml_gps_longitude.plist",
    "plist_synth_xml_gps_longitude.plist.n.json",
    false,
  );
}

/// Codex R3 F2 — a binary-plist integer object whose `Get64u` value exceeds
/// `i64::MAX` (`0x8000000000000000`). PLIST.pm:35 reads integers UNSIGNED
/// (`8 => \&Get64u`) and never sign-extends, so bundled emits the unsigned
/// scalar `9223372036854775808`; the prior `as i64` cast wrapped it to
/// `-9223372036854775808`. Bundled `exiftool` is the golden.
#[test]
fn plist_bin_uint64_conformance() {
  check(
    "plist_synth_bin_uint64.plist",
    "plist_synth_bin_uint64.plist.json",
    true,
  );
  check(
    "plist_synth_bin_uint64.plist",
    "plist_synth_bin_uint64.plist.n.json",
    false,
  );
}

/// Codex R3 F3 — a binary `<array>` whose member is itself an `<array>`
/// containing a `<dict>` (`cast=[[{name:"Ann"}]]`). PLIST.pm:381-383 calls
/// `ExtractObject($et,$plistInfo,$parent)` at EVERY array level with the
/// array's `$parent` unchanged, so the nested dict's `key`/`value` pairs
/// STILL route through `HandleTag` as `cast/name` (⇒ `CastName`) BEFORE
/// PLIST.pm:384 `ref ne 'HASH'` drops the dict from the inner arrayref. The
/// R2/F4 fix only recursed into IMMEDIATE-member dicts; a dict one array level
/// deeper was dropped by `value_to_list_leaf`. Bundled emits BOTH
/// `PLIST:CastName="Ann"` and `PLIST:Cast=[[]]`.
#[test]
fn plist_bin_nested_array_dict_conformance() {
  check(
    "plist_synth_bin_nested_array_dict.plist",
    "plist_synth_bin_nested_array_dict.plist.json",
    true,
  );
  check(
    "plist_synth_bin_nested_array_dict.plist",
    "plist_synth_bin_nested_array_dict.plist.n.json",
    false,
  );
}

/// Codex R3 F4 — a binary `<date>` with a FRACTIONAL second (0.6 s past the
/// Apple epoch). `ConvertUnixTime` (ExifTool.pm:6780-6786) ROUNDS the
/// fraction (`sprintf('%.0f',$frac)` with the default `dec=0` + the
/// leading-`1` carry), so 0.6 s ⇒ `2001:01:01 00:00:01`; the prior port
/// `trunc()`'d ⇒ `…00:00:00`. `TZ=UTC`-pinned (`pin_utc`) for a
/// host-independent `+00:00` offset. Bundled `exiftool` is the golden.
#[test]
fn plist_bin_frac_date_conformance() {
  pin_utc();
  check(
    "plist_synth_bin_frac_date.plist",
    "plist_synth_bin_frac_date.plist.json",
    true,
  );
  check(
    "plist_synth_bin_frac_date.plist",
    "plist_synth_bin_frac_date.plist.n.json",
    false,
  );
}

/// Codex R4 F1 — a binary `<date>` with an EXACT half-second fraction. Perl's
/// `sprintf('%.0f', $frac)` (ExifTool.pm:6783) rounds half-to-EVEN, so an
/// exact `.5` does NOT carry: `apple=0.5` ⇒ `2001:01:01 00:00:00`. The prior
/// port used `f64::round()` (half-AWAY-from-zero) which mis-rounded this to
/// `…00:00:01`. `TZ=UTC`-pinned; bundled `exiftool` is the golden
/// (`ConvertUnixTime(0.5 + 11323*24*3600, 1)` ⇒ `2001:01:01 00:00:00+00:00`).
#[test]
fn plist_bin_halfeven_date_half_conformance() {
  pin_utc();
  check(
    "plist_synth_bin_halfeven_date_half.plist",
    "plist_synth_bin_halfeven_date_half.plist.json",
    true,
  );
  check(
    "plist_synth_bin_halfeven_date_half.plist",
    "plist_synth_bin_halfeven_date_half.plist.n.json",
    false,
  );
}

/// Codex R4 F1 — a binary `<date>` just PAST the half-second tie
/// (`apple=0.5000001`), which DOES round up to `2001:01:01 00:00:01`. Pairs
/// with the exact-tie case to pin both sides of the half-to-even boundary.
#[test]
fn plist_bin_halfeven_date_halfup_conformance() {
  pin_utc();
  check(
    "plist_synth_bin_halfeven_date_halfup.plist",
    "plist_synth_bin_halfeven_date_halfup.plist.json",
    true,
  );
  check(
    "plist_synth_bin_halfeven_date_halfup.plist",
    "plist_synth_bin_halfeven_date_halfup.plist.n.json",
    false,
  );
}

/// Codex R4 F1 — a binary `<date>` with a NEGATIVE half-second fraction
/// (`apple=-0.5`). ExifTool.pm:6782 folds the negative fraction into `[0,1)`
/// by borrowing a second (true floor), then half-to-even leaves `…:00` (no
/// carry) ⇒ one second before the epoch, `2000:12:31 23:59:59`.
#[test]
fn plist_bin_halfeven_date_neghalf_conformance() {
  pin_utc();
  check(
    "plist_synth_bin_halfeven_date_neghalf.plist",
    "plist_synth_bin_halfeven_date_neghalf.plist.json",
    true,
  );
  check(
    "plist_synth_bin_halfeven_date_neghalf.plist",
    "plist_synth_bin_halfeven_date_neghalf.plist.n.json",
    false,
  );
}

/// Codex R4 F2 — an XML MODD `DateTimeOriginal` with a POSITIVE fractional
/// day (`25569 + 0.6/86400`). PLIST.pm:73 `ConvertUnixTime(($val - 25569) *
/// 24 * 3600)` is applied to the FLOAT; the prior port truncated to an i64
/// first, dropping the fraction (and mis-firing the `$time == 0` sentinel for
/// sub-second values). Bundled `exiftool` ⇒ `1970:01:01 00:00:01`.
#[test]
fn plist_xml_frac_dto_pos_conformance() {
  pin_utc();
  check(
    "plist_synth_xml_frac_dto_pos.plist",
    "plist_synth_xml_frac_dto_pos.plist.json",
    true,
  );
  check(
    "plist_synth_xml_frac_dto_pos.plist",
    "plist_synth_xml_frac_dto_pos.plist.n.json",
    false,
  );
}

/// Codex R4 F2 — an XML MODD `DateTimeOriginal` whose fractional day lands at
/// the half-second (`25569 + 0.5/86400`; the IEEE-754 value is ~0.5000001 s,
/// not a true tie, so it rounds UP) ⇒ `1970:01:01 00:00:01`.
#[test]
fn plist_xml_frac_dto_half_conformance() {
  pin_utc();
  check(
    "plist_synth_xml_frac_dto_half.plist",
    "plist_synth_xml_frac_dto_half.plist.json",
    true,
  );
  check(
    "plist_synth_xml_frac_dto_half.plist",
    "plist_synth_xml_frac_dto_half.plist.n.json",
    false,
  );
}

/// Codex R4 F2 — an XML MODD `DateTimeOriginal` with a NEGATIVE fractional
/// day (`25569 - 0.6/86400`). The float is `-0.5999998888` s; ExifTool floors
/// to `$itime = -1` and rounds the folded fraction ⇒ `1969:12:31 23:59:59`.
#[test]
fn plist_xml_frac_dto_neg_conformance() {
  pin_utc();
  check(
    "plist_synth_xml_frac_dto_neg.plist",
    "plist_synth_xml_frac_dto_neg.plist.json",
    true,
  );
  check(
    "plist_synth_xml_frac_dto_neg.plist",
    "plist_synth_xml_frac_dto_neg.plist.n.json",
    false,
  );
}

/// Codex R20 F1 — AAE `adjustmentData` `CompressedPLIST` sub-directory.
///
/// An AAE file's `adjustmentData` key carries a (potentially raw-DEFLATE-
/// compressed) binary PLIST payload — bundled `PLIST.pm:142-146`
/// `CompressedPLIST => 1` + `SubDirectory => { TagTable => 'PLIST::Main' }`.
/// `FoundTag` (PLIST.pm:228-241) skips inflate when the payload is already
/// `bplist00`-prefixed (`$$val !~ /^bplist00/`), otherwise inflates via
/// `IO::Uncompress::RawInflate::rawinflate`. The inflated/raw bytes re-enter
/// `ProcessBinaryPLIST`, whose `SET_GROUP1='PLIST'` (PLIST.pm:484) scopes the
/// resulting tags into the family-1 `PLIST` group even when the outer XML
/// plist's siblings remain under `XML`.
///
/// This fixture's payload IS already `bplist00`-prefixed (the AAE
/// `SlowMotionRegions*` family); the port hits the bundled short-circuit and
/// dispatches the embedded binary plist via [`process_compressed_plist`]
/// without engaging `miniz_oxide`'s inflate path. The dep is still wired for
/// the truly-DEFLATE'd class (an AAE producer that compresses); the
/// PLIST.pm:228 short-circuit keeps the no-inflate path byte-identical to
/// bundled. Class-sweep verified — `adjustmentData` is the SOLE
/// `CompressedPLIST => 1` entry in `%PLIST::Main`
/// (`rg -n 'CompressedPLIST' PLIST.pm` = 2 matches, both this entry).
#[test]
fn plist_aae_compressed_conformance() {
  check(
    "plist_aae_compressed.aae",
    "plist_aae_compressed.aae.json",
    true,
  );
  check(
    "plist_aae_compressed.aae",
    "plist_aae_compressed.aae.n.json",
    false,
  );
}

/// Codex R20 F2 — legacy UCS-2BE PLIST recognition arm (PLIST.pm:494-499).
///
/// A `.plist` file whose body begins `\xfe\xff\x00` (BOM + first-char-NUL —
/// `$$et{FILE_EXT} eq 'PLIST'` + `$$dataPt =~ /^\xfe\xff\x00/`) is recognized
/// by `ProcessPLIST` as a legacy UCS-2BE-encoded plist. Bundled emits
/// `$et->Error('Old PLIST format currently not supported')` (PLIST.pm:498)
/// then `$result = 1` (PLIST.pm:499) — the Error is family-0 (the bundled
/// call sits OUTSIDE the binary-PLIST `SET_GROUP1='PLIST'` scope at :484), so
/// the JSON renders `ExifTool:Error` with NO `File:FileType` triplet
/// (the UCS-2BE branch never calls `SetFileType`). The port routes this at
/// the [`finalization_error`] seam (`src/parser.rs`): `ProcessPlist::parse`
/// rejects the body (neither `bplist0` nor `<`), every other candidate fails
/// the actual decode, and finalization short-circuits the `File format error`
/// arm to bundled's exact wording. Class-sweep verified — UCS-2BE is the
/// only XML-encoding recognition special case after UTF-8 BOM
/// (`rg -n 'FILE_EXT|encoding|BOM|UTF|UCS' PLIST.pm` = the UTF-8 charset
/// decode at :186 + the UCS-2BE-string binary type-6 at :308-311 + this
/// recognition arm; JSON branch is separate, handled at PLIST.pm:490-493).
#[test]
fn plist_ucs2be_legacy_conformance() {
  check(
    "plist_synth_ucs2be_legacy.plist",
    "plist_synth_ucs2be_legacy.plist.json",
    true,
  );
  check(
    "plist_synth_ucs2be_legacy.plist",
    "plist_synth_ucs2be_legacy.plist.n.json",
    false,
  );
}

/// Codex R20 F3 — binary dict CONSECUTIVE-duplicate-key list-fold
/// (PLIST.pm:362-378). A binary `<dict>` whose `[(key, value)…]` sequence has
/// adjacent same-key emissions accumulates them into one `List => 1` arrayref
/// via `LastPListTag` / `LIST_TAGS` (PLIST.pm:373-376), but the prior port's
/// `walk_tree` Dict branch emitted children straight into `out` — TagMap's
/// last-wins-by-name then silently discarded the first value. The fix runs
/// the dict-level emissions through a scratch buffer + `fold_consecutive
/// _lists`, so a root binary dict `{ a: v1, a: v2, b: v3 }` emits
/// `PLIST:TagA=[v1, v2], PLIST:TagB=v3` (matches the oracle).
#[test]
fn plist_bin_dup_consec_conformance() {
  check(
    "plist_synth_bin_dup_consec.plist",
    "plist_synth_bin_dup_consec.plist.json",
    true,
  );
  check(
    "plist_synth_bin_dup_consec.plist",
    "plist_synth_bin_dup_consec.plist.n.json",
    false,
  );
}

/// Codex R20 F3 (class-sweep) — consecutive-duplicate list-fold inside a
/// NESTED binary dict. Class-sweep proof that the dict-level fold applies at
/// EVERY nesting level: an outer dict `{ x: { a: v1, a: v2 }, b: v3 }` must
/// emit `PLIST:XA=[v1, v2], PLIST:TagB=v3` — the inner dict's consecutive
/// `a, a` pair folds at the inner level, the outer dict has nothing else
/// adjacent to fold. The scratch+fold is applied to EVERY [`PlistValue::Dict`]
/// in the binary-plist walker; dicts nested inside arrays already had this via
/// the array branch's `child_scratch` (Codex R2 F4), so the class is fully
/// covered.
#[test]
fn plist_bin_dup_nested_conformance() {
  check(
    "plist_synth_bin_dup_nested.plist",
    "plist_synth_bin_dup_nested.plist.json",
    true,
  );
  check(
    "plist_synth_bin_dup_nested.plist",
    "plist_synth_bin_dup_nested.plist.n.json",
    false,
  );
}

/// Codex R20 F3 (negative case) — NON-consecutive same-name duplicates do NOT
/// fold. Bundled's `LastPListTag` / `LIST_TAGS` run-break (PLIST.pm:373-375)
/// drops the accumulator when the next emission is a different tagInfo; a
/// later re-emission of the original tag DOES NOT resume the run. With
/// dynamic-name `List => 1` tags, the second same-name `HandleTag` then
/// REPLACES the prior value (oracle behavior: a root dict
/// `{ a: v1, b: v2, a: v3 }` ⇒ `PLIST:TagA=v3, PLIST:TagB=v2`). The port
/// matches via TagMap's last-wins-in-place insert — `fold_consecutive_lists`
/// is a no-op for non-adjacent same-name pairs, so the second `TagA`
/// emission overwrites the first.
#[test]
fn plist_bin_dup_nonconsec_conformance() {
  check(
    "plist_synth_bin_dup_nonconsec.plist",
    "plist_synth_bin_dup_nonconsec.plist.json",
    true,
  );
  check(
    "plist_synth_bin_dup_nonconsec.plist",
    "plist_synth_bin_dup_nonconsec.plist.n.json",
    false,
  );
}

/// Codex R7 F1 — a binary-plist type-8 UID whose byte width `%readProc` does
/// NOT cover (5/9 bytes) is rendered as a full `0x…` lower-hex string of ALL
/// its bytes (PLIST.pm:290 `"0x" . unpack 'H*', $buff`). The fixtures carry a
/// 5-byte UID `11 22 33 44 55` ⇒ `PLIST:Uid="0x1122334455"` and a 9-byte UID
/// `11..99` ⇒ `"0x112233445566778899"`.
#[test]
fn plist_bin_uid5_conformance() {
  check(
    "plist_synth_bin_uid5.plist",
    "plist_synth_bin_uid5.plist.json",
    true,
  );
  check(
    "plist_synth_bin_uid5.plist",
    "plist_synth_bin_uid5.plist.n.json",
    false,
  );
}

#[test]
fn plist_bin_uid9_conformance() {
  check(
    "plist_synth_bin_uid9.plist",
    "plist_synth_bin_uid9.plist.json",
    true,
  );
  check(
    "plist_synth_bin_uid9.plist",
    "plist_synth_bin_uid9.plist.n.json",
    false,
  );
}

/// Codex R7 F1 — a 16-byte type-8 UID is rendered as an ASF GUID via
/// `Image::ExifTool::ASF::GetGUID` (PLIST.pm:286-288, ASF.pm:525-533): the
/// first 4/2/2-byte fields are byte-reversed (`VvvNN`→`NnnNN`) and the result
/// is hex-formatted `8-4-4-4-12` upper-case. The fixture's UID bytes
/// `00 11 22 … FF` ⇒ `PLIST:Uid="33221100-5544-7766-8899-AABBCCDDEEFF"`.
#[test]
fn plist_bin_uid16_conformance() {
  check(
    "plist_synth_bin_uid16.plist",
    "plist_synth_bin_uid16.plist.json",
    true,
  );
  check(
    "plist_synth_bin_uid16.plist",
    "plist_synth_bin_uid16.plist.n.json",
    false,
  );
}

/// Codex R7 F2 — a leading XML comment containing a complete fake
/// `<plist>…</plist>` must NOT shadow the real root: the token-aware tag
/// scan (`next_markup`) skips the comment, so only the real
/// `<key>Real</key>` is extracted (`XML:Real="RealValue"`; the `Fake` tag
/// never appears).
#[test]
fn plist_xml_comment_fake_root_conformance() {
  check(
    "plist_synth_xml_comment_fake_root.plist",
    "plist_synth_xml_comment_fake_root.plist.json",
    true,
  );
  check(
    "plist_synth_xml_comment_fake_root.plist",
    "plist_synth_xml_comment_fake_root.plist.n.json",
    false,
  );
}

/// Codex R7 F2 — a `<!-- <array> … </array> -->` comment INSIDE an `<array>`
/// must not move the nesting depth: `match_close_offset` token-skips the
/// comment, so the real `</array>` is matched and the sibling
/// `<key>After</key>` is still parsed (`XML:Items="beta"`,
/// `XML:After="tail"`).
#[test]
fn plist_xml_comment_in_container_conformance() {
  check(
    "plist_synth_xml_comment_in_container.plist",
    "plist_synth_xml_comment_in_container.plist.json",
    true,
  );
  check(
    "plist_synth_xml_comment_in_container.plist",
    "plist_synth_xml_comment_in_container.plist.n.json",
    false,
  );
}

/// Codex R8 F1 — an XML comment INSIDE a scalar value must NOT leak into the
/// emitted value. XMP.pm:3847 sets `$wasComment` when the close-scan crosses
/// a comment; XMP.pm:4181 then strips `<!--…-->` from the leaf value before
/// `&$foundProc`. So `<string>foo<!-- <array/> -->bar</string>` decodes to
/// `foobar` (the comment text is dropped). Bundled `exiftool -j -G1 -struct`
/// golden — `XML:Title="foobar"`.
#[test]
fn plist_xml_scalar_comment_conformance() {
  check(
    "plist_synth_xml_scalar_comment.plist",
    "plist_synth_xml_scalar_comment.plist.json",
    true,
  );
  check(
    "plist_synth_xml_scalar_comment.plist",
    "plist_synth_xml_scalar_comment.plist.n.json",
    false,
  );
}

/// Codex R8 F2 — a whitespace-wrapped `<data>` payload picks the Base64
/// branch, not hex. PLIST.pm:172 tests the unescaped value DIRECTLY with
/// `/^[0-9a-f]+$/` (no whitespace removal), so `<data> 48656c6c6f </data>`
/// FAILS the lower-hex test (leading/trailing spaces) and falls through to
/// `DecodeBase64` (PLIST.pm:177-178) — yielding a 7-byte payload, NOT the
/// 5-byte hex decode of `Hello`. Bundled `exiftool -j -G1 -struct` golden.
#[test]
fn plist_xml_data_ws_hex_conformance() {
  check(
    "plist_synth_xml_data_ws_hex.plist",
    "plist_synth_xml_data_ws_hex.plist.json",
    true,
  );
  check(
    "plist_synth_xml_data_ws_hex.plist",
    "plist_synth_xml_data_ws_hex.plist.n.json",
    false,
  );
}

/// Codex R8 F3 — the slowMotion `*Flags` tags carry a BITMASK `PrintConv`
/// (PLIST.pm:98-104 / :111-117). `DecodeBits` (ExifTool.pm:6374) prints set
/// bits 0-4 as `Valid` / `Has been rounded` / `Positive infinity` /
/// `Negative infinity` / `Indefinite`, joined with `, `. `flags=1` ⇒
/// `Valid`; `flags=3` ⇒ `Valid, Has been rounded`. The `-n` snapshot shows
/// the raw integers. Bundled `exiftool -j -G1 -struct` golden.
#[test]
fn plist_xml_slowmotion_flags_conformance() {
  check(
    "plist_synth_xml_slowmotion_flags.plist",
    "plist_synth_xml_slowmotion_flags.plist.json",
    true,
  );
  check(
    "plist_synth_xml_slowmotion_flags.plist",
    "plist_synth_xml_slowmotion_flags.plist.n.json",
    false,
  );
}

/// Codex R9 F1 — XMP.pm:4181 strips inline comments from a leaf via
/// `$val =~ s/<!--.*?-->//g`, a substitution with NO `/s` modifier. Perl's
/// regex `.` therefore does NOT match a newline: a `<!--…-->` run whose span
/// crosses a newline is left VERBATIM, while a single-line run is removed.
/// The fixture exercises both in a `<string>` value (`foo<!--\n…\n-->bar`
/// preserved, `aaa<!-- one line -->bbb` ⇒ `aaabbb`) AND in a `<key>` name
/// (`k<!--\n…\n-->ey` survives comment-stripping, then the auto-name cleanup
/// drops the illegal `<`/`!`/`>`/`\n` ⇒ `K--Mlkey--Ey`). Bundled
/// `exiftool -j -G1 -struct` golden.
#[test]
fn plist_xml_multiline_comment_conformance() {
  check(
    "plist_synth_xml_multiline_comment.plist",
    "plist_synth_xml_multiline_comment.plist.json",
    true,
  );
  check(
    "plist_synth_xml_multiline_comment.plist",
    "plist_synth_xml_multiline_comment.plist.n.json",
    false,
  );
}

/// Codex R9 F2 — the slowMotion `*Flags` BITMASK `PrintConv` runs `DecodeBits`
/// (ExifTool.pm:6374) over the scalar leaf REGARDLESS of XML plist leaf type.
/// `split ' ', $vals` then numifies each word the Perl way, so a `<string>`
/// flags value is decoded just like an `<integer>`: `<string>3</string>` ⇒
/// `Valid, Has been rounded`; `<string>abc</string>` numifies to 0 ⇒
/// `(none)`. The `-n` snapshot keeps the raw leaf (`3` / `abc`). Bundled
/// `exiftool -j -G1 -struct` golden.
#[test]
fn plist_xml_slowmotion_flags_string_conformance() {
  check(
    "plist_synth_xml_slowmotion_flags_string.plist",
    "plist_synth_xml_slowmotion_flags_string.plist.json",
    true,
  );
  check(
    "plist_synth_xml_slowmotion_flags_string.plist",
    "plist_synth_xml_slowmotion_flags_string.plist.n.json",
    false,
  );
}

/// Codex R10 F1 — XMP.pm:4181 `s/<!--.*?-->//g` strips an inline comment
/// from a leaf. The port walks `<!--…-->` candidates one BYTE at a time;
/// a non-ASCII char inside an inline single-line comment (`Ti<!-- café
/// -->tle` in a `<key>`, `foo<!-- résumé -->bar` in a `<string>`) used to
/// make a `str` slice land mid-UTF-8-char and PANIC. The scan is now
/// byte-only — both comments are stripped, the `<key>` becomes `Title`
/// (PLIST.pm:188 Tag-prefix normalization) and `XML:Title` ⇒ `foobar`.
/// Bundled `exiftool -j -G1 -struct` golden.
#[test]
fn plist_xml_comment_non_ascii_conformance() {
  check(
    "plist_synth_xml_comment_non_ascii.plist",
    "plist_synth_xml_comment_non_ascii.plist.json",
    true,
  );
  check(
    "plist_synth_xml_comment_non_ascii.plist",
    "plist_synth_xml_comment_non_ascii.plist.n.json",
    false,
  );
}

/// Codex R10 F2 — the slowMotion `*Flags` `DecodeBits` (ExifTool.pm:6379
/// `$val & (1 << $i)`) numifies each `split ' '` word the way Perl's `&`
/// does: a numeric prefix WITH an exponent. `<string>1e2</string>` numifies
/// to 100 (bits 2,5,6 ⇒ `Positive infinity, [5], [6]`), NOT `1` as a
/// digit-only scan would give; `<string>-1e2</string>` ⇒ -100 ⇒ low-32
/// `0xFFFFFF9C`. The `-n` snapshot keeps the raw leaf (`1e2` / `-1e2`).
/// Bundled `exiftool -j -G1 -struct` golden.
#[test]
fn plist_xml_slowmotion_flags_exponent_conformance() {
  check(
    "plist_synth_xml_slowmotion_flags_exponent.plist",
    "plist_synth_xml_slowmotion_flags_exponent.plist.json",
    true,
  );
  check(
    "plist_synth_xml_slowmotion_flags_exponent.plist",
    "plist_synth_xml_slowmotion_flags_exponent.plist.n.json",
    false,
  );
}

/// Codex R10 F2 — a slowMotion `*Flags` word that overflows the integer
/// types. `<string>18446744073709551615</string>` (`u64::MAX`) stays EXACT
/// through Perl's UV — `&` sees every low-32 bit set (all five names +
/// `[5]`..`[31]`), where an `i64`-only parse would overflow to `0` ⇒
/// `(none)`. `<string>9e99</string>` overflows to a double whose `&`
/// saturates the UV high to all-ones — same all-bits decode. The `-n`
/// snapshot keeps the raw leaf. Bundled `exiftool -j -G1 -struct` golden.
#[test]
fn plist_xml_slowmotion_flags_overflow_conformance() {
  check(
    "plist_synth_xml_slowmotion_flags_overflow.plist",
    "plist_synth_xml_slowmotion_flags_overflow.plist.json",
    true,
  );
  check(
    "plist_synth_xml_slowmotion_flags_overflow.plist",
    "plist_synth_xml_slowmotion_flags_overflow.plist.n.json",
    false,
  );
}

/// Codex R15 F1 — a binary type-4 `data` object AT the 1 000 000-byte
/// threshold. PLIST.pm:300 (`if ($size < 1000000 or $et->Options('Binary'))`)
/// reads the payload only for `$size < 1000000`; AT `1000000` (and without
/// `-b`) PLIST.pm:302-303 stores the literal `"Binary data $size bytes"`
/// placeholder and never `$raf->Read`s the bytes — note the `else` branch is
/// also NOT bounds-checked, so the fixture can claim 1 000 000 bytes while
/// being only 57 bytes long. The default JSON path renders the placeholder
/// `(Binary data 1000000 bytes, use -b option to extract)` reporting the TRUE
/// size (the `exiftool` script wraps the PLIST.pm-stored scalar verbatim,
/// exiftool:3983-3984). The port now stores a length-only `PlistLeaf::DataLen`
/// — never copying the multi-MB payload. Bundled `exiftool -j -G1 -struct`
/// golden; identical in `-n`.
#[test]
fn plist_bin_data_boundary_conformance() {
  check(
    "plist_synth_bin_data_boundary.plist",
    "plist_synth_bin_data_boundary.plist.json",
    true,
  );
  check(
    "plist_synth_bin_data_boundary.plist",
    "plist_synth_bin_data_boundary.plist.n.json",
    false,
  );
}

/// Codex R15 F1 — a binary type-4 `data` object ABOVE the 1 000 000-byte
/// threshold (claims 2 000 000 bytes). Same PLIST.pm:300-303 placeholder path
/// as the boundary case: `$size >= 1000000` ⇒ the length-only
/// `"Binary data 2000000 bytes"` scalar, no `$raf->Read`. The pre-fix port
/// always sliced `dec.data.get(cursor..end)?` and `.to_vec()`'d the payload —
/// for this truncated fixture that slice is out of range, so the pre-fix code
/// also DROPPED the tag; the fix both avoids the copy AND mirrors bundled's
/// no-bounds-check `else` branch ⇒ `PLIST:Blob = (Binary data 2000000 bytes,
/// use -b option to extract)`. Bundled `exiftool -j -G1 -struct` golden;
/// identical in `-n`.
#[test]
fn plist_bin_data_oversize_conformance() {
  check(
    "plist_synth_bin_data_oversize.plist",
    "plist_synth_bin_data_oversize.plist.json",
    true,
  );
  check(
    "plist_synth_bin_data_oversize.plist",
    "plist_synth_bin_data_oversize.plist.n.json",
    false,
  );
}

/// Codex R17 F1 — an XML `<real>` carrying a NON-FINITE word (`inf`, `-inf`,
/// `nan`). PLIST.pm's XML path (`FoundTag`, PLIST.pm:171-198) routes `<real>`
/// into the final `else` branch (PLIST.pm:184-186 `$val = $et->Decode($val,
/// 'UTF8')`) — a charset decode only, with NO numeric type-parse: the
/// UNESCAPED scalar text is stored verbatim. The pre-fix port `parse::<f64>()`'d
/// the body, so `<real>inf</real>` became a non-finite `f64` and serialized as
/// the titlecase Perl-NV string `Inf` / `-Inf` / `NaN` — a VALUE change vs the
/// oracle's verbatim lowercase `"inf"` / `"-inf"` / `"nan"` (standard plist
/// writers emit lowercase for a non-finite float, so this is real input). The
/// fix stores `PlistValue::Str` and never type-parses on the XML path ⇒
/// `XML:RealInf="inf"`, `XML:RealNegInf="-inf"`, `XML:RealNan="nan"`,
/// identical for `-j` and `-n`. Bundled `exiftool -j -G1 -struct` is the
/// golden.
#[test]
fn plist_xml_real_nonfinite_conformance() {
  check(
    "plist_synth_xml_real_nonfinite.plist",
    "plist_synth_xml_real_nonfinite.plist.json",
    true,
  );
  check(
    "plist_synth_xml_real_nonfinite.plist",
    "plist_synth_xml_real_nonfinite.plist.n.json",
    false,
  );
}

/// Codex R17 F1 (class-sweep) — XML `<real>` / `<integer>` raw-text fidelity.
/// PLIST.pm's XML path never canonicalizes a numeric leaf (PLIST.pm:184-186),
/// so a trailing zero (`<real>1.50</real>`), an exponent form (`<real>1.4e2
/// </real>`), a whitespace-wrapped body (`<real> 3.0 </real>`), a leading zero
/// (`<integer>007</integer>`) and a hex-looking value (`<integer>0x10
/// </integer>`) are all stored as the verbatim scalar. The pre-fix port's
/// `.trim().parse::<f64>()` / `parse::<i64>()` discarded the trailing zero
/// (`1.50`→`1.5`), stripped the surrounding whitespace AND re-spelled the
/// number (`" 3.0 "`→`3`); `007` happened to survive only because `i64` parse
/// re-stringified it back — but `0x10` failed the parse and was already a
/// string. After the fix every XML numeric leaf is `PlistValue::Str`: the
/// value-semantic JSON comparator matches a numeric-shaped string against the
/// oracle's bare-number token (`"1.50"` ≈ `1.50`, `"1.4e2"` ≈ `1.4e2`) while a
/// non-JSON-numeric value (`"007"`, `"0x10"`, `" 3.0 "`) stays a quoted string
/// both sides. Bundled `exiftool -j -G1 -struct` is the golden.
#[test]
fn plist_xml_integer_real_raw_conformance() {
  check(
    "plist_synth_xml_integer_real_raw.plist",
    "plist_synth_xml_integer_real_raw.plist.json",
    true,
  );
  check(
    "plist_synth_xml_integer_real_raw.plist",
    "plist_synth_xml_integer_real_raw.plist.n.json",
    false,
  );
}

/// Codex R17 F1 (XML-leaf class-sweep) — an XML `<date>` body reaches
/// `ConvertXMPDate` whitespace-VERBATIM. PLIST.pm:180-181 calls
/// `ConvertXMPDate($val)` on the raw unescaped scalar, and the XMP read-path
/// that feeds `FoundTag` only trims (`s/^\s+//;s/\s+$//`) for an
/// `rdf:Description` prop (XMP.pm:4178-4181) — a plist `<date>` prop is never
/// `rdf:Description`, so no trim runs. `ConvertXMPDate`'s rewrite regex
/// `^(\d{4})-…$` is anchored: a clean body (`<date>2013-02-22T12:49:10Z</date>`)
/// matches and is rewritten to EXIF form (`2013:02:22 12:49:10Z`), but a
/// leading/trailing-whitespace body (`<date> … </date>`, `<date>\n…\n</date>`)
/// FAILS the match and passes through UNCHANGED with separators intact. The
/// pre-fix port did `convert_xmp_date(unescape_xml(inner).trim())` — the extra
/// `.trim()` made the whitespace forms match, emitting `"2013:02:22 …"` and
/// changing the VALUE. The fix drops the `.trim()` ⇒ `XML:DateWs` /
/// `XML:DateNl` keep their verbatim whitespace and raw `-`/`T` separators,
/// only `XML:DateClean` is rewritten. Bundled `exiftool -j -G1 -struct` is the
/// golden.
#[test]
fn plist_xml_date_raw_conformance() {
  check(
    "plist_synth_xml_date_raw.plist",
    "plist_synth_xml_date_raw.plist.json",
    true,
  );
  check(
    "plist_synth_xml_date_raw.plist",
    "plist_synth_xml_date_raw.plist.n.json",
    false,
  );
}

#[test]
fn wavpack_conformance() {
  // FORMATS.md row 6. Native `wvpk....` 32-byte header (no RIFF wrapper,
  // no ID3, no APE) ⇒ ProcessWV runs the WavPack::Main ProcessBinaryData
  // step (5 masked sub-tags) and the post-PBD `ProcessRIFF`/`ProcessAPE`
  // calls (WavPack.pm:97-102) emit nothing — see the orchestrator-scoped
  // deferral note in `src/formats/wavpack.rs`. Goldens captured from
  // bundled `perl exiftool`.
  check("WavPack.wv", "WavPack.wv.json", true);
  check("WavPack.wv", "WavPack.wv.n.json", false);
}

#[test]
fn wavpack_adversarial_conformance() {
  // Flags = 0xFFFFFFFF: every mask saturates ⇒ exercises the off-end of
  // every PrintConv hash (SampleRate index 15 = 'Custom' is the only
  // non-numeric entry; BytesPerSample raw=3 ⇒ +1 = 4 = the largest
  // ValueConv output). Pins that the byte-order (MM) and the mask /
  // shift derivation stay faithful even with every bit set.
  check(
    "WavPack_adversarial.wv",
    "WavPack_adversarial.wv.json",
    true,
  );
  check(
    "WavPack_adversarial.wv",
    "WavPack_adversarial.wv.n.json",
    false,
  );
}

#[test]
fn dsf_conformance() {
  // FORMATS.md row 7. Faithful DSF.pm port (1:1 of ExifTool 13.58
  // lib/Image/ExifTool/DSF.pm:55-99). The fixture is a synthesized minimal
  // valid DSF (no bundled `t/images/DSF.dsf`); see plan §3.1 for layout.
  check("DSF.dsf", "DSF.dsf.json", true);
  check("DSF.dsf", "DSF.dsf.n.json", false);
}

#[test]
fn dsf_short_fmt_warning_conformance() {
  // Pins DSF.pm:71-72 Warn + `return 1`: a DSF whose `fmtLen` violates the
  // `>12 && <1000` guard (here `fmtLen=8`) still emits File:* via
  // `SetFileType` (DSF.pm:64 runs BEFORE the guard, DSF.pm:67) plus the
  // ExifTool:Warning, and NO fmt-chunk payload tags.
  check("DSF_short.dsf", "DSF_short.dsf.json", true);
  check("DSF_short.dsf", "DSF_short.dsf.n.json", false);
}

#[test]
fn dv_conformance() {
  // FORMATS.md row 11. `tests/fixtures/DV.dv` is the bundled
  // `lib/Image/ExifTool/t/images/DV.dv` (4400 bytes, PAL 25Mbps 4:2:0,
  // 16:9 aspect, interlaced, 32 kHz audio). Goldens are bundled `perl
  // exiftool -j -G1 -struct` output with `System:*` and `Composite:*`
  // stripped uniformly (matching every other format conformance — the
  // composite-tag system is engine infrastructure outside DV.pm's
  // scope, deferred per `[[exifast-phase2-forward-items]]`).
  check("DV.dv", "DV.dv.json", true);
  check("DV.dv", "DV.dv.n.json", false);
}

#[test]
fn real_rm_conformance() {
  // FORMATS.md row 19. `tests/fixtures/Real.rm` is the bundled
  // `lib/Image/ExifTool/t/images/Real.rm` (1915 bytes). Exercises the
  // RealMedia chunk walk (PROP / MDPR×2 / CONT), the RJMD footer
  // metadata block, and the 128-byte ID3v1 trailer. The golden is bundled
  // `perl exiftool -j -G1 -struct` output with `System:*` + `Composite:*`
  // stripped uniformly (composite-tag synthesis is engine infrastructure
  // outside Real.pm's scope — deferred per `[[exifast-phase2-forward-items]]`;
  // bundled emits one Composite:DateTimeOriginal=2003 lifted from the
  // ID3v1:Year frame).
  check("Real.rm", "Real.rm.json", true);
  check("Real.rm", "Real.rm.n.json", false);
}

#[test]
fn real_ra_conformance() {
  // FORMATS.md row 19. `tests/fixtures/Real.ra` is the bundled
  // `lib/Image/ExifTool/t/images/Real.ra` (130 bytes, RealAudio V4).
  // Exercises the `.ra\xfd` magic, the V4 codec table (AudioBytes /
  // BytesPerMinute / AudioFrameSize / SampleRate / BitsPerSample /
  // Channels / Title / Copyright; the file has no Artist or Comment).
  // Goldens captured the same way as RM.
  check("Real.ra", "Real.ra.json", true);
  check("Real.ra", "Real.ra.n.json", false);
}

#[test]
fn real_synth_1audio_conformance() {
  // Codex R1 F1 adversarial — pinpoints the bundled `File:MIMEType`
  // override (Real.pm:653-657) for a 1-stream RM whose sole MDPR
  // carries `audio/x-pn-realaudio`. Bundled OVERRIDES the table-derived
  // `application/vnd.rn-realmedia` with the stream MIME (exactly the
  // override case that fires); this Rust port must agree.
  // Synthesized fixture (RMF header + PROP + 1 MDPR + DATA terminator);
  // goldens captured with `-x Composite:all`.
  check("real_synth_1audio.rm", "real_synth_1audio.rm.json", true);
  check("real_synth_1audio.rm", "real_synth_1audio.rm.n.json", false);
}

#[test]
fn real_synth_2_audio_audio_conformance() {
  // Codex R1 F1 adversarial — 2-stream RM with BOTH MIMEs populated
  // (`audio/x-pn-realaudio` each). Bundled @mimeTypes has 2 entries, so
  // the `@mimeTypes == 1` gate (Real.pm:654) fails ⇒ NO override; the
  // table-derived `application/vnd.rn-realmedia` is kept. Pins the
  // count-mismatch arm of the override branch.
  check(
    "real_synth_2_audio_audio.rm",
    "real_synth_2_audio_audio.rm.json",
    true,
  );
  check(
    "real_synth_2_audio_audio.rm",
    "real_synth_2_audio_audio.rm.n.json",
    false,
  );
}

#[test]
fn real_synth_id3v1_empty_title_conformance() {
  // Codex R1 F2 adversarial — RM + RJMD footer + ID3v1 trailer whose
  // Title slot is ALL NULL (faithful bundled `"ID3v1:Title": ""`). The
  // previous PrintConv-staged lift dropped the empty Title via
  // `nonempty()` (process.rs `stuff_id3v1_field`) and Real's
  // `emit_id3v1` skipped the tag entirely — silent metadata loss. The
  // direct-block parser
  // [`crate::formats::id3::v1::parse_id3v1_typed`] preserves
  // `Some("")` so the empty Title round-trips through `-j` and `-n`.
  check(
    "real_synth_id3v1_empty_title.rm",
    "real_synth_id3v1_empty_title.rm.json",
    true,
  );
  check(
    "real_synth_id3v1_empty_title.rm",
    "real_synth_id3v1_empty_title.rm.n.json",
    false,
  );
}

#[test]
fn real_synth_embedded_nul_mime_conformance() {
  // Codex R2 adversarial — RM whose 1 MDPR carries a StreamMimeType with
  // an EMBEDDED NUL byte (`audio/x\0pn-realaudio`). Bundled Real.pm:643
  // runs `$mime =~ s/\0.*//s` (first-NUL truncation) before pushing to
  // `@mimeTypes`, and the `Format => 'string[$val{10}]'` read at Real.pm:
  // 132-136 already truncates via ReadValue's `s/\0.*//s` at
  // ExifTool.pm:6300, so BOTH `Real-MDPR:StreamMimeType` AND
  // `File:MIMEType` (via the single-stream override at Real.pm:653-657)
  // emit the truncated `audio/x` form. Pre-fix the Rust port used
  // `strip_trailing_nuls`, which preserved the embedded NUL and leaked it
  // through both surfaces.
  check(
    "real_synth_embedded_nul_mime.rm",
    "real_synth_embedded_nul_mime.rm.json",
    true,
  );
  check(
    "real_synth_embedded_nul_mime.rm",
    "real_synth_embedded_nul_mime.rm.n.json",
    false,
  );
}

#[test]
fn real_synth_id3v1_sparse_genre_conformance() {
  // Codex R1 F2 adversarial — RM + RJMD footer + ID3v1 trailer whose
  // Genre byte is 192 (SPARSE — outside the GENRE_ENTRIES named-genre
  // table, between 191 `Psybient` and 255 `None`). Bundled emits
  // `"ID3v1:Genre": "Unknown (192)"` in `-j` mode and the raw int
  // `"ID3v1:Genre": 192` in `-n` mode. The previous PrintConv-staged
  // lift rendered `"Unknown (192)"` via the `%genre` hash fallback,
  // then the back-resolver (`id3v1_genre_byte_for_name`) failed to map
  // that string back to byte 192 — `v1.genre = None`, `v1.genre_name = None`,
  // and Real's `emit_id3v1` SKIPPED the Genre tag entirely. The
  // direct-block parser preserves the raw byte so both `-j` (rendered)
  // and `-n` (bare int) emit faithfully.
  check(
    "real_synth_id3v1_sparse_genre.rm",
    "real_synth_id3v1_sparse_genre.rm.json",
    true,
  );
  check(
    "real_synth_id3v1_sparse_genre.rm",
    "real_synth_id3v1_sparse_genre.rm.n.json",
    false,
  );
}

#[test]
fn real_synth_ram_pnm_conformance() {
  // PR #33 Copilot finding — the RAM/RPM Metafile branch (Real.pm:533-555).
  // `tests/fixtures/real_synth_ram_pnm.ram` is a synthetic RAM playlist:
  // a `pnm://` URL line, an `rtsp://` URL line, and a plain text line.
  // Exercises (1) the `RealKind::Ram` default when the extension is not
  // `RPM` (Real.pm:535-536), (2) the `^[a-z]{3,4}://` URL-vs-text split
  // (Real.pm:552 — `Real:URL` / `Real:Text`), and (3) the last-wins
  // duplicate-tag semantics: TWO `url` lines ⇒ bundled JSON keeps the
  // FINAL line (`rtsp://…/feature.rm`) as `Real:URL`. Goldens captured
  // with bundled `perl exiftool 13.58 -j -G1 -struct` (`-n` variant
  // identical — the `Real::Metafile` table has no PrintConv).
  check(
    "real_synth_ram_pnm.ram",
    "real_synth_ram_pnm.ram.json",
    true,
  );
  check(
    "real_synth_ram_pnm.ram",
    "real_synth_ram_pnm.ram.n.json",
    false,
  );
}

#[test]
fn real_synth_rpm_pnm_conformance() {
  // PR #33 Copilot finding — RAM-vs-RPM is decided ONLY by the file
  // extension (Real.pm:535-536 `$$et{FILE_EXT} eq 'RPM'`). Same kind of
  // `pnm://`-headed metafile as `real_synth_ram_pnm.ram`, but the `.rpm`
  // extension flips the typed `RealKind` to `Rpm` ⇒ `File:FileType=RPM`
  // and the RPM MIME `audio/x-pn-realaudio-plugin`. Pins that the `ext`
  // channel is threaded through `AnyParser::Real` → `parse_with_ext` →
  // `parse_metafile` (the pre-fix stub discarded `ext` and always
  // returned `RealKind::Ram`).
  check(
    "real_synth_rpm_pnm.rpm",
    "real_synth_rpm_pnm.rpm.json",
    true,
  );
  check(
    "real_synth_rpm_pnm.rpm",
    "real_synth_rpm_pnm.rpm.n.json",
    false,
  );
}

#[test]
fn real_synth_metafile_http_accept_conformance() {
  // PR #33 Copilot finding — the `http`-line acceptance gate (Real.pm:546:
  // `return 0 if $buff =~ /^http/ and $buff !~ /\.(ra|rm|rv|rmvb|smil)$/i`).
  // `real_synth_metafile_http_accept.ram`'s first non-empty line is
  // `http://…/promo.ra` — the `.ra` suffix SATISFIES the gate, so bundled
  // ACCEPTS the file as RAM. (The rejection half of the gate — an
  // `http://` line WITHOUT a Real media suffix ⇒ `return 0` ⇒ the file
  // falls through to `TXT` — is pinned by the `parse_metafile_http_*`
  // unit tests in `src/formats/real.rs`: exifast has no `Text`-module
  // parser, so a rejected metafile cannot be a conformance fixture.)
  check(
    "real_synth_metafile_http_accept.ram",
    "real_synth_metafile_http_accept.ram.json",
    true,
  );
  check(
    "real_synth_metafile_http_accept.ram",
    "real_synth_metafile_http_accept.ram.n.json",
    false,
  );
}

#[test]
fn dv_unknown_profile_conformance() {
  // Adversarial: 480-byte synthetic with the primary `\x1f\x07\0\x3f`
  // magic and `stype=0x1f` at offset 451 — never present in
  // `@dvProfiles`, so DV.pm:188 hits the `Warn("Unrecognized DV
  // profile")` branch. Faithful bundled-Perl output: `ExifTool:Warning`
  // tag + `File:*` triplet only, no `DV:*` tags. Goldens captured with
  // `-x Composite:all`.
  check("dv_unknown_profile.dv", "dv_unknown_profile.dv.json", true);
  check(
    "dv_unknown_profile.dv",
    "dv_unknown_profile.dv.n.json",
    false,
  );
}

#[test]
fn ogg_conformance() {
  // FORMATS.md row 9 (Ogg + Vorbis-comments): a real Ogg-Vorbis fixture
  // from the bundled-ExifTool corpus. The committed golden is bundled
  // `perl exiftool -j -G1 -struct ... -x Composite:all`:
  // `Composite:Duration` is the only hand-trim (Composite engine is on
  // the accepted-deferral list — see `docs/tracking.md` → "Residual
  // (still in accepted-deferral list)"). Every emitted tag —
  // including the `Vorbis:VorbisVersion` / `Vorbis:AudioChannels` /
  // `Vorbis:SampleRate` / `Vorbis:NominalBitrate` identification fields
  // ported in R2 F-OGG-TRIM — is value-equivalent to bundled Perl in both
  // PrintConv-on (default) and `-n` modes.
  check("Vorbis.ogg", "Vorbis.ogg.json", true);
  check("Vorbis.ogg", "Vorbis.ogg.n.json", false);
}

#[test]
fn malformed_ogg_error_conformance() {
  // Adversarial: a 16-byte file starting with `OggS` magic but truncated
  // before the page-header is even 27 bytes long. `.ogg` is a known
  // type ⇒ `ProcessOGG` runs, returns 0 (no valid page completed) ⇒
  // `'File format error'` (ExifTool.pm:3093). Pins that the OGG parser
  // does not "accept" without finalising a stream — symmetric with the
  // AAC `bad.aac` / `aac_profile3.aac` adversarial pattern.
  check("bad.ogg", "bad.ogg.json", true);
  check("bad.ogg", "bad.ogg.n.json", false);
}

#[test]
fn ogg_truncated_error_conformance() {
  // R1 regression pin: a 27-byte file with valid `OggS` magic but exactly
  // ONE byte short of the page-header minimum read. Bundled `Ogg.pm:94`
  // requires `$raf->Read($buff, 28) == 28` — at 27 bytes the read returns
  // 27, the `== 28` fails, the loop never enters, `$success` stays 0 ⇒
  // post-loop `'File format error'` (ExifTool.pm:3093). Pins that
  // `ProcessOgg` does NOT call `SetFileType` on a 27-byte OggS prefix
  // (the Codex round-1 F1 finding).
  check("ogg_truncated.ogg", "ogg_truncated.ogg.json", true);
  check("ogg_truncated.ogg", "ogg_truncated.ogg.n.json", false);
}

#[test]
fn ogg_vorbis_trailing_garbage_conformance() {
  // R2 regression pin (Codex round-2 [medium] disposition: finding rejected
  // as misframed — see commit message + `src/formats/ogg.rs::process_vorbis_comments`).
  //
  // Fixture: a complete two-page Ogg-Vorbis file whose comment packet is
  // `\x03vorbis` + vendor("test") + count=0 + `\x01\x02\x03` (3 trailing
  // garbage bytes) + framing-bit. Reaches `process_vorbis_comments` with
  // exactly that block.
  //
  // The Codex round-2 finding claimed bundled ExifTool emits
  // `ExifTool:Warning => 'Format error in Vorbis comments'` on this input.
  // EMPIRICAL EVIDENCE (this committed golden, captured from bundled
  // `perl exiftool`): NO `ExifTool:Warning` is emitted — only the Vorbis
  // identification fields (`VorbisVersion`/`AudioChannels`/`SampleRate`/
  // `NominalBitrate` — R2 F-OGG-TRIM port) plus `Vorbis:Vendor`.
  //
  // The reason (Vorbis.pm:157-210): `ProcessComments` reads the vendor in
  // the FIRST loop iteration (line 175 else-branch), sets `$num =
  // (pos+4 < end) ? Get32u(at count) : 0` (line 184; reads as 0 in the
  // trailing case since the count field contents are `\0\0\0\0`), then
  // unconditionally hits `$num-- or return 1` (line 205) at the end of the
  // iteration. With `$num == 0`, `$num--` returns the original 0 (falsy),
  // so `return 1` fires IMMEDIATELY — BEFORE the next iteration can run
  // `last if pos+4 > end` (line 168) that would otherwise fall through to
  // the warning at line 208. Perl therefore returns success without ever
  // reaching the warning line, and any bytes after the comment count
  // (whether 0, 3, or more) are silently ignored.
  //
  // This conformance test pins that exifast's `process_vorbis_comments`
  // matches the silent-accept behaviour. Adding a `pos != end` check
  // here (as the rejected finding proposed) would emit a warning on an
  // input Perl accepts cleanly — UNFAITHFUL by D5 and would break this
  // golden. The negative pin is the regression guard.
  check(
    "ogg_vorbis_trailing_garbage.ogg",
    "ogg_vorbis_trailing_garbage.ogg.json",
    true,
  );
  check(
    "ogg_vorbis_trailing_garbage.ogg",
    "ogg_vorbis_trailing_garbage.ogg.n.json",
    false,
  );
}

#[test]
fn ogg_vorbis_interleaved_list_conformance() {
  // R1-F2 regression pin: an Ogg-Vorbis comment block with INTERLEAVED
  // `List => 1` and non-List keys: vendor + ARTIST=Alice, TITLE=Song,
  // ARTIST=Bob, COMMENT=Foo. Bundled `perl exiftool` emits
  // `Vorbis:Artist = ["Alice","Bob"]` at the FIRST-occurrence position
  // (before Title, before Comment) — faithful FoundTag semantics
  // (ExifTool.pm:9505-9520). A previous implementation accumulated list
  // values in a HashMap and flushed alphabetically at end-of-parse, which
  // happened to coincide with bundled output for ARTIST-only fixtures
  // (alphabetical-of-one) but reordered interleaved comments. The fix
  // marks ARTIST/PERFORMER/CONTACT TagDefs with `.with_list(true)` and
  // routes them through `Metadata::push_listable` at encounter time —
  // identical seam to FLAC's Vorbis-comment path (`flac.rs:888-895`).
  //
  // R2 F-OGG-TRIM: identification-header tags (`Vorbis:VorbisVersion`,
  // `:AudioChannels`, `:SampleRate`) are now PORTED and present in the
  // golden — the R1-F2 deferral was reversed when the round-2 review
  // showed it forced new hand-trims that the 1:1 bar disallows.
  check(
    "ogg_vorbis_interleaved_list.ogg",
    "ogg_vorbis_interleaved_list.ogg.json",
    true,
  );
  check(
    "ogg_vorbis_interleaved_list.ogg",
    "ogg_vorbis_interleaved_list.ogg.n.json",
    false,
  );
}

#[test]
fn mp3_conformance() {
  // ID3-free MPEG-1 Layer III audio frame at 128 kbps / 44.1 kHz / Joint
  // Stereo (a single 417-byte frame: 4-byte header 0xfffb904c + 413 zero
  // bytes of audio payload). The bundled `perl exiftool -j -G1 -struct`
  // emits an additional `"Composite:Duration": "0.03 s (approx)"` (and
  // `0.0260625` under `-n`); both goldens here EXCLUDE that key because
  // composite tags are not yet ported (`%MPEG::Composite`, MPEG.pm:385-
  // 432 — a forward item tracked in the module header). The capture
  // suppresses it via `--Composite:Duration`.
  check("MP3.mp3", "MP3.mp3.json", true);
  check("MP3.mp3", "MP3.mp3.n.json", false);
}

#[test]
fn vbr_xing_lame_mp3_conformance() {
  // Synthesized 504-byte VBR Xing+LAME MP3. Pins the MPEG.pm:501-578 tail:
  // `%MPEG::Xing` (VBRFrames=1000, VBRBytes=200_000, VBRScale=78, Encoder=
  // "LAME3.99r", LameVBRQuality=2, LameQuality=2) and `%MPEG::Lame`
  // (LameMethod=4→"VBR (new/mtrh)", LameLowPassFilter=160→"16 kHz",
  // LameBitrate=128→"128 kbps", LameStereoMode=3→"Joint Stereo"). The
  // bundled `perl exiftool -j -G1 -struct` also emits `Composite:
  // AudioBitrate` (61.2 kbps under -j, 61250 under -n); both goldens
  // EXCLUDE that key (Composite tags are not yet ported — `%MPEG::
  // Composite` forward item) just as `mp3_conformance` excludes
  // `Composite:Duration`. The capture suppresses it via
  // `--Composite:AudioBitrate`.
  check("VBR.mp3", "VBR.mp3.json", true);
  check("VBR.mp3", "VBR.mp3.n.json", false);
}

#[test]
fn vbr_no_vbrscale_mp3_conformance() {
  // F2 (Codex R2): Xing+LAME MP3 with flags = 0x13 — VBRFrames | VBRBytes |
  // LAME, deliberately OMITTING the VBRScale flag bit (0x08). MPEG.pm:510
  // declares `my $vbrScale;` (undef); MPEG.pm:528-533 only assigns it when
  // `$flags & 0x08`. The LAME-quality calculation at MPEG.pm:563-565 then
  // evaluates `undef <= 100` in numeric context — Perl promotes undef to 0
  // with a runtime warning, so the calc runs unconditionally on the encoder
  // version: `int((100 - 0) / 10) = 10` (LameVBRQuality) and `(100 - 0) %
  // 10 = 0` (LameQuality). Bundled `perl exiftool -j -G1 -struct` confirms:
  // `LameVBRQuality=10, LameQuality=0` (with three "Use of uninitialized
  // value $vbrScale ..." warnings to STDERR). Pins the undef-as-zero
  // semantics — without the `vbr_scale.unwrap_or(0)` fallback in
  // `parse_xing_lame`'s LAME-quality arm (MPEG.pm:563-565), exifast omits
  // both LAME quality tags and this assertion fails.
  check("VBR_no_vbrscale.mp3", "VBR_no_vbrscale.mp3.json", true);
  check("VBR_no_vbrscale.mp3", "VBR_no_vbrscale.mp3.n.json", false);
}

#[test]
fn mus_layer2_conformance() {
  // Codex R3: 5-byte MUS fixture (`\xff\xfd\x90\x4c\x00`) = MPEG-1 Layer II
  // sync at 160 kbps / 44.1 kHz / Joint Stereo. Bundled `ID3::ProcessMP3`
  // dispatches `.mus` files through `ParseMPEGAudio($et, \$buff, $mp3)`
  // with `$mp3 = ($ext eq 'MUS') ? 0 : 1` (ID3.pm:1715-1717), so the
  // Layer-III-only check at MPEG.pm:485 is BYPASSED for `.mus` ⇒ Layer II
  // is accepted. Bundled `perl exiftool -j -G1 -struct
  // --System:all --Composite:all` emits `MPEG:AudioLayer=2`. exifast's
  // `ProcessMp3::process` must thread the caller `$mp3` flag through (NOT
  // recompute it from `ctx.file_type()=="MP3"`); without that, the Layer
  // III gate falsely rejects this fixture. Pins ID3.pm:1715-1717 +
  // MPEG.pm:485 caller-flag semantics.
  check("MUS_layer2.mus", "MUS_layer2.mus.json", true);
  check("MUS_layer2.mus", "MUS_layer2.mus.n.json", false);
}

#[test]
fn junk_past_8k_mp3_conformance() {
  // F1 (Codex R1): 8200 bytes of pseudo-random non-`\xff` filler followed
  // by a valid Layer III header at offset 8200. Bundled ExifTool's
  // `ID3::ProcessMP3` (ID3.pm:1704) reads only the first 8192 bytes; the
  // header at offset 8200 is outside the scan window, so the audio-frame
  // sync scan finds nothing ⇒ `ParseMPEGAudio` returns 0 ⇒ post-loop
  // `File format error` (ExifTool.pm:3093). exifast's bounded-scan
  // wrapper (`ProcessMp3::process` → ID3.pm:1684-1729) must match.
  // Without the bound, the unbounded scan would latch onto the sync byte
  // at offset 8200 and falsely accept ⇒ this test would fail.
  check("JunkPast8k.mp3", "JunkPast8k.mp3.json", true);
  check("JunkPast8k.mp3", "JunkPast8k.mp3.n.json", false);
}

#[test]
fn malformed_mp3_error_conformance() {
  // `.mp3` extension + 144 bytes that all fail the audio-frame header
  // validation (either sync-bit reject or bad bitrate). `MP3` is a known
  // type ⇒ post-loop ExifTool:Error finalizes as `File format error`
  // (ExifTool.pm:3093). Pins that `parse_mpeg_audio` returns false on
  // pure garbage AND that no File:* tags slip through (no SetFileType
  // was called).
  check("bad.mp3", "bad.mp3.json", true);
  check("bad.mp3", "bad.mp3.n.json", false);
}

#[test]
fn ogg_vorbis_specialkeys_conformance() {
  // R3 regression pin (Codex round-3 [medium] dispositions F1+F2).
  //
  // F1: `%specialTags` (ExifTool.pm:1228-1236) had been partially ported
  // as a 16-key stub including 3 keys NOT in Perl (`PARENT`, `DID_TAG_ID`,
  // `ID3`) and missing 15 that ARE in Perl (incl. `NAMESPACE`, `AVOID`,
  // `IS_OFFSET`, `LANG_INFO`, `TAG_PREFIX`, `PREFERRED`, `SHORT_NAME`,
  // `TABLE_DESC`, `IS_SUBDIR`, `EXTRACT_UNKNOWN`, `PRINT_CONV`,
  // `SRC_TABLE`, `SET_GROUP1`, `PERMANENT`, `INIT_TABLE`). For each
  // comment KEY in that set, `Vorbis.pm:180` appends `_` to the
  // synthesised tag name (so `NAMESPACE=x` ⇒ `Vorbis:Namespace_`).
  // Fixed by porting the full 28-key hash; this fixture pins seven of
  // them (`NAMESPACE`, `AVOID`, `IS_OFFSET`, `LANG_INFO`, `TAG_PREFIX`,
  // `PREFERRED`, `NOTES`) byte-exact against the bundled golden.
  //
  // F2: `underscore_camelcase` (port of Perl `s/([a-z0-9])_([a-z])/$1\U$2/g`,
  // Vorbis.pm:193) had walked positions in the ORIGINAL input string and
  // tested `bytes[i-1]` for lowercase against pre-replacement state, so
  // multi-underscore chains like `TRACK_A_B` (after ucfirst+lc =>
  // `Track_a_b`) produced `TrackAB` instead of Perl's `TrackA_b`.
  // Perl `s///g` advances `pos()` past the END of each replacement and
  // continues from there in the mutated string — so after `a_b` becomes
  // `aB`, the next character checked is the now-uppercase `B`, which
  // does NOT satisfy `[a-z0-9]` and the trailing `_b` is preserved.
  // Fixed by switching to cursor-over-MUTATED-output semantics; this
  // fixture pins `TRACK_A_B => TrackA_b`, `A_B_C_D_E => A_bC_dE`,
  // `KEY_A_LONG_NAME => KeyA_longName`, `FOO_BAR_X_Y => FooBarX_y`
  // byte-exact against the bundled golden.
  //
  // Fixture layout (323 bytes, synthetic Ogg-Vorbis, CRC-valid):
  //   - BOS page (header_type=0x02, seq=0): `\x01vorbis` identification
  //     packet (vendor`=` placeholder; channels=2, sample_rate=44100,
  //     nominal_bitrate=128000, blocksize0/1=0xB8, framing=1).
  //   - Page (header_type=0x00, seq=1): `\x03vorbis` comment packet
  //     with vendor="test vendor" + 11 KEY=VALUE comments + framing=1.
  // R2 F-OGG-TRIM: identification-binary fields (VorbisVersion /
  // AudioChannels / SampleRate / NominalBitrate) are now PORTED and
  // present in the golden — only `Composite:Duration` is hand-trimmed
  // (accepted-deferral; see `docs/tracking.md`).
  check(
    "synthetic_vorbis_specialkeys.ogg",
    "synthetic_vorbis_specialkeys.ogg.json",
    true,
  );
  check(
    "synthetic_vorbis_specialkeys.ogg",
    "synthetic_vorbis_specialkeys.ogg.n.json",
    false,
  );
}

#[test]
fn ogg_id3_prefixed_conformance() {
  // R3 F1 regression pin (Codex round-3 [high] disposition).
  //
  // Fixture: a real Ogg-Vorbis stream with a 34-byte ID3v2.3 PREFIX
  // (10-byte header + a TIT2 frame containing "IDPrefixTitle") in front
  // of the `OggS` page. Bundled `ProcessOGG` (Ogg.pm:79-83) runs
  // `ID3::ProcessID3` BEFORE the OGG container walk; the audio-format
  // loop (ID3.pm:1582-1601) then seeks past `$hdrEnd` and re-dispatches
  // OGG on the post-ID3 body. Net emission: `File:ID3Size`, every Vorbis
  // tag, plus the ID3v2 frame tags.
  //
  // Pre-fix the engine's `AnyParser::Ogg` arm stripped the ID3v2 prefix
  // to reparse `bytes[hdr_end..]` but never emitted the ID3 directory —
  // silent metadata loss (`File:ID3Size` + `ID3v2_3:Title` both dropped).
  // R3 F1 fix: nest typed `Id3Meta` into `ogg::Meta::id3` via
  // `ogg::parse_full_chained`, same pattern as APE/FLAC/DSF
  // (`ape::parse_full_chained`, `flac::parse_inner`, etc.).
  //
  // Golden: bundled `perl exiftool -j -G1 -struct ... --Composite:Duration`
  // (Composite engine is on the accepted-deferral list — see Vorbis.ogg).
  // Every other emitted tag is value-equivalent to bundled in both modes.
  check("ogg_id3_prefixed.ogg", "ogg_id3_prefixed.ogg.json", true);
  check("ogg_id3_prefixed.ogg", "ogg_id3_prefixed.ogg.n.json", false);
}

#[test]
fn ogg_metadata_block_picture_conformance() {
  // R3 F2 regression pin (Codex round-3 [high] disposition).
  //
  // Fixture: the bundled `Opus.opus` corpus file (exiftool/t/images/Opus.opus)
  // — a real Ogg-Opus stream carrying a `METADATA_BLOCK_PICTURE` Vorbis
  // comment (a base64-encoded payload with the FLAC METADATA_BLOCK type-6
  // on-wire structure: PictureType=3 "Front Cover", MIME=image/png,
  // Description="cover pic", 16x16 1bpp, 85 bytes of PNG data).
  //
  // Vorbis.pm:122-134 defines the `METADATA_BLOCK_PICTURE` SubDirectory
  // hop: the base64 RawConv decodes the value, then ProcessDirectory
  // dispatches it through `%Image::ExifTool::FLAC::Picture` (FLAC.pm:84-
  // 134). Bundled emits each Picture sub-field (`FLAC:PictureType`,
  // `:PictureMIMEType`, `:PictureDescription`, `:PictureWidth`,
  // `:PictureHeight`, `:PictureBitsPerPixel`, `:PictureIndexedColors`,
  // `:PictureLength`, `:Picture`).
  //
  // Pre-fix exifast's `metadata_block_picture_valueconv` only base64-
  // decoded the value into a single `Vorbis:Picture` Bytes blob, losing
  // every sub-field. Silent metadata loss caught by Codex round 3.
  //
  // Fix: a comments-level intercept in `process_vorbis_comments` decodes
  // the base64 then parses the result via `flac::parse_flac_picture`
  // (made `pub(crate)`); the parsed `Picture` is cloned into an owned
  // `OggPicture` accumulated on `ogg::Meta::pictures`. The typed
  // `serialize_tags` sink emits each Picture under the `FLAC` family-1
  // group with the same shape FLAC's `sink_picture` uses.
  check("Opus.opus", "Opus.opus.json", true);
  check("Opus.opus", "Opus.opus.n.json", false);
}

#[test]
#[ignore = "Ogg-FLAC transport (Ogg.pm:176-179, 190-195): \\x7fFLAC packet → \
  ProcessFLAC on substr(buff,9). FORMALLY ACCEPT-DEFERRED — see docs/tracking.md \
  (R3 F2 fallback). The METADATA_BLOCK_PICTURE half of R3 F2 IS fixed (see \
  ogg_metadata_block_picture_conformance)."]
fn ogg_flac_transport_deferred() {
  // R3 F2 FALLBACK (formally accept-deferred per task spec). Bundled
  // `FLAC.ogg` extracts `FLAC:BlockSizeMin/Max`, `FLAC:FrameSizeMin/Max`,
  // `FLAC:SampleRate`, `FLAC:Channels`, `FLAC:BitsPerSample`,
  // `FLAC:TotalSamples`, `FLAC:MD5Signature`, `Vorbis:Vendor`.
  //
  // exifast's current OGG parser emits only the orchestration triplet
  // (`File:FileType`, `:FileTypeExtension`, `:MIMEType`) for this
  // fixture; the `\x7fFLAC` packet hits `PacketKind::Flac` which is
  // a silent no-op (`process_packet` returns `PacketOutcome::FlacDeferred`).
  //
  // Implementation cost: porting the bundled `numFlac` accumulator
  // (Ogg.pm:123-126, 176-179, 190-195) — track the FLAC header packet
  // count, accumulate packets across pages, and after all are read run
  // `ProcessFLAC` on the assembled `substr(buff, 9)` buffer (which
  // begins with `fLaC` magic — see hex dump of FLAC.ogg). Then nest a
  // `flac::Meta` into `ogg::Meta`, which forces a self-referential
  // shape (the flac::Meta borrows from the buffer that's owned by the
  // ogg::Meta).
  //
  // Per-user contract: this is FORMALLY ACCEPT-DEFERRED, NOT silent.
  // `#[ignore]` keeps the test off the default run but committed; the
  // golden is committed for the eventual port; `docs/tracking.md`
  // records the residual; this comment + the
  // `PacketKind::Flac => PacketOutcome::FlacDeferred` arm in
  // `src/formats/ogg.rs::process_packet` document it in code too.
  //
  // Run manually to verify the gap closes when the port lands:
  //   `cargo test --ignored ogg_flac_transport_deferred`
  check("FLAC.ogg", "FLAC.ogg.json", true);
  check("FLAC.ogg", "FLAC.ogg.n.json", false);
}

#[test]
fn ogg_opus_synthetic_conformance() {
  // A synthetic minimal Ogg-Opus stream (BOS page wrapping `OpusHead` +
  // EOS page wrapping `OpusTags` with vendor + 2 KEY=VALUE comments —
  // built in `examples/gen_synthetic_opus.rs`). Avoids the real
  // `Opus.opus` corpus fixture's `METADATA_BLOCK_PICTURE` (now COVERED
  // by `ogg_metadata_block_picture_conformance` — R3 F2 fix).
  // Exercises `OverrideFileType('OPUS')`
  // (Ogg.pm:50) firing on the `OpusHead` packet, the `OpusTags`
  // Vorbis-comments delegation (Opus.pm:32), AND the `Opus::Header`
  // binary table (Opus.pm:36-51, R2 F-OGG-TRIM port) emitting
  // `Opus:OpusVersion`/`AudioChannels`/`SampleRate`/`OutputGain` byte-
  // exact against the bundled golden.
  check(
    "synthetic_opus_minimal.opus",
    "synthetic_opus_minimal.opus.json",
    true,
  );
  check(
    "synthetic_opus_minimal.opus",
    "synthetic_opus_minimal.opus.n.json",
    false,
  );
}

#[test]
fn audible_aa_conformance() {
  // FORMATS.md row 10. Bundled fixture
  // `exiftool/t/images/Audible.aa`; goldens captured from `LC_ALL=C
  // TZ=UTC perl exiftool -j -G1 -struct -api QuickTimeUTC=1 ...`. Both
  // snapshots asserted (the PrintConv vs `-n` diff is only on
  // `File:FileTypeExtension` here: `aa` vs `AA`).
  check("Audible.aa", "Audible.aa.json", true);
  check("Audible.aa", "Audible.aa.n.json", false);
}

#[test]
fn audible_chapters_aa_conformance() {
  // Adversarial synthesized fixture: minimal valid AA exercising the
  // type-6 ChapterCount path (Audible.pm:221-225, absent from the
  // bundled Audible.aa fixture) AND `UnescapeHTML` (Audible.pm:261)
  // via a dictionary value `"A &amp; B"` ⇒ `"A & B"`. Goldens captured
  // from bundled `perl exiftool` exactly as for Audible.aa.
  check("Audible_chapters.aa", "Audible_chapters.aa.json", true);
  check("Audible_chapters.aa", "Audible_chapters.aa.n.json", false);
}

#[test]
fn audible_eof_aa_conformance() {
  // Adversarial: TOC has a type-6 entry whose offset is past EOF (the
  // 0xFFFFFFFF sentinel). The faithful Perl behavior (Audible.pm:222
  // inline `next if length < 4 or $raf->Read($buff, 4) != 4`) is to
  // silently skip the chunk — no Warn — and CONTINUE the TOC walk so
  // the subsequent valid type-2 dictionary still emits its tags. Pins
  // Codex R1 finding #1's fix: there is NO "Chunk 6 seek error" warning
  // for an in-memory/file backing where Seek succeeds but Read fails.
  check("Audible_eof.aa", "Audible_eof.aa.json", true);
  check("Audible_eof.aa", "Audible_eof.aa.n.json", false);
}

#[test]
fn audible_warn_aa_conformance() {
  // Adversarial: malformed AA whose first chunk-2 dictionary has
  // `num > 0x200` ⇒ Audible.pm:240 `Warn('Bad dictionary count'),
  // next`, and a second chunk-6 still emits a valid ChapterCount.
  // Bundled golden has `ExifTool:Warning` PLUS `Audible:ChapterCount`,
  // proving the loop continues past the Warn (Codex R1 finding #3).
  // The warning's position within the JSON object is not significant
  // under jsondiff's order-insensitive comparison (per the
  // [[exifast-phase2-forward-items]] "Warning JSON ordering" entry —
  // non-blocking until a format requires position-faithful warning
  // ordering at the byte level; tracked for the engine-level fix when
  // the gap becomes visible at the byte-exact bar).
  check("Audible_warn.aa", "Audible_warn.aa.json", true);
  check("Audible_warn.aa", "Audible_warn.aa.n.json", false);
}

#[test]
fn audible_badutf_aa_conformance() {
  // Adversarial: chunk-2 dictionary value contains a raw 0xFF byte
  // (`A\xffB`). Bundled Perl ExifTool's pipeline:
  //   bytes "A\xffB" → UnescapeHTML (no-op, no `&`) →
  //   Decode($_, 'UTF8') (no-op, from==to==UTF8) →
  //   HandleTag(Author, "A\xffB") →
  //   JSON serialize → FixUTF8 (replaces 0xff with '?') →
  //   "A?B"
  // Pins Codex R4 finding's fix: invalid input bytes flow through to
  // FixUTF8 (now applied at the parser boundary in this AA port, until
  // the engine grows a serializer-tier FixUTF8 — tracked in
  // [[exifast-phase2-forward-items]] "engine-wide FixUTF8 at JSON
  // serialization"). Rust's `String::from_utf8_lossy` (U+FFFD =
  // EF BF BD) would diverge — this confirms the byte-oriented
  // `fix_utf8(&unescape_html_bytes(...))` pipeline matches bundled
  // ExifTool exactly.
  check("Audible_badutf.aa", "Audible_badutf.aa.json", true);
  check("Audible_badutf.aa", "Audible_badutf.aa.n.json", false);
}

#[test]
fn audible_surrogate_aa_conformance() {
  // Adversarial: chunk-2 dictionary value `"X&#xD800;Y"`. Bundled Perl:
  //   bytes "X&#xD800;Y" → UnescapeHTML →
  //     pack('C0U', 0xD800) → "X\xed\xa0\x80Y" (invalid 3-byte surrogate
  //     encoding) →
  //   Decode($_, 'UTF8') (no-op) →
  //   HandleTag → JSON serialize → FixUTF8 (each of \xed \xa0 \x80
  //   replaced with '?') →
  //   "X???Y"
  // Pins Codex R4 finding's fix for the surrogate / out-of-range numeric
  // entity sub-case. Rust `char::from_u32(0xD800)` returns None (would
  // leave the entity literal as `&#xD800;`); the byte-oriented port
  // emits Perl's invalid 3-byte sequence via `pack_c0u`, which `fix_utf8`
  // then replaces with three `?`.
  check("Audible_surrogate.aa", "Audible_surrogate.aa.json", true);
  check("Audible_surrogate.aa", "Audible_surrogate.aa.n.json", false);
}

#[test]
fn audible_dup_aa_conformance() {
  // R5: two `author` entries in chunk-2 dictionary. Bundled Perl
  // `FoundTag` (ExifTool.pm:9504-9577) promotes the first entry to
  // `Author (1)` and writes the second at base `Author`; the `%noDups`
  // JSON serializer (exiftool:2744-2752) drops `(1)` so the final
  // output is `Audible:Author = "SECOND"`. Pin: replace-in-place
  // (`push_dict_last_wins`) keeps the first slot's position but
  // updates its value, exactly matching bundled output byte-for-byte.
  check("Audible_dup.aa", "Audible_dup.aa.json", true);
  check("Audible_dup.aa", "Audible_dup.aa.n.json", false);
}

#[test]
fn audible_bigent_aa_conformance() {
  // R5: chunk-2 dictionary value `"&#x100000000;"` — a numeric entity
  // whose body exceeds u32. Bundled Perl: `hex("100000000")` →
  // `0x100000000` → `pack('C0U', 0x100000000)` →
  // 7-byte invalid UTF-8 (`fe 84 80 80 80 80 80`) → `FixUTF8` ⇒ 7 `?`.
  // The previous u32-only `resolve_html_entity_codepoint` left the
  // entity literal; the new u64 path mirrors Perl byte-for-byte.
  check("Audible_bigent.aa", "Audible_bigent.aa.json", true);
  check("Audible_bigent.aa", "Audible_bigent.aa.n.json", false);
}

#[test]
fn audible_dupchap_aa_conformance() {
  // R6: two type-6 ChapterCount chunks in TOC (counts 1, then 2).
  // Bundled Perl `FoundTag` last-wins (ExifTool.pm:9504-9577) +
  // `%noDups` serializer filter ⇒ `Audible:ChapterCount` = 2. The
  // previous chunk-tag path used plain `push` instead of the AA dict's
  // last-wins helper, leaving Rust to emit ChapterCount = 1 (first
  // wins via `%noDups`). Routing every AA `HandleTag` equivalent
  // through `push_dict_last_wins` covers chunk-6 and chunk-11 the
  // same way as the dict path.
  check("Audible_dupchap.aa", "Audible_dupchap.aa.json", true);
  check("Audible_dupchap.aa", "Audible_dupchap.aa.n.json", false);
}

#[test]
fn audible_under_aa_conformance() {
  // R6: dict tag `__foo` exercises Perl `AddTagToTable` (ExifTool.pm:
  // 9217-9266) final name normalization: after MakeTagName +
  // `s/_(.)/\U$1/g` produces `_foo`, AddTagToTable's `length($name) <
  // 2 or $name !~ /^[A-Z]/i` rule prepends `Tag` because `_foo`'s
  // first char is not a letter. Bundled Perl emits `Audible:Tag_foo`;
  // the Rust port previously stopped after `s/_(.)/\U$1/g` and
  // emitted `Audible:_foo`.
  check("Audible_under.aa", "Audible_under.aa.json", true);
  check("Audible_under.aa", "Audible_under.aa.n.json", false);
}

#[test]
fn audible_dictcover_aa_conformance() {
  // R6: dictionary tag `_cover_art` (Audible.pm:43-47, `Binary => 1`)
  // takes the static-table branch but its raw value is binary — the
  // engine's universal `TagValue::Bytes` serializer emits
  // `(Binary data N bytes, use -b option to extract)`. The previous
  // dict-path treatment converted every static value to `TagValue::
  // Str(fix_utf8(unescape_html_bytes(...)))`, which dropped the
  // binary semantics and (worse) reshaped the byte length via
  // fix_utf8's invalid-byte replacement. Bundled Perl emits
  // `(Binary data 5 bytes, ...)` for the 5-byte value `"ABCDE"`.
  check("Audible_dictcover.aa", "Audible_dictcover.aa.json", true);
  check("Audible_dictcover.aa", "Audible_dictcover.aa.n.json", false);
}

#[test]
fn audible_reserved_aa_conformance() {
  // R7: dict tags `GROUPS` and `FORMAT` are in Perl `%specialTags`
  // (ExifTool.pm:1229-1236, table-internal hash keys). When the dict
  // loop hits one, Perl's `unless ($$tagTablePtr{$tag})` branch sees
  // a defined hashref (the table's actual GROUPS) and SKIPS
  // AddTagToTable; HandleTag then calls GetTagInfo which warns and
  // returns empty for special tags, so FoundTag is NEVER reached and
  // the tag is dropped. Bundled Perl emits ONLY `Audible:Title`; the
  // previous Rust port emitted `Audible:GROUPS` and `Audible:FORMAT`
  // too via the dynamic-name fallthrough.
  check("Audible_reserved.aa", "Audible_reserved.aa.json", true);
  check("Audible_reserved.aa", "Audible_reserved.aa.n.json", false);
}

#[test]
fn audible_ftype_aa_conformance() {
  // R7: dict entries `file_type` and `FileType` both resolve to
  // dynamic name `FileType` (after MakeTagName + `s/_(.)/\U$1/g` +
  // AddTagToTable). The engine's `SetFileType` (Audible.pm:207)
  // already pushed `File:FileType=AA` with `Priority => 2`
  // (ExifTool.pm:1437); Perl FoundTag (ExifTool.pm:9533-9574) sees
  // PRIORITY{FileType}=2 vs the AA push's default $priority=1, takes
  // the else branch (`$tag = $nextTag`) and stores the FIRST AA push
  // at `FileType (1)`, the SECOND at `FileType (2)`. The JSON noDups
  // dedup (exiftool:2951) keys by `<family1>:<name>` and picks the
  // first occurrence, so bundled Perl emits
  // `Audible:FileType = "FIRST"`. The R5 last-wins helper would have
  // emitted `SECOND`; R7 fix: when the AA dynamic-tag name collides
  // with an engine-pre-pushed bare name in a different group, treat
  // AA duplicates as FIRST-wins (mirroring Perl's no-promotion arm).
  check("Audible_ftype.aa", "Audible_ftype.aa.json", true);
  check("Audible_ftype.aa", "Audible_ftype.aa.n.json", false);
}

#[test]
fn audible_ftypeext_aa_conformance() {
  // R8 negative case: dict entries `file_type_extension=FIRST` and
  // `FileTypeExtension=SECOND` both resolve to dynamic name
  // `FileTypeExtension`. Unlike `FileType` (Priority 2), bundled
  // Perl's `File:FileTypeExtension` uses the DEFAULT Priority 1
  // (ExifTool.pm:1444+ has no `Priority =>` line), so FoundTag's
  // promote arm fires symmetrically and emits the LAST value:
  // `Audible:FileTypeExtension = "SECOND"`. The R7 fix was over-
  // broad (treated every cross-group same-name collision as first-
  // wins); R8 narrows the helper to the single Priority-2 name
  // `FileType`, restoring last-wins for the symmetric case.
  check("Audible_ftypeext.aa", "Audible_ftypeext.aa.json", true);
  check("Audible_ftypeext.aa", "Audible_ftypeext.aa.n.json", false);
}

#[test]
fn audible_etver_aa_conformance() {
  // R8 negative case: dict entries `exif_tool_version=FIRST` and
  // `ExifToolVersion=SECOND` both resolve to dynamic name
  // `ExifToolVersion`. The engine pre-emits
  // `ExifTool:ExifToolVersion` with default Priority 1 (no `Priority
  // =>` line, ExifTool.pm:1451+), so FoundTag's promote arm fires
  // and bundled Perl emits `Audible:ExifToolVersion = "SECOND"`.
  // Confirms the narrowed R8 check: cross-group `ExifToolVersion`
  // does NOT trigger first-wins.
  check("Audible_etver.aa", "Audible_etver.aa.json", true);
  check("Audible_etver.aa", "Audible_etver.aa.n.json", false);
}

#[test]
fn unsupported_bz2_conformance() {
  check("Unsupported.bz2", "Unsupported.bz2.json", true);
  check("Unsupported.bz2", "Unsupported.bz2.n.json", false);
}

// ExifTool's post-loop `ExifTool:Error` finalization (ExifTool.pm:3080-3128):
// when nothing is finalized, invalid inputs must be distinguishable. Goldens
// are bundled `perl exiftool -j -G1 -struct` (and `-n`) output; the default
// and `-n` snapshots are byte-identical for every case (the Error string has
// no PrintConv) but BOTH are asserted, mirroring the format conformance.

#[test]
fn empty_file_error_conformance() {
  // 0-byte file ⇒ `$self->Error('File is empty')` (ExifTool.pm:3086).
  check("Empty.dat", "Empty.dat.json", true);
  check("Empty.dat", "Empty.dat.n.json", false);
}

#[test]
fn unknown_type_error_conformance() {
  // 8 non-magic bytes, unrecognized extension ⇒ buff < 16, no known type
  // ⇒ 'Unknown file type' (ExifTool.pm:3095).
  check("mystery.xyz", "mystery.xyz.json", true);
  check("mystery.xyz", "mystery.xyz.n.json", false);
}

#[test]
fn malformed_aac_error_conformance() {
  // `\xff\xf1\xf0…` passes the AAC %magicNumber gate but `ProcessAAC`
  // rejects (sampling-freq index > 12, AAC.pm:103); `.aac` is a known
  // type ⇒ 'File format error' (ExifTool.pm:3093).
  check("bad.aac", "bad.aac.json", true);
  check("bad.aac", "bad.aac.n.json", false);
}

#[test]
fn aac_reserved_profile_error_conformance() {
  // Adversarial: ff f1 c0 00 00 00 00 — byte2=0xC0. Passes the AAC
  // %magicNumber gate; ProcessAAC's faithful >>16/>>12 checks (AAC.pm:
  // 102-103) don't trip, but $len < 7 (AAC.pm:105) ⇒ reject ⇒ '.aac'
  // known type ⇒ 'File format error' (ExifTool.pm:3093). Pins that the
  // faithful shift offsets are NOT to be "corrected" to >>14/>>10:
  // exifast must match bundled ExifTool byte-exact here.
  check("aac_profile3.aac", "aac_profile3.aac.json", true);
  check("aac_profile3.aac", "aac_profile3.aac.n.json", false);
}

#[test]
fn ape_conformance() {
  // Real fixture from exiftool/t/images/APE.ape: NewHeader (version 3990)
  // + APETAGEX v2 footer with 14 tags including Cover Art (front).
  check("APE.ape", "APE.ape.json", true);
  check("APE.ape", "APE.ape.n.json", false);
}

#[test]
fn ape_old_header_conformance() {
  // Adversarial synthesized fixture: OldHeader (version <= 3970) with no
  // APETAGEX trailer. Exercises the APE.pm:149-151 OldHeader branch +
  // APE.pm:170 `return 1` (no-trailer) path.
  check("APE_old.ape", "APE_old.ape.json", true);
  check("APE_old.ape", "APE_old.ape.n.json", false);
}

#[test]
fn ape_apetagex_only_conformance() {
  // Adversarial synthesized fixture (Codex r5 finding): starts directly
  // with APETAGEX (no MAC header). Exercises the APE.pm:142-144
  // header_at_start path with the Composite Duration Require failing
  // cleanly (no MAC ingredients ⇒ no Composite tag). Also covers the
  // dynamic MakeTag path ('My Custom Tag' → 'MyCustomTag') alongside a
  // static-dictionary tag ('Title' → 'Title').
  check("APE_apetagex.ape", "APE_apetagex.ape.json", true);
  check("APE_apetagex.ape", "APE_apetagex.ape.n.json", false);
}

#[test]
fn ape_wire_composite_ingredients_conformance() {
  // Adversarial wire-format fixture (Codex r8 follow-up). Carries four
  // APE tag-stream entries whose KEYS spell the four Composite Duration
  // ingredient names exactly: 'SampleRate', 'TotalFrames',
  // 'BlocksPerFrame', 'FinalFrameBlocks'. Bundled ExifTool 13.58
  // confirms NO `Composite:Duration` is emitted — because APE.pm:105
  // `MakeTag` runs `ucfirst lc` on the wire key first, producing
  // `Samplerate` (lowercase 'r'), `Totalframes` (lowercase 'f'), etc.
  // The Composite Require key `APE:SampleRate` (capital 'R') does NOT
  // match `Samplerate`, so no Composite tag fires. Pins this faithful
  // case-mangling behavior: a future regression that preserved camelCase
  // in MakeTag would WRONGLY emit a Composite here.
  check(
    "APE_wire_composite_ingredients.ape",
    "APE_wire_composite_ingredients.ape.json",
    true,
  );
  check(
    "APE_wire_composite_ingredients.ape",
    "APE_wire_composite_ingredients.ape.n.json",
    false,
  );
}

#[test]
fn ape_spaced_composite_conformance() {
  // Adversarial wire-format fixture (Codex r9 finding): four APE tag
  // entries whose KEYS contain SPACES — `Sample Rate`, `Total Frames`,
  // `Blocks Per Frame`, `Final Frame Blocks`. APE.pm:107 `MakeTag`
  // applies `s/[^\w-]+(.?)/\U$1/sg` AFTER `ucfirst lc`: `Sample Rate` →
  // ucfirst lc `Sample rate` → s/// at the space (non-word, then
  // uppercase the next char) → `SampleRate`. The Composite Require key
  // `APE:SampleRate` MATCHES, so Composite:Duration IS emitted
  // (`14.71 s`). Pins the family-0 + Str-coercion composite lookup
  // path end-to-end.
  check(
    "APE_spaced_composite.ape",
    "APE_spaced_composite.ape.json",
    true,
  );
  check(
    "APE_spaced_composite.ape",
    "APE_spaced_composite.ape.n.json",
    false,
  );
}

#[test]
fn ape_dup_override_conformance() {
  // Adversarial wire-format fixture (Codex r9 finding): MAC NewHeader
  // emits `SampleRate=44100`, then the APETAGEX footer emits a
  // `Sample Rate=48000` (which MakeTag normalises to `SampleRate`). Both
  // tags appear as `MAC:SampleRate` and `APE:SampleRate`; the Composite
  // Duration MUST use the LATEST value (48000, the wire-format override),
  // matching ExifTool's HandleTag/DUPL_TAG semantics (the bare-name key
  // is given to the most recent FoundTag call). Faithful Duration =
  // ((10-1)*73728+42662)/48000 = 14.71 s (NOT 16.01 s from 44100). Pins
  // the `iter().rev().find` last-wins behaviour in the composite lookup.
  check("APE_dup_override.ape", "APE_dup_override.ape.json", true);
  check("APE_dup_override.ape", "APE_dup_override.ape.n.json", false);
}

#[test]
fn ape_nonfinite_composite_conformance() {
  // Adversarial wire-format fixture (Codex r9 finding): one ingredient
  // (`Total Frames`) has value `"Inf"` (a string Perl coerces to IEEE
  // infinity). The composite arithmetic `(Inf-1)*73728+42662 = Inf;
  // /48000 = Inf`. ExifTool emits `APE:TotalFrames: "Inf"` (string,
  // because Inf fails IsFloat) and `Composite:Duration: "Inf"`. Pins:
  // (a) perl_numeric_coerce_f64 recognises "Inf"; (b) the composite
  // arithmetic in f64 propagates non-finite cleanly; (c) the composite
  // emit promotes non-finite f64 to Perl-cased `TagValue::Str("Inf")`
  // — Rust's f64::to_string() would emit lowercase `inf` and
  // byte-diverge.
  check(
    "APE_nonfinite_composite.ape",
    "APE_nonfinite_composite.ape.json",
    true,
  );
  check(
    "APE_nonfinite_composite.ape",
    "APE_nonfinite_composite.ape.n.json",
    false,
  );
}

#[test]
fn ape_huge_composite_conformance() {
  // Adversarial wire-format fixture (Codex r10 finding): four APE tag
  // entries where the Composite Duration arithmetic produces a value
  // beyond `i64::MAX` seconds (`1e15 * 1e15 / 1` ≈ 1e30 s). The previous
  // Rust port cast `(time / 3600.0) as i64` — saturating to `i64::MAX`
  // and emitting a corrupt h:m:s. Bundled Perl ExifTool 13.58 emits the
  // hours count via Perl's NV stringification (`%.15g`) which yields
  // `1.15740740740741e+25 days 0:00:00`. Pins the f64-throughout
  // ConvertDuration days-carve-out and the perl_nv_str helper.
  check(
    "APE_huge_composite.ape",
    "APE_huge_composite.ape.json",
    true,
  );
  check(
    "APE_huge_composite.ape",
    "APE_huge_composite.ape.n.json",
    false,
  );
}

#[test]
fn ape_repeated_keys_conformance() {
  // Adversarial wire-format fixture (Codex r13 follow-up): same APE
  // wire key emitted TWICE. Two `Title` entries (`First Title`,
  // `Second Title`) and two `Sample Rate` entries (`44100`, `48000`).
  // ExifTool HandleTag/FoundTag DUPL_TAG semantics give the bare key
  // to the LAST FoundTag call (renaming earlier ones to `Name (1)`,
  // `Name (2)`, …); default `-G1 -j` JSON suppresses the renamed
  // duplicates. Bundled Perl 13.58 emits ONLY the second value for
  // each key: `APE:Title="Second Title"`, `APE:SampleRate=48000`.
  check("APE_repeated.ape", "APE_repeated.ape.json", true);
  check("APE_repeated.ape", "APE_repeated.ape.n.json", false);
}

#[test]
fn ape_dynamic_edge_keys_conformance() {
  // Adversarial wire-format fixture (Codex r13 finding): four edge
  // dynamic APE tag keys exercising AddTagToTable (ExifTool.pm:9243-9255)
  // name normalization post-processing that MakeTag invokes:
  //   `1abc` → `Tag1abc` (prepend "Tag" because doesn't start with letter)
  //   `_abc` → `Tag_abc` (prepend "Tag" because doesn't start with letter)
  //   `a`    → `TagA` (prepend "Tag" because length<2; ucfirst → A)
  //   `\xe9` → `Tag` (non-ASCII byte stripped by tr/-_a-zA-Z0-9//dc ⇒
  //                   empty ⇒ length<2 ⇒ prepend "Tag")
  // Verified against bundled Perl 13.58. Pins make_tag's
  // AddTagToTable-equivalent post-processing.
  check(
    "APE_dynamic_edge_keys.ape",
    "APE_dynamic_edge_keys.ape.json",
    true,
  );
  check(
    "APE_dynamic_edge_keys.ape",
    "APE_dynamic_edge_keys.ape.n.json",
    false,
  );
}

#[test]
fn ape_two63_boundary_composite_conformance() {
  // Adversarial wire-format fixture (Codex r12 finding): `Sample Rate=1`,
  // `Total Frames=9223372036854775808` (= 2^63), `Blocks Per Frame=86400`,
  // `Final Frame Blocks=0`. Composite arithmetic:
  //   `(2^63 - 1) * 86400 / 1 ≈ 7.97e23` seconds → days = `2^63` exactly.
  // This pins the exact f64 boundary `i64::MAX as f64 == 2^63` (because
  // i64::MAX = 2^63-1 isn't representable in f64; the cast rounds UP).
  // Earlier `perl_nv_str` treated `n as i64` on `n=2^63` and saturated
  // to `i64::MAX = 2^63-1`, losing one. Bundled Perl 13.58 uses its UV
  // path and emits `"9223372036854775808 days 0:00:00"`. The fix splits
  // signed/unsigned carve-outs at the exact f64 power-of-two boundary.
  check(
    "APE_two63_boundary.ape",
    "APE_two63_boundary.ape.json",
    true,
  );
  check(
    "APE_two63_boundary.ape",
    "APE_two63_boundary.ape.n.json",
    false,
  );
}

#[test]
fn ape_u64_days_composite_conformance() {
  // Adversarial wire-format fixture (Codex r11 finding): four APE tag
  // entries chosen so the Composite Duration arithmetic produces a days
  // count strictly above `i64::MAX` (≈ 9.22e18) but at-or-below
  // `u64::MAX` (≈ 1.84e19). Perl preserves DECIMAL stringification in
  // that range via its UV (u64) integer path. Earlier `perl_nv_str` only
  // handled the signed `i64` range and emitted scientific notation
  // here, byte-diverging from bundled Perl. Empirically against bundled
  // Perl 13.58: composite duration `8.64e+23` seconds (≈ 1e19 days)
  // stringifies as `"10000000000000002048 days -32768:00:00"` — note
  // the `-32768` negative-hours residue is itself a faithful Perl quirk
  // caused by f64 precision loss in `$h -= $d * 24` and `%02d` integer
  // formatting (verified against bundled Perl). Pins the u64-range
  // integer carve-out in `perl_nv_str`.
  check("APE_u64_days.ape", "APE_u64_days.ape.json", true);
  check("APE_u64_days.ape", "APE_u64_days.ape.n.json", false);
}

#[test]
fn all_zero_file_error_conformance() {
  // 32 `\0` ⇒ buff ≥ 16 and all-same ⇒ the all-same-byte insight;
  // whole file is `\0` ⇒ 'Entire file is binary zeros'
  // (ExifTool.pm:3111,3115).
  check("allzero.dat", "allzero.dat.json", true);
  check("allzero.dat", "allzero.dat.n.json", false);
}

#[test]
fn raw_unsupported_error_conformance() {
  // 8 `\0` named `RAW.raw` ⇒ buff < 16 ⇒ the not-all-same arm; the
  // scalar `GetFileType("RAW.raw")` returns `"RAW"` (the multi row
  // `%fileTypeLookup{RAW}`) ⇒ Perl `$fileType eq 'RAW'` branch fires
  // ⇒ 'Unsupported RAW file type' (ExifTool.pm:3091-3092). Goldens
  // are bundled `perl exiftool` output.
  check("RAW.raw", "RAW.raw.json", true);
  check("RAW.raw", "RAW.raw.n.json", false);
}

#[test]
fn mpc_conformance() {
  // Pure SV7 MPC happy path (32-byte MP+ header, no ID3 leading / APE
  // trailer / ID3v1 — those are deferred to PRs #6 (ID3), the APE PR).
  // Synthesized from APE.mpc[263..295], the embedded MP+ frame in
  // exiftool/t/images/APE.mpc; oracle = bundled `perl exiftool` output.
  // MPC.pm:97-106 (SV7 ProcessDirectory) + MPC.pm:98 SetByteOrder('II')
  // (first end-to-end exerciser of bitstream::BitOrder::Ii).
  check("MPC.mpc", "MPC.mpc.json", true);
  check("MPC.mpc", "MPC.mpc.n.json", false);
}

#[test]
fn mpc_sv8_warn_conformance() {
  // MPC.pm:107-109 Warn path: a valid MP+ magic with version != 0x07 still
  // calls SetFileType (MPC.pm:94, before the version dispatch) then emits
  // `ExifTool:Warning = 'Audio info currently not extracted from this
  // version MPC file'`. Goldens captured from bundled `perl exiftool`.
  // Adversarial — pins that the version-dispatch branch is taken AFTER
  // SetFileType (the inverted ordering would emit just the Warning with no
  // File:* tags, which would diverge from bundled ExifTool byte-exact).
  check("sv8.mpc", "sv8.mpc.json", true);
  check("sv8.mpc", "sv8.mpc.n.json", false);
}

#[test]
fn mpc_with_id3v2_prefix_conformance() {
  // F2 (Codex adversarial) regression pin: MPC.pm:84-87 ID3-prefix
  // dispatch. Pre-fix the `AnyParser::Mpc` arm called the bare
  // `parse_borrowed` (header-only) and DROPPED the ID3 chain — so an
  // ID3-prefixed MPC silently lost `File:ID3Size` + every `ID3v2_*:*`
  // frame tag. `parse_full_chained` now nests a typed `Id3Meta` on
  // `mpc::Meta` (same pattern APE/DSF/FLAC use) and emits it.
  //
  // Fixture (66 bytes): ID3v2.3 with TIT2="MpcId3v2Title" (34 bytes) +
  // 32-byte MP+ SV7 header copied from MPC.mpc. Bundled emits the full
  // chain incl. `ID3v2_3:Title="MpcId3v2Title"`. Goldens captured from
  // bundled `perl exiftool` via tools/gen_golden.sh (untrimmed).
  check(
    "mpc_with_id3v2_prefix.mpc",
    "mpc_with_id3v2_prefix.mpc.json",
    true,
  );
  check(
    "mpc_with_id3v2_prefix.mpc",
    "mpc_with_id3v2_prefix.mpc.n.json",
    false,
  );
}

#[test]
fn mpc_with_apev2_trailer_conformance() {
  // F2 (Codex adversarial) regression pin: MPC.pm:111-113 APE-trailer
  // dispatch. Pre-fix the `AnyParser::Mpc` arm dropped the APE chain
  // (`parse_borrowed` is header-only) — so an APE-trailer-on-MPC fixture
  // silently lost every `APE:*` tag. `parse_full_chained` now runs
  // `ape::parse_trailer_only_owned` on the post-header buffer and nests
  // the resulting `ape::Meta`.
  //
  // Fixture (91 bytes): 32-byte MP+ SV7 header + APEv2 trailer carrying
  // `APE:Artist="MpcApeArtist"` (59-byte body + 32-byte footer).
  // Goldens captured from bundled `perl exiftool` via
  // tools/gen_golden.sh (untrimmed).
  check(
    "mpc_with_apev2_trailer.mpc",
    "mpc_with_apev2_trailer.mpc.json",
    true,
  );
  check(
    "mpc_with_apev2_trailer.mpc",
    "mpc_with_apev2_trailer.mpc.n.json",
    false,
  );
}

#[test]
fn wavpack_with_apev2_trailer_conformance() {
  // F2 (Codex adversarial) regression pin: WavPack.pm:100-103 APE-
  // trailer dispatch (`APE::ProcessAPE` after the wvpk-header
  // extraction). Pre-fix the `AnyParser::Wv` arm dropped the chain.
  // `parse_full_chained` now runs `ProcessID3` (recursion-guarded) +
  // `parse_trailer_only_owned` and nests both typed sub-Metas on
  // `wavpack::Meta`.
  //
  // Fixture (90 bytes): 32-byte wvpk header (copied from WavPack.wv) +
  // APEv2 trailer carrying `APE:Artist="WvApeArtist"`. The WV header
  // emits `File:BytesPerSample`/`AudioType`/`Compression`/`DataFormat`/
  // `SampleRate`; the APE trailer adds `APE:Artist`. Goldens captured
  // from bundled `perl exiftool` via tools/gen_golden.sh (untrimmed).
  check(
    "wavpack_with_apev2_trailer.wv",
    "wavpack_with_apev2_trailer.wv.json",
    true,
  );
  check(
    "wavpack_with_apev2_trailer.wv",
    "wavpack_with_apev2_trailer.wv.n.json",
    false,
  );
}

#[test]
fn red_r3d_conformance() {
  // FORMATS.md row 12: Image::ExifTool::Red. Bundled fixture
  // `tests/fixtures/Red.r3d` is the real `t/images/Red.r3d` (1160 bytes,
  // RED2 + ~50 directory entries). Goldens are bundled `perl exiftool`
  // output stripped of the 5 `Composite:*` lines (composite synthesis is
  // engine-level, NOT in Red.pm — see Red::ProcessR3D module docs).
  check("Red.r3d", "Red.r3d.json", true);
  check("Red.r3d", "Red.r3d.n.json", false);
}

#[test]
fn red_bad_magic_error_conformance() {
  // 8 bytes, magic gate `\0\0..RED(1|2)` fails. `.r3d` is a known type but
  // no parser accepted ⇒ post-loop 'File format error' (ExifTool.pm:3093).
  check("red_bad_magic.r3d", "red_bad_magic.r3d.json", true);
  check("red_bad_magic.r3d", "red_bad_magic.r3d.n.json", false);
}

#[test]
fn red_short_size_error_conformance() {
  // 8 bytes, magic OK, `$size = 4 < 8` ⇒ ProcessR3D returns 0 (Red.pm:228).
  // No parser accepted ⇒ 'File format error'.
  check("red_short.r3d", "red_short.r3d.json", true);
  check("red_short.r3d", "red_short.r3d.n.json", false);
}

#[test]
fn red_truncated_header_conformance() {
  // 8 bytes, magic OK, `$size = 0x40 > 8` but the `Read($size-8)` of the
  // remaining header bytes fails ⇒ SetFileType triplet is emitted then
  // `$et->Warn("Truncated R3D file")` (Red.pm:236). Bundled output:
  // ExifToolVersion, Warning, File:{FileType, FileTypeExtension, MIMEType}.
  check(
    "red_truncated_header.r3d",
    "red_truncated_header.r3d.json",
    true,
  );
  check(
    "red_truncated_header.r3d",
    "red_truncated_header.r3d.n.json",
    false,
  );
}

// FORMATS.md row 2 — ID3 pathfinder + MP3 completion. Each fixture is a
// synthetic ID3v2.x or ID3v1 file (no MPEG audio frame body — MPEG.pm is
// row 17, out-of-PR-scope; APE.pm row 5 likewise). The bundled-Perl
// oracle JSON is captured by hand from `perl exiftool -j -G1 -struct …`.

#[test]
fn id3v2_2_conformance() {
  // Synthetic ID3v2.2 file: TT2/TP1/TCO/TCM/COM/PIC frames; no Composite
  // triggers (no Year). Exercises ProcessID3 + ProcessID3v2 (6-byte
  // frame header path) + PIC sub-attribute emission (PIC-1/-2/-3 +
  // binary Picture).
  check("ID3v2_2.mp3", "ID3v2_2.mp3.json", true);
  check("ID3v2_2.mp3", "ID3v2_2.mp3.n.json", false);
}

#[test]
fn id3v1_conformance() {
  // 128-byte ID3v1 TAG trailer + 256 leading null bytes. Year set to
  // `\0\0\0\0` ⇒ ID3v1:Year="" ⇒ Composite:DateTimeOriginal NOT emitted
  // (Perl ValueConv `return undef unless $val[1]`, ID3.pm:853). Exercises
  // ProcessID3 ID3v1 trailer detection + ProcessID3v1 (binary table).
  check("ID3v1.mp3", "ID3v1.mp3.json", true);
  check("ID3v1.mp3", "ID3v1.mp3.n.json", false);
}

#[test]
fn id3v2_3_conformance() {
  // Synthetic ID3v2.3 file: TIT2/TPE1/TALB/TCON/COMM/APIC frames. v2.3
  // uses 10-byte frame headers (a4 N n) and standard int32 sizes.
  check("ID3v2_3.mp3", "ID3v2_3.mp3.json", true);
  check("ID3v2_3.mp3", "ID3v2_3.mp3.n.json", false);
}

#[test]
fn id3v2_4_conformance() {
  // Synthetic ID3v2.4 file: TIT2/TPE1 with sync-safe sizes. Exercises
  // ProcessID3v2 v2.4 sync-safe length detection (the no-iTunes-bug
  // path where sync-safe size IS valid).
  check("ID3v2_4.mp3", "ID3v2_4.mp3.json", true);
  check("ID3v2_4.mp3", "ID3v2_4.mp3.n.json", false);
}

#[test]
fn id3v2_3_extended_header_conformance() {
  // R4-F1 regression — pins the FAITHFUL bundled-Perl behavior:
  //   ID3.pm:1481 `$hBuff = substr($hBuff, $len)` strips EXACTLY $len
  //   bytes from the buffer, where $len is the writer's ext-header
  //   length-field value. Canonical real-world ID3v2.3 writers store
  //   $len = total_ext_header_size INCLUDING the 4-byte length field
  //   (verified against bundled `perl exiftool` on this fixture).
  //   Naively "fixing" the strip to `$len + 4` would diverge from
  //   bundled — Codex review R4 misread the ID3 spec on this point.
  //
  // The fixture is a v2.3 file with ext-header value=10 (full ext
  // size) + TIT2 frame. Bundled emits ID3v2_3:Title="ExtHdr".
  check("ID3v2_3_exthdr.mp3", "ID3v2_3_exthdr.mp3.json", true);
  check("ID3v2_3_exthdr.mp3", "ID3v2_3_exthdr.mp3.n.json", false);
}

#[test]
fn id3v2_corrupt_with_valid_id3v1_trailer_conformance() {
  // R3-F1 regression: a file with a corrupt ID3v2 header (here `ID3v5`,
  // unsupported) BUT a valid ID3v1 trailer at the end. Bundled ID3.pm
  // `last`s out of the v2 header loop (ID3.pm:1454-1465) AND CONTINUES
  // to the ID3v1 trailer scan at ID3.pm:1510-1517 — the trailer tags
  // must still be emitted. Previously my port early-returned on the
  // v5 Warn and dropped all ID3v1 tags. Pinned by this conformance:
  // `Warning="Unsupported ID3 version: 2.5.0"` + full ID3v1:* tag set.
  check("ID3v2_v5_with_v1.mp3", "ID3v2_v5_with_v1.mp3.json", true);
  check("ID3v2_v5_with_v1.mp3", "ID3v2_v5_with_v1.mp3.n.json", false);
}

#[test]
fn id3v2_4_big_frame_conformance() {
  // R2 regression — v2.4 single frame with sync-safe size > 127 followed
  // by EOF (no terminator). Bundled `ProcessID3v2` (ID3.pm:1143-1152)
  // emits `[minor] Missing ID3 terminating frame` Warn AND extracts the
  // 200-byte title. Previously my port defaulted to RAW int32 in the
  // sync-safe-above-127 branch and dropped the frame. Pinned by this
  // conformance fixture: 200 'A's + the bundled Warn.
  check("ID3v2_4_big.mp3", "ID3v2_4_big.mp3.json", true);
  check("ID3v2_4_big.mp3", "ID3v2_4_big.mp3.n.json", false);
}

#[test]
fn id3v5_unsupported_conformance() {
  // ID3 magic + version 5.0 ⇒ ExifTool emits Warn "Unsupported ID3
  // version: 2.5.0" (ID3.pm:1460). $rtnVal=1 was set at ID3.pm:1453
  // BEFORE the version check, so SetFileType('MP3') + ID3Size=0 still
  // run in the post-loop rtnVal-truthy block (ID3.pm:1580-1611).
  check("ID3v5_unsupported.mp3", "ID3v5_unsupported.mp3.json", true);
  check(
    "ID3v5_unsupported.mp3",
    "ID3v5_unsupported.mp3.n.json",
    false,
  );
}

#[test]
fn id3_with_mpeg_audio_conformance() {
  // R1-F1 regression pin: ID3v2 header + MPEG Layer-III audio frames in
  // the same MP3 file. Bundled `ProcessMP3` (ID3.pm:1684-1727) emits
  // BOTH `ID3v2_*:Title` AND `MPEG:*` audio tags via the recursive
  // @audioFormats dance (ID3.pm:1580-1602, recursive ProcessID3 returns
  // 0 due to DoneID3 flag ⇒ unless-rtnVal branch ID3.pm:1696-1719 runs
  // ParseMPEGAudio on the post-ID3 buffer). Fixture is a hand-crafted
  // 57-byte MP3 with a 25-byte ID3v2.3 header containing TIT2="Test"
  // followed by a single MPEG-1 Layer-III frame.
  check(
    "ID3v2_with_mpeg_audio.mp3",
    "ID3v2_with_mpeg_audio.mp3.json",
    true,
  );
  check(
    "ID3v2_with_mpeg_audio.mp3",
    "ID3v2_with_mpeg_audio.mp3.n.json",
    false,
  );
}

#[test]
fn mp3_with_large_id3v2_artwork_conformance() {
  // Codex R5 high-severity regression pin: an MP3 with a large ID3v2.3
  // header (9261-byte body, containing a 9216-byte APIC artwork JPEG)
  // followed by a valid MPEG-1 Layer-III frame. The post-ID3 audio frame
  // sits at offset 9271 (> 8192) — beyond the 8192-byte `$scanLen`
  // window from offset 0.
  //
  // Bundled `ProcessMP3` (ID3.pm:1684-1729) handles this via the audio
  // loop at ID3.pm:1580-1601: ProcessID3 finds the ID3v2 prefix, sets
  // `$rtnVal=1` and `$$et{DoneID3}=1`, then the foreach @audioFormats
  // loop does `$raf->Seek($hdrEnd, 0)` (ID3.pm:1590) BEFORE invoking the
  // recursive ProcessMP3, which then reads a FRESH 8192-byte buffer from
  // the post-ID3 file position. Without that seek-then-read, the audio
  // frame is silently missed.
  //
  // Pre-fix: exifast scanned `data[..8192]` from offset 0 — the post-ID3
  // audio frame at offset 9271 was NEVER reached, so `MPEG:*` tags
  // were silently dropped. Post-fix: id3/process.rs threads `hdr_end`
  // through to mpeg::ProcessMp3.process_with_start_offset, mirroring
  // bundled's `Seek($hdrEnd, 0)` + `Read($buff, $scanLen)` pair byte-
  // for-byte.
  //
  // Goldens captured via bundled Perl ExifTool 13.58 with
  // `-x System:all -x Composite:all` (same exclusions as
  // `id3_with_mpeg_audio_conformance` — Composite:Duration is engine-
  // deferred per the FLAC-id3-prefix precedent).
  check(
    "mp3_with_large_id3v2_artwork.mp3",
    "mp3_with_large_id3v2_artwork.mp3.json",
    true,
  );
  check(
    "mp3_with_large_id3v2_artwork.mp3",
    "mp3_with_large_id3v2_artwork.mp3.n.json",
    false,
  );
}

#[test]
fn flac_conformance() {
  // FLAC.pm:239-280 + Vorbis.pm:157-210. The fixture's metadata blocks
  // contain a StreamInfo (block 0) AND a VorbisComment (block 4) with
  // vendor + 6 user comments (REPLAYGAIN_*, Title, Copyright). Goldens
  // are captured from bundled Perl ExifTool 13.58.
  check("FLAC.flac", "FLAC.flac.json", true);
  check("FLAC.flac", "FLAC.flac.n.json", false);
}

#[test]
fn bad_flac_conformance() {
  // Adversarial: `fLaC` + 4-byte StreamInfo header claiming 1 MiB payload
  // (truncated). FLAC.pm:263 sets $err=1, :278 emits 'Format error in
  // FLAC file' warning; :279 still returns 1 (SetFileType already fired
  // at :255). Goldens captured by hand from bundled Perl ExifTool
  // (gen_golden.sh can't handle ExifTool exit 1 — see [[exifast-phase2-
  // forward-items]]).
  check("bad_flac.flac", "bad_flac.flac.json", true);
  check("bad_flac.flac", "bad_flac.flac.n.json", false);
}

#[test]
fn flac_multi_artist_conformance() {
  // R1-F2 regression pin: Vorbis.pm:85 `ARTIST => { List => 1 }`. Fixture
  // is a synthetic FLAC with StreamInfo + VorbisComment containing two
  // ARTIST entries. Bundled ExifTool emits `"Vorbis:Artist": ["Alice",
  // "Bob"]` (JSON array); exifast must coalesce same-(group, name)
  // repeats via `push_listable` (ExifTool.pm:9520).
  check(
    "FLAC_multi_artist.flac",
    "FLAC_multi_artist.flac.json",
    true,
  );
  check(
    "FLAC_multi_artist.flac",
    "FLAC_multi_artist.flac.n.json",
    false,
  );
}

#[test]
fn red2_framerate_div_by_zero_conformance() {
  // Codex round-3 F1 regression: RED2 `int16u[3]` at offset 0x56 is
  // `(0, 0, 24000)` — the first word (`$a[0]`) is zero. Perl ValueConv
  // `($a[1]*0x10000 + $a[2])/$a[0]` dies with `Illegal division by zero`
  // inside `GetValue`'s eval (ExifTool.pm:3652-3655); the resulting
  // `$value = undef` drops the `Red:FrameRate` tag from output. Bundled
  // `perl exiftool -j -G` on this fixture emits RedcodeVersion / ImageWidth
  // / ImageHeight (extracted before FrameRate) but no `Red:FrameRate` —
  // empirically verified.
  check(
    "red2_framerate_div_by_zero.r3d",
    "red2_framerate_div_by_zero.r3d.json",
    true,
  );
  check(
    "red2_framerate_div_by_zero.r3d",
    "red2_framerate_div_by_zero.r3d.n.json",
    false,
  );
}

#[test]
fn flac_id3_prefix_conformance() {
  // R1-F1 regression pin: FLAC.pm:244-247 ID3-prefix dispatch. Fixture is
  // a real FLAC body prefixed with a (10-byte, no-extended-header) empty
  // ID3v2 tag. Bundled ExifTool runs `ID3::ProcessID3` first (emits
  // `File:ID3Size = 10` + any ID3v2 frames) then extracts the FLAC body.
  //
  // F1 fix (Codex adversarial): `flac::parse_inner` now invokes the typed
  // `parse_id3_with_hdr_end` (same nesting pattern APE/DSF use) and the
  // sink emits the chained ID3 sub-Meta BEFORE the FLAC body tags. The
  // golden is regenerated UNTRIMMED from bundled — `File:ID3Size = 10`
  // is committed (the previous hand-trim is removed).
  check("FLAC_id3_prefix.flac", "FLAC_id3_prefix.flac.json", true);
  check("FLAC_id3_prefix.flac", "FLAC_id3_prefix.flac.n.json", false);
}

#[test]
fn flac_picture_conformance() {
  // R1-F3 regression pin: FLAC.pm:51-54 Picture block (subdir to
  // %FLAC::Picture). Fixture is a synthetic FLAC carrying a Picture
  // block with PictureType + MIME + Description + Width/Height/
  // BitsPerPixel/IndexedColors + raw PNG bytes. exifast must emit
  // ALL ported sub-fields byte-equivalent to bundled `perl exiftool -j`.
  check("FLAC_picture.flac", "FLAC_picture.flac.json", true);
  check("FLAC_picture.flac", "FLAC_picture.flac.n.json", false);
}

#[test]
fn flac_coverart_conformance() {
  // R1-F3 regression pin: Vorbis.pm:97-105 `COVERART => { Binary => 1,
  // ValueConv => DecodeBase64 }`. Fixture is a FLAC with a VorbisComment
  // block containing COVERART (base64 of raw image bytes) +
  // COVERARTMIME=image/jpeg + TITLE. Bundled `perl exiftool -j` emits
  // `"Vorbis:CoverArt": "(Binary data 27 bytes, use -b option to
  // extract)"` after decoding. exifast must match byte-equivalent.
  check("FLAC_coverart.flac", "FLAC_coverart.flac.json", true);
  check("FLAC_coverart.flac", "FLAC_coverart.flac.n.json", false);
}

#[test]
fn flac_metadata_block_picture_conformance() {
  // R1-F3 regression pin: Vorbis.pm:122-135
  // `METADATA_BLOCK_PICTURE => { RawConv => DecodeBase64, SubDirectory =>
  // FLAC::Picture }`. Bundled ExifTool's ProcessDirectory recursion guard
  // (ExifTool.pm:9056-9059) fires here invariably ("Picture pointer
  // references previous VorbisComment directory") — verified via `perl
  // exiftool -j -G1` on a synthetic fixture (2026-05-20). The Picture
  // sub-fields are NOT emitted; only the warning is. exifast mirrors
  // that faithful disposition exactly.
  check("FLAC_mbpicture.flac", "FLAC_mbpicture.flac.json", true);
  check("FLAC_mbpicture.flac", "FLAC_mbpicture.flac.n.json", false);
}

#[test]
fn flac_id3v24_footer_conformance() {
  // R2-F1 regression pin: ID3.pm:1484-1487 — `if ($flags & 0x10) { $raf->
  // Seek(10, 1); }` skips the optional v2.4 footer (10 bytes) AFTER the
  // header + synchsafe-size payload. Fixture is a real FLAC body prefixed
  // with an ID3v2.4 header (flags=0x10, size=0) immediately followed by a
  // 10-byte `3DI` footer and the `fLaC` magic. Bundled ExifTool runs
  // `ID3::ProcessID3` (emits `File:ID3Size = 10`), then extracts the FLAC
  // body.
  //
  // F1 fix (Codex adversarial): the typed FLAC parser nests the ID3 sub-
  // Meta via `parse_id3_with_hdr_end` (which honours the v2.4 footer flag
  // in its hdr_end calculation, matching ID3.pm:1484-1487). The golden
  // is regenerated UNTRIMMED — `File:ID3Size = 10` is committed.
  check(
    "FLAC_id3v24_footer.flac",
    "FLAC_id3v24_footer.flac.json",
    true,
  );
  check(
    "FLAC_id3v24_footer.flac",
    "FLAC_id3v24_footer.flac.n.json",
    false,
  );
}

#[test]
fn id3v2_short_header_conformance() {
  // ID3 magic + only 2 bytes total (5 bytes of header). ID3.pm:1454
  // `$raf->Read($hBuff,7)==7 or $et->Warn('Short ID3 header'), last`.
  // Same rtnVal-was-already-1 pattern: File:* + ID3Size=0 still emitted.
  check("ID3v2_short.mp3", "ID3v2_short.mp3.json", true);
  check("ID3v2_short.mp3", "ID3v2_short.mp3.n.json", false);
}

#[test]
fn id3v2_truncated_data_conformance() {
  // ID3 magic + declared size 100 but only 3 body bytes. ID3.pm:1464
  // Warn "Truncated ID3 data".
  check("ID3v2_truncated.mp3", "ID3v2_truncated.mp3.json", true);
  check("ID3v2_truncated.mp3", "ID3v2_truncated.mp3.n.json", false);
}

#[test]
fn no_ext_layer2_mpeg_conformance() {
  // R8-F1 regression. A dotless file whose contents start with the valid
  // MPEG Layer-II frame sync `ff fd 90 4c`. Bundled `ProcessMP3`
  // (ID3.pm:1684-1728) invokes `ParseMPEGAudio` with `$mp3 = 1` because
  // `$ext ne 'MUS'` (ID3.pm:1715-1717); the Layer-III gate at
  // MPEG.pm:485 then rejects this sync (`0x040000 != 0x020000`).
  // Without the .mp3 extension MPEG.pm:488 `return 0 unless $ext eq
  // 'MP3'` bails immediately, so the candidate loop continues and the
  // post-loop emits `Unknown file type`. Previously my port used the
  // same `ext_is_mp3` boolean for both the 8192-byte scan window AND
  // the Layer-III gate — for a non-MP3-ext dispatch path it skipped
  // the Layer-III check and would have accepted this Layer-II header.
  // Pinned: `Error="Unknown file type"`, no `File:*` tags.
  check(
    "no_ext_layer2_mpeg.bin",
    "no_ext_layer2_mpeg.bin.json",
    true,
  );
  check(
    "no_ext_layer2_mpeg.bin",
    "no_ext_layer2_mpeg.bin.n.json",
    false,
  );
}

#[test]
fn red2_short_first_block_conformance() {
  // Codex round-2 F2 regression: RED2 declared `$size = 0x40` (< 0x44),
  // file has trailing bytes past the declared first block. Pre-fix this
  // port would read `rdi/rda/rdx` from offsets 0x40..0x42 of the FULL
  // file (outside `$buff`), compute a nonsense directory position, and
  // enter fallback scanning. Faithful Perl (Red.pm:251-252) bounds `$buff`
  // to `$size` first, then checks `length($buff) < 0x44` and warns
  // "Truncated R3D file" — RedcodeVersion still flows from the prior
  // RED2 subtable extraction (Red.pm:175-206 read at offset 0x07).
  check(
    "red2_short_first_block.r3d",
    "red2_short_first_block.r3d.json",
    true,
  );
  check(
    "red2_short_first_block.r3d",
    "red2_short_first_block.r3d.n.json",
    false,
  );
}

#[test]
fn flac_picture_truncated_conformance() {
  // R2-F3 regression pin: FLAC.pm:131 `Picture => undef[$val{7}]` ⇒
  // ExifTool.pm:6290-6298 `ReadValue` clamps `count` to the remaining
  // bytes (`$count = int($size / $len)`) and emits the partial blob.
  // Fixture declares PictureLength=8 but supplies only 4 payload bytes;
  // bundled emits `Picture` as `(Binary data 4 bytes, use -b option to
  // extract)` (the clamped count) and still emits every preceding sub-
  // field of the Picture block. exifast must match byte-equivalent.
  check(
    "FLAC_picture_truncated.flac",
    "FLAC_picture_truncated.flac.json",
    true,
  );
  check(
    "FLAC_picture_truncated.flac",
    "FLAC_picture_truncated.flac.n.json",
    false,
  );
}

#[test]
fn id3v2_3_with_v2_4_frame_conformance() {
  // R8-F2 regression (v2.3 → v2.4 fallback). A v2.3 file containing
  // a v2.4-only frame (`TMOO` = Mood). Bundled ID3.pm:833-836
  // `%otherTable` maps v2.3 ↔ v2.4; ID3.pm:1166-1172: when the per-
  // frame `GetTagInfo` misses in the current-version table, the alt
  // table is consulted, and on a hit a minor `Warn("Frame '${id}' is
  // not valid for this ID3 version", 1)` is emitted + the tag IS still
  // extracted under the alt table's `TagDef` (whose `group1()` is
  // `ID3v2_4`). TMOO chosen because it is NOT a Composite source
  // (Composite tag derivation is out-of-PR-scope, row 17 +); pins
  // the fallback emission without depending on out-of-scope Composite
  // machinery. Pinned: `Warning="[minor] Frame 'TMOO' is not valid
  // for this ID3 version"` + `ID3v2_4:Mood="Happy"`.
  check(
    "ID3v2_3_with_v2_4_frame.mp3",
    "ID3v2_3_with_v2_4_frame.mp3.json",
    true,
  );
  check(
    "ID3v2_3_with_v2_4_frame.mp3",
    "ID3v2_3_with_v2_4_frame.mp3.n.json",
    false,
  );
}

#[test]
fn flac_duration_conformance() {
  // R2-F2 regression pin: FLAC.pm:137-149 `%FLAC::Composite` Duration =
  // `($val[0] and $val[1]) ? $val[1] / $val[0] : undef` (TotalSamples /
  // SampleRate) with `PrintConv => 'ConvertDuration($val)'`. Fixture is
  // a synthetic FLAC with TotalSamples=240000 and SampleRate=8000 ⇒
  // duration=30.0 s; bundled emits `"Composite:Duration": "0:00:30"`
  // (default, formatted by ConvertDuration / `sprintf("%d:%.2d:%.2d")`
  // ExifTool.pm:6883) and `"Composite:Duration": 30` under `-n` (raw
  // numeric).
  check("FLAC_duration.flac", "FLAC_duration.flac.json", true);
  check("FLAC_duration.flac", "FLAC_duration.flac.n.json", false);
}

#[test]
fn id3v2_4_with_v2_3_frame_conformance() {
  // R8-F2 regression (v2.4 → v2.3 fallback). A v2.4 file containing
  // a v2.3-only frame (`TSIZ` = Size). Symmetric to the above; bundled
  // emits the same minor Warn but the tag goes under `ID3v2_3:Size`
  // (the alt table's group1). TSIZ chosen because it is NOT a
  // Composite source (Year/Date/Time WOULD trigger
  // Composite:DateTimeOriginal). Pinned: `Warning="[minor] Frame
  // 'TSIZ' is not valid for this ID3 version"` + `ID3v2_3:Size=12345`.
  check(
    "ID3v2_4_with_v2_3_frame.mp3",
    "ID3v2_4_with_v2_3_frame.mp3.json",
    true,
  );
  check(
    "ID3v2_4_with_v2_3_frame.mp3",
    "ID3v2_4_with_v2_3_frame.mp3.n.json",
    false,
  );
}

#[test]
fn id3_dup_short_frame_conformance() {
  // Golden-v2 Phase C — the `[x$n]` multi-warning count (ExifTool.pm:3199-3201
  // + the `WAS_WARNED` dedup at :5632-5639). A crafted ID3v2.3 + minimal MP3
  // with TWO short `COMM` frames (1-byte body each) both trip
  // `$valLen > 4 or $et->Warn("Short COMM frame")` (ID3.pm:1300); ExifTool
  // emits the `Warning` tag ONCE and appends ` [x2]`. Oracle-verified vs
  // `perl exiftool 13.59` (version stamp normalized to 13.58): the SOLE delta
  // vs a single-COMM file is `ExifTool:Warning = "Short COMM frame [x2]"`.
  // Goldens EXCLUDE `Composite:*` (the `%MPEG::Composite` forward item, like
  // every MP3 golden). The `-j`/`-n` warning text is identical (the count is
  // not a PrintConv-toggled value).
  check(
    "ID3_dup_short_frame.mp3",
    "ID3_dup_short_frame.mp3.json",
    true,
  );
  check(
    "ID3_dup_short_frame.mp3",
    "ID3_dup_short_frame.mp3.n.json",
    false,
  );
}

#[test]
fn id3v2_3_invalid_apic_conformance() {
  // R8-F3 regression (APIC Latin). A v2.3 file with a malformed APIC
  // frame: MIME + 0 + picType + description WITHOUT the description's
  // trailing `\0` terminator. Bundled ID3.pm:1321 regex
  // `.(.*?)\0(.)(.*?)\0` does NOT match (final `\0` absent), ID3.pm:
  // 1324 `... or $et->Warn("Invalid $id frame"), next` fires.
  // Previously my port treated the entire remaining buffer as the
  // description and emitted empty image bytes; now the picture frame
  // is skipped entirely. Pinned: `Warning="Invalid APIC frame"` + NO
  // `APIC*` tags.
  check(
    "ID3v2_3_invalid_APIC.mp3",
    "ID3v2_3_invalid_APIC.mp3.json",
    true,
  );
  check(
    "ID3v2_3_invalid_APIC.mp3",
    "ID3v2_3_invalid_APIC.mp3.n.json",
    false,
  );
}

#[test]
fn id3v2_3_invalid_apic_utf16_conformance() {
  // R8-F3 regression (APIC UTF-16). The UTF-16 branch of the bundled
  // regex (ID3.pm:1319 `.(.*?)\0(.)((?:..)*?)\0\0`) requires a word-
  // aligned `\0\0` description terminator; fixture omits it ⇒ same
  // `Invalid APIC frame` Warn + skip semantics.
  check(
    "ID3v2_3_invalid_APIC_utf16.mp3",
    "ID3v2_3_invalid_APIC_utf16.mp3.json",
    true,
  );
  check(
    "ID3v2_3_invalid_APIC_utf16.mp3",
    "ID3v2_3_invalid_APIC_utf16.mp3.n.json",
    false,
  );
}

#[test]
fn id3v2_2_invalid_pic_conformance() {
  // R8-F3 regression (PIC v2.2). The 3-byte image-format + 1-byte
  // picType + description-without-`\0`. Bundled ID3.pm:1321 PIC regex
  // `.(...)(.)(.*?)\0` requires the trailing `\0`; absent ⇒
  // `Warn("Invalid PIC frame")` + frame skipped. Pinned to confirm
  // the v2.2 path uses the `Invalid PIC frame` wording (NOT APIC).
  check(
    "ID3v2_2_invalid_PIC.mp3",
    "ID3v2_2_invalid_PIC.mp3.json",
    true,
  );
  check(
    "ID3v2_2_invalid_PIC.mp3",
    "ID3v2_2_invalid_PIC.mp3.n.json",
    false,
  );
}

#[test]
fn aiff_conformance() {
  // Synthesized AIFF fixture: FORM <sz> AIFF + COMT (1 comment) + COMM
  // (SampleRate=0 keeps Composite Duration's `Require` from firing) +
  // NAME + AUTH + (c) + ANNO + APPL. Exercises every %AIFF::Main scalar
  // tag, %AIFF::Common ProcessBinaryData, %AIFF::Comment ProcessComment,
  // and the AIFF time-epoch ConvertUnixTime path.
  check("AIFF.aif", "AIFF.aif.json", true);
  check("AIFF.aif", "AIFF.aif.n.json", false);
}

#[test]
fn aiff_duplicate_name_chunk_last_wins_conformance() {
  // Codex R11 regression: an AIFF with TWO `NAME` chunks. Perl's FoundTag
  // (`ExifTool.pm:9437-9519`) detects the duplicate and, when both
  // values share the default priority of 1, MOVES the OLD value to a
  // `"Name (1)"` copy-key slot and stores the NEW value under the
  // canonical `"Name"` key. The JSON serializer (`exiftool:2744`) then
  // suppresses any `\(\d+\)` copy-keys via `next if $tag =~ /^(.*?) ?\(/
  // and defined $$info{$1}`. Net effect: LAST chunk's value wins.
  //
  // The prior `Metadata::push` was unconditional-append + first-wins
  // serializer dedup ⇒ FIRST chunk's value won, diverging from Perl.
  // Post-fix: `push` is now replace-in-place for any existing same
  // `group + name` key, faithful to FoundTag's priority-≥-old branch.
  // Oracle (bundled `perl exiftool`, captured 2026-05-20) on a
  // synthesized two-NAME-chunk AIFF (`"First Name"` then `"Second
  // Name"`): emits `"AIFF:Name": "Second Name"`.
  check("AIFF_dup_name.aif", "AIFF_dup_name.aif.json", true);
  check("AIFF_dup_name.aif", "AIFF_dup_name.aif.n.json", false);
}

#[test]
#[ignore = "Phase-2 defer: ID3 SubDirectory dispatch lives in parallel PR #6 (ID3 port). See module-doc of src/formats/aiff.rs and the `ID3 ` branch of process_aiff. This fixture pins the POST-merge oracle output (File:ID3Size + ID3v2_3:Title) so when ID3 lands the test will auto-pass; today it documents the deliberate divergence."]
fn aiff_id3_chunk_subdirectory_dispatch_deferred_conformance() {
  // Codex R12 regression: an AIFF containing an `ID3 ` chunk carrying a
  // minimal ID3v2.3 frame (TIT2 = "Test Title"). Bundled `perl exiftool`
  // (oracle captured 2026-05-20) emits `File:ID3Size` AND `ID3v2_3:Title`
  // via AIFF.pm:69-75's `SubDirectory => { TagTable => 'Image::ExifTool::
  // ID3::Main', ProcessProc => &ProcessID3 }`. exifast's `ID3 ` chunk
  // handler currently silent-skips the body (Phase-2 defer, see module
  // doc of `src/formats/aiff.rs`), so this conformance check would FAIL
  // until the parallel ID3 PR (#6) integrates `ProcessID3`. The fixture
  // and golden are committed NOW so the deferral is empirically
  // documented; the `#[ignore]` attribute holds the test out of the
  // default suite. Remove the `#[ignore]` once ID3 lands and exifast
  // becomes byte-exact here.
  check("AIFF_id3.aif", "AIFF_id3.aif.json", true);
  check("AIFF_id3.aif", "AIFF_id3.aif.n.json", false);
}

#[test]
fn aiff_duration_composite_conformance() {
  // Codex R4 oracle: an AIFF with nonzero SampleRate AND NumSampleFrames
  // MUST emit `Composite:Duration`. Bundled Perl `Image::ExifTool::AIFF
  // ::Composite::Duration` formula: `NumSampleFrames / SampleRate`,
  // PrintConv via `ConvertDuration` (ExifTool.pm:6866). Fixture has
  // SampleRate=22050, NumSampleFrames=44100 ⇒ 2.0 s. Default ⇒
  // `"2.00 s"` (sprintf %.2f); `-n` ⇒ bare `2` (the raw f64 stringified
  // by the EscapeJSON gate; `format_g(2.0,15) == "2"`).
  check("AIFF_duration.aif", "AIFF_duration.aif.json", true);
  check("AIFF_duration.aif", "AIFF_duration.aif.n.json", false);
}

#[test]
fn aiff_duration_float_sample_rate_conformance() {
  // Codex R6 regression: AIFF SampleRate is 80-bit extended (AIFF.pm:91);
  // `get_extended` returns `TagValue::F64` for non-integer rates and
  // `TagValue::I64` for the common integer case. The prior I64-only match
  // in `emit_composite_duration` silently dropped Duration whenever the
  // rate was non-integer (e.g. NTSC pull-down 44056.94 Hz). This fixture
  // pins SampleRate=22050.5 with NumSampleFrames=44101 ⇒ exactly 2.0 s,
  // forcing the f64 branch through `tag_as_f64` and verifying that the
  // `(Some(sr), Some(nf))` destructure now succeeds. Default ⇒ `"2.00 s"`
  // (sprintf %.2f); `-n` ⇒ bare `2` (format_g(2.0,15) == "2").
  check(
    "AIFF_duration_float.aif",
    "AIFF_duration_float.aif.json",
    true,
  );
  check(
    "AIFF_duration_float.aif",
    "AIFF_duration_float.aif.n.json",
    false,
  );
}

#[test]
fn aifc_noninteger_sample_rate_conformance() {
  // Codex R6 regression (AIFC variant): non-integer 80-bit extended rate
  // 44056.94 Hz (the canonical NTSC pull-down rate 44100 * 1000/1001).
  // Exercises the F64 path of `tag_as_f64` for both the SampleRate tag
  // serialization (`AIFF:SampleRate` ⇒ 44056.94) AND the Composite
  // Duration numerator (NumSampleFrames=44057 / 44056.94 ≈ 1.0000013...).
  // Default ⇒ `"1.00 s"` (sprintf %.2f truncates); `-n` ⇒ raw f64
  // `1.00000136187397` (format_g 15-digit roundtrip preserves precision).
  check(
    "AIFC_noninteger_rate.aifc",
    "AIFC_noninteger_rate.aifc.json",
    true,
  );
  check(
    "AIFC_noninteger_rate.aifc",
    "AIFC_noninteger_rate.aifc.n.json",
    false,
  );
}

#[test]
fn aiff_extended_integer_overflow_conformance() {
  // Codex R7 regression: 80-bit extended `403e8000000000000001` decodes to
  // the EXACT integer 2^63 + 1 = 9223372036854775809, which overflows i64.
  // Perl's `GetExtended` preserves the exact integer (Perl scalars keep
  // UV/IV when arithmetic permits), and the EscapeJSON gate quotes any >15
  // digit integer text — so bundled ExifTool emits `AIFF:SampleRate` as
  // the QUOTED string `"9223372036854775809"`. Prior `(sig as f64) as i64`
  // rounded the significand to 2^63 (lossy at the 53-bit mantissa boundary)
  // and then saturated the cast to i64::MAX, storing 9223372036854775807.
  // Post-fix `get_extended` uses integer arithmetic on the bit pattern to
  // detect the exact integer value and emits `TagValue::Str("9223372036854775809")`
  // for the >i64::MAX magnitude — the serializer's `is_json_number_literal`
  // gate then quotes it (16+ digits exceeds the `\d{1,15}` cap), byte-exact
  // to Perl. The Composite:Duration with NumSampleFrames=1000 is the
  // same 1000 / 9223372036854775809.0 ≈ 1.0842021724855e-16 in both
  // languages (the f64 division uses the IEEE-754 rounded denominator).
  check(
    "AIFF_ext_int_overflow.aif",
    "AIFF_ext_int_overflow.aif.json",
    true,
  );
  check(
    "AIFF_ext_int_overflow.aif",
    "AIFF_ext_int_overflow.aif.n.json",
    false,
  );
}

#[test]
fn aiff_extended_integer_negative_overflow_conformance() {
  // Codex R7 follow-up: 80-bit extended `c03e8000000000000001` decodes
  // to -(2^63 + 1) = -9223372036854775809, whose magnitude exceeds i64::MIN.
  // Perl's `GetExtended` forces NV here (`-1 * UV` cannot stay UV when
  // UV > i64::MAX), so the scalar becomes NV stringified as `%.15g` ⇒
  // `-9.22337203685478e+18`. Oracle (bundled `perl exiftool`, captured
  // 2026-05-20): `"AIFF:SampleRate": -9.22337203685478e+18` (BARE numeric,
  // not a quoted string — `%.15g` form is < 15 digits with the exponent).
  // The prior `int_or_str` symmetric branch emitted
  // `TagValue::Str("-9223372036854775809")` (exact-decimal quoted), which
  // diverged from the oracle. Post-fix: negatives > 2^63 magnitude route
  // through `TagValue::F64(- mag as f64)`, matching Perl's NV path.
  check(
    "AIFF_ext_int_neg_overflow.aif",
    "AIFF_ext_int_neg_overflow.aif.json",
    true,
  );
  check(
    "AIFF_ext_int_neg_overflow.aif",
    "AIFF_ext_int_neg_overflow.aif.n.json",
    false,
  );
}

#[test]
fn aiff_huge_duration_conformance() {
  // Codex R7 regression: SampleRate extended `3fab8000000000000000` decodes
  // to 2^-84 = 5.16987882845642e-26 (a very small non-integer). With
  // NumSampleFrames=1, Composite:Duration = 1 / 2^-84 = 2^84 ≈
  // 1.93428131138341e+25 seconds. Prior `convert_duration` cast `h/m/s`
  // through `f64::trunc as i64` and SATURATED at i64::MAX for the huge h
  // value, producing wrong sub-day numbers. Perl keeps h/m/d as NV (f64)
  // scalars through the modulo arithmetic, only casting the SMALL
  // REMAINDERS to integer at the final `%d:%.2d:%.2d` printf. Oracle
  // (2026-05-20): default PrintConv ⇒ `"2.23875151780487e+20 days 0:00:00"`
  // (the days count `$d` interpolated via Perl's default NV stringification,
  // byte-exact to `format_g(d, 15)` in scientific notation); `-n` ⇒ raw
  // f64 `1.93428131138341e+25` (format_g(_, 15) roundtrip).
  check(
    "AIFF_huge_duration.aif",
    "AIFF_huge_duration.aif.json",
    true,
  );
  check(
    "AIFF_huge_duration.aif",
    "AIFF_huge_duration.aif.n.json",
    false,
  );
}

#[test]
fn aiff_negative_zero_significand_extended_conformance() {
  // Codex R8 regression: an AIFF SampleRate extended with `sig == 0` but
  // a NON-zero biased exponent and the negative sign bit set
  // (`80010000000000000000`). Mathematically the value is `-1 * 0 *
  // 2^-16445 = 0`. Perl evaluates `$sign * $sig * (2 ** $exp)` and the
  // NV multiplication by 0 yields exactly 0 (the sign bit is dropped by
  // the multiplication itself, NOT preserved as -0). The prior
  // `get_extended` guard was `sig == 0 && biased == 0`, so this
  // adversarial input flowed through the f64 reconstruction `0.0`
  // followed by `-0.0 = -val` ⇒ `TagValue::F64(-0.0)`, and the
  // serializer's `format_g(-0.0, 15)` emitted bare `-0` — diverging
  // from the oracle's bare `0`. Post-fix: `sig == 0` (any biased)
  // short-circuits to `TagValue::I64(0)`, byte-exact.
  check("AIFF_neg_zero_sig.aif", "AIFF_neg_zero_sig.aif.json", true);
  check(
    "AIFF_neg_zero_sig.aif",
    "AIFF_neg_zero_sig.aif.n.json",
    false,
  );
}

#[test]
fn aiff_zero_significand_max_exponent_nan_conformance() {
  // Codex R9 regression: an AIFF SampleRate extended with `sig == 0` AND
  // `biased == 0x7FFF` (the infinity exponent slot, `0x7fff0000000000000000`).
  // Mathematically `0 * 2 ** 16321 = 0 * Inf = NaN` per IEEE-754. Perl's
  // NV multiplication `$sig * (2 ** $exp)` with `$sig = 0` and `$exp = 16321`
  // yields NaN, which Perl stringifies as titlecase `NaN`. The R8 fix
  // `sig == 0 ⇒ I64(0)` was too broad — it returned bare 0 here, diverging
  // from oracle's `"NaN"`. Post-fix: the short-circuit fires only when
  // `biased != 0x7FFF`; the infinity-exponent + zero-sig case falls
  // through to the f64 path where `0.0 * 2^16321 = NaN` is propagated
  // via `perl_nonfinite_str`. Oracle (2026-05-20) confirms both
  // SampleRate and Composite:Duration emit quoted `"NaN"` (the
  // ConvertDuration `unless IsFloat` branch on a NaN also returns NaN).
  check(
    "AIFF_zero_sig_max_exp.aif",
    "AIFF_zero_sig_max_exp.aif.json",
    true,
  );
  check(
    "AIFF_zero_sig_max_exp.aif",
    "AIFF_zero_sig_max_exp.aif.n.json",
    false,
  );
}

#[test]
fn aiff_infinity_sample_rate_conformance() {
  // Codex R8 regression: an AIFF SampleRate extended with the maximum
  // biased exponent (`7fff8000000000000000`). The 80-bit-extended-to-f64
  // reconstruction overflows to `f64::INFINITY`. Perl's NV scalar for
  // infinity stringifies as titlecase `Inf` (verified 2026-05-20 via
  // `perl -e 'print 1e308*1e308'` ⇒ `Inf`). Prior `serialize.rs` non-
  // finite branch called `f64::to_string` which emits lowercase `inf` —
  // diverging from the oracle. Post-fix: `perl_nonfinite_str` produces
  // titlecase `Inf`/`-Inf`/`NaN`, byte-exact to Perl. The
  // Composite:Duration falls through as `1000.0 / inf = 0.0` ⇒ default
  // PrintConv `"0 s"` (the `time == 0.0` branch of ConvertDuration),
  // `-n` ⇒ bare `0`.
  check(
    "AIFF_inf_sample_rate.aif",
    "AIFF_inf_sample_rate.aif.json",
    true,
  );
  check(
    "AIFF_inf_sample_rate.aif",
    "AIFF_inf_sample_rate.aif.n.json",
    false,
  );
}

#[test]
fn aiff_exp53_integer_fits_i64_routes_via_nv_conformance() {
  // Codex R10 regression: SampleRate extended `40730000000000000001`
  // (biased=0x4073=16499, exp=53, sig=1). Mathematically `1 * 2^53 =
  // 9007199254740992` is an EXACT integer that fits i64. The prior
  // `exp >= 0` integer-detection path emitted `TagValue::Str
  // ("9007199254740992")` (16 digits ⇒ EscapeJSON quote), but Perl's
  // `$sig * (2 ** $exp)`:
  // - `2 ** 53` is NV (Devel::Peek-verified)
  // - `UV(1) * NV(2^53)`: when the NV factor != 1, Perl's multiplication
  //   PROMOTES to NV; the result is NV(9007199254740992) which
  //   stringifies via `%.15g` to `9.00719925474099e+15`.
  // Oracle (2026-05-20) confirms BARE `9.00719925474099e+15` (NV
  // scientific). Post-fix: the integer-detection path fires ONLY when
  // `exp == 0` (the only case where `2**exp = 1` and Perl preserves
  // UV); for any `exp != 0`, route through f64/NV. Pinned by this
  // adversarial input where the int_or_str path WOULD have fit i64 but
  // Perl's NV typing means the output must be scientific.
  check(
    "AIFF_r10_exp53_fits_i64.aif",
    "AIFF_r10_exp53_fits_i64.aif.json",
    true,
  );
  check(
    "AIFF_r10_exp53_fits_i64.aif",
    "AIFF_r10_exp53_fits_i64.aif.n.json",
    false,
  );
}

#[test]
fn aiff_first_overflow_zero_significand_conformance() {
  // Codex R9 recommendation: pin the "first-overflow zero significand"
  // boundary — SampleRate extended `443e0000000000000000` (biased =
  // 0x443E = 17470, exp = 17470-16383-63 = 1024, sig = 0). Even though
  // sig=0, `2^1024` overflows f64 to Inf at the f64::MAX_EXP boundary,
  // so `0 * 2^1024 = 0 * Inf = NaN`. Oracle (2026-05-20) emits
  // `"AIFF:SampleRate": "NaN"` and `"Composite:Duration": "NaN"` —
  // pinning the gate `2f64.powi(exp).is_finite()` for the sig==0
  // short-circuit (the prior `biased != 0x7FFF` test was too lax: any
  // `exp >= 1024` overflows even though `biased < 0x7FFF`).
  check(
    "AIFF_first_overflow_zero_sig.aif",
    "AIFF_first_overflow_zero_sig.aif.json",
    true,
  );
  check(
    "AIFF_first_overflow_zero_sig.aif",
    "AIFF_first_overflow_zero_sig.aif.n.json",
    false,
  );
}

#[test]
fn aiff_first_nv_exponent_conformance() {
  // Codex R9 recommendation: pin the "first NV exponent" boundary —
  // SampleRate extended `40738000000000000000` (biased=0x4073=16499,
  // exp=16499-16383-63=53, sig=2^63). Pure-integer value: 2^63 * 2^53
  // = 2^116. u128 holds this (sig_bits=64, shift=53, total=117 <= 128),
  // so `int_or_str(false, 2^116)` ⇒ magnitude > u64::MAX ⇒ Perl forces
  // NV ⇒ `TagValue::F64(2^116 as f64)`. The serializer's `format_g(_,
  // 15)` then produces `8.30767497365572e+34` — byte-exact to Perl's
  // `%.15g` of 2^116 (oracle 2026-05-20). Pins the int_or_str
  // `mag > u64::MAX ⇒ F64` branch as the "first NV exponent" boundary.
  check("AIFF_first_nv_exp.aif", "AIFF_first_nv_exp.aif.json", true);
  check(
    "AIFF_first_nv_exp.aif",
    "AIFF_first_nv_exp.aif.n.json",
    false,
  );
}

#[test]
fn aiff_huge_positive_exponent_overflow_conformance() {
  // Codex R9 regression: SampleRate extended `407f8000000000000000` —
  // biased exp 0x407F = 16511, exp = 16511 - 16383 - 63 = 65, sig =
  // 0x8000000000000000 (= 2^63). Pure-integer value: 2^63 * 2^65 = 2^128.
  // u128 cannot exactly hold 2^128, so the `exp >= 0` integer-detection
  // branch MUST detect this overflow and fall through to the f64/NV path.
  //
  // The prior `(sig as u128).checked_shl(shift)` ONLY checked the shift
  // amount (< 128), NOT the value-overflow: `(2^63_u128) << 65` returned
  // `Some(0)` because the high bit was silently dropped, then
  // `int_or_str(false, 0)` emitted `I64(0)`, diverging from Perl's
  // `3.40282366920938e+38` (= 2^128 as NV, byte-exact `%.15g`).
  //
  // Post-fix uses the precise bit-count gate `64 - sig.leading_zeros() +
  // shift <= 128`; here `64 - 1 + 65 = 128` ≤ 128, so the path COULD
  // proceed — but the result `2^128` overflows u128 to 0 anyway. Actually
  // the correct gate is STRICT `< 128` for sig with high bit set when
  // the shift would push it past u128. Bundled oracle (2026-05-20):
  // `AIFF:SampleRate = 3.40282366920938e+38` (bare NV) and
  // `Composite:Duration = "0.00 s"` (1000/2^128 ≈ 2.94e-36, <30s ⇒
  // `%.2f s` ⇒ "0.00 s").
  check("AIFF_huge_pos_exp.aif", "AIFF_huge_pos_exp.aif.json", true);
  check(
    "AIFF_huge_pos_exp.aif",
    "AIFF_huge_pos_exp.aif.n.json",
    false,
  );
}

#[test]
fn aifc_conformance() {
  // Synthesized AIFC: FORM <sz> AIFC + FVER + COMM (with CompressionType
  // + CompressorName pstring) + NAME. Exercises the AIFC magic path
  // (SetFileType("AIFC")), the FVER FormatVersionTime branch, and the
  // CompressionType PrintConv hash + pstring decode in COMM.
  check("AIFC.aifc", "AIFC.aifc.json", true);
  check("AIFC.aifc", "AIFC.aifc.n.json", false);
}

#[test]
fn aifc_macroman_high_byte_compressor_name_conformance() {
  // Codex R1 regression: AIFC `CompressorName` pstring carrying MacRoman
  // high bytes 0x80 ("Ä") and 0x81 ("Å"). A prior
  // `from_utf8(...).unwrap_or_default()` in the binary engine would have
  // corrupted 0x80 (invalid UTF-8 start) to the empty string and lost the
  // tag; the post-fix path emits raw `TagValue::Bytes` that the MacRoman
  // ValueConv decodes faithfully. Oracle (bundled `perl exiftool`, captured
  // 2026-05-20): `AIFF:CompressorName = "Ä Å"` (U+00C4 U+0020 U+00C5).
  check("AIFC_macroman.aifc", "AIFC_macroman.aifc.json", true);
  check("AIFC_macroman.aifc", "AIFC_macroman.aifc.n.json", false);
}

#[test]
fn aifc_highbyte_compressiontype_conformance() {
  // Codex R3 regression: AIFC `CompressionType` (a no-ValueConv string[4]
  // with a hash PrintConv) carrying the invalid-UTF-8 lead byte 0x80
  // followed by ASCII "ABC". Perl's hash PrintConv lookup misses (no key
  // matches the raw 4 bytes), so the fallback path is `"Unknown ($val)"`,
  // where `$val` flows through `EscapeJSON` → `FixUTF8` (XMP.pm:2943):
  // invalid bytes are replaced with `?`. Bundled `perl exiftool` (oracle
  // captured 2026-05-20) emits `"Unknown (?ABC)"` under default PrintConv
  // and `"?ABC"` under `-n`. The earlier Latin-1 1:1 mapping in
  // `convert::exiftool_val_string` + the no-ValueConv `Bytes → Str` arms
  // in `processbinarydata.rs:323-326` and `formats/aiff.rs::APPL` would
  // have emitted `"\u{0080}ABC"` instead. This fixture pins the FixUTF8
  // path end-to-end on both the PrintConv (hash-key fallback) and `-n`
  // (raw byte-string serialize) branches.
  check(
    "AIFC_highbyte_comp.aifc",
    "AIFC_highbyte_comp.aifc.json",
    true,
  );
  check(
    "AIFC_highbyte_comp.aifc",
    "AIFC_highbyte_comp.aifc.n.json",
    false,
  );
}

#[test]
fn aifc_pre1970_format_version_time_conformance() {
  // Codex R4 regression: AIFC `FormatVersionTime` with raw u32 = 0 ⇒
  // pre-Unix-epoch timestamp `-2_082_844_800` after the AIFF.pm:26
  // `$val - ((66 * 365 + 17) * 24 * 3600)` subtraction. Perl runs
  // `gmtime` on the signed difference; `datetime::convert_unix_time`
  // here likewise decodes negative input via the proleptic Gregorian
  // Hinnant algorithm. Oracle (bundled `perl exiftool`, captured
  // 2026-05-20): `"1904:01:01 00:00:00"` — the Mac/AIFF epoch itself.
  // Codex R4 raised a `saturating_sub` concern as the source of a
  // potential zero-date sentinel; empirical refutation: the input is an
  // `i64` carrying a `u32`, so `0_i64.saturating_sub(2_082_844_800) =
  // -2_082_844_800` (identical to signed subtraction — `i64` saturates
  // at `i64::MIN`, not at 0). The code now uses plain `-` for clarity
  // and this fixture pins the negative-result path so any future
  // refactor toward `u64` / wrapping math is caught immediately.
  check("AIFC_pre1970.aifc", "AIFC_pre1970.aifc.json", true);
  check("AIFC_pre1970.aifc", "AIFC_pre1970.aifc.n.json", false);
}

#[test]
fn aifc_truncated_comm_conformance() {
  // Codex R3 regression: a truncated AIFC COMM chunk that provides only 1
  // byte of `CompressionType` (declared `string[4]`). ExifTool's `ReadValue`
  // (ExifTool.pm:6290-6293) shortens the count to the remaining bytes
  // (`int(size/len)`) and still emits a value when `count >= 1`; only when
  // zero bytes are available does it return `undef`. A prior
  // `if more < n { None }` bailout in `processbinarydata::StringFixed`
  // silently dropped truncated fields. Oracle (bundled `perl exiftool`,
  // captured 2026-05-20): `CompressionType = "Unknown (N)"` under default
  // PrintConv and `"N"` under `-n`; `CompressorName` is absent (no body
  // bytes for the pstring length byte after the clamped CompressionType).
  check(
    "AIFC_truncated_comm.aifc",
    "AIFC_truncated_comm.aifc.json",
    true,
  );
  check(
    "AIFC_truncated_comm.aifc",
    "AIFC_truncated_comm.aifc.n.json",
    false,
  );
}

#[test]
fn aiff_short_header_error_conformance() {
  // Adversarial: 11-byte FORM header (`FORM\0\0\0\x10AIF`) — too short for
  // the 12-byte magic verify (AIFF.pm:191). Reject before SetFileType
  // ⇒ no AIFF parser finalizes ⇒ the post-loop ExifTool:Error block fires
  // (ExifTool.pm:3080-3128). With the .aif extension a known type was
  // detected ⇒ 'File format error' (ExifTool.pm:3093).
  check("AIFF_short.aif", "AIFF_short.aif.json", true);
  check("AIFF_short.aif", "AIFF_short.aif.n.json", false);
}

#[test]
fn aiff_large_chunk_warn_conformance() {
  // Adversarial: valid AIFF header + COMM chunk with len=0xFFFFFFFF
  // (`len2 = len + (len & 1) > 100 MB`). Default `LargeFileSupport` is
  // truthy (`1`, ExifTool.pm:1167), so the AIFF.pm:230-235 inner
  // branches all fall through; the AIFF.pm:237-240 "known tagInfo" arm
  // fires ⇒ `Warn("Skipping large Common chunk (> 100 MB)")` + `undef
  // $tagInfo` ⇒ chunk body skipped. The oracle (bundled `perl exiftool`,
  // captured 2026-05-20) emits exactly this warning, then File:* tags.
  check("AIFF_huge.aif", "AIFF_huge.aif.json", true);
  check("AIFF_huge.aif", "AIFF_huge.aif.n.json", false);
}

#[test]
fn ape_id3_prefixed_conformance() {
  // Codex R2-F1 cross-format regression pin: APE.pm:122-127 embedded
  // ID3 dispatch. Fixture is a hand-crafted `.ape` whose first bytes
  // are an ID3v2.3 header (TIT2="TestTitle") followed by a 32-byte
  // MAC header (OldHeader, vers=3970) and an APEv2 trailer (Artist=
  // Tester). Bundled `perl exiftool` (verified 2026-05-20 against
  // 13.58):
  //   - ProcessAPE → ProcessID3 finds ID3 (DoneID3=1, $rtnVal=1).
  //   - ProcessID3's audio-loop (ID3.pm:1582-1601) recursively
  //     ProcessAPE → SetFileType(APE), MAC tags, APE trailer tag.
  //   - ID3.pm:1604 SetFileType('MP3') no-op (first-wins).
  //   - ID3.pm:1606-1611 emit File:ID3Size + ID3v2_3:Title.
  // Faithful Rust port flattens the audio-loop recursion: a single
  // ProcessApe::process runs both ID3 extraction AND the MAC/APE-trailer
  // work. Pinned: File:FileType=APE (not MP3), ID3v2_3:Title=TestTitle,
  // MAC:APEVersion=3.97, APE:Artist=Tester all present.
  check("ape_id3_prefixed.ape", "ape_id3_prefixed.ape.json", true);
  check("ape_id3_prefixed.ape", "ape_id3_prefixed.ape.n.json", false);
}

#[test]
fn mp3_with_apev2_trailer_conformance() {
  // Codex R2-F2 cross-format regression pin: ID3.pm:1722-1727 MP3 →
  // APE trailer fallback. Fixture is a hand-crafted `.mp3` with an
  // ID3v2.3 header (TIT2="TestMp3"), MPEG-1 Layer-III sync frame,
  // and APEv2 trailer (Artist=ApeTester). Bundled flow:
  //   - ProcessMP3 calls ProcessID3 → ID3 detected ($rtnVal=1).
  //   - audio loop's recursive ProcessMP3 invokes ParseMPEGAudio →
  //     MPEG:* tags emitted.
  //   - ProcessID3 emits File:ID3Size + ID3v2_3:Title.
  //   - ID3.pm:1722-1727 `if ($rtnVal and not $$et{DoneAPE}) {
  //     ProcessAPE(...) }` fires; ProcessAPE (chained, FileType set)
  //     finds the APEv2 footer → APE:Artist tag emitted.
  // Faithful port: ProcessMp3::process invokes process_id3_inner +
  // mpeg::ProcessMp3, then if rtn_val && !DoneAPE calls
  // ProcessApe::process_trailer_only — exactly mirroring the bundled
  // ordering.
  check(
    "mp3_with_apev2_trailer.mp3",
    "mp3_with_apev2_trailer.mp3.json",
    true,
  );
  check(
    "mp3_with_apev2_trailer.mp3",
    "mp3_with_apev2_trailer.mp3.n.json",
    false,
  );
}

#[test]
fn dsf_with_id3v2_trailer_conformance() {
  // Codex R2-F3 cross-format regression pin: DSF.pm:88-97 ID3v2
  // trailer at `metaPos`. Fixture is a hand-crafted `.dsf` with
  // valid DSD/fmt/data chunks and an ID3v2.3 trailer pointed-at by
  // `metaPos` (offset 28 of the DSD header). The ID3v2 trailer
  // contains TIT2="DsfTitle". Bundled flow:
  //   - DSF.pm:64 SetFileType (DSF), reads fmt chunk, emits
  //     `File:*` triplet + DSF binary-data tags.
  //   - DSF.pm:88-97 `if ($metaPos and $metaLen > 0 and $metaLen <
  //     20_000_000 and Seek+Read)` ⇒ ProcessDirectory(ID3::Main)
  //     over the trailer slice. PROCESS_PROC = ProcessID3Dir →
  //     ProcessID3 finds ID3 at slice offset 0, emits
  //     File:ID3Size + ID3v2_3:Title.
  // Faithful port: ProcessDsf::process reads metaPos from fmt chunk
  // header, slices `data[metaPos..metaPos+metaLen]`, and dispatches
  // process_id3_v2_slice over it.
  check(
    "dsf_with_id3v2_trailer.dsf",
    "dsf_with_id3v2_trailer.dsf.json",
    true,
  );
  check(
    "dsf_with_id3v2_trailer.dsf",
    "dsf_with_id3v2_trailer.dsf.n.json",
    false,
  );
}

#[test]
fn ape_id3v24_footer_then_mac_conformance() {
  // Codex R3 F1 regression pin: ID3.pm:1443 `$hdrEnd = 0`, :1486
  // `Seek(10, 1)` when `flags & 0x10` (v2.4 footer flag), :1504
  // `$hdrEnd = $raf->Tell()`. Without the +10 advance the chained
  // ProcessAPE re-reads from the wrong offset and sees `3DI` (the
  // footer magic) instead of `MAC ` — bundled finds the MAC body, our
  // pre-fix peek did not.
  //
  // Fixture layout (138 bytes):
  //   * 10-byte ID3v2.4 main header (vers=4.0, flags=0x10 [footer-flag],
  //     syncsafe size=24)
  //   * 24-byte body: TIT2 frame "TestV24Footer" (Title)
  //   * 10-byte FOOTER: `3DI` + vers + flags + size mirror of header
  //   * 32-byte MAC OldHeader (vers=3970, sample rate=44100, etc.)
  //   * 56-byte APEv2 trailer carrying APE:Artist="V24FooterTester"
  //     (32-byte footer + 24-byte tag-entry body)
  //
  // Pre-fix behavior: hdr_end = 10 + 24 = 34, slicing skipped the
  // 10-byte footer — `MAC ` magic was at offset 44 but APE saw the
  // footer bytes at offset 34 (`3DI\x04\x00\x10\x00\x00\x00\x18MAC `),
  // failed the magic check, fell through to the `id3_found` branch and
  // returned silently with NO `MAC:*`/`APE:*` tags.
  //
  // Post-fix behavior (matches bundled `perl exiftool 13.58`):
  // hdr_end = 10 + 24 + 10 = 44 → ape_slice begins at offset 44 with
  // `MAC ...` → full MAC header + APE trailer scan succeeds.
  check(
    "ape_id3v24_footer_then_mac.ape",
    "ape_id3v24_footer_then_mac.ape.json",
    true,
  );
  check(
    "ape_id3v24_footer_then_mac.ape",
    "ape_id3v24_footer_then_mac.ape.n.json",
    false,
  );
}

#[test]
fn mp3_with_apev2_and_id3v1_trailer_conformance() {
  // Codex R3 F2 regression pin: APE.pm:169 `$footPos -= $$et{DoneID3}
  // if $$et{DoneID3} > 1` — when ID3.pm:1527 stores 128 (ID3v1 trailer
  // size) in `$$et{DoneID3}`, the APETAGEX 32-byte trailer header sits
  // at `EOF - 32 - 128`, not `EOF - 32`. Pre-fix our APE scan used
  // `data.len() - 32` unconditionally, landing INSIDE the ID3v1 `TAG`
  // block and silently missing the APE trailer.
  //
  // Fixture layout (252 bytes):
  //   * ID3v2.3 (TIT2="TestMp3Id3v1") — 34 bytes total
  //   * MPEG-1 Layer-III sync frame + padding (32 bytes)
  //   * APEv2 trailer carrying APE:Artist="Mp3ApeArtist" (58 bytes
  //     trailer body + 32-byte footer)
  //   * ID3v1 TAG block (128 bytes) at EOF
  //
  // Post-fix behavior (matches bundled): the APE trailer is found at
  // `EOF - 32 - 128 = 92`, APE:Artist is emitted, AND the ID3v1 trailer
  // tags fire from the standalone ProcessID3 invocation. Bundled also
  // emits Composite:Duration via DoneID3-aware scanning; that composite
  // is the documented ACCEPTED-DEFERRAL hand-trim (Composite engine,
  // Phase 3+ — see docs/tracking.md) so the committed goldens omit it.
  check(
    "mp3_with_apev2_and_id3v1_trailer.mp3",
    "mp3_with_apev2_and_id3v1_trailer.mp3.json",
    true,
  );
  check(
    "mp3_with_apev2_and_id3v1_trailer.mp3",
    "mp3_with_apev2_and_id3v1_trailer.mp3.n.json",
    false,
  );
}

#[test]
fn ape_with_id3v1_trailer_conformance() {
  // Codex R3 F2 second regression pin: same DoneID3-shift logic in the
  // MAIN `plan_ape_inner` footer path (not just `plan_apetagex_trailer_
  // only`). A pure `.ape` file (no ID3v2 prefix) with both an APE
  // trailer AND an ID3v1 trailer was missing the APE:* tags pre-fix
  // because the footer scan at `data.len() - 32` lands inside the
  // 128-byte ID3v1 `TAG` block.
  //
  // Fixture layout (248 bytes):
  //   * 32-byte MAC OldHeader (vers=3970)
  //   * APEv2 trailer carrying APE:Artist="ApeId3v1Artist" + APE:Title=
  //     "ApeId3v1Title" (88 bytes: 56-byte tag-entry body + 32-byte footer)
  //   * ID3v1 TAG block (128 bytes) at EOF
  //
  // Post-fix behavior (matches bundled): ProcessID3 (called from
  // APE.pm:124-127) finds the ID3v1 trailer, sets DoneID3 = 128;
  // ProcessAPE's footer scan now uses `EOF - 32 - 128 = 88` and finds
  // the APETAGEX magic. Bundled also emits `Composite:DateTimeOriginal`
  // (from the engine composite system) which is the documented
  // ACCEPTED-DEFERRAL hand-trim (Composite engine, Phase 3+ — see
  // docs/tracking.md) so the committed golden omits it.
  check(
    "ape_with_id3v1_trailer.ape",
    "ape_with_id3v1_trailer.ape.json",
    true,
  );
  check(
    "ape_with_id3v1_trailer.ape",
    "ape_with_id3v1_trailer.ape.n.json",
    false,
  );
}

#[test]
fn ape_with_enhancedtag_and_id3v1_conformance() {
  // Codex R4 F2 regression pin: ID3.pm:1521-1525 — when a standard
  // ID3v1 TAG block is detected at `EOF - 128`, bundled ALSO probes
  // 227 bytes BEFORE it for an Enhanced TAG (matching `/^TAG+/`):
  //   my $eSize = 227;
  //   if ($raf->Seek(-$trailSize - $eSize, 2)
  //       and $raf->Read($eBuff, $eSize) == $eSize
  //       and $eBuff =~ /^TAG+/) {
  //       $id3Trailer{EnhancedTAG} = \$eBuff;
  //       $trailSize += $eSize;
  //   }
  //   $$et{DoneID3} = $trailSize;   # ID3.pm:1527
  //
  // The `^TAG+/` regex is `^TA` followed by `G+` (one or more G's) —
  // confirmed via `perl -e 'print "match" if "TAG" =~ /^TAG+/'`.
  // "TAG+rest" matches via the initial `TAG`. The fixture's Enhanced
  // TAG block begins with the literal bytes `TAG+` (the spec magic);
  // the bundled regex matches because `TAG` ⊂ `TAG+rest`.
  //
  // With Enhanced TAG present, bundled stores `DoneID3 = 128 + 227 =
  // 355` and APE.pm:169 `$footPos -= $$et{DoneID3}` walks BEFORE the
  // Enhanced TAG block when scanning for the APETAGEX footer. Our
  // pre-fix code hardcoded `128`, so the APE footer scan landed
  // INSIDE the Enhanced TAG block → APETAGEX magic missed → SILENT
  // miss of the APE:Artist tag.
  //
  // Fixture layout (454 bytes):
  //   * 32-byte MAC OldHeader (vers=3970)
  //   * APEv2 trailer (67 bytes: 35-byte body + 32-byte footer)
  //     carrying APE:Artist="ApeEnhancedTAGArtist"
  //   * 227-byte Enhanced TAG block (magic `TAG+`)
  //   * 128-byte standard ID3v1 TAG block at EOF
  //
  // F4 fix (Codex adversarial): the 7 `ID3v1_Enh:*` fields are now
  // emitted by `id3::v1_enh::process_id3v1_enh`, faithful to
  // `%Image::ExifTool::ID3::v1_Enh` (ID3.pm:380-425). The committed
  // golden retains all 7 — no longer hand-trimmed.
  //
  // ACCEPTED-DEFERRAL HAND-TRIM (a single line):
  // `Composite:DateTimeOriginal: 2024` is present in bundled output
  // and is the only Composite tag for this fixture. The Composite
  // metadata engine is the documented Phase-3+ accepted-deferral
  // (Composite:Duration / Composite:DateTimeOriginal etc., see
  // docs/tracking.md → "Accepted deferrals"). Hand-trim of ONLY this
  // one line is acceptable per the deferral contract; when the
  // Composite engine lands, re-capture via `tools/gen_golden.sh`.
  check(
    "ape_with_enhancedtag_and_id3v1.ape",
    "ape_with_enhancedtag_and_id3v1.ape.json",
    true,
  );
  check(
    "ape_with_enhancedtag_and_id3v1.ape",
    "ape_with_enhancedtag_and_id3v1.ape.n.json",
    false,
  );
}

#[test]
fn id3v24_footer_truncated_then_nothing_conformance() {
  // Codex R4 F1 regression pin: slice panic on truncated v2.4 footer.
  // ID3.pm:1484-1486 — `if ($flags & 0x10) { $raf->Seek(10, 1); }` —
  // the footer-flag seek is UNCONDITIONAL: filesystems allow seeking
  // past EOF, so `$raf->Tell()` at :1504 yields `10 + size + 10` even
  // when the 10 footer bytes were never written to the file. Bundled's
  // audio-loop then reads ZERO bytes past the EOF (no crash).
  //
  // Our pre-fix code computed `hdr_end = 10 + 24 + 10 = 44` and then
  // sliced `ctx.data()[44..]` over a 34-byte buffer → PANIC. The fix
  // at the consumer side (`ctx.data().get(hdr_end..).unwrap_or(&[])`
  // in `formats/ape.rs`) routes the same hdr_end through a saturating-
  // empty slice, byte-exactly matching bundled's "seek past EOF then
  // read nothing" behavior.
  //
  // Fixture layout (34 bytes):
  //   * 10-byte ID3v2.4 main header (vers=4.0, flags=0x10 [footer-flag],
  //     syncsafe size=24)
  //   * 24-byte body: TIT2 frame "TestV24TrFt0!" (13-byte text)
  //   * NO footer bytes (file truncated AT body end)
  //
  // Bundled golden: FileType=MP3 (extension fallback, no MPEG-audio
  // magic detected), ID3Size=34 (10 header + 24 body, faithful to
  // ID3.pm:1496 `$id3Len += length($hBuff) + 10` — bundled counts the
  // BODY-bytes-actually-read, not the would-have-been-skipped 10 footer
  // bytes), ID3v2_4:Title="TestV24TrFt0!".
  check(
    "id3v24_footer_truncated_then_nothing.mp3",
    "id3v24_footer_truncated_then_nothing.mp3.json",
    true,
  );
  check(
    "id3v24_footer_truncated_then_nothing.mp3",
    "id3v24_footer_truncated_then_nothing.mp3.n.json",
    false,
  );
}

#[test]
fn moi_conformance() {
  // FORMATS.md row 12a: Image::ExifTool::MOI. Bundled fixture
  // `tests/fixtures/MOI.moi` is the real `t/images/MOI.moi` (320 bytes,
  // V6 sidecar with DateTime / Duration / AspectRatio / AudioCodec /
  // AudioBitrate / VideoBitrate). Goldens captured from bundled
  // `perl exiftool` (`-j -G1 -struct` and `-n`).
  //
  // Exercises:
  //   - V6 magic + embedded BE u32 filesize gate (MOI.pm:110-114)
  //   - SetByteOrder('MM') for int16u/int32u walks (MOI.pm:116)
  //   - DateTimeOriginal `undef[8]` + sprintf('%06.3f',…) format
  //   - Duration `int32u/1000` + ConvertDuration sub-30s path
  //   - AspectRatio nibble decode (lo<2 + hi=5 ⇒ "4:3 PAL")
  //   - AudioCodec PrintHex + direct hash hit (0xC1 ⇒ AC3)
  //   - AudioBitrate `*16000+48000` + ConvertBitrate (kbps)
  //   - VideoBitrate hash ValueConv + ConvertBitrate (Mbps)
  check("MOI.moi", "MOI.moi.json", true);
  check("MOI.moi", "MOI.moi.n.json", false);
}

#[test]
#[cfg(all(feature = "h264", feature = "serde"))]
fn h264_conformance() {
  // FORMATS.md row 16: Image::ExifTool::H264. H264 is ENGINE-ONLY — ExifTool
  // has NO `H264` file type (`%magicNumber`/`%fileTypeLookup` carry no
  // entry), so a raw `.h264` NAL stream is reported as `Unknown file type`
  // by bundled `exiftool`. `H264::ParseH264Video` is invoked solely as a
  // callback by `M2TS::ProcessM2TS` (M2TS.pm:343-346) on the de-packetized
  // PES payload.
  //
  // Because there is no file type, this format CANNOT be driven through the
  // file-type-dispatched `extract_info` path the other `*_conformance`
  // tests use (`check(...)` above resolves a parser via `any_parser_for`,
  // which intentionally has no `H264` arm). This test therefore drives the
  // typed `parse_h264` entry directly and renders via the public `Rendered`
  // serde view — the same value-equivalence gate, minus the file-type hop.
  //
  // Fixture: `tests/golden/h264/H264_avchd.h264` — a SYNTHESIZED 68-byte
  // raw H.264 stream (one SEI NAL whose type-5 user-data payload carries an
  // MDPM block with the UUID 17ee8c60f84d11d98cd60800200c9a66). It exercises
  // TimeCode (reverse-hex ValueConv), the Shutter binary subdir (LittleEndian
  // int16u + masked ExposureTime + PrintExposureTime), the int32u-enum tags
  // ExposureProgram / WhiteBalance / SceneCaptureType, and the MakeModel
  // subdir (int16u Make → convMake → "Canon"). Goldens captured by invoking
  // bundled `Image::ExifTool::H264::ParseH264Video` directly (PrintConv on /
  // off) — see the fixture-synthesis note in the PR.
  use exifast::{AnyMeta, Rendered};

  let root = env!("CARGO_MANIFEST_DIR");

  // Each fixture: the synthesized `.h264` NAL stream + `-j`/`-n` goldens.
  // Goldens were captured by invoking bundled `Image::ExifTool::H264::
  // ParseH264Video` directly (under `SetByteOrder('MM')`, matching the
  // M2TS::ProcessM2TS pipeline — M2TS.pm:619 — that delivers a real AVCHD
  // SEI). The adversarial fixtures (added for Codex R1 F1/F2) cover each
  // MDPM tag family the original happy-path fixture missed:
  //   * `H264_avchd`    — TimeCode / Shutter / int32u-enum / MakeModel.
  //   * `h264_gps`      — the full GPS block (0xb0-0xca): GPSVersionID,
  //                       lat/long (`Combine => 2` + ToDegrees/ToDMS),
  //                       altitude, GPSTimeStamp (ConvertTimeStamp/
  //                       PrintTimeStamp), the string `*Ref` enums,
  //                       GPSMapDatum (`Combine => 1`) and GPSDateStamp
  //                       (`Combine => 2` + ExifDate).
  //   * `h264_exif`     — the rational32u/s image tags (0xa0-0xa9):
  //                       ExposureTime (PrintExposureTime), FNumber,
  //                       BrightnessValue, ExposureCompensation
  //                       (PrintFraction), MaxApertureValue (`2**(v/2)`),
  //                       Flash (%Exif::flash), CustomRendered,
  //                       FocalLengthIn35mmFormat.
  //   * `h264_maker`    — Camera1 / Camera2 subdirs plus the Canon-only
  //                       RecInfo (0xe1) and FrameInfo (0xee) subdirs,
  //                       gated by the `Make eq "Canon"` Condition.
  //   * `h264_sony_model` — the Sony-only Model tag (0xe4, `Combine => 2`
  //                       string), gated by `Make eq "Sony"`.
  //   * `h264_trunc_sps` — Codex R1 F2: a `0x67` SPS NAL with a truncated
  //                       body. The Exp-Golomb reader drains, so
  //                       `ParseSeqParamSet`'s `return unless $$bstr{Mask}`
  //                       (H264.pm:787) drops the size — bundled
  //                       `ParseH264Video` emits NOTHING, so the goldens
  //                       are empty objects.
  //   * `h264_gps_zerodenom` — Codex R2 F1: GPSLatitude (`1/0, 30/1, 0/1`)
  //                       and GPSLongitude (`2/0, 0/0, 0/1`) carry
  //                       zero-denominator components. `GetRational32u`
  //                       yields `inf`/`undef` (ExifTool.pm:6089), and
  //                       `GPS::ToDegrees` voids the WHOLE coordinate
  //                       (`return ''` — GPS.pm:584); bundled emits the
  //                       tag with an empty ValueConv AND PrintConv.
  //   * `h264_gps_ts_zerodenom` — Codex R2 F1: GPSTimeStamp (`1/0, 30/1,
  //                       45/1`) with a zero-denominator hour. The `inf`
  //                       component numifies to infinity in
  //                       `GPS::ConvertTimeStamp` (GPS.pm:459), yielding
  //                       `Inf:NaN:000000000NaN` for both `-j` and `-n`.
  //   * `h264_exif_frac` — Codex R3 F1: non-terminating rational32 ValueConv
  //                       inputs. BrightnessValue / FocalLengthIn35mmFormat /
  //                       MaxApertureValue all carry `1/3`. `GetRational32u`
  //                       hands `2 ** ($val/2)` the `RoundFloat(1/3, 7)`
  //                       STRING `0.3333333` (ExifTool.pm:6094), so bundled
  //                       MaxApertureValue `-n` is `1.12246203534218`, NOT
  //                       the exact `1.12246204830937`.
  //   * `h264_gps_frac`  — Codex R3 F1: GPSLatitude (`10/1, 1/3, 1/3`) and
  //                       GPSTimeStamp (`1/3, 1/3, 1/3`) — non-terminating
  //                       components. `GPS::ToDegrees` / `ConvertTimeStamp`
  //                       combine the `RoundFloat(n/d, 7)` STRINGS, so
  //                       bundled latitude `-n` is `10.0056481475833`, NOT
  //                       the exact `10.0056481481481`.
  //   * `h264_exif_zerodenom`  — Codex R4 F1: zero-denominator EXIF rationals
  //                       must numify (NOT short-circuit to the raw word)
  //                       before ValueConv/PrintConv. ExposureCompensation
  //                       (0xa4 `1/0`) and MaxApertureValue (0xa5 `1/0`).
  //                       `GetRational32*` ⇒ `inf` (ExifTool.pm:6087/6094).
  //                       0xa4 has no ValueConv: `-n` is the raw `inf`, `-j`
  //                       runs `PrintFraction(inf→+∞)` = `+Inf`. 0xa5's
  //                       ValueConv `2 ** (inf/2)` = `+∞` ⇒ `-n` `Inf`, `-j`
  //                       `sprintf("%.1f", +∞)` = `Inf`.
  //   * `h264_exif_zerodenom2` — Codex R4 F1: the `0/0` companions.
  //                       `GetRational32*` ⇒ `undef`. 0xa4 `-n` is the raw
  //                       `undef`, `-j` `PrintFraction(undef→0)` = `0`. 0xa5
  //                       ValueConv `2 ** (0/2)` = `1` ⇒ `-n` `1`, `-j`
  //                       `sprintf("%.1f", 1)` = `1.0`.
  //   * `h264_offmap` — Codex R5 F2: PrintConv-hash MISSES render as
  //                       `Unknown (N)` (normal) / `Unknown (0x%x)` (PrintHex)
  //                       in `-j`, raw in `-n` (ExifTool.pm:3616-3623).
  //                       ExposureProgram (0xa2=9) ⇒ `Unknown (9)`; Flash
  //                       (0xa6=0x99, PrintHex) ⇒ `Unknown (0x99)`;
  //                       CustomRendered (0xa7=5) ⇒ `Unknown (5)`; GPSStatus
  //                       string-enum (0xbe="Z", GPS group) ⇒ `Unknown (Z)`;
  //                       Make convMake-miss (0xe0=0x9999, PrintHex) ⇒
  //                       `Unknown (0x9999)`. (Also exercises R5 F1: GPSStatus
  //                       lands under the family-1 `GPS` group.)
  //   * `h264_camera_offmap` — Codex R5 F2 in the Camera1 subtable: the
  //                       masked sub-byte enums also render misses as
  //                       `Unknown (N)`. ExposureProgram (mask 0xf0 ⇒ 5) and
  //                       WhiteBalance (mask 0xe0 ⇒ 5) ⇒ `Unknown (5)`; the
  //                       computed-OTHER tags (ApertureSetting, Gain) are
  //                       unaffected.
  //   * `h264_camera_priority` — Codex R15 F1: an ASCENDING MDPM stream with a
  //                       `0x70` Camera1 subdirectory (`ff 00 20 00` ⇒ Camera1
  //                       `WhiteBalance` mask 0xe0 ⇒ 1 ⇒ "Hold") FOLLOWED by a
  //                       top-level `0xa8` `WhiteBalance` (`00 00 00 00` ⇒ 0 ⇒
  //                       "Auto") whose table entry is `Priority => 0`
  //                       (H264.pm:215). `FoundTag` keeps the higher-priority
  //                       Camera1 value as the visible `H264:WhiteBalance` and
  //                       relegates the later `Priority => 0` value to a
  //                       `WhiteBalance (1)` duplicate copy
  //                       (ExifTool.pm:9458-9580); the default `Duplicates`-off
  //                       render drops that copy (ExifTool.pm:5396-5404 /
  //                       5522-5538), so bundled `ParseH264Video` emits
  //                       `H264:WhiteBalance` = "Hold" (`-j`) / `1` (`-n`) — NOT
  //                       the later "Auto"/`0`. The pre-fix port wrote every
  //                       entry with last-wins, overwriting "Hold" with the
  //                       lower-priority "Auto"; this fixture pins the
  //                       priority-winner. (Camera1 also emits ApertureSetting=
  //                       Auto, Gain=-3 dB, ExposureProgram=Program AE, Focus=
  //                       Auto (0) from the same 4 bytes.)
  //   * `h264_gps_mapdatum_empty` — Codex R6 F1: an all-NUL `0xc7 GPSMapDatum`
  //                       (Combine=1 with an all-NUL `0xc8`). GPSMapDatum has
  //                       NO `RawConv` (H264.pm:371-377), so bundled
  //                       `ParseH264Video`/`HandleTag` emit a present-but-empty
  //                       `GPS:GPSMapDatum` (`""`) in both `-j` and `-n` —
  //                       it must NOT be dropped (contrast the Sony `0xe4
  //                       Model` drop-empty RawConv).
  //   * `h264_gps_datestamp_empty` — Codex R6 F1: an all-NUL `0xca
  //                       GPSDateStamp` (Combine=2 with all-NUL `0xcb`/`0xcc`).
  //                       No `RawConv`; `ExifDate("")` returns `""`
  //                       (Exif.pm:6068-6076), so bundled `ParseH264Video`
  //                       emits a present-but-empty `GPS:GPSDateStamp` (`""`)
  //                       in both `-j` and `-n`.
  //   * `h264_oos_mdpm` — Codex R7 F1: an out-of-order MDPM block — `0xa8`
  //                       WhiteBalance=1 then `0xa2` ExposureProgram=2
  //                       (`0xa2 < 0xa8`). H264.pm:988-990 emits
  //                       `Warn('Entries in MDPM directory are out of
  //                       sequence')` and stops the walk, so bundled
  //                       `ParseH264Video` yields `H264:WhiteBalance` PLUS
  //                       `ExifTool:Warning` — the `0xa2` record is dropped.
  //                       Codex R8 F1: under `-n` the WhiteBalance value is the
  //                       bare JSON NUMBER `1` (not `"1"`) — the EscapeJSON
  //                       number gate (exiftool:3809). See the dedicated
  //                       `h264_oos_mdpm_n_emits_json_number` exact-type test.
  //   * `h264_forbidden_bit` — Codex R8 F2: a stream `00 00 00 01 86` whose
  //                       NAL header `0x86` has forbidden_zero_bit set.
  //                       H264.pm:1058 emits `Warn('H264 forbidden bit error')`
  //                       before stopping the scan, so bundled `ParseH264Video`
  //                       yields a lone `ExifTool:Warning`.
  //   * `h264_sei_leading_emulation` — Codex R9 F1: an SEI NAL body that
  //                       STARTS with a `00 00 03` triple (`06 | 00 00 03
  //                       00 05 1a <UUID+MDPM> 01 b1 4e 00 00 00 80`).
  //                       H264.pm:1064 seeds the de-escape regex at
  //                       `pos = $pos + 1`, so a `00 00 03` whose first
  //                       byte is at NAL-body index 0 is NEVER stripped —
  //                       the body parses as SEI type0/size0, type3/size0,
  //                       type5/size26, reaching the MDPM payload. Bundled
  //                       `ParseH264Video` emits `GPS:GPSLatitudeRef`.
  //   * `h264_mdpm_trunc_record` — Codex R9 F2: a type-5 MDPM payload with
  //                       `count=1`, tag `0xb1`, and a SINGLE data byte
  //                       `N` (fewer than the nominal four). H264.pm:993
  //                       `substr($$dataPt, $pos+1, 4)` short-reads — the
  //                       record still dispatches via `HandleTag`, so the
  //                       one-byte string yields `GPS:GPSLatitudeRef`.
  //   * `h264_mdpm_short_num` — Codex R10 F1: a type-5 MDPM payload with
  //                       `count=1`, tag `0xa8` WhiteBalance (`int32u`), and
  //                       a SINGLE `0x00` data byte. ExifTool's `ReadValue`
  //                       returns the empty string `''` for an underlength
  //                       `Count`-less fixed-width format (`ExifTool.pm:6285`
  //                       — `return '' if … $size < $len`); `HandleTag`
  //                       still emits the tag. The empty value misses the
  //                       WhiteBalance PrintConv hash, so bundled
  //                       `ParseH264Video` yields `H264:WhiteBalance` =
  //                       `"Unknown ()"` (`-j`) / `""` (`-n`) — the
  //                       underlength record must NOT be dropped.
  //   * `h264_mdpm_trunc_combine` — Codex R10 F2: a type-5 MDPM payload with
  //                       `count=2`: `0xc7 GPSMapDatum` data `WGS8`
  //                       (`Combine => 1`) followed by a TRUNCATED `0xc8`
  //                       consecutive record whose sole data byte is `4`.
  //                       H264.pm:1005 only checks the consecutive tag byte
  //                       exists before the payload end (`$pos + 5 >= $end`),
  //                       then H264.pm:1009 `substr($$dataPt, $pos+1, 4)`
  //                       SHORT-READS the truncated record's lone byte. The
  //                       combined string is `WGS8` + `4` = `WGS84`, so
  //                       bundled `ParseH264Video` emits `GPS:GPSMapDatum`
  //                       = `"WGS84"` — the truncated next record is
  //                       absorbed, not dropped.
  //   * `h264_mdpm_short_rational` — Codex R11 F1: a type-5 MDPM payload with
  //                       `count=1`, tag `0xa0` ExposureTime (`rational32u`),
  //                       and a SINGLE `0x01` data byte. ExifTool's
  //                       `ReadValue` returns the empty string `''` for an
  //                       underlength `Count`-less `rational32u` (`$len = 4`,
  //                       `$size = 1 < $len` ⇒ `return ''`, `ExifTool.pm:6285`)
  //                       — the SAME short-read rule as the R10 F1 integer
  //                       fix. `HandleTag` still emits the tag, and
  //                       `PrintExposureTime('')` returns `''` verbatim
  //                       (`IsFloat('')` false), so bundled `ParseH264Video`
  //                       yields `H264:ExposureTime` = `""` in BOTH `-j` and
  //                       `-n` — the underlength rational must NOT be dropped.
  //   * `h264_mdpm_short_gps` — Codex R11 F1: a type-5 MDPM payload with
  //                       `count=1`, tag `0xb2` GPSLatitude (`rational32u`,
  //                       `Combine => 2`), and only THREE data bytes. No
  //                       consecutive `0xb3` record exists, so the combined
  //                       buffer stays three bytes (`< 4`); `ReadValue`
  //                       returns `''`. `GPS::ToDegrees('')` finds no decimal
  //                       (`return '' unless defined $d`, GPS.pm:594) and
  //                       `GPS::ToDMS('')` returns `''`, so bundled
  //                       `ParseH264Video` emits `GPS:GPSLatitude` = `""` in
  //                       BOTH `-j` and `-n` — the short combined rational
  //                       must NOT be dropped.
  //   * `h264_mdpm_short_timecode` — Codex R12 F1: a type-5 MDPM payload with
  //                       `count=1`, tag `0x13` TimeCode, and a SINGLE `0x01`
  //                       data byte. `0x13` has only a `ValueConv` (no
  //                       fixed-width `Format`), so `ProcessSEI`'s short-read
  //                       `$buff` flows straight into the ValueConv with NO
  //                       length gate. `sprintf("%.2x:%.2x:%.2x:%.2x",
  //                       reverse unpack("C*",$val))` consumes the one byte
  //                       and three Perl-undef args (⇒ `00`), so bundled
  //                       `ParseH264Video` emits `H264:TimeCode` =
  //                       `"01:00:00:00"` — the short record must NOT drop.
  //   * `h264_mdpm_empty_timecode` — Codex R12 F1: a type-5 MDPM payload with
  //                       `count=1`, tag `0x13`, and ZERO data bytes (the NAL
  //                       ends right after the tag id). `unpack("C*","")`
  //                       yields the empty list; all four `%.2x` specs see
  //                       Perl-undef, so bundled `ParseH264Video` emits
  //                       `H264:TimeCode` = `"00:00:00:00"`.
  //   * `h264_mdpm_short_datetime` — Codex R12 F1: a type-5 MDPM payload with
  //                       `count=1`, tag `0x18` DateTimeOriginal, and only
  //                       FOUR bytes (`80 20 13 05`) — fewer than the eight
  //                       its ValueConv expects, with no consecutive `0x19`
  //                       to `Combine`. `ProcessSEI` short-reads `$buff`;
  //                       `0x18` has only a `ValueConv`, so it runs with NO
  //                       length gate. Perl's `sprintf` consumes its 11 specs
  //                       positionally against `(@a, tz_sign, tz_hours,
  //                       tz_min, dst)` — the short `@a` slides the computed
  //                       args into earlier `%.2x` slots (numifying there)
  //                       and leaves the tail specs Perl-undef, so bundled
  //                       `ParseH264Video` emits a malformed-but-PRESENT
  //                       `H264:DateTimeOriginal` = `"2013:05:00 00:00:0000:"`
  //                       — the short record must NOT be dropped.
  //   * `h264_mdpm_partial_datetime` — Codex R12 F1: a type-5 MDPM payload
  //                       with `count=2`: a full 4-byte `0x18` record
  //                       (`80 20 13 05`) followed by a TRUNCATED consecutive
  //                       `0x19` whose data is only `16 0a 1e` (three bytes).
  //                       `Combine => 1` absorbs the truncated `0x19` (H264.pm
  //                       :1005 only checks the tag byte precedes the payload
  //                       end), giving a 7-byte buffer — still short of eight.
  //                       Bundled `ParseH264Video` emits a malformed-but-
  //                       PRESENT `H264:DateTimeOriginal` =
  //                       `"2013:05:16 0a:1e:00000:"`.
  //   * `h264_sei_ext_type` — Codex R13 F1: an SEI message whose payload TYPE
  //                       is 255-extended (`ff 06` ⇒ H264.pm:941-946
  //                       `$type += $t` = 261), followed by a byte-perfect
  //                       type-5 MDPM payload (UUID + "MDPM" + `0xa8`
  //                       WhiteBalance). 261 is neither 5 nor 0x80, so bundled
  //                       `ProcessSEI` skips the message at H264.pm:965
  //                       (`$pos += $size`) and the MDPM payload is NEVER
  //                       decoded — `ParseH264Video` emits NOTHING (`{}` in
  //                       both `-j` and `-n`). The port must accumulate the
  //                       255-extended type WITHOUT wrapping a narrow integer
  //                       into 5/0x80; see the dedicated in-crate test
  //                       `sei_payload_type_extension_does_not_overflow_into_type5`
  //                       which drives the full 2^32 wrap pattern.
  //   * `h264_sps_golomb63` — Codex R14 F1: a `0x67` SPS whose
  //                       `pic_width_in_mbs_minus1` / `pic_height_in_map_units
  //                       _minus1` Exp-Golomb codes each have 63 leading zero
  //                       bits (after emulation de-escape). Bundled `GetGolomb`
  //                       returns huge UNSIGNED values (`≈ 9.2e18`); the
  //                       `(w + 1) * 16` size math then PROMOTES TO A FLOAT
  //                       (`≈ 1.5e20`), failing the `<= 4096` window, so
  //                       bundled `ParseH264Video` emits NOTHING (`{}`). The
  //                       pre-fix port cast the `u64` Golomb to `i64`
  //                       (negative) and `wrapping_mul`-ed it back into the
  //                       window, fabricating `ImageWidth=160`/`ImageHeight
  //                       =128` — this fixture pins the `{}` agreement.
  //   * `h264_sps_golomb64` — Codex R14 F1 boundary companion: the SAME SPS
  //                       shape but with 64-leading-zero Golomb codes. After
  //                       de-escape this one decodes to a GENUINELY valid
  //                       small size, so bundled `ParseH264Video` emits
  //                       `ImageWidth=160`/`ImageHeight=128` in BOTH `-j` and
  //                       `-n`. It guards that the rewritten `get_golomb`
  //                       (which now reads `count + 1` bits directly instead
  //                       of synthesising the leading 1 with `1u64 <<
  //                       count.min(63)`) still tracks Perl across the
  //                       64-bit-`UV`-wrap boundary, where the old synthesis
  //                       was wrong.
  for fixture in [
    "H264_avchd",
    "h264_gps",
    "h264_exif",
    "h264_maker",
    "h264_sony_model",
    "h264_trunc_sps",
    "h264_gps_zerodenom",
    "h264_gps_ts_zerodenom",
    "h264_exif_frac",
    "h264_gps_frac",
    "h264_exif_zerodenom",
    "h264_exif_zerodenom2",
    "h264_offmap",
    "h264_camera_offmap",
    "h264_camera_priority",
    "h264_gps_mapdatum_empty",
    "h264_gps_datestamp_empty",
    "h264_oos_mdpm",
    "h264_forbidden_bit",
    "h264_sei_leading_emulation",
    "h264_mdpm_trunc_record",
    "h264_mdpm_short_num",
    "h264_mdpm_trunc_combine",
    "h264_mdpm_short_rational",
    "h264_mdpm_short_gps",
    "h264_mdpm_short_timecode",
    "h264_mdpm_empty_timecode",
    "h264_mdpm_short_datetime",
    "h264_mdpm_partial_datetime",
    "h264_sei_ext_type",
    "h264_sps_golomb63",
    "h264_sps_golomb64",
  ] {
    let data = std::fs::read(format!("{root}/tests/golden/h264/{fixture}.h264"))
      .unwrap_or_else(|e| panic!("read {fixture}.h264 fixture: {e}"));
    for (print_on, suffix) in [(true, "json"), (false, "n.json")] {
      let golden_name = format!("{fixture}.h264.{suffix}");
      let want = std::fs::read_to_string(format!("{root}/tests/golden/h264/{golden_name}"))
        .unwrap_or_else(|e| panic!("read golden {golden_name}: {e}"));
      let meta = exifast::parse_h264(&data).expect("synthetic H264 stream must be accepted");
      let any = AnyMeta::H264(meta);
      let got = serde_json::to_string(&Rendered::new(&any, print_on)).expect("render H264 meta");
      if let Err(e) = json_equivalent(&got, &want) {
        panic!(
          "{fixture}.h264 vs {golden_name}: value mismatch: {}\n--- got ---\n{got}\n\
           --- want ---\n{want}",
          e.message()
        );
      }
    }
  }
}

/// Codex R8 F1 — EXACT JSON-type regression. `h264_conformance` compares H264
/// goldens with [`json_equivalent`], which deliberately blurs `"1"` (string)
/// and `1` (number) so it would PASS even if a numeric `-n` value regressed to
/// a JSON string. This test asserts the concrete JSON TOKEN type instead:
/// under `-n`, bundled `ParseH264Video` emits `H264:WhiteBalance` as the bare
/// number `1` (the EscapeJSON number gate, exiftool:3809), NOT `"1"`.
#[test]
#[cfg(all(feature = "h264", feature = "serde"))]
fn h264_oos_mdpm_n_emits_json_number() {
  use exifast::{AnyMeta, Rendered};

  let root = env!("CARGO_MANIFEST_DIR");
  let data = std::fs::read(format!("{root}/tests/golden/h264/h264_oos_mdpm.h264"))
    .expect("read h264_oos_mdpm fixture");
  let meta = exifast::parse_h264(&data).expect("h264_oos_mdpm must be accepted");
  let any = AnyMeta::H264(meta);

  // `-n` (print_conv = false): WhiteBalance must be a bare JSON NUMBER.
  let n_json = serde_json::to_string(&Rendered::new(&any, false)).expect("render -n");
  let n_val: serde_json::Value = serde_json::from_str(&n_json).expect("parse -n json");
  let wb_n = &n_val["H264:WhiteBalance"];
  assert!(
    wb_n.is_number() && !wb_n.is_string(),
    "h264_oos_mdpm -n WhiteBalance must be a JSON number, got: {wb_n} (full: {n_json})"
  );
  assert_eq!(
    wb_n.as_u64(),
    Some(1),
    "h264_oos_mdpm -n WhiteBalance value"
  );

  // `-j` (print_conv = true): WhiteBalance is the PrintConv STRING "Manual".
  let j_json = serde_json::to_string(&Rendered::new(&any, true)).expect("render -j");
  let j_val: serde_json::Value = serde_json::from_str(&j_json).expect("parse -j json");
  let wb_j = &j_val["H264:WhiteBalance"];
  assert_eq!(
    wb_j.as_str(),
    Some("Manual"),
    "h264_oos_mdpm -j WhiteBalance must be the PrintConv string (full: {j_json})"
  );
}

/// Codex R8 F2 — a NAL header with forbidden_zero_bit set must surface
/// `ExifTool:Warning: H264 forbidden bit error` (H264.pm:1058
/// `$et->Warn('H264 forbidden bit error'), last`). The stream `00 00 00 01 86`
/// has a single NAL whose header `0x86` (`0b1000_0110`) sets the forbidden bit.
#[test]
#[cfg(all(feature = "h264", feature = "serde"))]
fn h264_forbidden_bit_surfaces_warning() {
  use exifast::{AnyMeta, Rendered};

  let data: [u8; 5] = [0x00, 0x00, 0x00, 0x01, 0x86];
  let meta = exifast::parse_h264(&data).expect("a stream with a start code must be accepted");
  let any = AnyMeta::H264(meta);

  for print_on in [true, false] {
    let json = serde_json::to_string(&Rendered::new(&any, print_on)).expect("render forbidden");
    let val: serde_json::Value = serde_json::from_str(&json).expect("parse json");
    assert_eq!(
      val["ExifTool:Warning"].as_str(),
      Some("H264 forbidden bit error"),
      "forbidden-bit warning must be surfaced (print_conv={print_on}, full: {json})"
    );
  }
}

#[test]
fn flash_conformance() {
  // FORMATS.md row 18: Image::ExifTool::Flash (FLV side). Bundled fixture
  // `tests/fixtures/Flash.flv` is the real `t/images/Flash.flv` (1358 bytes,
  // FLV\x01 with onMetaData script-data, audio MP3 11kHz mono, video On2
  // VP6, cue-points, key-frame index). Goldens captured from bundled
  // `perl exiftool` (`-j -G1 -struct` and `-j -G1 -struct -n`), with
  // `System:*` lines stripped (consistent with the established trim
  // precedent) AND the `Composite:ImageSize` / `Composite:Megapixels`
  // pair stripped — Composite metadata synthesis is an engine-level
  // forward-item (see `docs/tracking.md` Composite-engine accepted
  // deferral, also noted in the Red/DV/Audible conformance goldens).
  //
  // Exercises:
  //   - 9-byte FLV header gate (Flash.pm:474-475)
  //   - tag-stream loop (Flash.pm:483-523) with prev-tag-size + 11-byte
  //     header decode
  //   - `0x08` audio packet bit-stream (`%Flash::Audio`, Flash.pm:91-135)
  //   - `0x09` video packet bit-stream (`%Flash::Video`, Flash.pm:138-154)
  //   - `0x12` script-data Meta with AMF0 object/mixed-array/array/double/
  //     boolean/string/date dispatch (`ProcessMeta`, Flash.pm:290-461)
  //   - `onMetaData` packet-gate (Flash.pm:444-447 `%processMetaPacket`)
  //   - struct-prefixed sub-tag names (CuePoint0Name / CuePoint1ParameterParam1,
  //     Flash.pm:380 `$structName . ucfirst($tag)`)
  //   - ValueConv `*1000` for `audiodatarate` / `videodatarate` (Flash.pm:168/237)
  //   - PrintConv `ConvertBitrate` (Flash.pm:169/238)
  //   - PrintConv `ConvertDuration` (Flash.pm:192)
  //   - PrintConv `int($val * 1000 + 0.5) / 1000` for FrameRate (Flash.pm:197)
  //   - AMF date type with timezone suffix (Flash.pm:309-325)
  //   - auto-add path `ucfirst($tag)` for the `test` key (Flash.pm:391)
  //   - double-array emission (KeyFramesTimes / KeyFramePositions,
  //     Flash.pm:410-426)
  check("Flash.flv", "Flash.flv.json", true);
  check("Flash.flv", "Flash.flv.n.json", false);
}

#[test]
fn flash_amf_strict_array_string_conformance() {
  // Codex R1/F1 adversarial fixture: AMF0 strict-array (0x0a) of strings
  // (type 0x02). Bundled Flash.pm:410-426 collects every non-struct child
  // (`push @vals, $v unless $isStruct{$t}`) and `HandleTag` emits the
  // whole list under the auto-added `StrList` name as a JSON array of
  // strings: `["alpha","beta","gamma"]`. Pins the F1 fix: the prior
  // walker silently dropped every non-double element.
  check(
    "flash_array_strings.flv",
    "flash_array_strings.flv.json",
    true,
  );
  check(
    "flash_array_strings.flv",
    "flash_array_strings.flv.n.json",
    false,
  );
}

#[test]
fn flash_amf_nonfinite_string_conformance() {
  // Codex PR #32 R20/F1 fixtures: numeric `%Flash::Meta` fields encoded as
  // AMF strings carrying the IEEE non-finite spellings. Perl's `Perl_my_atof`
  // coerces `inf`/`nan`/`infinity`/`1.#INF` (any case + optional sign) to
  // `±Inf`/`NaN` in numeric context, so the `$val * 1000` ValueConv
  // (audiodatarate/videodatarate/totaldatarate, Flash.pm:168/230/237) yields a
  // non-finite NV. `ConvertBitrate` (audio/video, Flash.pm:169/238) and
  // `int($val+0.5)` (total, Flash.pm:231) then `IsFloat`-reject the non-finite
  // (ExifTool.pm:6894 / the regex needs a leading digit) and pass it through —
  // stringifying to Perl's titlecase `Inf`/`-Inf`/`NaN` in BOTH `-j` and `-n`.
  // `framerate` (no ValueConv, Flash.pm:195-198) keeps the RAW AMF string under
  // `-n` (lowercase `inf`/`nan` as authored) and runs the RoundMilli arithmetic
  // under `-j` (→ titlecase). `flash_amf_nonfinite_inf.flv` is all-`inf`;
  // `flash_amf_nonfinite_nan.flv` mixes `NaN` (AudioBitrate), `Inf`
  // (VideoBitrate), `-inf` (TotalDataRate → `-Inf`) and `nan` (FrameRate).
  // Pre-fix `perl_str_to_f64` returned `0.0` for every spelling, so the
  // ValueConv tags collapsed to `0`/`0 bps`, and `ConvertBitrate`/
  // `ConvertDuration` emitted Rust's lowercase `inf`/`-inf`.
  check(
    "flash_amf_nonfinite_inf.flv",
    "flash_amf_nonfinite_inf.flv.json",
    true,
  );
  check(
    "flash_amf_nonfinite_inf.flv",
    "flash_amf_nonfinite_inf.flv.n.json",
    false,
  );
  check(
    "flash_amf_nonfinite_nan.flv",
    "flash_amf_nonfinite_nan.flv.json",
    true,
  );
  check(
    "flash_amf_nonfinite_nan.flv",
    "flash_amf_nonfinite_nan.flv.n.json",
    false,
  );
}

#[test]
fn flash_amf_strict_array_creationdate_valueconv_conformance() {
  // Codex PR #32 R15/F1 fixture: AMF0 strict-array (0x0a) of strings under
  // the `creationdate` key, whose elements carry trailing whitespace
  // (`["A   ", "B\t "]`). Bundled `GetValue` (ExifTool.pm:3567-3681) applies
  // the owning tag's ValueConv (`$val=~s/\s+$//; $val`, Flash.pm:182) to
  // EACH TOP-LEVEL array element, so bundled emits `Flash:CreateDate
  // ["A","B"]` under BOTH `-j` and `-n` (the ValueConv is pre-PrintConv).
  // Pins R15/F1: the prior walker stored top-level array strings raw,
  // preserving the trailing whitespace and diverging from bundled.
  check(
    "flash_creationdate_strict_array.flv",
    "flash_creationdate_strict_array.flv.json",
    true,
  );
  check(
    "flash_creationdate_strict_array.flv",
    "flash_creationdate_strict_array.flv.n.json",
    false,
  );
}

#[test]
fn flash_amf_strict_array_bool_conformance() {
  // Codex R1/F1 fixture: strict-array of booleans (type 0x01). Bundled
  // Flash.pm:329 converts each `0/1` to `"No"/"Yes"` INSIDE ProcessMeta
  // (pre-PrintConv) so both `-j` and `-n` see the string array
  // `["Yes","No","Yes"]` (verified — bundled `-n` shows the same shape).
  check("flash_array_bools.flv", "flash_array_bools.flv.json", true);
  check(
    "flash_array_bools.flv",
    "flash_array_bools.flv.n.json",
    false,
  );
}

#[test]
fn flash_amf_strict_array_date_conformance() {
  // Codex R1/F1 fixture: strict-array of dates (type 0x0b). Bundled
  // Flash.pm:316-324 emits each as the `YYYY:MM:DD HH:MM:SS.ssssss±HH:MM`
  // string (NO local-tz shift; the tz suffix is the AMF-recorded value).
  check("flash_array_dates.flv", "flash_array_dates.flv.json", true);
  check(
    "flash_array_dates.flv",
    "flash_array_dates.flv.n.json",
    false,
  );
}

#[test]
fn flash_amf_strict_array_mixed_conformance() {
  // Codex R1/F1 fixture: strict-array of heterogeneous AMF types
  // (string + double + boolean + date). Bundled emits a single mixed
  // JSON array `["hello",42.5,"Yes","2024:01:01 00:00:00.000000+00:00"]`
  // — pins the F1 fix's per-element shape preservation across the four
  // common AMF leaf types.
  check("flash_array_mixed.flv", "flash_array_mixed.flv.json", true);
  check(
    "flash_array_mixed.flv",
    "flash_array_mixed.flv.n.json",
    false,
  );
}

#[test]
fn flash_amf_truncated_double_conformance() {
  // Codex R1/F2 fixture: AMF double (type 0x00) truncated mid-payload
  // inside a mixed-array. Bundled Flash.pm:456 emits
  // `ExifTool:Warning: Truncated AMF record 0x0` AND retains the prior
  // good entry (`Flash:GoodVal: 1.5`). Pins the F2 fix: the prior
  // walker silently aborted the packet with NO warning.
  check(
    "flash_trunc_double.flv",
    "flash_trunc_double.flv.json",
    true,
  );
  check(
    "flash_trunc_double.flv",
    "flash_trunc_double.flv.n.json",
    false,
  );
}

#[test]
fn flash_amf_truncated_string_conformance() {
  // Codex R1/F2 fixture: AMF string (type 0x02) with a length field that
  // overruns the buffer. Bundled emits `Truncated AMF record 0x2` +
  // retains the prior good entry.
  check(
    "flash_trunc_string.flv",
    "flash_trunc_string.flv.json",
    true,
  );
  check(
    "flash_trunc_string.flv",
    "flash_trunc_string.flv.n.json",
    false,
  );
}

#[test]
fn flash_amf_truncated_date_conformance() {
  // Codex R1/F2 fixture: AMF date (type 0x0b) — f64 parses cleanly but
  // the 2-byte tz suffix is missing. Bundled has a SUBTLE branch here
  // (Flash.pm:309-313): the `last if $pos + 2 > $dirLen` exits the
  // Record AFTER `$val` is already assigned to the raw double; line 455
  // sees `defined $val` so NO truncation warning. The half-parsed value
  // is emitted as a bare double (`$val/1000`, no date formatting). Pins
  // this exact bundled behavior.
  check("flash_trunc_date.flv", "flash_trunc_date.flv.json", true);
  check("flash_trunc_date.flv", "flash_trunc_date.flv.n.json", false);
}

#[test]
fn flash_amf_truncated_array_conformance() {
  // Codex R1/F2 fixture: AMF strict-array (type 0x0a) with claimed count
  // > available elements. Bundled emits `Truncated AMF record 0xa`
  // (Flash.pm:456 fires from Frame 2 because `$val = \@vals` is never
  // reached) + retains the prior good entry. Pins the F2 array path.
  check("flash_trunc_array.flv", "flash_trunc_array.flv.json", true);
  check(
    "flash_trunc_array.flv",
    "flash_trunc_array.flv.n.json",
    false,
  );
}

#[test]
fn flash_amf_rec0_double_walks_past_conformance() {
  // Codex R2/F1 adversarial fixture: rec=0 is a top-level AMF Double
  // (0x00 + 8-byte payload `42.0`), followed by `onMetaData` at rec=1
  // and a normal onMetaData object at rec=2.
  //
  // Bundled Flash.pm (verified via `perl exiftool` on this synthetic):
  // the post-record gate at line 442-447 only `last`s when `$type ==
  // 0x02 and not $rec` AND the string is NOT in `%processMetaPacket`.
  // For a non-string at rec=0 the else-arm (line 448-452) is a verbose-
  // only no-op; the loop CONTINUES to rec=1 and walks the onMetaData
  // packet. Bundled net output for this fixture is `Flash:Duration:
  // "7.50 s"` (PrintConv on) / `7.5` (PrintConv off) — pins that
  // exifast's walker matches bundled (the original Codex R2/F1 framing
  // suggested bundled rejects, but bundled empirically does NOT).
  check(
    "flash_f1_double_first.flv",
    "flash_f1_double_first.flv.json",
    true,
  );
  check(
    "flash_f1_double_first.flv",
    "flash_f1_double_first.flv.n.json",
    false,
  );
}

#[test]
fn flash_amf_rec0_struct_walks_inline_conformance() {
  // Codex R2/F1 fixture: rec=0 is a top-level AMF object (`0x03`) with
  // one key/value pair (`Preroll: 1`). Flash.pm:337-440's isStruct
  // branch walks the children INLINE (no rec-0 gate — line 442's
  // `unless ($isStruct{$type})` SKIPS the gate). Loop then advances
  // and the next record is `onMetaData` + Duration object.
  //
  // Bundled net output: BOTH `Flash:Preroll: 1` AND `Flash:Duration:
  // "7.50 s"` (verified empirically). Pins exifast's struct-at-rec=0
  // path — the original Codex R2/F1 framing claimed bundled rejects
  // structs at rec=0, but Flash.pm:442 demonstrably bypasses the gate
  // for any struct type.
  check(
    "flash_f1_struct_first.flv",
    "flash_f1_struct_first.flv.json",
    true,
  );
  check(
    "flash_f1_struct_first.flv",
    "flash_f1_struct_first.flv.n.json",
    false,
  );
}

#[test]
fn flash_amf_nested_strict_array_conformance() {
  // Codex R2/F2 fixture: an `onMetaData` object whose `outerArr` tag is
  // a strict-array (`0x0a`) of two elements — element[0] is itself a
  // nested strict-array `[1.0, 2.0]`, element[1] is the double `99.0`.
  //
  // Bundled Flash.pm:410-426 recurses into the inner ProcessMeta call
  // for a 0x0a child; the inner call builds `$val = \@vals` and returns
  // `(0x0a, $val)`. The outer Frame 2 then `push @vals, $v unless
  // $isStruct{$t}` — `0x0a` is NOT in `%isStruct`, so the inner array
  // reference IS appended. Bundled emits `OuterArr: [[1,2],99]` (the
  // nested list is preserved verbatim in the JSON output).
  //
  // PRIOR BUG (pre-R2/F2): walk_array's leaf path called read_value on
  // 0x0a, which returned `AmfValue::StrictArray` WITHOUT consuming the
  // nested count+payload. The cursor then sat mid-nested-array → silent
  // data corruption (an arbitrary subsequent f64 read interpreted the
  // inner array bytes as a leaf double, producing junk values like
  // `1.087e-311`).
  check(
    "flash_f2_nested_array.flv",
    "flash_f2_nested_array.flv.json",
    true,
  );
  check(
    "flash_f2_nested_array.flv",
    "flash_f2_nested_array.flv.n.json",
    false,
  );
}

#[test]
fn flash_amf_unsupported_after_valid_packet_conformance() {
  // Codex R2/F3 fixture: valid `onMetaData` + Duration object, followed
  // by an unsupported AMF type byte (`0x11` — AMF3 data marker,
  // Flash.pm:434 in the `else` arm at lines 435-439).
  //
  // Bundled emits BOTH `Flash:Duration: "7.50 s"` AND the dedicated
  // warning `"AMF AMF3data record not yet supported"`. Flash.pm:437's
  // `$et->Warn(...)` is UNCONDITIONAL — it does NOT gate on the
  // `$val` defined check at line 455-457.
  //
  // PRIOR BUG (pre-R2/F3): `read_value` returned the unsupported-type
  // marker via `ReadResult::Truncated(t)` (reusing the truncation
  // discriminant). The top-level walker's `if top_val_seen { warnings
  // .pop(); }` then SILENTLY POPPED the unsupported warning, dropping
  // the diagnostic for any unsupported type that followed a valid
  // record. The new `ReadResult::Unsupported(t)` discriminant
  // preserves the warning at all callers.
  check(
    "flash_f3_unsupported.flv",
    "flash_f3_unsupported.flv.json",
    true,
  );
  check(
    "flash_f3_unsupported.flv",
    "flash_f3_unsupported.flv.n.json",
    false,
  );
}

#[test]
fn flash_amf_empty_and_reference_scalars_conformance() {
  // Codex R3/F1 fixture: onMetaData mixed-array holding the five AMF
  // scalar shapes whose emission bundled handles via the
  // `$val = ''` (Flash.pm:403-405, null/undef/0x0d) and
  // `$val = Get16u(...)` (Flash.pm:406-409, reference) branches — plus
  // one real double for control. Bundled `perl exiftool` emits all
  // five keys: `Flash:NullKey: ""`, `Flash:UndefKey: ""`,
  // `Flash:UnsupKey: ""`, `Flash:RefKey: 3`, `Flash:DoubleKey: 7.5`.
  //
  // PRIOR BUG (pre-R3/F1): `emit_resolved` mapped `AmfValue::Empty` and
  // `AmfValue::Reference(_)` to `return;` — silently dropping FOUR of
  // the five children. Net Rust output was a single-entry `Flash:
  // DoubleKey: 7.5`. Post-fix: Empty → `""`, Reference(v) → numeric v.
  check("flash_amf_scalars.flv", "flash_amf_scalars.flv.json", true);
  check(
    "flash_amf_scalars.flv",
    "flash_amf_scalars.flv.n.json",
    false,
  );
}

#[test]
fn flash_amf_strict_array_with_empties_conformance() {
  // Codex R3/F2 fixture: onMetaData mixed-array with one key `mixList`
  // holding a strict-array `[null, undef, ref(3), double(4.0)]`.
  // Bundled Flash.pm:417-422 pushes EVERY non-struct `$v` into `@vals`
  // — null/undef contribute `""`, reference contributes its u16 value
  // (3), double contributes 4 — yielding `Flash:MixList: ["","",3,4]`.
  //
  // PRIOR BUG (pre-R3/F2): `collect_array_items`'s match arm for
  // `AmfValue::Empty | Reference(_) | ObjectEnd` did `{}` (drop). Net
  // Rust output was `Flash:MixList: [4]` — a silent 75% data loss
  // that matched neither `-j` nor `-n` bundled output.
  check(
    "flash_array_with_empties.flv",
    "flash_array_with_empties.flv.json",
    true,
  );
  check(
    "flash_array_with_empties.flv",
    "flash_array_with_empties.flv.n.json",
    false,
  );
}

#[test]
fn flash_amf_top_level_strict_array_walks_past_conformance() {
  // Codex R3/F3 fixture: onMetaData (rec=0) + top-level strict-array
  // (rec=1, `[1.0, 2.0]`) + mixed-array (rec=2) with `goodKey: 7.5`.
  // Bundled Flash.pm:410-426's `0x0a` branch is reachable from the
  // OUTER record loop — it consumes the u32 count + every element via
  // recursive `ProcessMeta`, sets `$val = \@vals`, falls through to
  // line 442's `unless ($isStruct{$type})`, hits the else at lines
  // 448-452 (verbose-only "ignored lone array value" — NO emit),
  // then advances to the next record. Net bundled output is
  // `Flash:GoodKey: 7.5` (proving walk-past of the top-level 0x0a).
  //
  // PRIOR BUG (pre-R3/F3): `process_meta` sent the top-level 0x0a
  // record to `read_value`, which returned `AmfValue::StrictArray`
  // WITHOUT consuming the nested count+payload. The cursor remained
  // mid-array → the next record (`0x08` mixed-array) was parsed from
  // a wrong offset → spurious garbage and silent loss of the
  // `goodKey` entry.
  check(
    "flash_top_strict_array.flv",
    "flash_top_strict_array.flv.json",
    true,
  );
  check(
    "flash_top_strict_array.flv",
    "flash_top_strict_array.flv.n.json",
    false,
  );
}

#[test]
fn flash_amf_array_abort_propagates_to_sibling_conformance() {
  // Codex R4/F1 fixture: onMetaData mixed-array containing two pairs —
  // `badArr` whose strict-array payload starts with an unsupported AMF
  // type byte (0x11 = AMF3 data marker, Flash.pm:434), followed by a
  // sibling `after` with a valid double. Bundled Flash.pm:382-386's
  // `last Record unless defined $t and defined $v` ABORTS the entire
  // struct walk on the failed inner ProcessMeta call (the unsupported
  // type at line 437-439 sets `undef $type; last` → outer Frame 2 array
  // branch never assigns `$val = \@vals` → returns `(0x0a, undef)` → the
  // struct walker's defined-$v check fails → `last Record`).
  //
  // Net bundled output: the dedicated unsupported warning
  // `"AMF AMF3data record not yet supported"` AND no `Flash:BadArr` AND
  // no `Flash:After` (both siblings dropped). The `after` key MUST NOT
  // appear — that is the assertion this fixture pins.
  //
  // PRIOR BUG (pre-R4/F1): `walk_pairs` called `walk_array` then
  // unconditionally `continue`d, ignoring the abort cue. Sibling `after`
  // was then emitted as `Flash:After: 99` → divergence from bundled (one
  // extra tag).
  check(
    "flash_f4_array_abort_sibling.flv",
    "flash_f4_array_abort_sibling.flv.json",
    true,
  );
  check(
    "flash_f4_array_abort_sibling.flv",
    "flash_f4_array_abort_sibling.flv.n.json",
    false,
  );
}

#[test]
fn flash_amf_nested_strict_array_prefix_propagation_conformance() {
  // Codex R4/F2 fixture: onMetaData mixed-array with one key `outerArr`
  // holding a strict-array of TWO nested strict-arrays, each containing
  // TWO object elements `{name: "X"}`. Bundled Flash.pm:415-418 captures
  // `$structName = $$dirInfo{StructName}` at array entry then sets
  // `$$dirInfo{StructName} = $structName . $i` for each element BEFORE
  // the recursive ProcessMeta call. When the recursive call hits another
  // 0x0a, it ALSO captures the (now per-index-prefixed) structName and
  // applies its own `$i` suffix to inner elements. Net: bundled emits
  // `Flash:OuterArr00Name: "A"`, `OuterArr01Name: "B"`, `OuterArr10Name:
  // "C"`, `OuterArr11Name: "D"` (PLUS `Flash:OuterArr: [[],[]]` because
  // the empty `@vals` of each inner array — its struct children were
  // emitted as their own tags, removed by `unless $isStruct{$t}` at line
  // 422 — IS still pushed into the outer `@vals`).
  //
  // PRIOR BUG (pre-R4/F2): `collect_array_items` recursed into the
  // nested strict-array WITH THE OUTER `struct_name` UNCHANGED, so the
  // inner object's `name` key built tag `OuterArr0Name` for BOTH
  // outerArr[0][0] AND outerArr[1][0] → silent collision under first-wins
  // emission. Post-fix: recurse with `format!("{struct_name}{i}")` so
  // the inner walker uses `OuterArr0`/`OuterArr1` as its prefix.
  check(
    "flash_f4_nested_array_prefix.flv",
    "flash_f4_nested_array_prefix.flv.json",
    true,
  );
  check(
    "flash_f4_nested_array_prefix.flv",
    "flash_f4_nested_array_prefix.flv.n.json",
    false,
  );
}

#[test]
fn flash_amf_array_struct_element_failure_does_not_abort_conformance() {
  // Codex R5 fixture (FALSE POSITIVE — see explanation below).
  // onMetaData mixed-array with key `arr` whose strict-array payload
  // is `[object{badChild: unsupported(0x11)}, object{name: "Valid"}]`
  // PLUS a parent-level sibling `after: 42.0`. The R5 finding asserted
  // that the inner-inner ProcessMeta call for the struct element
  // returns `(undef, undef)` (driving the array loop to abort via line
  // 420 `last Record unless defined $v`), and that `collect_array_items`
  // discards the `WalkOutcome::Abort` from the nested `walk_pairs`
  // recursion — emitting siblings bundled would drop.
  //
  // EMPIRICAL VERIFICATION via `perl exiftool 13.58` on this fixture
  // CONTRADICTS the abort-propagation claim:
  //
  //   bundled emits: `Flash:Arr: [1.25323377490797e-308]` PLUS the
  //   `AMF AMF3data record not yet supported` warning, AND drops
  //   both `Flash:Arr1Name` (the would-be `name="Valid"` tag) AND
  //   the parent-level sibling `Flash:After`.
  //
  // The `[1.25e-308]` value is a deliberate misparse — bundled's
  // cursor sits past the 0x11 byte after the inner-inner returns; at
  // array i=1 the next byte 0x00 is read as a `double` (AMF type 0x00)
  // and the following 8 bytes happen to decode as `1.25e-308`.
  // Subsequent reads desync further — the outer mixedArray pair loop
  // eventually hits a truncated key (the `Truncated mixedArray record`
  // warning appears in verbose output but JSON dedups warnings).
  //
  // Why bundled does NOT abort: Flash.pm:337-440's isStruct branch
  // sets `$val = ''` at line 340 as a DUMMY VALUE — `$val` stays
  // DEFINED across the inner pair-loop's `last Record` at line 386.
  // The struct's ProcessMeta thus returns `(0x03, '')` (NOT
  // `(undef, undef)`); the array loop's line 420 `last Record unless
  // defined $v` checks only `$v`, which is `''` and is therefore
  // DEFINED. The loop continues at i+1 with the desynced cursor.
  // Contrast with R4/F1's case (`flash_f4_array_abort_sibling.flv`)
  // where the array element is a DIRECT unsupported scalar — there
  // the inner ProcessMeta hits Flash.pm:435-439's `undef $type; last`
  // BEFORE any `$val = ''` assignment, returning `(undef, undef)`,
  // and the array loop's line 420 DOES fire.
  //
  // The current Rust walker already matches bundled value-for-value
  // for this fixture in both `-j` and `-n` modes: `collect_array_items`
  // discards the `Abort` from the struct child's `walk_pairs` (lines
  // 1564-1572 in src/formats/flash.rs) and continues to i=1, which
  // reads 0x00 then 8 bytes as the same `1.25e-308` double; the outer
  // `walk_pairs` then hits its own truncated-key warning at the
  // misparsed length, which is deduped against the unsupported warning
  // at the JSON emission stage. NO CODE CHANGE; this fixture PINS
  // the cursor-desync-after-struct-element-failure behaviour so a
  // future regression (e.g., a well-meaning "propagate abort"
  // refactor that would drop `Flash:Arr` here) would fail conformance.
  check(
    "flash_f5_array_struct_abort.flv",
    "flash_f5_array_struct_abort.flv.json",
    true,
  );
  check(
    "flash_f5_array_struct_abort.flv",
    "flash_f5_array_struct_abort.flv.n.json",
    false,
  );
}

#[test]
fn flash_nested_struct_child_abort_does_not_drop_parent_sibling_conformance() {
  // Codex PR #32 R16/F1 — onMetaData mixed-array with a STRUCT-VALUED
  // child `badChild` (AMF object 0x03) whose object body starts with an
  // empty-key pair (`00 00`) followed by an unsupported AMF3 marker
  // (`0x11`), then a parent sibling `after: 9.0`, then the mixed-array
  // object-end (`00 00 09`). Fixture bytes: the `00 00 11` triple the
  // finding calls out.
  //
  // The inner-inner ProcessMeta call for the empty-key pair's value
  // reads 0x11 → Flash.pm:435-439 `undef $type; last` → returns
  // `(undef, '')`. Back in `badChild`'s OWN isStruct pair loop
  // (Flash.pm:337-411), line 386 `last Record unless defined $t and
  // defined $v` fires → the inner pair loop exits. But `badChild`'s
  // ProcessMeta was entered as a `$single` struct child: line 340 set
  // `$val = ''` (the struct dummy) BEFORE any of this, so control
  // falls to line 441 `last if $single` and `badChild` RETURNS
  // `($type=0x03, $val='')` — both DEFINED. The parent (outer) pair
  // loop's line 386 check passes, line 387 `next if $isStruct{$t}`
  // fires, and the parent CONTINUES — parsing the `after` sibling.
  //
  // Bundled `perl exiftool 13.58` emits (BOTH `-j` and `-n`):
  //   `ExifTool:Warning: AMF AMF3data record not yet supported`
  //   `Flash:After: 9`
  //
  // Pre-R16/F1 the Rust `walk_pairs` struct-child branch `return`ed
  // `WalkOutcome::Abort` on a recursive `walk_pairs == Abort` (and on
  // an `IntroOutcome::Truncated` introducer), aborting the PARENT walk
  // and silently dropping `Flash:After`. R16/F1 discards the recursive
  // `WalkOutcome` (mirroring `collect_array_items`'s R5 array-of-struct
  // resolution) — warnings + advanced cursor preserved, parent loop
  // continues exactly as Perl does with `(type, '')`. This fixture
  // PINS that recovery.
  check(
    "flash_r16_nested_struct_abort.flv",
    "flash_r16_nested_struct_abort.flv.json",
    true,
  );
  check(
    "flash_r16_nested_struct_abort.flv",
    "flash_r16_nested_struct_abort.flv.n.json",
    false,
  );
}

#[test]
fn flash_struct_child_truncated_intro_preserves_parent_warning_conformance() {
  // Codex PR #32 R17/F1 — a struct-valued child whose struct INTRODUCER
  // is itself truncated must NOT enter the child pair loop.
  //
  // Fixture: `onMetaData` mixedArray → key `obj` → an AMF object (0x03)
  // → key `child` → value type `0x08` (mixedArray) followed by only the
  // two bytes `00 05` (a 4-byte mixed-array top-index is required, so
  // the introducer is truncated).
  //
  // Bundled Flash.pm: the struct branch (lines 337-411) sets `$val=''`
  // (line 340) THEN runs the `0x08` introducer check `last if
  // $pos + 4 > $dirLen` (line 342) — `last`ing OUT of the struct branch
  // BEFORE the `for(;;)` pair loop is ever entered. The `child`
  // ProcessMeta (a `$single` call) falls to line 441 `last if $single`
  // and returns `(0x08, '')` — both DEFINED. The `obj` object's own
  // pair loop continues (line 387 `next if $isStruct{$t}`), reads the
  // `00 05` bytes as a key length, hits `$pos + 2 + 5 > $dirLen` →
  // `Warn("Truncated object record")` (line 354, struct type 0x03) →
  // `last Record`. `obj`'s ProcessMeta returns `(0x03,'')`; the
  // grandparent `onMetaData` mixedArray loop continues, re-reads the
  // SAME `00 05` bytes → `Warn("Truncated mixedArray record")`.
  //
  // Bundled `perl exiftool 13.58` `-v3` emits both warnings IN ORDER —
  // `Truncated object record` then `Truncated mixedArray record`. The
  // `-j` / `-n` JSON `Warning` key is first-wins, so it surfaces
  // `Truncated object record` (BOTH modes).
  //
  // Pre-R17/F1 the Rust struct-child branch ALWAYS called `walk_pairs`
  // — bundled's `for(;;)` pair loop — even for a truncated introducer.
  // For the truncated `0x08` child, `walk_pairs(struct_type=0x08)`
  // re-read the `00 05` bytes FIRST and pushed `Truncated mixedArray
  // record` BEFORE the `obj` parent could push `Truncated object
  // record`, inverting the warning order and surfacing the wrong
  // first-wins JSON warning. R17/F1 branches on `consume_struct_intro`:
  // `walk_pairs` runs ONLY for `IntroOutcome::Ok`; a `Truncated`
  // introducer preserves the cursor + any helper warning and continues
  // the parent pair loop without descending. This fixture PINS the
  // warning text + order.
  check(
    "flash_r17_struct_child_trunc_intro.flv",
    "flash_r17_struct_child_trunc_intro.flv.json",
    true,
  );
  check(
    "flash_r17_struct_child_trunc_intro.flv",
    "flash_r17_struct_child_trunc_intro.flv.n.json",
    false,
  );
}

#[test]
fn flash_nested_livexml_preserved_conformance() {
  // Codex PR #32 R7 — adversarial fixture for the XMP SubDirectory gate.
  //
  // The R6 gate `(SubTable::Meta && raw_key == "liveXML")` was TOO BROAD:
  // it dropped a NESTED `foo.liveXML` (a key named `liveXML` UNDER a
  // parent struct named `foo`) with the XMP-deferral warning, even
  // though bundled Flash.pm emits the nested case as a plain auto-add
  // scalar `Flash:FooLiveXML`. The pre-R7 walker:
  //
  //   - probed `SubDirectory` on the RAW key `liveXML` → matched the
  //     Meta entry,
  //   - hit `is_xmp_subdirectory_dispatch(Meta, "liveXML") == true`,
  //   - dropped the value and pushed `XMP SubDirectory dispatch
  //     deferred (Phase-3+)`.
  //
  // Silent metadata loss. Bundled Flash.pm:365-394 handles the nested
  // case differently:
  //
  //   - Flash.pm:365 probes `$$subTablePtr{$tag}` with the RAW
  //     un-prefixed key `liveXML` → matches the SubDirectory entry.
  //   - Flash.pm:370 `if ($subTable =~ /^Image::ExifTool::Flash::/)`
  //     guard FAILS (target is `XMP::Main`, foreign) → `$tag` is NOT
  //     rewritten and `$subTablePtr` is NOT swapped.
  //   - Flash.pm:380 applies the parent prefix: `$tag = $structName .
  //     ucfirst($tag)` → `$tag = "FooLiveXML"`.
  //   - Flash.pm:390-393 then runs `$$subTablePtr{"FooLiveXML"}` on
  //     the UN-SWAPPED Meta table → no match → AddTagToTable +
  //     HandleTag with the plain string value.
  //
  // Bundled output (oracle `perl exiftool 13.58`, captured 2026-05-22):
  //
  //   Flash:FooLiveXML: "some_value"
  //
  // NO warning, NO XMP suppression. R7 fix: narrow the gate to
  // `struct_name.is_empty()` (the un-prefixed top-level case — the
  // ONLY shape that reaches the Meta `liveXML` SubDirectory in
  // bundled). The pre-R7 top-level fixture
  // (`flash_xmp_livexml.flv`) still triggers the deferral warning;
  // this fixture covers the nested branch.
  check(
    "flash_nested_livexml.flv",
    "flash_nested_livexml.flv.json",
    true,
  );
  check(
    "flash_nested_livexml.flv",
    "flash_nested_livexml.flv.n.json",
    false,
  );
}

#[test]
#[ignore = "FORMATS.md row 15 XMP infra Phase-3+ deferral (Codex PR #32 R6): \
  Flash.pm:243-246 dispatches the `liveXML` AMF key through \
  `SubDirectory => { TagTable => 'Image::ExifTool::XMP::Main' }`. Bundled \
  emits `XMP-*:*` tags via XMP::ProcessXMP; exifast cannot synthesize them \
  without the XMP parser (6693 LOC). Interim behaviour pins a deferral \
  Warning (visible non-silent deferral, see src/formats/flash.rs:: \
  `is_xmp_subdirectory_dispatch`). This fixture pins the POST-XMP-port \
  oracle output (XMP-dc:Format='application/x-shockwave-flash') so when \
  XMP::Main lands the test will auto-pass; today it documents the \
  deliberate divergence. Run manually with: \
  `cargo test --ignored flash_xmp_livexml_subdirectory_deferred_conformance`"]
fn flash_xmp_livexml_subdirectory_deferred_conformance() {
  // Codex PR #32 R6 fixture: a synthetic FLV with one `0x12` Script Data
  // packet containing an AMF onXMPData top-level packet whose inner
  // mixed-array carries a single key `liveXML` mapping to an XMP packet
  // string (`<x:xmpmeta...><dc:format>application/x-shockwave-flash
  // </dc:format>...</x:xmpmeta>`).
  //
  // Bundled `perl exiftool 13.58` (oracle captured 2026-05-22) emits
  // `XMP-dc:Format: "application/x-shockwave-flash"` via Flash.pm:243-246's
  // SubDirectory dispatch into `Image::ExifTool::XMP::Main` (XMP.pm +
  // XMP2.pl, FORMATS.md row 15, 6693 LOC, Phase-3+).
  //
  // exifast's current Flash port surfaces the deferral as
  // `ExifTool:Warning: "XMP SubDirectory dispatch deferred (Phase-3+)"`
  // and DROPS the auto-add `Flash:LiveXML` scalar that would otherwise
  // carry the raw `<x:xmpmeta>` blob (a WRONG-SHAPE divergence bundled
  // never emits). See `src/formats/flash.rs::is_xmp_subdirectory_dispatch`
  // for the accept-deferral comment and behaviour.
  //
  // Per-user contract: this is FORMALLY ACCEPT-DEFERRED, NOT silent. The
  // `#[ignore]` keeps the test off the default run but committed; the
  // golden is committed for the eventual XMP port; `docs/tracking.md`
  // records the residual under "PR #32 R6 — liveXML/onXMPData XMP
  // deferral"; the parser-side handling is anchored at
  // `is_xmp_subdirectory_dispatch` so the deferral is visible in code too.
  //
  // The fixture is also listed in
  // `tests/typed_serde_parity.rs::NOT_ACTIVE` so the active-conformance
  // fixture-count sweep skips it (matches `FLAC.ogg` + `AIFF_id3.aif`).
  //
  // Remove the `#[ignore]` (and the warning emission) when the XMP
  // parser lands.
  check("flash_xmp_livexml.flv", "flash_xmp_livexml.flv.json", true);
  check(
    "flash_xmp_livexml.flv",
    "flash_xmp_livexml.flv.n.json",
    false,
  );
}

#[test]
fn flash_empty_key_livexml_preserved_conformance() {
  // Codex PR #32 R8/F1 — adversarial fixture for the
  // `is_xmp_subdirectory_dispatch` gate's Option<&str> distinction.
  //
  // Pre-R8 the gate was `struct_name.is_empty()`, collapsing two
  // distinct Perl states that Flash.pm:380's `if defined $structName`
  // treats differently:
  //
  //   * Perl `undef $structName` (top-level / no struct in effect) —
  //     line 380 does NOT fire, the SubDirectory dispatches XMP at
  //     line 390. This is the original `flash_xmp_livexml.flv`
  //     accept-deferred case (R6).
  //
  //   * Perl defined `$structName = ""` (e.g. a child under a key
  //     `""`) — line 380 DOES fire: `$tag = "" . ucfirst("liveXML") =
  //     "LiveXML"`. The line 390 SubDirectory lookup on `"LiveXML"`
  //     MISSES the lowercase-keyed Meta `liveXML` entry. Auto-add
  //     emits `Flash:LiveXML` as a plain string scalar — bundled DOES
  //     NOT dispatch XMP for this shape, and the value is preserved.
  //
  // Bundled output (oracle `perl exiftool 13.58`, captured
  // 2026-05-22) on a synthetic FLV containing
  // `onMetaData{"": {liveXML: "some_value"}}`:
  //
  //   Flash:LiveXML: "some_value"
  //
  // NO warning, NO XMP suppression. R8 fix: refactor `struct_name`
  // from `&str` to `Option<&str>` throughout (`None` = Perl undef,
  // `Some(s)` = Perl defined including empty), gate the XMP
  // dispatch on `is_none()` not `is_empty()`. The pre-R7 top-level
  // fixture (`flash_xmp_livexml.flv`) and the R7 nested fixture
  // (`flash_nested_livexml.flv`) continue to exercise their original
  // branches; this fixture covers the empty-key-parent gap.
  check(
    "flash_empty_key_livexml.flv",
    "flash_empty_key_livexml.flv.json",
    true,
  );
  check(
    "flash_empty_key_livexml.flv",
    "flash_empty_key_livexml.flv.n.json",
    false,
  );
}

#[test]
fn flash_toplevel_array_objects_conformance() {
  // Codex PR #32 R8/F2 — adversarial fixture for the array-index
  // append site's Option<&str> distinction.
  //
  // Flash.pm:418 gates the per-element struct-name append on
  // `if defined $structName`:
  //
  //   $$dirInfo{StructName} = $structName . $i if defined $structName;
  //
  // At the TOP LEVEL, `$structName` is `undef` (Flash.pm:296 declares
  // but never assigns at outer scope). So when a top-level strict-array
  // (Flash.pm:410-426 reached via the outer Record loop) contains
  // object elements, the recursive ProcessMeta calls for each element
  // inherit `$$dirInfo{StructName}` UNCHANGED (still undef). The inner
  // struct walker then hits line 380 with `$structName=undef` → the
  // prefix application does NOT fire → tag stays raw lowercase
  // (`name`) → `resolve_emit` Meta lookup MISSES → auto-add ucfirsts
  // → emits `Flash:Name` for EACH object element.
  //
  // Net bundled output (oracle `perl exiftool 13.58`, captured
  // 2026-05-22) on a synthetic FLV with a top-level strict-array
  // `[{name: "A"}, {name: "B"}]` followed by a mixed-array
  // `{trailKey: 9}`:
  //
  //   Flash:Name: "B"        (last-wins from the 2 object elements)
  //   Flash:TrailKey: 9      (walk-past proof — see R3/F3 fixture)
  //
  // PRIOR BUG (pre-R8): `collect_array_items` unconditionally ran
  // `format!("{struct_name}{i}")` regardless of `struct_name == ""`
  // sentinel, manufacturing prefix `0`/`1` and emitting
  // `Flash:0Name: "A"` + `Flash:1Name: "B"` — two tags bundled NEVER
  // emits (the `0Name` / `1Name` names also fail the
  // `is_word_key` `/^\w+$/` check because they start with a digit;
  // pre-R8 the names were silently dropped instead of merging into
  // the bundled `Flash:Name` last-wins shape).
  //
  // R8 fix: gate the array-index append on `struct_name.is_some()`,
  // propagating `None` to the inner walker when the outer carry is
  // also `None`. EMPIRICAL via `-v3` confirms bundled prints
  // `(adding name)` twice (no per-element prefix) and `(ignored lone
  // array value)` for the top-level 0x0a record.
  check(
    "flash_toplevel_array_objects.flv",
    "flash_toplevel_array_objects.flv.json",
    true,
  );
  check(
    "flash_toplevel_array_objects.flv",
    "flash_toplevel_array_objects.flv.n.json",
    false,
  );
}

#[test]
fn flash_keyed_array_truncated_count_conformance() {
  // Codex PR #32 R9/F1 — adversarial fixture pinning the keyed-array-
  // truncated-count case. A mixed-array contains a key whose value type
  // is `0x0a` (strict-array), but with FEWER THAN 4 BYTES following for
  // the count (`pos + 4 > dirLen`).
  //
  // Bundled Flash.pm:410-411 hits `last if $pos + 4 > $dirLen` inside the
  // recursive ProcessMeta call (the inner frame has $val=undef from
  // line 297's fresh declaration); the inner frame's loop exits without
  // assigning $val. Line 455 (`not defined $val and defined $type`)
  // then fires → emits `"Truncated AMF record 0xa"` because $type=0x0a
  // was set at line 303 before the count check. Returns `(0x0a, undef)`;
  // the outer struct walker at line 386 (`last Record unless defined
  // $t and defined $v`) sees $v=undef → `last Record` aborts.
  //
  // Net bundled (oracle `perl exiftool 13.58`, captured 2026-05-22):
  //   ExifTool:Warning: "Truncated AMF record 0xa"
  //   Flash:GoodKey: 9             (preserved from before the abort)
  //
  // PRIOR BUG (pre-R9/F1): `collect_array_items` returned `None`
  // SILENTLY when `*pos + 4 > data.len()` at the count read — no
  // warning pushed, the outer struct walker continued past the abort,
  // silently dropping the bundled `Truncated AMF record 0xa`
  // diagnostic. Silent metadata loss in the malformed-AMF path.
  //
  // R9 fix: distinguish missing-count failure (`Outcome::TruncatedCount`)
  // from element-failure (`Outcome::Abort`) in `collect_array_items`'s
  // return value; the keyed-value caller (`walk_array` from
  // `walk_pairs`) emits the warning + aborts.
  check(
    "flash_keyed_array_truncated_count.flv",
    "flash_keyed_array_truncated_count.flv.json",
    true,
  );
  check(
    "flash_keyed_array_truncated_count.flv",
    "flash_keyed_array_truncated_count.flv.n.json",
    false,
  );
}

#[test]
fn flash_typed_object_truncated_name_conformance() {
  // Codex PR #32 R9/F2 — adversarial fixture pinning the top-level
  // typed-object (`0x10`) truncated-name case. rec=0 is the packet name
  // `onMetaData`; rec=1 is type 0x10 with a declared u16 name length of
  // 5 but no name bytes following.
  //
  // Bundled Flash.pm:340-354: enters the isStruct branch, sets $val='',
  // sets $getName=1; the inner for(;;) pair loop runs line 350-353:
  // reads the u16 length (5), checks `$pos + 2 + $len > $dirLen` —
  // TRUE → emits `et->Warn("Truncated $amfType[$type] record")` where
  // $amfType[0x10] = "typedObject", then `last Record`.
  //
  // Net bundled (oracle `perl exiftool 13.58`, captured 2026-05-22):
  //   ExifTool:Warning: "Truncated typedObject record"
  //
  // PRIOR BUG (pre-R9/F2): `skip_struct_intro` consumed the typed-object
  // name as a SILENT introducer, returning false on overrun. The
  // top-level walker dropped the warning entirely. Silent metadata
  // loss in the malformed-AMF path.
  //
  // R9 fix: split the typed-object name parsing from the generic
  // `skip_struct_intro`; on overrun push `"Truncated typedObject
  // record"` and signal abort to the caller (matching Flash.pm:353's
  // exact warning text + `last Record` cue).
  check(
    "flash_typed_object_truncated_name.flv",
    "flash_typed_object_truncated_name.flv.json",
    true,
  );
  check(
    "flash_typed_object_truncated_name.flv",
    "flash_typed_object_truncated_name.flv.n.json",
    false,
  );
}

#[test]
fn flash_array_typed_object_truncated_name_conformance() {
  // Codex PR #32 R9/F2 — adversarial fixture pinning the nested-inside-
  // strict-array typed-object truncated-name case. A mixed-array
  // contains key `arr` → strict-array of 1 element, where the element
  // is a type 0x10 typed-object with declared name length 5 but no
  // name bytes.
  //
  // Bundled trace (`-v3` 2026-05-22):
  //   + [mixedArray]                  (outer mixed-array)
  //     + [typedObject]               (inner ProcessMeta call from
  //       Warning = Truncated typedObject record   array-element loop)
  //     Warning = Truncated mixedArray record      (outer struct walker
  //                                                 re-reads the same
  //                                                 truncated 2 bytes as
  //                                                 a key-length and hits
  //                                                 line 353 with
  //                                                 $type=0x08)
  //
  // In `-j` JSON output, ONLY the FIRST warning surfaces via
  // `ExifTool:Warning`. Bundled `-j` net (captured 2026-05-22):
  //   ExifTool:Warning: "Truncated typedObject record"
  //   Flash:GoodKey: 9
  //
  // R9 fix: the typed-object truncated-name path now emits the faithful
  // `"Truncated typedObject record"` warning whether reached at top
  // level OR nested-in-array. Pins that the bundled FIRST warning
  // (typedObject, NOT the array-trunc or mixedArray) surfaces.
  check(
    "flash_array_typed_object_truncated_name.flv",
    "flash_array_typed_object_truncated_name.flv.json",
    true,
  );
  check(
    "flash_array_typed_object_truncated_name.flv",
    "flash_array_typed_object_truncated_name.flv.n.json",
    false,
  );
}

#[test]
fn flash_array_typed_object_truncated_length_conformance() {
  // Codex PR #32 R10 — adversarial fixture pinning the nested-inside-
  // strict-array typed-object NAME-LENGTH-truncation (silent) path. A
  // mixed-array contains key `arr` → strict-array of 1 element, where
  // the element is a type 0x10 typed-object with 0 bytes remaining for
  // the 2-byte name-length field.
  //
  // Bundled trace (`-v3` 2026-05-22): the array element's inner
  // ProcessMeta enters the 0x10 isStruct branch (Flash.pm:337), sets
  // `$val=''` (line 340), `$getName=1` (line 346), enters the inner
  // pair loop `for (;;)` (line 348). Line 350 `last Record if $pos+2
  //   > $dirLen` fires (silent — NO warning), exits the inner Record
  // loop. Post-loop sees `$val=''` defined → no line 455 warning
  // either. Inner returns (0x10, '') to the array walker (Flash.pm:419).
  // Array walker continues: `$v=''` defined, `$isStruct{0x10}` skips
  // push, num=1 exits loop. `$val=\@vals` (empty) assigned (line 426).
  // Returns (0x0a, []) to the outer mixedArray pair loop. Pair loop's
  // empty-array check at line 388 skips emit. Next pair-loop iteration:
  // line 350 `last Record` (out of bytes, silent) exits the outer too.
  // Post-loop $val='' defined → no warning.
  //
  // Bundled `-j` net (captured 2026-05-22):
  //   Flash:GoodKey: 9
  //   (NO ExifTool:Warning)
  //
  // R10 fix: pre-R10 `collect_array_items` lumped EVERY
  // `IntroOutcome::Truncated` from `consume_struct_intro` into a single
  // abort path that ALWAYS pushed `"Truncated AMF record 0xa"` (the
  // outer 0xa frame's bundled-faithful warning). For the silent paths
  // (0x10 name-LENGTH-truncation and 0x08 top-index-truncation),
  // bundled emits NO warning across the entire stack — the inner's
  // `$val=''` keeps every higher frame's line 455 check silent. The
  // fix splits `IntroOutcome::Truncated` into reason-tagged variants
  // and the array caller skips the spurious "Truncated AMF record 0xa"
  // push for the silent reasons. Pins NO warning emission in both `-j`
  // and `-j -n` modes.
  check(
    "flash_array_typed_object_truncated_length.flv",
    "flash_array_typed_object_truncated_length.flv.json",
    true,
  );
  check(
    "flash_array_typed_object_truncated_length.flv",
    "flash_array_typed_object_truncated_length.flv.n.json",
    false,
  );
}

#[test]
fn flash_array_mixed_array_truncated_top_index_conformance() {
  // Codex PR #32 R10 — adversarial fixture pinning the nested-inside-
  // strict-array mixed-array TOP-INDEX-truncation (silent) path. A
  // mixed-array contains key `arr` → strict-array of 1 element, where
  // the element is a type 0x08 mixed-array with 0 bytes remaining for
  // the 4-byte top-index field.
  //
  // Bundled trace (`-v3` 2026-05-22): the array element's inner
  // ProcessMeta enters the 0x08 isStruct branch (Flash.pm:337), sets
  // `$val=''` (line 340), hits the `$type==0x08` block at line 341,
  // line 343 `last if $pos+4 > $dirLen` fires `last` (unlabeled,
  // exits the inner Record loop since the inner for(;;) hasn't
  // started yet) — silent, NO warning. Post-loop sees `$val=''`
  // defined → no line 455 warning. Inner returns (0x08, '') to the
  // array walker. Same continuation as the typed-object-length case:
  // array completes with empty @vals, outer mixedArray skips empty
  // array, outer Record loop exits silently.
  //
  // Bundled `-j` net (captured 2026-05-22):
  //   Flash:GoodKey: 9
  //   (NO ExifTool:Warning)
  //
  // Same R10 fix as `flash_array_typed_object_truncated_length` — the
  // silent 0x08 top-index path now propagates as
  // `IntroTruncReason::TopIndex` (not bundled with the warn-emitting
  // typedObject-name-overrun path), so the array caller skips the
  // spurious "Truncated AMF record 0xa" push.
  check(
    "flash_array_mixed_array_truncated_top_index.flv",
    "flash_array_mixed_array_truncated_top_index.flv.json",
    true,
  );
  check(
    "flash_array_mixed_array_truncated_top_index.flv",
    "flash_array_mixed_array_truncated_top_index.flv.n.json",
    false,
  );
}

#[test]
fn flash_array_struct_intro_trunc_continues_conformance() {
  // Codex PR #32 R11/F1 — adversarial fixture pinning that a struct-
  // introducer truncation on a NON-LAST strict-array element does NOT
  // abort the element loop early. A mixed-array contains key `arr` →
  // strict-array with COUNT=2; element 0 is a type 0x10 typed-object
  // with ZERO bytes remaining for the 2-byte name-length field
  // (`IntroTruncReason::NameLength` — the SILENT introducer path).
  //
  // Bundled trace (`-v3` 2026-05-22 on
  // `flash_array_struct_intro_trunc_continues.flv`):
  //   + [mixedArray]
  //   | (adding goodKey)
  //   + [typedObject]                 (element 0 inner ProcessMeta)
  //   | Warning = Truncated AMF record 0xa
  //
  // Element 0: inner ProcessMeta enters the 0x10 isStruct branch
  // (Flash.pm:337), sets `$val=''` (line 340, the dummy), hits the
  // inner pair-loop's `last Record if $pos + 2 > $dirLen` (line 350)
  // — `$val` STAYS DEFINED (`''`). Inner returns `(0x10, '')`. The
  // array loop's `last Record unless defined $v` (line 420) is
  // SATISFIED → loop continues to element 1. Element 1: inner
  // ProcessMeta hits `last if $pos >= $dirLen` (line 302) →
  // `(undef, undef)` → array loop `last Record` → the array frame's
  // `$val = \@vals` (line 426) is never assigned → `$val=undef +
  // $type=0xa` → line 455 emits `Truncated AMF record 0xa`.
  //
  // Bundled `-j` net (captured 2026-05-22):
  //   ExifTool:Warning: "Truncated AMF record 0xa"
  //   Flash:GoodKey: 9
  //
  // PRIOR BUG (pre-R11): `collect_array_items` mapped EVERY
  // `IntroOutcome::Truncated(_)` to a SILENT `ArrayOutcome::Abort`,
  // terminating the element loop at element 0. The Rust path emitted
  // NEITHER the `Truncated AMF record 0xa` warning NOR continued to
  // surface the array-frame diagnostic — silent metadata divergence.
  //
  // R11 fix: the `IntroOutcome::Truncated(_)` arm now `continue`s the
  // element loop (collecting no list item — struct types are never
  // pushed), faithfully modelling bundled's `($type, '')` defined
  // return; the next iteration's EOF check raises the frame warning.
  check(
    "flash_array_struct_intro_trunc_continues.flv",
    "flash_array_struct_intro_trunc_continues.flv.json",
    true,
  );
  check(
    "flash_array_struct_intro_trunc_continues.flv",
    "flash_array_struct_intro_trunc_continues.flv.n.json",
    false,
  );
}

#[test]
fn flash_amf_date_zero_sentinel_conformance() {
  // Codex PR #32 R11/F2 — adversarial fixture pinning ExifTool's
  // zero-time sentinel for an AMF date (type 0x0b) of 0 milliseconds.
  // A mixed-array contains key `epoch` → AMF date with double payload
  // `0.0` and tz int16 `0`.
  //
  // Flash.pm:305-324: `$val = GetDouble(...) = 0`, `$val /= 1000` → 0,
  // `$val = ConvertUnixTime($val, 0, 6)`. Bundled ExifTool.pm:6776:
  // `return '0000:00:00 00:00:00' if $time == 0;` — the sentinel is
  // returned BEFORE any `gmtime`/`$dec` fractional formatting (so NO
  // `.ssssss`). Flash.pm:317-324 then appends the AMF tz suffix.
  //
  // Bundled `-j` net (captured 2026-05-22 via `perl exiftool 13.58`):
  //   Flash:Epoch: "0000:00:00 00:00:00+00:00"
  //
  // PRIOR BUG (pre-R11): `convert_unix_time` ran
  // `unix_to_civil_micro(0.0)` unconditionally → `1970:01:01
  // 00:00:00.000000+00:00` — diverging from bundled's sentinel.
  //
  // R11 fix: `convert_unix_time` short-circuits `secs == 0.0` to the
  // `"0000:00:00 00:00:00"` sentinel + AMF tz suffix.
  check(
    "flash_amf_date_zero_sentinel.flv",
    "flash_amf_date_zero_sentinel.flv.json",
    true,
  );
  check(
    "flash_amf_date_zero_sentinel.flv",
    "flash_amf_date_zero_sentinel.flv.n.json",
    false,
  );
}

#[test]
fn flash_amf_strict_array_known_tag_printconv_conformance() {
  // Codex PR #32 R12/F1 — adversarial fixture pinning per-element
  // PrintConv for a KNOWN Flash tag whose AMF value is a strict-array
  // (type 0x0a). A mixed-array carries key `duration` → strict-array of
  // two doubles `[1.5, 61.0]`.
  //
  // Flash.pm:394/516: `HandleTag` is called with the AMF array
  // reference itself; ExifTool's `GetValue` (ExifTool.pm:3567-3685)
  // then iterates the arrayref and applies the tag's PrintConv to EVERY
  // element. `duration` → `ConvertDuration($val)` (Flash.pm:190-193):
  //   -j: Flash:Duration: ["1.50 s","0:01:01"]
  //   -n: Flash:Duration: [1.5,61]   (PrintConv skipped)
  //
  // PRIOR BUG (pre-R12): the `FlashValue::List` emit arm serialized the
  // raw numeric list for BOTH modes, ignoring `entry.pc` — `-j` emitted
  // `[1.5,61]` instead of the per-element PrintConv strings.
  //
  // R12 fix: `flash_list_item_with_pc` applies `entry.pc` to each
  // numeric element when `print_conv` is set; raw pass-through under -n.
  check(
    "flash_duration_strict_array.flv",
    "flash_duration_strict_array.flv.json",
    true,
  );
  check(
    "flash_duration_strict_array.flv",
    "flash_duration_strict_array.flv.n.json",
    false,
  );
}

#[test]
fn flash_amf_date_pre1000_year_padding_conformance() {
  // Codex PR #32 R12/F2 — adversarial fixture pinning the space-padded
  // year of a pre-1000 AMF date. A mixed-array carries key
  // `metadatadate` → AMF date (type 0x0b) with double payload
  // -30641760000000 ms (= Unix second -30641760000 = 0999-01-01 UTC)
  // and tz int16 `0`.
  //
  // Flash.pm:305-324: `$val = GetDouble(...)`, `$val /= 1000`,
  // `$val = ConvertUnixTime($val, 0, 6)`. Bundled ExifTool.pm:6797
  // formats the year via Perl `sprintf` `%4d` — MINIMUM-WIDTH
  // SPACE-padded, NOT zero-padded:
  //   Flash:MetadataDate: " 999:01:01 00:00:00.000000+00:00"
  //
  // PRIOR BUG (pre-R12): `convert_unix_time` used `{:04}` (zero-pad) →
  // `"0999:01:01 ..."`, diverging from bundled's leading space.
  //
  // R12 fix: `convert_unix_time` formats the year with `{:>4}`
  // (right-justify, space fill) to mirror `%4d`.
  check(
    "flash_amf_date_pre1000.flv",
    "flash_amf_date_pre1000.flv.json",
    true,
  );
  check(
    "flash_amf_date_pre1000.flv",
    "flash_amf_date_pre1000.flv.n.json",
    false,
  );
}

#[test]
fn flash_amf_nested_strict_array_known_tag_raw_conformance() {
  // Codex PR #32 R13/F1 — adversarial fixture pinning that a NESTED
  // strict-array element does NOT inherit the owning tag's PrintConv. A
  // mixed-array carries key `duration` → strict-array of ONE element,
  // which is itself a strict-array `[1.5, 61.0]`.
  //
  // ExifTool's `GetValue` (ExifTool.pm:3577 `$val = $$vals[0]` / 3678
  // `$val = $$vals[$i]`) iterates only the TOP-LEVEL arrayref; it never
  // recurses into a nested arrayref. The tag PrintConv eval
  // (`ConvertDuration($val)`) is applied to the SCALAR top-level element
  // only — here the single element IS the nested arrayref, so the
  // PrintConv passes the ref through unchanged and the nested numbers
  // stay raw:
  //   -j: Flash:Duration: [[1.5,61]]
  //   -n: Flash:Duration: [[1.5,61]]   (PrintConv skipped either way)
  //
  // PRIOR BUG (pre-R13): `flash_list_item_with_pc` recursed into the
  // nested `List` with the SAME parent `pc`, so under -j it wrongly
  // emitted `[["1.50 s","0:01:01"]]`.
  //
  // R13 fix: the nested `List` arm renders via `flash_list_item_raw`
  // (PrintConv disabled at every depth).
  check(
    "flash_duration_nested_array.flv",
    "flash_duration_nested_array.flv.json",
    true,
  );
  check(
    "flash_duration_nested_array.flv",
    "flash_duration_nested_array.flv.n.json",
    false,
  );
}

#[test]
fn flash_amf_mixed_top_level_conversion_conformance() {
  // Codex PR #32 R14/F1 — adversarial fixture pinning that the owning tag
  // conversion is applied ONCE PER TOP-LEVEL element (not disabled
  // wholesale, and not recursed). A mixed-array carries key `duration` →
  // strict-array of THREE top-level elements: scalar `1.5`, a nested
  // strict-array `[2,3]`, scalar `61`.
  //
  // ExifTool's `GetValue` (ExifTool.pm:3567-3672) iterates the TOP-LEVEL
  // arrayref, running `ConvertDuration($val)` on each element. The two
  // scalars convert (`"1.50 s"`, `"0:01:01"`); the nested arrayref hits
  // `return $time unless IsFloat($time)` (ExifTool.pm:6869) and passes
  // through unchanged WITHOUT recursive descent — its inner numbers stay
  // raw:
  //   -j: Flash:Duration: ["1.50 s",[2,3],"0:01:01"]
  //   -n: Flash:Duration: [1.5,[2,3],61]
  //
  // The R13 fix rendered EVERY nested `List` raw, which is correct here
  // (and for the pure-nested `flash_duration_nested_array.flv`) BUT R14
  // observed it also disables the conversion for the top-level SCALAR
  // siblings if naively framed as "PrintConv off at depth". This fixture
  // proves the scalars STILL convert while the nested arrayref stays raw.
  //
  // Arithmetic / *datarate tags (FrameRate, TotalDataRate, AudioBitrate)
  // are deliberately NOT fixtured for the nested-arrayref case: bundled
  // coerces the arrayref to a non-deterministic Perl SV memory address
  // (changes every run under ASLR), so no stable golden exists. See the
  // `flash_list_item_with_pc` doc and the `collect_array_items_*_mul_1000`
  // unit tests for the deterministic port behavior.
  check(
    "flash_duration_mixed_nested.flv",
    "flash_duration_mixed_nested.flv.json",
    true,
  );
  check(
    "flash_duration_mixed_nested.flv",
    "flash_duration_mixed_nested.flv.n.json",
    false,
  );
}

#[test]
fn flash_audio_encoding_reserved_unknown_printconv_conformance() {
  // Codex PR #32 R13/F2 — adversarial fixture pinning the hash-PrintConv
  // MISS idiom. An audio-only FLV (header flags 0x04) with audio config
  // octet 0x9F → AudioEncoding nibble = 9 (reserved; absent from the
  // `%Flash::Audio` Bit0-3 hash, Flash.pm:96-113).
  //
  // ExifTool's `GetValue` (ExifTool.pm:3603-3625) sets `$value =
  // "Unknown ($val)"` when `$$conv{$val}` is undefined and the hash has
  // no BITMASK/OTHER. None of the Flash audio/video hashes declares
  // PrintHex, so the decimal `Unknown (N)` form is used:
  //   -j: Flash:AudioEncoding: "Unknown (9)"
  //   -n: Flash:AudioEncoding: 9   (PrintConv skipped → raw nibble)
  //
  // PRIOR BUG (pre-R13): the hash miss fell through to the raw numeric
  // under -j, emitting `9` instead of `"Unknown (9)"`.
  check(
    "flash_audio_encoding_reserved.flv",
    "flash_audio_encoding_reserved.flv.json",
    true,
  );
  check(
    "flash_audio_encoding_reserved.flv",
    "flash_audio_encoding_reserved.flv.n.json",
    false,
  );
}

#[test]
fn flash_audio_tail_truncation_emits_tags_conformance() {
  // Codex PR #32 R13/F3 — adversarial fixture pinning that an audio
  // packet whose DECLARED payload is truncated AFTER the first config
  // byte still emits all four Flash audio tags with NO warning. An
  // audio-only FLV (flags 0x04) tag declares dataSize 5 but the file ends
  // right after the single config byte (octet 0x2F → MP3 / 44100 / 16 /
  // stereo).
  //
  // Flash.pm:500 reads only ONE byte for an audio packet
  // (`$raf->Read($buff,1)==1`), subtracts it from `$len`, HandleTag, then
  // `last unless $flags` (line 521) BEFORE the residual `Seek($len,1)`
  // (line 522). Since the audio flag (0x04) was the only requested flag,
  // `$flags` clears to 0 and the loop exits before the residual seek ever
  // touches the truncated tail:
  //   -j: AudioEncoding "MP3" / SampleRate 44100 / BitsPerSample 16 /
  //       Channels "2 (stereo)" — no warning.
  //   -n: AudioEncoding 2 / 44100 / 16 / 2 — no warning.
  //
  // PRIOR BUG (pre-R13): `parse_inner` required the ENTIRE declared body
  // before dispatching, so the truncated tail took the failure path,
  // pushed `Bad Audio packet`, and emitted nothing.
  //
  // R13 fix: the full-body availability check moved into the per-type
  // branches — audio/video need only `len >= 1` + one config byte, and
  // the residual seek emulates Perl's later skip/stop.
  check(
    "flash_audio_tail_truncated.flv",
    "flash_audio_tail_truncated.flv.json",
    true,
  );
  check(
    "flash_audio_tail_truncated.flv",
    "flash_audio_tail_truncated.flv.n.json",
    false,
  );
}

#[test]
fn flash_amf_bad_utf8_fixup_conformance() {
  // Codex PR #32 R18/F1 — adversarial fixture pinning ExifTool's
  // FixUTF8-at-JSON semantics for every AMF string-like kind. The
  // onMetaData mixed-array carries three values whose payload is the
  // invalid-UTF-8 byte run `41 ff 42`:
  //   * `badStr`  — AMF string     (0x02, Flash.pm:331-336)
  //   * `badLong` — AMF long string (0x0c, Flash.pm:427-432)
  //   * `badXml`  — AMF XML doc      (0x0f, Flash.pm:427-432)
  //
  // Bundled Flash.pm keeps the RAW bytes (`$val = substr(...)`) and the
  // `exiftool` JSON emitter applies `Image::ExifTool::XMP::FixUTF8`
  // (exiftool:3822 → XMP.pm:2948-2972), replacing the stray `0xff` with
  // the literal ASCII `?`. Bundled `perl exiftool` (verified oracle)
  // emits `Flash:BadStr/BadLong/BadXml = "A?B"` in BOTH -j and -n.
  //
  // PRIOR BUG (pre-R18): the 0x02 and 0x0c/0x0f arms decoded via
  // `String::from_utf8_lossy`, materializing U+FFFD (`EF BF BD`) — a
  // 3-byte mismatch versus the single `?` byte, failing the jsondiff
  // gate. R18 fix routes all payload-derived AMF strings through
  // `crate::convert::fix_utf8`, the faithful FixUTF8 transliteration.
  check(
    "flash_amf_bad_utf8.flv",
    "flash_amf_bad_utf8.flv.json",
    true,
  );
  check(
    "flash_amf_bad_utf8.flv",
    "flash_amf_bad_utf8.flv.n.json",
    false,
  );
}

#[test]
fn exif_badformat_entry0_conformance() {
  // PR #36 Codex R2 F1 — IFD0 whose FIRST entry (index 0) carries an
  // unrecognized format code (99). ExifTool warns `Bad format (99) for
  // IFD0 entry 0` (`++$warnCount`) and, because the bad format is at
  // entry 0 — "assume corrupted IFD if this is our first entry" —
  // `return 0`, aborting the WHOLE directory (Exif.pm:6464-6477). The
  // valid Orientation entry that follows is NEVER reached: bundled emits
  // ONLY the warning, no IFD0 tags. Verified against bundled `perl
  // exiftool` 2026-05-22.
  check(
    "Exif_badformat_entry0.tif",
    "Exif_badformat_entry0.tif.json",
    true,
  );
  check(
    "Exif_badformat_entry0.tif",
    "Exif_badformat_entry0.tif.n.json",
    false,
  );
}
#[test]
fn exif_make_invalid_utf8_fixutf8_conformance() {
  // #200 — an EXIF text value (IFD0 Make) holding INVALID UTF-8 must render
  // through ExifTool's `FixUTF8` (default `$bad = '?'`, `XMP.pm:2969`), NOT the
  // Unicode REPLACEMENT CHARACTER U+FFFD that `from_utf8_lossy` substitutes.
  // ExifTool applies `FixUTF8` at the JSON serialization boundary
  // (`exiftool:3823` `EscapeJSON`), so every emitted string is fixed regardless
  // of tag. `Exif_make_invalid_utf8.tif` is a CRAFTED big-endian TIFF whose
  // IFD0 `Make` (0x010f, ASCII) carries the bytes `41 c3 a9 42 ff 43 fe 44 00`
  // = `A` + valid `é` (C3 A9) + `B` + invalid `0xFF` + `C` + invalid `0xFE` +
  // `D`. Bundled `perl exiftool 13.59 -j -G1` emits `"IFD0:Make": "AéB?C?D"`
  // (the valid `é` passes through; each invalid byte → one `?`); identical in
  // `-n`. Verified vs bundled 13.59; golden via `tools/gen_golden.sh`. Pins
  // that the EXIF `string`/`utf8` decode (`ifd::lossy_string` → `fix_utf8`)
  // emits `?`, not `\u{FFFD}`.
  check(
    "Exif_make_invalid_utf8.tif",
    "Exif_make_invalid_utf8.tif.json",
    true,
  );
  check(
    "Exif_make_invalid_utf8.tif",
    "Exif_make_invalid_utf8.tif.n.json",
    false,
  );
}
#[test]
fn exif_usercomment_invalid_utf8_fixutf8_conformance() {
  // #200 (round 2) — UserComment (0x9286) decodes through `ConvertExifText`
  // (`exif::exiftext::convert_exif_text`), whose ASCII-prefix payload branch
  // must render invalid UTF-8 via ExifTool's `FixUTF8` (default `$bad = '?'`,
  // `XMP.pm:2969`), NOT the Unicode REPLACEMENT CHARACTER U+FFFD that
  // `from_utf8_lossy` substitutes. ExifTool applies `FixUTF8` at the JSON
  // serialization boundary (`exiftool:3823` `EscapeJSON`), so the payload's
  // invalid bytes — which never survive into a `TagValue::Str` the `-j`
  // serializer could fix — must already be `?` at decode. The R1 fix routed
  // only the TIFF `string`/`utf8` decode (`ifd::lossy_string`) through
  // `fix_utf8`; this fixture pins the `ConvertExifText` payload path too.
  //
  // `Exif_usercomment_invalid_utf8.tif` is a CRAFTED big-endian TIFF whose
  // IFD0 → ExifIFD → UserComment carries `ASCII\0\0\0` + `41 c3 a9 42 ff 43
  // fe 44` = `A` + valid `é` (C3 A9) + `B` + invalid `0xFF` + `C` + invalid
  // `0xFE` + `D`. Bundled `perl exiftool 13.59 -j -G1` emits
  // `"ExifIFD:UserComment": "AéB?C?D"` (the valid `é` passes through; each
  // invalid byte → one `?`); identical in `-n`. Verified vs bundled 13.59;
  // golden via `tools/gen_golden.sh`.
  check(
    "Exif_usercomment_invalid_utf8.tif",
    "Exif_usercomment_invalid_utf8.tif.json",
    true,
  );
  check(
    "Exif_usercomment_invalid_utf8.tif",
    "Exif_usercomment_invalid_utf8.tif.n.json",
    false,
  );
}
#[test]
fn exif_gps_processingmethod_invalid_utf8_fixutf8_conformance() {
  // #200 (round 2) — GPSProcessingMethod (0x001b) also decodes through
  // `ConvertExifText`; its ASCII-prefix payload must render invalid UTF-8 as
  // `?` via `FixUTF8`, same as UserComment (both pass `$asciiFlex == 1`).
  // This pins the GPS sub-IFD path of the fix.
  //
  // `Exif_gps_processingmethod_invalid_utf8.tif` is a CRAFTED big-endian TIFF
  // whose IFD0 → GPS IFD → GPSProcessingMethod carries `ASCII\0\0\0` + `41 ff
  // 42 fe 43` = `A` + invalid `0xFF` + `B` + invalid `0xFE` + `C`. Bundled
  // `perl exiftool 13.59 -j -G1` emits `"GPS:GPSProcessingMethod": "A?B?C"`
  // (one `?` per bad byte); identical in `-n`. Verified vs bundled 13.59;
  // golden via `tools/gen_golden.sh`.
  check(
    "Exif_gps_processingmethod_invalid_utf8.tif",
    "Exif_gps_processingmethod_invalid_utf8.tif.json",
    true,
  );
  check(
    "Exif_gps_processingmethod_invalid_utf8.tif",
    "Exif_gps_processingmethod_invalid_utf8.tif.n.json",
    false,
  );
}
#[test]
fn exif_excessive_count_conformance() {
  // Golden-v2 Phase C — the `[Minor]` (ignorable == 2) prefix path. A crafted
  // big-endian TIFF whose IFD0 carries ONE KNOWN tag (Orientation 0x0112) with
  // on-disk format int8u and count 100001 — in the (100000, 2000000] band, so
  // `$minor = $count > 2000000 ? 0 : 2 = 2` (Exif.pm:6766). The full value is
  // present (the count guard at Exif.pm:6764 fires only after a successful
  // read), so ExifTool warns + skips the entry with the `[Minor] ` prefix (the
  // `'2'` arm of ExifTool.pm:5630). Oracle-verified vs `perl exiftool 13.59`
  // (version stamp normalized to 13.58): `ExifTool:Warning = "[Minor] Ignoring
  // IFD0 Orientation with excessive count"`. The prefix now comes from
  // `run_diagnostics` (was previously absent — a pre-Phase-C fidelity gap).
  check(
    "Exif_excessive_count.tif",
    "Exif_excessive_count.tif.json",
    true,
  );
  check(
    "Exif_excessive_count.tif",
    "Exif_excessive_count.tif.n.json",
    false,
  );
}
#[test]
fn exif_badformat_ifd1_conformance() {
  // PR #36 Codex R3 F1 — IFD0 whose FIRST entry (index 0) has a bad format
  // code (99) AND a NON-zero next-IFD pointer to a structurally valid IFD1
  // (thumbnail) carrying a real `Orientation`. ExifTool's `return 0`
  // (Exif.pm:6477) exits `ProcessExif` ENTIRELY — before the line-7202
  // trailing-IFD scan — so the IFD0 abort suppresses IFD1 too. Bundled
  // emits ONLY `Bad format (99) for IFD0 entry 0`, NO `IFD1:Orientation`.
  // Pins that `walk_entries`'s entry-0 abort propagates out of
  // `walk_one_ifd` BEFORE the next-IFD pointer is read. Verified against
  // bundled `perl exiftool` 2026-05-22.
  check(
    "Exif_badformat_ifd1.tif",
    "Exif_badformat_ifd1.tif.json",
    true,
  );
  check(
    "Exif_badformat_ifd1.tif",
    "Exif_badformat_ifd1.tif.n.json",
    false,
  );
}
#[test]
fn exif_badoffset_eof_conformance() {
  // PR #36 Codex R1 F1 — an out-of-line value whose offset is inside the
  // block but `offset + size` runs past EOF. ExifTool would seek in the
  // file (`$raf`, Exif.pm:6552-6608); the `Read` fails, yielding
  // `Error reading value for IFD0 entry 2, ID 0x0131 Software`
  // (Exif.pm:6594) and `$bad = 1` — the tag is dropped. The valid
  // IFD0:Make / IFD0:Model survive. Verified against bundled `perl
  // exiftool` 2026-05-22; goldens via `tools/gen_golden.sh`.
  check(
    "Exif_badoffset_eof.tif",
    "Exif_badoffset_eof.tif.json",
    true,
  );
  check(
    "Exif_badoffset_eof.tif",
    "Exif_badoffset_eof.tif.n.json",
    false,
  );
}
#[test]
fn exif_badoffset_low_conformance() {
  // PR #36 Codex R1 F1 — an out-of-line value (>4 bytes) whose 32-bit
  // offset points into the 8-byte TIFF header (offset 4). ExifTool's
  // "offset shouldn't point into TIFF header" guard (`$valuePtr < 8 …
  // $suspect = $warnCount`, Exif.pm:6539) — reinforced here by the
  // value range overlapping the IFD (Exif.pm:6549) — flags the tag
  // `$suspect` and the trailing check (Exif.pm:6673-6678) emits
  // `Suspicious IFD0 offset for Software` then skips the tag. The
  // valid IFD0:Make / IFD0:Model are still emitted. Verified against
  // bundled `perl exiftool -j -G1 -struct` 2026-05-22; goldens via
  // `tools/gen_golden.sh Exif_badoffset_low.tif`.
  check(
    "Exif_badoffset_low.tif",
    "Exif_badoffset_low.tif.json",
    true,
  );
  check(
    "Exif_badoffset_low.tif",
    "Exif_badoffset_low.tif.n.json",
    false,
  );
}
#[test]
fn exif_conformance() {
  // FORMATS.md row 13: Image::ExifTool::Exif. A standalone TIFF file IS an
  // Exif/TIFF block — `File:FileType == "TIFF"` dispatches to `ProcessExif`.
  //
  // Fixture `tests/fixtures/Exif.tif` is a SYNTHESIZED minimal standalone
  // TIFF (the bundled `t/images/*.tif` fixtures pull IPTC / ICC_Profile /
  // GeoTiff SubDirectories from SEPARATE ExifTool modules that are NOT part
  // of the Exif.pm port — so they cannot be a clean Exif-only conformance
  // gate). The synthetic TIFF exercises ONLY the Exif IFD machinery, the
  // same documented-synthetic-fixture approach as the Matroska adversarial
  // fixtures. Generated by `tools/gen_exif_fixtures.py`.
  //
  // Big-endian (MM) header; exercises:
  //   - TIFF header parse (DoProcessTIFF, ExifTool.pm:8628-8645)
  //   - the IFD walker (ProcessExif, Exif.pm:6278-7240)
  //   - IFD0 → IFD1 next-IFD chain (Exif.pm:7203-7228 — IFD1 thumbnail)
  //   - the ExifIFD SubIFD via tag 0x8769 (Exif.pm:2006-2015)
  //   - type decoders: ASCII / SHORT / LONG / RATIONAL / UNDEF (ReadValue)
  //   - inline (≤4-byte) vs out-of-line value pointers
  //   - PrintConv: Orientation/Compression/ResolutionUnit/ColorSpace/
  //     ExposureMode hashes; PrintExposureTime; PrintFNumber;
  //     `%.1f mm` FocalLength; ShutterSpeedValue APEX ValueConv;
  //     ApertureValue APEX; ExifVersion `undef`-as-ASCII
  //   - File:ExifByteOrder (ExifTool.pm:8691)
  // Goldens: bundled `perl exiftool -j -G1 -struct` with `System:*` stripped,
  // KEEPING the ported Tier-A EXIF Composites `Aperture` (4.0) + `ShutterSpeed`
  // (1/160) which exifast now builds (#133 PR 3 — EXIF is allow-listed), and
  // dropping only the still-unported lens Composites by name
  // (`FocalLength35efl`/`LightValue`/`LensID`, #133 PR 4). The `gen_golden.sh
  // Exif.tif` arm bakes this in.
  check("Exif.tif", "Exif.tif.json", true);
  check("Exif.tif", "Exif.tif.n.json", false);
}
#[test]
fn dji_ae_dbg_info_conformance() {
  // #115: the DJI `ae_dbg_info` debug MakerNote — a 0x927C value that is a
  // `[key:val]…` bracketed-string run, NOT an IFD. `MakerNotes.pm:93-97` routes
  // a value matching `^\[ae_dbg_info:/` (`NotIFD => 1`) to `%DJI::Info` /
  // `ProcessDJIInfo` (`DJI.pm:74-95` table, `:960-983` proc), which walks the
  // brackets and emits one `DJI:*` tag per `[key:val]` pair.
  //
  // Fixture `tests/fixtures/DJI_ae_dbg_info.tif` (crafted by
  // `tools/gen_exif_fixtures.py`, little-endian) carries IFD0 `Make=DJI` and a
  // 0x927C MakerNote
  //   [ae_dbg_info:…][ae_histogram_info:…][awb_dbg_info:…]
  //   [GimbalDegree(Y,P,R):…][FlightDegree(Y,P,R):…][sensor_id:…]
  //   [some_unknown_tag:hello world]
  // pinning:
  //   - the named-key renames (`%DJI::Info`): ae_dbg_info → AEDebugInfo,
  //     ae_histogram_info → AEHistogramInfo, awb_dbg_info → AWBDebugInfo,
  //     GimbalDegree(Y,P,R) → GimbalDegree, FlightDegree(Y,P,R) → FlightDegree,
  //     sensor_id → SensorID;
  //   - the `MakeTagInfo => 1` synthesis for an UNKNOWN key
  //     (some_unknown_tag → `DJI:Some_Unknown_Tag`, `ExifTool.pm:9312-9317`).
  // All seven values are printable ASCII ⇒ string emissions. `%DJI::Info` has
  // no PrintConv/ValueConv, so the `-j` and `-n` renderings are IDENTICAL.
  check("DJI_ae_dbg_info.tif", "DJI_ae_dbg_info.tif.json", true);
  check("DJI_ae_dbg_info.tif", "DJI_ae_dbg_info.tif.n.json", false);
}
#[test]
fn bigtiff_subifd_conformance() {
  // #240 — BigTIFF SubIFD pointer recursion (`ProcessBigIFD`'s `$$tagInfo{SubIFD}`
  // branch, `BigTIFF.pm:171-198`). The bundled `BigTIFF.btf` is a FLAT single-IFD
  // image with NO SubIFD pointers, so it never exercises the recursion; this is a
  // CRAFTED BigTIFF (version 43, 8-byte offsets — `tools/gen_bigtiff_subifd_fixture.py`)
  // whose little-endian IFD0 carries Make/Model plus an ExifOffset (0x8769) pointer
  // to an ExifIFD (ExposureTime/FNumber/ISO/ExifVersion) AND a GPSInfo (0x8825)
  // pointer to a GPS IFD (GPSVersionID/Ref/Latitude bytes).
  //
  // It pins the FAITHFUL recursion semantics — verified against bundled ExifTool
  // 13.59 (the gap proof + oracle): `ProcessBigIFD` recurses EVERY SubIFD pointer
  // REUSING the inherited `%Exif::Main` (NOT the pointer's `SubDirectory{TagTable}`)
  // and names the family-1 dir from the POINTER TAG (`$$tagInfo{Name}`). So:
  //   - the ExifIFD child emits `ExifOffset:ExposureTime`/`FNumber`/`ISO`/`ExifVersion`
  //     (group `ExifOffset`, NOT `ExifIFD`);
  //   - the GPS child's 0x0001/0x0002 resolve in `%Exif::Main` (NOT `%GPS::Main`),
  //     so they emit as `GPSInfo:InteropIndex` ("Unknown (N)") / `GPSInfo:InteropVersion`
  //     ("37 48 30"), NOT `GPS:GPSLatitudeRef`/`GPS:GPSLatitude`.
  // The ported EXIF Composites (`Aperture`/`ShutterSpeed`/`LightValue`, built from
  // the ExifOffset child's FNumber/ExposureTime) are kept (EXIF is Composite
  // allow-listed, #133); `gen_golden.sh` strips only `System:*` for this fixture.
  check("BigTIFF_subifd.btf", "BigTIFF_subifd.btf.json", true);
  check("BigTIFF_subifd.btf", "BigTIFF_subifd.btf.n.json", false);
}

#[test]
fn bigtiff_subifd_multi_offset_conformance() {
  // #240 Codex round 2 — `ProcessBigIFD` recurses EVERY parsed SubIFD offset,
  // not just the first, and not just an `int64u`/`ifd64` shape: it `ReadValue`s
  // the pointer, `my @offsets = split ' ', $val`s the resulting STRING, and
  // recurses each token (`BigTIFF.pm:184-198`) with NO integer-format gate. The
  // R1 `BigTIFF_subifd.btf` fixture uses LONG8 count=1 pointers, so it cannot
  // catch the first-only / integer-only regression. This CRAFTED BigTIFF
  // (little-endian, 8-byte offsets) exercises BOTH gaps in one file:
  //   - an ExifOffset (0x8769) `LONG8` count=2 pointer → TWO child ExifIFDs.
  //     ExifTool walks both and `$subdirName .= $i if $i`-suffixes the family-1
  //     group of the 2nd: `ExifOffset:ISO` (400) + `ExifOffset1:ISO` (800)
  //     (oracle-confirmed on bundled 13.59; the first-only walk dropped 800);
  //   - a GPSInfo (0x8825) ASCII-NUMERIC pointer (a `string` whose text "180"
  //     is the child offset). `split ' ', "180"` numifies it → offset 180, so
  //     the GPS child recurses REUSING `%Exif::Main`: `GPSInfo:InteropIndex`
  //     ("Unknown (N)" / "N"), NOT `%GPS::Main` (the U64/I64-only extractor
  //     returned None for this `RawValue::Text` and dropped it entirely).
  // ISO-only children carry no FNumber/ExposureTime, so NO `Composite:*` is
  // synthesized — the golden is File:/IFD0:/ExifOffset*:/GPSInfo: only (no
  // EXCLUDE arm; `gen_golden.sh` strips `System:*` via COMMON).
  check(
    "BigTIFF_subifd_multi.btf",
    "BigTIFF_subifd_multi.btf.json",
    true,
  );
  check(
    "BigTIFF_subifd_multi.btf",
    "BigTIFF_subifd_multi.btf.n.json",
    false,
  );
}

#[test]
fn bigtiff_subifd_exp_offset_conformance() {
  // #240 round-2 follow-up (the Codex [medium] finding) — `ProcessBigIFD` numifies
  // the `split ' ', $val` SubIFD-offset token in Perl numeric context, i.e. via
  // Perl's FULL string→number grammar (fraction + exponent), NOT a leading-decimal-
  // digit run. A digit-prefix-only reader coerces an ASCII pointer `"1e3"` to 1 and
  // recurses at byte 1 (dropping the child); Perl `0 + "1e3" == 1000`, so the child
  // is at byte 1000. This CRAFTED BigTIFF (little-endian, 8-byte offsets —
  // `tools/gen_bigtiff_subifd_fixture.py <out> exp`) has IFD0 carry Make/Model plus
  // a GPSInfo (0x8825) pointer whose VALUE is the ASCII string `"1e3"`, with the GPS
  // child IFD placed at absolute byte 1000.
  //
  // Ground-truthed against bundled ExifTool 13.59: it recurses the child at byte
  // 1000, REUSING the inherited `%Exif::Main` (so 0x0001/0x0002 → `GPSInfo:
  // InteropIndex` "Unknown (N)" / `GPSInfo:InteropVersion` "37 48 30", NOT
  // `%GPS::Main`). The GPS-only child carries no FNumber/ExposureTime ⇒ no
  // `Composite:*` is synthesized; `gen_golden.sh` strips only `System:*`.
  // Pins [`crate::convert::perl_str_to_f64`]-based offset coercion: the child tags
  // appear iff exifast recurses at the Perl-coerced 1000 (the pre-fix 1 dropped them).
  check(
    "BigTIFF_subifd_exp.btf",
    "BigTIFF_subifd_exp.btf.json",
    true,
  );
  check(
    "BigTIFF_subifd_exp.btf",
    "BigTIFF_subifd_exp.btf.n.json",
    false,
  );
}
#[test]
fn bigtiff_jpegpreview_strip_not_preview_conformance() {
  // The `dng_tiff_jpeg_preview` gate is TIFF_TYPE-scoped — a BigTIFF must NOT
  // take the classic-TIFF `PreviewImage`/`JpgFromRaw` arms. `ProcessBTF`/
  // `ProcessBigIFD` is dispatched from `DoProcessTIFF`'s `$identifier == 0x2b`
  // arm and `return 1`s at `ExifTool.pm:8668` BEFORE `$$self{TIFF_TYPE} =
  // $fileType` (`:8715`), so `$$self{TIFF_TYPE}` stays its constructor default
  // `''` (`:4369`) for the whole BigTIFF walk. `'' !~ /^(DNG|TIFF)$/`
  // (`Exif.pm:635`/`:735`), so the `0x111`/`0x117` conditional tag lists fall to
  // the DEFAULT `StripOffsets`/`StripByteCounts` arm (`Exif.pm:631-643`) — even
  // though IFD0 carries `SubfileType=1` (0xfe) + `Compression=7` (0x103, JPEG),
  // the EXACT shape that DOES trigger the `PreviewImage` arm for a classic
  // `TIFF`-typed file (cf. `tiff_jpgfromraw_conformance`).
  //
  // This CRAFTED little-endian BigTIFF (version 43, 8-byte offsets —
  // `tools/gen_bigtiff_subifd_fixture.py <out> jpegpreview`) has IFD0 carry
  // SubfileType/Compression/Make/Model + `StripOffsets` (0x111) → a 4-byte strip
  // blob + `StripByteCounts` (0x117). Ground-truthed against bundled ExifTool
  // 13.59: it emits `IFD0:StripOffsets` + `IFD0:StripByteCounts` (plus
  // `IFD0:SubfileType`/`IFD0:Compression`), with NO `PreviewImageStart`/`Length`/
  // `PreviewImage` and NO `JpgFromRaw*`. Pins that `parse_bigtiff` walks with
  // `Walker::file_type == None` (the `''` TIFF_TYPE sentinel), so the gate is
  // false — guarding the `file_type`-per-entry class against a BigTIFF inheriting
  // the caller's `Some("TIFF")` and synthesizing a spurious PreviewImage.
  check(
    "BigTIFF_jpegpreview.btf",
    "BigTIFF_jpegpreview.btf.json",
    true,
  );
  check(
    "BigTIFF_jpegpreview.btf",
    "BigTIFF_jpegpreview.btf.n.json",
    false,
  );

  // Explicit negative assertions on the raw -j / -n output: NEITHER the renamed
  // preview offset/length leaves NOR the synthetic image tag appear (a
  // regression of the gate would rename 0x111/0x117 + add a `PreviewImage`).
  let root = env!("CARGO_MANIFEST_DIR");
  let data = std::fs::read(format!("{root}/tests/fixtures/BigTIFF_jpegpreview.btf"))
    .expect("read BigTIFF_jpegpreview.btf");
  for print_on in [true, false] {
    let got = extract_info("BigTIFF_jpegpreview.btf", &data, print_on);
    assert!(
      got.contains("\"IFD0:StripOffsets\":152") && got.contains("\"IFD0:StripByteCounts\":4"),
      "BigTIFF IFD0 0x0111/0x0117 must stay StripOffsets/StripByteCounts (print_conv={print_on}): {got}",
    );
    assert!(
      !got.contains("PreviewImage") && !got.contains("JpgFromRaw"),
      "a BigTIFF must NOT take the DNG/TIFF PreviewImage/JpgFromRaw arms \
       (TIFF_TYPE is '' for the BigTIFF walk) (print_conv={print_on}): {got}",
    );
  }
}
#[test]
fn exif_eofoverrun_chain_conformance() {
  // PR #36 Codex R14 F1 — IFD0 entry 1 is an out-of-line value (Software)
  // that overruns EOF, with a VALID entry 2 (Orientation) AFTER it AND a
  // NON-zero next-IFD pointer to a structurally valid IFD1. A standalone
  // TIFF carries a RAF (`DoProcessTIFF` sets `RAF => $raf`,
  // ExifTool.pm:8717; `ProcessExif` reads it, Exif.pm:6289), so the
  // out-of-line read takes the `if ($raf)` path (Exif.pm:6552); the past-
  // EOF `$raf->Read` fails (Exif.pm:6593) → `Error reading value for IFD0
  // entry 1, ID 0x0131 Software` (Exif.pm:6594) → `return 0 unless
  // $inMakerNotes or $htmlDump or $truncOK` (Exif.pm:6602) — the WHOLE
  // directory aborts. That `return 0` exits `ProcessExif` BEFORE the line-
  // 7202 trailing-IFD scan, so the chain is never followed: bundled emits
  // ONLY `IFD0:Make` + the warning — `IFD0:Orientation` (later entry) and
  // every IFD1 tag are SUPPRESSED. Pins that `walk_entry`'s EOF read-
  // failure returns `false` (abort), so neither the entry loop nor the
  // next-IFD pointer surfaces a tag the oracle drops. The MakerNotes /
  // truncOK exemption (where bundled warns + continues) never applies to
  // this walker: it defers MakerNote parsing and emits no TruncateOK tag.
  // Verified against bundled `perl exiftool` 2026-05-22.
  check(
    "Exif_eofoverrun_chain.tif",
    "Exif_eofoverrun_chain.tif.json",
    true,
  );
  check(
    "Exif_eofoverrun_chain.tif",
    "Exif_eofoverrun_chain.tif.n.json",
    false,
  );
}
#[test]
fn exif_focallength35_conformance() {
  // PR #36 Codex R1 F3 — FocalLengthIn35mmFormat (0xa405) is an `int16u`
  // with PrintConv `"$val mm"` (Exif.pm:2896): Perl interpolates the
  // integer scalar with NO decimal point, so `75` renders `"75 mm"`.
  // This is DISTINCT from FocalLength (0x920a), a `rational64u` with
  // `sprintf("%.1f mm",$val)` (Exif.pm:2425) → `"50.0 mm"`. The pre-fix
  // shared `Conv::FocalLengthMm` wrongly rendered `"75.0 mm"`. The
  // fixture carries 0xa405 only (no 0x920a) so bundled emits no
  // `Composite:FocalLength35efl`. Verified against bundled `perl
  // exiftool` 2026-05-22.
  check(
    "Exif_focallength35.tif",
    "Exif_focallength35.tif.json",
    true,
  );
  check(
    "Exif_focallength35.tif",
    "Exif_focallength35.tif.n.json",
    false,
  );
}
#[test]
fn exif_gap_tags_conformance() {
  // Table-codegen Step B — the binary-EXIF coverage-gap `%Exif::Main` leaf
  // tags the camera-relevant hand subset (`src/exif/tables.rs` `EXIF_TAGS`)
  // dropped on the binary IFD path, now emitted via the `--kind exif`
  // generated shadow (they fall through the hand-first `tables::lookup` to
  // the generated table). The fixture exercises the plain (`Conv::None`)
  // tags (ProcessingSoftware/HostComputer/TimeZoneOffset/
  // StandardOutputSensitivity/ISOSpeed*/ImageNumber/ImageHistory/
  // SubjectArea/SubjectLocation/Humidity/Pressure/WaterDepth/Acceleration/
  // CameraElevationAngle/CompositeImageCount), the `Binary => 1` placeholder
  // (Opto-ElectricConvFactor → `(Binary data 8 bytes, …)`), the two
  // declarative HASH PrintConvs (SecurityClassification `"C"`→`"Confidential"`
  // / `Conv::StrLabel`; CompositeImage `2`→`"General Composite Image"` /
  // `Conv::IntLabel`), and the code-valued `AmbientTemperature` (0x9400,
  // `Conv::CelsiusSuffix` → `"23.5 C"`). No Make/Model/IFD1 and no
  // FNumber+FocalLength combo, so bundled emits NO `Composite:*` tags.
  // Verified byte-identical to bundled `perl exiftool` 13.59.
  check("Exif_gap_tags.tif", "Exif_gap_tags.tif.json", true);
  check("Exif_gap_tags.tif", "Exif_gap_tags.tif.n.json", false);
}
#[test]
fn exif_ambient_multi_conformance() {
  // Codex follow-up to Step B — `AmbientTemperature` (0x9400) `Conv::CelsiusSuffix`
  // with a MALFORMED count>1 `rational64s` value (`235/10`, `-50/10`). The
  // PrintConv `'"$val C"'` (Exif.pm:2590) interpolates the WHOLE post-`ReadValue`
  // value — the space-joined element list — with ` C` appended ONCE, NOT the
  // first element only. Pre-fix the conv used `first_rational_str` and wrongly
  // emitted `"23.5 C"`; the fix renders the full value (`value_space_joined`) ⇒
  // `-j` → `"23.5 -5 C"`, `-n` → `"23.5 -5"` (`-50/10` rounds to `-5` via the
  // `GetRational64s` `%.10g`). Verified byte-identical to bundled `perl
  // exiftool` 13.59.
  check(
    "Exif_ambient_multi.tif",
    "Exif_ambient_multi.tif.json",
    true,
  );
  check(
    "Exif_ambient_multi.tif",
    "Exif_ambient_multi.tif.n.json",
    false,
  );
}
#[test]
fn exif_composite_exposure_conformance() {
  // Table-codegen Step B — `CompositeImageExposureTimes` (0xa462), the
  // bespoke `undef`-format `RawConv`/`PrintConv` pair (Exif.pm:3068-3119)
  // ported as `Conv::CompositeImageExposureTimes`. The blob is decoded as a
  // sequence of `rational64u` quotients EXCEPT at byte offsets 56/58 (element
  // indices 7/8) which are `int16u` counts; the PrintConv maps every element
  // EXCEPT those two through `PrintExposureTime`. The fixture lays 11 values
  // (7 rationals, the 2 int16u counts `3`/`2`, 2 more rationals) so the
  // carve-out is exercised: `-j` → `"1/160 … 1/640 3 2 1/160 1/200"`, `-n` →
  // `"0.00625 … 0.0015625 3 2 0.00625 0.005"`. Verified byte-identical to
  // bundled `perl exiftool` 13.59.
  check(
    "Exif_composite_exposure.tif",
    "Exif_composite_exposure.tif.json",
    true,
  );
  check(
    "Exif_composite_exposure.tif",
    "Exif_composite_exposure.tif.n.json",
    false,
  );
}
#[test]
fn exif_composite_exposure_edge_conformance() {
  // Codex follow-up to Step B — `CompositeImageExposureTimes` (0xa462) edge
  // cases for the `RawConv`→`PrintConv` token pipeline (Exif.pm:3068-3119).
  // ExifTool's `RawConv` stringifies each rational via `GetRational64u` =
  // `RoundFloat(n/d, 10)` (`%.10g`, or `undef`/`inf` for a zero denominator)
  // and the `PrintConv` re-`split`s + `PrintExposureTime`'s each TOKEN — so the
  // print value is keyed on the ROUNDED token, NOT the unrounded quotient.
  //   idx0 `2/19` → token `0.1052631579` → `int(0.5 + 1/0.1052631579) =
  //        int(9.999…) = 9` ⇒ `"1/9"` (the unrounded `0.10526…` has `1/secs =
  //        9.5` exactly ⇒ `int(10.0) = 10` ⇒ the WRONG `"1/10"`).
  //   idx1 `0/0` → `GetRational64u` word `undef`; not a float ⇒ passes through
  //        unchanged (the unrounded path would divide `0/0 = NaN` ⇒ `"NaN"`).
  // The pre-fix decoder fed the unrounded `f64` quotient to PrintExposureTime
  // and diverged on BOTH. `-j` → `"1/9 undef …"`, `-n` → `"0.1052631579 undef
  // …"`. Verified byte-identical to bundled `perl exiftool` 13.59.
  check(
    "Exif_composite_exposure_edge.tif",
    "Exif_composite_exposure_edge.tif.json",
    true,
  );
  check(
    "Exif_composite_exposure_edge.tif",
    "Exif_composite_exposure_edge.tif.n.json",
    false,
  );
}
#[test]
fn exif_composite_exposure_wrongfmt_conformance() {
  // #198 — `CompositeImageExposureTimes` (0xa462) written with the WRONG
  // on-disk format (`string`/ASCII, not `undef`). The bespoke `RawConv`
  // (Exif.pm:3079) byte-walks `$val` REGARDLESS of `Format`, so the dispatch
  // reads the bytes via `RawValue::val_bytes()` (A2) — for a `string` value
  // that is the pre-FixUTF8 original bytes (A1's `RawValue::Text.raw`). The
  // 8-byte ASCII `"ABCDEFGH"` decodes as ONE rational64u 0x41424344/0x45464748
  // ≈ 0.9420: `-j` → `0.9` (PrintExposureTime `%.1f`, a BARE number), `-n` →
  // `0.9420322801` (the RawConv token). Pre-fix this `RawValue::Text` shape
  // fell to `emit_raw` (the raw string "ABCDEFGH") — the #198 deferral, now
  // closed. Verified byte-identical to bundled `perl exiftool 13.59`.
  check(
    "Exif_composite_exposure_wrongfmt.tif",
    "Exif_composite_exposure_wrongfmt.tif.json",
    true,
  );
  check(
    "Exif_composite_exposure_wrongfmt.tif",
    "Exif_composite_exposure_wrongfmt.tif.n.json",
    false,
  );
}
#[test]
fn exif_composite_exposure_wrongfmt_highbit_conformance() {
  // #198 R4 — the LOSSY-BYTES case proving A1/A2 retain `$val`'s ORIGINAL
  // bytes. A `string`-typed 0xa462 with INVALID-UTF-8 high-bit bytes
  // (`\x80..\x87`): the byte-walk must see the original bytes, NOT the lossy
  // FixUTF8 display text (where each high byte → U+FFFD, corrupting the
  // rational decode). The 8 bytes decode as ONE rational64u
  // 0x80818283/0x84858687 ≈ 0.9697: `-j` → `1` (PrintExposureTime `%.1f` =
  // "1.0", `s/\.0$//`), `-n` → `0.9696978699`. Bundled `perl exiftool 13.59`
  // byte-walks the same original bytes (this is the oracle of record); a
  // pre-A1 lossy re-encode would have diverged. Verified byte-identical.
  check(
    "Exif_composite_exposure_wrongfmt_highbit.tif",
    "Exif_composite_exposure_wrongfmt_highbit.tif.json",
    true,
  );
  check(
    "Exif_composite_exposure_wrongfmt_highbit.tif",
    "Exif_composite_exposure_wrongfmt_highbit.tif.n.json",
    false,
  );
}
#[test]
fn exif_composite_exposure_single_conformance() {
  // Codex R3 — `CompositeImageExposureTimes` (0xa462) decoding to EXACTLY ONE
  // element, pinning the single-element JSON TYPE per ExifTool. The lone token
  // IS the whole `$val`, so `EscapeJSON` (exiftool:3809) number-gates it: a
  // numeric token (`single_number` 1/2 → `0.5`; `single_fraction` `-n` token
  // `0.004`) is a BARE JSON NUMBER, while a non-numeric token (`single_undef`
  // 0/0 → `undef`; `single_fraction` `-j` PrintExposureTime `1/250`) stays a
  // quoted STRING. Pre-R3 the conv space-`join`-ed the single token through
  // `write_str`, emitting a one-element numeric result as a JSON STRING — a
  // type error the value-semantic harness MASKS; the targeted JSON-type
  // assertion below (`exif_composite_exposure_single_number_is_json_number`)
  // catches it. All values verified byte-identical to bundled `exiftool 13.59`.
  for (fixture, golden, print_on) in [
    (
      "Exif_composite_exposure_single_number.tif",
      "Exif_composite_exposure_single_number.tif.json",
      true,
    ),
    (
      "Exif_composite_exposure_single_number.tif",
      "Exif_composite_exposure_single_number.tif.n.json",
      false,
    ),
    (
      "Exif_composite_exposure_single_undef.tif",
      "Exif_composite_exposure_single_undef.tif.json",
      true,
    ),
    (
      "Exif_composite_exposure_single_undef.tif",
      "Exif_composite_exposure_single_undef.tif.n.json",
      false,
    ),
    (
      "Exif_composite_exposure_single_fraction.tif",
      "Exif_composite_exposure_single_fraction.tif.json",
      true,
    ),
    (
      "Exif_composite_exposure_single_fraction.tif",
      "Exif_composite_exposure_single_fraction.tif.n.json",
      false,
    ),
  ] {
    check(fixture, golden, print_on);
  }
}
#[test]
fn exif_composite_exposure_single_number_is_json_number() {
  // Codex R3 type-masking guard — the §4 conformance `check` uses the
  // value-semantic `json_equivalent`, which treats `"0.5" == 0.5` (string vs
  // number) as equal, so it CANNOT catch a `CompositeImageExposureTimes`
  // single-element result emitted as a quoted JSON string instead of a bare
  // number (the R3 finding). Assert the JSON TYPE directly: parse exifast's
  // `-j` AND `-n` output and require the field be a serde_json NUMBER (not a
  // String) for the single-NUMERIC-element shapes. Targeted to this tag — the
  // global harness semantics are unchanged.
  for fixture in [
    // correctly-`undef`-typed one-rational blob 1/2 → 0.5 (both modes) — the
    // real-camera path. (The wrong-format ASCII blob fixture was removed; its
    // faithful decode is deferred to issue #198.)
    "Exif_composite_exposure_single_number.tif",
  ] {
    let root = env!("CARGO_MANIFEST_DIR");
    let data = std::fs::read(format!("{root}/tests/fixtures/{fixture}"))
      .unwrap_or_else(|e| panic!("read fixture {fixture}: {e}"));
    for print_on in [true, false] {
      let json = extract_info(fixture, &data, print_on);
      let v: serde_json::Value = serde_json::from_str(&json)
        .unwrap_or_else(|e| panic!("{fixture} ({print_on}): invalid JSON: {e}"));
      let field = v.as_array().unwrap()[0]
        .as_object()
        .unwrap()
        .get("ExifIFD:CompositeImageExposureTimes")
        .unwrap_or_else(|| panic!("{fixture} ({print_on}): missing CompositeImageExposureTimes"));
      assert!(
        field.is_number(),
        "{fixture} (print_conv={print_on}): CompositeImageExposureTimes must be a \
         JSON NUMBER (bundled exiftool emits a bare number), got {field:?} \
         (a quoted string here = the R3 type regression the value-semantic \
         conformance check masks)"
      );
    }
  }
  // The complementary NON-numeric single-element shape stays a STRING: a single
  // `undef` (0/0) and a `-j` `1/250` fraction MUST remain quoted. Asserting
  // BOTH directions guards against an over-broad fix that numbers everything.
  for (fixture, print_on) in [
    ("Exif_composite_exposure_single_undef.tif", true),
    ("Exif_composite_exposure_single_undef.tif", false),
    ("Exif_composite_exposure_single_fraction.tif", true),
  ] {
    let root = env!("CARGO_MANIFEST_DIR");
    let data = std::fs::read(format!("{root}/tests/fixtures/{fixture}"))
      .unwrap_or_else(|e| panic!("read fixture {fixture}: {e}"));
    let json = extract_info(fixture, &data, print_on);
    let v: serde_json::Value = serde_json::from_str(&json)
      .unwrap_or_else(|e| panic!("{fixture} ({print_on}): invalid JSON: {e}"));
    let field = v.as_array().unwrap()[0]
      .as_object()
      .unwrap()
      .get("ExifIFD:CompositeImageExposureTimes")
      .unwrap_or_else(|| panic!("{fixture} ({print_on}): missing CompositeImageExposureTimes"));
    assert!(
      field.is_string(),
      "{fixture} (print_conv={print_on}): a single NON-numeric token \
       (undef / a `1/N` PrintExposureTime fraction) must stay a quoted JSON \
       STRING, got {field:?}"
    );
  }
}
#[test]
fn exif_ambient_wrongfmt_conformance() {
  // Codex R2 class-sweep — `AmbientTemperature` (0x9400) `Conv::CelsiusSuffix`
  // written with the WRONG on-disk format (`undef`, not `rational64s`). Like
  // the 0xa462 RawConv, `PrintConv => '"$val C"'` (Exif.pm:2590) is NOT
  // format-gated: it interpolates whatever post-`ReadValue` scalar STRING it
  // got. For an `undef`-typed value `ReadValue` returns the raw byte string
  // VERBATIM (no NUL-trim — only `string` trims, ExifTool.pm:6312), so the
  // 4-byte `b"-5.5"` → `$val` = `"-5.5"`: `-j` → `"-5.5 C"` (quoted), `-n` →
  // `-5.5` (a bare JSON number via the EscapeJSON gate). This `undef`/`Bytes`
  // shape is the one `value_space_joined` does NOT render; pre-fix the conv fell
  // to the binary `write_bytes` path instead of `"-5.5 C"`. Verified
  // byte-identical to bundled `perl exiftool` 13.59.
  check(
    "Exif_ambient_wrongfmt.tif",
    "Exif_ambient_wrongfmt.tif.json",
    true,
  );
  check(
    "Exif_ambient_wrongfmt.tif",
    "Exif_ambient_wrongfmt.tif.n.json",
    false,
  );
}
#[test]
fn exif_componentsconfig_wrongfmt_conformance() {
  // #201 — `ComponentsConfiguration` (0x9101) `Conv::ComponentsConfiguration`
  // written with the WRONG on-disk format. Unlike the 0xa462/0x9400 `$val`
  // byte-walks, 0x9101 carries a `Format => 'int8u'` READ override
  // (`Exif.pm:2298`, `tables::format_override`): ExifTool re-reads the on-disk
  // value as `int(size/1)` int8u ELEMENTS regardless of the declared format
  // code, so the per-byte PrintConv (`Exif.pm:2304-2333`) sees the raw value
  // bytes one-per-element.
  //
  // `wrongfmt` = `int16u[2]` `0x0102 0x0300` (on-disk bytes `01 02 03 00`): the
  // int8u re-read yields elements `1 2 3 0` → `-j` "Y, Cb, Cr, -" (NOT the
  // int16u decode "258 768"), `-n` "1 2 3 0". This is the discriminating shape —
  // a `RawValue::val_bytes()` byte-walk would emit the space-joined int16u `$val`
  // ("258 768"), so ONLY re-reading the raw on-disk bytes as int8u matches.
  //
  // `wrongfmt_err` = `int8u[4]` `7 99 0 1` (codes 7/99 not in the 0..6 hash):
  // pins the `OTHER` sub's `$$conv{$_} || "Err ($_)"` fall-through
  // (`Exif.pm:2330`) → `-j` "Err (7), Err (99), -, Y" (NOT "?"), `-n` "7 99 0 1".
  //
  // Pre-fix exifast decoded 0x9101 per its on-disk format and the
  // `RawValue::Bytes`-only conv arm fell through to `emit_raw` (the int16u
  // "258 768" / the int8u space-join). Both verified byte-identical to bundled
  // `perl exiftool` 13.59.
  //
  // #201 R2 — the SINGLETON / short shapes the four-byte `wrongfmt`/`wrongfmt_err`
  // values do NOT exercise. Under `-n` ExifTool emits the post-`ReadValue` raw
  // SCALAR: a one-element 0x9101 (`int(size/1)==1`) is a BARE JSON number (the
  // EscapeJSON number gate), while a COUNT>1 value space-joins to a quoted string.
  // The pre-R2 `-n` arm unconditionally joined + `write_str`, so a singleton
  // emitted the STRING "1" rather than the bare number `1`.
  //   * `singleton` = `int8u[1]` code `1` → `-j` "Y", `-n` `1` (bare number, NOT
  //     "1"). The discriminating shape for this fix.
  //   * `pair` = `int8u[2]` codes `1 2` → `-j` "Y, Cb", `-n` "1 2" (the
  //     count==2 boundary — still the space-joined quoted string).
  // Both verified byte-identical to bundled `perl exiftool` 13.59.
  check(
    "Exif_componentsconfig_wrongfmt.tif",
    "Exif_componentsconfig_wrongfmt.tif.json",
    true,
  );
  check(
    "Exif_componentsconfig_wrongfmt.tif",
    "Exif_componentsconfig_wrongfmt.tif.n.json",
    false,
  );
  check(
    "Exif_componentsconfig_wrongfmt_err.tif",
    "Exif_componentsconfig_wrongfmt_err.tif.json",
    true,
  );
  check(
    "Exif_componentsconfig_wrongfmt_err.tif",
    "Exif_componentsconfig_wrongfmt_err.tif.n.json",
    false,
  );
  check(
    "Exif_componentsconfig_singleton.tif",
    "Exif_componentsconfig_singleton.tif.json",
    true,
  );
  check(
    "Exif_componentsconfig_singleton.tif",
    "Exif_componentsconfig_singleton.tif.n.json",
    false,
  );
  check(
    "Exif_componentsconfig_pair.tif",
    "Exif_componentsconfig_pair.tif.json",
    true,
  );
  check(
    "Exif_componentsconfig_pair.tif",
    "Exif_componentsconfig_pair.tif.n.json",
    false,
  );
}
#[test]
fn exif_gps_versionid_undef_conformance() {
  // #399 item 1 — `GPSVersionID` (0x0000) written with the WRONG on-disk format
  // (`undef[4]`, not the spec `int8u[4]`). GPSVersionID has `Writable => 'int8u'`
  // and `PrintConv => '$val =~ tr/ /./; $val'` (GPS.pm:59-62) but NO `Format =>`
  // directive, so ExifTool reads it with the on-disk format — it does NOT re-read
  // an `undef` value as int8u. For `undef[4]` `02 03 00 00`, `ReadValue` returns
  // the raw 4 bytes, the PrintConv `tr/ /./` is a no-op (no space bytes), and the
  // JSON writer's `EscapeJSON` `tr/\0//d` (exiftool:3819) strips the trailing NULs
  // before `\u`-escaping the survivors — `-j` and `-n` BOTH emit "\u0002\u0003"
  // (the 2 non-NUL bytes), NOT the dotted "2.3.0.0" (that form is only for the
  // correct int8u/int8s on-disk shape). Pre-fix the `GpsConv::VersionId` arm
  // rendered only `RawValue::U64`; an `undef` value fell to `emit_raw` → the
  // binary `write_bytes` placeholder. Verified byte-identical to bundled
  // `perl exiftool` 13.59.
  check(
    "Exif_gps_versionid_undef.tif",
    "Exif_gps_versionid_undef.tif.json",
    true,
  );
  check(
    "Exif_gps_versionid_undef.tif",
    "Exif_gps_versionid_undef.tif.n.json",
    false,
  );
}
#[test]
fn exif_filesource_sigma_conformance() {
  // #399 item 2 — `FileSource` (0xa300) carrying the literal Sigma 4-byte value
  // `\x03\x00\x00\x00`. FileSource is `Writable => 'undef'` with a HASH PrintConv
  // whose keys are the integer codes 1/2/3 PLUS the literal 4-byte string
  // `"\3\0\0\0" => 'Sigma Digital Camera'` (Exif.pm:2820, "handle the case where
  // Sigma incorrectly gives this tag a count of 4"). A normal single byte `\x03`
  // takes the `undef[1] → int8u` carve-out (Exif.pm:6682) and matches the integer
  // key 3 → "Digital Camera"; only the 4-byte form matches the string key:
  //   -j → "Sigma Digital Camera"
  //   -n → "\u0003"   (the raw bytes 03 00 00 00, EscapeJSON `tr/\0//d`-stripped)
  // Pre-fix exifast's `Conv::IntLabel` handled only the single-byte int8u code;
  // the 4-byte `RawValue::Bytes` fell to `emit_raw` → the binary `write_bytes`
  // placeholder. The new `Conv::FileSource` matches the literal key (and falls to
  // `Unknown ($val)` over the raw byte string for any other multi-byte `undef`,
  // exactly as a HASH-PrintConv miss does). Verified byte-identical to bundled
  // `perl exiftool` 13.59.
  check(
    "Exif_filesource_sigma.tif",
    "Exif_filesource_sigma.tif.json",
    true,
  );
  check(
    "Exif_filesource_sigma.tif",
    "Exif_filesource_sigma.tif.n.json",
    false,
  );
}
#[test]
fn exif_gps_versionid_nulsplit_conformance() {
  // #399 (Codex [medium]) — the EscapeJSON ORDER for the raw-byte render path.
  // `GPSVersionID` (0x0000) as `undef[4]` `C2 00 A9 00` — a NUL byte SPLITS a
  // valid 2-byte UTF-8 sequence (`C2 A9` = `©`). ExifTool's `EscapeJSON` deletes
  // NULs FIRST (`tr/\0//d`, exiftool:3820) THEN runs `FixUTF8` (exiftool:3824),
  // so the survivors `C2 A9` reassemble into a single `©` for BOTH `-j` and `-n`.
  // The pre-fix `GpsConv::VersionId` arm ran `fix_utf8` on the raw bytes BEFORE
  // the serializer's `tr/\0//d`, validating `C2` and `A9` separately (the NUL
  // between them broke the sequence) → two `?`s → "??" after the late NUL-strip.
  // The fix routes the bytes through `convert::escape_json_raw_bytes`
  // (NUL-strip → FixUTF8), matching bundled `perl exiftool` 13.59 (`©`).
  check(
    "Exif_gps_versionid_nulsplit.tif",
    "Exif_gps_versionid_nulsplit.tif.json",
    true,
  );
  check(
    "Exif_gps_versionid_nulsplit.tif",
    "Exif_gps_versionid_nulsplit.tif.n.json",
    false,
  );
}
#[test]
fn exif_filesource_nulsplit_conformance() {
  // #399 (Codex [medium]) — the same EscapeJSON ORDER fix on the non-Sigma
  // multi-byte `FileSource` HASH-miss path. `FileSource` (0xa300) as `undef[4]`
  // `C2 00 A9 00` is NOT the Sigma literal key, so it is a HASH miss →
  // `Unknown ($val)` (printconv) / the bare `$val` (`-n`), where `$val` is the
  // raw byte string. ExifTool's `EscapeJSON` deletes the NULs FIRST then runs
  // `FixUTF8`, so the NUL-split `C2 A9` reassembles into `©`:
  //   -j → "Unknown (©)"   -n → "©"
  // (The `Unknown (` / `)` literals carry no NULs and are ASCII, so wrapping the
  // escaped value is byte-identical to ExifTool wrapping then escaping.) Verified
  // byte-identical to bundled `perl exiftool` 13.59.
  check(
    "Exif_filesource_nulsplit.tif",
    "Exif_filesource_nulsplit.tif.json",
    true,
  );
  check(
    "Exif_filesource_nulsplit.tif",
    "Exif_filesource_nulsplit.tif.n.json",
    false,
  );
}
#[test]
fn exif_gps_versionid_nulnum_conformance() {
  // #399 (Codex [medium]) — the EscapeJSON ORDER for a NUL-SPLIT NUMERIC raw-byte
  // value. `GPSVersionID` (0x0000) as `undef[4]` `31 00 32 00` (`"1\02\0"`): the
  // `tr/\0//d` NUL deletion PRODUCES the number-shaped lexeme `12`. ExifTool
  // classifies the ORIGINAL `$val` (WITH NULs) against the number gate BEFORE the
  // NUL strip (exiftool:3810), so the NUL-bearing original FAILS the gate and the
  // value is a QUOTED string `"12"` — NOT a bare `12` — for BOTH `-j` and `-n`.
  // The pre-fix path NUL-stripped FIRST and handed `"12"` to the serializer's own
  // number gate, which (wrongly) emitted a BARE number. The fix
  // (`escape_json_raw_bytes_classified` → `TagValue::JsonStr`) classifies the
  // original first, matching bundled `perl exiftool` 13.59 (quoted `"12"`). The
  // golden's STRING type (not number) is what the type-strict comparator pins.
  check(
    "Exif_gps_versionid_nulnum.tif",
    "Exif_gps_versionid_nulnum.tif.json",
    true,
  );
  check(
    "Exif_gps_versionid_nulnum.tif",
    "Exif_gps_versionid_nulnum.tif.n.json",
    false,
  );
}
#[test]
fn exif_gps_versionid_nulbool_conformance() {
  // #399 (Codex [medium]) — the same EscapeJSON ORDER for a NUL-SPLIT BOOLEAN.
  // `GPSVersionID` (0x0000) as `undef[8]` `74 00 72 00 75 00 65 00`
  // (`"t\0r\0u\0e\0"`): the NUL deletion PRODUCES the boolean word `true`.
  // ExifTool's `/^(true|false)$/i` boolean coercion (exiftool:3805) runs on the
  // ORIGINAL `$val` (WITH NULs) BEFORE the NUL strip, so the NUL-bearing original
  // does NOT match → the value is a QUOTED string `"true"`, NOT a bare JSON
  // boolean `true`, for BOTH `-j` and `-n`. Pins that the fix gates the boolean
  // coercion on the original too (the `TagValue::JsonStr` forced-string path).
  // Byte-identical to bundled `perl exiftool` 13.59.
  check(
    "Exif_gps_versionid_nulbool.tif",
    "Exif_gps_versionid_nulbool.tif.json",
    true,
  );
  check(
    "Exif_gps_versionid_nulbool.tif",
    "Exif_gps_versionid_nulbool.tif.n.json",
    false,
  );
}
#[test]
fn exif_filesource_nulnum_conformance() {
  // #399 (Codex [medium]) — the EscapeJSON ORDER on the `FileSource` HASH-miss
  // `-n` path for a NUL-SPLIT NUMERIC value. `FileSource` (0xa300) as `undef[4]`
  // `31 00 32 00` is a HASH miss → `Unknown ($val)` (printconv) / the bare `$val`
  // (`-n`). The `tr/\0//d` produces `12`; the NUL-bearing original fails the
  // number gate, so `-n` is a QUOTED string `"12"` (NOT a bare `12`). The `-j`
  // `Unknown (12)` is quoted regardless (the parens defeat the gate), but it is
  // included to pin both render modes. Byte-identical to bundled 13.59.
  check(
    "Exif_filesource_nulnum.tif",
    "Exif_filesource_nulnum.tif.json",
    true,
  );
  check(
    "Exif_filesource_nulnum.tif",
    "Exif_filesource_nulnum.tif.n.json",
    false,
  );
}
#[test]
fn exif_gps_after_interop_conformance() {
  // PR #36 Codex R12 F2 — the Windows Phone 7.5 InteropIFD/GPS pointer
  // collision. IFD0's GPSInfo (0x8825) and ExifIFD's InteropOffset
  // (0xa005) BOTH point at one shared sub-IFD. ExifTool's `%PROCESSED`
  // reprocess guard (ExifTool.pm:9050-9061) warns + aborts on a duplicate
  // directory address, EXCEPT for the GPS-after-InteropIFD case
  // (ExifTool.pm:9059). Critically the whole guard block is gated on
  // `$$dirInfo{DirLen}` being non-zero (ExifTool.pm:9052); IFD-pointer
  // SubDirectories (ExifIFD/GPS/InteropIFD via `Start => '$val'`) carry
  // `DirLen => 0`, so the guard NEVER fires for them — ExifTool silently
  // reprocesses the shared offset and emits BOTH tag sets.
  //
  // The R12/F2 bug: the exifast walker rejected ANY previously seen IFD
  // offset, so the GPS pass returned `None` and ALL GPS tags were silently
  // dropped. The fix tracks each seen offset WITH its owning `IfdKind` and
  // allows the GPS-after-InteropIFD reprocess (and only that case), with no
  // warning — faithful to the `DirLen == 0` directories the walker handles.
  //
  // The shared directory carries only GPS tag IDs absent from the tiny
  // `%InteropIFD` table — GPSVersionID (0x0000), GPSSatellites (0x0008),
  // GPSMapDatum (0x0012) — so the InteropIFD pass resolves NO leaf tags and
  // only the GPS pass emits, keeping the golden free of InteropIFD-PrintConv
  // and Composite-GPS divergences (separate ExifTool layers). Bundled
  // `perl exiftool` emits `GPS:GPSVersionID` / `GPS:GPSSatellites` /
  // `GPS:GPSMapDatum` — the regression guard for the dropped GPS reprocess.
  // Verified against bundled `perl exiftool` 2026-05-22.
  check(
    "Exif_gps_after_interop.tif",
    "Exif_gps_after_interop.tif.json",
    true,
  );
  check(
    "Exif_gps_after_interop.tif",
    "Exif_gps_after_interop.tif.n.json",
    false,
  );
}
#[test]
fn exif_gps_baddir_conformance() {
  // PR #36 Codex R2 F2 — IFD0 with a GPSInfo pointer to an offset PAST
  // end-of-file: the GPS IFD's 2-byte entry count cannot even be read.
  // ExifTool's RAF `Seek`/`Read` fails (`$success = 0`) ⇒ `Bad GPS
  // directory` (Exif.pm:6342-6381). IFD0 parses normally
  // (`IFD0:Orientation` emitted). Verified against bundled `perl
  // exiftool` 2026-05-22.
  check("Exif_gps_baddir.tif", "Exif_gps_baddir.tif.json", true);
  check("Exif_gps_baddir.tif", "Exif_gps_baddir.tif.n.json", false);
}
#[test]
fn exif_gps_badoffset_conformance() {
  // PR #36 Codex R2 F3 — a GPS sub-IFD with a GPSLatitude (0x0002) whose
  // out-of-line offset (4) points into the 8-byte TIFF header. ExifTool
  // warns `Suspicious GPS offset for GPSLatitude` — the tag NAME must
  // resolve against the GPS table (`%GPS::Main`), NOT the Interop table
  // (`%Interop::Main`), where 0x0002 is `InteropVersion`. Pins the
  // table-overlap fix. Verified against bundled `perl exiftool`
  // 2026-05-22.
  check(
    "Exif_gps_badoffset.tif",
    "Exif_gps_badoffset.tif.json",
    true,
  );
  check(
    "Exif_gps_badoffset.tif",
    "Exif_gps_badoffset.tif.n.json",
    false,
  );
}
#[test]
fn exif_gps_datestamp_conformance() {
  // PR #36 Codex R7 F1 — a GPS sub-IFD GPSDateStamp (0x001d) whose ON-DISK
  // format code is `string` (2) but whose bytes use `\0` separators
  // (`2024\0 05\0 22\0`, the Casio EX-H20G variant, GPS.pm:312). The GPS
  // table sets `Format => 'undef'` (GPS.pm:312), a READ-side override applied
  // BEFORE `ReadValue` (Exif.pm:6729-6744): it forces the value through
  // `undef` so the interior NULs survive, then the RawConv `$val=~s/\0+$//`
  // (GPS.pm:319) drops only the trailing run and `ExifDate` (GPS.pm:320)
  // re-separates the 8 digits ⇒ `GPS:GPSDateStamp` = "2024:05:22" (a
  // ValueConv ⇒ same in both -j and -n). Without the override the `string`
  // decode NUL-trims at the FIRST NUL to "2024", collapsing to just the year.
  // The R6 fix gated the `Format` override off for ALL GPS entries; R7
  // resolves it per-table instead (`gps::format_override(0x001d)` →
  // `Format::Undef`), keeping the GPS text tags 0x001b/0x001c (only
  // `Writable => 'undef'`, no `Format`) NUL-trimmed as bundled does.
  // Verified against bundled `perl exiftool` 2026-05-22.
  check(
    "Exif_gps_datestamp.tif",
    "Exif_gps_datestamp.tif.json",
    true,
  );
  check(
    "Exif_gps_datestamp.tif",
    "Exif_gps_datestamp.tif.n.json",
    false,
  );
}
#[test]
fn exif_gps_eofoverrun_conformance() {
  // PR #36 Codex R2 F3 — a GPS sub-IFD with a GPSLatitude (0x0002) whose
  // out-of-line `offset + size` runs past EOF. ExifTool warns `Error
  // reading value for GPS entry 1, ID 0x0002 GPSLatitude` — again the
  // tag name resolves against the GPS table (0x0002 = GPSLatitude, not
  // InteropVersion). Verified against bundled `perl exiftool`
  // 2026-05-22.
  check(
    "Exif_gps_eofoverrun.tif",
    "Exif_gps_eofoverrun.tif.json",
    true,
  );
  check(
    "Exif_gps_eofoverrun.tif",
    "Exif_gps_eofoverrun.tif.n.json",
    false,
  );
}
#[test]
fn exif_gps_int32s_conformance() {
  // PR #36 Codex R9 F1 — an IFD0 GPSInfo pointer (0x8825) encoded as
  // `int32s` (format code 9, a SIGNED integer) with a POSITIVE offset.
  // `%intFormat` (Exif.pm:125-136) lists `int32s => 9`, so the signed
  // format passes the offset-integrality gate (Exif.pm:6747) WITHOUT a
  // `Wrong format` warning — unlike the R8 `string` case. ExifTool uses
  // `$val` as `Start => '$val'`; `IsInt` (ExifTool.pm:5943) accepts it and,
  // the value being non-negative, the `$subdirStart < 0` reject
  // (Exif.pm:7017) does not fire — the GPS sub-IFD IS walked. Bundled emits
  // `GPS:GPSVersionID` = "2.3.0.0".
  //
  // Without R9 F1's fix the port's SubIFD-pointer extraction took ONLY
  // `RawValue::U64`; an `int32s` decodes to `RawValue::I64`, the old
  // `first_u64()` returned `None`, and the GPS sub-IFD was SILENTLY dropped.
  // Pins the walk + the emitted GPSVersionID. Verified against bundled
  // `perl exiftool` 2026-05-22.
  check("Exif_gps_int32s.tif", "Exif_gps_int32s.tif.json", true);
  check("Exif_gps_int32s.tif", "Exif_gps_int32s.tif.n.json", false);
}
#[test]
fn exif_gps_proctext_conformance() {
  // PR #36 Codex R3 F2 — GPS sub-IFD with GPSProcessingMethod (0x001b) and
  // GPSAreaInformation (0x001c), both `undef`-format carrying the 8-byte
  // `ASCII\0\0\0` charset prefix. ExifTool's `ConvertExifText` RawConv
  // (Exif.pm:5554-5601, wired GPS.pm:299/305) strips the prefix and
  // decodes the payload — bundled emits `GPS:GPSProcessingMethod` = "GPS"
  // and `GPS:GPSAreaInformation` = "Tokyo", NOT a binary placeholder.
  // Verified against bundled `perl exiftool` 2026-05-22.
  check("Exif_gps_proctext.tif", "Exif_gps_proctext.tif.json", true);
  check(
    "Exif_gps_proctext.tif",
    "Exif_gps_proctext.tif.n.json",
    false,
  );
}
#[test]
fn exif_gps_proctext_wrongfmt_conformance() {
  // Golden-value Contract A (#198 byte-walk class, GPS sibling) — a GPS
  // sub-IFD with GPSProcessingMethod (0x001b) declared `string` (format code
  // 2) instead of `undef` (the documented mis-writer, Exif.pm:2499). UNLIKE
  // UserComment 0x9286 the GPS text tags have NO `Format => 'undef'` override
  // (`gps::format_override` is GPSDateStamp-only; GPS.pm:296/304 set only
  // `Writable => 'undef'`), so the value is decoded as a STRING and reaches
  // the `GpsConv::ExifText` `ConvertExifText` RawConv as `RawValue::Text`
  // (NOT `RawValue::Bytes`). That arm now reads the bytes via
  // `RawValue::val_bytes()` — the pre-FixUTF8 `raw` of the on-disk `$val`,
  // not the lossy FixUTF8 display text the old `text.as_bytes()` arm used —
  // mirroring the UserComment 0x9286 sibling in `Conv::ExifText`. The payload
  // is a VALID all-ASCII, NUL-free, space-padded `ASCII   ` prefix + "Manual"
  // (so the output is oracle-matchable and avoids the from_utf8_lossy-vs-
  // FixUTF8 charset gap #200, which is observable only on invalid UTF-8).
  // Bundled `exiftool 13.59` strips the 8-byte prefix ⇒ `GPS:
  // GPSProcessingMethod` = "Manual" in BOTH -j and -n.
  check(
    "Exif_gps_proctext_wrongfmt.tif",
    "Exif_gps_proctext_wrongfmt.tif.json",
    true,
  );
  check(
    "Exif_gps_proctext_wrongfmt.tif",
    "Exif_gps_proctext_wrongfmt.tif.n.json",
    false,
  );
}
#[test]
fn exif_gps_shared_pointer_conformance() {
  // PR #36 Codex R13 F1 — the GENERAL IFD-pointer collision. IFD0's
  // ExifOffset (0x8769) AND GPSInfo (0x8825) BOTH point at one shared
  // sub-IFD. ExifTool's `%PROCESSED` reprocess guard (ExifTool.pm:9050-
  // 9061) warns + aborts on a duplicate directory address — but the whole
  // guard block is GATED on `$$dirInfo{DirLen}` being non-zero
  // (ExifTool.pm:9052, comment "directories don't overlap if the length is
  // zero"). For a standalone TIFF — the shape every exifast `TIFF` fixture
  // uses and the shape the golden oracle runs ExifTool against — an
  // IFD-pointer SubDirectory's `DirLen` is forced to 0 at Exif.pm:7020-
  // 7026: the value-data buffer holds only the IFD being parsed, so the
  // out-of-buffer `$subdirStart` trips `$subdirStart + 2 > $subdirDataLen`
  // and ExifTool resets `$subdirDataPt`/`$size` to re-read the directory
  // from the file. With `DirLen 0` the guard is SKIPPED for EVERY
  // IFD-pointer subdirectory, so ExifTool reprocesses ANY shared offset —
  // the GPS-after-InteropIFD carve-out (ExifTool.pm:9059) is just one
  // instance of the general rule.
  //
  // The R13/F1 bug: the R12/F2 fix admitted ONLY a GPS-after-InteropIFD
  // revisit, so the GPS pass over the ExifIFD-owned shared offset returned
  // `None` and ALL GPS tags were silently dropped. The re-modelled guard
  // records only chain IFDs (IFD0/Trailing — non-zero `DirLen`, ExifTool's
  // `%PROCESSED` loop breaker) in the seen-offset set and reprocesses any
  // IFD-pointer subdirectory revisit, rejecting only a genuine ancestor
  // cycle (an offset still on the active recursion path).
  //
  // The shared directory carries Orientation (0x0112, an Exif-IFD tag) and
  // GPSVersionID (0x0000, a GPS tag): the ExifIFD pass emits
  // `ExifIFD:Orientation`, the GPS pass emits `GPS:GPSVersionID`, and the
  // cross-table tag in each pass is unknown there ⇒ dropped — no PrintConv/
  // Composite golden noise. Bundled `perl exiftool` emits `IFD0:Orientation`
  // + `ExifIFD:Orientation` + `GPS:GPSVersionID` with NO warning — the
  // regression guard for the dropped GPS reprocess. Verified against bundled
  // `perl exiftool` 2026-05-22.
  check(
    "Exif_gps_shared_pointer.tif",
    "Exif_gps_shared_pointer.tif.json",
    true,
  );
  check(
    "Exif_gps_shared_pointer.tif",
    "Exif_gps_shared_pointer.tif.n.json",
    false,
  );
}
#[test]
fn exif_gps_unicode_conformance() {
  // PR #36 Codex R4 F1 — a BIG-ENDIAN (MM) TIFF whose GPS sub-IFD carries
  // `UNICODE\0`-prefixed UTF-16 text written LITTLE-ENDIAN. ExifTool's
  // `ConvertExifText` (Exif.pm:5554-5601) calls `Decode($str,'UTF16',
  // 'Unknown')`, which seeds the byte-order guess from `GetByteOrder()` (MM)
  // then FLIPS to LE via the Charset.pm:213-234 distribution heuristic for
  // the no-BOM `GPSProcessingMethod`, and honours the LE BOM directly for
  // `GPSAreaInformation` (Charset.pm:203-206). Bundled emits
  // `GPS:GPSProcessingMethod` = "MANUAL" and `GPS:GPSAreaInformation` =
  // "Tokyo" — a big-endian-only UTF-16 reader would mojibake both.
  // Verified against bundled `perl exiftool` 2026-05-22.
  check("Exif_gps_unicode.tif", "Exif_gps_unicode.tif.json", true);
  check("Exif_gps_unicode.tif", "Exif_gps_unicode.tif.n.json", false);
}
#[test]
fn exif_gps_wrongfmt_conformance() {
  // PR #36 Codex R8 F1 — an IFD0 GPSInfo pointer (0x8825) mis-encoded as
  // `string` (format code 2) instead of an integer. GPSInfo carries `Flags =>
  // 'SubIFD'` (Exif.pm:2134), so the offset-integrality check fires:
  // `Wrong format (string) for IFD0 0x8825 GPSInfo` (Exif.pm:6747-6748) and
  // in default (non-verbose) mode the entry is `next`-skipped (Exif.pm:6753)
  // — the GPS sub-IFD is NOT walked (no GPS:* tags), while IFD0:Orientation
  // is still emitted. Pins the fix for the silently-swallowed pointer: a
  // would-be-valid GPS IFD sits at the offset the inline bytes encode, so a
  // regression that followed the pointer would leak GPS:GPSVersionID. The
  // warning fires identically in -j and -n. Verified against bundled
  // `perl exiftool` 2026-05-22.
  check("Exif_gps_wrongfmt.tif", "Exif_gps_wrongfmt.tif.json", true);
  check(
    "Exif_gps_wrongfmt.tif",
    "Exif_gps_wrongfmt.tif.n.json",
    false,
  );
}
#[test]
fn exif_ifd65536_conformance() {
  // PR #36 Codex R12 F1 — a multi-page TIFF whose next-IFD chain runs
  // 65537 IFDs deep: IFD0 -> IFD1 -> ... -> IFD65536. ExifTool numbers each
  // trailing IFD with plain Perl arithmetic `DirName .= $ifdNum + 1`
  // (Exif.pm:7215-7216) — there is NO cap, so the 65537th linked directory
  // is processed as IFD65536.
  //
  // The R12/F1 bug: `walk_ifd_chain` stored the trailing-IFD number in a
  // `u16` and advanced it with `saturating_add`, so past IFD65535 the
  // counter pinned at 65535 — IFD65536 was mislabeled `IFD65535`,
  // overwriting the real IFD65535 tags. The fix widens `IfdKind::Trailing`
  // to `u32` with an unsaturating `+ 1` and renders `IFDn` from that wider
  // type into a 13-byte `IfdName` buffer.
  //
  // The fixture keeps the golden small: only IFD0 and the tail
  // (IFD65534/65535/65536) carry leaf tags; every interior IFD is a valid
  // zero-entry directory that still advances the chain. Bundled
  // `perl exiftool` emits DISTINCT `IFD65535:Software` = "exifast IFD65535"
  // and `IFD65536:Software` = "exifast IFD65536" — the regression guard for
  // the mislabeled / clobbered trailing IFD. Verified against bundled
  // `perl exiftool` 2026-05-22.
  check("Exif_ifd65536.tif", "Exif_ifd65536.tif.json", true);
  check("Exif_ifd65536.tif", "Exif_ifd65536.tif.n.json", false);
}
#[test]
fn exif_illegal_ifd0_size_conformance() {
  // PR #36 Codex R2 F2 — IFD0 whose declared extent leaves only ONE byte
  // after `$dirEnd`. ExifTool reads the IFD body from the file via RAF
  // (the 2-byte count, then `Read($buf2, 12*n+4)` capped at EOF), so
  // `$bytesFromEnd` is `min(file-bytes-after-$dirEnd, 4)` — here 1.
  // `$bytesFromEnd < 4` and not 0/2 ⇒ `Illegal IFD0 directory size (1
  // entries)` + abort (Exif.pm:6394-6399). NO tags. Verified against
  // bundled `perl exiftool` 2026-05-22.
  check(
    "Exif_illegal_ifd0_size.tif",
    "Exif_illegal_ifd0_size.tif.json",
    true,
  );
  check(
    "Exif_illegal_ifd0_size.tif",
    "Exif_illegal_ifd0_size.tif.n.json",
    false,
  );
}
#[test]
fn exif_illegal_subifd_size_conformance() {
  // PR #36 Codex R2 F2 — the same `$bytesFromEnd` check (Exif.pm:6394-
  // 6399) reached via a sub-IFD: IFD0 carries a GPSInfo pointer to a GPS
  // IFD whose declared extent leaves 3 bytes after `$dirEnd`. ExifTool
  // warns `Illegal GPS directory size (1 entries)` and aborts the GPS
  // directory; IFD0 itself parses normally (`IFD0:Make` emitted).
  // Verified against bundled `perl exiftool` 2026-05-22.
  check(
    "Exif_illegal_subifd_size.tif",
    "Exif_illegal_subifd_size.tif.json",
    true,
  );
  check(
    "Exif_illegal_subifd_size.tif",
    "Exif_illegal_subifd_size.tif.n.json",
    false,
  );
}
#[test]
#[ignore = "MakerNotes wave not yet landed: 0x927c MakerNote subdirectory tags (MakerNotes:*) are produced only once the MakerNotes port merges; remove #[ignore] then (FORMATS.md row 13 forward item)"]
fn exif_makernote_subdirectory_deferred_conformance() {
  // FORMATS.md row 13 forward item — when this is un-`#[ignore]`d the
  // MakerNotes wave will have landed and bundled's MakerNotes:* tags will
  // be produced. The fixture `Exif_makernote.tif` is a synthetic TIFF whose
  // ExifIFD carries a 0x927c MakerNote tag.
  check("Exif_makernote.tif", "Exif_makernote.tif.json", true);
  check("Exif_makernote.tif", "Exif_makernote.tif.n.json", false);
}
#[test]
fn makernotes_nikon_d2hs_conformance() {
  // NikonD2Hs.jpg — the riskiest Nikon production path AND the first IFD-
  // MakerNote conformance backstop: the ~66 `Nikon:*` tags (incl. encrypted
  // LensData0201, the serial-3001006 decrypt-key prescan, ShotInfo 0206,
  // FlashInfo 0100) are emitted byte-identically to bundled ExifTool 13.59.
  //
  // The goldens are generated with `gen_golden.sh EXCLUDE="…"` dropping the
  // tags exifast intentionally does NOT emit — every exclusion is a PRE-
  // EXISTING, documented, NON-Nikon-MakerNote-path deferral (not a regression
  // in the migrated Nikon path), so excluding them does not mask any Nikon
  // faithfulness gap:
  //   -x Composite:all     — exifast has no EXIF Composite subsystem.
  //   -x PreviewIFD:all    — Nikon SubIFD 0x0011 PreviewIFD is OtherDeferred.
  //   -x IFD1:ThumbnailImage — the embedded-thumbnail binary placeholder (same
  //                          documented engine-wide gap).
  // The JPEG SOF-segment `File:*` dimension tags (`File:ImageWidth`/
  // `ImageHeight`/`EncodingProcess`/`BitsPerSample`/`ColorComponents`/
  // `YCbCrSubSampling`) are NOW EMITTED (#261) and are part of this golden —
  // this file's `8x8 / Baseline DCT, Huffman coding / 8 / 3 / YCbCr4:2:0 (2 2)`
  // SOF0 is byte-identical to bundled.
  //   -x ExifIFD:CFAPattern  — a standard EXIF tag (0xa302) not in exifast's
  //                          EXIF table; unrelated to MakerNotes.
  //
  // `Nikon:WB_RGGBLevels` is NO LONGER excluded — this file's ColorBalance is
  // the ENCRYPTED `02xx` (ColorBalance02, version `0206`) variant, now PORTED
  // (`emit_color_balance` decrypts the block with the serial-3001006 /
  // ShutterCount keystream and reads `WB_RGGBLevels` = 562 256 256 537 at
  // `DecryptStart 284 + DirOffset 6`, #256). All 66 Nikon tags are now
  // byte-identical to bundled ExifTool.
  check("NikonD2Hs.jpg", "NikonD2Hs.jpg.json", true);
  check("NikonD2Hs.jpg", "NikonD2Hs.jpg.n.json", false);
}
#[test]
fn makernotes_pentax_k10d_conformance() {
  // Pentax.jpg (K10D) — the Pentax-MakerNote conformance backstop (#262, #173).
  // The 141 ported `Pentax:*` tags emit byte-identically to bundled ExifTool
  // 13.59: the
  // Phase-1 camera-indexing leaves + the `0x003f LensRec` → `LensType`
  // SubDirectory child (`LensType` = "Sigma or Tamron Lens (3 44)",
  // `PentaxModelID` = "K10D", `Quality` = "Better", `FNumber` = 13.0, the
  // %pentaxCities world-time pair, the dotted PentaxVersion "3.0.0.0", the
  // LV-converted metering segments, the WB_RGGBLevels run), PLUS the Phase-2a
  // binary SubDirectory tables — `CameraSettings` 0x0205 (`$count < 25` K10D
  // variant: PictureMode2 "Aperture Priority", the bitfields, the K10D-only
  // offset-13+ leaves RawAndJpgRecording/SRActive/Rotation/TvExposureTimeSetting/
  // AvApertureSetting/BaseExposureCompensation, …), `AEInfo` 0x0206 (`$count <= 25
  // and != 21`: AEExposureTime "1/101", AEAperture 12.9, the exp/log apertures),
  // and `FlashInfo` 0x0208 (`$count == 27`: FlashStatus "Off", InternalFlashMode
  // "Did not fire, Wireless (Master)", the TTL_DA quad).
  //
  // #173 adds the remaining `%Pentax::Main` long-tail: the model-/count-/format-
  // conditional + array-PrintConv Main leaves (FlashMode 0x000c, FocusMode 0x000d,
  // AFPointSelected 0x000e, ExposureCompensation 0x0016, AutoBracketing 0x0018,
  // FocalLength 0x001d, EffectiveLV 0x002d, ImageEditing 0x0032, PictureMode
  // 0x0033, DriveMode 0x0034, FlashExposureComp 0x004d, RawDevelopmentProcess
  // 0x0062), the XOR-decrypted ShutterCount 0x005d (`CryptShutterCount` with the
  // Date/Time DataMembers), the four binary SubDirectory tables ShakeReductionInfo
  // 0x005c (SRInfo) / BatteryInfo 0x0216 / AFInfo 0x021f / ColorInfo 0x0222, and
  // the four extra `%Pentax::LensData` leaves (AutoAperture, MinAperture,
  // FocusRangeIndex, MaxAperture) inside the already-ported LensInfo2 0x0207.
  //
  // The goldens are generated with `gen_golden.sh EXCLUDE="…"` dropping only the
  // tags exifast does NOT emit: the `IsOffset => 2` PreviewImageStart 0x0004 +
  // its DataTag PreviewImage (which need the maker-note original-base offset-
  // rebase + binary-extraction subsystem, not yet ported) — OR a documented
  // engine-wide deferral (Composite:all — no EXIF Composite subsystem;
  // IFD1:ThumbnailImage + PrintIM:PrintIMVersion — the same gaps the Nikon golden
  // excludes). None masks a faithfulness gap in the ported subset. The JPEG SOF
  // `File:*` dimension tags
  // (#261/#263) ARE part of this golden. The APP0 JFIF tags (`JFIF:JFIFVersion`/
  // `ResolutionUnit`/`X`/`YResolution`) are NOW EMITTED (the #114 JFIF port,
  // `src/exif/jpeg_app.rs`) — no longer excluded; the golden carries them
  // (regenerated to match).
  check("Pentax.jpg", "Pentax.jpg.json", true);
  check("Pentax.jpg", "Pentax.jpg.n.json", false);
}
#[test]
fn pentax_avi_conformance() {
  // Pentax.avi (K-x) — the Pentax AVI MakerNote bridge (#157). The RIFF parser
  // routes the `LIST_hydt` → `hymn` chunk through the shared `%Pentax::Main`
  // walker (`%Pentax::AVI` SubDirectory: `Start => 10`, `Base => '$start'`,
  // `ByteOrder => 'Unknown'`, `Pentax.pm:6373-6395`), so the Phase-1 Pentax
  // camera-indexing leaves emit byte-identically to bundled ExifTool 13.59
  // under family-1 `Pentax`: the K-x lens `LensType` = "smc PENTAX-DA L 18-55mm
  // F3.5-5.6" (the `0x003f LensRec` child), `PentaxModelID` = "K-x", `Quality`
  // = "Best", `WhiteBalance` = "Flash", the dotted `PentaxVersion` ("5.1.0.0"),
  // Contrast/Saturation/Sharpness, ImageTone "Natural", and the DSP/CPU
  // firmware versions — alongside the AVI `RIFF:`/`File:` stream (incl.
  // `RIFF:Software` "PENTAX K-x …"). The Phase-2a (#262) `CameraSettings`
  // (`$count < 25`, BASE leaves only — the K-x is not a K10D/GX10 body so the
  // offset-13+ leaves are model-gated out) and `AEInfo` (`$count == 24` ⇒ the
  // `$size > 20` `AEFlags` Hook shifts offsets 8+ by one) leaves emit too; the
  // K-x carries no `$count == 27` FlashInfo, so none is decoded (the scope-fence).
  //
  // #173 adds the K-x-applicable long-tail leaves the K10D `Pentax.jpg` golden
  // also gained: ExposureCompensation/PictureMode/DriveMode (Main), the SRInfo
  // 0x005c quartet, the LensData AutoAperture/MinAperture/FocusRangeIndex/
  // MaxAperture, and the ColorInfo WBShiftAB/WBShiftGM. (The K-x carries no
  // BatteryInfo/AFInfo record, and no FlashMode/FocusMode/EffectiveLV/ShutterCount
  // Main leaves, so none of those decode here.)
  //
  // The goldens are generated with `gen_golden.sh EXCLUDE="…"` dropping only the
  // tags exifast does NOT emit — every remaining exclusion is a still-deferred
  // port: the size-24-only AEInfo leaves AEWhiteBalance/AEMeteringMode2/
  // LevelIndicator, the K-x-only ColorInfo leaves Hue/HighLowKeyAdj/
  // MonochromeFilterEffect/MonochromeToning/CrossProcess, the ExtenderStatus/
  // SerialNumber/Artist/Copyright/FirmwareVersion long-tail — OR the engine-wide
  // Composite deferral (Composite:LensID/ImageSize/Megapixels/Duration — no EXIF
  // Composite subsystem). None masks a faithfulness gap in the ported subset; the
  // diff carries NO tag exifast emits that bundled does not.
  check("Pentax.avi", "Pentax.avi.json", true);
  check("Pentax.avi", "Pentax.avi.n.json", false);
}
#[test]
fn makernotes_dji_phantom4_conformance() {
  // DJIPhantom4.jpg (FC330) — the DJI-MakerNote conformance backstop on a REAL
  // drone JPEG (#121, MakerNote #163). The `0x927c` MakerNote is the verbatim
  // `%DJI::Main` text-record block (DJI.pm) — exifast emits all 10 `DJI:*`
  // leaves byte-identically to bundled ExifTool 13.59: `Make` = "DJI", the
  // three `SpeedX/Y/Z` (`+0.00`, the signed `%+.2f` PrintConv), the flight
  // `Pitch`/`Yaw`/`Roll` (-7.40 / -7.90 / -2.30) and `CameraPitch`/`CameraYaw`/
  // `CameraRoll` (-29.80 / -7.80 / +0.00) gimbal angles. The standard EXIF GPS
  // IFD is ALSO byte-exact (exifast emits the GPS IFD directly): `GPSLatitude`
  // = 32 deg 28' 42.95" N, `GPSLongitude` = 90 deg 15' 36.01" W, `GPSAltitude`
  // = 109.786 m — the raw GPS IFD tags. The ported GPS `Composite:*`
  // (`GPSLatitude`/`Longitude`/`Altitude`/`Position`, #133 PR 2) are ALSO
  // retained and byte-exact. All shared tags match for BOTH the `-j` PrintConv
  // and `-n` numeric snapshots.
  //
  // The golden is generated by `gen_golden.sh DJIPhantom4.jpg` on the DEFAULT
  // path (no `EXCLUDE` arm): exifast now emits EVERY tag bundled does for this
  // fixture, byte-exact in both `-j` and `-n`.
  //
  // The embedded XMP `APP1` packet (`http://ns.adobe.com/xap/1.0/\0` →
  // `Image::ExifTool::XMP::ProcessXMP`, #37) is NOW EMITTED — all 23 `XMP-*`
  // tags (`XMP-drone-dji:{Absolute,Relative}Altitude` / the six Gimbal/Flight
  // angle + three Flight-speed degrees / `Cam`/`GimbalReverse`,
  // `XMP-crs:{Version,HasSettings,HasCrop,AlreadyApplied}`,
  // `XMP-tiff:{Make,Model}`, `XMP-dc:Format`, `XMP-xmp:{Create,Modify}Date`,
  // `XMP-rdf:About`) routed through the shared XMP parser (the `src/exif/jpeg.rs`
  // marker-walk XMP hook, the SAME `parse_borrowed` a standalone `.xmp` / a
  // QuickTime `uuid`-XMP box uses), so the former `-x XMP:all` exclusion is GONE.
  //
  // The MPF (APP2 Multi-Picture Format — `MPF0`/`MPImage1`/`MPImage2`, incl. the
  // second-image `PreviewImage`), the Windows `XP*` tags (`IFD0:XPComment`/
  // `XPKeywords`, 0x9c9c/0x9c9e UCS-2), `ExifIFD:DeviceSettingDescription`
  // (0xa40b binary, the #114 JFIF/MPF/EXIF port), the full EXIF/lens
  // `Composite:*` chain (#133) and `IFD1:ThumbnailImage` (#331 `DataTag`) are all
  // emitted too — the golden carries every group (regenerated to match).
  check("DJIPhantom4.jpg", "DJIPhantom4.jpg.json", true);
  check("DJIPhantom4.jpg", "DJIPhantom4.jpg.n.json", false);
}
#[test]
fn makernotes_samsung_nx500_conformance() {
  // SamsungNX500.srw (NX500) — the Samsung Type2 MakerNote conformance backstop
  // on a REAL .srw raw (#210). The `0x927c` MakerNote dispatches to
  // `MakerNoteSamsung2` (`MakerNotes.pm:965-979`, EXIF-format magic) and walks
  // `%Samsung::Type2` through the shared `Walker` (body offset 0, inherit base,
  // `ByteOrder => Unknown` probed to big-endian, `FixBase => 1`, `ProcessProc =>
  // ProcessUnknown`). exifast emits all 45 `Samsung:*` leaves (29 plain + the
  // 16 decrypted Crypt leaves, #242) byte-identically to bundled ExifTool 13.59
  // — the camera-indexing identity
  // (`DeviceType` = "High-end NX Camera", `SamsungModelID` = "Various Models
  // (0x5001038)", `LensType` = "Samsung NX 45mm F1.8" via %samsungLensTypes,
  // `FirmwareName` = "1.10", `LensFirmware` = "01.00_01.10",
  // `InternalLensSerialNumber`), the exposure leaves (`ExposureTime` = "1/160"
  // via PrintExposureTime, `FNumber` = 8.9, `FocalLengthIn35mmFormat` = "69 mm"
  // with the /10 ValueConv, `ISO` = 20000, `ExposureCompensation`), the enum
  // leaves (`WhiteBalanceSetup`/`RawDataByteOrder`/`ColorSpace`/`SmartRange`/
  // `FaceDetect`/`FaceRecognition`), `MakerNoteVersion` = "0100" (the undef
  // ASCII-string render), the `CameraTemperature` undef rational, `SensorAreas`,
  // `SmartAlbumColor` = "n/a" (the `\0{4}` branch), and the five
  // `%Samsung::PictureWizard` ProcessBinaryData members (PictureWizardMode =
  // "Standard", Color = 65535, the -4-shifted Saturation/Sharpness/Contrast),
  // and the 16 decrypted Crypt leaves (#242, e.g. ColorMatrix =
  // "436 -120 -60 -42 312 -14 2 -94 348", WB_RGGBLevelsBlack = "128 128 128 128").
  // The "[minor] Unrecognized MakerNotes" warning bundled emitted while Samsung
  // was undecoded is GONE (the vendor now decodes). All 45 match for BOTH the
  // `-j` PrintConv and `-n` numeric snapshots (a Crypt row has no PrintConv, so
  // its plaintext is identical in both).
  //
  // #242: the 16 `RawConv => Samsung::Crypt(...)` encrypted leaves are now
  // DECRYPTED and emitted — WB_RGGBLevels{Uncorrected,Auto,Illuminator1,
  // Illuminator2,Black}, ColorMatrix{,SRGB,AdobeRGB}, CbCr{MatrixDefault,Matrix,
  // GainDefault,Gain}, ToneCurve{SRGBDefault,AdobeRGBDefault,SRGB,AdobeRGB}. The
  // cipher (`Samsung::Crypt`, Samsung.pm:1579-1605) decrypts each with the
  // `0xa020 EncryptionKey` int32u[11] captured DURING the Type2 walk; exifast's
  // plaintext space-joined integers match bundled ExifTool 13.59 BYTE-EXACT (the
  // real-input proof the cipher port is correct).
  //
  // The goldens are generated by the baked-in `gen_golden.sh SamsungNX500.srw`
  // arm dropping the tags exifast does NOT emit — every exclusion is a documented
  // deferral (none masks a Samsung-Type2 faithfulness gap; the diff carries NO
  // tag exifast emits that bundled does not):
  //   -x PreviewIFD:all  — the `0x0035 PreviewIFD` Nikon-PreviewIFD sub-IFD
  //                        (PreviewImage + its IFD tags), deferred.
  //   -x SubIFD:all -x SubIFD1:all — the SRW raw/JpgFromRaw sub-IFDs (the raw
  //                        image strips + the embedded JPEG), not walked.
  //   -x Composite:{LensID,WB_RGGBLevels,RedBalance,BlueBalance,CFAPattern} —
  //                        the MakerNote-derived Composites (#133 PR 4: exifast
  //                        now builds the ported EXIF + lens Composite chain —
  //                        Aperture/ShutterSpeed/ScaleFactor35efl/CircleOfConfusion/
  //                        FOV/FocalLength35efl/HyperfocalDistance/LightValue — but
  //                        not these MakerNote-synthesized ones), dropped by name.
  //   -x Composite:{ImageSize,Megapixels} — their `Require`d ImageWidth/Height
  //                        live in the deferred `SubIFD1` (6496x4336), so exifast
  //                        cannot build them (it carries only `ExifIFD:
  //                        ExifImageWidth`, a `Desire`). A documented sub-IFD
  //                        deferral, NOT a Composite-subsystem gap.
  // (The deferred `Unknown => 1` Crypt rows 0xa048/0xa05x are NOT excluded here:
  // ExifTool suppresses them from default `-j` output, so bundled never emits
  // them either — no `-x` is needed.)
  // (The `0x0011 OrientationInfo` row is absent from this body. The
  // `0xa002 SerialNumber` row IS present, but its value is `"0"` + NULs, which
  // fails the `Condition => '$$valPt =~ /^\w{5}/'` gate (`Samsung.pm:404-409`)
  // — bundled emits no `Samsung:SerialNumber` and exifast's emit-time
  // `condition_holds` gate drops it identically, so no exclusion is needed.)
  check("SamsungNX500.srw", "SamsungNX500.srw.json", true);
  check("SamsungNX500.srw", "SamsungNX500.srw.n.json", false);
}
#[test]
fn exif_manyifd_conformance() {
  // PR #36 Codex R11 F1 — a multi-page TIFF whose next-IFD chain runs 66
  // IFDs deep: IFD0 -> IFD1 -> ... -> IFD65. ExifTool's `Multi`
  // trailing-directory scan (Exif.pm:7202-7232) is an UNCAPPED `for (;;)`
  // loop — it follows the chain until a zero next pointer, an invalid
  // directory, or the reprocess guard, numbering each linked IFD
  // `DirName .= $ifdNum + 1` (Exif.pm:7215-7216).
  //
  // The R11/F1 bug: `walk_ifd_chain` capped the traversal at `0..MAX_IFDS`
  // (64). Because the cap counted IFD0, the parser emitted at most
  // IFD0..IFD63 and SILENTLY dropped IFD64/IFD65 from a valid 66-IFD
  // stream. The fix replaces the fixed cap with a faithful `loop {}` that
  // terminates only on the Perl conditions; the existing seen-offset
  // reprocess guard keeps it finite. `IfdKind::Trailing` was widened to
  // `u16` so `IFDn` numbers past 64.
  //
  // Bundled `perl exiftool` emits `IFD64:Software` = "exifast IFD64" and
  // `IFD65:Software` = "exifast IFD65" — the regression guard for the
  // dropped trailing IFDs. Verified against bundled `perl exiftool`
  // 2026-05-22.
  check("Exif_manyifd.tif", "Exif_manyifd.tif.json", true);
  check("Exif_manyifd.tif", "Exif_manyifd.tif.n.json", false);
}
#[test]
fn exif_multipage_conformance() {
  // PR #36 Codex R10 F1 — a multi-page TIFF whose next-IFD chain runs
  // THREE deep: IFD0 -> IFD1 -> IFD2. ExifTool's `Multi` trailing-directory
  // scan (Exif.pm:7202-7232) is a `for (;;)` loop: it re-reads
  // `Get32u($dataPt, $dirEnd)` after each trailing directory and increments
  // the directory number (`DirName .= $ifdNum + 1`, Exif.pm:7215-7216), so
  // IFD0 -> IFD1 -> IFD2 -> ... all process.
  //
  // The R10/F1 bug: `walk_one_ifd` only returned a non-zero next-IFD
  // pointer when `kind == IfdKind::Ifd0`, so the chain stopped after IFD1
  // and IFD2's tags were SILENTLY lost. The fix returns the next pointer
  // for any directory walked as part of the Multi chain
  // (`IfdKind::Ifd0 | IfdKind::Trailing(_)`) and numbers each trailing IFD
  // (`IfdKind::Trailing(n)` -> family-1 group `IFDn`).
  //
  // Bundled `perl exiftool` emits `IFD2:Compression` / `IFD2:Software` /
  // `IFD2:Orientation` — the regression guard for the lost third page.
  // Verified against bundled `perl exiftool` 2026-05-22.
  check("Exif_multipage.tif", "Exif_multipage.tif.json", true);
  check("Exif_multipage.tif", "Exif_multipage.tif.n.json", false);
}
#[test]
fn exif_pagecount_conformance() {
  // PR #68 (TIFF standalone container) — a two-page TIFF whose IFDs carry
  // `SubfileType` (0x00fe) values that trip the bundled `MultiPage` flag
  // and the synthesized `File:PageCount` tag (`ExifTool.pm:8756-8757`).
  //
  // Bundled `Exif.pm:452-457` `RawConv` for SubfileType:
  //   if ($val == ($val & 0x02)) {            # $val ∈ {0, 2}
  //     $$self{PageCount} += 1;
  //     $$self{MultiPage} = 1 if $val == 2 or $$self{PageCount} > 1;
  //   }
  //
  // Bundled `ExifTool.pm:8756-8757` (post-walk):
  //   if ($$self{TIFF_TYPE} eq 'TIFF') {
  //     $self->FoundTag(PageCount => $$self{PageCount}) if $$self{MultiPage};
  //   }
  //
  // IFD0 SubfileType=0 ⇒ PageCount=1 (val ∈ {0,2}, MultiPage stays 0).
  // IFD1 SubfileType=2 ⇒ PageCount=2 AND MultiPage=1 (val == 2).
  // Standalone TIFF ⇒ `File:PageCount = 2`.
  //
  // The pre-PR #68 walker counted IFDs but did not synthesize the tag, so
  // a real multi-page TIFF emitted IFD0..IFDn but no PageCount — silent
  // metadata loss vs bundled. This fixture pins the regression: the typed
  // walker tracks `pages`/`multi_page` via the SubfileType RawConv tap and
  // the standalone-TIFF entry (`parse_standalone_tiff_with_base`, the only
  // path that sets `TIFF_TYPE == 'TIFF'`) emits the synthesized
  // `File:PageCount` from `ExifMeta::multi_page_count()`.
  //
  // Embedded TIFF blocks (PNG `eXIf`, JPEG `APP1`, future QuickTime/RIFF)
  // do NOT emit PageCount — bundled gates on `TIFF_TYPE == 'TIFF'`. The
  // `parse_exif_block` / `parse_exif_block_with_base` entries pass
  // `tiff_type_is_tiff = false` and hold `multi_page_count = None`.
  // Verified against bundled `perl exiftool` 2026-05-24.
  check("Exif_pagecount.tif", "Exif_pagecount.tif.json", true);
  check("Exif_pagecount.tif", "Exif_pagecount.tif.n.json", false);
  // The SAME multi-page bytes under a TIFF-rooted SUBTYPE extension (`.dng`):
  // bundled detects `File:FileType = DNG`, `TIFF_TYPE = DNG`, and emits NO
  // `File:PageCount` (ExifTool.pm:8767) — every IFD tag is still extracted.
  // Pins #162 Codex R1 (the standalone-TIFF arm gates PageCount on the
  // candidate `Parent`, not a hard-coded `true`).
  check("Exif_pagecount.dng", "Exif_pagecount.dng.json", true);
  check("Exif_pagecount.dng", "Exif_pagecount.dng.n.json", false);
}
#[test]
fn exif_pagecount_suppressed_for_tiff_subtypes() {
  // #162 Codex R1: `File:PageCount` is synthesized ONLY when the outer file
  // type is literally `TIFF` (`$$self{TIFF_TYPE} eq 'TIFF'`, ExifTool.pm:8767).
  // A TIFF-rooted SUBTYPE (DNG/NEF/CR2/…) reaches the Exif arm through its
  // `TIFF` candidate (`file_type() == "TIFF"`) but carries the subtype as its
  // `Parent` (`$$dirInfo{Parent}`, ExifTool.pm:8546) ⇒ `TIFF_TYPE` is the
  // subtype ⇒ bundled emits NO `File:PageCount` even though the IFD chain trips
  // MultiPage. The walker still extracts every IFD tag. Oracle (`perl exiftool
  // -j -G1`, the Exif_pagecount bytes renamed): `.dng`/`.nef`/`.cr2` → NO
  // `File:PageCount`; `.tif` → `File:PageCount: 2`.
  let root = env!("CARGO_MANIFEST_DIR");
  let data = std::fs::read(format!("{root}/tests/fixtures/Exif_pagecount.tif"))
    .expect("read Exif_pagecount.tif");
  // Plain-TIFF control: the synthesized PageCount IS emitted.
  let tif = extract_info("Exif_pagecount.tif", &data, true);
  assert!(
    tif.contains("\"File:PageCount\""),
    "plain .tif must emit File:PageCount: {tif}",
  );
  // Every TIFF-rooted subtype (detected by EXTENSION → candidate `Parent` is the
  // subtype, not "TIFF") suppresses it, but the IFD tags are still extracted. (A
  // DOTLESS/magic-only RAW header would need magic-based subtype detection, which
  // the port does not do — tracked as a follow-up.)
  for name in [
    "Exif_pagecount.dng",
    "Exif_pagecount.nef",
    "Exif_pagecount.cr2",
    "Exif_pagecount.orf",
    "Exif_pagecount.rw2",
    "Exif_pagecount.3fr",
    "Exif_pagecount.arw",
  ] {
    for print_on in [true, false] {
      let got = extract_info(name, &data, print_on);
      assert!(
        !got.contains("\"File:PageCount\""),
        "{name} (print_conv={print_on}) must NOT emit File:PageCount: {got}",
      );
      assert!(
        got.contains("\"IFD0:Make\":\"Canon\""),
        "{name}: IFD0 tags must still be extracted: {got}",
      );
    }
  }
}
#[test]
fn composite_deferred_for_cr2_raw_imagesize_subtype() {
  // #133 Finding 2: a CR2 (TIFF-base Canon RAW) whose IFD0 `ImageWidth`/`Height`
  // DIFFER from the ExifIFD's `ExifImageWidth`/`Height`. Bundled ExifTool's
  // `Composite:ImageSize` (Exif.pm:4759) takes its `$$self{TIFF_TYPE} =~
  // /^(CR2|Canon 1D RAW|IIQ|EIP)$/` branch and emits `ExifImageWidth x Height`
  // (`"200x160"`), NOT `ImageWidth x Height` (`"100x80"`). The composite
  // post-pass has no `TIFF_TYPE` handle (`File:FileType` is finalized at the
  // JSON-orchestration layer, after `serialize_tags`), so exifast DEFERS all
  // composites for those RAW subtypes (`runs_composites` → false via
  // `exif_file_type_is_raw_imagesize_subtype`) rather than emit the WRONG
  // `ImageWidth`-based size. The golden is generated `-x Composite:all` (the
  // documented deferral), so the byte-exact `check` already proves NO Composite
  // is emitted; the explicit asserts below make the intent unmissable — in
  // particular that the WRONG `"100x80"` is never produced.
  check("CR2_imagesize.cr2", "CR2_imagesize.cr2.json", true);
  check("CR2_imagesize.cr2", "CR2_imagesize.cr2.n.json", false);

  let root = env!("CARGO_MANIFEST_DIR");
  let data = std::fs::read(format!("{root}/tests/fixtures/CR2_imagesize.cr2"))
    .expect("read CR2_imagesize.cr2");
  for print_on in [true, false] {
    let got = extract_info("CR2_imagesize.cr2", &data, print_on);
    // File:FileType MUST be CR2 (the `CR\x02\0` magic) — the gate's predicate.
    assert!(
      got.contains("\"File:FileType\":\"CR2\""),
      "fixture must finalize as CR2 (print_conv={print_on}): {got}",
    );
    // The whole Composite subsystem is deferred for the CR2 subtype.
    assert!(
      !got.contains("\"Composite:ImageSize\""),
      "CR2 must NOT emit Composite:ImageSize (print_conv={print_on}): {got}",
    );
    assert!(
      !got.contains("\"Composite:Megapixels\""),
      "CR2 must NOT emit Composite:Megapixels (print_conv={print_on}): {got}",
    );
    // Crucially, the WRONG `ImageWidth`-based size must never appear.
    assert!(
      !got.contains("100x80") && !got.contains("100 80"),
      "CR2 must NOT emit the ImageWidth-based size (print_conv={print_on}): {got}",
    );
    // The raw IFD tags ARE still extracted (only the composite pass is gated).
    assert!(
      got.contains("\"ExifIFD:ExifImageWidth\""),
      "CR2 IFD tags must still be extracted (print_conv={print_on}): {got}",
    );
  }
}
#[test]
fn cr2_preview_image_conformance() {
  // #331-P2 (#352/#353): a CR2 whose IFD0 0x0111/0x0117 offset-pair
  // (`PreviewImageStart`/`PreviewImageLength`, `Exif.pm:645-661`/`:742-758`,
  // gated `$$self{TIFF_TYPE} eq "CR2"`) drives the synthetic
  // `IFD0:PreviewImage = (Binary data 4 bytes, …)` via the EXIF `DataTag`
  // channel — the IFD0-side proof of the P2 wiring. The 4-byte SOI+EOI blob is
  // in-bounds, so the placeholder is emitted under the offset tag's OWN groups.
  check("CR2_preview_image.cr2", "CR2_preview_image.cr2.json", true);
  check(
    "CR2_preview_image.cr2",
    "CR2_preview_image.cr2.n.json",
    false,
  );

  let root = env!("CARGO_MANIFEST_DIR");
  let data = std::fs::read(format!("{root}/tests/fixtures/CR2_preview_image.cr2"))
    .expect("read CR2_preview_image.cr2");
  for print_on in [true, false] {
    let got = extract_info("CR2_preview_image.cr2", &data, print_on);
    assert!(
      got.contains("\"File:FileType\":\"CR2\""),
      "fixture must finalize as CR2 (print_conv={print_on}): {got}",
    );
    assert!(
      got.contains("\"IFD0:PreviewImage\":\"(Binary data 4 bytes, use -b option to extract)\""),
      "CR2 must emit IFD0:PreviewImage via the P2 DataTag channel (print_conv={print_on}): {got}",
    );
  }
}
#[test]
fn arw_preview_image_conformance() {
  // #331-P2 (#352/#353): a Sony ARW whose IFD0 0x0201/0x0202 offset-pair
  // (`PreviewImageStart`/`PreviewImageLength`, `Exif.pm:1226-1237`, gated
  // `DIR_NAME eq "IFD0" and TIFF_TYPE =~ /^(ARW|SR2)$/`) drives
  // `IFD0:PreviewImage` — the SAME 0x0201 id that names `ThumbnailImage` in
  // IFD1, here selected to `PreviewImage` by the IFD0/ARW condition.
  check("ARW_preview_image.arw", "ARW_preview_image.arw.json", true);
  check(
    "ARW_preview_image.arw",
    "ARW_preview_image.arw.n.json",
    false,
  );

  let root = env!("CARGO_MANIFEST_DIR");
  let data = std::fs::read(format!("{root}/tests/fixtures/ARW_preview_image.arw"))
    .expect("read ARW_preview_image.arw");
  for print_on in [true, false] {
    let got = extract_info("ARW_preview_image.arw", &data, print_on);
    assert!(
      got.contains("\"File:FileType\":\"ARW\""),
      "fixture must finalize as ARW (print_conv={print_on}): {got}",
    );
    assert!(
      got.contains("\"IFD0:PreviewImage\":\"(Binary data 4 bytes, use -b option to extract)\""),
      "ARW must emit IFD0:PreviewImage via the P2 DataTag channel (print_conv={print_on}): {got}",
    );
  }
}

/// The real Sony ARW raws (FX3 / SLT-A33) — the SR2 subsystem + the Sony ARW
/// `SubIFD:*` raw tags + the standalone conversions (Compression 32767, the IFD2
/// `JpgFromRaw*`/`YCbCrSubSampling`, the `IsImageData` placeholders) are
/// byte-exact in BOTH `-j` and `-n`. The `%Sony::Main` ENCRYPTED sub-table tower
/// (the `Decipher` cipher + the model-version ProcessBinaryData tables) is a
/// separate deferred port, so its `Sony:*` exposure/AF/lens leaves and the
/// dependent `Composite:*` are dropped from BOTH sides here (the SAME keys the
/// `NOT_ACTIVE` deferral in `tests/typed_serde_parity.rs` documents). This test
/// LOCKS the SR2/SubIFD/conversion foundation byte-exact as a regression guard;
/// when the sub-table tower lands, the exclusions shrink and the fixtures move
/// into the active byte-exact set.
#[test]
fn sony_arw_real_sr2_and_subifd_conformance() {
  // The deferred `%Sony::Main` sub-table leaves (+ extra/divergent Sony Main
  // leaves whose final value comes from those sub-tables' DataMembers) and the
  // `Composite:*` that `Require`/`Desire` them. FX3 (newer body: the `Tag9xxx`
  // encrypted series + `Tag202a`).
  // The FX3 `%Sony::Main` encrypted sub-table tower is now FULLY PORTED — the
  // `Decipher` cipher + the model/version-dispatched ProcessBinaryData tables
  // (`Tag9050c`/`Tag9400c`/`Tag9401`(ISOInfo)/`Tag9402`/`Tag9406`/`Tag940c`/
  // `Tag9416` + the plain `Tag202a`) emit every remaining `Sony:*` exposure/AF/
  // lens/battery/ISO leaf, and the five dependent `Composite:*`
  // (LensID/BlueBalance/RedBalance/CFAPattern/FocusDistance2) now compute
  // byte-exact. The SOLE residual is one embedded-XMP leaf:
  const FX3_DEFERRED: &[&str] = &[
    // `XMP-xmp:Rating` (= 0) — the IFD0 `0x02bc` ApplicationNotes XMP packet
    // (`<xmp:Rating>0</xmp:Rating>`). exifast routes embedded XMP to the shared
    // `ProcessXMP` parser ONLY from the JPEG `APP1` marker walk (`src/exif/
    // jpeg.rs`); the TIFF/raw IFD0 `0x02bc` SubDirectory → `XMP::Main` routing
    // (`Exif.pm`, the ApplicationNotes arm) is a SEPARATE, cross-cutting
    // subsystem (it would emit XMP for every TIFF/DNG/CR2/NEF raw) that is NOT
    // part of the Sony deep-table port — deferred to its own campaign. This is
    // the lone niche exclusion; the `Sony:Rating` (= 0) MakerNote leaf IS
    // emitted byte-exact.
    "XMP-xmp:Rating",
  ];
  // A33 (older SLT body: `CameraInfo3`/`AFInfo`(AFStatus grid)/`CameraSettings3`/
  // `ExtraInfo3`/`MoreInfo`/`Tag900b`).
  const A33_DEFERRED: &[&str] = &[
    "Composite:BlueBalance",
    "Composite:CFAPattern",
    "Composite:FocalLength35efl",
    "Composite:FocusDistance2",
    "Composite:LensID",
    "Composite:RedBalance",
    "Sony:AELock",
    "Sony:AFAreaMode",
    "Sony:AFButtonPressed",
    "Sony:AFPoint",
    "Sony:AFPointSelected",
    "Sony:AFStatusActiveSensor",
    "Sony:AFStatusBottomHorizontal",
    "Sony:AFStatusBottomVertical",
    "Sony:AFStatusCenterHorizontal",
    "Sony:AFStatusCenterVertical",
    "Sony:AFStatusFarLeft",
    "Sony:AFStatusFarRight",
    "Sony:AFStatusLeft",
    "Sony:AFStatusLower-left",
    "Sony:AFStatusLower-middle",
    "Sony:AFStatusLower-right",
    "Sony:AFStatusNearLeft",
    "Sony:AFStatusNearRight",
    "Sony:AFStatusRight",
    "Sony:AFStatusTopHorizontal",
    "Sony:AFStatusTopVertical",
    "Sony:AFStatusUpper-left",
    "Sony:AFStatusUpper-middle",
    "Sony:AFStatusUpper-right",
    "Sony:ApertureSetting",
    "Sony:AspectRatio",
    "Sony:BatteryLevel",
    "Sony:BatteryState",
    "Sony:BatteryTemperature",
    "Sony:BatteryVoltage1",
    "Sony:BatteryVoltage2",
    "Sony:CameraOrientation",
    "Sony:ColorCompensationFilterSet",
    "Sony:ColorSpace",
    "Sony:ColorTemperatureSetting",
    "Sony:ContrastSetting",
    "Sony:CreativeStyleSetting",
    "Sony:CustomWB_RBLevels",
    "Sony:CustomWB_RGBLevels",
    "Sony:DriveMode",
    "Sony:DriveMode2",
    "Sony:DriveModeSetting",
    "Sony:DynamicRangeOptimizerLevel",
    "Sony:DynamicRangeOptimizerSetting",
    "Sony:ExposureCompensation2",
    "Sony:ExposureCompensationSet",
    "Sony:ExposureProgram",
    "Sony:ExposureTime",
    "Sony:FNumber",
    "Sony:FaceDetection",
    "Sony:FacesDetected",
    "Sony:FlashAction",
    "Sony:FlashActionExternal",
    "Sony:FlashControl",
    "Sony:FlashExposureComp",
    "Sony:FlashExposureCompSet",
    "Sony:FlashExposureCompSet2",
    "Sony:FlashMode",
    "Sony:FlashStatus",
    "Sony:FlashStatusBuilt-in",
    "Sony:FlashStatusExternal",
    "Sony:FocalLength",
    "Sony:FocalLength2",
    "Sony:FocalLengthTeleZoom",
    "Sony:FocusMode",
    "Sony:FocusMode2",
    "Sony:FocusModeSetting",
    "Sony:FocusPosition2",
    "Sony:FocusStatus",
    "Sony:FolderNumber",
    "Sony:HDRLevel",
    "Sony:HDRSetting",
    "Sony:ISO",
    "Sony:ISOSetting",
    "Sony:ImageCount",
    "Sony:ImageNumber",
    "Sony:LensMount",
    "Sony:LiveViewAFMethod",
    "Sony:LiveViewAFSetting",
    "Sony:LiveViewFocusMode",
    "Sony:LiveViewMetering",
    "Sony:MeteringMode",
    "Sony:MultiFrameNoiseReduction",
    "Sony:Orientation2",
    "Sony:PanoramaSize3D",
    "Sony:RedEyeReduction",
    "Sony:SaturationSetting",
    "Sony:SequenceNumber",
    "Sony:SharpnessSetting",
    "Sony:ShotNumberSincePowerUp",
    "Sony:ShotNumberSincePowerUp2",
    "Sony:ShutterCount",
    "Sony:ShutterSpeedSetting",
    "Sony:SmileShutter",
    "Sony:SmileShutterMode",
    "Sony:SonyImageSize",
    "Sony:SweepPanoramaDirection",
    "Sony:SweepPanoramaSize",
    "Sony:TiffMeteringImage",
    "Sony:ViewingMode",
    "Sony:ViewingMode2",
    "Sony:WhiteBalanceSetting",
  ];
  check_excluding(
    "Sony_ILME-FX3_real.ARW",
    "Sony_ILME-FX3_real.ARW.json",
    true,
    FX3_DEFERRED,
  );
  check_excluding(
    "Sony_ILME-FX3_real.ARW",
    "Sony_ILME-FX3_real.ARW.n.json",
    false,
    FX3_DEFERRED,
  );
  check_excluding(
    "Sony_SLT-A33_real.ARW",
    "Sony_SLT-A33_real.ARW.json",
    true,
    A33_DEFERRED,
  );
  check_excluding(
    "Sony_SLT-A33_real.ARW",
    "Sony_SLT-A33_real.ARW.n.json",
    false,
    A33_DEFERRED,
  );

  // Positively assert the SR2 subsystem actually fired (the decrypt + nested
  // IFD walk), not just that the residual was excluded: the decrypted SR2SubIFD
  // WB levels + the SR2DataIFD ColorMode + the SR2SubIFDKey hex render.
  let root = env!("CARGO_MANIFEST_DIR");
  let data = std::fs::read(format!("{root}/tests/fixtures/Sony_ILME-FX3_real.ARW"))
    .expect("read Sony_ILME-FX3_real.ARW");
  let got = extract_info("Sony_ILME-FX3_real.ARW", &data, true);
  for needle in [
    "\"SR2:SR2SubIFDKey\":\"0x44332211\"",
    "\"SR2SubIFD:WB_RGGBLevels\":\"2501 1024 1024 1486\"",
    "\"SR2DataIFD:ColorMode\":\"Standard\"",
    "\"SR2DataIFD9:ColorMode\":\"Sepia\"",
    "\"SubIFD:Compression\":\"Sony ARW Compressed\"",
    // The Tag9050c decipher + ProcessBinaryData (the `0x9050` enciphered block):
    // Shutter / FlashStatus / ShutterCount(2) / SonyExposureTime / SonyFNumber /
    // ReleaseMode2 / InternalSerialNumber.
    "\"Sony:Shutter\":\"Mechanical (2738 5168 6484)\"",
    "\"Sony:FlashStatus\":\"No Flash present\"",
    "\"Sony:ShutterCount\":2",
    "\"Sony:ShutterCount2\":2",
    "\"Sony:SonyExposureTime\":\"1/128\"",
    "\"Sony:SonyFNumber\":2.9",
    "\"Sony:InternalSerialNumber\":\"47ff0000a708\"",
    // The Tag9400c decipher + ProcessBinaryData (the `0x9400` enciphered block):
    // ReleaseMode2 (last-wins from Tag9050c) / SequenceImageNumber /
    // SequenceFileNumber / SequenceLength (the 0x001e "N files" form) /
    // CameraOrientation / Quality2 (the modern HEIF-aware variant).
    "\"Sony:ReleaseMode2\":\"Normal\"",
    "\"Sony:SequenceImageNumber\":1",
    "\"Sony:SequenceFileNumber\":1",
    "\"Sony:SequenceLength\":\"1 file\"",
    "\"Sony:CameraOrientation\":\"Horizontal (normal)\"",
    "\"Sony:Quality2\":\"RAW\"",
  ] {
    assert!(
      got.contains(needle),
      "SR2/SubIFD + Tag9050c/Tag9400c foundation must emit {needle}: {got}",
    );
  }
}
#[test]
#[ignore = "DNG_preview_image.dng's full -G1 golden is not byte-exact because \
            `IFD0:DNGVersion` (0xc612) is not yet an emitted leaf (a deferred \
            leaf-table item — the walker taps 0xc612 for the `$$self{DNGVersion}` \
            DataMember but does not display it). The #331-P2 classic-TIFF SubIFD \
            walk NOW lands (the SubIFD leaves + NO-PreviewImage gating are asserted \
            positively below); only DNGVersion display remains. NOT_ACTIVE in \
            typed_serde_parity; re-activate once DNGVersion is an emitted leaf."]
fn dng_preview_image_no_preview() {
  // #331-P2 (#352/#353): a DNG whose IFD0→SubIFD (0x014a) carries `SubfileType=1`
  // + StripOffsets/StripByteCounts (0x0111/0x0117) but NO `Compression`. ExifTool
  // routes 0x0111 to the PLAIN `StripOffsets` arm (`Exif.pm:639-653`): the
  // CR2/IFD0 exclusion misses (it is a SubIFD) AND the `Compression=7`
  // DNG-preview exclusion misses (no Compression tag), so the first arm wins and
  // the later `PreviewImageStart`/`JpgFromRaw` arms are never reached. The
  // classic-TIFF SubIFD multi-offset walk now emits the SubIFD's structural
  // leaves; the port must emit them AND NO `PreviewImage` — proving the SubIFD
  // walk works and the P2 DataTag wiring is Condition-gated (it does NOT
  // spuriously fire on a DNG's plain SubIFD strips). (The byte-exact `check` is
  // deferred only on the `IFD0:DNGVersion` leaf — see the `#[ignore]` reason.)
  let root = env!("CARGO_MANIFEST_DIR");
  let data = std::fs::read(format!("{root}/tests/fixtures/DNG_preview_image.dng"))
    .expect("read DNG_preview_image.dng");
  for print_on in [true, false] {
    let got = extract_info("DNG_preview_image.dng", &data, print_on);
    assert!(
      got.contains("\"File:FileType\":\"DNG\""),
      "fixture must finalize as DNG (print_conv={print_on}): {got}",
    );
    // The classic-TIFF SubIFD (0x014a) walk now emits the SubIFD's structural
    // leaves under the `SubIFD:` family-1 group (#331-P2).
    assert!(
      got.contains("\"SubIFD:StripOffsets\":169") && got.contains("\"SubIFD:StripByteCounts\":4"),
      "the classic-TIFF SubIFD walk must emit SubIFD:StripOffsets/StripByteCounts \
       (print_conv={print_on}): {got}",
    );
    assert!(
      !got.contains("PreviewImage") && !got.contains("JpgFromRaw"),
      "DNG must NOT emit any PreviewImage/JpgFromRaw (the SubIFD strips are not a \
       preview — no Compression=7) (print_conv={print_on}): {got}",
    );
  }
}
#[test]
fn tiff_jpgfromraw_conformance() {
  // #331-P2 (#352): the SubIFD2:JpgFromRaw verifier — a minimal little-endian
  // TIFF whose IFD0 0x014a SubIFD pointer carries THREE offsets, descended as
  // `SubIFD`/`SubIFD1`/`SubIFD2` (`Exif.pm:7074-7076`'s `s/\d*$/$dirNum/`).
  // SubIFD2 carries `SubfileType=1` + `Compression=7` (JPEG) + 0x0111/0x0117,
  // which resolve to `JpgFromRawStart`/`JpgFromRawLength` (`Exif.pm:673-684`/
  // `:769-778`): the plain `StripOffsets` arm is excluded by the DNG/TIFF
  // JPEG-preview gate (`Compression eq '7' and SubfileType ne '0'`), the CR2 arm
  // misses, and the `PreviewImage` arm misses (`DIR_NAME eq "SubIFD2"`). The
  // offset-pair drives the synthetic `SubIFD2:JpgFromRaw = (Binary data 4 bytes,
  // …)` via the EXIF DataTag channel. SubIFD0 carries plain `StripOffsets`/
  // `StripByteCounts` (no Compression ⇒ the plain arm wins ⇒ NO DataTag) — the
  // SubIFD-context StripOffsets path P1 could not reach.
  check("TIFF_jpgfromraw.tif", "TIFF_jpgfromraw.tif.json", true);
  check("TIFF_jpgfromraw.tif", "TIFF_jpgfromraw.tif.n.json", false);

  let root = env!("CARGO_MANIFEST_DIR");
  let data = std::fs::read(format!("{root}/tests/fixtures/TIFF_jpgfromraw.tif"))
    .expect("read TIFF_jpgfromraw.tif");
  for print_on in [true, false] {
    let got = extract_info("TIFF_jpgfromraw.tif", &data, print_on);
    assert!(
      got.contains("\"File:FileType\":\"TIFF\""),
      "fixture must finalize as TIFF (print_conv={print_on}): {got}",
    );
    // The headline P2 target: SubIFD2:JpgFromRaw via the DataTag channel.
    assert!(
      got.contains("\"SubIFD2:JpgFromRaw\":\"(Binary data 4 bytes, use -b option to extract)\""),
      "SubIFD2 must emit JpgFromRaw via the P2 DataTag channel (print_conv={print_on}): {got}",
    );
    // The SubIFD2 offset-pair leaves are renamed JpgFromRawStart/Length (NOT the
    // default StripOffsets/StripByteCounts) by the SubIFD2 condition.
    assert!(
      got.contains("\"SubIFD2:JpgFromRawStart\":245")
        && got.contains("\"SubIFD2:JpgFromRawLength\":4"),
      "SubIFD2 0x0111/0x0117 must be named JpgFromRawStart/Length (print_conv={print_on}): {got}",
    );
    // SubIFD0 (no Compression) keeps the plain StripOffsets arm — NO JpgFromRaw
    // there, proving the DataMember-gated condition does not over-fire.
    assert!(
      got.contains("\"SubIFD:StripOffsets\":241"),
      "SubIFD0 (no Compression) must keep plain StripOffsets (print_conv={print_on}): {got}",
    );
  }
}
#[test]
fn exif_numeric_emission_json_token_type() {
  // PR #36 Codex R18/F1 — Exif/GPS numeric values must be emitted as bare
  // JSON NUMBER tokens, not quoted strings. The conformance `check`s above
  // use the value-semantic `json_equivalent` (`"300" == 300`), which is
  // BLIND to the JSON token TYPE; this test asserts the token TYPE directly.
  //
  // Bundled ExifTool stringifies every `$val` and runs `EscapeJSON`'s number
  // gate (`exiftool:3809`): a value matching `^-?(\d|[1-9]\d{1,14})
  // (\.\d{1,16})?(e[-+]?\d{1,3})?$` prints as a bare JSON NUMBER, anything
  // else as a quoted string. Pre-fix, exifast routed numeric PrintConv
  // results AND scalar rationals through `write_str` (→ `TagValue::Str` → a
  // JSON STRING) — value-equivalent but the WRONG token type.
  //
  // Verified end-to-end on the real camera JPEG `ExifGPS.jpg` (= bundled
  // `t/images/GPS.jpg`). Each `(key, expect-number)` below was cross-checked
  // against bundled `perl exiftool 13.58 -j -G1` / `-n` output.
  use serde_json::Value;

  fn obj(print_on: bool) -> serde_json::Map<String, Value> {
    let root = env!("CARGO_MANIFEST_DIR");
    let data =
      std::fs::read(format!("{root}/tests/fixtures/ExifGPS.jpg")).expect("read ExifGPS.jpg");
    let doc = extract_info("ExifGPS.jpg", &data, print_on);
    let v: Value = serde_json::from_str(&doc).expect("valid JSON");
    v.as_array().unwrap()[0].as_object().unwrap().clone()
  }

  fn assert_token(o: &serde_json::Map<String, Value>, key: &str, want_number: bool, mode: &str) {
    match o.get(key) {
      Some(Value::Number(_)) if want_number => {}
      Some(Value::String(_)) if !want_number => {}
      other => panic!(
        "{mode}: {key} expected a JSON {} token, got {other:?}",
        if want_number { "NUMBER" } else { "STRING" }
      ),
    }
  }

  // -j (PrintConv) — in-gate numeric PrintConv results + scalar rationals
  // are bare JSON NUMBERS; `/`- and space-bearing values stay STRINGS.
  let j = obj(true);
  for (key, want_number) in [
    ("IFD0:XResolution", true),              // scalar rational 300/1 → 300
    ("IFD1:XResolution", true),              // scalar rational 72/1 → 72
    ("ExifIFD:FNumber", true),               // PrintFNumber `%.1f`/`%.2f` → 0.64
    ("ExifIFD:ApertureValue", true),         // APEX PrintConv `%.1f` → 16.0
    ("ExifIFD:BrightnessValue", true),       // scalar rational → 0.26015625
    ("ExifIFD:ExposureCompensation", true),  // PrintFraction → -0.65
    ("ExifIFD:FocalPlaneXResolution", true), // scalar rational → 12.05078125
    ("ExifIFD:ShutterSpeedValue", false),    // `1/724` — a `/` ⇒ STRING
    ("ExifIFD:FocalLength", false),          // `0.0 mm` — a space ⇒ STRING
    ("GPS:GPSTimeStamp", false),             // `14:58:24` — `:` ⇒ STRING
    ("GPS:GPSLatitude", false),              // `54 deg 59' 22.80"` ⇒ STRING
  ] {
    assert_token(&j, key, want_number, "-j");
  }

  // -n (post-ValueConv) — raw scalars through the SAME gate. The critical
  // out-of-gate case is `ExifIFD:ShutterSpeedValue`: its ValueConv
  // `2 ** -$val` stringifies to `0.00138106793200498` — a 17-digit fraction,
  // EXCEEDING the gate's `\.\d{1,16}` cap, so bundled QUOTES it. exifast must
  // too (a `write_f64` would wrongly emit a bare number).
  let n = obj(false);
  for (key, want_number) in [
    ("IFD0:XResolution", true),      // 300
    ("ExifIFD:FNumber", true),       // raw rational quotient 0.640234375
    ("ExifIFD:ApertureValue", true), // APEX ValueConv → 16
    ("ExifIFD:BrightnessValue", true),
    ("ExifIFD:ExposureCompensation", true), // -0.6500000006
    ("ExifIFD:FocalPlaneXResolution", true),
    ("GPS:GPSLatitude", true),            // ToDegrees decimal → 54.98966…
    ("ExifIFD:ShutterSpeedValue", false), // 17-digit fraction ⇒ out of gate
    ("GPS:GPSTimeStamp", false),          // `14:58:24` ⇒ STRING
  ] {
    assert_token(&n, key, want_number, "-n");
  }
}
#[test]
fn exif_trailing_space_conformance() {
  // PR #36 Codex R15 F1 — space-padded EXIF `string` fields (normal camera /
  // encoder output for a fixed-width or EXIF-"unknown" ASCII field) carry a
  // trailing-trim conversion that bundled ExifTool applies BEFORE serializing,
  // in BOTH -j and -n. Two distinct conversions are pinned here:
  //
  //   - IFD0 Make/Model/Software/Artist: `RawConv => '$val =~ s/\s+$//'`
  //     (Exif.pm:585/599/906/925) — strips EVERY trailing whitespace char
  //     (Perl `\s` = space/tab/NL/CR/FF/VT). A RawConv runs at the raw stage,
  //     so the trim shows in both modes. The fixture's Model "EOS R5\t " has a
  //     trailing TAB+space — both stripped to "EOS R5", proving `\s` (not just
  //     space) is honored.
  //   - ExifIFD SubSecTime/SubSecTimeOriginal/SubSecTimeDigitized:
  //     `ValueConv => '$val=~s/ +$//'` (Exif.pm:2543/2552/2560) — trims
  //     trailing SPACES only; the trimmed all-digit value serializes as a JSON
  //     number (123/45/70). The spaces-only-vs-`\s` distinction is unit-tested
  //     in `src/exif` (an embedded TAB trips a minimal-TIFF inline-value bound,
  //     so it is not in the fixture).
  //
  // Without the trim the port would index space-padded duplicates (`"Canon   "`
  // vs `"Canon"`) — a camera/software facet split. Synthetic standalone TIFF
  // `tools/gen_exif_fixtures.py::make_exif_trailing_space_tif`. Goldens:
  // bundled `perl exiftool -j -G1 -struct` (`-n` too), `System:*` stripped,
  // KEEPING the ported `Composite:SubSecDateTimeOriginal` ("2021:08:14
  // 16:45:09.45") which exifast now builds from `DateTimeOriginal` +
  // `SubSecTimeOriginal` (#133 PR 3 — EXIF is allow-listed). Verified vs bundled
  // `perl exiftool`.
  check(
    "Exif_trailing_space.tif",
    "Exif_trailing_space.tif.json",
    true,
  );
  check(
    "Exif_trailing_space.tif",
    "Exif_trailing_space.tif.n.json",
    false,
  );
}
#[test]
fn exif_truncated_ifd_conformance() {
  // PR #36 Codex R1 F2 — IFD0 declares 5 entries but the file ends after
  // 2. The directory's declared extent (`$dirEnd`) runs past the buffer;
  // ExifTool's read-what-we-can salvage (`$numEntries = int(($dirSize-2)
  // /12)`, Exif.pm:6386) is GATED to MakerNotes (`return 0 unless
  // $inMakerNotes …`, Exif.pm:6382-6385). For a normal IFD0 ExifTool
  // warns `Bad IFD0 directory` (Exif.pm:6381) and aborts the WHOLE
  // directory — NO partial tags. The exifast walker never recurses into
  // a MakerNote IFD (deferred), so every directory it handles aborts.
  // Verified against bundled `perl exiftool` 2026-05-22.
  check(
    "Exif_truncated_ifd.tif",
    "Exif_truncated_ifd.tif.json",
    true,
  );
  check(
    "Exif_truncated_ifd.tif",
    "Exif_truncated_ifd.tif.n.json",
    false,
  );
}
#[test]
fn exif_usercomment_ascii_conformance() {
  // PR #36 Codex R5 F1 — ExifIFD UserComment (0x9286) is `Format => 'undef'`
  // with `RawConv => ConvertExifText($self,$val,1,$tag)` (Exif.pm:2497-2507),
  // the SAME RawConv the GPS text tags use but in the ExifIFD and WITHOUT the
  // `gps` feature. An `ASCII\0\0\0`-prefixed value has the prefix stripped and
  // is truncated at the first NUL ⇒ bundled emits `ExifIFD:UserComment` =
  // "Hello World", NOT a `(Binary data …)` placeholder. Pins the bug: 0x9286
  // was wired `Conv::None`. A RawConv applies in BOTH -j and -n. Verified
  // against bundled `perl exiftool` 2026-05-22.
  check(
    "Exif_usercomment_ascii.tif",
    "Exif_usercomment_ascii.tif.json",
    true,
  );
  check(
    "Exif_usercomment_ascii.tif",
    "Exif_usercomment_ascii.tif.n.json",
    false,
  );
}
#[test]
fn exif_usercomment_bom_conformance() {
  // PR #36 Codex R5 F1 — a BIG-ENDIAN (MM) TIFF whose ExifIFD UserComment
  // carries a `UNICODE\0`-prefixed UTF-16LE payload that begins with an LE
  // BOM. The BOM pins the order and DISABLES the heuristic (Charset.pm:203-
  // 206), so `ConvertExifText` decodes LE regardless of the MM TIFF order ⇒
  // bundled emits `ExifIFD:UserComment` = "Tokyo". Verified against bundled
  // `perl exiftool` 2026-05-22.
  check(
    "Exif_usercomment_bom.tif",
    "Exif_usercomment_bom.tif.json",
    true,
  );
  check(
    "Exif_usercomment_bom.tif",
    "Exif_usercomment_bom.tif.n.json",
    false,
  );
}
#[test]
fn exif_usercomment_int8u_conformance() {
  // PR #36 Codex R6 F1 — ExifIFD UserComment (0x9286) whose ON-DISK format
  // code is `int8u` (1), the OTHER documented mis-writer (Exif.pm:2499). The
  // `Format => 'undef'` read-side override (Exif.pm:6729-6744) forces it
  // through `undef` ⇒ bundled emits `ExifIFD:UserComment` = "Hello World"
  // (NOT a comma-joined int8u array, and NOT a NUL-truncated "ASCII"). The
  // override re-shapes `$count = int($size / $formatSize['undef'])`, i.e. the
  // full on-disk byte window. Verified against bundled `perl exiftool`
  // 2026-05-22.
  check(
    "Exif_usercomment_int8u.tif",
    "Exif_usercomment_int8u.tif.json",
    true,
  );
  check(
    "Exif_usercomment_int8u.tif",
    "Exif_usercomment_int8u.tif.n.json",
    false,
  );
}
#[test]
fn exif_usercomment_string_conformance() {
  // PR #36 Codex R6 F1 — ExifIFD UserComment (0x9286) whose ON-DISK format
  // code is `string` (2), the documented mis-writer (Exif.pm:2499 "I have
  // seen other applications write it incorrectly as 'string' or 'int8u'").
  // ExifTool's `Format => 'undef'` (Exif.pm:2500) is a READ-side override
  // applied BEFORE `ReadValue` (Exif.pm:6729-6744): it forces the value
  // through `undef` so `ReadValue` does NOT NUL-trim at the charset prefix's
  // interior NULs. `ConvertExifText` then strips the 8-byte `ASCII\0\0\0`
  // prefix ⇒ bundled emits `ExifIFD:UserComment` = "Hello World". WITHOUT the
  // override the `string` decode trims `ASCII\0\0\0Hello World` at the first
  // NUL to "ASCII" and the payload is lost — exactly the R6/F1 bug. A RawConv
  // applies in BOTH -j and -n. Verified against bundled `perl exiftool`
  // 2026-05-22.
  check(
    "Exif_usercomment_string.tif",
    "Exif_usercomment_string.tif.json",
    true,
  );
  check(
    "Exif_usercomment_string.tif",
    "Exif_usercomment_string.tif.n.json",
    false,
  );
}
#[test]
fn exif_usercomment_unicode_conformance() {
  // PR #36 Codex R5 F1 — a BIG-ENDIAN (MM) TIFF whose ExifIFD UserComment
  // carries a `UNICODE\0`-prefixed UTF-16 payload written LITTLE-ENDIAN with
  // NO BOM (the MicrosoftPhoto case, Exif.pm:5582-5583). `ConvertExifText`
  // calls `Decode($str,'UTF16','Unknown')`, which seeds the order from
  // `GetByteOrder()` (MM) then FLIPS to LE via the Charset.pm:213-234
  // distribution heuristic. Bundled emits `ExifIFD:UserComment` = "MANUAL" —
  // proving the EXIF byte order is threaded to the ExifIFD UserComment, not
  // just the GPS text tags. Verified against bundled `perl exiftool`
  // 2026-05-22.
  check(
    "Exif_usercomment_unicode.tif",
    "Exif_usercomment_unicode.tif.json",
    true,
  );
  check(
    "Exif_usercomment_unicode.tif",
    "Exif_usercomment_unicode.tif.n.json",
    false,
  );
}
#[test]
fn geotiff_real_conformance() {
  // The REAL ExifTool `t/images/GeoTiff.tif` — a big-endian (MM) TIFF carrying
  // the GeoKey directory (`Image::ExifTool::GeoTiff`'s `ProcessGeoTiff`). It
  // exercises the IFD0 `ModelTransform` double[16] leaf AND the GeoKeys decoded
  // from all three blocks: inline int16u (`GTModelType` 1024 → "Projected",
  // `GeographicType` 2048 → "User Defined"), `GeoTiffAsciiParams` strings
  // (`GeogCitation`/`PCSCitation` → "Hough UTM zone 17N"),
  // `GeoTiffDoubleParams` doubles (`GeogSemiMajorAxis` 6378270 /
  // `GeogSemiMinorAxis` 6356794.343479), the synthetic `GeoTiffVersion` "1.1.0",
  // AND the GIANT `Projection` table (16017 → "UTM zone 17N"). The three
  // `Binary => 1` block tags (0x87af/0x87b0/0x87b1) are CAPTURED + decoded but
  // never emitted (no `RequestAll`). Verified byte-exact vs bundled `perl
  // exiftool 13.59 -j -G1` (`-j` PrintConv labels; `-n` the raw GeoKey ints).
  //
  // `IFD0:ColorMap` (0x0140, the RGB palette this image carries) is now PORTED
  // (a `Format => 'binary'`, `Binary => 1` tag in `%Exif::Main`, `Exif.pm:961`)
  // and emits bundled's `"(Binary data 1536 bytes, use -b option to extract)"`
  // placeholder under IFD0 — so it is compared byte-exactly like every other
  // GeoTiff tag (and the `IFD0:ModelTransform` leaf), no exclusion (#428).
  check("GeoTiff.tif", "GeoTiff.tif.json", true);
  check("GeoTiff.tif", "GeoTiff.tif.n.json", false);
}
#[test]
fn geotiff_mini_conformance() {
  // A CRAFTED minimal little-endian TIFF exercising all three GeoKey `loc`
  // source paths in one directory (`GeoTiff.pm:2176-2185`):
  //   * `GTModelType` (1024) — loc=0, an inline int16u → "Projected" PrintConv;
  //   * `GeogCitation` (2049) — loc=0x87b1, a `GeoTiffAsciiParams` string
  //     ("WGS 84|", the trailing `|` terminator stripped → "WGS 84");
  //   * `GeogSemiMajorAxis` (2057) — loc=0x87b0, a `GeoTiffDoubleParams` double
  //     (6378137).
  // Plus the IFD0 `PixelScale` (double[3] "10 10 0") and `ModelTiePoint`
  // (double[6] "0 0 0 100 200 0") leaf tags and the synthetic `GeoTiffVersion`
  // "1.1.0". Proves the inline/double/string dispatch + the `|`-terminator
  // strip. Byte-exact vs bundled 13.59.
  check("GeoTiff_mini.tif", "GeoTiff_mini.tif.json", true);
  check("GeoTiff_mini.tif", "GeoTiff_mini.tif.n.json", false);
}
#[test]
fn geotiff_projcs_conformance() {
  // A CRAFTED minimal LE TIFF whose GeoKeyDirectory carries
  // `ProjectedCSType` = 32617 (an inline int16u GeoKey) — PROVING the GIANT
  // ~993-row `ProjectedCSType` table resolves 32617 → "WGS84 UTM zone 17N"
  // (`-j`) and the raw 32617 (`-n`), alongside `GTModelType` 1 → "Projected"
  // and `GTRasterType` 1 → "Pixel Is Area". Byte-exact vs bundled 13.59.
  check("GeoTiff_projcs.tif", "GeoTiff_projcs.tif.json", true);
  check("GeoTiff_projcs.tif", "GeoTiff_projcs.tif.n.json", false);
}
#[test]
fn geotiff_bigtiff_conformance() {
  // A CRAFTED minimal little-endian BigTIFF (`0x002B`, 8-byte offsets/counts)
  // carrying the SAME GeoKey blocks as `GeoTiff_mini.tif` (GeoKeyDirectory +
  // GeoDoubleParams + GeoAsciiParams + PixelScale + ModelTiePoint). It pins the
  // BigTIFF-specific GeoTiff handling: `ProcessGeoTiff` is UNREACHABLE for a
  // BigTIFF (`DoProcessTIFF`'s `$identifier == 0x2b` arm `return 1`s at
  // `ExifTool.pm:8668`, BEFORE the `:8740` `ProcessGeoTiff` call; `BigTIFF.pm`
  // has no GeoTiff reference), so a BigTIFF GeoTIFF emits NO `GeoTiff:*` GeoKeys.
  // Instead the three `Binary => 1` block tags survive as `(Binary data N bytes
  // …)` placeholders under IFD0 (the `ProcessGeoTiff` `DeleteTag` cleanup that
  // removes them on the classic path never runs). The byte count is the
  // post-`ReadValue` `$val` length — `ProcessBigIFD` joins the int16u/double
  // array with the ON-DISK format (no `Format => 'undef'` override) and 0x87af/
  // 0x87b0's `RawConv => '$val . GetByteOrder()'` appends the 2-byte order tag:
  //   * GeoTiffDirectory  = len("1 1 0 3 …")+2 = 50,
  //   * GeoTiffDoubleParams = len("6378137")+2 = 9,
  //   * GeoTiffAsciiParams  = len("WGS 84|")   = 7.
  // Byte-exact vs bundled ExifTool 13.59 (`-j` and `-n`).
  check("GeoTiff_bigtiff.tif", "GeoTiff_bigtiff.tif.json", true);
  check("GeoTiff_bigtiff.tif", "GeoTiff_bigtiff.tif.n.json", false);
}
#[test]
fn bigtiff_colormap_conformance() {
  // A CRAFTED minimal little-endian BigTIFF (`0x002B`, 8-byte offsets/counts)
  // carrying an IFD0 `ColorMap` (0x0140) `int16u[3*2^BitsPerSample]` RGB palette
  // (BitsPerSample=2 → int16u[12]). It pins the BigTIFF-specific ColorMap
  // Binary-placeholder byte count (#428 Codex [medium]): `ColorMap` is `Format
  // => 'binary'`, `Binary => 1` (`Exif.pm:961-965`). On the CLASSIC path
  // `ProcessExif` applies the `'binary'` (= `undef`) `Format` override so the
  // value re-reads as raw bytes and the `(Binary data N bytes …)` placeholder
  // reports the ON-DISK byte length (GeoTiff.tif: int16u[768] → 1536). A BigTIFF
  // does NOT apply that override: `ProcessBigIFD` `ReadValue`s with the on-disk
  // `int16u` (`BigTIFF.pm:122`) and `HandleTag`s the resulting space-joined
  // `$val`, so `Binary => 1` reports `length(join(' ', @vals))` — NOT 2*N, NOT
  // the classic undef reshape. For the `0 0 0 21845 0 0 0 21845 0 65535 65535
  // 65535` palette that is 43 bytes. Byte-exact vs bundled ExifTool 13.59
  // (`-j` and `-n`); the classic `GeoTiff.tif` (1536) stays unchanged.
  check("BigTIFF_colormap.tif", "BigTIFF_colormap.tif.json", true);
  check("BigTIFF_colormap.tif", "BigTIFF_colormap.tif.n.json", false);
}
#[test]
fn gps_conformance() {
  // FORMATS.md row 14: Image::ExifTool::GPS. The GPS IFD is a standard Exif
  // sub-IFD reached through the IFD0 `GPSInfo` tag (0x8825, Exif.pm:2130-
  // 2141); the Exif IFD walker decodes it with the `%GPS::Main` tag table.
  //
  // Fixture `tests/fixtures/ExifGPS.tif` is a SYNTHESIZED minimal standalone
  // TIFF with IFD0 + a GPS sub-IFD, generated by `tools/gen_exif_fixtures.py`.
  // It exercises the GPS sub-IFD decode in isolation. Codex R16/F1: this
  // synthetic-TIFF-only test MASKED the real product gap — a camera JPEG
  // (the primary camera-photo format) was never routed to the Exif walker.
  // The real-input coverage is now `jpeg_exif_gps_conformance` below, which
  // pins the full Make/Model/DateTime + GPS extraction from the bundled
  // GPS-bearing JPEG `t/images/GPS.jpg` (committed as `ExifGPS.jpg`).
  //
  // Little-endian (II) header; exercises:
  //   - the GPS SubIFD dispatch via tag 0x8825
  //   - GPSVersionID `tr/ /./` int8u-quadruple PrintConv (GPS.pm:61)
  //   - GPSLatitude/GPSLongitude `%coordConv` — ToDegrees ValueConv
  //     (D/M/S rationals → decimal degrees, GPS.pm:582-601), ToDMS
  //     PrintConv (`D deg M' S"`, GPS.pm:495-573)
  //   - GPSLatitudeRef/GPSLongitudeRef `%printConvLatRef`/`%printConvLonRef`
  //     (N→North, E→East — GPS.pm:22-48)
  //   - GPSTimeStamp ConvertTimeStamp + PrintTimeStamp (GPS.pm:455-487)
  //   - GPSDateStamp ExifDate (Exif.pm:6068-6076)
  //   - GPSAltitude `"$val m"` + GPSAltitudeRef hash
  // Goldens: bundled `perl exiftool -j -G1 -struct` (`-n` too), `System:*`
  // stripped. The five ported GPS `Composite:*` (`GPSLatitude`/`Longitude`/
  // `Altitude`/`DateTime`/`Position`, #133 PR 2) ARE retained — this fixture
  // carries ONLY GPS Composites, so no `Composite:*` exclusion is needed
  // (`tools/gen_golden.sh` default path).
  check("ExifGPS.tif", "ExifGPS.tif.json", true);
  check("ExifGPS.tif", "ExifGPS.tif.n.json", false);
}
#[test]
fn jpeg_exif_gps_conformance() {
  // Codex R16/F1 — THE core product capability: a real camera JPEG must read
  // its Exif/GPS. Fixture `tests/fixtures/ExifGPS.jpg` IS the bundled
  // `lib/Image/ExifTool/t/images/GPS.jpg` (2133 bytes, FUJIFILM FinePixS1Pro
  // with a GPS sub-IFD), the canonical GPS-bearing JPEG ExifTool ships.
  //
  // This exercises the JPEG container front-end (`src/exif/jpeg.rs`): the
  // marker walk from SOI (`\xff\xd8`), the `APP1` (`0xe1`) Exif arm matching
  // `^(.{0,4})Exif\0.` (ExifTool.pm:7739), stripping the 6-byte `Exif\0\0`
  // header (ExifTool.pm:7780 `DirStart(…, $hdrLen, $hdrLen)`) and handing the
  // embedded TIFF block to `ProcessTIFF` → `ProcessExif` (ExifTool.pm:7783)
  // via `exif::parse_exif_block_with_base`. The TIFF-block file offset is
  // passed as ExifTool's `$base` so `IsOffset` tags (`ThumbnailOffset`
  // 0x0201, `IsOffset => 1`, Exif.pm:1169) are rebased to absolute file
  // offsets (Exif.pm:7156-7170) — the golden's `IFD1:ThumbnailOffset` is
  // 1050, matching bundled (= the raw 1038 + the 12-byte base: SOI 2 + APP1
  // marker/len 4 + `Exif\0\0` 6).
  //
  // Asserts byte-exact (value-equivalent) extraction of Make / Model /
  // ModifyDate / DateTimeOriginal AND the full GPS block (lat/lon/ref/
  // timestamp/mapdatum/versionid), plus IFD0/ExifIFD/IFD1 + File:ExifByteOrder
  // and the File:* JPEG triplet.
  //
  // Goldens are bundled `tools/gen_golden.sh` output with `System:*` stripped.
  // The ported GPS `Composite:*` (`GPSLatitude`/`Longitude`/`Position`, #133 PR
  // 2) ARE retained (this file has GPS lat/lon but no altitude/datestamp, so
  // those two GPS Composites do not build); the still-deferred camera
  // Composites (`Aperture`/`ImageSize`/`Megapixels`/`ShutterSpeed`/
  // `FocalLength35efl`, a later #133 PR) are excluded by name in
  // `tools/gen_golden.sh`, alongside the JPEG-port-deferred IPTC/thumbnail.
  // The `SOF` size tags (`File:ImageWidth`/`ImageHeight`/`BitsPerSample`/
  // `ColorComponents`/`EncodingProcess`/`YCbCrSubSampling`,
  // ExifTool.pm:7419-7462) are NOW EMITTED (#261) — this file's
  // `120x80 / Baseline DCT, Huffman coding / 8 / 3 / YCbCr4:2:0 (2 2)` SOF0 is
  // byte-identical to bundled and part of this golden. Still DEFERRED (a
  // JPEG-container follow-up — see `docs/tracking.md`): the APP13
  // Photoshop/IPTC segment (`IPTC:*` + `File:CurrentIPTCDigest`,
  // ExifTool.pm:7861) and the binary `IFD1:ThumbnailImage` body (offset/length
  // ARE extracted). The Exif/GPS + SOF arms of `ProcessJPEG` are ported; the
  // remaining segments are out of scope.
  check("ExifGPS.jpg", "ExifGPS.jpg.json", true);
  check("ExifGPS.jpg", "ExifGPS.jpg.n.json", false);
}
#[test]
fn jpeg_malformed_app1_exif_conformance() {
  // PR #36 Codex R17/F1 — a valid JPEG whose `APP1` `Exif\0\0` segment is NOT
  // a valid TIFF block (`Exif\0\0` + the literal bytes `GARBAGE-not-a-tiff-
  // block`), followed by `SOS` + `EOI`.
  //
  // Bundled `ProcessJPEG` SPLITS container acceptance from Exif extraction:
  // `$self->SetFileType()` runs at ExifTool.pm:7304 — BEFORE the `Marker:`
  // loop and INDEPENDENTLY of the `APP1` Exif arm — so the file is finalized
  // `File:FileType == "JPEG"` / `image/jpeg`. The `APP1` segment matches the
  // Exif arm `^(.{0,4})Exif\0.` (ExifTool.pm:7739) but `ProcessTIFF` fails on
  // the garbage block, yielding `$self->Warn('Malformed APP1 EXIF segment')`
  // (ExifTool.pm:7783) — a NON-FATAL warning, not a container rejection.
  //
  // Pre-fix, the engine treated the JPEG candidate's `Ok(None)` (no usable
  // Exif) as a candidate REJECTION, so this file fell through to a
  // finalization Error instead of being accepted as a JPEG. The golden — the
  // `File:*` JPEG triplet + `ExifTool:Warning: "Malformed APP1 EXIF segment"`,
  // with NO `File:ExifByteOrder` (no TIFF block was processed) — is bundled
  // `tools/gen_golden.sh` output and confirms the accept-and-warn behavior.
  check(
    "JPEG_malformed_app1_exif.jpg",
    "JPEG_malformed_app1_exif.jpg.json",
    true,
  );
  check(
    "JPEG_malformed_app1_exif.jpg",
    "JPEG_malformed_app1_exif.jpg.n.json",
    false,
  );
}
#[test]
fn jpeg_two_independent_app1_exif_conformance() {
  // PR #36 Codex R17/F2 — a JPEG carrying TWO independent `APP1` Exif blocks,
  // each a self-contained little-endian TIFF (`Exif\0\0II\x2a\0…`): block 1's
  // IFD0 holds `Make = "Canon"`, block 2's IFD0 holds `Model = "EOS5D"`.
  //
  // Bundled's `APP1` Exif arm processes a segment and ends with `next`
  // (ExifTool.pm:7821): the `Marker:` loop CONTINUES, so a later INDEPENDENT
  // `APP1` Exif segment still contributes its tags. Bundled's extended-EXIF
  // discriminator (ExifTool.pm:7764-7765 — an `APP1` Exif followed by an
  // `APP1` whose payload is `^Exif\0\0` NOT followed by a TIFF magic) does NOT
  // fire here because each block begins `Exif\0\0II\x2a\0` (a real TIFF
  // magic), so the pair is two independent blocks, not a multi-segment chain.
  //
  // Pre-fix, `parse_jpeg_exif` returned immediately after the FIRST `APP1`
  // Exif parsed, dropping `IFD0:Model` from the second block. The golden — the
  // `File:*` triplet + `File:ExifByteOrder` + `IFD0:Make` + `IFD0:Model`,
  // bundled `tools/gen_golden.sh` output — confirms both blocks contribute.
  check(
    "JPEG_two_app1_exif.jpg",
    "JPEG_two_app1_exif.jpg.json",
    true,
  );
  check(
    "JPEG_two_app1_exif.jpg",
    "JPEG_two_app1_exif.jpg.n.json",
    false,
  );
}
#[test]
fn jpeg_unknown_header_conformance() {
  // PR #36 Codex R18/F2 — a valid JPEG preceded by a 4-byte unknown header
  // (`JUNK` + `\xff\xd8` + an `APP1` Exif block). Synthetic fixture from
  // `tools/gen_exif_fixtures.py::make_jpeg_unknown_header`.
  //
  // The file-type detector's terminal candidate (`ExifTool.pm:3026-3034`)
  // scans PAST the unknown header for `\xff\xd8\xff`, sets the type to JPEG,
  // and `Warn`s `Processing JPEG-like data after unknown 4-byte header`. The
  // detector records `$dirInfo{Base} = $pos + $skip` (`ExifTool.pm:3030`);
  // after `ProcessJPEG` succeeds, bundled `DeleteTag`s the WHOLE `File:*`
  // triplet — `FileType` / `FileTypeExtension` / `MIMEType` — ("Reset file
  // type due to unknown header", `ExifTool.pm:3069-3073`).
  //
  // Pre-fix, exifast's Exif dispatch accepted a JPEG only when its `SOI` was
  // at byte 0, so this file was detected as a JPEG candidate then mis-rejected
  // into a `File format error`. The fix threads the candidate's `header_skip`
  // into `parse_any`: the JPEG body is sliced at `bytes[header_skip..]` and
  // the embedded Exif `Base` is rebased by `header_skip`. The golden's
  // `IFD1:ThumbnailOffset` is 90 — the raw IFD value 74 PLUS the TIFF block's
  // file offset 16 (4 junk + 2 `SOI` + 4 `APP1` hdr + 6 `Exif\0\0`), proving
  // the `IsOffset` rebase still spans the skipped header — and the rebased
  // `IFD1:ThumbnailImage` blob (`90 + 4 = 94`) lands inside the EXIF buffer, so
  // the #331 `DataTag` channel emits the `(Binary data 4 bytes …)` placeholder.
  // The golden is now PLAIN `tools/gen_golden.sh` output (the old hand-trim that
  // removed the deferred `IFD1:ThumbnailImage` body is obsolete — it is emitted
  // faithfully); it still carries NO `File:*` triplet (bundled `DeleteTag`s it
  // for the unknown-header case), only the recovered Exif tags + the
  // `IFD1:ThumbnailImage` + the unknown-header `Warning`.
  check(
    "JPEG_unknown_header.jpg",
    "JPEG_unknown_header.jpg.json",
    true,
  );
  check(
    "JPEG_unknown_header.jpg",
    "JPEG_unknown_header.jpg.n.json",
    false,
  );
}

#[test]
#[ignore = "port gap: DJI MakerNote / MPF / JFIF / Composite; see #109"]
fn dji_thermal_rjpeg_conformance() {
  // DJI Mavic 3 Thermal (M3T) radiometric JPEG from HuggingFace STRDrones/DJI
  // dataset. Contains DJI MakerNote with thermal data (ThermalData, Emissivity,
  // AmbientTemperature, ObjectDistance, RelativeHumidity, ReflectedTemperature,
  // ThermalCalibration, SensorID). Unblocks #109.
  check("DJI_M3T_thermal.RJPEG", "DJI_M3T_thermal.RJPEG.json", true);
  check(
    "DJI_M3T_thermal.RJPEG",
    "DJI_M3T_thermal.RJPEG.n.json",
    false,
  );
}

#[test]
fn dji_matrice30t_conformance() {
  // DJI Matrice 30T (M30T) thermal JPEG from HuggingFace STRDrones/DJI dataset
  // (#114). Matrice-series enterprise thermal drone. The JPEG carries metadata
  // in NINE markers beyond the `APP1` Exif block, all now ported
  // (`src/exif/jpeg_app.rs` + the 3 standard-EXIF tags below):
  //   - APP0 JFIF (`%JFIF::Main`): `JFIFVersion`/`ResolutionUnit`/`X`/`YResolution`.
  //   - APP2 MPF (`%MPF::Main` TIFF IFD + `%MPF::MPImage` binary sub-dir): the
  //     `MPFVersion`/`NumberOfImages`/`ImageUIDList`/`TotalFrames` header + the
  //     two `MPImage<N>` entries (`MPImageFlags` BITMASK / `MPImageFormat` /
  //     `MPImageType` PrintHex / `MPImageLength` / the `IsOffset`-rebased
  //     `MPImageStart` / `DependentImage1/2EntryNumber`), and the first Large
  //     Thumbnail re-extracted as `MPImage2:PreviewImage` (`ExtractMPImages`).
  //   - APP3 `DJI:ThermalData` (the multi-segment combined raw thermal frame,
  //     `JPEG.pm:113`) + APP5 `DJI:ThermalCalibration` (`JPEG.pm:174`), binary.
  //   - APP4 `%DJI::ThermalParams2` (`DJI.pm:123`): `AmbientTemperature`/
  //     `ObjectDistance`/`Emissivity`/`RelativeHumidity`/`ReflectedTemperature`/
  //     `IDString` (the M3T/M30T thermal floats).
  //   - APP7 `DJI-DBG\0` → `%DJI::Info` `ProcessDJIInfo` → `DJI:SensorID`.
  // Plus the standard-EXIF gaps the golden carries: `IFD0:XPComment`/
  // `XPKeywords` (Windows XP UCS-2(LE), `Exif.pm:2643`/`:2661`),
  // `ExifIFD:DeviceSettingDescription` (`Binary => 1`, 0xa40b) and
  // `ExifIFD:MakerNoteUnknownText` (the `@MakerNotes::Main` printable-text
  // fallback — the 0x927c blob is the literal `"DJI MakerNotes"` text, which
  // starts `DJI` so the `MakerNoteDJI` arm's negative lookahead excludes it).
  //
  // The goldens are generated with `gen_golden.sh EXCLUDE="-x Composite:all -x
  // IFD1:ThumbnailImage"`:
  //   -x Composite:all   — exifast has no EXIF Composite subsystem (drops the
  //                        9 `Composite:*` camera-synthesis tags: Aperture/DOF/
  //                        FOV/FocalLength35efl/HyperfocalDistance/ImageSize/
  //                        Megapixels/ScaleFactor35efl/CircleOfConfusion).
  //   -x IFD1:ThumbnailImage — the embedded-thumbnail binary placeholder is a
  //                        `%Exif::Composite` tag (re-grouped to EXIF/IFD1), the
  //                        SAME documented engine-wide gap the DJIPhantom4 /
  //                        Pentax / Nikon goldens drop (the `ThumbnailOffset`/
  //                        `Length` ARE kept). `MPImage2:PreviewImage` (an MPF
  //                        family-0 tag, not Composite) IS emitted.
  // All 90 remaining tags match for BOTH the `-j` PrintConv and `-n` numeric
  // snapshots (byte-exact, the token-exact `json_equivalent_strict` gate).
  check("DJI_Matrice30T.jpg", "DJI_Matrice30T.jpg.json", true);
  check("DJI_Matrice30T.jpg", "DJI_Matrice30T.jpg.n.json", false);
}

#[test]
#[ignore = "port gap: XMP-GPano / Composite; see #92"]
fn insta360_equirectangular_conformance() {
  // Insta360 ONE stitched equirectangular 360° photo from GitHub
  // hakanson/Insta360-images-20180318. Contains XMP-GPano metadata
  // (ProjectionType=equirectangular, CaptureSoftware, StitchingSoftware).
  // Unblocks #92 (spherical projection metadata).
  check(
    "Insta360ONE_equirectangular.jpg",
    "Insta360ONE_equirectangular.jpg.json",
    true,
  );
  check(
    "Insta360ONE_equirectangular.jpg",
    "Insta360ONE_equirectangular.jpg.n.json",
    false,
  );
}

#[test]
fn xmp_base64_control_byte_split_conformance() {
  // Codex R3 F1 regression: `rdf:datatype="base64"` decoded payloads keep
  // ExifTool's binary/text split (XMP.pm:3646-3647 —
  // `$val = $$val unless length $$val > 100 or
  // $$val =~ /[\0-\x08\x0b\x0e-\x1f]/`). Single control bytes NUL (0x00),
  // vertical-tab (0x0b) and shift-out (0x0e) stay BINARY ⇒ the
  // `(Binary data 1 bytes, …)` placeholder; tab/LF/CR (not in the control
  // class — `\x0c` is excluded too, the Perl `\0x0c` token being `\0` +
  // literal `x0c`) and "hello" stay TEXT. Oracle (bundled `perl exiftool`
  // 13.58, captured 2026-05-22).
  check("XMP_base64_ctrl.xmp", "XMP_base64_ctrl.xmp.json", true);
  check("XMP_base64_ctrl.xmp", "XMP_base64_ctrl.xmp.n.json", false);
}

#[test]
fn xmp_base64_binary_payload_conformance() {
  // Codex R3 F1 regression: a `<=100`-byte non-UTF-8 JPEG header
  // (`FF D8 FF E0`) decodes to LOSSY TEXT `"????"` (no control bytes, length
  // <= 100, so `$$val` is a string; the invalid UTF-8 is replaced with `?`
  // by `EscapeJSON`/`FixUTF8` at JSON time), while a `>100`-byte payload
  // stays BINARY regardless of contents. Before the fix the bytes were forced
  // through `String::from_utf8` and either coerced to a NUL string or, on
  // failure, left as un-decoded base64 text. Oracle (bundled `perl exiftool`
  // 13.58, captured 2026-05-22).
  check("XMP_base64_binary.xmp", "XMP_base64_binary.xmp.json", true);
  check(
    "XMP_base64_binary.xmp",
    "XMP_base64_binary.xmp.n.json",
    false,
  );
}

#[test]
fn xmp_base64_malformed_payload_conformance() {
  // Codex R4 F1 regression: `DecodeBase64` (XMP.pm:2981) NEVER fails — it
  // truncates the input at the first byte outside the allow-list
  // `[A-Za-z0-9+/= \t\n\r\f]` (XMP.pm:2988) and decodes the surviving prefix
  // (XMP.pm:2990, partial groups included), so malformed payloads are decoded
  // rather than emitted as the literal undecoded base64 text. Cases:
  //   trailingJunk  `aGVsbG8=#junk` → "hello" (`#` and the rest dropped),
  //   vtabTruncate  `aGVs<VT>bG8=`  → "hel"   (VT 0x0b is NOT in the
  //                 allow-list, so it truncates; only `aGVs` survives),
  //   noPadding     `aGVsbG8`       → "hello" (partial trailing group decode).
  // Before the fix the decoder returned `None` on the first invalid byte and
  // the caller fell back to the raw base64 string. Oracle (bundled
  // `perl exiftool` 13.58, captured 2026-05-22).
  check(
    "XMP_base64_malformed.xmp",
    "XMP_base64_malformed.xmp.json",
    true,
  );
  check(
    "XMP_base64_malformed.xmp",
    "XMP_base64_malformed.xmp.n.json",
    false,
  );
}

#[test]
fn xmp_base64_escaped_payload_conformance() {
  // Codex R5 F1 regression: Perl decodes the RAW (still XML-escaped) value
  // FIRST — `$val = DecodeBase64($val)` (XMP.pm:3645) — and only THEN
  // un-escapes the decoded text (XMP.pm:3655-3669). Un-escaping before the
  // base64 decode is wrong:
  //   escTruncate `aGVs&#x62;G8=` → "hel"  (the `&` is outside the base64
  //               allow-list, so DecodeBase64 truncates at `aGVs`; un-escaping
  //               `&#x62;`→`b` first would wrongly rebuild `aGVsbG8=` → "hello"),
  //   escAmp      `YSZhbXA7Yg==`  → "a&b"  (decodes to the bytes `a&amp;b`,
  //               which the post-decode UnescapeXML turns into `a&b`; the buggy
  //               pre-decode order stored the raw `a&amp;b`).
  // Oracle (bundled `perl exiftool` 13.58, captured 2026-05-22).
  check(
    "XMP_base64_escaped.xmp",
    "XMP_base64_escaped.xmp.json",
    true,
  );
  check(
    "XMP_base64_escaped.xmp",
    "XMP_base64_escaped.xmp.n.json",
    false,
  );
}

#[test]
fn xmp_multiline_comment_preserved_conformance() {
  // Codex R1 F1: both leaf comment-strip sites run `s/<!--.*?-->//g` with NO
  // `/s` flag (XMP.pm:4180 rdf:Description, :4182 `$wasComment` scalar), so a
  // `<!--…-->` whose minimal body up to the first `-->` crosses an LF is left
  // VERBATIM; only single-line comments are removed (per-comment, leftmost
  // resume). The fixture exercises BOTH paths:
  //   scalar (`$wasComment`):  dc:Title `aaa<!-- one line -->bbb` → `aaabbb`;
  //                            dc:Source `ccc<!--\nML\n-->ddd` preserved;
  //                            dc:Coverage `x<!-- a -->y<!--\nz\n-->w` →
  //                            `xy<!--\nz\n-->w` (single stripped, multi kept);
  //   rdf:Description literal: a nested `<rdf:Description>` value
  //                            `  pre<!-- gone -->mid<!--\nkept\n-->post  `
  //                            → `premid<!--\nkept\n-->post` (single stripped,
  //                            multi kept, surrounding whitespace trimmed).
  // Oracle: bundled `perl exiftool` 13.59 (version pinned 13.58 to match the
  // engine's hard-coded ExifToolVersion, like every committed XMP golden).
  check(
    "XMP_comment_multiline.xmp",
    "XMP_comment_multiline.xmp.json",
    true,
  );
  check(
    "XMP_comment_multiline.xmp",
    "XMP_comment_multiline.xmp.n.json",
    false,
  );
}

#[test]
fn xmp_cdata_unclosed_falls_back_to_unescape_conformance() {
  // Codex R1 F2: the CDATA-special un-escape path activates ONLY when a
  // COMPLETE `<![CDATA[ … ]]>` pair exists (XMP.pm:3657
  // `if ($val =~ /<!\[CDATA\[(.*?)\]\]>/sg)` — `]]>` is mandatory). An opening
  // marker with NO close is NOT special: the WHOLE value (literal `<![CDATA[`
  // text included) goes through `UnescapeXML` (XMP.pm:3669). Both values are
  // `rdf:datatype="base64"` text payloads (no control bytes / no `x`,`0`,`c` →
  // the binary guard keeps them text):
  //   cdataUnclosed `pre<![CDATA[a&amp;b`            → `pre<![CDATA[a&b`
  //                 (marker kept literal, `&amp;`→`&` over the whole value);
  //   cdataComplete `A<![CDATA[in&amp;side]]>out&amp;Y` → `Ain&amp;sideout&Y`
  //                 (CDATA body verbatim, surrounding text un-escaped).
  // Oracle: bundled `perl exiftool` 13.59 (version pinned 13.58 as above).
  check(
    "XMP_cdata_unclosed.xmp",
    "XMP_cdata_unclosed.xmp.json",
    true,
  );
  check(
    "XMP_cdata_unclosed.xmp",
    "XMP_cdata_unclosed.xmp.n.json",
    false,
  );
}

#[test]
fn xmp_stray_lt_in_text_conformance() {
  // Codex R3-A: the close-scan regex (XMP.pm:3836
  // `<(?:(/?)\Q$prop\E([-\w:.\x80-\xff]*)(.*?(/?))>|(!\[CDATA\[|!--))`/sg) is
  // UNANCHORED — a `<` that does NOT begin `[/]?\Q$prop\E…>` (here the stray
  // `<` in `dc:title` text `bad < text`) is skipped ONE byte by the `/g`
  // engine, NOT consumed through the next `>`. The previous port skipped any
  // irrelevant `<…>` THROUGH its `>`, swallowing the real `</dc:title>` and
  // dropping Title AND the following `dc:format` sibling. Both must survive:
  //   Title="bad < text", Format="image/jpeg".
  // Oracle: bundled `perl exiftool` 13.59 (version pinned 13.58).
  check("XMP_stray_lt.xmp", "XMP_stray_lt.xmp.json", true);
  check("XMP_stray_lt.xmp", "XMP_stray_lt.xmp.n.json", false);
}

#[test]
fn xmp_close_extra_name_conformance() {
  // Codex R3-A: `$2` = the name-EXTENSION chars after the exact prop name;
  // `next if $2` (XMP.pm:3853) ignores a token whose name merely STARTS with
  // the prop — `</dc:titleExtra>` does NOT close `dc:title`. So the close is
  // the LATER `</dc:title>` and the literal value keeps the verbatim text
  // INCLUDING the ignored `</dc:titleExtra>`:
  //   Title="real</dc:titleExtra> still", Format="image/png".
  // (The previous port treated any `</dc:title…>` prefix-match as the close,
  // ending the element early at `</dc:titleExtra>`.)
  // Oracle: bundled `perl exiftool` 13.59 (version pinned 13.58).
  check("XMP_close_extra.xmp", "XMP_close_extra.xmp.json", true);
  check("XMP_close_extra.xmp", "XMP_close_extra.xmp.n.json", false);
}

#[test]
fn xmp_nodeid_blank_node_conformance() {
  // Codex R3-B: `rdf:nodeID` blank-node resolution (SaveBlankInfo /
  // ProcessBlankInfo, WriteXMP.pl:433/465). A subject element
  // `<exif:Flash rdf:nodeID="n1"/>` + a blank node
  // `<rdf:Description rdf:nodeID="n1"><exif:Fired>…<exif:Mode>…` must
  // RECOMBINE into the structured `XMP-exif:Flash = {Fired, Mode}` — the
  // subject's `…/rdf:Description/exif:Flash` PREFIX (kept by the
  // `unless $prop eq rdf:Description` rule + selected by the
  // `$pre =~ m{/rdf:Description/}` filter) joined with the `/exif:Fired`,
  // `/exif:Mode` SUFFIXES. The previous port dropped the `exif:Flash` level,
  // emitting a flat `Fired`/`Mode` (and `Mode` missed its `On` PrintConv for
  // lack of the `Flash` struct parent). ExifTool also derives `Composite:Flash`
  // and System:* tags, which this XMP-only port does not emit (so the trimmed
  // golden omits them, as every XMP golden omits System:*).
  // Oracle structure: bundled `perl exiftool` 13.59 (version pinned 13.58).
  check("XMP_nodeid_flash.xmp", "XMP_nodeid_flash.xmp.json", true);
  check("XMP_nodeid_flash.xmp", "XMP_nodeid_flash.xmp.n.json", false);
}

#[test]
fn xmp_noncanonical_prefix_conformance() {
  // Codex R6 F1 regression: `FoundXMP` reads `rdf:datatype`/`et:encoding`
  // (XMP.pm:3644) and `xml:lang` (XMP.pm:3497) from the `%attrs` HASH —
  // whose keys are namespace-NORMALIZED by the attribute loop's
  // `$attr = $$xlatNS{$1} . substr(...)` (XMP.pm:3976). So a noncanonical
  // RDF prefix still hits the base64 decode path:
  //   `xmlns:r="…22-rdf-syntax-ns#"` + `r:datatype="base64"`
  //     `aGVsbG8=` → "hello",  `/9j/4A==` → binary JPEG header "????",
  //   canonical `rdf:datatype="base64"` → `d29ybGQ=` → "world".
  // Before the fix the lookup scanned the RAW attribute text for a literal
  // `rdf:datatype`, missed it, and emitted the undecoded base64 string.
  // The `rdf:value`/`resource`/`about` fallback (XMP.pm:4186) is the
  // OPPOSITE — it matches the RAW `$attrs` string with a literal `\brdf:`,
  // so a noncanonical `r:resource` does NOT trigger it (Link stays "").
  // Oracle (bundled `perl exiftool` 13.58, captured 2026-05-22).
  check("XMP_ncprefix.xmp", "XMP_ncprefix.xmp.json", true);
  check("XMP_ncprefix.xmp", "XMP_ncprefix.xmp.n.json", false);
}

#[test]
fn xmp_rdf_resource_spaced_conformance() {
  // Codex R7 F1 regression: the empty-value fallback (XMP.pm:4185-4186)
  // matches the RAW `$attrs` string with the literal Perl regexes
  // `\brdf:(?:value|resource)=(['"])(.*?)\1` and `\brdf:about=(['"])...`.
  // Those regexes have NO `\s*` around the `=`, so an attribute written
  // with spaces — `rdf:resource = "…"` — does NOT match and the element
  // value stays empty. Reparsing via the general attribute scanner
  // (XMP.pm:3886 `(\S+?)\s*=\s*(['"])`) would wrongly tolerate the spaces
  // and emit the resource. `Link`/`ValSpaced` → "" (spaced `=`),
  // `LinkTight`/`ValTight` → their values (tight `=`).
  // Oracle (bundled `perl exiftool` 13.58, captured 2026-05-22).
  check(
    "XMP_rdf_resource_spaced.xmp",
    "XMP_rdf_resource_spaced.xmp.json",
    true,
  );
  check(
    "XMP_rdf_resource_spaced.xmp",
    "XMP_rdf_resource_spaced.xmp.n.json",
    false,
  );
}

#[test]
fn xmp_attr_junk_conformance() {
  // Codex R2 finding: the COMMON-branch attribute scanner (XMP.pm:3884-3900,
  // `length($attrs) < 2000`) reads attributes with an UNANCHORED `/g` regex in
  // a `for(;;)` loop: `$attrs =~ /(\S+?)\s*=\s*(['"])/g`. Because it is
  // unanchored, a junk token with no `=quote` after it is simply SKIPPED — the
  // engine advances to the next `name\s*=\s*quote` match. So in
  //   `rdf:about="" xmlns:dc="…" junk dc:title="Lost" dc:format="image/jpeg"`
  // the bare `junk` does NOT terminate the scan: `dc:title=Lost` and
  // `dc:format=image/jpeg` STILL extract. The pre-fix `iter_attrs` parsed
  // strictly left-to-right and `break`ed on the first malformed token, silently
  // dropping `dc:title` and every later attribute. The fix mirrors Perl's
  // left-to-right unanchored scan (advance past a malformed candidate, resume
  // searching for the next `\S+?\s*=\s*['"]` pair).
  // Oracle: bundled `perl exiftool` 13.59 (gen_golden.sh COMMON args).
  check("XMP_attr_junk.xmp", "XMP_attr_junk.xmp.json", true);
  check("XMP_attr_junk.xmp", "XMP_attr_junk.xmp.n.json", false);
}

#[test]
fn xmp_et_encoding_conformance() {
  // Codex R7 F2 regression: a NON-ignored shorthand attribute is removed
  // from `%attrs` (`delete $attrs{$shortName}`, XMP.pm:4133) once it has
  // been extracted as its own property, so the later
  // `FoundXMP(..., \%attrs)` (XMP.pm:4206) no longer sees it. `et:encoding`
  // (ns `et` — not in `%ignoreNamespace`, not in `%ignoreEtProp`, not in
  // `%recognizedAttrs`) IS extracted+deleted: it surfaces as its own tag
  // (`PayloadEncoding`) and the parent value stays RAW (`aGVsbG8=`, NOT
  // base64-decoded to "hello"). `rdf:datatype` (ns `rdf`) is caught by
  // `$ignoreNamespace{rdf}` (XMP.pm:4123) and never deleted, so it still
  // survives and drives the parent decode (`d29ybGQ=` → "world").
  // Oracle (bundled `perl exiftool` 13.58, captured 2026-05-22).
  check("XMP_et_encoding.xmp", "XMP_et_encoding.xmp.json", true);
  check("XMP_et_encoding.xmp", "XMP_et_encoding.xmp.n.json", false);
}

#[test]
fn xmp_li_1000_item_cap_conformance() {
  // Codex R8 F1 regression: `ParseXMPElement` imposes a reasonable maximum
  // on the number of items in a list (XMP.pm:3991-3999). At the 1001st
  // `rdf:li` (`$nItems == 1000`), the default read path — `exifast` has no
  // `IgnoreMinorErrors` option, so it is always the default path — raises a
  // minor warning `Warn("Extracted only 1000 $ns:$tg items. ...", 2)` and
  // `last`s out of the element loop, so exactly the first 1000 items are
  // extracted. `Warn(..., 2)` prepends the literal `[Minor] ` marker
  // (ExifTool.pm:5619). `$ns:$tg` is the namespace + raw tag id of the
  // enclosing path from `GetXMPTagID` BEFORE the `rdf:li` is pushed
  // (XMP.pm:3992-3994) — `dc:subject` for a `dc:subject`/`rdf:Bag` list.
  // Fixture `XMP_li_cap.xmp` has 1001 `<rdf:li>` keywords; oracle (bundled
  // `perl exiftool` 13.58, captured 2026-05-22) extracts `Subject` =
  // [kw1 .. kw1000] (1000 items, kw1001 dropped) and emits
  // `Warning: "[Minor] Extracted only 1000 dc:subject items. ..."`.
  check("XMP_li_cap.xmp", "XMP_li_cap.xmp.json", true);
  check("XMP_li_cap.xmp", "XMP_li_cap.xmp.n.json", false);
}

#[test]
fn xmp_svg_and_xml_inputs_are_not_misfinalized_as_xmp() {
  // Codex R8 F2 regression: `ProcessXMP` recognizes several XML flavours
  // and `SetFileType`s each separately — `<svg`-rooted / `<?xml`+`<svg`
  // ⇒ `SetFileType('SVG')` (image/svg+xml, the `SVG` tag table),
  // `<?xml`+`<plist` ⇒ the `PLIST` module, other `<?xml` ⇒
  // `SetFileType('XML')` (application/xml) — XMP.pm:4420-4427. The SVG /
  // PLIST / XML sub-ports are deferred (`docs/tracking.md`), so the XMP
  // parser REJECTS those inputs (`Ok(None)`) instead of mis-finalizing
  // them as FileType `XMP` / `application/rdf+xml`. An `.svg` file (the
  // extension dispatches to the `XMP` candidate) must therefore NOT come
  // out tagged `XMP`. Verified vs bundled `perl exiftool` 13.58
  // (2026-05-22): `test.svg` ⇒ `File:FileType` = `SVG`.
  let svg = br#"<?xml version="1.0" encoding="UTF-8"?>
<svg xmlns="http://www.w3.org/2000/svg" width="100" height="100">
  <title>Deferred SVG</title>
</svg>"#;
  for print_on in [true, false] {
    let out = extract_info("deferred.svg", svg, print_on);
    assert!(
      !out.contains("\"XMP\""),
      "SVG must not be mis-finalized as FileType XMP (R8/F2), got: {out}"
    );
    assert!(
      !out.contains("application/rdf+xml"),
      "SVG must not get the XMP MIME type (R8/F2), got: {out}"
    );
  }
  // A `<?xml`-rooted XMP sidecar (carrying `<x:xmpmeta>`) is still XMP.
  let xmp = br#"<?xml version="1.0"?>
<x:xmpmeta xmlns:x="adobe:ns:meta/">
 <rdf:RDF xmlns:rdf="http://www.w3.org/1999/02/22-rdf-syntax-ns#">
  <rdf:Description xmlns:dc="http://purl.org/dc/elements/1.1/">
   <dc:format>image/jpeg</dc:format>
  </rdf:Description>
 </rdf:RDF>
</x:xmpmeta>"#;
  let out = extract_info("sidecar.xmp", xmp, true);
  assert!(
    out.contains("\"File:FileType\":\"XMP\""),
    "a <?xml-rooted XMP sidecar must still finalize to XMP, got: {out}"
  );
}

#[test]
fn xmp_numeric_entity_overflow_and_surrogate_conformance() {
  // Codex R9/F2 regression: `UnescapeChar` (XMP.pm:2919-2936) resolves a
  // numeric reference, then emits it via `pack('C0U', $val)` (XMP.pm:2933) —
  // variable-length UTF-8 WITHOUT validity checks. For a code point above
  // U+10FFFF or in the surrogate range that yields malformed bytes, which the
  // downstream `Decode`/`FixUTF8` (XMP.pm:2943-2972) — reached at JSON-escape
  // time — replaces with ONE `?` per bad byte (NOT a single `?`, and NOT the
  // literal entity text). Bundled `perl exiftool` 13.58 (captured 2026-05-22):
  //   `A&#x100000000;B` → 7-byte loose-UTF-8 `FE 84 80 80 80 80 80` ⇒ "A???????B"
  //   `S&#xD800;E`      → 3-byte loose-UTF-8 `ED A0 80`            ⇒ "S???E"
  //   `over&#x110000;flow` → 4-byte `F4 90 80 80`                 ⇒ "over????flow"
  //   `good&#x100;point`   → `Ā` (U+0100, in range, valid)
  // The old port returned `None` from the overflow/surrogate parse and left
  // the literal `&#x…;` text. The fixture ALSO pins the class-sweep edge
  // cases `UnescapeChar` leaves LITERAL (XMP.pm:2924-2929 anchors lowercase
  // `^#x([0-9a-fA-F]+)$` / `^#(\d+)$`, and `s/&(#?\w+);/.../` needs a `#?\w+`
  // body): `&#X41;` (uppercase X) and `&#x+41;` (sign breaks `\w+`) stay
  // verbatim — the old code wrongly resolved both to `A`.
  check("XMP_numentity.xmp", "XMP_numentity.xmp.json", true);
  check("XMP_numentity.xmp", "XMP_numentity.xmp.n.json", false);
}

#[test]
fn xmp_leading_whitespace_recognition_anchoring() {
  // Codex R9/F1 regression: `ProcessXMP` recognition is a TWO-TIER match.
  // Tier 1 (XMP.pm:4341 `^\s*(<\?xpacket begin=|<x(mp)?:x[ma]pmeta)`) tolerates
  // leading whitespace; Tier 2 (the `else` block, XMP.pm:4345-4354 — BOM /
  // `<?xml` / `<rdf:RDF` / `<svg`) is anchored at byte 0 with an OPTIONAL
  // byte-0 BOM but NO leading whitespace. So leading whitespace before
  // `<rdf:RDF` or `<?xml` makes ExifTool finalize the file to TXT, NOT XMP.
  // The old port trimmed whitespace before EVERY branch, wrongly accepting
  // these as XMP. Bundled `perl exiftool` 13.58 (captured 2026-05-22):
  //   `   <rdf:RDF …`               ⇒ FileType TXT (NOT XMP)
  //   `   <?xml …<x:xmpmeta …`      ⇒ FileType TXT (NOT XMP)
  //   `   <?xpacket begin=…`        ⇒ FileType XMP  (Tier-1 `^\s*`)
  //   `   <x:xmpmeta …`             ⇒ FileType XMP  (Tier-1 `^\s*`)
  let rdf = b"   <rdf:RDF xmlns:rdf=\"http://www.w3.org/1999/02/22-rdf-syntax-ns#\">\
<rdf:Description xmlns:dc=\"http://purl.org/dc/elements/1.1/\" dc:title=\"WS\"/></rdf:RDF>";
  let xml = b"   <?xml version=\"1.0\"?><x:xmpmeta xmlns:x=\"adobe:ns:meta/\">\
<rdf:RDF xmlns:rdf=\"http://www.w3.org/1999/02/22-rdf-syntax-ns#\">\
<rdf:Description xmlns:dc=\"http://purl.org/dc/elements/1.1/\" dc:title=\"WS\"/></rdf:RDF></x:xmpmeta>";
  for print_on in [true, false] {
    // Leading whitespace before <rdf:RDF / <?xml: REJECTED as XMP (would be
    // TXT in ExifTool — a deferred FileType the XMP candidate must not claim).
    let out = extract_info("ws_rdf.xmp", rdf, print_on);
    assert!(
      !out.contains("\"XMP\"") && !out.contains("application/rdf+xml"),
      "leading whitespace before <rdf:RDF must NOT finalize as XMP (R9/F1), got: {out}"
    );
    let out = extract_info("ws_xml.xmp", xml, print_on);
    assert!(
      !out.contains("\"XMP\"") && !out.contains("application/rdf+xml"),
      "leading whitespace before <?xml must NOT finalize as XMP (R9/F1), got: {out}"
    );
  }
  // Tier-1 `^\s*`: leading whitespace before <?xpacket / <x:xmpmeta IS XMP.
  let xpacket = b"   <?xpacket begin=\"\"?><x:xmpmeta xmlns:x=\"adobe:ns:meta/\">\
<rdf:RDF xmlns:rdf=\"http://www.w3.org/1999/02/22-rdf-syntax-ns#\">\
<rdf:Description xmlns:dc=\"http://purl.org/dc/elements/1.1/\"><dc:format>image/jpeg</dc:format>\
</rdf:Description></rdf:RDF></x:xmpmeta>";
  let xmpmeta = b"   <x:xmpmeta xmlns:x=\"adobe:ns:meta/\">\
<rdf:RDF xmlns:rdf=\"http://www.w3.org/1999/02/22-rdf-syntax-ns#\">\
<rdf:Description xmlns:dc=\"http://purl.org/dc/elements/1.1/\"><dc:format>image/jpeg</dc:format>\
</rdf:Description></rdf:RDF></x:xmpmeta>";
  let out = extract_info("ws_xpacket.xmp", xpacket, true);
  assert!(
    out.contains("\"File:FileType\":\"XMP\""),
    "leading whitespace before <?xpacket must still be XMP (Tier-1 ^\\s*), got: {out}"
  );
  let out = extract_info("ws_xmpmeta.xmp", xmpmeta, true);
  assert!(
    out.contains("\"File:FileType\":\"XMP\""),
    "leading whitespace before <x:xmpmeta must still be XMP (Tier-1 ^\\s*), got: {out}"
  );
}

#[test]
fn xmp_double_utf8_encoded_conformance() {
  // Codex R10/F1 regression: a UTF-8-BOM + `<?xpacket begin=` sidecar is the
  // `$double` capture (XMP.pm:4351 `^(\xfe\xff|\xff\xfe|\xef\xbb\xbf)(<\?xpacket
  // begin=)`). ProcessXMP enters the `if ($double)` block (XMP.pm:4467-4498),
  // strips the BOM from the ORIGINAL data, and re-packs as characters: for the
  // UTF-8 BOM, `Charset::Decompose(_,_,'UTF8')` (= `unpack('C0U*')`,
  // Charset.pm:165-181) decodes the buffer to code points, then `pack('C*')`
  // truncates each to its low byte (XMP.pm:4478-4480). When that succeeds (no
  // malformed-UTF-8 warning) ExifTool emits `XMP is double UTF-encoded`
  // (XMP.pm:4494) and parses the re-packed bytes; here `dc:title = é` (U+00E9,
  // UTF-8 `c3 a9`) → byte `0xE9` → `FixUTF8` (XMP.pm:2943-2972) → `?`. The old
  // port stripped the BOM, accepted `<?xpacket` as ordinary XMP, and kept `é`
  // with no warning. Bundled `perl exiftool` 13.58 (captured 2026-05-22):
  //   `ExifTool:Warning` = "XMP is double UTF-encoded", `XMP-dc:Title` = "?".
  check("XMP_double_utf8.xmp", "XMP_double_utf8.xmp.json", true);
  check("XMP_double_utf8.xmp", "XMP_double_utf8.xmp.n.json", false);
}

#[test]
fn xmp_utf16le_non_bmp_conformance() {
  // Codex R10/F2 regression: ProcessXMP transcodes UTF-16 via `pack('C0U*',
  // unpack('v*'/'n*', $$dataPt))` (XMP.pm:4571-4587) — each 16-bit unit is
  // decoded INDEPENDENTLY (surrogate pairs are NOT combined) and emitted as
  // `pack('C0U')` loose UTF-8. For `dc:title = A😀B` (U+1F600), the UTF-16LE
  // surrogate PAIR `D83D DE00` is two units → 6 loose-UTF-8 bytes
  // (`ed a0 bd ed b8 80`) → `FixUTF8` (XMP.pm:2943-2972) → six `?`. No warning
  // (the leading `\xff\xfe` BOM validates the encoding marker, XMP.pm:4567).
  // The old port `String::from_utf16_lossy` combined the pair into the real
  // scalar and indexed `A😀B`. Bundled `perl exiftool` 13.58 (captured
  // 2026-05-22): `XMP-dc:Title` = "A??????B", no warning.
  check(
    "XMP_utf16le_nonbmp.xmp",
    "XMP_utf16le_nonbmp.xmp.json",
    true,
  );
  check(
    "XMP_utf16le_nonbmp.xmp",
    "XMP_utf16le_nonbmp.xmp.n.json",
    false,
  );
}

#[test]
fn xmp_nikon_basic_param_nxd_override_conformance() {
  // Codex R11/F1 regression: an `xmlns` URI beginning
  // `http://ns.nikon.com/BASIC_PARAM` (a Nikon NX-D settings sidecar) triggers
  // `OverrideFileType('NXD','application/x-nikon-nxd')` (XMP.pm:3915-3916), so
  // ExifTool finalizes `File:FileType=NXD`, `File:FileTypeExtension=nxd` (the
  // `-n` form keeps the uppercase `NXD`), and the EXPLICIT
  // `File:MIMEType=application/x-nikon-nxd` (NXD has NO `%mimeType` entry, so
  // the override's explicit MIME argument is the sole source) instead of
  // generic `XMP` + `application/rdf+xml`. The `XMP-nbp:*` settings tags still
  // come through the normal namespace path. Before the fix the port had no
  // override state and indexed this sidecar as plain XMP with the wrong MIME.
  // Oracle (bundled `perl exiftool` 13.58, captured 2026-05-22).
  check("XMP_nikon_nxd.xmp", "XMP_nikon_nxd.xmp.json", true);
  check("XMP_nikon_nxd.xmp", "XMP_nikon_nxd.xmp.n.json", false);
}

#[test]
fn xmp_nikon_nxd_extension_override_guard_conformance() {
  // Codex R11/F1 class-sweep: the SAME Nikon NX-D content as
  // `XMP_nikon_nxd.xmp` but under a `.nxd` EXTENSION. `OverrideFileType` is
  // guarded by `$fileType ne $$self{VALUE}{FileType}` (ExifTool.pm:9715), and
  // for a `.nxd` file `SetFileType` already resolves `NXD` (the `NXD => XMP`
  // sub-type-by-ext promotion, ExifTool.pm:9686-9690), so `'NXD' ne 'NXD'` is
  // FALSE: the namespace override is a NO-OP. FileType stays `NXD` but the MIME
  // is the BASE `application/rdf+xml` (NOT the explicit `application/x-nikon-nxd`
  // the `.xmp` sidecar gets). Pins the override GUARD so a `.nxd`-named file is
  // not given the explicit MIME by mistake. Oracle (bundled `perl exiftool`
  // 13.58, captured 2026-05-22).
  check("XMP_nikon_nxd_ext.nxd", "XMP_nikon_nxd_ext.nxd.json", true);
  check(
    "XMP_nikon_nxd_ext.nxd",
    "XMP_nikon_nxd_ext.nxd.n.json",
    false,
  );
}

#[test]
fn xmp_base64_literal_x0c_typo_conformance() {
  // Codex R11/F2 regression: the base64 binary-guard regex (XMP.pm:3647 `… or
  // $$val =~ /[\0-\x08\x0b\0x0c\x0e-\x1f]/`) ships a TYPO that ExifTool 13.58
  // keeps verbatim — `\0x0c` is parsed as `\0` (NUL) FOLLOWED BY the LITERAL
  // characters `x` (0x78), `0` (0x30), `c` (0x63), NOT as `\x0c` (FF). So a
  // short `rdf:datatype="base64"` payload that decodes to `cat`/`x`/`0`/`c`
  // (each contains an x/0/c byte) is treated as a binary placeholder, while a
  // payload WITHOUT any control/x/0/c byte stays text (`dog` → "dog"; `9` → 9
  // — only the digit `0` is special, not all digits). Before the fix the port
  // modeled only the control ranges and emitted `cat`/`x`/`0`/`c` as text.
  // Oracle (bundled `perl exiftool` 13.58, captured 2026-05-22).
  check("XMP_base64_x0c.xmp", "XMP_base64_x0c.xmp.json", true);
  check("XMP_base64_x0c.xmp", "XMP_base64_x0c.xmp.n.json", false);
}

#[test]
fn xmp_plus_signed_rational_not_converted_conformance() {
  // Codex R12/F1 + class-sweep regression: `ConvertRational` (XMP.pm:3400-
  // 3411) gates the value with the Perl regex `^(-?\d+)/(-?\d+)$` — exactly
  // one `/`, an OPTIONAL `-` (NEVER a `+`) then digits on each side. So a
  // leading-`+` rational does NOT match and is NOT converted. Rust's
  // `i64::parse` is looser (it accepts `+`), so the port wrongly converted
  // `+1/3` to a `0.333...` quotient. The class sweep also covers the
  // downstream numeric `ValueConv`/`PrintConv`s, which model raw Perl
  // arithmetic / `sprintf` with NO `IsFloat` gate — Perl coerces `$val`
  // (`"+1/3" + 0 == 1`), whereas the port's `f64::parse` rejects the `/3`.
  // Oracle (bundled `perl exiftool` 13.58, captured 2026-05-22):
  //   `exif:ExposureBiasValue=+1/3` → `-n` "+1/3"  (ConvertRational rejects)
  //                                   `-j` "+1"    (PrintFraction coerces 1)
  //   `exif:FocalLength=+50/1`       → `-n` "+50/1" `-j` "50.0 mm" (FocalMm)
  //   `exif:ApertureValue=+2/1`      → `-n` 2  `-j` 2.0 (sqrt(2)**2, Fixed1)
  //   `exif:BrightnessValue=-1/3`    → -0.333333333333333 (valid: converts)
  // Golden also KEEPS the ported `Composite:Aperture` (2.0, from `XMP-exif:
  // FNumber`) which exifast now builds (#133 PR 3 — XMP is allow-listed); its
  // `gen_golden.sh` arm drops only the unported `Composite:FocalLength35efl`
  // (NOT the generic `XMP*` `Composite:all`).
  check("XMP_rational_plus.xmp", "XMP_rational_plus.xmp.json", true);
  check(
    "XMP_rational_plus.xmp",
    "XMP_rational_plus.xmp.n.json",
    false,
  );
}

#[test]
fn xmp_exif_colorspace_value_conv_conformance() {
  // Codex R14/F1 regression: `exif:ColorSpace` (XMP.pm:2000) carries
  // `ValueConv => '$val == 0xffffffff ? 0xffff : $val'` (XMP.pm:2003) — some
  // applications incorrectly write `-1` as a 32-bit unsigned long, so a
  // written `4294967295` (0xffffffff) collapses NUMERICALLY to the EXIF
  // `0xffff` "Uncalibrated" sentinel. The port previously declared the tag
  // raw (PrintConv hash only, no ValueConv), so `4294967295` passed straight
  // to the `{1,2,0xffff}` PrintConv hash and MISSED — emitting
  // `Unknown (4294967295)`. Oracle (bundled `perl exiftool` 13.58):
  //   `exif:ColorSpace=4294967295` → `-n` 65535  `-j` "Uncalibrated"
  check("XMP_colorspace.xmp", "XMP_colorspace.xmp.json", true);
  check("XMP_colorspace.xmp", "XMP_colorspace.xmp.n.json", false);
}

#[test]
fn xmp_exif_cross_module_printconv_conformance() {
  // Codex R4-A: XMP tags whose bundled `PrintConv` is a REFERENCE to another
  // module's hash (`\%Image::ExifTool::Exif::compression` / `…::
  // photometricInterpretation` / `…::lightSource`, XMP.pm:1913/1917/2132) must
  // render the LABEL, not the raw integer. They are now wired to LOCAL ports
  // of those bundled hashes (the `xmp` feature is independent of `exif`, so a
  // cross-module `use` can't be used — same local-const pattern as
  // `TIFF_ORIENTATION`). `exif:MeteringMode` (inline hash, already correct)
  // guards the no-regression case, and `exif:Flash` guards that the bare
  // integer stays RAW (its `\%flash` PrintConv is the deferred
  // `Composite:Flash` tag's, NOT `XMP-exif:Flash` — bundled emits `5`).
  // Oracle (bundled `perl exiftool` 13.59, `-x Composite:all`):
  //   tiff:Compression=6                 -j "JPEG (old-style)"  -n 6
  //   tiff:PhotometricInterpretation=6   -j "YCbCr"             -n 6
  //   exif:LightSource=10                -j "Cloudy"            -n 10
  //   exif:MeteringMode=5                -j "Multi-segment"     -n 5
  //   exif:Flash=5                       -j 5                   -n 5
  check(
    "XMP_exif_printconv.xmp",
    "XMP_exif_printconv.xmp.json",
    true,
  );
  check(
    "XMP_exif_printconv.xmp",
    "XMP_exif_printconv.xmp.n.json",
    false,
  );
}

#[test]
fn xmp_et_qualifier_suppression_conformance() {
  // Codex R4-B: `ParseXMPElement` IGNORES `et:desc` always, and `et:val` when
  // preceded by `et:prt` (XMP.pm:4202 `/^et:(desc|prt|val)$/ and ($count or
  // $1 eq 'desc')`, with a `--$count` sibling-count adjustment). Since
  // `GetXMPTagID` strips the `et:*` suffix, all three would otherwise collapse
  // to the parent `foo:Tag` and the LAST (`et:val`) would win. The suppression
  // makes the `et:prt` value the emitted one. Oracle: `XMP-foo:Tag=Print`.
  check("XMP_et_qual.xmp", "XMP_et_qual.xmp.json", true);
  check("XMP_et_qual.xmp", "XMP_et_qual.xmp.n.json", false);
}

#[test]
fn xmp_aux_lensinfo_rational_list_conformance() {
  // Codex R14/F1 regression: `aux:LensInfo` (XMP.pm:2596) carries
  // `ValueConv => \&ConvertRationalList` (XMP.pm:2600) +
  // `PrintConv => \&Image::ExifTool::Exif::PrintLensInfo` (XMP.pm:2615). The
  // tag has NO explicit `Writable` (plain-string default) so XMPAutoConv's
  // `ConvertRational` does NOT pre-convert it — `ConvertRationalList`
  // (XMP.pm:3418) converts the raw `N/D N/D N/D N/D` string field-by-field,
  // then `PrintLensInfo` (Exif.pm:5800) renders the focal/aperture form. The
  // port previously declared the tag raw/identity, emitting the literal
  // `24/1 70/1 28/10 40/10` in BOTH modes. Oracle (bundled `perl exiftool`
  // 13.58):
  //   `aux:LensInfo=24/1 70/1 28/10 40/10`
  //       → `-n` "24 70 2.8 4"  `-j` "24-70mm f/2.8-4"
  check("XMP_lensinfo.xmp", "XMP_lensinfo.xmp.json", true);
  check("XMP_lensinfo.xmp", "XMP_lensinfo.xmp.n.json", false);
}

#[test]
fn xmp_aux_lensinfo_prime_zero_upper_focal_conformance() {
  // Codex R14/F1 class-sweep: `PrintLensInfo` (Exif.pm:5800) appends the
  // upper focal/aperture only when it is Perl-truthy AND differs from the
  // lower value — `$val .= "-$vals[1]" if $vals[1] and $vals[1] ne $vals[0]`
  // (Exif.pm:5814). A fixed-focal-length ("prime") lens writes `0` for the
  // upper focal (the Pentax Q does this); Perl `"0"` is falsy, so the `-0`
  // is dropped and the form is `50mm f/1.4`. Oracle (bundled `perl exiftool`
  // 13.58):
  //   `aux:LensInfo=50/1 0/1 14/10 14/10`
  //       → `-n` "50 0 1.4 1.4"  `-j` "50mm f/1.4"
  check(
    "XMP_lensinfo_prime.xmp",
    "XMP_lensinfo_prime.xmp.json",
    true,
  );
  check(
    "XMP_lensinfo_prime.xmp",
    "XMP_lensinfo_prime.xmp.n.json",
    false,
  );
}

#[test]
fn xmp_aux_approximate_focus_distance_conformance() {
  // Codex R14/F1 regression: `aux:ApproximateFocusDistance` (XMP.pm:2630)
  // carries `Writable => 'rational'` and a PrintConv hash whose only mapped
  // row is `4294967295 => 'infinity'` (XMP.pm:2633), paired with an
  // `OTHER => sub` (XMP.pm:2634-2638) whose READ branch returns the value
  // UNCHANGED on a miss (NOT `Unknown ($val)`). The `rational` Writable means
  // XMPAutoConv's `ConvertRational` runs first: a finite `53/10` → `5.3`
  // (a hash miss → OTHER passes `5.3` through), and the sentinel
  // `4294967295/1` → `4294967295` keys the `infinity` row. The port
  // previously declared the tag with a plain hash PrintConv, so the finite
  // `5.3` MISSED → `Unknown (5.3)`. Oracle (bundled `perl exiftool` 13.58):
  //   `aux:ApproximateFocusDistance=53/10`        → `-n` 5.3  `-j` 5.3
  //   `aux:ApproximateFocusDistance=4294967295/1` → `-n` 4294967295
  //                                                 `-j` "infinity"
  check("XMP_aux_focusdist.xmp", "XMP_aux_focusdist.xmp.json", true);
  check(
    "XMP_aux_focusdist.xmp",
    "XMP_aux_focusdist.xmp.n.json",
    false,
  );
  check(
    "XMP_aux_focusdist_inf.xmp",
    "XMP_aux_focusdist_inf.xmp.json",
    true,
  );
  check(
    "XMP_aux_focusdist_inf.xmp",
    "XMP_aux_focusdist_inf.xmp.n.json",
    false,
  );
}

#[test]
fn xmp_aux_neutral_density_and_lightroom_tags_conformance() {
  // Codex R5/F1 value-divergence fix: the AUX table stopped at
  // `LensDistortInfo`; the Lightroom LR6+/LR7+/LR11+ tags (XMP.pm:2641-2658)
  // were absent, so the missing-from-table DEFAULT path ran XMPAutoConv's
  // `ConvertRational` on them. The headline bug: `aux:NeutralDensityFactor`
  // (XMP.pm:2648, a `{}` no-Writable string whose DENOMINATOR is significant)
  // was mis-converted `"1/2"` → `0.5`. With the explicit table rows it stays
  // `"1/2"` VERBATIM (a table-present no-Writable tag has `IsDefault` FALSE ⇒
  // XMP.pm:3676 skips the AutoConv block). Oracle (bundled `perl exiftool`
  // 13.59):
  //   `aux:NeutralDensityFactor=1/2`            → "1/2" (NOT 0.5)
  //   `aux:LensDistortInfo=1/100 2/100 …`       → kept verbatim
  //   `aux:EnhanceSuperResolutionScale=2/1`     → 2 (Writable=>'rational')
  //   `aux:Enhance{Details,SuperResolution,Denoise}Version`, `…LumaAmount`
  //                                             → plain ints (no AutoConv)
  //   `aux:*AlreadyApplied=True|False`          → boolean true/false
  check(
    "XMP_aux_neutraldensity.xmp",
    "XMP_aux_neutraldensity.xmp.json",
    true,
  );
  check(
    "XMP_aux_neutraldensity.xmp",
    "XMP_aux_neutraldensity.xmp.n.json",
    false,
  );
}

#[test]
fn xmp_thumbnails_struct_base64_image_is_binary_conformance() {
  // Codex R5/F2 value-divergence fix: `xmp:Thumbnails` (XMP.pm:1062,
  // `Struct => \%sThumbnail`) and `xmp:PageInfo` (XMP.pm:1068,
  // `Struct => \%sPageInfo`) were un-ported, so a `<xmpGImg:image>` thumbnail
  // emitted the LITERAL base64 scalar. Per `%sThumbnail`/`%sPageInfo`
  // (XMP.pm:361-386) the `image` field carries `ValueConv => DecodeBase64`,
  // which returns a scalar REF ⇒ the value is BINARY and renders as
  // `(Binary data N bytes, use -b option to extract)` REGARDLESS of length
  // (unlike the `rdf:datatype="base64"` attribute path, which derefs ≤100-byte
  // control-free payloads to text). Oracle (bundled `perl exiftool` 13.59,
  // `-struct`): each struct emits `{Format, Height, Image, Width[, PageNumber]}`
  // with `Image` the binary placeholder (33 bytes / 5 bytes here).
  check("XMP_thumbnail.xmp", "XMP_thumbnail.xmp.json", true);
  check("XMP_thumbnail.xmp", "XMP_thumbnail.xmp.n.json", false);
}

/// Golden-pattern **L2** projection: an `.xmp` sidecar feeds the normalized
/// cross-format [`MediaMetadata`](exifast::metadata::MediaMetadata) domain
/// (XMP is a camera-metadata source per the product scope). Reads the
/// post-ValueConv (`-n`) form, so values are already machine-ready. Verified
/// against the `XMP.xmp` / `XMP_gps.xmp` fixtures' `-n` goldens:
///   * `XMP-tiff:Make` "Canon", `XMP-tiff:Model` "Canon DIGITAL IXUS 40",
///     `XMP-xmp:CreatorTool` software; `XMP-exif:FocalLength` 5.8,
///     `XMP-exif:FNumber` 2.8 (lens + capture); `XMP-exif:ExposureTime` 0.4.
///   * `XMP_gps.xmp`: `XMP-exif:GPSLatitude` 45.5, `GPSLongitude` -122.508…
///     (already signed decimal degrees in `-n`).
#[test]
#[cfg(all(feature = "xmp", feature = "gps"))]
fn xmp_projects_camera_lens_capture_and_gps_domain() {
  use exifast::metadata::Project;

  let root = env!("CARGO_MANIFEST_DIR");
  // --- XMP.xmp: camera / lens / capture ---
  let data = std::fs::read(format!("{root}/tests/fixtures/XMP.xmp")).expect("read XMP.xmp");
  let meta = exifast::parse_xmp(&data).expect("XMP.xmp parses");
  let md = Project::project(&meta);

  let camera = md.camera().expect("camera domain populated");
  assert_eq!(camera.make(), Some("Canon"));
  assert_eq!(camera.model(), Some("Canon DIGITAL IXUS 40"));
  assert_eq!(camera.software(), Some("Adobe Photoshop CS2 Windows"));

  let lens = md.lens().expect("lens domain populated");
  assert_eq!(lens.focal_length_mm(), Some(5.8));
  assert_eq!(lens.aperture(), Some(2.8));

  let capture = md.capture().expect("capture domain populated");
  assert_eq!(capture.exposure_time_s(), Some(0.4));
  assert_eq!(capture.f_number(), Some(2.8));

  // --- XMP_gps.xmp: GPS (signed decimal degrees from the `-n` ValueConv) ---
  let gdata =
    std::fs::read(format!("{root}/tests/fixtures/XMP_gps.xmp")).expect("read XMP_gps.xmp");
  let gmeta = exifast::parse_xmp(&gdata).expect("XMP_gps.xmp parses");
  let gmd = Project::project(&gmeta);
  let gps = gmd.gps().expect("gps domain populated");
  assert_eq!(gps.latitude(), Some(45.5));
  // -122.508333…; compare with a tolerance (the `-n` text is full-precision).
  let lon = gps.longitude().expect("longitude present");
  assert!(
    (lon - (-122.508_333_333_333_3)).abs() < 1e-9,
    "longitude {lon}"
  );
}

/// Golden-pattern **L2** projection — GPS altitude SIGN. `XMP-exif:GPSAltitude`
/// is the UNSIGNED magnitude; `XMP-exif:GPSAltitudeRef` carries the sign
/// (`0` above / `1` below sea level, XMP.pm:2329-2348). Mirrors the EXIF
/// projector (`project.rs` `gps_altitude`), which the JSON-level tag value
/// does NOT (the `-n` tag stays the unsigned `35`); only the domain
/// projection negates. Oracle (`-n`, both fixtures): `GPSAltitude` 35,
/// `GPSAltitudeRef` 1 (below) / 0 (above).
#[test]
#[cfg(all(feature = "xmp", feature = "gps"))]
fn xmp_projects_gps_altitude_signed_by_ref() {
  use exifast::metadata::Project;
  let root = env!("CARGO_MANIFEST_DIR");

  // Below sea level (ref == 1) ⇒ NEGATIVE magnitude.
  let below = std::fs::read(format!("{root}/tests/fixtures/XMP_gps_belowsea.xmp"))
    .expect("read XMP_gps_belowsea.xmp");
  let bmeta = exifast::parse_xmp(&below).expect("XMP_gps_belowsea.xmp parses");
  let bmd = Project::project(&bmeta);
  let bgps = bmd.gps().expect("gps domain populated");
  assert_eq!(bgps.altitude_m(), Some(-35.0));

  // Above sea level (ref == 0) ⇒ POSITIVE magnitude (positive control).
  let above = std::fs::read(format!("{root}/tests/fixtures/XMP_gps_abovesea.xmp"))
    .expect("read XMP_gps_abovesea.xmp");
  let ameta = exifast::parse_xmp(&above).expect("XMP_gps_abovesea.xmp parses");
  let amd = Project::project(&ameta);
  let agps = amd.gps().expect("gps domain populated");
  assert_eq!(agps.altitude_m(), Some(35.0));
}

// The `Composite:GPSAltitude` def `Desire`s the XMP altitude/ref pair
// (GPS.pm:406), so exifast emits `Composite:GPSAltitude` from the embedded
// `XMP-exif:GPSAltitude`/`…Ref` here — byte-matching bundled (`-j` `35 m Below/
// Above Sea Level`, `-n` `-35`/`35`). The XMP-only ref Composites bundled ALSO
// synthesizes (`GPSLatitudeRef`/`GPSLongitudeRef`/`GPSPosition`) are NOT ported,
// so they stay excluded (`tools/gen_golden.sh` drops just those three).
#[test]
fn xmp_gps_belowsea_conformance() {
  check("XMP_gps_belowsea.xmp", "XMP_gps_belowsea.xmp.json", true);
  check("XMP_gps_belowsea.xmp", "XMP_gps_belowsea.xmp.n.json", false);
}

#[test]
fn xmp_gps_abovesea_conformance() {
  check("XMP_gps_abovesea.xmp", "XMP_gps_abovesea.xmp.json", true);
  check("XMP_gps_abovesea.xmp", "XMP_gps_abovesea.xmp.n.json", false);
}

#[test]
fn xmp_no_closing_tag_conformance() {
  // F2 — the close-scan finds no `</dc:title>` before end-of-data, so
  // `find_close` returns `CloseErr::NoClosingTag` and the walker raises
  // `XMP format error (no closing tag for dc:title)` (XMP.pm:3839, emitted via
  // `$et->Warn` at XMP.pm:4237 on the read path) before `last Element`. The
  // top-level `rdf:Description` still closes, so this is the ONE parse-error
  // class whose oracle warning carries NO ` [x$n]` count — the port's single
  // first-wins warning matches it byte-for-byte. (The unterminated-CDATA /
  // -comment classes are covered by `xmp_parse_error_warnings_emitted` below:
  // their bundled oracle appends ` [x2]` because ExifTool re-runs the packet
  // through the PLIST module after the failed XMP parse — a dual-module
  // artifact the single-parse port does not and should not reproduce.)
  check(
    "XMP_no_closing_tag.xmp",
    "XMP_no_closing_tag.xmp.json",
    true,
  );
  check(
    "XMP_no_closing_tag.xmp",
    "XMP_no_closing_tag.xmp.n.json",
    false,
  );
}

#[test]
fn xmp_uri_fixed_conformance() {
  // F2 adjacent Warn-site (XMP.pm:3914-3915): the `dc` URI is given WITHOUT its
  // trailing slash (`…/1.1` vs the canonical `…/1.1/`); the trailing-slash
  // patch matches the known dc namespace, so the port raises the MINOR warning
  // `[minor] Fixed incorrect URI for xmlns:dc` (`$et->Warn($_, 1)`) and still
  // extracts `XMP-dc:Title`. Reachable in DEFAULT extraction (NOT validate-
  // gated), single warning (no ` [x$n]`), so byte-identical to the oracle.
  check("XMP_uri_fixed.xmp", "XMP_uri_fixed.xmp.json", true);
  check("XMP_uri_fixed.xmp", "XMP_uri_fixed.xmp.n.json", false);
}

#[test]
fn xmp_uri_double_slash_conformance() {
  // R9 [medium]: XMP.pm:3911 `$try =~ s{/$}{} or $try .= '/'` toggles EXACTLY
  // ONE trailing slash. A repairable camera namespace `xmlns:exif=…/exif/1.0//`
  // (double slash) must drop ONE slash → `…/exif/1.0/` (the known `exif` URI),
  // raising `[minor] Fixed incorrect URI for xmlns:exif` and still extracting
  // `XMP-exif:GPSLatitude`/`GPSLongitude`. The earlier `trim_end_matches('/')`
  // stripped BOTH slashes → `…/exif/1.0` → known-URI lookup miss → the exif/GPS
  // namespace mis-translated to a temp prefix (camera GPS under the wrong group).
  check(
    "XMP_uri_double_slash.xmp",
    "XMP_uri_double_slash.xmp.json",
    true,
  );
  check(
    "XMP_uri_double_slash.xmp",
    "XMP_uri_double_slash.xmp.n.json",
    false,
  );
}

#[test]
fn xmp_iso_seq_conformance() {
  // R10 [medium] (premise corrected): bundled ExifTool 13.59 emits a single-item
  // `exif:ISOSpeedRatings` RDF `Seq` as the ARRAY `XMP-exif:ISO: [100]`
  // (XMP.pm:2068-2072 `List => 'Seq'` keeps it a list even with one item), NOT
  // the scalar `100`. The port preserves that faithful shape — this pins the
  // JSON so the domain-projection fix below does not regress it.
  check("XMP_iso_seq.xmp", "XMP_iso_seq.xmp.json", true);
  check("XMP_iso_seq.xmp", "XMP_iso_seq.xmp.n.json", false);
}

#[test]
#[cfg(feature = "xmp")]
fn xmp_projects_iso_from_single_item_seq() {
  // R10 fix: XMP `ISO` (`List => 'Seq'`) is ALWAYS a list, so the JSON tag is
  // `[100]`; the normalized `capture.iso` projection must descend the
  // single-element `rdf:Seq` to the scalar `100` (`domain_numeric`), else every
  // XMP sidecar loses its ISO in the domain layer.
  use exifast::metadata::Project;
  let root = env!("CARGO_MANIFEST_DIR");
  let data =
    std::fs::read(format!("{root}/tests/fixtures/XMP_iso_seq.xmp")).expect("read XMP_iso_seq.xmp");
  let meta = exifast::parse_xmp(&data).expect("XMP_iso_seq.xmp parses");
  let md = Project::project(&meta);
  let capture = md.capture().expect("capture settings populated");
  assert_eq!(capture.iso(), Some(100));
}

/// F2 — each malformed-XMP parse-error path now raises the matching
/// `$et->Warn($err)` (XMP.pm:3839/3845/3849, emitted once at XMP.pm:4237 on the
/// read path) instead of silently `break`ing. Asserts the port surfaces the
/// EXACT bare warning string as `ExifTool:Warning` for all three close-scan /
/// scan-level error classes.
///
/// `XMP_no_closing_tag.xmp` ALSO has a byte-identical conformance golden
/// (`xmp_no_closing_tag_conformance`); the other two do NOT, by design: their
/// bundled oracle appends ` [x2]` because ExifTool, after the failed XMP parse
/// returns 0 elements, re-runs the SAME packet through the PLIST module
/// (`PLIST::ProcessPLIST` → `XMP::ProcessXMP`, PLIST.pm:467), so `$et->Warn`
/// fires twice and the `WAS_WARNED` count loop (ExifTool.pm:3199) emits ` [x2]`.
/// An unterminated CDATA/comment consumes every following byte (incl. the
/// ancestor close tags), so NO top-level element can complete ⇒ the first parse
/// always returns 0 ⇒ the PLIST re-run always fires; the ` [x2]` is therefore
/// intrinsic to these two classes. The port performs a SINGLE XMP parse and
/// records ONE first-wins warning (`Walker::warn`, the documented-faithful
/// analogue of the LAST `$et->Warn` at 4237), so it emits the bare string with
/// no count. Matching ` [x2]` would require the port to double-process the
/// packet through PLIST — unfaithful to the single-parse design — so the
/// emission (the actual fix) is pinned here while the cosmetic count delta is
/// left as a deliberate, documented divergence.
#[test]
#[cfg(feature = "xmp")]
fn xmp_parse_error_warnings_emitted() {
  let root = env!("CARGO_MANIFEST_DIR");
  for (fixture, want) in [
    (
      "XMP_no_closing_tag.xmp",
      "XMP format error (no closing tag for dc:title)",
    ),
    ("XMP_missing_cdata_term.xmp", "Missing CDATA terminator"),
    ("XMP_missing_comment_term.xmp", "Missing comment terminator"),
  ] {
    let data = std::fs::read(format!("{root}/tests/fixtures/{fixture}"))
      .unwrap_or_else(|e| panic!("read {fixture}: {e}"));
    let meta = exifast::parse_xmp(&data).unwrap_or_else(|| panic!("{fixture} parses as XMP"));
    let diags = exifast::diagnostics::Diagnose::diagnostics(&meta);
    let got: Vec<&str> = diags
      .iter()
      .map(exifast::diagnostics::Diagnostic::message)
      .collect();
    assert_eq!(
      got,
      vec![want],
      "{fixture}: expected exactly the bare parse-error warning"
    );
  }
}

// ===========================================================================
// xtask-GENERATED full XMP table (Phase-1 Task 7) — representative new-tag
// oracle. These exercise namespaces / tags the hand-written XMP table did NOT
// cover, now supplied by the xtask-generated `tables_generated.rs` (additive
// fallback). The byte-identity of EVERY pre-existing golden (the additive
// invariant) is proven by the rest of this suite + the `git diff --stat
// origin/main -- tests/golden/` showing only ADDITIONS. Exhaustive per-tag
// coverage of all ~4262 generated tags is a tracked FOLLOW-UP, not this PR.
// ===========================================================================

#[test]
fn xmp_generated_crs_camera_raw_settings_conformance() {
  // `crs` (Lightroom camera-raw-settings) is a GENERATED-ONLY namespace (no
  // hand table). Exercises a plain string (`RawFileName`), a `real` autoconv
  // (`Version` → 15.4), an as-is string (`Exposure2012` → "+0.55", W::Str so
  // no ConvertRational), and — the key case — a GENERATED value-MAP label:
  // `crs:CropUnit=1` → "inches" (`CRS_CROPUNIT` IntMap, generated from -listx).
  // Oracle (bundled `perl exiftool` 13.59, `-x Composite:all`).
  check("XMP_gen_crs.xmp", "XMP_gen_crs.xmp.json", true);
  check("XMP_gen_crs.xmp", "XMP_gen_crs.xmp.n.json", false);
}

#[test]
fn xmp_generated_lightroom_namespace_conformance() {
  // `lr` (Lightroom) GENERATED-ONLY namespace, incl. an ExifTool `Name` remap
  // carried in `-listx` (`lr:hierarchicalSubject` → `HierarchicalSubject`, a
  // Bag list) + a plain `lr:privateRTKInfo` → `PrivateRTKInfo`.
  check("XMP_gen_lr.xmp", "XMP_gen_lr.xmp.json", true);
  check("XMP_gen_lr.xmp", "XMP_gen_lr.xmp.n.json", false);
}

#[test]
fn xmp_generated_xmpmm_media_management_conformance() {
  // `xmpMM` (XMP Media Management) GENERATED-ONLY namespace — a top-level tag
  // (`DocumentID`/`OriginalDocumentID`/`RenditionClass`) plus a `-listx`
  // pre-flattened struct field (`DerivedFromDocumentID`), all plain strings.
  check("XMP_gen_xmpmm.xmp", "XMP_gen_xmpmm.xmp.json", true);
  check("XMP_gen_xmpmm.xmp", "XMP_gen_xmpmm.xmp.n.json", false);
}

#[test]
fn xmp_generated_nested_struct_field_conformance() {
  // Codex R1 [high]: a NESTED structured `xmpMM:DerivedFrom/stRef:maskMarkers`
  // (vs the flat `DerivedFromMaskMarkers` spelling) must reach the GENERATED
  // flattened field's PrintConv. ExifTool flattens to `DerivedFromMaskMarkers`
  // (XMP.pm:3495-3516) and applies its `%sResourceRef` `maskMarkers` PrintConv
  // (XMP.pm:321 `{All,None}`); an unmapped value renders `Unknown (Frobnicate)`
  // (ExifTool.pm:3622). Pre-fix `resolve_field` looked up the innermost
  // `maskMarkers` and missed the flattened generated field → raw passthrough;
  // the fix looks up the flattened `id.tag` first. Pins the structured-form
  // PrintConv-miss so the generated layer works for nested (not just flat) XMP.
  check(
    "XMP_gen_nested_struct.xmp",
    "XMP_gen_nested_struct.xmp.json",
    true,
  );
  check(
    "XMP_gen_nested_struct.xmp",
    "XMP_gen_nested_struct.xmp.n.json",
    false,
  );
}

#[test]
fn xmp_generated_covered_namespace_extra_tags_conformance() {
  // The ADDITIVE fallback in a HAND-COVERED namespace + Name remaps in a new
  // one: `exif:OECFColumns` / `exif:SpatialFrequencyResponseRows` are flattened
  // EXIF struct children the hand `exif` table omits — now supplied by
  // `GEN_EXIF` (W::Integer). `exifEX:BodySerialNumber` / `CameraOwnerName` are
  // the generated-only `exifEX` namespace, emitting via their `-listx` `Name`
  // remaps `SerialNumber` / `OwnerName` (and `0123456789` stays a STRING — no
  // numeric coercion under W::Str). Oracle (bundled `perl exiftool` 13.59).
  check(
    "XMP_gen_covered_extra.xmp",
    "XMP_gen_covered_extra.xmp.json",
    true,
  );
  check(
    "XMP_gen_covered_extra.xmp",
    "XMP_gen_covered_extra.xmp.n.json",
    false,
  );
}

#[test]
fn xmp_generated_phf_backed_value_map_conformance() {
  // The phf-backed large value-map path (the codegen `PHF_THRESHOLD`): PLUS
  // `MediaSummaryCode` has 2143 string-keyed rows → a `phf::Map`, looked up via
  // the shared `value_map_get` exact-string API. `8ISH` → "Shipping".
  // Oracle (bundled `perl exiftool` 13.59).
  check("XMP_gen_phf_map.xmp", "XMP_gen_phf_map.xmp.json", true);
  check("XMP_gen_phf_map.xmp", "XMP_gen_phf_map.xmp.n.json", false);
}

#[test]
fn xmp_generated_unported_conv_passes_through_raw_conformance() {
  // `P::Unported` faithful raw passthrough: `HDRGainMap:HDRGainMapVersion`
  // (XMP2.pl:1791) carries a CODE `PrintConv`
  // (`IsInt($val) ? join(".",unpack("C*",pack "N",$val)) : $val`) NOT in
  // `-listx`; the conv_registry marks it `Unported`, so the generated table
  // emits `P::Unported("XMP:HDRGainMapVersion")` and the value is passed through
  // RAW. For the chosen NON-integer value `1.2.3.4`, the bundled `IsInt` branch
  // also returns `$val` verbatim, so the oracle matches byte-for-byte (an
  // INTEGER value would diverge — the un-ported formatting is a tracked
  // follow-up, never a guessed conversion). Oracle (bundled `perl exiftool`
  // 13.59).
  check("XMP_gen_unported.xmp", "XMP_gen_unported.xmp.json", true);
  check("XMP_gen_unported.xmp", "XMP_gen_unported.xmp.n.json", false);
}

#[test]
#[cfg(all(feature = "png", feature = "xmp"))]
fn png_rawprofile_xmp_conformance() {
  // Issue #179: an ImageMagick `Raw profile type xmp` tEXt chunk (`PNG.pm:746`)
  // hex-decodes to a raw XMP packet that `ProcessProfile` dispatches to
  // `ProcessDirectory(XMP::Main)` = `ProcessXMP`. The PNG port now routes that
  // packet through the ported XMP module (`exifast::formats::xmp`) and emits the
  // decoded `XMP-x`/`XMP-dc`/`XMP-xmp`/`XMP-exif` tags (previously the chunk
  // only reset `$$et{PROCESSED}` and its content was dropped). Crafted minimal
  // 1x1 RGB fixture (`tools/gen_png_rawprofile_fixtures.py`); the golden drops
  // `Composite:*` (the PNG port has no Composite subsystem — see
  // `tools/gen_golden.sh`'s `PNG_rawprofile_*` case). Gated on the `xmp` feature
  // because the PNG crate feature does not pull it in. Oracle: bundled
  // `perl exiftool -j -G1 -struct` 13.59.
  check(
    "PNG_rawprofile_xmp.png",
    "PNG_rawprofile_xmp.png.json",
    true,
  );
  check(
    "PNG_rawprofile_xmp.png",
    "PNG_rawprofile_xmp.png.n.json",
    false,
  );
  // NONCANONICAL raw-profile: the hex body has a dangling odd nibble. Perl
  // `pack('H*')` PADS it (trailing `\xa0`, declared length set to match) rather
  // than dropping it, and the byte lands harmlessly after the XMP packet end —
  // so bundled emits the same XMP tags and NO wrong-size warning. A decoder that
  // truncated the odd nibble would mis-size the profile; this golden pins the
  // faithful pad behavior end-to-end (`PNG.pm:1169` `pack('H*', …)`).
  check(
    "PNG_rawprofile_xmp_oddnibble.png",
    "PNG_rawprofile_xmp_oddnibble.png.json",
    true,
  );
  check(
    "PNG_rawprofile_xmp_oddnibble.png",
    "PNG_rawprofile_xmp_oddnibble.png.n.json",
    false,
  );
  // #205 — diagnostics WALK-ORDER: a malformed `Raw profile type xmp` (the
  // double-UTF packet → `XMP is double UTF-encoded`, XMP.pm:4494) positioned
  // BEFORE a later bad `eXIf` (→ `Invalid eXIf chunk`, PNG.pm:1382). ExifTool's
  // serial chunk walk emits the XMP warning FIRST (the XMP chunk is earlier), so
  // it — not the later eXIf warning — is the document FIRST `ExifTool:Warning`
  // (`Warning` is `Priority=0` first-wins, ExifTool.pm:5404-5417). The PNG port
  // previously drained the raw-profile-XMP decode warning dead-last and surfaced
  // `Invalid eXIf chunk` instead; the unified ordered diagnostic replay
  // (`PngMeta::diag_order`) now emits each document warning at its chunk-walk
  // position, byte-matching bundled. `PNG:eXIf` is dropped from BOTH sides: the
  // invalid eXIf chunk makes bundled emit a `(Binary data …)` placeholder the
  // PNG port suppresses (the pre-existing eXIf-suppression deferral) — the
  // warning ORDER is what this golden pins. Oracle: bundled `perl exiftool -j
  // -G1 -struct` 13.59.
  check_excluding(
    "PNG_rawprofile_xmp_warnorder.png",
    "PNG_rawprofile_xmp_warnorder.png.json",
    true,
    &["PNG:eXIf"],
  );
  check_excluding(
    "PNG_rawprofile_xmp_warnorder.png",
    "PNG_rawprofile_xmp_warnorder.png.n.json",
    false,
    &["PNG:eXIf"],
  );
}

#[test]
#[cfg(feature = "png")]
fn png_crafted_input_hardening_conformance() {
  // #180 — POST-IEND TRAILER family-1 group on a warning raised while parsing a
  // trailer chunk. A complete (IEND-terminated) PNG followed by a TRAILER `iCCP`
  // chunk whose zlib stream is corrupt. Bundled (`PNG.pm:1479-1484`) processes
  // post-IEND chunks under `$$et{SET_GROUP1} = 'Trailer'`, so the `Error
  // inflating iCCP` warning (`PNG.pm:942`) — raised WHILE parsing the trailer
  // chunk — resolves its family-1 group to `Trailer` (`ExifTool.pm:9475`) and
  // surfaces as the `Trailer:Warning` TAG, NOT the document `ExifTool:Warning`.
  // The trailer-ENTRY warning `Trailer data after PNG IEND chunk` (`PNG.pm:1481`)
  // is raised BEFORE `SET_GROUP1`, so it stays `ExifTool:Warning` (and `[minor]`).
  // The trailer iCCP's `ProfileName` rides the `Trailer` group too. The port
  // previously emitted the inflate-error warning as a flat document-level
  // `ExifTool:Warning` (no `Trailer:Warning` key); it now group-scopes every
  // post-IEND-trailer warning via the `trailer_warning_start` watermark. Bundled
  // also emits a deferred `Trailer:ICC_Profile` binary placeholder (no
  // ICC_Profile sub-port) the port suppresses — dropped from both sides. Oracle:
  // bundled `perl exiftool -j -G1 -struct` 13.59.
  check_excluding(
    "PNG_trailer_iccp_warn.png",
    "PNG_trailer_iccp_warn.png.json",
    true,
    &["Trailer:ICC_Profile"],
  );
  check_excluding(
    "PNG_trailer_iccp_warn.png",
    "PNG_trailer_iccp_warn.png.n.json",
    false,
    &["Trailer:ICC_Profile"],
  );
  // #178-item1 — NESTED-zXIf inner inflate recursion warning text. A `zxIf`
  // (compressed EXIF) chunk whose body inflates to a SECOND `\0`-typed (still
  // "compressed") block of only 3 bytes. Bundled's `ProcessPNG_eXIf`
  // (`PNG.pm:1378-1389`) re-enters `FoundPNG` (level 2) on the inflated buffer
  // and, seeing the `\0` type again, does `substr($inner, 5)` — empty/`undef` on
  // the 3-byte inner block — so the second inflate FAILS ⇒ `Error inflating
  // zxIf`. The port (pre-#178) treated the sub-5-byte inner `\0` block as a
  // non-II/MM TIFF and warned `Invalid zxIf chunk`; it now bounded-recurses the
  // inner inflate (depth-guarded against a nested-compression DoS) so the warning
  // matches bundled. Both extract no EXIF. Bundled emits a `PNG:zxIf` binary
  // placeholder the port suppresses (the pre-existing eXIf/zxIf-suppression
  // deferral, as `PNG_rawprofile_xmp_warnorder` drops `PNG:eXIf`) — dropped from
  // both sides. Oracle: bundled `perl exiftool -j -G1 -struct` 13.59.
  check_excluding(
    "PNG_nested_zxif.png",
    "PNG_nested_zxif.png.json",
    true,
    &["PNG:zxIf"],
  );
  check_excluding(
    "PNG_nested_zxif.png",
    "PNG_nested_zxif.png.n.json",
    false,
    &["PNG:zxIf"],
  );
}

#[test]
#[cfg(all(feature = "png", feature = "xmp"))]
fn png_trailer_xmp_warn_conformance() {
  // #180 (round 2) — POST-IEND TRAILER diagnostic re-scoping for an embedded XMP
  // sub-Meta. A complete (IEND-terminated) PNG followed by a TRAILER `Raw profile
  // type xmp` tEXt chunk carrying the double-UTF packet. Bundled processes
  // post-IEND chunks under `$$et{SET_GROUP1} = 'Trailer'` (`PNG.pm:1479-1484`), so
  // the XMP sub-Meta's `XMP is double UTF-encoded` `$et->Warn` (`XMP.pm:4494`, a
  // DOCUMENT-level warning — empty `$grps[1]`) resolves under that global to the
  // family-1 `Trailer:Warning` TAG (`ExifTool.pm:9475`), NOT the document-level
  // `ExifTool:Warning`. It then LOSES the priority-0 first-wins race
  // (`ExifTool.pm:5404-5417`) to the EARLIER `Trailer:Warning = "[minor] Text/EXIF
  // chunk(s) found after PNG IDAT …"` (`PNG.pm:1604`, raised when the trailer tEXt
  // chunk is first encountered) and is SUPPRESSED — so the observable proof of the
  // re-scoping is the ABSENCE of a stray doc-level `ExifTool:Warning` for it. The
  // PNG port previously forwarded the XMP diagnostic UNCHANGED (leaking it as a
  // doc-level `ExifTool:Warning`) and shifted the decoded `XMP-dc:Format` tag to
  // `Trailer:Format`; it now (a) re-scopes the trailing XMP/EXIF diagnostics to
  // the `Trailer` group via the `xmp_is_trailing`/`event_is_trailing` watermarks
  // (mirroring the `warning_is_trailing` Warning arm) and (b) keeps the explicit
  // `XMP-<ns>` family-1 group (the `$grps[1] or …` short-circuit) so
  // `XMP-dc:Format` stays `XMP-dc`, NOT `Trailer`. No deferred-subsystem key to
  // drop, so a PLAIN `check`. Gated on the `xmp` feature (the golden expects the
  // decoded `XMP-dc:Format`, which a non-`xmp` build drops — mirrors
  // `png_rawprofile_xmp_conformance`). Oracle: bundled
  // `perl exiftool -j -G1 -struct` 13.59.
  check(
    "PNG_trailer_xmp_warn.png",
    "PNG_trailer_xmp_warn.png.json",
    true,
  );
  check(
    "PNG_trailer_xmp_warn.png",
    "PNG_trailer_xmp_warn.png.n.json",
    false,
  );
}

#[test]
#[cfg(feature = "png")]
fn png_idot_conformance() {
  // #142 — the Apple `iDOT` private vendor chunk (`AppleDataOffsets`,
  // `PNG.pm:331-342`, ref NealKrawetz). The chunk table is `Name =>
  // 'AppleDataOffsets', Binary => 1` with NO SubDirectory, so `FoundPNG`
  // (`PNG.pm:970-1148`) resolves the tagInfo, finds no subdir, and stores the
  // WHOLE 28-byte chunk value under `PNG:AppleDataOffsets`; because it is
  // `Binary => 1` the value renders as the universal `(Binary data 28 bytes,
  // use -b option to extract)` placeholder at any size. Crafted minimal 1x1 RGB
  // fixture (`tools/gen_png_idot_fixture.py`) whose only vendor chunk is `iDOT`,
  // placed directly after IHDR (the real Apple-PNG layout). PNG is in the
  // Composite allow-list, so the ported `Composite:ImageSize`/`Megapixels` are
  // kept and compared too (no exclusion — a PLAIN `check`). The OTHER four PNG
  // private chunks (`caBX`-JUMBF / `cpIp`-FlashPix / `meTa`-XML / `seAl`-SEAL,
  // `PNG.pm:343-382`) dispatch into large SubDirectory subsystems exifast does
  // not have and remain deferred (#142). Oracle: bundled `perl exiftool -j -G1
  // -struct` 13.59.
  check("PNG_idot.png", "PNG_idot.png.json", true);
  check("PNG_idot.png", "PNG_idot.png.n.json", false);
}

#[test]
#[cfg(feature = "png")]
fn png_gdat_conformance() {
  // #142 (Codex F2) — the `gdAT` gain-map chunk (`GainMapImage`, `PNG.pm:374-
  // 378`). The chunk table is `Name => 'GainMapImage', Groups => { 2 =>
  // 'Preview' }, Binary => 1` with NO SubDirectory — the SAME simple shape as
  // `iDOT` — so `FoundPNG` stores the WHOLE chunk value under
  // `PNG:GainMapImage` and renders the universal `(Binary data 20 bytes, use
  // -b option to extract)` placeholder (`-j`); exifast retains only the
  // payload LENGTH and renders the placeholder from it. The family-2 `Preview`
  // group does not surface under `-G1` (family-1 stays `PNG`). Crafted minimal
  // 1x1 RGB fixture (`tools/gen_png_idot_fixture.py`) whose only vendor chunk
  // is `gdAT`. PNG is in the Composite allow-list, so the ported
  // `Composite:ImageSize`/`Megapixels` are compared too (a PLAIN `check`).
  // Oracle: bundled `perl exiftool -j -G1 -struct` 13.59.
  check("PNG_gdat.png", "PNG_gdat.png.json", true);
  check("PNG_gdat.png", "PNG_gdat.png.n.json", false);
}

#[test]
#[cfg(feature = "png")]
fn png_idot_main_trailer_conformance() {
  // #142 (Codex [medium]) — the per-group `iDOT` fix. A PNG can carry the
  // `Binary => 1` `iDOT` chunk BOTH before `IEND` (stored under the `PNG`
  // family-1 group) AND as a post-`IEND` TRAILER chunk (stored under the
  // `Trailer` group, `PNG.pm:1479-1484` `SET_GROUP1 = 'Trailer'`). Bundled
  // emits BOTH placeholders — `PNG:AppleDataOffsets` (28 bytes, the pre-`IEND`
  // main) AND `Trailer:AppleDataOffsets` (4 bytes, the post-`IEND` trailer) —
  // under their DISTINCT family-1 groups. The previous singleton
  // `Option<usize>` model lost the main (the trailer setter overwrote it); the
  // per-group [`BinaryChunkLengths`] keeps both, STILL length-only (no payload
  // bytes). The trailer-ENTRY warning `Trailer data after PNG IEND chunk`
  // (`PNG.pm:1481`, raised BEFORE `SET_GROUP1`) stays the document `[minor]
  // ExifTool:Warning`. Crafted main+trailer fixture
  // (`tools/gen_png_idot_fixture.py`). PNG is in the Composite allow-list, so
  // the ported `Composite:ImageSize`/`Megapixels` are compared too (a PLAIN
  // `check` — no deferred keys to drop). Oracle: bundled `perl exiftool -j -G1
  // -struct` 13.59.
  check("PNG_idot_trailer.png", "PNG_idot_trailer.png.json", true);
  check("PNG_idot_trailer.png", "PNG_idot_trailer.png.n.json", false);
}

#[test]
#[cfg(feature = "png")]
fn png_gdat_main_trailer_conformance() {
  // #142 (Codex [medium]) — the same per-group fix for `gdAT` (GainMapImage).
  // A pre-`IEND` `gdAT` (→ `PNG:GainMapImage`, 20 bytes) and a post-`IEND`
  // trailer `gdAT` (→ `Trailer:GainMapImage`, 8 bytes) BOTH emit under their
  // distinct family-1 groups (the family-2 `Preview` group does not surface at
  // `-G1`). STILL length-only. The document `[minor] ExifTool:Warning` (the
  // trailer-entry warning) is emitted too. Crafted main+trailer fixture
  // (`tools/gen_png_idot_fixture.py`); a PLAIN `check`. Oracle: bundled `perl
  // exiftool -j -G1 -struct` 13.59.
  check("PNG_gdat_trailer.png", "PNG_gdat_trailer.png.json", true);
  check("PNG_gdat_trailer.png", "PNG_gdat_trailer.png.n.json", false);
}

#[test]
#[cfg(feature = "png")]
fn png_apng_conformance() {
  // #141 — the animated-PNG `acTL` Animation Control chunk (`PNG.pm:302-307`),
  // whose SubDirectory is the `AnimationControl` `ProcessBinaryData` table
  // (`PNG.pm:766-782`, `FORMAT => 'int32u'`): `AnimationFrames` (tag 0,
  // `num_frames`) + `AnimationPlays` (tag 1, `num_plays`, `PrintConv => '$val
  // || "inf"'` so a `0` play count renders as `"inf"` under `-j` and the raw
  // `0` under `-n`). `AnimationFrames`'s RawConv calls `OverrideFileType("APNG",
  // undef, "PNG")` (`PNG.pm:776`), promoting `File:FileType` → `APNG`,
  // `MIMEType` → `image/apng` (the `%mimeType{APNG}` lookup), and
  // `FileTypeExtension` → the EXPLICIT `"PNG"` arg (`png`/`PNG`) since `APNG`
  // has no `%fileTypeExt` entry. The `fcTL`/`fdAT` per-frame chunks have NO
  // bundled table (`PNG.pm:329-330` is comment-only), so the APNG metadata is
  // the `acTL` summary alone — verified vs bundled 13.59 (the crafted fixture
  // carries TWO `fcTL` + one `fdAT` frame, none of which emit any tag). Crafted
  // minimal 1x1 RGB APNG (`tools/make_apng.py`, valid CRC32 throughout;
  // `-validate` = OK). PNG is in the Composite allow-list, so the ported
  // `Composite:ImageSize`/`Megapixels` are compared too (a PLAIN `check`).
  // Oracle: bundled `perl exiftool -j -G1 -struct` 13.59.
  check("PNG_apng.png", "PNG_apng.png.json", true);
  check("PNG_apng.png", "PNG_apng.png.n.json", false);
}

#[test]
#[cfg(feature = "png")]
fn mng_mhdr_conformance() {
  // #143 — the MNG (Multi-image Network Graphics) sibling container. A
  // `\x8aMNG\r\n\x1a\n` signature (`PNG.pm:63`) selects the `MNG` container, so
  // `ProcessPNG` dispatches the header `MHDR` chunk through the `%MNG::Main`
  // FALLBACK table (`PNG.pm:1655`) onto the `MNGHeader` `ProcessBinaryData`
  // sub-table (`MNG.pm:146-160`, `FORMAT => 'int32u'`): ImageWidth/ImageHeight/
  // TicksPerSecond/NominalLayerCount/NominalFrameCount/NominalPlayTime (7x
  // int32u) + SimplicityProfile, whose `sprintf("0x%.8x", $val)` PrintConv
  // hand-port (`MNG.pm:158`) renders `0x00000049` under `-j` and the raw `73`
  // under `-n`. `File:FileType` = `MNG` (signature-authoritative), MIMEType
  // `video/mng`. The MNG container is in the Composite allow-list, so the ported
  // `Composite:ImageSize`/`Megapixels` (from ImageWidth/ImageHeight) are kept
  // and compared (a PLAIN `check`). Crafted minimal `MHDR`+`MEND` fixture
  // (`tools/gen_mng_fixtures.py`). Oracle: bundled `perl exiftool -j -G1 -struct`
  // 13.59.
  check("MNG_mhdr.mng", "MNG_mhdr.mng.json", true);
  check("MNG_mhdr.mng", "MNG_mhdr.mng.n.json", false);
}

#[test]
#[cfg(feature = "png")]
fn jng_jhdr_conformance() {
  // #143 — the JNG (JPEG Network Graphics) sibling container. A
  // `\x8bJNG\r\n\x1a\n` signature (`PNG.pm:64`) selects the `JNG` container
  // (whose END chunk is `IEND`, the same as PNG); the header `JHDR` chunk routes
  // through the `%MNG::Main` fallback onto the `JNGHeader` sub-table
  // (`MNG.pm:598-643`): ImageWidth/ImageHeight (int32u) then the int8u
  // ColorType/BitDepth/Compression/Interlace/AlphaBitDepth/AlphaCompression/
  // AlphaFilter/AlphaInterlace, with their int->label PrintConvs (`ColorType` 10
  // → "Color", `Compression` 8 → "Huffman-coded baseline JPEG", `Interlace` 0 →
  // "Sequential", `AlphaCompression` 8 → "JNG 8-bit Grayscale JDAA",
  // `AlphaFilter` 0 → "Adaptive MNG (N/A for JPEG)", `AlphaInterlace` 0 →
  // "Noninterlaced") under `-j`, raw ints under `-n`. `File:FileType` = `JNG`,
  // MIMEType `image/jng`. A PLAIN `check` (Composite allow-list). Crafted
  // minimal `JHDR`+`IEND` fixture. Oracle: bundled `perl exiftool` 13.59.
  check("JNG_jhdr.jng", "JNG_jhdr.jng.json", true);
  check("JNG_jhdr.jng", "JNG_jhdr.jng.n.json", false);
}

#[test]
#[cfg(feature = "png")]
fn mng_chunks_conformance() {
  // #143 — the MNG sub-table KITCHEN-SINK: one MNG-specific chunk per remaining
  // `%MNG::Main` entry, covering all 17 `ProcessBinaryData` sub-tables (BACK/
  // BASI/CLIP/CLON/DEFI/DHDR/eXPi/fPRI/JHDR-via-the-minimal-JNG/LOOP/MAGN/MHDR/
  // MOVE/PAST/PROM/SHOW/TERM), the 3 inline `ValueConv` chunks (DISC
  // `join(" ",unpack("n*"))` → "1 2 3"; DROP `$val=~/..../g` 4-char split →
  // "BACK MHDR"; SEEK `$val=~s/\0.*//s` NUL-strip → "point1"), the 6 `Binary =>
  // 1` chunks (DBYK/FRAM/nEED/ORDR/PPLT/SAVE — each the universal `(Binary data
  // N bytes …)` placeholder from the chunk LENGTH, incl. a 0-byte SAVE), and the
  // `pHYg` (`GlobalPixelSize`) chunk whose SubDirectory onto `PNG::PhysicalPixel`
  // routes to the SHARED PNG `pHYs` decoder, emitting `PixelsPerUnitX`/`…Y`/
  // `PixelUnits` under family-1 `PNG-pHYs` (NOT `MNG`). Exercises every
  // hand-ported conv (the BASI ColorType "RGB with Alpha"; the preserved-as-is
  // ExifTool typos "Parital"/"Desination"→"Target Origin") and the last-wins
  // `TagMap` dedup (BASI's ImageWidth=64 overrides MHDR's 160; CLIP/MOVE/fPRI
  // share `DeltaType`), so `Composite:ImageSize` resolves to 64x48 (BASI's
  // dimensions). A PLAIN `check` (Composite allow-list). Crafted multi-chunk
  // fixture (`tools/gen_mng_fixtures.py`). Oracle: bundled `perl exiftool -j -G1
  // -struct` 13.59.
  check("MNG_chunks.mng", "MNG_chunks.mng.json", true);
  check("MNG_chunks.mng", "MNG_chunks.mng.n.json", false);
}

#[test]
#[cfg(feature = "png")]
fn mng_trailer_conformance() {
  // #143 Codex Finding 2 — a post-`MEND` MNG TRAILER chunk. The fixture is a
  // MNG (`MHDR` + `MEND`) followed by a single trailing `BACK` chunk
  // (BackgroundColor "1 2 3"). After the `MEND` end chunk the walker enters
  // trailer mode (`PNG.pm:1479-1484` `SET_GROUP1 = 'Trailer'`), so the `BACK`
  // chunk's MNG leaf emits under family-1 `Trailer`, NOT `MNG` —
  // `Trailer:BackgroundColor`, distinct from the main `MNG:*` (the
  // `(doc, family1, name)` dedup key). The document carries the minor
  // `Trailer data after MNG MEND chunk` warning. The MHDR ImageWidth/Height
  // feed the ported `Composite:ImageSize`/`Megapixels` (kept, PNG Composite
  // allow-list). The same-named main-vs-trailer COEXISTENCE (a trailer chunk
  // does NOT overwrite the main `MNG:*`) is covered by the MngMeta unit test
  // `post_end_chunk_emits_under_trailer_group` (a single trailing chunk here
  // sidesteps the unrelated multi-chunk `[x2]` trailer-warning aggregation).
  // Crafted (PNG-CRC chunk builder). Oracle: bundled `perl exiftool -j -G1
  // -struct` 13.59.
  check("MNG_trailer.mng", "MNG_trailer.mng.json", true);
  check("MNG_trailer.mng", "MNG_trailer.mng.n.json", false);
}

#[test]
#[cfg(feature = "png")]
fn mng_embedded_ihdr_conformance() {
  // #143 — a realistic MIXED MNG: the header `MHDR` (ImageWidth=160) FOLLOWED
  // by an embedded PNG `IHDR` chunk (ImageWidth=320), then `MEND`. `ProcessPNG`
  // resolves a chunk against `%PNG::Main` BEFORE the `%MNG::Main` fallback
  // (`PNG.pm:1653-1656`), so the `MHDR` emits the MNGHeader leaves
  // (`MNG:ImageWidth=160`) while the embedded `IHDR` emits the PNG ImageHeader
  // leaves (`PNG:ImageWidth=320`) — BOTH dimension pairs are present.
  //
  // `Composite:ImageSize` `Require`s the BARE `ImageWidth`/`ImageHeight`. Both
  // the MNG (MHDR) and the PNG-IHDR producers are equal priority 1, and
  // ExifTool keeps the LAST-walked of an equal-priority duplicate
  // (`ExifTool.pm:9544-9560`), so the `IHDR` — walked AFTER the `MHDR` — wins ⇒
  // bundled `Composite:ImageSize = 320x240` (NOT the MHDR 160x120). exifast's
  // category-grouped emission lists the PNG-IHDR singleton's `ImageWidth` and
  // its first-match composite resolution likewise yields `320x240`, so the
  // realistic mixed case is byte-for-byte identical to bundled.
  //
  // This guards that the realistic MHDR→IHDR mixed-MNG composite matches
  // bundled. (The CRAFTED three-equal-producer Case-A — MHDR→IHDR→BASI — that
  // needs the port-wide composite-engine priority+recency fix is DEFERRED to
  // #436; the Codex R3 finding's "MHDR wins" premise was ground-truth-disputed
  // — bundled keeps the LAST-walked IHDR here.) Crafted via
  // `tools/gen_mng_fixtures.py`. Oracle: bundled `perl exiftool -j -G1 -struct`
  // 13.59 (`MNG:ImageWidth=160` + `PNG:ImageWidth=320` + `Composite:ImageSize=
  // 320x240`). NO code change — a pure fixture addition.
  check("MNG_embedded_ihdr.mng", "MNG_embedded_ihdr.mng.json", true);
  check(
    "MNG_embedded_ihdr.mng",
    "MNG_embedded_ihdr.mng.n.json",
    false,
  );
}

#[test]
#[cfg(feature = "png")]
fn png_cabx_jumbf_conformance() {
  // #142 (JUMBF / C2PA, Phase 1: box structure) — a PNG `caBX` chunk
  // (`PNG.pm:343-346`: `caBX` -> `Jpeg2000::Main` SubDirectory) carries a JUMBF
  // box stream. `jumb` (the superbox, `ProcessJUMB`, `Jpeg2000.pm:777`) opens a
  // `Doc<N>` sub-document and recurses; `jumd` (the description box,
  // `ProcessJUMD`, `Jpeg2000.pm:803`) carries a 16-byte type-UUID + a toggle
  // byte + a NUL-terminated label. This structure-only fixture is
  // `jumb -> jumd(JSON type-UUID, toggles Requestable+Label, label "c2pa.test")`
  // with NO content box (the json/cbor CONTENT decoders are Phases 2-3, so a
  // Phase-1 golden must avoid them to stay byte-exact). `JUMBF:JUMDType` renders
  // the `Jpeg2000.pm:746-752` PrintConv split + ASCII-detect under `-j`
  // (`(json)-0011-0010-800000aa00389b71`) and the raw `unpack "H*"` hex under
  // `-n` (`6a736f6e…`); `JUMBF:JUMDLabel` is the raw label. `JUMDToggles` is
  // `Unknown => 1` (`Jpeg2000.pm:761`) so it is SUPPRESSED from the default
  // output. `File:FileType` stays PNG (`caBX` is just a chunk); the ported PNG
  // `Composite:ImageSize`/`Megapixels` are kept (PNG is Composite-allow-listed).
  // Crafted via `tools/gen_jumbf_fixtures.py`. Oracle: bundled `perl exiftool
  // -j -G1 -struct` 13.59.
  check("PNG_cabx_jumbf.png", "PNG_cabx_jumbf.png.json", true);
  check("PNG_cabx_jumbf.png", "PNG_cabx_jumbf.png.n.json", false);
}

#[test]
#[cfg(feature = "png")]
fn png_cabx_binary_conformance() {
  // #142 (JUMBF Phase 1) — the binary content boxes. `jumb -> jumd(raw JPEG
  // type-UUID `6579d6fb…`, NO label) + bfdb + bidb`. The raw type-UUID's first
  // 4 bytes are NOT printable ASCII, so `JUMBF:JUMDType` renders the raw
  // `6579d6fb-dba2-446b-b2ac1b82feeb89d1` (no `(text)` substitution,
  // `Jpeg2000.pm:750`). `bfdb` (`BinaryDataType`, `Jpeg2000.pm:425`) carries a
  // toggle byte + a NUL-padded MIME type — its ValueConv drops the toggle byte
  // and trims NULs -> `Jpeg2000:BinaryDataType = image/jpeg`. `bidb`
  // (`BinaryData`, `Binary => 1`, `Groups => { 2 => Preview }`,
  // `Jpeg2000.pm:433`) emits the `(Binary data 16 bytes …)` placeholder from the
  // payload LENGTH. Both content tags emit under the `Jpeg2000` group (they live
  // in `%Jpeg2000::Main`, default group `Jpeg2000`, NOT `JUMBF`) since this
  // jumd carries no label to rename them. Crafted via
  // `tools/gen_jumbf_fixtures.py`. Oracle: bundled `perl exiftool` 13.59.
  check("PNG_cabx_binary.png", "PNG_cabx_binary.png.json", true);
  check("PNG_cabx_binary.png", "PNG_cabx_binary.png.n.json", false);
}

#[test]
#[cfg(feature = "png")]
fn png_cabx_label_rename_conformance() {
  // #142 (JUMBF Phase 1) — the JUMBFLabel rename (`Jpeg2000.pm:1205-1212`).
  // `jumb -> jumd(label "c2pa.assertions") + bfdb + c2sh`. The label is
  // sanitized (`Jpeg2000.pm:824-831`: capitalize-after-illegal + strip-illegal +
  // `C2pa`->`C2PA`) to the `JUMBFLabel` `C2PAAssertions`, which RENAMES the
  // following content tags by joining the label + each box's `JUMBF_Suffix`
  // (`bfdb`->`Type`, `c2sh`->`Salt`) and applying `AddTagToTable`'s name
  // legalization (`ExifTool.pm:6488`): `Jpeg2000:C2PAAssertionsType =
  // application/octet-stream` and `Jpeg2000:C2PAAssertionsSalt = deadbeefcafe`
  // (the `c2sh` `unpack "H*"` hex). The renamed tags keep the `Jpeg2000` group.
  // Crafted via `tools/gen_jumbf_fixtures.py`. Oracle: bundled `perl exiftool`
  // 13.59.
  check(
    "PNG_cabx_label_rename.png",
    "PNG_cabx_label_rename.png.json",
    true,
  );
  check(
    "PNG_cabx_label_rename.png",
    "PNG_cabx_label_rename.png.n.json",
    false,
  );
}

#[test]
#[cfg(feature = "png")]
fn png_cabx_json_conformance() {
  // #142 (JUMBF / C2PA, Phase 2: the `json` content decoder) — a PNG `caBX`
  // chunk whose `jumb -> jumd(label "c2pa.test", JSON type-UUID) + json{...}`
  // carries a representative C2PA-ish JSON document. The `json` box
  // (`Jpeg2000.pm:409-418`: `JSONData`, `SubDirectory => JSON::Main`) is decoded
  // by `ProcessJSON` (`JSON.pm:118`) over `Import::ReadJSONObject`
  // (`Import.pm:138`), emitting FLATTENED `JSON:<key>` tags (group `JSON`,
  // `JSON.pm:23`) on this box's `Doc1` axis. Under the golden's `-struct` regime
  // (`Options('Struct') == 1`), each TOP-LEVEL key becomes ONE tag
  // (`JSON.pm:96-98` emits the struct then `return unless Struct > 1`): a nested
  // object is a `-struct` Map with RAW inner keys (`JSON:Thumbnail`), an array
  // stays a list (`JSON:Assertions` of objects, `JSON:Ingredients` of scalars),
  // and scalars render through the `EscapeJSON` number/boolean gate
  // (`XMPStruct.pl:166-176`) — `JSON:Version`/`Score` BARE numbers,
  // `JSON:Validated`/`Revoked` BARE booleans, `JSON:Signature` the quoted
  // `"null"` (the `MissingTagValue` default, `JSON.pm:6`), and `JSON:Serial` the
  // QUOTED 19-digit number (the gate caps the integer part at 15 digits). The
  // top-level NAMES are legalized (`FoundTag` + `AddTagToTable`): `ucfirst`
  // (`claim_generator -> Claim_generator`, `instanceID -> InstanceID`) and the
  // C2PA-case hack (`c2pa.manifest -> C2PAmanifest`). The `JSON:*` tags keep
  // group `JSON` regardless of the active JUMBFLabel (the rename only affects
  // the block-extract name, not the SubDirectory's flattened tags). `-j` and
  // `-n` agree on every JSON value (no PrintConv). Crafted via
  // `tools/gen_jumbf_fixtures.py`. Oracle: bundled `perl exiftool -j -G1 -struct`
  // 13.59.
  check("PNG_cabx_json.png", "PNG_cabx_json.png.json", true);
  check("PNG_cabx_json.png", "PNG_cabx_json.png.n.json", false);
}

#[test]
#[cfg(feature = "png")]
fn png_cabx_cbor_conformance() {
  // #142 (JUMBF / C2PA, Phase 3: the `cbor` content decoder, the FINAL phase) —
  // a PNG `caBX` chunk whose `jumb -> jumd(label "c2pa.test", `(cbor)` type-UUID)
  // + cbor{...}` carries a representative C2PA-ish CBOR document (RFC 8949, the
  // native C2PA manifest-store format). The `cbor` box (`Jpeg2000.pm:420-424`:
  // `CBORData`, `Flags => ['Binary','Protected']` — NO `BlockExtract`,
  // `SubDirectory => CBOR::Main`) is decoded by `ProcessCBOR` (`CBOR.pm:274`) over
  // the recursive `ReadCBORValue` (`CBOR.pm:88`), emitting FLATTENED `CBOR:<key>`
  // tags (family-0 `JUMBF` / family-1 `CBOR`, `CBOR.pm:64`) on this box's `Doc1`
  // axis via the SAME `JSON::ProcessTag` flatten the `json` box uses. Exercises
  // every CBOR major type + the faithful ExifTool QUIRKS, oracle-verified vs
  // bundled 13.59:
  //   * the predefined `CBOR::Main` names (`dc:title`->`CBOR:Title`,
  //     `dc:format`->`CBOR:Format`, `instanceID`->`CBOR:InstanceID`) vs the
  //     auto-legalized keys (`claim_generator`->`Claim_generator`, the C2PA-case
  //     hack `c2pa.manifest`->`C2PAmanifest`);
  //   * a native unsigned int (`CBOR:Count` 42 BARE), the `-1 * num` NEGATIVE
  //     quirk (wire `-7` -> `CBOR:Neg` `-6`, `CBOR.pm:121`), a 19-digit int
  //     (`CBOR:Serial` QUOTED by the `EscapeJSON` 15-digit gate);
  //   * a byte string + a COSE_Sign1 `tag(18)` BOTH as the `(Binary data N
  //     bytes …)` placeholder — COSE stays OPAQUE, no crypto (`CBOR.pm:138-144`);
  //   * a nested map as a `-struct` Map with RAW inner keys (`CBOR:Thumbnail` —
  //     a nested `-6`, a nested placeholder, a nested EMPTY array preserved as
  //     `[]` — the empty-array skip is TOP-LEVEL only);
  //   * arrays of scalars (`CBOR:Ingredients`) + of maps (`CBOR:Assertions`);
  //   * a double (`CBOR:Score` 0.5) + the faithfully-buggy HALF-float (wire
  //     `0x3c00` = true IEEE 1.0 -> `CBOR:Half` `7.88860905221012e-31` via
  //     `($mant+1024) ** ($exp-25)`, `CBOR.pm:237-248`), `true`/`false`, and
  //     `null` (the literal `"null"` `MissingTagValue` default, `CBOR.pm:59`);
  //   * a `tag(0)` date-time string through `ConvertXMPDate` (`CBOR.pm:213-215`,
  //     locale-INDEPENDENT: `2021-06-15T12:30:45Z` -> `CBOR:Created`
  //     `2021:06:15 12:30:45Z`).
  // The `CBOR:*` tags keep family-1 `CBOR` regardless of the active JUMBFLabel
  // (`cbor` lacks `BlockExtract`, so the `Jpeg2000.pm:1206` rename never fires).
  // `-j` and `-n` agree on every CBOR value (the major-6 conversions are applied
  // at decode; no PrintConv). NO tag-1 epoch is used (`ConvertUnixTime`'s
  // `$toLocal=1` is machine-locale dependent). Crafted via
  // `tools/gen_jumbf_fixtures.py`. Oracle: bundled `perl exiftool -j -G1 -struct`
  // 13.59.
  check("PNG_cabx_cbor.png", "PNG_cabx_cbor.png.json", true);
  check("PNG_cabx_cbor.png", "PNG_cabx_cbor.png.n.json", false);
}

// Add one `#[test]` per ported format here, in FORMATS.md order, each
// asserting both snapshots: check("X.ext","X.ext.json",true) and
// check("X.ext","X.ext.n.json",false).

// #362 / #213 — BlackVue DR770X dashcam (PittaSoft). The top-level
// `free`/`%QuickTime::Pittasoft` SubDirectory (Copyright/StartTime/
// OriginalFileName + the PreviewImage/GPSLog binary placeholders + the no-`ee`
// first-record TimeCode/Accelerometer from `3gf `) and the audio `chan`
// `%QuickTime::ChannelLayout` (LayoutFlags/AudioChannelTypes/
// NumChannelDescriptions) are byte-exact at both `-j`/`-n`, plus the no-`ee`
// `EEWarn` (the `3gf ` multi-record truncation, which outranks the later
// truncated-`mdat` doc warning by file position). The ported Composites
// (ImageSize/Megapixels/AvgBitrate/Rotation) are kept; only `System:all` is
// excluded (the gen_golden arm). No `.ee.*` golden — `-ee` surfaces no timed
// metadata for this file.
#[test]
fn mp4_blackvue_dr770x_conformance() {
  check(
    "MP4_blackvue_dr770x.mp4",
    "MP4_blackvue_dr770x.mp4.json",
    true,
  );
  check(
    "MP4_blackvue_dr770x.mp4",
    "MP4_blackvue_dr770x.mp4.n.json",
    false,
  );
}

// #138 / #129 — Pruveeo D90 dashcam: LIGOGPSINFO data in an MPEG-TS container.
// The no-`ee` path is byte-exact (M2TS/H264 structural tags; the Composite
// `ImageSize`/`Megapixels` are excluded per the QuickTime/MPEG-MOV precedent —
// the port has no Composite subsystem). The `-ee` LIGOGPSINFO timed GPS (the
// `type == 6 and $pid == 0x0300` dashcam arm, M2TS.pm:308-318) is pinned in
// `tests/timed_metadata_conformance.rs::pruveeo_d90_ligogps_ee_byte_exact`.
#[test]
fn mpeg2_ts_pruveeo_d90_conformance() {
  check(
    "MPEG2_TS_pruveeo_d90.ts",
    "MPEG2_TS_pruveeo_d90.ts.json",
    true,
  );
  check(
    "MPEG2_TS_pruveeo_d90.ts",
    "MPEG2_TS_pruveeo_d90.ts.n.json",
    false,
  );
}

// #311/#318 — the five additional Pentax body fixtures (K-1/K-3/K-5 II/K-70/KP).
// The #379 Pentax port (the same body-agnostic Main leaves + the AEInfo3/
// LensInfo/KelvinWB/world-time/level/CAF/face/AWB/EV/filter/CameraInfo/
// BatteryInfo sub-tables proven on `JPEG_pentax_ks2.jpg`) decodes the BULK of
// each body byte-exact vs bundled ExifTool 13.59 — 221-230 tags per fixture,
// across both byte orders (K-1/K-3/K-70/KP little-endian; K-5 II BIG-endian, its
// sub-table values decoded BE via the resolved-subdir probe order). The
// conformance assertion below verifies those byte-exact; only the documented
// `*_DEFERRED` residuals are dropped from BOTH sides (the goldens keep the
// faithful full 13.59 dump).
//
// `Composite:Flash` (the XMP-Flash bitmask Composite), `Composite:LensID` (the
// unambiguous-Pentax-LensType resolution Composite) and `PrintIM:PrintIMVersion`
// (the IFD0 `0xc4a5` PrintIM directory) are NOW PORTED (#381) — emitted
// byte-exact for these bodies, so they are NO LONGER in the `*_DEFERRED` lists.
// EVERY `*_DEFERRED` list still shares ONE cross-cutting deferral (plus KS-2's
// `Composite:DateTimeCreated`, which needs an IPTC date these bodies lack):
//   * `XMP-tiff:YCbCrSubSampling` — the unported `RawJoin`/`%JPEG::
//                                   yCbCrSubSampling` PrintConv (`xmp/tables.rs`).
//
// #311 PORTED the per-body multi-model `%Pentax::Main` conditional branches the
// `#379` body-agnostic port had suppressed (see `vendors/pentax/tags.rs::
// conditional_leaf`, `printconv.rs::af_point_selected_for_model` and
// `subtables.rs::{emit_af_point_info,emit_battery_info}`), now emitted byte-exact:
//
//   * `AFPointSelected` (0x000e)   — the model-keyed K-1/645Z (33-point) and
//        K-3/KP (27-point) element-0 hashes (`Pentax.pm:1219-1408`), routed by
//        `$$self{Model}` + the count-2 second positional element. (K-5 II/K-70/K-S2
//        keep the "other models" 11-point hash.)
//   * `ExposureCompensation` (0x0016) — the `Count => 2` variant (`Pentax.pm:1605`):
//        its ValueConv strips all but element 0, so it equals the `$count == 1`
//        scalar. Now un-gated.
//   * `NumAFPoints`/`AFPointsInFocus`/`AFPointsSelected`/`AFPointsSpecial` — the
//        `%Pentax::AFPointInfo` (0x0245) SubDirectory + its `DecodeAFPoints`
//        bit-mask decoder (`Pentax.pm:6067-6100`, K-1/KP/K-70). The
//        `DecodeAFPoints` `$mask`/`$bitVal` separation is now faithful.
//   * `BodyBatteryVoltage3`/`4` (`%Pentax::BatteryInfo` offsets 6/8,
//        `Pentax.pm:4941-4960`, `/(K-5|K-r|645D)\b/` and `/(K-5|K-r)\b/`, K-5 II).
//
// PLUS the per-body `Pentax:*` residuals NOT in #311 scope (still DEFERRED — the
// port emits nothing, so the golden retains the bundled value and the key is
// dropped from both sides):
//
//   * `ContrastHighlight`/`ContrastShadow`/`ContrastHighlightShadowAdj`
//        (0x006d/6e/6f), `ISOAutoMinSpeed` (0x007a), `ShutterType` (0x0087),
//        `SkinToneCorrection` (0x0095), `SensorSize` (0x0064) — `%Pentax::Main`
//        leaves not yet in `PENTAX_TAGS`.
//   * `PixelShiftResolution` — the `%Pentax::PixelShiftInfo` (0x0243)
//        SubDirectory (unported).
//   * `SensorTemperature`/`SensorTemperature2`/`CameraTemperature4`/`5` — the
//        `%Pentax::TempInfo` (0x03ff) SubDirectory (unported).
//   * (K-5 II only) the `$count`-91 `%Pentax::LensInfo3` variant
//        (`LensFocalLength`/`MaxAperture`/`MinFocusDistance`/`NominalMax`/`Min
//        Aperture`/`FocusRangeIndex`), the `%Pentax::WBLevels` (0x022d)
//        `WB_RGGBLevels*` table, the `%Pentax::ShotInfo` `CameraOrientation`,
//        the `%Pentax::AEInfo` `LevelIndicator`, the `%Pentax::CameraSettings`
//        `ISOAuto`/`LinkAEToAFPoint`/`SensitivitySteps`, and the
//        `Pentax:PreviewImageStart` IsOffset pointer — all deferred
//        K-5-II-specific `$count`/offset SubDirectory variants.
//
// (The K-3 Mark III `AFInfoK3III` `AFPointValues`/`AFPointsSelected` and the
// *istD-family AFPointSelected variants are also deferred — no fixture.)

// K-1: #311 PORTED the K-1 (`/(K-1|645Z)\b/`) AFPointSelected model variant, the
// count-2 ExposureCompensation, and the `%Pentax::AFPointInfo` (0x0245) subdir
// (NumAFPoints + AFPointsInFocus/AFPointsSelected/AFPointsSpecial via
// `DecodeAFPoints`) — all now byte-exact, so they are NO LONGER excluded. The
// residual deferrals are NON-#311 `%Pentax::Main` leaves not yet in `PENTAX_TAGS`
// (Contrast*/ISOAutoMinSpeed/ShutterType/SkinToneCorrection) and the `0x0243
// PixelShiftInfo` subdir (PixelShiftResolution).
const K1_DEFERRED: &[&str] = &[
  "XMP-tiff:YCbCrSubSampling",
  "Pentax:ContrastHighlight",
  "Pentax:ContrastHighlightShadowAdj",
  "Pentax:ContrastShadow",
  "Pentax:ISOAutoMinSpeed",
  "Pentax:PixelShiftResolution",
  "Pentax:ShutterType",
  "Pentax:SkinToneCorrection",
];

// K-3: #311 PORTED the K-3 (`/(K-3|KP)\b/`) AFPointSelected model variant (now
// byte-exact, no longer excluded). The residuals are the `0x03ff TempInfo` subdir
// (SensorTemperature/2) and the non-#311 Contrast*/ISOAutoMinSpeed Main leaves.
const K3_DEFERRED: &[&str] = &[
  "XMP-tiff:YCbCrSubSampling",
  "Pentax:ContrastHighlight",
  "Pentax:ContrastHighlightShadowAdj",
  "Pentax:ContrastShadow",
  "Pentax:ISOAutoMinSpeed",
  "Pentax:SensorTemperature",
  "Pentax:SensorTemperature2",
];

// K-5 II (BIG-endian): #311 PORTED the `%Pentax::BatteryInfo` `/(K-5|K-r|645D)\b/`
// BodyBatteryVoltage3 (offset 6) and `/(K-5|K-r)\b/` BodyBatteryVoltage4 (offset
// 8) — now byte-exact, no longer excluded. The remaining residuals are the
// deferred K-5-II `$count`/offset SubDirectory variants (LensInfo3 / WBLevels /
// ShotInfo / AEInfo / CameraSettings / TempInfo) + the Contrast/ISOAutoMinSpeed
// Main leaves + the IsOffset PreviewImageStart — none of them #311.
const K5_II_DEFERRED: &[&str] = &[
  "XMP-tiff:YCbCrSubSampling",
  "Pentax:CameraOrientation",
  "Pentax:CameraTemperature4",
  "Pentax:CameraTemperature5",
  "Pentax:ContrastHighlight",
  "Pentax:ContrastHighlightShadowAdj",
  "Pentax:ContrastShadow",
  "Pentax:FocusRangeIndex",
  "Pentax:ISOAuto",
  "Pentax:ISOAutoMinSpeed",
  "Pentax:LensFocalLength",
  "Pentax:LevelIndicator",
  "Pentax:LinkAEToAFPoint",
  "Pentax:MaxAperture",
  "Pentax:MinFocusDistance",
  "Pentax:NominalMaxAperture",
  "Pentax:NominalMinAperture",
  "Pentax:PreviewImageStart",
  "Pentax:SensitivitySteps",
  "Pentax:SensorSize",
  "Pentax:SensorTemperature",
  "Pentax:SensorTemperature2",
  "Pentax:WB_RGGBLevelsCloudy",
  "Pentax:WB_RGGBLevelsDaylight",
  "Pentax:WB_RGGBLevelsFlash",
  "Pentax:WB_RGGBLevelsFluorescentD",
  "Pentax:WB_RGGBLevelsFluorescentL",
  "Pentax:WB_RGGBLevelsFluorescentN",
  "Pentax:WB_RGGBLevelsFluorescentW",
  "Pentax:WB_RGGBLevelsShade",
  "Pentax:WB_RGGBLevelsTungsten",
  "Pentax:WB_RGGBLevelsUserSelected",
];

// KP: identical residual shape to K-1 after #311. PORTED: the KP (`/(K-3|KP)\b/`)
// AFPointSelected variant, the count-2 ExposureCompensation, and the
// `%Pentax::AFPointInfo` (0x0245) subdir (NumAFPoints + AFPointsInFocus/Selected/
// Special) — all byte-exact, no longer excluded. The residuals are the non-#311
// Contrast*/ISOAutoMinSpeed/ShutterType/SkinToneCorrection Main leaves and the
// `0x0243 PixelShiftInfo` subdir.
const KP_DEFERRED: &[&str] = &[
  "XMP-tiff:YCbCrSubSampling",
  "Pentax:ContrastHighlight",
  "Pentax:ContrastHighlightShadowAdj",
  "Pentax:ContrastShadow",
  "Pentax:ISOAutoMinSpeed",
  "Pentax:PixelShiftResolution",
  "Pentax:ShutterType",
  "Pentax:SkinToneCorrection",
];

// K-70 deferred Pentax leaves. Like K-1/KP but NO 0x000e AFPointSelected (the
// K-70 0x000e is the unrelated CAFPointInfo internal, already emitted) and NO
// ISOAutoMinSpeed in the bundled dump — the AFPointInfo/PixelShiftInfo/Contrast/
// ShutterType/SkinToneCorrection/ExposureCompensation/AFPointsInFocus residuals.
//
// #380 RESOLVED: the three EXIF-rational-PRECISION residuals this body's `1/60`
// ExposureTime once surfaced (`ExifIFD:ExposureTime`, `Composite:ShutterSpeed`
// which selects it verbatim, and `Composite:LightValue` whose `CalculateLV`
// consumes the shutter) are no longer deferred. `Conv::ExposureTime` now rounds
// the `rational64u` quotient via `RoundFloat($num/$den, 10)` (`Exif.pm:6114`),
// exactly as ExifTool's `GetRational64u` reader does, so `-n` prints
// `0.01666666667` (not full-f64 `0.0166666666666667`) and the rounded value
// propagates byte-exact to the two Composites. The remaining entries are only
// unimplemented Pentax leaves, so K-70 now activates honestly.
// #311 PORTED the count-2 ExposureCompensation and the `%Pentax::AFPointInfo`
// (0x0245) subdir (NumAFPoints + AFPointsInFocus/Selected/Special via
// `DecodeAFPoints`) — byte-exact, no longer excluded. (K-70's 0x000e is the
// unrelated CAFPointInfo internal, already emitted, so no AFPointSelected entry.)
// The residuals are the non-#311 Contrast*/ShutterType/SkinToneCorrection Main
// leaves and the `0x0243 PixelShiftInfo` subdir.
const K70_DEFERRED: &[&str] = &[
  "XMP-tiff:YCbCrSubSampling",
  "Pentax:ContrastHighlight",
  "Pentax:ContrastHighlightShadowAdj",
  "Pentax:ContrastShadow",
  "Pentax:PixelShiftResolution",
  "Pentax:ShutterType",
  "Pentax:SkinToneCorrection",
];

// #311 — Pentax K-1 MakerNote conditional branches
#[test]
fn jpeg_pentax_k1_conformance() {
  check_excluding(
    "JPEG_pentax_k1.jpg",
    "JPEG_pentax_k1.jpg.json",
    true,
    K1_DEFERRED,
  );
  check_excluding(
    "JPEG_pentax_k1.jpg",
    "JPEG_pentax_k1.jpg.n.json",
    false,
    K1_DEFERRED,
  );
}

// #311 — Pentax K-3 MakerNote (FlashExposureComp count-2, AFPointsInFocus)
#[test]
fn jpeg_pentax_k3_conformance() {
  check_excluding(
    "JPEG_pentax_k3.jpg",
    "JPEG_pentax_k3.jpg.json",
    true,
    K3_DEFERRED,
  );
  check_excluding(
    "JPEG_pentax_k3.jpg",
    "JPEG_pentax_k3.jpg.n.json",
    false,
    K3_DEFERRED,
  );
}

// #311 — Pentax K-5 II MakerNote. BIG-endian body — the bulk of the sub-table
// values decode BE byte-exact; only the deferred K-5-II `$count`/offset variant
// SubDirectories remain (see `K5_II_DEFERRED`).
#[test]
fn jpeg_pentax_k5_ii_conformance() {
  check_excluding(
    "JPEG_pentax_k5_ii.jpg",
    "JPEG_pentax_k5_ii.jpg.json",
    true,
    K5_II_DEFERRED,
  );
  check_excluding(
    "JPEG_pentax_k5_ii.jpg",
    "JPEG_pentax_k5_ii.jpg.n.json",
    false,
    K5_II_DEFERRED,
  );
}

// #311 — Pentax KP MakerNote (AFPointSelected, BatteryVoltage)
#[test]
fn jpeg_pentax_kp_conformance() {
  check_excluding(
    "JPEG_pentax_kp.jpg",
    "JPEG_pentax_kp.jpg.json",
    true,
    KP_DEFERRED,
  );
  check_excluding(
    "JPEG_pentax_kp.jpg",
    "JPEG_pentax_kp.jpg.n.json",
    false,
    KP_DEFERRED,
  );
}

// #311 — Pentax K-70 MakerNote (AFPointSelected, BatteryVoltage).
//
// ACTIVATED by #380: this body's `1/60` `rational64u` ExposureTime was the first
// active fixture whose shutter is NOT a clean rational. `Conv::ExposureTime` now
// rounds the quotient via `RoundFloat($num/$den, 10)` (`Exif.pm:6114`) exactly as
// ExifTool's `GetRational64u` reader does, so `ExifIFD:ExposureTime` renders
// `0.01666666667` (not full-f64 `0.0166666666666667`) and the rounded value
// propagates byte-exact to `Composite:ShutterSpeed` (selects it verbatim) and
// `Composite:LightValue` (`CalculateLV` consumes the shutter). `K70_DEFERRED` now
// strips ONLY unimplemented Pentax leaves, so K-70 activates honestly alongside
// the other four bodies (NOT_ACTIVE entry dropped, count 572→573).
#[test]
fn jpeg_pentax_k70_conformance() {
  check_excluding(
    "JPEG_pentax_k70.jpg",
    "JPEG_pentax_k70.jpg.json",
    true,
    K70_DEFERRED,
  );
  check_excluding(
    "JPEG_pentax_k70.jpg",
    "JPEG_pentax_k70.jpg.n.json",
    false,
    K70_DEFERRED,
  );
}

// #311 — Pentax K-S2 MakerNote. Full Pentax tag set (140 tags) byte-exact vs
// bundled 13.59: the AEInfo3/LensInfo5/KelvinWB/TimeInfo/LensCorr/FaceInfo/
// AWBInfo/EVStepInfo/LevelInfo/CAFPointInfo/FilterInfo sub-tables + the
// BodyBatteryVoltage1/2 BatteryInfo variant + the parent-order-threaded
// CameraInfo + the Main-table leaves (AspectRatio/HDR/DynamicRangeExpansion/
// FaceDetect/ColorMatrixA2/B2/AFPointSelected[2-element]/AFPointsInFocus/
// FlashExposureComp[int8s array]/… + ExtenderStatus).
//
// `Composite:Flash` (the XMP-Flash bitmask Composite), `Composite:LensID` (the
// unambiguous-Pentax-LensType resolution Composite), `Composite:DateTimeCreated`
// (the IPTC `DateCreated`+`TimeCreated` Composite) and `PrintIM:PrintIMVersion`
// (the IFD0 `0xc4a5` PrintIM directory) are NOW PORTED (#381) — emitted
// byte-exact, so they are NO LONGER excluded. The sole remaining deferral is
// `XMP-tiff:YCbCrSubSampling` (exifast emits the raw `[2,1]` — the
// `tiff:YCbCrSubSampling` field is DOCUMENTED as needing the unported `RawJoin`
// + `%JPEG::yCbCrSubSampling` PrintConv, `xmp/tables.rs:47`). The golden keeps
// it (faithful 242-tag 13.59 dump); it is dropped from BOTH sides so the Pentax
// set + the four newly-emitted cross-cutting tags + the rest verify byte-exact.
#[test]
fn jpeg_pentax_ks2_conformance() {
  const DEFERRED: &[&str] = &["XMP-tiff:YCbCrSubSampling"];
  check_excluding(
    "JPEG_pentax_ks2.jpg",
    "JPEG_pentax_ks2.jpg.json",
    true,
    DEFERRED,
  );
  check_excluding(
    "JPEG_pentax_ks2.jpg",
    "JPEG_pentax_ks2.jpg.n.json",
    false,
    DEFERRED,
  );
}

// #122 / #361 — Parrot Anafi drone MP4. The `mett` metadata track carries no
// per-sample timed telemetry that bundled ExifTool 13.59 surfaces (`-ee` output
// is byte-identical to the base — there is no `.ee.*` golden), so the base
// goldens fully pin the parity. exifast emits the QuickTime/Track structure +
// the `udta` Parrot `UserData:Make`/`Model` + the ported ImageSize/Megapixels/
// AvgBitrate/Rotation Composites byte-exact.
//
// #361 — the embedded XMP packet (`uuid`-XMP → the shared XMP parser, 21 `XMP-*`
// tags), the `udta/meta`(`mdir`) ItemList/`ilst` (Title/Artist/ContentCreateDate/
// Encoder/CoverArt/GPSCoordinates) + its `QuickTime:HandlerVendorID` ("Apple"),
// the `moov/meta`(`mdta`) Keys (CompatibleBrands/MajorBrand/Balance), the audio
// `trak/meta`(`mdta`) `AudioKeys:Balance`, and the `UserData:LocationInformation`
// (`loci`) struct are ALL now decoded byte-exact (33 tags that were previously
// dropped by name).
//
// The ONLY remaining deferral is `Composite:GPS*`: bundled's `Composite:
// GPSLatitude`/`Longitude`/`Altitude`/`AltitudeRef` come from the unported
// `%QuickTime::Composite` `GPSCoordinates`/`LocationInformation` tables
// (QuickTime.pm:8668-8728), which OVERRIDE the XMP-derived ones; plus the XMP
// `Composite:GPSLatitudeRef`/`GPSLongitudeRef` and the composite-on-composite
// `Composite:GPSPosition`. Porting that `%QuickTime::Composite` GPS table is the
// port-wide deferral the GoPro/SP2 arms also carry (it would change ~12 goldens
// + needs same-name composite override resolution). exifast DOES emit one
// XMP-derived `Composite:GPSAltitude` (byte-exact vs bundled for an XMP-only
// file, but diverging here because the QT composite is missing to override it),
// so the seven `Composite:GPS*` keys are dropped from BOTH sides (the golden
// keeps the matching `-x` in `tools/gen_golden.sh`).
//
// The exclusion is the EXACT, FULLY-QUALIFIED `Composite:GPS*` key set bundled
// emits for this fixture (`perl exiftool -G1 -j` lists exactly these seven);
// the distinct `XMP-exif:GPS{Altitude,AltitudeRef,Latitude,Longitude}` tags
// (also part of the #361 fix) are NOT excluded and so are verified byte-exact
// in this comparison — a regression in the embedded-XMP GPS parse would fail
// here rather than be masked by an over-broad `:tail` match.
#[test]
fn mp4_parrot_anafi_conformance() {
  const GPS_COMPOSITES: &[&str] = &[
    "Composite:GPSAltitude",
    "Composite:GPSAltitudeRef",
    "Composite:GPSLatitude",
    "Composite:GPSLatitudeRef",
    "Composite:GPSLongitude",
    "Composite:GPSLongitudeRef",
    "Composite:GPSPosition",
  ];
  check_excluding(
    "MP4_parrot_anafi.mp4",
    "MP4_parrot_anafi.mp4.json",
    true,
    GPS_COMPOSITES,
  );
  check_excluding(
    "MP4_parrot_anafi.mp4",
    "MP4_parrot_anafi.mp4.n.json",
    false,
    GPS_COMPOSITES,
  );
}

// #361 R4/R6 — the audio-track `meta`(`mdta`) `keys` must resolve through the
// COMPLETE `ProcessKeys` order (QuickTime.pm:9806-9854): active `%QuickTime::
// AudioKeys` (QuickTime.pm:6895) → `%ItemList` → `%UserData` → derive — NOT the
// generic `%QuickTime::Keys`. `MP4_audiokeys_mute.mp4` is a CRAFTED audio-only
// MP4 whose `soun` `trak` carries every flavor:
//   - `Balance` (shared with `%Keys`) + `Mute` (the AudioKeys SOLE conv —
//     `Format => int8u` + `PrintConv => { 0 => 'Off', 1 => 'On' }`: `On` at `-j`,
//     `1` at `-n`) — the active-table arm;
//   - `manu` / `modl` — UserData 4-cc aliases (QuickTime.pm:1879/1885) the
//     cross-table arm resolves to `AudioKeys:Make` / `AudioKeys:Model` (the
//     UserData NAME under the ACTIVE AudioKeys group, NOT a derived
//     `AudioKeys:Manu`/`Modl`). Conv-less — the UserData RawConv (Canon-prefix
//     strip) is NOT copied by ProcessKeys (verified vs bundled 13.59: a clean
//     ASCII value passes through verbatim);
//   - three NON-table keys — `make`, `creationdate`, `acme.totally.bogus.zzz` —
//     the DERIVE arm emits (`AudioKeys:Make`/`Creationdate`/`AcmeTotallyBogusZzz`,
//     CONV-LESS — `Creationdate` is the RAW string, NOT the `%Keys` date
//     ValueConv, proving the AudioKeys table is consulted, not `%Keys`);
//   - (#361 R7) two RAW `0xA9`-prefixed 4-cc ids `\xa9day` / `\xa9too` whose RAW
//     key bytes must reach the cross-table (a UTF-8 decode mangles the `0xA9`
//     into a 6-byte U+FFFD that can never match the 4-byte ItemList id) →
//     `AudioKeys:ContentCreateDate` (the ItemList `%iso8601Date` ValueConv —
//     "2024:05:06 07:08:09-05:00", the ItemList NAME, NOT the `creationdate`
//     `CreationDate`) and `AudioKeys:Encoder`. `AudioKeys:Make` stays `CanonManu`
//     (the `manu` cross-table id), unchanged by the additions.
// No exclusion beyond `System:all`: the ported `Composite:AvgBitrate` is
// verified byte-exact.
#[test]
fn mp4_audiokeys_mute_conformance() {
  check(
    "MP4_audiokeys_mute.mp4",
    "MP4_audiokeys_mute.mp4.json",
    true,
  );
  check(
    "MP4_audiokeys_mute.mp4",
    "MP4_audiokeys_mute.mp4.n.json",
    false,
  );
}

// #361 R7 — the MOVIE-LEVEL `moov/meta`(`mdta`) `keys` box runs the GENERIC
// `%QuickTime::Keys` resolver (a video trak, so NOT AudioKeys) through the
// COMPLETE `ProcessKeys` order (QuickTime.pm:9806-9854): active `%Keys` →
// `%ItemList` → `%UserData` → DERIVE. `MP4_movie_keys.mov` exercises the two real
// gaps R6 left open:
//   - the DERIVE step ([high] fix): a NON-table movie key
//     `com.apple.quicktime.acme.totally.bogus.zzz` ⇒ `Keys:AcmeTotallyBogusZzz`
//     (previously DROPPED — `apply_key` ignored the cross-table miss and had no
//     derive fallback, unlike the AudioKeys path);
//   - the RAW `0xA9` cross-table resolution: `\xa9day` ⇒ `Keys:ContentCreateDate`
//     (ItemList `%iso8601Date` — the ItemList NAME, distinct from the `%Keys`
//     `creationdate` `CreationDate`) and `\xa9xyz` ⇒ `Keys:GPSCoordinates`
//     (ItemList `ConvertISO6709` + `PrintGPSCoordinates`); `manu` ⇒ `Keys:Make`
//     (UserData). All ground-truthed vs bundled 13.59.
// The 3 `Composite:GPS*` bundled synthesizes from `Keys:GPSCoordinates` (the
// unported `%QuickTime::Composite` table, QuickTime.pm:8668) are excluded BY NAME
// from BOTH sides (the SAME port-wide GPS-composite deferral as the SP2/anafi
// arms); the ported `Composite:ImageSize`/`Megapixels`/`AvgBitrate`/`Rotation`
// are verified byte-exact.
#[test]
fn mp4_movie_keys_conformance() {
  const GPS_COMPOSITES: &[&str] = &[
    "Composite:GPSLatitude",
    "Composite:GPSLongitude",
    "Composite:GPSPosition",
  ];
  check_excluding(
    "MP4_movie_keys.mov",
    "MP4_movie_keys.mov.json",
    true,
    GPS_COMPOSITES,
  );
  check_excluding(
    "MP4_movie_keys.mov",
    "MP4_movie_keys.mov.n.json",
    false,
    GPS_COMPOSITES,
  );
}

// #138 / #348 — Viofo A119 dashcam with LigoGPS freeGPS atom in MP4. The non-`ee`
// `.json`/`.n.json` are the always-on QuickTime/Track/Composite structure (no
// GPS — the LigoGPS GPS is `-ee`/trailer-gated); the `'ver '`/`thma` SkipInfo
// (70mai/Viofo `skip` atom → QuickTime:Version + ThumbnailImage) emits, and the
// audio `trak`'s dual `hdlr` (`mdia/hdlr soun` + nested `minf/hdlr url `,
// QuickTime.pm:7319) now resolves byte-exact (#348): bundled keeps the `url `
// dref triplet for the AUDIO track (the FINAL `trak`'s `minf/hdlr` owns the bare
// `Track2:Handler*` key) yet the `soun` media triplet for VIDEO, and exifast
// mirrors that selection. ACTIVE — byte-exact at both `-j` and `-n`. The LigoGPS
// GPS itself is pinned at `-ee` in `tests/timed_metadata_conformance.rs`
// (`viofo_a119_ligogps_ee_byte_exact`).
#[test]
fn mp4_viofo_a119_gps_conformance() {
  check(
    "MP4_viofo_a119_gps.mp4",
    "MP4_viofo_a119_gps.mp4.json",
    true,
  );
  check(
    "MP4_viofo_a119_gps.mp4",
    "MP4_viofo_a119_gps.mp4.n.json",
    false,
  );
}

// #100 / #348 — Rove R2-4K dashcam MP4. The non-`ee` `.json`/`.n.json` are the
// always-on QuickTime/Track/Composite structure (the Rove timed GPS is
// `-ee`/trailer-gated). Like the Viofo sibling, the audio `trak` carries a dual
// `hdlr` (`mdia/hdlr soun` + nested `minf/hdlr url `), and bundled keeps the
// `url ` dref triplet for AUDIO yet the `soun` media triplet for VIDEO — the
// dual-`hdlr` dedup now reproduced (#348). ACTIVE — byte-exact at both `-j`/`-n`.
#[test]
fn quicktime_rove_r2_4k_conformance() {
  check(
    "QuickTime_rove_r2_4k.MP4",
    "QuickTime_rove_r2_4k.MP4.json",
    true,
  );
  check(
    "QuickTime_rove_r2_4k.MP4",
    "QuickTime_rove_r2_4k.MP4.n.json",
    false,
  );
}

// #130 — MPEG-TS with MISB KLV metadata stream. This fixture's PMT declares
// only a type-0x1b H.264 video stream (no type-0x15 packetized-metadata PID),
// and the file carries no SMPTE/MISB universal label (06 0e 2b 34), so bundled
// ExifTool 13.59 decodes no MISB KLV tags — even under `-ee`. The byte-exact
// tag set is the standard M2TS/H264/Composite one exifast already emits (plus
// the `ExtractEmbedded` Warning); there is nothing to MISB-decode here.
#[test]
fn mpeg2_ts_misb_klv_conformance() {
  check("MPEG2_TS_misb_klv.ts", "MPEG2_TS_misb_klv.ts.json", true);
  check("MPEG2_TS_misb_klv.ts", "MPEG2_TS_misb_klv.ts.n.json", false);
}

// #128 — MPEG-2 video + AC3 audio in MPEG-TS (stream types 0x02, 0x81). The
// teammate fixture (#408) re-added the (now-active, see below) Pentax PEF test
// stubs from a pre-#393 base; those duplicates are dropped here — #393's
// `check_excluding` versions remain the canonical ones. The MPEG2 video PES
// decode (`MPEG:ImageWidth/Height/AspectRatio/FrameRate/VideoBitrate`) +
// `%MPEG::Composite` `Duration` landed (#128), so the fixture is active.
#[test]
fn mpeg2_ts_mpeg2video_conformance() {
  check(
    "MPEG2_TS_mpeg2video.ts",
    "MPEG2_TS_mpeg2video.ts.json",
    true,
  );
  check(
    "MPEG2_TS_mpeg2video.ts",
    "MPEG2_TS_mpeg2video.ts.n.json",
    false,
  );
}
// #211 — Real GoPro HERO6 Black with a live `gpmd` GPS/sensor track (from
// gopro/gpmf-parser). The DEFAULT (no-`ee`) `.json`/`.n.json` are byte-exact:
// the `gpmd`/`fdsc` traks are `meta`-handler ⇒ fully `-ee` gated, so the base
// document is the container + the moov-level `udta` `GoPro:*`/`UserData:*`
// identity (incl. the simple `UserData:GPSCoordinates` ISO6709 string) + the
// ported ImageSize/Megapixels/AvgBitrate/Rotation Composites. The timed GPMF
// `Doc<N>` block surfaces only under `-ee` —
// `timed_metadata_conformance.rs::gopro_hero6_gpmd_ee_byte_exact` pins it.
#[test]
fn quicktime_gopro_hero6_gpmf_conformance() {
  check(
    "QuickTime_gopro_hero6_gpmf.mp4",
    "QuickTime_gopro_hero6_gpmf.mp4.json",
    true,
  );
  check(
    "QuickTime_gopro_hero6_gpmf.mp4",
    "QuickTime_gopro_hero6_gpmf.mp4.n.json",
    false,
  );
}

// #210 — Real Samsung NX1 SRW with a populated Type2 MakerNote. The same
// Type2 surface as the (already-active) NX500: the `0x927c` MakerNote
// dispatches to `MakerNoteSamsung2` and walks `%Samsung::Type2` through the
// shared `Walker`, and exifast emits all 45 `Samsung:*` leaves byte-exact vs
// bundled ExifTool 13.59 — the NX1 camera-indexing identity (`DeviceType` =
// "High-end NX Camera", `SamsungModelID` = "Various Models (0x5001038)",
// `LensType` = "Samsung NX 16-50mm F2-2.8 S ED OIS" via %samsungLensTypes,
// `FirmwareName` = 1.40, `LensFirmware` = "01.03_01.18",
// `InternalLensSerialNumber` = 429900057200), the exposure leaves
// (`ExposureTime` = "1/2500", `FNumber` = 8.5, `FocalLengthIn35mmFormat` =
// "53 mm", `ISO` = 400), and — UNLIKE the NX500's `"undef"` — a POPULATED
// `CameraTemperature` = "0.7513126037 C" (the rational64s identity ValueConv
// rendered as a decimal + the `" C"` digit-gated PrintConv suffix), proving
// the rational render on a real (non-`0/0`) value. The five
// `%Samsung::PictureWizard` members + the 16 decrypted #242 Crypt leaves (e.g.
// `ColorMatrix` = "434 -140 -40 -30 294 -10 10 -76 320",
// `WB_RGGBLevelsBlack` = "128 128 128 128") all match. The Type2 port needed
// NO NX1-specific gap-closing (identical 45-tag table to the NX500). The
// goldens are generated by the baked-in `gen_golden.sh SamsungNX1.srw` arm
// (the same SubIFD/SubIFD1 raw-image + MakerNote-Composite exclusions as the
// NX500 arm; PreviewIFD is KEPT now that #242 landed).
#[test]
fn makernotes_samsung_nx1_conformance() {
  check("SamsungNX1.srw", "SamsungNX1.srw.json", true);
  check("SamsungNX1.srw", "SamsungNX1.srw.n.json", false);
}

// #393 — Pentax K-3 Mark III: AFInfoK3III, BatteryInfo re-layout, LevelInfo, FaceInfo
// #393 — Pentax K-3 Mark III PEF. The MakerNote `K-3 Mark III` variants are now
// byte-exact: the `%BatteryInfo` re-layout (PowerSource/PowerAvailable +
// Body/Grip BatteryState/Percent/Voltage, the int32u voltage `$val*4e-8+0.27219`),
// the `%AFInfo` K-3III leaves (AFPointsSelected via the 101-point grid, LiveView,
// First/ActionInAFC, AFCHold/PointTracking/Sensitivity, SubjectRecognition), the
// `%AFInfoK3III` (0x040c — AFMode/AFSelectionMode/MaxNum/NumAFPoints + AFFrameSize/
// AFAreas/AFAreaSize), the `%FaceInfoK3III` (0x040b — FaceImageSize/CAFArea/
// FacesDetectedA/B), `%PixelShiftInfo` (0x0243) and `%TempInfo` (0x03ff — ShotNumber
// `$val+1` + SensorTemperature), plus the K-3III Main scalars (ContrastHighlight-
// ShadowAdj/ISOAutoMinSpeed/WhiteLevel/ShutterType/SkinToneCorrection).
//
// `K3III_PEF_DEFERRED` are the NON-MakerNote residuals (out of #393 scope): the
// `ExifIFD:CFAPattern` (the `%cfaPattern` PrintConv is unported — also deferred for
// `NikonD2Hs.jpg`); the PEF IFD2 raw-image chain — bundled resolves the IFD2 0x111/
// 0x117 pair to `JpgFromRaw*` (the `%Exif::Main` 0x111 JpgFromRaw arm + the PEF
// raw-IFD `SubfileType` DataMember, a #331-family raw-IFD concern), whereas the
// port resolves them to `IFD2:ThumbnailOffset/Length` and (because the JpgFromRaw
// blob lies past the truncated fixture) raises the `runs past the EXIF data`
// Warning — so the bundled `JpgFromRaw*` AND the port's `ThumbnailOffset/Length` +
// `ExifTool:Warning` are dropped from both sides; and the `Pentax:PreviewImage`/
// `PreviewImageStart` IsOffset binary extraction (a deferred #331 P2/P3 item, also
// excluded for `Pentax.jpg`). The MakerNote camera-identity surface is fully active.
#[test]
fn pef_pentax_k3_mark_iii_conformance() {
  check_excluding(
    "PEF_pentax_k3_mark_iii.pef",
    "PEF_pentax_k3_mark_iii.pef.json",
    true,
    K3III_PEF_DEFERRED,
  );
  check_excluding(
    "PEF_pentax_k3_mark_iii.pef",
    "PEF_pentax_k3_mark_iii.pef.n.json",
    false,
    K3III_PEF_DEFERRED,
  );
}

const K3III_PEF_DEFERRED: &[&str] = &[
  "ExifIFD:CFAPattern",
  "IFD2:JpgFromRaw",
  "IFD2:JpgFromRawStart",
  "IFD2:JpgFromRawLength",
  "IFD2:ThumbnailOffset",
  "IFD2:ThumbnailLength",
  "ExifTool:Warning",
  "Pentax:PreviewImage",
  "Pentax:PreviewImageStart",
];

// #393 — Pentax *ist D PEF. The OLD-format MakerNote is now byte-exact: the
// `%LensInfo` (0x0207 count-36) → `%LensData` at offset 3 (AutoAperture/MinAperture/
// LensFStops/MinFocusDistance/FocusRangeIndex/LensFocalLength/NominalMax/MinAperture),
// the `0x003c AFPointsInFocus` (`$val & 0x7ff` + the 11-point BITMASK), the *istD
// Main scalars (PentaxImageSize/FrameNumber/SensorSize/ImageAreaOffset/RawImageSize/
// ColorMatrixA/B), and the `0x001f/0x0020/0x0021` array-PrintConv pair (`Saturation`/
// `Contrast`/`Sharpness` → `"0 (normal); 0"`). The `Pentax:LensType` ("A Series
// Lens") and the `ExifTool:Warning` ("Bad IFD2 directory") are both byte-exact.
//
// `ISTD_PEF_DEFERRED` are the residuals: `Composite:LensID` (the camera Composite
// subsystem builds it from `Pentax:LensType`, but `Composite:LensID` stays deferred
// port-wide — also excluded for `Pentax.jpg`); the `ExifIFD:CFAPattern` (unported
// `%cfaPattern`, as above); and the `Pentax:PreviewImage`/`PreviewImageStart`/
// `ToneCurve` IsOffset/binary leaves (the deferred #331 binary-extraction items).
#[test]
fn pef_pentax_istd_conformance() {
  check_excluding(
    "PEF_pentax_istd.pef",
    "PEF_pentax_istd.pef.json",
    true,
    ISTD_PEF_DEFERRED,
  );
  check_excluding(
    "PEF_pentax_istd.pef",
    "PEF_pentax_istd.pef.n.json",
    false,
    ISTD_PEF_DEFERRED,
  );
}

const ISTD_PEF_DEFERRED: &[&str] = &[
  "Composite:LensID",
  "ExifIFD:CFAPattern",
  "Pentax:PreviewImage",
  "Pentax:PreviewImageStart",
  "Pentax:ToneCurve",
];
