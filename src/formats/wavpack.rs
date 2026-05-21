//! Faithful port of `Image::ExifTool::WavPack` (lib/Image/ExifTool/WavPack.pm).
//! WavPack.pm is 144 lines: one tag table + one Process<Type> sub.
//!
//! PROCESS_PROC is `ExifTool::ProcessBinaryData` (WavPack.pm:22) running over
//! a 32-byte header. With `FORMAT => 'int32u'` (WavPack.pm:24) and ALL five
//! tag IDs sharing the integer part `6` (`6.1`..`6.5`, WavPack.pm:31-73), every
//! tag reads the SAME `int32u` at offset `6 * 4 = 24` and applies its own
//! `Mask` (ExifTool.pm:10067-10068 `val = (val & mask) >> BitShift`,
//! `BitShift` auto-derived from the trailing zero bits of `Mask`,
//! ExifTool.pm:5905-5910). So a faithful Rust transliteration reads the
//! single `int32u` once (big-endian, ExifTool global default 'MM',
//! ExifTool.pm:5981 — `WavPack.pm` never calls `SetByteOrder`) and emits
//! the 5 tags in numeric order (the Perl `sort` at ExifTool.pm:9907).
//!
//! Byte-order verified against the bundled `perl exiftool` oracle: an
//! on-disk LE flags value `0x0480008d` produces BytesPerSample=1,
//! AudioType=Mono, Compression=Lossless, DataFormat=Integer,
//! SampleRate=48000 — exactly what `u32::from_be_bytes(...)` + the
//! `%WavPack::Main` masks compute.
//!
//! `ProcessWV` (WavPack.pm:80-105) also calls `RIFF::ProcessRIFF` and
//! `APE::ProcessAPE` AFTER its own `ProcessBinaryData`, to extract any
//! RIFF/ID3/APE trailer metadata. Per the orchestrator's WavPack scope
//! both are **faithfully deferred** to the dedicated RIFF / ID3 / APE
//! rows (FORMATS.md rows 2 / 5 / 22). The oracle confirms that on a
//! native-wvpk fixture with NO RIFF / no ID3 / no APE trailer those two
//! Perl calls emit zero tags / warnings — so the deferral is byte-exact
//! for the fixtures shipped here.

use crate::{
  parser::{FormatParser, ParseContext},
  tagtable::{PrintConv, PrintConvHash, PrintValue, TagDef, TagId, TagTable, ValueConv},
  value::{Group, TagValue},
};

// BitShifts derived at const-eval from the Mask. Faithful to
// ExifTool.pm:5905-5910:
//   ++$bitShift until $mask & (1 << $bitShift);
// i.e. BitShift = number of trailing zero bits of Mask. `trailing_zeros()`
// is `const fn` on u32 (Rust ≥ 1.46) and total — no runtime cost, no panic
// surface — so the *_SHIFT constants are derived from their *_MASK
// constants. This makes the mask/shift invariant enforced by construction
// (a mask change automatically updates the shift; no need to keep two
// hand-edited constants in sync). The Perl loop algorithm and the
// resulting shifts are byte-identical.
const fn bit_shift(mask: u32) -> u32 {
  mask.trailing_zeros()
}
const BYTES_PER_SAMPLE_MASK: u32 = 0x0000_0003; // WavPack.pm:33
const BYTES_PER_SAMPLE_SHIFT: u32 = bit_shift(BYTES_PER_SAMPLE_MASK); // 0
const AUDIO_TYPE_MASK: u32 = 0x0000_0004; // WavPack.pm:38
const AUDIO_TYPE_SHIFT: u32 = bit_shift(AUDIO_TYPE_MASK); // 2
const COMPRESSION_MASK: u32 = 0x0000_0008; // WavPack.pm:43
const COMPRESSION_SHIFT: u32 = bit_shift(COMPRESSION_MASK); // 3
const DATA_FORMAT_MASK: u32 = 0x0000_0080; // WavPack.pm:48
const DATA_FORMAT_SHIFT: u32 = bit_shift(DATA_FORMAT_MASK); // 7
const SAMPLE_RATE_MASK: u32 = 0x0780_0000; // WavPack.pm:53
const SAMPLE_RATE_SHIFT: u32 = bit_shift(SAMPLE_RATE_MASK); // 23

/// WavPack.pm:33-35. `Mask => 0x03; ValueConv => '$val + 1'`. The raw
/// 2-bit field is in `[0,3]`; the conv produces `[1,4]` bytes per sample
/// (1 = 8-bit, 2 = 16-bit, 3 = 24-bit, 4 = 32-bit). PrintConv is absent,
/// so the post-ValueConv integer is emitted directly under both `-j` and
/// `-n` (bundled `perl exiftool` shows e.g. `"File:BytesPerSample": 1`).
fn bytes_per_sample_conv(v: &TagValue) -> TagValue {
  match v {
    // Raw int from the bit-shift below ⇒ stays I64 after +1.
    TagValue::I64(n) => TagValue::I64(n + 1),
    // Defensive identity (should never happen on this path — the mask
    // produces an I64).
    other => other.clone(),
  }
}

// WavPack.pm:31-35  BytesPerSample
static BYTES_PER_SAMPLE: TagDef = TagDef::new(
  "BytesPerSample",
  "File",
  ValueConv::Func(bytes_per_sample_conv),
  PrintConv::None,
);
// WavPack.pm:36-40  AudioType
static AUDIO_TYPE: TagDef = TagDef::new(
  "AudioType",
  "File",
  ValueConv::None,
  PrintConv::Hash(PrintConvHash::direct(&[
    ("0", PrintValue::Str("Stereo")),
    ("1", PrintValue::Str("Mono")),
  ])),
);
// WavPack.pm:41-45  Compression
static COMPRESSION: TagDef = TagDef::new(
  "Compression",
  "File",
  ValueConv::None,
  PrintConv::Hash(PrintConvHash::direct(&[
    ("0", PrintValue::Str("Lossless")),
    ("1", PrintValue::Str("Hybrid")),
  ])),
);
// WavPack.pm:46-50  DataFormat
static DATA_FORMAT: TagDef = TagDef::new(
  "DataFormat",
  "File",
  ValueConv::None,
  PrintConv::Hash(PrintConvHash::direct(&[
    ("0", PrintValue::Str("Integer")),
    ("1", PrintValue::Str("Floating Point")),
  ])),
);
// WavPack.pm:51-73  SampleRate. The Perl table is `# (NC)` (not committed)
// with index 15 ⇒ 'Custom'; faithful by-value. Numeric entries serialize
// as JSON numbers (PrintValue::I64), `Custom` as a string.
static SAMPLE_RATE: TagDef = TagDef::new(
  "SampleRate",
  "File",
  ValueConv::None,
  PrintConv::Hash(PrintConvHash::direct(&[
    ("0", PrintValue::I64(6000)),
    ("1", PrintValue::I64(8000)),
    ("2", PrintValue::I64(9600)),
    ("3", PrintValue::I64(11025)),
    ("4", PrintValue::I64(12000)),
    ("5", PrintValue::I64(16000)),
    ("6", PrintValue::I64(22050)),
    ("7", PrintValue::I64(24000)),
    ("8", PrintValue::I64(32000)),
    ("9", PrintValue::I64(44100)),
    ("10", PrintValue::I64(48000)),
    ("11", PrintValue::I64(64000)),
    ("12", PrintValue::I64(88200)),
    ("13", PrintValue::I64(96000)),
    ("14", PrintValue::I64(192000)),
    ("15", PrintValue::Str("Custom")),
  ])),
);

fn wavpack_get(id: TagId) -> Option<&'static TagDef> {
  match id {
    TagId::Str("BytesPerSample") => Some(&BYTES_PER_SAMPLE),
    TagId::Str("AudioType") => Some(&AUDIO_TYPE),
    TagId::Str("Compression") => Some(&COMPRESSION),
    TagId::Str("DataFormat") => Some(&DATA_FORMAT),
    TagId::Str("SampleRate") => Some(&SAMPLE_RATE),
    _ => None,
  }
}

/// `%WavPack::Main` (WavPack.pm:21). family-0 group "File"
/// (`GROUPS => { 0 => 'File', 1 => 'File', 2 => 'Audio' }`, WavPack.pm:23);
/// `-G1` ⇒ "File:" prefix. The family-2 'Audio' is not emitted under
/// `-G1`. Keyed by **String** TagIds (Perl tag IDs are `6.1`..`6.5`; we
/// pre-resolve them to the equivalent named keys at the call site since
/// every tag shares `int(index) = 6` and thus the same byte window).
pub static WAVPACK_MAIN: TagTable = TagTable::new("File", wavpack_get);

/// WavPack parser (faithful `ProcessWV`, WavPack.pm:80-105).
pub struct ProcessWv;

impl FormatParser for ProcessWv {
  fn process(&self, ctx: &mut ParseContext<'_>) -> bool {
    // Snapshot the 32-byte header out of `ctx.data()` so the immutable
    // borrow ends before the upcoming `&mut ctx` (set_file_type /
    // metadata) calls; `buff32` IS Perl `$buff` (the first 32 bytes of
    // the file). Mirrors the AAC parser's `buff7` pattern.
    let buff32: [u8; 32] = {
      let data = ctx.data();
      // WavPack.pm:87 `return 0 unless $raf->Read($buff, 32) == 32`.
      if data.len() < 32 {
        return false;
      }
      // WavPack.pm:88 `return 0 unless $buff =~ /^wvpk.{4}[\x02\x10]\x04/s`.
      //   bytes 0..4 == "wvpk"
      //   bytes 4..8 = ckSize  (any value, `.{4}` consumes them)
      //   byte 8 ∈ {0x02, 0x10}
      //   byte 9 == 0x04
      if &data[..4] != b"wvpk" {
        return false;
      }
      if data[8] != 0x02 && data[8] != 0x10 {
        return false;
      }
      if data[9] != 0x04 {
        return false;
      }
      // Explicit copy is panic-free (no try_into).
      let mut out = [0u8; 32];
      out.copy_from_slice(&data[..32]);
      out
    };

    // WavPack.pm:89 `$et->SetFileType()` — no-arg ⇒ detected file type ("WV").
    ctx.set_file_type(None, None, None);
    let print_conv_enabled = ctx.print_conv_enabled();

    // WavPack.pm:91-95 `$et->ProcessBinaryData(\%dirInfo, GetTagTable(
    // 'Image::ExifTool::WavPack::Main'))`. With `FORMAT=>'int32u'` and all
    // five tag IDs sharing `int(index) = 6`, every tag's entry offset is
    // `6 * 4 = 24` (ExifTool.pm:9946 `$entry = int($index) * $increment +
    // $varSize`, $varSize stays 0 across the integer-keyed loop). The
    // shared `int32u` is read with the current byte order (ExifTool.pm:
    // 6239 `int32u => \&Get32u`); WavPack.pm never calls `SetByteOrder`,
    // so the global default 'MM' (ExifTool.pm:5981) applies — big-endian.
    //
    // ExifTool byte-order-state quirk (verified against bundled
    // `perl exiftool` 2026-05-20): `$currentByteOrder` is process-wide
    // and `ExifTool::Init` (ExifTool.pm:4316-4365) does NOT reset it
    // between files in a batch invocation. Other audio modules
    // (FLAC.pm:256, APE.pm:140/173, MPC.pm:98) explicitly call
    // `SetByteOrder('MM'|'II')`; WavPack.pm does not, so e.g.
    // `perl exiftool le.tiff WavPack.wv` reads these flags as `II`
    // (because the TIFF read flipped the global). Our port is faithful
    // to the FRESH-PROCESS state — global default 'MM' — which is the
    // §4 conformance bar (tools/gen_golden.sh invokes Perl once per
    // file). exifast's library API is per-file (`extract_info` builds a
    // fresh `Metadata` per call); no shared parser state exists across
    // calls, so the Perl batch-mode leak is structurally invisible
    // here. Threading byte-order state through `ParseContext` would be
    // dead code today and is intentionally not done.
    let flags = u32::from_be_bytes([buff32[24], buff32[25], buff32[26], buff32[27]]);

    // Faithful order: ExifTool.pm:9907 sorts integer-keyed tags
    // numerically — 6.1, 6.2, 6.3, 6.4, 6.5 — and each loop iteration
    // calls `FoundTag`. So the output sequence (after the File:* triplet
    // from SetFileType above) is BytesPerSample, AudioType, Compression,
    // DataFormat, SampleRate.
    push_masked(
      ctx,
      &BYTES_PER_SAMPLE,
      flags,
      BYTES_PER_SAMPLE_MASK,
      BYTES_PER_SAMPLE_SHIFT,
      print_conv_enabled,
    );
    push_masked(
      ctx,
      &AUDIO_TYPE,
      flags,
      AUDIO_TYPE_MASK,
      AUDIO_TYPE_SHIFT,
      print_conv_enabled,
    );
    push_masked(
      ctx,
      &COMPRESSION,
      flags,
      COMPRESSION_MASK,
      COMPRESSION_SHIFT,
      print_conv_enabled,
    );
    push_masked(
      ctx,
      &DATA_FORMAT,
      flags,
      DATA_FORMAT_MASK,
      DATA_FORMAT_SHIFT,
      print_conv_enabled,
    );
    push_masked(
      ctx,
      &SAMPLE_RATE,
      flags,
      SAMPLE_RATE_MASK,
      SAMPLE_RATE_SHIFT,
      print_conv_enabled,
    );

    // WavPack.pm:96-103: `RIFF::ProcessRIFF` + `APE::ProcessAPE` trailers.
    // ----------------------------------------------------------------
    // Phase-2 forward (orchestrator scope: this PR is WavPack only).
    // For a native-wvpk fixture with NO RIFF wrapper / ID3 / APE trailer
    // both Perl calls are observably no-ops (bundled `perl exiftool` on
    // tests/fixtures/WavPack.wv emits exactly the File:* + 5 WavPack
    // tags — no RIFF::*, no ID3::*, no APE:*). The dedicated RIFF /
    // ID3 / APE rows (FORMATS.md rows 22 / 2 / 5) will wire these
    // delegations when they land; deferring them here is byte-exact
    // against the fixtures we ship.
    // ----------------------------------------------------------------

    true // WavPack.pm:104 `return 1`
  }
}

/// Emit one masked sub-field of the int32u flags word. Mirrors
/// `ProcessBinaryData`'s mask/shift step (ExifTool.pm:10067-10068):
///   `val = (val & mask) >> shift`
/// then runs the def's ValueConv / PrintConv pipeline via `convert::apply`
/// and pushes the resulting tag (faithful `FoundTag`,
/// ExifTool.pm:5648-ish) into the parser's value sink. `shift` is the
/// pre-computed `BitShift` (from the module-level `bit_shift` helper);
/// the parameter is named `shift` to avoid shadowing the helper at the
/// call site.
fn push_masked(
  ctx: &mut ParseContext<'_>,
  def: &'static TagDef,
  flags: u32,
  mask: u32,
  shift: u32,
  print_conv_enabled: bool,
) {
  let raw_u = (flags & mask) >> shift;
  // The largest possible raw value after masking is 0x0F (SampleRate's
  // 4-bit field) — fits in i64 trivially. Every WavPack ProcessBinaryData
  // raw is non-negative and ≤ 15, so i64 is exact and matches the Perl
  // scalar's UV path.
  let raw = TagValue::I64(i64::from(raw_u));
  let out = crate::convert::apply(def, &raw, print_conv_enabled);
  ctx.metadata().push(
    Group::new(WAVPACK_MAIN.group0(), def.group1()),
    def.name(),
    out,
  );
}

#[cfg(test)]
mod tests {
  use super::*;
  use crate::value::Metadata;

  /// Build a 32-byte wvpk header with the given LE flags word. All other
  /// fields use deterministic values; only the flags drive WavPack's tags.
  fn header_with_flags(flags_le: u32) -> [u8; 32] {
    let mut h = [0u8; 32];
    h[0..4].copy_from_slice(b"wvpk");
    h[4..8].copy_from_slice(&100u32.to_le_bytes()); // ckSize
    h[8] = 0x10; // version low
    h[9] = 0x04; // version high (0x0410)
    // [10] block_index_u8 = 0
    // [11] total_samples_u8 = 0
    h[12..16].copy_from_slice(&1000u32.to_le_bytes()); // total_samples
    // [16..20] block_index = 0
    h[20..24].copy_from_slice(&500u32.to_le_bytes()); // block_samples
    h[24..28].copy_from_slice(&flags_le.to_le_bytes()); // flags (LE on disk)
    // [28..32] crc = 0
    h
  }

  #[test]
  fn table_and_lookup_are_faithful() {
    let g = WAVPACK_MAIN.get();
    // The five WavPack tags resolve via TagId::Str (faithful to the
    // way `wavpack_get` keys; the Perl IDs 6.1..6.5 collapse onto a
    // single offset so we look them up by name).
    assert_eq!(
      g(TagId::Str("BytesPerSample")).unwrap().name(),
      "BytesPerSample"
    );
    assert_eq!(g(TagId::Str("AudioType")).unwrap().name(), "AudioType");
    assert_eq!(g(TagId::Str("Compression")).unwrap().name(), "Compression");
    assert_eq!(g(TagId::Str("DataFormat")).unwrap().name(), "DataFormat");
    assert_eq!(g(TagId::Str("SampleRate")).unwrap().name(), "SampleRate");
    assert!(g(TagId::Str("Other")).is_none());
    assert!(g(TagId::Int(0)).is_none());
    assert_eq!(WAVPACK_MAIN.group0(), "File"); // WavPack.pm:23
    // BitShift derivation: per ExifTool.pm:5905-5910 each shift = #
    // trailing zero bits of the mask. Pinned to the exact integer values
    // documented in the .pm so a mask-literal typo is caught even if the
    // `bit_shift` helper is ever changed.
    assert_eq!(BYTES_PER_SAMPLE_MASK, 0x0000_0003);
    assert_eq!(AUDIO_TYPE_MASK, 0x0000_0004);
    assert_eq!(COMPRESSION_MASK, 0x0000_0008);
    assert_eq!(DATA_FORMAT_MASK, 0x0000_0080);
    assert_eq!(SAMPLE_RATE_MASK, 0x0780_0000);
    assert_eq!(BYTES_PER_SAMPLE_SHIFT, 0);
    assert_eq!(AUDIO_TYPE_SHIFT, 2);
    assert_eq!(COMPRESSION_SHIFT, 3);
    assert_eq!(DATA_FORMAT_SHIFT, 7);
    assert_eq!(SAMPLE_RATE_SHIFT, 23);
    // ValueConv +1: BytesPerSample only.
    assert!(BYTES_PER_SAMPLE.value_conv().is_func());
    assert!(AUDIO_TYPE.value_conv().is_none());
    // SampleRate PrintConv hash size is 16 (indices 0..=15).
    match SAMPLE_RATE.print_conv() {
      PrintConv::Hash(h) => assert_eq!(h.direct_entries().len(), 16),
      _ => panic!("expected hash"),
    }
  }

  #[test]
  fn rejects_short_header() {
    let mut m = Metadata::new("WavPack.wv");
    let data = vec![0u8; 16]; // < 32 bytes
    let mut c = ParseContext::new(&data, "WV", 0, "WV", None, true, &mut m);
    assert!(!ProcessWv.process(&mut c));
    assert!(m.tags().is_empty()); // no SetFileType run
  }

  #[test]
  fn rejects_bad_magic() {
    let mut m = Metadata::new("WavPack.wv");
    let mut data = vec![0u8; 32];
    // Wrong magic.
    data[..4].copy_from_slice(b"WVPK");
    let mut c = ParseContext::new(&data, "WV", 0, "WV", None, true, &mut m);
    assert!(!ProcessWv.process(&mut c));
    assert!(m.tags().is_empty());
  }

  #[test]
  fn rejects_bad_version_byte_8() {
    // Byte 8 must be ∈ {0x02, 0x10}; any other rejects (WavPack.pm:88).
    let mut m = Metadata::new("WavPack.wv");
    let mut data = vec![0u8; 32];
    data[..4].copy_from_slice(b"wvpk");
    data[8] = 0x05; // out of {0x02, 0x10}
    data[9] = 0x04;
    let mut c = ParseContext::new(&data, "WV", 0, "WV", None, true, &mut m);
    assert!(!ProcessWv.process(&mut c));
    assert!(m.tags().is_empty());
  }

  #[test]
  fn rejects_bad_version_byte_9() {
    // Byte 9 must be 0x04; any other rejects.
    let mut m = Metadata::new("WavPack.wv");
    let mut data = vec![0u8; 32];
    data[..4].copy_from_slice(b"wvpk");
    data[8] = 0x10;
    data[9] = 0x05; // not 0x04
    let mut c = ParseContext::new(&data, "WV", 0, "WV", None, true, &mut m);
    assert!(!ProcessWv.process(&mut c));
    assert!(m.tags().is_empty());
  }

  #[test]
  fn accepts_version_02() {
    // Byte 8 == 0x02 is the other allowed version (WavPack.pm:88).
    let mut m = Metadata::new("WavPack.wv");
    let mut data = header_with_flags(0);
    data[8] = 0x02; // 0x0402
    let mut c = ParseContext::new(&data, "WV", 0, "WV", None, true, &mut m);
    assert!(ProcessWv.process(&mut c));
    // File:FileType=WV plus 5 WavPack tags.
    assert!(m.tags().iter().any(|t| t.name() == "FileType"));
    assert!(m.tags().iter().any(|t| t.name() == "BytesPerSample"));
  }

  #[test]
  fn extracts_tags_from_oracle_pattern_print_on() {
    // Mirrors the conformance fixture: on-disk LE flags 0x0480008d.
    // BE read of bytes 24..27 = 0x8d008004; oracle-verified ⇒
    //   BytesPerSample raw=0 +1 = 1
    //   AudioType raw=1 → 'Mono'
    //   Compression raw=0 → 'Lossless'
    //   DataFormat raw=0 → 'Integer'
    //   SampleRate raw=10 → 48000
    let mut m = Metadata::new("WavPack.wv");
    let data = header_with_flags(0x0480_008d);
    let mut c = ParseContext::new(&data, "WV", 0, "WV", None, true, &mut m);
    assert!(ProcessWv.process(&mut c));
    let get = |name: &str| {
      m.tags()
        .iter()
        .find(|t| t.name() == name)
        .map(|t| t.value().clone())
    };
    assert_eq!(get("BytesPerSample"), Some(TagValue::I64(1)));
    assert_eq!(get("AudioType"), Some(TagValue::Str("Mono".into())));
    assert_eq!(get("Compression"), Some(TagValue::Str("Lossless".into())));
    assert_eq!(get("DataFormat"), Some(TagValue::Str("Integer".into())));
    assert_eq!(get("SampleRate"), Some(TagValue::I64(48000)));
  }

  #[test]
  fn extracts_tags_print_off() {
    // `-n` (print_conv_enabled=false): ValueConv runs (BytesPerSample +1),
    // PrintConv does NOT — the raw mask values are emitted directly as
    // numbers (matches the oracle's "-n" snapshot).
    let mut m = Metadata::new("WavPack.wv");
    let data = header_with_flags(0x0480_008d);
    let mut c = ParseContext::new(&data, "WV", 0, "WV", None, false, &mut m);
    assert!(ProcessWv.process(&mut c));
    let get = |name: &str| {
      m.tags()
        .iter()
        .find(|t| t.name() == name)
        .map(|t| t.value().clone())
    };
    // ValueConv-only output (PrintConv hash lookups skipped).
    assert_eq!(get("BytesPerSample"), Some(TagValue::I64(1))); // +1 applied
    assert_eq!(get("AudioType"), Some(TagValue::I64(1)));
    assert_eq!(get("Compression"), Some(TagValue::I64(0)));
    assert_eq!(get("DataFormat"), Some(TagValue::I64(0)));
    assert_eq!(get("SampleRate"), Some(TagValue::I64(10)));
  }

  #[test]
  fn adversarial_all_bits_set() {
    // flags = 0xFFFFFFFF: every mask saturates.
    //   BytesPerSample raw=3 → +1 = 4
    //   AudioType raw=1 → 'Mono'
    //   Compression raw=1 → 'Hybrid'
    //   DataFormat raw=1 → 'Floating Point'
    //   SampleRate raw=15 → 'Custom'  (the only string entry, PrintValue::Str)
    let mut m = Metadata::new("WavPack_adv.wv");
    let data = header_with_flags(0xFFFF_FFFF);
    let mut c = ParseContext::new(&data, "WV", 0, "WV", None, true, &mut m);
    assert!(ProcessWv.process(&mut c));
    let get = |name: &str| {
      m.tags()
        .iter()
        .find(|t| t.name() == name)
        .map(|t| t.value().clone())
    };
    assert_eq!(get("BytesPerSample"), Some(TagValue::I64(4)));
    assert_eq!(get("AudioType"), Some(TagValue::Str("Mono".into())));
    assert_eq!(get("Compression"), Some(TagValue::Str("Hybrid".into())));
    assert_eq!(
      get("DataFormat"),
      Some(TagValue::Str("Floating Point".into()))
    );
    assert_eq!(get("SampleRate"), Some(TagValue::Str("Custom".into())));
    // Final File:FileType=WV from SetFileType.
    assert_eq!(
      m.tags()
        .iter()
        .find(|t| t.name() == "FileType")
        .map(|t| t.value().clone()),
      Some(TagValue::Str("WV".into()))
    );
  }

  #[test]
  fn tag_order_is_set_file_type_then_numeric() {
    // ExifTool.pm:9907 numeric sort ⇒ 6.1, 6.2, 6.3, 6.4, 6.5. After
    // SetFileType pushes the File:* triplet, the parser pushes the
    // five WavPack tags in that order. Lock the order in.
    let mut m = Metadata::new("WavPack.wv");
    let data = header_with_flags(0x0480_008d);
    let mut c = ParseContext::new(&data, "WV", 0, "WV", None, true, &mut m);
    assert!(ProcessWv.process(&mut c));
    let names: Vec<&str> = m.tags().iter().map(|t| t.name()).collect();
    assert_eq!(
      names,
      vec![
        "FileType",
        "FileTypeExtension",
        "MIMEType",
        "BytesPerSample",
        "AudioType",
        "Compression",
        "DataFormat",
        "SampleRate",
      ]
    );
  }
}
