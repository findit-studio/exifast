//! Faithful port of `Image::ExifTool::DSF` (lib/Image/ExifTool/DSF.pm,
//! ExifTool 13.58, 138 lines). DSD Stream File container: `'DSD '` chunk +
//! `'fmt '` chunk. Read-only.
//!
//! The ID3v2 trailer arm (DSF.pm:88-97) was IMPLEMENTED in Codex R2-F3
//! via `crate::formats::id3::process::process_id3_v2_slice` — modelling
//! the bundled `ProcessDirectory(GetTagTable('Image::ExifTool::ID3::Main'))`
//! dispatch over `data[metaPos..metaPos+metaLen]`. Pinned by
//! `tests/fixtures/dsf_with_id3v2_trailer.dsf`.

use crate::{
  parser::{FormatParser, ParseContext},
  tagtable::{PrintConv, PrintConvHash, PrintValue, TagDef, TagId, TagTable, ValueConv},
  value::{Group, Metadata, TagValue},
};

// DSF.pm:30 `3 => 'FormatVersion'`.
static FORMAT_VERSION: TagDef =
  TagDef::new("FormatVersion", "File", ValueConv::None, PrintConv::None);
// DSF.pm:31 `4 => { Name => 'FormatID', PrintConv => { 0 => 'DSD Raw' }}`.
static FORMAT_ID: TagDef = TagDef::new(
  "FormatID",
  "File",
  ValueConv::None,
  PrintConv::Hash(PrintConvHash::direct(&[("0", PrintValue::Str("DSD Raw"))])),
);
// DSF.pm:32-43 `5 => { Name => 'ChannelType', PrintConv => { 1..7 } }`.
static CHANNEL_TYPE: TagDef = TagDef::new(
  "ChannelType",
  "File",
  ValueConv::None,
  PrintConv::Hash(PrintConvHash::direct(&[
    ("1", PrintValue::Str("Mono")),
    ("2", PrintValue::Str("Stereo (Left, Right)")),
    ("3", PrintValue::Str("3 Channels (Left, Right, Center)")),
    ("4", PrintValue::Str("Quad (Left, Right, Back L, Back R)")),
    (
      "5",
      PrintValue::Str("4 Channels (Left, Right, Center, Bass)"),
    ),
    (
      "6",
      PrintValue::Str("5 Channels (Left, Right, Center, Back L, Back R)"),
    ),
    (
      "7",
      PrintValue::Str("5.1 Channels (Left, Right, Center, Bass, Back L, Back R)"),
    ),
  ])),
);
// DSF.pm:44 `6 => 'ChannelCount'`.
static CHANNEL_COUNT: TagDef =
  TagDef::new("ChannelCount", "File", ValueConv::None, PrintConv::None);
// DSF.pm:45 `7 => 'SampleRate'`.
static SAMPLE_RATE: TagDef = TagDef::new("SampleRate", "File", ValueConv::None, PrintConv::None);
// DSF.pm:46 `8 => 'BitsPerSample'`.
static BITS_PER_SAMPLE: TagDef =
  TagDef::new("BitsPerSample", "File", ValueConv::None, PrintConv::None);
// DSF.pm:47 `9 => { Name => 'SampleCount', Format => 'int64u' }`.
//
// `Format => 'int64u'` consumes 8 bytes at byte offset 36 (key 9 * 4-byte
// int32u stride), which is why DSF::Main has no key 10 (would land inside the
// int64u payload). The DSF-local binary walk in this module reads exactly
// 8 LE bytes here; values above `i64::MAX` are emitted as `TagValue::Str`
// (exact decimal) — same faithful UV→NV-shape that `bitstream` uses for its
// integer-accumulation path, and which the serializer's number gate keeps as
// a bare JSON integer (≥ 16-digit string lookup, `EscapeJSON` line 3809).
static SAMPLE_COUNT: TagDef =
  TagDef::new("SampleCount", "File", ValueConv::None, PrintConv::None).with_format("int64u");
// DSF.pm:48 `11 => 'BlockSize'`.
static BLOCK_SIZE: TagDef = TagDef::new("BlockSize", "File", ValueConv::None, PrintConv::None);

/// `%DSF::Main` (DSF.pm:20-49). family-0/1 groups both `'File'`
/// (DSF.pm:22 `GROUPS => { 0 => 'File', 1 => 'File', 2 => 'Audio' }`;
/// family-2 'Audio' is not emitted under `-G1`). Keyed by integer
/// (`TagId::Int`) — contrast AAC which is string-keyed.
fn dsf_get(id: TagId) -> Option<&'static TagDef> {
  match id {
    TagId::Int(3) => Some(&FORMAT_VERSION),
    TagId::Int(4) => Some(&FORMAT_ID),
    TagId::Int(5) => Some(&CHANNEL_TYPE),
    TagId::Int(6) => Some(&CHANNEL_COUNT),
    TagId::Int(7) => Some(&SAMPLE_RATE),
    TagId::Int(8) => Some(&BITS_PER_SAMPLE),
    TagId::Int(9) => Some(&SAMPLE_COUNT),
    TagId::Int(11) => Some(&BLOCK_SIZE),
    _ => None,
  }
}

/// `%Image::ExifTool::DSF::Main` (DSF.pm:20). Family-0 group `"File"`
/// (DSF.pm:22). Per-tag family-1 is also `"File"`.
pub static DSF_MAIN: TagTable = TagTable::new("File", dsf_get);

/// Sorted integer keys of `%DSF::Main` in ASCENDING order. Faithful to Perl's
/// `sort { $a <=> $b } keys %$tagTbl` for ProcessBinaryData (the engine walks
/// keys in numeric order — DSF.pm has no `FIRST_ENTRY` hint, so order is the
/// numeric sort of present keys). 10 is absent (consumed by key 9's
/// `Format => 'int64u'`).
const DSF_KEYS: &[i64] = &[3, 4, 5, 6, 7, 8, 9, 11];

/// DSF-local subset of `Image::ExifTool::ProcessBinaryData` (ExifTool.pm,
/// `sub ProcessBinaryData`). Only the slice exercised by DSF::Main is
/// transliterated; promoting this to a shared engine module is deferred
/// until a second `ProcessBinaryData` consumer ports (same incremental-
/// derivation discipline as `BitOrder::Ii`, D11, the PrintConv array
/// variant).
///
/// `buf` is the dirInfo buffer DSF::ProcessDSF feeds in (DSF.pm:80-85, after
/// `$buff = substr($buff,28) . $buf2` — `'fmt '` + chunkSize + payload,
/// total length == `$fmtLen`).
///
/// Per-tag walk:
/// - `byte_offset = key * 4` (table-level `FORMAT => 'int32u'`,
///   DSF.pm:23; stride 4 bytes).
/// - Width: `def.format()` `None` ⇒ 4 (int32u); `Some("int64u")` ⇒ 8.
/// - Bounds-checked read; first out-of-range field breaks the loop early
///   (DSF_KEYS is strictly ascending so subsequent keys cannot fit either —
///   faithful to ExifTool.pm:9953 `last if $more <= 0`).
/// - Apply `convert::apply` (ValueConv then PrintConv when enabled), push to
///   `m` with family-0/1 = `("File", "File")` (DSF.pm:22).
fn walk_binary_data(buf: &[u8], m: &mut Metadata, print_conv_enabled: bool) {
  for &key in DSF_KEYS {
    let Some(def) = dsf_get(TagId::Int(key)) else {
      continue;
    };
    // `key` is bounded by 11 in DSF_KEYS; cast and *4 cannot overflow `usize`
    // on any 16+ bit target. `saturating_*` documents the panic-free intent.
    let off = (key as usize).saturating_mul(4);
    let width: usize = match def.format() {
      Some("int64u") => 8,
      _ => 4,
    };
    let end = off.saturating_add(width);
    if end > buf.len() {
      // DSF_KEYS is strictly ascending (verified by the `prev` assertion in
      // tests) and the table-level int32u stride means `off = key * 4` is
      // monotonic, so once `end > buf.len()` for one key, every subsequent
      // key is also out of range. Faithful to ExifTool.pm:9953
      // `last if $more <= 0; # all done if we have reached the end of data`.
      break;
    }
    let raw = if width == 8 {
      // int64u little-endian (DSF.pm:66 SetByteOrder('II')). `copy_from_slice`
      // panics on length mismatch, but we just bound-checked `end <= buf.len()`
      // with `width == 8`, so the 8-byte slice always exists.
      let mut le = [0u8; 8];
      le.copy_from_slice(&buf[off..off + 8]);
      let v = u64::from_le_bytes(le);
      if v <= i64::MAX as u64 {
        TagValue::I64(v as i64)
      } else {
        // Faithful Perl UV→NV-shape: a u64 above i64::MAX cannot fit in
        // `i64`; emit the exact decimal string. The serializer's number gate
        // (EscapeJSON line 3809) keeps a ≥16-digit bare integer as a JSON
        // number — byte-exact vs `exiftool -j` for large unsigned values.
        TagValue::Str(v.to_string().into())
      }
    } else {
      // int32u little-endian (the table-level FORMAT, DSF.pm:23). A u32
      // always fits in i64 (max 4_294_967_295 < 9.2e18).
      let mut le = [0u8; 4];
      le.copy_from_slice(&buf[off..off + 4]);
      TagValue::I64(u32::from_le_bytes(le) as i64)
    };
    let out = crate::convert::apply(def, &raw, print_conv_enabled);
    m.push(Group::new("File", "File"), def.name(), out);
  }
}

/// DSF parser (faithful `ProcessDSF`, DSF.pm:55-99).
pub struct ProcessDsf;

impl FormatParser for ProcessDsf {
  fn process(&self, ctx: &mut ParseContext<'_>) -> bool {
    // PHASE A — header validation against an immutable borrow of `ctx.data()`.
    // We drop the borrow before touching `ctx.metadata()` / `ctx.set_file_type`
    // (mutable borrows). The validation reads only `&data[..40]`.
    let data_len = ctx.data().len();
    // DSF.pm:62 `$raf->Read($buff,40)==40 or return 0`.
    if data_len < 40 {
      return false;
    }
    {
      let head = &ctx.data()[..40];
      // DSF.pm:63 `$buff =~ /^DSD \x1c\0{7}.{16}fmt /s`. The regex is
      // anchored (^) and the `{16}` middle is "any 16 bytes" (Perl `.` under
      // `/s` matches any byte including \n). Translated literally as four
      // byte-equality checks; the 16-byte middle (fileSize+metaPos) is
      // unconstrained.
      if &head[0..4] != b"DSD " {
        return false;
      }
      if head[4] != 0x1c {
        return false;
      }
      if !head[5..12].iter().all(|&b| b == 0) {
        return false;
      }
      if &head[28..32] != b"fmt " {
        return false;
      }
    }
    // PHASE B — extract every numeric value we need from the header into
    // local variables, AGAIN behind a scoped immutable borrow that ends
    // before any `&mut ctx` call below. After this block we hold only
    // `Copy` locals (no live borrow of `ctx`).
    // DSF.pm:66 `SetByteOrder('II')` — every Get* below is little-endian.
    let fmt_len: u64;
    let file_size: u64;
    let meta_pos: u64;
    {
      let head = &ctx.data()[..40];
      // DSF.pm:67 `my $fmtLen = Get64u(\$buff,32)`.
      let mut le = [0u8; 8];
      le.copy_from_slice(&head[32..40]);
      fmt_len = u64::from_le_bytes(le);
      // DSF.pm:74-75 `$fileSize = Get64u(\$buff,12); $metaPos = Get64u(
      // \$buff,20)` — local-only, NOT emitted as DSF tags. Read here for
      // use by the ID3v2 trailer arm at DSF.pm:88-97.
      let mut le = [0u8; 8];
      le.copy_from_slice(&head[12..20]);
      file_size = u64::from_le_bytes(le);
      let mut le = [0u8; 8];
      le.copy_from_slice(&head[20..28]);
      meta_pos = u64::from_le_bytes(le);
    }
    // DSF.pm:64 `$et->SetFileType()` — no-arg ⇒ detected type ("DSF").
    // SetFileType MUST run before the guard check: DSF.pm orders it (line
    // 64) BEFORE the read-and-guard (lines 67-72), so a Warn-then-return-1
    // file still emits the File:* triplet (verified vs the bundled-Perl
    // golden for `tests/fixtures/DSF_short.dsf`).
    ctx.set_file_type(None, None, None);
    let print_on = ctx.print_conv_enabled();
    // DSF.pm:68-72 `unless ($fmtLen > 12 and $fmtLen < 1000 and $raf->Read(
    //   $buf2, $fmtLen - 12) == $fmtLen - 12) { Warn; return 1 }`.
    //
    // The `fmt_len > 12` guard is what makes the `fmt_len - 12` subtraction
    // below panic-free in unsigned Rust (signed-Perl → usize underflow
    // footgun, per [[exifast-phase2-forward-items]]). The `fmt_len < 1000`
    // guard is NOT a `usize`-cast safety requirement (999 fits any realistic
    // `usize`); it exists for two load-bearing reasons:
    //   1. ExifTool conformance — DSF.pm:68 enforces this exact bound, so a
    //      Perl-rejecting file must also be rejected here for byte-exact
    //      diffs against `exiftool -j`.
    //   2. Bounded allocation — the `Vec::with_capacity(fmt_len as usize)`
    //      below stays under 1KB regardless of input, so a malicious header
    //      cannot trigger a huge `dir` allocation. The header guard does
    //      this work; the payload-bytes guard would still admit a sparse
    //      file with a 999-byte declared fmtLen.
    // Both guards are load-bearing — do NOT reorder.
    let ok = fmt_len > 12 && fmt_len < 1000 && {
      let need = (fmt_len - 12) as usize;
      data_len >= 40usize.saturating_add(need)
    };
    if !ok {
      // DSF.pm:71 `$et->Warn('Error reading DSF fmt chunk')`.
      ctx.metadata().push_warning("Error reading DSF fmt chunk");
      // DSF.pm:72 `return 1` — accept (the File:* triplet stays), no payload.
      return true;
    }
    // DSF.pm:76 `$buff = substr($buff,28) . $buf2` — the dirInfo buffer is
    // `'fmt '` + chunkSize (12 bytes from head[28..40]) + payload (fmt_len -
    // 12 bytes from data[40..]). Total length == fmt_len. Build via an
    // immutable scoped borrow (released before the metadata() &mut call).
    let payload_len = (fmt_len - 12) as usize;
    let dir: Vec<u8> = {
      let data = ctx.data();
      let mut dir = Vec::with_capacity(fmt_len as usize);
      dir.extend_from_slice(&data[28..40]);
      dir.extend_from_slice(&data[40..40 + payload_len]);
      dir
    };
    // DSF.pm:80-85 ProcessBinaryData(\%dirInfo, $tagTbl). The DSF-local walk
    // (above) reads the fixed key set in ascending order.
    walk_binary_data(&dir, ctx.metadata(), print_on);
    // DSF.pm:88-97 ID3v2 trailer dispatch (Codex R2-F3). Faithful gate:
    //   my $metaLen = $fileSize - $metaPos;
    //   if ($metaPos and $metaLen > 0 and $metaLen < 20000000 and
    //       $raf->Seek($metaPos, 0) and $raf->Read($buff, $metaLen) ==
    //       $metaLen)
    //   {
    //       $dirInfo{DataPos} = $metaPos; $dirInfo{DirLen} = $metaLen;
    //       my $id3Tbl = GetTagTable('Image::ExifTool::ID3::Main');
    //       $et->ProcessDirectory(\%dirInfo, $id3Tbl);
    //   }
    //
    // `$metaLen = $fileSize - $metaPos` uses unsigned-aware Perl
    // arithmetic on Get64u values; Rust signed-overflow safety: use
    // `checked_sub` for the (file_size < meta_pos) underflow case (a
    // malformed header), which faithfully short-circuits to "no
    // trailer" (the Perl `$metaLen > 0` guard rejects negative-Perl /
    // wrap-around values too). The `$raf->Seek + Read == metaLen`
    // guard maps to a slice-bounds check against `ctx.data()`
    // (in-memory; bundled reads the bytes from disk). `ProcessDirectory
    // (ID3::Main)` invokes `PROCESS_PROC = ProcessID3Dir` (ID3.pm:80 →
    // 1637-1642), which dispatches to `ProcessID3` over the trailer
    // DataPt — modelled by `process_id3_v2_slice` (chained, no
    // SetFileType: DSF.pm:64 already typed the file as DSF). Pinned by
    // `tests/fixtures/dsf_with_id3v2_trailer.dsf` conformance.
    if meta_pos > 0 {
      if let Some(meta_len) = file_size.checked_sub(meta_pos) {
        if meta_len > 0 && meta_len < 20_000_000 {
          // Slice-bounds check vs the in-memory file (mirrors
          // `$raf->Read($buff, $metaLen) == $metaLen`).
          let mp = meta_pos as usize;
          let ml = meta_len as usize;
          if let Some(slice_end) = mp.checked_add(ml) {
            if slice_end <= data_len {
              let trailer: Vec<u8> = ctx.data()[mp..slice_end].to_vec();
              let _ = crate::formats::id3::process::process_id3_v2_slice(&trailer, ctx);
            }
          }
        }
      }
    }
    true // DSF.pm:99 `return 1`
  }
}

#[cfg(test)]
mod tests {
  use super::*;
  use crate::{parser::ParseContext, value::Metadata};

  // --- Task 3: table + dispatch ------------------------------------------

  #[test]
  fn table_and_keys_are_faithful() {
    let g = DSF_MAIN.get();
    // Every emitted DSF tag.
    assert_eq!(g(TagId::Int(3)).unwrap().name(), "FormatVersion");
    assert_eq!(g(TagId::Int(4)).unwrap().name(), "FormatID");
    assert_eq!(g(TagId::Int(5)).unwrap().name(), "ChannelType");
    assert_eq!(g(TagId::Int(6)).unwrap().name(), "ChannelCount");
    assert_eq!(g(TagId::Int(7)).unwrap().name(), "SampleRate");
    assert_eq!(g(TagId::Int(8)).unwrap().name(), "BitsPerSample");
    assert_eq!(g(TagId::Int(9)).unwrap().name(), "SampleCount");
    assert_eq!(g(TagId::Int(11)).unwrap().name(), "BlockSize");
    // Per-tag family-1 is "File" (DSF.pm:22).
    for &k in DSF_KEYS {
      assert_eq!(g(TagId::Int(k)).unwrap().group1(), "File");
    }
    // Family-0 carried by the table is "File" (DSF.pm:22).
    assert_eq!(DSF_MAIN.group0(), "File");
    // Key 10 is intentionally absent (consumed by key 9's int64u).
    assert!(g(TagId::Int(10)).is_none());
    // Bogus integer keys miss.
    assert!(g(TagId::Int(0)).is_none());
    assert!(g(TagId::Int(12)).is_none());
    // DSF is integer-keyed; string ids never match.
    assert!(g(TagId::Str("FormatVersion")).is_none());
    assert!(g(TagId::Str("3")).is_none());
  }

  #[test]
  fn dsf_keys_const_is_ascending_and_complete() {
    // ASCENDING (faithful Perl `sort {$a<=>$b}`); every DSF_KEYS entry
    // resolves through dsf_get (catches manual slice/dispatch drift).
    let mut prev = i64::MIN;
    for &k in DSF_KEYS {
      assert!(k > prev, "DSF_KEYS must be strictly ascending");
      prev = k;
      assert!(
        dsf_get(TagId::Int(k)).is_some(),
        "DSF_KEYS entry {k} missing from dsf_get"
      );
    }
    assert_eq!(DSF_KEYS, &[3, 4, 5, 6, 7, 8, 9, 11]);
  }

  #[test]
  fn print_conv_shapes_are_faithful() {
    let g = DSF_MAIN.get();
    // FormatID hash has exactly one entry { "0" => "DSD Raw" } (DSF.pm:31).
    match g(TagId::Int(4)).unwrap().print_conv() {
      PrintConv::Hash(h) => {
        let de = h.direct_entries();
        assert_eq!(de.len(), 1);
        assert_eq!(de[0], ("0", PrintValue::Str("DSD Raw")));
        assert!(h.bitmask().is_none());
        assert!(h.other().is_none());
      }
      _ => panic!("FormatID print_conv must be a hash"),
    }
    // ChannelType hash has 7 entries (DSF.pm:34-42).
    match g(TagId::Int(5)).unwrap().print_conv() {
      PrintConv::Hash(h) => {
        assert_eq!(h.direct_entries().len(), 7);
        assert_eq!(
          h.direct_entries()[1],
          ("2", PrintValue::Str("Stereo (Left, Right)"))
        );
      }
      _ => panic!("ChannelType print_conv must be a hash"),
    }
    // Non-hash tags have PrintConv::None.
    assert!(g(TagId::Int(3)).unwrap().print_conv().is_none());
    assert!(g(TagId::Int(11)).unwrap().print_conv().is_none());
    // SampleCount carries the int64u Format key.
    assert_eq!(g(TagId::Int(9)).unwrap().format(), Some("int64u"));
    // All other emitted tags have no Format key (int32u via the table FORMAT).
    for k in [3, 4, 5, 6, 7, 8, 11] {
      assert_eq!(g(TagId::Int(k)).unwrap().format(), None);
    }
  }

  // --- Task 4: ProcessBinaryData walk ------------------------------------

  /// Build a dirInfo-shape buffer with the same layout DSF.pm:76 yields:
  /// `'fmt '` + 8-byte chunkSize + payload. Helper only.
  fn dir(payload: &[u8]) -> Vec<u8> {
    let mut b = Vec::with_capacity(12 + payload.len());
    b.extend_from_slice(b"fmt ");
    b.extend_from_slice(&((12 + payload.len()) as u64).to_le_bytes());
    b.extend_from_slice(payload);
    b
  }

  #[test]
  fn walk_emits_tags_in_ascending_key_order() {
    // Standard payload: FormatVersion=1, FormatID=0, ChannelType=2, etc.
    let mut p = Vec::new();
    p.extend_from_slice(&1u32.to_le_bytes()); // 3 FormatVersion
    p.extend_from_slice(&0u32.to_le_bytes()); // 4 FormatID
    p.extend_from_slice(&2u32.to_le_bytes()); // 5 ChannelType
    p.extend_from_slice(&2u32.to_le_bytes()); // 6 ChannelCount
    p.extend_from_slice(&2_822_400u32.to_le_bytes()); // 7 SampleRate
    p.extend_from_slice(&1u32.to_le_bytes()); // 8 BitsPerSample
    p.extend_from_slice(&2_822_400u64.to_le_bytes()); // 9 SampleCount
    p.extend_from_slice(&4096u32.to_le_bytes()); // 11 BlockSize
    let buf = dir(&p);
    let mut m = Metadata::new("x");
    walk_binary_data(&buf, &mut m, false); // -n: no PrintConv
    let names: Vec<&str> = m.tags().iter().map(|t| t.name()).collect();
    assert_eq!(
      names,
      [
        "FormatVersion",
        "FormatID",
        "ChannelType",
        "ChannelCount",
        "SampleRate",
        "BitsPerSample",
        "SampleCount",
        "BlockSize",
      ]
    );
    for t in m.tags() {
      assert_eq!(t.group().family1(), "File");
      assert_eq!(t.group().family0(), "File");
    }
    // -n raw values: FormatID is the bare integer 0, ChannelType is 2.
    let by_name = |n: &str| {
      m.tags()
        .iter()
        .find(|t| t.name() == n)
        .map(|t| t.value().clone())
        .unwrap()
    };
    assert_eq!(by_name("FormatID"), TagValue::I64(0));
    assert_eq!(by_name("ChannelType"), TagValue::I64(2));
    assert_eq!(by_name("SampleRate"), TagValue::I64(2_822_400));
    assert_eq!(by_name("SampleCount"), TagValue::I64(2_822_400));
    assert_eq!(by_name("BlockSize"), TagValue::I64(4096));
  }

  #[test]
  fn walk_applies_print_conv_when_enabled() {
    let mut p = Vec::new();
    p.extend_from_slice(&1u32.to_le_bytes());
    p.extend_from_slice(&0u32.to_le_bytes()); // FormatID = 0 ⇒ "DSD Raw"
    p.extend_from_slice(&2u32.to_le_bytes()); // ChannelType = 2 ⇒ "Stereo (...)"
    p.extend_from_slice(&2u32.to_le_bytes());
    p.extend_from_slice(&44100u32.to_le_bytes());
    p.extend_from_slice(&1u32.to_le_bytes());
    p.extend_from_slice(&100u64.to_le_bytes());
    p.extend_from_slice(&512u32.to_le_bytes());
    let buf = dir(&p);
    let mut m = Metadata::new("x");
    walk_binary_data(&buf, &mut m, true); // PrintConv on
    let by_name = |n: &str| {
      m.tags()
        .iter()
        .find(|t| t.name() == n)
        .map(|t| t.value().clone())
        .unwrap()
    };
    assert_eq!(by_name("FormatID"), TagValue::Str("DSD Raw".into()));
    assert_eq!(
      by_name("ChannelType"),
      TagValue::Str("Stereo (Left, Right)".into())
    );
  }

  #[test]
  fn walk_int64u_above_i64_max_is_decimal_string() {
    // Craft SampleCount = u64::MAX (above i64::MAX) — must emit as decimal
    // string `TagValue::Str("18446744073709551615")` (faithful UV→NV shape).
    let mut p = vec![0u8; 36]; // payload fills keys 3..=11 with zeros (placeholder)
    // overwrite SampleCount slot (key 9 ⇒ payload byte offset 36-12=24 … wait:
    // key * 4 = 36 in the dirInfo buffer; dirInfo starts with 12 bytes of
    // 'fmt'+size, so payload byte offset = 36-12 = 24.
    p[24..32].copy_from_slice(&u64::MAX.to_le_bytes());
    let buf = dir(&p);
    let mut m = Metadata::new("x");
    walk_binary_data(&buf, &mut m, false);
    let sc = m
      .tags()
      .iter()
      .find(|t| t.name() == "SampleCount")
      .unwrap()
      .value()
      .clone();
    assert_eq!(sc, TagValue::Str("18446744073709551615".into()));
  }

  #[test]
  fn walk_unsigned_at_i64_max_boundary() {
    // SampleCount = i64::MAX ⇒ TagValue::I64(i64::MAX).
    let mut p = vec![0u8; 36];
    p[24..32].copy_from_slice(&(i64::MAX as u64).to_le_bytes());
    let buf = dir(&p);
    let mut m = Metadata::new("x");
    walk_binary_data(&buf, &mut m, false);
    assert_eq!(
      m.tags()
        .iter()
        .find(|t| t.name() == "SampleCount")
        .unwrap()
        .value(),
      &TagValue::I64(i64::MAX)
    );
    // Boundary + 1 ⇒ decimal string.
    p[24..32].copy_from_slice(&((i64::MAX as u64) + 1).to_le_bytes());
    let buf = dir(&p);
    let mut m = Metadata::new("x");
    walk_binary_data(&buf, &mut m, false);
    assert_eq!(
      m.tags()
        .iter()
        .find(|t| t.name() == "SampleCount")
        .unwrap()
        .value(),
      &TagValue::Str("9223372036854775808".into())
    );
  }

  #[test]
  fn walk_out_of_range_field_is_skipped() {
    // dirInfo buffer ending at offset 36 — keys 3..=8 fit, 9 (offset 36, 8
    // bytes) does NOT, 11 (offset 44, 4 bytes) also does NOT.
    let mut p = Vec::with_capacity(24);
    for _ in 0..6 {
      p.extend_from_slice(&0u32.to_le_bytes()); // keys 3..8 (6 × 4 = 24 bytes)
    }
    let buf = dir(&p); // 12 + 24 = 36 bytes total
    assert_eq!(buf.len(), 36);
    let mut m = Metadata::new("x");
    walk_binary_data(&buf, &mut m, false);
    let names: Vec<&str> = m.tags().iter().map(|t| t.name()).collect();
    assert_eq!(
      names,
      [
        "FormatVersion",
        "FormatID",
        "ChannelType",
        "ChannelCount",
        "SampleRate",
        "BitsPerSample",
      ]
    );
    // SampleCount and BlockSize are silently absent: the strictly-ascending
    // DSF_KEYS means once key 9 is out of range, key 11 is too — faithful to
    // ExifTool.pm:9953 `last if $more <= 0` (early-exit, not per-key skip).
    assert!(m.tags().iter().all(|t| t.name() != "SampleCount"));
    assert!(m.tags().iter().all(|t| t.name() != "BlockSize"));
  }

  // --- Task 5: ProcessDsf header + dispatch ------------------------------

  /// 76-byte minimal valid DSF (matches the spec's §3.1 fixture exactly).
  fn happy_path_dsf() -> Vec<u8> {
    let mut v = Vec::with_capacity(76);
    v.extend_from_slice(b"DSD ");
    v.extend_from_slice(&0x1cu64.to_le_bytes()); // DSD chunk size
    v.extend_from_slice(&76u64.to_le_bytes()); // fileSize
    v.extend_from_slice(&0u64.to_le_bytes()); // metaPos = 0
    v.extend_from_slice(b"fmt ");
    v.extend_from_slice(&48u64.to_le_bytes()); // fmtLen
    // payload (36 bytes):
    v.extend_from_slice(&1u32.to_le_bytes());
    v.extend_from_slice(&0u32.to_le_bytes());
    v.extend_from_slice(&2u32.to_le_bytes());
    v.extend_from_slice(&2u32.to_le_bytes());
    v.extend_from_slice(&2_822_400u32.to_le_bytes());
    v.extend_from_slice(&1u32.to_le_bytes());
    v.extend_from_slice(&2_822_400u64.to_le_bytes());
    v.extend_from_slice(&4096u32.to_le_bytes());
    assert_eq!(v.len(), 76);
    v
  }

  #[test]
  fn rejects_when_short() {
    // < 40 bytes ⇒ DSF.pm:62 `return 0`. No File:* pushed.
    for n in [0usize, 39] {
      let buf = vec![0u8; n];
      let mut m = Metadata::new("x.dsf");
      let mut c = ParseContext::new(&buf, "DSF", 0, "DSF", None, true, &mut m);
      assert!(!ProcessDsf.process(&mut c));
      assert!(m.tags().is_empty(), "n={n}");
    }
  }

  #[test]
  fn rejects_when_wrong_magic() {
    // 40 bytes that fail the regex ⇒ DSF.pm:63 `return 0`. No File:* pushed.
    let bad_first4 = {
      let mut v = happy_path_dsf()[..40].to_vec();
      v[0..4].copy_from_slice(b"XXXX");
      v
    };
    let bad_1c_byte = {
      let mut v = happy_path_dsf()[..40].to_vec();
      v[4] = 0x00; // not 0x1c
      v
    };
    let bad_zeros = {
      let mut v = happy_path_dsf()[..40].to_vec();
      v[5] = 0xff; // not \0
      v
    };
    let bad_fmt_marker = {
      let mut v = happy_path_dsf()[..40].to_vec();
      v[28..32].copy_from_slice(b"FMTA");
      v
    };
    for (label, buf) in [
      ("first4", bad_first4),
      ("1c_byte", bad_1c_byte),
      ("zeros", bad_zeros),
      ("fmt_marker", bad_fmt_marker),
    ] {
      let mut m = Metadata::new("x.dsf");
      let mut c = ParseContext::new(&buf, "DSF", 0, "DSF", None, true, &mut m);
      assert!(!ProcessDsf.process(&mut c), "{label}");
      assert!(m.tags().is_empty(), "{label}: tags must be empty on reject");
    }
  }

  #[test]
  fn accepts_minimal_valid_emits_full_set() {
    let buf = happy_path_dsf();
    let mut m = Metadata::new("x.dsf");
    let mut c = ParseContext::new(&buf, "DSF", 0, "DSF", None, true, &mut m);
    assert!(ProcessDsf.process(&mut c));
    let names: Vec<&str> = m.tags().iter().map(|t| t.name()).collect();
    // File:* triplet pushed first (parser-driven SetFileType, DSF.pm:64),
    // then the fmt-chunk tags in DSF::Main key order.
    assert_eq!(
      names,
      [
        "FileType",
        "FileTypeExtension",
        "MIMEType",
        "FormatVersion",
        "FormatID",
        "ChannelType",
        "ChannelCount",
        "SampleRate",
        "BitsPerSample",
        "SampleCount",
        "BlockSize",
      ]
    );
    // No warning on happy path.
    assert!(m.warnings().is_empty());
    // Spot-check final converted values (PrintConv on).
    let by_name = |n: &str| {
      m.tags()
        .iter()
        .find(|t| t.name() == n)
        .map(|t| t.value().clone())
        .unwrap()
    };
    assert_eq!(by_name("FileType"), TagValue::Str("DSF".into()));
    assert_eq!(by_name("FileTypeExtension"), TagValue::Str("dsf".into()));
    assert_eq!(by_name("MIMEType"), TagValue::Str("audio/x-dsf".into()));
    assert_eq!(by_name("FormatID"), TagValue::Str("DSD Raw".into()));
    assert_eq!(
      by_name("ChannelType"),
      TagValue::Str("Stereo (Left, Right)".into())
    );
  }

  #[test]
  fn warns_on_short_fmt_chunk_returns_true() {
    // DSF.pm:68-72 guard fails (fmtLen=8 ≤ 12) ⇒ Warn + return 1.
    // The File:* triplet is pushed (DSF.pm:64 ran first); no payload tags.
    let mut buf = Vec::with_capacity(40);
    buf.extend_from_slice(b"DSD ");
    buf.extend_from_slice(&0x1cu64.to_le_bytes());
    buf.extend_from_slice(&40u64.to_le_bytes()); // fileSize
    buf.extend_from_slice(&0u64.to_le_bytes()); // metaPos
    buf.extend_from_slice(b"fmt ");
    buf.extend_from_slice(&8u64.to_le_bytes()); // fmtLen = 8 (≤ 12 ⇒ guard fail)
    assert_eq!(buf.len(), 40);
    let mut m = Metadata::new("x.dsf");
    let mut c = ParseContext::new(&buf, "DSF", 0, "DSF", None, true, &mut m);
    assert!(ProcessDsf.process(&mut c)); // DSF.pm:72 `return 1`
    let names: Vec<&str> = m.tags().iter().map(|t| t.name()).collect();
    assert_eq!(names, ["FileType", "FileTypeExtension", "MIMEType"]);
    assert_eq!(
      m.warnings(),
      ["Error reading DSF fmt chunk".to_string()].as_slice()
    );
  }

  #[test]
  fn warns_on_too_large_fmt_chunk_returns_true() {
    // DSF.pm:68 `$fmtLen < 1000`: fmtLen = 1000 ⇒ guard fails (the `<` is
    // strict). Pins the upper bound.
    let mut buf = Vec::with_capacity(40);
    buf.extend_from_slice(b"DSD ");
    buf.extend_from_slice(&0x1cu64.to_le_bytes());
    buf.extend_from_slice(&40u64.to_le_bytes());
    buf.extend_from_slice(&0u64.to_le_bytes());
    buf.extend_from_slice(b"fmt ");
    buf.extend_from_slice(&1000u64.to_le_bytes()); // fmtLen = 1000 (NOT < 1000)
    let mut m = Metadata::new("x.dsf");
    let mut c = ParseContext::new(&buf, "DSF", 0, "DSF", None, true, &mut m);
    assert!(ProcessDsf.process(&mut c));
    assert_eq!(
      m.warnings(),
      ["Error reading DSF fmt chunk".to_string()].as_slice()
    );
  }

  #[test]
  fn accepts_fmt_len_999_at_upper_boundary() {
    // Adjacent passing boundary to `fmt_len == 1000`. DSF.pm:68 `$fmtLen <
    // 1000` is strict, so 999 with a 987-byte trailing payload must parse
    // successfully and emit no "Error reading DSF fmt chunk" warning. The
    // payload is mostly zeros (only the first 36 bytes carry the eight
    // fmt-chunk fields — the remaining 951 bytes are unused tail).
    let mut buf = Vec::with_capacity(40 + 987);
    buf.extend_from_slice(b"DSD ");
    buf.extend_from_slice(&0x1cu64.to_le_bytes());
    buf.extend_from_slice(&(40u64 + 987).to_le_bytes()); // fileSize
    buf.extend_from_slice(&0u64.to_le_bytes()); // metaPos = 0 ⇒ no ID3 trailer
    buf.extend_from_slice(b"fmt ");
    buf.extend_from_slice(&999u64.to_le_bytes()); // fmtLen = 999 (< 1000 ✓)
    // First 36 bytes of payload: the eight DSF::Main fields in key order.
    buf.extend_from_slice(&1u32.to_le_bytes()); // key 3 FormatVersion
    buf.extend_from_slice(&0u32.to_le_bytes()); // key 4 FormatID = 'DSD Raw'
    buf.extend_from_slice(&2u32.to_le_bytes()); // key 5 ChannelType = Stereo
    buf.extend_from_slice(&2u32.to_le_bytes()); // key 6 ChannelCount
    buf.extend_from_slice(&2_822_400u32.to_le_bytes()); // key 7 SampleRate
    buf.extend_from_slice(&1u32.to_le_bytes()); // key 8 BitsPerSample
    buf.extend_from_slice(&2_822_400u64.to_le_bytes()); // key 9 SampleCount
    buf.extend_from_slice(&4096u32.to_le_bytes()); // key 11 BlockSize
    // Pad to total payload of 987 bytes (951 zeros after the 36-byte head).
    buf.extend(std::iter::repeat(0u8).take(987 - 36));
    assert_eq!(buf.len(), 40 + 987);
    let mut m = Metadata::new("x.dsf");
    let mut c = ParseContext::new(&buf, "DSF", 0, "DSF", None, true, &mut m);
    assert!(ProcessDsf.process(&mut c));
    // No warning at the passing side of the boundary.
    assert!(
      m.warnings().is_empty(),
      "fmt_len=999 must not emit any warning, got: {:?}",
      m.warnings()
    );
    // All eight payload tags present alongside the File:* triplet.
    let names: Vec<&str> = m.tags().iter().map(|t| t.name()).collect();
    assert_eq!(
      names,
      [
        "FileType",
        "FileTypeExtension",
        "MIMEType",
        "FormatVersion",
        "FormatID",
        "ChannelType",
        "ChannelCount",
        "SampleRate",
        "BitsPerSample",
        "SampleCount",
        "BlockSize",
      ]
    );
  }

  #[test]
  fn warns_on_truncated_fmt_payload_returns_true() {
    // fmtLen claims a payload longer than the file actually has.
    let mut buf = Vec::with_capacity(40);
    buf.extend_from_slice(b"DSD ");
    buf.extend_from_slice(&0x1cu64.to_le_bytes());
    buf.extend_from_slice(&40u64.to_le_bytes());
    buf.extend_from_slice(&0u64.to_le_bytes());
    buf.extend_from_slice(b"fmt ");
    buf.extend_from_slice(&48u64.to_le_bytes()); // fmtLen = 48 ⇒ need 36 more bytes
    assert_eq!(buf.len(), 40); // but we have NOTHING after the 40-byte header
    let mut m = Metadata::new("x.dsf");
    let mut c = ParseContext::new(&buf, "DSF", 0, "DSF", None, true, &mut m);
    assert!(ProcessDsf.process(&mut c));
    assert_eq!(
      m.warnings(),
      ["Error reading DSF fmt chunk".to_string()].as_slice()
    );
    // No payload tags emitted (the walk never ran).
    assert!(
      m.tags().iter().all(|t| {
        let n = t.name();
        n == "FileType" || n == "FileTypeExtension" || n == "MIMEType"
      }),
      "no DSF fmt tags expected on a short read"
    );
  }

  #[test]
  fn fmt_len_equals_12_underflow_guard() {
    // CRITICAL: DSF.pm:68 strict `$fmtLen > 12`. With fmtLen==12 the
    // subtraction `$fmtLen - 12 == 0` would not underflow in Perl, but the
    // `>` guard prevents the (no-op) read. We MUST NOT subtract 12 from
    // fmt_len when fmt_len <= 12 — that would underflow in unsigned Rust.
    // This pins the panic-free behavior at the boundary.
    let mut buf = Vec::with_capacity(40);
    buf.extend_from_slice(b"DSD ");
    buf.extend_from_slice(&0x1cu64.to_le_bytes());
    buf.extend_from_slice(&40u64.to_le_bytes());
    buf.extend_from_slice(&0u64.to_le_bytes());
    buf.extend_from_slice(b"fmt ");
    buf.extend_from_slice(&12u64.to_le_bytes()); // fmtLen = 12 (NOT > 12)
    let mut m = Metadata::new("x.dsf");
    let mut c = ParseContext::new(&buf, "DSF", 0, "DSF", None, true, &mut m);
    // Must not panic (no debug-mode underflow) and must Warn-then-accept.
    assert!(ProcessDsf.process(&mut c));
    assert_eq!(
      m.warnings(),
      ["Error reading DSF fmt chunk".to_string()].as_slice()
    );
  }

  #[test]
  fn fmt_len_zero_underflow_guard() {
    // Even more adversarial: fmtLen = 0 (or 1). The guard MUST fire BEFORE
    // any subtraction; faithful behavior is Warn + return 1.
    for fmt_len in [0u64, 1, 11] {
      let mut buf = Vec::with_capacity(40);
      buf.extend_from_slice(b"DSD ");
      buf.extend_from_slice(&0x1cu64.to_le_bytes());
      buf.extend_from_slice(&40u64.to_le_bytes());
      buf.extend_from_slice(&0u64.to_le_bytes());
      buf.extend_from_slice(b"fmt ");
      buf.extend_from_slice(&fmt_len.to_le_bytes());
      let mut m = Metadata::new("x.dsf");
      let mut c = ParseContext::new(&buf, "DSF", 0, "DSF", None, true, &mut m);
      assert!(ProcessDsf.process(&mut c), "fmt_len={fmt_len}");
      assert_eq!(
        m.warnings(),
        ["Error reading DSF fmt chunk".to_string()].as_slice(),
        "fmt_len={fmt_len}"
      );
    }
  }
}
