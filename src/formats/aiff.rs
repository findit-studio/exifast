//! Faithful port of `Image::ExifTool::AIFF` (lib/Image/ExifTool/AIFF.pm).
//! Implements `ProcessAIFF` (AIFF.pm:184-273), the four tag tables
//! (`%AIFF::Main`, `%AIFF::Common`, `%AIFF::FormatVers`, `%AIFF::Comment`),
//! and the custom `ProcessComment` chunk decoder (AIFF.pm:155-178).
//!
//! Two notable deferrals (in-code) — both faithful-by-derivation Phase-2
//! forward-items, NOT silent omissions:
//!
//! 1. **`'ID3 '` chunk (AIFF.pm:69-75)** — `SubDirectory => { TagTable =>
//!    'Image::ExifTool::ID3::Main', ProcessProc => &ProcessID3 }`. The
//!    parallel ID3 port (PR #6) is the canonical home for ProcessID3; here
//!    we recognize the chunk but skip its body (no `File:ID3Size`, no
//!    `ID3v2_*` tags). Real-file AIFF fixtures that carry an `ID3 ` chunk
//!    will be re-enabled when ID3 lands.
//!
//! 2. **`%AIFF::Composite Duration` (AIFF.pm:136-145)** — IMPLEMENTED
//!    inline in [`emit_composite_duration`] (post-chunk-loop). The
//!    tag is a self-contained composite whose `RawConv = $val[1]/$val[0]`
//!    needs neither the D11 conversion context nor the broader composite
//!    runtime (it depends only on two AIFF-extracted numerics). Codex R4
//!    raised the prior defer as no-ship; faithful inline derivation
//!    landed in this PR, validated against `tests/fixtures/AIFF_duration.aif`
//!    (bundled-Perl oracle 2026-05-20). Codex R6 then showed the I64-only
//!    capture path silently dropped Duration when SampleRate was a non-
//!    integer 80-bit extended (e.g. NTSC pull-down 44056.94 Hz); the
//!    f64 capture now accepts both I64 and F64 and is pinned by
//!    `AIFF_duration_float.aif` (rate=22050.5) and `AIFC_noninteger_rate.aifc`
//!    (rate=44056.94, oracle Duration `1.00000136187397` under `-n`).
//!    Codex R7 then surfaced two further divergences (also fixed):
//!    (a) `get_extended` was rounding the 64-bit significand through f64
//!    before the integer test, losing precision above 2^53 — now
//!    detects integer-valued extendeds via INTEGER arithmetic on the
//!    bit pattern, emitting `TagValue::Str("<decimal>")` for exact
//!    integers that overflow i64 (oracle quotes them); `tag_as_f64`
//!    accepts Str via Perl-`atof` semantics so Duration still computes.
//!    Pinned by `AIFF_ext_int_overflow.aif` (SampleRate = 2^63 + 1).
//!    (b) `convert_duration` was casting h/m/s through `f64::trunc as
//!    i64`, saturating for huge finite durations — now keeps h/m/d as
//!    f64 through the modulo arithmetic, only casting the SMALL
//!    REMAINDERS to i64 at the final `%d:%.2d:%.2d` printf (the days
//!    count `$d` is interpolated via `format_g(d, 15)`, matching Perl's
//!    default NV stringification). Pinned by `AIFF_huge_duration.aif`
//!    (Duration ≈ 1.93e+25 s, oracle days-string `2.23875151780487e+20`).
//!    Other Composite tags (multi-tag, context-dependent, or non-self-
//!    contained) still need the broader Composite runtime — that's the
//!    parallel ID3 PR's D11 derivation.
//!
//! 3. **DjVu branch body (AIFF.pm:204-207)** — when `AT&TFORM` is followed
//!    by `DJVU` or `DJVM` at bytes 12..16, AIFF.pm routes the chunk loop to
//!    `Image::ExifTool::DjVu::Main`. Out of Stage-1 audio/video scope
//!    (DjVu = document image). Detection IS faithful (SetFileType +
//!    accept) and the AIFF.pm:206 `' (multi-page)'` FileType suffix for
//!    `DJVM` is also faithful — oracle (2026-05-20) on `AT&TFORMxxxxDJVM`
//!    ⇒ `File:FileType="DJVU (multi-page)"`. Only the DjVu sub-table
//!    dispatch (AIFF.pm:204) is deferred to a dedicated DjVu PR. A bare
//!    `AT&TFORM` without the DJVU/DJVM tail still rejects (AIFF.pm:199).

use crate::{
  charset::decode_macroman,
  datetime::{convert_datetime, convert_unix_time, AIFF_EPOCH_OFFSET},
  parser::{FormatParser, ParseContext},
  processbinarydata::process_binary_data,
  tagtable::{PrintConv, PrintConvHash, PrintValue, TagDef, TagId, TagTable, ValueConv},
  value::{Group, Metadata, TagValue},
};

// =============================================================================
// %AIFF::Main (AIFF.pm:31-82)
//
// Family-0 group "AIFF" (AIFF.pm:32 `GROUPS => { 2 => 'Audio' }` sets family-2
// only; the table's package is `Image::ExifTool::AIFF::Main` so family-0/1
// is "AIFF" per ExifTool's convention — verified against the AIFF.aif oracle
// which prints `AIFF:Name`, `AIFF:Author`, etc. under `-G1`).
//
// Scalar tags (NAME/AUTH/(c) /ANNO/APPL) all apply `Decode($val, "MacRoman")`
// in their Perl source (AIFF.pm:53/58/63/67; APPL is "ApplicationData" with
// no ValueConv but its first 4 bytes are the application signature — we
// emit the raw bytes verbatim, matching the oracle's `"AAAAappdat"`).
// =============================================================================

/// AIFF.pm:53,58,63,67,115,132 `Decode($val, "MacRoman")`. The chunk-loop
/// strips trailing NULs (AIFF.pm:250) BEFORE this ValueConv runs, so any
/// trailing-NUL handling here would be defensive only.
fn decode_macroman_tagvalue(v: &TagValue) -> TagValue {
  // The chunk loop passes the raw bytes as TagValue::Bytes (no UTF-8
  // assumption); decode them via the faithful MacRoman table and emit Str.
  // For TagValue::Str passthrough (already UTF-8), re-encode each char from
  // its lossless single-byte mapping is impossible — so we only support
  // Bytes here (the only producer). Defensive: pass through Str unchanged.
  match v {
    TagValue::Bytes(b) => TagValue::Str(decode_macroman(b).into()),
    other => other.clone(),
  }
}

// AIFF.pm:39-42 — FVER subdirectory (FormatVersion).
static FORMAT_VERSION_TAG: TagDef =
  TagDef::new("FormatVersion", "AIFF", ValueConv::None, PrintConv::None);

// AIFF.pm:43-46 — COMM subdirectory (Common).
static COMMON_TAG: TagDef = TagDef::new("Common", "AIFF", ValueConv::None, PrintConv::None);

// AIFF.pm:47-50 — COMT subdirectory (Comment).
static COMMENT_TAG: TagDef = TagDef::new("Comment", "AIFF", ValueConv::None, PrintConv::None);

// AIFF.pm:51-54 — NAME tag.
static NAME_TAG: TagDef = TagDef::new(
  "Name",
  "AIFF",
  ValueConv::Func(decode_macroman_tagvalue),
  PrintConv::None,
);

// AIFF.pm:55-59 — AUTH tag.
static AUTHOR_TAG: TagDef = TagDef::new(
  "Author",
  "AIFF",
  ValueConv::Func(decode_macroman_tagvalue),
  PrintConv::None,
);

// AIFF.pm:60-64 — '(c) ' tag (Copyright).
static COPYRIGHT_TAG: TagDef = TagDef::new(
  "Copyright",
  "AIFF",
  ValueConv::Func(decode_macroman_tagvalue),
  PrintConv::None,
);

// AIFF.pm:65-68 — ANNO tag.
static ANNOTATION_TAG: TagDef = TagDef::new(
  "Annotation",
  "AIFF",
  ValueConv::Func(decode_macroman_tagvalue),
  PrintConv::None,
);

// AIFF.pm:69-75 — 'ID3 ' tag (SubDirectory to ID3::Main). DEFERRED per the
// module-level doc; we keep the TagDef so the chunk is recognized but the
// chunk body is dropped (no SubDirectory dispatch implemented for ID3 yet).
static ID3_TAG: TagDef = TagDef::new("ID3", "AIFF", ValueConv::None, PrintConv::None);

// AIFF.pm:76 — APPL tag (ApplicationData), no ValueConv.
static APPLICATION_DATA_TAG: TagDef =
  TagDef::new("ApplicationData", "AIFF", ValueConv::None, PrintConv::None);

/// `%AIFF::Main` lookup (AIFF.pm:31-82). Keys are 4-character chunk IDs.
fn aiff_main_get(id: TagId) -> Option<&'static TagDef> {
  match id {
    TagId::Str("FVER") => Some(&FORMAT_VERSION_TAG),
    TagId::Str("COMM") => Some(&COMMON_TAG),
    TagId::Str("COMT") => Some(&COMMENT_TAG),
    TagId::Str("NAME") => Some(&NAME_TAG),
    TagId::Str("AUTH") => Some(&AUTHOR_TAG),
    TagId::Str("(c) ") => Some(&COPYRIGHT_TAG),
    TagId::Str("ANNO") => Some(&ANNOTATION_TAG),
    TagId::Str("ID3 ") => Some(&ID3_TAG),
    TagId::Str("APPL") => Some(&APPLICATION_DATA_TAG),
    _ => None,
  }
}

/// `%AIFF::Main` (AIFF.pm:31). family-0 group "AIFF".
pub static AIFF_MAIN: TagTable = TagTable::new("AIFF", aiff_main_get);

// =============================================================================
// %AIFF::Common (AIFF.pm:84-117)
//
// PROCESS_PROC = ProcessBinaryData, FORMAT = 'int16u'. Six tags.
// =============================================================================

static NUM_CHANNELS_TAG: TagDef =
  TagDef::new("NumChannels", "AIFF", ValueConv::None, PrintConv::None);

static NUM_SAMPLE_FRAMES_TAG: TagDef =
  TagDef::new("NumSampleFrames", "AIFF", ValueConv::None, PrintConv::None).with_format("int32u");

static SAMPLE_SIZE_TAG: TagDef =
  TagDef::new("SampleSize", "AIFF", ValueConv::None, PrintConv::None);

static SAMPLE_RATE_TAG: TagDef =
  TagDef::new("SampleRate", "AIFF", ValueConv::None, PrintConv::None).with_format("extended");

/// AIFF.pm:95-110 — `CompressionType` PrintConv hash.
static COMPRESSION_TYPE_TAG: TagDef = TagDef::new(
  "CompressionType",
  "AIFF",
  ValueConv::None,
  PrintConv::Hash(PrintConvHash::direct(&[
    ("NONE", PrintValue::Str("None")),
    ("ACE2", PrintValue::Str("ACE 2-to-1")),
    ("ACE8", PrintValue::Str("ACE 8-to-3")),
    ("MAC3", PrintValue::Str("MAC 3-to-1")),
    ("MAC6", PrintValue::Str("MAC 6-to-1")),
    ("sowt", PrintValue::Str("Little-endian, no compression")),
    ("alaw", PrintValue::Str("a-law")),
    ("ALAW", PrintValue::Str("A-law")),
    ("ulaw", PrintValue::Str("mu-law")),
    ("ULAW", PrintValue::Str("Mu-law")),
    ("GSM ", PrintValue::Str("GSM")),
    ("G722", PrintValue::Str("G722")),
    ("G726", PrintValue::Str("G726")),
    ("G728", PrintValue::Str("G728")),
  ])),
)
.with_format("string[4]");

// AIFF.pm:115 `ValueConv => '$self->Decode($val, "MacRoman")'` on the
// CompressorName pstring. The pstring path in [`process_binary_data`] emits
// `TagValue::Bytes` (raw byte string, faithful to Perl `substr` — Codex R1
// fix: a prior `from_utf8(...).unwrap_or_default()` here would have
// corrupted any high-byte MacRoman payload such as `0x80` → "Ä" into the
// empty string). The shared [`decode_macroman_tagvalue`] now handles Bytes
// directly; no separate helper is needed.
static COMPRESSOR_NAME_TAG: TagDef = TagDef::new(
  "CompressorName",
  "AIFF",
  ValueConv::Func(decode_macroman_tagvalue),
  PrintConv::None,
)
.with_format("pstring");

fn aiff_common_get(id: TagId) -> Option<&'static TagDef> {
  match id {
    TagId::Int(0) => Some(&NUM_CHANNELS_TAG),
    TagId::Int(1) => Some(&NUM_SAMPLE_FRAMES_TAG),
    TagId::Int(3) => Some(&SAMPLE_SIZE_TAG),
    TagId::Int(4) => Some(&SAMPLE_RATE_TAG),
    TagId::Int(9) => Some(&COMPRESSION_TYPE_TAG),
    TagId::Int(11) => Some(&COMPRESSOR_NAME_TAG),
    _ => None,
  }
}

/// `%AIFF::Common` (AIFF.pm:84). family-0 group "AIFF".
pub static AIFF_COMMON: TagTable = TagTable::new("AIFF", aiff_common_get);

/// Sorted integer keys of `%AIFF::Common` (ExifTool `sort { $a <=> $b }
/// TagTableKeys`, ExifTool.pm:9907). Required by [`process_binary_data`]
/// to walk tags in numeric order so the `entry >= size` early-exit works.
pub const AIFF_COMMON_KEYS: &[i64] = &[0, 1, 3, 4, 9, 11];

// =============================================================================
// %AIFF::FormatVers (AIFF.pm:119-123)
//
// PROCESS_PROC = ProcessBinaryData, FORMAT = 'int32u'. One tag.
// %timeInfo (AIFF.pm:24-28): ValueConv subtracts AIFF_EPOCH_OFFSET and calls
// ConvertUnixTime; PrintConv calls ConvertDateTime (identity under default
// options).
// =============================================================================

/// AIFF.pm:24-26 `ValueConv => 'ConvertUnixTime($val - ((66*365+17)*24*3600))'`.
/// Applied to a raw int32u from the bit stream; subtract AIFF/Mac → Unix
/// epoch offset, run `ConvertUnixTime` (GMT branch under `TZ=UTC`).
fn aiff_time_value_conv(v: &TagValue) -> TagValue {
  match v {
    TagValue::I64(n) => {
      // AIFF.pm:26 `$val - ((66 * 365 + 17) * 24 * 3600)`. Faithful to
      // Perl: plain signed subtraction. The input is an `int32u` widened
      // to `i64` (range `[0, u32::MAX]`), so `n - AIFF_EPOCH_OFFSET`
      // lands in `[-2_082_844_800, 2_212_122_495]` — well within `i64`
      // bounds, no overflow possible. Negative results (raw values
      // below 2_082_844_800, i.e. pre-1970-01-01 Mac/AIFF timestamps)
      // are FAITHFUL: Perl `gmtime(-N)` decodes as a pre-Unix-epoch
      // date (e.g. raw 0 ⇒ unix -2_082_844_800 ⇒ "1904:01:01 00:00:00"
      // = the Mac/AIFF epoch itself, verified against bundled
      // ExifTool on AIFC_pre1970.aifc). `convert_unix_time` likewise
      // decodes negative input via Hinnant's proleptic Gregorian.
      // (Codex R4 raised a `saturating_sub` concern; empirically a
      // no-op on `i64` here — `0_i64.saturating_sub(2_082_844_800) =
      // -2_082_844_800`, identical to signed subtraction. Plain `-`
      // pinned for clarity + the AIFC_pre1970 conformance fixture.)
      let unix = *n - AIFF_EPOCH_OFFSET;
      TagValue::Str(convert_unix_time(unix).into())
    }
    other => other.clone(),
  }
}

/// AIFF.pm:27 `PrintConv => '$self->ConvertDateTime($val)'`. Under the AIFF
/// read path no `DateFormat` is set, so `ConvertDateTime` is identity
/// ([`convert_datetime`]). Modeled as a `Func` so future `DateFormat`
/// derivation can replace the body without touching the table.
fn aiff_datetime_print_conv(v: &TagValue) -> TagValue {
  match v {
    TagValue::Str(s) => TagValue::Str(convert_datetime(s).into()),
    other => other.clone(),
  }
}

static FORMAT_VERSION_TIME_TAG: TagDef = TagDef::new(
  "FormatVersionTime",
  "AIFF",
  ValueConv::Func(aiff_time_value_conv),
  PrintConv::Func(aiff_datetime_print_conv),
);

fn aiff_format_vers_get(id: TagId) -> Option<&'static TagDef> {
  match id {
    TagId::Int(0) => Some(&FORMAT_VERSION_TIME_TAG),
    _ => None,
  }
}

/// `%AIFF::FormatVers` (AIFF.pm:119).
pub static AIFF_FORMAT_VERS: TagTable = TagTable::new("AIFF", aiff_format_vers_get);

/// Sorted integer keys of `%AIFF::FormatVers`.
pub const AIFF_FORMAT_VERS_KEYS: &[i64] = &[0];

// =============================================================================
// %AIFF::Comment (AIFF.pm:125-134)
//
// PROCESS_PROC = ProcessComment (custom, AIFF.pm:155-178). Three tags
// (CommentTime, MarkerID, Comment). The custom proc walks numComments
// (u16) × (time u32, markerID u16, size u16, text<size>), padding each
// comment to even byte count.
// =============================================================================

static COMMENT_TIME_TAG: TagDef = TagDef::new(
  "CommentTime",
  "AIFF",
  ValueConv::Func(aiff_time_value_conv),
  PrintConv::Func(aiff_datetime_print_conv),
);

static MARKER_ID_TAG: TagDef = TagDef::new("MarkerID", "AIFF", ValueConv::None, PrintConv::None);

static COMMENT_TEXT_TAG: TagDef = TagDef::new(
  "Comment",
  "AIFF",
  ValueConv::Func(decode_macroman_tagvalue),
  PrintConv::None,
);

fn aiff_comment_get(id: TagId) -> Option<&'static TagDef> {
  match id {
    TagId::Int(0) => Some(&COMMENT_TIME_TAG),
    TagId::Int(1) => Some(&MARKER_ID_TAG),
    TagId::Int(2) => Some(&COMMENT_TEXT_TAG),
    _ => None,
  }
}

/// `%AIFF::Comment` (AIFF.pm:125). Custom dispatch via [`process_comment`].
pub static AIFF_COMMENT: TagTable = TagTable::new("AIFF", aiff_comment_get);

/// Faithful `ProcessComment` (AIFF.pm:155-178). Reads `numComments` (u16)
/// then for each comment: time u32, markerID u16, size u16, text<size>;
/// size is rounded up to even per :175 (`++$size if $size & 0x01`).
fn process_comment(data: &[u8], into: &mut Metadata, print_conv_enabled: bool) {
  // AIFF.pm:161 `return 0 unless $dirLen > 2`.
  if data.len() <= 2 {
    return;
  }
  // AIFF.pm:162 `my $numComments = unpack('n', $$dataPt)`.
  let num_comments = u16::from_be_bytes([data[0], data[1]]) as usize;
  let mut pos: usize = 2;
  for _ in 0..num_comments {
    // AIFF.pm:167 `last if $pos + 8 > $dirLen`.
    if pos + 8 > data.len() {
      break;
    }
    // AIFF.pm:168 `my ($time, $markerID, $size) = unpack("x${pos}Nnn", $$dataPt)`.
    let time = u32::from_be_bytes([data[pos], data[pos + 1], data[pos + 2], data[pos + 3]]);
    let marker_id = u16::from_be_bytes([data[pos + 4], data[pos + 5]]);
    let size = u16::from_be_bytes([data[pos + 6], data[pos + 7]]) as usize;

    // AIFF.pm:169 `$et->HandleTag($tagTablePtr, 0, $time);`.
    if let Some(def) = (AIFF_COMMENT.get())(TagId::Int(0)) {
      let raw = TagValue::I64(i64::from(time));
      let out = crate::convert::apply(def, &raw, print_conv_enabled);
      into.push(
        Group::new(AIFF_COMMENT.group0(), def.group1()),
        def.name(),
        out,
      );
    }
    // AIFF.pm:170 `$et->HandleTag($tagTablePtr, 1, $markerID) if $markerID;`.
    if marker_id != 0 {
      if let Some(def) = (AIFF_COMMENT.get())(TagId::Int(1)) {
        let raw = TagValue::I64(i64::from(marker_id));
        let out = crate::convert::apply(def, &raw, print_conv_enabled);
        into.push(
          Group::new(AIFF_COMMENT.group0(), def.group1()),
          def.name(),
          out,
        );
      }
    }
    // AIFF.pm:171 `$pos += 8`.
    pos += 8;
    // AIFF.pm:172 `last if $pos + $size > $dirLen`.
    if pos + size > data.len() {
      break;
    }
    // AIFF.pm:173-174 `my $val = substr($$dataPt, $pos, $size);
    // $et->HandleTag($tagTablePtr, 2, $val)`.
    if let Some(def) = (AIFF_COMMENT.get())(TagId::Int(2)) {
      let raw = TagValue::Bytes(data[pos..pos + size].to_vec());
      let out = crate::convert::apply(def, &raw, print_conv_enabled);
      into.push(
        Group::new(AIFF_COMMENT.group0(), def.group1()),
        def.name(),
        out,
      );
    }
    // AIFF.pm:175 `++$size if $size & 0x01` — pad to even.
    let padded = size + (size & 1);
    pos += padded;
  }
}

// =============================================================================
// ProcessAIFF parser (AIFF.pm:184-273)
// =============================================================================

/// Trim trailing NULs from a scalar chunk (AIFF.pm:250 `$buff =~ s/\0+$//`).
/// Applied to non-SubDirectory, non-Binary chunks before HandleTag.
fn strip_trailing_nuls(b: &[u8]) -> &[u8] {
  let mut end = b.len();
  while end > 0 && b[end - 1] == 0 {
    end -= 1;
  }
  &b[..end]
}

/// AIFF parser (faithful `ProcessAIFF`, AIFF.pm:184-273).
pub struct ProcessAiff;

impl FormatParser for ProcessAiff {
  fn process(&self, ctx: &mut ParseContext<'_>) -> bool {
    // Pre-validate the FORM header against the immutable borrow, then drop
    // the `&data` and switch to `ctx.metadata()` + `ctx.data()` per-iteration
    // borrows (the chunk loop alternates borrows and cannot hold a long-lived
    // `&data` while pushing to metadata).
    // Header validation + DjVu branch. AIFF.pm:191 reads 12 bytes; the DjVu
    // arm (AIFF.pm:194-207) reads 4 MORE bytes (16 total) to verify DJVU/DJVM
    // tail. Decide the magic type ("AIFF", "AIFC", or "DJVU") here against
    // an immutable borrow, then drop it before any `ctx.metadata()` calls.
    // Discriminator for the DjVu sub-type. AIFF.pm:206 appends
    // `' (multi-page)'` to `$$et{VALUE}{FileType}` ONLY when the 4-byte
    // tail at bytes 12..16 is exactly `DJVM` (multi-page DjVu container);
    // the single-page `DJVU` arm leaves FileType as `"DJVU"`.
    let mut djvm_multi_page = false;
    let magic_type: &'static str = {
      let data = ctx.data();
      // AIFF.pm:191 `return 0 unless $raf->Read($buff, 12) == 12`.
      if data.len() < 12 {
        return false;
      }
      // AIFF.pm:194-207 DjVu arm. `AT&TFORM` magic + (`DJVU`|`DJVM`) at
      // bytes 12..16. AIFF.pm reads 4 EXTRA bytes (`return 0 unless
      // $raf->Read($buf2,4) == 4 and $buf2 =~ /^(DJVU|DJVM)/`); the
      // resulting file type is `'DJVU'` (AIFF.pm:202 `$et->SetFileType
      // ('DJVU')`), with `' (multi-page)'` appended when the tail was
      // `DJVM` (AIFF.pm:206). The DjVu TAG table dispatch (AIFF.pm:204
      // `GetTagTable('Image::ExifTool::DjVu::Main')`) is still Stage-2
      // deferred — only the SetFileType/FileType suffix is faithful here.
      if data.starts_with(b"AT&TFORM") {
        // AIFF.pm:199 `return 0 unless $raf->Read($buf2,4) == 4 and
        // $buf2 =~ /^(DJVU|DJVM)/`.
        if data.len() < 16 {
          return false;
        }
        match &data[12..16] {
          b"DJVU" => {}
          b"DJVM" => {
            djvm_multi_page = true;
          }
          _ => return false,
        }
        "DJVU"
      } else {
        // AIFF.pm:209 `return 0 unless $buff =~ /^FORM....(AIF(F|C))/s` —
        // 4-byte FORM lit, ANY 4-byte length, then "AIF" + ('F'|'C').
        if &data[0..4] != b"FORM" {
          return false;
        }
        match &data[8..12] {
          b"AIFF" => "AIFF",
          b"AIFC" => "AIFC",
          _ => return false,
        }
      }
    };
    // AIFF.pm:202/210 `$et->SetFileType($1|'DJVU')` — drive SetFileType
    // through the parser (no-arg form would default to the candidate; we
    // faithfully pass the explicit magic).
    ctx.set_file_type(Some(magic_type), None, None);
    let print_conv_enabled = ctx.print_conv_enabled();

    // DjVu branch.
    if magic_type == "DJVU" {
      // AIFF.pm:206 `$$et{VALUE}{FileType} .= " (multi-page)" if $buf2 eq
      // 'DJVM' and $$et{VALUE}{FileType};`. Faithfully overwrite the
      // pushed `File:FileType` value with the suffixed string. The
      // FileTypeExtension/MIMEType are NOT touched by AIFF.pm:206 (it's
      // an explicit `.=` on FileType only). Bundled-Perl oracle (2026-05-20)
      // on `AT&TFORMxxxxDJVM` confirms `File:FileType="DJVU (multi-page)"`
      // with the rest of the File:* triplet unchanged.
      if djvm_multi_page {
        let m = ctx.metadata();
        let file_grp = Group::new("File", "File");
        m.set_tag_value(
          &file_grp,
          "FileType",
          TagValue::Str("DJVU (multi-page)".into()),
        );
      }
      // Faithfully stop after SetFileType (Stage-2 defer per module doc).
      // AIFF.pm:204-207 would build a DjVu tag table here and run the
      // chunk loop with `$type = 'DjVu'`; we have no DjVu module ported,
      // so the chunk loop is skipped and the parser accepts with only the
      // File:* tags emitted. Identical to AIFF.pm's `fast3` mode (:203
      // `return 1 if $fast3`), which is one of two faithful Perl exits
      // for this branch.
      return true;
    }

    // AIFF.pm:215 `SetByteOrder('MM')` — AIFF is big-endian throughout.
    // AIFF.pm:220-270 chunk loop.
    let mut pos: usize = 12;
    // Faithful Perl outer-loop counter (`for ($n=0;;++$n)`, AIFF.pm:220). The
    // empty-chunk branch (AIFF.pm:259) does its OWN pre-increment of `$n` then
    // `next`s, so the for's post-iteration `++$n` ALSO runs — `$n` bumps by 2
    // per consecutive empty chunk. The known-tag branch sets `$n = 0`
    // (AIFF.pm:269) and the for's `++$n` makes it 1 for the next iteration.
    // Modeling `$n` exactly (rather than a Rust-side abort threshold) keeps
    // the abort point byte-identical to Perl in BOTH the "start of file" and
    // "mid-file after a known tag" cases — Codex round-1 caught the off-by-
    // half in the earlier `empty_run >= 51` approximation.
    let mut n: u32 = 0;
    loop {
      // Snapshot the 8-byte chunk header against an immutable borrow that
      // ends with this block — the rest of the loop body uses ctx.metadata()
      // for pushes and re-borrows ctx.data() for the chunk body.
      let header = {
        let data = ctx.data();
        // AIFF.pm:221 `$raf->Read($buff, 8) == 8 or last`. `checked_add`
        // defends a saturating `pos == usize::MAX` from a prior huge-`len2`
        // iteration (32-bit `usize` host); the parser exits cleanly there.
        if pos.checked_add(8).map_or(true, |n| n > data.len()) {
          None
        } else {
          // AIFF.pm:223 `my ($tag, $len) = unpack('a4N', $buff)`.
          let tag_bytes: [u8; 4] = [data[pos], data[pos + 1], data[pos + 2], data[pos + 3]];
          let len = u32::from_be_bytes([data[pos + 4], data[pos + 5], data[pos + 6], data[pos + 7]])
            as usize;
          Some((tag_bytes, len))
        }
      };
      let Some((tag_bytes, len)) = header else {
        break;
      };
      pos += 8; // :222 `$pos += 8`.
                // AIFF.pm:227 `my $len2 = $len + ($len & 0x01)` — chunks padded to
                // an even number of bytes. Perl scalars are 64-bit; on a 32-bit
                // host `usize` is 32-bit and `len + 1` would wrap when
                // `len == u32::MAX`. We `saturating_add`: `len2` then equals
                // `usize::MAX`, which is guaranteed `> data.len()` so the
                // short-read / unknown-chunk EOF arms both still fire
                // correctly. Equivalent to Perl on the host's natural width.
      let len2 = len.saturating_add(len & 0x01);
      // AIFF.pm:224 `$et->GetTagInfo($tagTablePtr, $tag)`.
      let tag_str = match core::str::from_utf8(&tag_bytes) {
        Ok(s) => tag_str_to_static(s),
        Err(_) => "", // non-UTF-8 chunk id ⇒ skip
      };
      let mut tag_info = (AIFF_MAIN.get())(TagId::Str(tag_str));

      // AIFF.pm:228-241 large-chunk handling.
      if len2 > 100_000_000 {
        // AIFF.pm:229-236: `LargeFileSupport` default is `1` (truthy,
        // ExifTool.pm:1167 `[ 'LargeFileSupport', 1, ... ]`), so the
        // `if (not $et->Options('LargeFileSupport'))` and `elsif (...
        // eq '2')` branches BOTH fall through under default options.
        // The read path here has no Options surface — i.e. we faithfully
        // emulate the default-LFS-on Perl behavior, which means neither
        // the "End of processing" nor the "Skipping large chunk
        // (LargeFileSupport is 2)" branch fires. The fall-through
        // reaches AIFF.pm:237-240: known tagInfo ⇒ "Skipping large
        // $$tagInfo{Name} chunk (> 100 MB)" + `undef $tagInfo` so the
        // chunk body is skipped via the `else { Seek }` arm (AIFF.pm:265-
        // 267). The oracle for `AIFF_huge.aif` (`bundled perl exiftool`,
        // captured 2026-05-20) confirms exactly this Warning.
        if let Some(def) = tag_info {
          ctx
            .metadata()
            .push_warning(format!("Skipping large {} chunk (> 100 MB)", def.name()));
          tag_info = None;
        }
      }

      if let Some(def) = tag_info {
        // AIFF.pm:248 `$raf->Read($buff, $len2) >= $len or $err=1, last;`.
        // Need enough bytes for the (unpadded) `$len` data; the +1 pad byte
        // is allowed to be missing. `pos.checked_add(len)` defends 32-bit
        // `usize` hosts against overflow when an attacker-controlled `len`
        // approaches `usize::MAX` (Perl scalars are 64-bit and this would
        // simply be a huge number; we treat it as "short-read" identically).
        let need = pos.checked_add(len);
        if need.map_or(true, |n| n > ctx.data().len()) {
          // Short read ⇒ Perl's `$err = 1; last` → after-loop Warn
          // (AIFF.pm:271) `Warn("Error reading $type file (corrupted?)")`.
          ctx
            .metadata()
            .push_warning(format!("Error reading {} file (corrupted?)", magic_type));
          break;
        }
        // Snapshot the chunk body into an owned Vec so we can release the
        // &ctx.data() borrow before pushing tags. Cheap for the small
        // chunks AIFF carries; AIFF.pm:248 itself copies into $buff.
        let body_owned: Vec<u8> = ctx.data()[pos..pos + len].to_vec();
        let body_raw: &[u8] = &body_owned;
        // Dispatch by chunk:
        //   COMM  → process_binary_data(AIFF_COMMON, FORMAT=int16u)
        //   FVER  → process_binary_data(AIFF_FORMAT_VERS, FORMAT=int32u)
        //   COMT  → process_comment (custom)
        //   ID3   → deferred (skip body; recognized but no tags emitted)
        //   else  → scalar tag (NAME/AUTH/(c) /ANNO/APPL) — trim trailing
        //           NULs (AIFF.pm:249-251) and HandleTag via convert::apply.
        match tag_str {
          "COMM" => process_binary_data(
            body_raw,
            "int16u",
            &AIFF_COMMON,
            AIFF_COMMON_KEYS,
            ctx.metadata(),
            print_conv_enabled,
          ),
          "FVER" => process_binary_data(
            body_raw,
            "int32u",
            &AIFF_FORMAT_VERS,
            AIFF_FORMAT_VERS_KEYS,
            ctx.metadata(),
            print_conv_enabled,
          ),
          "COMT" => process_comment(body_raw, ctx.metadata(), print_conv_enabled),
          "ID3 " => {
            // Faithful defer (see module doc): skip the ID3 chunk body.
            // The parallel ID3 PR will integrate ProcessID3 here later.
          }
          _ => {
            // Scalar tag (NAME, AUTH, '(c) ', ANNO, APPL — all defined in
            // %AIFF::Main with ValueConv `Decode($val, "MacRoman")` for the
            // text tags, no SubDirectory, no Binary).
            let stripped = strip_trailing_nuls(body_raw);
            let raw = TagValue::Bytes(stripped.to_vec());
            let out = crate::convert::apply(def, &raw, print_conv_enabled);
            // ValueConv::Func with decode_macroman_tagvalue handles Bytes;
            // for the no-ValueConv APPL tag the Bytes survive to here. Perl
            // scalar context on raw bytes prints them as-is through
            // `EscapeJSON`, which runs `FixUTF8` (XMP.pm:2943) on the
            // string: valid UTF-8 is preserved; invalid bytes are replaced
            // with `?`. Codex R3 verified bundled ExifTool emits an
            // `AT&TFORM`-style APPL signature `\x80ABC` as `"?ABC"`, NOT
            // as Latin-1 `"\u{0080}ABC"`. Routing through
            // [`crate::convert::fix_utf8`] keeps the byte-exact output.
            let out = match out {
              TagValue::Bytes(b) => TagValue::Str(crate::convert::fix_utf8(&b).into()),
              other => other,
            };
            ctx.metadata().push(
              Group::new(AIFF_MAIN.group0(), def.group1()),
              def.name(),
              out,
            );
          }
        }
        pos = pos.saturating_add(len2); // AIFF.pm:268 `$pos += $len2`.
                                        // AIFF.pm:269 `$n = 0;` (inside the body, before the for-step),
                                        // then the for's `++$n` at top of next iter:
        n = 0;
        n = n.saturating_add(1);
      } else if len == 0 {
        // AIFF.pm:220,258-261. Perl `for ($n=0;;++$n)` increments `$n` at the
        // END of every iteration; the empty-chunk branch ALSO does
        // `next if ++$n < 100` (AIFF.pm:259), so when the body's `++$n` is
        // STILL `< 100` the loop `next`s — that ALSO runs the for-step
        // `++$n`. Net: `$n` bumps by 2 per consecutive empty chunk on the
        // success path. The abort fires when the body's `++$n` produces
        // `$n >= 100`. Starting from `$n=0`: iter 1 body→1 next ++→2, iter 2
        // 2→3 ++→4, ..., iter 51 body sees $n=100, ++→101, `101<100` false
        // ⇒ Warn + last. So abort at the **51st** consecutive empty chunk
        // from start-of-file, and at the **50th** from a known-tag reset
        // (Codex R1: byte-exact matters; the earlier `empty_run >= 51`
        // approximation diverged at the post-known-tag boundary by one).
        n = n.saturating_add(1); // AIFF.pm:259 `++$n`
        if n >= 100 {
          ctx
            .metadata()
            .push_warning("Aborting scan.  Too many empty chunks");
          break;
        }
        n = n.saturating_add(1); // for-step `++$n` after `next`
                                 // No `pos += len2` here (len == 0, len2 == 0) — fall-through to top.
      } else {
        // AIFF.pm:265-267 `else { $raf->Seek($len2, 1) or $err=1, last }`.
        // Unknown chunk with non-zero length: skip its body. Perl's `Seek`
        // past EOF is BENIGN on a regular RAF (it just sets position past
        // EOF; the next iteration's `Read($buff, 8)` returns 0 and the loop
        // exits without setting `$err`). So we advance `pos` saturating; the
        // next iteration's `pos + 8 > data.len()` check exits cleanly with
        // no "Error reading…" warning — matching the bundled `perl exiftool`
        // behavior on `AIFF_huge.aif` (oracle: only the "Skipping large
        // Common chunk" warning, no second "Error reading…" warning).
        pos = pos.saturating_add(len2);
        // AIFF.pm:268-269 `$pos += $len2; $n = 0;` are OUTSIDE the if/elsif/
        // else, INSIDE the for body — so they run for every branch that does
        // NOT `next` or `last`, including this unknown-non-empty (Seek) arm.
        // `$n = 0` then the for-step `++$n` ⇒ `n = 1` next iter (same cadence
        // as the known-tag arm).
        n = 0;
        n = n.saturating_add(1);
      }
    }
    // AIFF.pm:148 `Image::ExifTool::AddCompositeTags('Image::ExifTool::AIFF')`
    // — register the %AIFF::Composite Duration tag. Faithful inline derivation:
    // AIFF.pm:136-145 defines exactly one composite, `Duration`, with
    //   `Require => { 0 => 'AIFF:SampleRate', 1 => 'AIFF:NumSampleFrames' }`
    //   `RawConv => '($val[0] and $val[1]) ? $val[1] / $val[0] : undef'`
    //   `PrintConv => 'ConvertDuration($val)'`
    // No `ValueConv` (so PrintConv runs on the raw quotient). RawConv emits
    // `undef` (no tag) when either input is 0 / undef. We compute this
    // inline against the just-extracted %AIFF::Common tags so the Composite
    // runtime / D11 conversion context aren't required for this single
    // self-contained tag — its RawConv is pure (no $$self{TimeScale} etc.).
    // Codex R4 flagged the prior defer as "no-ship" for ordinary AIFF
    // files; this faithful inline path emits `Composite:Duration` for
    // nonzero SampleRate AND NumSampleFrames, matching bundled Perl
    // byte-exact on `AIFF_duration.aif` (oracle 2026-05-20).
    emit_composite_duration(ctx.metadata(), print_conv_enabled);

    // AIFF.pm:272 `return 1` — we accept the file once SetFileType ran.
    true
  }
}

/// Compute and push the AIFF Composite Duration tag (AIFF.pm:136-145), using
/// the just-extracted `AIFF:SampleRate` (i64 OR f64) and `AIFF:NumSampleFrames`
/// (i64). The values arrive PRE-PrintConv (post-ValueConv); SampleRate's
/// ValueConv is `None` (extended → I64 for integer-valued rates, F64 for
/// non-integer rates — see `tag_as_f64` below), NumSampleFrames's is `None`
/// (int32u → I64).
///
/// AIFF.pm:142 `RawConv => '($val[0] and $val[1]) ? $val[1] / $val[0] :
/// undef'` — Perl's `&&` truth-tests treat 0 as falsy, so when either is 0
/// the result is `undef` and no tag is emitted. Non-zero ⇒ float division.
/// PrintConv via [`crate::datetime::convert_duration`] (`ConvertDuration`,
/// ExifTool.pm:6866).
fn emit_composite_duration(meta: &mut Metadata, print_conv_enabled: bool) {
  // Find the two required tags. The AIFF chunk loop pushes them under
  // family-1 group "AIFF", with names "SampleRate" and "NumSampleFrames".
  // SampleRate is 80-bit extended (AIFF.pm:91), which `get_extended` emits
  // as I64 for integer-valued rates that fit in i64 (the common case:
  // 22050, 44100, 48000), F64 for non-integer rates (e.g. NTSC pull-down
  // 44056.94...), and Str("<decimal>") for exact integers that overflow
  // i64 (e.g. 2^63+1 = 9223372036854775809 — Codex R7 fix). Perl `/` on a
  // string-or-numeric scalar coerces to NV via `atof`/`looks_like_number`,
  // so accept all three TagValue shapes here and convert to f64 (Codex R6
  // + R7 fix: I64-only dropped Duration on the F64 path; I64+F64-only
  // dropped Duration on the new Str-overflow path). NumSampleFrames is
  // int32u (AIFF.pm:89) ⇒ always I64, but accept F64/Str defensively
  // against future Format widening.
  fn tag_as_f64(v: &TagValue) -> Option<f64> {
    match v {
      TagValue::I64(n) => Some(*n as f64),
      TagValue::F64(x) => Some(*x),
      // Perl's NV coercion of a numeric-looking string is `atof`-style:
      // leading optional sign, digits, optional `.fraction`, optional
      // exponent. `f64::from_str` matches that for the integer decimal
      // text `get_extended` produces (e.g. "9223372036854775809" ⇒ f64
      // 9223372036854775808.0 with 53-bit rounding — byte-exact to
      // Perl's `0 + "9223372036854775809"`).
      TagValue::Str(s) => s.parse::<f64>().ok(),
      _ => None,
    }
  }
  let mut sample_rate: Option<f64> = None;
  let mut num_frames: Option<f64> = None;
  for t in meta.tags() {
    if t.group().family1() == "AIFF" {
      match t.name() {
        "SampleRate" => sample_rate = tag_as_f64(t.value()),
        "NumSampleFrames" => num_frames = tag_as_f64(t.value()),
        _ => {}
      }
    }
  }
  // AIFF.pm:142 `($val[0] and $val[1]) ? ... : undef` — Perl truthy on
  // non-zero numerics (0/0.0/undef all fail; NaN is truthy in Perl scalar
  // context). Post-Codex-R9, `get_extended` CAN return NaN for adversarial
  // 80-bit inputs (e.g. `sig == 0 && biased == 0x7FFF` is `0 * Inf = NaN`
  // per IEEE-754; or `sig == 0` with `2^exp` overflowing f64 to Inf at
  // `f64::MAX_EXP = 1024`). In Perl those flow through as truthy NV NaN
  // and the division `NumSampleFrames / NaN = NaN` propagates; the
  // serializer then quotes it via `perl_nonfinite_str` ⇒ `"NaN"`. The
  // conformance fixtures `AIFF_zero_sig_max_exp.aif` /
  // `AIFF_first_overflow_zero_sig.aif` pin that intentional propagation.
  let (Some(sr), Some(nf)) = (sample_rate, num_frames) else {
    return;
  };
  if sr == 0.0 || nf == 0.0 {
    return;
  }
  // RawConv: float division.
  let duration = nf / sr;
  // PrintConv via ConvertDuration. `-n` (print_conv_enabled == false)
  // skips PrintConv and emits the raw float (the F64 routes through
  // `EscapeJSON`'s number gate via the format_g(_,15) stringifier; an
  // integer-valued float like `2.0` prints bare as `2`, matching the
  // bundled Perl oracle).
  let value = if print_conv_enabled {
    TagValue::Str(crate::datetime::convert_duration(duration).into())
  } else {
    TagValue::F64(duration)
  };
  meta.push(Group::new("Composite", "Composite"), "Duration", value);
}

/// Convert a runtime `&str` chunk tag into a `'static` reference that
/// matches the `TagId::Str(&'static str)` arms in [`aiff_main_get`]. The
/// AIFF.pm:31-82 main table only has a fixed set of 4-byte ASCII keys
/// (`FVER`, `COMM`, `COMT`, `NAME`, `AUTH`, `(c) `, `ANNO`, `ID3 `, `APPL`);
/// returning a sentinel `""` for anything else makes the lookup miss
/// cleanly (no panic, no allocation).
fn tag_str_to_static(s: &str) -> &'static str {
  match s {
    "FVER" => "FVER",
    "COMM" => "COMM",
    "COMT" => "COMT",
    "NAME" => "NAME",
    "AUTH" => "AUTH",
    "(c) " => "(c) ",
    "ANNO" => "ANNO",
    "ID3 " => "ID3 ",
    "APPL" => "APPL",
    _ => "",
  }
}

#[cfg(test)]
mod tests {
  use super::*;
  use crate::parser::ParseContext;
  use crate::value::Metadata;

  #[test]
  fn main_table_and_keys_resolve_per_aiff_pm() {
    let g = AIFF_MAIN.get();
    assert_eq!(g(TagId::Str("FVER")).unwrap().name(), "FormatVersion");
    assert_eq!(g(TagId::Str("COMM")).unwrap().name(), "Common");
    assert_eq!(g(TagId::Str("COMT")).unwrap().name(), "Comment");
    assert_eq!(g(TagId::Str("NAME")).unwrap().name(), "Name");
    assert_eq!(g(TagId::Str("AUTH")).unwrap().name(), "Author");
    assert_eq!(g(TagId::Str("(c) ")).unwrap().name(), "Copyright");
    assert_eq!(g(TagId::Str("ANNO")).unwrap().name(), "Annotation");
    assert_eq!(g(TagId::Str("ID3 ")).unwrap().name(), "ID3");
    assert_eq!(g(TagId::Str("APPL")).unwrap().name(), "ApplicationData");
    assert!(g(TagId::Str("XXXX")).is_none());
  }

  #[test]
  fn common_keys_in_ascending_order_match_aiff_pm() {
    // AIFF.pm:88-115: keys 0, 1, 3, 4, 9, 11. ExifTool `sort { $a <=> $b }`.
    assert_eq!(AIFF_COMMON_KEYS, &[0, 1, 3, 4, 9, 11]);
    let g = AIFF_COMMON.get();
    for &k in AIFF_COMMON_KEYS {
      assert!(
        g(TagId::Int(k)).is_some(),
        "AIFF_COMMON_KEYS entry {k} missing"
      );
    }
  }

  #[test]
  fn compression_type_printconv_table_matches_aiff_pm() {
    let def = (AIFF_COMMON.get())(TagId::Int(9)).unwrap();
    assert_eq!(def.name(), "CompressionType");
    let h = match def.print_conv() {
      PrintConv::Hash(h) => h,
      _ => panic!("expected Hash print_conv"),
    };
    let entries = h.direct_entries();
    assert_eq!(entries.len(), 14);
    assert_eq!(entries[0], ("NONE", PrintValue::Str("None")));
    assert_eq!(
      entries[5],
      ("sowt", PrintValue::Str("Little-endian, no compression"))
    );
    // Note the trailing space in 'GSM '.
    assert_eq!(entries[10], ("GSM ", PrintValue::Str("GSM")));
  }

  #[test]
  fn rejects_non_form_data() {
    let mut m = Metadata::new("x");
    let mut c = ParseContext::new(b"NOFORMxxxAIFF", "AIFF", 0, "AIFF", None, true, &mut m);
    assert!(!ProcessAiff.process(&mut c));
    // Reject before SetFileType ⇒ no File:* pushed.
    assert!(m.tags().is_empty());
  }

  #[test]
  fn rejects_short_data() {
    let mut m = Metadata::new("x");
    let mut c = ParseContext::new(b"FORM\x00\x00", "AIFF", 0, "AIFF", None, true, &mut m);
    assert!(!ProcessAiff.process(&mut c));
    assert!(m.tags().is_empty());
  }

  #[test]
  fn djvu_signature_sets_file_type_and_accepts_with_no_body_tags() {
    // AIFF.pm:194-207 DjVu arm: `AT&TFORM` + (`DJVU`|`DJVM`) at bytes 12..16.
    // Faithful: SetFileType('DJVU') and accept; DjVu sub-table dispatch is
    // Stage-2 deferred (see module doc), so NO DjVu-body tags are pushed.
    let mut m = Metadata::new("x.djvu");
    let mut c = ParseContext::new(b"AT&TFORMxxxxDJVU", "AIFF", 0, "AIFF", None, true, &mut m);
    assert!(ProcessAiff.process(&mut c));
    let ft = m.tags().iter().find(|t| t.name() == "FileType").unwrap();
    assert_eq!(ft.value(), &TagValue::Str("DJVU".into()));
    // No AIFF body tags emitted (chunk loop is skipped per the DjVu arm).
    let body_names: Vec<&str> = m
      .tags()
      .iter()
      .map(|t| t.name())
      .filter(|n| {
        !matches!(
          *n,
          "ExifToolVersion" | "FileType" | "FileTypeExtension" | "MIMEType"
        )
      })
      .collect();
    assert!(
      body_names.is_empty(),
      "no body tags allowed: {body_names:?}"
    );
  }

  #[test]
  fn at_t_form_without_djvu_djvm_rejects() {
    // AIFF.pm:199 `return 0 unless ... $buf2 =~ /^(DJVU|DJVM)/`. A bare
    // `AT&TFORM` followed by anything other than DJVU/DJVM MUST reject.
    let mut m = Metadata::new("x");
    let mut c = ParseContext::new(b"AT&TFORMxxxxFOOO", "AIFF", 0, "AIFF", None, true, &mut m);
    assert!(!ProcessAiff.process(&mut c));
    assert!(m.tags().is_empty());
  }

  #[test]
  fn djvm_signature_appends_multi_page_suffix_to_file_type() {
    // AIFF.pm:199 regex matches both `DJVU` and `DJVM`. AIFF.pm:206
    // appends `' (multi-page)'` to `$$et{VALUE}{FileType}` when the tail
    // is `DJVM` (multi-page DjVu container). Bundled-Perl oracle
    // (2026-05-20) on `AT&TFORMxxxxDJVM` ⇒ `File:FileType="DJVU
    // (multi-page)"`. The FileTypeExtension/MIMEType are NOT modified
    // (AIFF.pm:206 is `.=` on FileType only).
    let mut m = Metadata::new("x.djvu");
    let mut c = ParseContext::new(b"AT&TFORMxxxxDJVM", "AIFF", 0, "AIFF", None, true, &mut m);
    assert!(ProcessAiff.process(&mut c));
    let ft = m.tags().iter().find(|t| t.name() == "FileType").unwrap();
    assert_eq!(ft.value(), &TagValue::Str("DJVU (multi-page)".into()));
    // FileTypeExtension is from %fileTypeExt{DJVU} ('djvu') — unchanged.
    let fte = m
      .tags()
      .iter()
      .find(|t| t.name() == "FileTypeExtension")
      .unwrap();
    // Default PrintConv (`lc`) makes the displayed value lowercase.
    assert_eq!(fte.value(), &TagValue::Str("djvu".into()));
    // MIMEType from %mimeType{DJVU} = "image/vnd.djvu", also unchanged.
    let mime = m.tags().iter().find(|t| t.name() == "MIMEType").unwrap();
    assert_eq!(mime.value(), &TagValue::Str("image/vnd.djvu".into()));
  }

  #[test]
  fn aiff_minimal_header_accepts_and_sets_file_type() {
    // 12-byte header: FORM + 4-byte length + "AIFF" magic, no chunks.
    let mut m = Metadata::new("x.aif");
    let data = b"FORM\x00\x00\x00\x04AIFF";
    let mut c = ParseContext::new(data, "AIFF", 0, "AIFF", None, true, &mut m);
    assert!(ProcessAiff.process(&mut c));
    let ft = m.tags().iter().find(|t| t.name() == "FileType").unwrap();
    assert_eq!(ft.value(), &TagValue::Str("AIFF".into()));
  }

  #[test]
  fn aifc_magic_sets_file_type_aifc() {
    let mut m = Metadata::new("x.aifc");
    let data = b"FORM\x00\x00\x00\x04AIFC";
    let mut c = ParseContext::new(data, "AIFF", 0, "AIFF", None, true, &mut m);
    assert!(ProcessAiff.process(&mut c));
    let ft = m.tags().iter().find(|t| t.name() == "FileType").unwrap();
    assert_eq!(ft.value(), &TagValue::Str("AIFC".into()));
  }

  #[test]
  fn process_comment_handles_truncated_input() {
    // numComments=2 but only one fits — second iteration `last`s.
    let mut m = Metadata::new("x");
    let mut data: Vec<u8> = Vec::new();
    data.extend_from_slice(&2u16.to_be_bytes()); // numComments
    data.extend_from_slice(&0u32.to_be_bytes()); // time
    data.extend_from_slice(&0u16.to_be_bytes()); // markerID = 0 ⇒ skip MarkerID tag
    data.extend_from_slice(&4u16.to_be_bytes()); // size
    data.extend_from_slice(b"abcd"); // text
                                     // Second comment header truncated: data ends after first.
    process_comment(&data, &mut m, false);
    assert_eq!(m.tags().len(), 2); // CommentTime + Comment text (no MarkerID b/c 0)
    assert_eq!(m.tags()[0].name(), "CommentTime");
    assert_eq!(m.tags()[1].name(), "Comment");
  }

  #[test]
  fn strip_trailing_nuls_handles_edges() {
    assert_eq!(strip_trailing_nuls(b""), b"");
    assert_eq!(strip_trailing_nuls(b"abc"), b"abc");
    assert_eq!(strip_trailing_nuls(b"abc\0"), b"abc");
    assert_eq!(strip_trailing_nuls(b"abc\0\0\0"), b"abc");
    assert_eq!(strip_trailing_nuls(b"\0\0"), b"");
  }

  /// Synthesize an AIFF stream with `n_empty` zero-length unknown chunks
  /// (each `<TAG><0u32>` = 8 bytes, where `<TAG>` is an unknown 4-byte ID).
  fn aiff_with_n_empty_chunks(n_empty: usize) -> Vec<u8> {
    let mut v: Vec<u8> = Vec::new();
    v.extend_from_slice(b"FORM\x00\x00\x00\x04AIFF"); // 12-byte header
    for _ in 0..n_empty {
      v.extend_from_slice(b"XXXX\x00\x00\x00\x00"); // unknown tag, len=0
    }
    v
  }

  #[test]
  fn empty_chunk_streak_below_threshold_does_not_abort() {
    // Perl `for ($n=0;;++$n)` with empty-arm `next if ++$n < 100`: from
    // start-of-file (`$n=0`), iter k's body sees `$n = 2(k-1)`, body++
    // to `2k-1`. The first iter where `2k-1 >= 100` is k=51 (body++→101).
    // So 50 empty chunks should NOT abort.
    let mut m = Metadata::new("x.aif");
    let data = aiff_with_n_empty_chunks(50);
    let mut c = ParseContext::new(&data, "AIFF", 0, "AIFF", None, true, &mut m);
    assert!(ProcessAiff.process(&mut c));
    // No "Aborting scan" warning; just the parser-driven File:* tags.
    assert!(
      !m.warnings().iter().any(|w| w.contains("Aborting scan")),
      "warnings: {:?}",
      m.warnings()
    );
  }

  #[test]
  fn empty_chunk_streak_at_threshold_aborts_at_perl_iter_51() {
    // 51 consecutive empty chunks from $n=0 ⇒ iter 51 body sees `$n=100`,
    // body++→101, `101<100` false ⇒ Warn + last (AIFF.pm:259-261).
    let mut m = Metadata::new("x.aif");
    let data = aiff_with_n_empty_chunks(60); // more than enough
    let mut c = ParseContext::new(&data, "AIFF", 0, "AIFF", None, true, &mut m);
    assert!(ProcessAiff.process(&mut c));
    assert!(
      m.warnings()
        .iter()
        .any(|w| w == "Aborting scan.  Too many empty chunks"),
      "expected the abort warning; got: {:?}",
      m.warnings()
    );
  }

  #[test]
  fn id3_chunk_recognized_then_silently_skipped() {
    // Codex R1/R4: `ID3 ` chunk is recognized by %AIFF::Main but its body
    // is deferred to the parallel ID3 PR — silently skipped (no Warning,
    // no tags). Pin THIS behavior so when ID3 lands as a dispatchable
    // sub-table the regression is caught. User-mandated defer:
    // `[[exifast]] DEFER: ID3-in-AIFF (parallel ID3 PR will integrate;
    // emit faithful Warn or skip)` — we chose `skip` here because real
    // Perl AIFF.pm dispatches to ProcessID3 (no Warning); adding one
    // would diverge.
    //
    // The fixture: FORM AIFF + `ID3 ` chunk with a tiny body, no other
    // chunks. After this PR's behavior is enshrined the only tags should
    // be the File:* triplet (driven by SetFileType) and no AIFF:* /
    // Composite:* / ExifTool:Warning tags.
    let mut m = Metadata::new("x.aif");
    let mut data: Vec<u8> = Vec::new();
    data.extend_from_slice(b"FORM");
    let body_inner = b"ID3 \x00\x00\x00\x04ID3v"; // 4-byte ID3 magic + 4 bytes
    let total = 4 + body_inner.len();
    data.extend_from_slice(&(total as u32).to_be_bytes());
    data.extend_from_slice(b"AIFF");
    data.extend_from_slice(body_inner);
    let mut c = ParseContext::new(&data, "AIFF", 0, "AIFF", None, true, &mut m);
    assert!(ProcessAiff.process(&mut c));
    // File:* tags present from SetFileType.
    assert!(m.tags().iter().any(|t| t.name() == "FileType"));
    // No AIFF body tags (ID3 body dropped) and no warnings.
    assert!(
      m.tags().iter().all(|t| t.group().family1() != "AIFF"),
      "no AIFF:* tags expected from silent ID3 skip, got: {:?}",
      m.tags()
        .iter()
        .map(|t| format!("{}:{}", t.group().family1(), t.name()))
        .collect::<Vec<_>>()
    );
    assert!(m.warnings().is_empty(), "warnings: {:?}", m.warnings());
  }

  #[test]
  fn composite_duration_emitted_when_both_inputs_nonzero() {
    // AIFF.pm:136-145: `Duration` Composite. Inline implementation in
    // [`emit_composite_duration`] (post-chunk-loop). RawConv = nf/sr,
    // PrintConv via `convert_duration` (`ConvertDuration`,
    // ExifTool.pm:6866). Synthetic: SR=22050, NF=44100 ⇒ 2.0s.
    let mut m = Metadata::new("x.aif");
    let mut data: Vec<u8> = Vec::new();
    data.extend_from_slice(b"FORM");
    // COMM with SampleRate=22050, NumSampleFrames=44100.
    // COMM body: NumCh(u16=1) + NumSF(u32=44100) + SampleSize(u16=8) +
    // SampleRate(extended 10 bytes, 22050 = 0x400D AC44 ...) = 18 bytes.
    let mut comm_body: Vec<u8> = Vec::new();
    comm_body.extend_from_slice(&1u16.to_be_bytes()); // NumCh
    comm_body.extend_from_slice(&44100u32.to_be_bytes()); // NumSampleFrames
    comm_body.extend_from_slice(&8u16.to_be_bytes()); // SampleSize
    comm_body.extend_from_slice(&0x400D_u16.to_be_bytes()); // extended exp
    comm_body.extend_from_slice(&0xAC44_0000_0000_0000_u64.to_be_bytes()); // sig
    let mut comm_chunk: Vec<u8> = Vec::new();
    comm_chunk.extend_from_slice(b"COMM");
    comm_chunk.extend_from_slice(&(comm_body.len() as u32).to_be_bytes());
    comm_chunk.extend_from_slice(&comm_body);
    let body = [b"AIFF".as_slice(), &comm_chunk].concat();
    data.extend_from_slice(&(body.len() as u32).to_be_bytes());
    data.extend_from_slice(&body);
    let mut c = ParseContext::new(&data, "AIFF", 0, "AIFF", None, true, &mut m);
    assert!(ProcessAiff.process(&mut c));
    let dur = m
      .tags()
      .iter()
      .find(|t| t.name() == "Duration" && t.group().family1() == "Composite")
      .expect("Composite:Duration emitted");
    assert_eq!(dur.value(), &TagValue::Str("2.00 s".into()));
  }

  #[test]
  fn composite_duration_skipped_when_sample_rate_zero() {
    // AIFF.pm:142 RawConv `($val[0] and $val[1]) ? ... : undef`. A zero
    // SampleRate ⇒ no Duration tag emitted. The committed `AIFF.aif`
    // fixture exercises this (SampleRate=0).
    let mut m = Metadata::new("x.aif");
    // Reuse the standard AIFF.aif fixture's COMM body (SR=0).
    let data = std::fs::read(format!(
      "{}/tests/fixtures/AIFF.aif",
      env!("CARGO_MANIFEST_DIR")
    ))
    .expect("read AIFF.aif fixture");
    let mut c = ParseContext::new(&data, "AIFF", 0, "AIFF", None, true, &mut m);
    assert!(ProcessAiff.process(&mut c));
    assert!(
      m.tags()
        .iter()
        .all(|t| !(t.name() == "Duration" && t.group().family1() == "Composite")),
      "Composite:Duration must NOT be emitted when SampleRate=0: {:?}",
      m.tags()
        .iter()
        .map(|t| format!("{}:{}", t.group().family1(), t.name()))
        .collect::<Vec<_>>()
    );
  }
}
