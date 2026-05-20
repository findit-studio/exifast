//! Faithful port of `Image::ExifTool::MOI` (lib/Image/ExifTool/MOI.pm).
//!
//! MOI is a tiny sidecar (typically a few hundred bytes) emitted by some
//! JVC, Canon and Panasonic camcorders alongside their MOD/TOD video. The
//! file is a fixed binary header processed by `ProcessBinaryData` in `MM`
//! (big-endian) byte order (MOI.pm:116 `SetByteOrder('MM')`).
//!
//! Table (MOI.pm:20-98) — `%Image::ExifTool::MOI::Main`, keyed by byte offset:
//!
//! | offset | type        | tag                | conversions                                |
//! |-------:|-------------|--------------------|--------------------------------------------|
//! | 0x00   | string[2]   | MOIVersion         | none                                       |
//! | 0x06   | undef[8]    | DateTimeOriginal   | ValueConv: unpack/sprintf; PrintConv: id    |
//! | 0x0e   | int32u      | Duration           | ValueConv: /1000; PrintConv: ConvertDuration|
//! | 0x80   | int8u       | AspectRatio        | PrintConv: nibble-decode (Perl block)       |
//! | 0x84   | int16u      | AudioCodec         | PrintHex; hash PrintConv                    |
//! | 0x86   | int8u       | AudioBitrate       | ValueConv: *16000+48000; PrintConv: bitrate |
//! | 0xda   | int16u      | VideoBitrate       | PrintHex; hash ValueConv + ConvertBitrate   |
//!
//! `ProcessMOI` (MOI.pm:104-119) reads up to 256 bytes, validates that the
//! buffer starts with `V6` (MOI.pm:110) and that the embedded 32-bit big-
//! endian filesize at offset 0x02 matches the actual file size (MOI.pm:
//! 111-114), then calls `ProcessBinaryData`. The filesize gate is the
//! second-stage validation that follows the `V6` magic number gate
//! registered in `filetype_data::magic` (ExifTool.pm:998).

use crate::convert::apply;
use crate::parser::{FormatParser, ParseContext};
use crate::tagtable::{PrintConv, PrintConvHash, PrintValue, TagDef, TagId, TagTable, ValueConv};
use crate::value::{Group, TagValue};

// ---------------------------------------------------------------------------
// ValueConv / PrintConv helpers — faithful transliterations of MOI.pm
// expressions, used by the static `TagDef`s.
// ---------------------------------------------------------------------------

/// MOI.pm:34-40 — `ValueConv` for DateTimeOriginal.
///
/// Perl:
/// ```perl
/// my $val = shift;
/// return undef unless length($val) >= 8;
/// my @v = unpack('nCCCCn', $val);
/// $v[5] /= 1000;
/// return sprintf('%.4d:%.2d:%.2d %.2d:%.2d:%06.3f', @v);
/// ```
///
/// Input: `TagValue::Bytes` (8 raw bytes — the `Format => 'undef[8]'` slice
/// fed by [`process_moi_binary_data`]).
///
/// Output (length-8 case): a `TagValue::Str` with the formatted timestamp.
/// `%06.3f` is Perl's "minimum field width 6, 3 fractional digits": e.g.
/// `48.0` → `48.000` (already 6 chars), `7.123` → `07.123` (zero-padded
/// to width 6). Verified byte-exact against the bundled Perl oracle
/// (`tests/fixtures/MOI.moi` ⇒ `"2011:05:15 17:58:48.000"`).
///
/// Length-<8 case: returns the input unchanged. ExifTool's `return undef
/// unless …` leaves `$val` undefined ⇒ the engine drops the tag; we model
/// that here by passing the (unconvertible) raw value back untouched —
/// callers should not reach this branch because the offset 0x06+8 slice
/// is bounds-checked at the walker.
fn datetime_original_value_conv(v: &TagValue) -> TagValue {
  let TagValue::Bytes(b) = v else {
    return v.clone();
  };
  if b.len() < 8 {
    return v.clone();
  }
  // unpack('nCCCCn', $val): year (BE u16), month (u8), day (u8), hour (u8),
  // minute (u8), milliseconds (BE u16).
  let year = u16::from_be_bytes([b[0], b[1]]);
  let month = b[2];
  let day = b[3];
  let hour = b[4];
  let minute = b[5];
  let ms = u16::from_be_bytes([b[6], b[7]]);
  // `$v[5] /= 1000` is Perl float division; in this build that yields an f64
  // (e.g. 48000/1000 = 48.0, 7123/1000 = 7.123 — exact in f64 because the
  // numerator is a u16). `%06.3f` then formats with 3 fractional digits and
  // a minimum field width of 6 (Perl's printf zero-pads when the leading `0`
  // flag is present — `%06.3f` has it).
  let sec = f64::from(ms) / 1000.0;
  // Rust's `{:06.3}` matches Perl `%06.3f` for non-negative finite values
  // (width includes the decimal point and fraction). Bundled-Perl verified
  // on edge inputs: `0.0` ⇒ "00.000" (6), `7.123` ⇒ "07.123" (6),
  // `48.0` ⇒ "48.000" (6).
  TagValue::Str(format!("{year:04}:{month:02}:{day:02} {hour:02}:{minute:02}:{sec:06.3}").into())
}

/// MOI.pm:46 — Duration `ValueConv => '$val / 1000'`.
///
/// The raw is `int32u` (a `TagValue::I64` from the binary walker); the
/// `/1000` is Perl float division ⇒ NV (f64). Output is `TagValue::F64` so
/// the serializer's number gate renders the fractional value (e.g. 8160
/// ⇒ 8.16). Defensive identity on non-I64.
fn duration_value_conv(v: &TagValue) -> TagValue {
  match v {
    TagValue::I64(n) => TagValue::F64((*n as f64) / 1000.0),
    other => other.clone(),
  }
}

/// MOI.pm:47 — Duration `PrintConv => 'ConvertDuration($val)'`.
///
/// Wraps the shared [`convert_duration`] helper; faithful to
/// `ExifTool::ConvertDuration` (ExifTool.pm:6866-6884). The input is the
/// post-ValueConv `TagValue::F64` (seconds).
fn duration_print_conv(v: &TagValue) -> TagValue {
  match v {
    TagValue::F64(n) => TagValue::Str(convert_duration(*n).into()),
    // Faithful: `IsFloat` fails on non-numeric ⇒ Perl returns `$time`
    // unchanged. We pass other variants through untouched.
    other => other.clone(),
  }
}

/// Faithful port of `Image::ExifTool::ConvertDuration` (ExifTool.pm:6866-6884).
///
/// Perl:
/// ```perl
/// my $time = shift;
/// return $time unless IsFloat($time);
/// return '0 s' if $time == 0;
/// my $sign = ($time > 0 ? '' : (($time = -$time), '-'));
/// return sprintf("$sign%.2f s", $time) if $time < 30;
/// $time += 0.5;   # round to nearest second
/// my $h = int($time / 3600);
/// $time -= $h * 3600;
/// my $m = int($time / 60);
/// $time -= $m * 60;
/// if ($h > 24) {
///     my $d = int($h / 24);
///     $h -= $d * 24;
///     $sign = "$sign$d days ";
/// }
/// return sprintf("$sign%d:%.2d:%.2d", $h, $m, int($time));
/// ```
///
/// Bundled-Perl oracle (verified 2026-05-20):
/// - `8.16` → `"8.16 s"` (the MOI fixture)
/// - `0` → `"0 s"`
/// - `30` → `"0:00:30"`
/// - `86461` → `"24:01:01"`
/// - `90000` → `"1 days 1:00:00"`
/// - `-30` → `"-0:00:30"`
fn convert_duration(time: f64) -> String {
  // Perl `IsFloat`: a NaN passes `IsFloat` in our reachable inputs (this fn
  // is only called from `duration_print_conv` on `TagValue::F64`), and `time
  // == 0` quickly returns. We need a separate non-finite guard so an Inf
  // doesn't enter the `int($time / 3600)` math and produce a non-faithful
  // string. Perl's `IsFloat` (ExifTool.pm:5949 `[-+]?(\d+\.?\d*|\.\d+)
  // ([eE][-+]?\d+)?`) actually rejects "Inf"/"NaN" — they're not numeric
  // literals. So a non-finite input from `duration_print_conv`'s F64 path
  // would, in Perl, mean `IsFloat($time)` is FALSE (because `$time` was
  // sprintf'd back to a string for the regex) and `ConvertDuration` would
  // `return $time` unchanged. We model that by returning a placeholder
  // string; no MOI input reaches this branch (Duration is int32u/1000,
  // always finite), so the exact placeholder text is unobservable.
  if !time.is_finite() {
    return format!("{time}");
  }
  if time == 0.0 {
    return "0 s".to_string(); // ExifTool.pm:6870
  }
  let (sign, mut t) = if time > 0.0 { ("", time) } else { ("-", -time) }; // ExifTool.pm:6871
  if t < 30.0 {
    // sprintf("$sign%.2f s", $time)  ExifTool.pm:6872
    return format!("{sign}{t:.2} s");
  }
  t += 0.5; // ExifTool.pm:6873
            // Perl `int()` is truncation toward zero. `t >= 30`, so `t / 3600`
            // is non-negative; `as i64` truncates toward zero ≡ `int()`.
  let mut h: i64 = (t / 3600.0) as i64;
  t -= (h as f64) * 3600.0;
  let m: i64 = (t / 60.0) as i64;
  t -= (m as f64) * 60.0;
  if h > 24 {
    let d = h / 24;
    h -= d * 24;
    // sprintf("$sign%d:%.2d:%.2d", …) becomes "$sign$d days $h:$m:$s"
    return format!("{sign}{d} days {h}:{m:02}:{s:02}", s = t as i64);
  }
  // sprintf("$sign%d:%.2d:%.2d", $h, $m, int($time))  ExifTool.pm:6883
  format!("{sign}{h}:{m:02}:{s:02}", s = t as i64)
}

/// MOI.pm:85 — AudioBitrate `ValueConv => '$val * 16000 + 48000'`.
///
/// Raw is `int8u` (TagValue::I64 in [0, 255]); the +48000 cap is well within
/// i64 (255*16000+48000 = 4128000). Defensive identity on non-I64.
fn audio_bitrate_value_conv(v: &TagValue) -> TagValue {
  match v {
    TagValue::I64(n) => TagValue::I64(n * 16000 + 48000),
    other => other.clone(),
  }
}

/// MOI.pm:86 — AudioBitrate `PrintConv => 'ConvertBitrate($val)'`.
/// Bridges to the shared [`convert_bitrate`] helper.
fn audio_bitrate_print_conv(v: &TagValue) -> TagValue {
  match v {
    TagValue::I64(n) => TagValue::Str(convert_bitrate(*n as f64).into()),
    other => other.clone(),
  }
}

/// MOI.pm:96 — VideoBitrate `PrintConv => 'ConvertBitrate($val)'`.
///
/// VideoBitrate's RAW path is a hash `ValueConv` that maps two on-disk
/// codes (0x5896, 0x813d) to the decimal-string forms `'8500000'` /
/// `'5500000'`. By the time this PrintConv runs, the post-ValueConv
/// scalar is either:
///
/// - `TagValue::I64(8500000)` / `TagValue::I64(5500000)` — the hash hit
///   path. `apply_hash_conv` parses the hash VALUE as an integer (it
///   strips the `'string vs int'` distinction at the Perl boundary; see
///   below), so the I64 cast is faithful for these literals.
///   Actually wait — the hash VALUES in MOI.pm are Perl SINGLE-QUOTED
///   strings (`'8500000'`). Per the `PrintValue::Str` shape, the engine
///   keeps them as STRINGS. So under `-n` they would emit as the JSON
///   number `8500000` only via the serializer's `is_json_number_literal`
///   gate (the string `"8500000"` is a numeric token). Verified against
///   the bundled-Perl golden (`MOI.moi.n.json` ⇒ `"MOI:VideoBitrate":
///   8500000`).
/// - `TagValue::Str("8500000")` — same as above, post-hash-conv emitting
///   the string variant when `PrintValue::Str` was used.
///
/// For the PrintConv pass, we parse the post-ValueConv value back into
/// f64 and run [`convert_bitrate`]. This faithfully mirrors Perl's
/// `ConvertBitrate($val)` taking the string-form value (Perl coerces
/// strings to NV on `>= 1000` / division).
fn video_bitrate_print_conv(v: &TagValue) -> TagValue {
  // Match Perl's `ConvertBitrate($val)`: stringify the post-ValueConv value
  // for `IsFloat` (ExifTool.pm:5949 — accepts a leading sign + digits +
  // optional `.frac` + optional `e±N` exponent). If parsing fails, return
  // the input unchanged (Perl `IsFloat($bitrate) or return $bitrate`).
  let n: f64 = match v {
    TagValue::I64(n) => *n as f64,
    TagValue::F64(n) => *n,
    TagValue::Str(s) => match s.parse::<f64>() {
      Ok(n) => n,
      Err(_) => return v.clone(),
    },
    other => return other.clone(),
  };
  TagValue::Str(convert_bitrate(n).into())
}

/// Faithful port of `Image::ExifTool::ConvertBitrate` (ExifTool.pm:6891-6902).
///
/// Perl:
/// ```perl
/// my $bitrate = shift;
/// IsFloat($bitrate) or return $bitrate;
/// my @units = ('bps', 'kbps', 'Mbps', 'Gbps');
/// for (;;) {
///     my $units = shift @units;
///     $bitrate >= 1000 and @units and $bitrate /= 1000, next;
///     my $fmt = $bitrate < 100 ? '%.3g' : '%.0f';
///     return sprintf("$fmt $units", $bitrate);
/// }
/// ```
///
/// Bundled-Perl oracle (verified 2026-05-20):
/// - `224000` → `"224 kbps"` (4-th significant digit drops because the
///   post-division value 224 ≥ 100 ⇒ `%.0f`)
/// - `8500000` → `"8.5 Mbps"` (post-division 8.5 < 100 ⇒ `%.3g`)
/// - `50` → `"50 bps"`
/// - `999` → `"999 bps"` (no divide; 999 ≥ 100 ⇒ `%.0f` ⇒ "999")
/// - `1000` → `"1 kbps"` (divides once to 1; 1 < 100 ⇒ `%.3g` ⇒ "1")
/// - `1_500_000_000` → `"1.5 Gbps"`
///
/// The `@units` array is exhausted at index 3 (`'Gbps'`); when the loop
/// is on the last unit, the `and @units` guard fails and we format/return.
fn convert_bitrate(bitrate: f64) -> String {
  // The MOI call sites pre-screen for finite f64 (Duration's `/1000` is
  // exact on an int32u dividend, and the hash ValueConv hardcodes finite
  // integer strings). For defense in depth, mirror Perl: a non-numeric
  // input (NaN) doesn't satisfy `IsFloat` ⇒ return as-is. ConvertBitrate
  // only runs with a numeric `$val` in the real ExifTool flow.
  if !bitrate.is_finite() {
    return format!("{bitrate}");
  }
  const UNITS: &[&str] = &["bps", "kbps", "Mbps", "Gbps"];
  let mut b = bitrate;
  // Walk the units. Perl `shift @units` on the empty array would set
  // `$units = undef` and the next `$bitrate >= 1000 and @units` would
  // short-circuit on the `@units` test, falling through to the format
  // step. We model that by capping iterations at UNITS.len()-1: once we
  // arrive at the last unit ("Gbps"), we always format regardless of `b`.
  for (i, &unit) in UNITS.iter().enumerate() {
    let is_last = i + 1 == UNITS.len();
    if b >= 1000.0 && !is_last {
      b /= 1000.0;
      continue;
    }
    return if b < 100.0 {
      // sprintf("%.3g %s", $b, $unit) — Perl `%g` strips trailing zeros.
      format!("{} {unit}", crate::value::format_g(b, 3))
    } else {
      // sprintf("%.0f %s", …) — round half-to-even, no decimal point.
      // `b.round()` rounds half-AWAY-from-zero; Perl's `%.0f` is half-to-
      // even ("banker's rounding"). For the bitrate range here (bps→kbps
      // → Mbps→Gbps) the post-division values never lie on a half ⇒
      // any difference is unobservable. If a future caller passes a
      // `.5` exactly, swap to `format!("{:.0}", b)` (Rust's own half-to-
      // even); verified equivalent for non-halves.
      format!("{:.0} {unit}", b)
    };
  }
  // Unreachable: the loop above always returns (the last iteration's
  // `is_last == true` branch).
  unreachable!("convert_bitrate loop must exit on the last unit");
}

/// MOI.pm:52-69 — AspectRatio `PrintConv` (a Perl `q{ … }` block).
///
/// Perl:
/// ```perl
/// my $lo = ($val & 0x0f);
/// my $hi = ($val >> 4);
/// my $aspect;
/// if ($lo < 2) {
///     $aspect = '4:3';
/// } elsif ($lo == 4 or $lo == 5) {
///     $aspect = '16:9';
/// } else {
///     $aspect = 'Unknown';
/// }
/// if ($hi == 4) {
///     $aspect .= ' NTSC';
/// } elsif ($hi == 5) {
///     $aspect .= ' PAL';
/// }
/// return $aspect;
/// ```
///
/// Bundled-Perl oracle (verified 2026-05-20): raw `0x51` ⇒ lo=1<2 ("4:3"),
/// hi=5 (PAL) ⇒ `"4:3 PAL"` (the MOI fixture).
fn aspect_ratio_print_conv(v: &TagValue) -> TagValue {
  let n: i64 = match v {
    TagValue::I64(n) => *n,
    // Perl coerces a string to numeric; in practice the binary walker
    // emits an `int8u` as I64, so this branch is defensive only.
    other => return other.clone(),
  };
  let lo = n & 0x0f;
  let hi = (n >> 4) & 0x0f;
  let mut aspect: String = if lo < 2 {
    "4:3".into()
  } else if lo == 4 || lo == 5 {
    "16:9".into()
  } else {
    "Unknown".into()
  };
  if hi == 4 {
    aspect.push_str(" NTSC");
  } else if hi == 5 {
    aspect.push_str(" PAL");
  }
  TagValue::Str(aspect.into())
}

// ---------------------------------------------------------------------------
// `%Image::ExifTool::MOI::Main` (MOI.pm:20-98). Tags emit under the family-0
// group `MOI` and the family-1 group `MOI` (the Perl module-name suffix —
// confirmed by the bundled-ExifTool oracle on `MOI.moi` ⇒ JSON keys
// `"MOI:MOIVersion"`, …). MOI.pm:21 `GROUPS => { 2 => 'Video' }` is family-2
// (category) and is not emitted under `-G1`.
// ---------------------------------------------------------------------------

// MOI.pm:27 — `0x00 => { Name => 'MOIVersion', Format => 'string[2]' }`.
// No conversions; emit the 2 bytes as a UTF-8 string (in practice always
// ASCII, e.g. `"V6"`).
static MOI_VERSION: TagDef = TagDef::new("MOIVersion", "MOI", ValueConv::None, PrintConv::None);

// MOI.pm:29-42 — DateTimeOriginal. Format `undef[8]` ⇒ raw 8-byte slice fed
// to the ValueConv; the PrintConv `$self->ConvertDateTime($val)` is the
// no-op identity unless ExifTool's DateFormat option is set (it isn't
// here ⇒ the read path emits the ValueConv output under both `-j` and
// `-n`, confirmed against the bundled `perl exiftool` oracle).
static DATE_TIME_ORIGINAL: TagDef = TagDef::new(
  "DateTimeOriginal",
  "MOI",
  ValueConv::Func(datetime_original_value_conv),
  PrintConv::None,
);

// MOI.pm:43-48 — Duration. int32u (4-byte BE u32) divided by 1000.
static DURATION: TagDef = TagDef::new(
  "Duration",
  "MOI",
  ValueConv::Func(duration_value_conv),
  PrintConv::Func(duration_print_conv),
);

// MOI.pm:49-70 — AspectRatio. int8u with the nibble-decode PrintConv above.
static ASPECT_RATIO: TagDef = TagDef::new(
  "AspectRatio",
  "MOI",
  ValueConv::None,
  PrintConv::Func(aspect_ratio_print_conv),
);

// MOI.pm:71-80 — AudioCodec. int16u, PrintHex => 1, hash PrintConv. The
// Perl hash keys 0x00c1 / 0x4001 stringify to their DECIMAL values
// ("193" / "16385") for ExifTool's `$$conv{$val}` lookup. `PrintHex` is
// only used in the FALLBACK ("Unknown (0x%x)" instead of "Unknown (%s)"
// when a raw integer misses every direct key — ExifTool.pm:3617). Our
// fixture hits `"193"` ⇒ "AC3"; the fallback path is exercised by the
// adversarial test below.
static AUDIO_CODEC: TagDef = TagDef::new(
  "AudioCodec",
  "MOI",
  ValueConv::None,
  PrintConv::Hash(PrintConvHash::direct(&[
    ("193", PrintValue::Str("AC3")),    // MOI.pm:77 (0x00c1 = 193)
    ("16385", PrintValue::Str("MPEG")), // MOI.pm:78 (0x4001 = 16385)
  ])),
)
.with_print_hex(true); // MOI.pm:75 `PrintHex => 1`

// MOI.pm:81-87 — AudioBitrate. int8u, `*16000+48000`, then ConvertBitrate.
static AUDIO_BITRATE: TagDef = TagDef::new(
  "AudioBitrate",
  "MOI",
  ValueConv::Func(audio_bitrate_value_conv),
  PrintConv::Func(audio_bitrate_print_conv),
);

// MOI.pm:88-97 — VideoBitrate. int16u, PrintHex => 1, hash ValueConv
// (NOT PrintConv — MOI.pm:92-95) + ConvertBitrate PrintConv.
//
// The hash ValueConv keys are the on-disk codes (`0x5896` = 22678, `0x813d`
// = 33085) stringified for `$$conv{$val}` lookup. Values are Perl single-
// quoted strings (`'8500000'`, `'5500000'`); we keep them as strings
// (`PrintValue::Str`) because the serializer's `is_json_number_literal`
// gate will emit them as bare JSON numbers anyway (the strings are pure
// integer tokens). Verified byte-exact against the bundled `perl exiftool`
// `-n` oracle on `MOI.moi` (`"MOI:VideoBitrate": 8500000`).
//
// PrintHex applies to the FALLBACK only; for the fixture (raw 0x5896 hits
// the hash) it's unused. A miss with `PrintHex` set would produce the
// ValueConv output `Unknown (0x5896)` for an unmapped raw — that string
// then fails `IsFloat` in `ConvertBitrate` and is returned unchanged.
static VIDEO_BITRATE: TagDef = TagDef::new(
  "VideoBitrate",
  "MOI",
  ValueConv::Hash(PrintConvHash::direct(&[
    ("22678", PrintValue::Str("8500000")), // MOI.pm:93 (0x5896 = 22678)
    ("33085", PrintValue::Str("5500000")), // MOI.pm:94 (0x813d = 33085)
  ])),
  PrintConv::Func(video_bitrate_print_conv),
)
.with_print_hex(true); // MOI.pm:91 `PrintHex => 1`

fn moi_get(id: TagId) -> Option<&'static TagDef> {
  match id {
    TagId::Int(0x00) => Some(&MOI_VERSION),
    TagId::Int(0x06) => Some(&DATE_TIME_ORIGINAL),
    TagId::Int(0x0e) => Some(&DURATION),
    TagId::Int(0x80) => Some(&ASPECT_RATIO),
    TagId::Int(0x84) => Some(&AUDIO_CODEC),
    TagId::Int(0x86) => Some(&AUDIO_BITRATE),
    TagId::Int(0xda) => Some(&VIDEO_BITRATE),
    _ => None,
  }
}

/// Faithful `%Image::ExifTool::MOI::Main` (MOI.pm:20-98). family-0 group
/// `MOI`; family-1 also `MOI` (the Perl module-name suffix — confirmed by
/// the bundled-ExifTool oracle on `MOI.moi`).
pub static MOI_MAIN: TagTable = TagTable::new("MOI", moi_get);

/// Sorted offsets of `%MOI::Main` in ASCENDING order — ExifTool emits the
/// tags in this order (ExifTool.pm:9907 `sort { $a <=> $b } keys $tagTablePtr`).
const MOI_OFFSETS: &[u32] = &[0x00, 0x06, 0x0e, 0x80, 0x84, 0x86, 0xda];

/// Walk `%MOI::Main`'s offsets and emit the tags. This is a hand-rolled
/// `ProcessBinaryData` (ExifTool.pm:9907-9991) specialized to MOI:
/// `FORMAT` is unset on the table (each tag carries its own Format), all
/// offsets are pre-known integers (no `Hook` / variable spacing — the
/// table is fully static), and byte order is `MM` (MOI.pm:116
/// `SetByteOrder('MM')`).
///
/// The walker reads exactly the bytes each tag needs:
/// - `string[2]`: 2 raw bytes ⇒ `TagValue::Str` (UTF-8 lossy; in practice
///   MOI versions are ASCII like `"V6"`).
/// - `undef[8]`: 8 raw bytes ⇒ `TagValue::Bytes` (DateTimeOriginal's
///   ValueConv consumes it).
/// - `int8u`: 1 byte ⇒ `TagValue::I64` (in [0, 255]).
/// - `int16u`: 2 BE bytes ⇒ `TagValue::I64` (in [0, 65535]).
/// - `int32u`: 4 BE bytes ⇒ `TagValue::I64` (in [0, 4294967295]).
///
/// A tag whose offset+length runs past the buffer is silently dropped
/// (faithful: ExifTool.pm:9942 `next if $entry + $varSize + $count *
/// $format_size > $size` — out-of-bounds entries are not extracted).
fn process_moi_binary_data(ctx: &mut ParseContext<'_>, buff: &[u8], print_conv_enabled: bool) {
  for &off in MOI_OFFSETS {
    let off = off as usize;
    let Some(def) = moi_get(TagId::Int(off as i64)) else {
      continue;
    };
    // Match on the tag definition's *name* to pick the Perl `Format`. The
    // alternative — adding a `format` runtime to TagDef — is heavier than
    // the table itself for a 7-tag module; this hand-roll keeps the seam
    // tiny while staying byte-exact.
    let raw = match def.name() {
      // string[2]  (MOI.pm:27)
      "MOIVersion" => {
        let Some(slice) = buff.get(off..off + 2) else {
          continue;
        };
        // Perl `string[2]` is a fixed-length latin-1/utf-8 string,
        // null-trimmed (ExifTool.pm:6253 `s/\0+$//`). MOI's MOIVersion is
        // always 2 ASCII chars in real files (`V6`); we mirror Perl by
        // trimming trailing NULs before constructing the string.
        let end = slice.iter().rposition(|&b| b != 0).map_or(0, |i| i + 1);
        TagValue::Str(String::from_utf8_lossy(&slice[..end]).into_owned().into())
      }
      // undef[8]  (MOI.pm:32)
      "DateTimeOriginal" => {
        let Some(slice) = buff.get(off..off + 8) else {
          continue;
        };
        TagValue::Bytes(slice.to_vec())
      }
      // int8u  (MOI.pm:51, MOI.pm:83)
      "AspectRatio" | "AudioBitrate" => {
        let Some(&b) = buff.get(off) else {
          continue;
        };
        TagValue::I64(i64::from(b))
      }
      // int16u  (MOI.pm:73, MOI.pm:90) — MM order (MOI.pm:116).
      "AudioCodec" | "VideoBitrate" => {
        let Some(slice) = buff.get(off..off + 2) else {
          continue;
        };
        let n = u16::from_be_bytes([slice[0], slice[1]]);
        TagValue::I64(i64::from(n))
      }
      // int32u  (MOI.pm:45) — MM order.
      "Duration" => {
        let Some(slice) = buff.get(off..off + 4) else {
          continue;
        };
        let n = u32::from_be_bytes([slice[0], slice[1], slice[2], slice[3]]);
        TagValue::I64(i64::from(n))
      }
      // Faithful to ExifTool.pm:9907 keyed walk: anything else is a table-
      // author error (the static `MOI_OFFSETS` is the single source of
      // truth, and every offset in it MUST appear in this match).
      _ => continue,
    };
    let out = apply(def, &raw, print_conv_enabled);
    ctx
      .metadata()
      .push(Group::new(MOI_MAIN.group0(), def.group1()), def.name(), out);
  }
}

/// MOI parser — faithful port of `Image::ExifTool::MOI::ProcessMOI`
/// (MOI.pm:104-119).
pub struct ProcessMoi;

impl FormatParser for ProcessMoi {
  fn process(&self, ctx: &mut ParseContext<'_>) -> bool {
    // MOI.pm:110 — `$raf->Read($buff,256) == 256 and $buff =~ /^V6/ or
    // return 0`. The 256-byte read AND the `V6` prefix are BOTH required;
    // a short file (< 256 bytes) fails the read length and rejects, even
    // if it starts with V6. Bundled `perl exiftool` on a short V6-prefixed
    // file emits the post-loop 'File format error' (ExifTool.pm:3093).
    let total_len = ctx.data().len();
    if total_len < 256 {
      return false;
    }
    // Copy the 256-byte buffer out so the upcoming `&mut ctx`
    // (set_file_type, metadata().push) does not conflict with `$buff`;
    // `buff256` IS Perl's `$buff` (the validated header bytes).
    let buff256: [u8; 256] = {
      let head = &ctx.data()[..256];
      if &head[..2] != b"V6" {
        return false;
      }
      // MOI.pm:111-114 — `if (defined $$et{VALUE}{FileSize}) { my $size =
      // unpack('x2N', $buff); $size == $$et{VALUE}{FileSize} or return 0; }`
      //
      // The reader path *does* know FileSize: it is `total_len`. ExifTool
      // populates `$$self{VALUE}{FileSize}` from `stat` (ExifTool.pm:3007),
      // so the guard is always armed in practice — comparing the embedded
      // 32-bit BE filesize against the actual file size, rejecting if they
      // disagree. We mirror that: read the BE u32 at offset 0x02, compare
      // to `total_len`. NOTE: MOI's filesize field is `int32u` (4 bytes),
      // so files > 4 GiB cannot match (a non-issue: MOI sidecars are
      // typically a few hundred bytes; the upstream fixture is 320 B).
      let embedded_size = u32::from_be_bytes([head[2], head[3], head[4], head[5]]) as u64;
      if embedded_size != total_len as u64 {
        return false;
      }
      // Explicit copy is panic-free (no try_into); the local array is
      // needed because the binary-data walker borrows ctx mutably to
      // push tags.
      let mut out = [0u8; 256];
      out.copy_from_slice(head);
      out
    };
    // MOI.pm:115 — `$et->SetFileType()`. No-arg ⇒ detected file type ("MOI").
    ctx.set_file_type(None, None, None);
    let print_conv_enabled = ctx.print_conv_enabled();
    // MOI.pm:116 — `SetByteOrder('MM')`. We don't carry a persistent byte-
    // order register; the walker reads each `int16u`/`int32u` as
    // `from_be_bytes` directly (the only consumer of the byte order).
    // MOI.pm:117-118 — `ProcessBinaryData({ DataPt => \$buff }, GetTagTable(
    // 'Image::ExifTool::MOI::Main'))`.
    process_moi_binary_data(ctx, &buff256, print_conv_enabled);
    // MOI.pm:118 — `return $et->ProcessBinaryData(...)`; in the read path
    // `ProcessBinaryData` is `return 1` (it never refuses for an
    // arms-passed binary). Faithful ⇒ `return 1` here.
    true
  }
}

#[cfg(test)]
mod tests {
  use super::*;
  use crate::value::Metadata;

  // ---------- ValueConv / PrintConv helpers ------------------------------

  #[test]
  fn datetime_original_formats_fixture_value() {
    // The MOI.moi fixture's 8 bytes at offset 0x06: 07 db 05 0f 11 3a bb 80.
    // unpack('nCCCCn'): year=0x07db=2011, month=5, day=15, hour=17,
    //                   minute=58, ms=0xbb80=48000. 48000/1000 = 48.0.
    // sprintf('%.4d:%.2d:%.2d %.2d:%.2d:%06.3f', ...) ⇒
    //   "2011:05:15 17:58:48.000".
    let v = datetime_original_value_conv(&TagValue::Bytes(vec![
      0x07, 0xdb, 0x05, 0x0f, 0x11, 0x3a, 0xbb, 0x80,
    ]));
    assert_eq!(v, TagValue::Str("2011:05:15 17:58:48.000".into()));
  }

  #[test]
  fn datetime_original_pads_fractional_seconds_to_width_six() {
    // 7.123 s ⇒ "07.123" (width-6 zero-padded). Bundled-Perl verified.
    let v = datetime_original_value_conv(&TagValue::Bytes(vec![
      0x07, 0xdb, 0x05, 0x0f, 0x11, 0x3a, 0x1b, 0xd3, // ms=7123
    ]));
    assert_eq!(v, TagValue::Str("2011:05:15 17:58:07.123".into()));
  }

  #[test]
  fn datetime_original_short_input_passes_through() {
    // < 8 bytes ⇒ Perl `return undef` ⇒ engine drops; we model the conv as
    // identity (the walker won't reach this path because of bounds checks).
    let raw = TagValue::Bytes(vec![0x07, 0xdb]);
    assert_eq!(datetime_original_value_conv(&raw), raw);
    // Non-Bytes ⇒ defensive identity (never happens in real flow).
    let raw2 = TagValue::I64(42);
    assert_eq!(datetime_original_value_conv(&raw2), raw2);
  }

  #[test]
  fn duration_value_conv_divides_by_thousand() {
    assert_eq!(
      duration_value_conv(&TagValue::I64(8160)),
      TagValue::F64(8.16)
    );
    assert_eq!(duration_value_conv(&TagValue::I64(0)), TagValue::F64(0.0));
    assert_eq!(
      duration_value_conv(&TagValue::I64(86461000)),
      TagValue::F64(86461.0)
    );
    // Defensive identity on a non-I64 (the walker always feeds I64).
    let s = TagValue::Str("x".into());
    assert_eq!(duration_value_conv(&s), s);
  }

  #[test]
  fn convert_duration_matches_perl_oracle() {
    // Bundled-Perl `Image::ExifTool::ConvertDuration` 2026-05-20:
    assert_eq!(convert_duration(8.16), "8.16 s");
    assert_eq!(convert_duration(0.0), "0 s");
    assert_eq!(convert_duration(0.5), "0.50 s");
    assert_eq!(convert_duration(0.01), "0.01 s");
    assert_eq!(convert_duration(29.99), "29.99 s");
    // The 30-second boundary: 30 + 0.5 = 30.5; int(30.5/3600)=0, etc.
    assert_eq!(convert_duration(30.0), "0:00:30");
    assert_eq!(convert_duration(30.5), "0:00:31"); // rounds via +0.5
    assert_eq!(convert_duration(3600.0), "1:00:00");
    assert_eq!(convert_duration(86400.0), "24:00:00");
    assert_eq!(convert_duration(86461.0), "24:01:01");
    assert_eq!(convert_duration(90000.0), "1 days 1:00:00");
    // Negatives carry the leading "-" sign:
    assert_eq!(convert_duration(-30.0), "-0:00:30");
    assert_eq!(convert_duration(-29.0), "-29.00 s");
    assert_eq!(convert_duration(-86461.0), "-24:01:01");
  }

  #[test]
  fn convert_bitrate_matches_perl_oracle() {
    // Bundled-Perl `Image::ExifTool::ConvertBitrate` 2026-05-20:
    assert_eq!(convert_bitrate(224000.0), "224 kbps");
    assert_eq!(convert_bitrate(8_500_000.0), "8.5 Mbps");
    assert_eq!(convert_bitrate(50.0), "50 bps");
    assert_eq!(convert_bitrate(95.0), "95 bps");
    assert_eq!(convert_bitrate(120.0), "120 bps");
    assert_eq!(convert_bitrate(999.0), "999 bps");
    assert_eq!(convert_bitrate(1000.0), "1 kbps");
    assert_eq!(convert_bitrate(1_500_000_000.0), "1.5 Gbps");
    // Exhausts the units table ⇒ stays in Gbps even at extreme magnitudes.
    assert_eq!(convert_bitrate(5_000_000_000_000.0), "5000 Gbps");
  }

  #[test]
  fn aspect_ratio_print_conv_decodes_nibbles() {
    // Fixture: raw = 0x51 ⇒ lo=1<2 ⇒ "4:3"; hi=5 ⇒ " PAL".
    assert_eq!(
      aspect_ratio_print_conv(&TagValue::I64(0x51)),
      TagValue::Str("4:3 PAL".into())
    );
    // lo<2 only (no hi modifier).
    assert_eq!(
      aspect_ratio_print_conv(&TagValue::I64(0x01)),
      TagValue::Str("4:3".into())
    );
    // lo=4 ⇒ "16:9"; hi=4 ⇒ " NTSC".
    assert_eq!(
      aspect_ratio_print_conv(&TagValue::I64(0x44)),
      TagValue::Str("16:9 NTSC".into())
    );
    // lo=5 ⇒ "16:9"; hi=5 ⇒ " PAL".
    assert_eq!(
      aspect_ratio_print_conv(&TagValue::I64(0x55)),
      TagValue::Str("16:9 PAL".into())
    );
    // lo>5 ⇒ "Unknown"; hi=0 ⇒ no suffix.
    assert_eq!(
      aspect_ratio_print_conv(&TagValue::I64(0x07)),
      TagValue::Str("Unknown".into())
    );
    // lo=2/3 (in [2,3]) ⇒ "Unknown" (the `elsif $lo == 4 or $lo == 5`
    // misses, falls through to `else 'Unknown'`).
    assert_eq!(
      aspect_ratio_print_conv(&TagValue::I64(0x02)),
      TagValue::Str("Unknown".into())
    );
    // hi=3 (not 4 / 5) ⇒ no suffix.
    assert_eq!(
      aspect_ratio_print_conv(&TagValue::I64(0x31)),
      TagValue::Str("4:3".into())
    );
  }

  #[test]
  fn audio_bitrate_value_conv_applies_formula() {
    // raw=11 (MOI.moi fixture) ⇒ 11*16000+48000 = 224000.
    assert_eq!(
      audio_bitrate_value_conv(&TagValue::I64(11)),
      TagValue::I64(224000)
    );
    // raw=0 ⇒ 48000 (the additive base).
    assert_eq!(
      audio_bitrate_value_conv(&TagValue::I64(0)),
      TagValue::I64(48000)
    );
    // raw=255 ⇒ 4128000 (well below i64::MAX, no overflow).
    assert_eq!(
      audio_bitrate_value_conv(&TagValue::I64(255)),
      TagValue::I64(4128000)
    );
  }

  #[test]
  fn audio_bitrate_print_conv_formats_kbps() {
    // 224000 bps ⇒ "224 kbps".
    assert_eq!(
      audio_bitrate_print_conv(&TagValue::I64(224000)),
      TagValue::Str("224 kbps".into())
    );
  }

  #[test]
  fn video_bitrate_print_conv_handles_post_hash_types() {
    // Post-ValueConv types observed in our flow: I64 (if the hash value
    // is parsed as int) and Str (current model, where PrintValue::Str
    // keeps "8500000" as a string).
    assert_eq!(
      video_bitrate_print_conv(&TagValue::I64(8_500_000)),
      TagValue::Str("8.5 Mbps".into())
    );
    assert_eq!(
      video_bitrate_print_conv(&TagValue::Str("8500000".into())),
      TagValue::Str("8.5 Mbps".into())
    );
    // Non-numeric ⇒ identity (ConvertBitrate `IsFloat or return $bitrate`).
    let bad = TagValue::Str("Unknown (0x5896)".into());
    assert_eq!(video_bitrate_print_conv(&bad), bad);
  }

  // ---------- Table & lookup ----------------------------------------------

  #[test]
  fn table_resolves_every_listed_offset() {
    let g = MOI_MAIN.get();
    assert_eq!(g(TagId::Int(0x00)).unwrap().name(), "MOIVersion");
    assert_eq!(g(TagId::Int(0x06)).unwrap().name(), "DateTimeOriginal");
    assert_eq!(g(TagId::Int(0x0e)).unwrap().name(), "Duration");
    assert_eq!(g(TagId::Int(0x80)).unwrap().name(), "AspectRatio");
    assert_eq!(g(TagId::Int(0x84)).unwrap().name(), "AudioCodec");
    assert_eq!(g(TagId::Int(0x86)).unwrap().name(), "AudioBitrate");
    assert_eq!(g(TagId::Int(0xda)).unwrap().name(), "VideoBitrate");
    assert!(g(TagId::Int(0x99)).is_none());
    assert!(g(TagId::Str("AnyName")).is_none());
    // Family-0 group is "MOI" (MOI.pm module-name suffix).
    assert_eq!(MOI_MAIN.group0(), "MOI");
    // PrintHex flags set on the two `PrintHex => 1` tags only.
    assert!(g(TagId::Int(0x84)).unwrap().print_hex());
    assert!(g(TagId::Int(0xda)).unwrap().print_hex());
    assert!(!g(TagId::Int(0x00)).unwrap().print_hex());
    assert!(!g(TagId::Int(0x80)).unwrap().print_hex());
    // MOI_OFFSETS is in strictly ascending order.
    for w in MOI_OFFSETS.windows(2) {
      assert!(w[0] < w[1], "MOI_OFFSETS must be strictly ascending");
    }
    // Every offset in MOI_OFFSETS resolves through moi_get.
    for &off in MOI_OFFSETS {
      assert!(
        g(TagId::Int(off as i64)).is_some(),
        "offset 0x{off:x} not in moi_get"
      );
    }
  }

  // ---------- ProcessMoi (parser entry) -----------------------------------

  /// Build a 320-byte buffer matching the bundled `MOI.moi` fixture: `V6`
  /// at 0x00, embedded BE filesize=320 at 0x02, the documented DateTime/
  /// Duration/AspectRatio/AudioCodec/AudioBitrate bytes, and VideoBitrate
  /// `0x5896` at 0xda.
  fn fixture_buffer() -> Vec<u8> {
    let mut b = vec![0u8; 320];
    b[0] = b'V';
    b[1] = b'6';
    b[2..6].copy_from_slice(&320u32.to_be_bytes());
    // DateTimeOriginal: 2011-05-15 17:58:48.000 (ms=48000=0xbb80)
    b[6..14].copy_from_slice(&[0x07, 0xdb, 0x05, 0x0f, 0x11, 0x3a, 0xbb, 0x80]);
    // Duration: 8160 ms (BE u32) ⇒ 8.16 s
    b[14..18].copy_from_slice(&8160u32.to_be_bytes());
    // AspectRatio: 0x51 (4:3 PAL)
    b[0x80] = 0x51;
    // AudioCodec: BE u16 = 0x00c1 (AC3)
    b[0x84..0x86].copy_from_slice(&0x00c1u16.to_be_bytes());
    // AudioBitrate: 11 ⇒ *16000+48000 = 224000
    b[0x86] = 11;
    // VideoBitrate: BE u16 = 0x5896 ⇒ ValueConv hash hit (8500000)
    b[0xda..0xdc].copy_from_slice(&0x5896u16.to_be_bytes());
    b
  }

  fn run(data: &[u8], print_on: bool) -> Metadata {
    let mut m = Metadata::new("MOI.moi");
    let mut c = ParseContext::new(data, "MOI", 0, "MOI", None, print_on, &mut m);
    ProcessMoi.process(&mut c);
    m
  }

  #[test]
  fn fixture_round_trip_print_on() {
    let m = run(&fixture_buffer(), true);
    let by_name = |n: &str| {
      m.tags()
        .iter()
        .find(|t| t.name() == n)
        .map(|t| t.value().clone())
    };
    assert_eq!(by_name("FileType"), Some(TagValue::Str("MOI".into())));
    assert_eq!(by_name("MOIVersion"), Some(TagValue::Str("V6".into())));
    assert_eq!(
      by_name("DateTimeOriginal"),
      Some(TagValue::Str("2011:05:15 17:58:48.000".into()))
    );
    assert_eq!(by_name("Duration"), Some(TagValue::Str("8.16 s".into())));
    assert_eq!(
      by_name("AspectRatio"),
      Some(TagValue::Str("4:3 PAL".into()))
    );
    assert_eq!(by_name("AudioCodec"), Some(TagValue::Str("AC3".into())));
    assert_eq!(
      by_name("AudioBitrate"),
      Some(TagValue::Str("224 kbps".into()))
    );
    assert_eq!(
      by_name("VideoBitrate"),
      Some(TagValue::Str("8.5 Mbps".into()))
    );
  }

  #[test]
  fn fixture_round_trip_print_off() {
    let m = run(&fixture_buffer(), false);
    let by_name = |n: &str| {
      m.tags()
        .iter()
        .find(|t| t.name() == n)
        .map(|t| t.value().clone())
    };
    // -n: ValueConv only.
    assert_eq!(by_name("MOIVersion"), Some(TagValue::Str("V6".into())));
    // DateTimeOriginal has no PrintConv ⇒ ValueConv string under both modes.
    assert_eq!(
      by_name("DateTimeOriginal"),
      Some(TagValue::Str("2011:05:15 17:58:48.000".into()))
    );
    assert_eq!(by_name("Duration"), Some(TagValue::F64(8.16)));
    // AspectRatio has no ValueConv ⇒ raw integer under -n.
    assert_eq!(by_name("AspectRatio"), Some(TagValue::I64(0x51)));
    // AudioCodec ValueConv is None ⇒ raw integer under -n.
    assert_eq!(by_name("AudioCodec"), Some(TagValue::I64(0x00c1)));
    // AudioBitrate ValueConv =*16000+48000.
    assert_eq!(by_name("AudioBitrate"), Some(TagValue::I64(224000)));
    // VideoBitrate hash ValueConv hit: "22678" ⇒ Str("8500000"). The
    // serializer's number gate prints it as a bare 8500000 — verified by
    // the conformance test against `MOI.moi.n.json`.
    assert_eq!(
      by_name("VideoBitrate"),
      Some(TagValue::Str("8500000".into()))
    );
  }

  #[test]
  fn rejects_short_buffer_and_bad_magic() {
    // 0-byte: too short to even read 256 bytes.
    let mut m = Metadata::new("X.moi");
    let mut c = ParseContext::new(&[], "MOI", 0, "MOI", None, true, &mut m);
    assert!(!ProcessMoi.process(&mut c));
    assert!(m.tags().is_empty());
    // 256 bytes but wrong magic: reject before SetFileType.
    let mut m2 = Metadata::new("X.moi");
    let buf = vec![0u8; 256];
    let mut c2 = ParseContext::new(&buf, "MOI", 0, "MOI", None, true, &mut m2);
    assert!(!ProcessMoi.process(&mut c2));
    assert!(m2.tags().is_empty());
  }

  #[test]
  fn rejects_mismatched_embedded_filesize() {
    // 320-byte buffer, V6 magic, but the embedded BE u32 at offset 0x02
    // claims a different size ⇒ reject (MOI.pm:111-114).
    let mut buf = vec![0u8; 320];
    buf[0] = b'V';
    buf[1] = b'6';
    buf[2..6].copy_from_slice(&999u32.to_be_bytes()); // lies — actual is 320
    let mut m = Metadata::new("X.moi");
    let mut c = ParseContext::new(&buf, "MOI", 0, "MOI", None, true, &mut m);
    assert!(!ProcessMoi.process(&mut c));
    // Reject happens before SetFileType ⇒ no tags emitted (faithful to
    // MOI.pm:114 `or return 0` BEFORE :115 `SetFileType()`).
    assert!(m.tags().is_empty());
  }

  #[test]
  fn audio_codec_falls_back_to_unknown_hex_on_miss() {
    // Adversarial: byte 0x84..0x86 = 0xDEAD (not in the hash). PrintHex=1
    // ⇒ fallback "Unknown (0xdead)" under -j; ValueConv is None ⇒ raw
    // integer 57005 under -n.
    let mut b = fixture_buffer();
    b[0x84..0x86].copy_from_slice(&0xdeadu16.to_be_bytes());
    let m = run(&b, true);
    let v = m
      .tags()
      .iter()
      .find(|t| t.name() == "AudioCodec")
      .map(|t| t.value().clone());
    assert_eq!(v, Some(TagValue::Str("Unknown (0xdead)".into())));
    let m_n = run(&b, false);
    let v_n = m_n
      .tags()
      .iter()
      .find(|t| t.name() == "AudioCodec")
      .map(|t| t.value().clone());
    assert_eq!(v_n, Some(TagValue::I64(0xdead)));
  }

  #[test]
  fn pushes_tags_in_ascending_offset_order() {
    // Faithful to ExifTool.pm:9907 `sort { $a <=> $b }`.
    let m = run(&fixture_buffer(), true);
    let format_names: Vec<&str> = m
      .tags()
      .iter()
      .filter(|t| t.group().family1() == "MOI")
      .map(crate::value::Tag::name)
      .collect();
    assert_eq!(
      format_names,
      &[
        "MOIVersion",
        "DateTimeOriginal",
        "Duration",
        "AspectRatio",
        "AudioCodec",
        "AudioBitrate",
        "VideoBitrate",
      ]
    );
  }
}
