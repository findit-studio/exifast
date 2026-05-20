//! Faithful port of `Image::ExifTool::MPC` (lib/Image/ExifTool/MPC.pm).
//! PROCESS_PROC is `FLAC::ProcessBitStream` (MPC.pm:22) → `crate::bitstream`.

use crate::tagtable::{PrintConv, PrintConvHash, PrintValue, TagDef, TagId, TagTable, ValueConv};
use crate::value::TagValue;

// MPC.pm:28 — TotalFrames (Bit032-063 = 32-bit integer): no PrintConv.
static TOTAL_FRAMES: TagDef = TagDef::new("TotalFrames", "MPC", ValueConv::None, PrintConv::None);

// MPC.pm:29-37 — SampleRate. Hash PrintConv: int-keyed in Perl, string-keyed
// in our model (Perl `$$conv{$val}` keys are stringified). VALUES are bare
// numbers (e.g. `0 => 44100`) ⇒ PrintValue::I64 — matches AAC.pm's identical
// `%convSampleRate` shape, faithfully a hash-of-int → -j emits JSON numbers.
static SAMPLE_RATE: TagDef = TagDef::new(
  "SampleRate",
  "MPC",
  ValueConv::None,
  PrintConv::Hash(PrintConvHash::direct(&[
    ("0", PrintValue::I64(44100)),
    ("1", PrintValue::I64(48000)),
    ("2", PrintValue::I64(37800)),
    ("3", PrintValue::I64(32000)),
  ])),
);

// MPC.pm:38-54 — Quality. Hash PrintConv: keys `1, 5, 6, 7, 8, 9, 10, 11,
// 12, 13, 14, 15` (sparse — the Perl table has NO entries for 2/3/4: a
// `Quality` raw value of 2/3/4 falls through to ExifTool's generic
// `Unknown (N)` fallback per `ExifTool.pm:3622`). Values are strings: some
// look like bare integers in quotes (e.g. `5 => '0'`, `6 => '1'`); Perl
// preserves string vs int via the literal, so these are STRING values in
// the Perl source ⇒ emit as PrintValue::Str under -j.
static QUALITY: TagDef = TagDef::new(
  "Quality",
  "MPC",
  ValueConv::None,
  PrintConv::Hash(PrintConvHash::direct(&[
    ("1", PrintValue::Str("Unstable/Experimental")),
    ("5", PrintValue::Str("0")),
    ("6", PrintValue::Str("1")),
    ("7", PrintValue::Str("2 (Telephone)")),
    ("8", PrintValue::Str("3 (Thumb)")),
    ("9", PrintValue::Str("4 (Radio)")),
    ("10", PrintValue::Str("5 (Standard)")),
    ("11", PrintValue::Str("6 (Xtreme)")),
    ("12", PrintValue::Str("7 (Insane)")),
    ("13", PrintValue::Str("8 (BrainDead)")),
    ("14", PrintValue::Str("9")),
    ("15", PrintValue::Str("10")),
  ])),
);

// MPC.pm:55 — MaxBand (6-bit integer): no PrintConv.
static MAX_BAND: TagDef = TagDef::new("MaxBand", "MPC", ValueConv::None, PrintConv::None);

// MPC.pm:56-59 — ReplayGain* (each a 16-bit integer): no PrintConv.
static REPLAY_GAIN_TRACK_PEAK: TagDef = TagDef::new(
  "ReplayGainTrackPeak",
  "MPC",
  ValueConv::None,
  PrintConv::None,
);
static REPLAY_GAIN_TRACK_GAIN: TagDef = TagDef::new(
  "ReplayGainTrackGain",
  "MPC",
  ValueConv::None,
  PrintConv::None,
);
static REPLAY_GAIN_ALBUM_PEAK: TagDef = TagDef::new(
  "ReplayGainAlbumPeak",
  "MPC",
  ValueConv::None,
  PrintConv::None,
);
static REPLAY_GAIN_ALBUM_GAIN: TagDef = TagDef::new(
  "ReplayGainAlbumGain",
  "MPC",
  ValueConv::None,
  PrintConv::None,
);

// MPC.pm:60-63 — FastSeek (1-bit). Hash PrintConv 0=>'No', 1=>'Yes'.
static FAST_SEEK: TagDef = TagDef::new(
  "FastSeek",
  "MPC",
  ValueConv::None,
  PrintConv::Hash(PrintConvHash::direct(&[
    ("0", PrintValue::Str("No")),
    ("1", PrintValue::Str("Yes")),
  ])),
);

// MPC.pm:64-67 — Gapless (1-bit). Hash PrintConv 0=>'No', 1=>'Yes'.
static GAPLESS: TagDef = TagDef::new(
  "Gapless",
  "MPC",
  ValueConv::None,
  PrintConv::Hash(PrintConvHash::direct(&[
    ("0", PrintValue::Str("No")),
    ("1", PrintValue::Str("Yes")),
  ])),
);

/// MPC.pm:70 `$val =~ s/(\d)(\d)(\d)$/$1.$2.$3/; $val`.
///
/// Perl's `=~ s/(\d)(\d)(\d)$/$1.$2.$3/` performs ONE substitution at the
/// tail of `$val`'s stringified scalar (the regex is tail-anchored on three
/// trailing digits). Faithful Rust transliteration:
///
/// - **Match path** (the value's last 3 chars are ASCII digits): insert
///   `.` between them and return as `TagValue::Str` (the substitution always
///   produces a string in Perl, because the `$1.$2.$3` replacement contains
///   non-digit characters; the JSON writer then emits a JSON string).
/// - **No-match path** (Perl `s///` left `$val` unchanged): return the
///   ORIGINAL `TagValue` UNCHANGED, faithfully preserving its scalar type.
///   Perl's failed `s///` does NOT coerce a dual-typed `$val` to a string;
///   if the bit-stream produced a `TagValue::I64`, the JSON writer must
///   still emit a JSON number. Forcing `TagValue::Str` here would break
///   byte-exactness on a 1- or 2-digit version (e.g. an integer `15` would
///   serialize as JSON `"15"` instead of `15`).
///
/// The byte 0x73 (115 decimal) from the oracle MPC.mpc header takes the
/// match path and yields `"1.1.5"`, byte-exact vs bundled Perl.
fn encoder_version_print(val: &TagValue) -> TagValue {
  // Stringify the way Perl's `$val =~ s/.../.../ ` would see it. The
  // string is consumed only to check the regex tail and to build the
  // dotted output; on no-match the ORIGINAL `val` is returned unchanged
  // (preserving its scalar type — see fn doc).
  let s: String = match val {
    TagValue::I64(n) => n.to_string(),
    TagValue::Str(s) => s.to_string(),
    // F64/Bool/Rational/Bytes/List don't appear here (the bit-stream
    // ValueConv produces an integer for the 8-bit EncoderVersion field),
    // but be defensive: an unexpected non-numeric scalar matches no Perl
    // `\d` and falls to the no-match path ⇒ return `val` unchanged.
    _ => return val.clone(),
  };
  let bytes = s.as_bytes();
  if bytes.len() < 3 || !bytes[bytes.len() - 3..].iter().all(u8::is_ascii_digit) {
    // No-match: Perl's `s///` leaves `$val` unchanged ⇒ return the ORIGINAL
    // (preserving I64 vs Str typing). Forcing `TagValue::Str(s)` here would
    // turn a 2-digit version like `15` into JSON `"15"` instead of `15`,
    // diverging from bundled `perl exiftool`.
    return val.clone();
  }
  let (head, tail) = s.split_at(s.len() - 3);
  // Tail is exactly 3 ASCII digits; insert dots: "abc" -> "a.b.c". The
  // substitution always produces a string in Perl (the `$1.$2.$3` replacement
  // contains non-digit chars), so the match-path return is `TagValue::Str`.
  let mut out = String::with_capacity(head.len() + 5);
  out.push_str(head);
  let tb = tail.as_bytes();
  out.push(tb[0] as char);
  out.push('.');
  out.push(tb[1] as char);
  out.push('.');
  out.push(tb[2] as char);
  TagValue::Str(out.into())
}

// MPC.pm:68-71 — EncoderVersion. Func PrintConv per MPC.pm:70.
static ENCODER_VERSION: TagDef = TagDef::new(
  "EncoderVersion",
  "MPC",
  ValueConv::None,
  PrintConv::Func(encoder_version_print),
);

fn mpc_get(id: TagId) -> Option<&'static TagDef> {
  match id {
    TagId::Str("Bit032-063") => Some(&TOTAL_FRAMES),
    TagId::Str("Bit080-081") => Some(&SAMPLE_RATE),
    TagId::Str("Bit084-087") => Some(&QUALITY),
    TagId::Str("Bit088-093") => Some(&MAX_BAND),
    TagId::Str("Bit096-111") => Some(&REPLAY_GAIN_TRACK_PEAK),
    TagId::Str("Bit112-127") => Some(&REPLAY_GAIN_TRACK_GAIN),
    TagId::Str("Bit128-143") => Some(&REPLAY_GAIN_ALBUM_PEAK),
    TagId::Str("Bit144-159") => Some(&REPLAY_GAIN_ALBUM_GAIN),
    TagId::Str("Bit179") => Some(&FAST_SEEK),
    TagId::Str("Bit191") => Some(&GAPLESS),
    TagId::Str("Bit216-223") => Some(&ENCODER_VERSION),
    _ => None,
  }
}

/// `%MPC::Main` (MPC.pm:21-72). family-0 group "MPC"; family-1 "MPC".
/// Family-2 'Audio' (MPC.pm:23 `GROUPS => {2=>'Audio'}`) is not emitted
/// under `-G1` (the JSON key prefix is family-1, not family-2).
pub static MPC_MAIN: TagTable = TagTable::new("MPC", mpc_get);

// TEMPLATE: keep MPC_BIT_KEYS in sync with mpc_get's `Bit*` arms AND in
// ascending zero-padded bit-offset order — `bitstream::process_bit_stream`'s
// `i2 >= dirLen` early-exit silently skips later fields if mis-ordered.
/// Sorted `Bit<a>-<b>` keys of `%MPC::Main` (ExifTool `sort keys`,
/// FLAC.pm:172) in ASCENDING bit-offset order (required by
/// `bitstream::process_bit_stream`).
pub const MPC_BIT_KEYS: &[&str] = &[
  "Bit032-063", // TotalFrames        (MPC.pm:28)
  "Bit080-081", // SampleRate         (MPC.pm:29)
  "Bit084-087", // Quality            (MPC.pm:38)
  "Bit088-093", // MaxBand            (MPC.pm:55)
  "Bit096-111", // ReplayGainTrackPeak (MPC.pm:56)
  "Bit112-127", // ReplayGainTrackGain (MPC.pm:57)
  "Bit128-143", // ReplayGainAlbumPeak (MPC.pm:58)
  "Bit144-159", // ReplayGainAlbumGain (MPC.pm:59)
  "Bit179",     // FastSeek           (MPC.pm:60)
  "Bit191",     // Gapless            (MPC.pm:64)
  "Bit216-223", // EncoderVersion     (MPC.pm:68)
];

/// MPC parser (faithful `ProcessMPC`, MPC.pm:79-116).
pub struct ProcessMpc;

impl crate::parser::FormatParser for ProcessMpc {
  fn process(&self, ctx: &mut crate::parser::ParseContext<'_>) -> bool {
    // MPC.pm:84-87 `unless ($$et{DoneID3}) { ProcessID3 ... and return 1 }`.
    // Phase-2 DEFERRED to PR #6 (ID3): on a real MPC file that BEGINS with an
    // ID3v2 magic (`ID3...`), ProcessID3 would consume the ID3v2 leading
    // block, advance `$raf`, then dispatch the audio module from inside ID3
    // (ID3.pm:1580-1601 `foreach $type (@audioFormats) { ... }`), and return
    // 1 — at which point ProcessMPC returns 1 immediately. On a file WITHOUT
    // ID3v2 leading bytes (the in-scope input set here), ProcessID3 reads 3
    // bytes, finds no `^ID3` match (ID3.pm:1452), and returns 0 — at which
    // point this `unless` block is a no-op. Inputs in this PR's scope are
    // exactly the no-ID3 case: a pure SV7 MP+ file or a non-SV7 MP+ file.
    //
    // No `Warn` here is faithful: Perl's `ProcessID3` is silent in the
    // no-ID3 case (it does NOT warn for "no ID3 found"; it simply returns 0).
    // Re-derive the actual integration when the ID3 port lands.

    // MPC.pm:92 `$raf->Read($buff,32) == 32 and $buff =~ /^MP\+(.)/s or return 0`.
    // Copy the 32-byte header out of the borrowed `ctx.data()` so the upcoming
    // `&mut ctx` (set_file_type + bit-stream call) does not conflict with
    // `$buff`; `hdr` IS Perl `$buff`. Stack-allocated copy is panic-free.
    let hdr: [u8; 32] = {
      let data = ctx.data();
      if data.len() < 32 {
        return false; // short read ⇒ Perl `$raf->Read != 32` ⇒ return 0
      }
      let mut h = [0u8; 32];
      h.copy_from_slice(&data[..32]);
      h
    };
    if &hdr[..3] != b"MP+" {
      return false; // magic mismatch ⇒ Perl regex no-match ⇒ return 0
    }
    // MPC.pm:93 `my $vers = ord($1) & 0x0f` — low nibble of byte 3.
    let vers = hdr[3] & 0x0f;
    // MPC.pm:94 `$et->SetFileType()` — no-arg ⇒ detected file type ("MPC").
    // Called AFTER magic passes, BEFORE the version dispatch, so the non-SV7
    // branch still emits the File:* triplet alongside the Warning.
    ctx.set_file_type(None, None, None);
    let print_conv_enabled = ctx.print_conv_enabled();

    // MPC.pm:97-106 — SV7 path: ProcessDirectory(MPC::Main) over the 32-byte
    // header, byte order 'II' (MPC.pm:98). `Options('Verbose')` (MPC.pm:100)
    // is faithfully deferred (no Verbose option on the read path).
    if vers == 0x07 {
      crate::bitstream::process_bit_stream(
        &hdr,
        crate::bitstream::BitOrder::Ii, // MPC.pm:98 SetByteOrder('II') — little-endian
        MPC_BIT_KEYS,
        &MPC_MAIN,
        ctx.metadata(),
        print_conv_enabled,
      );
    } else {
      // MPC.pm:107-109 `$et->Warn('Audio info currently not extracted from
      // this version MPC file')`. Verbatim string.
      ctx
        .metadata()
        .push_warning("Audio info currently not extracted from this version MPC file");
    }

    // MPC.pm:111-113 `require Image::ExifTool::APE; ProcessAPE($et, $dirInfo)`.
    // Phase-2 DEFERRED to the APE port: on a file WITH an APE trailer,
    // ProcessAPE seeks to the file end, reads the APE trailer, and pushes
    // `APE:*` tags. On a file WITHOUT an APE trailer (the in-scope inputs
    // here), ProcessAPE seeks to end-32 bytes, reads 32 bytes, finds no
    // "APETAGEX" magic at the trailer position (APE.pm:128-133), and returns
    // 0 with no warning. Re-derive the actual integration when the APE port
    // lands; until then the no-APE case is byte-exact.

    true // MPC.pm:115 `return 1`
  }
}

#[cfg(test)]
mod tests {
  use super::*;
  use crate::parser::{FormatParser, ParseContext};
  use crate::value::Metadata;

  #[test]
  fn table_and_keys_are_faithful() {
    let g = MPC_MAIN.get();
    // MPC.pm:28
    assert_eq!(g(TagId::Str("Bit032-063")).unwrap().name(), "TotalFrames");
    // MPC.pm:29-37: SampleRate (Hash PrintConv 0..3)
    let sr = g(TagId::Str("Bit080-081")).unwrap();
    assert_eq!(sr.name(), "SampleRate");
    assert!(matches!(sr.print_conv(), PrintConv::Hash(_)));
    // MPC.pm:38-54: Quality (Hash PrintConv 1..15)
    let q = g(TagId::Str("Bit084-087")).unwrap();
    assert_eq!(q.name(), "Quality");
    // MPC.pm:55
    assert_eq!(g(TagId::Str("Bit088-093")).unwrap().name(), "MaxBand");
    // MPC.pm:56-59
    assert_eq!(
      g(TagId::Str("Bit096-111")).unwrap().name(),
      "ReplayGainTrackPeak"
    );
    assert_eq!(
      g(TagId::Str("Bit112-127")).unwrap().name(),
      "ReplayGainTrackGain"
    );
    assert_eq!(
      g(TagId::Str("Bit128-143")).unwrap().name(),
      "ReplayGainAlbumPeak"
    );
    assert_eq!(
      g(TagId::Str("Bit144-159")).unwrap().name(),
      "ReplayGainAlbumGain"
    );
    // MPC.pm:60-63 FastSeek (Hash 0/1 -> No/Yes)
    assert_eq!(g(TagId::Str("Bit179")).unwrap().name(), "FastSeek");
    // MPC.pm:64-67 Gapless (Hash 0/1 -> No/Yes)
    assert_eq!(g(TagId::Str("Bit191")).unwrap().name(), "Gapless");
    // MPC.pm:68-71 EncoderVersion (Func PrintConv)
    assert_eq!(
      g(TagId::Str("Bit216-223")).unwrap().name(),
      "EncoderVersion"
    );
    // Bad key -> None
    assert!(g(TagId::Str("Bit999")).is_none());
    assert!(g(TagId::Int(0)).is_none());
    // group0 = "MPC" (MPC.pm:21 package; MPC.pm:23 GROUPS=>{2=>'Audio'} is the
    // family-2 group which is not emitted under -G1).
    assert_eq!(MPC_MAIN.group0(), "MPC");
    // TEMPLATE INVARIANT: every MPC_BIT_KEYS entry must resolve through mpc_get.
    for key in MPC_BIT_KEYS {
      assert!(
        g(TagId::Str(key)).is_some(),
        "MPC_BIT_KEYS entry {key:?} missing from mpc_get"
      );
    }
    // Ascending bit-offset order (required by process_bit_stream's i2>=dirLen).
    let mut prev = 0usize;
    for key in MPC_BIT_KEYS {
      let n: usize = key
        .strip_prefix("Bit")
        .and_then(|s| s.split('-').next())
        .and_then(|s| s.parse().ok())
        .unwrap();
      assert!(n >= prev, "MPC_BIT_KEYS not ascending at {key:?}");
      prev = n;
    }
  }

  #[test]
  fn encoder_version_print_conv_inserts_dots() {
    // MPC.pm:70 `$val =~ s/(\d)(\d)(\d)$/$1.$2.$3/; $val`
    // Oracle: bundled Perl on the synthesized SV7 fixture returns "1.1.5"
    // for the EncoderVersion byte 0x73 (== 115 decimal). The PrintConv runs
    // on the stringified ValueConv result (Bit216-223 ⇒ integer 115). The
    // match-path output is always a `TagValue::Str` because the `$1.$2.$3`
    // replacement contains non-digit characters (the dots).
    let def = MPC_MAIN.get()(TagId::Str("Bit216-223")).unwrap();
    let out = crate::convert::apply(def, &TagValue::I64(115), true);
    assert_eq!(out, TagValue::Str("1.1.5".into()));
    // Below-100 (2 digits): no substitution (regex tail-anchored on 3
    // digits) ⇒ Perl's failed `s///` leaves `$val` UNCHANGED. Faithful
    // Rust preserves the ORIGINAL scalar type: `TagValue::I64(15)` stays
    // `TagValue::I64(15)`, so the JSON writer emits `15` (number), not
    // `"15"` (string). Caught by Copilot review on PR #7.
    let out_lt100 = crate::convert::apply(def, &TagValue::I64(15), true);
    assert_eq!(out_lt100, TagValue::I64(15));
    // 4-digit value: only the LAST three digits are rewritten (Perl substitutes
    // the trailing `(\d)(\d)(\d)$`). `1234` ⇒ `12.3.4` (leading `1`, then dots
    // between the trailing three).
    let out_4d = crate::convert::apply(def, &TagValue::I64(1234), true);
    assert_eq!(out_4d, TagValue::Str("12.3.4".into()));
    // -n: print_conv_enabled=false ⇒ raw integer flows through unchanged.
    let raw = crate::convert::apply(def, &TagValue::I64(115), false);
    assert_eq!(raw, TagValue::I64(115));
    // No-match on a non-digit-tail Str: returns the ORIGINAL Str unchanged
    // (no panic, no coercion). Pins that the no-match path is type-faithful
    // for both TagValue::I64 and TagValue::Str inputs.
    let out_alpha = crate::convert::apply(def, &TagValue::Str("ABC".into()), true);
    assert_eq!(out_alpha, TagValue::Str("ABC".into()));
    // No-match short Str: < 3 chars ⇒ Perl regex no-match ⇒ unchanged.
    let out_short = crate::convert::apply(def, &TagValue::Str("ab".into()), true);
    assert_eq!(out_short, TagValue::Str("ab".into()));
  }

  #[test]
  fn rejects_non_mpc_magic() {
    // MPC.pm:92 `... $buff =~ /^MP\+(.)/s or return 0` — magic mismatch
    // returns 0 BEFORE SetFileType (MPC.pm:94), so nothing is pushed.
    let mut m = Metadata::new("x.mpc");
    let data = [0u8; 32];
    let mut c = ParseContext::new(&data, "MPC", 0, "MPC", None, true, &mut m);
    assert!(!ProcessMpc.process(&mut c));
    assert!(m.tags().is_empty());
  }

  #[test]
  fn rejects_short_read() {
    // MPC.pm:92 `$raf->Read($buff,32) == 32 ...` — < 32 bytes ⇒ return 0.
    // Faithful even for a buffer that starts with "MP+" but is too short.
    let mut m = Metadata::new("x.mpc");
    let data = b"MP+\x07\x00\x00\x00";
    let mut c = ParseContext::new(data, "MPC", 0, "MPC", None, true, &mut m);
    assert!(!ProcessMpc.process(&mut c));
    assert!(m.tags().is_empty());
  }
}
