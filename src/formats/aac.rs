//! Faithful port of `Image::ExifTool::AAC` (lib/Image/ExifTool/AAC.pm).
//! PROCESS_PROC is `FLAC::ProcessBitStream` (AAC.pm:29) → `crate::bitstream`.

use crate::{
  bitstream::{process_bit_stream, BitOrder},
  parser::{FormatParser, ParseContext},
  tagtable::{PrintConv, PrintConvHash, PrintValue, TagDef, TagId, TagTable, ValueConv},
  value::{Group, TagValue},
};

/// `%convSampleRate` (AAC.pm:18-26) as a hash ValueConv (string keys —
/// ExifTool indexes the conv hash with the stringified `$val`).
const CONV_SAMPLE_RATE: &[(&str, PrintValue)] = &[
  ("0", PrintValue::I64(96000)),
  ("1", PrintValue::I64(88200)),
  ("2", PrintValue::I64(64000)),
  ("3", PrintValue::I64(48000)),
  ("4", PrintValue::I64(44100)),
  ("5", PrintValue::I64(32000)),
  ("6", PrintValue::I64(24000)),
  ("7", PrintValue::I64(22050)),
  ("8", PrintValue::I64(16000)),
  ("9", PrintValue::I64(12000)),
  ("10", PrintValue::I64(11025)),
  ("11", PrintValue::I64(8000)),
  ("12", PrintValue::I64(7350)),
];

// AAC.pm:38-42
static PROFILE_TYPE: TagDef = TagDef::new(
  "ProfileType",
  "AAC",
  ValueConv::None,
  PrintConv::Hash(PrintConvHash::direct(&[
    ("0", PrintValue::Str("Main")),
    ("1", PrintValue::Str("Low Complexity")),
    ("2", PrintValue::Str("Scalable Sampling Rate")),
  ])),
);
// AAC.pm:46
static SAMPLE_RATE: TagDef = TagDef::new(
  "SampleRate",
  "AAC",
  ValueConv::Hash(PrintConvHash::direct(CONV_SAMPLE_RATE)),
  PrintConv::None,
);
// AAC.pm:51-60
static CHANNELS: TagDef = TagDef::new(
  "Channels",
  "AAC",
  ValueConv::None,
  PrintConv::Hash(PrintConvHash::direct(&[
    ("0", PrintValue::Str("?")),
    ("1", PrintValue::I64(1)),
    ("2", PrintValue::I64(2)),
    ("3", PrintValue::I64(3)),
    ("4", PrintValue::I64(4)),
    ("5", PrintValue::I64(5)),
    ("6", PrintValue::Str("5+1")),
    ("7", PrintValue::Str("7+1")),
  ])),
);
// AAC.pm:71-74
static ENCODER: TagDef = TagDef::new("Encoder", "AAC", ValueConv::None, PrintConv::None);

fn aac_get(id: TagId) -> Option<&'static TagDef> {
  match id {
    TagId::Str("Bit016-017") => Some(&PROFILE_TYPE),
    TagId::Str("Bit018-021") => Some(&SAMPLE_RATE),
    TagId::Str("Bit023-025") => Some(&CHANNELS),
    TagId::Str("Encoder") => Some(&ENCODER),
    _ => None,
  }
}

/// `%AAC::Main` (AAC.pm:28). family-0 group "AAC"; family-1 "AAC" (`-G1` ⇒
/// `AAC:`); family-2 'Audio' (AAC.pm:30) is not emitted under `-G1`.
pub static AAC_MAIN: TagTable = TagTable::new("AAC", aac_get);

// TEMPLATE: keep AAC_BIT_KEYS in sync with aac_get's `Bit*` arms AND in
// ascending zero-padded bit-offset order — `bitstream::process_bit_stream`'s
// `i2 >= dirLen` early-exit silently skips later fields if mis-ordered.
/// Sorted `Bit<a>-<b>` keys of `%AAC::Main` (ExifTool `sort keys`,
/// FLAC.pm:172) in ASCENDING bit-offset order (required by
/// `bitstream::process_bit_stream`). `Encoder` is not a bit field (set via
/// HandleTag in ProcessAAC), so it is excluded here.
pub const AAC_BIT_KEYS: &[&str] = &["Bit016-017", "Bit018-021", "Bit023-025"];

/// AAC parser (faithful `ProcessAAC`, AAC.pm:81-140).
pub struct ProcessAac;

impl FormatParser for ProcessAac {
  fn process(&self, ctx: &mut ParseContext<'_>) -> bool {
    let data = ctx.data();
    // AAC.pm:99-105 header validation. A reject here returns 0 BEFORE
    // `$et->SetFileType()` (AAC.pm:107), so nothing is pushed.
    if data.len() < 7 {
      return false; // $raf->Read($buff,7)==7 or return 0  (AAC.pm:99)
    }
    let buff = &data[..7];
    if buff[0] != 0xff || (buff[1] != 0xf0 && buff[1] != 0xf1) {
      return false; // unless $buff =~ /^\xff[\xf0\xf1]/  (AAC.pm:100)
    }
    // my @t = unpack('NnC', $buff)  (AAC.pm:101)
    let t0 = u32::from_be_bytes([buff[0], buff[1], buff[2], buff[3]]); // $t[0] = 'N'
    let t1 = u16::from_be_bytes([buff[4], buff[5]]); // $t[1] = 'n'
    let t2 = buff[6]; // $t[2] = 'C'

    // Faithful 1:1 of AAC.pm:102-103. The shift offsets (>>16, >>12) are
    // ExifTool's own — they intentionally differ from the %AAC::Main bit
    // table's Bit016-017 / Bit018-021 extraction. Do NOT "correct" them to
    // >>14 / >>10: byte-exact conformance to bundled ExifTool requires
    // replicating this exactly (oracle: a `ff f1 c0 ..` header ⇒ "File
    // format error", see tests/fixtures/aac_profile3.aac conformance).
    if (t0 >> 16) & 0x03 == 3 {
      return false; // AAC.pm:102 (reserved profile type)
    }
    if (t0 >> 12) & 0x0f > 12 {
      return false; // AAC.pm:103 (validate sampling frequency index)
    }
    // my $len = (($t[0] << 11) & 0x1800) | (($t[1] >> 5) & 0x07ff)  (AAC.pm:104)
    let len = (((t0 << 11) & 0x1800) | ((t1 as u32 >> 5) & 0x07ff)) as usize;
    if len < 7 {
      return false; // AAC.pm:105
    }
    // Validation passed (AAC.pm:105). Copy the 7-byte header out of the
    // borrowed `ctx.data()` so the upcoming `&mut ctx` (set_file_type /
    // metadata) does not conflict with `$buff`; `buff7` IS Perl `$buff`
    // (the first frame, before the AAC.pm:113 re-read).
    // buff = &data[..7] (data.len() >= 7 checked above) — explicit copy is
    // panic-free (no try_into); the local array is needed because the Encoder
    // filler scan later borrows ctx.data() immutably.
    let buff7: [u8; 7] = [
      buff[0], buff[1], buff[2], buff[3], buff[4], buff[5], buff[6],
    ];

    // $et->SetFileType() (AAC.pm:107): no-arg ⇒ detected file type ("AAC").
    // The parser drives this itself (faithful: Process<Type> calls
    // $et->SetFileType), before ProcessDirectory.
    ctx.set_file_type(None, None, None);
    let print_conv_enabled = ctx.print_conv_enabled();

    // $et->ProcessDirectory({DataPt=>\$buff}, AAC::Main) (AAC.pm:109-110):
    process_bit_stream(
      &buff7,
      BitOrder::Mm,
      AAC_BIT_KEYS,
      &AAC_MAIN,
      ctx.metadata(),
      print_conv_enabled,
    );

    // Read the first frame data to check for a filler with the encoder name
    // (AAC.pm:112-137). The Perl `while` runs at most once: the body ends
    // with an unconditional `last` (AAC.pm:136). Compute the (already
    // s///-stripped) Encoder bytes first against an immutable `ctx.data()`,
    // then HandleTag via `ctx.metadata()` — this keeps the byte logic
    // identical to before while satisfying the borrow checker.
    let encoder: Option<Vec<u8>> = {
      let data = ctx.data();
      let mut found: Option<Vec<u8>> = None;
      // while ($len > 8 and $raf->Read($buff,$len-7) == $len-7)  (AAC.pm:113)
      if len > 8 && data.len() >= 7 + (len - 7) {
        let frame = &data[7..7 + (len - 7)]; // $buff (re-read), length == $len-7
        let no_crc = (t0 & 0x0001_0000) != 0; // my $noCRC = ($t[0] & 0x00010000)  (AAC.pm:114)
        let blocks = (t2 & 0x03) as usize; // my $blocks = ($t[2] & 0x03)  (AAC.pm:115)
        let mut pos = 0usize; // my $pos = 0  (AAC.pm:116)
        if !no_crc {
          pos += 2 + 2 * blocks; // $pos += 2 + 2 * $blocks unless $noCRC  (AAC.pm:117)
        }
        if pos + 2 <= frame.len() {
          // last if $pos + 2 > length($buff)  (AAC.pm:118; here $buff == frame)
          let tmp = u16::from_be_bytes([frame[pos], frame[pos + 1]]); // unpack "x${pos}n" (AAC.pm:119)
          let id = tmp >> 13; // my $id = $tmp >> 13  (AAC.pm:120)
          if id == 6 {
            // if ($id == 6)  (AAC.pm:122 filler element)
            let mut cnt = ((tmp >> 9) & 0x0f) as usize; // my $cnt = ($tmp >> 9) & 0x0f  (AAC.pm:123)
            pos += 1; // ++$pos  (AAC.pm:124)
            if cnt == 15 {
              // if ($cnt == 15)  (AAC.pm:125)
              // AAC.pm:126 `$cnt += (($tmp>>1)&0xff) - 1` is signed Perl; reorder
              // for usize safety. cnt==15 here (this is the `cnt==15` branch), so
              // `cnt - 1` == 14 cannot underflow; value is identical to Perl
              // (15 + byte - 1 == 14 + byte).
              debug_assert_eq!(cnt, 15, "cnt==15 is the precondition of this branch");
              cnt = cnt - 1 + (((tmp >> 1) & 0xff) as usize);
              pos += 1; // ++$pos  (AAC.pm:127)
            }
            if pos + cnt <= frame.len() {
              // if ($pos + $cnt <= length($buff))  (AAC.pm:129)
              let dat = &frame[pos..pos + cnt]; // my $dat = substr($buff,$pos,$cnt)  (AAC.pm:130)
                                                // $dat =~ s/^\0+// ; $dat =~ s/\0+$//  (AAC.pm:131-132)
              let s = dat.iter().position(|&b| b != 0).unwrap_or(dat.len());
              let e = dat.iter().rposition(|&b| b != 0).map_or(s, |i| i + 1);
              // e >= s by construction (map_or(s,…) | rposition+1 > s)
              let trimmed = &dat[s..e];
              // HandleTag(Encoder=>$dat) if $dat =~ /^[\x20-\x7e]+$/  (AAC.pm:133;
              // the regex is applied to $dat AFTER the two s/// strips above).
              if !trimmed.is_empty() && trimmed.iter().all(|&b| (0x20..=0x7e).contains(&b)) {
                found = Some(trimmed.to_vec());
              }
            }
          }
        }
        // `last` (AAC.pm:136): no iteration.
      }
      found
    };
    if let Some(trimmed) = encoder {
      if let Some(def) = (AAC_MAIN.get())(TagId::Str("Encoder")) {
        let raw = TagValue::Str(core::str::from_utf8(&trimmed).unwrap_or_default().into());
        let out = crate::convert::apply(def, &raw, print_conv_enabled);
        ctx
          .metadata()
          .push(Group::new(AAC_MAIN.group0(), def.group1()), def.name(), out);
      }
    }
    true // return 1  (AAC.pm:139)
  }
}

#[cfg(test)]
mod tests {
  use super::*;

  #[test]
  fn table_and_keys_are_faithful() {
    let g = AAC_MAIN.get();
    assert_eq!(g(TagId::Str("Bit016-017")).unwrap().name(), "ProfileType");
    assert_eq!(g(TagId::Str("Bit018-021")).unwrap().name(), "SampleRate");
    assert!(matches!(
      g(TagId::Str("Bit018-021")).unwrap().value_conv(),
      ValueConv::Hash(_)
    ));
    assert_eq!(g(TagId::Str("Bit023-025")).unwrap().name(), "Channels");
    assert_eq!(g(TagId::Str("Encoder")).unwrap().name(), "Encoder");
    assert!(g(TagId::Str("Bit999")).is_none());
    assert!(g(TagId::Int(0)).is_none());
    assert_eq!(AAC_BIT_KEYS, &["Bit016-017", "Bit018-021", "Bit023-025"]);
    assert_eq!(AAC_MAIN.group0(), "AAC");
    // %convSampleRate spot-checks vs AAC.pm:18-26.
    assert_eq!(CONV_SAMPLE_RATE.len(), 13);
    assert_eq!(CONV_SAMPLE_RATE[4], ("4", PrintValue::I64(44100)));
    assert_eq!(CONV_SAMPLE_RATE[11], ("11", PrintValue::I64(8000)));
    // TEMPLATE INVARIANT: every AAC_BIT_KEYS entry must resolve through
    // aac_get — catches the manual slice drifting out of sync with the
    // dispatch Bit* arms if a key is added to one side only. (The reverse
    // direction is not testable in safe Rust; keep them aligned by hand.)
    for key in AAC_BIT_KEYS {
      assert!(
        g(TagId::Str(key)).is_some(),
        "AAC_BIT_KEYS entry {key:?} missing from aac_get"
      );
    }
  }

  #[test]
  fn rejects_non_aac_sync() {
    use crate::parser::ParseContext;
    // A reject must push nothing AND not finalize a type (return 0 happens
    // before AAC.pm:107 `$et->SetFileType()`).
    let mut m = crate::value::Metadata::new("x");
    let data = [0u8; 7];
    let mut c = ParseContext::new(&data, "AAC", 0, "AAC", None, true, &mut m);
    assert!(!ProcessAac.process(&mut c));
    assert!(m.tags().is_empty());
    let mut m2 = crate::value::Metadata::new("x");
    let bad = [0xff, 0x00];
    let mut c2 = ParseContext::new(&bad, "AAC", 0, "AAC", None, true, &mut m2);
    assert!(!ProcessAac.process(&mut c2)); // too short / bad sync
    assert!(m2.tags().is_empty());
  }

  #[test]
  fn filler_cnt15_byte0_no_panic() {
    use crate::parser::FormatParser;
    // Byte derivation:
    //   [0]=0xff [1]=0xf1 → sync OK, no_crc=true (bit16 of t0 set)
    //   t0 = 0xff_f1_00_00; (t0>>16)&0x03 = 0x01 ≠ 3 ✓; (t0>>12)&0x0f = 0x00 ≤ 12 ✓
    //   t1 = 0x02_80 → len = ((t0<<11)&0x1800)|((t1>>5)&0x07ff)
    //                       = 0 | ((0x0280>>5)&0x7ff) = 0x14 = 20 ✓ (≥7)
    //   no_crc=true → pos=0 after header; frame = data[7..20] (13 bytes)
    //   frame[0..2] = [0xde, 0x00] → tmp = 0xde00
    //   id  = 0xde00 >> 13 = 6 ✓ (filler element)
    //   cnt = (0xde00 >> 9) & 0x0f = 0x6f & 0x0f = 15 ✓ → enters cnt==15 branch
    //   (tmp>>1)&0xff = (0xde00>>1)&0xff = 0x6f00&0xff = 0 ✓ → byte==0 triggers bug
    //   After fix: cnt = 14 + 0 = 14; pos = 2
    //   pos + cnt = 16 > 13 (frame.len) → payload slice guard fails → no Encoder emitted
    // Must accept (return true) and emit NO Encoder tag.
    let input = [
      0xff, 0xf1, 0x00, 0x00, 0x02, 0x80, 0x00, // header: sync, len=20, no_crc
      0xde, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // frame: id=6 cnt=15 byte=0 …
      0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    ];
    let mut m = crate::value::Metadata::new("x");
    let mut c = crate::parser::ParseContext::new(&input, "AAC", 0, "AAC", None, true, &mut m);
    assert!(ProcessAac.process(&mut c));
    assert!(m.tags().iter().all(|t| t.name() != "Encoder"));
    // Accept ⇒ the parser drove SetFileType (AAC.pm:107): File:* present.
    assert_eq!(
      m.tags()
        .iter()
        .find(|t| t.name() == "FileType")
        .map(|t| t.value()),
      Some(&TagValue::Str("AAC".into()))
    );
  }
}
