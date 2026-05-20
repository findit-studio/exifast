//! Faithful port of `Image::ExifTool::FLAC::ProcessBitStream` (FLAC.pm:158-233).
//! Shared by AAC (PROCESS_PROC) and, later, FLAC StreamInfo.
//!
//! Bit numbering is MSB-first: in 'MM' order bit 0 is the high-order bit of
//! byte 0 (FLAC.pm:61 "bit 0 is the high-order bit").

use crate::{
  convert::apply,
  tagtable::{TagId, TagTable},
  value::{format_g, Group, Metadata, TagValue},
};

/// Byte order of the bit stream (FLAC.pm `GetByteOrder()`; ExifTool global
/// default is 'MM' / big-endian — AAC never calls `SetByteOrder`).
#[derive(Clone, Copy, Debug, PartialEq, derive_more::IsVariant)]
pub enum BitOrder {
  /// Big-endian ('MM'): FLAC/AAC.
  Mm,
  /// Little-endian ('II'). First real consumer: MPC (MPC.pm:98
  /// `SetByteOrder('II')`); verified byte-exact via
  /// `tests/conformance.rs::mpc_conformance` against the bundled Perl
  /// oracle on `MPC.mpc` — the SV7 happy path exercises every
  /// `MPC_BIT_KEYS` extraction in `Ii` order (TotalFrames, SampleRate,
  /// Quality, EncoderVersion, …). This retires the "BitOrder::Ii
  /// faithful-but-unexercised" forward item in
  /// `[[exifast-phase2-forward-items]]`.
  Ii,
}

/// Parse a `Bit<a>-<b>` key into `(b1, b2)` (FLAC.pm:173-174:
/// `next unless $tag =~ /^Bit(\d+)-?(\d+)?/; ($b1,$b2)=($1,$2||$1)`).
fn parse_bits(key: &str) -> Option<(usize, usize)> {
  let rest = key.strip_prefix("Bit")?;
  // inner free fn (no captures) — avoids a borrowing closure
  fn digits(s: &str) -> Option<(usize, &str)> {
    let n = s.find(|c: char| !c.is_ascii_digit()).unwrap_or(s.len());
    if n == 0 {
      return None;
    }
    Some((s[..n].parse().ok()?, &s[n..]))
  }
  let (b1, after) = digits(rest)?;
  let b2 = match after.strip_prefix('-') {
    Some(t) => digits(t).map_or(b1, |(v, _)| v),
    None => b1,
  };
  Some((b1, b2))
}

/// Faithful port of `FLAC::ProcessBitStream` (FLAC.pm:158-233).
/// When a tag has no `Format` key, its bits are accumulated into an unsigned
/// integer (FLAC.pm:179-222). When `Format` IS set (e.g. `Format => 'undef'`),
/// the raw `Size = i2 - i1 + 1` bytes at `Start = i1` are emitted as
/// `TagValue::Bytes` and the integer path is skipped (FLAC.pm:179-181, 224-229).
/// `bit_keys` is the module's statically-known, sorted list of `Bit<a>-<b>`
/// keys (ExifTool does `sort keys %$tagTablePtr`; Rust statics are not
/// enumerable, so the format module supplies the equivalent sorted slice).
///
/// `bit_keys` MUST be in ascending bit-offset order (ExifTool's `sort keys`
/// works because all known tables use zero-padded 3-digit offsets, e.g.
/// `Bit016-017`). The `i2 >= dirLen` early-exit (FLAC.pm:177) assumes this;
/// out-of-order keys would silently skip valid later fields. Any key with a
/// descending range (`b1 > b2`) is a table-author error and is skipped
/// (no tag emitted) rather than spinning in the shift-down loop; this covers
/// both cross-byte keys (i1 > i2) and same-byte keys (i1 == i2, where the
/// mask computes to 0 and the shift-down `while last_mask & 0x01 == 0`
/// would loop forever).
///
/// **No-`Format` integer accumulation — faithful Perl scalar (UV→NV)
/// semantics:** Perl's `$val = $val * 256 + N` stays an exact UV
/// (unsigned integer ≤ u64::MAX in this build) until the next multiply
/// would overflow, then auto-promotes to NV (an f64 in this build, the
/// same IEEE-754 double Perl uses by default). Once NV, subsequent
/// arithmetic stays NV (matching Perl). The trailing-zero shift
/// (FLAC.pm:219-222 `until ($mask & 0x01) { $val /= 2; $mask >>= 1 }`)
/// runs in whichever mode the value is currently in: u64 integer /2, or
/// f64 /2.0 (always exact for finite values). No `>16-byte` guard:
/// Perl loses precision past 53 bits silently — we do the same in NV
/// mode (acceptable because Perl does too). After the shift-down:
/// - u64 mode, val ≤ `i64::MAX` ⇒ `TagValue::I64` (unchanged for all
///   currently-ported fields: AAC ≤ 2 bytes, FLAC `TotalSamples` 36-bit).
/// - u64 mode, val > `i64::MAX` ⇒ `TagValue::Str(exact_decimal)` — the
///   serializer's number gate (`EscapeJSON` line 3809) quotes ≥ 16-digit
///   bare integers, exactly as ExifTool `-j` emits a big unsigned int.
/// - NV (f64) mode ⇒ `TagValue::Str(format_g(val, 15))` — Perl's default
///   `%.15g` NV stringification (e.g. `"4.72236648286965e+21"` for
///   9-byte all-0xFF, byte-exact vs the bundled Perl oracle).
pub fn process_bit_stream(
  data: &[u8],
  order: BitOrder,
  bit_keys: &[&'static str],
  table: &TagTable,
  into: &mut Metadata,
  print_conv_enabled: bool,
) {
  let dir_len = data.len(); // DirStart=0, DirLen=length($$dataPt) (FLAC.pm:163-164)
  for key in bit_keys {
    let Some((b1, b2)) = parse_bits(key) else {
      continue; // FLAC.pm:173
    };
    let (i1, i2) = (b1 / 8, b2 / 8); // FLAC.pm:175
    let (f1, f2) = (b1 % 8, b2 % 8); // FLAC.pm:176
    if i2 >= dir_len {
      break; // FLAC.pm:177 `last if $i2 >= $dirLen`
    }
    // A descending range (b1 > b2, incl. the same-byte case i1==i2 where the
    // mask would compute to 0 and the shift-down loop would spin forever) is
    // a malformed table key — skip it (no tag), completing the no-hang guard
    // for ALL descending keys, not just cross-byte (i1 > i2).
    if b1 > b2 {
      continue;
    }
    // Resolve the tag definition before branching (Perl checks
    // `$$tagTablePtr{$tag}{Format}` — the def must exist first).
    // If the key is not in the table, skip it (no tag emitted).
    let get = table.get();
    let Some(def) = get(TagId::Str(key)) else {
      continue;
    };
    // FLAC.pm:179-181: "if Format is unspecified, convert the specified number
    // of bits to an unsigned integer, otherwise allow HandleTag to convert
    // whole bytes the normal way (via undefined $val)".
    let raw = if def.format().is_some() {
      // TEMPLATE: copy this arm for any tag with Format set (e.g. FLAC StreamInfo MD5Signature).
      // Format IS set: `$val` stays undef; HandleTag reads raw bytes.
      // FLAC.pm:224-229: `Start => $dirStart + $i1`, `Size => $i2 - $i1 + 1`
      // (dirStart=0, Start=i1, inclusive end=i2). The `i2 >= dir_len` break
      // above guarantees i2 < data.len() and the `b1 > b2` continue above
      // guarantees i1 <= i2, so this inclusive slice is always in-bounds.
      TagValue::Bytes(data[i1..=i2].to_vec())
    } else {
      // Format NOT set: unsigned-integer accumulation (FLAC.pm:182-222).
      // Faithful Perl scalar: `$val` starts as UV (here: u64) and
      // auto-promotes to NV (here: f64) when the next `*256 + byte` would
      // overflow u64. Once NV, every subsequent operation stays NV
      // (Perl scalars don't downgrade). No `>16-byte` guard — Perl's NV
      // simply loses precision past ~15 significant digits; we mirror it.
      enum Acc {
        // u64 mode (Perl UV). The exact integer value.
        U(u64),
        // f64 mode (Perl NV). Auto-promoted after a u64 overflow.
        F(f64),
      }
      // Multiply-and-add `acc * 256 + add` with UV→NV promotion on
      // overflow. `add` is at most 255 (it is `mask & byte`).
      fn mul256_add(acc: Acc, add: u8) -> Acc {
        match acc {
          Acc::U(v) => match v.checked_mul(256).and_then(|x| x.checked_add(add as u64)) {
            Some(n) => Acc::U(n),
            // Perl `$val = $val * 256 + N` auto-promotes to NV the moment
            // u64 cannot hold the result. From this byte on, accumulate
            // in f64 (matching Perl's NV path).
            None => Acc::F(v as f64 * 256.0 + add as f64),
          },
          Acc::F(v) => Acc::F(v * 256.0 + add as f64),
        }
      }
      let mut acc = Acc::U(0);
      let mut last_mask: u32 = 0;
      let byte = |i: usize| data[i] as u32; // Get8u($dataPt,$i+$dirStart), dirStart=0
      match order {
        BitOrder::Mm => {
          // FLAC.pm:185-199: `if ($byteOrder eq 'MM')` — loop ascending i1..=i2
          // (comment says "loop from high byte to low byte"; bit-0 is the MSB so
          // i1 carries the most-significant byte of the extracted field).
          for i in i1..=i2 {
            let mut mask: u32 = 0xff;
            if i == i1 && f1 != 0 {
              // mask off high bits in first word (0 is high bit) (FLAC.pm:190-191)
              for b in (8 - f1)..=7 {
                mask ^= 1 << b;
              }
            }
            if i == i2 && f2 < 7 {
              // mask off low bits in last word (7 is low bit) (FLAC.pm:194-195)
              for b in 0..=(6 - f2) {
                mask ^= 1 << b;
              }
            }
            let add = (mask & byte(i)) as u8; // FLAC.pm:197 (mask & Get8u)
            acc = mul256_add(acc, add);
            last_mask = mask;
          }
        }
        BitOrder::Ii => {
          // FLAC.pm:200-217: `else` — loop descending i2..=i1 (little-endian
          // bit streams; comment: "FLAC is big-endian, but support little-endian
          // bit streams so this routine can be used by other modules").
          for i in (i1..=i2).rev() {
            let mut mask: u32 = 0xff;
            if i == i1 && f1 != 0 {
              // mask off low bits in first word (0 is low bit) (FLAC.pm:207-208)
              for b in 0..f1 {
                mask ^= 1 << b;
              }
            }
            if i == i2 && f2 < 7 {
              // mask off high bits in last word (7 is high bit) (FLAC.pm:211-212)
              for b in (f2 + 1)..=7 {
                mask ^= 1 << b;
              }
            }
            let add = (mask & byte(i)) as u8; // FLAC.pm:214 (mask & Get8u)
            acc = mul256_add(acc, add);
            last_mask = mask;
          }
        }
      }
      // FLAC.pm:219-222 shift word down until low bit is in position 0.
      // Perl `$val /= 2` is integer-exact on a UV with a 0 low bit (the
      // last-byte mask AND clears that bit, so `val` is divisible) and
      // exact-exponent-decrement on an NV. We match: u64 `/= 2` (integer
      // division; exact because the low bit is 0 by construction) and
      // f64 `/= 2.0` (exact for finite values: just decrements the
      // exponent).
      while last_mask & 0x01 == 0 {
        acc = match acc {
          Acc::U(v) => Acc::U(v / 2),
          Acc::F(v) => Acc::F(v / 2.0),
        };
        last_mask >>= 1;
      }
      match acc {
        // u64 mode ≤ i64::MAX ⇒ TagValue::I64 (unchanged for all ported
        // fields: AAC ≤ 2 bytes, FLAC TotalSamples 36-bit).
        Acc::U(v) if v <= i64::MAX as u64 => TagValue::I64(v as i64),
        // u64 mode > i64::MAX ⇒ exact decimal string (Perl UV stringifies
        // as exact integer); the serializer's number gate quotes ≥16-digit
        // bare integers, exactly as ExifTool -j emits a big unsigned int.
        Acc::U(v) => TagValue::Str(v.to_string().into()),
        // NV (f64) mode ⇒ Perl's default `%.15g` NV stringification (e.g.
        // 9-byte all-0xFF ⇒ "4.72236648286965e+21", byte-exact oracle).
        Acc::F(v) => TagValue::Str(format_g(v, 15).into()),
      }
    };
    // HandleTag (FLAC.pm:224-229): ValueConv then PrintConv via the engine.
    // Same tail for both the Format and no-Format paths.
    let out = apply(def, &raw, print_conv_enabled);
    into.push(Group::new(table.group0(), def.group1()), def.name(), out);
  }
}

#[cfg(test)]
mod tests {
  use super::*;
  use crate::tagtable::{PrintConv, PrintConvHash, PrintValue, TagDef, ValueConv};
  use crate::{serialize::to_exiftool_json, value::Group};

  // Faithful AAC::Main subset for the synthetic header
  // [0xFF,0xF1,0x50,0x80,0x00,0x00,0x00]:
  //   ProfileType Bit016-017 = (0x50&0xC0)>>6 = 1
  //   SampleRate  Bit018-021 = (0x50&0x3C)>>2 = 4  (ValueConv 4 -> 44100)
  //   Channels    Bit023-025 = ((0x50&1)<<2)|(0x80>>6) = 2
  static PROFILE: TagDef = TagDef::new(
    "ProfileType",
    "AAC",
    ValueConv::None,
    PrintConv::Hash(PrintConvHash::direct(&[(
      "1",
      PrintValue::Str("Low Complexity"),
    )])),
  );
  static SAMPLERATE: TagDef = TagDef::new(
    "SampleRate",
    "AAC",
    ValueConv::Hash(PrintConvHash::direct(&[("4", PrintValue::I64(44100))])),
    PrintConv::None,
  );
  static CHANNELS: TagDef = TagDef::new(
    "Channels",
    "AAC",
    ValueConv::None,
    PrintConv::Hash(PrintConvHash::direct(&[("2", PrintValue::I64(2))])),
  );
  fn get(id: TagId) -> Option<&'static TagDef> {
    match id {
      TagId::Str("Bit016-017") => Some(&PROFILE),
      TagId::Str("Bit018-021") => Some(&SAMPLERATE),
      TagId::Str("Bit023-025") => Some(&CHANNELS),
      _ => None,
    }
  }

  #[test]
  fn mm_extracts_aac_header_fields_print_on() {
    let table = TagTable::new("AAC", get);
    let buff = [0xFFu8, 0xF1, 0x50, 0x80, 0x00, 0x00, 0x00];
    let keys = ["Bit016-017", "Bit018-021", "Bit023-025"];
    let mut m = Metadata::new("x.aac");
    process_bit_stream(&buff, BitOrder::Mm, &keys, &table, &mut m, true);
    let got: Vec<(&str, &TagValue)> = m.tags().iter().map(|t| (t.name(), t.value())).collect();
    assert_eq!(
      got,
      vec![
        ("ProfileType", &TagValue::Str("Low Complexity".into())),
        ("SampleRate", &TagValue::I64(44100)),
        ("Channels", &TagValue::I64(2)),
      ]
    );
    assert_eq!(m.tags()[0].group().family1(), "AAC");
  }

  #[test]
  fn mm_print_off_keeps_raw_but_valueconv_applies() {
    let table = TagTable::new("AAC", get);
    let buff = [0xFFu8, 0xF1, 0x50, 0x80, 0x00, 0x00, 0x00];
    let keys = ["Bit016-017", "Bit018-021", "Bit023-025"];
    let mut m = Metadata::new("x.aac");
    process_bit_stream(&buff, BitOrder::Mm, &keys, &table, &mut m, false);
    let got: Vec<(&str, &TagValue)> = m.tags().iter().map(|t| (t.name(), t.value())).collect();
    assert_eq!(
      got,
      vec![
        ("ProfileType", &TagValue::I64(1)),
        ("SampleRate", &TagValue::I64(44100)),
        ("Channels", &TagValue::I64(2)),
      ]
    );
  }

  #[test]
  fn stops_when_end_byte_reaches_dirlen() {
    let table = TagTable::new("AAC", get);
    let buff = [0xFFu8, 0xF1];
    let keys = ["Bit016-017", "Bit018-021", "Bit023-025"];
    let mut m = Metadata::new("x.aac");
    process_bit_stream(&buff, BitOrder::Mm, &keys, &table, &mut m, true);
    assert!(
      m.tags().is_empty(),
      "i2 >= dirLen must stop before emitting"
    );
  }

  #[test]
  fn descending_offset_key_is_skipped_not_hung() {
    // Any b1 > b2 key is a malformed table entry; the guard skips it
    // (no tag, no panic, no infinite loop).
    //
    // Sub-case 1 — cross-byte descending: b1=24 > b2=16, i1=3 > i2=2.
    // The byte range i1..=i2 would iterate zero times; without the guard,
    // last_mask stays 0 and the shift-down `while last_mask & 0x01 == 0`
    // spins forever.
    let table = TagTable::new("AAC", get);
    let buff = [0xFFu8, 0xF1, 0x50, 0x80, 0x00, 0x00, 0x00];
    let keys = ["Bit024-016"]; // descending cross-byte: b1=24 > b2=16, i1=3 > i2=2
    let mut m = Metadata::new("x.aac");
    process_bit_stream(&buff, BitOrder::Mm, &keys, &table, &mut m, true);
    assert!(m.tags().is_empty());

    // Sub-case 2 — same-byte descending: b1=17 > b2=16, i1==i2==2.
    // The byte loop runs once, but both f1>0 and f2<7 masks clear all bits
    // so last_mask == 0 and the shift-down loop would spin forever without
    // the `b1 > b2` guard (the old `i1 > i2` guard did NOT catch this case).
    let keys2 = ["Bit017-016"]; // same-byte descending: b1=17 > b2=16, i1==i2==2
    let mut m2 = Metadata::new("x.aac");
    process_bit_stream(&buff, BitOrder::Mm, &keys2, &table, &mut m2, true);
    assert!(m2.tags().is_empty());
  }

  #[test]
  fn format_undef_key_takes_raw_bytes_then_valueconv() {
    // Faithful to FLAC.pm:179-231: when Format is set, the bit-field
    // unsigned-integer accumulation is SKIPPED; instead, the raw bytes
    // at Start=i1..i1+Size are passed to HandleTag as the raw value
    // (here `TagValue::Bytes`), then ValueConv applies.
    //
    // `unpack("H*",$val)`: raw bytes -> lowercase hex string — the FLAC
    // MD5Signature shape (FLAC.pm:181); here we prove the engine path end-to-end.
    fn hex(v: &TagValue) -> TagValue {
      match v {
        TagValue::Bytes(b) => {
          let mut s = String::with_capacity(b.len() * 2);
          for x in b {
            s.push_str(&format!("{x:02x}"));
          }
          TagValue::Str(s.into())
        }
        other => other.clone(),
      }
    }
    // Bit000-031 spans bytes 0-3 (4 bytes, i1=0, i2=3, Size=4).
    static MD5: TagDef = TagDef::new(
      "MD5Signature",
      "FLAC",
      ValueConv::Func(hex),
      PrintConv::None,
    )
    .with_format("undef");
    fn get_md5(id: TagId) -> Option<&'static TagDef> {
      match id {
        TagId::Str("Bit000-031") => Some(&MD5),
        _ => None,
      }
    }
    let table = TagTable::new("FLAC", get_md5);
    // Raw data: 0xDE 0xAD 0xBE 0xEF plus one extra byte to keep dir_len > i2.
    let data = [0xDEu8, 0xAD, 0xBE, 0xEF, 0x00];
    let mut m = Metadata::new("x.flac");
    // FLAC.pm:179-231: Format set => raw bytes [i1..i1+Size] = [0..4].
    process_bit_stream(&data, BitOrder::Mm, &["Bit000-031"], &table, &mut m, true);
    assert_eq!(m.tags().len(), 1, "exactly one tag emitted");
    assert_eq!(m.tags()[0].name(), "MD5Signature");
    // ValueConv(Func(hex)) applied to TagValue::Bytes([DE,AD,BE,EF]).
    assert_eq!(m.tags()[0].value(), &TagValue::Str("deadbeef".into()));
    assert_eq!(m.tags()[0].group().family1(), "FLAC");
  }

  #[test]
  fn no_format_key_still_produces_integer() {
    // Regression: a tag WITHOUT `with_format` must still go through the
    // unsigned-integer accumulation (FLAC.pm:182-222). Reuses the existing
    // AAC ProfileType fixture to verify the int path is unaffected.
    let table = TagTable::new("AAC", get);
    // Bit016-017 = (0x50 & 0xC0) >> 6 = 1; PrintConv maps 1 -> "Low Complexity".
    let buff = [0xFFu8, 0xF1, 0x50, 0x80, 0x00, 0x00, 0x00];
    let mut m = Metadata::new("x.aac");
    process_bit_stream(&buff, BitOrder::Mm, &["Bit016-017"], &table, &mut m, false);
    assert_eq!(m.tags().len(), 1);
    assert_eq!(m.tags()[0].name(), "ProfileType");
    // print_conv_enabled=false: raw integer after unsigned-int accumulation.
    assert_eq!(m.tags()[0].value(), &TagValue::I64(1));
  }

  #[test]
  fn format_span_wider_than_8_bytes_no_panic() {
    // The Format (raw-bytes) path has NO span restriction and MUST handle
    // spans up to the full data length. (The no-Format int path also handles
    // any width — UV→NV auto-promotion per Perl, FLAC.pm:182-222 — covered
    // by `no_format_17_byte_no_longer_skipped_emits_nv` below.)
    //
    // This mirrors FLAC's real 16-byte MD5 `Bit144-271` (b1=144, b2=271 =>
    // i1=18, i2=33, Size=16). Here we use `Bit000-127` (b1=0, b2=127 =>
    // i1=0, i2=15, Size=16) over 16 known bytes — the Format path handles
    // this span, the call returns, and the full 32-char hex string is exact.
    fn hex(v: &TagValue) -> TagValue {
      match v {
        TagValue::Bytes(b) => {
          let mut s = String::with_capacity(b.len() * 2);
          for x in b {
            s.push_str(&format!("{x:02x}"));
          }
          TagValue::Str(s.into())
        }
        other => other.clone(),
      }
    }
    static MD5_WIDE: TagDef = TagDef::new(
      "MD5Signature",
      "FLAC",
      ValueConv::Func(hex),
      PrintConv::None,
    )
    .with_format("undef");
    fn get_wide(id: TagId) -> Option<&'static TagDef> {
      match id {
        TagId::Str("Bit000-127") => Some(&MD5_WIDE),
        _ => None,
      }
    }
    let table = TagTable::new("FLAC", get_wide);
    // 16 known bytes (b1=0, b2=127 => i1=0, i2=15 => 16-byte span).
    let data: [u8; 16] = [
      0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xAA, 0xBB, 0xCC, 0xDD, 0xEE,
      0xFF,
    ];
    let mut m = Metadata::new("x.flac");
    // Format path: must NOT panic; must return with the correct hex string.
    process_bit_stream(&data, BitOrder::Mm, &["Bit000-127"], &table, &mut m, true);
    assert_eq!(
      m.tags().len(),
      1,
      "exactly one tag emitted for the 16-byte span"
    );
    assert_eq!(m.tags()[0].name(), "MD5Signature");
    // ValueConv(hex) applied to all 16 bytes -> exact 32-char hex string.
    assert_eq!(
      m.tags()[0].value(),
      &TagValue::Str("00112233445566778899aabbccddeeff".into())
    );
  }

  // ── Tests pinning the faithful Perl UV→NV no-Format accumulation. ──
  //
  // Helper: build a minimal TagDef (no conv) for a no-Format Bit key and
  // drive process_bit_stream.  Returns the first tag's value, or None if no
  // tag was emitted.
  fn extract_no_format(key: &'static str, data: &[u8]) -> Option<TagValue> {
    static DEF: TagDef = TagDef::new("Field", "Test", ValueConv::None, PrintConv::None);
    fn get_field(id: TagId) -> Option<&'static TagDef> {
      // Accept any Bit key — the key string is only checked in the table lookup.
      match id {
        TagId::Str(_) => Some(&DEF),
        _ => None,
      }
    }
    let table = TagTable::new("Test", get_field);
    let mut m = Metadata::new("x.test");
    process_bit_stream(data, BitOrder::Mm, &[key], &table, &mut m, false);
    m.tags().first().map(|t| t.value().clone())
  }

  #[test]
  fn no_format_7_byte_all_ff_is_exact_i64() {
    // Oracle (bundled Perl, re-derived 2026-05-19):
    //   perl -e 'my @b = (0xFF) x 7; my $v=0; foreach (@b){$v=$v*256+$_} print $v'
    //   ⇒ 72057594037927935
    // Stays UV (fits u64), and ≤ i64::MAX ⇒ TagValue::I64.
    // Bit000-055: b1=0, b2=55 ⇒ i1=0, i2=6, f1=0, f2=7 (full 7 bytes).
    let data = [0xFFu8; 7];
    let got = extract_no_format("Bit000-055", &data)
      .expect("tag must be emitted for a 7-byte all-0xFF field");
    assert_eq!(
      got,
      TagValue::I64(72_057_594_037_927_935),
      "7-byte all-0xFF must stay UV (u64) and fit i64 (Perl oracle: 72057594037927935)"
    );
  }

  #[test]
  fn no_format_8_byte_all_ff_is_u64_max_exact_decimal() {
    // Oracle (bundled Perl, re-derived 2026-05-19):
    //   perl -e 'my @b = (0xFF) x 8; my $v=0; foreach (@b){$v=$v*256+$_} print $v'
    //   ⇒ 18446744073709551615 (= u64::MAX, exact UV)
    // Stays UV (fits u64), > i64::MAX ⇒ TagValue::Str(exact_decimal).
    // Bit000-063: b1=0, b2=63 ⇒ i1=0, i2=7, f1=0, f2=7 (full 8 bytes,
    // no masking, no shift-down). val = 0xFFFFFFFFFFFFFFFF.
    let data = [0xFFu8; 8];
    let got = extract_no_format("Bit000-063", &data)
      .expect("tag must be emitted for an 8-byte all-0xFF field");
    assert_eq!(
      got,
      TagValue::Str("18446744073709551615".into()),
      "u64::MAX must be the exact decimal (Perl oracle: 18446744073709551615), \
       not -1 (the old u64→i64 sign-flip)"
    );
    // Serializer: the number gate quotes ≥16-digit integers, exactly as
    // ExifTool's EscapeJSON (line 3809) emits a big unsigned int.
    let mut m = Metadata::new("x.test");
    m.push(Group::new("Test", "Test"), "Field", got);
    let json = to_exiftool_json(&m);
    assert!(
      json.contains("\"Test:Field\": \"18446744073709551615\""),
      "≥16-digit value must be quoted by the number gate: {json}"
    );
    assert!(
      !json.contains("\"Test:Field\": -1"),
      "must NOT be -1 (the old u64→i64 sign-flip): {json}"
    );
  }

  #[test]
  fn no_format_9_byte_all_ff_promotes_to_nv_format_g() {
    // Oracle (bundled Perl, re-derived 2026-05-19):
    //   perl -e 'my @b = (0xFF) x 9; my $v=0; foreach (@b){$v=$v*256+$_} print $v'
    //   ⇒ 4.72236648286965e+21 (Perl NV `%.15g` stringification)
    // 9 bytes of 0xFF: the 9th `*256 + 0xFF` overflows u64 ⇒ promotes
    // to NV (f64); from there on, accumulation is in f64. Final
    // stringification: format_g(f64, 15) — Perl's default `%.15g`.
    // Bit000-071: b1=0, b2=71 ⇒ i1=0, i2=8, f1=0, f2=7 (full 9 bytes).
    let data = [0xFFu8; 9];
    let got = extract_no_format("Bit000-071", &data)
      .expect("tag must be emitted for a 9-byte all-0xFF field");
    assert_eq!(
      got,
      TagValue::Str("4.72236648286965e+21".into()),
      "9-byte all-0xFF promotes to NV ⇒ Perl `%.15g` (oracle: 4.72236648286965e+21)"
    );
    // Number gate accepts scientific: emitted bare (not quoted), like
    // bundled `perl exiftool -j` emits an NV. The gate's regex
    // (ExifTool.pm:3809) accepts `4.72236648286965e+21`.
    let mut m = Metadata::new("x.test");
    m.push(Group::new("Test", "Test"), "Field", got);
    let json = to_exiftool_json(&m);
    assert!(
      json.contains("\"Test:Field\": 4.72236648286965e+21"),
      "NV-string must pass the number gate as a bare JSON number: {json}"
    );
  }

  #[test]
  fn no_format_16_byte_all_ff_is_nv_format_g_oracle() {
    // Oracle (bundled Perl, re-derived 2026-05-19):
    //   perl -e 'my @b = (0xFF) x 16; my $v=0; foreach (@b){$v=$v*256+$_} print $v'
    //   ⇒ 3.40282366920938e+38 (Perl NV `%.15g`)
    // 16 bytes of 0xFF: promotes to NV around the 9th byte; final value
    // ≈ 2^128 - 1 lost to f64 precision (Perl loses it too).
    // Bit000-127: b1=0, b2=127 ⇒ i1=0, i2=15, f1=0, f2=7 (full 16 bytes).
    let data = [0xFFu8; 16];
    let got = extract_no_format("Bit000-127", &data)
      .expect("tag must be emitted for a 16-byte all-0xFF field");
    assert_eq!(
      got,
      TagValue::Str("3.40282366920938e+38".into()),
      "16-byte all-0xFF NV (oracle: 3.40282366920938e+38)"
    );
  }

  #[test]
  fn no_format_17_byte_no_longer_skipped_emits_nv() {
    // The old `>16-byte` guard artificially dropped these spans; Perl
    // simply keeps multiplying in NV (precision loss is acceptable
    // because Perl loses it too). The new path emits a faithful NV.
    // Bit000-135: b1=0, b2=135 ⇒ i1=0, i2=16, span=17.
    // Oracle (bundled Perl):
    //   perl -e 'my @b = (0xFF) x 17; my $v=0; foreach (@b){$v=$v*256+$_} print $v'
    //   ⇒ 8.71122859317602e+40
    let data = [0xFFu8; 17];
    let got = extract_no_format("Bit000-135", &data)
      .expect("tag must be emitted (no `>16-byte` artificial drop)");
    assert_eq!(
      got,
      TagValue::Str("8.71122859317602e+40".into()),
      "17-byte all-0xFF NV (oracle: 8.71122859317602e+40 — no artificial drop)"
    );
  }

  #[test]
  fn no_format_small_value_is_i64_and_emitted_bare() {
    // Prove the common (≤ i64::MAX) path is byte-exact unchanged.
    // 5-byte buffer: Bit032-047 = bytes[4..=5], f1=0,f2=7 => val = 0xFFFF = 65535.
    // val ≤ i64::MAX => TagValue::I64(65535); ≤15 digits => bare number.
    let mut data = [0u8; 6];
    data[4] = 0xFF;
    data[5] = 0xFF;
    let got = extract_no_format("Bit032-047", &data).expect("tag must be emitted");
    assert_eq!(
      got,
      TagValue::I64(65535),
      "value fitting in i64 must stay TagValue::I64"
    );
    let mut m = Metadata::new("x.test");
    m.push(Group::new("Test", "Test"), "Field", got);
    let json = to_exiftool_json(&m);
    assert!(
      json.contains("\"Test:Field\": 65535"),
      "≤15-digit i64 must be emitted bare (not quoted): {json}"
    );
    assert!(
      !json.contains("\"65535\""),
      "must NOT be a quoted string: {json}"
    );
  }

  #[test]
  fn no_format_8_byte_i64_max_split_boundary() {
    // Pins the u64-mode i64::MAX / i64::MAX+1 representation-split (D5).
    //
    //   - val == i64::MAX (9223372036854775807) => TagValue::I64
    //   - val == i64::MAX + 1 (9223372036854775808) => TagValue::Str(exact decimal)
    //
    // Both stay in u64 mode (fit u64). Bit000-063: b1=0, b2=63 => i1=0,
    // i2=7, f1=0, f2=7 (full 8 bytes, no masking, no shift-down).
    //   i64::MAX      = 0x7FFF_FFFF_FFFF_FFFF => bytes [7F FF FF FF FF FF FF FF]
    //   i64::MAX + 1  = 0x8000_0000_0000_0000 => bytes [80 00 00 00 00 00 00 00]
    //
    // Serializer gate (EscapeJSON line 3809): both 19-digit values are
    // >= 16 digits so the gate QUOTES them, exactly as the bundled Perl
    // regex (verified in `i64_runs_through_exiftool_escapejson_number_gate`).

    // -- i64::MAX side: val <= i64::MAX => TagValue::I64 --
    let data_max = [0x7Fu8, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF];
    let got_max =
      extract_no_format("Bit000-063", &data_max).expect("tag must be emitted for i64::MAX bytes");
    assert_eq!(
      got_max,
      TagValue::I64(9_223_372_036_854_775_807),
      "i64::MAX must be TagValue::I64(9223372036854775807)"
    );
    let mut m_max = Metadata::new("x.test");
    m_max.push(Group::new("Test", "Test"), "Field", got_max);
    let json_max = to_exiftool_json(&m_max);
    assert!(
      json_max.contains("\"Test:Field\": \"9223372036854775807\""),
      "i64::MAX (19 digits) must be quoted by the number gate: {json_max}"
    );

    // -- i64::MAX+1 side: val > i64::MAX => TagValue::Str(exact decimal) --
    let data_over = [0x80u8, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00];
    let got_over = extract_no_format("Bit000-063", &data_over)
      .expect("tag must be emitted for i64::MAX+1 bytes");
    assert_eq!(
      got_over,
      TagValue::Str("9223372036854775808".into()),
      "i64::MAX+1 must be TagValue::Str(\"9223372036854775808\") (no sign-flip)"
    );
    let mut m_over = Metadata::new("x.test");
    m_over.push(Group::new("Test", "Test"), "Field", got_over);
    let json_over = to_exiftool_json(&m_over);
    assert!(
      json_over.contains("\"Test:Field\": \"9223372036854775808\""),
      "i64::MAX+1 (19 digits) must be quoted by the number gate: {json_over}"
    );
  }
}
