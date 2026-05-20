//! Faithful port of `DecodeString` (ID3.pm:1054-1092) and `UnSyncSafe`
//! (ID3.pm:1098-1106).

/// Convert a sync-safe 28-bit integer encoded as a 32-bit big-endian value
/// (every 8th bit forced to zero) into the actual number. Faithful port of
/// `UnSyncSafe` (ID3.pm:1098-1106):
///
/// ```perl
/// sub UnSyncSafe($) {
///     my $val = shift;
///     return undef if $val & 0x80808080;     # any high bit set is invalid
///     return ($val & 0x0000007f)
///         | (($val & 0x00007f00) >> 1)
///         | (($val & 0x007f0000) >> 2)
///         | (($val & 0x7f000000) >> 3);
/// }
/// ```
#[must_use]
pub const fn unsync_safe(val: u32) -> Option<u32> {
  if val & 0x8080_8080 != 0 {
    return None;
  }
  Some(
    (val & 0x0000_007f)
      | ((val & 0x0000_7f00) >> 1)
      | ((val & 0x007f_0000) >> 2)
      | ((val & 0x7f00_0000) >> 3),
  )
}

/// Faithful port of `DecodeString` (ID3.pm:1054-1092). Returns a list of
/// strings (matching Perl `wantarray`) — callers that want the joined
/// form invoke `decode_string_joined`. Encoding semantics:
///
/// - `enc == 0` (`ISO-8859-1`) or `enc == 3` (`UTF-8`): strip trailing
///   nulls, then split on remaining null bytes; decode each part.
/// - `enc == 1` (`UTF-16` with optional BOM): split on word-aligned `\0\0`;
///   strip BOM (FFFE→II, FEFF→MM); decode each as UTF-16 in that order.
/// - `enc == 2` (`UTF-16BE`): same as enc==1 but force MM byte order.
/// - any other: returns `"<Unknown encoding $enc> $val"` (single element).
///
/// `enc = None` ⇒ Perl `unless defined $enc, $enc = unpack('C', $val); $val
/// = substr($val, 1)` — the FIRST BYTE of `val` is the encoding (the
/// canonical ID3v2 text-frame entry point).
#[must_use]
pub fn decode_string(val: &[u8], enc: Option<u8>) -> Vec<String> {
  if val.is_empty() {
    return vec![String::new()];
  }
  let (enc, mut bytes): (u8, &[u8]) = match enc {
    Some(e) => (e, val),
    None => (val[0], &val[1..]),
  };
  match enc {
    0 | 3 => {
      // Strip trailing null padding (ID3.pm:1064 `$val =~ s/\0+$//`).
      while !bytes.is_empty() && *bytes.last().unwrap() == 0 {
        bytes = &bytes[..bytes.len() - 1];
      }
      // Split on remaining \0 (ID3.pm:1066 `split "\0", $val`); each part
      // is decoded per `enc` (Latin1 vs UTF8). `split "\0"` in Perl drops
      // trailing empty fields.
      let mut out = Vec::new();
      let mut cur = Vec::new();
      for &b in bytes {
        if b == 0 {
          out.push(decode_one(&cur, enc));
          cur.clear();
        } else {
          cur.push(b);
        }
      }
      if !cur.is_empty() {
        out.push(decode_one(&cur, enc));
      }
      if out.is_empty() {
        out.push(String::new());
      }
      out
    }
    1 | 2 => {
      // UTF-16: split on word-aligned `\0\0`.
      // ID3.pm:1070-1085 — start with BOM=FEFF (MM), accept FEFF/FFFE.
      let force_be = enc == 2;
      let mut out: Vec<String> = Vec::new();
      let mut bom_be = true; // FEFF = MM = big-endian. enc==2 keeps this.
      let mut rest = bytes;
      loop {
        // Find first word-aligned `\0\0`.
        let mut split_at: Option<usize> = None;
        let mut i = 0usize;
        while i + 1 < rest.len() {
          if rest[i] == 0 && rest[i + 1] == 0 {
            split_at = Some(i);
            break;
          }
          i += 2;
        }
        let (v, next) = match split_at {
          Some(p) => (&rest[..p], &rest[p + 2..]),
          None => {
            if rest.len() < 2 {
              break;
            }
            // No trailing null pair; consume the rest, then break.
            let v = rest;
            rest = &[];
            (v, rest)
          }
        };
        // BOM detection (only for enc==1).
        let (be, payload) = if !force_be && v.len() >= 2 {
          let mark = [v[0], v[1]];
          if mark == [0xfe, 0xff] {
            bom_be = true;
            (true, &v[2..])
          } else if mark == [0xff, 0xfe] {
            bom_be = false;
            (false, &v[2..])
          } else {
            (bom_be, v)
          }
        } else {
          (true /* force MM */, v)
        };
        out.push(decode_utf16(payload, be));
        if split_at.is_none() {
          break;
        }
        rest = next;
        if rest.is_empty() {
          break;
        }
      }
      if out.is_empty() {
        out.push(String::new());
      }
      out
    }
    other => {
      // Strip trailing nulls then emit the "<Unknown encoding $enc> $val"
      // form (ID3.pm:1086-1088). `$val` is the raw bytes after the enc
      // byte (lossy UTF-8 keeps valid sequences exact).
      let mut bytes = bytes.to_vec();
      while bytes.last() == Some(&0) {
        bytes.pop();
      }
      vec![format!(
        "<Unknown encoding {other}> {}",
        String::from_utf8_lossy(&bytes)
      )]
    }
  }
}

/// `decode_string` then `join "/", @vals` (ID3.pm:1091). Used by text
/// frames which want the joined form (most callers).
#[must_use]
pub fn decode_string_joined(val: &[u8], enc: Option<u8>) -> String {
  decode_string(val, enc).join("/")
}

fn decode_one(v: &[u8], enc: u8) -> String {
  match enc {
    0 => {
      // ISO-8859-1 → UTF-8 (each byte = Unicode code point).
      let mut s = String::with_capacity(v.len());
      for &b in v {
        s.push(b as char);
      }
      s
    }
    3 => {
      // UTF-8 (lossy).
      String::from_utf8_lossy(v).into_owned()
    }
    _ => unreachable!("decode_one only called with enc 0 or 3"),
  }
}

fn decode_utf16(v: &[u8], be: bool) -> String {
  let mut units: Vec<u16> = Vec::with_capacity(v.len() / 2);
  let mut i = 0;
  while i + 1 < v.len() {
    let u = if be {
      u16::from_be_bytes([v[i], v[i + 1]])
    } else {
      u16::from_le_bytes([v[i], v[i + 1]])
    };
    units.push(u);
    i += 2;
  }
  // Strip trailing 0 code units (Perl strips trailing nulls per encoding).
  while units.last() == Some(&0) {
    units.pop();
  }
  String::from_utf16_lossy(&units)
}

#[cfg(test)]
mod tests {
  use super::*;

  #[test]
  fn unsync_safe_basic() {
    // 0x40 = 64 → 64 (no-op, all high bits clear).
    assert_eq!(unsync_safe(0x0000_0040), Some(64));
    // 0x80 in byte 0 = MSB set → invalid.
    assert_eq!(unsync_safe(0x0000_0080), None);
    // Multi-byte: 0x00_00_01_7f → 0x7f | (0x01 << 7) = 0xff.
    assert_eq!(unsync_safe(0x0000_017f), Some(0xff));
    // The example sync-safe encoding of 391 (=0x187):
    // Binary 391 = 110000111 → sync-safe split: 00000011 00000111
    // → bytes `0x00 0x00 0x03 0x07` → 391 = (0x03<<7) | 0x07 = 391.
    assert_eq!(unsync_safe(0x0000_0307), Some(391));
  }

  #[test]
  fn decode_string_latin1_enc0_strips_trailing_nulls() {
    // enc=0 ISO-8859-1; one part.
    let v = b"\x00Hello\x00\x00";
    let parts = decode_string(v, None);
    assert_eq!(parts, vec!["Hello".to_string()]);
  }

  #[test]
  fn decode_string_split_on_internal_null() {
    // enc=3 UTF-8; two parts separated by null.
    let mut v: Vec<u8> = vec![0x03];
    v.extend_from_slice(b"foo\x00bar");
    let parts = decode_string(&v, None);
    assert_eq!(parts, vec!["foo".to_string(), "bar".to_string()]);
  }

  #[test]
  fn decode_string_utf16_with_bom() {
    // enc=1 UTF-16 with FEFF BOM: encode "Hi" as MM.
    let v: Vec<u8> = vec![0x01, 0xfe, 0xff, 0x00, b'H', 0x00, b'i'];
    let parts = decode_string(&v, None);
    assert_eq!(parts, vec!["Hi".to_string()]);
  }

  #[test]
  fn decode_string_utf16be_enc2() {
    // enc=2 forces MM. "ok" = 00 6f 00 6b.
    let v: Vec<u8> = vec![0x02, 0x00, b'o', 0x00, b'k'];
    let parts = decode_string(&v, None);
    assert_eq!(parts, vec!["ok".to_string()]);
  }

  #[test]
  fn decode_string_unknown_encoding() {
    let v: Vec<u8> = vec![0x05, b'x', b'y'];
    let parts = decode_string(&v, None);
    assert_eq!(parts, vec!["<Unknown encoding 5> xy".to_string()]);
  }

  #[test]
  fn decode_string_empty_input_yields_empty_string() {
    assert_eq!(decode_string(&[], None), vec![String::new()]);
  }

  #[test]
  fn decode_string_joined_uses_slash_separator() {
    // ID3.pm:1091 `join('/', @vals)`.
    let mut v: Vec<u8> = vec![0];
    v.extend_from_slice(b"a\x00b\x00c");
    assert_eq!(decode_string_joined(&v, None), "a/b/c");
  }
}
