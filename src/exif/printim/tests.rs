use super::*;

/// Build a minimal valid PrintIM block: the `"PrintIM"` header, a NUL, the
/// 4-byte ASCII version at offset 8, two reserved bytes, and the `$num` count at
/// offset 14, followed by `num * 6` record bytes (so the size check passes).
fn block(version: &[u8; 4], num: u16, order: ByteOrder) -> Vec<u8> {
  let mut b = Vec::new();
  b.extend_from_slice(b"PrintIM\0"); // 0..8
  b.extend_from_slice(version); // 8..12
  b.extend_from_slice(&[0, 0]); // 12..14 reserved
  b.extend_from_slice(&match order {
    ByteOrder::Little => num.to_le_bytes(),
    ByteOrder::Big => num.to_be_bytes(),
  }); // 14..16
  b.extend(std::iter::repeat_n(0u8, (num as usize) * 6)); // records
  b
}

#[test]
fn parses_the_four_ascii_version_bytes() {
  let b = block(b"0300", 33, ByteOrder::Little);
  assert_eq!(parse_version(&b, ByteOrder::Little).as_deref(), Ok("0300"));
}

#[test]
fn version_is_byte_order_independent() {
  // The version bytes are read from the fixed 8..12 ASCII span regardless of
  // the inherited TIFF order (only the `$num` count is order-sensitive).
  let b = block(b"0250", 5, ByteOrder::Big);
  assert_eq!(parse_version(&b, ByteOrder::Big).as_deref(), Ok("0250"));
}

#[test]
fn rejects_a_block_without_the_printim_header() {
  // `unless substr($$dataPt, $offset, 7) eq 'PrintIM'` ⇒ 'Invalid PrintIM
  // header' (PrintIM.pm:60), no version. `$et->Warn(msg)` with NO `,1` flag ⇒
  // a NORMAL (level-0) warning.
  let mut b = block(b"0300", 1, ByteOrder::Little);
  b[0] = b'X'; // corrupt the "PrintIM" header
  assert_eq!(
    parse_version(&b, ByteOrder::Little),
    Err(PrintImError::Normal("Invalid PrintIM header"))
  );
}

#[test]
fn rejects_an_empty_block_as_minor() {
  // `return 0 unless $size` ⇒ `$et->Warn('Empty PrintIM data', 1)`
  // (PrintIM.pm:52) — the trailing `1` is the `sub Warn` MINOR flag, so this
  // surfaces as a `[minor]` warning (the ONLY PrintIM minor guard).
  let err = parse_version(&[], ByteOrder::Little).unwrap_err();
  assert_eq!(err, PrintImError::Minor("Empty PrintIM data"));
  assert!(
    err.is_minor(),
    "the empty-block guard is `Warn(.., 1)` = minor"
  );
  assert_eq!(err.message(), "Empty PrintIM data");
}

#[test]
fn rejects_a_block_of_15_or_fewer_bytes() {
  // `unless $size > 15` ⇒ 'Bad PrintIM data' (PrintIM.pm:56) — exactly 15 bytes
  // is too short. `$et->Warn(msg)` with no flag ⇒ a NORMAL warning.
  let short = b"PrintIM\x000300\0\0\0";
  assert_eq!(short.len(), 15);
  let err = parse_version(short, ByteOrder::Little).unwrap_err();
  assert_eq!(err, PrintImError::Normal("Bad PrintIM data"));
  assert!(
    !err.is_minor(),
    "the bad-data guard is `Warn(msg)` = normal"
  );
}

#[test]
fn toggles_byte_order_when_the_count_overflows_the_block() {
  // A `$num` written in the OPPOSITE order makes the first size check fail;
  // `ProcessPrintIM` toggles and re-reads. Here a real `num=2` (12 record
  // bytes) is written big-endian but the inherited order is little-endian: the
  // little-endian read of `00 02` is `0x0200` (512) ⇒ size check fails ⇒ toggle
  // to big-endian reads `2` ⇒ passes. The version still parses.
  let b = block(b"0300", 2, ByteOrder::Big);
  assert_eq!(parse_version(&b, ByteOrder::Little).as_deref(), Ok("0300"));
}

#[test]
fn rejects_a_count_too_large_in_both_orders() {
  // A `$num` so large the `16 + num*6` size requirement fails in BOTH orders
  // (a 16-byte block claiming 0xffff records) ⇒ 'Bad PrintIM size' (PrintIM.pm:
  // 70), no version. `$et->Warn(msg)` with no flag ⇒ a NORMAL warning.
  let mut b = Vec::new();
  // "PrintIM" + NUL, version "0300" (8..12), two reserved, count 0xffff (14..16).
  b.extend_from_slice(b"PrintIM\x000300\0\0\xff\xff");
  assert_eq!(b.len(), 16);
  let err = parse_version(&b, ByteOrder::Little).unwrap_err();
  assert_eq!(err, PrintImError::Normal("Bad PrintIM size"));
  assert!(
    !err.is_minor(),
    "the bad-size guard is `Warn(msg)` = normal"
  );
}
