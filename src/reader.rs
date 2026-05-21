//! A bounded, panic-free binary cursor over an in-memory buffer.

use crate::error::{Error, OutOfBounds, Result, UnexpectedEof};

/// A cursor over `&[u8]` with big/little-endian integer reads. Every read is
/// bounds-checked and returns `Err` instead of panicking (ExifTool never
/// aborts on truncated input — spec §3.3).
pub struct ByteReader<'a> {
  buf: &'a [u8],
  pos: usize,
}

macro_rules! read_int {
  ($name:ident, $ty:ty, $from:ident, $n:expr) => {
    /// Read a fixed-size integer.
    pub fn $name(&mut self) -> Result<$ty> {
      let b = self.read_bytes($n)?;
      let mut a = [0u8; $n];
      a.copy_from_slice(b);
      Ok(<$ty>::$from(a))
    }
  };
}

impl<'a> ByteReader<'a> {
  /// Wrap a buffer, positioned at byte 0.
  #[must_use]
  #[inline(always)]
  pub const fn new(buf: &'a [u8]) -> Self {
    Self { buf, pos: 0 }
  }

  /// Current byte offset.
  #[must_use]
  #[inline(always)]
  pub const fn position(&self) -> usize {
    self.pos
  }

  /// Total length of the underlying buffer.
  #[must_use]
  #[inline(always)]
  pub const fn len(&self) -> usize {
    self.buf.len()
  }

  /// True if the buffer is empty.
  #[must_use]
  #[inline(always)]
  pub const fn is_empty(&self) -> bool {
    self.buf.is_empty()
  }

  /// Bytes remaining after the cursor.
  #[must_use]
  #[inline(always)]
  pub const fn remaining(&self) -> usize {
    self.buf.len().saturating_sub(self.pos)
  }

  /// Move the cursor to an absolute offset (may equal `len()`).
  pub fn seek(&mut self, offset: usize) -> Result<()> {
    if offset > self.buf.len() {
      return Err(Error::OutOfBounds(OutOfBounds::new(offset, self.buf.len())));
    }
    self.pos = offset;
    Ok(())
  }

  /// Advance the cursor by `n` bytes.
  pub fn skip(&mut self, n: usize) -> Result<()> {
    let target = self
      .pos
      .checked_add(n)
      .ok_or(Error::OutOfBounds(OutOfBounds::new(
        usize::MAX,
        self.buf.len(),
      )))?;
    self.seek(target)
  }

  /// Borrow the next `n` bytes and advance.
  pub fn read_bytes(&mut self, n: usize) -> Result<&'a [u8]> {
    let end = self
      .pos
      .checked_add(n)
      .ok_or(Error::OutOfBounds(OutOfBounds::new(
        usize::MAX,
        self.buf.len(),
      )))?;
    if end > self.buf.len() {
      return Err(Error::UnexpectedEof(UnexpectedEof::new(
        n,
        self.remaining(),
      )));
    }
    let s = &self.buf[self.pos..end];
    self.pos = end;
    Ok(s)
  }

  /// Read one byte.
  pub fn u8(&mut self) -> Result<u8> {
    Ok(self.read_bytes(1)?[0])
  }

  read_int!(u16_be, u16, from_be_bytes, 2);
  read_int!(u16_le, u16, from_le_bytes, 2);
  read_int!(u32_be, u32, from_be_bytes, 4);
  read_int!(u32_le, u32, from_le_bytes, 4);
  read_int!(u64_be, u64, from_be_bytes, 8);
  read_int!(u64_le, u64, from_le_bytes, 8);
  read_int!(i16_be, i16, from_be_bytes, 2);
  read_int!(i32_be, i32, from_be_bytes, 4);
}

#[cfg(test)]
mod tests {
  use super::*;

  #[test]
  fn reads_be_and_le_then_eofs_cleanly() {
    let data = [0x00, 0x01, 0x02, 0x03];
    let mut r = ByteReader::new(&data);
    assert_eq!(r.u16_be().unwrap(), 0x0001);
    assert_eq!(r.u16_le().unwrap(), 0x0302);
    assert_eq!(r.position(), 4);
    assert_eq!(
      r.u8().unwrap_err(),
      Error::UnexpectedEof(UnexpectedEof::new(1, 0))
    );
  }

  #[test]
  fn seek_past_end_is_error_not_panic() {
    let mut r = ByteReader::new(&[1, 2, 3]);
    assert_eq!(
      r.seek(99).unwrap_err(),
      Error::OutOfBounds(OutOfBounds::new(99, 3))
    );
  }

  #[test]
  fn skip_overflow_is_error_not_panic() {
    let mut r = ByteReader::new(&[1, 2, 3]);
    r.seek(1).unwrap(); // pos = 1 (do not use skip to set up — it's under test)
    assert_eq!(
      r.skip(usize::MAX).unwrap_err(),
      Error::OutOfBounds(OutOfBounds::new(usize::MAX, 3))
    );
  }
}
