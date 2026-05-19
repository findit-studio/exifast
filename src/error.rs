//! Crate-wide error type.

use std::fmt;

/// The result type used throughout `exifast`.
pub type Result<T> = std::result::Result<T, Error>;

/// Payload for `Error::UnexpectedEof`: how many bytes were needed vs available.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct UnexpectedEof {
  needed: usize,
  available: usize,
}

impl UnexpectedEof {
  /// Construct an `UnexpectedEof` with the given byte counts.
  #[must_use]
  pub const fn new(needed: usize, available: usize) -> Self {
    Self { needed, available }
  }

  /// Number of bytes that were requested.
  #[must_use]
  pub const fn needed(&self) -> usize {
    self.needed
  }

  /// Number of bytes that were actually available.
  #[must_use]
  pub const fn available(&self) -> usize {
    self.available
  }
}

/// Payload for `Error::OutOfBounds`: the requested offset and the buffer length.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct OutOfBounds {
  offset: usize,
  len: usize,
}

#[allow(clippy::len_without_is_empty)]
impl OutOfBounds {
  /// Construct an `OutOfBounds` with the given offset and buffer length.
  #[must_use]
  pub const fn new(offset: usize, len: usize) -> Self {
    Self { offset, len }
  }

  /// The offset that was requested.
  #[must_use]
  pub const fn offset(&self) -> usize {
    self.offset
  }

  /// The total length of the buffer at the time of the error.
  #[must_use]
  pub const fn len(&self) -> usize {
    self.len
  }
}

/// Errors produced while reading, detecting, or serializing a file.
#[derive(
  Debug, PartialEq, Eq, derive_more::IsVariant, derive_more::Unwrap, derive_more::TryUnwrap,
)]
#[unwrap(ref, ref_mut)]
#[try_unwrap(ref, ref_mut)]
pub enum Error {
  /// A read attempted to go past the end of the available bytes.
  UnexpectedEof(UnexpectedEof),
  /// A seek/offset landed outside the buffer.
  OutOfBounds(OutOfBounds),
  /// The file type could not be determined.
  UnknownFileType,
}

impl fmt::Display for Error {
  fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
    match self {
      Error::UnexpectedEof(e) => write!(
        f,
        "unexpected end of data: needed {} bytes, {} available",
        e.needed(),
        e.available()
      ),
      Error::OutOfBounds(e) => {
        write!(f, "offset {} out of bounds (len {})", e.offset(), e.len())
      }
      Error::UnknownFileType => write!(f, "unknown file type"),
    }
  }
}

impl std::error::Error for Error {}

#[cfg(test)]
mod tests {
  use super::*;

  #[test]
  fn display_is_human_readable() {
    let e = Error::UnexpectedEof(UnexpectedEof::new(4, 1));
    assert_eq!(
      e.to_string(),
      "unexpected end of data: needed 4 bytes, 1 available"
    );
  }
}
