//! The per-format tag-table abstraction. Each ported ExifTool module supplies
//! its own static `TagTable`; the shared `convert` runtime interprets these.

use crate::value::TagValue;

/// A value-stage conversion (ExifTool `ValueConv`). `Func` is a faithful Rust
/// transliteration of the Perl expression.
#[derive(Clone, Copy, derive_more::IsVariant, derive_more::Unwrap, derive_more::TryUnwrap)]
#[unwrap(ref, ref_mut)]
#[try_unwrap(ref, ref_mut)]
pub enum ValueConv {
  /// No value conversion.
  None,
  /// Pure transformation of the raw value.
  Func(fn(&TagValue) -> TagValue),
}

/// A single value in an ExifTool hash `PrintConv` (the right-hand side of a
/// `key => value` pair). ExifTool hash PrintConvs map integer keys to arbitrary
/// Perl scalars: some are strings (e.g. `'5.1'`), some are bare numbers (e.g.
/// AAC.pm `Channels` maps `2 => 2`, which `exiftool -j` emits as the JSON
/// number `2`, not the string `"2"`). This enum lets the static tables carry
/// the faithful scalar type so the serializer reproduces ExifTool byte-for-byte.
///
/// `F64` is included for completeness with ExifTool hash values that are bare
/// floats; like [`TagValue`] it therefore derives `PartialEq` only (no `Eq`).
#[derive(
  Debug, Clone, Copy, PartialEq, derive_more::IsVariant, derive_more::Unwrap, derive_more::TryUnwrap,
)]
#[unwrap(ref, ref_mut)]
#[try_unwrap(ref, ref_mut)]
pub enum PrintValue {
  /// A string display value (e.g. ExifTool `1 => 'Horizontal (normal)'`).
  Str(&'static str),
  /// An integer display value (e.g. ExifTool `2 => 2`), emitted as a JSON
  /// number.
  I64(i64),
  /// A floating-point display value, emitted as a JSON number.
  F64(f64),
}

/// A faithful model of an ExifTool *hash* `PrintConv` — `ref $conv eq 'HASH'`
/// (`ExifTool.pm:3603`). A single Perl conv hash can simultaneously carry
/// plain `key => value` entries, a `BITMASK => {…}` sub-hash, and an `OTHER`
/// callback; ExifTool consults them in a fixed order
/// (`ExifTool.pm:3603-3624`). `Image::ExifTool::QuickTime::TrackProperty`
/// (`QuickTime.pm:2627`) proves a single conv hash with **both** a direct key
/// (`0 => 'No presentation'`) **and** `BITMASK`, so these are independent
/// optional fields, not alternatives.
///
/// All fields are `'static` references / `Option` of `Copy` types / a `fn`
/// pointer, so `PrintConvHash` is itself `Copy` — required because the
/// [`PrintConv`] enum is `Copy`.
#[derive(Clone, Copy)]
pub struct PrintConvHash {
  direct: &'static [(&'static str, PrintValue)],
  bitmask: Option<&'static [(u8, &'static str)]>,
  other: Option<fn(&TagValue) -> Option<TagValue>>,
}

impl PrintConvHash {
  /// Construct a hash PrintConv from its direct `%$conv` entries (minus
  /// `BITMASK`/`OTHER`), optional `$$conv{BITMASK}` (bit-position → name),
  /// and optional `$$conv{OTHER}` callback (ExifTool `&{$$conv{OTHER}}(
  /// $val, undef, $conv)` — fallible: returning `None` ≡ Perl `undef`,
  /// which falls through to the `Unknown` fallback, `ExifTool.pm:3616`).
  #[must_use]
  pub const fn new(
    direct: &'static [(&'static str, PrintValue)],
    bitmask: Option<&'static [(u8, &'static str)]>,
    other: Option<fn(&TagValue) -> Option<TagValue>>,
  ) -> Self {
    Self {
      direct,
      bitmask,
      other,
    }
  }

  /// A hash PrintConv with only direct `key => value` entries (no
  /// `BITMASK`, no `OTHER`) — the common case (e.g. EXIF `Orientation`,
  /// `AIFF.pm` `CompressionType`).
  #[must_use]
  pub const fn direct(entries: &'static [(&'static str, PrintValue)]) -> Self {
    Self {
      direct: entries,
      bitmask: None,
      other: None,
    }
  }

  /// The direct `%$conv` entries (Perl hash keys are strings; the
  /// post-ValueConv `$val` is stringified for `$$conv{$val}`,
  /// `ExifTool.pm:3605`).
  #[must_use]
  pub const fn direct_entries(&self) -> &'static [(&'static str, PrintValue)] {
    self.direct
  }

  /// `$$conv{BITMASK}` if present: bit-position → decoded name, fed to
  /// `DecodeBits` (`ExifTool.pm:3607`).
  #[must_use]
  pub const fn bitmask(&self) -> Option<&'static [(u8, &'static str)]> {
    self.bitmask
  }

  /// `$$conv{OTHER}` if present: ExifTool's alternate conversion routine
  /// (`ExifTool.pm:3610-3615`), modelled as a fallible Rust fn.
  #[must_use]
  pub const fn other(&self) -> Option<fn(&TagValue) -> Option<TagValue>> {
    self.other
  }
}

/// A print-stage conversion (ExifTool `PrintConv`).
#[derive(Clone, Copy, derive_more::IsVariant, derive_more::Unwrap, derive_more::TryUnwrap)]
#[unwrap(ref, ref_mut)]
#[try_unwrap(ref, ref_mut)]
pub enum PrintConv {
  /// No print conversion (value passed through).
  None,
  /// A Perl *hash* PrintConv (`ref $conv eq 'HASH'`, `ExifTool.pm:3603`):
  /// direct **string**-keyed entries plus optional `BITMASK`/`OTHER`.
  /// ExifTool indexes the direct sub-hash with `$$conv{$val}`
  /// (`ExifTool.pm:3605`); Perl hash keys are strings, so the
  /// post-ValueConv value is *stringified* for the lookup. This faithfully
  /// subsumes the integer case — e.g. EXIF `Orientation` is keyed `"1"`,
  /// `"3"`, … — and the many string-keyed tables (e.g. `AIFF.pm`
  /// `CompressionType`: `NONE`, `sowt`, `ULAW`, …). The value may be a
  /// string or a number, mirroring ExifTool exactly.
  Hash(PrintConvHash),
  /// Arbitrary transliterated conversion to a display value.
  Func(fn(&TagValue) -> TagValue),
}

/// Definition of one tag within a table.
pub struct TagDef {
  name: &'static str,
  group1: &'static str,
  value_conv: ValueConv,
  print_conv: PrintConv,
  print_hex: bool,
  bits_per_word: Option<u8>,
}

impl TagDef {
  /// Construct a `TagDef` with the given name, group1, value conversion, and
  /// print conversion. `PrintHex` defaults `false` and `BitsPerWord`
  /// defaults `None` — exactly as a Perl tagInfo hash without those keys
  /// (most tags); set them with [`TagDef::with_print_hex`] /
  /// [`TagDef::with_bits_per_word`].
  #[must_use]
  pub const fn new(
    name: &'static str,
    group1: &'static str,
    value_conv: ValueConv,
    print_conv: PrintConv,
  ) -> Self {
    Self {
      name,
      group1,
      value_conv,
      print_conv,
      print_hex: false,
      bits_per_word: None,
    }
  }

  /// Set the `$$tagInfo{PrintHex}` flag (`ExifTool.pm:3617`). When set, an
  /// unmapped *integer* value under a `PrintConv` becomes
  /// `Unknown (0x%x)` instead of `Unknown (%s)` (e.g. `RIFF.pm:693`,
  /// `ASF.pm:451`, `Matroska.pm:270`).
  #[must_use]
  pub const fn with_print_hex(mut self, print_hex: bool) -> Self {
    self.print_hex = print_hex;
    self
  }

  /// Set `$$tagInfo{BitsPerWord}` (`ExifTool.pm:3607` → `DecodeBits`'s 3rd
  /// arg). `None` ⇒ `DecodeBits` default of 32 (`ExifTool.pm:6377`).
  #[must_use]
  pub const fn with_bits_per_word(mut self, bits_per_word: u8) -> Self {
    self.bits_per_word = Some(bits_per_word);
    self
  }

  /// Tag name as ExifTool reports it.
  #[must_use]
  pub const fn name(&self) -> &'static str {
    self.name
  }

  /// ExifTool family-1 group (the `Group1:` JSON prefix).
  #[must_use]
  pub const fn group1(&self) -> &'static str {
    self.group1
  }

  /// Value-stage conversion.
  #[must_use]
  pub const fn value_conv(&self) -> ValueConv {
    self.value_conv
  }

  /// Print-stage conversion.
  #[must_use]
  pub const fn print_conv(&self) -> PrintConv {
    self.print_conv
  }

  /// `$$tagInfo{PrintHex}` (`ExifTool.pm:3617`); `false` when the Perl
  /// tagInfo omits the key.
  #[must_use]
  pub const fn print_hex(&self) -> bool {
    self.print_hex
  }

  /// `$$tagInfo{BitsPerWord}` (`ExifTool.pm:3607`); `None` ⇒ `DecodeBits`
  /// default of 32 (`ExifTool.pm:6377`).
  #[must_use]
  pub const fn bits_per_word(&self) -> Option<u8> {
    self.bits_per_word
  }
}

/// An ExifTool tag-table key. ExifTool tag tables are Perl hashes whose keys
/// are opaque scalars: most are numbers (e.g. EXIF `0x0112`), but many modules
/// key by **strings** instead — e.g. the bundled `Image::ExifTool::AAC::Main`
/// uses `'Bit016-017'`, `'Bit018-021'`, `'Bit023-025'` and `Encoder`
/// (`lib/Image/ExifTool/AAC.pm`). `TagId` carries that faithful key type so a
/// ported table can be looked up exactly as ExifTool indexes its hash.
///
/// Both variants are `Copy` (`i64` / `&'static str`), so `TagId` is `Copy`,
/// `Eq` and `Hash`.
#[derive(
  Debug,
  Clone,
  Copy,
  PartialEq,
  Eq,
  Hash,
  derive_more::IsVariant,
  derive_more::Unwrap,
  derive_more::TryUnwrap,
)]
#[unwrap(ref, ref_mut)]
#[try_unwrap(ref, ref_mut)]
pub enum TagId {
  /// A numeric tag id (e.g. EXIF `0x0112`).
  Int(i64),
  /// A string tag id (e.g. AAC `"Bit016-017"`, `"Encoder"`).
  Str(&'static str),
}

/// A static per-format tag table: family-0 group + (tag id → def) lookup fn.
pub struct TagTable {
  group0: &'static str,
  get: fn(id: TagId) -> Option<&'static TagDef>,
}

impl TagTable {
  /// Construct a `TagTable` with the given family-0 group and lookup function.
  #[must_use]
  pub const fn new(group0: &'static str, get: fn(TagId) -> Option<&'static TagDef>) -> Self {
    Self { group0, get }
  }

  /// ExifTool family-0 group for tags from this table.
  #[must_use]
  pub const fn group0(&self) -> &'static str {
    self.group0
  }

  /// Resolve an opaque ([`TagId`]) tag id — numeric or string — to its
  /// definition, exactly as ExifTool indexes its tag-table hash.
  #[must_use]
  pub const fn get(&self) -> fn(TagId) -> Option<&'static TagDef> {
    self.get
  }
}

#[cfg(test)]
mod tests {
  use super::*;

  // ExifTool keys the PrintConv hash by the stringified `$val`
  // (`$$conv{$val}`, ExifTool.pm:3603), so the EXIF `Orientation` integer
  // entries are string keys `"1"`, `"3"`, … exactly as Perl indexes them.
  static ORIENTATION: TagDef = TagDef::new(
    "Orientation",
    "IFD0",
    ValueConv::None,
    PrintConv::Hash(PrintConvHash::direct(&[
      ("1", PrintValue::Str("Horizontal (normal)")),
      ("3", PrintValue::Str("Rotate 180")),
    ])),
  );

  fn get(id: TagId) -> Option<&'static TagDef> {
    match id {
      TagId::Int(0x0112) => Some(&ORIENTATION),
      _ => None,
    }
  }

  #[test]
  fn table_lookup_resolves_def() {
    let t = TagTable::new("EXIF", get);
    let d = (t.get())(TagId::Int(0x0112)).expect("orientation def");
    assert_eq!(d.name(), "Orientation");
    assert!((t.get())(TagId::Int(0x9999)).is_none());
    // A string id never matches this numeric-keyed table.
    assert!((t.get())(TagId::Str("0x0112")).is_none());
    match d.print_conv() {
      PrintConv::Hash(h) => {
        assert_eq!(
          h.direct_entries()[0],
          ("1", PrintValue::Str("Horizontal (normal)"))
        );
        assert!(h.bitmask().is_none());
        assert!(h.other().is_none());
      }
      _ => panic!("expected Hash print_conv"),
    }
    // New `TagDef` props default off (Perl tagInfo without the keys).
    assert!(!d.print_hex());
    assert_eq!(d.bits_per_word(), None);
    // D9 set still holds on the (still non-unit) `PrintConv` enum.
    assert!(d.print_conv().is_hash());
    assert!(!d.print_conv().is_none());
  }

  #[test]
  fn string_keyed_table_dispatch() {
    // Faithful to `Image::ExifTool::AAC::Main`, whose hash keys are
    // STRINGS: `'Bit016-017'` → ProfileType, `Encoder` → Encoder
    // (lib/Image/ExifTool/AAC.pm). Proves `TagId::Str` dispatch works.
    static ENCODER: TagDef = TagDef::new("Encoder", "AAC", ValueConv::None, PrintConv::None);
    static PROFILE_TYPE: TagDef = TagDef::new(
      "ProfileType",
      "AAC",
      ValueConv::None,
      PrintConv::Hash(PrintConvHash::direct(&[
        ("0", PrintValue::Str("Main")),
        ("1", PrintValue::Str("Low Complexity")),
      ])),
    );

    fn aac_get(id: TagId) -> Option<&'static TagDef> {
      match id {
        TagId::Str("Encoder") => Some(&ENCODER),
        TagId::Str("Bit016-017") => Some(&PROFILE_TYPE),
        _ => None,
      }
    }

    let t = TagTable::new("AAC", aac_get);
    // Distinct string ids resolve to distinct defs.
    assert_eq!(
      (t.get())(TagId::Str("Encoder")).expect("encoder").name(),
      "Encoder"
    );
    assert_eq!(
      (t.get())(TagId::Str("Bit016-017")).expect("profile").name(),
      "ProfileType"
    );
    // Unknown string id, and ANY numeric id, miss this string-keyed table.
    assert!((t.get())(TagId::Str("Bit999")).is_none());
    assert!((t.get())(TagId::Int(0x0112)).is_none());
    assert!((t.get())(TagId::Int(0)).is_none());
    // TagId derive sanity (D9 set + Copy/Eq/Hash).
    assert!(TagId::Str("Encoder").is_str());
    assert!(!TagId::Str("Encoder").is_int());
    assert_eq!(TagId::Int(7).unwrap_int(), 7);
    assert_eq!(TagId::Str("x").try_unwrap_int().ok(), None);
  }

  #[test]
  fn print_value_carries_numeric_scalars() {
    // ExifTool hash PrintConvs can map to bare numbers (AAC Channels shape).
    static CHANNELS: TagDef = TagDef::new(
      "Channels",
      "AAC",
      ValueConv::None,
      PrintConv::Hash(PrintConvHash::direct(&[
        ("1", PrintValue::I64(1)),
        ("2", PrintValue::I64(2)),
      ])),
    );
    match CHANNELS.print_conv() {
      PrintConv::Hash(h) => {
        assert_eq!(h.direct_entries()[1], ("2", PrintValue::I64(2)));
        assert!(h.direct_entries()[1].1.is_i_64());
      }
      _ => panic!("expected Hash print_conv"),
    }
  }

  #[test]
  fn print_conv_hash_carries_direct_bitmask_and_other_simultaneously() {
    // `Image::ExifTool::QuickTime::TrackProperty` (QuickTime.pm:2627)
    // proves a single conv hash with BOTH a direct key
    // (`0 => 'No presentation'`) AND `BITMASK => { 0 => 'Main track' }`.
    fn other_cb(_v: &TagValue) -> Option<TagValue> {
      Some(TagValue::Str("from-OTHER".into()))
    }
    static QT_TRACKPROP: TagDef = TagDef::new(
      "TrackProperty",
      "QuickTime",
      ValueConv::None,
      PrintConv::Hash(PrintConvHash::new(
        &[("0", PrintValue::Str("No presentation"))],
        Some(&[(0, "Main track")]),
        Some(other_cb),
      )),
    );
    match QT_TRACKPROP.print_conv() {
      PrintConv::Hash(h) => {
        assert_eq!(
          h.direct_entries()[0],
          ("0", PrintValue::Str("No presentation"))
        );
        assert_eq!(h.bitmask(), Some(&[(0u8, "Main track")][..]));
        assert!(h.other().is_some());
      }
      _ => panic!("expected Hash print_conv"),
    }
  }

  #[test]
  fn tagdef_print_hex_and_bits_per_word_builders() {
    // `RIFF.pm:693` / `ASF.pm:451` / `Matroska.pm:270` set
    // `PrintHex => 1`; `BitsPerWord` is the optional `DecodeBits` 3rd arg.
    static T: TagDef = TagDef::new("E", "RIFF", ValueConv::None, PrintConv::None)
      .with_print_hex(true)
      .with_bits_per_word(16);
    assert!(T.print_hex());
    assert_eq!(T.bits_per_word(), Some(16));
    // Defaults remain off without the builders.
    static U: TagDef = TagDef::new("U", "X", ValueConv::None, PrintConv::None);
    assert!(!U.print_hex());
    assert_eq!(U.bits_per_word(), None);
  }
}
