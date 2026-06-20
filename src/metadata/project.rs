//! The domain-projection trait (golden pattern **L2**).
//!
//! [`Project`] is the single seam that maps a faithful per-format `Meta`
//! (the L1 parse layer — e.g. [`ExifMeta`](crate::exif::ExifMeta),
//! [`QuickTimeMeta`](crate::metadata::QuickTimeMeta)) into the normalized,
//! format-agnostic [`MediaMetadata`] aggregate (the L2 domain layer). It is
//! the lib-first "give me camera / lens / GPS regardless of container"
//! payoff: a caller indexing a media library calls `.project()` on whatever
//! `Meta` a file decoded to and reads the same [`CameraInfo`] /
//! [`LensInfo`] / [`GpsLocation`] / [`CaptureSettings`] / [`MediaInfo`]
//! structs.
//!
//! The projection is **additive** over the faithful parse + tag-emission
//! layers — it reads an already-parsed `Meta` and never touches tag output.
//! Each `impl` writes only the domains its format can decode and leaves the
//! rest `None`; two projections of the same file (e.g. a container's
//! structural facts plus an embedded format's camera facts) combine through
//! [`MediaMetadata::merge`](crate::metadata::MediaMetadata::merge).
//!
//! [`CameraInfo`]: crate::metadata::CameraInfo
//! [`LensInfo`]: crate::metadata::LensInfo
//! [`GpsLocation`]: crate::metadata::GpsLocation
//! [`CaptureSettings`]: crate::metadata::CaptureSettings
//! [`MediaInfo`]: crate::metadata::MediaInfo

use crate::metadata::domain::MediaMetadata;

/// Project a typed format `Meta` into the normalized cross-format domain
/// ([`MediaMetadata`]) — the golden-pattern **L2** entry point.
///
/// Implementors map their format-specific fields onto the shared domain
/// structs, filling what they can decode and leaving the rest `None`. See
/// the [module docs](self) for the layering rationale.
pub trait Project {
  /// Build the normalized [`MediaMetadata`] projection from `self`.
  #[must_use]
  fn project(&self) -> MediaMetadata;
}

// ===========================================================================
// `impl Project for ExifMeta` — EXIF IFD + vendor MakerNote → domain
// ===========================================================================

#[cfg(feature = "exif")]
mod exif_impl {
  use super::Project;
  use crate::exif::ifd::RawValue;
  use crate::exif::{ExifMeta, IfdKind};
  use crate::metadata::domain::{
    CameraInfo, CaptureSettings, GpsLocation, LensInfo, MediaMetadata, Orientation,
  };
  use std::string::{String, ToString};

  impl Project for ExifMeta<'_> {
    /// Project EXIF/TIFF metadata onto the normalized domain.
    ///
    /// Two contributions are built and [`merge`](MediaMetadata::merge)d, EXIF
    /// first (higher priority), the vendor MakerNote second (fills the gaps —
    /// chiefly lens identity, which the standard EXIF IFD often omits):
    ///
    /// | domain field | EXIF source (IFD0 / ExifIFD / GPS) | MakerNote fallback |
    /// |---|---|---|
    /// | `camera.make` | `Make` | — |
    /// | `camera.model` | `Model` | Canon `model_name` |
    /// | `camera.software` | `Software` | — |
    /// | `camera.serial` | `SerialNumber` / `BodySerialNumber` | Canon `serial_number` |
    /// | `lens.model` | `LensModel` | Canon `lens_name` (else `lens_model_string`) |
    /// | `lens.make` | `LensMake` | — |
    /// | `lens.focal_length_mm` | `FocalLength` | Canon `focal_range_mm.0` (min) |
    /// | `lens.aperture` | `FNumber` / `MaxApertureValue` | — |
    /// | `gps.{latitude,longitude}` | `GPSLatitude`/`GPSLongitude` + their refs | — |
    /// | `gps.altitude_m` | `GPSAltitude` + `GPSAltitudeRef` | — |
    /// | `gps.timestamp` | `GPSDateStamp` | — |
    /// | `capture.exposure_time_s` | `ExposureTime` | — |
    /// | `capture.iso` | `ISO` | — |
    /// | `capture.f_number` | `FNumber` | — |
    /// | `media.orientation` | `Orientation` (`0x0112`) | — |
    ///
    /// The [`MediaInfo`](crate::metadata::MediaInfo) container domain carries
    /// only `orientation` here — a bare Exif/TIFF block has no duration /
    /// track structure, but it does have the display `Orientation` (the
    /// QuickTime / container ports populate the rest and merge these camera
    /// facts in via the embedded-Exif projection).
    fn project(&self) -> MediaMetadata {
      let exif = self.project_exif();
      match self.project_maker_note() {
        Some(mn) => exif.merge(mn),
        None => exif,
      }
    }
  }

  impl ExifMeta<'_> {
    /// The contribution from the standard EXIF IFDs (IFD0 / ExifIFD / GPS).
    fn project_exif(&self) -> MediaMetadata {
      let mut out = MediaMetadata::new();

      // ---- CameraInfo (IFD0 + body-serial tags) ----------------------------
      let mut camera = CameraInfo::new();
      camera
        .update_make(self.entry_text("Make"))
        .update_model(self.entry_text("Model"))
        .update_software(self.entry_text("Software"))
        // `SerialNumber` is the modern body-serial tag; `BodySerialNumber`
        // (0xa431) is the EXIF-2.3 name some bodies use instead.
        .update_serial(
          self
            .entry_text("SerialNumber")
            .or_else(|| self.entry_text("BodySerialNumber")),
        );
      if !camera.is_empty() {
        out.set_camera(camera);
      }

      // ---- LensInfo --------------------------------------------------------
      let mut lens = LensInfo::new();
      lens
        .update_model(self.entry_text("LensModel"))
        .update_make(self.entry_text("LensMake"))
        .update_focal_length_mm(self.entry_rational_f64("FocalLength"))
        // The capture aperture (`FNumber`) is the closest single-source proxy
        // for "the aperture this lens was used at"; fall back to the lens's
        // `MaxApertureValue` (an APEX value, but the only other aperture the
        // standard IFD carries) when `FNumber` is absent.
        .update_aperture(
          self
            .entry_rational_f64("FNumber")
            .or_else(|| self.entry_rational_f64("MaxApertureValue")),
        );
      if !lens.is_empty() {
        out.set_lens(lens);
      }

      // ---- GpsLocation -----------------------------------------------------
      let mut gps = GpsLocation::new();
      gps
        .update_latitude(self.gps_coord("GPSLatitude", "GPSLatitudeRef"))
        .update_longitude(self.gps_coord("GPSLongitude", "GPSLongitudeRef"))
        .update_altitude_m(self.gps_altitude())
        .update_timestamp(self.entry_text("GPSDateStamp"));
      if !gps.is_empty() {
        out.set_gps(gps);
      }

      // ---- CaptureSettings -------------------------------------------------
      let mut capture = CaptureSettings::new();
      capture
        .update_exposure_time_s(self.entry_rational_f64("ExposureTime"))
        .update_iso(self.entry_u32("ISO"))
        .update_f_number(self.entry_rational_f64("FNumber"));
      if !capture.is_empty() {
        out.set_capture(capture);
      }

      // ---- MediaInfo (orientation only) ------------------------------------
      // A bare Exif/TIFF block has no duration / track structure, but it DOES
      // carry the display `Orientation` (0x0112) — the one `MediaInfo` field a
      // still contributes. A consumer orients a decoded thumbnail from it.
      out.media_mut().update_orientation(self.orientation());

      out
    }

    /// The PRIMARY image's EXIF `Orientation` (`0x0112`) as a normalized
    /// [`Orientation`], or `None` when IFD0 carries no valid `Orientation`.
    ///
    /// Resolution is restricted to **IFD0** (`tag_id == 0x0112` AND
    /// [`ifd()`](crate::exif::ExifEntry::ifd) `== IfdKind::Ifd0`): the display
    /// orientation `MediaInfo` reports is the PRIMARY image's. A thumbnail's
    /// (IFD1) or a sub-IFD's (ExifIFD) `Orientation` must not populate it — a
    /// by-name first-match across all emitted entries would otherwise let an
    /// IFD1 `Orientation` leak into the primary frame's orientation (the
    /// thumbnail-orientation hazard). The raw `1`–`8` is read directly (NOT
    /// the PrintConv label).
    fn orientation(&self) -> Option<Orientation> {
      let raw = self
        .entries()
        .iter()
        .find(|e| e.tag_id() == 0x0112 && e.ifd() == IfdKind::Ifd0)?
        .value_ref()
        .raw()
        .first_i64()?;
      let value = u8::try_from(raw).ok()?;
      Orientation::from_exif_value(value)
    }

    /// The contribution from the typed vendor MakerNote, if one decoded.
    /// Currently fills the Canon-specific camera/lens identity that the
    /// standard IFD usually omits; other vendors leave it `None` (their
    /// typed surfaces populate as the per-vendor ports land).
    fn project_maker_note(&self) -> Option<MediaMetadata> {
      let canon = self.maker_note()?.meta().canon()?;
      let mut out = MediaMetadata::new();

      let mut camera = CameraInfo::new();
      camera
        .update_model(canon.model_name().map(ToString::to_string))
        // Canon's int32u body serial; render it as the bare decimal (the
        // domain's `serial` is a free-form string).
        .update_serial(canon.serial_number().map(|n| n.to_string()));
      if !camera.is_empty() {
        out.set_camera(camera);
      }

      let mut lens = LensInfo::new();
      lens
        // Prefer the resolved `%canonLensTypes` name; fall back to the
        // EXIF-style `LensModel` string newer bodies write.
        .update_model(
          canon
            .lens_name()
            .or_else(|| canon.lens_model_string())
            .map(ToString::to_string),
        )
        // CameraSettings carries a (min, max) focal range; the min is the
        // single representative focal length for the lens-identity domain.
        .update_focal_length_mm(canon.focal_range_mm().map(|(min, _max)| min));
      if !lens.is_empty() {
        out.set_lens(lens);
      }

      Some(out)
    }

    /// The first entry named `name` whose value is a (NUL-trimmed) string,
    /// with trailing whitespace stripped. EXIF identity strings are commonly
    /// space-padded; bundled ExifTool trims them via `RawConv => '$val =~
    /// s/\s+$//'` (`Exif.pm:585`/`599`/`906` for Make/Model/Software), and the
    /// normalized domain wants the clean value (`"Canon   "` → `"Canon"`).
    /// Perl `\s` = ASCII whitespace.
    fn entry_text(&self, name: &str) -> Option<String> {
      match self.entry(name)?.value_ref().raw() {
        RawValue::Text { text: s, .. } => {
          let trimmed = s.trim_end_matches(|c: char| c.is_ascii_whitespace());
          (!trimmed.is_empty()).then(|| trimmed.to_owned())
        }
        _ => None,
      }
    }

    /// The first entry named `name` read as a single `f64` — a single
    /// rational (`num/denom`, denominator 0 rejected), float, or integer.
    fn entry_rational_f64(&self, name: &str) -> Option<f64> {
      raw_first_f64(self.entry(name)?.value_ref().raw())
    }

    /// The first entry named `name` read as a `u32` (a single unsigned or
    /// non-negative signed integer). Used for `ISO`.
    fn entry_u32(&self, name: &str) -> Option<u32> {
      match self.entry(name)?.value_ref().raw() {
        RawValue::U64(v) => v.first().and_then(|&n| u32::try_from(n).ok()),
        RawValue::I64(v) => v.first().and_then(|&n| u32::try_from(n).ok()),
        _ => None,
      }
    }

    /// Decode a GPS coordinate: the `coord` tag is three rationals
    /// (degrees, minutes, seconds) combined as `deg + min/60 + sec/3600`;
    /// the `ref_name` tag (`"S"`/`"W"` → negative) sets the hemisphere sign.
    /// Faithful to ExifTool's `ToDegrees` GPS ValueConv (`GPS.pm`).
    fn gps_coord(&self, coord: &str, ref_name: &str) -> Option<f64> {
      let RawValue::Rational(parts) = self.entry(coord)?.value_ref().raw() else {
        return None;
      };
      // Degrees-minutes-seconds; a shorter list contributes what it has
      // (ExifTool's `ToDegrees` reads up to three components, defaulting the
      // rest to 0).
      let mut deg = 0.0_f64;
      for (i, r) in parts.iter().take(3).enumerate() {
        if r.denominator() == 0 {
          continue;
        }
        let v = r.numerator() as f64 / r.denominator() as f64;
        deg += v / 60_f64.powi(i as i32);
      }
      let negative = matches!(self.entry_text(ref_name).as_deref(), Some("S" | "W"));
      Some(if negative { -deg } else { deg })
    }

    /// Decode `GPSAltitude` (a single rational, metres) signed by
    /// `GPSAltitudeRef` (`1` ⇒ below sea level ⇒ negative; `GPS.pm`).
    fn gps_altitude(&self) -> Option<f64> {
      let alt = raw_first_f64(self.entry("GPSAltitude")?.value_ref().raw())?;
      let below_sea = matches!(
        self.entry("GPSAltitudeRef").map(|e| e.value_ref().raw()),
        Some(RawValue::U64(v)) if v.first() == Some(&1)
      );
      Some(if below_sea { -alt } else { alt })
    }
  }

  /// Read the first element of a numeric [`RawValue`] as `f64`: a rational
  /// (`num/denom`, denominator 0 ⇒ `None`), a float, or an integer.
  fn raw_first_f64(raw: &RawValue) -> Option<f64> {
    match raw {
      RawValue::Rational(rs) => rs.first().and_then(|r| {
        if r.denominator() == 0 {
          None
        } else {
          Some(r.numerator() as f64 / r.denominator() as f64)
        }
      }),
      RawValue::F64(v) => v.first().copied(),
      RawValue::U64(v) => v.first().map(|&n| n as f64),
      RawValue::I64(v) => v.first().map(|&n| n as f64),
      _ => None,
    }
  }
}
