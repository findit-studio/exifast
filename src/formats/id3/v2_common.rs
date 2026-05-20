//! Faithful port of `%id3v2_common` (ID3.pm:527-654) — frames shared
//! between ID3v2.3 and ID3v2.4. Each common frame has TWO `TagDef`
//! instances (one per version) because the family-1 group differs
//! (`"ID3v2_3"` vs `"ID3v2_4"`; Perl uses `%id3v2_common` then copies into
//! both `%v2_3` and `%v2_4`, then mutates `Groups{1}`, ID3.pm:867-879).
//!
//! Helpers [`common_v2_3`] / [`common_v2_4`] return the lookup result for
//! a 4-byte frame ID against the version-specific tables; the version-
//! specific tables ([`super::v2_3`] / [`super::v2_4`]) consult this module
//! first, then fall back to their version-only frames.

use crate::{
  formats::id3::{picture_type::PICTURE_TYPE_HASH, text},
  tagtable::{PrintConv, PrintConvHash, PrintValue, TagDef, TagId, ValueConv},
};

// ============================================================
//  Macros for declaring the same frame in TWO versions at once.
// ============================================================

macro_rules! pair_text {
  ($v3:ident, $v4:ident, $name:expr) => {
    static $v3: TagDef = TagDef::new($name, "ID3v2_3", ValueConv::None, PrintConv::None);
    static $v4: TagDef = TagDef::new($name, "ID3v2_4", ValueConv::None, PrintConv::None);
  };
}

macro_rules! pair_funcconv_print {
  ($v3:ident, $v4:ident, $name:expr, $print:expr) => {
    static $v3: TagDef = TagDef::new($name, "ID3v2_3", ValueConv::None, PrintConv::Func($print));
    static $v4: TagDef = TagDef::new($name, "ID3v2_4", ValueConv::None, PrintConv::Func($print));
  };
}

macro_rules! pair_hashprint {
  ($v3:ident, $v4:ident, $name:expr, $hash:expr) => {
    static $v3: TagDef = TagDef::new($name, "ID3v2_3", ValueConv::None, PrintConv::Hash($hash));
    static $v4: TagDef = TagDef::new($name, "ID3v2_4", ValueConv::None, PrintConv::Hash($hash));
  };
}

// ===== Picture frame + APIC-N attribute fields =====

pair_text!(APIC_V3, APIC_V4, "Picture");
pair_text!(APIC_1_V3, APIC_1_V4, "PictureMIMEType");
pair_hashprint!(APIC_2_V3, APIC_2_V4, "PictureType", PICTURE_TYPE_HASH);
pair_text!(APIC_3_V3, APIC_3_V4, "PictureDescription");

// ===== Comment + simple text frames =====

pair_text!(COMM_V3, COMM_V4, "Comment");
pair_text!(GEOB_V3, GEOB_V4, "GeneralEncapsulatedObject");
pair_text!(MCDI_V3, MCDI_V4, "MusicCDIdentifier");
pair_text!(OWNE_V3, OWNE_V4, "Ownership");
pair_text!(PCNT_V3, PCNT_V4, "PlayCounter");
pair_funcconv_print!(POPM_V3, POPM_V4, "Popularimeter", text::print_popularimeter);
pair_text!(PRIV_V3, PRIV_V4, "Private");
pair_text!(SYLT_V3, SYLT_V4, "SynLyrics");
pair_text!(TALB_V3, TALB_V4, "Album");
pair_text!(TBPM_V3, TBPM_V4, "BeatsPerMinute");
pair_hashprint!(
  TCMP_V3,
  TCMP_V4,
  "Compilation",
  PrintConvHash::direct(&[("0", PrintValue::Str("No")), ("1", PrintValue::Str("Yes")),])
);
pair_text!(TCOM_V3, TCOM_V4, "Composer");
pair_funcconv_print!(TCON_V3, TCON_V4, "Genre", text::print_genre);
pair_text!(TCOP_V3, TCOP_V4, "Copyright");
pair_text!(TDLY_V3, TDLY_V4, "PlaylistDelay");
pair_text!(TENC_V3, TENC_V4, "EncodedBy");
pair_text!(TEXT_V3, TEXT_V4, "Lyricist");
pair_text!(TFLT_V3, TFLT_V4, "FileType");
pair_text!(TIT1_V3, TIT1_V4, "Grouping");
pair_text!(TIT2_V3, TIT2_V4, "Title");
pair_text!(TIT3_V3, TIT3_V4, "Subtitle");
pair_text!(TKEY_V3, TKEY_V4, "InitialKey");
pair_text!(TLAN_V3, TLAN_V4, "Language");
// TLEN: ID3.pm:592-596 `ValueConv => '$val / 1000', PrintConv => '"$val s"'`.
static TLEN_V3: TagDef = TagDef::new(
  "Length",
  "ID3v2_3",
  ValueConv::Func(text::value_length),
  PrintConv::Func(text::print_length),
);
static TLEN_V4: TagDef = TagDef::new(
  "Length",
  "ID3v2_4",
  ValueConv::Func(text::value_length),
  PrintConv::Func(text::print_length),
);
pair_text!(TMED_V3, TMED_V4, "Media");
pair_text!(TOAL_V3, TOAL_V4, "OriginalAlbum");
pair_text!(TOFN_V3, TOFN_V4, "OriginalFileName");
pair_text!(TOLY_V3, TOLY_V4, "OriginalLyricist");
pair_text!(TOPE_V3, TOPE_V4, "OriginalArtist");
pair_text!(TOWN_V3, TOWN_V4, "FileOwner");
pair_text!(TPE1_V3, TPE1_V4, "Artist");
pair_text!(TPE2_V3, TPE2_V4, "Band");
pair_text!(TPE3_V3, TPE3_V4, "Conductor");
pair_text!(TPE4_V3, TPE4_V4, "InterpretedBy");
pair_text!(TPOS_V3, TPOS_V4, "PartOfSet");
pair_text!(TPUB_V3, TPUB_V4, "Publisher");
pair_text!(TRCK_V3, TRCK_V4, "Track");
pair_text!(TRSN_V3, TRSN_V4, "InternetRadioStationName");
pair_text!(TRSO_V3, TRSO_V4, "InternetRadioStationOwner");
pair_text!(TSRC_V3, TSRC_V4, "ISRC");
pair_text!(TSSE_V3, TSSE_V4, "EncoderSettings");
pair_text!(TXXX_V3, TXXX_V4, "UserDefinedText");
pair_text!(USER_V3, USER_V4, "TermsOfUse");
pair_text!(USLT_V3, USLT_V4, "Lyrics");
pair_text!(WCOM_V3, WCOM_V4, "CommercialURL");
pair_text!(WCOP_V3, WCOP_V4, "CopyrightURL");
pair_text!(WOAF_V3, WOAF_V4, "FileURL");
pair_text!(WOAR_V3, WOAR_V4, "ArtistURL");
pair_text!(WOAS_V3, WOAS_V4, "SourceURL");
pair_text!(WORS_V3, WORS_V4, "InternetRadioStationURL");
pair_text!(WPAY_V3, WPAY_V4, "PaymentURL");
pair_text!(WPUB_V3, WPUB_V4, "PublisherURL");
pair_text!(WXXX_V3, WXXX_V4, "UserDefinedURL");
// non-standard
pair_text!(TSO2_V3, TSO2_V4, "AlbumArtistSortOrder");
pair_text!(TSOC_V3, TSOC_V4, "ComposerSortOrder");
pair_text!(ITNU_V3, ITNU_V4, "iTunesU");
pair_text!(PCST_V3, PCST_V4, "Podcast");
pair_text!(TDES_V3, TDES_V4, "PodcastDescription");
pair_text!(TGID_V3, TGID_V4, "PodcastID");
pair_text!(WFED_V3, WFED_V4, "PodcastURL");
pair_text!(TKWD_V3, TKWD_V4, "PodcastKeywords");
pair_text!(TCAT_V3, TCAT_V4, "PodcastCategory");
// XDOR has `%dateTimeConv` (ID3.pm:643). Implement as `ValueConv::Func`
// of `convert_xmp_date` (same as the TDEN/TDOR/TDRC/TDRL/TDTG group in
// v2_4.rs). See v2_4.rs's date-tag block for the full bundled cite.
static XDOR_V3: TagDef = TagDef::new(
  "OriginalReleaseTime",
  "ID3v2_3",
  ValueConv::Func(text::convert_xmp_date),
  PrintConv::None,
);
static XDOR_V4: TagDef = TagDef::new(
  "OriginalReleaseTime",
  "ID3v2_4",
  ValueConv::Func(text::convert_xmp_date),
  PrintConv::None,
);
pair_text!(XSOA_V3, XSOA_V4, "AlbumSortOrder");
pair_text!(XSOP_V3, XSOP_V4, "PerformerSortOrder");
pair_text!(XSOT_V3, XSOT_V4, "TitleSortOrder");
pair_text!(XOLY_V3, XOLY_V4, "OlympusDSS");
pair_text!(GRP1_V3, GRP1_V4, "Grouping");
pair_text!(MVNM_V3, MVNM_V4, "MovementName");
pair_text!(MVIN_V3, MVIN_V4, "MovementNumber");

/// Lookup a 4-byte frame ID against the v2.3 view of `%id3v2_common`.
/// Returns `None` if the frame is not in the common set (so the caller
/// can fall back to the v2.3-only set).
#[must_use]
pub fn common_v2_3(id: TagId) -> Option<&'static TagDef> {
  common_lookup(id, true)
}

/// v2.4 view of `%id3v2_common`.
#[must_use]
pub fn common_v2_4(id: TagId) -> Option<&'static TagDef> {
  common_lookup(id, false)
}

fn common_lookup(id: TagId, v3: bool) -> Option<&'static TagDef> {
  match id {
    TagId::Str("APIC") => Some(if v3 { &APIC_V3 } else { &APIC_V4 }),
    TagId::Str("APIC-1") => Some(if v3 { &APIC_1_V3 } else { &APIC_1_V4 }),
    TagId::Str("APIC-2") => Some(if v3 { &APIC_2_V3 } else { &APIC_2_V4 }),
    TagId::Str("APIC-3") => Some(if v3 { &APIC_3_V3 } else { &APIC_3_V4 }),
    TagId::Str("COMM") => Some(if v3 { &COMM_V3 } else { &COMM_V4 }),
    TagId::Str("GEOB") => Some(if v3 { &GEOB_V3 } else { &GEOB_V4 }),
    TagId::Str("MCDI") => Some(if v3 { &MCDI_V3 } else { &MCDI_V4 }),
    TagId::Str("OWNE") => Some(if v3 { &OWNE_V3 } else { &OWNE_V4 }),
    TagId::Str("PCNT") => Some(if v3 { &PCNT_V3 } else { &PCNT_V4 }),
    TagId::Str("POPM") => Some(if v3 { &POPM_V3 } else { &POPM_V4 }),
    TagId::Str("PRIV") => Some(if v3 { &PRIV_V3 } else { &PRIV_V4 }),
    TagId::Str("SYLT") => Some(if v3 { &SYLT_V3 } else { &SYLT_V4 }),
    TagId::Str("TALB") => Some(if v3 { &TALB_V3 } else { &TALB_V4 }),
    TagId::Str("TBPM") => Some(if v3 { &TBPM_V3 } else { &TBPM_V4 }),
    TagId::Str("TCMP") => Some(if v3 { &TCMP_V3 } else { &TCMP_V4 }),
    TagId::Str("TCOM") => Some(if v3 { &TCOM_V3 } else { &TCOM_V4 }),
    TagId::Str("TCON") => Some(if v3 { &TCON_V3 } else { &TCON_V4 }),
    TagId::Str("TCOP") => Some(if v3 { &TCOP_V3 } else { &TCOP_V4 }),
    TagId::Str("TDLY") => Some(if v3 { &TDLY_V3 } else { &TDLY_V4 }),
    TagId::Str("TENC") => Some(if v3 { &TENC_V3 } else { &TENC_V4 }),
    TagId::Str("TEXT") => Some(if v3 { &TEXT_V3 } else { &TEXT_V4 }),
    TagId::Str("TFLT") => Some(if v3 { &TFLT_V3 } else { &TFLT_V4 }),
    TagId::Str("TIT1") => Some(if v3 { &TIT1_V3 } else { &TIT1_V4 }),
    TagId::Str("TIT2") => Some(if v3 { &TIT2_V3 } else { &TIT2_V4 }),
    TagId::Str("TIT3") => Some(if v3 { &TIT3_V3 } else { &TIT3_V4 }),
    TagId::Str("TKEY") => Some(if v3 { &TKEY_V3 } else { &TKEY_V4 }),
    TagId::Str("TLAN") => Some(if v3 { &TLAN_V3 } else { &TLAN_V4 }),
    TagId::Str("TLEN") => Some(if v3 { &TLEN_V3 } else { &TLEN_V4 }),
    TagId::Str("TMED") => Some(if v3 { &TMED_V3 } else { &TMED_V4 }),
    TagId::Str("TOAL") => Some(if v3 { &TOAL_V3 } else { &TOAL_V4 }),
    TagId::Str("TOFN") => Some(if v3 { &TOFN_V3 } else { &TOFN_V4 }),
    TagId::Str("TOLY") => Some(if v3 { &TOLY_V3 } else { &TOLY_V4 }),
    TagId::Str("TOPE") => Some(if v3 { &TOPE_V3 } else { &TOPE_V4 }),
    TagId::Str("TOWN") => Some(if v3 { &TOWN_V3 } else { &TOWN_V4 }),
    TagId::Str("TPE1") => Some(if v3 { &TPE1_V3 } else { &TPE1_V4 }),
    TagId::Str("TPE2") => Some(if v3 { &TPE2_V3 } else { &TPE2_V4 }),
    TagId::Str("TPE3") => Some(if v3 { &TPE3_V3 } else { &TPE3_V4 }),
    TagId::Str("TPE4") => Some(if v3 { &TPE4_V3 } else { &TPE4_V4 }),
    TagId::Str("TPOS") => Some(if v3 { &TPOS_V3 } else { &TPOS_V4 }),
    TagId::Str("TPUB") => Some(if v3 { &TPUB_V3 } else { &TPUB_V4 }),
    TagId::Str("TRCK") => Some(if v3 { &TRCK_V3 } else { &TRCK_V4 }),
    TagId::Str("TRSN") => Some(if v3 { &TRSN_V3 } else { &TRSN_V4 }),
    TagId::Str("TRSO") => Some(if v3 { &TRSO_V3 } else { &TRSO_V4 }),
    TagId::Str("TSRC") => Some(if v3 { &TSRC_V3 } else { &TSRC_V4 }),
    TagId::Str("TSSE") => Some(if v3 { &TSSE_V3 } else { &TSSE_V4 }),
    TagId::Str("TXXX") => Some(if v3 { &TXXX_V3 } else { &TXXX_V4 }),
    TagId::Str("USER") => Some(if v3 { &USER_V3 } else { &USER_V4 }),
    TagId::Str("USLT") => Some(if v3 { &USLT_V3 } else { &USLT_V4 }),
    TagId::Str("WCOM") => Some(if v3 { &WCOM_V3 } else { &WCOM_V4 }),
    TagId::Str("WCOP") => Some(if v3 { &WCOP_V3 } else { &WCOP_V4 }),
    TagId::Str("WOAF") => Some(if v3 { &WOAF_V3 } else { &WOAF_V4 }),
    TagId::Str("WOAR") => Some(if v3 { &WOAR_V3 } else { &WOAR_V4 }),
    TagId::Str("WOAS") => Some(if v3 { &WOAS_V3 } else { &WOAS_V4 }),
    TagId::Str("WORS") => Some(if v3 { &WORS_V3 } else { &WORS_V4 }),
    TagId::Str("WPAY") => Some(if v3 { &WPAY_V3 } else { &WPAY_V4 }),
    TagId::Str("WPUB") => Some(if v3 { &WPUB_V3 } else { &WPUB_V4 }),
    TagId::Str("WXXX") => Some(if v3 { &WXXX_V3 } else { &WXXX_V4 }),
    TagId::Str("TSO2") => Some(if v3 { &TSO2_V3 } else { &TSO2_V4 }),
    TagId::Str("TSOC") => Some(if v3 { &TSOC_V3 } else { &TSOC_V4 }),
    TagId::Str("ITNU") => Some(if v3 { &ITNU_V3 } else { &ITNU_V4 }),
    TagId::Str("PCST") => Some(if v3 { &PCST_V3 } else { &PCST_V4 }),
    TagId::Str("TDES") => Some(if v3 { &TDES_V3 } else { &TDES_V4 }),
    TagId::Str("TGID") => Some(if v3 { &TGID_V3 } else { &TGID_V4 }),
    TagId::Str("WFED") => Some(if v3 { &WFED_V3 } else { &WFED_V4 }),
    TagId::Str("TKWD") => Some(if v3 { &TKWD_V3 } else { &TKWD_V4 }),
    TagId::Str("TCAT") => Some(if v3 { &TCAT_V3 } else { &TCAT_V4 }),
    TagId::Str("XDOR") => Some(if v3 { &XDOR_V3 } else { &XDOR_V4 }),
    TagId::Str("XSOA") => Some(if v3 { &XSOA_V3 } else { &XSOA_V4 }),
    TagId::Str("XSOP") => Some(if v3 { &XSOP_V3 } else { &XSOP_V4 }),
    TagId::Str("XSOT") => Some(if v3 { &XSOT_V3 } else { &XSOT_V4 }),
    TagId::Str("XOLY") => Some(if v3 { &XOLY_V3 } else { &XOLY_V4 }),
    TagId::Str("GRP1") => Some(if v3 { &GRP1_V3 } else { &GRP1_V4 }),
    TagId::Str("MVNM") => Some(if v3 { &MVNM_V3 } else { &MVNM_V4 }),
    TagId::Str("MVIN") => Some(if v3 { &MVIN_V3 } else { &MVIN_V4 }),
    _ => None,
  }
}

#[cfg(test)]
mod tests {
  use super::*;

  #[test]
  fn common_lookup_versions_differ_in_group1_only() {
    let a = common_v2_3(TagId::Str("TIT2")).unwrap();
    let b = common_v2_4(TagId::Str("TIT2")).unwrap();
    assert_eq!(a.name(), "Title");
    assert_eq!(b.name(), "Title");
    assert_eq!(a.group1(), "ID3v2_3");
    assert_eq!(b.group1(), "ID3v2_4");
  }

  #[test]
  fn common_lookup_apic_subfields_present() {
    assert_eq!(
      common_v2_3(TagId::Str("APIC-2")).unwrap().name(),
      "PictureType"
    );
    assert_eq!(
      common_v2_4(TagId::Str("APIC-3")).unwrap().name(),
      "PictureDescription"
    );
  }

  #[test]
  fn common_lookup_misses_nontable_id() {
    assert!(common_v2_3(TagId::Str("ZZZZ")).is_none());
    assert!(common_v2_4(TagId::Str("ZZZZ")).is_none());
  }
}
