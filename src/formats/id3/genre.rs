//! Faithful port of `%genre` (ID3.pm:131-332). The ID3v1 genre lookup
//! table — used by both ID3v1::Genre (numeric ID) and ID3v2 `TCON`/`TCO`
//! (via [`super::text::print_genre`]) for parenthesized numeric refs.
//!
//! Entries 0..=191 + 255 are the canonical Winamp/extension list. The two
//! ID3v2 short forms `CR` (Cover) and `RX` (Remix) live at the end of the
//! Perl hash but are looked up by string in `PrintGenre`; they are
//! intentionally NOT in this i64-keyed table — see [`genre_short_form`].

/// Faithful port of `%genre` (ID3.pm:131-332). Indexed by genre number;
/// returns the canonical name. `None` for unknown numbers (PrintGenre
/// then synthesizes `"Unknown ($n)"`, ID3.pm:1026).
#[must_use]
pub const fn genre_name(id: i64) -> Option<&'static str> {
  match id {
    0 => Some("Blues"),
    1 => Some("Classic Rock"),
    2 => Some("Country"),
    3 => Some("Dance"),
    4 => Some("Disco"),
    5 => Some("Funk"),
    6 => Some("Grunge"),
    7 => Some("Hip-Hop"),
    8 => Some("Jazz"),
    9 => Some("Metal"),
    10 => Some("New Age"),
    11 => Some("Oldies"),
    12 => Some("Other"),
    13 => Some("Pop"),
    14 => Some("R&B"),
    15 => Some("Rap"),
    16 => Some("Reggae"),
    17 => Some("Rock"),
    18 => Some("Techno"),
    19 => Some("Industrial"),
    20 => Some("Alternative"),
    21 => Some("Ska"),
    22 => Some("Death Metal"),
    23 => Some("Pranks"),
    24 => Some("Soundtrack"),
    25 => Some("Euro-Techno"),
    26 => Some("Ambient"),
    27 => Some("Trip-Hop"),
    28 => Some("Vocal"),
    29 => Some("Jazz+Funk"),
    30 => Some("Fusion"),
    31 => Some("Trance"),
    32 => Some("Classical"),
    33 => Some("Instrumental"),
    34 => Some("Acid"),
    35 => Some("House"),
    36 => Some("Game"),
    37 => Some("Sound Clip"),
    38 => Some("Gospel"),
    39 => Some("Noise"),
    40 => Some("Alt. Rock"),
    41 => Some("Bass"),
    42 => Some("Soul"),
    43 => Some("Punk"),
    44 => Some("Space"),
    45 => Some("Meditative"),
    46 => Some("Instrumental Pop"),
    47 => Some("Instrumental Rock"),
    48 => Some("Ethnic"),
    49 => Some("Gothic"),
    50 => Some("Darkwave"),
    51 => Some("Techno-Industrial"),
    52 => Some("Electronic"),
    53 => Some("Pop-Folk"),
    54 => Some("Eurodance"),
    55 => Some("Dream"),
    56 => Some("Southern Rock"),
    57 => Some("Comedy"),
    58 => Some("Cult"),
    59 => Some("Gangsta Rap"),
    60 => Some("Top 40"),
    61 => Some("Christian Rap"),
    62 => Some("Pop/Funk"),
    63 => Some("Jungle"),
    64 => Some("Native American"),
    65 => Some("Cabaret"),
    66 => Some("New Wave"),
    67 => Some("Psychedelic"),
    68 => Some("Rave"),
    69 => Some("Showtunes"),
    70 => Some("Trailer"),
    71 => Some("Lo-Fi"),
    72 => Some("Tribal"),
    73 => Some("Acid Punk"),
    74 => Some("Acid Jazz"),
    75 => Some("Polka"),
    76 => Some("Retro"),
    77 => Some("Musical"),
    78 => Some("Rock & Roll"),
    79 => Some("Hard Rock"),
    80 => Some("Folk"),
    81 => Some("Folk-Rock"),
    82 => Some("National Folk"),
    83 => Some("Swing"),
    84 => Some("Fast-Fusion"),
    85 => Some("Bebop"),
    86 => Some("Latin"),
    87 => Some("Revival"),
    88 => Some("Celtic"),
    89 => Some("Bluegrass"),
    90 => Some("Avantgarde"),
    91 => Some("Gothic Rock"),
    92 => Some("Progressive Rock"),
    93 => Some("Psychedelic Rock"),
    94 => Some("Symphonic Rock"),
    95 => Some("Slow Rock"),
    96 => Some("Big Band"),
    97 => Some("Chorus"),
    98 => Some("Easy Listening"),
    99 => Some("Acoustic"),
    100 => Some("Humour"),
    101 => Some("Speech"),
    102 => Some("Chanson"),
    103 => Some("Opera"),
    104 => Some("Chamber Music"),
    105 => Some("Sonata"),
    106 => Some("Symphony"),
    107 => Some("Booty Bass"),
    108 => Some("Primus"),
    109 => Some("Porn Groove"),
    110 => Some("Satire"),
    111 => Some("Slow Jam"),
    112 => Some("Club"),
    113 => Some("Tango"),
    114 => Some("Samba"),
    115 => Some("Folklore"),
    116 => Some("Ballad"),
    117 => Some("Power Ballad"),
    118 => Some("Rhythmic Soul"),
    119 => Some("Freestyle"),
    120 => Some("Duet"),
    121 => Some("Punk Rock"),
    122 => Some("Drum Solo"),
    123 => Some("A Cappella"),
    124 => Some("Euro-House"),
    125 => Some("Dance Hall"),
    126 => Some("Goa"),
    127 => Some("Drum & Bass"),
    128 => Some("Club-House"),
    129 => Some("Hardcore"),
    130 => Some("Terror"),
    131 => Some("Indie"),
    132 => Some("BritPop"),
    133 => Some("Afro-Punk"),
    134 => Some("Polsk Punk"),
    135 => Some("Beat"),
    136 => Some("Christian Gangsta Rap"),
    137 => Some("Heavy Metal"),
    138 => Some("Black Metal"),
    139 => Some("Crossover"),
    140 => Some("Contemporary Christian"),
    141 => Some("Christian Rock"),
    142 => Some("Merengue"),
    143 => Some("Salsa"),
    144 => Some("Thrash Metal"),
    145 => Some("Anime"),
    146 => Some("JPop"),
    147 => Some("Synthpop"),
    148 => Some("Abstract"),
    149 => Some("Art Rock"),
    150 => Some("Baroque"),
    151 => Some("Bhangra"),
    152 => Some("Big Beat"),
    153 => Some("Breakbeat"),
    154 => Some("Chillout"),
    155 => Some("Downtempo"),
    156 => Some("Dub"),
    157 => Some("EBM"),
    158 => Some("Eclectic"),
    159 => Some("Electro"),
    160 => Some("Electroclash"),
    161 => Some("Emo"),
    162 => Some("Experimental"),
    163 => Some("Garage"),
    164 => Some("Global"),
    165 => Some("IDM"),
    166 => Some("Illbient"),
    167 => Some("Industro-Goth"),
    168 => Some("Jam Band"),
    169 => Some("Krautrock"),
    170 => Some("Leftfield"),
    171 => Some("Lounge"),
    172 => Some("Math Rock"),
    173 => Some("New Romantic"),
    174 => Some("Nu-Breakz"),
    175 => Some("Post-Punk"),
    176 => Some("Post-Rock"),
    177 => Some("Psytrance"),
    178 => Some("Shoegaze"),
    179 => Some("Space Rock"),
    180 => Some("Trop Rock"),
    181 => Some("World Music"),
    182 => Some("Neoclassical"),
    183 => Some("Audiobook"),
    184 => Some("Audio Theatre"),
    185 => Some("Neue Deutsche Welle"),
    186 => Some("Podcast"),
    187 => Some("Indie Rock"),
    188 => Some("G-Funk"),
    189 => Some("Dubstep"),
    190 => Some("Garage Rock"),
    191 => Some("Psybient"),
    255 => Some("None"),
    _ => None,
  }
}

/// ID3v2-only short-form alphabetic genre codes (ID3.pm:330-331). Looked
/// up by string in `PrintGenre` (ID3.pm:1033 `s/\((\d+)\)/\($genre{$1}\)/`
/// — but `PrintGenre` operates on the full TCON/TCO string with `(N)`
/// number refs; the short-form alphabetic codes appear NOT in number-
/// parens but as bare tokens in v2.4 slash-separated lists, e.g. `"CR"`).
#[must_use]
pub const fn genre_short_form(s: &str) -> Option<&'static str> {
  match s.as_bytes() {
    b"CR" => Some("Cover"),
    b"RX" => Some("Remix"),
    _ => None,
  }
}

#[cfg(test)]
mod tests {
  use super::*;

  #[test]
  fn genre_name_spot_checks_vs_id3_pm() {
    // ID3.pm:139 — 7 => 'Hip-Hop' (the very fixture our golden uses).
    assert_eq!(genre_name(7), Some("Hip-Hop"));
    // ID3.pm:131 — 0 => 'Blues'.
    assert_eq!(genre_name(0), Some("Blues"));
    // ID3.pm:212-213 — 80 => 'Folk' (Winamp extension start).
    assert_eq!(genre_name(80), Some("Folk"));
    // ID3.pm:265-266 — 131 => 'Indie'.
    assert_eq!(genre_name(131), Some("Indie"));
    // ID3.pm:328 — 255 => 'None'.
    assert_eq!(genre_name(255), Some("None"));
    // Out-of-table → None (PrintGenre will synthesize "Unknown ($n)").
    assert_eq!(genre_name(192), None);
    assert_eq!(genre_name(254), None);
    assert_eq!(genre_name(-1), None);
    assert_eq!(genre_name(1000), None);
  }

  #[test]
  fn genre_short_form_id3v2_codes() {
    // ID3.pm:330-331 — CR=Cover, RX=Remix.
    assert_eq!(genre_short_form("CR"), Some("Cover"));
    assert_eq!(genre_short_form("RX"), Some("Remix"));
    assert_eq!(genre_short_form("XX"), None);
  }
}
