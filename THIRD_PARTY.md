# Third-Party Notices

## ExifTool (primary upstream — `exifast` is a derivative work)

- **Project:** ExifTool — https://exiftool.org/
- **Author:** Phil Harvey
- **Copyright:** Copyright 2003–2026 Phil Harvey
- **Upstream version ported:** 13.58
- **License:** Distributed under the same terms as Perl itself — the Artistic
  License *or* the GNU General Public License. The upstream distribution
  bundles the GNU GPL version 3.

`exifast` is a faithful Rust transliteration of ExifTool's metadata-reading
logic and tag tables. As a derivative work it is licensed under
`GPL-3.0-or-later` (compatible with the GPL arm of ExifTool's dual license).
Source files that transliterate ExifTool carry `// ExifTool: <Module>.pm:<line>`
provenance comments.

Test fixtures under `tests/fixtures/` that originate from ExifTool's
`t/images/` directory remain under ExifTool's license and copyright.

## Rust dependencies

| Crate | License | Used for |
|-------|---------|----------|
| derive_more | MIT | enum IsVariant/Unwrap/TryUnwrap accessors (spec D9) |
| serde | MIT OR Apache-2.0 | (de)serialization derives |
| serde_json | MIT OR Apache-2.0 | JSON output + golden diffing |
| smol_str | MIT OR Apache-2.0 | small-string optimization for tag/group/value strings |

(GPL-3.0-or-later is compatible with the MIT/Apache-2.0 licensed dependencies
above; this table is updated as dependencies change.)
