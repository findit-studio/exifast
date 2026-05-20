# exifast — Format Port Tracker (Stage 1: video/audio, read-only)

Single source of truth for the 1:1 ExifTool → Rust port. Work **top to bottom**,
one row at a time. Design rationale, scope decisions, and the per-format
micro-cycle are maintained as internal planning notes (not published in
this repository).

**Bar for `✅`:** every fixture for that module matches real
`./exiftool -j -G1 -struct` (incl. PrintConv) with order-independent,
byte-exact values (key order ignored; scalars byte-for-byte). See spec §4.

**Status:** `⬜ Not started` · `🟡 Spec'd` · `🔵 In progress` · `✅ 1:1 verified` · `⏸️ Deferred (Stage 2)`
**Golden diff:** `—` not run · `n/m` n of m fixtures clean · `clean`

LOC are indicative (ExifTool 13.58). "Module" is the file under
`exiftool/lib/Image/ExifTool/`. Fixtures are in `exiftool/t/images/` unless
marked `ffmpeg-gen` (we generate per spec D6).

| # | Format | ExifTool module | ~LOC | Phase | Depends on | Fixture(s) | Status | Golden diff | Spec/Plan |
|--:|---|---|--:|:--:|---|---|:--:|:--:|---|
| 0 | **Engine** (reader/filetype/tagtable/value/convert/serialize) | *(new Rust)* | — | 1 | — | n/a | ✅ | — | — |
| 1 | **AAC** | AAC.pm | 177 | 2 | Engine | `AAC.aac` | ✅ | clean | — |
| 2 | **ID3** *(infra; also completes **MP3**)* | ID3.pm | 1775 | 2 | Engine | `MP3.mp3` | ⬜ | — | — |
| 2a | **MPEG audio frame** *(MP3 subset; ID3 not required)* | MPEG.pm (audio) | 735 | 2 | Engine | `MP3.mp3` (ID3-free) | ✅ | clean | — |
| 3 | **AIFF** (AIFF/AIF/AIFC) | AIFF.pm | 316 | 2 | Engine, ID3 | `AIFF.aif` | ⬜ | — | — |
| 4 | **MPC** | MPC.pm | 156 | 2 | Engine, ID3/APE tags | `APE.mpc` | ⬜ | — | — |
| 5 | **APE** | APE.pm | 287 | 2 | Engine, ID3 | `APE.ape` | ⬜ | — | — |
| 6 | **WavPack** (WV/WVP) | WavPack.pm | 144 | 2 | Engine, ID3/APE tags | `WavPack.wv` + adversarial | ✅ | clean | — |
| 7 | **DSF** | DSF.pm | 138 | 2 | Engine, ID3 | ⚠️ ffmpeg-gen `DSF.dsf` | ⬜ | — | — |
| 8 | **FLAC** | FLAC.pm | 321 | 2 | Engine, ID3, Vorbis | `FLAC.flac` | ⬜ | — | — |
| 9 | **Ogg + Vorbis** (OGG/OGV/OPUS) | Ogg.pm + Vorbis.pm | 496 | 2 | Engine, FLAC (ogg-flac) | `Vorbis.ogg`, `Opus.opus`, `FLAC.ogg` | ⬜ | — | — |
| 10 | **Audible** (AA) | Audible.pm | 317 | 2 | Engine | `Audible.aa` | ⬜ | — | — |
| 11 | **DV** | DV.pm | 315 | 2 | Engine | `DV.dv` | ⬜ | — | — |
| 12 | **Red** (R3D) | Red.pm | 335 | 2 | Engine | `Red.r3d` | ✅ | clean (Composite deferred) | docs/superpowers/plans/2026-05-20-red-port.md |
| 13 | **Exif** *(infra)* | Exif.pm | 7324 | 3 | Engine | via containers | ⬜ | — | — |
| 14 | **GPS** *(infra)* | GPS.pm | 641 | 3 | Engine, Exif | via containers | ⬜ | — | — |
| 15 | **XMP** *(infra)* | XMP.pm + XMP2.pl | 6693 | 3 | Engine | via containers | ⬜ | — | — |
| 16 | **H264** *(sub-dep of M2TS/MPEG)* | H264.pm | 1149 | 3 | Engine | via M2TS/MPEG | ⬜ | — | — |
| 17 | **MPEG** (MPEG/MPG/M2V/VOB) | MPEG.pm | 735 | 3 | Engine, H264 | ⚠️ ffmpeg-gen `MPEG.mpg` | ⬜ | — | — |
| 18 | **Flash** (FLV) | Flash.pm | 749 | 3 | Engine | `Flash.flv` | ⬜ | — | — |
| 19 | **Real** (RM/RMVB/RV/RA/RAM/RPM) | Real.pm | 739 | 3 | Engine | `Real.rm`, `Real.ra` | ⬜ | — | — |
| 20 | **M2TS** (M2TS/M2T/MTS/TS) | M2TS.pm | 1084 | 3 | Engine, H264 | `M2TS.mts` | ⬜ | — | — |
| 21 | **ASF** (ASF/WMV/WMA/DIVX/DVR-MS) | ASF.pm | 901 | 3 | Engine, XMP | `ASF.wmv` | ⬜ | — | — |
| 22 | **RIFF** (AVI/WAV/LA/OFR/PAC) | RIFF.pm | 2273 | 3 | Engine, Exif, XMP, ID3 | `RIFF.avi`, `RIFF.wav` | ⬜ | — | — |
| 23 | **Matroska** (MKV/MKA/MKS/WEBM) | Matroska.pm | 1289 | 3 | Engine | `Matroska.mkv` | ⬜ | — | — |
| 24 | **MXF** | MXF.pm | 3031 | 3 | Engine | `MXF.mxf` | ⬜ | — | — |
| 25 | **QuickTime core** (MOV/MP4/M4A/M4V/3GP/3G2) | QuickTime.pm | 10771 | 4 | Engine, Exif, GPS, XMP | `QuickTime.mov`, `QuickTime.m4a` | ⬜ | — | — |
| 26 | **QuickTime variants** (360/F4V/GLV/LRV/INSV/MQV/AAX/DVB) | QuickTime.pm *(same .pm, brand-specific)* | — | 4 | #25 | per-variant ⚠️ may need ffmpeg | ⬜ | — | — |
| 27 | **QuickTimeStream** (timed GPS/telemetry) | QuickTimeStream.pl | 3840 | 4 | #25, GPS | ⚠️ needs telemetry sample | ⬜ | — | — |
| 28 | **DSS / DS2** | Olympus.pm *(DSS subset)* | ~4462 | 4 *(last)* | Engine | `Olympus.dss` | ⬜ | — | — |

## Deferred to Stage 2 (image/RAW — out of scope here)

These file types ride on Stage-1 modules but carry image/RAW (not video/audio)
metadata; they are explicitly **not** Stage 1. MakerNotes are likewise Stage 2
(see spec §5).

| File types | Rides on | Status |
|---|---|:--:|
| HEIC / HEIF / AVIF / QTIF / CR3 / CRM | QuickTime.pm | ⏸️ |
| WEBP | RIFF.pm | ⏸️ |
| SWF | Flash.pm | ⏸️ |
| MakerNotes (Canon/Nikon/Sony/Apple/…) | shared, embedded | ⏸️ |

## How to use this tracker

For each row, run the per-format micro-cycle (spec §9): read the `.pm` →
generate golden JSON → `writing-plans` for that one module → TDD against
`conformance.rs` → all fixtures `clean` → set row `✅`, fill Golden diff and
Spec/Plan, commit. Phases gate ordering: finish lower-numbered rows first
because later rows depend on them.
