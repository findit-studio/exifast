//! Integration tests for the RIFF / AVI parser (FORMATS.md row 26). Covers
//! the synthetic + bundled fixtures end-to-end through the engine entry
//! [`extract_info`].

#![cfg(all(feature = "json", feature = "riff"))]

use exifast::parser::extract_info;

#[test]
fn bundled_riff_avi_extracts_camera_metadata() {
  // Bundled `lib/Image/ExifTool/t/images/RIFF.avi` — a 1262-byte Motion JPEG
  // Canon AVI fixture from 2003. Carries the most-common AVI tag surface:
  // hdrl/avih (FrameRate / FrameCount / dimensions), strl/strh (StreamType /
  // codec / VideoFrameRate / VideoFrameCount), strl/strf for both vids
  // (BMP-V3 header) and auds (AudioFormat / Encoding=PCM), LIST_INFO
  // (`ISFT` = "CanonMVI01"), IDIT (DateTimeOriginal). We test the engine
  // path which exercises the file-type detection → parser registry hop.
  let root = env!("CARGO_MANIFEST_DIR");
  let data = std::fs::read(format!("{root}/tests/fixtures/RIFF.avi")).expect("read RIFF.avi");
  let got = extract_info("RIFF.avi", &data, /* print_on */ true);
  // The doc must mention the AVI file type + MIME + camera identity tags.
  assert!(
    got.contains("\"File:FileType\":\"AVI\""),
    "missing AVI file type:\n{got}"
  );
  assert!(
    got.contains("\"File:MIMEType\":\"video/x-msvideo\""),
    "missing AVI MIME:\n{got}"
  );
  assert!(
    got.contains("\"RIFF:Software\":\"CanonMVI01\""),
    "missing ISFT software:\n{got}"
  );
  assert!(
    got.contains("\"RIFF:DateTimeOriginal\":\"2003:03:10 15:04:43\""),
    "missing IDIT date:\n{got}"
  );
  assert!(
    got.contains("\"RIFF:VideoCodec\":\"mjpg\""),
    "missing video codec:\n{got}"
  );
  assert!(
    got.contains("\"RIFF:Encoding\":\"Microsoft PCM\""),
    "missing PCM encoding label:\n{got}"
  );
  assert!(
    got.contains("\"RIFF:StreamType\":\"Video\""),
    "missing StreamType PrintConv:\n{got}"
  );
  // BMP-strf hop.
  assert!(
    got.contains("\"File:BMPVersion\":\"Windows V3\""),
    "missing BMPVersion:\n{got}"
  );
  assert!(
    got.contains("\"File:Compression\":\"MJPG\""),
    "missing BMP FourCC compression:\n{got}"
  );
}

#[test]
fn bundled_riff_avi_n_mode_emits_raw_values() {
  // `-n` mode strips PrintConv: Encoding → 1, StreamType → "vids",
  // BMPVersion → 40.
  let root = env!("CARGO_MANIFEST_DIR");
  let data = std::fs::read(format!("{root}/tests/fixtures/RIFF.avi")).expect("read RIFF.avi");
  let got = extract_info("RIFF.avi", &data, /* print_on */ false);
  assert!(
    got.contains("\"RIFF:Encoding\":1"),
    "raw PCM encoding code:\n{got}"
  );
  assert!(
    got.contains("\"RIFF:StreamType\":\"vids\""),
    "raw StreamType FourCC:\n{got}"
  );
  assert!(
    got.contains("\"File:BMPVersion\":40"),
    "raw BMPVersion:\n{got}"
  );
}

#[test]
fn media_metadata_projection_from_riff() {
  // The `from_riff` projection should populate MediaInfo with width / height /
  // created / duration (FrameCount/FrameRate) and CameraInfo.software from
  // INFO/ISFT.
  use exifast::AnyMeta;
  use exifast::filetype::detection_candidates;
  use exifast::format_parser::{SharedFlags, any_parser_for};
  use exifast::metadata::MediaMetadata;

  let root = env!("CARGO_MANIFEST_DIR");
  let data = std::fs::read(format!("{root}/tests/fixtures/RIFF.avi")).expect("read RIFF.avi");
  let candidates = detection_candidates("RIFF.avi", &data);
  let mut shared = SharedFlags::new();
  let mut riff_meta = None;
  for cand in candidates {
    if let Some(p) = any_parser_for(cand.file_type())
      && let Some(meta) = p.parse_any(&data, &mut shared, Some("avi"), 0, None, false)
    {
      if let AnyMeta::Riff(rm) = meta {
        riff_meta = Some(rm);
      }
      break;
    }
  }
  let riff = riff_meta.expect("RIFF.avi parsed as AnyMeta::Riff");

  let projected = MediaMetadata::from_riff(&riff);
  assert_eq!(projected.media().width(), Some(320));
  assert_eq!(projected.media().height(), Some(240));
  assert_eq!(projected.media().created(), Some("2003:03:10 15:04:43"));
  // RIFF.avi has video + audio streams.
  assert!(projected.media().has_video());
  assert!(projected.media().has_audio());
  // Software from INFO/ISFT.
  let camera = projected.camera().expect("CameraInfo populated by ISFT");
  assert_eq!(camera.software(), Some("CanonMVI01"));
}

// ===========================================================================
// WAV-specific tag tables (#152) — crafted fixtures + bundled `exiftool`
// oracle. The bundled `RIFF.wav` is plain PCM and carries none of these
// chunks, so each test builds a minimal valid RIFF/WAVE container in memory
// and asserts byte-exact against `perl exiftool -G1 -j[/-n] <file>` (13.59).
// ===========================================================================

/// Build a `(FOURCC, le-u32 length, payload)` chunk with the RIFF odd-length
/// pad byte (RIFF.pm:2140).
fn wav_chunk(fourcc: &[u8; 4], payload: &[u8]) -> Vec<u8> {
  let mut out = Vec::with_capacity(8 + payload.len() + 1);
  out.extend_from_slice(fourcc);
  out.extend_from_slice(&(payload.len() as u32).to_le_bytes());
  out.extend_from_slice(payload);
  if payload.len() & 1 == 1 {
    out.push(0); // pad
  }
  out
}

/// Wrap a body in a `RIFF....WAVE` outer container.
fn riff_wave(body: &[u8]) -> Vec<u8> {
  let mut out = Vec::with_capacity(12 + body.len());
  out.extend_from_slice(b"RIFF");
  out.extend_from_slice(&((4 + body.len()) as u32).to_le_bytes());
  out.extend_from_slice(b"WAVE");
  out.extend_from_slice(body);
  out
}

/// A minimal PCM `fmt ` chunk (1ch / 44100 / 16-bit) common to every fixture.
fn fmt_pcm() -> Vec<u8> {
  let mut p = Vec::new();
  p.extend_from_slice(&1u16.to_le_bytes()); // Encoding = PCM
  p.extend_from_slice(&1u16.to_le_bytes()); // NumChannels
  p.extend_from_slice(&44100u32.to_le_bytes()); // SampleRate
  p.extend_from_slice(&88200u32.to_le_bytes()); // AvgBytesPerSec
  p.extend_from_slice(&2u16.to_le_bytes()); // BlockAlign
  p.extend_from_slice(&16u16.to_le_bytes()); // BitsPerSample
  wav_chunk(b"fmt ", &p)
}

fn data_min() -> Vec<u8> {
  wav_chunk(b"data", &[0, 0, 0, 0])
}

#[test]
fn wav_bext_broadcast_extension_matches_oracle() {
  // `bext` BroadcastExtension (RIFF.pm:712-759). Oracle:
  //   perl exiftool -G1 -j wav_bext.wav  =>
  //     "RIFF:Description": "Test broadcast description"
  //     "RIFF:Originator": "exifast-test"
  //     "RIFF:OriginatorReference": "REF12345"
  //     "RIFF:DateTimeOriginal": "2024:03:10 12:30:45"
  //     "RIFF:TimeReference": 4418424085
  //     "RIFF:BWFVersion": 2
  //     "RIFF:BWF_UMID": "1234567800000000000000000000000000000000000000000000000000000000"
  //     "RIFF:CodingHistory": "A=PCM,F=44100,W=16,M=mono"
  let mut p = Vec::new();
  let mut desc = b"Test broadcast description".to_vec();
  desc.resize(256, 0);
  p.extend_from_slice(&desc);
  let mut orig = b"exifast-test".to_vec();
  orig.resize(32, 0);
  p.extend_from_slice(&orig);
  let mut origref = b"REF12345".to_vec();
  origref.resize(32, 0);
  p.extend_from_slice(&origref);
  p.extend_from_slice(b"2024-03-1012:30:45"); // 18-byte date+time region
  p.extend_from_slice(&123_456_789u32.to_le_bytes()); // TimeReference low
  p.extend_from_slice(&1u32.to_le_bytes()); // TimeReference high
  p.extend_from_slice(&2u16.to_le_bytes()); // BWFVersion
  let mut umid = vec![0x12u8, 0x34, 0x56, 0x78];
  umid.resize(64, 0);
  p.extend_from_slice(&umid); // BWF_UMID undef[64]
  p.extend_from_slice(&[0u8; 190]); // reserved
  p.extend_from_slice(b"A=PCM,F=44100,W=16,M=mono"); // CodingHistory
  let data = riff_wave(&[fmt_pcm(), wav_chunk(b"bext", &p), data_min()].concat());

  let got = extract_info("wav_bext.wav", &data, true);
  for needle in [
    r#""RIFF:Description":"Test broadcast description""#,
    r#""RIFF:Originator":"exifast-test""#,
    r#""RIFF:OriginatorReference":"REF12345""#,
    r#""RIFF:DateTimeOriginal":"2024:03:10 12:30:45""#,
    r#""RIFF:TimeReference":4418424085"#,
    r#""RIFF:BWFVersion":2"#,
    r#""RIFF:BWF_UMID":"1234567800000000000000000000000000000000000000000000000000000000""#,
    r#""RIFF:CodingHistory":"A=PCM,F=44100,W=16,M=mono""#,
  ] {
    assert!(got.contains(needle), "missing {needle}:\n{got}");
  }
}

#[test]
fn wav_smpl_sampler_matches_oracle() {
  // `smpl` Sampler (RIFF.pm:787-818). Oracle (-j):
  //   "RIFF:Manufacturer":0,"RIFF:Product":0,"RIFF:SamplePeriod":22675,
  //   "RIFF:MIDIUnityNote":60,"RIFF:MIDIPitchFraction":0,
  //   "RIFF:SMPTEFormat":"none","RIFF:SMPTEOffset":"01:02:03:04",
  //   "RIFF:NumSampleLoops":1,"RIFF:SamplerDataLen":0,
  //   "RIFF:SamplerData":"(Binary data 20 bytes, use -b option to extract)"
  // (-n): "RIFF:SMPTEFormat":0
  let mut p = Vec::new();
  for v in [0u32, 0, 22675, 60, 0, 0, 0x0102_0304, 1, 0] {
    p.extend_from_slice(&v.to_le_bytes());
  }
  p.extend_from_slice(&[0u8; 24]); // one 24-byte loop record (SamplerData region)
  let data = riff_wave(&[fmt_pcm(), wav_chunk(b"smpl", &p), data_min()].concat());

  let got = extract_info("wav_smpl.wav", &data, true);
  for needle in [
    r#""RIFF:SamplePeriod":22675"#,
    r#""RIFF:MIDIUnityNote":60"#,
    r#""RIFF:SMPTEFormat":"none""#,
    r#""RIFF:SMPTEOffset":"01:02:03:04""#,
    r#""RIFF:NumSampleLoops":1"#,
    r#""RIFF:SamplerDataLen":0"#,
    r#""RIFF:SamplerData":"(Binary data 20 bytes, use -b option to extract)""#,
  ] {
    assert!(got.contains(needle), "missing {needle}:\n{got}");
  }
  let got_n = extract_info("wav_smpl.wav", &data, false);
  assert!(
    got_n.contains(r#""RIFF:SMPTEFormat":0"#),
    "raw SMPTEFormat:\n{got_n}"
  );
  // SMPTEOffset is a ValueConv (identical in both modes).
  assert!(
    got_n.contains(r#""RIFF:SMPTEOffset":"01:02:03:04""#),
    "raw SMPTEOffset:\n{got_n}"
  );
}

#[test]
fn wav_smpl_no_sampler_data_when_size_below_40() {
  // `SamplerData undef[$size-40]` — a 36-byte smpl (9 int32u, no loop) gives a
  // NEGATIVE count, so ExifTool emits NO SamplerData (verified vs 13.59:
  // `$size=36` => field absent), but every int32u scalar still emits.
  let mut p = Vec::new();
  for v in [0u32, 0, 22675, 60, 0, 0, 0x0102_0304, 0, 0] {
    p.extend_from_slice(&v.to_le_bytes());
  }
  assert_eq!(p.len(), 36);
  let data = riff_wave(&[fmt_pcm(), wav_chunk(b"smpl", &p), data_min()].concat());
  let got = extract_info("wav_smpl36.wav", &data, true);
  assert!(
    got.contains(r#""RIFF:NumSampleLoops":0"#),
    "scalar still emitted:\n{got}"
  );
  assert!(
    !got.contains("RIFF:SamplerData\""),
    "SamplerData must be absent for size<40:\n{got}"
  );
}

#[test]
fn wav_inst_instrument_int8s_matches_oracle() {
  // `inst` Instrument (RIFF.pm:821-832, int8s). Oracle:
  //   "RIFF:UnshiftedNote":60,"RIFF:FineTune":0,"RIFF:Gain":-3,
  //   "RIFF:LowNote":0,"RIFF:HighNote":127,"RIFF:LowVelocity":0,
  //   "RIFF:HighVelocity":127
  let p: Vec<u8> = [60i8, 0, -3, 0, 127, 0, 127]
    .iter()
    .map(|&b| b as u8)
    .collect();
  let data = riff_wave(&[fmt_pcm(), wav_chunk(b"inst", &p), data_min()].concat());
  let got = extract_info("wav_inst.wav", &data, true);
  for needle in [
    r#""RIFF:UnshiftedNote":60"#,
    r#""RIFF:Gain":-3"#,
    r#""RIFF:HighNote":127"#,
    r#""RIFF:HighVelocity":127"#,
  ] {
    assert!(got.contains(needle), "missing {needle}:\n{got}");
  }
}

#[test]
fn wav_acid_acidizer_matches_oracle() {
  // `acid` Acidizer (RIFF.pm:1500-1545). Two records to exercise BITMASK
  // multi-bit + Meter swap + RootNote hash.
  //
  // Record A (flags bit1, RootNote 0x3c, Meter 4/4, Tempo 120.5). Oracle (-j):
  //   "RIFF:AcidizerFlags":"Root note set","RIFF:RootNote":"High C",
  //   "RIFF:Beats":4,"RIFF:Meter":"4/4","RIFF:Tempo":120.5
  // (-n): AcidizerFlags 2, RootNote 60, Meter "4 4".
  let mut a = Vec::new();
  a.extend_from_slice(&0b10u32.to_le_bytes()); // AcidizerFlags
  a.extend_from_slice(&0x3cu16.to_le_bytes()); // RootNote
  a.extend_from_slice(&0u16.to_le_bytes()); // (gap)
  a.extend_from_slice(&0u32.to_le_bytes()); // (gap to offset 12)
  a.extend_from_slice(&4u32.to_le_bytes()); // Beats
  a.extend_from_slice(&4u16.to_le_bytes()); // Meter denominator
  a.extend_from_slice(&4u16.to_le_bytes()); // Meter numerator
  a.extend_from_slice(&120.5f32.to_le_bytes()); // Tempo
  let data_a = riff_wave(&[fmt_pcm(), wav_chunk(b"acid", &a), data_min()].concat());
  let got_a = extract_info("wav_acid.wav", &data_a, true);
  for needle in [
    r#""RIFF:AcidizerFlags":"Root note set""#,
    r#""RIFF:RootNote":"High C""#,
    r#""RIFF:Beats":4"#,
    r#""RIFF:Meter":"4/4""#,
    r#""RIFF:Tempo":120.5"#,
  ] {
    assert!(got_a.contains(needle), "missing {needle}:\n{got_a}");
  }
  let got_a_n = extract_info("wav_acid.wav", &data_a, false);
  for needle in [
    r#""RIFF:AcidizerFlags":2"#,
    r#""RIFF:RootNote":60"#,
    r#""RIFF:Meter":"4 4""#,
  ] {
    assert!(got_a_n.contains(needle), "missing raw {needle}:\n{got_a_n}");
  }

  // Record B (flags bits 0,2,4, RootNote 0x35, Meter 4/3, Tempo 140.25).
  // Oracle (-j): "RIFF:AcidizerFlags":"One shot, Stretch, High octave",
  //   "RIFF:RootNote":"F","RIFF:Meter":"3/4". (-n) flags 21, RootNote 53,
  //   Meter "4 3".
  let mut b = Vec::new();
  b.extend_from_slice(&0b10101u32.to_le_bytes());
  b.extend_from_slice(&0x35u16.to_le_bytes());
  b.extend_from_slice(&0u16.to_le_bytes());
  b.extend_from_slice(&0u32.to_le_bytes());
  b.extend_from_slice(&8u32.to_le_bytes());
  b.extend_from_slice(&4u16.to_le_bytes()); // denominator
  b.extend_from_slice(&3u16.to_le_bytes()); // numerator
  b.extend_from_slice(&140.25f32.to_le_bytes());
  let data_b = riff_wave(&[fmt_pcm(), wav_chunk(b"acid", &b), data_min()].concat());
  let got_b = extract_info("wav_acid2.wav", &data_b, true);
  for needle in [
    r#""RIFF:AcidizerFlags":"One shot, Stretch, High octave""#,
    r#""RIFF:RootNote":"F""#,
    r#""RIFF:Meter":"3/4""#,
    r#""RIFF:Tempo":140.25"#,
  ] {
    assert!(got_b.contains(needle), "missing {needle}:\n{got_b}");
  }
  let got_b_n = extract_info("wav_acid2.wav", &data_b, false);
  assert!(
    got_b_n.contains(r#""RIFF:AcidizerFlags":21"#) && got_b_n.contains(r#""RIFF:Meter":"4 3""#),
    "raw record B:\n{got_b_n}"
  );
}

#[test]
fn wav_fact_num_samples_matches_oracle() {
  // `fact` NumberOfSamples — RawConv Get32u (RIFF.pm:512-515).
  let data = riff_wave(
    &[
      fmt_pcm(),
      wav_chunk(b"fact", &44100u32.to_le_bytes()),
      data_min(),
    ]
    .concat(),
  );
  let got = extract_info("wav_fact.wav", &data, true);
  assert!(
    got.contains(r#""RIFF:NumberOfSamples":44100"#),
    "missing NumberOfSamples:\n{got}"
  );
}

#[test]
fn wav_cue_and_plst_binary_placeholders_match_oracle() {
  // `cue ` CuePoints / `plst` Playlist — Binary => 1 (RIFF.pm:516-524).
  let mut cue = Vec::new();
  cue.extend_from_slice(&1u32.to_le_bytes()); // num cue points
  cue.extend_from_slice(&[0u8; 24]); // one cue-point record
  assert_eq!(cue.len(), 28);
  let data_cue = riff_wave(&[fmt_pcm(), wav_chunk(b"cue ", &cue), data_min()].concat());
  let got_cue = extract_info("wav_cue.wav", &data_cue, true);
  assert!(
    got_cue.contains(r#""RIFF:CuePoints":"(Binary data 28 bytes, use -b option to extract)""#),
    "missing CuePoints placeholder:\n{got_cue}"
  );

  let mut plst = Vec::new();
  plst.extend_from_slice(&1u32.to_le_bytes());
  plst.extend_from_slice(&[0u8; 12]);
  assert_eq!(plst.len(), 16);
  let data_plst = riff_wave(&[fmt_pcm(), wav_chunk(b"plst", &plst), data_min()].concat());
  let got_plst = extract_info("wav_plst.wav", &data_plst, true);
  assert!(
    got_plst.contains(r#""RIFF:Playlist":"(Binary data 16 bytes, use -b option to extract)""#),
    "missing Playlist placeholder:\n{got_plst}"
  );
}

#[test]
fn wav_ds64_rf64_sizes_match_oracle() {
  // `ds64` DataSize64 (RIFF.pm:762-784, RF64 container). Oracle (-j):
  //   "RIFF:RIFFSize64":"5.0 MB","RIFF:DataSize64":"4.0 MB",
  //   "RIFF:NumberOfSamples64":1000000
  // (-n): raw 5000000 / 4000000 / 1000000 (NumberOfSamples64 has no PrintConv).
  let mut ds = Vec::new();
  ds.extend_from_slice(&5_000_000u64.to_le_bytes());
  ds.extend_from_slice(&4_000_000u64.to_le_bytes());
  ds.extend_from_slice(&1_000_000u64.to_le_bytes());
  // RF64 outer container: RIFF size field = 0xFFFFFFFF.
  let body = [wav_chunk(b"ds64", &ds), fmt_pcm(), data_min()].concat();
  let mut data = Vec::new();
  data.extend_from_slice(b"RF64");
  data.extend_from_slice(&0xFFFF_FFFFu32.to_le_bytes());
  data.extend_from_slice(b"WAVE");
  data.extend_from_slice(&body);

  let got = extract_info("wav_ds64.wav", &data, true);
  for needle in [
    r#""RIFF:RIFFSize64":"5.0 MB""#,
    r#""RIFF:DataSize64":"4.0 MB""#,
    r#""RIFF:NumberOfSamples64":1000000"#,
  ] {
    assert!(got.contains(needle), "missing {needle}:\n{got}");
  }
  let got_n = extract_info("wav_ds64.wav", &data, false);
  for needle in [
    r#""RIFF:RIFFSize64":5000000"#,
    r#""RIFF:DataSize64":4000000"#,
    r#""RIFF:NumberOfSamples64":1000000"#,
  ] {
    assert!(got_n.contains(needle), "missing raw {needle}:\n{got_n}");
  }
}

#[test]
fn wav_adtl_labl_note_ltxt_match_oracle() {
  // LIST_adtl cue-point sub-chunks (RIFF.pm:369-390). Oracle (-j):
  //   "RIFF:CuePointLabel":"1 Marker One"
  //   "RIFF:CuePointNote":"2 A note"
  //   "RIFF:LabeledText":"3 100 'rgn ' 0 1033 0 0 Region text"
  // The ltxt text region begins at byte 18 (overlapping the Codepage int16u);
  // ExifTool's JSON tr/\0//d removes the leading NULs.
  let mut labl = Vec::new();
  labl.extend_from_slice(&1u32.to_le_bytes());
  labl.extend_from_slice(b"Marker One\0");
  let mut note = Vec::new();
  note.extend_from_slice(&2u32.to_le_bytes());
  note.extend_from_slice(b"A note\0");
  let mut ltxt = Vec::new();
  ltxt.extend_from_slice(&3u32.to_le_bytes()); // CuePointID
  ltxt.extend_from_slice(&100u32.to_le_bytes()); // Length
  ltxt.extend_from_slice(b"rgn "); // Purpose (a4, trailing space KEPT)
  ltxt.extend_from_slice(&0u16.to_le_bytes()); // Country
  ltxt.extend_from_slice(&1033u16.to_le_bytes()); // Language
  ltxt.extend_from_slice(&0u16.to_le_bytes()); // Dialect
  ltxt.extend_from_slice(&0u16.to_le_bytes()); // Codepage
  ltxt.extend_from_slice(b"Region text\0");

  let adtl_body = [
    b"adtl".to_vec(),
    wav_chunk(b"labl", &labl),
    wav_chunk(b"note", &note),
    wav_chunk(b"ltxt", &ltxt),
  ]
  .concat();
  let mut list = Vec::new();
  list.extend_from_slice(b"LIST");
  list.extend_from_slice(&(adtl_body.len() as u32).to_le_bytes());
  list.extend_from_slice(&adtl_body);

  let data = riff_wave(&[fmt_pcm(), list, data_min()].concat());
  let got = extract_info("wav_adtl.wav", &data, true);
  for needle in [
    r#""RIFF:CuePointLabel":"1 Marker One""#,
    r#""RIFF:CuePointNote":"2 A note""#,
    r#""RIFF:LabeledText":"3 100 'rgn ' 0 1033 0 0 Region text""#,
  ] {
    assert!(got.contains(needle), "missing {needle}:\n{got}");
  }
  // No \0 must survive into the JSON (faithful EscapeJSON tr/\0//d).
  assert!(
    !got.contains("\\u0000"),
    "NUL must be stripped from JSON value:\n{got}"
  );
}

#[test]
fn wav_acid_rootnote_offmap_emits_unknown() {
  // `acid` RootNote (RIFF.pm:1508-1531) is a plain `PrintConv => { ... }` hash
  // with NO OTHER and NO PrintHex, so a hash MISS renders via ExifTool's
  // generic fallback `Unknown ($val)` with the DECIMAL `$val`, NOT a raw
  // number. RootNote=0 is off-map. Oracle (13.59):
  //   perl exiftool -G1 -j -RootNote   => "RIFF:RootNote": "Unknown (0)"
  //   perl exiftool -G1 -j -n -RootNote => "RIFF:RootNote": 0
  //   (hit 0x3c)        -G1 -j          => "RIFF:RootNote": "High C"
  fn acid_with_root_note(root: u16) -> Vec<u8> {
    let mut a = Vec::new();
    a.extend_from_slice(&0u32.to_le_bytes()); // AcidizerFlags
    a.extend_from_slice(&root.to_le_bytes()); // RootNote
    a.extend_from_slice(&0u16.to_le_bytes()); // (gap)
    a.extend_from_slice(&0u32.to_le_bytes()); // (gap to offset 12)
    a.extend_from_slice(&4u32.to_le_bytes()); // Beats
    a.extend_from_slice(&4u16.to_le_bytes()); // Meter denominator
    a.extend_from_slice(&4u16.to_le_bytes()); // Meter numerator
    a.extend_from_slice(&120.0f32.to_le_bytes()); // Tempo
    riff_wave(&[fmt_pcm(), wav_chunk(b"acid", &a), data_min()].concat())
  }

  // Off-map (0) → "Unknown (0)" in -j, raw 0 in -n.
  let off = acid_with_root_note(0);
  let got = extract_info("wav_acid_rn0.wav", &off, true);
  assert!(
    got.contains(r#""RIFF:RootNote":"Unknown (0)""#),
    "off-map RootNote must render Unknown (0):\n{got}"
  );
  let got_n = extract_info("wav_acid_rn0.wav", &off, false);
  assert!(
    got_n.contains(r#""RIFF:RootNote":0"#),
    "-n RootNote must be the raw number:\n{got_n}"
  );

  // On-map (0x3c) still renders the label (hit path not regressed).
  let hit = acid_with_root_note(0x3c);
  let got_hit = extract_info("wav_acid_rn60.wav", &hit, true);
  assert!(
    got_hit.contains(r#""RIFF:RootNote":"High C""#),
    "on-map RootNote must render its label:\n{got_hit}"
  );
}

#[test]
fn wav_smpl_smpteformat_offmap_emits_unknown() {
  // `smpl` SMPTEFormat (RIFF.pm:797-805) is a plain `PrintConv => { ... }` hash
  // with NO OTHER and NO PrintHex, so a hash MISS renders `Unknown ($val)`
  // (decimal), NOT a raw number. SMPTEFormat=1 is off-map. Oracle (13.59):
  //   -G1 -j    => "RIFF:SMPTEFormat": "Unknown (1)"
  //   -G1 -j -n => "RIFF:SMPTEFormat": 1
  //   (hit 0)   => "RIFF:SMPTEFormat": "none"
  fn smpl_with_smpte(fmt: u32) -> Vec<u8> {
    let mut p = Vec::new();
    for v in [0u32, 0, 22675, 60, 0, fmt, 0x0102_0304, 0, 0] {
      p.extend_from_slice(&v.to_le_bytes());
    }
    riff_wave(&[fmt_pcm(), wav_chunk(b"smpl", &p), data_min()].concat())
  }

  // Off-map (1) → "Unknown (1)" in -j, raw 1 in -n.
  let off = smpl_with_smpte(1);
  let got = extract_info("wav_smpl_smpte1.wav", &off, true);
  assert!(
    got.contains(r#""RIFF:SMPTEFormat":"Unknown (1)""#),
    "off-map SMPTEFormat must render Unknown (1):\n{got}"
  );
  let got_n = extract_info("wav_smpl_smpte1.wav", &off, false);
  assert!(
    got_n.contains(r#""RIFF:SMPTEFormat":1"#),
    "-n SMPTEFormat must be the raw number:\n{got_n}"
  );

  // On-map (0) still renders "none" (hit path not regressed).
  let hit = smpl_with_smpte(0);
  let got_hit = extract_info("wav_smpl_smpte0.wav", &hit, true);
  assert!(
    got_hit.contains(r#""RIFF:SMPTEFormat":"none""#),
    "on-map SMPTEFormat must render its label:\n{got_hit}"
  );
}

#[test]
fn wav_adtl_repeated_labl_first_wins() {
  // `labl` (RIFF.pm:371-375) carries `Priority => 0` ("so they are stored in
  // sequence"). Two `labl` chunks share the tag NAME `CuePointLabel`, so they
  // collide on `(group, name)` regardless of the embedded cue-point ID, and
  // ExifTool's Priority-0 survivor is the FIRST-extracted. Oracle (13.59):
  //   two labl, same cue id (1,1)    => "RIFF:CuePointLabel": "1 First label"
  //   two labl, diff cue id (1,2)    => "RIFF:CuePointLabel": "1 First label"
  fn two_labl(id1: u32, id2: u32) -> Vec<u8> {
    let mut labl1 = id1.to_le_bytes().to_vec();
    labl1.extend_from_slice(b"First label\0");
    let mut labl2 = id2.to_le_bytes().to_vec();
    labl2.extend_from_slice(b"Second label\0");
    let adtl_body = [
      b"adtl".to_vec(),
      wav_chunk(b"labl", &labl1),
      wav_chunk(b"labl", &labl2),
    ]
    .concat();
    let mut list = Vec::new();
    list.extend_from_slice(b"LIST");
    list.extend_from_slice(&(adtl_body.len() as u32).to_le_bytes());
    list.extend_from_slice(&adtl_body);
    riff_wave(&[fmt_pcm(), list, data_min()].concat())
  }

  // Same cue id: the FIRST label survives.
  let same = two_labl(1, 1);
  let got = extract_info("wav_adtl_2labl.wav", &same, true);
  assert!(
    got.contains(r#""RIFF:CuePointLabel":"1 First label""#),
    "Priority=0 first-wins: first labl must survive:\n{got}"
  );
  assert!(
    !got.contains("Second label"),
    "the second labl must be dropped (first-wins):\n{got}"
  );

  // Different cue id: still the FIRST label survives (the name collides
  // regardless of cue id).
  let diff = two_labl(1, 2);
  let got_diff = extract_info("wav_adtl_2labl_diff.wav", &diff, true);
  assert!(
    got_diff.contains(r#""RIFF:CuePointLabel":"1 First label""#),
    "Priority=0 first-wins across distinct cue ids:\n{got_diff}"
  );
  assert!(
    !got_diff.contains("Second label"),
    "the second labl must be dropped (first-wins):\n{got_diff}"
  );
}

/// Build a minimal AVI (`RIFF`/`AVI ` + `LIST_hdrl`/`avih` + one `JUNK` chunk)
/// carrying `junk` as the JUNK payload. The `avih` is a 56-byte int32u header
/// (320x240, 10 frames, 1 stream) — enough for the walker to set the AVI file
/// type and reach the top-level `JUNK` chunk.
fn riff_avi_with_junk(junk: &[u8]) -> Vec<u8> {
  let mut avih = Vec::new();
  for v in [41666u32, 0, 0, 0x10, 10, 0, 1, 0, 320, 240, 0, 0, 0, 0] {
    avih.extend_from_slice(&v.to_le_bytes());
  }
  let mut hdrl = Vec::from(*b"hdrl");
  hdrl.extend_from_slice(&wav_chunk(b"avih", &avih));
  let lst = wav_chunk(b"LIST", &hdrl);
  let junk_chunk = wav_chunk(b"JUNK", junk);
  let mut body = Vec::from(*b"AVI ");
  body.extend_from_slice(&lst);
  body.extend_from_slice(&junk_chunk);
  let mut out = Vec::from(*b"RIFF");
  out.extend_from_slice(&((body.len()) as u32).to_le_bytes());
  out.extend_from_slice(&body);
  out
}

#[test]
fn junk_textjunk_ascii_fallback_emits() {
  // RIFF.pm:488-491 `TextJunk`: a printable run + trailing NULs → `RIFF:TextJunk`.
  let data = riff_avi_with_junk(b"Hello RIFF Junk Text\0\0\0\0");
  let got = extract_info("t.avi", &data, true);
  assert!(
    got.contains("\"RIFF:TextJunk\":\"Hello RIFF Junk Text\""),
    "TextJunk fallback should emit the printable run:\n{got}"
  );
}

#[test]
fn junk_textjunk_rejects_embedded_control_byte() {
  // The RawConv is end-anchored (`\0*$`): a control byte AFTER the printable run
  // (not a trailing NUL) fails the whole match ⇒ no `TextJunk`.
  let data = riff_avi_with_junk(b"Hello\x01World\0");
  let got = extract_info("t.avi", &data, true);
  assert!(
    !got.contains("RIFF:TextJunk"),
    "an embedded control byte must reject TextJunk:\n{got}"
  );
}

#[test]
fn junk_textjunk_rejects_high_byte() {
  // A high byte (0x7f-0xff) is excluded from the printable class ⇒ no match.
  let data = riff_avi_with_junk(b"Caf\xe9\0\0");
  let got = extract_info("t.avi", &data, true);
  assert!(
    !got.contains("RIFF:TextJunk"),
    "a high byte must reject TextJunk:\n{got}"
  );
}

#[test]
fn junk_textjunk_rejects_empty_or_all_nul() {
  // `+` requires a NON-EMPTY printable run; an all-NUL payload has none ⇒ undef.
  let data = riff_avi_with_junk(b"\0\0\0\0");
  let got = extract_info("t.avi", &data, true);
  assert!(
    !got.contains("RIFF:TextJunk"),
    "an all-NUL JUNK must not emit TextJunk:\n{got}"
  );
}

#[test]
fn junk_pentax_junk_emits_model_under_makernotes() {
  // RIFF.pm:469-473 `PentaxJunk` (`^IIII\x01\0` → `%Pentax::Junk`): Model @ 0x0c.
  let mut junk = vec![0u8; 0x2c];
  junk[0..4].copy_from_slice(b"IIII");
  junk[4..6].copy_from_slice(b"\x01\x00");
  junk[0x0c..0x0c + 12].copy_from_slice(b"Optio RS1000");
  let data = riff_avi_with_junk(&junk);
  let got = extract_info("t.avi", &data, true);
  assert!(
    got.contains("\"Pentax:Model\":\"Optio RS1000\""),
    "PentaxJunk Model should emit under MakerNotes:Pentax:\n{got}"
  );
  // It must NOT also leak as a RIFF:TextJunk (the Pentax condition wins first).
  assert!(
    !got.contains("RIFF:TextJunk"),
    "a Pentax-signature JUNK must not fall through to TextJunk:\n{got}"
  );
}

#[test]
fn junk_deferred_vendor_signature_not_emitted_as_textjunk() {
  // RIFF.pm:445 `OlympusJunk` (`^OLYMDigital Camera`) routes to a deferred
  // subsystem — the printable signature must NOT be mis-emitted as `TextJunk`
  // (the ordered conditions match Olympus FIRST).
  let mut junk = Vec::from(*b"OLYMDigital Camera");
  junk.extend_from_slice(&[0u8; 8]);
  let data = riff_avi_with_junk(&junk);
  let got = extract_info("t.avi", &data, true);
  assert!(
    !got.contains("RIFF:TextJunk"),
    "an OlympusJunk-signature JUNK must not emit TextJunk:\n{got}"
  );
}

#[test]
fn junq_oldxmp_not_routed_through_junk_dispatch() {
  // `JUNQ` is the `%Main` `OldXMP` tag (RIFF.pm:498-502), NOT a `JUNK` variant.
  // A `JUNQ` chunk whose bytes would match the TextJunk RawConv must still NOT
  // emit `RIFF:TextJunk` (it never reaches the JUNK dispatch).
  let mut avih = Vec::new();
  for v in [41666u32, 0, 0, 0x10, 10, 0, 1, 0, 320, 240, 0, 0, 0, 0] {
    avih.extend_from_slice(&v.to_le_bytes());
  }
  let mut hdrl = Vec::from(*b"hdrl");
  hdrl.extend_from_slice(&wav_chunk(b"avih", &avih));
  let lst = wav_chunk(b"LIST", &hdrl);
  let junq = wav_chunk(b"JUNQ", b"PrintableOldXMP\0");
  let mut body = Vec::from(*b"AVI ");
  body.extend_from_slice(&lst);
  body.extend_from_slice(&junq);
  let mut data = Vec::from(*b"RIFF");
  data.extend_from_slice(&((body.len()) as u32).to_le_bytes());
  data.extend_from_slice(&body);
  let got = extract_info("t.avi", &data, true);
  assert!(
    !got.contains("RIFF:TextJunk"),
    "JUNQ must not be routed through the JUNK TextJunk dispatch:\n{got}"
  );
}

// ===========================================================================
// `%Pentax::Junk2` FNumber PrintConv (`sprintf("%.1f",$val)`, Pentax.pm:6633) —
// faithful `%.1f` half-even + the `-j`/`-n` rendering + the zero-denominator
// `inf`/`undef` path + the derived `Composite:Aperture` (#154 Codex [high]).
// Each expected value below was captured from bundled ExifTool 13.59 (`-j`/`-n`
// `-G1` on the crafted FNumber).
// ===========================================================================

/// Build a minimal `PentaxJunk2` AVI (`^PENTDigital Camera` → `%Pentax::Junk2`,
/// RIFF.pm:474-478) whose `FNumber` `rational64u` (@ payload 0x5e) is
/// `num`/`denom`. `Make` (@0x12) and `Model` (@0x2c) carry fixed strings so the
/// derived `Composite:Aperture` (which selects the raw FNumber operand) is the
/// only aperture surface under test.
fn pentaxjunk2_avi_fnumber(num: u32, denom: u32) -> Vec<u8> {
  let mut payload = vec![0u8; 0x66];
  payload[0..18].copy_from_slice(b"PENTDigital Camera");
  payload[0x12..0x12 + 6].copy_from_slice(b"PENTAX");
  payload[0x2c..0x2c + 10].copy_from_slice(b"Optio RZ18");
  payload[0x5e..0x5e + 4].copy_from_slice(&num.to_le_bytes());
  payload[0x5e + 4..0x5e + 8].copy_from_slice(&denom.to_le_bytes());
  riff_avi_with_junk(&payload)
}

#[test]
fn pentaxjunk2_fnumber_whole_renders_dot_zero() {
  // 4/1: bundled `-j` `FNumber`/`Aperture` = `4.0` (the `%.1f` string `"4.0"`
  // passes EscapeJSON's number gate → a BARE JSON number WITH the `.0`); `-n` =
  // `4` (the raw `%g` quotient). NOT a bare `4` at `-j` (the pre-fix bug).
  let data = pentaxjunk2_avi_fnumber(4, 1);
  let j = extract_info("pj2.avi", &data, true);
  assert!(
    j.contains("\"Pentax:FNumber\":4.0,"),
    "4/1 -j FNumber must render the bare JSON number 4.0 (not 4):\n{j}"
  );
  assert!(
    j.contains("\"Composite:Aperture\":4.0,"),
    "4/1 -j Composite:Aperture must follow FNumber as 4.0:\n{j}"
  );
  let n = extract_info("pj2.avi", &data, false);
  assert!(
    n.contains("\"Pentax:FNumber\":4,"),
    "4/1 -n FNumber must render the raw quotient 4:\n{n}"
  );
  assert!(
    n.contains("\"Composite:Aperture\":4,"),
    "4/1 -n Composite:Aperture must follow FNumber as 4:\n{n}"
  );
}

#[test]
fn pentaxjunk2_fnumber_is_round_half_even_not_half_away() {
  // The crux of the finding: Perl `sprintf("%.1f",$val)` is round-HALF-EVEN, so
  // `225/100` (= 2.25, a tie) rounds DOWN to `2.2` (the nearest EVEN last digit),
  // NOT `.round()`'s half-away `2.3`. Rust's `format!("{:.1}")` is also
  // half-even, so the two agree byte-for-byte. `-n` keeps the raw `2.25`.
  let data = pentaxjunk2_avi_fnumber(225, 100);
  let j = extract_info("pj2.avi", &data, true);
  assert!(
    j.contains("\"Pentax:FNumber\":2.2,"),
    "225/100 -j FNumber must be the half-even 2.2 (NOT the half-away 2.3):\n{j}"
  );
  assert!(
    j.contains("\"Composite:Aperture\":2.2,"),
    "225/100 -j Composite:Aperture must follow FNumber as 2.2:\n{j}"
  );
  let n = extract_info("pj2.avi", &data, false);
  assert!(
    n.contains("\"Pentax:FNumber\":2.25,"),
    "225/100 -n FNumber must keep the raw quotient 2.25:\n{n}"
  );
  assert!(
    n.contains("\"Composite:Aperture\":2.25,"),
    "225/100 -n Composite:Aperture must keep the raw 2.25:\n{n}"
  );
}

#[test]
fn pentaxjunk2_fnumber_half_even_ties_round_to_even() {
  // Two more half-even ties confirm the rounding rule against bundled: `235/100`
  // (= 2.35) → `2.4` (round UP to even), `245/100` (= 2.45) → `2.5` (round UP to
  // even). A naive half-away `.round()` would give the same `2.4`/`2.5` here, but
  // `225/100`→`2.2` (above) is where half-even and half-away diverge; these pin
  // the whole tie class against bundled.
  for (num, fj, fn_) in [(235u32, "2.4", "2.35"), (245u32, "2.5", "2.45")] {
    let data = pentaxjunk2_avi_fnumber(num, 100);
    let j = extract_info("pj2.avi", &data, true);
    assert!(
      j.contains(&format!("\"Pentax:FNumber\":{fj},")),
      "{num}/100 -j FNumber must be the half-even {fj}:\n{j}"
    );
    let n = extract_info("pj2.avi", &data, false);
    assert!(
      n.contains(&format!("\"Pentax:FNumber\":{fn_},")),
      "{num}/100 -n FNumber must keep the raw {fn_}:\n{n}"
    );
  }
}

#[test]
fn pentaxjunk2_fnumber_zero_denom_nonzero_num_is_inf() {
  // A degenerate `1/0` rational: ExifTool `ReadValue` yields the bare word
  // `"inf"` (numerator != 0). bundled `-n` `FNumber`/`Aperture` = `"inf"`
  // (lowercase, QUOTED); `-j` `FNumber` = `"Inf"` (Perl `sprintf("%.1f",Inf)` is
  // TITLECASE) while `Composite:Aperture` = `"inf"` (the raw operand passes
  // through `PrintFNumber` unchanged). The tag is EMITTED, not suppressed.
  let data = pentaxjunk2_avi_fnumber(1, 0);
  let j = extract_info("pj2.avi", &data, true);
  assert!(
    j.contains("\"Pentax:FNumber\":\"Inf\","),
    "1/0 -j FNumber must be the titlecase quoted \"Inf\":\n{j}"
  );
  assert!(
    j.contains("\"Composite:Aperture\":\"inf\","),
    "1/0 -j Composite:Aperture must be the lowercase quoted \"inf\":\n{j}"
  );
  let n = extract_info("pj2.avi", &data, false);
  assert!(
    n.contains("\"Pentax:FNumber\":\"inf\","),
    "1/0 -n FNumber must be the lowercase quoted \"inf\":\n{n}"
  );
  assert!(
    n.contains("\"Composite:Aperture\":\"inf\","),
    "1/0 -n Composite:Aperture must be the lowercase quoted \"inf\":\n{n}"
  );
}

#[test]
fn pentaxjunk2_fnumber_zero_over_zero_is_undef() {
  // A `0/0` rational: ExifTool `ReadValue` yields the bare word `"undef"`.
  // bundled `-n` `FNumber`/`Aperture` = `"undef"` (QUOTED). At `-j` the asymmetry
  // is exact: `FNumber` = `0.0` (Perl numifies the STRING `"undef"` to `0`, so
  // `sprintf("%.1f","undef")` = `"0.0"` → a bare JSON `0.0`), while
  // `Composite:Aperture` = `"undef"` (its operand is the raw word `"undef"`,
  // which `PrintFNumber` leaves verbatim). Both EMITTED, not suppressed.
  let data = pentaxjunk2_avi_fnumber(0, 0);
  let j = extract_info("pj2.avi", &data, true);
  assert!(
    j.contains("\"Pentax:FNumber\":0.0,"),
    "0/0 -j FNumber must be the bare JSON number 0.0 (sprintf of numified undef):\n{j}"
  );
  assert!(
    j.contains("\"Composite:Aperture\":\"undef\","),
    "0/0 -j Composite:Aperture must be the quoted \"undef\":\n{j}"
  );
  let n = extract_info("pj2.avi", &data, false);
  assert!(
    n.contains("\"Pentax:FNumber\":\"undef\","),
    "0/0 -n FNumber must be the quoted \"undef\":\n{n}"
  );
  assert!(
    n.contains("\"Composite:Aperture\":\"undef\","),
    "0/0 -n Composite:Aperture must be the quoted \"undef\":\n{n}"
  );
}

#[test]
fn pentaxjunk2_fnumber_typical_decimal_is_unchanged() {
  // The real-device value (`28/10` = 2.8) keeps rendering `2.8` at `-j`
  // (`sprintf("%.1f",2.8)` = `"2.8"` → bare `2.8`) and `2.8` at `-n` — so the
  // bundled `AVI_pentaxjunk2.avi` golden is byte-identical after the fix.
  let data = pentaxjunk2_avi_fnumber(28, 10);
  let j = extract_info("pj2.avi", &data, true);
  assert!(
    j.contains("\"Pentax:FNumber\":2.8,") && j.contains("\"Composite:Aperture\":2.8,"),
    "28/10 must render 2.8 in -j (FNumber + Aperture):\n{j}"
  );
  let n = extract_info("pj2.avi", &data, false);
  assert!(
    n.contains("\"Pentax:FNumber\":2.8,") && n.contains("\"Composite:Aperture\":2.8,"),
    "28/10 must render 2.8 in -n (FNumber + Aperture):\n{n}"
  );
}

#[test]
fn pentaxjunk2_fnumber_roundfloat10_drops_excess_precision_whole() {
  // ExifTool `ReadValue` of a `rational64u` is `RoundFloat(num/denom, 10)` — 10
  // significant figures — applied BEFORE both the `%.1f` PrintConv AND the
  // `-n`/Composite ValueConv. `4000000001/4` = raw `1000000000.25`, but
  // `RoundFloat(_, 10)` = `1000000000` (the `.25` is beyond 10 sig figs). bundled
  // 13.59: `-j` `FNumber`/`Aperture` = `1000000000.0` (`%.1f` of the rounded
  // WHOLE value); `-n` `FNumber`/`Aperture` = `1000000000` (a bare INTEGER, NOT
  // `1000000000.25`). The pre-fix code formatted the RAW quotient → `-j`
  // `1000000000.2`, `-n` `1000000000.25` (both DIVERGE).
  let data = pentaxjunk2_avi_fnumber(4_000_000_001, 4);
  let j = extract_info("pj2.avi", &data, true);
  assert!(
    j.contains("\"Pentax:FNumber\":1000000000.0,"),
    "4000000001/4 -j FNumber must be %.1f of RoundFloat(_,10)=1000000000.0 (not the raw 1000000000.2):\n{j}"
  );
  assert!(
    j.contains("\"Composite:Aperture\":1000000000.0,"),
    "4000000001/4 -j Composite:Aperture must follow the rounded FNumber as 1000000000.0:\n{j}"
  );
  let n = extract_info("pj2.avi", &data, false);
  assert!(
    n.contains("\"Pentax:FNumber\":1000000000,"),
    "4000000001/4 -n FNumber must be the whole RoundFloat(_,10)=1000000000 (not the raw 1000000000.25):\n{n}"
  );
  assert!(
    n.contains("\"Composite:Aperture\":1000000000,"),
    "4000000001/4 -n Composite:Aperture must follow the rounded FNumber as 1000000000:\n{n}"
  );
}

#[test]
fn pentaxjunk2_fnumber_roundfloat10_caps_repeating_fraction() {
  // `1/3` = a 15-significant-figure repeating fraction raw, but `RoundFloat(_, 10)`
  // = `0.3333333333` (exactly 10 sig figs). bundled 13.59: `-n` `FNumber` =
  // `0.3333333333` (NOT the 15-digit `0.333333333333333`) and `Composite:Aperture`
  // = `0.3333333333` (its operand is that same rounded value); `-j` `FNumber` =
  // `0.3` (`%.1f` of the rounded value) while `Composite:Aperture` = `0.33`
  // (`PrintFNumber` of the operand `0.3333333333` → `sprintf("%.2g",...)`-style
  // `0.33`). The pre-fix code carried the raw 15-digit quotient (`-n` DIVERGES).
  let data = pentaxjunk2_avi_fnumber(1, 3);
  let j = extract_info("pj2.avi", &data, true);
  assert!(
    j.contains("\"Pentax:FNumber\":0.3,"),
    "1/3 -j FNumber must be %.1f of RoundFloat(_,10)=0.3:\n{j}"
  );
  assert!(
    j.contains("\"Composite:Aperture\":0.33,"),
    "1/3 -j Composite:Aperture must be PrintFNumber of the rounded operand = 0.33:\n{j}"
  );
  let n = extract_info("pj2.avi", &data, false);
  assert!(
    n.contains("\"Pentax:FNumber\":0.3333333333,"),
    "1/3 -n FNumber must be RoundFloat(_,10)=0.3333333333 (NOT the 15-digit raw quotient):\n{n}"
  );
  assert!(
    n.contains("\"Composite:Aperture\":0.3333333333,"),
    "1/3 -n Composite:Aperture must follow the rounded FNumber as 0.3333333333:\n{n}"
  );
}

#[test]
fn pentaxjunk2_fnumber_roundfloat10_exponent_token_is_emitted_verbatim() {
  // The TERMINAL precision case (#154 Codex [medium]): a `RoundFloat(num/denom, 10)`
  // whose magnitude is below 1e-4 renders in SCIENTIFIC notation — ExifTool's `%g`
  // emits a 2-digit signed exponent (`format_g(_, 10)`), so a tiny `1/100000` has
  // `$val` `1e-05` and `1/30000` has `0.00003333333333` rounded to `3.333333333e-05`.
  // The `-n`/Composite ValueConv view must emit that exact `$val` LEXEME — emitting
  // the float instead, then re-rendering it, DIVERGES (serde_json/Ryū renders the
  // f64 as `0.00001` for `1e-05`, and `1e-6` for `1/1000000` whose `$val` is
  // `1e-06`). All tokens below were captured from bundled ExifTool 13.59
  // (`-G1 -j`/`-n` on the crafted FNumber).
  for (num, denom, n_token, j_fnumber, j_aperture) in [
    // 1/100000 = 1e-5: $val "1e-05"; %.1f of 1e-05 = "0.0"; PrintFNumber = "0.00".
    (1u32, 100_000u32, "1e-05", "0.0", "0.00"),
    // 1/1000000 = 1e-6: $val "1e-06" (NOT Ryū's "1e-6").
    (1, 1_000_000, "1e-06", "0.0", "0.00"),
    // 1/30000 = RoundFloat(_,10) "3.333333333e-05" (NOT Ryū's "0.00003333333333").
    (1, 30_000, "3.333333333e-05", "0.0", "0.00"),
  ] {
    let data = pentaxjunk2_avi_fnumber(num, denom);
    let n = extract_info("pj2.avi", &data, false);
    assert!(
      n.contains(&format!("\"Pentax:FNumber\":{n_token},")),
      "{num}/{denom} -n FNumber must be the verbatim RoundFloat(_,10) exponent token {n_token} (NOT a float re-render):\n{n}"
    );
    assert!(
      n.contains(&format!("\"Composite:Aperture\":{n_token},")),
      "{num}/{denom} -n Composite:Aperture must follow the FNumber lexeme as {n_token}:\n{n}"
    );
    let j = extract_info("pj2.avi", &data, true);
    assert!(
      j.contains(&format!("\"Pentax:FNumber\":{j_fnumber},")),
      "{num}/{denom} -j FNumber must be %.1f of the value = {j_fnumber}:\n{j}"
    );
    assert!(
      j.contains(&format!("\"Composite:Aperture\":{j_aperture},")),
      "{num}/{denom} -j Composite:Aperture must be PrintFNumber of the operand = {j_aperture}:\n{j}"
    );
  }
}

/// Build a minimal `PentaxJunk2` AVI whose `Make` (`string[24]` @ 0x12) carries
/// the raw bytes `make_bytes` (caller supplies any embedded NUL); `FNumber` is a
/// benign `28/10`. Used to pin ExifTool's `string`-format first-NUL truncation.
fn pentaxjunk2_avi_make_bytes(make_bytes: &[u8]) -> Vec<u8> {
  let mut payload = vec![0u8; 0x66];
  payload[0..18].copy_from_slice(b"PENTDigital Camera");
  let n = make_bytes.len().min(24);
  payload[0x12..0x12 + n].copy_from_slice(&make_bytes[..n]);
  payload[0x2c..0x2c + 10].copy_from_slice(b"Optio RZ18");
  payload[0x5e..0x5e + 4].copy_from_slice(&28u32.to_le_bytes());
  payload[0x5e + 4..0x5e + 8].copy_from_slice(&10u32.to_le_bytes());
  riff_avi_with_junk(&payload)
}

#[test]
fn pentaxjunk2_string_field_truncates_at_embedded_nul() {
  // ExifTool's `string` format truncates at the FIRST NUL (`$val =~ s/\0.*//s`,
  // ExifTool.pm:6311) — a `string[24]` `Make` of `PEN\0TRAILING!` reads `"PEN"`,
  // the post-NUL bytes DROPPED (NOT retained, and NOT just trailing-NUL trimmed).
  // bundled `-j` `Pentax:Make` = `"PEN"`.
  let data = pentaxjunk2_avi_make_bytes(b"PEN\x00TRAILING!");
  let got = extract_info("pj2.avi", &data, true);
  assert!(
    got.contains("\"Pentax:Make\":\"PEN\","),
    "a string[24] Make must truncate at the embedded NUL to \"PEN\":\n{got}"
  );
  // The post-NUL text must NOT leak into the value.
  assert!(
    !got.contains("TRAILING"),
    "bytes after the embedded NUL must be dropped:\n{got}"
  );
}

#[test]
fn pentaxjunk2_repeated_junk_is_last_wins_matching_bundled() {
  // #422 RESOLVED: with TWO FULL-length `PentaxJunk2` chunks, bundled ExifTool
  // is LAST-wins (the later chunk's `Make`/`FNumber`/… override via the TagMap).
  // exifast's JUNK dispatch now matches — each matched chunk is appended in walk
  // order and replayed at emit, so the central `TagMap` resolves each leaf to the
  // last-walked: the SECOND chunk's `RICOH ` / `FNumber 5.0` survive. (Previously
  // this pinned the deferred first-wins divergence noted in #154; the byte-exact
  // `AVI_pentaxjunk2_dup.avi` golden is the bundled-13.59 oracle for this path.
  // The PARTIAL-repeat per-leaf union — where a later SHORTER chunk does NOT
  // override the earlier chunk's out-of-range leaves — is pinned just below.)
  let first = {
    let mut p = vec![0u8; 0x66];
    p[0..18].copy_from_slice(b"PENTDigital Camera");
    p[0x12..0x12 + 6].copy_from_slice(b"PENTAX");
    p[0x2c..0x2c + 10].copy_from_slice(b"Optio RZ18");
    p[0x5e..0x5e + 4].copy_from_slice(&28u32.to_le_bytes());
    p[0x5e + 4..0x5e + 8].copy_from_slice(&10u32.to_le_bytes());
    p
  };
  let second = {
    let mut p = vec![0u8; 0x66];
    p[0..18].copy_from_slice(b"PENTDigital Camera");
    p[0x12..0x12 + 6].copy_from_slice(b"RICOH ");
    p[0x2c..0x2c + 10].copy_from_slice(b"Optio RZ18");
    p[0x5e..0x5e + 4].copy_from_slice(&50u32.to_le_bytes());
    p[0x5e + 4..0x5e + 8].copy_from_slice(&10u32.to_le_bytes());
    p
  };
  // Two JUNK chunks back to back inside the AVI body.
  let mut avih = Vec::new();
  for v in [41666u32, 0, 0, 0x10, 10, 0, 1, 0, 320, 240, 0, 0, 0, 0] {
    avih.extend_from_slice(&v.to_le_bytes());
  }
  let mut hdrl = Vec::from(*b"hdrl");
  hdrl.extend_from_slice(&wav_chunk(b"avih", &avih));
  let lst = wav_chunk(b"LIST", &hdrl);
  let mut body = Vec::from(*b"AVI ");
  body.extend_from_slice(&lst);
  body.extend_from_slice(&wav_chunk(b"JUNK", &first));
  body.extend_from_slice(&wav_chunk(b"JUNK", &second));
  let mut data = Vec::from(*b"RIFF");
  data.extend_from_slice(&((body.len()) as u32).to_le_bytes());
  data.extend_from_slice(&body);
  let got = extract_info("pj2dup.avi", &data, true);
  // exifast last-wins (#422): the SECOND chunk's 5.0 / RICOH survive.
  assert!(
    got.contains("\"Pentax:FNumber\":5.0,"),
    "exifast captures the last PentaxJunk2 (FNumber 5.0):\n{got}"
  );
  assert!(
    got.contains("\"Pentax:Make\":\"RICOH \","),
    "exifast captures the last PentaxJunk2 (Make RICOH):\n{got}"
  );
}

#[test]
fn pentaxjunk2_partial_repeat_keeps_earlier_leaves_per_tag() {
  // #422 Codex [high]: the repeated-`JUNK` dispatch is PER-EMITTED-LEAF, NOT a
  // whole-payload last-wins. A FULL `PentaxJunk2` (Make/Model/FNumber/DateTime)
  // followed by a SHORTER same-signature `PentaxJunk2` carrying ONLY `Make` (the
  // rest of the leaves past the chunk end) must keep the FIRST chunk's
  // `Model`/`FNumber`/`DateTime1`/`DateTime2` while the later `Make` wins — the
  // central `TagMap` resolves each tag independently. The pre-fix whole-payload
  // OVERWRITE dropped Model/FNumber/DateTime (it kept only the short chunk's
  // subset); the ordered-Vec + replay-all dispatch preserves the union. Bundled
  // 13.59 oracle: `AVI_pentaxjunk2_partial.avi` (the byte-exact golden).
  let first = {
    let mut p = vec![0u8; 0xc0];
    p[0..18].copy_from_slice(b"PENTDigital Camera");
    p[0x12..0x12 + 6].copy_from_slice(b"PENTAX");
    p[0x2c..0x2c + 10].copy_from_slice(b"Optio RZ18");
    p[0x5e..0x5e + 4].copy_from_slice(&28u32.to_le_bytes());
    p[0x5e + 4..0x5e + 8].copy_from_slice(&10u32.to_le_bytes());
    p[0x83..0x83 + 19].copy_from_slice(b"2014:01:02 03:04:05");
    p[0x9d..0x9d + 19].copy_from_slice(b"2014:01:02 03:04:06");
    p
  };
  // SHORTER second chunk: 0x2c bytes — only `Make` @ 0x12 (string[24], ends
  // 0x2a) is in range; `Model` @ 0x2c, `FNumber` @ 0x5e, `DateTime` @ 0x83/0x9d
  // are all PAST the chunk end, so this chunk emits NO Model/FNumber/DateTime.
  let second = {
    let mut p = vec![0u8; 0x2c];
    p[0..18].copy_from_slice(b"PENTDigital Camera");
    p[0x12..0x12 + 6].copy_from_slice(b"RICOH ");
    p
  };
  let mut avih = Vec::new();
  for v in [41666u32, 0, 0, 0x10, 10, 0, 1, 0, 320, 240, 0, 0, 0, 0] {
    avih.extend_from_slice(&v.to_le_bytes());
  }
  let mut hdrl = Vec::from(*b"hdrl");
  hdrl.extend_from_slice(&wav_chunk(b"avih", &avih));
  let lst = wav_chunk(b"LIST", &hdrl);
  let mut body = Vec::from(*b"AVI ");
  body.extend_from_slice(&lst);
  body.extend_from_slice(&wav_chunk(b"JUNK", &first));
  body.extend_from_slice(&wav_chunk(b"JUNK", &second));
  let mut data = Vec::from(*b"RIFF");
  data.extend_from_slice(&((body.len()) as u32).to_le_bytes());
  data.extend_from_slice(&body);
  let got = extract_info("pj2partial.avi", &data, true);
  // The FIRST (full) chunk's leaves the short chunk lacks SURVIVE.
  assert!(
    got.contains("\"Pentax:Model\":\"Optio RZ18\","),
    "the earlier chunk's Model must survive a shorter repeat:\n{got}"
  );
  assert!(
    got.contains("\"Pentax:FNumber\":2.8,"),
    "the earlier chunk's FNumber must survive a shorter repeat:\n{got}"
  );
  assert!(
    got.contains("\"Pentax:DateTime1\":\"2014:01:02 03:04:05\","),
    "the earlier chunk's DateTime1 must survive a shorter repeat:\n{got}"
  );
  assert!(
    got.contains("\"Pentax:DateTime2\":\"2014:01:02 03:04:06\","),
    "the earlier chunk's DateTime2 must survive a shorter repeat:\n{got}"
  );
  // The LATER (short) chunk's `Make` wins per-leaf.
  assert!(
    got.contains("\"Pentax:Make\":\"RICOH \","),
    "the later (shorter) chunk's Make must win per-leaf:\n{got}"
  );
}

/// Build a single-`JUNK` AVI whose `PentaxJunk2` payload is `len` bytes total:
/// the `PENTDigital Camera` signature (18 bytes) then `make_fill` written across
/// the `Make` region (0x12), padded with NUL to `len`. For `len > 0x12` the
/// `Make` leaf has `len - 0x12` bytes available.
fn pentaxjunk2_avi_truncated(len: usize, make_fill: &[u8]) -> Vec<u8> {
  let mut p = vec![0u8; len];
  let sig = b"PENTDigital Camera";
  let s = sig.len().min(len);
  p[..s].copy_from_slice(&sig[..s]);
  if len > 0x12 {
    let avail = len - 0x12;
    let n = make_fill.len().min(avail);
    p[0x12..0x12 + n].copy_from_slice(&make_fill[..n]);
  }
  riff_avi_with_junk(&p)
}

/// Build a single-`JUNK` AVI whose `PentaxJunk` payload is `len` bytes total: the
/// `IIII\x01\0` signature (6 bytes) then `model_fill` written across the `Model`
/// region (0x0c), padded with NUL to `len`.
fn pentaxjunk_avi_truncated(len: usize, model_fill: &[u8]) -> Vec<u8> {
  let mut p = vec![0u8; len];
  let sig = b"IIII\x01\x00";
  let s = sig.len().min(len);
  p[..s].copy_from_slice(&sig[..s]);
  if len > 0x0c {
    let avail = len - 0x0c;
    let n = model_fill.len().min(avail);
    p[0x0c..0x0c + n].copy_from_slice(&model_fill[..n]);
  }
  riff_avi_with_junk(&p)
}

#[test]
fn pentaxjunk2_make_string_clamps_to_available_bytes() {
  // #422 Codex [medium]: ExifTool's `ReadValue` for a fixed `string[N]` CLAMPS to
  // the available bytes (`ExifTool.pm:6301-6303` shortens the count) and drops
  // ONLY at ZERO bytes — so a `Make` `string[24]` @ 0x12 with FEWER than 24 bytes
  // emits a PARTIAL string (not nothing). The R3 all-or-nothing read
  // (`payload.get(off..off+24)`) wrongly dropped these. bundled 13.59 oracle
  // (`PENTDigital Camera` + the 24-char fill `ABCDEFGHIJKLMNOPQRSTUVWX`):
  //   len 18 → no Make (offset 0x12 == len, 0 bytes);
  //   len 19 → "A" (1 byte); len 30 → "ABCDEFGHIJKL" (12); len 41 → 23 bytes;
  //   len 42 → "ABCDEFGHIJKLMNOPQRSTUVWX" (the full 24).
  let fill = b"ABCDEFGHIJKLMNOPQRSTUVWX"; // 24 distinct chars
  for (len, expected) in [
    (19usize, Some("A")),
    (30, Some("ABCDEFGHIJKL")),
    (41, Some("ABCDEFGHIJKLMNOPQRSTUVW")),
    (42, Some("ABCDEFGHIJKLMNOPQRSTUVWX")),
  ] {
    let data = pentaxjunk2_avi_truncated(len, fill);
    let got = extract_info("pj2trunc.avi", &data, true);
    let needle = format!("\"Pentax:Make\":\"{}\",", expected.unwrap());
    assert!(
      got.contains(&needle),
      "Junk2 len {len}: Make must clamp to the available bytes ({needle}):\n{got}"
    );
  }
  // len 18 (== the Make offset 0x12): ZERO bytes at the leaf ⇒ NO Make at all
  // (the whole chunk is signature-only and dropped). Matches bundled.
  let data18 = pentaxjunk2_avi_truncated(18, fill);
  let got18 = extract_info("pj2trunc.avi", &data18, true);
  assert!(
    !got18.contains("Pentax:Make"),
    "Junk2 len 18 (offset == len, 0 bytes) must emit no Make:\n{got18}"
  );
}

#[test]
fn pentaxjunk_model_string_clamps_to_available_bytes() {
  // The `PentaxJunk` (variant 1) `Model` `string[32]` @ 0x0c clamps the same way.
  // bundled 13.59 oracle (`IIII\x01\0` + the 32-char fill):
  //   len 12 → no Model (offset 0x0c == len); len 13 → "A" (1 byte);
  //   len 20 → "ABCDEFGH" (8); len 44 → the full 32 bytes.
  let fill = b"ABCDEFGHIJKLMNOPQRSTUVWXYZ012345"; // 32 distinct chars
  for (len, expected) in [
    (13usize, "A"),
    (20, "ABCDEFGH"),
    (44, "ABCDEFGHIJKLMNOPQRSTUVWXYZ012345"),
  ] {
    let data = pentaxjunk_avi_truncated(len, fill);
    let got = extract_info("pj1trunc.avi", &data, true);
    let needle = format!("\"Pentax:Model\":\"{expected}\",");
    assert!(
      got.contains(&needle),
      "Junk len {len}: Model must clamp to the available bytes ({needle}):\n{got}"
    );
  }
  let data12 = pentaxjunk_avi_truncated(12, fill);
  let got12 = extract_info("pj1trunc.avi", &data12, true);
  assert!(
    !got12.contains("Pentax:Model"),
    "Junk len 12 (offset == len, 0 bytes) must emit no Model:\n{got12}"
  );
}

#[test]
fn pentaxjunk2_below_threshold_short_repeat_wins_partial_make_per_leaf() {
  // #422 Codex [medium], the per-leaf union below the full Make width: a FULL
  // `PentaxJunk2` followed by a SHORT (30-byte) same-signature chunk whose `Make`
  // is PARTIAL (12 of 24 bytes). Because the short chunk now emits its clamped
  // Make, the per-leaf last-wins resolves `Make` to the SHORT's partial value,
  // while `Model`/`FNumber` (which the short chunk lacks — past its end) stay the
  // FULL chunk's. The R3 code dropped the 30-byte chunk entirely (threshold 42),
  // so its partial Make never won. bundled 13.59 oracle: full(Make=PENTAX,
  // FNumber=2.8, Model="Optio RZ18") THEN short30(partial Make="RICOHRICOHRI") →
  // Make "RICOHRICOHRI", Model "Optio RZ18", FNumber 2.8.
  let first = {
    let mut p = vec![0u8; 0x66];
    p[0..18].copy_from_slice(b"PENTDigital Camera");
    p[0x12..0x12 + 6].copy_from_slice(b"PENTAX");
    p[0x2c..0x2c + 10].copy_from_slice(b"Optio RZ18");
    p[0x5e..0x5e + 4].copy_from_slice(&28u32.to_le_bytes());
    p[0x5e + 4..0x5e + 8].copy_from_slice(&10u32.to_le_bytes());
    p
  };
  // 30-byte short: Make @ 0x12 has 30-18 = 12 bytes ⇒ partial "RICOHRICOHRI".
  let second = {
    let mut p = vec![0u8; 30];
    p[0..18].copy_from_slice(b"PENTDigital Camera");
    let fill = b"RICOHRICOHRICOH";
    let avail = 30 - 0x12; // 12
    let n = fill.len().min(avail);
    p[0x12..0x12 + n].copy_from_slice(&fill[..n]);
    p
  };
  let mut avih = Vec::new();
  for v in [41666u32, 0, 0, 0x10, 10, 0, 1, 0, 320, 240, 0, 0, 0, 0] {
    avih.extend_from_slice(&v.to_le_bytes());
  }
  let mut hdrl = Vec::from(*b"hdrl");
  hdrl.extend_from_slice(&wav_chunk(b"avih", &avih));
  let lst = wav_chunk(b"LIST", &hdrl);
  let mut body = Vec::from(*b"AVI ");
  body.extend_from_slice(&lst);
  body.extend_from_slice(&wav_chunk(b"JUNK", &first));
  body.extend_from_slice(&wav_chunk(b"JUNK", &second));
  let mut data = Vec::from(*b"RIFF");
  data.extend_from_slice(&((body.len()) as u32).to_le_bytes());
  data.extend_from_slice(&body);
  let got = extract_info("pj2shortwin.avi", &data, true);
  // The SHORT chunk's PARTIAL Make wins per-leaf.
  assert!(
    got.contains("\"Pentax:Make\":\"RICOHRICOHRI\","),
    "the shorter repeat's clamped (partial) Make must win per-leaf:\n{got}"
  );
  // The FULL chunk's leaves the short chunk lacks SURVIVE.
  assert!(
    got.contains("\"Pentax:Model\":\"Optio RZ18\","),
    "the full chunk's Model must survive the shorter repeat:\n{got}"
  );
  assert!(
    got.contains("\"Pentax:FNumber\":2.8,"),
    "the full chunk's FNumber must survive the shorter repeat:\n{got}"
  );
}
