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
      && let Some(meta) = p.parse_any(&data, &mut shared, Some("avi"), 0, None)
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
