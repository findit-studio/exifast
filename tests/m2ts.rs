//! Integration tests for the M2TS port: end-to-end synthetic streams →
//! [`exifast::AnyMeta`], plus a smoke test against the bundled canonical
//! Canon AVCHD M2TS fixture (the byte-exact conformance lives in
//! `tests/conformance.rs::m2ts_conformance`).
//!
//! Gated on `feature = "m2ts"` — the typed `Meta` type and parser entry
//! live behind the same gate.
#![cfg(feature = "m2ts")]

use exifast::format_parser::{SharedFlags, any_parser_for};

/// Build a SYNTHETIC 192-byte (BDAV) M2TS buffer with `n` null packets.
/// The 4-byte timecode prefix is zero; the 188-byte TS packet body is a
/// PID 0x1fff null packet (no adaptation, no payload). This is the
/// minimum the probe accepts: 4 valid syncs in a row at the 192-byte
/// stride (M2TS.pm:606-614).
fn synth_null_192(n: usize) -> Vec<u8> {
  let mut buf = Vec::with_capacity(n * 192);
  for _ in 0..n {
    // 4-byte BDAV timecode prefix.
    buf.extend_from_slice(&[0u8; 4]);
    // 188-byte TS packet: sync 0x47, PID 0x1fff (null), no adaptation,
    // no payload. Body is 0xff fill (idle).
    buf.push(0x47);
    buf.push(0x1f);
    buf.push(0xff);
    buf.push(0x10);
    buf.extend(core::iter::repeat_n(0xff_u8, 184));
  }
  buf
}

#[test]
fn synthetic_null_stream_yields_m2ts_meta() {
  let buf = synth_null_192(8);
  let parser = any_parser_for("M2TS").expect("M2TS feature enabled");
  let mut shared = SharedFlags::new();
  let meta = parser
    .parse_any(&buf, &mut shared, Some("mts"), 0, None, false)
    .expect("parser accepts the synthetic stream");
  match meta {
    exifast::AnyMeta::M2ts(m) => {
      // Synthetic null stream carries no PAT / PMT, so no stream-type
      // tags, no AC-3 descriptor, no H.264 sub-Meta, no PCR (Duration
      // remains None).
      assert!(m.video_stream_type().is_none());
      assert!(m.audio_stream_type().is_none());
      assert!(m.duration().is_none());
      assert!(m.ac3_audio_bitrate().is_none());
      assert!(m.ac3_audio_sample_rate().is_none());
      assert!(m.h264().is_none());
      // The 4-byte timecode is present ⇒ `M2TS` (not `M2T`).
      assert_eq!(m.file_type().as_file_type(), "M2TS");
    }
    other => panic!("expected AnyMeta::M2ts, got {other:?}"),
  }
}

#[test]
fn synthetic_188_byte_stream_yields_m2t_file_type() {
  // A 188-byte (raw, no timecode) stream — M2TS.pm:617 ⇒ `M2T`.
  let mut buf = Vec::with_capacity(8 * 188);
  for _ in 0..8 {
    buf.push(0x47);
    buf.push(0x1f);
    buf.push(0xff);
    buf.push(0x10);
    buf.extend(core::iter::repeat_n(0xff_u8, 184));
  }
  let parser = any_parser_for("M2TS").expect("M2TS feature enabled");
  let mut shared = SharedFlags::new();
  let meta = parser
    .parse_any(&buf, &mut shared, Some("ts"), 0, None, false)
    .expect("parser accepts the synthetic stream");
  let m = match meta {
    exifast::AnyMeta::M2ts(m) => m,
    other => panic!("expected AnyMeta::M2ts, got {other:?}"),
  };
  assert_eq!(m.file_type().as_file_type(), "M2T");
}

#[test]
fn truncated_input_is_rejected() {
  // < 383 bytes ⇒ probe returns None ⇒ `None` (Golden-v2 §4: parse is
  // `Option`-valued, no fallible path).
  let buf = synth_null_192(1); // 192 bytes — well under 383
  let parser = any_parser_for("M2TS").expect("M2TS feature enabled");
  let mut shared = SharedFlags::new();
  let result = parser.parse_any(&buf, &mut shared, Some("mts"), 0, None, false);
  assert!(result.is_none(), "truncated input must be rejected");
}

#[test]
fn random_garbage_is_rejected() {
  let buf = vec![0xa5u8; 2048]; // no sync byte
  let parser = any_parser_for("M2TS").expect("M2TS feature enabled");
  let mut shared = SharedFlags::new();
  let result = parser.parse_any(&buf, &mut shared, Some("mts"), 0, None, false);
  assert!(result.is_none(), "garbage must be rejected");
}

// ===========================================================================
// Synthetic TS-stream builders for the state-machine fidelity tests
// (Duration backscan / H.264 extra-frame / PES-before-PMT). Every expected
// value below was oracle-verified against the bundled `exiftool` on a
// byte-identical stream (see the per-test comments).
// ===========================================================================

/// One 192-byte BDAV packet: 4-byte zero timecode + 188-byte TS packet.
/// `adaptation` is the adaptation-field BODY (flags byte onward, WITHOUT the
/// length byte); `payload` follows. Body is `0xff`-padded to 188 bytes.
fn ts_packet(pid: u16, pusi: bool, adaptation: Option<&[u8]>, payload: &[u8]) -> Vec<u8> {
  let mut prefix: u32 = 0x4700_0000;
  if pusi {
    prefix |= 0x0040_0000;
  }
  prefix |= (u32::from(pid) & 0x1fff) << 8;
  if adaptation.is_some() {
    prefix |= 0x0000_0020;
  }
  if !payload.is_empty() {
    prefix |= 0x0000_0010;
  }
  let mut pkt = Vec::with_capacity(188);
  pkt.extend_from_slice(&prefix.to_be_bytes());
  if let Some(af) = adaptation {
    pkt.push(af.len() as u8);
    pkt.extend_from_slice(af);
  }
  pkt.extend_from_slice(payload);
  assert!(pkt.len() <= 188, "TS packet body overflow: {}", pkt.len());
  pkt.resize(188, 0xff);
  let mut out = vec![0u8; 4]; // zero timecode
  out.extend_from_slice(&pkt);
  out
}

/// PCR-bearing adaptation field with `pcr_ext == 0`, so the bundled value
/// `endTime = 300 * (2*base + 0) + 0 = 600 * base` (M2TS.pm:743). Flags byte
/// = 0x10 (PCR_flag); body length 7 (> 6, so the PCR is read).
fn pcr_af(base: u32) -> Vec<u8> {
  let mut af = vec![0x10u8]; // flags: PCR_flag
  af.extend_from_slice(&base.to_be_bytes()); // 4-byte base
  af.extend_from_slice(&[0u8, 0u8]); // 2-byte ext = 0
  af
}

/// PAT naming a single PMT PID (program 1). Includes the leading pointer
/// field. CRC is present but ignored (dropped by the `-4` at M2TS.pm:815).
fn pat(pmt_pid: u16) -> Vec<u8> {
  let mut body = Vec::new();
  body.extend_from_slice(&1u16.to_be_bytes()); // transport_stream_id
  body.extend_from_slice(&[0u8, 0u8, 0u8]); // version / section / last
  body.extend_from_slice(&1u16.to_be_bytes()); // program_number
  body.extend_from_slice(&(0xe000u16 | (pmt_pid & 0x1fff)).to_be_bytes());
  body.extend_from_slice(&[0u8; 4]); // CRC
  let section_length = body.len() as u16;
  let mut sect = vec![0x00u8]; // table_id PAT
  sect.extend_from_slice(&(0x8000 | 0x3000 | (section_length & 0x0fff)).to_be_bytes());
  sect.extend_from_slice(&body);
  let mut out = vec![0u8]; // pointer field
  out.extend_from_slice(&sect);
  out
}

/// PMT (program 1) for the given `(stream_type, elementary_pid, descriptors)`
/// rows, with a PCR PID. Includes the pointer field; CRC present-but-ignored.
fn pmt(streams: &[(u8, u16, &[u8])], pcr_pid: u16) -> Vec<u8> {
  let mut body = Vec::new();
  body.extend_from_slice(&1u16.to_be_bytes()); // program_number
  body.extend_from_slice(&[0u8, 0u8, 0u8]); // version / section / last
  body.extend_from_slice(&(0xe000u16 | (pcr_pid & 0x1fff)).to_be_bytes());
  body.extend_from_slice(&(0xf000u16).to_be_bytes()); // program_info_length 0
  for &(st, epid, desc) in streams {
    body.push(st);
    body.extend_from_slice(&(0xe000u16 | (epid & 0x1fff)).to_be_bytes());
    body.extend_from_slice(&(0xf000u16 | (desc.len() as u16 & 0x0fff)).to_be_bytes());
    body.extend_from_slice(desc);
  }
  body.extend_from_slice(&[0u8; 4]); // CRC
  let section_length = body.len() as u16;
  let mut sect = vec![0x02u8]; // table_id PMT
  sect.extend_from_slice(&(0x8000 | 0x3000 | (section_length & 0x0fff)).to_be_bytes());
  sect.extend_from_slice(&body);
  let mut out = vec![0u8]; // pointer field
  out.extend_from_slice(&sect);
  out
}

/// AC-3 stream descriptor (tag 0x81): bitrate idx 12 (256 kbps), surround 0,
/// channels idx 2 (M2TS.pm:269-280).
fn ac3_descriptor() -> Vec<u8> {
  vec![0x81, 0x03, 0x00, 12 << 2, 2 << 1]
}

/// PES packet wrapper with a syntax header (`stream_id` 0xe0 video / 0xc0
/// audio). `pes_packet_length` 0 ⇒ no `packLen` (M2TS.pm:940-944).
fn pes(stream_id: u8, payload: &[u8]) -> Vec<u8> {
  let mut out = vec![0x00, 0x00, 0x01, stream_id, 0x00, 0x00];
  out.extend_from_slice(&[0x80, 0x00, 0x00]); // flags1/flags2/header_data_length
  out.extend_from_slice(payload);
  out
}

/// Escape an RBSP (insert `0x03` after any `00 00` run, the inverse of the
/// de-emulation at H264.pm:1063-1069).
fn escape_rbsp(input: &[u8]) -> Vec<u8> {
  let mut out = Vec::with_capacity(input.len());
  let mut zeros = 0u8;
  for &b in input {
    if zeros >= 2 && b <= 3 {
      out.push(0x03);
      zeros = 0;
    }
    out.push(b);
    zeros = if b == 0 { zeros + 1 } else { 0 };
  }
  out
}

/// 20-byte AVCHD MDPM UUID tag (16-byte uuid + "MDPM", H264.pm:960-963).
const MDPM_UUID: [u8; 20] = [
  0x17, 0xee, 0x8c, 0x60, 0xf8, 0x4d, 0x11, 0xd9, 0x8c, 0xd6, 0x08, 0x00, 0x20, 0x0c, 0x9a, 0x66,
  b'M', b'D', b'P', b'M',
];

/// An H.264 NAL byte stream with a type-5 SEI carrying an MDPM block
/// (TimeCode 0x13 + MakeModel 0xe0 ⇒ Canon), then a trailing AUD. Mirrors the
/// `avchd_fixture` in `src/formats/h264.rs`.
fn h264_with_mdpm() -> Vec<u8> {
  let mut recs = Vec::new();
  recs.extend_from_slice(&[0x13, 0x01, 0x02, 0x03, 0x04]); // TimeCode
  recs.extend_from_slice(&[0xe0, 0x10, 0x11, 0x31, 0x02]); // MakeModel -> Canon (0x1011)
  let mut payload = Vec::new();
  payload.extend_from_slice(&MDPM_UUID);
  payload.push(2); // entry count
  payload.extend_from_slice(&recs);
  let mut sei = vec![5u8, payload.len() as u8];
  sei.extend_from_slice(&payload);
  sei.push(0x80); // terminator
  let mut stream = vec![0x00, 0x00, 0x00, 0x01, 0x06];
  stream.extend_from_slice(&escape_rbsp(&sei));
  stream.extend_from_slice(&[0x00, 0x00, 0x00, 0x01, 0x09, 0x10]); // trailing AUD
  stream
}

/// An H.264 NAL stream with ONLY an SPS NAL (no SEI/MDPM) + a trailing AUD —
/// the "first frame carries no user data" case (Panasonic, H264.pm:1100-1104).
fn h264_no_user_data() -> Vec<u8> {
  let mut stream = vec![0x00, 0x00, 0x00, 0x01, 0x07];
  stream.extend_from_slice(&[0x42, 0x00, 0x1f, 0x00]);
  stream.extend_from_slice(&[0x00, 0x00, 0x00, 0x01, 0x09, 0x10]);
  stream
}

/// An H.264 NAL stream whose SPS decodes to a real picture size (1536x352),
/// with NO SEI/MDPM — the Panasonic first frame.
fn h264_sps_with_size() -> Vec<u8> {
  let mut stream = vec![0x00, 0x00, 0x00, 0x01, 0x07];
  stream.extend_from_slice(&[0x42, 0xc0, 0x1e, 0xd9, 0x00, 0x60, 0x16, 0xc9]);
  stream.extend_from_slice(&[0x00, 0x00, 0x00, 0x01, 0x09, 0x10]);
  stream
}

/// An H.264 NAL stream carrying ONLY an MDPM MakeModel (Canon) SEI, no SPS —
/// the Panasonic second frame.
fn h264_mdpm_only() -> Vec<u8> {
  let mut payload = Vec::new();
  payload.extend_from_slice(&MDPM_UUID);
  payload.push(1); // one entry
  payload.extend_from_slice(&[0xe0, 0x10, 0x11, 0x31, 0x02]); // MakeModel -> Canon
  let mut sei = vec![5u8, payload.len() as u8];
  sei.extend_from_slice(&payload);
  sei.push(0x80);
  let mut stream = vec![0x00, 0x00, 0x00, 0x01, 0x06];
  stream.extend_from_slice(&escape_rbsp(&sei));
  stream.extend_from_slice(&[0x00, 0x00, 0x00, 0x01, 0x09, 0x10]);
  stream
}

/// Parse a synthetic M2TS buffer through the engine, returning the typed
/// `m2ts::Meta`.
fn parse_m2ts(buf: &[u8]) -> exifast::formats::m2ts::Meta<'_> {
  let parser = any_parser_for("M2TS").expect("M2TS feature enabled");
  let mut shared = SharedFlags::new();
  let meta = parser
    .parse_any(buf, &mut shared, Some("mts"), 0, None, false)
    .expect("parser accepts the synthetic stream");
  match meta {
    exifast::AnyMeta::M2ts(m) => m,
    other => panic!("expected AnyMeta::M2ts, got {other:?}"),
  }
}

/// Like [`parse_m2ts`] but with `extract_embedded = true` (`-ee`). The
/// LIGOGPSINFO PID-0x0300 decode arm is `-ee`-gated (M2TS.pm:308-318 is an
/// ExtractEmbedded feature), so any test that needs the LIGOGPS decode to run —
/// or its `LIGOGPSINFO format error` walker warning to fire — must parse at
/// `-ee`.
fn parse_m2ts_ee(buf: &[u8]) -> exifast::formats::m2ts::Meta<'_> {
  let parser = any_parser_for("M2TS").expect("M2TS feature enabled");
  let mut shared = SharedFlags::new();
  let meta = parser
    .parse_any(buf, &mut shared, Some("mts"), 0, None, true)
    .expect("parser accepts the synthetic stream");
  match meta {
    exifast::AnyMeta::M2ts(m) => m,
    other => panic!("expected AnyMeta::M2ts, got {other:?}"),
  }
}

const VIDEO_PID: u16 = 0x0011;
const AUDIO_PID: u16 = 0x0044;
const PCR_PID: u16 = 0x1001;
const PMT_PID: u16 = 0x0100;

/// FINDING 1 — Duration must use the LAST PCR (EOF backscan), not stop early.
///
/// The needed PIDs (PAT/PMT/H.264/AC-3) all parse near the START; the forward
/// pass then STOPS (`%needPID` empty, M2TS.pm:653) having seen only the first
/// PCR (`endTime = 600*10 = 6000`). The bundled backscan (M2TS.pm:653-694)
/// walks back from EOF and finds the LAST PCR (`endTime = 600*10010 =
/// 6006000`), so `Duration = (6006000 - 6000) / 27e6 = 0.2222 s` spans the
/// whole stream — NOT a near-zero early value.
///
/// Oracle-verified: a byte-identical stream gives bundled `exiftool -n`
/// `"M2TS:Duration": 0.222222222222222` with a `[Starting backscan for last
/// PCR]` verbose trace.
#[test]
fn duration_uses_last_pcr_via_eof_backscan() {
  let mut buf = Vec::new();
  buf.extend_from_slice(&ts_packet(0, true, None, &pat(PMT_PID)));
  let streams = [
    (0x1bu8, VIDEO_PID, &[][..]),
    (0x81u8, AUDIO_PID, &ac3_descriptor()[..]),
  ];
  buf.extend_from_slice(&ts_packet(PMT_PID, true, None, &pmt(&streams, PCR_PID)));
  // First PCR (endTime = 6000) — what the forward pass would stop on.
  buf.extend_from_slice(&ts_packet(PCR_PID, false, Some(&pcr_af(10)), &[]));
  // H.264: frame1 carries MDPM; frame2 start flushes frame1 ⇒ ParsePID finds
  // user data ⇒ returns 0 (Done) ⇒ video PID done.
  buf.extend_from_slice(&ts_packet(
    VIDEO_PID,
    true,
    None,
    &pes(0xe0, &h264_with_mdpm()),
  ));
  buf.extend_from_slice(&ts_packet(
    VIDEO_PID,
    true,
    None,
    &pes(0xe0, &h264_with_mdpm()),
  ));
  // AC-3: frame1 + frame2 start ⇒ flush ⇒ Done.
  let ac3: Vec<u8> = {
    let mut v = vec![0x0b, 0x77, 0xaa, 0xbb, 0x00];
    v.extend(core::iter::repeat_n(0u8, 40));
    v
  };
  buf.extend_from_slice(&ts_packet(AUDIO_PID, true, None, &pes(0xc0, &ac3)));
  buf.extend_from_slice(&ts_packet(AUDIO_PID, true, None, &pes(0xc0, &ac3)));
  // All needed PIDs are now done ⇒ forward pass stops here. Filler + the LAST
  // PCR near EOF (endTime = 6006000) reachable only via the backscan.
  for _ in 0..3 {
    buf.extend_from_slice(&ts_packet(0x1fff, false, None, &[0xff; 10]));
  }
  buf.extend_from_slice(&ts_packet(PCR_PID, false, Some(&pcr_af(10010)), &[]));
  buf.extend_from_slice(&ts_packet(0x1fff, false, None, &[0xff; 10]));

  let m = parse_m2ts(&buf);
  let d = m
    .duration()
    .expect("a multi-PCR stream must report a Duration");
  // (6006000 - 6000) / 27_000_000 s = 0.2222… s.
  let secs = d.as_secs_f64();
  assert!(
    (secs - (6_000_000.0 / 27_000_000.0)).abs() < 1e-9,
    "Duration must span first→last PCR (got {secs} s, want {} s)",
    6_000_000.0 / 27_000_000.0
  );
  // The H.264 MDPM still surfaced (the early parse that emptied needPID).
  assert_eq!(m.h264().and_then(|h| h.make()), Some("Canon"));
}

/// FINDING 2 — honor `ParseH264Video`'s extra-frame return (H264.pm:1100-1104).
///
/// The first H.264 frame carries NO SEI/MDPM (Panasonic-style); the SECOND
/// frame carries the MDPM MakeModel record. Bundled `ParseH264Video` returns
/// `1` on the first (no user data) so the M2TS walker keeps the video PID in
/// the "want more" state and parses the second frame, where the MakeModel is
/// found. A walker that marked the PID done after the first frame would miss
/// `H264:Make`.
#[test]
fn h264_second_frame_mdpm_is_not_dropped() {
  let mut buf = Vec::new();
  buf.extend_from_slice(&ts_packet(0, true, None, &pat(PMT_PID)));
  let streams = [(0x1bu8, VIDEO_PID, &[][..])];
  buf.extend_from_slice(&ts_packet(PMT_PID, true, None, &pmt(&streams, PCR_PID)));
  // Frame 1: SPS only, NO user data ⇒ ParseH264Video returns 1 (want more).
  buf.extend_from_slice(&ts_packet(
    VIDEO_PID,
    true,
    None,
    &pes(0xe0, &h264_no_user_data()),
  ));
  // Frame 2 start flushes frame 1 (no user data ⇒ keep needing), then frame 2
  // (the MDPM) accumulates.
  buf.extend_from_slice(&ts_packet(
    VIDEO_PID,
    true,
    None,
    &pes(0xe0, &h264_with_mdpm()),
  ));
  // A third payload-start flushes frame 2 ⇒ MakeModel found.
  buf.extend_from_slice(&ts_packet(
    VIDEO_PID,
    true,
    None,
    &pes(0xe0, &h264_no_user_data()),
  ));
  // Pad so the probe has ≥ 4 packets and the file is well-formed.
  for _ in 0..4 {
    buf.extend_from_slice(&ts_packet(0x1fff, false, None, &[0xff; 10]));
  }

  let m = parse_m2ts(&buf);
  assert_eq!(
    m.h264().and_then(|h| h.make()),
    Some("Canon"),
    "the MakeModel in the SECOND H.264 frame must be extracted (H264.pm:1100-1104)"
  );
}

/// FINDING 2 (cumulative) — the extra-frame scan must ACCUMULATE across
/// frames, not replace. Frame 1 is an SPS (image size, no user data); frame 2
/// carries ONLY the MDPM MakeModel. Bundled keeps both (the SPS is processed
/// once and the MDPM is appended to the same `$$et`), so `H264:ImageWidth`/
/// `ImageHeight` (frame 1) AND `H264:Make` (frame 2) all survive.
///
/// Oracle-verified: bundled `exiftool -n` on a byte-identical stream gives
/// `H264:ImageWidth 1536`, `H264:ImageHeight 352`, `H264:Make 4113`.
#[test]
fn h264_extra_frame_accumulates_sps_and_mdpm() {
  let mut buf = Vec::new();
  buf.extend_from_slice(&ts_packet(0, true, None, &pat(PMT_PID)));
  let streams = [(0x1bu8, VIDEO_PID, &[][..])];
  buf.extend_from_slice(&ts_packet(PMT_PID, true, None, &pmt(&streams, PCR_PID)));
  buf.extend_from_slice(&ts_packet(
    VIDEO_PID,
    true,
    None,
    &pes(0xe0, &h264_sps_with_size()),
  ));
  buf.extend_from_slice(&ts_packet(
    VIDEO_PID,
    true,
    None,
    &pes(0xe0, &h264_mdpm_only()),
  ));
  buf.extend_from_slice(&ts_packet(
    VIDEO_PID,
    true,
    None,
    &pes(0xe0, &h264_no_user_data()),
  ));
  for _ in 0..4 {
    buf.extend_from_slice(&ts_packet(0x1fff, false, None, &[0xff; 10]));
  }

  let m = parse_m2ts(&buf);
  let h = m.h264().expect("an H.264 sub-Meta");
  // MakeModel from frame 2.
  assert_eq!(h.make(), Some("Canon"));
  // SPS image size from frame 1 must NOT be lost when frame 2 replaces the
  // accumulator (the merge keeps the earlier frame's entries).
  let names: Vec<&str> = h.entries().iter().map(|e| e.name()).collect();
  assert!(
    names.contains(&"ImageWidth") && names.contains(&"ImageHeight"),
    "frame-1 SPS dimensions must survive the cumulative merge; got {names:?}"
  );
}

/// The H.264 full scan to EOF (M2TS.pm:347 `$more = 1`) is `-ee`-GATED.
///
/// M2TS.pm:347 forces the forward pass to run to EOF (`$more = 1`) ONLY inside
/// `if ($$et{OPTIONS}{ExtractEmbedded})`; without `-ee` the H.264 arm returns
/// `ParseH264Video`'s own `$more`, so the forward pass early-stops the moment
/// every needed PID is satisfied and a PCR has been seen (M2TS.pm:653). The
/// per-sample H.264 data is decoded into the same `Meta` either way, but the
/// WALK EXTENT differs — so a file whose FIRST user-data H.264 SEI lies PAST
/// that early-stop must NOT have its `H264:*` MDPM tags surface at no-`ee`
/// (ExifTool early-stops there too) yet MUST surface at `-ee` (the full scan
/// reaches it).
///
/// Stream layout: PAT, PMT (H.264 video + a PCR PID), a first PCR (so the
/// early-stop's `start_time.is_some()` guard is armed), then THREE SPS-only
/// (no-user-data) H.264 frames — frame 2's flush leaves `ParsedH264` set so
/// frame 3's flush returns `Done` at no-`ee`, draining `%needPID` to 0 and
/// stopping the forward pass — then a long filler run, and FINALLY a frame
/// carrying the MDPM MakeModel (Canon). At no-`ee` the forward pass has already
/// stopped before that last frame's packets are read; at `-ee` the forced full
/// scan reaches them.
#[test]
fn h264_full_scan_is_ee_gated_late_first_sei_suppressed_at_no_ee() {
  let mut buf = Vec::new();
  buf.extend_from_slice(&ts_packet(0, true, None, &pat(PMT_PID)));
  let streams = [(0x1bu8, VIDEO_PID, &[][..])];
  buf.extend_from_slice(&ts_packet(PMT_PID, true, None, &pmt(&streams, PCR_PID)));
  // A first PCR arms the early-stop guard (`need_count == 0 && start_time`).
  buf.extend_from_slice(&ts_packet(PCR_PID, false, Some(&pcr_af(10)), &[]));
  // Three SPS-only frames: frame-2 flush sets `ParsedH264`; frame-3 flush then
  // returns `Done` at no-`ee` (no user data + already parsed) ⇒ video PID done
  // ⇒ forward pass stops here (a PCR was seen).
  for _ in 0..3 {
    buf.extend_from_slice(&ts_packet(
      VIDEO_PID,
      true,
      None,
      &pes(0xe0, &h264_no_user_data()),
    ));
  }
  // Long filler PAST the no-`ee` early-stop budget.
  for _ in 0..32 {
    buf.extend_from_slice(&ts_packet(0x1fff, false, None, &[0xff; 10]));
  }
  // The FIRST user-data H.264 SEI (MDPM MakeModel ⇒ Canon) — reachable only by
  // the `-ee` full scan. Two frame-starts so the MDPM frame is flushed + parsed
  // (the second start flushes the MDPM-bearing first; the EOF flush is a no-op
  // for it). At no-`ee` the forward pass never reaches these packets.
  buf.extend_from_slice(&ts_packet(
    VIDEO_PID,
    true,
    None,
    &pes(0xe0, &h264_with_mdpm()),
  ));
  buf.extend_from_slice(&ts_packet(
    VIDEO_PID,
    true,
    None,
    &pes(0xe0, &h264_no_user_data()),
  ));

  // NO-`ee` (the engine default, mirrored by `parse_m2ts` / `extract_info`):
  // the forward pass early-stops before the late MDPM ⇒ NO `H264:Make`.
  let m_no_ee = parse_m2ts(&buf);
  assert_eq!(
    m_no_ee.h264().and_then(|h| h.make()),
    None,
    "at no-`ee` the `-ee`-gated full scan must NOT run, so a late first \
     user-data H.264 SEI past the early-stop is never parsed (byte-identical \
     to the pre-LIGOGPS early-stop behavior)"
  );

  // `-ee`: the forced full scan (M2TS.pm:347) reaches the late MDPM frame ⇒
  // `H264:Make` surfaces (this is also the path that reaches the LIGOGPSINFO
  // PES near EOF — the #129 feature).
  let parser = any_parser_for("M2TS").expect("M2TS feature enabled");
  let mut shared = SharedFlags::new();
  let meta_ee = parser
    .parse_any(&buf, &mut shared, Some("mts"), 0, None, true)
    .expect("parser accepts the synthetic stream");
  let m_ee = match meta_ee {
    exifast::AnyMeta::M2ts(m) => m,
    other => panic!("expected AnyMeta::M2ts, got {other:?}"),
  };
  assert_eq!(
    m_ee.h264().and_then(|h| h.make()),
    Some("Canon"),
    "at `-ee` the full scan to EOF must reach the late first user-data H.264 \
     SEI (the same scan that reaches the LIGOGPSINFO PES)"
  );
}

/// FINDING 3 — a PES seen BEFORE the PMT must not permanently kill the stream.
///
/// The video elementary PES (PID 0x0011) begins BEFORE the PAT/PMT have
/// identified its type. Bundled `ParsePID` returns `-1` (unknown type,
/// M2TS.pm:292) and the walker keeps the PID eligible (`next if $more < 0`,
/// M2TS.pm:968 / `unless ($more)` truthiness at M2TS.pm:907) instead of
/// marking it done. Once the PMT arrives, the stream is parsed and the MDPM
/// MakeModel surfaces. A walker that collapsed `-1` to "done" would skip the
/// stream forever.
#[test]
fn pes_before_pmt_is_still_extracted_after_pmt_arrives() {
  let mut buf = Vec::new();
  // A video PES (start) BEFORE any PAT/PMT — type is unknown here.
  buf.extend_from_slice(&ts_packet(
    VIDEO_PID,
    true,
    None,
    &pes(0xe0, &h264_with_mdpm()),
  ));
  // A second PES-start on the same PID flushes the first while the type is
  // STILL unknown ⇒ ParsePID returns -1 ⇒ the PID must stay eligible.
  buf.extend_from_slice(&ts_packet(
    VIDEO_PID,
    true,
    None,
    &pes(0xe0, &h264_with_mdpm()),
  ));
  // NOW the PAT + PMT arrive (identifying PID 0x0011 as H.264).
  buf.extend_from_slice(&ts_packet(0, true, None, &pat(PMT_PID)));
  let streams = [(0x1bu8, VIDEO_PID, &[][..])];
  buf.extend_from_slice(&ts_packet(PMT_PID, true, None, &pmt(&streams, PCR_PID)));
  // Further video frames now parse with a known type ⇒ MakeModel found.
  buf.extend_from_slice(&ts_packet(
    VIDEO_PID,
    true,
    None,
    &pes(0xe0, &h264_with_mdpm()),
  ));
  buf.extend_from_slice(&ts_packet(
    VIDEO_PID,
    true,
    None,
    &pes(0xe0, &h264_with_mdpm()),
  ));
  for _ in 0..4 {
    buf.extend_from_slice(&ts_packet(0x1fff, false, None, &[0xff; 10]));
  }

  let m = parse_m2ts(&buf);
  assert_eq!(
    m.h264().and_then(|h| h.make()),
    Some("Canon"),
    "a PES that started before the PMT must still be extracted once the PMT arrives"
  );
}

#[cfg(feature = "json")]
#[test]
fn canon_avchd_fixture_extracts_h264_make_canon() {
  // End-to-end: the bundled canonical Canon AVCHD M2TS fixture
  // (`tests/fixtures/M2TS.mts`) feeds through `extract_info` and the
  // resulting JSON document carries the H.264 MDPM-derived `Make` as
  // `"Canon"`. This pins the M2TS → H.264 PES forwarding seam
  // (M2TS.pm:343-345) without needing the byte-exact conformance
  // golden (which lives in `tests/conformance.rs::m2ts_conformance`).
  let root = env!("CARGO_MANIFEST_DIR");
  let data = std::fs::read(format!("{root}/tests/fixtures/M2TS.mts")).expect("read fixture");
  let got = exifast::parser::extract_info("M2TS.mts", &data, true);
  assert!(
    got.contains("\"H264:Make\":\"Canon\""),
    "expected H264:Make=Canon in:\n{got}"
  );
  assert!(
    got.contains("\"M2TS:VideoStreamType\":\"H.264 (AVC) Video\""),
    "expected H.264 VideoStreamType in:\n{got}"
  );
  assert!(
    got.contains("\"AC3:AudioSampleRate\":\"48000\"")
      || got.contains("\"AC3:AudioSampleRate\":48000"),
    "expected AC3:AudioSampleRate=48000 in:\n{got}"
  );
  assert!(
    got.contains("\"File:FileType\":\"M2TS\""),
    "expected File:FileType=M2TS in:\n{got}"
  );
}

// ===========================================================================
// #307 — the parse-time `-ee` (`ParseOptions`) typed-path wiring + the M2TS
// LIGOGPS domain-GPS regression. The M2TS walk extent is `-ee`-gated
// (M2TS.pm:347): the LIGOGPSINFO dashcam-GPS PES sits near EOF, so the typed
// `parse_bytes` / `media_metadata` path surfaces the LIGOGPS `GpsLocation`
// ONLY when `-ee` reaches the parse — which the default (no-`ee`) options do
// NOT. The expected first-fix coords are the Pruveeo D90 `.ee.json` golden's
// `Doc1` row (`30 deg 24' 9.10" N` / `89 deg 1' 33.12" W`).
// ===========================================================================

/// First decoded LIGOGPS fix, decimal degrees (the `.ee.json` `Doc1` row).
const PRUVEEO_FIRST_LAT: f64 = 30.0 + 24.0 / 60.0 + 9.10 / 3600.0; // +30.40252...
const PRUVEEO_FIRST_LON: f64 = -(89.0 + 1.0 / 60.0 + 33.12 / 3600.0); // -89.02586...

/// `parse_bytes_with_options(.., -ee on)` on the Pruveeo D90 `.ts` extends the
/// parse-time walk to the near-EOF LIGOGPSINFO PES, decodes it, and projects
/// the first fix into `media_metadata().gps()` — the product path. The default
/// (no-`ee`) options early-stop the walk before that PES, so `gps()` is `None`
/// (the faithful no-`ee` baseline). This is the #307 repro.
#[cfg(feature = "std")]
#[test]
fn pruveeo_ligogps_surfaces_in_media_metadata_only_at_ee() {
  use exifast::ParseOptions;

  let root = env!("CARGO_MANIFEST_DIR");
  let data =
    std::fs::read(format!("{root}/tests/fixtures/MPEG2_TS_pruveeo_d90.ts")).expect("read fixture");

  // ── -ee ON: the walk reaches the LIGOGPS PES ⇒ domain GPS surfaces. ──
  let any =
    exifast::parse_bytes_with_options(&data, &ParseOptions::default().with_extract_embedded(true))
      .expect("Pruveeo D90 .ts is a recognized M2TS file");
  let md = any.project();
  let gps = md
    .gps()
    .expect("at -ee the M2TS LIGOGPS first fix must populate MediaMetadata::gps");
  let lat = gps.latitude().expect("LIGOGPS latitude");
  let lon = gps.longitude().expect("LIGOGPS longitude");
  assert!(
    (lat - PRUVEEO_FIRST_LAT).abs() < 1e-4,
    "LIGOGPS latitude: got {lat}, expected ~{PRUVEEO_FIRST_LAT}"
  );
  assert!(
    (lon - PRUVEEO_FIRST_LON).abs() < 1e-4,
    "LIGOGPS longitude: got {lon}, expected ~{PRUVEEO_FIRST_LON}"
  );

  // The one-call domain entry yields the SAME GPS.
  let md2 = exifast::media_metadata_with_options(
    &data,
    &ParseOptions::default().with_extract_embedded(true),
  )
  .expect("media_metadata_with_options recognizes the M2TS file");
  assert_eq!(
    md2.gps().and_then(|g| g.latitude()),
    Some(lat),
    "media_metadata_with_options must surface the same LIGOGPS latitude"
  );

  // ── no-`ee` (default): the walk early-stops before the LIGOGPS PES. ──
  let any_base = exifast::parse_bytes(&data).expect("Pruveeo D90 .ts is recognized at no-ee too");
  let md_base = any_base.project();
  assert!(
    md_base.gps().is_none(),
    "at no-`ee` the M2TS walk early-stops before the LIGOGPS PES, so the \
     domain GPS is None (the faithful baseline)"
  );
  // The top-level `media_metadata` (default options) agrees.
  assert!(
    exifast::media_metadata(&data)
      .expect("media_metadata recognizes the M2TS file")
      .gps()
      .is_none(),
    "default media_metadata must keep the no-`ee` baseline (gps None)"
  );
}

/// The `Rendered::new_with_options` refactor: it now takes the SAME
/// [`ParseOptions`] the parse entry points take. Rendering an `-ee`-parsed
/// `AnyMeta` (from `parse_bytes_with_options`) with an `-ee` `ParseOptions`
/// emits the per-sample `LIGO:*` GPS tags the no-`ee` baseline suppresses. This
/// pins the unified parse-time + render-time `-ee` shape end-to-end for M2TS.
#[cfg(all(feature = "json", feature = "serde"))]
#[test]
fn pruveeo_rendered_with_ee_options_emits_ligogps_tags() {
  use exifast::{ParseOptions, Rendered};

  let root = env!("CARGO_MANIFEST_DIR");
  let data =
    std::fs::read(format!("{root}/tests/fixtures/MPEG2_TS_pruveeo_d90.ts")).expect("read fixture");

  let opts = ParseOptions::default().with_extract_embedded(true);
  // Parse-time `-ee` is required for M2TS so the walk reaches the LIGOGPS PES;
  // the SAME options drive the render-time emission.
  let any = exifast::parse_bytes_with_options(&data, &opts).expect("recognized M2TS");
  let on_json =
    serde_json::to_string(&Rendered::new_with_options(&any, true, &opts)).expect("serialize -ee");
  assert!(
    on_json.contains("LIGO:GPSLatitude"),
    "-ee render of an -ee-parsed M2TS must emit the LIGOGPS per-sample tags:\n{on_json}"
  );

  // The default (no-`ee`) render of a no-`ee` parse suppresses them.
  let base = exifast::parse_bytes(&data).expect("recognized M2TS at no-ee");
  let off_json = serde_json::to_string(&Rendered::new(&base, true)).expect("serialize no-ee");
  assert!(
    !off_json.contains("LIGO:GPSLatitude"),
    "no-`ee` render must suppress the LIGOGPS per-sample tags:\n{off_json}"
  );
}

// ===========================================================================
// Codex-review fidelity regression tests (PR #134). Every expected value
// below was oracle-verified against bundled `exiftool` on the BYTE-IDENTICAL
// stream the builder emits (see each test's comment).
// ===========================================================================

/// An AC-3 stream descriptor (tag 0x81) with explicit `(bitrate_idx, surround,
/// channels_idx)` (M2TS.pm:269-280: `b[1] >> 2`, `b[1] & 3`, `(b[2] >> 1) &
/// 0x0f`). Five bytes: tag, len=3, body[0] (unused), body[1], body[2].
fn ac3_descriptor_with(bitrate_idx: u8, surround: u8, channels_idx: u8) -> Vec<u8> {
  vec![
    0x81,
    0x03,
    0x00,
    (bitrate_idx << 2) | (surround & 0x03),
    channels_idx << 1,
  ]
}

/// An AC-3 PES payload whose first AC-3 sync (`0x0b 0x77 .. ..`) is followed by
/// a byte whose top two bits encode `rate_idx` (M2TS.pm:253-260). Short (< 256
/// bytes) so it is parsed only at the EOF final-flush unless flushed by a
/// later PES start.
fn ac3_pes_rate(rate_idx: u8) -> Vec<u8> {
  let mut body = vec![0x0b, 0x77, 0xaa, 0xbb, rate_idx << 6];
  body.extend(core::iter::repeat_n(0u8, 40));
  pes(0xc0, &body)
}

/// An H.264 NAL stream: an SPS decoding to 1280x720 PLUS an MDPM MakeModel
/// (Canon) SEI — the Panasonic "second frame" carrying BOTH a (different) SPS
/// and the user data. The SPS bytes were oracle-verified to decode to
/// 1280x720 (distinct from `h264_sps_with_size`'s 1536x352).
fn h264_sps1280_with_mdpm() -> Vec<u8> {
  let mut payload = Vec::new();
  payload.extend_from_slice(&MDPM_UUID);
  payload.push(1);
  payload.extend_from_slice(&[0xe0, 0x10, 0x11, 0x31, 0x02]); // MakeModel -> Canon
  let mut sei = vec![5u8, payload.len() as u8];
  sei.extend_from_slice(&payload);
  sei.push(0x80);
  let mut stream = vec![0x00, 0x00, 0x00, 0x01, 0x07];
  stream.extend_from_slice(&[0x42, 0xc0, 0x1e, 0xd9, 0x00, 0x50, 0x05, 0xbb]); // SPS 1280x720
  stream.extend_from_slice(&[0x00, 0x00, 0x00, 0x01, 0x06]);
  stream.extend_from_slice(&escape_rbsp(&sei));
  stream.extend_from_slice(&[0x00, 0x00, 0x00, 0x01, 0x09, 0x10]);
  stream
}

/// A 192-byte packet whose sync byte is NOT 0x47 (a deliberate sync error).
fn ts_packet_bad_sync(pid: u16) -> Vec<u8> {
  let mut pkt = ts_packet(pid, false, None, &[]);
  // byte 4 is the sync byte (after the 4-byte zero timecode).
  pkt[4] = 0x00;
  pkt
}

/// FINDINGS 2 + 3 + 4 + 7 (survivor semantics + PrintConv-in-raw-mode) — a PMT
/// with TWO Video rows (H.264 then MPEG-2), TWO Audio rows (AC-3 then MPEG-1),
/// the AC-3 row carrying TWO 0x81 descriptors. M2TS.pm:860-863 `HandleTag`s the
/// StreamType for every newly-`pidName`-seen Audio/Video PID (last-wins), and
/// M2TS.pm:885-889 decodes EVERY descriptor in the first PMT (last-wins).
///
/// Oracle (bundled `exiftool -n` on the byte-identical stream):
///   VideoStreamType 2, AudioStreamType 3, AC3 AudioBitrate 160000,
///   SurroundMode 2, AudioChannels 5 (RAW idx — PrintConv would be "3/1"),
///   AudioSampleRate 2.
#[test]
fn pmt_survivors_are_last_wins_not_first_wins() {
  let desc = {
    let mut d = ac3_descriptor_with(12, 0, 2); // first descriptor (256 kbps)
    d.extend_from_slice(&ac3_descriptor_with(9, 2, 5)); // second -> survivor
    d
  };
  let streams = [
    (0x1bu8, 0x0011u16, &[][..]),   // Video row 1 (H.264)
    (0x02u8, 0x0012u16, &[][..]),   // Video row 2 (MPEG-2 Video) -> survivor
    (0x81u8, AUDIO_PID, &desc[..]), // Audio row 1 (AC-3, two descriptors)
    (0x03u8, 0x0045u16, &[][..]),   // Audio row 2 (MPEG-1 Audio) -> survivor
  ];
  let mut buf = Vec::new();
  buf.extend_from_slice(&ts_packet(0, true, None, &pat(PMT_PID)));
  buf.extend_from_slice(&ts_packet(PMT_PID, true, None, &pmt(&streams, PCR_PID)));
  buf.extend_from_slice(&ts_packet(AUDIO_PID, true, None, &ac3_pes_rate(2)));
  buf.extend_from_slice(&ts_packet(AUDIO_PID, true, None, &ac3_pes_rate(2)));
  for _ in 0..6 {
    buf.extend_from_slice(&ts_packet(0x1fff, false, None, &[0xff; 10]));
  }

  let m = parse_m2ts(&buf);
  // Finding 2 — LAST newly-seen Video / Audio PID wins.
  assert_eq!(
    m.video_stream_type(),
    Some(0x02),
    "VideoStreamType must be the LAST video PMT row (0x02), not the first (0x1b)"
  );
  assert_eq!(
    m.audio_stream_type(),
    Some(0x03),
    "AudioStreamType must be the LAST audio PMT row (0x03), not the first (0x81)"
  );
  // Finding 3 — the LAST AC-3 descriptor in the first PMT wins.
  assert_eq!(
    m.ac3_audio_bitrate(),
    Some(9),
    "AC-3 bitrate idx must be the 2nd descriptor (9)"
  );
  assert_eq!(m.ac3_surround_mode(), Some(2));
  assert_eq!(m.ac3_audio_channels(), Some(5));
  // Finding 4 — the AC-3 PES sample-rate probe assigns on every match.
  assert_eq!(m.ac3_audio_sample_rate(), Some(2));
}

/// FINDING 7 — `AC3:AudioChannels` (PrintConv-only, no ValueConv) must emit the
/// RAW index in `-n` and the PrintConv text in `-j`. Idx 5 ⇒ `-n` 5, `-j`
/// "3/1" (a non-numeric form the prior buggy code would have leaked into `-n`).
#[cfg(feature = "json")]
#[test]
fn ac3_audio_channels_raw_in_numeric_mode() {
  let desc = ac3_descriptor_with(12, 0, 5); // channels idx 5 -> "3/1"
  let streams = [(0x81u8, AUDIO_PID, &desc[..])];
  let mut buf = Vec::new();
  buf.extend_from_slice(&ts_packet(0, true, None, &pat(PMT_PID)));
  buf.extend_from_slice(&ts_packet(PMT_PID, true, None, &pmt(&streams, PCR_PID)));
  buf.extend_from_slice(&ts_packet(AUDIO_PID, true, None, &ac3_pes_rate(0)));
  buf.extend_from_slice(&ts_packet(AUDIO_PID, true, None, &ac3_pes_rate(0)));
  for _ in 0..4 {
    buf.extend_from_slice(&ts_packet(0x1fff, false, None, &[0xff; 10]));
  }
  let m = parse_m2ts(&buf);
  assert_eq!(m.ac3_audio_channels(), Some(5));

  use exifast::emit::{ConvMode, EmitOptions, Taggable};
  use exifast::value::TagValue;
  // `-n` (Numeric) must be the RAW index 5, NOT the PrintConv string "3/1".
  let numeric: Vec<_> = m
    .tags(EmitOptions::g1(ConvMode::ValueConv, false))
    .collect();
  let ch_n = numeric
    .iter()
    .find(|t| t.tag().name() == "AudioChannels")
    .expect("AudioChannels present");
  assert_eq!(
    ch_n.tag().value_ref(),
    &TagValue::U64(5),
    "AC3:AudioChannels in -n must be the raw index 5, not a PrintConv string"
  );
  // `-j` (PrintConv) is "3/1".
  let pc: Vec<_> = m
    .tags(EmitOptions::g1(ConvMode::PrintConv, false))
    .collect();
  let ch_p = pc
    .iter()
    .find(|t| t.tag().name() == "AudioChannels")
    .expect("AudioChannels present");
  assert_eq!(ch_p.tag().value_ref(), &TagValue::Str("3/1".into()));
}

/// FINDING 5 — `M2TS:Duration` must keep full 27 MHz precision. A 6_000_000-tick
/// span (firstPCR=6000, lastPCR=6006000) is `6_000_000 / 27_000_000 =
/// 0.2222222222222222`; bundled `exiftool -n` prints `0.222222222222222` (15
/// sig figs), NOT the nanosecond-rounded `0.222222222` the prior `Duration`
/// path produced. The exact-f64 emission rides the raw tick delta.
#[cfg(feature = "json")]
#[test]
fn duration_keeps_full_pcr_precision_in_numeric() {
  let mut buf = Vec::new();
  buf.extend_from_slice(&ts_packet(0, true, None, &pat(PMT_PID)));
  let streams = [
    (0x1bu8, VIDEO_PID, &[][..]),
    (0x81u8, AUDIO_PID, &ac3_descriptor()[..]),
  ];
  buf.extend_from_slice(&ts_packet(PMT_PID, true, None, &pmt(&streams, PCR_PID)));
  buf.extend_from_slice(&ts_packet(PCR_PID, false, Some(&pcr_af(10)), &[])); // firstPCR 6000
  buf.extend_from_slice(&ts_packet(
    VIDEO_PID,
    true,
    None,
    &pes(0xe0, &h264_with_mdpm()),
  ));
  buf.extend_from_slice(&ts_packet(
    VIDEO_PID,
    true,
    None,
    &pes(0xe0, &h264_with_mdpm()),
  ));
  let ac3: Vec<u8> = {
    let mut v = vec![0x0b, 0x77, 0xaa, 0xbb, 0x00];
    v.extend(core::iter::repeat_n(0u8, 40));
    v
  };
  buf.extend_from_slice(&ts_packet(AUDIO_PID, true, None, &pes(0xc0, &ac3)));
  buf.extend_from_slice(&ts_packet(AUDIO_PID, true, None, &pes(0xc0, &ac3)));
  for _ in 0..3 {
    buf.extend_from_slice(&ts_packet(0x1fff, false, None, &[0xff; 10]));
  }
  buf.extend_from_slice(&ts_packet(PCR_PID, false, Some(&pcr_af(10010)), &[])); // lastPCR 6006000
  buf.extend_from_slice(&ts_packet(0x1fff, false, None, &[0xff; 10]));

  let m = parse_m2ts(&buf);
  assert_eq!(
    m.duration_ticks(),
    Some(6_000_000),
    "the raw PCR tick delta must be exact (6006000 - 6000)"
  );

  // Render the M2TS:Duration tag in -n and confirm the full-precision f64.
  use exifast::emit::{ConvMode, EmitOptions, Taggable};
  use exifast::value::TagValue;
  let numeric: Vec<_> = m
    .tags(EmitOptions::g1(ConvMode::ValueConv, false))
    .collect();
  let dur = numeric
    .iter()
    .find(|t| t.tag().name() == "Duration")
    .expect("Duration present");
  match dur.tag().value_ref() {
    TagValue::F64(secs) => {
      let exact = 6_000_000.0_f64 / 27_000_000.0;
      assert_eq!(
        *secs, exact,
        "Duration must be the exact f64 6_000_000/27_000_000, not nanosecond-rounded"
      );
      // The nanosecond-rounded value (the prior bug) differs from `exact`.
      let rounded = (exact * 1e9).round() / 1e9;
      assert_ne!(*secs, rounded, "the fix must NOT pre-round to nanoseconds");
    }
    other => panic!("Duration must be an f64 in -n, got {other:?}"),
  }
}

/// FINDING 6 — the per-FILE `GotNAL07` latch must carry across H.264 frames so a
/// SECOND frame's SPS is NOT re-emitted. Frame 1 = SPS 1536x352 (no user data);
/// frame 2 = SPS 1280x720 + MDPM Canon. Bundled keeps frame 1's 1536x352 AND
/// frame 2's Make (oracle-verified), because `GotNAL07` suppresses frame 2's
/// SPS. A stateless re-parse would last-wins-clobber the size to 1280x720.
#[test]
fn h264_cross_frame_sps_is_suppressed_first_wins_size() {
  let mut buf = Vec::new();
  buf.extend_from_slice(&ts_packet(0, true, None, &pat(PMT_PID)));
  let streams = [(0x1bu8, VIDEO_PID, &[][..])];
  buf.extend_from_slice(&ts_packet(PMT_PID, true, None, &pmt(&streams, PCR_PID)));
  buf.extend_from_slice(&ts_packet(
    VIDEO_PID,
    true,
    None,
    &pes(0xe0, &h264_sps_with_size()),
  )); // frame1: 1536x352, no UD
  buf.extend_from_slice(&ts_packet(
    VIDEO_PID,
    true,
    None,
    &pes(0xe0, &h264_sps1280_with_mdpm()),
  )); // frame2: 1280x720 + MDPM
  buf.extend_from_slice(&ts_packet(
    VIDEO_PID,
    true,
    None,
    &pes(0xe0, &h264_sps_with_size()),
  ));
  for _ in 0..4 {
    buf.extend_from_slice(&ts_packet(0x1fff, false, None, &[0xff; 10]));
  }

  let m = parse_m2ts(&buf);
  let h = m.h264().expect("H.264 sub-Meta");
  assert_eq!(
    h.make(),
    Some("Canon"),
    "frame 2's MakeModel must be extracted"
  );
  // The SURVIVING ImageWidth/ImageHeight must be frame 1's 1536x352 (frame 2's
  // SPS suppressed by GotNAL07). Resolve the last-wins survivor by walk order.
  let width = h
    .entries()
    .iter()
    .filter(|e| e.name() == "ImageWidth")
    .next_back()
    .and_then(|e| e.value_ref().as_u64());
  let height = h
    .entries()
    .iter()
    .filter(|e| e.name() == "ImageHeight")
    .next_back()
    .and_then(|e| e.value_ref().as_u64());
  assert_eq!(
    width,
    Some(1536),
    "frame 1's SPS width must survive (GotNAL07 suppresses frame 2)"
  );
  assert_eq!(height, Some(352), "frame 1's SPS height must survive");
}

/// FINDING 8 — the EOF final flush must order pending PIDs by their STRINGIFIED
/// value (`sort keys %data`), not numerically. PIDs 68 and 100 are both AC-3,
/// each a single short PES (parsed only at EOF). String sort is "100" < "68",
/// so PID 100 flushes first and PID 68 LAST ⇒ PID 68's sample rate (idx 2)
/// survives. Numeric order (68 < 100) would let PID 100 (idx 1) win.
///
/// Oracle: bundled `exiftool -n` ⇒ `AC3:AudioSampleRate 2` (PID 68's value).
#[test]
fn eof_flush_uses_string_pid_order() {
  let streams = [(0x81u8, 68u16, &[][..]), (0x81u8, 100u16, &[][..])];
  let mut buf = Vec::new();
  buf.extend_from_slice(&ts_packet(0, true, None, &pat(PMT_PID)));
  buf.extend_from_slice(&ts_packet(PMT_PID, true, None, &pmt(&streams, PCR_PID)));
  buf.extend_from_slice(&ts_packet(68, true, None, &ac3_pes_rate(2)));
  buf.extend_from_slice(&ts_packet(100, true, None, &ac3_pes_rate(1)));
  for _ in 0..4 {
    buf.extend_from_slice(&ts_packet(0x1fff, false, None, &[0xff; 10]));
  }
  let m = parse_m2ts(&buf);
  assert_eq!(
    m.ac3_audio_sample_rate(),
    Some(2),
    "EOF flush must be string-ordered: PID 68 flushes LAST, so its rate (2) wins"
  );
}

/// FINDING 1 — a PMT section with `section_length == 0` (which still passes the
/// header guards: byte `pos+1` = 0x80 sets the syntax indicator AND a zero low
/// nibble) makes the Perl `$end` NEGATIVE; the row loops never run. The unsigned
/// `pos + section_length + 3 - 4` would underflow (debug panic / runaway). The
/// parser must accept the stream and emit NO stream-type tags (no panic).
#[test]
fn zero_section_length_pmt_does_not_panic() {
  // PMT section: table_id 0x02, syntax/len bytes 0x80 0x00 (section_length 0),
  // then padding so slen >= pos + 8.
  let mut sect = vec![0x02u8, 0x80, 0x00];
  sect.extend_from_slice(&[0u8; 12]);
  let mut pmt_pkt = vec![0u8]; // pointer field
  pmt_pkt.extend_from_slice(&sect);
  let mut buf = Vec::new();
  buf.extend_from_slice(&ts_packet(0, true, None, &pat(PMT_PID)));
  buf.extend_from_slice(&ts_packet(PMT_PID, true, None, &pmt_pkt));
  for _ in 0..4 {
    buf.extend_from_slice(&ts_packet(0x1fff, false, None, &[0xff; 10]));
  }
  let m = parse_m2ts(&buf);
  assert!(m.video_stream_type().is_none());
  assert!(m.audio_stream_type().is_none());
}

/// FINDING 9 — malformed `$et->Warn` sites must surface as `ExifTool:Warning`.
/// A PMT packet with a Bad pointer field (pointer 250 > packet end) raises
/// `Warn('Bad pointer field')` and `last` (M2TS.pm:764). The PAT was parsed
/// first, but the `last` stops the walk before any stream-type tag, exactly
/// like bundled (`exiftool` ⇒ `ExifTool:Warning "Bad pointer field"`, no
/// VideoStreamType).
#[cfg(feature = "json")]
#[test]
fn bad_pointer_field_emits_warning() {
  let mut bad_pmt = vec![250u8]; // pointer field 250 (> 188 packet) -> Bad pointer
  bad_pmt.push(0x02);
  bad_pmt.extend_from_slice(&[0u8; 10]);
  let mut buf = Vec::new();
  buf.extend_from_slice(&ts_packet(0, true, None, &pat(PMT_PID)));
  buf.extend_from_slice(&ts_packet(PMT_PID, true, None, &bad_pmt));
  for _ in 0..6 {
    buf.extend_from_slice(&ts_packet(0x1fff, false, None, &[0xff; 10]));
  }

  use exifast::diagnostics::Diagnose;
  let m = parse_m2ts(&buf);
  let diags = Diagnose::diagnostics(&m);
  assert!(
    diags.iter().any(|d| d.message() == "Bad pointer field"),
    "expected a 'Bad pointer field' diagnostic, got {:?}",
    diags.iter().map(|d| d.message()).collect::<Vec<_>>()
  );
  // End-to-end: the document JSON carries it as ExifTool:Warning.
  let json = exifast::parser::extract_info("bad.mts", &buf, true);
  assert!(
    json.contains("\"ExifTool:Warning\":\"Bad pointer field\""),
    "expected ExifTool:Warning=Bad pointer field in:\n{json}"
  );
}

/// FINDING 9 (ordering) — when the H.264 minor warning fires BEFORE a later
/// `M2TS synchronization error`, the FIRST (minor) warning is the document
/// `ExifTool:Warning` survivor (priority-0 first-wins). Oracle-verified:
/// bundled `exiftool` surfaces only `[minor] The ExtractEmbedded option…`.
#[cfg(feature = "json")]
#[test]
fn h264_minor_warning_precedes_later_sync_error() {
  let mut buf = Vec::new();
  buf.extend_from_slice(&ts_packet(0, true, None, &pat(PMT_PID)));
  let streams = [(0x1bu8, VIDEO_PID, &[][..])];
  buf.extend_from_slice(&ts_packet(PMT_PID, true, None, &pmt(&streams, PCR_PID)));
  buf.extend_from_slice(&ts_packet(
    VIDEO_PID,
    true,
    None,
    &pes(0xe0, &h264_with_mdpm()),
  ));
  buf.extend_from_slice(&ts_packet(
    VIDEO_PID,
    true,
    None,
    &pes(0xe0, &h264_with_mdpm()),
  ));
  // A bad-sync packet AFTER the H.264 was parsed -> sync error (later in walk).
  buf.extend_from_slice(&ts_packet_bad_sync(0x1fff));
  for _ in 0..4 {
    buf.extend_from_slice(&ts_packet(0x1fff, false, None, &[0xff; 10]));
  }

  let json = exifast::parser::extract_info("h264_sync.mts", &buf, true);
  assert!(
    json.contains(
      "\"ExifTool:Warning\":\"[minor] The ExtractEmbedded option may find more tags in the video data\""
    ),
    "the H.264 minor warning (earlier in walk order) must be the surviving ExifTool:Warning in:\n{json}"
  );
}

/// A PES private-stream (`stream_id` 0xbf, `%noSyntax` — no 3-byte PES syntax
/// header skip, M2TS.pm:925 / `is_no_syntax`) wrapper carrying `payload`
/// directly after the 6-byte PES prefix. The LIGOGPSINFO dashcam stream
/// (`type == 6 and $pid == 0x0300`, M2TS.pm:308) rides this private stream, so
/// the ordinary [`pes`] helper (which injects a `[80 00 00]` syntax header) must
/// NOT be used — those 3 bytes would be read as the start of the LIGOGPSINFO
/// block. `pes_packet_length` 0 ⇒ no `packLen`.
fn pes_no_syntax(payload: &[u8]) -> Vec<u8> {
  let mut out = vec![0x00, 0x00, 0x01, 0xbf, 0x00, 0x00];
  out.extend_from_slice(payload);
  out
}

/// A MALFORMED `LIGOGPSINFO\0` block that decodes to a `LIGOGPSINFO format
/// error` (`ParseLigoGPS` rejects it, LigoGPS.pm:235). Layout per
/// `process_ligogps`: the records start at offset `0x14`, each `0x84` bytes.
/// The single record is a plain-ASCII-date record (passes `m(^.{4}\d{4}/\d{2}/
/// \d{2} )s`, LigoGPS.pm:304) whose body `2024/01/01 ` is followed by a
/// non-whitespace token, so the lead-field regex (date + time + `N/S:lat`
/// E/W:lon + speed`) fails on the missing time/coordinate fields ⇒ the walker
/// raises `$et->Warn('LIGOGPSINFO format error')`.
fn malformed_ligogps_block() -> Vec<u8> {
  let mut blk = Vec::new();
  blk.extend_from_slice(b"LIGOGPSINFO\0"); // 12-byte header prefix
  // Pad to the 0x14 (20) records offset; 0xff keeps the `pos-8` no-fuzz probe
  // (`\0\0\0[\x01\x14]`, LigoGPS.pm:299) from matching (irrelevant to the
  // format-error path, but avoids any incidental behavior change).
  while blk.len() < 0x14 {
    blk.push(0xff);
  }
  // TWO 0x84-byte records (so the PES — 6-byte prefix + 0x14 offset + 2*0x84 =
  // 290 bytes — spans two TS packets, letting the type-6 accumulator cross the
  // 256-byte `SAVE_LEN_SMALL` in-loop dispatch threshold). Each record: [0..4]
  // counter, [4..15] = "2024/01/01 " (the ASCII date LigoGPS.pm:304 accepts),
  // then a single non-whitespace token so the LigoGPS.pm:235 lead-field regex
  // fails (no time / coordinate fields) ⇒ `LIGOGPSINFO format error`.
  let mut rec = Vec::new();
  rec.extend_from_slice(&[0u8; 4]); // counter (NOT "####" ⇒ the plain-ASCII arm)
  rec.extend_from_slice(b"2024/01/01 "); // YYYY/MM/DD + space (11 bytes)
  rec.extend_from_slice(&[b'X'; 0x84 - 4 - 11]); // garbage, no whitespace/NUL
  assert_eq!(rec.len(), 0x84);
  blk.extend_from_slice(&rec);
  blk.extend_from_slice(&rec);
  blk
}

/// Codex R3 FINDING (ordering) — a malformed LIGOGPSINFO PES that decodes
/// (raising `LIGOGPSINFO format error`, LigoGPS.pm:235) BEFORE a later `M2TS
/// synchronization error` (M2TS.pm:708) must be the document `ExifTool:Warning`
/// survivor — the LIGOGPS warning is a DOCUMENT-level `$et->Warn` pushed AT ITS
/// PID-0x0300 PES walk position (not appended after the structural corpus), so
/// the priority-0 FIRST-wins resolution (ExifTool.pm `%noDups`; Extra.pm
/// Warning `Priority => 0`) keeps the EARLIER LIGOGPS warning, NOT the later
/// sync error. Mirrors `h264_minor_warning_precedes_later_sync_error`.
///
/// The PMT declares PID 0x0300 as stream-type 6 (`ISO 13818-1 PES private
/// data`); it is NOT auto-needed, but the elementary-stream path accumulates
/// it and (no PCR ⇒ the walk never early-stops) dispatches it IN-LOOP once the
/// accumulator reaches `SAVE_LEN_SMALL` (256 bytes) across two TS packets, i.e.
/// at the LIGOGPS PES walk position, BEFORE the trailing bad-sync packet.
#[cfg(feature = "json")]
#[test]
fn ligogps_format_error_precedes_later_sync_error() {
  const LIGO_PID: u16 = 0x0300;
  let block = malformed_ligogps_block();
  let pes = pes_no_syntax(&block);
  // Split the PES across a START packet + one continuation so the type-6
  // accumulator crosses the 256-byte `SAVE_LEN_SMALL` in-loop dispatch
  // threshold AT the LIGOGPS walk position (a single TS packet's ~178-byte
  // payload is below it ⇒ would otherwise dispatch only at the EOF flush).
  // 184 = one TS packet's full payload (4-byte TS header + 184 = 188); the
  // continuation then carries the remaining bytes so the type-6 accumulator
  // reaches >= 256 IN-LOOP, at the LIGOGPS PES walk position.
  let split = 184usize.min(pes.len());
  let (head, tail) = pes.split_at(split);
  assert!(
    !tail.is_empty(),
    "the PES must span two TS packets for in-loop dispatch"
  );

  let mut buf = Vec::new();
  buf.extend_from_slice(&ts_packet(0, true, None, &pat(PMT_PID)));
  let streams = [(6u8, LIGO_PID, &[][..])];
  buf.extend_from_slice(&ts_packet(PMT_PID, true, None, &pmt(&streams, PCR_PID)));
  // LIGOGPSINFO PES: start packet (PES prefix + header), then a continuation
  // that pushes the accumulator past the in-loop dispatch threshold.
  buf.extend_from_slice(&ts_packet(LIGO_PID, true, None, head));
  buf.extend_from_slice(&ts_packet(LIGO_PID, false, None, tail));
  // A bad-sync packet AFTER the LIGOGPS PES decoded -> sync error (later walk).
  buf.extend_from_slice(&ts_packet_bad_sync(0x1fff));
  for _ in 0..4 {
    buf.extend_from_slice(&ts_packet(0x1fff, false, None, &[0xff; 10]));
  }

  // The typed corpus must carry the LIGOGPS warning BEFORE the sync error in
  // WALK order (the in-walk push), so the FIRST-wins document survivor is it.
  // Parsed at `-ee`: the LIGOGPSINFO decode arm (and its walker warning) is now
  // `-ee`-gated (#307), so the malformed PES is only decoded under `-ee`.
  use exifast::diagnostics::Diagnose;
  let m = parse_m2ts_ee(&buf);
  let msgs: Vec<_> = Diagnose::diagnostics(&m)
    .iter()
    .map(|d| d.message().to_string())
    .collect();
  let ligo_idx = msgs.iter().position(|x| x == "LIGOGPSINFO format error");
  let sync_idx = msgs.iter().position(|x| x == "M2TS synchronization error");
  assert!(
    ligo_idx.is_some(),
    "expected a 'LIGOGPSINFO format error' diagnostic, got {msgs:?}"
  );
  assert!(
    sync_idx.is_some(),
    "expected a later 'M2TS synchronization error' diagnostic, got {msgs:?}"
  );
  assert!(
    ligo_idx < sync_idx,
    "the LIGOGPS warning must precede the sync error in walk order, got {msgs:?}"
  );
  // Single-emit guarantee: the latch keeps the LIGOGPS warning to ONE entry.
  assert_eq!(
    msgs
      .iter()
      .filter(|x| **x == "LIGOGPSINFO format error")
      .count(),
    1,
    "the LIGOGPS warning must be emitted exactly once (latched), got {msgs:?}"
  );

  // End-to-end: the surviving document `ExifTool:Warning` is the LIGOGPS one.
  // The `-ee` options reach the LIGOGPSINFO decode arm (the warning is a decode
  // product, so the no-`ee` document would NOT carry it — #307).
  let json = exifast::parser::extract_info_with_options(
    "ligo_sync.mts",
    &buf,
    true,
    exifast::ParseOptions::default().with_extract_embedded(true),
  );
  assert!(
    json.contains("\"ExifTool:Warning\":\"LIGOGPSINFO format error\""),
    "the earlier LIGOGPS warning must be the surviving ExifTool:Warning in:\n{json}"
  );
}

/// A VALID `LIGOGPSINFO\0` block carrying ONE plain-ASCII GPS record (the
/// Redtiger/F9 4K format `process_ligogps` accepts, LigoGPS.pm:304): `[counter]
/// YYYY/MM/DD HH:MM:SS [NS]:lat [EW]:lon spd km/h …`. The PES is 12 (header) + 8
/// (preamble, records-offset 0x14) + 0x84 (one record) = 152 bytes ⇒ `noFuzz ==
/// (len != 200) == true`, so the record decodes WITHOUT defuzzing — straight to
/// the lat/lon the text spells. With `N:45.500 W:120.500` the first fix is
/// +45.500 / -120.500.
fn valid_ligogps_block() -> Vec<u8> {
  let mut blk = Vec::new();
  blk.extend_from_slice(b"LIGOGPSINFO\0"); // 12-byte header prefix
  // 8-byte preamble: bytes [0x0c..0x10] = [0,0,0,0x14] put the records offset at
  // 0x14 (the `process_ligogps` auto-detect, LigoGPS.pm:299), then 4 zero bytes.
  blk.extend_from_slice(&[0, 0, 0, 0x14, 0, 0, 0, 0]);
  // One 0x84-byte record: 4-byte counter + the plain-ASCII GPS line, NUL-padded.
  let mut rec = Vec::with_capacity(0x84);
  rec.extend_from_slice(&[0x01, 0x02, 0x03, 0x04]); // counter (NOT "####")
  rec.extend_from_slice(b"2024/06/15 14:30:00 N:45.500 W:120.500 50.0 km/h H:100.0");
  while rec.len() < 0x84 {
    rec.push(0);
  }
  assert_eq!(rec.len(), 0x84);
  blk.extend_from_slice(&rec);
  blk
}

/// #307 — the LIGOGPSINFO decode is gated EXPLICITLY on parse-time
/// `extract_embedded`, NOT on the incidental walk extent. Build an M2TS whose
/// PID-0x0300 LIGOGPSINFO PES appears EARLY and that has NO PCR — so the forward
/// pass NEVER early-stops (the `need_count == 0 && start_time` guard never arms)
/// and the PES is reached on EVERY parse, no-`ee` or `-ee`. The `Project`
/// projection copies any decoded first fix into `MediaMetadata::gps`
/// MODE-INDEPENDENTLY, so were the decode tied only to the walk position this
/// stream WOULD surface GPS at the default no-`ee` `media_metadata` — violating
/// the #307 contract (this LIGOGPS GPS only at parse-time `-ee`). With the decode
/// `-ee`-gated, no-`ee` decodes NOTHING (gps `None`), `-ee` decodes the fix.
#[cfg(feature = "std")]
#[test]
fn ligogps_early_pid_decode_is_extract_embedded_gated_not_walk_position() {
  use exifast::ParseOptions;
  const LIGO_PID: u16 = 0x0300;

  // PMT declares PID 0x0300 as stream-type 6 (`PES private data`); NO PCR PID is
  // signalled (PCR_PID == 0x1fff, the reserved null PID — never carries a PCR),
  // so the walk has no last-PCR to early-stop toward: it runs to EOF regardless
  // of mode, reaching the LIGOGPS PES on BOTH parses.
  let block = valid_ligogps_block();
  let pes = pes_no_syntax(&block);
  let mut buf = Vec::new();
  buf.extend_from_slice(&ts_packet(0, true, None, &pat(PMT_PID)));
  let streams = [(6u8, LIGO_PID, &[][..])];
  buf.extend_from_slice(&ts_packet(PMT_PID, true, None, &pmt(&streams, 0x1fff)));
  // The LIGOGPS PES rides one START packet near the FRONT of the stream — long
  // before any (here, nonexistent) early-stop. The 152-byte block fits one TS
  // packet; the EOF flush dispatches it through `parse_pid` (the `-ee`-gated arm).
  buf.extend_from_slice(&ts_packet(LIGO_PID, true, None, &pes));
  // A little trailing inert null filler so the PES is plainly NOT the last thing
  // in the stream (the "appears early" intent), without adding a PCR.
  for _ in 0..4 {
    buf.extend_from_slice(&ts_packet(0x1fff, false, None, &[0xff; 10]));
  }

  // ── default (no-`ee`): the decode is suppressed ⇒ NO domain GPS, even though
  //    the walk reaches the PID (no PCR ⇒ no early-stop). ──
  let md_base = exifast::media_metadata(&buf).expect("recognized M2TS at no-ee");
  assert!(
    md_base.gps().is_none(),
    "no-`ee` must NOT surface LIGOGPS GPS even when the PID-0x0300 PES is reached \
     (the decode is `extract_embedded`-gated, not walk-position-gated): got {:?}",
    md_base.gps()
  );

  // ── `-ee`: the decode runs ⇒ the first fix flows to `MediaMetadata::gps`. ──
  let md_ee = exifast::media_metadata_with_options(
    &buf,
    &ParseOptions::default().with_extract_embedded(true),
  )
  .expect("recognized M2TS at -ee");
  let gps = md_ee
    .gps()
    .expect("at -ee the early LIGOGPS PES decodes and projects MediaMetadata::gps");
  let lat = gps.latitude().expect("LIGOGPS latitude");
  let lon = gps.longitude().expect("LIGOGPS longitude");
  assert!(
    (lat - 45.500).abs() < 1e-3,
    "LIGOGPS latitude: got {lat}, expected ~45.500"
  );
  assert!(
    (lon - -120.500).abs() < 1e-3,
    "LIGOGPS longitude: got {lon}, expected ~-120.500"
  );
}

/// Codex R2 FINDING A — a FIRST PMT carried on a SEEDED RESERVED PID (1, 2, or
/// 0x1fff) must STILL decode its AC-3 stream descriptors. Perl seeds `%didPID =
/// ( 1 => 0, 2 => 0, 0x1fff => 0 )` (M2TS.pm:629): DEFINED but Perl-FALSE. The
/// AC-3 descriptor gate is `unless ($didPID{$pid})` (M2TS.pm:886) — TRUTHINESS
/// — so a seeded `0` does NOT suppress the decode (only the M2TS.pm:897
/// elementary-stream path, gated on DEFINEDNESS, is skipped for these PIDs).
/// The earlier single-flag model conflated the two and suppressed the decode.
///
/// Oracle (bundled `exiftool 13.59 -n -G1` on the byte-identical stream, for
/// EACH of PIDs 1 / 2 / 0x1fff carrying the PMT):
///   M2TS:AudioStreamType 129, AC3:AudioBitrate 256000 (raw idx 12),
///   SurroundMode 0, AudioChannels 2 — and NO `ExifTool:Warning`.
#[test]
fn pmt_on_seeded_reserved_pid_still_decodes_ac3_descriptor() {
  // PMT row: an AC-3 elementary stream (PID 0x44) with one 0x81 descriptor
  // (bitrate idx 12 ⇒ raw getter 12 / ValueConv 256000; surround 0; channels 2).
  let desc = ac3_descriptor_with(12, 0, 2);
  let streams = [(0x81u8, AUDIO_PID, &desc[..])];
  for reserved_pid in [1u16, 2u16, 0x1fffu16] {
    let mut buf = Vec::new();
    // PAT routes program 1 to the reserved PID, so the PMT (carried on that
    // reserved PID) reaches the PMT branch (`pmt_pids` membership).
    buf.extend_from_slice(&ts_packet(0, true, None, &pat(reserved_pid)));
    buf.extend_from_slice(&ts_packet(
      reserved_pid,
      true,
      None,
      &pmt(&streams, PCR_PID),
    ));
    for _ in 0..6 {
      buf.extend_from_slice(&ts_packet(0x1fff, false, None, &[0xff; 10]));
    }
    let m = parse_m2ts(&buf);
    // The AC-3 descriptor decoded despite the PMT riding a seeded reserved PID.
    assert_eq!(
      m.ac3_audio_bitrate(),
      Some(12),
      "PMT on reserved PID 0x{reserved_pid:04x}: AC3:AudioBitrate must decode (raw idx 12)"
    );
    assert_eq!(
      m.ac3_surround_mode(),
      Some(0),
      "PMT on reserved PID 0x{reserved_pid:04x}: AC3:SurroundMode must decode (0)"
    );
    assert_eq!(
      m.ac3_audio_channels(),
      Some(2),
      "PMT on reserved PID 0x{reserved_pid:04x}: AC3:AudioChannels must decode (2)"
    );
    // The Audio elementary PID (0x44, not reserved) is named ⇒ StreamType 0x81.
    assert_eq!(
      m.audio_stream_type(),
      Some(0x81),
      "PMT on reserved PID 0x{reserved_pid:04x}: AudioStreamType must emit (0x81)"
    );
  }
}

/// Codex R2 FINDING A (end-to-end, oracle bitrate) — confirm the emitted
/// `AC3:AudioBitrate` ValueConv (raw idx 12 ⇒ 256000) survives a PMT carried on
/// reserved PID 1, matching bundled `exiftool -n` `AC3:AudioBitrate 256000`.
#[cfg(feature = "json")]
#[test]
fn pmt_on_reserved_pid_emits_ac3_bitrate_value() {
  let desc = ac3_descriptor_with(12, 0, 2);
  let streams = [(0x81u8, AUDIO_PID, &desc[..])];
  let mut buf = Vec::new();
  buf.extend_from_slice(&ts_packet(0, true, None, &pat(1)));
  buf.extend_from_slice(&ts_packet(1, true, None, &pmt(&streams, PCR_PID)));
  for _ in 0..6 {
    buf.extend_from_slice(&ts_packet(0x1fff, false, None, &[0xff; 10]));
  }
  // `-n` (Numeric / ValueConv): AudioBitrate idx 12 → 256000 (M2TS.pm:192).
  use exifast::emit::{ConvMode, EmitOptions, Taggable};
  use exifast::value::TagValue;
  let m = parse_m2ts(&buf);
  let numeric: Vec<_> = m
    .tags(EmitOptions::g1(ConvMode::ValueConv, false))
    .collect();
  let br = numeric
    .iter()
    .find(|t| t.tag().name() == "AudioBitrate")
    .expect("AudioBitrate present (PMT on reserved PID decoded)");
  assert_eq!(
    br.tag().value_ref(),
    &TagValue::U64(256000),
    "AC3:AudioBitrate -n must be ValueConv 256000 for a PMT on reserved PID 1"
  );
}

/// Codex R2 FINDING B — a pointer field landing EXACTLY at packet end must emit
/// "Bad pointer field", not "Truncated payload". Perl: `$pos += 1 +
/// $pointer_field; $pos >= $pEnd and $et->Warn('Bad pointer field'), last`
/// (M2TS.pm:763-764) — the check is `>=`, so equality fires it. A no-adaptation
/// 188-byte PAT packet with pointer 183 lands `pos = 4 + 1 + 183 = 188 ==
/// packet.len()`. The prior `packet.get(pos..)` SUCCEEDED for `pos ==
/// packet.len()` (empty slice) and fell through to the section-header guard,
/// wrongly emitting "Truncated payload".
///
/// Oracle (bundled `exiftool 13.59` on the byte-identical stream):
///   `ExifTool:Warning = "Bad pointer field"` (and no "Truncated payload").
#[cfg(feature = "json")]
#[test]
fn pointer_field_at_packet_end_emits_bad_pointer_not_truncated() {
  // PAT (PID 0), payload_unit_start, NO adaptation; payload is the single
  // pointer byte 183. In `process_psi`, pos = 4 (past prefix), reads pointer
  // 183, then pos = 4 + 1 + 183 = 188 = packet length (exact end).
  let mut buf = Vec::new();
  buf.extend_from_slice(&ts_packet(0, true, None, &[183u8]));
  for _ in 0..6 {
    buf.extend_from_slice(&ts_packet(0x1fff, false, None, &[0xff; 10]));
  }

  use exifast::diagnostics::Diagnose;
  let m = parse_m2ts(&buf);
  let msgs: Vec<_> = Diagnose::diagnostics(&m)
    .iter()
    .map(|d| d.message().to_string())
    .collect();
  assert!(
    msgs.iter().any(|m| m == "Bad pointer field"),
    "pos==packet.len() must warn 'Bad pointer field', got {msgs:?}"
  );
  assert!(
    !msgs.iter().any(|m| m == "Truncated payload"),
    "pos==packet.len() must NOT warn 'Truncated payload', got {msgs:?}"
  );
  // End-to-end: the surviving document `ExifTool:Warning` is the Bad pointer.
  let json = exifast::parser::extract_info("ptr_end.mts", &buf, true);
  assert!(
    json.contains("\"ExifTool:Warning\":\"Bad pointer field\""),
    "expected ExifTool:Warning=Bad pointer field in:\n{json}"
  );
}
