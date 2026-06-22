// SPDX-License-Identifier: GPL-3.0-or-later
// exifast — a 1:1 Rust port of ExifTool (Phil Harvey). See THIRD_PARTY.md.
//
// Per-protocol dispatch tables — a 1:1 transcription of the
// `%Image::ExifTool::DJI::Protobuf` tag table (DJI.pm:268-859) PLUS the
// nested message tables it references via SubDirectory:
//   - DJI::FrameInfo  (DJI.pm:886-894) — fields 1=Width, 2=Height, 3=Rate
//   - DJI::GPSInfo    (DJI.pm:896-921) — fields 1=CoordUnits, 2=Lat, 3=Lon
//   - DJI::DroneInfo  (DJI.pm:868-875) — fields 1=Roll, 2=Pitch, 3=Yaw
//   - DJI::GimbalInfo (DJI.pm:877-884) — fields 1=Pitch, 2=Roll, 3=Yaw
//
// Each row's `path` is the FULL protobuf field-number chain to the leaf — the
// DJI.pm key (e.g. `dvtm_ac203_3-4-2-2`) with the SubDirectory tables spliced
// in (e.g. `dvtm_ac203_3-4-2-1` GPSInfo → child fields 1/2/3 become paths
// `3-4-2-1-1` / `3-4-2-1-2` / `3-4-2-1-3`). Rows MUST stay sorted by `path`
// (the `all_protocol_tables_sorted` test enforces this) for binary search.
//
// `# (NC)` "Not Confirmed" markers in DJI.pm are preserved as-is — they are
// included exactly when the bundled default table extracts them.
//
// FrameNumber (`3-1-1`) IS a row on EVERY protocol arm (DJI.pm:279/:320/:361/
// :404/:446/:479/:515/:558/:598/:639/:677/:721/:744/:782/:833/:868,
// `#forum17996`): a NAMED tag (`Name => 'FrameNumber', Format => 'unsigned'`)
// with no `Unknown` flag ⇒ ExifTool extracts it by default at `-ee`. It lives
// in the per-frame `3-1` message next to TimeStamp (`3-1-2`), so it is emitted
// PER `djmd` sample (one `Doc<N>` each), not clip-level.
//
// Walked-but-discarded fields (AccelerometerX/Y/Z, "model code", version
// numbers) are NOT rows here: they are `Unknown => 1` non-default extractions.
// See the module docs.
//
// SerialNumber2 (`2-2-3-1`) IS a row on the AVATA2 + DJI Neo arms only
// (DJI.pm:399/:553): a NAMED tag with no `Unknown` flag ⇒ ExifTool extracts it
// by default at `-ee`. The `# (NC)` on both rows is a "Not Confirmed" source
// comment, not a non-default marker. No other protocol declares it.
//
// NOTE on GPSAltitude vs AbsoluteAltitude: the ac203/ac204/ac206 arms name
// the `3-4-2-2` leaf `GPSAltitude` with `Format => 'unsigned'`
// (DJI.pm:296-301/:336/:377) — a PLAIN varint scaled `/1000`, NOT the int64s
// hack (`K::GpsAltitude`). Every OTHER arm (incl. oq101 `3-4-2-2`,
// DJI.pm:700) names it `AbsoluteAltitude` with `Format => 'int64s'`
// (`K::AbsoluteAltitude`). The two differ only in the emitted tag NAME and on
// a hostile varint ≥ INT64S_MIN; for real (non-negative) altitudes they are
// numerically identical.

use FieldKind as K;

// ===========================================================================
// dvtm_ac203 — Osmo Action 4 (DJI.pm:268-307)
// ===========================================================================
static AC203: &[Row] = &[
  Row { path: &[1, 1, 5], kind: K::SerialNumber },     // DJI.pm:271
  Row { path: &[1, 1, 10], kind: K::Model },           // DJI.pm:273
  Row { path: &[2, 3, 1], kind: K::FrameWidth },       // DJI.pm:274-277 FrameInfo
  Row { path: &[2, 3, 2], kind: K::FrameHeight },      //   "
  Row { path: &[2, 3, 3], kind: K::FrameRate },        //   "
  Row { path: &[3, 1, 1], kind: K::FrameNumber },      // DJI.pm:279 (forum17996)
  Row { path: &[3, 2, 3, 1], kind: K::Iso },           // DJI.pm:280 (forum17996)
  Row { path: &[3, 2, 4, 1], kind: K::ShutterSpeed },  // DJI.pm:281-285
  Row { path: &[3, 2, 6, 1], kind: K::ColorTemperature }, // DJI.pm:284
  Row { path: &[3, 4, 2, 1, 1], kind: K::CoordinateUnits }, // DJI.pm:290-293 GPSInfo
  Row { path: &[3, 4, 2, 1, 2], kind: K::GpsLatitude }, //   "
  Row { path: &[3, 4, 2, 1, 3], kind: K::GpsLongitude }, //   "
  Row { path: &[3, 4, 2, 2], kind: K::GpsAltitude },   // DJI.pm:296-301 GPSAltitude (unsigned)
  Row { path: &[3, 4, 2, 6, 1], kind: K::GpsDateTime }, // DJI.pm:302-309
];

// ===========================================================================
// dvtm_ac204 — Osmo Action 5 (DJI.pm:308-345)
// ===========================================================================
static AC204: &[Row] = &[
  Row { path: &[1, 1, 5], kind: K::SerialNumber },     // DJI.pm:311
  Row { path: &[1, 1, 10], kind: K::Model },           // DJI.pm:313
  Row { path: &[2, 3, 1], kind: K::FrameWidth },       // DJI.pm:314-317 FrameInfo
  Row { path: &[2, 3, 2], kind: K::FrameHeight },
  Row { path: &[2, 3, 3], kind: K::FrameRate },
  Row { path: &[3, 1, 1], kind: K::FrameNumber },      // DJI.pm:320 (forum17996)
  Row { path: &[3, 2, 3, 1], kind: K::Iso },           // DJI.pm:321 (forum17996)
  Row { path: &[3, 2, 4, 1], kind: K::ShutterSpeed },  // DJI.pm:322-326
  Row { path: &[3, 2, 6, 1], kind: K::ColorTemperature }, // DJI.pm:327
  Row { path: &[3, 4, 2, 1, 1], kind: K::CoordinateUnits }, // DJI.pm:328-331 GPSInfo
  Row { path: &[3, 4, 2, 1, 2], kind: K::GpsLatitude },
  Row { path: &[3, 4, 2, 1, 3], kind: K::GpsLongitude },
  Row { path: &[3, 4, 2, 2], kind: K::GpsAltitude },   // DJI.pm:336-341 GPSAltitude (unsigned)
  Row { path: &[3, 4, 2, 6, 1], kind: K::GpsDateTime }, // DJI.pm:342-349
];

// ===========================================================================
// dvtm_ac206 — Osmo Action 6 (same as Action 5; DJI.pm:346-384)
// ===========================================================================
static AC206: &[Row] = &[
  Row { path: &[1, 1, 5], kind: K::SerialNumber },     // DJI.pm:349
  Row { path: &[1, 1, 10], kind: K::Model },           // DJI.pm:351
  Row { path: &[2, 3, 1], kind: K::FrameWidth },       // DJI.pm:353-356 FrameInfo
  Row { path: &[2, 3, 2], kind: K::FrameHeight },
  Row { path: &[2, 3, 3], kind: K::FrameRate },
  Row { path: &[3, 1, 1], kind: K::FrameNumber },      // DJI.pm:361 (forum17996)
  Row { path: &[3, 2, 3, 1], kind: K::Iso },           // DJI.pm:362 (forum17996)
  Row { path: &[3, 2, 4, 1], kind: K::ShutterSpeed },  // DJI.pm:363-367
  Row { path: &[3, 2, 6, 1], kind: K::ColorTemperature }, // DJI.pm:368
  Row { path: &[3, 4, 2, 1, 1], kind: K::CoordinateUnits }, // DJI.pm:367-370 GPSInfo
  Row { path: &[3, 4, 2, 1, 2], kind: K::GpsLatitude },
  Row { path: &[3, 4, 2, 1, 3], kind: K::GpsLongitude },
  Row { path: &[3, 4, 2, 2], kind: K::GpsAltitude },   // DJI.pm:377-382 GPSAltitude (unsigned)
  Row { path: &[3, 4, 2, 6, 1], kind: K::GpsDateTime }, // DJI.pm:383-390
];

// ===========================================================================
// dvtm_AVATA2 — Avata 2 (DJI.pm:385-430)
// ===========================================================================
static AVATA2: &[Row] = &[
  Row { path: &[1, 1, 5], kind: K::SerialNumber },     // DJI.pm:390
  Row { path: &[1, 1, 10], kind: K::Model },           // DJI.pm:391
  Row { path: &[2, 2, 3, 1], kind: K::SerialNumber2 }, // DJI.pm:399 (NC)
  Row { path: &[2, 3, 1], kind: K::FrameWidth },       // DJI.pm:394-397 FrameInfo
  Row { path: &[2, 3, 2], kind: K::FrameHeight },
  Row { path: &[2, 3, 3], kind: K::FrameRate },
  Row { path: &[3, 1, 1], kind: K::FrameNumber },      // DJI.pm:404
  Row { path: &[3, 1, 2], kind: K::TimeStamp },        // DJI.pm:399-405
  Row { path: &[3, 2, 2, 1], kind: K::Iso },           // DJI.pm:408
  Row { path: &[3, 2, 4, 1], kind: K::ShutterSpeed },  // DJI.pm:409-413
  Row { path: &[3, 2, 6, 1], kind: K::ColorTemperature }, // DJI.pm:414
  Row { path: &[3, 2, 10, 1], kind: K::FNumber },      // DJI.pm:415-419
  Row { path: &[3, 4, 3, 1], kind: K::DroneRoll },     // DJI.pm:421-424 DroneInfo
  Row { path: &[3, 4, 3, 2], kind: K::DronePitch },
  Row { path: &[3, 4, 3, 3], kind: K::DroneYaw },
  Row { path: &[3, 4, 4, 1, 1], kind: K::CoordinateUnits }, // DJI.pm:425-428 GPSInfo
  Row { path: &[3, 4, 4, 1, 2], kind: K::GpsLatitude },
  Row { path: &[3, 4, 4, 1, 3], kind: K::GpsLongitude },
  Row { path: &[3, 4, 4, 2], kind: K::AbsoluteAltitude }, // DJI.pm:429
  Row { path: &[3, 4, 5, 1], kind: K::RelativeAltitude }, // DJI.pm:430
];

// ===========================================================================
// dvtm_wm265e — Mavic 3 (DJI.pm:431-462)
// ===========================================================================
static WM265E: &[Row] = &[
  Row { path: &[1, 1, 5], kind: K::SerialNumber },     // DJI.pm:434
  Row { path: &[1, 1, 10], kind: K::Model },           // DJI.pm:435
  Row { path: &[2, 2, 1], kind: K::FrameWidth },       // DJI.pm:436-439 FrameInfo
  Row { path: &[2, 2, 2], kind: K::FrameHeight },
  Row { path: &[2, 2, 3], kind: K::FrameRate },
  Row { path: &[3, 1, 1], kind: K::FrameNumber },      // DJI.pm:446
  Row { path: &[3, 2, 2, 1], kind: K::Iso },           // DJI.pm:441
  Row { path: &[3, 2, 3, 1], kind: K::ShutterSpeed },  // DJI.pm:442-446
  Row { path: &[3, 2, 6, 1], kind: K::DigitalZoom },   // DJI.pm:448
  Row { path: &[3, 3, 3, 1], kind: K::DroneRoll },     // DJI.pm:453-456 DroneInfo
  Row { path: &[3, 3, 3, 2], kind: K::DronePitch },
  Row { path: &[3, 3, 3, 3], kind: K::DroneYaw },
  Row { path: &[3, 3, 4, 1, 1], kind: K::CoordinateUnits }, // DJI.pm:449-452 GPSInfo
  Row { path: &[3, 3, 4, 1, 2], kind: K::GpsLatitude },
  Row { path: &[3, 3, 4, 1, 3], kind: K::GpsLongitude },
  Row { path: &[3, 3, 4, 2], kind: K::AbsoluteAltitude }, // DJI.pm:457
  Row { path: &[3, 3, 5, 1], kind: K::RelativeAltitude }, // DJI.pm:458
  Row { path: &[3, 4, 3, 1], kind: K::GimbalPitch },   // DJI.pm:459-462 GimbalInfo
  Row { path: &[3, 4, 3, 2], kind: K::GimbalRoll },
  Row { path: &[3, 4, 3, 3], kind: K::GimbalYaw },
];

// ===========================================================================
// dvtm_pm320 — Matrice 30 (DJI.pm:463-497)
// ===========================================================================
static PM320: &[Row] = &[
  Row { path: &[1, 1, 5], kind: K::SerialNumber },     // DJI.pm:466
  Row { path: &[1, 1, 10], kind: K::Model },           // DJI.pm:467
  Row { path: &[2, 2, 1], kind: K::FrameWidth },       // DJI.pm:468-471 FrameInfo
  Row { path: &[2, 2, 2], kind: K::FrameHeight },
  Row { path: &[2, 2, 3], kind: K::FrameRate },
  Row { path: &[3, 1, 1], kind: K::FrameNumber },      // DJI.pm:479
  Row { path: &[3, 2, 2, 1], kind: K::Iso },           // DJI.pm:472
  Row { path: &[3, 2, 3, 1], kind: K::ShutterSpeed },  // DJI.pm:473-477
  Row { path: &[3, 2, 4, 1], kind: K::FNumber },       // DJI.pm:478-482
  Row { path: &[3, 2, 6, 1], kind: K::DigitalZoom },   // DJI.pm:483
  Row { path: &[3, 3, 3, 1], kind: K::DroneRoll },     // DJI.pm:488-491 DroneInfo
  Row { path: &[3, 3, 3, 2], kind: K::DronePitch },
  Row { path: &[3, 3, 3, 3], kind: K::DroneYaw },
  Row { path: &[3, 3, 4, 1, 1], kind: K::CoordinateUnits }, // DJI.pm:484-487 GPSInfo
  Row { path: &[3, 3, 4, 1, 2], kind: K::GpsLatitude },
  Row { path: &[3, 3, 4, 1, 3], kind: K::GpsLongitude },
  Row { path: &[3, 3, 4, 2], kind: K::AbsoluteAltitude }, // DJI.pm:492
  Row { path: &[3, 3, 5, 1], kind: K::RelativeAltitude }, // DJI.pm:493
  Row { path: &[3, 4, 3, 1], kind: K::GimbalPitch },   // DJI.pm:494-497 GimbalInfo
  Row { path: &[3, 4, 3, 2], kind: K::GimbalRoll },
  Row { path: &[3, 4, 3, 3], kind: K::GimbalYaw },
];

// ===========================================================================
// dvtm_Mini4_Pro — Mini 4 Pro (DJI.pm:498-533)
// ===========================================================================
static MINI4PRO: &[Row] = &[
  Row { path: &[1, 1, 5], kind: K::SerialNumber },     // DJI.pm:501
  Row { path: &[1, 1, 10], kind: K::Model },           // DJI.pm:502
  Row { path: &[2, 3, 1], kind: K::FrameWidth },       // DJI.pm:503-506 FrameInfo
  Row { path: &[2, 3, 2], kind: K::FrameHeight },
  Row { path: &[2, 3, 3], kind: K::FrameRate },
  Row { path: &[3, 1, 1], kind: K::FrameNumber },      // DJI.pm:515
  Row { path: &[3, 2, 7, 1], kind: K::Iso },           // DJI.pm:507
  Row { path: &[3, 2, 10, 1], kind: K::ShutterSpeed }, // DJI.pm:508-512
  Row { path: &[3, 2, 11, 1], kind: K::FNumber },      // DJI.pm:513-517
  Row { path: &[3, 2, 32, 1], kind: K::ColorTemperature }, // DJI.pm:518
  Row { path: &[3, 2, 37, 1], kind: K::Temperature },  // DJI.pm:519
  Row { path: &[3, 3, 3, 1], kind: K::DroneRoll },     // DJI.pm:524-527 DroneInfo
  Row { path: &[3, 3, 3, 2], kind: K::DronePitch },
  Row { path: &[3, 3, 3, 3], kind: K::DroneYaw },
  Row { path: &[3, 3, 4, 1, 1], kind: K::CoordinateUnits }, // DJI.pm:520-523 GPSInfo
  Row { path: &[3, 3, 4, 1, 2], kind: K::GpsLatitude },
  Row { path: &[3, 3, 4, 1, 3], kind: K::GpsLongitude },
  Row { path: &[3, 3, 4, 2], kind: K::AbsoluteAltitude }, // DJI.pm:528
  Row { path: &[3, 3, 5, 1], kind: K::RelativeAltitude }, // DJI.pm:529
  Row { path: &[3, 4, 3, 1], kind: K::GimbalPitch },   // DJI.pm:530-533 GimbalInfo
  Row { path: &[3, 4, 3, 2], kind: K::GimbalRoll },
  Row { path: &[3, 4, 3, 3], kind: K::GimbalYaw },
];

// ===========================================================================
// dvtm_dji_neo — DJI Neo (very similar to AVATA2; DJI.pm:534-580)
// ===========================================================================
static DJI_NEO: &[Row] = &[
  Row { path: &[1, 1, 5], kind: K::SerialNumber },     // DJI.pm:539
  Row { path: &[1, 1, 10], kind: K::Model },           // DJI.pm:540
  Row { path: &[2, 2, 3, 1], kind: K::SerialNumber2 }, // DJI.pm:553 (NC)
  Row { path: &[2, 3, 1], kind: K::FrameWidth },       // DJI.pm:545-548 FrameInfo
  Row { path: &[2, 3, 2], kind: K::FrameHeight },
  Row { path: &[2, 3, 3], kind: K::FrameRate },
  Row { path: &[3, 1, 1], kind: K::FrameNumber },      // DJI.pm:558
  Row { path: &[3, 1, 2], kind: K::TimeStamp },        // DJI.pm:550-556
  Row { path: &[3, 2, 2, 1], kind: K::Iso },           // DJI.pm:559
  Row { path: &[3, 2, 4, 1], kind: K::ShutterSpeed },  // DJI.pm:560-564
  Row { path: &[3, 2, 6, 1], kind: K::ColorTemperature }, // DJI.pm:565
  Row { path: &[3, 2, 10, 1], kind: K::FNumber },      // DJI.pm:566-570
  Row { path: &[3, 4, 3, 1], kind: K::DroneRoll },     // DJI.pm:572-575 DroneInfo
  Row { path: &[3, 4, 3, 2], kind: K::DronePitch },
  Row { path: &[3, 4, 3, 3], kind: K::DroneYaw },
  Row { path: &[3, 4, 4, 1, 1], kind: K::CoordinateUnits }, // DJI.pm:576-579 GPSInfo
  Row { path: &[3, 4, 4, 1, 2], kind: K::GpsLatitude },
  Row { path: &[3, 4, 4, 1, 3], kind: K::GpsLongitude },
  Row { path: &[3, 4, 4, 2], kind: K::AbsoluteAltitude }, // DJI.pm:580
];

// ===========================================================================
// dvtm_Air3 — Air 3 (DJI.pm:581-620)
// ===========================================================================
static AIR3: &[Row] = &[
  Row { path: &[1, 1, 5], kind: K::SerialNumber },     // DJI.pm:584
  Row { path: &[2, 3, 1], kind: K::FrameWidth },       // DJI.pm:585-588 FrameInfo
  Row { path: &[2, 3, 2], kind: K::FrameHeight },
  Row { path: &[2, 3, 3], kind: K::FrameRate },
  Row { path: &[3, 1, 1], kind: K::FrameNumber },      // DJI.pm:598 (NC)
  Row { path: &[3, 1, 2], kind: K::TimeStamp },        // DJI.pm:589-594
  Row { path: &[3, 2, 7, 1], kind: K::Iso },           // DJI.pm:595
  Row { path: &[3, 2, 10, 1], kind: K::ShutterSpeed }, // DJI.pm:596-600
  Row { path: &[3, 2, 11, 1], kind: K::FNumber },      // DJI.pm:602-606
  Row { path: &[3, 2, 32, 1], kind: K::ColorTemperature }, // DJI.pm:601
  Row { path: &[3, 3, 3, 1], kind: K::DroneRoll },     // DJI.pm:607-610 DroneInfo
  Row { path: &[3, 3, 3, 2], kind: K::DronePitch },
  Row { path: &[3, 3, 3, 3], kind: K::DroneYaw },
  Row { path: &[3, 3, 4, 1, 1], kind: K::CoordinateUnits }, // DJI.pm:611-614 GPSInfo
  Row { path: &[3, 3, 4, 1, 2], kind: K::GpsLatitude },
  Row { path: &[3, 3, 4, 1, 3], kind: K::GpsLongitude },
  Row { path: &[3, 3, 4, 2], kind: K::AbsoluteAltitude }, // DJI.pm:615
  Row { path: &[3, 3, 5, 1], kind: K::RelativeAltitude }, // DJI.pm:616
  Row { path: &[3, 4, 3, 1], kind: K::GimbalPitch },   // DJI.pm:617-620 GimbalInfo
  Row { path: &[3, 4, 3, 2], kind: K::GimbalRoll },
  Row { path: &[3, 4, 3, 3], kind: K::GimbalYaw },
];

// ===========================================================================
// dvtm_Air3s — Air 3s (same structure as Air 3; DJI.pm:621-660)
// ===========================================================================
static AIR3S: &[Row] = &[
  Row { path: &[1, 1, 5], kind: K::SerialNumber },     // DJI.pm:624
  Row { path: &[2, 3, 1], kind: K::FrameWidth },       // DJI.pm:625-628 FrameInfo
  Row { path: &[2, 3, 2], kind: K::FrameHeight },
  Row { path: &[2, 3, 3], kind: K::FrameRate },
  Row { path: &[3, 1, 1], kind: K::FrameNumber },      // DJI.pm:639 (NC)
  Row { path: &[3, 1, 2], kind: K::TimeStamp },        // DJI.pm:629-634
  Row { path: &[3, 2, 7, 1], kind: K::Iso },           // DJI.pm:635
  Row { path: &[3, 2, 10, 1], kind: K::ShutterSpeed }, // DJI.pm:636-640
  Row { path: &[3, 2, 11, 1], kind: K::FNumber },      // DJI.pm:642-646
  Row { path: &[3, 2, 32, 1], kind: K::ColorTemperature }, // DJI.pm:641
  Row { path: &[3, 3, 3, 1], kind: K::DroneRoll },     // DJI.pm:647-650 DroneInfo
  Row { path: &[3, 3, 3, 2], kind: K::DronePitch },
  Row { path: &[3, 3, 3, 3], kind: K::DroneYaw },
  Row { path: &[3, 3, 4, 1, 1], kind: K::CoordinateUnits }, // DJI.pm:651-654 GPSInfo
  Row { path: &[3, 3, 4, 1, 2], kind: K::GpsLatitude },
  Row { path: &[3, 3, 4, 1, 3], kind: K::GpsLongitude },
  Row { path: &[3, 3, 4, 2], kind: K::AbsoluteAltitude }, // DJI.pm:655
  Row { path: &[3, 3, 5, 1], kind: K::RelativeAltitude }, // DJI.pm:656
  Row { path: &[3, 4, 3, 1], kind: K::GimbalPitch },   // DJI.pm:657-660 GimbalInfo
  Row { path: &[3, 4, 3, 2], kind: K::GimbalRoll },
  Row { path: &[3, 4, 3, 3], kind: K::GimbalYaw },
];

// ===========================================================================
// dvtm_oq101 — Osmo 360 (similar to Action 4/5; DJI.pm:661-699)
// ===========================================================================
static OQ101: &[Row] = &[
  Row { path: &[1, 1, 5], kind: K::SerialNumber },     // DJI.pm:664
  Row { path: &[1, 1, 10], kind: K::Model },           // DJI.pm:665
  Row { path: &[1, 14, 1], kind: K::FNumber },         // DJI.pm:679-683
  Row { path: &[3, 1, 1], kind: K::FrameNumber },      // DJI.pm:677
  Row { path: &[3, 1, 2], kind: K::TimeStamp },        // DJI.pm:666-671
  Row { path: &[3, 2, 3, 1], kind: K::Iso },           // DJI.pm:672
  Row { path: &[3, 2, 4, 1], kind: K::ShutterSpeed },  // DJI.pm:673-677
  Row { path: &[3, 2, 6, 1], kind: K::ColorTemperature }, // DJI.pm:678
  Row { path: &[3, 4, 2, 1, 1], kind: K::CoordinateUnits }, // DJI.pm:684-687 GPSInfo
  Row { path: &[3, 4, 2, 1, 2], kind: K::GpsLatitude },
  Row { path: &[3, 4, 2, 1, 3], kind: K::GpsLongitude },
  Row { path: &[3, 4, 2, 2], kind: K::AbsoluteAltitude }, // DJI.pm:688
  Row { path: &[3, 4, 2, 6, 1], kind: K::GpsDateTime }, // DJI.pm:689-696
];

// ===========================================================================
// dvtm_PP-101 — Osmo Pocket 3 (DJI.pm:700-721)
// ===========================================================================
static PP101: &[Row] = &[
  Row { path: &[1, 1, 5], kind: K::SerialNumber },     // DJI.pm:703
  Row { path: &[1, 1, 10], kind: K::Model },           // DJI.pm:704
  Row { path: &[2, 3, 1], kind: K::FrameWidth },       // DJI.pm:705-708 FrameInfo
  Row { path: &[2, 3, 2], kind: K::FrameHeight },
  Row { path: &[2, 3, 3], kind: K::FrameRate },
  Row { path: &[3, 1, 1], kind: K::FrameNumber },      // DJI.pm:721
  Row { path: &[3, 1, 2], kind: K::TimeStamp },        // DJI.pm:709-714
  Row { path: &[3, 2, 9, 1], kind: K::Iso },           // DJI.pm:715
  Row { path: &[3, 2, 10, 1], kind: K::ShutterSpeed }, // DJI.pm:716-720
  Row { path: &[3, 2, 24, 1], kind: K::ColorTemperature }, // DJI.pm:721
];

// ===========================================================================
// dvtm_wa345e — Matrice 4E (DJI.pm:722-758)
// ===========================================================================
static WA345E: &[Row] = &[
  Row { path: &[1, 1, 5], kind: K::SerialNumber },     // DJI.pm:725
  Row { path: &[1, 1, 10], kind: K::Model },           // DJI.pm:726
  Row { path: &[2, 2, 1], kind: K::FrameWidth },       // DJI.pm:727-730 FrameInfo
  Row { path: &[2, 2, 2], kind: K::FrameHeight },
  Row { path: &[2, 2, 3], kind: K::FrameRate },
  Row { path: &[3, 1, 1], kind: K::FrameNumber },      // DJI.pm:744
  Row { path: &[3, 1, 2], kind: K::TimeStamp },        // DJI.pm:731-736
  Row { path: &[3, 3, 3, 1], kind: K::DroneRoll },     // DJI.pm:737-740 DroneInfo
  Row { path: &[3, 3, 3, 2], kind: K::DronePitch },
  Row { path: &[3, 3, 3, 3], kind: K::DroneYaw },
  Row { path: &[3, 3, 4, 1, 1], kind: K::CoordinateUnits }, // DJI.pm:741-744 GPSInfo
  Row { path: &[3, 3, 4, 1, 2], kind: K::GpsLatitude },
  Row { path: &[3, 3, 4, 1, 3], kind: K::GpsLongitude },
  Row { path: &[3, 3, 4, 2], kind: K::AbsoluteAltitude }, // DJI.pm:745
  Row { path: &[3, 3, 4, 6, 1], kind: K::GpsDateTime }, // DJI.pm:751-758
  Row { path: &[3, 3, 5, 1], kind: K::RelativeAltitude }, // DJI.pm:746
  Row { path: &[3, 4, 3, 1], kind: K::GimbalPitch },   // DJI.pm:747-750 GimbalInfo
  Row { path: &[3, 4, 3, 2], kind: K::GimbalRoll },
  Row { path: &[3, 4, 3, 3], kind: K::GimbalYaw },
];

// ===========================================================================
// dvtm_wm261 — Mavic 3 Pro (DJI.pm:759-806)
// ===========================================================================
static WM261: &[Row] = &[
  Row { path: &[1, 1, 5], kind: K::SerialNumber },     // DJI.pm:762
  Row { path: &[1, 1, 10], kind: K::Model },           // DJI.pm:763
  Row { path: &[2, 3, 1], kind: K::FrameWidth },       // DJI.pm:764-767 FrameInfo
  Row { path: &[2, 3, 2], kind: K::FrameHeight },
  Row { path: &[2, 3, 3], kind: K::FrameRate },
  Row { path: &[3, 1, 1], kind: K::FrameNumber },      // DJI.pm:782
  Row { path: &[3, 1, 2], kind: K::TimeStamp },        // DJI.pm:768-773
  Row { path: &[3, 2, 9, 1], kind: K::Iso },           // DJI.pm:774
  Row { path: &[3, 2, 10, 1], kind: K::ShutterSpeed }, // DJI.pm:775-779
  Row { path: &[3, 2, 11, 1], kind: K::FNumber },      // DJI.pm:780-784
  Row { path: &[3, 3, 3, 1], kind: K::DroneRoll },     // DJI.pm:785-788 DroneInfo
  Row { path: &[3, 3, 3, 2], kind: K::DronePitch },
  Row { path: &[3, 3, 3, 3], kind: K::DroneYaw },
  Row { path: &[3, 3, 4, 1, 1], kind: K::CoordinateUnits }, // DJI.pm:789-792 GPSInfo
  Row { path: &[3, 3, 4, 1, 2], kind: K::GpsLatitude },
  Row { path: &[3, 3, 4, 1, 3], kind: K::GpsLongitude },
  Row { path: &[3, 3, 4, 2], kind: K::AbsoluteAltitude }, // DJI.pm:793
  Row { path: &[3, 3, 4, 6, 1], kind: K::GpsDateTime }, // DJI.pm:799-806
  Row { path: &[3, 3, 5, 1], kind: K::RelativeAltitude }, // DJI.pm:794
  Row { path: &[3, 4, 3, 1], kind: K::GimbalPitch },   // DJI.pm:795-798 GimbalInfo
  Row { path: &[3, 4, 3, 2], kind: K::GimbalRoll },
  Row { path: &[3, 4, 3, 3], kind: K::GimbalYaw },
];

// ===========================================================================
// dvtm_Mavic4 — Mavic 4 Pro (DJI.pm:807-846)
//   GPSInfo arm forces degrees (DJI.pm:841 Condition => '$$self{CoordUnits}
//   = 1') — see `forces_degrees_at`.
// ===========================================================================
static MAVIC4: &[Row] = &[
  Row { path: &[1, 1, 5], kind: K::SerialNumber },     // DJI.pm:810
  Row { path: &[1, 1, 10], kind: K::Model },           // DJI.pm:811
  Row { path: &[2, 3, 1], kind: K::FrameWidth },       // DJI.pm:814-817 FrameInfo
  Row { path: &[2, 3, 2], kind: K::FrameHeight },
  Row { path: &[2, 3, 3], kind: K::FrameRate },
  Row { path: &[3, 1, 1], kind: K::FrameNumber },      // DJI.pm:833
  Row { path: &[3, 1, 2], kind: K::TimeStamp },        // DJI.pm:818-823
  Row { path: &[3, 2, 9, 1], kind: K::Iso },           // DJI.pm:826
  Row { path: &[3, 2, 10, 1], kind: K::ShutterSpeed }, // DJI.pm:827-831
  Row { path: &[3, 2, 24, 1], kind: K::ColorTemperature }, // DJI.pm:832
  Row { path: &[3, 2, 37, 1], kind: K::Temperature },  // DJI.pm:834
  Row { path: &[3, 3, 3, 1], kind: K::DroneRoll },     // DJI.pm:835-838 DroneInfo
  Row { path: &[3, 3, 3, 2], kind: K::DronePitch },
  Row { path: &[3, 3, 3, 3], kind: K::DroneYaw },
  Row { path: &[3, 3, 4, 1, 1], kind: K::CoordinateUnits }, // DJI.pm:839-843 GPSInfo
  Row { path: &[3, 3, 4, 1, 2], kind: K::GpsLatitude },
  Row { path: &[3, 3, 4, 1, 3], kind: K::GpsLongitude },
  Row { path: &[3, 3, 4, 2], kind: K::AbsoluteAltitude }, // DJI.pm:844
  Row { path: &[3, 3, 5, 1], kind: K::RelativeAltitude }, // DJI.pm:845
];

// ===========================================================================
// dvtm_Mini5Pro — Mini 5 Pro (DJI.pm:847-859)
//   GPSInfo arm forces degrees (DJI.pm:855) — see `forces_degrees_at`.
// ===========================================================================
static MINI5PRO: &[Row] = &[
  Row { path: &[1, 1, 5], kind: K::SerialNumber },     // DJI.pm:850
  Row { path: &[1, 1, 10], kind: K::Model },           // DJI.pm:851
  Row { path: &[3, 1, 1], kind: K::FrameNumber },      // DJI.pm:868 (NC)
  Row { path: &[3, 2, 37, 1], kind: K::Temperature },  // DJI.pm:852
  Row { path: &[3, 3, 4, 1, 1], kind: K::CoordinateUnits }, // DJI.pm:853-857 GPSInfo
  Row { path: &[3, 3, 4, 1, 2], kind: K::GpsLatitude },
  Row { path: &[3, 3, 4, 1, 3], kind: K::GpsLongitude },
  Row { path: &[3, 3, 4, 2], kind: K::AbsoluteAltitude }, // DJI.pm:858
];

// ===========================================================================
// PROTOCOLS — the master dispatch table (DJI.pm:26-43 %knownProtocol order)
// ===========================================================================
static PROTOCOLS: &[Protocol] = &[
  Protocol { name: "dvtm_ac203", rows: AC203 },
  Protocol { name: "dvtm_ac204", rows: AC204 },
  Protocol { name: "dvtm_ac206", rows: AC206 },
  Protocol { name: "dvtm_AVATA2", rows: AVATA2 },
  Protocol { name: "dvtm_wm265e", rows: WM265E },
  Protocol { name: "dvtm_pm320", rows: PM320 },
  Protocol { name: "dvtm_Mini4_Pro", rows: MINI4PRO },
  Protocol { name: "dvtm_dji_neo", rows: DJI_NEO },
  Protocol { name: "dvtm_Air3", rows: AIR3 },
  Protocol { name: "dvtm_Air3s", rows: AIR3S },
  Protocol { name: "dvtm_oq101", rows: OQ101 },
  Protocol { name: "dvtm_PP-101", rows: PP101 },
  Protocol { name: "dvtm_wa345e", rows: WA345E },
  Protocol { name: "dvtm_wm261", rows: WM261 },
  Protocol { name: "dvtm_Mavic4", rows: MAVIC4 },
  Protocol { name: "dvtm_Mini5Pro", rows: MINI5PRO },
];

/// `%knownProtocol` membership (DJI.pm:26-43). The verbatim `.proto` strings
/// bundled accepts without the "Unknown protocol" warning.
const KNOWN_PROTOCOLS: &[&str] = &[
  "dvtm_ac203.proto",
  "dvtm_ac204.proto",
  "dvtm_ac206.proto",
  "dvtm_AVATA2.proto",
  "dvtm_wm265e.proto",
  "dvtm_pm320.proto",
  "dvtm_Mini4_Pro.proto",
  "dvtm_dji_neo.proto",
  "dvtm_Air3.proto",
  "dvtm_Air3s.proto",
  "dvtm_PP-101.proto",
  "dvtm_oq101.proto",
  "dvtm_wa345e.proto",
  "dvtm_wm261.proto",
  "dvtm_Mavic4.proto",
  "dvtm_Mini5Pro.proto",
];

/// `true` when `protocol` (the verbatim `.proto` string) is in
/// `%knownProtocol` (DJI.pm:26-43).
fn is_known_protocol(protocol: &str) -> bool {
  KNOWN_PROTOCOLS.contains(&protocol)
}

impl Protocol {
  /// `true` when `path` is the GPSInfo container for a protocol whose
  /// bundled arm carries `Condition => '$$self{CoordUnits} = 1'` —
  /// i.e. Mavic 4 Pro (DJI.pm:841) and Mini 5 Pro (DJI.pm:855). Both place
  /// GPSInfo at `3-3-4-1`. Returns `false` for every other protocol.
  fn forces_degrees_at(&self, path: &[u64]) -> bool {
    matches!(self.name, "dvtm_Mavic4" | "dvtm_Mini5Pro") && path == [3, 3, 4, 1]
  }
}

#[cfg(test)]
mod table_tests {
  use super::*;

  #[test]
  fn known_protocol_membership() {
    assert!(is_known_protocol("dvtm_ac203.proto"));
    assert!(is_known_protocol("dvtm_Mavic4.proto"));
    assert!(!is_known_protocol("dvtm_future.proto"));
  }

  #[test]
  fn forces_degrees_only_mavic4_mini5pro() {
    let m4 = protocol_for("dvtm_Mavic4").unwrap();
    assert!(m4.forces_degrees_at(&[3, 3, 4, 1]));
    assert!(!m4.forces_degrees_at(&[3, 3, 4, 2]));
    let wm = protocol_for("dvtm_wm265e").unwrap();
    assert!(!wm.forces_degrees_at(&[3, 3, 4, 1]));
  }

  #[test]
  fn every_known_protocol_has_a_table() {
    // Every %knownProtocol entry (except the explicitly-unknown O3
    // dvtm_wm169) must resolve to a dispatch table.
    for kp in KNOWN_PROTOCOLS {
      let name = kp.strip_suffix(".proto").unwrap();
      assert!(protocol_for(name).is_some(), "no table for {name}");
    }
  }
}
