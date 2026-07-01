//! OLE compound-document (Windows Compound Binary File) decoder for the PNG
//! `cpIp` chunk — a faithful port of `Image::ExifTool::FlashPix::ProcessFPX`
//! (`FlashPix.pm:2043`) plus the property-set reader `ProcessProperties`
//! (`FlashPix.pm:1691`) / `ReadFPXValue` (`FlashPix.pm:1282`) and the two summary
//! property tables `%FlashPix::SummaryInfo` (`FlashPix.pm:386`) +
//! `%FlashPix::DocumentInfo` (`FlashPix.pm:452`).
//!
//! `PNG.pm:354-367` routes a `cpIp` chunk ("OLE information found in PNG Plus
//! images written by Picture It!") to `ProcessFPX` on the `%FlashPix::Main`
//! table, and its `Condition` mutates `File:FileType` from `PNG` to `PNG Plus`.
//! The chunk payload is an OLE compound document (`d0cf11e0a1b11ae1` signature,
//! fixed-size sectors, a FAT, a directory tree, and a mini-FAT for small
//! streams); ExifTool wraps the in-memory `DataPt` in a RAF (`FlashPix.pm:2051`).
//! This port reads directly over the `&[u8]` chunk bytes.
//!
//! Scope: the OLE walker + the `SummaryInformation` / `DocumentSummaryInformation`
//! property sets (the two summary tables). The UserDefined dictionary, the
//! `_PID_HLINKS` hyperlinks, embedded-document `Doc<N>` grouping, and the other
//! `%FlashPix::Main` streams (`CompObj`, `Image Info`, `Current User`, …) are out
//! of scope for this chunk.
//!
//! SOUNDNESS: every sector index is bounds-checked (`buf.get`), every chain walk
//! is length-capped, the FAT/DIFAT/mini-FAT loads are byte- and cycle-bounded, and
//! `ReadFPXValue` uses saturating arithmetic — a malformed OLE must never panic,
//! read out of bounds, or loop forever (#443-class discipline).

use crate::emit::{EmitOptions, EmittedTag};
use crate::value::{Group, TagValue};
use smol_str::SmolStr;
use std::{string::String, vec::Vec};

// ---- OLE sector-type sentinels (FlashPix.pm:42-46) --------------------------
const HDR_SIZE: usize = 512;
const END_OF_CHAIN: u32 = 0xffff_fffe;
const FREE_SECT: u32 = 0xffff_ffff;

// ---- OLE format flags / codes (FlashPix.pm:49-56) ---------------------------
const VT_VECTOR: u32 = 0x1000;

// ---- Soundness caps ---------------------------------------------------------
/// Max bytes reassembled for any one FAT/mini-FAT stream chain — bounds memory
/// on a crafted OLE whose chains fan out. Larger than any realistic `cpIp`.
const MAX_CHAIN_BYTES: usize = 64 << 20;
/// Max directory entries walked (128 bytes each) — bounds a crafted huge dir.
const MAX_DIR_ENTRIES: usize = 1 << 16;
/// Max `VT_VARIANT` recursion depth in [`read_fpx_value`].
const MAX_VARIANT_DEPTH: u32 = 32;
/// Max property entries decoded from one property section. A real `SummaryInfo`
/// holds well under 50; this rejects an attacker's multi-million count before the
/// per-entry loop (CPU/alloc bound). FAR above any realistic OLE.
const MAX_PROPERTIES: usize = 1 << 16;
/// Max element count honoured for a single `VT_VECTOR` — rejects a crafted count
/// that would expand a byte range into millions of values (alloc bound). Real
/// vectors are well under 1000.
const MAX_VECTOR_ELEMS: usize = 1 << 16;
/// OLE-WIDE budget on the total property entries + values materialized across
/// EVERY summary stream in one compound document. Threaded through the whole
/// directory walk (NOT reset per stream), so a crafted directory that repeats a
/// recognized `SummaryInformation` entry cannot multiply `meta.tags` /
/// `meta.warnings` without bound (`MAX_DIR_ENTRIES * MAX_PROPERTIES` OOM). FAR
/// above any realistic OLE's total tag count — only a hostile repeated-stream
/// input trips it, so a real file stays byte-identical.
const MAX_TOTAL_EMITTED: usize = 1 << 16;

// ---- Little-endian / big-endian primitive reads (bounds-checked) ------------
#[inline]
fn get_u16(buf: &[u8], off: usize, le: bool) -> Option<u16> {
  let b: [u8; 2] = buf.get(off..off + 2)?.try_into().ok()?;
  Some(if le {
    u16::from_le_bytes(b)
  } else {
    u16::from_be_bytes(b)
  })
}

#[inline]
fn get_u32(buf: &[u8], off: usize, le: bool) -> Option<u32> {
  let b: [u8; 4] = buf.get(off..off + 4)?.try_into().ok()?;
  Some(if le {
    u32::from_le_bytes(b)
  } else {
    u32::from_be_bytes(b)
  })
}

#[inline]
fn get_u32_be(buf: &[u8], off: usize) -> Option<u32> {
  let b: [u8; 4] = buf.get(off..off + 4)?.try_into().ok()?;
  Some(u32::from_be_bytes(b))
}

#[inline]
fn get_u64(buf: &[u8], off: usize, le: bool) -> Option<u64> {
  let b: [u8; 8] = buf.get(off..off + 8)?.try_into().ok()?;
  Some(if le {
    u64::from_le_bytes(b)
  } else {
    u64::from_be_bytes(b)
  })
}

/// The decoded FlashPix metadata of a `cpIp` OLE compound document.
///
/// Encapsulated per the crate accessor convention: build with [`process`], read
/// via [`FlashPixMeta::is_empty`] / [`FlashPixMeta::warnings`] and emit tags via
/// [`FlashPixMeta::tags`]. `None`-worthy (drop when [`is_empty`](Self::is_empty))
/// so a `cpIp` whose OLE recognized nothing keeps the PNG output byte-identical.
#[derive(Debug, Clone, PartialEq)]
pub(crate) struct FlashPixMeta {
  /// Decoded property tags in walk order (family-1 `FlashPix`).
  tags: Vec<FpxTag>,
  /// `$et->Warn(...)` messages in emission order — surfaced via the PNG
  /// [`Diagnose`](crate::diagnostics::Diagnose) channel at the `cpIp` position.
  warnings: Vec<SmolStr>,
}

impl FlashPixMeta {
  const fn new() -> Self {
    Self {
      tags: Vec::new(),
      warnings: Vec::new(),
    }
  }

  /// `true` IFF nothing was decoded — no tags AND no warnings. The caller drops
  /// an empty `FlashPixMeta` so a `cpIp` whose OLE recognized nothing keeps the
  /// PNG output byte-identical (the `File:FileType` → `PNG Plus` mutation is
  /// driven separately by mere `cpIp` presence, `PNG.pm:355-361`).
  pub(crate) fn is_empty(&self) -> bool {
    self.tags.is_empty() && self.warnings.is_empty()
  }

  /// The walker warnings, in emission order.
  pub(crate) fn warnings(&self) -> &[SmolStr] {
    &self.warnings
  }

  fn warn(&mut self, msg: &str) {
    self.warnings.push(SmolStr::new(msg));
  }
}

impl crate::emit::Taggable for FlashPixMeta {
  /// Yield the decoded FlashPix property tags, in walk order, under family-0 /
  /// family-1 `FlashPix` (`%FlashPix::Main` `GROUPS`, the SummaryInfo/DocumentInfo
  /// tables inherit the module group). Values render per [`EmitOptions::mode`]
  /// ([`FpxValue::render`]); none carry `Unknown => 1`.
  fn tags(&self, opts: EmitOptions) -> impl Iterator<Item = EmittedTag> + '_ {
    let print = matches!(opts.mode, crate::emit::ConvMode::PrintConv);
    self.tags.iter().map(move |t| {
      EmittedTag::new(
        Group::new("FlashPix", "FlashPix"),
        t.name.clone(),
        t.value.render(print),
        false,
      )
    })
  }
}

/// One decoded FlashPix property.
#[derive(Debug, Clone, PartialEq)]
struct FpxTag {
  name: SmolStr,
  value: FpxValue,
}

/// A decoded property value, stored so it renders per [`ConvMode`] at emission
/// (most variants are mode-independent).
#[derive(Debug, Clone, PartialEq)]
enum FpxValue {
  /// A string (LPSTR/LPWSTR/BSTR), a date string (FILETIME/DATE > 1 year, already
  /// `ConvertUnixTime`'d), or a ValueConv result (`AppVersion`) — identical in
  /// `-j`/`-n`.
  Str(SmolStr),
  /// A signed integer scalar.
  Int(i64),
  /// A floating-point scalar (VT_R4/VT_R8, or a small FILETIME kept as seconds).
  Float(f64),
  /// An ordered list (VT_VECTOR / VT_VARIANT array).
  List(Vec<TagValue>),
  /// Raw binary byte length (VT_BLOB/VT_CF, or a `Binary => 1` tag) → placeholder.
  Binary(usize),
  /// `TotalEditTime` seconds — `-j` = `ConvertTimeSpan`, `-n` = the number.
  TimeSpan(f64),
  /// A `0`/`1` flag — `-j` = `No`/`Yes` (raw otherwise), `-n` = the number.
  YesNo(i64),
  /// A code page — `-j` = the Microsoft code-page name (raw otherwise), `-n` =
  /// the number.
  CodePage(i64),
  /// The `Security` bitmask — `-j` = `DecodeBits` (`None` for `0`), `-n` = the
  /// number.
  Security(i64),
}

impl FpxValue {
  fn render(&self, print: bool) -> TagValue {
    match self {
      FpxValue::Str(s) => TagValue::Str(s.clone()),
      FpxValue::Int(n) => TagValue::I64(*n),
      FpxValue::Float(f) => TagValue::F64(*f),
      FpxValue::List(v) => TagValue::List(v.clone()),
      FpxValue::Binary(len) => TagValue::Str(crate::value::binary_placeholder(*len as u64)),
      FpxValue::TimeSpan(secs) => {
        if print {
          TagValue::Str(SmolStr::from(convert_time_span(*secs)))
        } else {
          TagValue::F64(*secs)
        }
      }
      FpxValue::YesNo(n) => {
        if print {
          match n {
            0 => TagValue::Str(SmolStr::new("No")),
            1 => TagValue::Str(SmolStr::new("Yes")),
            _ => TagValue::I64(*n), // PrintConv fallback to the raw value
          }
        } else {
          TagValue::I64(*n)
        }
      }
      FpxValue::CodePage(n) => {
        if print {
          match code_page_name(*n) {
            Some(name) => TagValue::Str(SmolStr::new(name)),
            None => TagValue::I64(*n),
          }
        } else {
          TagValue::I64(*n)
        }
      }
      FpxValue::Security(n) => {
        if print {
          TagValue::Str(SmolStr::from(decode_security(*n)))
        } else {
          TagValue::I64(*n)
        }
      }
    }
  }
}

// ============================================================================
// OLE compound-document walker (ProcessFPX, FlashPix.pm:2043)
// ============================================================================

/// Decode a PNG `cpIp` chunk payload (an OLE compound document) into a
/// [`FlashPixMeta`] (`PNG.pm:354-367` → `ProcessFPX`). Returns the decoded meta
/// (possibly [`FlashPixMeta::is_empty`] for a payload that is not a valid OLE
/// compound document or recognized no summary streams).
#[must_use]
pub(crate) fn process(cpip: &[u8]) -> FlashPixMeta {
  let mut meta = FlashPixMeta::new();
  // `return 0 unless $raf->Read($buff,HDR_SIZE) == HDR_SIZE` + signature check
  // (FlashPix.pm:2054-2056). A short or non-OLE chunk decodes to nothing.
  let header = match cpip.get(..HDR_SIZE) {
    Some(h) => h,
    None => return meta,
  };
  if header.get(..8) != Some(&[0xd0, 0xcf, 0x11, 0xe0, 0xa1, 0xb1, 0x1a, 0xe1]) {
    return meta;
  }
  // Byte order: `SetByteOrder(substr($buff,0x1c,2) eq "\xff\xfe" ? 'MM' : 'II')`
  // (FlashPix.pm:2062). A standard OLE stores `FE FF` here ⇒ `II` (little-endian).
  let le = header.get(0x1c..0x1e) != Some(&[0xff, 0xfe]);

  // Header fields (FlashPix.pm:2068-2076). `1 << shift` is capped so a crafted
  // shift can neither overflow nor demand an absurd sector size.
  let sect_size = match shift_size(get_u16(header, 0x1e, le)) {
    Some(s) => s,
    None => return meta,
  };
  let mini_size = match shift_size(get_u16(header, 0x20, le)) {
    Some(s) => s,
    None => return meta,
  };
  let fat_count = get_u32(header, 0x2c, le).unwrap_or(0);
  let dir_start = get_u32(header, 0x30, le).unwrap_or(END_OF_CHAIN);
  let mini_cutoff = get_u32(header, 0x38, le).unwrap_or(0);
  let mini_start = get_u32(header, 0x3c, le).unwrap_or(END_OF_CHAIN);
  let dif_start = get_u32(header, 0x44, le).unwrap_or(END_OF_CHAIN);
  let dif_count = get_u32(header, 0x48, le).unwrap_or(0);

  // `$hdrSize = $sectSize > HDR_SIZE ? $sectSize : HDR_SIZE` (FlashPix.pm:2093).
  let hdr_size = sect_size.max(HDR_SIZE);

  let fat = load_fat(
    cpip, header, sect_size, hdr_size, fat_count, dif_start, dif_count, le, &mut meta,
  );
  // `LoadChain` for the mini-FAT + directory (FlashPix.pm:2139-2144). A failed
  // directory load leaves an empty meta (ExifTool `$et->Error` aborts the file).
  let mini_fat = load_chain(cpip, &fat, mini_start, sect_size, hdr_size, le);
  let dir = match load_chain(cpip, &fat, dir_start, sect_size, hdr_size, le) {
    Some(d) => d,
    None => return meta,
  };
  let mini_fat = mini_fat.unwrap_or_default();

  // ONE budget for the whole compound document — shared across every summary
  // stream so repeated stream entries cannot reset it (Finding 1).
  let mut budget = MAX_TOTAL_EMITTED;
  walk_directory(
    cpip,
    &dir,
    &fat,
    &mini_fat,
    sect_size,
    mini_size,
    hdr_size,
    mini_cutoff,
    le,
    &mut budget,
    &mut meta,
  );
  meta
}

/// `1 << shift`, rejecting a shift that would overflow or yield a size outside
/// `[64 B, 16 MiB]` (the CFBF spec mandates a mini-sector shift of 6 = 64 B and a
/// sector shift of 9 = 512 B or 12 = 4096 B; ExifTool honours any power of two,
/// and the cap keeps a crafted shift sound).
#[inline]
fn shift_size(shift: Option<u16>) -> Option<usize> {
  let shift = shift? as u32;
  if !(6..=24).contains(&shift) {
    return None;
  }
  Some(1usize << shift)
}

/// Load the FAT by walking the header DIFAT (109 entries) + the DIFAT sector
/// chain (`ProcessFPX`, FlashPix.pm:2088-2135). Every FAT-sector read is
/// bounds-checked; the DIFAT walk is `dif_count`-bounded, cycle-guarded with an
/// O(1) visited-sector bitset, and capped at the buffer's actual sector count
/// (an index past EOF is invalid) — O(n), never O(n^2) (Finding 2).
#[allow(clippy::too_many_arguments)]
fn load_fat(
  cpip: &[u8],
  header: &[u8],
  sect_size: usize,
  hdr_size: usize,
  fat_count: u32,
  mut dif_start: u32,
  dif_count: u32,
  le: bool,
  meta: &mut FlashPixMeta,
) -> Vec<u8> {
  let mut fat: Vec<u8> = Vec::new();
  if sect_size == 0 {
    return fat;
  }
  let mut fat_count_check: u32 = 0;
  let mut dif_count_check: u32 = 0;
  // O(1) visited-DIF-sector set for cycle detection, lazily sized to the
  // buffer's actual sector count. Indexing it doubles as the buffer-sector
  // bound: a DIF index at/beyond `max_sectors` cannot address in-buffer bytes
  // (an ExifTool read fails past EOF), so the walk visits each in-buffer sector
  // at most once — O(n), replacing the O(n^2) `Vec::contains` scan. 64-byte
  // sectors stay accepted (shift_size honours shift 6); this only bounds how far
  // a DIF chain may reach.
  let max_sectors = cpip.len() / sect_size;
  let mut visited_dif: Option<Vec<bool>> = None;
  // The current DIFAT buffer + scan window. Starts as the 512-byte header
  // (entries `0x4c..end`), then each DIF sector (entries `0..sectSize-4`).
  let mut difat: Vec<u8> = header.to_vec();
  let mut pos: usize = 0x4c;
  let mut end_pos: usize = difat.len();
  loop {
    while pos + 4 <= end_pos {
      let sect = get_u32(&difat, pos, le).unwrap_or(FREE_SECT);
      pos += 4;
      if sect == FREE_SECT {
        continue;
      }
      match read_sector(cpip, sect, sect_size, hdr_size) {
        Some(s) if fat.len() < MAX_CHAIN_BYTES => fat.extend_from_slice(s),
        _ => {
          // `$et->Error("Error reading FAT from sector $sect"); return 1`
          // (FlashPix.pm:2105) — abort the FAT load with what we have.
          meta.warn("Error reading FAT sector");
          return fat;
        }
      }
      fat_count_check += 1;
    }
    if dif_start >= END_OF_CHAIN {
      break;
    }
    dif_count_check += 1;
    if dif_count_check > dif_count {
      meta.warn("Unterminated DIF FAT");
      break;
    }
    // O(1) visited check + buffer-sector bound: `get_mut` returns `None` for an
    // index at/beyond the buffer's sector count (invalid — the read fails past
    // EOF) and `Some(true)` for an already-visited sector (a cycle).
    let visited = visited_dif.get_or_insert_with(|| std::vec![false; max_sectors]);
    match visited.get_mut(dif_start as usize) {
      Some(seen) if !*seen => *seen = true,
      Some(_) => {
        meta.warn("Cyclical reference in DIF FAT");
        break;
      }
      None => {
        meta.warn("Error reading DIF sector");
        break;
      }
    }
    let next = match read_sector(cpip, dif_start, sect_size, hdr_size) {
      Some(s) => s.to_vec(),
      None => {
        meta.warn("Error reading DIF sector");
        break;
      }
    };
    difat = next;
    pos = 0;
    end_pos = sect_size.saturating_sub(4);
    dif_start = get_u32(&difat, end_pos, le).unwrap_or(END_OF_CHAIN);
  }
  if fat_count_check != fat_count {
    meta.warn("Bad number of FAT sectors");
  }
  fat
}

/// Read one `sect_size`-byte sector at `sect * sect_size + hdr_size` (the main
/// FAT addressing). Returns `None` on any out-of-range sector (bounds-safe).
#[inline]
fn read_sector(cpip: &[u8], sect: u32, sect_size: usize, hdr_size: usize) -> Option<&[u8]> {
  let off = (sect as usize)
    .checked_mul(sect_size)?
    .checked_add(hdr_size)?;
  cpip.get(off..off.checked_add(sect_size)?)
}

/// Follow a sector chain through `fat` (or a mini-FAT), reassembling the stream
/// bytes (`LoadChain`, FlashPix.pm:1820-1839). `hdr_size == 0` reads from a
/// mini-stream buffer, `hdr_size == sect_size.max(512)` from the main file.
/// Cycle-guarded (a visited sector aborts) and byte-capped. `None` = read error.
fn load_chain(
  source: &[u8],
  fat: &[u8],
  start: u32,
  sect_size: usize,
  hdr_size: usize,
  le: bool,
) -> Option<Vec<u8>> {
  if sect_size == 0 {
    return None;
  }
  let mut chain: Vec<u8> = Vec::new();
  let mut sect = start;
  // A valid chain visits distinct sectors, so it cannot be longer than the
  // source holds; the `+2` slack lets a cycle trip the cap instead of looping.
  let max_iters = source.len() / sect_size + 2;
  for _ in 0..max_iters {
    if sect >= END_OF_CHAIN {
      return Some(chain);
    }
    let off = (sect as usize)
      .checked_mul(sect_size)?
      .checked_add(hdr_size)?;
    let s = source.get(off..off.checked_add(sect_size)?)?;
    if chain.len() >= MAX_CHAIN_BYTES {
      return None;
    }
    chain.extend_from_slice(s);
    // `return undef if $sect * 4 > length($$fatPt) - 4` (FlashPix.pm:1836).
    let fat_off = (sect as usize).checked_mul(4)?;
    if fat_off + 4 > fat.len() {
      return Some(chain);
    }
    sect = get_u32(fat, fat_off, le)?;
  }
  None // exceeded the sector bound ⇒ cyclic/malformed chain
}

/// Walk the directory (`ProcessFPX`, FlashPix.pm:2167-2328). Loads the mini-stream
/// from the first (Root) entry, then dispatches the `SummaryInformation` /
/// `DocumentSummaryInformation` streams to [`process_properties`]. The
/// object-hierarchy `Doc<N>` grouping (embedded documents) is out of scope: the
/// two summary streams sit at the root level and always emit as Main tags.
#[allow(clippy::too_many_arguments)]
fn walk_directory(
  cpip: &[u8],
  dir: &[u8],
  fat: &[u8],
  mini_fat: &[u8],
  sect_size: usize,
  mini_size: usize,
  hdr_size: usize,
  mini_cutoff: u32,
  le: bool,
  budget: &mut usize,
  meta: &mut FlashPixMeta,
) {
  let mut mini_stream: Option<Vec<u8>> = None;
  let mut index = 0usize;
  let mut pos = 0usize;
  while pos + 128 <= dir.len() && index < MAX_DIR_ENTRIES {
    let Some(entry) = dir.get(pos..pos + 128) else {
      break;
    };
    let etype = entry.get(0x42).copied().unwrap_or(0);
    // `next if $type == 0` (invalid); `type > 5` ⇒ rest is garbage, stop.
    if etype == 0 {
      pos += 128;
      index += 1;
      continue;
    }
    if etype > 5 {
      meta.warn("Invalid directory entry type");
      break;
    }
    let sect = get_u32(entry, 0x74, le).unwrap_or(FREE_SECT);
    let size = get_u32(entry, 0x78, le).unwrap_or(0);

    // Load the mini-stream from the FIRST entry (Root), FlashPix.pm:2192-2199,
    // truncated to the Root entry's declared size so mini-FAT reads cannot reach
    // main-sector padding beyond the real mini-stream content.
    if mini_stream.is_none() {
      let mut ms = load_chain(cpip, fat, sect, sect_size, hdr_size, le).unwrap_or_default();
      ms.truncate(size as usize);
      mini_stream = Some(ms);
    }

    if let Some(table) = stream_table(entry) {
      // STREAM type only (2). Load the stream bytes from the main FAT (size >=
      // cutoff) or the mini-FAT (FlashPix.pm:2235-2244).
      if etype == 2 {
        let buff = if size >= mini_cutoff {
          load_chain(cpip, fat, sect, sect_size, hdr_size, le)
        } else if size != 0 {
          let ms = mini_stream.as_deref().unwrap_or(&[]);
          load_chain(ms, mini_fat, sect, mini_size, 0, le)
        } else {
          Some(Vec::new())
        };
        match buff {
          Some(mut buff) => {
            // `LoadChain` returns whole sectors; ExifTool bounds a stream to its
            // declared directory-entry size (FlashPix.pm:2288-2291). Truncate to
            // `size` so a property set cannot be decoded out of sector padding
            // (`truncate` is a no-op when the chain is shorter — read what's
            // available, matching ExifTool's `substr($buff, 0, $size)`).
            buff.truncate(size as usize);
            if !buff.is_empty() {
              process_properties(&buff, table, le, budget, meta);
            }
          }
          None => meta.warn("Error reading stream"),
        }
        // The OLE-wide budget is exhausted (a crafted directory repeating a
        // recognized stream) — stop decoding further streams so `meta.tags`
        // stays bounded regardless of how many entries repeat (Finding 1).
        if *budget == 0 {
          meta.warn("FPX property budget exhausted");
          break;
        }
      }
    }
    pos += 128;
    index += 1;
  }
}

/// Which summary property table a directory entry's stream name selects, or
/// `None` for every other stream (`%FlashPix::Main`, FlashPix.pm:171-183 — only
/// the two summary streams are in scope). The name is UTF-16LE, capped at 32
/// code units and truncated at the first NUL (FlashPix.pm:2180-2183).
fn stream_table(entry: &[u8]) -> Option<Table> {
  let name = entry_name(entry);
  if name == "\u{5}SummaryInformation" {
    Some(Table::SummaryInfo)
  } else if name == "\u{5}DocumentSummaryInformation" {
    Some(Table::DocumentInfo)
  } else {
    None
  }
}

/// Decode a directory entry's UTF-16LE name (`FlashPix.pm:2180-2183`). ExifTool
/// treats the `0x40` length as a code-unit count, caps it at 32, reads that many
/// UTF-16LE units, and truncates at the first NUL.
fn entry_name(entry: &[u8]) -> String {
  let mut len = get_u16(entry, 0x40, true).unwrap_or(0) as usize;
  if len > 32 {
    len = 32;
  }
  let mut s = String::new();
  for i in 0..len {
    let Some(u) = get_u16(entry, i * 2, true) else {
      break;
    };
    if u == 0 {
      break; // truncate at NUL
    }
    s.push(char::from_u32(u32::from(u)).unwrap_or('\u{fffd}'));
  }
  s
}

// ============================================================================
// Property-set reader (ProcessProperties, FlashPix.pm:1691)
// ============================================================================

/// Which summary property table a stream dispatches to.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Table {
  SummaryInfo,
  DocumentInfo,
}

/// Process an OLE property set (`ProcessProperties`, FlashPix.pm:1691). Reads the
/// property-set header + its FIRST (predefined) section and emits the recognized
/// `SummaryInfo` / `DocumentInfo` tags.
///
/// The second (UserDefined) section of `DocumentSummaryInformation` (reached via
/// the `Multi` flag, FlashPix.pm:1810) is deferred: its property IDs are named by
/// an in-stream dictionary (PID 0, FlashPix.pm:1738-1760) that this port does not
/// decode, so continuing through `%DocumentInfo` would MISATTRIBUTE a custom PID
/// (e.g. 2 → "Category"). We therefore stop after the predefined section rather
/// than misname the UserDefined properties.
fn process_properties(
  data: &[u8],
  table: Table,
  ole_le: bool,
  budget: &mut usize,
  meta: &mut FlashPixMeta,
) {
  let dir_end = data.len();
  if dir_end < 48 {
    meta.warn("Truncated FPX properties");
    return;
  }
  // `CheckBOM` (FlashPix.pm:1677) — may toggle the byte order for this set.
  let le = match get_u16(data, 0, ole_le) {
    Some(0xfffe) => ole_le,
    Some(0xfeff) => !ole_le,
    _ => {
      meta.warn("Bad FPX property byte order mark");
      return;
    }
  };
  // Start of the first section (offset at byte 44, FlashPix.pm:1711).
  let pos = get_u32(data, 44, le).unwrap_or(0) as usize;
  if pos < 48 {
    meta.warn("Bad FPX property section offset");
    return;
  }
  if pos + 8 > dir_end {
    return;
  }
  let size = get_u32(data, pos, le).unwrap_or(0) as usize;
  if size == 0 {
    return;
  }
  // The property list + every value offset belong to THIS section; clamp all
  // bounds to the declared section end so a hostile first-section offset cannot
  // reach into a following (UserDefined) section's bytes and emit as a
  // predefined tag (Finding 3). `min` also caps an over-declared section at the
  // buffer end (an ExifTool read fails past EOF). A well-formed single-section
  // stream has `section_end == dir_end`, so the real fixture is byte-identical.
  let section_end = dir_end.min(pos.saturating_add(size));
  let num_entries = get_u32(data, pos + 4, le).unwrap_or(0) as usize;
  // Hard cap: a real property section holds well under 50 entries. Reject an
  // attacker's multi-million count before the per-entry loop.
  if num_entries > MAX_PROPERTIES {
    meta.warn("Excessive FPX property count");
    return;
  }
  if pos + 8 + 8usize.saturating_mul(num_entries) > section_end {
    meta.warn("Truncated property list");
    return;
  }
  let mut code_page: Option<i64> = None;
  let mut truncated = false;
  for index in 0..num_entries {
    // Charge the OLE-wide budget per property entry so a repeated stream (or a
    // huge entry count) cannot spin `meta.tags` / `meta.warnings` without bound;
    // when exhausted the caller halts the whole walk (Finding 1).
    if *budget == 0 {
      break;
    }
    *budget -= 1;
    let entry = pos + 8 + 8 * index;
    let tag = get_u32(data, entry, le).unwrap_or(0);
    let offset = get_u32(data, entry + 4, le).unwrap_or(0) as usize;
    let val_start = pos + 4 + offset;
    if val_start >= section_end {
      truncated = true;
      break;
    }
    let ty = get_u32(data, pos + offset, le).unwrap_or(0);
    if tag == 0 {
      // Dictionary (UserDefined name lookup) — out of scope; skip it.
      continue;
    }
    let (value, _next) = read_fpx_value(
      data,
      val_start,
      ty,
      section_end,
      false,
      code_page,
      le,
      0,
      budget,
    );
    let Some(raw) = value else {
      meta.warn("Error reading property value");
      continue;
    };
    // Common IDs (CodePage / LocaleIndicator) resolve against SummaryInfo
    // regardless of the current table (FlashPix.pm:1777-1784).
    let def = if tag == 1 || tag == 0x8000_0000 {
      summary_info(tag)
    } else {
      match table {
        Table::SummaryInfo => summary_info(tag),
        Table::DocumentInfo => document_info(tag),
      }
    };
    if tag == 1 {
      // CodePage may be stored as int16s; normalise negatives + save it.
      if let FpxRaw::Int(mut n) = raw {
        if n < 0 {
          n += 0x1_0000;
        }
        code_page = Some(n);
      }
    }
    if let Some(def) = def {
      meta.tags.push(FpxTag {
        name: SmolStr::new(def.name),
        value: apply_conv(def.conv, raw),
      });
    }
  }
  if truncated {
    meta.warn("Truncated property data");
  }
}

/// Read one property value (`ReadFPXValue`, FlashPix.pm:1282). Returns the decoded
/// value (or `None` on an unsupported/failed read) and the updated value position.
/// Faithful for the scalar/string/date types; `VT_VECTOR`/`VT_VARIANT` are read
/// soundly into a [`FpxRaw::List`]. All arithmetic saturates against `dir_end`.
#[allow(clippy::too_many_arguments)]
fn read_fpx_value(
  data: &[u8],
  mut val_pos: usize,
  ty: u32,
  dir_end: usize,
  mut no_pad: bool,
  code_page: Option<i64>,
  le: bool,
  depth: u32,
  budget: &mut usize,
) -> (Option<FpxRaw>, usize) {
  if depth > MAX_VARIANT_DEPTH {
    return (None, val_pos);
  }
  let format = ty & 0x0fff;
  if numeric_format(format).is_none() && !is_special_format(format) {
    // Unsupported format code ⇒ no value (VT_EMPTY/VT_NULL push '').
    return (
      if format == 0 || format == 1 {
        Some(FpxRaw::Str(SmolStr::default()))
      } else {
        None
      },
      val_pos,
    );
  }

  // Handle the VT_VECTOR flag (a leading int32u element count).
  let flags = ty & 0xf000;
  let mut count: usize = 1;
  if flags != 0 {
    if flags == VT_VECTOR {
      no_pad = true;
      if val_pos + 4 > dir_end {
        return (None, val_pos);
      }
      count = get_u32(data, val_pos, le).unwrap_or(0) as usize;
      val_pos += 4;
      if count == 0 {
        return (Some(FpxRaw::Str(SmolStr::default())), val_pos);
      }
      // Reject a crafted count that would expand into millions of values before
      // any allocation (even when the byte range would fit a large stream).
      if count > MAX_VECTOR_ELEMS {
        return (None, val_pos);
      }
    } else {
      return (None, val_pos); // unsupported flag (VT_ARRAY/VT_BYREF)
    }
  }

  // Numeric (non-VT_) formats — read `count` values, faithful padded advance.
  if let Some((size_per, kind)) = numeric_format(format) {
    let size = size_per.saturating_mul(count);
    if val_pos + size > dir_end {
      return (None, val_pos);
    }
    let mut vals: Vec<FpxRaw> = Vec::new();
    for i in 0..count {
      if *budget == 0 {
        break;
      }
      if let Some(v) = read_numeric(data, val_pos + i * size_per, kind, le) {
        *budget -= 1;
        vals.push(v);
      }
    }
    val_pos = val_pos.saturating_add((count.saturating_mul(size).saturating_add(3)) & !3usize);
    return (collapse(vals), val_pos);
  }

  // Special VT_ types (string/date/blob/variant/…) — per-item loop. Each reader
  // returns the value AND the updated `val_pos` (matching ExifTool's `$_[2] =
  // $valPos`), plus, for strings, the byte length used for vector-pad tracking.
  let mut vals: Vec<FpxRaw> = Vec::new();
  let mut prev_len: Option<usize> = None;
  for _item in 0..count {
    if *budget == 0 {
      break;
    }
    // VT_VECTOR items are sometimes padded to a 4-byte boundary (and sometimes
    // not) — skip an all-zero pad after a mis-aligned previous string
    // (FlashPix.pm:1327-1334).
    if let Some(pl) = prev_len.filter(|pl| no_pad && pl & 0x3 != 0) {
      let pad = 4 - (pl & 0x3);
      if val_pos + pad <= dir_end
        && data
          .get(val_pos..val_pos + pad)
          .is_some_and(|s| s.iter().all(|&b| b == 0))
      {
        val_pos += pad;
      }
    }
    prev_len = None;
    let (v, new_pos, consumed_len) = match format {
      12 => {
        // VT_VARIANT: a 4-byte sub-type then a recursive value.
        if val_pos + 4 > dir_end {
          break;
        }
        let sub_ty = get_u32(data, val_pos, le).unwrap_or(0);
        val_pos += 4;
        let (sv, np) = read_fpx_value(
          data,
          val_pos,
          sub_ty,
          dir_end,
          no_pad,
          code_page,
          le,
          depth + 1,
          budget,
        );
        val_pos = np;
        match sv {
          Some(v) => {
            *budget = budget.saturating_sub(1);
            vals.push(v);
            continue; // VT_VARIANT does not add `size` again
          }
          None => break,
        }
      }
      64 => read_filetime(data, val_pos, dir_end, le),
      7 => read_vt_date(data, val_pos, dir_end, le),
      8 | 30 | 31 => read_string(data, val_pos, format, dir_end, no_pad, code_page, le),
      65 | 71 => read_blob(data, val_pos, dir_end, le),
      72 => read_clsid(data, val_pos, dir_end),
      _ => break,
    };
    match v {
      Some(v) => {
        *budget -= 1;
        vals.push(v);
      }
      None => break,
    }
    val_pos = new_pos;
    prev_len = consumed_len;
  }
  (collapse(vals), val_pos)
}

/// Collapse a value list to a scalar when it holds exactly one element.
fn collapse(mut vals: Vec<FpxRaw>) -> Option<FpxRaw> {
  match vals.len() {
    0 => None,
    1 => Some(vals.pop().unwrap()),
    _ => Some(FpxRaw::List(
      vals.iter().map(FpxRaw::to_tag_value).collect(),
    )),
  }
}

/// A raw decoded property value before table-conv is applied.
#[derive(Debug, Clone)]
enum FpxRaw {
  Str(SmolStr),
  Int(i64),
  Float(f64),
  List(Vec<TagValue>),
  Binary(usize),
}

impl FpxRaw {
  fn to_tag_value(&self) -> TagValue {
    match self {
      FpxRaw::Str(s) => TagValue::Str(s.clone()),
      FpxRaw::Int(n) => TagValue::I64(*n),
      FpxRaw::Float(f) => TagValue::F64(*f),
      FpxRaw::List(v) => TagValue::List(v.clone()),
      FpxRaw::Binary(len) => TagValue::Str(crate::value::binary_placeholder(*len as u64)),
    }
  }
}

/// The numeric base format for a VT code: `(byte size, kind)` or `None` for the
/// special (string/date/blob/variant) types (`%oleFormat`, FlashPix.pm:59-99).
fn numeric_format(code: u32) -> Option<(usize, NumKind)> {
  Some(match code {
    2 | 11 => (2, NumKind::I16), // VT_I2 / VT_BOOL (int16s)
    3 | 10 => (4, NumKind::I32), // VT_I4 / VT_ERROR (int32s)
    4 => (4, NumKind::F32),      // VT_R4
    5 => (8, NumKind::F64),      // VT_R8
    16 => (1, NumKind::I8),      // VT_I1
    17 => (1, NumKind::U8),      // VT_UI1
    18 => (2, NumKind::U16),     // VT_UI2
    19 => (4, NumKind::U32),     // VT_UI4
    20 => (8, NumKind::I64),     // VT_I8
    21 => (8, NumKind::U64),     // VT_UI8
    _ => return None,
  })
}

fn is_special_format(code: u32) -> bool {
  matches!(code, 7 | 8 | 12 | 30 | 31 | 64 | 65 | 71 | 72)
}

#[derive(Debug, Clone, Copy)]
enum NumKind {
  I8,
  U8,
  I16,
  U16,
  I32,
  U32,
  I64,
  U64,
  F32,
  F64,
}

fn read_numeric(data: &[u8], pos: usize, kind: NumKind, le: bool) -> Option<FpxRaw> {
  Some(match kind {
    NumKind::I8 => FpxRaw::Int(i64::from(*data.get(pos)? as i8)),
    NumKind::U8 => FpxRaw::Int(i64::from(*data.get(pos)?)),
    NumKind::I16 => FpxRaw::Int(i64::from(get_u16(data, pos, le)? as i16)),
    NumKind::U16 => FpxRaw::Int(i64::from(get_u16(data, pos, le)?)),
    NumKind::I32 => FpxRaw::Int(i64::from(get_u32(data, pos, le)? as i32)),
    NumKind::U32 => FpxRaw::Int(i64::from(get_u32(data, pos, le)?)),
    NumKind::I64 => FpxRaw::Int(get_u64(data, pos, le)? as i64),
    NumKind::U64 => FpxRaw::Int(get_u64(data, pos, le)? as i64),
    NumKind::F32 => {
      let b: [u8; 4] = data.get(pos..pos + 4)?.try_into().ok()?;
      FpxRaw::Float(f64::from(if le {
        f32::from_le_bytes(b)
      } else {
        f32::from_be_bytes(b)
      }))
    }
    NumKind::F64 => {
      let b: [u8; 8] = data.get(pos..pos + 8)?.try_into().ok()?;
      FpxRaw::Float(if le {
        f64::from_le_bytes(b)
      } else {
        f64::from_be_bytes(b)
      })
    }
  })
}

/// VT_FILETIME (FlashPix.pm:1343-1366): 100-ns increments since 1601-01-01. A
/// value under one year stays a raw second count (a time span, e.g.
/// `TotalEditTime`); a larger value shifts to the Unix epoch (with ExifTool's
/// byte-swap-correction hack) and renders as a date string. Advances `pos` by 8.
fn read_filetime(
  data: &[u8],
  pos: usize,
  dir_end: usize,
  le: bool,
) -> (Option<FpxRaw>, usize, Option<usize>) {
  if pos + 8 > dir_end {
    return (None, pos, None);
  }
  let Some(raw) = get_u64(data, pos, le) else {
    return (None, pos, None);
  };
  let mut val = 1e-7 * (raw as f64);
  let sec_day = 24.0 * 3600.0;
  let value = if val > 365.0 * sec_day {
    let unix_zero = 134774.0 * sec_day; // 1601 → 1970
    val -= unix_zero;
    let sec_100yr = 100.0 * 365.0 * sec_day;
    if val < 0.0 || val > sec_100yr {
      // Some software writes the wrong byte order but proper word order: read
      // two big-endian words (`unpack "NN"`, FlashPix.pm:1356).
      if let (Some(w0), Some(w1)) = (get_u32_be(data, pos), get_u32_be(data, pos + 4)) {
        let v2 = (f64::from(w0) + f64::from(w1) * 4_294_967_296.0) * 1e-7 - unix_zero;
        if v2 > 0.0 && v2 < sec_100yr {
          val = v2;
        } else if val < 0.0 && val + unix_zero > 0.0 {
          val += unix_zero;
        }
      }
    }
    FpxRaw::Str(SmolStr::from(crate::datetime::convert_unix_time_f64(val)))
  } else {
    FpxRaw::Float(val)
  };
  (Some(value), pos + 8, None)
}

/// VT_DATE (FlashPix.pm:1367-1371): a double = days since 1899-12-30. Advances 8.
fn read_vt_date(
  data: &[u8],
  pos: usize,
  dir_end: usize,
  le: bool,
) -> (Option<FpxRaw>, usize, Option<usize>) {
  if pos + 8 > dir_end {
    return (None, pos, None);
  }
  let b: Option<[u8; 8]> = data.get(pos..pos + 8).and_then(|s| s.try_into().ok());
  let Some(b) = b else {
    return (None, pos, None);
  };
  let mut val = if le {
    f64::from_le_bytes(b)
  } else {
    f64::from_be_bytes(b)
  };
  if val != 0.0 {
    val = (val - 25569.0) * 24.0 * 3600.0;
  }
  (
    Some(FpxRaw::Str(SmolStr::from(
      crate::datetime::convert_unix_time_f64(val),
    ))),
    pos + 8,
    None,
  )
}

/// VT_BSTR / VT_LPSTR / VT_LPWSTR (FlashPix.pm:1372-1395): an int32u count then
/// the string bytes. Advances `pos` by the count field (4) plus the string byte
/// length (padded to 4 unless `no_pad`); returns the string byte length as the
/// vector-padding hint.
fn read_string(
  data: &[u8],
  pos: usize,
  format: u32,
  dir_end: usize,
  no_pad: bool,
  code_page: Option<i64>,
  le: bool,
) -> (Option<FpxRaw>, usize, Option<usize>) {
  let Some(count) = get_u32(data, pos, le) else {
    return (None, pos, None);
  };
  let mut len = count as usize;
  if format == 31 {
    len = len.saturating_mul(2); // VT_LPWSTR: word count → byte count
  }
  if pos.saturating_add(len).saturating_add(4) > dir_end {
    return (None, pos, None);
  }
  let Some(bytes) = data.get(pos + 4..pos + 4 + len) else {
    return (None, pos, None);
  };
  let s = if format == 31 {
    decode_utf16le(bytes)
  } else {
    decode_codepage(bytes, code_page)
  };
  // Truncate at the first NUL (FlashPix.pm:1391).
  let s = match s.find('\0') {
    Some(i) => SmolStr::new(&s[..i]),
    None => SmolStr::from(s),
  };
  let advance = if no_pad { len } else { (len + 3) & !3usize };
  let new_pos = pos.saturating_add(advance).saturating_add(4);
  (Some(FpxRaw::Str(s)), new_pos, Some(len))
}

/// VT_BLOB / VT_CF (FlashPix.pm:1396-1405): an int32u length then binary data,
/// always padded to 4 bytes; advances `pos` by the padded length plus the count
/// field (4).
fn read_blob(
  data: &[u8],
  pos: usize,
  dir_end: usize,
  le: bool,
) -> (Option<FpxRaw>, usize, Option<usize>) {
  let Some(count) = get_u32(data, pos, le) else {
    return (None, pos, None);
  };
  let len = count as usize;
  if pos.saturating_add(len).saturating_add(4) > dir_end {
    return (None, pos, None);
  }
  let new_pos = pos.saturating_add((len + 3) & !3usize).saturating_add(4);
  (Some(FpxRaw::Binary(len)), new_pos, None)
}

/// VT_CLSID (FlashPix.pm:1406-1407): a 16-byte GUID → the ASF GUID string form;
/// advances `pos` by 16.
fn read_clsid(data: &[u8], pos: usize, dir_end: usize) -> (Option<FpxRaw>, usize, Option<usize>) {
  if pos + 16 > dir_end {
    return (None, pos, None);
  }
  let arr: [u8; 16] = match data.get(pos..pos + 16).and_then(|s| s.try_into().ok()) {
    Some(a) => a,
    None => return (None, pos, None),
  };
  // ASF::GetGUID: first three groups little-endian, last two big-endian.
  let [
    b0,
    b1,
    b2,
    b3,
    b4,
    b5,
    b6,
    b7,
    b8,
    b9,
    ba,
    bb,
    bc,
    bd,
    be,
    bf,
  ] = arr;
  let guid = std::format!(
    "{b3:02X}{b2:02X}{b1:02X}{b0:02X}-{b5:02X}{b4:02X}-{b7:02X}{b6:02X}-\
     {b8:02X}{b9:02X}-{ba:02X}{bb:02X}{bc:02X}{bd:02X}{be:02X}{bf:02X}"
  );
  (Some(FpxRaw::Str(SmolStr::from(guid))), pos + 16, None)
}

/// Apply a table conversion descriptor to a raw value.
fn apply_conv(conv: Conv, raw: FpxRaw) -> FpxValue {
  match conv {
    Conv::None => raw_to_value(raw),
    Conv::TimeSpan => match raw {
      FpxRaw::Float(f) => FpxValue::TimeSpan(f),
      FpxRaw::Int(n) => FpxValue::TimeSpan(n as f64),
      other => raw_to_value(other),
    },
    Conv::YesNo => match raw {
      FpxRaw::Int(n) => FpxValue::YesNo(n),
      other => raw_to_value(other),
    },
    Conv::CodePage => match raw {
      FpxRaw::Int(n) => FpxValue::CodePage(n),
      other => raw_to_value(other),
    },
    Conv::Security => match raw {
      FpxRaw::Int(n) => FpxValue::Security(n),
      other => raw_to_value(other),
    },
    Conv::AppVersion => match raw {
      FpxRaw::Int(n) => FpxValue::Str(SmolStr::from(std::format!(
        "{}.{:04}",
        (n as u32) >> 16,
        (n as u32) & 0xffff
      ))),
      other => raw_to_value(other),
    },
  }
}

fn raw_to_value(raw: FpxRaw) -> FpxValue {
  match raw {
    FpxRaw::Str(s) => FpxValue::Str(s),
    FpxRaw::Int(n) => FpxValue::Int(n),
    FpxRaw::Float(f) => FpxValue::Float(f),
    FpxRaw::List(v) => FpxValue::List(v),
    FpxRaw::Binary(len) => FpxValue::Binary(len),
  }
}

// ============================================================================
// %FlashPix::SummaryInfo (FlashPix.pm:386) + %FlashPix::DocumentInfo (:452)
// ============================================================================

/// A property-table entry: the tag Name + its conversion descriptor.
struct FpxDef {
  name: &'static str,
  conv: Conv,
}

/// The subset of ExifTool conversions the two summary tables use.
#[derive(Debug, Clone, Copy)]
enum Conv {
  /// No conversion (plain string/int/float, or a date already rendered by
  /// FILETIME/DATE — the `CreateDate`/`ModifyDate` `ConvertDateTime` PrintConv is
  /// identity on an already-`ConvertUnixTime`'d value in both `-j` and `-n`).
  None,
  /// `TotalEditTime` seconds → `ConvertTimeSpan` (PrintConv).
  TimeSpan,
  /// `0`/`1` → `No`/`Yes` (PrintConv).
  YesNo,
  /// A Microsoft code page → its name (PrintConv, `SeparateTable`).
  CodePage,
  /// `Security` bitmask (PrintConv `DecodeBits` + `0 => None`).
  Security,
  /// `AppVersion` `sprintf("%d.%.4d", $val>>16, $val&0xffff)` (ValueConv).
  AppVersion,
}

const fn def(name: &'static str, conv: Conv) -> FpxDef {
  FpxDef { name, conv }
}

fn summary_info(tag: u32) -> Option<FpxDef> {
  Some(match tag {
    0x01 => def("CodePage", Conv::CodePage),
    0x02 => def("Title", Conv::None),
    0x03 => def("Subject", Conv::None),
    0x04 => def("Author", Conv::None),
    0x05 => def("Keywords", Conv::None),
    0x06 => def("Comments", Conv::None),
    0x07 => def("Template", Conv::None),
    0x08 => def("LastModifiedBy", Conv::None),
    0x09 => def("RevisionNumber", Conv::None),
    0x0a => def("TotalEditTime", Conv::TimeSpan),
    0x0b => def("LastPrinted", Conv::None),
    0x0c => def("CreateDate", Conv::None),
    0x0d => def("ModifyDate", Conv::None),
    0x0e => def("Pages", Conv::None),
    0x0f => def("Words", Conv::None),
    0x10 => def("Characters", Conv::None),
    0x11 => def("ThumbnailClip", Conv::None), // Binary => 1 (read as VT_BLOB/CF)
    0x12 => def("Software", Conv::None),
    0x13 => def("Security", Conv::Security),
    0x22 => def("CreatedBy", Conv::None),
    0x23 => def("DocumentID", Conv::None),
    0x8000_0000 => def("LocaleIndicator", Conv::None),
    _ => return None,
  })
}

fn document_info(tag: u32) -> Option<FpxDef> {
  Some(match tag {
    0x02 => def("Category", Conv::None),
    0x03 => def("PresentationTarget", Conv::None),
    0x04 => def("Bytes", Conv::None),
    0x05 => def("Lines", Conv::None),
    0x06 => def("Paragraphs", Conv::None),
    0x07 => def("Slides", Conv::None),
    0x08 => def("Notes", Conv::None),
    0x09 => def("HiddenSlides", Conv::None),
    0x0a => def("MMClips", Conv::None),
    0x0b => def("ScaleCrop", Conv::YesNo),
    0x0c => def("HeadingPairs", Conv::None),
    0x0d => def("TitleOfParts", Conv::None),
    0x0e => def("Manager", Conv::None),
    0x0f => def("Company", Conv::None),
    0x10 => def("LinksUpToDate", Conv::YesNo),
    0x11 => def("CharCountWithSpaces", Conv::None),
    0x13 => def("SharedDoc", Conv::YesNo),
    0x16 => def("HyperlinksChanged", Conv::YesNo),
    0x17 => def("AppVersion", Conv::AppVersion),
    0x1a => def("ContentType", Conv::None),
    0x1b => def("ContentStatus", Conv::None),
    0x1c => def("Language", Conv::None),
    0x1d => def("DocVersion", Conv::None),
    _ => return None,
  })
}

// ---- PrintConv / ValueConv helpers ------------------------------------------

/// `ConvertTimeSpan($val)` (ExifTool.pm:6699, no multiplier) — a bare second
/// count rendered as seconds/minutes/hours/days.
fn convert_time_span(val: f64) -> String {
  if !val.is_finite() || val == 0.0 {
    return std::format!("{val}");
  }
  if val < 60.0 {
    std::format!("{val} seconds")
  } else if val < 3600.0 {
    std::format!("{:.1} minutes", val / 60.0)
  } else if val < 24.0 * 3600.0 {
    std::format!("{:.1} hours", val / 3600.0)
  } else {
    std::format!("{:.1} days", val / (24.0 * 3600.0))
  }
}

/// The `Security` bitmask PrintConv (FlashPix.pm:435-443): `0 => None`, else
/// `DecodeBits` over bits 0-3 ([[exifast-bitmask-decodebits]]).
fn decode_security(n: i64) -> String {
  if n == 0 {
    return String::from("None");
  }
  const LABELS: [&str; 4] = [
    "Password protected",
    "Read-only recommended",
    "Read-only enforced",
    "Locked for annotations",
  ];
  let mut parts: Vec<String> = Vec::new();
  for bit in 0..32u32 {
    if n & (1i64 << bit) != 0 {
      match LABELS.get(bit as usize) {
        Some(label) => parts.push(String::from(*label)),
        None => parts.push(std::format!("[{bit}]")),
      }
    }
  }
  if parts.is_empty() {
    String::from("(none)")
  } else {
    parts.join(", ")
  }
}

/// A realistic subset of the Microsoft `%codePage` PrintConv (Microsoft.pm:28) —
/// the code pages found in Office / FlashPix documents. An unmapped value renders
/// as the raw number (ExifTool PrintConv fallback), so this stays sound + faithful
/// for the common cases without transcribing all 152 entries.
fn code_page_name(n: i64) -> Option<&'static str> {
  Some(match n {
    437 => "DOS United States",
    850 => "DOS Latin 1 (Western European)",
    852 => "DOS Latin 2 (Central European)",
    866 => "DOS Russian (Cyrillic)",
    874 => "Windows Thai (same as 28605, ISO 8859-15)",
    932 => "Windows Japanese (Shift-JIS)",
    936 => "Windows Simplified Chinese (PRC, Singapore)",
    949 => "Windows Korean (Unified Hangul Code)",
    950 => "Windows Traditional Chinese (Taiwan)",
    1200 => "Unicode UTF-16, little endian",
    1201 => "Unicode UTF-16, big endian",
    1250 => "Windows Latin 2 (Central European)",
    1251 => "Windows Cyrillic",
    1252 => "Windows Latin 1 (Western European)",
    1253 => "Windows Greek",
    1254 => "Windows Turkish",
    1255 => "Windows Hebrew",
    1256 => "Windows Arabic",
    1257 => "Windows Baltic",
    1258 => "Windows Vietnamese",
    10000 => "Mac Roman (Western European)",
    65000 => "Unicode (UTF-7)",
    65001 => "Unicode (UTF-8)",
    _ => return None,
  })
}

// ---- Charset decoding (bounded, ASCII-faithful) -----------------------------

/// Decode UTF-16LE bytes lossily (`$et->Decode($val, 'UTF16')`, the VT_LPWSTR /
/// `code page 1200` path). An odd trailing byte is dropped.
fn decode_utf16le(bytes: &[u8]) -> String {
  let units: Vec<u16> = bytes
    .chunks_exact(2)
    .filter_map(|c| c.try_into().ok().map(u16::from_le_bytes))
    .collect();
  String::from_utf16_lossy(&units)
}

/// Decode a code-page string (`ProcessProperties`, FlashPix.pm:1383-1390). Bounded
/// to the byte-preserving / Unicode cases the port needs: 1200 → UTF-16LE, 65001
/// → UTF-8, everything else (and no code page) → Latin-1 (identity for ASCII,
/// which is all the summary tables' realistic content). Higher-plane single-byte
/// charsets are not transcoded — sound, and exact for ASCII payloads.
fn decode_codepage(bytes: &[u8], code_page: Option<i64>) -> String {
  match code_page {
    Some(1200) => decode_utf16le(bytes),
    Some(65001) => String::from_utf8_lossy(bytes).into_owned(),
    _ => bytes.iter().map(|&b| b as char).collect(), // Latin-1 (ASCII-identity)
  }
}

#[cfg(test)]
// The file-level panic-safety contract is enforced by the parser code above;
// the test-builder helpers below index fixed-layout buffers freely (an
// out-of-range index is a test-assertion failure, not a shipped panic).
#[allow(clippy::indexing_slicing)]
mod tests {
  use super::*;
  use crate::emit::{ConvMode, EmitOptions, Taggable};

  // ---- Minimal OLE builder (a main-FAT layout: mini_cutoff = 0, so every
  // stream lives in the main FAT — the mini-FAT read path is covered end-to-end
  // by the `PNG_cpip.png` conformance fixture). ----------------------------
  fn le16(n: u16) -> Vec<u8> {
    n.to_le_bytes().to_vec()
  }
  fn le32(n: u32) -> Vec<u8> {
    n.to_le_bytes().to_vec()
  }
  fn le64(n: u64) -> Vec<u8> {
    n.to_le_bytes().to_vec()
  }

  fn v_lpstr(s: &str) -> (u32, Vec<u8>) {
    let mut sb = s.as_bytes().to_vec();
    sb.push(0);
    let count = sb.len();
    let pad = (4 - count % 4) % 4;
    let mut vb = le32(count as u32);
    vb.extend(sb);
    vb.extend(std::vec![0u8; pad]);
    (30, vb)
  }
  fn v_i4(n: i32) -> (u32, Vec<u8>) {
    (3, n.to_le_bytes().to_vec())
  }
  fn v_filetime(unix: i64) -> (u32, Vec<u8>) {
    let ft = (unix + 11_644_473_600) as u64 * 10_000_000;
    (64, le64(ft))
  }

  fn section(props: &[(u32, u32, Vec<u8>)]) -> Vec<u8> {
    let header_len = 8 + 8 * props.len();
    let mut pairs = Vec::new();
    let mut values = Vec::new();
    let mut offset = header_len;
    for (id, ty, vb) in props {
      pairs.extend(le32(*id));
      pairs.extend(le32(offset as u32));
      let mut prop = le32(*ty);
      prop.extend(vb.iter().copied());
      offset += prop.len();
      values.extend(prop);
    }
    let body_len = pairs.len() + values.len();
    let mut out = le32((8 + body_len) as u32);
    out.extend(le32(props.len() as u32));
    out.extend(pairs);
    out.extend(values);
    out
  }

  fn property_set(sec: &[u8]) -> Vec<u8> {
    let mut h = Vec::new();
    h.extend(le16(0xFFFE)); // BOM
    h.extend(le16(0)); // version
    h.extend(le32(0)); // OS version
    h.extend(std::vec![0u8; 16]); // CLSID
    h.extend(le32(1)); // num property sets
    h.extend(std::vec![0u8; 16]); // FMTID
    h.extend(le32(48)); // section offset
    h.extend_from_slice(sec);
    h
  }

  /// A two-section property set (as DocumentSummaryInformation uses): section 1 =
  /// predefined DocumentInfo, section 2 = UserDefined. The first section offset
  /// still lands at byte 44 (read by `process_properties`).
  fn two_section_property_set(sec1: &[u8], sec2: &[u8]) -> Vec<u8> {
    let off1 = 28 + 2 * (16 + 4); // 2 FMTID+offset descriptors precede the sections
    let mut h = Vec::new();
    h.extend(le16(0xFFFE)); // BOM
    h.extend(le16(0)); // version
    h.extend(le32(0)); // OS version
    h.extend(std::vec![0u8; 16]); // CLSID
    h.extend(le32(2)); // num property sets
    h.extend(std::vec![0u8; 16]); // FMTID 1
    h.extend(le32(off1 as u32)); // section 1 offset (byte 44)
    h.extend(std::vec![0u8; 16]); // FMTID 2
    h.extend(le32((off1 + sec1.len()) as u32)); // section 2 offset
    h.extend_from_slice(sec1);
    h.extend_from_slice(sec2);
    h
  }

  fn dir_entry(name: &str, etype: u8, start: u32, size: u32, child: u32, right: u32) -> Vec<u8> {
    let mut nb: Vec<u8> = name.encode_utf16().flat_map(u16::to_le_bytes).collect();
    nb.extend([0, 0]); // NUL terminator
    let name_len = nb.len();
    let mut e = nb;
    e.resize(64, 0);
    e.extend(le16(name_len as u16)); // 0x40
    e.push(etype); // 0x42
    e.push(1); // 0x43 color
    e.extend(le32(FREE_SECT)); // 0x44 left
    e.extend(le32(right)); // 0x48 right
    e.extend(le32(child)); // 0x4C child
    e.extend(std::vec![0u8; 16]); // 0x50 CLSID
    e.extend(le32(0)); // 0x60 state
    e.extend(le64(0)); // 0x64 ctime
    e.extend(le64(0)); // 0x6C mtime
    e.extend(le32(start)); // 0x74 start sector
    e.extend(le64(u64::from(size))); // 0x78 size
    assert_eq!(e.len(), 128);
    e
  }

  fn build_ole(summary: &[u8]) -> Vec<u8> {
    build_ole_named("\u{5}SummaryInformation", summary, summary.len() as u32)
  }

  /// Like [`build_ole`] but with a custom stream name + an explicit declared size
  /// on the directory entry (so tests can under-declare a stream's size).
  fn build_ole_named(name: &str, stream: &[u8], declared_size: u32) -> Vec<u8> {
    // sector 0 = property-set stream, 1 = directory, 2 = FAT
    let mut sec0 = stream.to_vec();
    sec0.resize(512, 0);
    let mut dir = Vec::new();
    dir.extend(dir_entry("Root Entry", 5, END_OF_CHAIN, 0, 1, FREE_SECT));
    dir.extend(dir_entry(name, 2, 0, declared_size, FREE_SECT, FREE_SECT));
    dir.resize(512, 0);
    let mut fat = Vec::new();
    fat.extend(le32(END_OF_CHAIN)); // sector 0 (summary)
    fat.extend(le32(END_OF_CHAIN)); // sector 1 (directory)
    fat.extend(le32(0xffff_fffd)); // sector 2 = FAT itself (FAT_SECT)
    fat.resize(512, 0xff); // remaining entries = FREE_SECT (0xffffffff)
    let mut h = Vec::new();
    h.extend([0xd0, 0xcf, 0x11, 0xe0, 0xa1, 0xb1, 0x1a, 0xe1]);
    h.extend(std::vec![0u8; 16]); // CLSID
    h.extend(le16(0x3E)); // minor
    h.extend(le16(0x03)); // major
    h.extend(le16(0xFFFE)); // byte order
    h.extend(le16(9)); // sector shift (512)
    h.extend(le16(6)); // mini-sector shift (64)
    h.extend(std::vec![0u8; 6]); // reserved
    h.extend(le32(0)); // num dir sectors
    h.extend(le32(1)); // num FAT sectors
    h.extend(le32(1)); // first dir sector
    h.extend(le32(0)); // txn sig
    h.extend(le32(0)); // mini cutoff (0 ⇒ all streams in the main FAT)
    h.extend(le32(END_OF_CHAIN)); // first mini-FAT sector
    h.extend(le32(0)); // num mini-FAT sectors
    h.extend(le32(END_OF_CHAIN)); // first DIFAT sector
    h.extend(le32(0)); // num DIFAT sectors
    h.extend(le32(2)); // DIFAT[0] = FAT sector 2
    for _ in 0..108 {
      h.extend(le32(FREE_SECT));
    }
    assert_eq!(h.len(), 512);
    let mut out = h;
    out.extend(sec0);
    out.extend(dir);
    out.extend(fat);
    out
  }

  fn tag_named<'a>(tags: &'a [EmittedTag], name: &str) -> &'a TagValue {
    tags
      .iter()
      .find(|t| t.tag().name() == name)
      .unwrap_or_else(|| panic!("tag {name} not found"))
      .tag()
      .value_ref()
  }

  #[test]
  fn walker_extracts_summary_info() {
    // 2007:02:09 16:23:23 UTC.
    let ole = build_ole(&property_set(&section(&[
      (0x02, v_lpstr("hi").0, v_lpstr("hi").1),
      (0x0f, v_i4(42).0, v_i4(42).1),
      (
        0x0c,
        v_filetime(1_171_038_203).0,
        v_filetime(1_171_038_203).1,
      ),
    ])));
    let meta = process(&ole);
    assert!(!meta.is_empty());
    let tags: Vec<EmittedTag> =
      Taggable::tags(&meta, EmitOptions::g1(ConvMode::PrintConv, false)).collect();
    match tag_named(&tags, "Title") {
      TagValue::Str(s) => assert_eq!(s, "hi"),
      other => panic!("Title = {other:?}"),
    }
    match tag_named(&tags, "Words") {
      TagValue::I64(n) => assert_eq!(*n, 42),
      other => panic!("Words = {other:?}"),
    }
    match tag_named(&tags, "CreateDate") {
      TagValue::Str(s) => assert_eq!(s, "2007:02:09 16:23:23"),
      other => panic!("CreateDate = {other:?}"),
    }
  }

  #[test]
  fn malformed_ole_no_panic() {
    // Empty, short, bad-signature, all-zero, all-0xff, valid-header-then-garbage.
    let inputs: Vec<Vec<u8>> = std::vec![
      Vec::new(),
      std::vec![0xd0, 0xcf, 0x11, 0xe0],
      std::vec![0u8; 512],
      std::vec![0xffu8; 4096],
      {
        let mut h = std::vec![0u8; 512];
        h[..8].copy_from_slice(&[0xd0, 0xcf, 0x11, 0xe0, 0xa1, 0xb1, 0x1a, 0xe1]);
        h
      },
      b"not an OLE compound document at all, just bytes".to_vec(),
    ];
    for input in inputs {
      let m = process(&input); // must not panic / OOB / loop
      let _ = m.is_empty();
    }
  }

  #[test]
  fn truncation_fuzz_no_panic() {
    // A valid OLE truncated at every length must never panic.
    let ole = build_ole(&property_set(&section(&[(
      0x02,
      v_lpstr("x").0,
      v_lpstr("x").1,
    )])));
    for len in 0..=ole.len() {
      let _ = process(&ole[..len]);
    }
  }

  #[test]
  fn corrupt_fat_and_dir_no_panic() {
    // Corrupt the header DIFAT[0] to a wild sector, and the directory start to a
    // wild sector — the bounds-checked loads must return gracefully.
    let mut ole = build_ole(&property_set(&section(&[(
      0x02,
      v_lpstr("x").0,
      v_lpstr("x").1,
    )])));
    ole[0x30..0x34].copy_from_slice(&0x00ff_ffffu32.to_le_bytes()); // dir start
    ole[0x4c..0x50].copy_from_slice(&0x00ff_ffffu32.to_le_bytes()); // DIFAT[0]
    let _ = process(&ole);
  }

  #[test]
  fn convert_time_span_matches_exiftool() {
    assert_eq!(convert_time_span(264.0), "4.4 minutes");
    assert_eq!(convert_time_span(30.0), "30 seconds");
    assert_eq!(convert_time_span(7200.0), "2.0 hours");
    assert_eq!(convert_time_span(0.0), "0");
  }

  #[test]
  fn decode_security_bitmask() {
    assert_eq!(decode_security(0), "None");
    assert_eq!(decode_security(1), "Password protected");
    assert_eq!(
      decode_security(3),
      "Password protected, Read-only recommended"
    );
  }

  #[test]
  fn code_page_name_subset() {
    assert_eq!(
      code_page_name(1252),
      Some("Windows Latin 1 (Western European)")
    );
    assert_eq!(code_page_name(10000), Some("Mac Roman (Western European)"));
    assert_eq!(code_page_name(99999), None);
  }

  #[test]
  fn revision_number_string_stays_string() {
    // VT_LPSTR "1" (RevisionNumber) is stored as a string; the JSON serializer's
    // shared number gate renders it bare downstream, but the raw value is `Str`.
    let ole = build_ole(&property_set(&section(&[(
      0x09,
      v_lpstr("1").0,
      v_lpstr("1").1,
    )])));
    let meta = process(&ole);
    let tags: Vec<EmittedTag> =
      Taggable::tags(&meta, EmitOptions::g1(ConvMode::ValueConv, false)).collect();
    match tag_named(&tags, "RevisionNumber") {
      TagValue::Str(s) => assert_eq!(s, "1"),
      other => panic!("RevisionNumber = {other:?}"),
    }
  }

  #[test]
  fn hostile_oversized_property_count() {
    // A section header declaring an absurd property count must be rejected by the
    // MAX_PROPERTIES cap (no multi-million-iteration loop, no OOM/hang), emitting
    // nothing.
    let mut sec = section(&[(0x02, v_lpstr("hi").0, v_lpstr("hi").1)]);
    sec[4..8].copy_from_slice(&5_000_000u32.to_le_bytes()); // overwrite numEntries
    let meta = process(&build_ole(&property_set(&sec)));
    let tags: Vec<EmittedTag> =
      Taggable::tags(&meta, EmitOptions::g1(ConvMode::PrintConv, false)).collect();
    assert!(tags.is_empty(), "the capped section must emit no tags");
    assert!(
      meta.warnings().iter().any(|w| w.contains("Excessive")),
      "expected the property-count cap warning, got {:?}",
      meta.warnings()
    );
  }

  #[test]
  fn hostile_vector_count_capped() {
    // A VT_UI1|VT_VECTOR whose element count exceeds MAX_VECTOR_ELEMS is rejected
    // before allocation EVEN when the declared byte range fits the buffer (so the
    // saturating byte-bound alone would not catch it) — no giant allocation.
    let count = MAX_VECTOR_ELEMS + 1;
    let mut data = le32(count as u32);
    data.resize(4 + count, 0); // byte range large enough that the size check passes
    let mut budget = MAX_TOTAL_EMITTED;
    let ty = 17 | VT_VECTOR; // VT_UI1 vector (size_per = 1)
    let (v, _pos) = read_fpx_value(&data, 0, ty, data.len(), false, None, true, 0, &mut budget);
    assert!(
      v.is_none(),
      "vector count above MAX_VECTOR_ELEMS must be rejected"
    );
  }

  #[test]
  fn hostile_stream_size_truncates_padding() {
    // A valid property set lives in the stream, but the directory entry declares
    // size = 1: the loaded 512-byte sector is truncated to 1 byte, so the property
    // set (which sits past byte 1) must NOT be decoded out of the sector padding.
    let ps = property_set(&section(&[(0x02, v_lpstr("hi").0, v_lpstr("hi").1)]));
    let meta = process(&build_ole_named("\u{5}SummaryInformation", &ps, 1));
    let tags: Vec<EmittedTag> =
      Taggable::tags(&meta, EmitOptions::g1(ConvMode::PrintConv, false)).collect();
    assert!(
      tags.iter().all(|t| t.tag().name() != "Title"),
      "must not decode a property set out of sector padding beyond the declared size"
    );
    // Sanity: with the correct declared size the same stream DOES decode Title.
    let ok = process(&build_ole_named(
      "\u{5}SummaryInformation",
      &ps,
      ps.len() as u32,
    ));
    let ok_tags: Vec<EmittedTag> =
      Taggable::tags(&ok, EmitOptions::g1(ConvMode::PrintConv, false)).collect();
    assert!(ok_tags.iter().any(|t| t.tag().name() == "Title"));
  }

  #[test]
  fn hostile_userdefined_section_skipped() {
    // DocumentSummaryInformation with section 1 (predefined) = Slides (PID 7) and
    // section 2 (UserDefined) = a custom PID 2. The UserDefined section must be
    // skipped — PID 2 must NOT be misattributed to "Category".
    let sec1 = section(&[(0x07, v_i4(3).0, v_i4(3).1)]); // Slides = 3
    let sec2 = section(&[(0x02, v_i4(9).0, v_i4(9).1)]); // custom PID 2
    let ps = two_section_property_set(&sec1, &sec2);
    let ole = build_ole_named("\u{5}DocumentSummaryInformation", &ps, ps.len() as u32);
    let meta = process(&ole);
    let tags: Vec<EmittedTag> =
      Taggable::tags(&meta, EmitOptions::g1(ConvMode::PrintConv, false)).collect();
    assert!(
      tags.iter().any(|t| t.tag().name() == "Slides"),
      "the predefined section 1 must still decode"
    );
    assert!(
      tags.iter().all(|t| t.tag().name() != "Category"),
      "the UserDefined section 2 must be skipped, not decoded as Category"
    );
  }

  // ---- Structural crafted-input DoS regression tests (Findings 1/2/3) -----

  /// A `VT_UI1|VT_VECTOR` value of `n` elements — `n` budget units in `n` value
  /// bytes (the most budget-dense single property, used to drain the OLE-wide
  /// budget in ONE stream).
  fn v_ui1_vector(n: usize) -> (u32, Vec<u8>) {
    let mut vb = le32(n as u32);
    vb.extend(std::vec![0u8; n]);
    (17 | VT_VECTOR, vb) // 17 = VT_UI1
  }

  /// Build an OLE whose directory holds `repeats` identical stream entries, all
  /// pointing at the one main-FAT stream (chained across 512-byte sectors) — the
  /// repeated-recognized-stream shape that Finding 1 defends against.
  fn build_ole_repeated(name: &str, stream: &[u8], repeats: usize) -> Vec<u8> {
    let sect = 512usize;
    let ceil = |x: usize| x.div_ceil(sect).max(1);
    let s_count = ceil(stream.len());
    let d_count = ceil((1 + repeats) * 128);
    let dir_start = s_count;
    let fat_start = s_count + d_count;
    let epf = sect / 4; // FAT entries per sector
    let non_fat = s_count + d_count;
    let mut fat_count = 1usize;
    while fat_count * epf < non_fat + fat_count {
      fat_count += 1;
    }

    // FAT: stream chain, then dir chain, then the FAT sectors themselves.
    let mut fat_e = std::vec![FREE_SECT; fat_count * epf];
    for (i, e) in fat_e.iter_mut().take(s_count).enumerate() {
      *e = if i + 1 < s_count {
        (i + 1) as u32
      } else {
        END_OF_CHAIN
      };
    }
    for (i, e) in fat_e.iter_mut().skip(dir_start).take(d_count).enumerate() {
      *e = if i + 1 < d_count {
        (dir_start + i + 1) as u32
      } else {
        END_OF_CHAIN
      };
    }
    for e in fat_e.iter_mut().skip(fat_start).take(fat_count) {
      *e = 0xffff_fffd; // FAT_SECT
    }

    let mut dir = Vec::new();
    dir.extend(dir_entry("Root Entry", 5, END_OF_CHAIN, 0, 1, FREE_SECT));
    for _ in 0..repeats {
      dir.extend(dir_entry(
        name,
        2,
        0,
        stream.len() as u32,
        FREE_SECT,
        FREE_SECT,
      ));
    }
    dir.resize(d_count * sect, 0);

    let mut sec_stream = stream.to_vec();
    sec_stream.resize(s_count * sect, 0);

    let mut fat_bytes = Vec::new();
    for e in &fat_e {
      fat_bytes.extend(le32(*e));
    }

    let mut h = Vec::new();
    h.extend([0xd0, 0xcf, 0x11, 0xe0, 0xa1, 0xb1, 0x1a, 0xe1]);
    h.extend(std::vec![0u8; 16]);
    h.extend(le16(0x3E));
    h.extend(le16(0x03));
    h.extend(le16(0xFFFE));
    h.extend(le16(9)); // 512-byte sectors
    h.extend(le16(6)); // 64-byte mini-sectors
    h.extend(std::vec![0u8; 6]);
    h.extend(le32(0)); // num dir sectors
    h.extend(le32(fat_count as u32));
    h.extend(le32(dir_start as u32));
    h.extend(le32(0)); // txn sig
    h.extend(le32(0)); // mini cutoff (0 ⇒ all streams in the main FAT)
    h.extend(le32(END_OF_CHAIN)); // mini-FAT start
    h.extend(le32(0)); // mini-FAT count
    h.extend(le32(END_OF_CHAIN)); // DIFAT start
    h.extend(le32(0)); // DIFAT count
    let mut difat_n = 0;
    for i in 0..fat_count {
      h.extend(le32((fat_start + i) as u32));
      difat_n += 1;
    }
    for _ in difat_n..109 {
      h.extend(le32(FREE_SECT));
    }
    assert_eq!(h.len(), 512);

    let mut out = h;
    out.extend(sec_stream);
    out.extend(dir);
    out.extend(fat_bytes);
    out
  }

  #[test]
  fn hostile_repeated_streams_share_budget() {
    // Finding 1: ONE OLE-wide budget is threaded across every summary stream, so
    // a directory that repeats a recognized stream cannot reset it. Eight
    // identical SummaryInformation entries each point at a stream whose single
    // property is a ~64K-element vector that alone drains the budget; only the
    // FIRST stream is decoded and the walk stops (bounded tags, no OOM/hang).
    let (vt, vb) = v_ui1_vector(1 << 16);
    let ps = property_set(&section(&[(0x02, vt, vb)]));
    let ole = build_ole_repeated("\u{5}SummaryInformation", &ps, 8);
    let meta = process(&ole);
    assert!(
      meta.tags.len() <= 2,
      "the OLE-wide budget must stop the walk after the first stream, not decode \
       all 8 repeats: got {} tags",
      meta.tags.len()
    );
    assert!(
      meta
        .warnings()
        .iter()
        .any(|w| w.contains("budget exhausted")),
      "expected the OLE-wide budget-exhausted warning, got {:?}",
      meta.warnings()
    );
  }

  #[test]
  fn hostile_long_difat_chain_bounded() {
    // Finding 2: a long ACYCLIC DIFAT chain of distinct in-buffer 64-byte sectors
    // must walk in O(n) (bitset dedup + buffer-sector bound) and terminate, never
    // O(n^2) / hang. Each DIF sector's 15 FAT slots are FREE; its last 4 bytes
    // chain to the next DIF sector; the final one ends the chain. This also
    // confirms 64-byte sectors stay ACCEPTED (faithful — ExifTool does not
    // validate the sector shift).
    let sect_size = 64usize;
    let hdr_size = 512usize;
    let k = 20_000usize;
    let mut cpip = std::vec![0u8; hdr_size + k * sect_size];
    for i in 0..k {
      let base = hdr_size + i * sect_size;
      for j in 0..15 {
        cpip[base + j * 4..base + j * 4 + 4].copy_from_slice(&FREE_SECT.to_le_bytes());
      }
      let next = if i + 1 < k {
        (i + 1) as u32
      } else {
        END_OF_CHAIN
      };
      cpip[base + 60..base + 64].copy_from_slice(&next.to_le_bytes());
    }
    let mut header = std::vec![0u8; 512];
    for off in (0x4c..512).step_by(4) {
      header[off..off + 4].copy_from_slice(&FREE_SECT.to_le_bytes());
    }
    let mut meta = FlashPixMeta::new();
    let fat = load_fat(
      &cpip, &header, sect_size, hdr_size, 0, 0, k as u32, true, &mut meta,
    );
    assert!(
      fat.is_empty(),
      "all DIF FAT slots were FREE → no FAT bytes loaded"
    );
    assert!(
      !meta.warnings().iter().any(|w| w.contains("Cyclical")),
      "an acyclic DIF chain must not be flagged cyclical: {:?}",
      meta.warnings()
    );
  }

  #[test]
  fn hostile_cross_section_offset_fenced() {
    // Finding 3: a section-1 property whose value offset points PAST the declared
    // section (into section 2) must be fenced by `section_end` and NOT emitted —
    // else a hostile first-section PID could smuggle a value out of the
    // UserDefined section under a predefined name.
    let mut sec1 = section(&[(0x07, v_i4(3).0, v_i4(3).1)]); // Slides, well-formed
    // Overwrite the single property's offset field (sec1[12..16]) so val_start
    // lands at the section-2 boundary (offset 20 → val_start = pos + 24 = the
    // declared section end), i.e. outside `section_end`.
    sec1[12..16].copy_from_slice(&20u32.to_le_bytes());
    let sec2 = section(&[(0x02, v_i4(9).0, v_i4(9).1)]);
    let ps = two_section_property_set(&sec1, &sec2);
    let ole = build_ole_named("\u{5}DocumentSummaryInformation", &ps, ps.len() as u32);
    let meta = process(&ole);
    let tags: Vec<EmittedTag> =
      Taggable::tags(&meta, EmitOptions::g1(ConvMode::PrintConv, false)).collect();
    assert!(
      tags.iter().all(|t| t.tag().name() != "Slides"),
      "a value offset past the section end must be fenced, not emitted"
    );
  }
}
