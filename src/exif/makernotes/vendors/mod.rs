// SPDX-License-Identifier: GPL-3.0-or-later
// exifast — a 1:1 Rust port of ExifTool (Phil Harvey). See THIRD_PARTY.md.

//! Per-vendor MakerNote-decoded structs — Phase 1 placeholders.
//!
//! Each module is an empty shell that gives Phase 2+ a stable typed
//! accessor surface. The structs are zero-sized today; future phases
//! populate them with private fields per vendor's tag table.

pub mod apple;
pub mod canon;
pub mod dji;
pub mod gopro;
pub mod panasonic;
pub mod sony;

pub use apple::AppleMakerNote;
pub use canon::CanonMakerNote;
pub use dji::DjiMakerNote;
pub use gopro::GoProMakerNote;
pub use panasonic::PanasonicMakerNote;
pub use sony::SonyMakerNote;
