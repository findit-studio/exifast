// SPDX-License-Identifier: GPL-3.0-or-later
// Data tables for filetype.rs (included via include!()). Faithful 1:1
// transliteration of ExifTool.pm %fileTypeLookup / %moduleName / %magicNumber.
// Kept in this file (not split) per spec D10.

// --- single-type slices (so Lookup::Single can hold &'static [&'static str]) -

macro_rules! ft_single {
    ($t:literal, $d:literal) => {
        Lookup::Single({ const S: &[&str] = &[$t]; S }, $d)
    };
}
macro_rules! ft_multi {
    ([$($t:literal),+], $d:literal) => {
        Lookup::Multi({ const S: &[&str] = &[$($t),+]; S }, $d)
    };
}

/// `%fileTypeLookup` (ExifTool.pm:230-586). EXT (uppercased) -> entry.
/// 350 keys. Values are FILE TYPES / aliases, never module names.
fn file_type_lookup(ext: &str) -> Option<Lookup> {
    Some(match ext {
        "360" => ft_single!("MOV", "GoPro 360 video"),
        "3FR" => ft_single!("TIFF", "Hasselblad RAW format"),
        "3G2" => ft_single!("MOV", "3rd Gen. Partnership Project 2 audio/video"),
        "3GP" => ft_single!("MOV", "3rd Gen. Partnership Project audio/video"),
        "3GP2" => Lookup::Alias("3G2"),
        "3GPP" => Lookup::Alias("3GP"),
        "7Z" => ft_single!("7Z", "7z archive"),
        "A" => ft_single!("EXE", "Static library"),
        "AA" => ft_single!("AA", "Audible Audiobook"),
        "AAC" => ft_single!("AAC", "Advanced Audio Coding"),
        "AAE" => ft_single!("PLIST", "Apple edit information"),
        "AAX" => ft_single!("MOV", "Audible Enhanced Audiobook"),
        "ACR" => ft_single!("DICOM", "American College of Radiology ACR-NEMA"),
        "ACFM" => ft_single!("Font", "Adobe Composite Font Metrics"),
        "AFM" => ft_single!("Font", "Adobe Font Metrics"),
        "AMFM" => ft_single!("Font", "Adobe Multiple Master Font Metrics"),
        "AI" => ft_multi!(["PDF", "PS"], "Adobe Illustrator"),
        "AIF" => Lookup::Alias("AIFF"),
        "AIFC" => ft_single!("AIFF", "Audio Interchange File Format Compressed"),
        "AIFF" => ft_single!("AIFF", "Audio Interchange File Format"),
        "AIT" => Lookup::Alias("AI"),
        "ALIAS" => ft_single!("ALIAS", "MacOS file alias"),
        "APE" => ft_single!("APE", "Monkey's Audio format"),
        "APNG" => ft_single!("PNG", "Animated Portable Network Graphics"),
        "ARW" => ft_single!("TIFF", "Sony Alpha RAW format"),
        "ARQ" => ft_single!("TIFF", "Sony Alpha Pixel-Shift RAW format"),
        "ASF" => ft_single!("ASF", "Microsoft Advanced Systems Format"),
        "AVC" => ft_single!("AVC", "Advanced Video Connection"),
        "AVI" => ft_single!("RIFF", "Audio Video Interleaved"),
        "AVIF" => ft_single!("MOV", "AV1 Image File Format"),
        "AZW" => Lookup::Alias("MOBI"),
        "AZW3" => Lookup::Alias("MOBI"),
        "BMP" => ft_single!("BMP", "Windows Bitmap"),
        "BPG" => ft_single!("BPG", "Better Portable Graphics"),
        "BTF" => ft_single!("BTF", "Big Tagged Image File Format"),
        "BZ2" => ft_single!("BZ2", "BZIP2 archive"),
        "CAP" => Lookup::Alias("PCAP"),
        "C2PA" => ft_single!("JUMBF", "Coalition for Content Provenance and Authenticity"),
        "CHM" => ft_single!("CHM", "Microsoft Compiled HTML format"),
        "CIFF" => ft_single!("CRW", "Camera Image File Format"),
        "COS" => ft_single!("COS", "Capture One Settings"),
        "CR2" => ft_single!("TIFF", "Canon RAW 2 format"),
        "CR3" => ft_single!("MOV", "Canon RAW 3 format"),
        "CRM" => ft_single!("MOV", "Canon RAW Movie"),
        "CRW" => ft_single!("CRW", "Canon RAW format"),
        "CS1" => ft_single!("PSD", "Sinar CaptureShop 1-Shot RAW"),
        "CSV" => ft_single!("TXT", "Comma-Separated Values"),
        "CUR" => ft_single!("ICO", "Windows Cursor"),
        "CZI" => ft_single!("CZI", "Zeiss Integrated Software RAW"),
        "DC3" => Lookup::Alias("DICM"),
        "DCM" => Lookup::Alias("DICM"),
        "DCP" => ft_single!("TIFF", "DNG Camera Profile"),
        "DCR" => ft_single!("TIFF", "Kodak Digital Camera RAW"),
        "DCX" => ft_single!("DCX", "Multi-page PC Paintbrush"),
        "DEX" => ft_single!("DEX", "Dalvik Executable format"),
        "DFONT" => ft_single!("Font", "Macintosh Data fork Font"),
        "DIB" => ft_single!("BMP", "Device Independent Bitmap"),
        "DIC" => Lookup::Alias("DICM"),
        "DICM" => ft_single!("DICOM", "Digital Imaging and Communications in Medicine"),
        "DIR" => ft_single!("DIR", "Directory"),
        "DIVX" => ft_single!("ASF", "DivX media format"),
        "DJV" => Lookup::Alias("DJVU"),
        "DJVU" => ft_single!("AIFF", "DjVu image"),
        "DLL" => ft_single!("EXE", "Windows Dynamic Link Library"),
        "DNG" => ft_single!("TIFF", "Digital Negative"),
        "DOC" => ft_single!("FPX", "Microsoft Word Document"),
        "DOCM" => ft_multi!(["ZIP", "FPX"], "Office Open XML Document Macro-enabled"),
        "DOCX" => ft_multi!(["ZIP", "FPX"], "Office Open XML Document"),
        "DOT" => ft_single!("FPX", "Microsoft Word Template"),
        "DOTM" => ft_multi!(["ZIP", "FPX"], "Office Open XML Document Template Macro-enabled"),
        "DOTX" => ft_multi!(["ZIP", "FPX"], "Office Open XML Document Template"),
        "DPX" => ft_single!("DPX", "Digital Picture Exchange"),
        "DR4" => ft_single!("DR4", "Canon VRD version 4 Recipe"),
        "DS2" => ft_single!("DSS", "Digital Speech Standard 2"),
        "DSF" => ft_single!("DSF", "DSF Stream File"),
        "DSS" => ft_single!("DSS", "Digital Speech Standard"),
        "DV" => ft_single!("DV", "Digital Video"),
        "DVB" => ft_single!("MOV", "Digital Video Broadcasting"),
        "DVR-MS" => ft_single!("ASF", "Microsoft Digital Video recording"),
        "DWF" => ft_single!("DWF", "Autodesk drawing (Design Web Format)"),
        "DWG" => ft_single!("DWG", "AutoCAD Drawing"),
        "DYLIB" => ft_single!("EXE", "Mach-O Dynamic Link Library"),
        "DXF" => ft_single!("DXF", "AutoCAD Drawing Exchange Format"),
        "EIP" => ft_single!("ZIP", "Capture One Enhanced Image Package"),
        "EPS" => ft_single!("EPS", "Encapsulated PostScript Format"),
        "EPS2" => Lookup::Alias("EPS"),
        "EPS3" => Lookup::Alias("EPS"),
        "EPSF" => Lookup::Alias("EPS"),
        "EPUB" => ft_single!("ZIP", "Electronic Publication"),
        "ERF" => ft_single!("TIFF", "Epson Raw Format"),
        "EXE" => ft_single!("EXE", "Windows executable file"),
        "EXR" => ft_single!("EXR", "Open EXR"),
        "EXIF" => ft_single!("EXIF", "Exchangable Image File Metadata"),
        "EXV" => ft_single!("EXV", "Exiv2 metadata"),
        "F4A" => ft_single!("MOV", "Adobe Flash Player 9+ Audio"),
        "F4B" => ft_single!("MOV", "Adobe Flash Player 9+ audio Book"),
        "F4P" => ft_single!("MOV", "Adobe Flash Player 9+ Protected"),
        "F4V" => ft_single!("MOV", "Adobe Flash Player 9+ Video"),
        "FFF" => ft_multi!(["TIFF", "FLIR"], "Hasselblad Flexible File Format"),
        "FIT" => ft_single!("FIT", "Garmin Flexible and Interoperable data Transfer"),
        "FITS" => ft_single!("FITS", "Flexible Image Transport System"),
        "FLAC" => ft_single!("FLAC", "Free Lossless Audio Codec"),
        "FLA" => ft_single!("FPX", "Macromedia/Adobe Flash project"),
        "FLIF" => ft_single!("FLIF", "Free Lossless Image Format"),
        "FLIR" => ft_single!("FLIR", "FLIR File Format"),
        "FLV" => ft_single!("FLV", "Flash Video"),
        "FPF" => ft_single!("FPF", "FLIR Public image Format"),
        "FPX" => ft_single!("FPX", "FlashPix"),
        "GIF" => ft_single!("GIF", "Compuserve Graphics Interchange Format"),
        "GLV" => ft_single!("MOV", "Garmin Low-resolution Video"),
        "GPR" => ft_single!("TIFF", "General Purpose RAW"),
        "GZ" => Lookup::Alias("GZIP"),
        "GZIP" => ft_single!("GZIP", "GNU ZIP compressed archive"),
        "HDP" => ft_single!("TIFF", "Windows HD Photo"),
        "HDR" => ft_single!("HDR", "Radiance RGBE High Dynamic Range"),
        "HEIC" => ft_single!("MOV", "High Efficiency Image Format still image"),
        "HEIF" => ft_single!("MOV", "High Efficiency Image Format"),
        "HIF" => Lookup::Alias("HEIF"),
        "HTM" => Lookup::Alias("HTML"),
        "HTML" => ft_single!("HTML", "HyperText Markup Language"),
        "ICAL" => Lookup::Alias("ICS"),
        "ICC" => ft_single!("ICC", "International Color Consortium"),
        "ICM" => Lookup::Alias("ICC"),
        "ICO" => ft_single!("ICO", "Windows Icon"),
        "ICS" => ft_single!("VCard", "iCalendar Schedule"),
        "IDML" => ft_single!("ZIP", "Adobe InDesign Markup Language"),
        "IIQ" => ft_single!("TIFF", "Phase One Intelligent Image Quality RAW"),
        "IND" => ft_single!("IND", "Adobe InDesign"),
        "INDD" => ft_single!("IND", "Adobe InDesign Document"),
        "INDT" => ft_single!("IND", "Adobe InDesign Template"),
        "INSV" => ft_single!("MOV", "Insta360 Video"),
        "INSP" => ft_single!("JPEG", "Insta360 Picture"),
        "INX" => ft_single!("XMP", "Adobe InDesign Interchange"),
        "ISO" => ft_single!("ISO", "ISO 9660 disk image"),
        "ITC" => ft_single!("ITC", "iTunes Cover Flow"),
        "J2C" => ft_single!("JP2", "JPEG 2000 codestream"),
        "J2K" => Lookup::Alias("J2C"),
        "JNG" => ft_single!("PNG", "JPG Network Graphics"),
        "JP2" => ft_single!("JP2", "JPEG 2000 file"),
        "JPC" => Lookup::Alias("J2C"),
        "JPE" => Lookup::Alias("JPEG"),
        "JPEG" => ft_single!("JPEG", "Joint Photographic Experts Group"),
        "JPH" => ft_single!("JP2", "High-throughput JPEG 2000"),
        "JPF" => Lookup::Alias("JP2"),
        "JPG" => Lookup::Alias("JPEG"),
        "JPM" => ft_single!("JP2", "JPEG 2000 compound image"),
        "JPS" => ft_single!("JPEG", "JPEG Stereo image"),
        "JPX" => ft_single!("JP2", "JPEG 2000 with extensions"),
        "JSON" => ft_single!("JSON", "JavaScript Object Notation"),
        "JUMBF" => ft_single!("JUMBF", "JPEG Universal Metadata Box Format"),
        "JXL" => ft_single!("JXL", "JPEG XL"),
        "JXR" => ft_single!("TIFF", "JPEG XR"),
        "K25" => ft_single!("TIFF", "Kodak DC25 RAW"),
        "KDC" => ft_single!("TIFF", "Kodak Digital Camera RAW"),
        "KEY" => ft_single!("ZIP", "Apple Keynote presentation"),
        "KTH" => ft_single!("ZIP", "Apple Keynote Theme"),
        "KVAR" => ft_single!("KVAR", "Kandao Video Asset Resource"),
        "LA" => ft_single!("RIFF", "Lossless Audio"),
        "LFP" => ft_single!("LFP", "Lytro Light Field Picture"),
        "LFR" => Lookup::Alias("LFP"),
        "LIF" => ft_single!("LIF", "Leica Image File"),
        "LNK" => ft_single!("LNK", "Windows shortcut"),
        "LRF" => ft_single!("MOV", "Low-Resolution video File"),
        "LRI" => ft_single!("LRI", "Light RAW"),
        "LRV" => ft_single!("MOV", "Low-Resolution Video"),
        "M2T" => Lookup::Alias("M2TS"),
        "M2TS" => ft_single!("M2TS", "MPEG-2 Transport Stream"),
        "M2V" => ft_single!("MPEG", "MPEG-2 Video"),
        "M4A" => ft_single!("MOV", "MPEG-4 Audio"),
        "M4B" => ft_single!("MOV", "MPEG-4 audio Book"),
        "M4P" => ft_single!("MOV", "MPEG-4 Protected"),
        "M4V" => ft_single!("MOV", "MPEG-4 Video"),
        "MACOS" => ft_single!("MacOS", "MacOS ._ sidecar file"),
        "MAX" => ft_single!("FPX", "3D Studio MAX"),
        "MEF" => ft_single!("TIFF", "Mamiya (RAW) Electronic Format"),
        "MIE" => ft_single!("MIE", "Meta Information Encapsulation format"),
        "MIF" => Lookup::Alias("MIFF"),
        "MIFF" => ft_single!("MIFF", "Magick Image File Format"),
        "MKA" => ft_single!("MKV", "Matroska Audio"),
        "MKS" => ft_single!("MKV", "Matroska Subtitle"),
        "MKV" => ft_single!("MKV", "Matroska Video"),
        "MNG" => ft_single!("PNG", "Multiple-image Network Graphics"),
        "MOBI" => ft_single!("PDB", "Mobipocket electronic book"),
        "MODD" => ft_single!("PLIST", "Sony Picture Motion metadata"),
        "MOI" => ft_single!("MOI", "MOD Information file"),
        "MOS" => ft_single!("TIFF", "Creo Leaf Mosaic"),
        "MOV" => ft_single!("MOV", "Apple QuickTime movie"),
        "MP3" => ft_single!("MP3", "MPEG-1 Layer 3 audio"),
        "MP4" => ft_single!("MOV", "MPEG-4 video"),
        "MPC" => ft_single!("MPC", "Musepack Audio"),
        "MPEG" => ft_single!("MPEG", "MPEG-1 or MPEG-2 audio/video"),
        "MPG" => Lookup::Alias("MPEG"),
        "MPO" => ft_single!("JPEG", "Extended Multi-Picture format"),
        "MQV" => ft_single!("MOV", "Sony Mobile Quicktime Video"),
        "MRC" => ft_single!("MRC", "Medical Research Council image"),
        "MRW" => ft_single!("MRW", "Minolta RAW format"),
        "MTS" => Lookup::Alias("M2TS"),
        "MXF" => ft_single!("MXF", "Material Exchange Format"),
        "NEF" => ft_single!("TIFF", "Nikon (RAW) Electronic Format"),
        "NEWER" => Lookup::Alias("COS"),
        "NKA" => ft_single!("NKA", "Nikon NX Studio Adjustments"),
        "NKSC" => ft_single!("XMP", "Nikon Sidecar"),
        "NMBTEMPLATE" => ft_single!("ZIP", "Apple Numbers Template"),
        "NRW" => ft_single!("TIFF", "Nikon RAW (2)"),
        "NUMBERS" => ft_single!("ZIP", "Apple Numbers spreadsheet"),
        "NXD" => ft_single!("XMP", "Nikon NX-D Settings"),
        "O" => ft_single!("EXE", "Relocatable Object"),
        "ODB" => ft_single!("ZIP", "Open Document Database"),
        "ODC" => ft_single!("ZIP", "Open Document Chart"),
        "ODF" => ft_single!("ZIP", "Open Document Formula"),
        "ODG" => ft_single!("ZIP", "Open Document Graphics"),
        "ODI" => ft_single!("ZIP", "Open Document Image"),
        "ODP" => ft_single!("ZIP", "Open Document Presentation"),
        "ODS" => ft_single!("ZIP", "Open Document Spreadsheet"),
        "ODT" => ft_single!("ZIP", "Open Document Text file"),
        "OFR" => ft_single!("RIFF", "OptimFROG audio"),
        "OGG" => ft_single!("OGG", "Ogg Vorbis audio file"),
        "OGV" => ft_single!("OGG", "Ogg Video file"),
        "ONP" => ft_single!("JSON", "ON1 Presets"),
        "OPUS" => ft_single!("OGG", "Ogg Opus audio file"),
        "ORF" => ft_single!("ORF", "Olympus RAW format"),
        "ORI" => Lookup::Alias("ORF"),
        "OTF" => ft_single!("Font", "Open Type Font"),
        "PAC" => ft_single!("RIFF", "Lossless Predictive Audio Compression"),
        "PAGES" => ft_single!("ZIP", "Apple Pages document"),
        "PBM" => ft_single!("PPM", "Portable BitMap"),
        "PCAP" => ft_single!("PCAP", "Packet Capture"),
        "PCAPNG" => ft_single!("PCAP", "Packet Capture Next Generation"),
        "PCD" => ft_single!("PCD", "Kodak Photo CD Image Pac"),
        "PCT" => Lookup::Alias("PICT"),
        "PCX" => ft_single!("PCX", "PC Paintbrush"),
        "PDB" => ft_single!("PDB", "Palm Database"),
        "PDF" => ft_single!("PDF", "Adobe Portable Document Format"),
        "PEF" => ft_single!("TIFF", "Pentax (RAW) Electronic Format"),
        "PFA" => ft_single!("Font", "PostScript Font ASCII"),
        "PFB" => ft_single!("Font", "PostScript Font Binary"),
        "PFM" => ft_multi!(["Font", "PFM2"], "Printer Font Metrics"),
        "PGF" => ft_single!("PGF", "Progressive Graphics File"),
        "PGM" => ft_single!("PPM", "Portable Gray Map"),
        "PHP" => ft_single!("PHP", "PHP Hypertext Preprocessor"),
        "PHP3" => Lookup::Alias("PHP"),
        "PHP4" => Lookup::Alias("PHP"),
        "PHP5" => Lookup::Alias("PHP"),
        "PHPS" => Lookup::Alias("PHP"),
        "PHTML" => Lookup::Alias("PHP"),
        "PICT" => ft_single!("PICT", "Apple PICTure"),
        "PLIST" => ft_single!("PLIST", "Apple Property List"),
        "PMP" => ft_single!("PMP", "Sony DSC-F1 Cyber-Shot PMP"),
        "PNG" => ft_single!("PNG", "Portable Network Graphics"),
        "POT" => ft_single!("FPX", "Microsoft PowerPoint Template"),
        "POTM" => ft_multi!(["ZIP", "FPX"], "Office Open XML Presentation Template Macro-enabled"),
        "POTX" => ft_multi!(["ZIP", "FPX"], "Office Open XML Presentation Template"),
        "PPAM" => ft_multi!(["ZIP", "FPX"], "Office Open XML Presentation Addin Macro-enabled"),
        "PPAX" => ft_multi!(["ZIP", "FPX"], "Office Open XML Presentation Addin"),
        "PPM" => ft_single!("PPM", "Portable Pixel Map"),
        "PPS" => ft_single!("FPX", "Microsoft PowerPoint Slideshow"),
        "PPSM" => ft_multi!(["ZIP", "FPX"], "Office Open XML Presentation Slideshow Macro-enabled"),
        "PPSX" => ft_multi!(["ZIP", "FPX"], "Office Open XML Presentation Slideshow"),
        "PPT" => ft_single!("FPX", "Microsoft PowerPoint Presentation"),
        "PPTM" => ft_multi!(["ZIP", "FPX"], "Office Open XML Presentation Macro-enabled"),
        "PPTX" => ft_multi!(["ZIP", "FPX"], "Office Open XML Presentation"),
        "PRC" => ft_single!("PDB", "Palm Database"),
        "PS" => ft_single!("PS", "PostScript"),
        "PS2" => Lookup::Alias("PS"),
        "PS3" => Lookup::Alias("PS"),
        "PSB" => ft_single!("PSD", "Photoshop Large Document"),
        "PSD" => ft_single!("PSD", "Photoshop Document"),
        "PSDT" => ft_single!("PSD", "Photoshop Document Template"),
        "PSP" => ft_single!("PSP", "Paint Shop Pro"),
        "PSPFRAME" => Lookup::Alias("PSP"),
        "PSPIMAGE" => Lookup::Alias("PSP"),
        "PSPSHAPE" => Lookup::Alias("PSP"),
        "PSPTUBE" => Lookup::Alias("PSP"),
        "QIF" => Lookup::Alias("QTIF"),
        "QT" => Lookup::Alias("MOV"),
        "QTI" => Lookup::Alias("QTIF"),
        "QTIF" => ft_single!("QTIF", "QuickTime Image File"),
        "R3D" => ft_single!("R3D", "Redcode RAW Video"),
        "RA" => ft_single!("Real", "Real Audio"),
        "RAF" => ft_single!("RAF", "FujiFilm RAW Format"),
        "RAM" => ft_single!("Real", "Real Audio Metafile"),
        "RAR" => ft_single!("RAR", "RAR Archive"),
        "RAW" => ft_multi!(["RAW", "TIFF"], "Kyocera Contax N Digital RAW or Panasonic RAW"),
        "RIF" => Lookup::Alias("RIFF"),
        "RIFF" => ft_single!("RIFF", "Resource Interchange File Format"),
        "RM" => ft_single!("Real", "Real Media"),
        "RMVB" => ft_single!("Real", "Real Media Variable Bitrate"),
        "RPM" => ft_single!("Real", "Real Media Plug-in Metafile"),
        "RSRC" => ft_single!("RSRC", "Mac OS Resource"),
        "RTF" => ft_single!("RTF", "Rich Text Format"),
        "RV" => ft_single!("Real", "Real Video"),
        "RW2" => ft_single!("TIFF", "Panasonic RAW 2"),
        "RWL" => ft_single!("TIFF", "Leica RAW"),
        "RWZ" => ft_single!("RWZ", "Rawzor compressed image"),
        "SEQ" => ft_single!("FLIR", "FLIR image Sequence"),
        "SKETCH" => ft_single!("ZIP", "Sketch design file"),
        "SO" => ft_single!("EXE", "Shared Object file"),
        "SR2" => ft_single!("TIFF", "Sony RAW Format 2"),
        "SRF" => ft_single!("TIFF", "Sony RAW Format"),
        "SRW" => ft_single!("TIFF", "Samsung RAW format"),
        "SVG" => ft_single!("XMP", "Scalable Vector Graphics"),
        "SWF" => ft_single!("SWF", "Shockwave Flash"),
        "TAR" => ft_single!("TAR", "TAR archive"),
        "THM" => ft_single!("JPEG", "Thumbnail"),
        "THMX" => ft_multi!(["ZIP", "FPX"], "Office Open XML Theme"),
        "TIF" => Lookup::Alias("TIFF"),
        "TIFF" => ft_single!("TIFF", "Tagged Image File Format"),
        "TNEF" => ft_single!("TNEF", "Transport Neural Encapsulation Format"),
        "TORRENT" => ft_single!("Torrent", "BitTorrent description file"),
        "TS" => Lookup::Alias("M2TS"),
        "TTC" => ft_single!("Font", "True Type Font Collection"),
        "TTF" => ft_single!("Font", "True Type Font"),
        "TUB" => Lookup::Alias("PSP"),
        "TXT" => ft_single!("TXT", "Text file"),
        "URL" => ft_single!("LNK", "Windows shortcut URL"),
        "VCARD" => ft_single!("VCard", "Virtual Card"),
        "VCF" => Lookup::Alias("VCARD"),
        "VOB" => ft_single!("MPEG", "Video Object"),
        "VNT" => ft_multi!(["FPX", "VCard"], "Scene7 Vignette or V-Note text file"),
        "VRD" => ft_single!("VRD", "Canon VRD Recipe Data"),
        "VSD" => ft_single!("FPX", "Microsoft Visio Drawing"),
        "WAV" => ft_single!("RIFF", "WAVeform (Windows digital audio)"),
        "WDP" => ft_single!("TIFF", "Windows Media Photo"),
        "WEBM" => ft_single!("MKV", "Google Web Movie"),
        "WEBP" => ft_single!("RIFF", "Google Web Picture"),
        "WMA" => ft_single!("ASF", "Windows Media Audio"),
        "WMF" => ft_single!("WMF", "Windows Metafile Format"),
        "WMV" => ft_single!("ASF", "Windows Media Video"),
        "WV" => ft_single!("WV", "WavPack Audio"),
        "WVP" => Lookup::Alias("WV"),
        "X3F" => ft_single!("X3F", "Sigma RAW format"),
        "XCF" => ft_single!("XCF", "GIMP native image format"),
        "XHTML" => ft_single!("HTML", "Extensible HyperText Markup Language"),
        "XISF" => ft_single!("XISF", "Extensible Image Serialization Format"),
        "XLA" => ft_single!("FPX", "Microsoft Excel Add-in"),
        "XLAM" => ft_multi!(["ZIP", "FPX"], "Office Open XML Spreadsheet Add-in Macro-enabled"),
        "XLS" => ft_single!("FPX", "Microsoft Excel Spreadsheet"),
        "XLSB" => ft_multi!(["ZIP", "FPX"], "Office Open XML Spreadsheet Binary"),
        "XLSM" => ft_multi!(["ZIP", "FPX"], "Office Open XML Spreadsheet Macro-enabled"),
        "XLSX" => ft_multi!(["ZIP", "FPX"], "Office Open XML Spreadsheet"),
        "XLT" => ft_single!("FPX", "Microsoft Excel Template"),
        "XLTM" => ft_multi!(["ZIP", "FPX"], "Office Open XML Spreadsheet Template Macro-enabled"),
        "XLTX" => ft_multi!(["ZIP", "FPX"], "Office Open XML Spreadsheet Template"),
        "XMP" => ft_single!("XMP", "Extensible Metadata Platform"),
        "VSDX" => ft_single!("ZIP", "Visio Diagram Document"),
        "WOFF" => ft_single!("Font", "Web Open Font Format"),
        "WOFF2" => ft_single!("Font", "Web Open Font Format 2"),
        "WPG" => ft_single!("WPG", "WordPerfect Graphics"),
        "WTV" => ft_single!("WTV", "Windows recorded TV show"),
        "ZIP" => ft_single!("ZIP", "ZIP archive"),
        _ => return None,
    })
}

/// `%moduleName` (ExifTool.pm:853-918). TYPE -> module dispatch.
///
/// Faithful to Perl `$module = $moduleName{$type}; $module = $type unless
/// defined $module;`: `''` => [`ModuleName::Core`], `'0'` =>
/// [`ModuleName::Unsupported`], an explicit module name => borrowed
/// `Module(<name>)`, and a type **absent** from `%moduleName` =>
/// `Module(Cow::Owned(<the type name itself>))` (Perl `$module = $type`).
/// There is no interning table and no `(unknown)` sentinel.
#[must_use]
pub fn module_for_type(file_type: &str) -> ModuleName {
    /// Borrow a `&'static` explicit `%moduleName` value into a `ModuleName`.
    const fn m(name: &'static str) -> ModuleName {
        ModuleName::Module(Cow::Borrowed(name))
    }
    match file_type {
        "AA" => m("Audible"),
        "ALIAS" => ModuleName::Unsupported,
        "AVC" => ModuleName::Unsupported,
        "BTF" => m("BigTIFF"),
        "BZ2" => ModuleName::Unsupported,
        "CRW" => m("CanonRaw"),
        "CHM" => m("EXE"),
        "COS" => m("CaptureOne"),
        "CZI" => m("ZISRAW"),
        "DEX" => ModuleName::Unsupported,
        "DOCX" => m("OOXML"),
        "DCX" => ModuleName::Unsupported,
        "DIR" => ModuleName::Unsupported,
        "DR4" => m("CanonVRD"),
        "DSS" => m("Olympus"),
        "DWF" => ModuleName::Unsupported,
        "DWG" => ModuleName::Unsupported,
        "DXF" => ModuleName::Unsupported,
        "EPS" => m("PostScript"),
        "EXIF" => ModuleName::Core,
        "EXR" => m("OpenEXR"),
        "EXV" => ModuleName::Core,
        "ICC" => m("ICC_Profile"),
        "IND" => m("InDesign"),
        "FIT" => m("Garmin"),
        "FLV" => m("Flash"),
        "FPF" => m("FLIR"),
        "FPX" => m("FlashPix"),
        "GZIP" => m("ZIP"),
        "HDR" => m("Radiance"),
        "JP2" => m("Jpeg2000"),
        "JPEG" => ModuleName::Core,
        "JUMBF" => m("Jpeg2000"),
        "JXL" => m("Jpeg2000"),
        "KVAR" => m("Kandao"),
        "LFP" => m("Lytro"),
        "LRI" => ModuleName::Unsupported,
        "MOV" => m("QuickTime"),
        "MKV" => m("Matroska"),
        "MP3" => m("ID3"),
        "MRW" => m("MinoltaRaw"),
        "NKA" => m("Nikon"),
        "OGG" => m("Ogg"),
        "ORF" => m("Olympus"),
        "PDB" => m("Palm"),
        "PCD" => m("PhotoCD"),
        "PFM2" => m("Other"),
        "PHP" => ModuleName::Unsupported,
        "PMP" => m("Sony"),
        "PS" => m("PostScript"),
        "PSD" => m("Photoshop"),
        "QTIF" => m("QuickTime"),
        "R3D" => m("Red"),
        "RAF" => m("FujiFilm"),
        "RAR" => m("ZIP"),
        "RAW" => m("KyoceraRaw"),
        "RWZ" => m("Rawzor"),
        "SWF" => m("Flash"),
        "TAR" => ModuleName::Unsupported,
        "TIFF" => ModuleName::Core,
        "TXT" => m("Text"),
        "VRD" => m("CanonVRD"),
        "WMF" => ModuleName::Unsupported,
        "WV" => m("WavPack"),
        "X3F" => m("SigmaRaw"),
        "XCF" => m("GIMP"),
        // Absent from %moduleName => Perl `$module = $type` (the type name
        // itself). Owned because it is the runtime type string.
        other => ModuleName::Module(Cow::Owned(other.to_string())),
    }
}

/// `%mimeType` (ExifTool.pm:616-847). 230 entries, verbatim (key ⇒ MIME
/// string). The hash is keyed by file TYPE (not extension); a TYPE absent
/// here yields `None`, exactly Perl `$mimeType{$fileType}` being `undef`
/// (which `SetFileType` turns into `'application/unknown'`,
/// ExifTool.pm:9704). Every value in the Perl source is a plain string
/// literal — there is no Perl-expression value — so this is a faithful
/// 1:1 transliteration. Some Perl keys are quoted/contain spaces
/// (`'3FR'`, `'7Z'`, `'Canon 1D RAW'`, `'DVR-MS'`) — ported as-is.
#[must_use]
pub(crate) fn mime_type_lookup(file_type: &str) -> Option<&'static str> {
    Some(match file_type {
        "3FR" => "image/x-hasselblad-3fr",                  // ExifTool.pm:617
        "7Z" => "application/x-7z-compressed",               // ExifTool.pm:618
        "AA" => "audio/audible",                             // ExifTool.pm:619
        "AAC" => "audio/aac",                                // ExifTool.pm:620
        "AAE" => "application/vnd.apple.photos",             // ExifTool.pm:621
        "AI" => "application/vnd.adobe.illustrator",         // ExifTool.pm:622
        "AIFF" => "audio/x-aiff",                            // ExifTool.pm:623
        "ALIAS" => "application/x-macos",                    // ExifTool.pm:624
        "APE" => "audio/x-monkeys-audio",                    // ExifTool.pm:625
        "APNG" => "image/apng",                              // ExifTool.pm:626
        "ASF" => "video/x-ms-asf",                           // ExifTool.pm:627
        "ARW" => "image/x-sony-arw",                         // ExifTool.pm:628
        "BMP" => "image/bmp",                                // ExifTool.pm:629
        "BPG" => "image/bpg",                                // ExifTool.pm:630
        "BTF" => "image/x-tiff-big",                         // ExifTool.pm:631
        "BZ2" => "application/bzip2",                         // ExifTool.pm:632
        "C2PA" => "application/c2pa",                         // ExifTool.pm:633
        "Canon 1D RAW" => "image/x-raw",                     // ExifTool.pm:634
        "CHM" => "application/x-chm",                         // ExifTool.pm:635
        "COS" => "application/octet-stream",                  // ExifTool.pm:636
        "CR2" => "image/x-canon-cr2",                         // ExifTool.pm:637
        "CR3" => "image/x-canon-cr3",                         // ExifTool.pm:638
        "CRM" => "video/x-canon-crm",                         // ExifTool.pm:639
        "CRW" => "image/x-canon-crw",                         // ExifTool.pm:640
        "CSV" => "text/csv",                                  // ExifTool.pm:641
        "CUR" => "image/x-cursor",                            // ExifTool.pm:642
        "CZI" => "image/x-zeiss-czi",                         // ExifTool.pm:643
        "DCP" => "application/octet-stream",                  // ExifTool.pm:644
        "DCR" => "image/x-kodak-dcr",                         // ExifTool.pm:645
        "DCX" => "image/dcx",                                 // ExifTool.pm:646
        "DEX" => "application/octet-stream",                  // ExifTool.pm:647
        "DFONT" => "application/x-dfont",                     // ExifTool.pm:648
        "DICOM" => "application/dicom",                       // ExifTool.pm:649
        "DIVX" => "video/divx",                               // ExifTool.pm:650
        "DJVU" => "image/vnd.djvu",                           // ExifTool.pm:651
        "DNG" => "image/x-adobe-dng",                         // ExifTool.pm:652
        "DOC" => "application/msword",                        // ExifTool.pm:653
        "DOCM" => "application/vnd.ms-word.document.macroEnabled.12", // ExifTool.pm:654
        "DOCX" => "application/vnd.openxmlformats-officedocument.wordprocessingml.document", // ExifTool.pm:655
        "DOT" => "application/msword",                        // ExifTool.pm:656
        "DOTM" => "application/vnd.ms-word.template.macroEnabledTemplate", // ExifTool.pm:657
        "DOTX" => "application/vnd.openxmlformats-officedocument.wordprocessingml.template", // ExifTool.pm:658
        "DPX" => "image/x-dpx",                               // ExifTool.pm:659
        "DR4" => "application/octet-stream",                  // ExifTool.pm:660
        "DS2" => "audio/x-ds2",                               // ExifTool.pm:661
        "DSF" => "audio/x-dsf",                               // ExifTool.pm:662
        "DSS" => "audio/x-dss",                               // ExifTool.pm:663
        "DV" => "video/x-dv",                                 // ExifTool.pm:664
        "DVR-MS" => "video/x-ms-dvr",                         // ExifTool.pm:665
        "DWF" => "model/vnd.dwf",                             // ExifTool.pm:666
        "DWG" => "image/vnd.dwg",                             // ExifTool.pm:667
        "DXF" => "application/dxf",                           // ExifTool.pm:668
        "EIP" => "application/x-captureone",                  // ExifTool.pm:669
        "EPS" => "application/postscript",                    // ExifTool.pm:670
        "ERF" => "image/x-epson-erf",                         // ExifTool.pm:671
        "EXE" => "application/octet-stream",                  // ExifTool.pm:672
        "EXR" => "image/x-exr",                               // ExifTool.pm:673
        "EXV" => "image/x-exv",                               // ExifTool.pm:674
        "FFF" => "image/x-hasselblad-fff",                    // ExifTool.pm:675
        "FIT" => "application/fit",                           // ExifTool.pm:676
        "FITS" => "image/fits",                               // ExifTool.pm:677
        "FLA" => "application/vnd.adobe.fla",                 // ExifTool.pm:678
        "FLAC" => "audio/flac",                               // ExifTool.pm:679
        "FLIF" => "image/flif",                               // ExifTool.pm:680
        "FLIR" => "image/x-flir-fff",                         // ExifTool.pm:681
        "FLV" => "video/x-flv",                               // ExifTool.pm:682
        "Font" => "application/x-font-type1",                 // ExifTool.pm:683
        "FPF" => "image/x-flir-fpf",                          // ExifTool.pm:684
        "FPX" => "image/vnd.fpx",                             // ExifTool.pm:685
        "GIF" => "image/gif",                                 // ExifTool.pm:686
        "GPR" => "image/x-gopro-gpr",                         // ExifTool.pm:687
        "GZIP" => "application/x-gzip",                        // ExifTool.pm:688
        "HDP" => "image/vnd.ms-photo",                        // ExifTool.pm:689
        "HDR" => "image/vnd.radiance",                        // ExifTool.pm:690
        "HTML" => "text/html",                                // ExifTool.pm:691
        "ICC" => "application/vnd.iccprofile",                // ExifTool.pm:692
        "ICO" => "image/x-icon",                              // ExifTool.pm:693
        "ICS" => "text/calendar",                             // ExifTool.pm:694
        "IDML" => "application/vnd.adobe.indesign-idml-package", // ExifTool.pm:695
        "IIQ" => "image/x-raw",                               // ExifTool.pm:696
        "IND" => "application/x-indesign",                    // ExifTool.pm:697
        "INX" => "application/x-indesign-interchange",        // ExifTool.pm:698
        "ISO" => "application/x-iso9660-image",               // ExifTool.pm:699
        "ITC" => "application/itunes",                        // ExifTool.pm:700
        "J2C" => "image/x-j2c",                               // ExifTool.pm:701
        "JNG" => "image/jng",                                 // ExifTool.pm:702
        "JP2" => "image/jp2",                                 // ExifTool.pm:703
        "JPEG" => "image/jpeg",                               // ExifTool.pm:704
        "JPH" => "image/jph",                                 // ExifTool.pm:705
        "JPM" => "image/jpm",                                 // ExifTool.pm:706
        "JPS" => "image/x-jps",                               // ExifTool.pm:707
        "JPX" => "image/jpx",                                 // ExifTool.pm:708
        "JSON" => "application/json",                          // ExifTool.pm:709
        "JUMBF" => "application/octet-stream",                 // ExifTool.pm:710
        "JXL" => "image/jxl",                                 // ExifTool.pm:711
        "JXR" => "image/jxr",                                 // ExifTool.pm:712
        "K25" => "image/x-kodak-k25",                          // ExifTool.pm:713
        "KDC" => "image/x-kodak-kdc",                          // ExifTool.pm:714
        "KEY" => "application/x-iwork-keynote-sffkey",         // ExifTool.pm:715
        "LFP" => "image/x-lytro-lfp",                          // ExifTool.pm:716
        "LIF" => "image/x-lif",                                // ExifTool.pm:717
        "LNK" => "application/octet-stream",                   // ExifTool.pm:718
        "LRI" => "image/x-light-lri",                          // ExifTool.pm:719
        "M2T" => "video/mpeg",                                 // ExifTool.pm:720
        "M2TS" => "video/m2ts",                                // ExifTool.pm:721
        "MAX" => "application/x-3ds",                           // ExifTool.pm:722
        "MEF" => "image/x-mamiya-mef",                          // ExifTool.pm:723
        "MIE" => "application/x-mie",                            // ExifTool.pm:724
        "MIFF" => "application/x-magick-image",                  // ExifTool.pm:725
        "MKA" => "audio/x-matroska",                             // ExifTool.pm:726
        "MKS" => "application/x-matroska",                       // ExifTool.pm:727
        "MKV" => "video/x-matroska",                             // ExifTool.pm:728
        "MNG" => "video/mng",                                    // ExifTool.pm:729
        "MOBI" => "application/x-mobipocket-ebook",              // ExifTool.pm:730
        "MOI" => "application/octet-stream",                     // ExifTool.pm:731
        "MOS" => "image/x-raw",                                  // ExifTool.pm:732
        "MOV" => "video/quicktime",                              // ExifTool.pm:733
        "MP3" => "audio/mpeg",                                   // ExifTool.pm:734
        "MP4" => "video/mp4",                                    // ExifTool.pm:735
        "MPC" => "audio/x-musepack",                             // ExifTool.pm:736
        "MPEG" => "video/mpeg",                                  // ExifTool.pm:737
        "MRC" => "image/x-mrc",                                  // ExifTool.pm:738
        "MRW" => "image/x-minolta-mrw",                          // ExifTool.pm:739
        "MXF" => "application/mxf",                               // ExifTool.pm:740
        "NEF" => "image/x-nikon-nef",                            // ExifTool.pm:741
        "NKSC" => "application/x-nikon-nxstudio",                // ExifTool.pm:742
        "NRW" => "image/x-nikon-nrw",                            // ExifTool.pm:743
        "NUMBERS" => "application/x-iwork-numbers-sffnumbers",   // ExifTool.pm:744
        "ODB" => "application/vnd.oasis.opendocument.database",  // ExifTool.pm:745
        "ODC" => "application/vnd.oasis.opendocument.chart",     // ExifTool.pm:746
        "ODF" => "application/vnd.oasis.opendocument.formula",   // ExifTool.pm:747
        "ODG" => "application/vnd.oasis.opendocument.graphics",  // ExifTool.pm:748
        "ODI" => "application/vnd.oasis.opendocument.image",     // ExifTool.pm:749
        "ODP" => "application/vnd.oasis.opendocument.presentation", // ExifTool.pm:750
        "ODS" => "application/vnd.oasis.opendocument.spreadsheet", // ExifTool.pm:751
        "ODT" => "application/vnd.oasis.opendocument.text",      // ExifTool.pm:752
        "OGG" => "audio/ogg",                                    // ExifTool.pm:753
        "OGV" => "video/ogg",                                    // ExifTool.pm:754
        "ONP" => "application/on1",                               // ExifTool.pm:755
        "ORF" => "image/x-olympus-orf",                          // ExifTool.pm:756
        "OTF" => "application/font-otf",                          // ExifTool.pm:757
        "PAGES" => "application/x-iwork-pages-sffpages",         // ExifTool.pm:758
        "PBM" => "image/x-portable-bitmap",                      // ExifTool.pm:759
        "PCAP" => "application/vnd.tcpdump.pcap",                // ExifTool.pm:760
        "PCD" => "image/x-photo-cd",                             // ExifTool.pm:761
        "PCX" => "image/pcx",                                     // ExifTool.pm:762
        "PDB" => "application/vnd.palm",                          // ExifTool.pm:763
        "PDF" => "application/pdf",                               // ExifTool.pm:764
        "PEF" => "image/x-pentax-pef",                           // ExifTool.pm:765
        "PFA" => "application/x-font-type1",                      // ExifTool.pm:766
        "PGF" => "image/pgf",                                     // ExifTool.pm:767
        "PGM" => "image/x-portable-graymap",                     // ExifTool.pm:768
        "PHP" => "application/x-httpd-php",                       // ExifTool.pm:769
        "PICT" => "image/pict",                                   // ExifTool.pm:770
        "PLIST" => "application/xml",                              // ExifTool.pm:771
        "PMP" => "image/x-sony-pmp",                              // ExifTool.pm:772
        "PNG" => "image/png",                                     // ExifTool.pm:773
        "POT" => "application/vnd.ms-powerpoint",                 // ExifTool.pm:774
        "POTM" => "application/vnd.ms-powerpoint.template.macroEnabled.12", // ExifTool.pm:775
        "POTX" => "application/vnd.openxmlformats-officedocument.presentationml.template", // ExifTool.pm:776
        "PPAM" => "application/vnd.ms-powerpoint.addin.macroEnabled.12", // ExifTool.pm:777
        "PPAX" => "application/vnd.openxmlformats-officedocument.presentationml.addin", // ExifTool.pm:778
        "PPM" => "image/x-portable-pixmap",                       // ExifTool.pm:779
        "PPS" => "application/vnd.ms-powerpoint",                 // ExifTool.pm:780
        "PPSM" => "application/vnd.ms-powerpoint.slideshow.macroEnabled.12", // ExifTool.pm:781
        "PPSX" => "application/vnd.openxmlformats-officedocument.presentationml.slideshow", // ExifTool.pm:782
        "PPT" => "application/vnd.ms-powerpoint",                 // ExifTool.pm:783
        "PPTM" => "application/vnd.ms-powerpoint.presentation.macroEnabled.12", // ExifTool.pm:784
        "PPTX" => "application/vnd.openxmlformats-officedocument.presentationml.presentation", // ExifTool.pm:785
        "PS" => "application/postscript",                         // ExifTool.pm:786
        "PSD" => "application/vnd.adobe.photoshop",               // ExifTool.pm:787
        "PSP" => "image/x-paintshoppro",                          // ExifTool.pm:788
        "QTIF" => "image/x-quicktime",                            // ExifTool.pm:789
        "R3D" => "video/x-red-r3d",                               // ExifTool.pm:790
        "RA" => "audio/x-pn-realaudio",                           // ExifTool.pm:791
        "RAF" => "image/x-fujifilm-raf",                          // ExifTool.pm:792
        "RAM" => "audio/x-pn-realaudio",                          // ExifTool.pm:793
        "RAR" => "application/x-rar-compressed",                  // ExifTool.pm:794
        "RAW" => "image/x-raw",                                   // ExifTool.pm:795
        "RM" => "application/vnd.rn-realmedia",                   // ExifTool.pm:796
        "RMVB" => "application/vnd.rn-realmedia-vbr",             // ExifTool.pm:797
        "RPM" => "audio/x-pn-realaudio-plugin",                   // ExifTool.pm:798
        "RSRC" => "application/ResEdit",                          // ExifTool.pm:799
        "RTF" => "text/rtf",                                      // ExifTool.pm:800
        "RV" => "video/vnd.rn-realvideo",                         // ExifTool.pm:801
        "RW2" => "image/x-panasonic-rw2",                         // ExifTool.pm:802
        "RWL" => "image/x-leica-rwl",                             // ExifTool.pm:803
        "RWZ" => "image/x-rawzor",                                // ExifTool.pm:804
        "SEQ" => "image/x-flir-seq",                              // ExifTool.pm:805
        "SKETCH" => "application/sketch",                         // ExifTool.pm:806
        "SR2" => "image/x-sony-sr2",                              // ExifTool.pm:807
        "SRF" => "image/x-sony-srf",                              // ExifTool.pm:808
        "SRW" => "image/x-samsung-srw",                           // ExifTool.pm:809
        "SVG" => "image/svg+xml",                                 // ExifTool.pm:810
        "SWF" => "application/x-shockwave-flash",                 // ExifTool.pm:811
        "TAR" => "application/x-tar",                              // ExifTool.pm:812
        "THMX" => "application/vnd.ms-officetheme",               // ExifTool.pm:813
        "TIFF" => "image/tiff",                                   // ExifTool.pm:814
        "TNEF" => "application/vnd.ms-tnef",                      // ExifTool.pm:815
        "Torrent" => "application/x-bittorrent",                  // ExifTool.pm:816
        "TTC" => "application/font-ttf",                          // ExifTool.pm:817
        "TTF" => "application/font-ttf",                          // ExifTool.pm:818
        "TXT" => "text/plain",                                    // ExifTool.pm:819
        "VCard" => "text/vcard",                                  // ExifTool.pm:820
        "VRD" => "application/octet-stream",                      // ExifTool.pm:821
        "VSD" => "application/x-visio",                            // ExifTool.pm:822
        "VSDX" => "application/vnd.ms-visio.drawing",             // ExifTool.pm:823
        "WDP" => "image/vnd.ms-photo",                            // ExifTool.pm:824
        "WEBM" => "video/webm",                                   // ExifTool.pm:825
        "WMA" => "audio/x-ms-wma",                                // ExifTool.pm:826
        "WMF" => "application/x-wmf",                              // ExifTool.pm:827
        "WMV" => "video/x-ms-wmv",                                // ExifTool.pm:828
        "WPG" => "image/x-wpg",                                   // ExifTool.pm:829
        "WTV" => "video/x-ms-wtv",                                // ExifTool.pm:830
        "WV" => "audio/x-wavpack",                                // ExifTool.pm:831
        "X3F" => "image/x-sigma-x3f",                             // ExifTool.pm:832
        "XCF" => "image/x-xcf",                                   // ExifTool.pm:833
        "XISF" => "image/x-xisf",                                 // ExifTool.pm:834
        "XLA" => "application/vnd.ms-excel",                      // ExifTool.pm:835
        "XLAM" => "application/vnd.ms-excel.addin.macroEnabled.12", // ExifTool.pm:836
        "XLS" => "application/vnd.ms-excel",                      // ExifTool.pm:837
        "XLSB" => "application/vnd.ms-excel.sheet.binary.macroEnabled.12", // ExifTool.pm:838
        "XLSM" => "application/vnd.ms-excel.sheet.macroEnabled.12", // ExifTool.pm:839
        "XLSX" => "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet", // ExifTool.pm:840
        "XLT" => "application/vnd.ms-excel",                      // ExifTool.pm:841
        "XLTM" => "application/vnd.ms-excel.template.macroEnabled.12", // ExifTool.pm:842
        "XLTX" => "application/vnd.openxmlformats-officedocument.spreadsheetml.template", // ExifTool.pm:843
        "XML" => "application/xml",                                // ExifTool.pm:844
        "XMP" => "application/rdf+xml",                            // ExifTool.pm:845
        "ZIP" => "application/zip",                                // ExifTool.pm:846
        _ => return None,
    })
}

/// `%fileTypeExt` (ExifTool.pm:590-600), verbatim. The typical extension
/// for a file TYPE *when it differs from the type name* — exactly 9 keys.
/// "case is not significant" (ExifTool.pm:589 comment): the values are the
/// lowercase Perl literals; `SetFileType` uppercases (`uc $normExt`) then
/// PrintConv `lc` (ExifTool.pm:1433), so case is round-tripped faithfully.
/// A TYPE absent here yields `None` ⇒ Perl `$normExt = $fileType`
/// (ExifTool.pm:9698,9720).
#[must_use]
pub(crate) fn file_type_ext_lookup(file_type: &str) -> Option<&'static str> {
    Some(match file_type {
        "Canon 1D RAW" => "tif", // ExifTool.pm:591
        "DICOM" => "dcm",        // ExifTool.pm:592
        "FLIR" => "fff",         // ExifTool.pm:593
        "GZIP" => "gz",          // ExifTool.pm:594
        "JPEG" => "jpg",         // ExifTool.pm:595
        "M2TS" => "mts",         // ExifTool.pm:596
        "MPEG" => "mpg",         // ExifTool.pm:597
        "TIFF" => "tif",         // ExifTool.pm:598
        "VCard" => "vcf",        // ExifTool.pm:599
        _ => return None,
    })
}

/// Faithful `@fileTypeLookup{$key}` *root-type-as-string* accessor for the
/// `SetFileType` sub-type-by-ext block (ExifTool.pm:9686-9692).
///
/// In Perl, a `%fileTypeLookup` value is either a string alias
/// (`AIF => 'AIFF'`), a single-type arrayref (`['TYPE','desc']`), or a
/// multi-type arrayref whose first element is itself an arrayref
/// (`[['ZIP','FPX'],'desc']`). The block tests:
/// ```text
///   my ($f,$e) = @fileTypeLookup{$fileType,$ext};
///   if (ref $f eq 'ARRAY' and ref $e eq 'ARRAY' and $$f[0] eq $$e[0]) { ...
/// ```
/// `ref $X eq 'ARRAY'` is true for single AND multi rows (both arrayrefs)
/// but false for a string alias. `$$X[0]` is then string-compared: for a
/// single row it is the TYPE string; for a multi row it is an *arrayref*,
/// which `eq` (string comparison) can never equal another row's first
/// element across keys (and never equals a single row's string). So the
/// `$$f[0] eq $$e[0]` test succeeds *only* when BOTH rows are single-type.
///
/// This returns `Some(types[0])` for a [`Lookup::Single`] (Perl: `$$X[0]`
/// is the TYPE string), and `None` for [`Lookup::Multi`] (Perl: `$$X[0]`
/// is an arrayref — never string-equal) or [`Lookup::Alias`]/absent key
/// (Perl: `ref` test fails). Direct hash access — NO alias resolution
/// (Perl `@fileTypeLookup{...}` is a plain slice).
#[must_use]
pub(crate) fn file_type_lookup_root(key: &str) -> Option<&'static str> {
    match file_type_lookup(key)? {
        Lookup::Single(types, _) => Some(types[0]),
        // Multi: Perl `$$X[0]` is an arrayref ⇒ never string-`eq` ⇒ as if
        // there is no comparable root. Alias: Perl `ref` test fails.
        Lookup::Multi(..) | Lookup::Alias(_) => None,
    }
}

/// `defined $fileTypeLookup{$key}` (the `not $fileTypeLookup{$$f[0]}` test,
/// ExifTool.pm:9690): does the key exist in `%fileTypeLookup` at all
/// (any value shape: alias, single, or multi)? Direct hash access, no
/// alias resolution. Perl `not $hash{$k}` is true when the key is absent
/// (undef) — every present `%fileTypeLookup` value is a truthy arrayref or
/// non-empty string, so "defined" == "truthy" here, exactly.
#[must_use]
pub(crate) fn file_type_lookup_defined(key: &str) -> bool {
    file_type_lookup(key).is_some()
}

/// `@fileTypes` master scan order (ExifTool.pm:197-204), verbatim. The
/// content-gated selection loop (`ExtractInfo`) appends every entry not in
/// the `GetFileType` candidate list (in this order) so all types are tested;
/// when there is no candidate at all, this whole list is scanned. Order is
/// load-bearing — do not sort.
pub(crate) const FILE_TYPES: &[&str] = &[
    "JPEG", "EXV", "CRW", "DR4", "TIFF", "GIF", "MRW", "RAF", "X3F", "JP2",
    "PNG", "MIE", "MIFF", "PS", "PDF", "PSD", "XMP", "BMP", "WPG", "BPG",
    "PPM", "WV", "RIFF", "AIFF", "ASF", "MOV", "MPEG", "Real", "SWF", "PSP",
    "FLV", "OGG", "FLAC", "APE", "MPC", "MKV", "MXF", "DV", "PMP", "IND",
    "PGF", "ICC", "ITC", "FLIR", "FLIF", "FPF", "LFP", "HTML", "VRD", "RTF",
    "FIT", "FITS", "XISF", "XCF", "DSF", "DSS", "QTIF", "FPX", "PICT", "ZIP",
    "GZIP", "PLIST", "RAR", "7Z", "BZ2", "CZI", "TAR", "EXE", "EXR", "HDR",
    "CHM", "LNK", "WMF", "AVC", "DEX", "DPX", "RAW", "Font", "JUMBF", "RSRC",
    "M2TS", "MacOS", "PHP", "PCX", "DCX", "DWF", "DWG", "DXF", "WTV",
    "Torrent", "VCard", "LRI", "R3D", "AA", "PDB", "PFM2", "MRC", "LIF",
    "JXL", "MOI", "ISO", "ALIAS", "PCAP", "JSON", "MP3", "KVAR", "TNEF",
    "DICOM", "PCD", "NKA", "ICO", "TXT", "AAC",
];

/// Resolve a runtime type/extension string to its canonical interned
/// `&'static str`, if it is a known file TYPE. Used only by the
/// `detection_candidates` end-of-list `recognizedExt` terminal
/// (ExifTool.pm:3023-3024, `$type = $recognizedExt`) to keep the candidate
/// type a `&'static str` without any `(unknown)` sentinel.
///
/// Faithful coverage: every `@fileTypes` member, plus the `%fileTypeLookup`
/// type-name keys whose `%moduleName` is an explicit `''`/`'0'` and which
/// have **no** `%magicNumber` entry (audited against ExifTool.pm:853-918 +
/// 924-1048: the only such type is `DIR`). Only those can ever be a
/// `recognizedExt`. Returns `None` for anything else.
#[must_use]
pub(crate) fn file_types_static(name: &str) -> Option<&'static str> {
    if let Some(&s) = FILE_TYPES.iter().find(|&&t| t == name) {
        return Some(s);
    }
    // `recognizedExt`-eligible type not present in @fileTypes (only DIR).
    match name {
        "DIR" => Some("DIR"),
        _ => None,
    }
}

/// `noMagic{MXF}=1; noMagic{DV}=1` (ExifTool.pm:2987-2988): skip the magic
/// gate for these types even though they have a `%magicNumber` entry.
#[must_use]
pub fn is_no_magic(file_type: &str) -> bool {
    matches!(file_type, "MXF" | "DV")
}

/// `%weakMagic = ( MP3 => 1 )` (ExifTool.pm:~1050).
#[must_use]
pub fn is_weak_magic(file_type: &str) -> bool {
    file_type == "MP3"
}

/// `%magicNumber` (ExifTool.pm:928-1047). 114 entries. Each Perl regex is
/// hand-translated to a byte matcher anchored at byte 0 (Perl `/^.../s`, so
/// `.` matches ANY byte including newline). A type with NO entry returns
/// [`Magic::NoSignature`] (NOT a match — there is simply no gate).
#[must_use]
pub fn magic(file_type: &str, head: &[u8]) -> Magic {
    let ok = match file_type {
        // AA: '.{4}\x57\x90\x75\x36'
        "AA" => m_seq(head, &[Any, Any, Any, Any, B(0x57), B(0x90), B(0x75), B(0x36)]),
        // AAC: '\xff[\xf0\xf1]'
        "AAC" => m_seq(head, &[B(0xff), Set(&[0xf0, 0xf1])]),
        // AIFF: '(FORM....AIF[FC]|AT&TFORM)'
        "AIFF" => {
            m_seq(
                head,
                &[
                    Lit(b"FORM"),
                    Any,
                    Any,
                    Any,
                    Any,
                    Lit(b"AIF"),
                    Set(b"FC"),
                ],
            ) || head.starts_with(b"AT&TFORM")
        }
        // ALIAS: "book\0\0\0\0mark\0\0\0\0"  (literal, NUL bytes)
        "ALIAS" => head.starts_with(b"book\0\0\0\0mark\0\0\0\0"),
        // APE: '(MAC |APETAGEX|ID3)'
        "APE" => {
            head.starts_with(b"MAC ")
                || head.starts_with(b"APETAGEX")
                || head.starts_with(b"ID3")
        }
        // ASF: 16-byte GUID
        "ASF" => head.starts_with(&[
            0x30, 0x26, 0xb2, 0x75, 0x8e, 0x66, 0xcf, 0x11, 0xa6, 0xd9, 0x00, 0xaa, 0x00, 0x62,
            0xce, 0x6c,
        ]),
        // AVC: '\+A\+V\+C\+'  (literal "+A+V+C+")
        "AVC" => head.starts_with(b"+A+V+C+"),
        // Torrent: 'd\d+:\w+'
        "Torrent" => m_seq(head, &[B(b'd'), Plus(dig()), B(b':'), Plus(wrd())]),
        // BMP: 'BM'
        "BMP" => head.starts_with(b"BM"),
        // BPG: "BPG\xfb"
        "BPG" => head.starts_with(&[b'B', b'P', b'G', 0xfb]),
        // BTF: '(II\x2b\0|MM\0\x2b)'
        "BTF" => {
            head.starts_with(&[b'I', b'I', 0x2b, 0x00])
                || head.starts_with(&[b'M', b'M', 0x00, 0x2b])
        }
        // BZ2: 'BZh[1-9]\x31\x41\x59\x26\x53\x59'
        "BZ2" => m_seq(
            head,
            &[
                Lit(b"BZh"),
                Range(b'1', b'9'),
                B(0x31),
                B(0x41),
                B(0x59),
                B(0x26),
                B(0x53),
                B(0x59),
            ],
        ),
        // CHM: 'ITSF.{20}\x10\xfd\x01\x7c\xaa\x7b\xd0\x11\x9e\x0c\0\xa0\xc9\x22\xe6\xec'
        "CHM" => m_seq(
            head,
            &[
                Lit(b"ITSF"),
                AnyN(20),
                B(0x10),
                B(0xfd),
                B(0x01),
                B(0x7c),
                B(0xaa),
                B(0x7b),
                B(0xd0),
                B(0x11),
                B(0x9e),
                B(0x0c),
                B(0x00),
                B(0xa0),
                B(0xc9),
                B(0x22),
                B(0xe6),
                B(0xec),
            ],
        ),
        // CRW: '(II|MM).{4}HEAP(CCDR|JPGM)'
        "CRW" => {
            m_seq(
                head,
                &[Lit(b"II"), Any, Any, Any, Any, Lit(b"HEAPCCDR")],
            ) || m_seq(
                head,
                &[Lit(b"II"), Any, Any, Any, Any, Lit(b"HEAPJPGM")],
            ) || m_seq(
                head,
                &[Lit(b"MM"), Any, Any, Any, Any, Lit(b"HEAPCCDR")],
            ) || m_seq(
                head,
                &[Lit(b"MM"), Any, Any, Any, Any, Lit(b"HEAPJPGM")],
            )
        }
        // CZI: 'ZISRAWFILE\0{6}'
        "CZI" => head.starts_with(b"ZISRAWFILE\0\0\0\0\0\0"),
        // DCX: '\xb1\x68\xde\x3a'
        "DCX" => head.starts_with(&[0xb1, 0x68, 0xde, 0x3a]),
        // DEX: "dex\n035\0"
        "DEX" => head.starts_with(b"dex\n035\0"),
        // DICOM: '(.{128}DICM|\0[\x02\x04\x06\x08]\0[\0-\x20]|[\x02\x04\x06\x08]\0[\0-\x20]\0)'
        "DICOM" => {
            m_seq(head, &[AnyN(128), Lit(b"DICM")])
                || m_seq(
                    head,
                    &[B(0x00), Set(&[0x02, 0x04, 0x06, 0x08]), B(0x00), Range(0x00, 0x20)],
                )
                || m_seq(
                    head,
                    &[Set(&[0x02, 0x04, 0x06, 0x08]), B(0x00), Range(0x00, 0x20), B(0x00)],
                )
        }
        // DOCX: 'PK\x03\x04'
        "DOCX" => head.starts_with(&[b'P', b'K', 0x03, 0x04]),
        // DPX: '(SDPX|XPDS)'
        "DPX" => head.starts_with(b"SDPX") || head.starts_with(b"XPDS"),
        // DR4: 'IIII[\x04|\x05]\0\x04\0'  (char class includes '|')
        "DR4" => m_seq(
            head,
            &[Lit(b"IIII"), Set(&[0x04, b'|', 0x05]), B(0x00), B(0x04), B(0x00)],
        ),
        // DSF: 'DSD \x1c\0{7}.{16}fmt '
        "DSF" => m_seq(
            head,
            &[
                Lit(b"DSD "),
                B(0x1c),
                B(0x00),
                B(0x00),
                B(0x00),
                B(0x00),
                B(0x00),
                B(0x00),
                B(0x00),
                AnyN(16),
                Lit(b"fmt "),
            ],
        ),
        // DSS: '(\x02dss|\x03ds2)'
        "DSS" => {
            m_seq(head, &[B(0x02), Lit(b"dss")]) || m_seq(head, &[B(0x03), Lit(b"ds2")])
        }
        // DV: '\x1f\x07\0[\x3f\xbf]'
        "DV" => m_seq(head, &[B(0x1f), B(0x07), B(0x00), Set(&[0x3f, 0xbf])]),
        // DWF: '\(DWF V\d'
        "DWF" => m_seq(head, &[Lit(b"(DWF V"), Digit]),
        // DWG: 'AC10\d{2}\0'
        "DWG" => m_seq(head, &[Lit(b"AC10"), Digit, Digit, B(0x00)]),
        // DXF: '\s*0\s+\0?\s*SECTION\s+2\s+HEADER'
        "DXF" => m_seq(
            head,
            &[
                StarWs,
                B(b'0'),
                PlusWs,
                OptByte(0x00),
                StarWs,
                Lit(b"SECTION"),
                PlusWs,
                B(b'2'),
                PlusWs,
                Lit(b"HEADER"),
            ],
        ),
        // EPS: '(%!PS|%!Ad|\xc5\xd0\xd3\xc6)'
        "EPS" => {
            head.starts_with(b"%!PS")
                || head.starts_with(b"%!Ad")
                || head.starts_with(&[0xc5, 0xd0, 0xd3, 0xc6])
        }
        // EXE: '(MZ|\xca\xfe\xba\xbe|\xfe\xed\xfa[\xce\xcf]|[\xce\xcf]\xfa\xed\xfe|Joy!peff|\x7fELF|#!\s*/\S*bin/|!<arch>\x0a)'
        "EXE" => {
            head.starts_with(b"MZ")
                || head.starts_with(&[0xca, 0xfe, 0xba, 0xbe])
                || m_seq(head, &[B(0xfe), B(0xed), B(0xfa), Set(&[0xce, 0xcf])])
                || m_seq(head, &[Set(&[0xce, 0xcf]), B(0xfa), B(0xed), B(0xfe)])
                || head.starts_with(b"Joy!peff")
                || m_seq(head, &[B(0x7f), Lit(b"ELF")])
                || m_seq(head, &[Lit(b"#!"), StarWs, B(b'/'), StarNonWs, Lit(b"bin/")])
                || head.starts_with(b"!<arch>\x0a")
        }
        // EXIF: '(II\x2a\0|MM\0\x2a)'
        "EXIF" => {
            head.starts_with(&[b'I', b'I', 0x2a, 0x00])
                || head.starts_with(&[b'M', b'M', 0x00, 0x2a])
        }
        // EXR: '\x76\x2f\x31\x01'
        "EXR" => head.starts_with(&[0x76, 0x2f, 0x31, 0x01]),
        // EXV: '\xff\x01Exiv2'
        "EXV" => m_seq(head, &[B(0xff), B(0x01), Lit(b"Exiv2")]),
        // FIT: '.{8}\.FIT'
        "FIT" => m_seq(head, &[AnyN(8), Lit(b".FIT")]),
        // FITS: 'SIMPLE  = {20}T'  (literal "SIMPLE  =" then 20 spaces then "T")
        "FITS" => {
            let mut v = Vec::with_capacity(30);
            v.extend_from_slice(b"SIMPLE  =");
            v.extend(std::iter::repeat(b' ').take(20));
            v.push(b'T');
            head.starts_with(&v)
        }
        // FLAC: '(fLaC|ID3)'
        "FLAC" => head.starts_with(b"fLaC") || head.starts_with(b"ID3"),
        // FLIF: 'FLIF[0-\x6f][0-2]'
        "FLIF" => m_seq(head, &[Lit(b"FLIF"), Range(b'0', 0x6f), Range(b'0', b'2')]),
        // FLIR: '[AF]FF\0'
        "FLIR" => m_seq(head, &[Set(b"AF"), Lit(b"FF"), B(0x00)]),
        // FLV: 'FLV\x01'
        "FLV" => head.starts_with(&[b'F', b'L', b'V', 0x01]),
        // Font: see note — alternation of font signatures.
        "Font" => magic_font(head),
        // FPF: 'FPF Public Image Format\0'
        "FPF" => head.starts_with(b"FPF Public Image Format\0"),
        // FPX: '\xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1'
        "FPX" => head.starts_with(&[0xd0, 0xcf, 0x11, 0xe0, 0xa1, 0xb1, 0x1a, 0xe1]),
        // GIF: 'GIF8[79]a'
        "GIF" => m_seq(head, &[Lit(b"GIF8"), Set(b"79"), B(b'a')]),
        // GZIP: '\x1f\x8b\x08'
        "GZIP" => head.starts_with(&[0x1f, 0x8b, 0x08]),
        // HDR: '#\?(RADIANCE|RGBE)\x0a'
        "HDR" => {
            m_seq(head, &[Lit(b"#?RADIANCE"), B(0x0a)])
                || m_seq(head, &[Lit(b"#?RGBE"), B(0x0a)])
        }
        // HTML: '(\xef\xbb\xbf)?\s*(?i)<(!DOCTYPE\s+HTML|HTML|\?xml)'
        "HTML" => magic_html(head),
        // ICC: '.{12}(scnr|mntr|prtr|link|spac|abst|nmcl|nkpf|cenc|mid |mlnk|mvis)
        //       (XYZ |Lab |Luv |YCbr|Yxy |RGB |GRAY|HSV |HLS |CMYK|CMY |[2-9A-F]CLR|nc..|\0{4}){2}'
        "ICC" => magic_icc(head),
        // ICO: '\0\0[\x01\x02]\0[^0]\0'
        "ICO" => m_seq(
            head,
            &[B(0x00), B(0x00), Set(&[0x01, 0x02]), B(0x00), NotByte(b'0'), B(0x00)],
        ),
        // IND: 16-byte GUID
        "IND" => head.starts_with(&[
            0x06, 0x06, 0xed, 0xf5, 0xd8, 0x1d, 0x46, 0xe5, 0xbd, 0x31, 0xef, 0xe7, 0xfe, 0x74,
            0xb7, 0x1d,
        ]),
        // ITC: '.{4}itch'
        "ITC" => m_seq(head, &[AnyN(4), Lit(b"itch")]),
        // JP2: '(\0\0\0\x0cjP(  |\x1a\x1a)\x0d\x0a\x87\x0a|\xff\x4f\xff\x51\0)'
        "JP2" => {
            m_seq(
                head,
                &[
                    B(0x00),
                    B(0x00),
                    B(0x00),
                    B(0x0c),
                    Lit(b"jP"),
                    Lit(b"  "),
                    B(0x0d),
                    B(0x0a),
                    B(0x87),
                    B(0x0a),
                ],
            ) || m_seq(
                head,
                &[
                    B(0x00),
                    B(0x00),
                    B(0x00),
                    B(0x0c),
                    Lit(b"jP"),
                    B(0x1a),
                    B(0x1a),
                    B(0x0d),
                    B(0x0a),
                    B(0x87),
                    B(0x0a),
                ],
            ) || head.starts_with(&[0xff, 0x4f, 0xff, 0x51, 0x00])
        }
        // JPEG: '\xff\xd8\xff'
        "JPEG" => head.starts_with(&[0xff, 0xd8, 0xff]),
        // JSON: '(\xef\xbb\xbf)?\s*(\[\s*)?\{\s*"[^"]*"\s*:'
        "JSON" => magic_json(head),
        // JUMBF: '.{4}jumb\0.{3}jumd'
        "JUMBF" => m_seq(
            head,
            &[AnyN(4), Lit(b"jumb"), B(0x00), AnyN(3), Lit(b"jumd")],
        ),
        // JXL: '(\xff\x0a|\0\0\0\x0cJXL \x0d\x0a......ftypjxl )'
        "JXL" => {
            head.starts_with(&[0xff, 0x0a])
                || m_seq(
                    head,
                    &[
                        B(0x00),
                        B(0x00),
                        B(0x00),
                        B(0x0c),
                        Lit(b"JXL "),
                        B(0x0d),
                        B(0x0a),
                        AnyN(6),
                        Lit(b"ftypjxl "),
                    ],
                )
        }
        // KVAR: '.{2}\0\0[A-Z].{31}(CHAR|BOOL|[US](8|16|32|64)|FLOAT|DOUBLE)\0'
        "KVAR" => magic_kvar(head),
        // LFP: '\x89LFP\x0d\x0a\x1a\x0a'
        "LFP" => m_seq(
            head,
            &[B(0x89), Lit(b"LFP"), B(0x0d), B(0x0a), B(0x1a), B(0x0a)],
        ),
        // LIF: '\x70\0{3}.{4}\x2a.{4}<\0'
        "LIF" => m_seq(
            head,
            &[
                B(0x70),
                B(0x00),
                B(0x00),
                B(0x00),
                AnyN(4),
                B(0x2a),
                AnyN(4),
                B(b'<'),
                B(0x00),
            ],
        ),
        // LNK: '(.{4}\x01\x14\x02\0{5}\xc0\0{6}\x46|\[[InternetShortcut\][\x0d\x0a])'
        "LNK" => magic_lnk(head),
        // LRI: 'LELR \0'
        "LRI" => head.starts_with(b"LELR \0"),
        // M2TS: '.{0,191}?\x47(.{187}|.{191})\x47(.{187}|.{191})\x47'
        "M2TS" => magic_m2ts(head),
        // MacOS: '\0\x05\x16\x07\0.\0\0Mac OS X        '  (8 trailing spaces)
        "MacOS" => m_seq(
            head,
            &[
                B(0x00),
                B(0x05),
                B(0x16),
                B(0x07),
                B(0x00),
                Any,
                B(0x00),
                B(0x00),
                Lit(b"Mac OS X        "),
            ],
        ),
        // MIE: '~[\x10\x18]\x04.0MIE'
        "MIE" => m_seq(
            head,
            &[B(b'~'), Set(&[0x10, 0x18]), B(0x04), Any, B(b'0'), Lit(b"MIE")],
        ),
        // MIFF: 'id=ImageMagick'
        "MIFF" => head.starts_with(b"id=ImageMagick"),
        // MKV: '\x1a\x45\xdf\xa3'
        "MKV" => head.starts_with(&[0x1a, 0x45, 0xdf, 0xa3]),
        // MOV: '.{4}(free|skip|wide|ftyp|pnot|PICT|pict|moov|mdat|junk|uuid)'
        "MOV" => {
            head.len() >= 8
                && matches!(
                    &head[4..8],
                    b"free" | b"skip" | b"wide" | b"ftyp" | b"pnot" | b"PICT" | b"pict"
                        | b"moov" | b"mdat" | b"junk" | b"uuid"
                )
        }
        // MPC: '(MP\+|ID3)'
        "MPC" => head.starts_with(b"MP+") || head.starts_with(b"ID3"),
        // MOI: 'V6'
        "MOI" => head.starts_with(b"V6"),
        // MPEG: '\0\0\x01[\xb0-\xbf]'
        "MPEG" => m_seq(head, &[B(0x00), B(0x00), B(0x01), Range(0xb0, 0xbf)]),
        // MRC: '.{64}[\x01\x02\x03]\0\0\0[\x01\x02\x03]\0\0\0[\x01\x02\x03]\0\0\0
        //       .{132}MAP[\0 ](\x44\x44|\x44\x41|\x11\x11)\0\0'
        "MRC" => magic_mrc(head),
        // MRW: '\0MR[MI]'
        "MRW" => m_seq(head, &[B(0x00), Lit(b"MR"), Set(b"MI")]),
        // MXF: '\x06\x0e\x2b\x34\x02\x05\x01\x01\x0d\x01\x02'
        "MXF" => {
            head.starts_with(&[0x06, 0x0e, 0x2b, 0x34, 0x02, 0x05, 0x01, 0x01, 0x0d, 0x01, 0x02])
        }
        // NKA: 'NIKONADJ'
        "NKA" => head.starts_with(b"NIKONADJ"),
        // OGG: '(OggS|ID3)'
        "OGG" => head.starts_with(b"OggS") || head.starts_with(b"ID3"),
        // ORF: '(II|MM)'
        "ORF" => head.starts_with(b"II") || head.starts_with(b"MM"),
        // PCAP: '\xa1\xb2(\xc3\xd4|\x3c\x4d)\0.\0.|(\xd4\xc3|\x4d\x3c)\xb2\xa1.\0.\0|
        //        \x0a\x0d\x0d\x0a.{4}(\x1a\x2b\x3c\x4d|\x4d\x3c\x2b\x1a)|GMBU\0\x02'
        "PCAP" => magic_pcap(head),
        // PCX: '\x0a[\0-\x05]\x01[\x01\x02\x04\x08].{64}[\0-\x02]'
        "PCX" => m_seq(
            head,
            &[
                B(0x0a),
                Range(0x00, 0x05),
                B(0x01),
                Set(&[0x01, 0x02, 0x04, 0x08]),
                AnyN(64),
                Range(0x00, 0x02),
            ],
        ),
        // PDB: '.{60}(<24 four-byte tags>)'
        "PDB" => magic_pdb(head),
        // PDF: '\s*%PDF-\d+\.\d+'
        "PDF" => m_seq(
            head,
            &[StarWs, Lit(b"%PDF-"), Plus(dig()), B(b'.'), Plus(dig())],
        ),
        // PFM: 'P[Ff]\x0a\d+ \d+\x0a[-+0-9.]+\x0a'
        "PFM" => m_seq(
            head,
            &[
                B(b'P'),
                Set(b"Ff"),
                B(0x0a),
                Plus(dig()),
                B(b' '),
                Plus(dig()),
                B(0x0a),
                Plus(cls(b"-+0123456789.")),
                B(0x0a),
            ],
        ),
        // PGF: 'PGF'
        "PGF" => head.starts_with(b"PGF"),
        // PHP: '<\?php\s'
        "PHP" => m_seq(head, &[Lit(b"<?php"), Ws]),
        // PICT: '(.{10}|.{522})(\x11\x01|\x00\x11)'
        "PICT" => {
            m_seq(head, &[AnyN(10), B(0x11), B(0x01)])
                || m_seq(head, &[AnyN(10), B(0x00), B(0x11)])
                || m_seq(head, &[AnyN(522), B(0x11), B(0x01)])
                || m_seq(head, &[AnyN(522), B(0x00), B(0x11)])
        }
        // PLIST: '(bplist0|\s*<|\xfe\xff\x00)'
        "PLIST" => {
            head.starts_with(b"bplist0")
                || m_seq(head, &[StarWs, B(b'<')])
                || head.starts_with(&[0xfe, 0xff, 0x00])
        }
        // PMP: '.{8}\0{3}\x7c.{112}\xff\xd8\xff\xdb'
        "PMP" => m_seq(
            head,
            &[
                AnyN(8),
                B(0x00),
                B(0x00),
                B(0x00),
                B(0x7c),
                AnyN(112),
                B(0xff),
                B(0xd8),
                B(0xff),
                B(0xdb),
            ],
        ),
        // PNG: '(\x89P|\x8aM|\x8bJ)NG\r\n\x1a\n'
        "PNG" => {
            m_seq(head, &[B(0x89), B(b'P'), Lit(b"NG\r\n"), B(0x1a), B(b'\n')])
                || m_seq(head, &[B(0x8a), B(b'M'), Lit(b"NG\r\n"), B(0x1a), B(b'\n')])
                || m_seq(head, &[B(0x8b), B(b'J'), Lit(b"NG\r\n"), B(0x1a), B(b'\n')])
        }
        // PPM: 'P[1-6]\s+'
        "PPM" => m_seq(head, &[B(b'P'), Range(b'1', b'6'), PlusWs]),
        // PS: '(%!PS|%!Ad|\xc5\xd0\xd3\xc6)'
        "PS" => {
            head.starts_with(b"%!PS")
                || head.starts_with(b"%!Ad")
                || head.starts_with(&[0xc5, 0xd0, 0xd3, 0xc6])
        }
        // PSD: '8BPS\0[\x01\x02]'
        "PSD" => m_seq(head, &[Lit(b"8BPS"), B(0x00), Set(&[0x01, 0x02])]),
        // PSP: 'Paint Shop Pro Image File\x0a\x1a\0{5}'
        "PSP" => head.starts_with(b"Paint Shop Pro Image File\x0a\x1a\0\0\0\0\0"),
        // QTIF: '.{4}(idsc|idat|iicc)'
        "QTIF" => {
            head.len() >= 8
                && matches!(&head[4..8], b"idsc" | b"idat" | b"iicc")
        }
        // R3D: '\0\0..RED(1|2)'
        "R3D" => m_seq(
            head,
            &[B(0x00), B(0x00), Any, Any, Lit(b"RED"), Set(b"12")],
        ),
        // RAF: 'FUJIFILM'
        "RAF" => head.starts_with(b"FUJIFILM"),
        // RAR: 'Rar!\x1a\x07\x01?\0'  ('?' = optional preceding \x01)
        "RAR" => {
            m_seq(head, &[Lit(b"Rar!"), B(0x1a), B(0x07), B(0x01), B(0x00)])
                || m_seq(head, &[Lit(b"Rar!"), B(0x1a), B(0x07), B(0x00)])
        }
        // RAW: '(.{25}ARECOYK|II|MM)'
        "RAW" => {
            m_seq(head, &[AnyN(25), Lit(b"ARECOYK")])
                || head.starts_with(b"II")
                || head.starts_with(b"MM")
        }
        // Real: '(\.RMF|\.ra\xfd|pnm://|rtsp://|http://)'
        "Real" => {
            head.starts_with(b".RMF")
                || m_seq(head, &[Lit(b".ra"), B(0xfd)])
                || head.starts_with(b"pnm://")
                || head.starts_with(b"rtsp://")
                || head.starts_with(b"http://")
        }
        // RIFF: '(RIFF|LA0[234]|OFR |LPAC|wvpk|RF64)'
        "RIFF" => {
            head.starts_with(b"RIFF")
                || m_seq(head, &[Lit(b"LA0"), Set(b"234")])
                || head.starts_with(b"OFR ")
                || head.starts_with(b"LPAC")
                || head.starts_with(b"wvpk")
                || head.starts_with(b"RF64")
        }
        // RSRC: '(....)?\0\0\x01\0'
        "RSRC" => {
            head.starts_with(&[0x00, 0x00, 0x01, 0x00])
                || m_seq(head, &[AnyN(4), B(0x00), B(0x00), B(0x01), B(0x00)])
        }
        // RTF: '[\n\r]*\{[\n\r]*\\rtf'
        "RTF" => m_seq(
            head,
            &[Star(cls(b"\n\r")), B(b'{'), Star(cls(b"\n\r")), Lit(b"\\rtf")],
        ),
        // RWZ: 'rawzor'
        "RWZ" => head.starts_with(b"rawzor"),
        // SWF: '[FC]WS[^\0]'
        "SWF" => m_seq(head, &[Set(b"FC"), Lit(b"WS"), NotByte(0x00)]),
        // TAR: '.{257}ustar(  )?\0'
        "TAR" => {
            m_seq(head, &[AnyN(257), Lit(b"ustar"), B(0x00)])
                || m_seq(head, &[AnyN(257), Lit(b"ustar  "), B(0x00)])
        }
        // TNEF: '\x78\x9f\x3e\x22..\x01\x06\x90\x08\0'
        "TNEF" => m_seq(
            head,
            &[
                B(0x78),
                B(0x9f),
                B(0x3e),
                B(0x22),
                Any,
                Any,
                B(0x01),
                B(0x06),
                B(0x90),
                B(0x08),
                B(0x00),
            ],
        ),
        // TXT: '(\xff\xfe|(\0\0)?\xfe\xff|(\xef\xbb\xbf)?[\x07-\x0d\x20-\x7e\x80-\xfe]*$)'
        "TXT" => magic_txt(head),
        // TIFF: '(II|MM)'
        "TIFF" => head.starts_with(b"II") || head.starts_with(b"MM"),
        // VCard: '(?i)BEGIN:(VCARD|VCALENDAR|VNOTE)\r\n'
        "VCard" => magic_vcard(head),
        // VRD: 'CANON OPTIONAL DATA\0'
        "VRD" => head.starts_with(b"CANON OPTIONAL DATA\0"),
        // WMF: '(\xd7\xcd\xc6\x9a\0\0|\x01\0\x09\0\0\x03)'
        "WMF" => {
            head.starts_with(&[0xd7, 0xcd, 0xc6, 0x9a, 0x00, 0x00])
                || head.starts_with(&[0x01, 0x00, 0x09, 0x00, 0x00, 0x03])
        }
        // WPG: '\xff\x57\x50\x43'
        "WPG" => head.starts_with(&[0xff, 0x57, 0x50, 0x43]),
        // WTV: 16-byte GUID
        "WTV" => head.starts_with(&[
            0xb7, 0xd8, 0x00, 0x20, 0x37, 0x49, 0xda, 0x11, 0xa6, 0x4e, 0x00, 0x07, 0xe9, 0x5e,
            0xad, 0x8d,
        ]),
        // X3F: 'FOVb'
        "X3F" => head.starts_with(b"FOVb"),
        // XCF: 'gimp xcf '
        "XCF" => head.starts_with(b"gimp xcf "),
        // XISF: 'XISF0100'
        "XISF" => head.starts_with(b"XISF0100"),
        // XMP: '\0{0,3}(\xfe\xff|\xff\xfe|\xef\xbb\xbf)?\0{0,3}\s*<'
        "XMP" => magic_xmp(head),
        // ZIP: 'PK\x03\x04'
        "ZIP" => head.starts_with(&[b'P', b'K', 0x03, 0x04]),
        // No %magicNumber entry => no gate.
        _ => return Magic::NoSignature,
    };
    if ok {
        Magic::Match
    } else {
        Magic::NoMatch
    }
}

// --- byte-matcher engine -----------------------------------------------------
//
// A tiny start-anchored matcher for the subset of Perl regex used by
// %magicNumber. All matches are anchored at byte 0 (Perl `/^.../s`), `.`
// matches ANY byte (Perl /s flag). Quantified/variadic regexes that need
// backtracking are hand-written as `magic_*` helpers below.

use Tok::*;

/// One regex token. Fixed-width tokens consume an exact number of bytes;
/// `Plus`/`Star` consume a class greedily but, because the overall pattern is
/// only ever followed by literal bytes in our usage, a greedy-with-no-backtrack
/// implementation would be wrong — so the few patterns needing `\s+`/`\s*`
/// before fixed bytes are handled by `MatchState` with minimal backtracking.
#[derive(Clone, Copy)]
enum Tok {
    /// Exactly one literal byte.
    B(u8),
    /// Exactly one byte, any value (Perl `.` under /s).
    Any,
    /// Exactly `n` bytes, any value (Perl `.{n}`).
    AnyN(usize),
    /// One byte in an inclusive range (Perl `[a-b]`).
    Range(u8, u8),
    /// One byte from an explicit set (Perl `[abc]`).
    Set(&'static [u8]),
    /// One byte that is NOT this value (Perl `[^x]`).
    NotByte(u8),
    /// A run of literal bytes (Perl literal string).
    Lit(&'static [u8]),
    /// One whitespace byte (Perl `\s`: space, \t, \n, \r, \f, \x0b).
    Ws,
    /// Zero or more whitespace bytes (Perl `\s*`).
    StarWs,
    /// One or more whitespace bytes (Perl `\s+`).
    PlusWs,
    /// Zero or more non-whitespace bytes (Perl `\S*`).
    StarNonWs,
    /// One digit byte 0-9 (Perl `\d`).
    Digit,
    /// One or more of the given single-byte class (Perl `X+`).
    Plus(Tok2),
    /// Zero or more of the given single-byte class (Perl `X*`).
    Star(Tok2),
    /// An optional single literal byte (Perl `x?`).
    OptByte(u8),
}

/// A single-byte class usable inside `Plus`/`Star` (kept separate so `Tok` is
/// not recursively unbounded).
#[derive(Clone, Copy)]
enum Tok2 {
    Digit,
    Word,
    SetCls(&'static [u8]),
}

#[inline]
fn is_ws(b: u8) -> bool {
    matches!(b, b' ' | b'\t' | b'\n' | b'\r' | 0x0c | 0x0b)
}

/// Skip a leading `\s*` run (Perl `\s` set), returning the remaining slice.
#[inline]
fn skip_ws(s: &[u8]) -> &[u8] {
    let mut i = 0;
    while i < s.len() && is_ws(s[i]) {
        i += 1;
    }
    &s[i..]
}

#[inline]
fn cls2(t: Tok2, b: u8) -> bool {
    match t {
        Tok2::Digit => b.is_ascii_digit(),
        Tok2::Word => b.is_ascii_alphanumeric() || b == b'_',
        Tok2::SetCls(s) => s.contains(&b),
    }
}

#[allow(non_snake_case)]
fn Plus(t: Tok2) -> Tok {
    Tok::Plus(t)
}
#[allow(non_snake_case)]
fn Star(t: Tok2) -> Tok {
    Tok::Star(t)
}
/// `\d` as a `Plus`/`Star` inner class.
fn dig() -> Tok2 {
    Tok2::Digit
}
/// `\w` as a `Plus`/`Star` inner class.
fn wrd() -> Tok2 {
    Tok2::Word
}
/// A `[bytes]` character class for use inside `Plus`/`Star`.
fn cls(s: &'static [u8]) -> Tok2 {
    Tok2::SetCls(s)
}

/// Match `toks` against the start of `head`. Returns the number of bytes
/// consumed on success (Perl `/^pat/s` — we only need a boolean for the gate,
/// but variable-width tokens require trying multiple lengths, so we recurse).
fn try_match(head: &[u8], toks: &[Tok]) -> bool {
    fn go(b: &[u8], i: usize, toks: &[Tok], ti: usize) -> bool {
        if ti == toks.len() {
            return true;
        }
        match toks[ti] {
            B(x) => b.get(i) == Some(&x) && go(b, i + 1, toks, ti + 1),
            Any => i < b.len() && go(b, i + 1, toks, ti + 1),
            AnyN(n) => i + n <= b.len() && go(b, i + n, toks, ti + 1),
            Range(lo, hi) => {
                matches!(b.get(i), Some(&v) if v >= lo && v <= hi)
                    && go(b, i + 1, toks, ti + 1)
            }
            Set(s) => matches!(b.get(i), Some(v) if s.contains(v)) && go(b, i + 1, toks, ti + 1),
            NotByte(x) => matches!(b.get(i), Some(&v) if v != x) && go(b, i + 1, toks, ti + 1),
            Lit(s) => b[i..].starts_with(s) && go(b, i + s.len(), toks, ti + 1),
            Ws => matches!(b.get(i), Some(&v) if is_ws(v)) && go(b, i + 1, toks, ti + 1),
            StarWs => {
                // Greedy with backtrack: try longest run first, then shorter.
                let mut j = i;
                while j < b.len() && is_ws(b[j]) {
                    j += 1;
                }
                loop {
                    if go(b, j, toks, ti + 1) {
                        return true;
                    }
                    if j == i {
                        return false;
                    }
                    j -= 1;
                }
            }
            PlusWs => {
                if !matches!(b.get(i), Some(&v) if is_ws(v)) {
                    return false;
                }
                let mut j = i + 1;
                while j < b.len() && is_ws(b[j]) {
                    j += 1;
                }
                loop {
                    if go(b, j, toks, ti + 1) {
                        return true;
                    }
                    if j == i + 1 {
                        return false;
                    }
                    j -= 1;
                }
            }
            StarNonWs => {
                let mut j = i;
                while j < b.len() && !is_ws(b[j]) {
                    j += 1;
                }
                loop {
                    if go(b, j, toks, ti + 1) {
                        return true;
                    }
                    if j == i {
                        return false;
                    }
                    j -= 1;
                }
            }
            Digit => {
                matches!(b.get(i), Some(v) if v.is_ascii_digit())
                    && go(b, i + 1, toks, ti + 1)
            }
            Tok::Plus(t) => {
                if !matches!(b.get(i), Some(&v) if cls2(t, v)) {
                    return false;
                }
                let mut j = i + 1;
                while j < b.len() && cls2(t, b[j]) {
                    j += 1;
                }
                loop {
                    if go(b, j, toks, ti + 1) {
                        return true;
                    }
                    if j == i + 1 {
                        return false;
                    }
                    j -= 1;
                }
            }
            Tok::Star(t) => {
                let mut j = i;
                while j < b.len() && cls2(t, b[j]) {
                    j += 1;
                }
                loop {
                    if go(b, j, toks, ti + 1) {
                        return true;
                    }
                    if j == i {
                        return false;
                    }
                    j -= 1;
                }
            }
            OptByte(x) => {
                if b.get(i) == Some(&x) && go(b, i + 1, toks, ti + 1) {
                    return true;
                }
                go(b, i, toks, ti + 1)
            }
        }
    }
    go(head, 0, toks, 0)
}

/// Alias kept readable at call sites.
#[inline]
fn m_seq(head: &[u8], toks: &[Tok]) -> bool {
    try_match(head, toks)
}

// --- hand-written matchers for backtracking-heavy regexes --------------------

/// Font: `((\0\x01\0\0|OTTO|true|typ1)[\0\x01]|ttcf\0[\x01\x02]\0\0|\0[\x01\x02]|`
///        `(.{6})?%!(PS-(AdobeFont-|Bitstream )|FontType1-)|`
///        `Start(Comp|Master)?FontMetrics|wOF[F2])`
fn magic_font(h: &[u8]) -> bool {
    let sfnt = |p: &[u8]| {
        (p.starts_with(&[0x00, 0x01, 0x00, 0x00])
            || p.starts_with(b"OTTO")
            || p.starts_with(b"true")
            || p.starts_with(b"typ1"))
            && matches!(p.get(4), Some(&v) if v == 0x00 || v == 0x01)
    };
    if sfnt(h) {
        return true;
    }
    if m_seq(h, &[Lit(b"ttcf"), B(0x00), Set(&[0x01, 0x02]), B(0x00), B(0x00)]) {
        return true;
    }
    if h.len() >= 2 && h[0] == 0x00 && (h[1] == 0x01 || h[1] == 0x02) {
        return true;
    }
    // (.{6})?%!(PS-(AdobeFont-|Bitstream )|FontType1-)
    let ps_at = |p: &[u8]| {
        p.starts_with(b"%!PS-AdobeFont-")
            || p.starts_with(b"%!PS-Bitstream ")
            || p.starts_with(b"%!FontType1-")
    };
    if ps_at(h) || (h.len() >= 6 && ps_at(&h[6..])) {
        return true;
    }
    // Start(Comp|Master)?FontMetrics
    if h.starts_with(b"StartFontMetrics")
        || h.starts_with(b"StartCompFontMetrics")
        || h.starts_with(b"StartMasterFontMetrics")
    {
        return true;
    }
    // wOF[F2]
    m_seq(h, &[Lit(b"wOF"), Set(b"F2")])
}

/// HTML: `(\xef\xbb\xbf)?\s*(?i)<(!DOCTYPE\s+HTML|HTML|\?xml)` (case-insensitive
/// from the `<` onward).
fn magic_html(h: &[u8]) -> bool {
    let mut p = h;
    if p.starts_with(&[0xef, 0xbb, 0xbf]) {
        p = &p[3..];
    }
    let mut i = 0;
    while i < p.len() && is_ws(p[i]) {
        i += 1;
    }
    let p = &p[i..];
    if p.first() != Some(&b'<') {
        return false;
    }
    let rest = &p[1..];
    let ci_starts = |s: &[u8], pat: &[u8]| {
        s.len() >= pat.len() && s[..pat.len()].eq_ignore_ascii_case(pat)
    };
    if ci_starts(rest, b"HTML") || ci_starts(rest, b"?xml") {
        return true;
    }
    // !DOCTYPE\s+HTML  (case-insensitive)
    if ci_starts(rest, b"!DOCTYPE") {
        let after = &rest[8..];
        let mut j = 0;
        while j < after.len() && is_ws(after[j]) {
            j += 1;
        }
        return j >= 1 && ci_starts(&after[j..], b"HTML");
    }
    false
}

/// ICC: `.{12}(scnr|mntr|prtr|link|spac|abst|nmcl|nkpf|cenc|mid |mlnk|mvis)`
///      `(XYZ |Lab |Luv |YCbr|Yxy |RGB |GRAY|HSV |HLS |CMYK|CMY |[2-9A-F]CLR|nc..|\0{4}){2}`
fn magic_icc(h: &[u8]) -> bool {
    if h.len() < 12 + 4 {
        return false;
    }
    let cls = &h[12..16];
    const DEVCLASS: [&[u8]; 12] = [
        b"scnr", b"mntr", b"prtr", b"link", b"spac", b"abst", b"nmcl", b"nkpf", b"cenc", b"mid ",
        b"mlnk", b"mvis",
    ];
    if !DEVCLASS.contains(&cls) {
        return false;
    }
    // Two consecutive 4-byte color-space groups starting at offset 16.
    fn group_ok(g: &[u8]) -> bool {
        const FIXED: [&[u8]; 11] = [
            b"XYZ ", b"Lab ", b"Luv ", b"YCbr", b"Yxy ", b"RGB ", b"GRAY", b"HSV ", b"HLS ",
            b"CMYK", b"CMY ",
        ];
        if g.len() < 4 {
            return false;
        }
        if FIXED.contains(&&g[..4]) {
            return true;
        }
        // [2-9A-F]CLR
        if matches!(g[0], b'2'..=b'9' | b'A'..=b'F') && &g[1..4] == b"CLR" {
            return true;
        }
        // nc..  (literal "nc" then any two bytes)
        if &g[..2] == b"nc" {
            return true;
        }
        // \0{4}
        g[..4] == [0, 0, 0, 0]
    }
    h.len() >= 24 && group_ok(&h[16..20]) && group_ok(&h[20..24])
}

/// LNK: ExifTool.pm:988 `%magicNumber{LNK}` (verbatim, /s):
/// `(.{4}\x01\x14\x02\0{5}\xc0\0{6}\x46|\[[InternetShortcut\][\x0d\x0a])`
///
/// Two start-anchored alternatives:
/// - alt1: 4 any bytes, then `\x01\x14\x02`, then 5x`\0`, then `\xc0`, then
///   6x`\0`, then `\x46` (20 bytes total).
/// - alt2: literal `[` (0x5B), then ONE byte from a single character class.
///   The class source is `[InternetShortcut\][\x0d\x0a]`: it opens at the
///   second `[`, contains the literal letters of `InternetShortcut`, then
///   `\]` (literal `]` 0x5D inside the class), then `[` (literal 0x5B inside
///   the class), then `\x0d` `\x0a`, and closes at the final `]`. So the
///   class is the SET of distinct bytes:
///   { I n t e r S h o c u } ∪ { 0x5D `]`, 0x5B `[`, 0x0D CR, 0x0A LF }
///   (case-sensitive — only the exact letters present in "InternetShortcut").
///   alt2 therefore matches exactly 2 bytes: byte0 == `[`, byte1 ∈ that set.
fn magic_lnk(h: &[u8]) -> bool {
    // alt1 (20 fixed/any bytes).
    let alt1 = h.len() >= 20
        && h[4] == 0x01
        && h[5] == 0x14
        && h[6] == 0x02
        && h[7..12] == [0, 0, 0, 0, 0]
        && h[12] == 0xc0
        && h[13..19] == [0, 0, 0, 0, 0, 0]
        && h[19] == 0x46;
    if alt1 {
        return true;
    }
    // alt2: '[' then one byte from the char-class. The distinct bytes of
    // "InternetShortcut" plus ']' '[' CR LF.
    const CLASS: &[u8] = b"InternetShortcut][\x0d\x0a";
    matches!((h.first(), h.get(1)), (Some(&b'['), Some(c)) if CLASS.contains(c))
}

/// JSON: `(\xef\xbb\xbf)?\s*(\[\s*)?\{\s*"[^"]*"\s*:`
fn magic_json(h: &[u8]) -> bool {
    let mut p = h;
    if p.starts_with(&[0xef, 0xbb, 0xbf]) {
        p = &p[3..];
    }
    p = skip_ws(p);
    // optional ( \[ \s* )
    if p.first() == Some(&b'[') {
        p = skip_ws(&p[1..]);
    }
    if p.first() != Some(&b'{') {
        return false;
    }
    p = skip_ws(&p[1..]);
    if p.first() != Some(&b'"') {
        return false;
    }
    p = &p[1..];
    let mut i = 0;
    while i < p.len() && p[i] != b'"' {
        i += 1;
    }
    if i >= p.len() {
        return false; // unterminated "[^"]*"
    }
    p = skip_ws(&p[i + 1..]);
    p.first() == Some(&b':')
}

/// KVAR: `.{2}\0\0[A-Z].{31}(CHAR|BOOL|[US](8|16|32|64)|FLOAT|DOUBLE)\0`
fn magic_kvar(h: &[u8]) -> bool {
    if h.len() < 2 + 2 + 1 + 31 {
        return false;
    }
    if h[2] != 0 || h[3] != 0 {
        return false;
    }
    if !h[4].is_ascii_uppercase() {
        return false;
    }
    let rest = &h[5 + 31..];
    let try_tok = |tok: &[u8]| {
        rest.starts_with(tok) && rest.get(tok.len()) == Some(&0)
    };
    if try_tok(b"CHAR") || try_tok(b"BOOL") || try_tok(b"FLOAT") || try_tok(b"DOUBLE") {
        return true;
    }
    // [US](8|16|32|64)
    if matches!(rest.first(), Some(&v) if v == b'U' || v == b'S') {
        for n in [b"8".as_slice(), b"16", b"32", b"64"] {
            if rest[1..].starts_with(n) && rest.get(1 + n.len()) == Some(&0) {
                return true;
            }
        }
    }
    false
}

/// M2TS: `.{0,191}?\x47(.{187}|.{191})\x47(.{187}|.{191})\x47`
/// Non-greedy 0..191 byte skip, then 0x47 sync bytes every 188 or 192 bytes.
fn magic_m2ts(h: &[u8]) -> bool {
    for skip in 0..=191usize {
        if skip >= h.len() {
            break;
        }
        if h[skip] != 0x47 {
            continue;
        }
        for &g1 in &[187usize, 191usize] {
            let p1 = skip + 1 + g1;
            if h.get(p1) != Some(&0x47) {
                continue;
            }
            for &g2 in &[187usize, 191usize] {
                let p2 = p1 + 1 + g2;
                if h.get(p2) == Some(&0x47) {
                    return true;
                }
            }
        }
    }
    false
}

/// MRC: `.{64}[\x01\x02\x03]\0\0\0[\x01\x02\x03]\0\0\0[\x01\x02\x03]\0\0\0`
///      `.{132}MAP[\0 ](\x44\x44|\x44\x41|\x11\x11)\0\0`
fn magic_mrc(h: &[u8]) -> bool {
    let mode = |b: u8| matches!(b, 1..=3);
    let need = 64 + 12 + 132 + 3 + 1 + 2 + 2;
    if h.len() < need {
        return false;
    }
    if !(mode(h[64]) && h[65] == 0 && h[66] == 0 && h[67] == 0) {
        return false;
    }
    if !(mode(h[68]) && h[69] == 0 && h[70] == 0 && h[71] == 0) {
        return false;
    }
    if !(mode(h[72]) && h[73] == 0 && h[74] == 0 && h[75] == 0) {
        return false;
    }
    let p = 76 + 132;
    if &h[p..p + 3] != b"MAP" {
        return false;
    }
    if !matches!(h[p + 3], 0x00 | b' ') {
        return false;
    }
    let sw = &h[p + 4..p + 6];
    if !(sw == [0x44, 0x44] || sw == [0x44, 0x41] || sw == [0x11, 0x11]) {
        return false;
    }
    h[p + 6] == 0 && h[p + 7] == 0
}

/// PCAP: `\xa1\xb2(\xc3\xd4|\x3c\x4d)\0.\0.|(\xd4\xc3|\x4d\x3c)\xb2\xa1.\0.\0|`
///       `\x0a\x0d\x0d\x0a.{4}(\x1a\x2b\x3c\x4d|\x4d\x3c\x2b\x1a)|GMBU\0\x02`
fn magic_pcap(h: &[u8]) -> bool {
    // alt 1: \xa1\xb2 (\xc3\xd4|\x3c\x4d) \0 . \0 .
    if h.len() >= 8
        && h[0] == 0xa1
        && h[1] == 0xb2
        && (h[2..4] == [0xc3, 0xd4] || h[2..4] == [0x3c, 0x4d])
        && h[4] == 0x00
        && h[6] == 0x00
    {
        return true;
    }
    // alt 2: (\xd4\xc3|\x4d\x3c) \xb2\xa1 . \0 . \0
    if h.len() >= 8
        && (h[0..2] == [0xd4, 0xc3] || h[0..2] == [0x4d, 0x3c])
        && h[2] == 0xb2
        && h[3] == 0xa1
        && h[5] == 0x00
        && h[7] == 0x00
    {
        return true;
    }
    // alt 3: \x0a\x0d\x0d\x0a .{4} (\x1a\x2b\x3c\x4d|\x4d\x3c\x2b\x1a)
    if h.len() >= 12
        && h[0..4] == [0x0a, 0x0d, 0x0d, 0x0a]
        && (h[8..12] == [0x1a, 0x2b, 0x3c, 0x4d] || h[8..12] == [0x4d, 0x3c, 0x2b, 0x1a])
    {
        return true;
    }
    // alt 4: GMBU\0\x02
    h.starts_with(b"GMBU\0\x02")
}

/// PDB: `.{60}(<24 four-byte creator tags>)`
fn magic_pdb(h: &[u8]) -> bool {
    if h.len() < 64 {
        return false;
    }
    const TAGS: [&[u8]; 24] = [
        b".pdf", b"TEXt", b"BVok", b"DB99", b"PNRd", b"DataPPrs", b"vIMG", b"PmDB", b"Info",
        b"ToGo", b"SDoc", b"JbDb", b"JfDb", b"DATA", b"Mdb1", b"BOOK", b"DataPlkr", b"DataSprd",
        b"SM01", b"TEXt", b"Info", b"DataTlMl", b"DataTlPt", b"dataTDBP",
    ];
    // Original 8-char tags (offset 60, 8 bytes). Reconstructed from the Perl
    // alternation .pdfADBE|TEXtREAd|BVokBDIC|DB99DBOS|PNRdPPrs|DataPPrs|
    // vIMGView|PmDBPmDB|InfoINDB|ToGoToGo|SDocSilX|JbDbJBas|JfDbJFil|
    // DATALSdb|Mdb1Mdb1|BOOKMOBI|DataPlkr|DataSprd|SM01SMem|TEXtTlDc|
    // InfoTlIf|DataTlMl|DataTlPt|dataTDBP|TdatTide|ToRaTRPW|zTXTGPlm|BDOCWrdS
    const FULL: [&[u8]; 28] = [
        b".pdfADBE", b"TEXtREAd", b"BVokBDIC", b"DB99DBOS", b"PNRdPPrs", b"DataPPrs", b"vIMGView",
        b"PmDBPmDB", b"InfoINDB", b"ToGoToGo", b"SDocSilX", b"JbDbJBas", b"JfDbJFil", b"DATALSdb",
        b"Mdb1Mdb1", b"BOOKMOBI", b"DataPlkr", b"DataSprd", b"SM01SMem", b"TEXtTlDc", b"InfoTlIf",
        b"DataTlMl", b"DataTlPt", b"dataTDBP", b"TdatTide", b"ToRaTRPW", b"zTXTGPlm", b"BDOCWrdS",
    ];
    let _ = TAGS;
    let at = &h[60..];
    FULL.iter().any(|t| at.starts_with(t))
}

/// TXT: `(\xff\xfe|(\0\0)?\xfe\xff|(\xef\xbb\xbf)?[\x07-\x0d\x20-\x7e\x80-\xfe]*$)`
/// The `$` (with /s) matches end-of-buffer. Empty buffer matches.
fn magic_txt(h: &[u8]) -> bool {
    // \xff\xfe  (UTF-16 LE BOM)
    if h.starts_with(&[0xff, 0xfe]) {
        return true;
    }
    // (\0\0)? \xfe\xff
    if h.starts_with(&[0xfe, 0xff]) || h.starts_with(&[0x00, 0x00, 0xfe, 0xff]) {
        return true;
    }
    // (\xef\xbb\xbf)? [class]* $   — every remaining byte must be in class.
    let body = if h.starts_with(&[0xef, 0xbb, 0xbf]) { &h[3..] } else { h };
    body.iter()
        .all(|&b| matches!(b, 0x07..=0x0d | 0x20..=0x7e | 0x80..=0xfe))
}

/// VCard: `(?i)BEGIN:(VCARD|VCALENDAR|VNOTE)\r\n`  (case-insensitive)
fn magic_vcard(h: &[u8]) -> bool {
    let ci = |s: &[u8], pat: &[u8]| s.len() >= pat.len() && s[..pat.len()].eq_ignore_ascii_case(pat);
    if !ci(h, b"BEGIN:") {
        return false;
    }
    let r = &h[6..];
    for kw in [b"VCARD".as_slice(), b"VCALENDAR", b"VNOTE"] {
        if ci(r, kw) && r.get(kw.len()) == Some(&b'\r') && r.get(kw.len() + 1) == Some(&b'\n') {
            return true;
        }
    }
    false
}

/// XMP: `\0{0,3}(\xfe\xff|\xff\xfe|\xef\xbb\xbf)?\0{0,3}\s*<`
fn magic_xmp(h: &[u8]) -> bool {
    for n0 in 0..=3usize {
        if n0 > h.len() {
            break;
        }
        if h[..n0].iter().any(|&b| b != 0) {
            continue;
        }
        let after0 = &h[n0..];
        for bom in [
            [].as_slice(),
            &[0xfe, 0xff],
            &[0xff, 0xfe],
            &[0xef, 0xbb, 0xbf],
        ] {
            if !after0.starts_with(bom) {
                continue;
            }
            let p = &after0[bom.len()..];
            for n1 in 0..=3usize {
                if n1 > p.len() {
                    break;
                }
                if p[..n1].iter().any(|&b| b != 0) {
                    continue;
                }
                let mut q = &p[n1..];
                let mut i = 0;
                while i < q.len() && is_ws(q[i]) {
                    i += 1;
                }
                q = &q[i..];
                if q.first() == Some(&b'<') {
                    return true;
                }
            }
        }
    }
    false
}
