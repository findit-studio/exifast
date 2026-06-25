#!/usr/bin/env perl
# Emit src/exif/mng/tables.rs from MNG.pm — the %MNG::Main chunk dispatch (the
# id->sub-table / Binary-chunk map) plus every ProcessBinaryData sub-table's
# per-offset leaf descriptors (offset/format/count + the int->label PrintConv
# slices), deduplicated (Perl last-wins) and sorted for binary search.
#
# Usage: tools/gen_mng_tables.pl path/to/MNG.pm > src/exif/mng/tables.rs
#
# CODEGEN-SURVEY TRAP (the #190 finding): `-listx`/declarative extraction carries
# NO ValueConv/RawConv. The 5 conv-bearing fields are HAND-PORTED here via the
# %HANDPORT override (keyed "ChunkSubName/FieldName"): MHDR SimplicityProfile
# (sprintf 0x%.8x), DISC DiscardObjects (join unpack n*), DROP DropChunks
# (4-char split), SEEK SeekPoint (NUL-strip), BASI ColorType (RawConv
# $PNG::colorType=$val — INERT passthrough in exifast's model; the value emits
# unchanged). Every other field is purely declarative.
use strict;
use warnings;
my $file = shift or die "usage: $0 MNG.pm\n";
open my $fh, '<', $file or die "open $file: $!\n";
my @lines = <$fh>;
close $fh;

sub rs { my $s = shift; $s =~ s/\\/\\\\/g; $s =~ s/"/\\"/g; return $s; }

# ── the 5 HAND-PORTED conv-bearing fields (the survey override list) ──────────
# Keyed "<SubTableName>/<FieldName>" → a `MngConv` variant token. Every other
# field is `MngConv::None` (declarative). The shapes were ground-truthed vs
# bundled ExifTool 13.59.
my %HANDPORT = (
  'MNGHeader/SimplicityProfile' => 'SimplicityProfile', # sprintf 0x%.8x (MNG.pm:158)
  # DISC/DROP/SEEK are INLINE ValueConv tags in %MNG::Main (NOT sub-tables); they
  # are handled by the dispatcher (see the Main walk + %INLINE_CONV below), not as
  # leaf descriptors, so they need no per-leaf override here.
  # BASI ColorType RawConv ($PNG::colorType=$val) is an INERT passthrough: the
  # value emits UNCHANGED and exifast has no PNG::colorType global to mutate, so
  # no override is needed (the declarative int->label PrintConv carries it).
);

# ── %magMethod shared PrintConv (MNG.pm:349-356) ─────────────────────────────
my ($mlo, $mhi);
for (my $i = 0; $i < @lines; $i++) {
  if ($lines[$i] =~ /^my\s+%magMethod\s*=\s*\(/) { $mlo = $i + 1; last; }
}
for (my $j = $mlo; $j < @lines; $j++) {
  if ($lines[$j] =~ /^\);/) { $mhi = $j - 1; last; }
}

# harvest INT=>'STR' rows in [lo,hi]; last-wins
sub harvest {
  my ($lo, $hi) = @_;
  my %h;
  for (my $i = $lo; $i <= $hi; $i++) {
    if ($lines[$i] =~ /^\s*(-?\d+)\s*=>\s*'((?:[^'\\]|\\.)*)'\s*,?\s*$/) {
      $h{$1} = $2;
    }
  }
  return \%h;
}
# Harvest INT=>'STR' pairs from an arbitrary text region (the brace-body of a
# PrintConv hash), handling BOTH the multi-line form (one pair per line) and the
# COMPACT single-line form (`0 => 'x', 1 => 'y'`). A global match over the joined
# text; last-wins for a duplicate key (Perl hash semantics). The string body
# allows escaped quotes (`\'`).
sub harvest_text {
  my ($txt) = @_;
  my %h;
  while ($txt =~ /(-?\d+)\s*=>\s*'((?:[^'\\]|\\.)*)'/g) {
    $h{$1} = $2;
  }
  return \%h;
}
sub emit_slice {
  my ($h) = @_;
  my @out;
  for my $k (sort { $a <=> $b } keys %$h) {
    push @out, sprintf("  (%d, \"%s\"),", $k, rs($h->{$k}));
  }
  return join("\n", @out);
}

# ── %MNG::Main dispatch: chunk -> {sub|binary|inline|subdir-png} ──────────────
# We parse the top-level chunk entries: a SubDirectory→TagTable 'MNG::X' becomes
# a sub-table reference; a `Binary => 1` becomes a binary chunk; an inline
# `ValueConv` (DISC/DROP/SEEK) becomes an inline-conv chunk; the pHYg row points
# at PNG::PhysicalPixel (handled specially as the shared pHYs decoder).
my ($main_lo, $main_hi);
for (my $i = 0; $i < @lines; $i++) {
  if ($lines[$i] =~ /^%Image::ExifTool::MNG::Main\s*=\s*\(/) { $main_lo = $i + 1; last; }
}
for (my $j = $main_lo; $j < @lines; $j++) {
  if ($lines[$j] =~ /^\);/) { $main_hi = $j - 1; last; }
}

my @main;   # {chunk, kind, name, table, valueconv}
my $i = $main_lo;
while ($i <= $main_hi) {
  my $l = $lines[$i];
  # a chunk key like `BACK => {` or `DBYK => {`
  if ($l =~ /^\s{4}(\w{3,4})\s*=>\s*\{/) {
    my $chunk = $1;
    my $bdepth = 1;
    my ($name, $table, $vconv, $binary);
    $i++;
    while ($i <= $main_hi && $bdepth > 0) {
      my $bl = $lines[$i];
      if ($bdepth == 1 && $bl =~ /Name\s*=>\s*'([^']*)'/)            { $name = $1; }
      if ($bdepth == 1 && $bl =~ /Binary\s*=>\s*1/)                  { $binary = 1; }
      if ($bdepth == 1 && $bl =~ /TagTable\s*=>\s*'Image::ExifTool::MNG::(\w+)'/) { $table = $1; }
      if ($bdepth == 1 && $bl =~ /TagTable\s*=>\s*'Image::ExifTool::PNG::PhysicalPixel'/) { $table = 'PNG_PhysicalPixel'; }
      if ($bdepth == 1 && $bl =~ /ValueConv\s*=>\s*'(.*)'/)          { $vconv = $1; }
      $bdepth += ($bl =~ tr/{//) - ($bl =~ tr/}//);
      $i++;
    }
    my %e = (chunk => $chunk, name => ($name // $chunk));
    if    ($binary)                  { $e{kind} = 'binary'; }
    elsif (defined $table && $table eq 'PNG_PhysicalPixel') { $e{kind} = 'phys'; }
    elsif (defined $table)           { $e{kind} = 'sub'; $e{table} = $table; }
    elsif (defined $vconv)           { $e{kind} = 'inline'; $e{vconv} = $vconv; }
    else                             { $e{kind} = 'sub'; $e{table} = $e{name}; }
    push @main, \%e;
    next;
  }
  $i++;
}

# ── each ProcessBinaryData sub-table ────────────────────────────────────────
# Parse `%Image::ExifTool::MNG::<Name> = ( ... )`: capture FORMAT, then each
# numeric offset entry (Name/Format/PrintConv).
my %subtables;   # name -> { format=>'int8u'|'int32u', leaves=>[ {off,name,fmt,count,pc=>hashref|undef} ] }
for (my $k = 0; $k < @lines; $k++) {
  next unless $lines[$k] =~ /^%Image::ExifTool::MNG::(\w+)\s*=\s*\(/;
  my $sub = $1;
  next if $sub eq 'Main';
  my $lo = $k + 1;
  my $hi;
  for (my $j = $lo; $j < @lines; $j++) {
    if ($lines[$j] =~ /^\);/) { $hi = $j - 1; last; }
  }
  my $format = 'int8u';
  my @leaves;
  my $p = $lo;
  while ($p <= $hi) {
    my $l = $lines[$p];
    if ($l =~ /^\s*FORMAT\s*=>\s*'(\w+)'/) { $format = $1; $p++; next; }
    # `N => 'Name',`  (simple scalar leaf, default format)
    if ($l =~ /^\s{4}(\d+)\s*=>\s*'([^']*)'\s*,?\s*$/) {
      push @leaves, { off => $1, name => $2, fmt => undef, count => 1, pc => undef };
      $p++; next;
    }
    # `N => {` ... `}` (a leaf with Name/Format/PrintConv)
    if ($l =~ /^\s{4}(\d+)\s*=>\s*\{/) {
      my $off = $1;
      my $bd = 1;
      my ($name, $fmt, $count, $pc, $pcref, $saw_count);
      $count = 1;
      $p++;
      while ($p <= $hi && $bd > 0) {
        my $bl = $lines[$p];
        if ($bd == 1 && $bl =~ /Name\s*=>\s*'([^']*)'/) { $name = $1; }
        if ($bd == 1 && $bl =~ /Format\s*=>\s*'(\w+)(?:\[(\d+)\])?'/) { $fmt = $1; if (defined $2) { $count = $2; $saw_count = 1; } }
        if ($bd == 1 && $bl =~ /PrintConv\s*=>\s*\\%magMethod/) { $pc = 'magMethod'; }
        if ($bd == 1 && $bl =~ /PrintConv\s*=>\s*\{/) {
          # Walk the brace-balanced region STARTING at the part of line $p that
          # follows `PrintConv => {`, so a COMPACT single-line hash
          # (`PrintConv => { 0 => 'x', 1 => 'y' },`) is harvested too — the
          # opening `{` (and possibly its matching `}`) live on line $p itself,
          # which the old `$plo = $p+1` range skipped (the single-line bug).
          my $head = $bl; $head =~ s/.*?PrintConv\s*=>\s*\{//;
          my $id = 1 + ($head =~ tr/{//) - ($head =~ tr/}//);
          my @region = ($head);
          my $q = $p + 1;
          while ($id > 0 && $q <= $hi) {
            my $ql = $lines[$q];
            push @region, $ql;
            $id += ($ql =~ tr/{//) - ($ql =~ tr/}//);
            $q++;
          }
          $pcref = harvest_text(join('', @region));
        }
        $bd += ($bl =~ tr/{//) - ($bl =~ tr/}//);
        $p++;
      }
      # A `string` leaf with NO explicit `[count]` reads from its offset to the
      # END of the chunk (`ProcessBinaryData`: `$count = $size - $entry`), not 1
      # byte. Encode that as count 0 — the module's `Strng` reader treats 0 as
      # "to end" (eXPi SnapshotName).
      $count = 0 if defined $fmt && $fmt eq 'string' && !$saw_count;
      push @leaves, { off => $off, name => ($name // "Tag$off"), fmt => $fmt, count => $count, pc => $pc, pcref => $pcref };
      next;
    }
    $p++;
  }
  $subtables{$sub} = { format => $format, leaves => \@leaves };
}

# ── EMIT RUST ────────────────────────────────────────────────────────────────
print <<'HDR';
// SPDX-License-Identifier: GPL-3.0-or-later
// exifast — a 1:1 Rust port of ExifTool (Phil Harvey). See THIRD_PARTY.md.
//
// GENERATED by tools/gen_mng_tables.pl from `Image::ExifTool::MNG` (`MNG.pm`,
// $VERSION 1.00). DO NOT EDIT BY HAND — re-run the extractor against the bundled
// ExifTool to regenerate.
//
// `%MNG::Main` dispatches each MNG/JNG chunk to one of: a ProcessBinaryData
// sub-table (`MngSubTable`, decoded per-field), an inline `ValueConv` chunk
// (DISC/DROP/SEEK), a `Binary => 1` chunk (emitted as the `(Binary data N
// bytes …)` placeholder), or the shared PNG `pHYs` decoder (pHYg). Each
// sub-table's per-offset leaf descriptors carry the byte offset, element
// format/count, and (optional) int->label PrintConv slice (SORTED for
// `binary_search_by_key`, last-wins-deduplicated). The 5 conv-bearing fields
// are HAND-PORTED (`MngConv` / the inline-conv kinds), the rest declarative —
// see the module header for the survey-trap contract.

//! MNG/JNG chunk dispatch + ProcessBinaryData sub-table leaf descriptors,
//! mechanically transcribed from `%Image::ExifTool::MNG::*` (`MNG.pm`). See the
//! generator header for the contract.

#![allow(clippy::unreadable_literal)]

use super::{MngChunkKind, MngConv, MngFormat, MngLeafDef, MngSubTable};

/// Look up an MNG/JNG chunk's dispatch kind by its 4-byte id (binary search over
/// the sorted [`MNG_CHUNKS`]).
pub(super) fn lookup(chunk: &[u8; 4]) -> Option<MngChunkKind> {
  MNG_CHUNKS
    .binary_search_by_key(&chunk.as_slice(), |&(c, _)| c.as_slice())
    .ok()
    .and_then(|i| MNG_CHUNKS.get(i))
    .map(|&(_, kind)| kind)
}

HDR

# the shared %magMethod
{
  my $h = harvest($mlo, $mhi);
  my $n = scalar keys %$h;
  print "/// The shared `%magMethod` PrintConv ($n entries, MNG.pm:349-356) —\n";
  print "/// referenced by MAGN `XMethod` + `YMethod`.\n";
  print "static MAG_METHOD: &[(i64, &str)] = &[\n";
  print emit_slice($h), "\n];\n\n";
}

# per-leaf inline PrintConv slices: emit one static per (sub,offset) that has an
# inline hash (not magMethod), named MNG_<SUB>_<OFF>.
for my $sub (sort keys %subtables) {
  for my $lf (@{ $subtables{$sub}{leaves} }) {
    next unless $lf->{pcref} && %{ $lf->{pcref} };
    my $up = uc "MNG_${sub}_$lf->{off}";
    my $n = scalar keys %{ $lf->{pcref} };
    print "/// `$sub` offset $lf->{off} (`$lf->{name}`) PrintConv ($n entries).\n";
    print "static $up: &[(i64, &str)] = &[\n";
    print emit_slice($lf->{pcref}), "\n];\n\n";
  }
}

# map a Perl format name → MngFormat variant token
sub fmt_token {
  my $f = shift // 'int8u';
  return 'MngFormat::Int8u'   if $f eq 'int8u';
  return 'MngFormat::Int16u'  if $f eq 'int16u';
  return 'MngFormat::Int32u'  if $f eq 'int32u';
  return 'MngFormat::Strng'   if $f eq 'string';
  die "unhandled MNG format '$f'\n";
}

# emit one leaf-array + one MngSubTable per sub-table (sorted by name)
sub increment_of { my $f = shift; return 4 if $f eq 'int32u'; return 2 if $f eq 'int16u'; return 1; }
for my $sub (sort keys %subtables) {
  my $st = $subtables{$sub};
  my $tfmt = $st->{format};
  my $incr = increment_of($tfmt);
  my $up = uc "MNG_LEAVES_$sub";
  print "/// `MNG::$sub` ProcessBinaryData leaves (table FORMAT $tfmt, increment $incr).\n";
  print "static $up: &[MngLeafDef] = &[\n";
  for my $lf (@{ $st->{leaves} }) {
    # element format: the leaf's own Format overrides the table FORMAT; when the
    # leaf has no Format AND the table has a FORMAT, the leaf inherits it.
    my $efmt = defined $lf->{fmt} ? $lf->{fmt} : $tfmt;
    my $ftok = fmt_token($efmt);
    # PrintConv slice token
    my $pc;
    if    ($lf->{pc} && $lf->{pc} eq 'magMethod') { $pc = 'Some(MAG_METHOD)'; }
    elsif ($lf->{pcref} && %{ $lf->{pcref} })     { $pc = 'Some(' . uc("MNG_${sub}_$lf->{off}") . ')'; }
    else                                          { $pc = 'None'; }
    # hand-port conv
    my $convkey = "$sub/$lf->{name}";
    my $conv = $HANDPORT{$convkey} ? "MngConv::$HANDPORT{$convkey}" : 'MngConv::None';
    printf "  MngLeafDef::new(%d, \"%s\", %s, %d, %s, %s),\n",
      $lf->{off}, rs($lf->{name}), $ftok, $lf->{count}, $pc, $conv;
  }
  print "];\n";
  my $tup = uc "MNG_SUB_$sub";
  print "/// `MNG::$sub` ProcessBinaryData sub-table (increment $incr).\n";
  print "static $tup: MngSubTable = MngSubTable::new($incr, $up);\n\n";
}

# the per-chunk dispatch table
print "/// Every `%MNG::Main` chunk, SORTED by 4-byte chunk id for binary search.\n";
print "pub(super) static MNG_CHUNKS: &[(&[u8; 4], MngChunkKind)] = &[\n";
my @sorted = sort { $a->{chunk} cmp $b->{chunk} } @main;
for my $e (@sorted) {
  my $c = $e->{chunk};
  # 4-byte literal; chunk ids are ASCII, pad is impossible (all 3-4 chars but PNG
  # chunk ids are always 4). MNG.pm uses 4-char ids exclusively.
  die "non-4-char chunk id '$c'\n" unless length($c) == 4;
  my $blit = 'b"' . $c . '"';
  my $kind;
  if    ($e->{kind} eq 'binary') { $kind = "MngChunkKind::Binary(\"" . rs($e->{name}) . "\")"; }
  elsif ($e->{kind} eq 'phys')   { $kind = "MngChunkKind::Phys"; }
  elsif ($e->{kind} eq 'inline') {
    my $conv = inline_conv_token($e->{vconv});
    $kind = "MngChunkKind::Inline(\"" . rs($e->{name}) . "\", $conv)";
  } else {
    my $up = uc "MNG_SUB_$e->{table}";
    $kind = "MngChunkKind::Sub(&$up)";
  }
  printf "  (%s, %s),\n", $blit, $kind;
}
print "];\n";

# map an inline ValueConv string → an InlineConv variant token
sub inline_conv_token {
  my $v = shift;
  return 'MngConv::DiscardObjects' if $v =~ /unpack\("n\*"/;     # DISC
  return 'MngConv::DropChunks'     if $v =~ /\$val=~\/\.\.\.\.\//; # DROP (4-char split)
  return 'MngConv::SeekPoint'      if $v =~ /s\/\\0\.\*\/\/s/;    # SEEK (NUL-strip)
  die "unhandled inline ValueConv '$v'\n";
}
