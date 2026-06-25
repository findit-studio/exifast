# Real-device fixture sources

These fixtures retain the first 1 MiB of genuine camera files from the
[raw.pixls.us](https://raw.pixls.us/) CC0 test corpus. The retained region
contains the original TIFF/EXIF MakerNote data; only the later image payload is
truncated to keep the repository small.

Before inclusion, ExifTool 13.59 `-j -G1 -a -s` output was compared between
each complete source file and its trimmed fixture. All `Sony:*`, `Canon:*`, and
`CanonCustom:*` values matched exactly.

| Fixture | Source | raw.pixls.us ID | Original SHA-256 | Related issues |
| --- | --- | ---: | --- | --- |
| `Sony_DSLR-A200_real.ARW` | Sony DSLR-A200, compressed ARW | 2271 | `04eacd403d92e0c90da9d91b87615af8eda1afc963350d3ab774557c36763eef` | #97-#103 |
| `Sony_SLT-A33_real.ARW` | Sony SLT-A33, compressed ARW | 2050 | `1a59856394f10d4fadb40f5ab9c6d1c89f473f4dbcdefd216fbbbbf1ad8d21f9` | #97-#103 |
| `Sony_ILME-FX3_real.ARW` | Sony ILME-FX3, ARW | 6874 | `394ceb1a356be8b17f18dc013bfd22895ba6ec7195f578b9be1c2fd0d5ea4773` | #97-#103 |
| `Canon_EOS-1D_real.TIF` | Canon EOS-1D RAW TIFF | 1958 | `e9856cb62ca32d6cbe83dbb35f16fe10b5d7d0ef92e84bdcb40be70aabe87e6a` | #84, #85, #87 |
| `Canon_EOS-5D_real.CR2` | Canon EOS 5D CR2 | 1346 | `b30089172973388d03e192a14a63f750e22914dfc01db5713b6b3bce3c9baeee` | #84, #85, #87 |
| `Canon_EOS-7D_sRAW_real.CR2` | Canon EOS 7D sRAW CR2 | 129 | `3789b1ba5d880613104637c40a06619cd9f3b54b0cf62d2d95b9f9e885edcf6e` | #84, #85, #87 |

The files are dedicated to the public domain under
[CC0 1.0](https://creativecommons.org/publicdomain/zero/1.0/).

Panasonic FaceN (#105) and DJI `btec` (#111) remain fixture-blocked: the public
Panasonic samples inspected contain zero face positions/recognitions, and no
public DJI QuickTime sample with a `btec` atom was found.
