// SPDX-License-Identifier: GPL-3.0-or-later
// exifast — a 1:1 Rust port of ExifTool (Phil Harvey). See THIRD_PARTY.md.

//! `%canonModelID` — Canon model-ID (`int32u`) → human-readable model
//! string (`Canon.pm:656-1024`). 357 entries. Canon stores the model
//! ID in `Canon::Main` tag 0x10 (`ModelID`, `Canon.pm:1623-1626`).
//!
//! Sorted by ID for binary-search lookup.

use smol_str::SmolStr;

/// One model-ID entry.
#[derive(Debug, Clone, Copy)]
pub struct CanonModelEntry {
  /// `Canon::Main:0x10` value (`int32u`).
  pub id: u32,
  /// Human-readable model name (`Canon.pm:656-1024` RHS).
  pub name: &'static str,
}

/// `%canonModelID` (`Canon.pm:656-1024`), sorted by ID.
pub const CANON_MODEL_IDS: &[CanonModelEntry] = &[
  CanonModelEntry {
    id: 0x00000412,
    name: "EOS M50 / Kiss M",
  },
  CanonModelEntry {
    id: 0x00000801,
    name: "PowerShot SX740 HS",
  },
  CanonModelEntry {
    id: 0x00000804,
    name: "PowerShot G5 X Mark II",
  },
  CanonModelEntry {
    id: 0x00000805,
    name: "PowerShot SX70 HS",
  },
  CanonModelEntry {
    id: 0x00000808,
    name: "PowerShot G7 X Mark III",
  },
  CanonModelEntry {
    id: 0x00000811,
    name: "EOS M6 Mark II",
  },
  CanonModelEntry {
    id: 0x00000812,
    name: "EOS M200",
  },
  CanonModelEntry {
    id: 0x01010000,
    name: "PowerShot A30",
  },
  CanonModelEntry {
    id: 0x01040000,
    name: "PowerShot S300 / Digital IXUS 300 / IXY Digital 300",
  },
  CanonModelEntry {
    id: 0x01060000,
    name: "PowerShot A20",
  },
  CanonModelEntry {
    id: 0x01080000,
    name: "PowerShot A10",
  },
  CanonModelEntry {
    id: 0x01090000,
    name: "PowerShot S110 / Digital IXUS v / IXY Digital 200",
  },
  CanonModelEntry {
    id: 0x01100000,
    name: "PowerShot G2",
  },
  CanonModelEntry {
    id: 0x01110000,
    name: "PowerShot S40",
  },
  CanonModelEntry {
    id: 0x01120000,
    name: "PowerShot S30",
  },
  CanonModelEntry {
    id: 0x01130000,
    name: "PowerShot A40",
  },
  CanonModelEntry {
    id: 0x01140000,
    name: "EOS D30",
  },
  CanonModelEntry {
    id: 0x01150000,
    name: "PowerShot A100",
  },
  CanonModelEntry {
    id: 0x01160000,
    name: "PowerShot S200 / Digital IXUS v2 / IXY Digital 200a",
  },
  CanonModelEntry {
    id: 0x01170000,
    name: "PowerShot A200",
  },
  CanonModelEntry {
    id: 0x01180000,
    name: "PowerShot S330 / Digital IXUS 330 / IXY Digital 300a",
  },
  CanonModelEntry {
    id: 0x01190000,
    name: "PowerShot G3",
  },
  CanonModelEntry {
    id: 0x01210000,
    name: "PowerShot S45",
  },
  CanonModelEntry {
    id: 0x01230000,
    name: "PowerShot SD100 / Digital IXUS II / IXY Digital 30",
  },
  CanonModelEntry {
    id: 0x01240000,
    name: "PowerShot S230 / Digital IXUS v3 / IXY Digital 320",
  },
  CanonModelEntry {
    id: 0x01250000,
    name: "PowerShot A70",
  },
  CanonModelEntry {
    id: 0x01260000,
    name: "PowerShot A60",
  },
  CanonModelEntry {
    id: 0x01270000,
    name: "PowerShot S400 / Digital IXUS 400 / IXY Digital 400",
  },
  CanonModelEntry {
    id: 0x01290000,
    name: "PowerShot G5",
  },
  CanonModelEntry {
    id: 0x01300000,
    name: "PowerShot A300",
  },
  CanonModelEntry {
    id: 0x01310000,
    name: "PowerShot S50",
  },
  CanonModelEntry {
    id: 0x01340000,
    name: "PowerShot A80",
  },
  CanonModelEntry {
    id: 0x01350000,
    name: "PowerShot SD10 / Digital IXUS i / IXY Digital L",
  },
  CanonModelEntry {
    id: 0x01360000,
    name: "PowerShot S1 IS",
  },
  CanonModelEntry {
    id: 0x01370000,
    name: "PowerShot Pro1",
  },
  CanonModelEntry {
    id: 0x01380000,
    name: "PowerShot S70",
  },
  CanonModelEntry {
    id: 0x01390000,
    name: "PowerShot S60",
  },
  CanonModelEntry {
    id: 0x01400000,
    name: "PowerShot G6",
  },
  CanonModelEntry {
    id: 0x01410000,
    name: "PowerShot S500 / Digital IXUS 500 / IXY Digital 500",
  },
  CanonModelEntry {
    id: 0x01420000,
    name: "PowerShot A75",
  },
  CanonModelEntry {
    id: 0x01440000,
    name: "PowerShot SD110 / Digital IXUS IIs / IXY Digital 30a",
  },
  CanonModelEntry {
    id: 0x01450000,
    name: "PowerShot A400",
  },
  CanonModelEntry {
    id: 0x01470000,
    name: "PowerShot A310",
  },
  CanonModelEntry {
    id: 0x01490000,
    name: "PowerShot A85",
  },
  CanonModelEntry {
    id: 0x01520000,
    name: "PowerShot S410 / Digital IXUS 430 / IXY Digital 450",
  },
  CanonModelEntry {
    id: 0x01530000,
    name: "PowerShot A95",
  },
  CanonModelEntry {
    id: 0x01540000,
    name: "PowerShot SD300 / Digital IXUS 40 / IXY Digital 50",
  },
  CanonModelEntry {
    id: 0x01550000,
    name: "PowerShot SD200 / Digital IXUS 30 / IXY Digital 40",
  },
  CanonModelEntry {
    id: 0x01560000,
    name: "PowerShot A520",
  },
  CanonModelEntry {
    id: 0x01570000,
    name: "PowerShot A510",
  },
  CanonModelEntry {
    id: 0x01590000,
    name: "PowerShot SD20 / Digital IXUS i5 / IXY Digital L2",
  },
  CanonModelEntry {
    id: 0x01640000,
    name: "PowerShot S2 IS",
  },
  CanonModelEntry {
    id: 0x01650000,
    name: "PowerShot SD430 / Digital IXUS Wireless / IXY Digital Wireless",
  },
  CanonModelEntry {
    id: 0x01660000,
    name: "PowerShot SD500 / Digital IXUS 700 / IXY Digital 600",
  },
  CanonModelEntry {
    id: 0x01668000,
    name: "EOS D60",
  },
  CanonModelEntry {
    id: 0x01700000,
    name: "PowerShot SD30 / Digital IXUS i Zoom / IXY Digital L3",
  },
  CanonModelEntry {
    id: 0x01740000,
    name: "PowerShot A430",
  },
  CanonModelEntry {
    id: 0x01750000,
    name: "PowerShot A410",
  },
  CanonModelEntry {
    id: 0x01760000,
    name: "PowerShot S80",
  },
  CanonModelEntry {
    id: 0x01780000,
    name: "PowerShot A620",
  },
  CanonModelEntry {
    id: 0x01790000,
    name: "PowerShot A610",
  },
  CanonModelEntry {
    id: 0x01800000,
    name: "PowerShot SD630 / Digital IXUS 65 / IXY Digital 80",
  },
  CanonModelEntry {
    id: 0x01810000,
    name: "PowerShot SD450 / Digital IXUS 55 / IXY Digital 60",
  },
  CanonModelEntry {
    id: 0x01820000,
    name: "PowerShot TX1",
  },
  CanonModelEntry {
    id: 0x01870000,
    name: "PowerShot SD400 / Digital IXUS 50 / IXY Digital 55",
  },
  CanonModelEntry {
    id: 0x01880000,
    name: "PowerShot A420",
  },
  CanonModelEntry {
    id: 0x01890000,
    name: "PowerShot SD900 / Digital IXUS 900 Ti / IXY Digital 1000",
  },
  CanonModelEntry {
    id: 0x01900000,
    name: "PowerShot SD550 / Digital IXUS 750 / IXY Digital 700",
  },
  CanonModelEntry {
    id: 0x01920000,
    name: "PowerShot A700",
  },
  CanonModelEntry {
    id: 0x01940000,
    name: "PowerShot SD700 IS / Digital IXUS 800 IS / IXY Digital 800 IS",
  },
  CanonModelEntry {
    id: 0x01950000,
    name: "PowerShot S3 IS",
  },
  CanonModelEntry {
    id: 0x01960000,
    name: "PowerShot A540",
  },
  CanonModelEntry {
    id: 0x01970000,
    name: "PowerShot SD600 / Digital IXUS 60 / IXY Digital 70",
  },
  CanonModelEntry {
    id: 0x01980000,
    name: "PowerShot G7",
  },
  CanonModelEntry {
    id: 0x01990000,
    name: "PowerShot A530",
  },
  CanonModelEntry {
    id: 0x02000000,
    name: "PowerShot SD800 IS / Digital IXUS 850 IS / IXY Digital 900 IS",
  },
  CanonModelEntry {
    id: 0x02010000,
    name: "PowerShot SD40 / Digital IXUS i7 / IXY Digital L4",
  },
  CanonModelEntry {
    id: 0x02020000,
    name: "PowerShot A710 IS",
  },
  CanonModelEntry {
    id: 0x02030000,
    name: "PowerShot A640",
  },
  CanonModelEntry {
    id: 0x02040000,
    name: "PowerShot A630",
  },
  CanonModelEntry {
    id: 0x02090000,
    name: "PowerShot S5 IS",
  },
  CanonModelEntry {
    id: 0x02100000,
    name: "PowerShot A460",
  },
  CanonModelEntry {
    id: 0x02120000,
    name: "PowerShot SD850 IS / Digital IXUS 950 IS / IXY Digital 810 IS",
  },
  CanonModelEntry {
    id: 0x02130000,
    name: "PowerShot A570 IS",
  },
  CanonModelEntry {
    id: 0x02140000,
    name: "PowerShot A560",
  },
  CanonModelEntry {
    id: 0x02150000,
    name: "PowerShot SD750 / Digital IXUS 75 / IXY Digital 90",
  },
  CanonModelEntry {
    id: 0x02160000,
    name: "PowerShot SD1000 / Digital IXUS 70 / IXY Digital 10",
  },
  CanonModelEntry {
    id: 0x02180000,
    name: "PowerShot A550",
  },
  CanonModelEntry {
    id: 0x02190000,
    name: "PowerShot A450",
  },
  CanonModelEntry {
    id: 0x02230000,
    name: "PowerShot G9",
  },
  CanonModelEntry {
    id: 0x02240000,
    name: "PowerShot A650 IS",
  },
  CanonModelEntry {
    id: 0x02260000,
    name: "PowerShot A720 IS",
  },
  CanonModelEntry {
    id: 0x02290000,
    name: "PowerShot SX100 IS",
  },
  CanonModelEntry {
    id: 0x02300000,
    name: "PowerShot SD950 IS / Digital IXUS 960 IS / IXY Digital 2000 IS",
  },
  CanonModelEntry {
    id: 0x02310000,
    name: "PowerShot SD870 IS / Digital IXUS 860 IS / IXY Digital 910 IS",
  },
  CanonModelEntry {
    id: 0x02320000,
    name: "PowerShot SD890 IS / Digital IXUS 970 IS / IXY Digital 820 IS",
  },
  CanonModelEntry {
    id: 0x02360000,
    name: "PowerShot SD790 IS / Digital IXUS 90 IS / IXY Digital 95 IS",
  },
  CanonModelEntry {
    id: 0x02370000,
    name: "PowerShot SD770 IS / Digital IXUS 85 IS / IXY Digital 25 IS",
  },
  CanonModelEntry {
    id: 0x02380000,
    name: "PowerShot A590 IS",
  },
  CanonModelEntry {
    id: 0x02390000,
    name: "PowerShot A580",
  },
  CanonModelEntry {
    id: 0x02420000,
    name: "PowerShot A470",
  },
  CanonModelEntry {
    id: 0x02430000,
    name: "PowerShot SD1100 IS / Digital IXUS 80 IS / IXY Digital 20 IS",
  },
  CanonModelEntry {
    id: 0x02460000,
    name: "PowerShot SX1 IS",
  },
  CanonModelEntry {
    id: 0x02470000,
    name: "PowerShot SX10 IS",
  },
  CanonModelEntry {
    id: 0x02480000,
    name: "PowerShot A1000 IS",
  },
  CanonModelEntry {
    id: 0x02490000,
    name: "PowerShot G10",
  },
  CanonModelEntry {
    id: 0x02510000,
    name: "PowerShot A2000 IS",
  },
  CanonModelEntry {
    id: 0x02520000,
    name: "PowerShot SX110 IS",
  },
  CanonModelEntry {
    id: 0x02530000,
    name: "PowerShot SD990 IS / Digital IXUS 980 IS / IXY Digital 3000 IS",
  },
  CanonModelEntry {
    id: 0x02540000,
    name: "PowerShot SD880 IS / Digital IXUS 870 IS / IXY Digital 920 IS",
  },
  CanonModelEntry {
    id: 0x02550000,
    name: "PowerShot E1",
  },
  CanonModelEntry {
    id: 0x02560000,
    name: "PowerShot D10",
  },
  CanonModelEntry {
    id: 0x02570000,
    name: "PowerShot SD960 IS / Digital IXUS 110 IS / IXY Digital 510 IS",
  },
  CanonModelEntry {
    id: 0x02580000,
    name: "PowerShot A2100 IS",
  },
  CanonModelEntry {
    id: 0x02590000,
    name: "PowerShot A480",
  },
  CanonModelEntry {
    id: 0x02600000,
    name: "PowerShot SX200 IS",
  },
  CanonModelEntry {
    id: 0x02610000,
    name: "PowerShot SD970 IS / Digital IXUS 990 IS / IXY Digital 830 IS",
  },
  CanonModelEntry {
    id: 0x02620000,
    name: "PowerShot SD780 IS / Digital IXUS 100 IS / IXY Digital 210 IS",
  },
  CanonModelEntry {
    id: 0x02630000,
    name: "PowerShot A1100 IS",
  },
  CanonModelEntry {
    id: 0x02640000,
    name: "PowerShot SD1200 IS / Digital IXUS 95 IS / IXY Digital 110 IS",
  },
  CanonModelEntry {
    id: 0x02700000,
    name: "PowerShot G11",
  },
  CanonModelEntry {
    id: 0x02710000,
    name: "PowerShot SX120 IS",
  },
  CanonModelEntry {
    id: 0x02720000,
    name: "PowerShot S90",
  },
  CanonModelEntry {
    id: 0x02750000,
    name: "PowerShot SX20 IS",
  },
  CanonModelEntry {
    id: 0x02760000,
    name: "PowerShot SD980 IS / Digital IXUS 200 IS / IXY Digital 930 IS",
  },
  CanonModelEntry {
    id: 0x02770000,
    name: "PowerShot SD940 IS / Digital IXUS 120 IS / IXY Digital 220 IS",
  },
  CanonModelEntry {
    id: 0x02800000,
    name: "PowerShot A495",
  },
  CanonModelEntry {
    id: 0x02810000,
    name: "PowerShot A490",
  },
  CanonModelEntry {
    id: 0x02820000,
    name: "PowerShot A3100/A3150 IS",
  },
  CanonModelEntry {
    id: 0x02830000,
    name: "PowerShot A3000 IS",
  },
  CanonModelEntry {
    id: 0x02840000,
    name: "PowerShot SD1400 IS / IXUS 130 / IXY 400F",
  },
  CanonModelEntry {
    id: 0x02850000,
    name: "PowerShot SD1300 IS / IXUS 105 / IXY 200F",
  },
  CanonModelEntry {
    id: 0x02860000,
    name: "PowerShot SD3500 IS / IXUS 210 / IXY 10S",
  },
  CanonModelEntry {
    id: 0x02870000,
    name: "PowerShot SX210 IS",
  },
  CanonModelEntry {
    id: 0x02880000,
    name: "PowerShot SD4000 IS / IXUS 300 HS / IXY 30S",
  },
  CanonModelEntry {
    id: 0x02890000,
    name: "PowerShot SD4500 IS / IXUS 1000 HS / IXY 50S",
  },
  CanonModelEntry {
    id: 0x02920000,
    name: "PowerShot G12",
  },
  CanonModelEntry {
    id: 0x02930000,
    name: "PowerShot SX30 IS",
  },
  CanonModelEntry {
    id: 0x02940000,
    name: "PowerShot SX130 IS",
  },
  CanonModelEntry {
    id: 0x02950000,
    name: "PowerShot S95",
  },
  CanonModelEntry {
    id: 0x02980000,
    name: "PowerShot A3300 IS",
  },
  CanonModelEntry {
    id: 0x02990000,
    name: "PowerShot A3200 IS",
  },
  CanonModelEntry {
    id: 0x03000000,
    name: "PowerShot ELPH 500 HS / IXUS 310 HS / IXY 31S",
  },
  CanonModelEntry {
    id: 0x03010000,
    name: "PowerShot Pro90 IS",
  },
  CanonModelEntry {
    id: 0x03010001,
    name: "PowerShot A800",
  },
  CanonModelEntry {
    id: 0x03020000,
    name: "PowerShot ELPH 100 HS / IXUS 115 HS / IXY 210F",
  },
  CanonModelEntry {
    id: 0x03030000,
    name: "PowerShot SX230 HS",
  },
  CanonModelEntry {
    id: 0x03040000,
    name: "PowerShot ELPH 300 HS / IXUS 220 HS / IXY 410F",
  },
  CanonModelEntry {
    id: 0x03050000,
    name: "PowerShot A2200",
  },
  CanonModelEntry {
    id: 0x03060000,
    name: "PowerShot A1200",
  },
  CanonModelEntry {
    id: 0x03070000,
    name: "PowerShot SX220 HS",
  },
  CanonModelEntry {
    id: 0x03080000,
    name: "PowerShot G1 X",
  },
  CanonModelEntry {
    id: 0x03090000,
    name: "PowerShot SX150 IS",
  },
  CanonModelEntry {
    id: 0x03100000,
    name: "PowerShot ELPH 510 HS / IXUS 1100 HS / IXY 51S",
  },
  CanonModelEntry {
    id: 0x03110000,
    name: "PowerShot S100 (new)",
  },
  CanonModelEntry {
    id: 0x03120000,
    name: "PowerShot ELPH 310 HS / IXUS 230 HS / IXY 600F",
  },
  CanonModelEntry {
    id: 0x03130000,
    name: "PowerShot SX40 HS",
  },
  CanonModelEntry {
    id: 0x03140000,
    name: "IXY 32S",
  },
  CanonModelEntry {
    id: 0x03160000,
    name: "PowerShot A1300",
  },
  CanonModelEntry {
    id: 0x03170000,
    name: "PowerShot A810",
  },
  CanonModelEntry {
    id: 0x03180000,
    name: "PowerShot ELPH 320 HS / IXUS 240 HS / IXY 420F",
  },
  CanonModelEntry {
    id: 0x03190000,
    name: "PowerShot ELPH 110 HS / IXUS 125 HS / IXY 220F",
  },
  CanonModelEntry {
    id: 0x03200000,
    name: "PowerShot D20",
  },
  CanonModelEntry {
    id: 0x03210000,
    name: "PowerShot A4000 IS",
  },
  CanonModelEntry {
    id: 0x03220000,
    name: "PowerShot SX260 HS",
  },
  CanonModelEntry {
    id: 0x03230000,
    name: "PowerShot SX240 HS",
  },
  CanonModelEntry {
    id: 0x03240000,
    name: "PowerShot ELPH 530 HS / IXUS 510 HS / IXY 1",
  },
  CanonModelEntry {
    id: 0x03250000,
    name: "PowerShot ELPH 520 HS / IXUS 500 HS / IXY 3",
  },
  CanonModelEntry {
    id: 0x03260000,
    name: "PowerShot A3400 IS",
  },
  CanonModelEntry {
    id: 0x03270000,
    name: "PowerShot A2400 IS",
  },
  CanonModelEntry {
    id: 0x03280000,
    name: "PowerShot A2300",
  },
  CanonModelEntry {
    id: 0x03320000,
    name: "PowerShot S100V",
  },
  CanonModelEntry {
    id: 0x03330000,
    name: "PowerShot G15",
  },
  CanonModelEntry {
    id: 0x03340000,
    name: "PowerShot SX50 HS",
  },
  CanonModelEntry {
    id: 0x03350000,
    name: "PowerShot SX160 IS",
  },
  CanonModelEntry {
    id: 0x03360000,
    name: "PowerShot S110 (new)",
  },
  CanonModelEntry {
    id: 0x03370000,
    name: "PowerShot SX500 IS",
  },
  CanonModelEntry {
    id: 0x03380000,
    name: "PowerShot N",
  },
  CanonModelEntry {
    id: 0x03390000,
    name: "IXUS 245 HS / IXY 430F",
  },
  CanonModelEntry {
    id: 0x03400000,
    name: "PowerShot SX280 HS",
  },
  CanonModelEntry {
    id: 0x03410000,
    name: "PowerShot SX270 HS",
  },
  CanonModelEntry {
    id: 0x03420000,
    name: "PowerShot A3500 IS",
  },
  CanonModelEntry {
    id: 0x03430000,
    name: "PowerShot A2600",
  },
  CanonModelEntry {
    id: 0x03440000,
    name: "PowerShot SX275 HS",
  },
  CanonModelEntry {
    id: 0x03450000,
    name: "PowerShot A1400",
  },
  CanonModelEntry {
    id: 0x03460000,
    name: "PowerShot ELPH 130 IS / IXUS 140 / IXY 110F",
  },
  CanonModelEntry {
    id: 0x03470000,
    name: "PowerShot ELPH 115/120 IS / IXUS 132/135 / IXY 90F/100F",
  },
  CanonModelEntry {
    id: 0x03490000,
    name: "PowerShot ELPH 330 HS / IXUS 255 HS / IXY 610F",
  },
  CanonModelEntry {
    id: 0x03510000,
    name: "PowerShot A2500",
  },
  CanonModelEntry {
    id: 0x03540000,
    name: "PowerShot G16",
  },
  CanonModelEntry {
    id: 0x03550000,
    name: "PowerShot S120",
  },
  CanonModelEntry {
    id: 0x03560000,
    name: "PowerShot SX170 IS",
  },
  CanonModelEntry {
    id: 0x03580000,
    name: "PowerShot SX510 HS",
  },
  CanonModelEntry {
    id: 0x03590000,
    name: "PowerShot S200 (new)",
  },
  CanonModelEntry {
    id: 0x03600000,
    name: "IXY 620F",
  },
  CanonModelEntry {
    id: 0x03610000,
    name: "PowerShot N100",
  },
  CanonModelEntry {
    id: 0x03640000,
    name: "PowerShot G1 X Mark II",
  },
  CanonModelEntry {
    id: 0x03650000,
    name: "PowerShot D30",
  },
  CanonModelEntry {
    id: 0x03660000,
    name: "PowerShot SX700 HS",
  },
  CanonModelEntry {
    id: 0x03670000,
    name: "PowerShot SX600 HS",
  },
  CanonModelEntry {
    id: 0x03680000,
    name: "PowerShot ELPH 140 IS / IXUS 150 / IXY 130",
  },
  CanonModelEntry {
    id: 0x03690000,
    name: "PowerShot ELPH 135 / IXUS 145 / IXY 120",
  },
  CanonModelEntry {
    id: 0x03700000,
    name: "PowerShot ELPH 340 HS / IXUS 265 HS / IXY 630",
  },
  CanonModelEntry {
    id: 0x03710000,
    name: "PowerShot ELPH 150 IS / IXUS 155 / IXY 140",
  },
  CanonModelEntry {
    id: 0x03740000,
    name: "EOS M3",
  },
  CanonModelEntry {
    id: 0x03750000,
    name: "PowerShot SX60 HS",
  },
  CanonModelEntry {
    id: 0x03760000,
    name: "PowerShot SX520 HS",
  },
  CanonModelEntry {
    id: 0x03770000,
    name: "PowerShot SX400 IS",
  },
  CanonModelEntry {
    id: 0x03780000,
    name: "PowerShot G7 X",
  },
  CanonModelEntry {
    id: 0x03790000,
    name: "PowerShot N2",
  },
  CanonModelEntry {
    id: 0x03800000,
    name: "PowerShot SX530 HS",
  },
  CanonModelEntry {
    id: 0x03820000,
    name: "PowerShot SX710 HS",
  },
  CanonModelEntry {
    id: 0x03830000,
    name: "PowerShot SX610 HS",
  },
  CanonModelEntry {
    id: 0x03840000,
    name: "EOS M10",
  },
  CanonModelEntry {
    id: 0x03850000,
    name: "PowerShot G3 X",
  },
  CanonModelEntry {
    id: 0x03860000,
    name: "PowerShot ELPH 165 HS / IXUS 165 / IXY 160",
  },
  CanonModelEntry {
    id: 0x03870000,
    name: "PowerShot ELPH 160 / IXUS 160",
  },
  CanonModelEntry {
    id: 0x03880000,
    name: "PowerShot ELPH 350 HS / IXUS 275 HS / IXY 640",
  },
  CanonModelEntry {
    id: 0x03890000,
    name: "PowerShot ELPH 170 IS / IXUS 170",
  },
  CanonModelEntry {
    id: 0x03910000,
    name: "PowerShot SX410 IS",
  },
  CanonModelEntry {
    id: 0x03930000,
    name: "PowerShot G9 X",
  },
  CanonModelEntry {
    id: 0x03940000,
    name: "EOS M5",
  },
  CanonModelEntry {
    id: 0x03950000,
    name: "PowerShot G5 X",
  },
  CanonModelEntry {
    id: 0x03970000,
    name: "PowerShot G7 X Mark II",
  },
  CanonModelEntry {
    id: 0x03980000,
    name: "EOS M100",
  },
  CanonModelEntry {
    id: 0x03990000,
    name: "PowerShot ELPH 360 HS / IXUS 285 HS / IXY 650",
  },
  CanonModelEntry {
    id: 0x04010000,
    name: "PowerShot SX540 HS",
  },
  CanonModelEntry {
    id: 0x04020000,
    name: "PowerShot SX420 IS",
  },
  CanonModelEntry {
    id: 0x04030000,
    name: "PowerShot ELPH 190 IS / IXUS 180 / IXY 190",
  },
  CanonModelEntry {
    id: 0x04040000,
    name: "PowerShot G1",
  },
  CanonModelEntry {
    id: 0x04040001,
    name: "PowerShot ELPH 180 IS / IXUS 175 / IXY 180",
  },
  CanonModelEntry {
    id: 0x04050000,
    name: "PowerShot SX720 HS",
  },
  CanonModelEntry {
    id: 0x04060000,
    name: "PowerShot SX620 HS",
  },
  CanonModelEntry {
    id: 0x04070000,
    name: "EOS M6",
  },
  CanonModelEntry {
    id: 0x04100000,
    name: "PowerShot G9 X Mark II",
  },
  CanonModelEntry {
    id: 0x04150000,
    name: "PowerShot ELPH 185 / IXUS 185 / IXY 200",
  },
  CanonModelEntry {
    id: 0x04160000,
    name: "PowerShot SX430 IS",
  },
  CanonModelEntry {
    id: 0x04170000,
    name: "PowerShot SX730 HS",
  },
  CanonModelEntry {
    id: 0x04180000,
    name: "PowerShot G1 X Mark III",
  },
  CanonModelEntry {
    id: 0x06040000,
    name: "PowerShot S100 / Digital IXUS / IXY Digital",
  },
  CanonModelEntry {
    id: 0x40000227,
    name: "EOS C50",
  },
  CanonModelEntry {
    id: 0x4007d673,
    name: "DC19/DC21/DC22",
  },
  CanonModelEntry {
    id: 0x4007d674,
    name: "XH A1",
  },
  CanonModelEntry {
    id: 0x4007d675,
    name: "HV10",
  },
  CanonModelEntry {
    id: 0x4007d676,
    name: "MD130/MD140/MD150/MD160/ZR850",
  },
  CanonModelEntry {
    id: 0x4007d777,
    name: "DC50",
  },
  CanonModelEntry {
    id: 0x4007d778,
    name: "HV20",
  },
  CanonModelEntry {
    id: 0x4007d779,
    name: "DC211",
  },
  CanonModelEntry {
    id: 0x4007d77a,
    name: "HG10",
  },
  CanonModelEntry {
    id: 0x4007d77b,
    name: "HR10",
  },
  CanonModelEntry {
    id: 0x4007d77d,
    name: "MD255/ZR950",
  },
  CanonModelEntry {
    id: 0x4007d81c,
    name: "HF11",
  },
  CanonModelEntry {
    id: 0x4007d878,
    name: "HV30",
  },
  CanonModelEntry {
    id: 0x4007d87c,
    name: "XH A1S",
  },
  CanonModelEntry {
    id: 0x4007d87e,
    name: "DC301/DC310/DC311/DC320/DC330",
  },
  CanonModelEntry {
    id: 0x4007d87f,
    name: "FS100",
  },
  CanonModelEntry {
    id: 0x4007d880,
    name: "HF10",
  },
  CanonModelEntry {
    id: 0x4007d882,
    name: "HG20/HG21",
  },
  CanonModelEntry {
    id: 0x4007d925,
    name: "HF21",
  },
  CanonModelEntry {
    id: 0x4007d926,
    name: "HF S11",
  },
  CanonModelEntry {
    id: 0x4007d978,
    name: "HV40",
  },
  CanonModelEntry {
    id: 0x4007d987,
    name: "DC410/DC411/DC420",
  },
  CanonModelEntry {
    id: 0x4007d988,
    name: "FS19/FS20/FS21/FS22/FS200",
  },
  CanonModelEntry {
    id: 0x4007d989,
    name: "HF20/HF200",
  },
  CanonModelEntry {
    id: 0x4007d98a,
    name: "HF S10/S100",
  },
  CanonModelEntry {
    id: 0x4007da8e,
    name: "HF R10/R16/R17/R18/R100/R106",
  },
  CanonModelEntry {
    id: 0x4007da8f,
    name: "HF M30/M31/M36/M300/M306",
  },
  CanonModelEntry {
    id: 0x4007da90,
    name: "HF S20/S21/S200",
  },
  CanonModelEntry {
    id: 0x4007da92,
    name: "FS31/FS36/FS37/FS300/FS305/FS306/FS307",
  },
  CanonModelEntry {
    id: 0x4007dca0,
    name: "EOS C300",
  },
  CanonModelEntry {
    id: 0x4007dda9,
    name: "HF G25",
  },
  CanonModelEntry {
    id: 0x4007dfb4,
    name: "XC10",
  },
  CanonModelEntry {
    id: 0x4007e1c3,
    name: "EOS C200",
  },
  CanonModelEntry {
    id: 0x80000001,
    name: "EOS-1D",
  },
  CanonModelEntry {
    id: 0x80000167,
    name: "EOS-1DS",
  },
  CanonModelEntry {
    id: 0x80000168,
    name: "EOS 10D",
  },
  CanonModelEntry {
    id: 0x80000169,
    name: "EOS-1D Mark III",
  },
  CanonModelEntry {
    id: 0x80000170,
    name: "EOS Digital Rebel / 300D / Kiss Digital",
  },
  CanonModelEntry {
    id: 0x80000174,
    name: "EOS-1D Mark II",
  },
  CanonModelEntry {
    id: 0x80000175,
    name: "EOS 20D",
  },
  CanonModelEntry {
    id: 0x80000176,
    name: "EOS Digital Rebel XSi / 450D / Kiss X2",
  },
  CanonModelEntry {
    id: 0x80000188,
    name: "EOS-1Ds Mark II",
  },
  CanonModelEntry {
    id: 0x80000189,
    name: "EOS Digital Rebel XT / 350D / Kiss Digital N",
  },
  CanonModelEntry {
    id: 0x80000190,
    name: "EOS 40D",
  },
  CanonModelEntry {
    id: 0x80000213,
    name: "EOS 5D",
  },
  CanonModelEntry {
    id: 0x80000215,
    name: "EOS-1Ds Mark III",
  },
  CanonModelEntry {
    id: 0x80000218,
    name: "EOS 5D Mark II",
  },
  CanonModelEntry {
    id: 0x80000219,
    name: "WFT-E1",
  },
  CanonModelEntry {
    id: 0x80000232,
    name: "EOS-1D Mark II N",
  },
  CanonModelEntry {
    id: 0x80000234,
    name: "EOS 30D",
  },
  CanonModelEntry {
    id: 0x80000236,
    name: "EOS Digital Rebel XTi / 400D / Kiss Digital X",
  },
  CanonModelEntry {
    id: 0x80000241,
    name: "WFT-E2",
  },
  CanonModelEntry {
    id: 0x80000246,
    name: "WFT-E3",
  },
  CanonModelEntry {
    id: 0x80000250,
    name: "EOS 7D",
  },
  CanonModelEntry {
    id: 0x80000252,
    name: "EOS Rebel T1i / 500D / Kiss X3",
  },
  CanonModelEntry {
    id: 0x80000254,
    name: "EOS Rebel XS / 1000D / Kiss F",
  },
  CanonModelEntry {
    id: 0x80000261,
    name: "EOS 50D",
  },
  CanonModelEntry {
    id: 0x80000269,
    name: "EOS-1D X",
  },
  CanonModelEntry {
    id: 0x80000270,
    name: "EOS Rebel T2i / 550D / Kiss X4",
  },
  CanonModelEntry {
    id: 0x80000271,
    name: "WFT-E4",
  },
  CanonModelEntry {
    id: 0x80000273,
    name: "WFT-E5",
  },
  CanonModelEntry {
    id: 0x80000281,
    name: "EOS-1D Mark IV",
  },
  CanonModelEntry {
    id: 0x80000285,
    name: "EOS 5D Mark III",
  },
  CanonModelEntry {
    id: 0x80000286,
    name: "EOS Rebel T3i / 600D / Kiss X5",
  },
  CanonModelEntry {
    id: 0x80000287,
    name: "EOS 60D",
  },
  CanonModelEntry {
    id: 0x80000288,
    name: "EOS Rebel T3 / 1100D / Kiss X50",
  },
  CanonModelEntry {
    id: 0x80000289,
    name: "EOS 7D Mark II",
  },
  CanonModelEntry {
    id: 0x80000297,
    name: "WFT-E2 II",
  },
  CanonModelEntry {
    id: 0x80000298,
    name: "WFT-E4 II",
  },
  CanonModelEntry {
    id: 0x80000301,
    name: "EOS Rebel T4i / 650D / Kiss X6i",
  },
  CanonModelEntry {
    id: 0x80000302,
    name: "EOS 6D",
  },
  CanonModelEntry {
    id: 0x80000324,
    name: "EOS-1D C",
  },
  CanonModelEntry {
    id: 0x80000325,
    name: "EOS 70D",
  },
  CanonModelEntry {
    id: 0x80000326,
    name: "EOS Rebel T5i / 700D / Kiss X7i",
  },
  CanonModelEntry {
    id: 0x80000327,
    name: "EOS Rebel T5 / 1200D / Kiss X70 / Hi",
  },
  CanonModelEntry {
    id: 0x80000328,
    name: "EOS-1D X Mark II",
  },
  CanonModelEntry {
    id: 0x80000331,
    name: "EOS M",
  },
  CanonModelEntry {
    id: 0x80000346,
    name: "EOS Rebel SL1 / 100D / Kiss X7",
  },
  CanonModelEntry {
    id: 0x80000347,
    name: "EOS Rebel T6s / 760D / 8000D",
  },
  CanonModelEntry {
    id: 0x80000349,
    name: "EOS 5D Mark IV",
  },
  CanonModelEntry {
    id: 0x80000350,
    name: "EOS 80D",
  },
  CanonModelEntry {
    id: 0x80000355,
    name: "EOS M2",
  },
  CanonModelEntry {
    id: 0x80000382,
    name: "EOS 5DS",
  },
  CanonModelEntry {
    id: 0x80000393,
    name: "EOS Rebel T6i / 750D / Kiss X8i",
  },
  CanonModelEntry {
    id: 0x80000401,
    name: "EOS 5DS R",
  },
  CanonModelEntry {
    id: 0x80000404,
    name: "EOS Rebel T6 / 1300D / Kiss X80",
  },
  CanonModelEntry {
    id: 0x80000405,
    name: "EOS Rebel T7i / 800D / Kiss X9i",
  },
  CanonModelEntry {
    id: 0x80000406,
    name: "EOS 6D Mark II",
  },
  CanonModelEntry {
    id: 0x80000408,
    name: "EOS 77D / 9000D",
  },
  CanonModelEntry {
    id: 0x80000417,
    name: "EOS Rebel SL2 / 200D / Kiss X9",
  },
  CanonModelEntry {
    id: 0x80000421,
    name: "EOS R5",
  },
  CanonModelEntry {
    id: 0x80000422,
    name: "EOS Rebel T100 / 4000D / 3000D",
  },
  CanonModelEntry {
    id: 0x80000424,
    name: "EOS R",
  },
  CanonModelEntry {
    id: 0x80000428,
    name: "EOS-1D X Mark III",
  },
  CanonModelEntry {
    id: 0x80000432,
    name: "EOS Rebel T7 / 2000D / 1500D / Kiss X90",
  },
  CanonModelEntry {
    id: 0x80000433,
    name: "EOS RP",
  },
  CanonModelEntry {
    id: 0x80000435,
    name: "EOS Rebel T8i / 850D / X10i",
  },
  CanonModelEntry {
    id: 0x80000436,
    name: "EOS SL3 / 250D / Kiss X10",
  },
  CanonModelEntry {
    id: 0x80000437,
    name: "EOS 90D",
  },
  CanonModelEntry {
    id: 0x80000450,
    name: "EOS R3",
  },
  CanonModelEntry {
    id: 0x80000453,
    name: "EOS R6",
  },
  CanonModelEntry {
    id: 0x80000464,
    name: "EOS R7",
  },
  CanonModelEntry {
    id: 0x80000465,
    name: "EOS R10",
  },
  CanonModelEntry {
    id: 0x80000467,
    name: "PowerShot ZOOM",
  },
  CanonModelEntry {
    id: 0x80000468,
    name: "EOS M50 Mark II / Kiss M2",
  },
  CanonModelEntry {
    id: 0x80000480,
    name: "EOS R50",
  },
  CanonModelEntry {
    id: 0x80000481,
    name: "EOS R6 Mark II",
  },
  CanonModelEntry {
    id: 0x80000487,
    name: "EOS R8",
  },
  CanonModelEntry {
    id: 0x80000491,
    name: "PowerShot V10",
  },
  CanonModelEntry {
    id: 0x80000495,
    name: "EOS R1",
  },
  CanonModelEntry {
    id: 0x80000496,
    name: "EOS R5 Mark II",
  },
  CanonModelEntry {
    id: 0x80000497,
    name: "PowerShot V1",
  },
  CanonModelEntry {
    id: 0x80000498,
    name: "EOS R100",
  },
  CanonModelEntry {
    id: 0x80000516,
    name: "EOS R50 V",
  },
  CanonModelEntry {
    id: 0x80000518,
    name: "EOS R6 Mark III",
  },
  CanonModelEntry {
    id: 0x80000520,
    name: "EOS D2000C",
  },
  CanonModelEntry {
    id: 0x80000560,
    name: "EOS D6000C",
  },
];

/// Look up a Canon model ID. Returns `None` for an unknown ID.
#[must_use]
pub fn lookup(id: u32) -> Option<&'static CanonModelEntry> {
  let idx = CANON_MODEL_IDS.binary_search_by_key(&id, |e| e.id).ok()?;
  Some(&CANON_MODEL_IDS[idx])
}

/// Resolve a model ID into a [`SmolStr`] for storage.
#[must_use]
pub fn lookup_name(id: u32) -> Option<SmolStr> {
  lookup(id).map(|e| SmolStr::from(e.name))
}

#[cfg(test)]
mod tests {
  use super::*;

  #[test]
  fn model_table_sorted() {
    let mut prev = 0u32;
    for e in CANON_MODEL_IDS {
      assert!(
        e.id > prev || prev == 0,
        "model table out of order at 0x{:08x}",
        e.id
      );
      prev = e.id;
    }
  }

  #[test]
  fn ten_representative_models_resolve() {
    let cases = [
      (0x1010000u32, "PowerShot A30"),
      (0x1140000, "EOS D30"),
      (0x80000174, "EOS-1D Mark II"),
      (0x80000189, "EOS Digital Rebel XT / 350D / Kiss Digital N"),
      (0x80000190, "EOS 40D"),
      (0x80000218, "EOS 5D Mark II"),
      (0x80000250, "EOS 7D"),
      (0x80000252, "EOS Rebel T1i / 500D / Kiss X3"),
      (0x80000269, "EOS-1D X"),
      (0x80000270, "EOS Rebel T2i / 550D / Kiss X4"),
    ];
    for (id, expected_name) in cases {
      let e = lookup(id).unwrap_or_else(|| panic!("model 0x{id:08x}"));
      assert_eq!(e.name, expected_name, "model id 0x{id:08x}");
    }
  }

  #[test]
  fn lookup_unknown_returns_none() {
    assert!(lookup(0xdeadbeef).is_none());
  }
}
