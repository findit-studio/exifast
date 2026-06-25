//! Smoke coverage for the real-device MakerNote fixtures that unblock the
//! deferred Sony (#97-#103) and Canon (#84/#85/#87) table ports.
#![cfg(feature = "json")]

use exifast::parser::extract_info;

#[test]
fn real_device_makernote_fixtures_parse() {
  let root = env!("CARGO_MANIFEST_DIR");
  for (fixture, model) in [
    ("Sony_DSLR-A200_real.ARW", "DSLR-A200"),
    ("Sony_SLT-A33_real.ARW", "SLT-A33"),
    ("Sony_ILME-FX3_real.ARW", "ILME-FX3"),
    ("Canon_EOS-1D_real.TIF", "Canon EOS-1D"),
    ("Canon_EOS-5D_real.CR2", "Canon EOS 5D"),
    ("Canon_EOS-7D_sRAW_real.CR2", "Canon EOS 7D"),
  ] {
    let data = std::fs::read(format!("{root}/tests/fixtures/{fixture}"))
      .unwrap_or_else(|e| panic!("read {fixture}: {e}"));
    assert_eq!(
      data.len(),
      1024 * 1024,
      "{fixture} should retain only the 1 MiB metadata-bearing prefix"
    );

    for print_conv in [true, false] {
      let json = extract_info(fixture, &data, print_conv);
      let parsed: serde_json::Value = serde_json::from_str(&json)
        .unwrap_or_else(|e| panic!("{fixture} produced invalid JSON: {e}\n{json}"));
      assert!(parsed.is_array(), "{fixture} output should be a JSON array");
      assert!(
        json.contains(model),
        "{fixture} should retain its real camera model in print_conv={print_conv} output"
      );
    }
  }
}
