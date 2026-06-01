//! Golden-v2 Contract 3b: public untrusted-input entry points must never panic.
use proptest::prelude::*;
proptest! {
    #![proptest_config(ProptestConfig { cases: 4096, ..ProptestConfig::default() })]
    #[test] fn parse_bytes_never_panics(data in proptest::collection::vec(any::<u8>(), 0..4096)) { let _ = exifast::parse_bytes(&data); }
    #[test] fn media_metadata_never_panics(data in proptest::collection::vec(any::<u8>(), 0..4096)) { let _ = exifast::media_metadata(&data); }
    #[test] fn parse_exif_block_never_panics(data in proptest::collection::vec(any::<u8>(), 0..4096)) { let _ = exifast::parse_exif_block(&data); }
}
proptest! {
    #![proptest_config(ProptestConfig { cases: 4096, ..ProptestConfig::default() })]
    #[test] fn parse_bytes_never_panics_atomish(chunks in proptest::collection::vec((any::<[u8;4]>(), any::<u32>()), 0..256)) {
        let mut data = std::vec::Vec::new();
        for (tag, size) in chunks { data.extend_from_slice(&size.to_be_bytes()); data.extend_from_slice(&tag); }
        let _ = exifast::parse_bytes(&data);
    }
}
