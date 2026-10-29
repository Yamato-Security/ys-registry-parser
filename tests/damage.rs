//! Damaged hives and arbitrary bytes: read as far as they go, never a panic or a hang.
#![allow(clippy::unwrap_used)]

use std::io::Read;

use proptest::prelude::*;

fn fixture() -> Vec<u8> {
    let path = format!(
        "{}/tests/fixtures/regipy/SAM.gz",
        env!("CARGO_MANIFEST_DIR")
    );
    let mut data = Vec::new();
    flate2::read::GzDecoder::new(std::fs::File::open(path).unwrap())
        .read_to_end(&mut data)
        .unwrap();
    data
}

/// Read everything there is to read.
fn read_all(data: Vec<u8>) {
    let Ok((hive, _)) = ys_registry_parser::Hive::open(data, &[]) else {
        return;
    };
    for entry in hive.walk() {
        let _ = (entry.key.name(), entry.key.class_name(), entry.key.status());
        for value in entry.key.values().0 {
            let (data, _) = value.read_data();
            let _ = ys_registry_parser::decode(value.data_type(), &data);
        }
    }
    let _ = hive.deleted();
}

proptest! {
    #![proptest_config(ProptestConfig::with_cases(128))]

    #[test]
    fn arbitrary_bytes(mut data in proptest::collection::vec(any::<u8>(), 0..20_000)) {
        if data.len() >= 4 {
            data[..4].copy_from_slice(b"regf");
        }
        read_all(data);
    }

    #[test]
    fn a_damaged_hive(flips in proptest::collection::vec((any::<usize>(), any::<u8>()), 1..300)) {
        let mut data = fixture();
        for (at, byte) in flips {
            let at = 4096 + at % (data.len() - 4096);
            data[at] = byte;
        }
        read_all(data);
    }
}
