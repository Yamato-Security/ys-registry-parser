//! Damaged hives and arbitrary bytes: read as far as they go, never a panic or a hang.
#![allow(clippy::unwrap_used)]

use std::io::Read;
use std::sync::OnceLock;

use proptest::prelude::*;
use ys_registry_parser::ntuser::{profile_name, recent_docs};
use ys_registry_parser::system::{ControlSets, computer_name, services};

fn fixture(name: &str) -> Vec<u8> {
    let path = format!(
        "{}/tests/fixtures/regipy/{name}.gz",
        env!("CARGO_MANIFEST_DIR")
    );
    let mut data = Vec::new();
    flate2::read::GzDecoder::new(std::fs::File::open(path).unwrap())
        .read_to_end(&mut data)
        .unwrap();
    data
}

/// The SYSTEM hive, unpacked once.
fn system() -> &'static [u8] {
    static SYSTEM: OnceLock<Vec<u8>> = OnceLock::new();
    SYSTEM.get_or_init(|| fixture("SYSTEM"))
}

/// The NTUSER.DAT hive, unpacked once.
fn ntuser() -> &'static [u8] {
    static NTUSER: OnceLock<Vec<u8>> = OnceLock::new();
    NTUSER.get_or_init(|| fixture("NTUSER.DAT"))
}

/// Flip bytes of `data` past its base block.
fn damage(mut data: Vec<u8>, flips: Vec<(usize, u8)>) -> Vec<u8> {
    for (at, byte) in flips {
        let at = 4096 + at % (data.len() - 4096);
        data[at] = byte;
    }
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
    let sets = ControlSets::read(&hive);
    let _ = computer_name(&hive);
    for set in sets.present {
        let _ = services(&hive, set);
    }
    let _ = (recent_docs(&hive), profile_name(&hive));
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
        read_all(damage(fixture("SAM"), flips));
    }
}

proptest! {
    #![proptest_config(ProptestConfig::with_cases(32))]

    #[test]
    fn a_damaged_system_hive(
        flips in proptest::collection::vec((any::<usize>(), any::<u8>()), 1..3000)
    ) {
        read_all(damage(system().to_vec(), flips));
    }

    #[test]
    fn a_damaged_ntuser_hive(
        flips in proptest::collection::vec((any::<usize>(), any::<u8>()), 1..3000)
    ) {
        read_all(damage(ntuser().to_vec(), flips));
    }
}
