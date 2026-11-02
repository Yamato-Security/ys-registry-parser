//! Damaged hives and arbitrary bytes: read as far as they go, never a panic or a hang.
#![allow(clippy::unwrap_used)]

use std::io::Read;
use std::sync::OnceLock;

use proptest::prelude::*;
use ys_registry_parser::ntuser::{
    classes_sid, profile_name, recent_docs, user_assist, user_assist_data, user_assist_settings,
};
use ys_registry_parser::office::{mru_item, office, trust_record};
use ys_registry_parser::persistence::{self, MachineClasses};
use ys_registry_parser::sam::{accounts, user_f, user_v};
use ys_registry_parser::software::{dynamic_info, profile_list, task_actions, task_cache};
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

/// Plaso's Windows 7 NTUSER.DAT, with Office lists and trust records, unpacked once.
fn plaso_win7() -> &'static [u8] {
    static NTUSER: OnceLock<Vec<u8>> = OnceLock::new();
    NTUSER.get_or_init(|| {
        let path = format!(
            "{}/tests/fixtures/plaso/NTUSER-WIN7.DAT.gz",
            env!("CARGO_MANIFEST_DIR")
        );
        let mut data = Vec::new();
        flate2::read::GzDecoder::new(std::fs::File::open(path).unwrap())
            .read_to_end(&mut data)
            .unwrap();
        data
    })
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
        let _ = persistence::system(&hive, set);
    }
    let _ = (recent_docs(&hive), profile_name(&hive), task_cache(&hive));
    let _ = (user_assist(&hive), user_assist_settings(&hive));
    let _ = (accounts(&hive), office(&hive));
    let machine = MachineClasses::read(&hive);
    let _ = (persistence::software(&hive), profile_list(&hive));
    let _ = persistence::ntuser(&hive, Some(&machine));
    let _ = (
        persistence::usrclass(&hive, Some(&machine)),
        classes_sid(&hive),
    );
    // recovery reads the hive several times over: on the smaller hives
    if hive.bytes().len() <= 4 << 20 {
        let _ = hive.recover();
    }
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

    /// Office's keys and values damaged: read without a panic.
    #[test]
    fn damaged_office_keys(
        flips in proptest::collection::vec((any::<usize>(), any::<u8>()), 1..3000)
    ) {
        if let Ok((hive, _)) =
            ys_registry_parser::Hive::open(damage(plaso_win7().to_vec(), flips), &[])
        {
            let _ = office(&hive);
        }
    }

    /// Office MRU items of any text: decoded or refused.
    #[test]
    fn office_mru_items(text in "(\\[[FTO]?[0-9A-Fa-fé]{0,20}\\]?){0,4}\\*?.{0,8}") {
        let _ = mru_item(&text);
    }
}

proptest! {
    #![proptest_config(ProptestConfig::with_cases(512))]

    /// `Actions` and `DynamicInfo` of any bytes, and of bytes that start as version 1, 2 or 3 do:
    /// decoded as far as they go.
    #[test]
    fn task_values(
        version in 0u16..5,
        context in proptest::collection::vec(any::<u8>(), 0..64),
        rest in proptest::collection::vec(any::<u8>(), 0..400)
    ) {
        let mut bytes = version.to_le_bytes().to_vec();
        if version >= 2 {
            bytes.extend((context.len() as u32).to_le_bytes());
            bytes.extend(&context);
        }
        bytes.extend(&rest);
        let _ = task_actions(&bytes);
        let _ = task_actions(&rest);
        let _ = user_assist_data(&rest).map(|d| d.run_count());
        let _ = dynamic_info(&rest);
        let _ = (user_f(&rest), user_v(&rest), user_v(&bytes));
        let _ = (trust_record(&rest), mru_item(&String::from_utf8_lossy(&rest)));
    }
}
