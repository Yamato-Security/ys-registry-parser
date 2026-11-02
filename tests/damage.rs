//! Damaged hives and arbitrary bytes: read as far as they go, never a panic or a hang.
#![allow(clippy::unwrap_used)]

use std::io::Read;
use std::sync::OnceLock;

use proptest::prelude::*;
use ys_registry_parser::ntuser::{
    classes_sid, profile_name, recent_docs, user_assist, user_assist_data, user_assist_settings,
};
use ys_registry_parser::persistence::{self, MachineClasses};
use ys_registry_parser::sam::{accounts, machine_sid, user_f, user_v};
use ys_registry_parser::software::{dynamic_info, profile_list, task_actions, task_cache};
use ys_registry_parser::system::{ControlSets, bam, computer_name, device_path, services};
use ys_registry_parser::usb;

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

/// The Windows 10 SYSTEM hive with BAM keys, unpacked once.
fn system_win10() -> &'static [u8] {
    static SYSTEM: OnceLock<Vec<u8>> = OnceLock::new();
    SYSTEM.get_or_init(|| fixture("SYSTEM_WIN_10_1709"))
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
    let mut devices = Vec::new();
    for set in sets.present {
        let _ = services(&hive, set);
        let _ = persistence::system(&hive, set);
        devices.extend(usb::devices(&hive, set).map(|d| d.0).unwrap_or_default());
        let _ = bam(&hive, set);
    }
    // the USB history of a hive that is every one of its hives at once
    let mounted = usb::mounted_devices(&hive).map(|m| m.0).unwrap_or_default();
    let portable = usb::portable_devices(&hive)
        .map(|p| p.0)
        .unwrap_or_default();
    let ready_boost = usb::ready_boost(&hive).map(|b| b.0).unwrap_or_default();
    let users = vec![(
        "user".to_owned(),
        usb::mount_points(&hive).map(|p| p.0).unwrap_or_default(),
    )];
    let _ = usb::history(&usb::Sources {
        devices: &devices,
        mounted: &mounted,
        portable: &portable,
        ready_boost: &ready_boost,
        users: &users,
    });
    let _ = (recent_docs(&hive), profile_name(&hive), task_cache(&hive));
    let _ = (user_assist(&hive), user_assist_settings(&hive));
    let _ = (accounts(&hive), machine_sid(&hive));
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

    /// BAM's keys and values damaged: read without a panic.
    #[test]
    fn a_damaged_bam(
        flips in proptest::collection::vec((any::<usize>(), any::<u8>()), 1..3000)
    ) {
        if let Ok((hive, _)) =
            ys_registry_parser::Hive::open(damage(system_win10().to_vec(), flips), &[])
        {
            for set in ControlSets::read(&hive).present {
                for entry in bam(&hive, set).map(|b| b.0).unwrap_or_default() {
                    let _ = device_path(&entry.program);
                }
            }
        }
    }

    #[test]
    fn a_damaged_ntuser_hive(
        flips in proptest::collection::vec((any::<usize>(), any::<u8>()), 1..3000)
    ) {
        read_all(damage(ntuser().to_vec(), flips));
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
        let _ = (usb::mount_target(&rest), usb::mount_target(&bytes));
        let text = String::from_utf8_lossy(&rest);
        let _ = (usb::device_ref(&text), usb::storage_name(&text), usb::vid_pid(&text));
        let _ = usb::serial("USBSTOR", &text);
        let _ = device_path(&String::from_utf8_lossy(&rest));
    }
}
