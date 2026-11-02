//! Damaged hives and arbitrary bytes: read as far as they go, never a panic or a hang.
#![allow(clippy::unwrap_used)]

use std::io::Read;
use std::sync::OnceLock;

use proptest::prelude::*;
use ys_registry_parser::comdlg32::{dialogs, item_list_problem};
use ys_registry_parser::installed::{self, install_date, msi_version, package_name, unpack_guid};
use ys_registry_parser::ntuser::{
    classes_sid, mui_cache, profile_name, recent_docs, user_assist, user_assist_data,
    user_assist_settings,
};
use ys_registry_parser::persistence::{self, MachineClasses};
use ys_registry_parser::remote_access::{
    connections, host_key_blob, host_key_fingerprint, host_key_name, mount_point_share, mru_list,
    rdp_target, unescape,
};
use ys_registry_parser::sam::{accounts, machine_sid, user_f, user_v};
use ys_registry_parser::shellbags::shell_bags;
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

/// The UsrClass.dat hive (`BagMRU` and `MuiCache`), unpacked once.
fn usrclass() -> &'static [u8] {
    static USRCLASS: OnceLock<Vec<u8>> = OnceLock::new();
    USRCLASS.get_or_init(|| fixture("UsrClass.dat"))
}

/// regipy's `NTUSER-WSL.DAT`, with WSL distributions and App Paths, unpacked once.
fn ntuser_wsl() -> &'static [u8] {
    static NTUSER: OnceLock<Vec<u8>> = OnceLock::new();
    NTUSER.get_or_init(|| fixture("NTUSER-WSL.DAT"))
}

/// Plaso's NTUSER.DAT, with the common dialogs' history, unpacked once.
fn plaso_ntuser() -> &'static [u8] {
    static NTUSER: OnceLock<Vec<u8>> = OnceLock::new();
    NTUSER.get_or_init(|| {
        let path = format!(
            "{}/tests/fixtures/plaso/NTUSER.DAT.gz",
            env!("CARGO_MANIFEST_DIR")
        );
        let mut data = Vec::new();
        flate2::read::GzDecoder::new(std::fs::File::open(path).unwrap())
            .read_to_end(&mut data)
            .unwrap();
        data
    })
}

/// notatin's Windows 7 NTUSER.DAT, with remote connections of every kind but PuTTY sessions,
/// unpacked once.
fn win7_ntuser() -> &'static [u8] {
    static NTUSER: OnceLock<Vec<u8>> = OnceLock::new();
    NTUSER.get_or_init(|| {
        let path = format!(
            "{}/tests/fixtures/notatin/win7_ntuser.dat.gz",
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
    let _ = connections(&hive);
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
    let _ = (
        user_assist(&hive),
        user_assist_settings(&hive),
        shell_bags(&hive),
        mui_cache(&hive),
    );
    let _ = (accounts(&hive), machine_sid(&hive), dialogs(&hive));
    let _ = (installed::software(&hive), installed::ntuser(&hive));
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

    /// MuiCache's key and values damaged: read without a panic.
    #[test]
    fn a_damaged_mui_cache(
        flips in proptest::collection::vec((any::<usize>(), any::<u8>()), 1..3000)
    ) {
        if let Ok((hive, _)) =
            ys_registry_parser::Hive::open(damage(usrclass().to_vec(), flips), &[])
        {
            let _ = mui_cache(&hive);
        }
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
    fn a_damaged_usrclass_hive(
        flips in proptest::collection::vec((any::<usize>(), any::<u8>()), 1..3000)
    ) {
        read_all(damage(usrclass().to_vec(), flips));
    }

    /// Installed software's keys and values damaged: read without a panic.
    #[test]
    fn damaged_installed_software(
        flips in proptest::collection::vec((any::<usize>(), any::<u8>()), 1..3000)
    ) {
        if let Ok((hive, _)) =
            ys_registry_parser::Hive::open(damage(ntuser_wsl().to_vec(), flips), &[])
        {
            for program in installed::ntuser(&hive).0 {
                let _ = program.key_path.rsplit('\\').next().map(package_name);
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
        let _ = (item_list_problem(&rest), item_list_problem(&bytes));
        let _ = (usb::mount_target(&rest), usb::mount_target(&bytes));
        let text = String::from_utf8_lossy(&rest);
        let _ = (unpack_guid(&text), install_date(&text), package_name(&text));
        let _ = msi_version(u32::from_le_bytes([version as u8, 0, 0, rest.len() as u8]));
        let _ = (usb::device_ref(&text), usb::storage_name(&text), usb::vid_pid(&text));
        let _ = usb::serial("USBSTOR", &text);
        let _ = device_path(&String::from_utf8_lossy(&rest));
    }
}

proptest! {
    #![proptest_config(ProptestConfig::with_cases(32))]
    /// The common dialogs' keys and values damaged: read without a panic.
    #[test]
    fn a_damaged_comdlg32(
        flips in proptest::collection::vec((any::<usize>(), any::<u8>()), 1..3000)
    ) {
        if let Ok((hive, _)) =
            ys_registry_parser::Hive::open(damage(plaso_ntuser().to_vec(), flips), &[])
        {
            for entry in dialogs(&hive).map(|d| d.0).unwrap_or_default() {
                let _ = entry.shell_items.as_deref().map(item_list_problem);
            }
        }
    }
}

proptest! {
    #![proptest_config(ProptestConfig::with_cases(32))]
    #[test]
    fn damaged_remote_connections(
        flips in proptest::collection::vec((any::<usize>(), any::<u8>()), 1..3000)
    ) {
        if let Ok((hive, _)) =
            ys_registry_parser::Hive::open(damage(win7_ntuser().to_vec(), flips), &[])
        {
            let _ = connections(&hive);
        }
    }

}

proptest! {
    #![proptest_config(ProptestConfig::with_cases(32))]
    #[test]
    fn remote_connection_texts(
        key_type in prop_oneof![
            Just("rsa2".to_owned()),
            Just("dss".to_owned()),
            Just("ssh-ed25519".to_owned()),
            Just("ssh-ed448".to_owned()),
            Just("ecdsa-sha2-nistp256".to_owned()),
            Just("ecdsa-sha2-nistp521".to_owned()),
            Just("rsa".to_owned()),
            ".{0,12}",
        ],
        stored in "(nistp256,|nistp521,)?(0x[0-9a-fA-F]{0,140},?){0,5}|.{0,64}",
        text in ".{0,64}"
    ) {
        let _ = (host_key_fingerprint(&key_type, &stored), host_key_blob(&key_type, &text));
        let _ = (host_key_name(&text), rdp_target(&text), unescape(&text));
        let _ = (mount_point_share(&text), mru_list(&text));
    }

}
