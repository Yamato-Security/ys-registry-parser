// Copyright (C) 2026 Shirofune Security Co., Ltd.
//
// Unless explicitly acquired and licensed from Licensor under another license, the contents of this
// file are subject to the Reciprocal Public License ("RPL") Version 1.5, or subsequent versions as
// allowed by the RPL, and You may not copy or use this file in either source code or executable
// form, except in compliance with the terms and conditions of the RPL.
//
// All software distributed under the RPL is provided strictly on an "AS IS" basis, WITHOUT WARRANTY
// OF ANY KIND, EITHER EXPRESS OR IMPLIED, AND LICENSOR HEREBY DISCLAIMS ALL SUCH WARRANTIES,
// INCLUDING WITHOUT LIMITATION, ANY WARRANTIES OF MERCHANTABILITY, FITNESS FOR A PARTICULAR
// PURPOSE, QUIET ENJOYMENT, OR NON-INFRINGEMENT. See the RPL for specific language governing rights
// and limitations under the RPL.

//! Damaged hives and arbitrary bytes: read as far as they go, never a panic or a hang.
#![allow(clippy::unwrap_used)]

use std::io::Read;
use std::sync::OnceLock;

use proptest::prelude::*;
use ys_registry_parser::app_history;
use ys_registry_parser::appcompat;
use ys_registry_parser::audit_policy::{audit_events, audit_policy};
use ys_registry_parser::bcd::{bcd, device_summary};
use ys_registry_parser::comdlg32::{dialogs, item_list_problem};
use ys_registry_parser::installed::{self, install_date, msi_version, package_name, unpack_guid};
use ys_registry_parser::lsa_secrets::{cached_logons, secret_kind, secrets};
use ys_registry_parser::mru::mru_lists;
use ys_registry_parser::networks;
use ys_registry_parser::ntuser::{
    classes_sid, mui_cache, profile_name, recent_docs, user_assist, user_assist_data,
    user_assist_settings,
};
use ys_registry_parser::ntuser::{
    feature_usage, feature_usage_created, programs_cache, recent_apps, taskband,
};
use ys_registry_parser::office::{mru_item, office, trust_record};
use ys_registry_parser::persistence::{self, MachineClasses};
use ys_registry_parser::remote_access::{
    connections, host_key_blob, host_key_fingerprint, host_key_name, mount_point_share, mru_list,
    rdp_target, unescape,
};
use ys_registry_parser::sam::{accounts, machine_sid, user_f, user_v};
use ys_registry_parser::security_settings;
use ys_registry_parser::shellbags::shell_bags;
use ys_registry_parser::software::{dynamic_info, profile_list, task_actions, task_cache};
use ys_registry_parser::system::{ControlSets, bam, computer_name, device_path, services};
use ys_registry_parser::system_info::{self, TransitionDate, domains, sid, utc_offset};
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

/// The SECURITY hive, unpacked once.
fn security() -> &'static [u8] {
    static SECURITY: OnceLock<Vec<u8>> = OnceLock::new();
    SECURITY.get_or_init(|| fixture("SECURITY"))
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

/// regipy's dirty `NTUSER.DAT`, with the Program Compatibility Assistant's `Store`, unpacked
/// once.
fn ntuser_pca() -> &'static [u8] {
    static NTUSER: OnceLock<Vec<u8>> = OnceLock::new();
    NTUSER.get_or_init(|| fixture("transactions_NTUSER.DAT"))
}

/// A CIT database of Plaso's Windows 10 `SOFTWARE` hive.
fn cit_database() -> Vec<u8> {
    std::fs::read(format!(
        "{}/tests/fixtures/plaso/cit_system_88EDBB9D.bin",
        env!("CARGO_MANIFEST_DIR")
    ))
    .unwrap()
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

/// The DFIR Artifact Museum's Windows 10 user hive, with Sysinternals keys, unpacked once.
fn ntuser_apt() -> &'static [u8] {
    static NTUSER: OnceLock<Vec<u8>> = OnceLock::new();
    NTUSER.get_or_init(|| {
        let path = format!(
            "{}/tests/fixtures/museum/w10_apt_NTUSER.DAT.gz",
            env!("CARGO_MANIFEST_DIR")
        );
        let mut data = Vec::new();
        flate2::read::GzDecoder::new(std::fs::File::open(path).unwrap())
            .read_to_end(&mut data)
            .unwrap();
        data
    })
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
    let _ = bcd(&hive);
    let _ = connections(&hive);
    let sets = ControlSets::read(&hive);
    let _ = computer_name(&hive);
    let mut devices = Vec::new();
    for set in sets.present {
        let _ = services(&hive, set);
        let _ = persistence::system(&hive, set);
        if let Some(n) = networks::system(&hive, set)
            && let Some(tz) = n.time_zone
        {
            let times = networks::software(&hive)
                .profiles
                .into_iter()
                .flat_map(|p| [p.date_created, p.date_last_connected]);
            for time in times.flatten() {
                let _ = tz.to_utc(&time);
            }
        }
        let _ = security_settings::system(&hive, set);
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
    let found = system_info::system(&hive);
    if let Some(zone) = &found.time_zone {
        let _ = zone.standard_start.map(|d| d.describe());
        let _ = zone.bias.map(utc_offset);
    }
    let _ = (system_info::software(&hive), machine_sid(&hive));
    let _ = domains(&hive);
    let _ = (
        security_settings::software(&hive),
        security_settings::ntuser(&hive),
    );
    if let Some(policy) = audit_policy(&hive) {
        for setting in &policy.events.settings {
            let _ = (setting.subcategory_id(), setting.setting.name());
        }
    }
    let _ = (appcompat::software(&hive), appcompat::ntuser(&hive));
    for secret in secrets(&hive).map(|s| s.0).unwrap_or_default() {
        let _ = (secret.kind.name(), secret.current.has_data());
    }
    let _ = cached_logons(&hive);
    let machine = MachineClasses::read(&hive);
    let _ = (feature_usage(&hive), feature_usage_created(&hive));
    let _ = (recent_apps(&hive), taskband(&hive), programs_cache(&hive));
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

    /// The BCD store's objects and elements damaged: read without a panic.
    #[test]
    fn a_damaged_bcd_store(flips in proptest::collection::vec((any::<usize>(), any::<u8>()), 1..300)) {
        read_all(damage(fixture("BCD"), flips));
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


    /// Third-party tools' keys and values damaged: read without a panic.
    #[test]
    fn damaged_app_history(
        flips in proptest::collection::vec((any::<usize>(), any::<u8>()), 1..3000)
    ) {
        for hive in [ntuser_apt(), ntuser()] {
            if let Ok((hive, _)) = ys_registry_parser::Hive::open(damage(hive.to_vec(), flips.clone()), &[]) {
                let _ = app_history::ntuser(&hive);
            }
        }
    }


    /// Compatibility data's keys and values damaged: read without a panic.
    #[test]
    fn damaged_appcompat(
        flips in proptest::collection::vec((any::<usize>(), any::<u8>()), 1..3000)
    ) {
        if let Ok((hive, _)) =
            ys_registry_parser::Hive::open(damage(ntuser_pca().to_vec(), flips), &[])
        {
            let _ = appcompat::ntuser(&hive);
        }
    }

    #[test]
    fn a_damaged_security_hive(
        flips in proptest::collection::vec((any::<usize>(), any::<u8>()), 1..300)
    ) {
        read_all(damage(security().to_vec(), flips));
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

    /// The MRU lists' keys and values damaged, with `TypedURLsTime`: read without a panic.
    #[test]
    fn damaged_mru_lists(
        flips in proptest::collection::vec((any::<usize>(), any::<u8>()), 1..3000)
    ) {
        if let Ok((hive, _)) =
            ys_registry_parser::Hive::open(damage(plaso_ntuser().to_vec(), flips), &[])
        {
            let _ = mru_lists(&hive);
        }
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
        let _ = networks::system_time(&rest).map(|t| t.map(|t| t.text()));
        let _ = secret_kind(&String::from_utf8_lossy(&rest));
        let _ = (device_summary(&rest), device_summary(&bytes));
        let _ = appcompat::lznt1(&rest, 1 << 16);
        let _ = appcompat::sign_media(&String::from_utf8_lossy(&rest));
        // PolAdtEv: any bytes, and bytes that start as the subcategory layout's header does
        let mut adt = vec![0, 1, 0, 0, version as u8, 0, 0, 0];
        adt.extend(&rest);
        let _ = (audit_events(&rest), audit_events(&adt));
        let _ = (trust_record(&rest), mru_item(&String::from_utf8_lossy(&rest)));
        let _ = (sid(&rest), sid(&bytes));
        let _ = TransitionDate::from_bytes(&rest).map(|d| d.describe());
        let _ = utc_offset(i32::from_le_bytes([version as u8, 0, 0, 0]).wrapping_mul(-1_000_003));
        let _ = (item_list_problem(&rest), item_list_problem(&bytes));
        let _ = (usb::mount_target(&rest), usb::mount_target(&bytes));
        let text = String::from_utf8_lossy(&rest);
        let _ = (unpack_guid(&text), install_date(&text), package_name(&text));
        let _ = msi_version(u32::from_le_bytes([version as u8, 0, 0, rest.len() as u8]));
        let _ = (usb::device_ref(&text), usb::storage_name(&text), usb::vid_pid(&text));
        let _ = usb::serial("USBSTOR", &text);
        let _ = device_path(&String::from_utf8_lossy(&rest));
    }

    /// A real CIT database with bytes changed: decompressed as far as it goes.
    #[test]
    fn damaged_lznt1(flips in proptest::collection::vec((any::<usize>(), any::<u8>()), 1..40)) {
        let mut data = cit_database();
        for (at, byte) in flips {
            let at = 8 + at % (data.len() - 8);
            data[at] = byte;
        }
        let _ = appcompat::lznt1(&data[8..], 1 << 20);

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

/// The Windows 10 NTUSER.DAT with every kind of `FeatureUsage` count and packaged apps pinned,
/// unpacked once.
fn ntuser_win10() -> &'static [u8] {
    static NTUSER: OnceLock<Vec<u8>> = OnceLock::new();
    NTUSER.get_or_init(|| fixture("NTUSER_BAGMRU.DAT"))
}

proptest! {
    #![proptest_config(ProptestConfig::with_cases(32))]

    /// Explorer's use counts, recent apps, pins and programs cache damaged: read without a panic.
    #[test]
    fn a_damaged_explorer_hive(
        flips in proptest::collection::vec((any::<usize>(), any::<u8>()), 1..3000)
    ) {
        if let Ok((hive, _)) =
            ys_registry_parser::Hive::open(damage(ntuser_win10().to_vec(), flips), &[])
        {
            let _ = (feature_usage(&hive), recent_apps(&hive));
            let _ = (taskband(&hive), programs_cache(&hive));
        }
    }
}
