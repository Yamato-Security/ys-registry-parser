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

//! The `SYSTEM` hive of regipy's test data (MIT; `tests/fixtures/regipy/`): its control sets,
//! computer name and services. Every service's values and failure actions are those a reader
//! built on yarp gives for the same hive (and for a dirty Windows 11 hive with its logs).
#![allow(clippy::unwrap_used)]

use std::io::Read;

use ys_registry_parser::Hive;
use ys_registry_parser::system::{
    Action, ControlSets, FailureAction, Moderator, Service, bam, computer_name, device_path,
    error_control_name, services, start_name, type_names,
};

fn system_bytes() -> Vec<u8> {
    let path = format!(
        "{}/tests/fixtures/regipy/SYSTEM.gz",
        env!("CARGO_MANIFEST_DIR")
    );
    let mut data = Vec::new();
    flate2::read::GzDecoder::new(std::fs::File::open(path).unwrap())
        .read_to_end(&mut data)
        .unwrap();
    data
}

fn open(data: Vec<u8>) -> Hive {
    Hive::open(data, &[]).unwrap().0
}

fn system() -> Hive {
    open(system_bytes())
}

fn value_offset(data: &[u8], path: &str, name: &str) -> usize {
    let hive = open(data.to_vec());
    let offset = hive.key(path).unwrap().value(name).unwrap().offset() as usize;
    4096 + offset
}

#[test]
fn control_sets_and_name() {
    let hive = system();
    assert_eq!(
        ControlSets::read(&hive),
        ControlSets {
            current: Some(1),
            default: Some(1),
            failed: Some(0),
            last_known_good: Some(2),
            present: vec![1, 2],
        }
    );
    assert_eq!(computer_name(&hive).as_deref(), Some("WKS-WIN732BITA"));
}

#[test]
fn services_of_each_control_set() {
    let hive = system();
    let (current, problems) = services(&hive, 1).unwrap();
    assert_eq!((current.len(), problems.len()), (467, 0));
    assert_eq!(services(&hive, 2).unwrap().0.len(), 466);
    assert!(services(&hive, 3).is_none());
    assert!(current.iter().all(|s| s.problems.is_empty() && !s.replayed));
    let find = |name: &str| current.iter().find(|s| s.name == name).unwrap();

    // a shared process's service: its DLL under Parameters, restarted twice when it fails
    let event_log = find("eventlog");
    assert_eq!(
        event_log,
        &Service {
            name: "eventlog".into(),
            last_written: 129_338_588_229_480_400,
            display_name: Some(r"@%SystemRoot%\system32\wevtsvc.dll,-200".into()),
            description: Some(r"@%SystemRoot%\system32\wevtsvc.dll,-201".into()),
            image_path: Some(
                r"%SystemRoot%\System32\svchost.exe -k LocalServiceNetworkRestricted".into()
            ),
            service_dll: Some(r"%SystemRoot%\System32\wevtsvc.dll".into()),
            start: Some(2),
            delayed_autostart: None,
            service_type: Some(0x20),
            error_control: Some(1),
            object_name: Some(r"NT AUTHORITY\LocalService".into()),
            group: Some("Event Log".into()),
            required_privileges: Some(vec![
                "SeChangeNotifyPrivilege".into(),
                "SeImpersonatePrivilege".into()
            ]),
            depend_on_service: None,
            depend_on_group: None,
            service_sid_type: Some(1),
            user_service_flags: None,
            reboot_message: None,
            failure_actions_on_non_crash_failures: Some(true),
            failure_command: None,
            failure_actions: event_log.failure_actions.clone(),
            failure_actions_raw: None,
            replayed: false,
            problems: Vec::new(),
        }
    );
    let actions = event_log.failure_actions.as_ref().unwrap();
    assert_eq!(actions.reset_period, 86_400);
    assert_eq!(
        actions.actions,
        [
            FailureAction {
                action: Action::Restart,
                delay_ms: 60_000
            },
            FailureAction {
                action: Action::Restart,
                delay_ms: 120_000
            },
            FailureAction {
                action: Action::None,
                delay_ms: 0
            },
        ]
    );
    assert_eq!(start_name(event_log.start.unwrap()), "automatic");
    assert_eq!(
        type_names(event_log.service_type.unwrap()),
        ["win32_share_process"]
    );
    assert_eq!(
        error_control_name(event_log.error_control.unwrap()),
        "normal"
    );

    // started after the other automatic services
    assert_eq!(find("wuauserv").delayed_autostart, Some(true));
    // a driver
    let tcpip = find("Tcpip");
    assert_eq!(
        tcpip.image_path.as_deref(),
        Some(r"System32\drivers\tcpip.sys")
    );
    assert_eq!((tcpip.start, tcpip.service_type), (Some(0), Some(1)));
    assert_eq!(tcpip.failure_actions, None);
    // a display name written as a multi-string of one string
    assert_eq!(find("NDProxy").display_name.as_deref(), Some("NDIS Proxy"));

    let with_actions = current
        .iter()
        .filter(|s| s.failure_actions.is_some())
        .count();
    assert_eq!(with_actions, 133);
}

#[test]
fn an_unusable_current_control_set_falls_back_to_the_first_present() {
    let mut data = system_bytes();
    let cell = value_offset(&data, "Select", "Current");
    // The resident DWORD is the vk record's data-offset field.
    data[cell + 12..cell + 16].copy_from_slice(&99u32.to_le_bytes());

    let hive = open(data);
    let sets = ControlSets::read(&hive);
    assert_eq!(sets.current, Some(99));
    assert_eq!(sets.current_or_first(), Some(1));
    assert_eq!(computer_name(&hive).as_deref(), Some("WKS-WIN732BITA"));

    let mut wrong_type = system_bytes();
    let cell = value_offset(&wrong_type, "Select", "Current");
    wrong_type[cell + 16..cell + 20].copy_from_slice(&5u32.to_le_bytes());
    let hive = open(wrong_type);
    let sets = ControlSets::read(&hive);
    assert_eq!(sets.current, None);
    assert_eq!(sets.current_or_first(), Some(1));
}

#[test]
fn service_numbers_must_be_dwords() {
    let mut data = system_bytes();
    let cell = value_offset(&data, r"ControlSet001\Services\eventlog", "Start");
    // The type is 12 bytes into the vk record, after the cell's four-byte header.
    data[cell + 16..cell + 20].copy_from_slice(&11u32.to_le_bytes());

    let hive = open(data);
    let eventlog = services(&hive, 1)
        .unwrap()
        .0
        .into_iter()
        .find(|service| service.name == "eventlog")
        .unwrap();
    assert_eq!(eventlog.start, None);
    assert!(
        eventlog
            .problems
            .iter()
            .any(|problem| problem == "Start: is REG_QWORD, not REG_DWORD")
    );
}

#[test]
fn failure_actions_must_be_binary_and_keep_malformed_bytes() {
    let original = system_bytes();
    let cell = value_offset(
        &original,
        r"ControlSet001\Services\eventlog",
        "FailureActions",
    );

    let mut wrong_type = original.clone();
    wrong_type[cell + 16..cell + 20].copy_from_slice(&1u32.to_le_bytes());
    let hive = open(wrong_type);
    let eventlog = services(&hive, 1)
        .unwrap()
        .0
        .into_iter()
        .find(|service| service.name == "eventlog")
        .unwrap();
    assert_eq!(eventlog.failure_actions, None);
    assert!(
        eventlog
            .failure_actions_raw
            .as_ref()
            .is_some_and(|b| !b.is_empty())
    );
    assert!(
        eventlog
            .problems
            .iter()
            .any(|problem| problem == "FailureActions: is REG_SZ, not REG_BINARY")
    );

    let mut cut_short = original;
    cut_short[cell + 8..cell + 12].copy_from_slice(&0x10_000u32.to_le_bytes());
    let hive = open(cut_short);
    let eventlog = services(&hive, 1)
        .unwrap()
        .0
        .into_iter()
        .find(|service| service.name == "eventlog")
        .unwrap();
    assert_eq!(eventlog.failure_actions, None);
    assert!(
        eventlog
            .failure_actions_raw
            .as_ref()
            .is_some_and(|b| !b.is_empty())
    );
    assert!(
        eventlog
            .problems
            .iter()
            .any(|problem| problem.starts_with("FailureActions: ") && problem.contains("cut short")),
        "{:?}",
        eventlog.problems
    );
}

/// regipy's `SYSTEM_WIN_10_1709` (MIT; `tests/fixtures/regipy/`): a Windows 10 1709 hive upgraded
/// to a later release, with BAM's keys in both layouts. Every entry is what regipy's `bam` plugin
/// gives (its times to the microsecond) and Plaso's (to the 100 ns).
fn win10_1709() -> Hive {
    let path = format!(
        "{}/tests/fixtures/regipy/SYSTEM_WIN_10_1709.gz",
        env!("CARGO_MANIFEST_DIR")
    );
    let mut data = Vec::new();
    flate2::read::GzDecoder::new(std::fs::File::open(path).unwrap())
        .read_to_end(&mut data)
        .unwrap();
    open(data)
}

#[test]
fn complete_service_recovery_lists_and_related_values() {
    let hive = win10_1709();
    let records = services(&hive, 1).unwrap().0;
    let find = |name: &str| records.iter().find(|s| s.name == name).unwrap();
    for (name, restarts, delay) in [("AarSvc", 3, 10_000), ("WSearch", 5, 30_000)] {
        let mut expected = vec![
            FailureAction {
                action: Action::Restart,
                delay_ms: delay
            };
            restarts
        ];
        expected.push(FailureAction {
            action: Action::None,
            delay_ms: 0,
        });
        let policy = find(name).failure_actions.as_ref().unwrap();
        assert_eq!(policy.reset_period, 86_400);
        assert_eq!(policy.actions, expected, "{name}");
        assert_eq!(policy.trailing, 0);
    }
    let schedule = &find("Schedule").failure_actions.as_ref().unwrap().actions;
    assert_eq!(
        schedule[0],
        FailureAction {
            action: Action::OwnRestart,
            delay_ms: 0
        }
    );
    assert_eq!(schedule[0].action.name(), "own_restart");
    assert_eq!(find("AarSvc").user_service_flags, Some(3));
    assert_eq!(find("AarSvc").failure_actions_on_non_crash_failures, None);
    assert_eq!(
        find("WSearch").failure_actions_on_non_crash_failures,
        Some(true)
    );
    assert_eq!(
        find("WSearch").depend_on_service.as_ref().unwrap(),
        &["RPCSS", "BrokerInfrastructure"]
    );
    assert_eq!(
        find("cdfs").depend_on_group.as_ref().unwrap(),
        &["SCSI CDROM Class"]
    );
    let service = find("MSiSCSI");
    assert_eq!(service.reboot_message.as_deref(), Some("See Note 3 below"));
    assert_eq!(service.failure_command.as_deref(), Some("customScript.cmd"));
}

#[test]
fn service_lists_and_recovery_flags_preserve_empty_absent_and_invalid_values() {
    let path = r"ControlSet001\Services\eventlog";
    let mut data = system_bytes();
    let flag = value_offset(&data, path, "FailureActionsOnNonCrashFailures");
    let privileges = value_offset(&data, path, "RequiredPrivileges");
    data[flag + 12..flag + 16].copy_from_slice(&0u32.to_le_bytes());
    // An inline, empty REG_MULTI_SZ (two UTF-16 NULs).
    data[privileges + 8..privileges + 12].copy_from_slice(&0x8000_0004u32.to_le_bytes());
    data[privileges + 12..privileges + 16].fill(0);
    let eventlog = |bytes| {
        services(&open(bytes), 1)
            .unwrap()
            .0
            .into_iter()
            .find(|s| s.name == "eventlog")
            .unwrap()
    };
    let empty = eventlog(data.clone());
    assert_eq!(empty.failure_actions_on_non_crash_failures, Some(false));
    assert_eq!(empty.required_privileges, Some(vec![]));
    assert_eq!(empty.depend_on_service, None);
    assert_eq!(empty.problems, Vec::<String>::new());

    data[privileges + 16..privileges + 20].copy_from_slice(&1u32.to_le_bytes());
    data[flag + 16..flag + 20].copy_from_slice(&3u32.to_le_bytes());
    let invalid = eventlog(data);
    assert_eq!(invalid.required_privileges, None);
    assert_eq!(invalid.failure_actions_on_non_crash_failures, None);
    assert!(
        invalid
            .problems
            .iter()
            .any(|p| p == "RequiredPrivileges: is REG_SZ, not REG_MULTI_SZ")
    );
    assert!(
        invalid
            .problems
            .iter()
            .any(|p| p == "FailureActionsOnNonCrashFailures: is REG_BINARY, not REG_DWORD")
    );
    assert_eq!(invalid.failure_actions.unwrap().actions.len(), 3);
}

#[test]
fn extra_bytes_are_preserved_without_inventing_an_action() {
    let mut data = system_bytes();
    let path = r"ControlSet001\Services\eventlog";
    let vk = value_offset(&data, path, "FailureActions");
    let blob = 4096 + u32::from_le_bytes(data[vk + 12..vk + 16].try_into().unwrap()) as usize + 4;
    data[blob + 12..blob + 16].copy_from_slice(&2u32.to_le_bytes());
    let raw = data[blob..blob + 44].to_vec();
    let svc = services(&open(data), 1)
        .unwrap()
        .0
        .into_iter()
        .find(|s| s.name == "eventlog")
        .unwrap();
    assert_eq!(svc.failure_actions_raw.as_ref(), Some(&raw));
    let policy = svc.failure_actions.unwrap();
    assert_eq!(policy.actions.len(), 2);
    assert_eq!(policy.trailing, 8);
    assert!(
        svc.problems
            .iter()
            .any(|p| p.contains("8 bytes after the declared actions"))
    );
}

#[test]
fn bam_in_both_layouts() {
    let hive = win10_1709();
    let (entries, problems) = bam(&hive, 1).unwrap();
    assert_eq!(problems, Vec::<String>::new());
    assert_eq!(entries.len(), 55);
    assert!(entries.iter().all(|e| e.moderator == Moderator::Bam
        && e.problems.is_empty()
        && e.data_raw.is_none()
        && e.last_run.is_some()
        && !e.replayed));
    let user = "S-1-5-21-2595688666-2948619230-3055395256-1001";
    let count = |layout: &str, sid: &str| {
        entries
            .iter()
            .filter(|e| {
                e.user_sid == sid
                    && e.key_path == format!(r"ControlSet001\Services\bam\{layout}\{sid}")
            })
            .count()
    };
    assert_eq!(
        [
            count(r"State\UserSettings", user),
            count(r"State\UserSettings", "S-1-5-90-0-1"),
            count("UserSettings", user),
            count("UserSettings", "S-1-5-90-0-1"),
        ],
        [30, 1, 23, 1]
    );
    // State\UserSettings first, then UserSettings; packaged apps and paths
    let first = &entries[0];
    assert_eq!(
        (first.program.as_str(), first.last_run),
        (
            "Microsoft.Windows.StartMenuExperienceHost_cw5n1h2txyewy",
            Some(132_317_609_713_588_336)
        )
    );
    assert_eq!(device_path(&first.program), None);
    let dwm = entries.last().unwrap();
    assert_eq!(
        dwm.key_path,
        r"ControlSet001\Services\bam\UserSettings\S-1-5-90-0-1"
    );
    assert_eq!(
        (dwm.program.as_str(), dwm.last_run),
        (
            r"\Device\HarddiskVolume2\Windows\System32\dwm.exe",
            Some(132_024_658_042_194_716)
        )
    );
    assert_eq!(
        device_path(&dwm.program),
        Some((r"\Device\HarddiskVolume2", r"\Windows\System32\dwm.exe"))
    );
    assert_eq!(
        entries
            .iter()
            .filter(|e| device_path(&e.program).is_none())
            .count(),
        34
    );
    // the hive has no other control set, and the Windows 7 hive no BAM
    assert!(bam(&hive, 2).is_none());
    assert!(bam(&system(), 1).is_none());
}
