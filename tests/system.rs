//! The `SYSTEM` hive of regipy's test data (MIT; `tests/fixtures/regipy/`): its control sets,
//! computer name and services. Every service's values and failure actions are those a reader
//! built on yarp gives for the same hive (and for a dirty Windows 11 hive with its logs).
#![allow(clippy::unwrap_used)]

use std::io::Read;

use ys_registry_parser::Hive;
use ys_registry_parser::system::{
    Action, ControlSets, FailureAction, Service, computer_name, error_control_name, services,
    start_name, type_names,
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
