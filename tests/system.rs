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

fn system() -> Hive {
    let path = format!(
        "{}/tests/fixtures/regipy/SYSTEM.gz",
        env!("CARGO_MANIFEST_DIR")
    );
    let mut data = Vec::new();
    flate2::read::GzDecoder::new(std::fs::File::open(path).unwrap())
        .read_to_end(&mut data)
        .unwrap();
    Hive::open(data, &[]).unwrap().0
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
