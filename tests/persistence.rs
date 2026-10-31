//! Autostarts in real hives from regipy's test data (MIT; `tests/fixtures/regipy/`), checked
//! against what regipy's `lsa_packages` and `ntuser_persistence` plugins read from them.
#![allow(clippy::unwrap_used)]

use std::collections::BTreeMap;
use std::io::Read;

use ys_registry_parser::ntuser::classes_sid;
use ys_registry_parser::persistence::{self, Autostart};
use ys_registry_parser::system::ControlSets;
use ys_registry_parser::{Hive, LogFile};

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

fn open(name: &str, logs: &[&str]) -> Hive {
    let logs: Vec<LogFile> = logs
        .iter()
        .map(|&l| LogFile {
            name: l.to_owned(),
            data: fixture(l),
        })
        .collect();
    Hive::open(fixture(name), &logs).unwrap().0
}

/// How many records of each mechanism.
fn counts(records: &[Autostart]) -> BTreeMap<&'static str, usize> {
    let mut counts = BTreeMap::new();
    for r in records {
        *counts.entry(r.mechanism.name()).or_default() += 1;
    }
    counts
}

/// The data of the records of `mechanism`.
fn data(records: &[Autostart], mechanism: &str) -> Vec<String> {
    records
        .iter()
        .filter(|r| r.mechanism.name() == mechanism)
        .map(|r| r.data.clone().unwrap_or_default())
        .collect()
}

#[test]
fn system_hive() {
    let hive = open("SYSTEM", &[]);
    let set = ControlSets::read(&hive).current_or_first().unwrap();
    let (records, problems) = persistence::system(&hive, set);
    assert_eq!(problems, Vec::<String>::new());
    assert!(records.iter().all(|r| r.problems.is_empty() && !r.replayed));
    assert_eq!(
        counts(&records),
        BTreeMap::from([
            ("boot_execute", 1),
            ("known_dlls", 28),
            ("lsa_authentication_package", 1),
            ("lsa_notification_package", 1),
            ("lsa_security_package", 6),
            ("print_monitor", 6),
            ("print_processor", 3),
            ("print_provider", 2),
            ("security_provider", 1),
            ("time_provider", 3),
        ])
    );
    // as regipy's lsa_packages reads them
    assert_eq!(data(&records, "lsa_authentication_package"), ["msv1_0"]);
    assert_eq!(
        data(&records, "lsa_security_package"),
        [
            "kerberos", "msv1_0", "schannel", "wdigest", "tspkg", "pku2u"
        ]
    );
    assert_eq!(data(&records, "lsa_notification_package"), ["scecli"]);
    assert_eq!(data(&records, "boot_execute"), ["autocheck autochk *"]);
    let ntp: Vec<(String, Option<bool>)> = records
        .iter()
        .filter(|r| r.mechanism.name() == "time_provider")
        .map(|r| {
            (
                r.key_path.rsplit('\\').next().unwrap().to_owned(),
                r.enabled,
            )
        })
        .collect();
    assert_eq!(
        ntp,
        [
            ("NtpClient".to_owned(), Some(true)),
            ("NtpServer".to_owned(), Some(false)),
            ("VMICTimeProvider".to_owned(), Some(true)),
        ]
    );
}

#[test]
fn user_hives() {
    // as regipy's ntuser_persistence reads it; the empty `Load` value starts nothing
    let (records, problems) = persistence::ntuser(&open("NTUSER.DAT", &[]), None);
    assert_eq!(problems, Vec::<String>::new());
    assert_eq!(records.len(), 1);
    let run = &records[0];
    assert_eq!(
        (
            run.key_path.as_str(),
            run.value_name.as_str(),
            run.data.as_deref(),
            run.image_path.as_deref(),
            run.arguments.as_deref()
        ),
        (
            r"Software\Microsoft\Windows\CurrentVersion\Run",
            "Sidebar",
            Some(r"%ProgramFiles%\Windows Sidebar\Sidebar.exe /autoRun"),
            Some(r"%ProgramFiles%\Windows Sidebar\Sidebar.exe"),
            Some("/autoRun")
        )
    );

    let hive = open("UsrClass.dat", &["UsrClass.dat.LOG1", "UsrClass.dat.LOG2"]);
    assert_eq!(
        classes_sid(&hive).as_deref(),
        Some("S-1-5-21-2734969515-1644526556-1039763013-1001")
    );
    let (records, problems) = persistence::usrclass(&hive, None);
    assert_eq!(problems, Vec::<String>::new());
    assert_eq!(counts(&records), BTreeMap::from([("com_server", 42)]));
    assert_eq!(records.iter().filter(|r| r.wow64).count(), 23);
    assert!(
        data(&records, "com_server")
            .iter()
            .any(|d| d.ends_with(r"\amd64\FileSyncShell64.dll"))
    );
}
