//! Security settings on regipy's Windows 7 `SYSTEM` (MIT; `tests/fixtures/regipy/`): `WDigest`
//! keeping cleartext passwords, Remote Desktop allowed without Network Level Authentication, and
//! event logs smaller than the default. The values are what regipy's `wdigest` and
//! `disable_last_access` give, and what python-registry and dissect.regf read.
#![allow(clippy::unwrap_used)]

use std::io::Read;

use ys_registry_parser::Hive;
use ys_registry_parser::security_settings::{Area, system};

fn regipy_system() -> Hive {
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
fn settings_of_a_windows_7_system() {
    let hive = regipy_system();
    let (settings, problems) = system(&hive, 1).unwrap();
    assert_eq!(problems, Vec::<String>::new());
    let lines: Vec<String> = settings
        .iter()
        .map(|s| {
            format!(
                "{} {} {} = {} {}",
                s.area.name(),
                s.setting,
                s.value_name,
                s.value.as_deref().unwrap_or("-"),
                match s.weakens_default {
                    Some(true) => "weakened",
                    Some(false) => "ok",
                    None => "-",
                }
            )
        })
        .collect();
    assert_eq!(
        lines,
        [
            "credentials wdigest_use_logon_credential UseLogonCredential = 1 weakened",
            "remote_access rdp_deny_connections fDenyTSConnections = 0 weakened",
            "remote_access rdp_port PortNumber = 3389 ok",
            "remote_access rdp_network_level_authentication UserAuthentication = 0 weakened",
            "network firewall_domain_profile EnableFirewall = 1 ok",
            "network firewall_private_profile EnableFirewall = 1 ok",
            "network firewall_public_profile EnableFirewall = 1 ok",
            "evidence ntfs_disable_last_access_update NtfsDisableLastAccessUpdate = 1 -",
            "evidence event_log_max_size MaxSize = 4194304 weakened",
            "evidence event_log_max_size MaxSize = 20971520 -",
            "evidence event_log_max_size MaxSize = 20971520 -",
            "evidence event_log_max_size MaxSize = 8388608 -",
            "evidence event_log_max_size MaxSize = 131072 -",
            "evidence event_log_max_size MaxSize = 4194304 weakened",
            "evidence event_log_max_size MaxSize = 4194304 weakened",
            "evidence event_log_max_size MaxSize = 15728640 -",
        ]
    );
    let wdigest = &settings[0];
    assert_eq!(
        wdigest.key_path,
        r"ControlSet001\Control\SecurityProviders\WDigest"
    );
    assert_eq!(
        wdigest.meaning,
        "WDigest keeps cleartext passwords in LSASS memory"
    );
    assert_eq!(wdigest.area, Area::Credentials);
    assert!(!wdigest.policy && !wdigest.replayed && wdigest.key_last_written > 0);
    assert_eq!(
        settings[13].meaning,
        "the Security log keeps up to 4 MiB, less than the default 20 MiB"
    );
    assert!(
        settings
            .iter()
            .all(|s| s.problems.is_empty() && s.data_raw.is_none())
    );
    // the other control set has the same, but WDigest's key; one that isn't there
    let (other, _) = system(&hive, 2).unwrap();
    assert_eq!(other.len(), 15);
    assert!(
        other
            .iter()
            .all(|s| s.key_path.starts_with("ControlSet002"))
    );
    assert!(system(&hive, 3).is_none());
}
